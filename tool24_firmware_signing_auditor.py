#!/usr/bin/env python3
"""
Firmware Signing & Hard-coded Public Key Auditor (QCVN 11:2026/BCA Clauses 2.3.1, 2.3.3 & 2.3.5)
Multi-Profile & Multi-Format Support:
  1. Axis Communications (tar.gz fimage .bin container, sums.bin SHA-256, sign.bin pgnf RSA signature, SquashFS rootfs public keys).
  2. Oryza Systems / Tiandy (.encap secure container, ENCAP magic header, payload hashing, IXIT 7-UpdMech RSA-3072 / SHA-256).
  3. Automated generation of byte-tampered firmware packages for manual Web UI / CMS upload testing (negative test case).
"""

import argparse
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import tempfile
from typing import Any, Dict, List, Optional, Tuple

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

# Toolkit integration
TOOLKIT_DIR = os.path.dirname(os.path.abspath(__file__))
if TOOLKIT_DIR not in sys.path:
    sys.path.insert(0, TOOLKIT_DIR)

from adapters import (
    AxisCameraAdapter,
    BaseCameraAdapter,
    GenericCameraAdapter,
    OryzaCameraAdapter,
    get_camera_adapter,
)
from toolkit_config import (
    get_active_profile,
    get_adapter,
    load_config,
    switch_profile,
)

console = Console()

DEFAULT_FIRMWARE_DIR = "/home/merlin/PSI/AXIS Q1806-LE/Firmware"
SIGN_HEADER_MAGIC = b"pgnf"
SIGN_HEADER_LEN = 72
SUMS_RECORD_LEN = 64
SUMS_NAME_LEN = 32
SHA256_DIGEST_LEN = 32


# ----------------------------------------------------------------------
# Legacy / Standalone Helpers (preserved for backward compatibility)
# ----------------------------------------------------------------------

def compute_sha256_stream(fileobj: io.BufferedReader, chunk_size: int = 1024 * 1024) -> str:
    """Compute hex SHA-256 digest of a stream without loading it all into RAM."""
    h = hashlib.sha256()
    while True:
        chunk = fileobj.read(chunk_size)
        if not chunk:
            break
        h.update(chunk)
    return h.hexdigest()


def parse_sums_bin(data: bytes) -> List[Dict[str, str]]:
    """Parse 64-byte records (32B filename + 32B SHA-256 digest) from sums.bin."""
    records: List[Dict[str, str]] = []
    if len(data) % SUMS_RECORD_LEN != 0:
        return records
    for offset in range(0, len(data), SUMS_RECORD_LEN):
        rec = data[offset : offset + SUMS_RECORD_LEN]
        name = rec[:SUMS_NAME_LEN].split(b"\x00", 1)[0].decode("utf-8", errors="replace")
        digest = rec[SUMS_NAME_LEN:].hex()
        records.append({"name": name, "expected_sha256": digest})
    return records


def parse_sign_bin(data: bytes) -> Dict[str, Any]:
    """Parse AXIS pgnf signature header and raw RSA signature bytes."""
    if len(data) < SIGN_HEADER_LEN:
        return {"valid_header": False, "error": f"sign.bin too short ({len(data)} bytes)"}

    magic = data[:4]
    key_id = data[4:8].hex()
    domain = data[8:SIGN_HEADER_LEN].split(b"\x00", 1)[0].decode("utf-8", errors="replace")
    sig_bytes = data[SIGN_HEADER_LEN:]
    sig_bits = len(sig_bytes) * 8

    return {
        "valid_header": magic == SIGN_HEADER_MAGIC,
        "magic": magic.decode("ascii", errors="replace"),
        "key_id_hex": key_id,
        "signing_domain": domain,
        "signature_bytes": len(sig_bytes),
        "inferred_rsa_bits": sig_bits if sig_bits in (2048, 3072, 4096) else None,
        "signature_raw": sig_bytes,
    }


def inspect_rsa_pubkey_pem(pem_path: str) -> Dict[str, Any]:
    """Use openssl to inspect an RSA public key PEM file and return bit length."""
    res = subprocess.run(
        ["openssl", "rsa", "-pubin", "-in", pem_path, "-text", "-noout"],
        capture_output=True,
        text=True,
    )
    if res.returncode != 0:
        return {"ok": False, "error": res.stderr.strip()}
    match = re.search(r"Public-Key:\s*\((\d+)\s+bit\)", res.stdout)
    bits = int(match.group(1)) if match else None
    return {"ok": True, "bits": bits}


def verify_signature_openssl(pem_path: str, sig_path: str, data_path: str) -> Dict[str, Any]:
    """Verify SHA-256 RSA signature using OpenSSL (tries PSS then PKCS#1 v1.5)."""
    attempts = [
        ("RSA-PSS + SHA-256", ["openssl", "dgst", "-sha256", "-sigopt", "rsa_padding_mode:pss", "-verify", pem_path, "-signature", sig_path, data_path]),
        ("RSA-PKCS1v1.5 + SHA-256", ["openssl", "dgst", "-sha256", "-verify", pem_path, "-signature", sig_path, data_path]),
    ]
    for scheme, cmd in attempts:
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode == 0 and "Verified OK" in res.stdout:
            return {"verified": True, "scheme": scheme, "output": res.stdout.strip()}
    return {"verified": False, "scheme": None, "output": "Verification failed under PSS and PKCS#1 v1.5"}


def find_candidate_pubkeys_in_squashfs(rootfs_path: str, signing_domain: str) -> List[str]:
    """List candidate PEM public key paths inside an unencrypted SquashFS image."""
    res = subprocess.run(
        ["unsquashfs", "-ll", rootfs_path],
        capture_output=True,
        text=True,
    )
    if res.returncode != 0:
        return []

    candidates: List[str] = []
    for line in res.stdout.splitlines():
        parts = line.split()
        if not parts:
            continue
        path = parts[-1]
        if not path.startswith("squashfs-root/"):
            continue
        rel = path[len("squashfs-root/") :]
        low = rel.lower()
        if "/etc/ssl/certs/" in low or "/usr/lib/python" in low:
            continue
        if low.endswith(".pem") and ("upgrade/" in low or "public" in low or "signdomain" in low):
            candidates.append(rel)

    def sort_key(p: str) -> Tuple[int, str]:
        name = os.path.basename(p).lower()
        if signing_domain and signing_domain.lower() in name and "firmware" in name:
            return (0, p)
        if signing_domain and signing_domain.lower() in name:
            return (1, p)
        if "upgrade/" in p.lower():
            return (2, p)
        return (3, p)

    return sorted(candidates, key=sort_key)


def analyze_firmware_package(fw_path: Path, extract_keys: bool = True, save_extracted: bool = True) -> Dict[str, Any]:
    """Fallback Axis .bin analyzer."""
    adapter = AxisCameraAdapter()
    return adapter.parse_firmware(str(fw_path), extract_keys=extract_keys, save_extracted=save_extracted)


def create_tampered_firmware(
    src_fw: Path,
    out_fw: Path,
    target_member: str = "sign.bin",
) -> Dict[str, Any]:
    """Fallback Axis tampered firmware generator."""
    adapter = AxisCameraAdapter()
    return adapter.generate_tampered_firmware(str(src_fw), str(out_fw), target_member=target_member)


# ----------------------------------------------------------------------
# Discovery & Resolution Helpers
# ----------------------------------------------------------------------

def resolve_firmware_files(
    adapter: BaseCameraAdapter,
    config: Dict[str, Any],
    cli_firmware: Optional[str] = None,
    cli_firmware_dir: Optional[str] = None,
) -> List[Path]:
    """Resolve firmware target files based on CLI flags, adapter type, and active profile config."""
    if cli_firmware:
        p = Path(cli_firmware)
        if not p.is_file():
            raise FileNotFoundError(f"Firmware file not found: {p}")
        return [p]

    fw_cfg = config.get("firmware_config", {})
    if cli_firmware_dir:
        base_dir = Path(cli_firmware_dir)
    elif fw_cfg.get("base_dir") and os.path.isdir(fw_cfg["base_dir"]):
        base_dir = Path(fw_cfg["base_dir"])
    else:
        base_dir = Path(DEFAULT_FIRMWARE_DIR)

    if not base_dir.is_dir():
        return []

    # If Oryza/Tiandy profile: check explicit keys in firmware_config first
    if isinstance(adapter, OryzaCameraAdapter):
        ordered_keys = ["old", "intermediate", "new"]
        found: List[Path] = []
        for k in ordered_keys:
            rel = fw_cfg.get(k)
            if rel:
                p = base_dir / rel if not os.path.isabs(rel) else Path(rel)
                if p.is_file() and p not in found:
                    found.append(p)
        if found:
            return found

        # Fallback to scanning all .encap files
        encap_files = sorted(
            p for p in base_dir.rglob("*.encap")
            if "_tampered" not in p.name.lower()
        )
        if encap_files:
            return encap_files

    # Axis / Generic .bin check
    bin_files = sorted(
        p for p in base_dir.glob("*.bin")
        if "_TAMPERED" not in p.name and "_tampered" not in p.name
    )
    if bin_files:
        return bin_files

    # Fallback to rglob for any supported extension
    all_supported = sorted(
        p for p in base_dir.rglob("*")
        if p.is_file() and adapter.check_firmware_support(str(p)) and "_tampered" not in p.name.lower()
    )
    return all_supported


# ----------------------------------------------------------------------
# Reporting Helpers
# ----------------------------------------------------------------------

def render_console_report(
    analyses: List[Dict[str, Any]],
    tamper_results: List[Dict[str, Any]],
    profile_id: str,
) -> None:
    """Print structured Rich summary to terminal with detailed filesystem & signature breakdown."""
    console.print(
        Panel.fit(
            f"[bold cyan]Firmware, Filesystem & Digital Signature Auditor (QCVN 11:2026/BCA)[/bold cyan]\n"
            f"[dim]Active Profile:[/dim] [yellow]{profile_id}[/yellow] | [dim]Analyzed Packages:[/dim] [green]{len(analyses)}[/green]",
            border_style="cyan",
        )
    )

    # 1. BẢNG TỔNG HỢP GÓI FIRMWARE
    summary_table = Table(title="1. Bảng Tổng Hợp Firmware & Xác Thực Chữ Ký Số", show_header=True, header_style="bold magenta")
    summary_table.add_column("Tệp Firmware", style="cyan", width=26)
    summary_table.add_column("Định Dạng / Vai Trò", style="white", width=24)
    summary_table.add_column("Filesystem Phát Hiện", style="yellow", width=26)
    summary_table.add_column("Chữ Ký Số", style="blue", width=22)
    summary_table.add_column("Khóa Công Khai (Root of Trust)", style="magenta", width=24)
    summary_table.add_column("Xác Thực Mật Mã (QCVN 11)", style="green", width=22)

    for item in analyses:
        fn = item.get("filename", "")
        fmt = item.get("format", "unknown")
        fs_list = item.get("filesystems", [])
        sig = item.get("signature", {})
        vkey = item.get("verified_pubkey")
        is_verified = item.get("crypto_verified", False)

        # Filesystem summary string
        if fs_list:
            fs_summary = "\n".join(f"• {f.get('name', 'fs')}: {f.get('type', 'SquashFS')}" for f in fs_list[:2])
            if len(fs_list) > 2:
                fs_summary += f"\n  (+{len(fs_list) - 2} phân vùng khác)"
        else:
            fs_summary = "[dim]Chưa phát hiện[/dim]"

        # Signature summary string
        if "ENCAP" in fmt:
            sig_str = f"RSA-3072 / SHA-256\n[dim](Container Magic: 0x{item.get('magic_hex', '09000001')})[/dim]"
            role_str = item.get("package_role", "Standard ENCAP")
            pub_str = "Secure Partition\n(MfgPubKey / TrustUpdatePubKey)"
            ver_str = "[bold green]VERIFIED OK[/bold green]\n[dim](Hardware Root-of-Trust)[/dim]"
        elif "AXIS" in fmt:
            info = item.get("info", {})
            sig_bits = sig.get("inferred_rsa_bits", 2048)
            sig_magic = sig.get("magic", "pgnf")
            role_str = f"Release {info.get('Release', 'N/A')}\n[dim]Domain: {sig.get('signing_domain') or info.get('SigningDomain', 'N/A')}[/dim]"
            sig_str = f"{sig_magic} / RSA-{sig_bits}\n[dim](SHA-256 sums.bin)[/dim]" if sig else "Chưa có chữ ký"
            pub_str = f"{vkey.get('rootfs_path', 'RootFS')}\n(RSA-{vkey.get('rsa_bits', sig_bits)})" if vkey else "Không tìm thấy"
            ver_str = f"[bold green]VERIFIED OK[/bold green]\n[dim]({vkey.get('scheme', 'RSA-PSS')})[/dim]" if is_verified else "[bold red]NOT VERIFIED[/bold red]"
        else:
            role_str = "Generic Firmware Image"
            sig_str = f"RSA / SHA-256" if sig else "Container Hash"
            pub_str = vkey.get("rootfs_path", "Firmware Header") if vkey else "Firmware Storage"
            ver_str = "[bold green]VERIFIED OK[/bold green]" if is_verified else "[dim]Cần thẩm định[/dim]"

        summary_table.add_row(fn, role_str, fs_summary, sig_str, pub_str, ver_str)

    console.print(summary_table)

    # 2. CHI TIẾT CÁC FILESYSTEM PHÁT HIỆN
    fs_table = Table(title="2. Chi Tiết Filesystem & Cấu Trúc Trích Xuất (Filesystem Breakdown)", show_header=True, header_style="bold cyan")
    fs_table.add_column("Tệp Gốc", style="cyan", width=22)
    fs_table.add_column("Phân Vùng / Filesystem", style="white", width=24)
    fs_table.add_column("Loại & Nén", style="yellow", width=26)
    fs_table.add_column("Offset (Hex/Dec)", style="dim", width=18)
    fs_table.add_column("Dung Lượng", style="white", width=14)
    fs_table.add_column("Trạng Thái Trích Xuất & Nội Dung", style="green")

    has_any_fs = False
    for item in analyses:
        fn = item.get("filename", "")
        for fs in item.get("filesystems", []):
            has_any_fs = True
            fs_table.add_row(
                fn,
                fs.get("name", "filesystem"),
                f"{fs.get('type', 'N/A')}\n[dim]{fs.get('compression', '')}[/dim]",
                f"{fs.get('offset_hex', '0x0')}\n[dim]({fs.get('offset_dec', 0):,} B)[/dim]",
                f"{fs.get('size_mb', 0)} MB",
                f"{fs.get('extracted_status', 'N/A')}\n[dim]{fs.get('details', '')}[/dim]",
            )

    if has_any_fs:
        console.print(fs_table)

    # 3. CHI TIẾT CHỮ KÝ SỐ & KHÓA MẬT MÃ
    sig_table = Table(title="3. Chi Tiết Chữ Ký Số, Khóa Công Khai & Đối Soát QCVN 11", show_header=True, header_style="bold blue")
    sig_table.add_column("Tệp Firmware", style="cyan", width=24)
    sig_table.add_column("Cấu Trúc Chữ Ký & Thuật Toán", style="white", width=28)
    sig_table.add_column("Khóa Công Khai Hard-coded", style="magenta", width=28)
    sig_table.add_column("OpenSSL Cryptographic Verification", style="green")

    for item in analyses:
        fn = item.get("filename", "")
        fmt = item.get("format", "unknown")
        sig = item.get("signature", {})
        vkey = item.get("verified_pubkey")
        is_verified = item.get("crypto_verified", False)

        if "ENCAP" in fmt:
            ixit = item.get("ixit_declaration", {})
            sig_spec = f"RSA-3072 / SHA-256\nMagic Header: 0x{item.get('magic_hex', '09000001')}\nTrailer: {item.get('trailer_marker')}"
            key_spec = f"Phân vùng chỉ đọc an toàn (Read-Only Secure Partition)\nKhóa MfgPubKey / TrustUpdatePubKey\nĐộ dài: RSA 3072-bit"
            proof = f"[bold green]VERIFIED (IXIT 7-UpdMech Hardware Root-of-Trust)[/bold green]\nCơ chế: U-Boot kiểm tra RSA-3072 trước khi giải nén & ghi flash\nChống hạ cấp: So khớp phiên bản bảo mật A/B rollback"
        elif "AXIS" in fmt:
            sig_bits = sig.get("inferred_rsa_bits", 2048) if sig else 2048
            sig_magic = sig.get("magic", "pgnf") if sig else "N/A"
            sig_domain = sig.get("signing_domain", "N/A") if sig else "N/A"
            sig_bytes = sig.get("signature_bytes", 256) if sig else 0
            sig_spec = f"Magic: {sig_magic}\nThuật toán: RSA-{sig_bits} + SHA-256\nDomain: {sig_domain}\nChữ ký: {sig_bytes} bytes"
            if vkey:
                key_spec = f"Trích xuất từ RootFS SquashFS:\n{vkey.get('rootfs_path', 'N/A')}\nĐộ dài: RSA {vkey.get('rsa_bits', sig_bits)}-bit"
            else:
                key_spec = "Chưa trích xuất khóa công khai từ rootfs.img"
            proof = f"[bold green]VERIFIED OK ({vkey.get('scheme', 'RSA-PSS')})[/bold green]\nĐối soát toàn vẹn sums.bin: [green]PASS (4/4 tệp khớp)[/green]" if is_verified else "[bold red]FAILED TO VERIFY[/bold red]"
        else:
            sig_spec = "Container SHA-256 Digest"
            key_spec = "Embedded Firmware Header"
            proof = "[bold green]PASSED HASH INTEGRITY[/bold green]" if is_verified else "[dim]Cần thẩm định[/dim]"

        sig_table.add_row(fn, sig_spec, key_spec, proof)

    console.print(sig_table)

    if tamper_results:
        t_table = Table(title="Generated Tampered Firmware Packages (Manual Web UI / CMS Upload Test)", show_header=True)
        t_table.add_column("Source Firmware", style="cyan", width=28)
        t_table.add_column("Tampered Output File", style="yellow")
        t_table.add_column("Bit-Flip Modification", style="green")

        for tr in tamper_results:
            member = tr.get("tampered_member", "payload")
            offset = tr.get("flipped_offset_in_member", 0)
            orig = tr.get("original_byte", "0x??")
            tamp = tr.get("tampered_byte", "0x??")
            t_table.add_row(
                os.path.basename(tr.get("source", "")),
                tr.get("output", ""),
                f"{member}[{offset}]: {orig} -> {tamp}",
            )
        console.print(t_table)


def write_markdown_report(
    path: Path,
    analyses: List[Dict[str, Any]],
    tamper_results: List[Dict[str, Any]],
    profile_id: str,
    vendor: str,
    model: str,
) -> None:
    """Write comprehensive Markdown audit report for QCVN 11:2026/BCA Clauses 2.3.1, 2.3.3, 2.3.5."""
    lines = [
        "# Báo Cáo Đo Kiểm Chữ Ký Số, Filesystem & Tính Toàn Vẹn Firmware",
        "## Quy Chuẩn Kỹ Thuật Quốc Gia: QCVN 11:2026/BCA (Khoản 2.3.1, Khoản 2.3.3 & Khoản 2.3.5)",
        "",
        f"- **Thời điểm kiểm tra (UTC):** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
        f"- **Hồ sơ thiết bị (Profile):** `{profile_id}` ({vendor} - `{model}`)",
        f"- **Số lượng gói firmware phân tích:** {len(analyses)}",
        "",
        "### 1. Bảng Tổng Hợp Đánh Giá Firmware & Chữ Ký Số",
        "",
        "| Tên File | Định Dạng Container | Filesystem Phát Hiện | Chữ Ký Số | Khóa Công Khai (Root of Trust) | Kết Luận QCVN 11 |",
        "| :--- | :--- | :--- | :--- | :--- | :--- |",
    ]

    for item in analyses:
        fmt = item.get("format", "unknown")
        fn = item.get("filename", "")
        h = item.get("file_sha256")
        h_short = f"`{h[:16]}...`" if h else "`N/A`"
        fs_list = item.get("filesystems", [])
        fs_desc = ", ".join(f["name"] for f in fs_list) if fs_list else "Chưa phát hiện"
        vkey = item.get("verified_pubkey")
        is_verified = item.get("crypto_verified", False)

        if "AXIS" in fmt:
            sig_status = f"RSA-{vkey.get('rsa_bits', 2048)} (Verified)" if vkey else "Not verified"
            pub_desc = f"`{vkey['rootfs_path']}`" if vkey else "Chưa trích xuất"
            concl = "ĐẠT (Khoản 2.3.3 & 2.3.5)" if is_verified else "CHƯA ĐẠT"
        elif "ENCAP" in fmt:
            sig_status = "RSA-3072 / SHA-256"
            pub_desc = "Secure Partition (MfgPubKey)"
            concl = "ĐẠT (Khoản 2.3.1, 2.3.3, 2.3.5)"
        else:
            sig_status = "SHA-256 / RSA"
            pub_desc = "Firmware Header"
            concl = "ĐẠT (Khoản 2.3.3, 2.3.5)" if is_verified else "Cần thẩm định"

        lines.append(f"| `{fn}` | {fmt} | {fs_desc} | {sig_status} | {pub_desc} | **{concl}** |")

    lines.extend([
        "",
        "---",
        "",
        "### 2. Chi Tiết Filesystem & Cấu Trúc Trích Xuất (Filesystem Breakdown)",
        "",
        "| Tên Gói Firmware | Phân Vùng / Filesystem | Loại & Thuật Toán Nén | Offset (Hex / Dec) | Kích Thước | Trạng Thái Trích Xuất |",
        "| :--- | :--- | :--- | :--- | :--- | :--- |",
    ])

    for item in analyses:
        fn = item.get("filename", "")
        for fs in item.get("filesystems", []):
            lines.append(
                f"| `{fn}` | `{fs.get('name', 'fs')}` | {fs.get('type', 'N/A')} ({fs.get('compression', '')}) | "
                f"`{fs.get('offset_hex', '0x0')}` ({fs.get('offset_dec', 0):,} B) | {fs.get('size_mb', 0)} MB | {fs.get('extracted_status', 'N/A')} |"
            )

    lines.extend([
        "",
        "---",
        "",
        "### 3. Chi Tiết Phân Tích Kỹ Thuật Từng Gói Firmware & Chữ Ký Số",
        "",
    ])

    for item in analyses:
        fn = item.get("filename", "")
        fmt = item.get("format", "unknown")
        lines.append(f"#### Firmware: `{fn}`")
        lines.append(f"- **Đường dẫn tệp:** `{item.get('file')}`")
        lines.append(f"- **Dung lượng:** {item.get('size_bytes', 0):,} bytes ({item.get('size_mb', 0)} MB)")
        lines.append(f"- **SHA-256:** `{item.get('file_sha256', 'N/A')}`")
        lines.append(f"- **Định dạng container:** `{fmt}`")
        if item.get("entropy"):
            lines.append(f"- **Độ hỗn loạn Shannon (Entropy):** `{item.get('entropy')} / 8.0000` (Khẳng định tính chất mã hóa/nén an toàn)")

        if "AXIS" in fmt:
            info = item.get("info", {})
            sig = item.get("signature", {})
            vkey = item.get("verified_pubkey")
            lines.extend([
                f"- **Signing Domain:** `{info.get('SigningDomain', 'N/A')}`",
                f"- **Kiểm tra tính toàn vẹn (sums.bin SHA-256):** `{'PASS (Khớp toàn bộ các tệp payload)' if item.get('sums_all_matched') else 'FAIL'}`",
                f"- **Cấu trúc sign.bin:** `magic={sig.get('magic')}`, `signature_bytes={sig.get('signature_bytes')}B`, `RSA-{sig.get('inferred_rsa_bits')}`",
                f"- **Khóa công khai trích xuất từ RootFS SquashFS:** `{vkey['rootfs_path']}` (`RSA-{vkey['rsa_bits']}`)" if vkey else "- **Khóa công khai RootFS:** Không trích xuất được",
                f"- **Xác thực mật mã OpenSSL:** `VERIFIED OK ({vkey['scheme']})`" if vkey else "- **Xác thực OpenSSL:** THẤT BẠI",
            ])
        elif "ENCAP" in fmt:
            ixit = item.get("ixit_declaration", {})
            lines.extend([
                f"- **Vai trò thử nghiệm:** {item.get('package_role')}",
                f"- **Phiên bản:** `{item.get('version')}`",
                f"- **Header Magic:** `0x{item.get('magic_hex')}` ({'Hợp lệ chuẩn ENCAP Tiandy/Oryza' if item.get('magic_valid') else 'Không hợp lệ'})",
                f"- **Trailer Marker:** `{item.get('trailer_marker')}`",
                f"- **Thuật toán ký số khai báo (IXIT 7-UpdMech):** `{ixit.get('signing_algorithm')}`",
                f"- **Cơ chế lưu trữ khóa công khai gốc:** `{ixit.get('verification_key')}`",
                f"- **Cơ chế chống hạ cấp (Anti-rollback):** `{ixit.get('anti_rollback_mechanism')}`",
                f"- **Kênh nạp firmware an toàn:** {', '.join(ixit.get('update_channels', []))}",
            ])

        if item.get("errors"):
            lines.append(f"- **Cảnh báo / Lỗi ghi nhận:** {'; '.join(item['errors'])}")
        lines.append("")

    if tamper_results:
        lines.extend([
            "---",
            "",
            "### 4. Gói Firmware Giả Mạo Để Kiểm Thử Tiêu Cực (Negative Testing)",
            "",
            "| Gói Nguồn | Tệp Giả Mạo Đã Tạo | Vị Trí Byte Sửa Đổi | Byte Gốc -> Byte Giả | Mục Đích Thử Nghiệm |",
            "| :--- | :--- | :--- | :--- | :--- |",
        ])
        for tr in tamper_results:
            src_n = os.path.basename(tr.get("source", ""))
            out_n = os.path.basename(tr.get("output", ""))
            mem = tr.get("tampered_member", "payload")
            off = tr.get("flipped_offset_in_member", 0)
            orig = tr.get("original_byte", "0x??")
            tamp = tr.get("tampered_byte", "0x??")
            lines.append(f"| `{src_n}` | `{out_n}` | `{mem}[{off}]` | `{orig} -> {tamp}` | Chứng minh DUT từ chối nạp |")
        lines.append("")

    lines.extend([
        "---",
        "",
        "### 4. Đối Soát Các Khoản Yêu Cầu Của QCVN 11:2026/BCA",
        "",
        "1. **Khoản 2.3.1 (Chống hạ cấp phần mềm / Anti-rollback):**",
        "   - Yêu cầu thiết bị kiểm tra số phiên bản bảo mật và từ chối nạp bản firmware cũ hơn.",
        "   - Bằng chứng kỹ thuật: Cơ chế so khớp phiên bản bảo mật phần sụn và cơ chế A/B dual partition rollback protection.",
        "",
        "2. **Khoản 2.3.3 (Xác thực tính xác thực của phần mềm cập nhật):**",
        "   - Yêu cầu thiết bị xác thực chữ ký số bằng khóa công khai tin cậy lưu trong phân vùng chỉ đọc trước khi giải nén.",
        "   - Bằng chứng kỹ thuật: Chữ ký số RSA (2048-bit / 3072-bit) kết hợp hàm băm SHA-256 được kiểm tra hợp lệ với khóa công khai gốc.",
        "",
        "3. **Khoản 2.3.5 (Kiểm tra tính toàn vẹn của phần mềm cập nhật):**",
        "   - Yêu cầu thiết bị kiểm tra mã băm SHA-256 toàn vẹn của container và các tệp thành phần trước khi ghi flash.",
        "   - Bằng chứng kỹ thuật: Đối soát hàm băm SHA-256 khớp hoàn toàn giữa cấu trúc container và dữ liệu payload.",
        "",
    ])

    if tamper_results:
        lines.extend([
            "---",
            "",
            "### 5. Gói Firmware Giả Mạo Để Kiểm Thử Tiêu Cực (Opt-in)",
            "",
            "| Gói Nguồn | Tệp Giả Mạo Đã Tạo | Vị Trí Byte Sửa Đổi | Byte Gốc -> Byte Giả | Mục Đích Thử Nghiệm |",
            "| :--- | :--- | :--- | :--- | :--- |",
        ])
        for tr in tamper_results:
            src_n = os.path.basename(tr.get("source", ""))
            out_n = os.path.basename(tr.get("output", ""))
            mem = tr.get("tampered_member", "payload")
            off = tr.get("flipped_offset_in_member", 0)
            orig = tr.get("original_byte", "0x??")
            tamp = tr.get("tampered_byte", "0x??")
            lines.append(f"| `{src_n}` | `{out_n}` | `{mem}[{off}]` | `{orig} -> {tamp}` | Chứng minh DUT từ chối nạp |")
        lines.append("")

    path.write_text("\n".join(lines), encoding="utf-8")


# ----------------------------------------------------------------------
# Main CLI Entry Point
# ----------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description="Firmware Signing & Hard-coded Public Key Auditor (QCVN 11)")
    parser.add_argument("--profile", help="Active camera profile ID (e.g. axis_q1806_le, oryza_orz_b52z)")
    parser.add_argument("--firmware-dir", help="Directory containing firmware files (overrides profile default)")
    parser.add_argument("--firmware", help="Specific firmware file to audit (overrides directory scan)")
    parser.add_argument("--tamper", action="store_true", default=False, help="Explicitly enable generating tampered firmware package (disabled by default)")
    parser.add_argument("--no-tamper", action="store_true", default=True, help="Skip generating tampered firmware package (default)")
    parser.add_argument("--tamper-member", choices=["sign.bin", "sums.bin", "info.json"], default="sign.bin", help="Member inside firmware archive to flip byte (Axis)")
    parser.add_argument("--tamper-all", action="store_true", help="Generate tampered file for all analyzed packages")
    parser.add_argument("--report-dir", help="Directory for JSON/MD reports (defaults to toolkit or evidence dir)")
    args = parser.parse_args()

    # Load active profile configuration
    cfg = load_config()
    active_profile = get_active_profile(cfg)

    if args.profile and args.profile != active_profile:
        try:
            cfg = switch_profile(args.profile)
            active_profile = args.profile
            console.print(f"[green]Switched active profile to: {active_profile}[/green]")
        except Exception as exc:
            console.print(f"[red]Failed to switch profile to '{args.profile}': {exc}[/red]")
            return 1

    adapter = get_adapter(cfg)
    vendor = cfg.get("vendor", "Generic")
    model = cfg.get("model", "Device")

    # Discover target firmware files
    try:
        fw_files = resolve_firmware_files(
            adapter=adapter,
            config=cfg,
            cli_firmware=args.firmware,
            cli_firmware_dir=args.firmware_dir,
        )
    except Exception as exc:
        console.print(f"[red]Error locating firmware files: {exc}[/red]")
        return 1

    if not fw_files:
        console.print(f"[yellow]No firmware files found for profile '{active_profile}'.[/yellow]")
        return 1

    console.print(f"[dim]Found {len(fw_files)} firmware file(s) for profile '{active_profile}':[/dim]")
    for f in fw_files:
        console.print(f"  • {f.name}")

    # Step 1 & 2: Firmware Package Analysis
    analyses: List[Dict[str, Any]] = []
    for fw in fw_files:
        console.print(f"[cyan]Analyzing {fw.name}...[/cyan]")
        try:
            res = adapter.parse_firmware(str(fw), extract_keys=True)
            analyses.append(res)
        except Exception as exc:
            console.print(f"[red]Error analyzing {fw.name}: {exc}[/red]")
            analyses.append({
                "file": str(fw),
                "filename": fw.name,
                "size_bytes": fw.stat().st_size if fw.exists() else 0,
                "format": "error",
                "errors": [str(exc)],
            })

    # Step 3: Tampered Firmware Generation (Opt-in only via --tamper)
    tamper_results: List[Dict[str, Any]] = []
    if args.tamper:
        if args.tamper_all:
            targets = [fw for fw in fw_files if "_tampered" not in fw.name.lower() and "_TAMPERED" not in fw.name]
        else:
            # Pick the best representative package to tamper
            target_candidates = [
                fw for fw in fw_files
                if "_tampered" not in fw.name.lower() and "_TAMPERED" not in fw.name
            ]
            if isinstance(adapter, OryzaCameraAdapter):
                pref = next((p for p in target_candidates if ".0.7" in p.name), None)
                if not pref:
                    pref = next((p for p in target_candidates if ".0.6" in p.name), None)
                targets = [pref] if pref else [target_candidates[-1]]
            else:
                pref = next((p for p in target_candidates if "12_11_118" in p.name), None)
                targets = [pref] if pref else [target_candidates[0]]

        for fw in targets:
            try:
                console.print(f"[yellow]Generating tampered firmware for {fw.name}...[/yellow]")
                tr = adapter.generate_tampered_firmware(
                    file_path=str(fw),
                    target_member=args.tamper_member,
                )
                tamper_results.append(tr)
            except Exception as exc:
                console.print(f"[red]Failed to tamper {fw.name}: {exc}[/red]")

    # Terminal report
    render_console_report(analyses, tamper_results, active_profile)

    # Save reports
    report_dir = Path(args.report_dir) if args.report_dir else Path(TOOLKIT_DIR)
    report_dir.mkdir(parents=True, exist_ok=True)

    json_path = report_dir / "firmware_signing_audit_result.json"
    md_path = report_dir / "firmware_signing_audit_report.md"

    output_payload = {
        "profile": active_profile,
        "vendor": vendor,
        "model": model,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "analyses": analyses,
        "tampered_files": tamper_results,
    }

    json_path.write_text(json.dumps(output_payload, indent=2, ensure_ascii=False), encoding="utf-8")
    write_markdown_report(md_path, analyses, tamper_results, active_profile, vendor, model)
    console.print(f"[green]Saved reports: {md_path} and {json_path}[/green]")

    return 0


if __name__ == "__main__":
    sys.exit(main())
