#!/usr/bin/env python3
"""
Firmware Signing & Hard-coded Public Key Auditor (QCVN 11 / Secure Update)
Performs:
  1. Static analysis of firmware packages (.bin) for hash & signature metadata.
  2. Extraction of hard-coded RSA public keys from rootfs.img (SquashFS) and
     cryptographic verification of the firmware signature using OpenSSL.
  3. Generation of a 1-byte tampered .bin package (valid tar.gz container)
     for manual negative testing via the device Web UI.
"""

import argparse
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()

DEFAULT_FIRMWARE_DIR = "/home/merlin/PSI/AXIS Q1806-LE/Firmware"
SIGN_HEADER_MAGIC = b"pgnf"
SIGN_HEADER_LEN = 72
SUMS_RECORD_LEN = 64
SUMS_NAME_LEN = 32
SHA256_DIGEST_LEN = 32


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

    # Prioritize exact signing domain match (e.g. axis-release-artpec-8-firmware.public.pem)
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
    """Analyze a single .bin firmware package (Step 1 + Step 2)."""
    result: Dict[str, Any] = {
        "file": str(fw_path),
        "filename": fw_path.name,
        "size_bytes": fw_path.stat().st_size,
        "file_sha256": hashlib.sha256(fw_path.read_bytes()).hexdigest() if fw_path.stat().st_size < 1024 else None,
        "format": "unknown",
        "extracted_dir": None,
        "info": {},
        "sums": [],
        "sums_all_matched": False,
        "signature": {},
        "rootfs_keys": [],
        "verified_pubkey": None,
        "crypto_verified": False,
        "errors": [],
    }

    if not tarfile.is_tarfile(str(fw_path)):
        # Handle gzip-wrapped tarfile check via tarfile.open
        try:
            with tarfile.open(fw_path, "r:gz") as tf:
                tf.getmembers()
        except Exception as exc:
            result["errors"].append(f"Not a valid tar.gz firmware archive: {exc}")
            return result

    result["format"] = "AXIS tar.gz fimage"
    persist_dir: Optional[Path] = None
    if save_extracted:
        persist_dir = fw_path.parent / f"extracted_{fw_path.stem}"
        persist_dir.mkdir(parents=True, exist_ok=True)
        result["extracted_dir"] = str(persist_dir)

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        actual_hashes: Dict[str, str] = {}
        rootfs_extracted: Optional[Path] = None

        with tarfile.open(fw_path, "r:gz") as tf:
            members = tf.getmembers()
            result["members"] = [{"name": m.name, "size": m.size} for m in members]

            for m in members:
                if not m.isfile():
                    continue
                fobj = tf.extractfile(m)
                if fobj is None:
                    continue
                if m.name in ("fwinfo.bin", "info.json", "boot.img", "rootfs.img"):
                    if m.name == "rootfs.img" and extract_keys:
                        rootfs_path = tmp / "rootfs.img"
                        h = hashlib.sha256()
                        with open(rootfs_path, "wb") as out_f:
                            while True:
                                buf = fobj.read(1024 * 1024)
                                if not buf:
                                    break
                                h.update(buf)
                                out_f.write(buf)
                        actual_hashes[m.name] = h.hexdigest()
                        rootfs_extracted = rootfs_path
                    else:
                        data = fobj.read()
                        actual_hashes[m.name] = hashlib.sha256(data).hexdigest()
                        if persist_dir and m.name in ("fwinfo.bin", "info.json"):
                            (persist_dir / m.name).write_bytes(data)
                        if m.name == "info.json":
                            try:
                                result["info"] = json.loads(data.decode("utf-8"))
                            except Exception as exc:
                                result["errors"].append(f"Failed to parse info.json: {exc}")
                elif m.name in ("sums.bin", "sign.bin"):
                    raw_meta = fobj.read()
                    (tmp / m.name).write_bytes(raw_meta)
                    if persist_dir:
                        (persist_dir / m.name).write_bytes(raw_meta)

        sums_path = tmp / "sums.bin"
        sign_path = tmp / "sign.bin"

        if sums_path.exists():
            records = parse_sums_bin(sums_path.read_bytes())
            for rec in records:
                actual = actual_hashes.get(rec["name"])
                rec["actual_sha256"] = actual
                rec["matched"] = actual == rec["expected_sha256"]
            result["sums"] = records
            result["sums_all_matched"] = bool(records) and all(r["matched"] for r in records)
        else:
            result["errors"].append("sums.bin missing from firmware archive")

        if sign_path.exists():
            sig_info = parse_sign_bin(sign_path.read_bytes())
            sig_raw = sig_info.pop("signature_raw", b"")
            result["signature"] = sig_info
            sig_raw_path = tmp / "sig.raw"
            sig_raw_path.write_bytes(sig_raw)
        else:
            result["errors"].append("sign.bin missing from firmware archive")
            sig_raw_path = None

        # Step 2: Inspect rootfs.img for hard-coded public key & verify signature
        if extract_keys and rootfs_extracted and rootfs_extracted.exists():
            magic = rootfs_extracted.read_bytes()[:4] if rootfs_extracted.stat().st_size >= 4 else b""
            # Read only first 4 bytes efficiently
            with open(rootfs_extracted, "rb") as rf:
                magic = rf.read(4)
            if magic != b"hsqs":
                result["errors"].append(f"rootfs.img is not unencrypted SquashFS (magic={magic.hex()})")
            else:
                domain = result["signature"].get("signing_domain") or result["info"].get("SigningDomain", "")
                candidates = find_candidate_pubkeys_in_squashfs(str(rootfs_extracted), domain)
                if candidates:
                    sq_out = (persist_dir / "rootfs_keys") if persist_dir else (tmp / "sq_keys")
                    subprocess.run(
                        ["unsquashfs", "-f", "-d", str(sq_out), str(rootfs_extracted), *candidates],
                        capture_output=True,
                    )
                    for rel in candidates:
                        pem_file = sq_out / rel
                        if not pem_file.exists():
                            continue
                        key_meta = inspect_rsa_pubkey_pem(str(pem_file))
                        entry: Dict[str, Any] = {
                            "rootfs_path": "/" + rel,
                            "rsa_bits": key_meta.get("bits"),
                            "valid_rsa_pub": key_meta.get("ok", False),
                            "verified_signature": False,
                            "scheme": None,
                        }
                        if key_meta.get("ok") and sig_raw_path and sums_path.exists():
                            ver = verify_signature_openssl(str(pem_file), str(sig_raw_path), str(sums_path))
                            entry["verified_signature"] = ver["verified"]
                            entry["scheme"] = ver["scheme"]
                            if ver["verified"] and not result["crypto_verified"]:
                                result["crypto_verified"] = True
                                result["verified_pubkey"] = entry
                        result["rootfs_keys"].append(entry)

    return result


def create_tampered_firmware(
    src_fw: Path,
    out_fw: Path,
    target_member: str = "sign.bin",
) -> Dict[str, Any]:
    """
    Create a valid .tar.gz copy of src_fw with exactly 1 byte flipped inside
    target_member (default: sign.bin signature payload) so the device extracts
    the archive cleanly and rejects it at signature verification.
    """
    if target_member not in ("sign.bin", "sums.bin", "info.json"):
        raise ValueError(f"Unsupported tamper target: {target_member}")

    modified_info: Dict[str, Any] = {
        "source": str(src_fw),
        "output": str(out_fw),
        "tampered_member": target_member,
    }

    with tarfile.open(src_fw, "r:gz") as src_tf, tarfile.open(out_fw, "w:gz") as dst_tf:
        for member in src_tf.getmembers():
            if not member.isfile():
                dst_tf.addfile(member)
                continue

            fobj = src_tf.extractfile(member)
            if fobj is None:
                continue

            if member.name != target_member:
                dst_tf.addfile(member, fobj)
                continue

            raw = bytearray(fobj.read())
            if target_member == "sign.bin":
                flip_idx = SIGN_HEADER_LEN + (len(raw) - SIGN_HEADER_LEN) // 2
            elif target_member == "sums.bin":
                flip_idx = SUMS_NAME_LEN
            else:
                flip_idx = max(0, len(raw) - 2)

            orig_byte = raw[flip_idx]
            new_byte = orig_byte ^ 0x01
            raw[flip_idx] = new_byte

            new_member = tarfile.TarInfo(name=member.name)
            new_member.size = len(raw)
            new_member.mode = member.mode
            new_member.mtime = member.mtime
            new_member.uid = member.uid
            new_member.gid = member.gid
            new_member.uname = member.uname
            new_member.gname = member.gname
            dst_tf.addfile(new_member, io.BytesIO(bytes(raw)))

            modified_info.update(
                {
                    "flipped_offset_in_member": flip_idx,
                    "original_byte": f"0x{orig_byte:02x}",
                    "tampered_byte": f"0x{new_byte:02x}",
                }
            )

    modified_info["output_size_bytes"] = out_fw.stat().st_size
    return modified_info


def render_console_report(analyses: List[Dict[str, Any]], tamper_results: List[Dict[str, Any]]) -> None:
    """Print structured Rich summary to terminal."""
    console.print(Panel.fit("[bold cyan]Firmware Signing & Hard-coded Public Key Auditor[/bold cyan]", border_style="cyan"))

    for item in analyses:
        info = item.get("info", {})
        sig = item.get("signature", {})
        vkey = item.get("verified_pubkey")

        table = Table(title=f"Firmware: {item['filename']}", show_header=True, header_style="bold magenta")
        table.add_column("Check", style="cyan", width=30)
        table.add_column("Result", style="white")

        table.add_row("Format", item.get("format", "unknown"))
        if info:
            table.add_row("Release / SigningDomain", f"{info.get('Release', '?')} / {info.get('SigningDomain', '?')}")
        table.add_row(
            "sums.bin (SHA-256)",
            "[green]PASS (all 4 files match)[/green]" if item.get("sums_all_matched") else "[red]FAIL / Missing[/red]",
        )
        if sig:
            rsa_bits = sig.get("inferred_rsa_bits")
            table.add_row(
                "sign.bin Metadata",
                f"magic={sig.get('magic')} | domain={sig.get('signing_domain')} | sig={sig.get('signature_bytes')}B (RSA-{rsa_bits})",
            )
        if vkey:
            table.add_row(
                "Hard-coded PubKey (rootfs)",
                f"[green]{vkey['rootfs_path']} (RSA-{vkey['rsa_bits']})[/green]",
            )
            table.add_row(
                "Cryptographic Verify",
                f"[bold green]VERIFIED OK ({vkey['scheme']})[/bold green]",
            )
        else:
            table.add_row("Cryptographic Verify", "[red]NOT VERIFIED[/red]")

        if item.get("errors"):
            table.add_row("Errors", "[red]" + "; ".join(item["errors"]) + "[/red]")

        console.print(table)

    if tamper_results:
        t_table = Table(title="Generated 1-Byte Tampered Firmware (For Manual Web UI Upload)", show_header=True)
        t_table.add_column("Source", style="cyan")
        t_table.add_column("Tampered Output", style="yellow")
        t_table.add_column("Modified Byte", style="green")
        for tr in tamper_results:
            t_table.add_row(
                os.path.basename(tr["source"]),
                tr["output"],
                f"{tr['tampered_member']}[{tr['flipped_offset_in_member']}]: {tr['original_byte']} -> {tr['tampered_byte']}",
            )
        console.print(t_table)


def write_markdown_report(path: Path, analyses: List[Dict[str, Any]], tamper_results: List[Dict[str, Any]]) -> None:
    """Write Markdown audit report."""
    lines = [
        "# Firmware Signing & Hard-coded Public Key Audit Report",
        "",
        f"- **Generated (UTC):** {datetime.now(timezone.utc).isoformat()}",
        "",
    ]
    for item in analyses:
        info = item.get("info", {})
        sig = item.get("signature", {})
        vkey = item.get("verified_pubkey")
        lines.extend(
            [
                f"## {item['filename']}",
                f"- **Release:** `{info.get('Release', 'N/A')}`",
                f"- **SigningDomain:** `{info.get('SigningDomain', 'N/A')}`",
                f"- **sums.bin SHA-256 Integrity:** `{'PASS' if item.get('sums_all_matched') else 'FAIL'}`",
                f"- **sign.bin:** `magic={sig.get('magic')}`, `sig_bytes={sig.get('signature_bytes')}`, `RSA-{sig.get('inferred_rsa_bits')}`",
                f"- **Hard-coded Public Key:** `{vkey['rootfs_path']}` (`RSA-{vkey['rsa_bits']}`)" if vkey else "- **Hard-coded Public Key:** Not verified",
                f"- **OpenSSL Verify:** `VERIFIED OK ({vkey['scheme']})`" if vkey else "- **OpenSSL Verify:** FAILED",
                "",
            ]
        )
    if tamper_results:
        lines.append("## Tampered Firmware Files (Manual Web UI Test)")
        for tr in tamper_results:
            lines.append(
                f"- `{tr['output']}` — flipped 1 byte in `{tr['tampered_member']}` "
                f"at offset `{tr['flipped_offset_in_member']}` (`{tr['original_byte']}` -> `{tr['tampered_byte']}`)"
            )
        lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Firmware Signing & Hard-coded Public Key Auditor")
    parser.add_argument("--firmware-dir", default=DEFAULT_FIRMWARE_DIR, help="Directory containing .bin firmware files")
    parser.add_argument("--firmware", help="Specific .bin firmware file to audit (overrides --firmware-dir scan)")
    parser.add_argument("--no-tamper", action="store_true", help="Skip generating 1-byte tampered .bin file")
    parser.add_argument("--tamper-member", choices=["sign.bin", "sums.bin", "info.json"], default="sign.bin", help="Member inside firmware to flip 1 byte")
    parser.add_argument("--tamper-all", action="store_true", help="Generate tampered file for every analyzed firmware (default: only newest/first)")
    parser.add_argument("--report-dir", default=os.path.dirname(os.path.abspath(__file__)), help="Directory for JSON/MD reports")
    args = parser.parse_args()

    if args.firmware:
        fw_files = [Path(args.firmware)]
    else:
        fw_dir = Path(args.firmware_dir)
        if not fw_dir.is_dir():
            console.print(f"[red]Firmware directory not found: {fw_dir}[/red]")
            return 1
        fw_files = sorted(
            p for p in fw_dir.glob("*.bin")
            if "_TAMPERED_1BYTE" not in p.name
        )

    if not fw_files:
        console.print("[yellow]No firmware .bin files found.[/yellow]")
        return 1

    analyses: List[Dict[str, Any]] = []
    for fw in fw_files:
        console.print(f"[cyan]Analyzing {fw.name}...[/cyan]")
        analyses.append(analyze_firmware_package(fw, extract_keys=True))

    tamper_results: List[Dict[str, Any]] = []
    if not args.no_tamper:
        targets = fw_files if args.tamper_all else [fw_files[-1]]
        for fw in targets:
            out_fw = fw.with_name(f"{fw.stem}_TAMPERED_1BYTE.bin")
            console.print(f"[yellow]Generating 1-byte tampered firmware: {out_fw.name}...[/yellow]")
            tamper_results.append(create_tampered_firmware(fw, out_fw, target_member=args.tamper_member))

    render_console_report(analyses, tamper_results)

    report_dir = Path(args.report_dir)
    json_path = report_dir / "firmware_signing_audit_result.json"
    md_path = report_dir / "firmware_signing_audit_report.md"
    json_path.write_text(json.dumps({"analyses": analyses, "tampered_files": tamper_results}, indent=2), encoding="utf-8")
    write_markdown_report(md_path, analyses, tamper_results)
    console.print(f"[green]Saved reports: {md_path} and {json_path}[/green]")
    return 0


if __name__ == "__main__":
    sys.exit(main())
