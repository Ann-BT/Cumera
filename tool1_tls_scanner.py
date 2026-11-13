#!/usr/bin/env python3
"""
Universal TLS & Cipher Suite Security Auditor (SOGIS ACM / QCVN 11 Compliant)
Author: Merlin / Antigravity
Exhaustively audits TLS versions, enumerates all supported Cipher Suites,
extracts and inspects X.509 Server Certificates, and classifies security under SOGIS.
Works with ANY IP Camera / Port without vendor assumptions.
"""

import subprocess
import re
import json
import os
import sys
import socket
import ssl
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pcap_recorder import start_pcap_capture, stop_pcap_capture, display_wireshark_panel

console = Console()

# SOGIS Agreed Cryptographic Mechanisms (ACM) Classification:
# 'R'  : Recommended (Modern ciphers with AEAD and Forward Secrecy)
# 'L'  : Legacy (Acceptable under restricted/transitional conditions)
# 'NR' : Not Recommended (Lacks PFS, weak keys, or CBC padding vulnerabilities)
# 'F'  : Forbidden (RC4, 3DES, DES, NULL, MD5)

SOGIS_R_CIPHERS = {
    # TLS 1.3
    "TLS_AES_128_GCM_SHA256": {"version": "TLSv1.3", "kex": "ECDHE/DHE", "enc": "AES-128-GCM", "mac": "AEAD"},
    "TLS_AES_256_GCM_SHA384": {"version": "TLSv1.3", "kex": "ECDHE/DHE", "enc": "AES-256-GCM", "mac": "AEAD"},
    "TLS_CHACHA20_POLY1305_SHA256": {"version": "TLSv1.3", "kex": "ECDHE/DHE", "enc": "CHACHA20-POLY1305", "mac": "AEAD"},
    # TLS 1.2 ECDHE with AEAD
    "ECDHE-ECDSA-AES128-GCM-SHA256": {"version": "TLSv1.2", "kex": "ECDHE", "enc": "AES-128-GCM", "mac": "AEAD"},
    "ECDHE-ECDSA-AES256-GCM-SHA384": {"version": "TLSv1.2", "kex": "ECDHE", "enc": "AES-256-GCM", "mac": "AEAD"},
    "ECDHE-RSA-AES128-GCM-SHA256": {"version": "TLSv1.2", "kex": "ECDHE", "enc": "AES-128-GCM", "mac": "AEAD"},
    "ECDHE-RSA-AES256-GCM-SHA384": {"version": "TLSv1.2", "kex": "ECDHE", "enc": "AES-256-GCM", "mac": "AEAD"},
    "ECDHE-RSA-CHACHA20-POLY1305": {"version": "TLSv1.2", "kex": "ECDHE", "enc": "CHACHA20-POLY1305", "mac": "AEAD"},
    "ECDHE-ECDSA-CHACHA20-POLY1305": {"version": "TLSv1.2", "kex": "ECDHE", "enc": "CHACHA20-POLY1305", "mac": "AEAD"},
}

SOGIS_LEGACY_CIPHERS = {
    "DHE-RSA-AES128-GCM-SHA256": {"version": "TLSv1.2", "kex": "DHE", "enc": "AES-128-GCM", "mac": "AEAD"},
    "DHE-RSA-AES256-GCM-SHA384": {"version": "TLSv1.2", "kex": "DHE", "enc": "AES-256-GCM", "mac": "AEAD"},
    "ECDHE-ECDSA-AES128-SHA256": {"version": "TLSv1.2", "kex": "ECDHE", "enc": "AES-128-CBC", "mac": "SHA256"},
    "ECDHE-ECDSA-AES256-SHA384": {"version": "TLSv1.2", "kex": "ECDHE", "enc": "AES-256-CBC", "mac": "SHA384"},
    "ECDHE-RSA-AES128-SHA256": {"version": "TLSv1.2", "kex": "ECDHE", "enc": "AES-128-CBC", "mac": "SHA256"},
    "ECDHE-RSA-AES256-SHA384": {"version": "TLSv1.2", "kex": "ECDHE", "enc": "AES-256-CBC", "mac": "SHA384"},
    "DHE-RSA-AES128-SHA256": {"version": "TLSv1.2", "kex": "DHE", "enc": "AES-128-CBC", "mac": "SHA256"},
    "DHE-RSA-AES256-SHA256": {"version": "TLSv1.2", "kex": "DHE", "enc": "AES-256-CBC", "mac": "SHA256"},
    "TLS_AES_128_CCM_SHA256": {"version": "TLSv1.3", "kex": "ECDHE/DHE", "enc": "AES-128-CCM", "mac": "AEAD"},
}

def extract_certificate_info(host: str, port: int) -> Optional[Dict[str, Any]]:
    """Extracts and parses the remote X.509 certificate."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=3) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert_der = ssock.getpeercert(binary_form=True)
                if not cert_der:
                    return None
                
                from cryptography import x509
                from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
                
                cert = x509.load_der_x509_certificate(cert_der)
                
                # Subject / Issuer
                subj_parts = [f"{attr.oid._name}={attr.value}" for attr in cert.subject]
                issuer_parts = [f"{attr.oid._name}={attr.value}" for attr in cert.issuer]
                
                # Public key
                pk = cert.public_key()
                if isinstance(pk, rsa.RSAPublicKey):
                    pk_info = f"RSA {pk.key_size} bits"
                    pk_type = "RSA"
                    pk_size = pk.key_size
                elif isinstance(pk, ec.EllipticCurvePublicKey):
                    pk_info = f"ECC {pk.curve.name} ({pk.key_size} bits)"
                    pk_type = f"ECC ({pk.curve.name})"
                    pk_size = pk.key_size
                elif isinstance(pk, dsa.DSAPublicKey):
                    pk_info = f"DSA {pk.key_size} bits"
                    pk_type = "DSA"
                    pk_size = pk.key_size
                else:
                    pk_info = str(type(pk).__name__)
                    pk_type = "Unknown"
                    pk_size = 0

                sig_alg = cert.signature_algorithm_oid._name
                nb = cert.not_valid_before_utc
                na = cert.not_valid_after_utc
                now = datetime.now(timezone.utc)
                is_expired = now > na
                is_valid = nb <= now <= na

                return {
                    "subject": ", ".join(subj_parts),
                    "issuer": ", ".join(issuer_parts),
                    "public_key": pk_info,
                    "public_key_type": pk_type,
                    "key_size": pk_size,
                    "signature_algorithm": sig_alg,
                    "not_before": nb.strftime("%Y-%m-%d %H:%M:%S UTC"),
                    "not_after": na.strftime("%Y-%m-%d %H:%M:%S UTC"),
                    "status": "HỢP LỆ (Còn hạn)" if is_valid else ("HẾT HẠN (Expired)" if is_expired else "CHƯA HIỆU LỰC")
                }
    except Exception:
        return None

def test_openssl_cipher(host: str, port: int, cipher: str, tls_flag: str = "") -> bool:
    cmd = ["openssl", "s_client", "-connect", f"{host}:{port}"]
    if tls_flag:
        cmd.append(tls_flag)
    cmd.extend(["-cipher", cipher])
    try:
        proc = subprocess.run(
            cmd,
            input=b"",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=2.0
        )
        out = proc.stdout.decode('utf-8', errors='ignore')
        if f"Cipher is {cipher}" in out or f"Cipher    : {cipher}" in out:
            return True
    except Exception:
        pass
    return False

def test_tls13_ciphersuites(host: str, port: int, ciphersuite: str) -> bool:
    cmd = ["openssl", "s_client", "-connect", f"{host}:{port}", "-tls1_3", "-ciphersuites", ciphersuite]
    try:
        proc = subprocess.run(
            cmd,
            input=b"",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=2.0
        )
        out = proc.stdout.decode('utf-8', errors='ignore')
        if f"Cipher is {ciphersuite}" in out or f"Cipher    : {ciphersuite}" in out:
            return True
    except Exception:
        pass
    return False

def test_protocol_support(host: str, port: int, proto_flag: str) -> bool:
    cmd = ["openssl", "s_client", "-connect", f"{host}:{port}", proto_flag]
    try:
        proc = subprocess.run(
            cmd,
            input=b"",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=2.0
        )
        out = proc.stdout.decode('utf-8', errors='ignore')
        return "CONNECTED(" in out and "Cipher is" in out and "Cipher is (NONE)" not in out
    except Exception:
        return False

def audit_tls_endpoint(host: str, port: int) -> Dict[str, Any]:
    """Exhaustively scans protocols, ciphers, and cert on a TLS port."""
    pcap_proc, pcap_file = start_pcap_capture(host, f"tcp port {port}", prefix=f"tls_audit_{port}")
    results = {
        "host": host,
        "port": port,
        "protocols": {},
        "ciphers": [],
        "certificate": None,
        "is_tls_open": False,
        "pcap_file": pcap_file
    }

    try:
        # 1. Check protocol versions
        protocols = [
            ("SSLv3", "-ssl3"),
            ("TLSv1.0", "-tls1"),
            ("TLSv1.1", "-tls1_1"),
            ("TLSv1.2", "-tls1_2"),
            ("TLSv1.3", "-tls1_3"),
        ]
        for name, flag in protocols:
            supported = test_protocol_support(host, port, flag)
            results["protocols"][name] = supported
            if supported:
                results["is_tls_open"] = True

        if not results["is_tls_open"]:
            return results

        # 2. Extract certificate
        results["certificate"] = extract_certificate_info(host, port)

        # 3. Test TLS 1.3 Ciphersuites
        tls13_candidates = [
            "TLS_AES_128_GCM_SHA256",
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256",
            "TLS_AES_128_CCM_SHA256",
            "TLS_AES_128_CCM_8_SHA256"
        ]
        if results["protocols"].get("TLSv1.3"):
            for c in tls13_candidates:
                if test_tls13_ciphersuites(host, port, c):
                    sogis = "R" if c in SOGIS_R_CIPHERS else ("L" if c in SOGIS_LEGACY_CIPHERS else "NR")
                    meta = SOGIS_R_CIPHERS.get(c, SOGIS_LEGACY_CIPHERS.get(c, {}))
                    results["ciphers"].append({
                        "name": c,
                        "protocol": "TLSv1.3",
                        "sogis": sogis,
                        "kex": meta.get("kex", "ECDHE/DHE"),
                        "enc": meta.get("enc", "AES-CCM" if "CCM" in c else "Unknown"),
                        "mac": meta.get("mac", "AEAD")
                    })

        # 4. Test TLS 1.2 Ciphers
        if results["protocols"].get("TLSv1.2"):
            p = subprocess.run(["openssl", "ciphers", "-v", "ALL:COMPLEMENTOFALL:@SECLEVEL=0"], stdout=subprocess.PIPE, text=True)
            lines = p.stdout.strip().split("\n")
            cipher_names = [l.split()[0] for l in lines if "TLSv1.2" in l or "SSLv3" in l]
            seen = set()
            unique_ciphers = [x for x in cipher_names if not (x in seen or seen.add(x))]

            for c in unique_ciphers:
                if test_openssl_cipher(host, port, c, "-tls1_2"):
                    sogis = "R" if c in SOGIS_R_CIPHERS else ("L" if c in SOGIS_LEGACY_CIPHERS else "NR")
                    if "RC4" in c or "3DES" in c or "DES" in c or "MD5" in c or "NULL" in c:
                        sogis = "F"
                    meta = SOGIS_R_CIPHERS.get(c, SOGIS_LEGACY_CIPHERS.get(c, {}))
                    results["ciphers"].append({
                        "name": c,
                        "protocol": "TLSv1.2",
                        "sogis": sogis,
                        "kex": meta.get("kex", c.split("-")[0] if "-" in c else "RSA"),
                        "enc": meta.get("enc", "CBC/GCM"),
                        "mac": meta.get("mac", "SHA1/SHA256" if "SHA" in c else "AEAD")
                    })

        # 5. Capture raw OpenSSL command output for verbatim evidence
        cmd_tls = ["openssl", "s_client", "-connect", f"{host}:{port}"]
        if results["protocols"].get("TLSv1.3"):
            cmd_tls.append("-tls1_3")
        elif results["protocols"].get("TLSv1.2"):
            cmd_tls.append("-tls1_2")
        try:
            proc = subprocess.run(cmd_tls, input=b"", stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=3.0)
            out_raw = proc.stdout.decode('utf-8', errors='ignore')
            results["raw_openssl_cmd"] = " ".join(cmd_tls)
            results["raw_openssl_output"] = out_raw.strip()
        except Exception as e:
            results["raw_openssl_cmd"] = " ".join(cmd_tls)
            results["raw_openssl_output"] = f"Lỗi thực thi OpenSSL: {e}"
    finally:
        stop_pcap_capture(pcap_proc)

    return results

def display_tls_audit(results: Dict[str, Any]):
    host = results["host"]
    port = results["port"]
    console.print(Panel(
        f"[bold cyan]ĐO KIỂM & PHÂN TÍCH MÃ HÓA ĐƯỜNG TRUYỀN (TLS & SOGIS ACM)[/bold cyan]\n"
        f"Mục tiêu: [bold white]{host}:{port}[/bold white]",
        border_style="cyan"
    ))

    if not results["is_tls_open"]:
        console.print(f"[yellow][!] Cổng {port} không hỗ trợ TLS hoặc dịch vụ đóng.[/yellow]")
        return

    # Table 1: Protocols
    t_proto = Table(title="1. BẢNG PHIÊN BẢN GIAO THỨC TLS HỖ TRỢ", show_lines=True)
    t_proto.add_column("Phiên bản", style="bold white", width=15)
    t_proto.add_column("Trạng thái", justify="center", width=15)
    t_proto.add_column("Đánh giá tiêu chuẩn (SOGIS ACM / QCVN 11)", width=45)

    for proto, sup in results["protocols"].items():
        if proto == "TLSv1.3":
            eva = "[bold green]KHUYẾN NGHỊ (SOGIS 'R' - Chuẩn cao nhất)[/bold green]" if sup else "[yellow]Chưa mở[/yellow]"
        elif proto == "TLSv1.2":
            eva = "[green]CHẤP NHẬN (Cần cấu hình đúng bộ mã AEAD PFS)[/green]" if sup else "[dim]Không mở[/dim]"
        else:
            eva = "[bold red]NGUY CƠ: Phải tắt bỏ (Giao thức lỗi thời)[/bold red]" if sup else "[bold green]AN TOÀN: Đã tắt bỏ triệt để[/bold green]"
        status = "[bold green]HỖ TRỢ (MỞ)[/bold green]" if sup else "[dim]TỪ CHỐI (ĐÓNG)[/dim]"
        t_proto.add_row(proto, status, eva)
    console.print(t_proto)

    # Table 2: Certificate
    if results["certificate"]:
        c = results["certificate"]
        t_cert = Table(title="\n2. THÔNG TIN CHỨNG THƯ SỐ MÁY CHỦ (X.509 CERTIFICATE)", show_lines=True)
        t_cert.add_column("Thuộc tính", style="bold yellow", width=25)
        t_cert.add_column("Giá trị trích xuất thực tế", style="white", width=55)

        t_cert.add_row("Chủ thể (Subject)", c["subject"])
        t_cert.add_row("Cơ quan cấp (Issuer)", c["issuer"])
        t_cert.add_row("Khóa công khai (Public Key)", f"[bold green]{c['public_key']}[/bold green]")
        t_cert.add_row("Thuật toán chữ ký (Signature)", c["signature_algorithm"])
        t_cert.add_row("Thời hạn hiệu lực (Validity)", f"{c['not_before']} -> {c['not_after']}")
        t_cert.add_row("Trạng thái chứng thư", f"[bold green]{c['status']}[/bold green]")
        console.print(t_cert)

    # Table 3: Cipher Suites
    t_cipher = Table(title="\n3. DANH MỤC BỘ MÃ (CIPHER SUITES) & PHÂN LOẠI SOGIS", show_lines=True)
    t_cipher.add_column("Tên Bộ mã (Cipher Suite)", style="bold white", width=35)
    t_cipher.add_column("Giao thức", justify="center", width=12)
    t_cipher.add_column("Trao đổi khóa (KEX)", justify="center", width=18)
    t_cipher.add_column("Mã hóa / MAC", justify="center", width=18)
    t_cipher.add_column("Chuẩn SOGIS ACM", justify="center", width=18)

    non_r_count = 0
    forbidden_count = 0
    for item in results["ciphers"]:
        sogis = item["sogis"]
        if sogis == "R":
            sogis_badge = "[bold green]R (Recommended)[/bold green]"
        elif sogis == "L":
            sogis_badge = "[yellow]L (Legacy)[/yellow]"
            non_r_count += 1
        elif sogis == "NR":
            sogis_badge = "[bold red]NR (Not Rec.)[/bold red]"
            non_r_count += 1
        else: # F
            sogis_badge = "[bold red reverse] F (Forbidden) [/bold red reverse]"
            forbidden_count += 1
            non_r_count += 1

        t_cipher.add_row(item["name"], item["protocol"], item["kex"], f"{item['enc']} / {item['mac']}", sogis_badge)

    console.print(t_cipher)

    # Raw Command & Response Output Evidence
    if results.get("raw_openssl_cmd") and results.get("raw_openssl_output"):
        console.print("\n[bold cyan]BẰNG CHỨNG THỰC NGHIỆM NGUYÊN VĂN (RAW COMMAND OUTPUT):[/bold cyan]")
        console.print(Panel(
            f"[bold green]$ {results['raw_openssl_cmd']}[/bold green]\n\n{results['raw_openssl_output']}",
            title="[bold yellow]Toàn văn Output lệnh OpenSSL s_client làm bằng chứng đàm phán TLS & Cipher[/bold yellow]",
            subtitle=f"[bold cyan]Wireshark: tcp.port == {results['port']} && (tls.handshake.type == 1 || tls.handshake.type == 2)[/bold cyan]",
            border_style="yellow"
        ))
        console.print(f"  [bold yellow]↳ Wireshark Filter/Sort:[/bold yellow] [bold green]tcp.port == {results['port']} && (tls.handshake.type == 1 || tls.handshake.type == 2)[/bold green]\n")

    # Summary
    console.print("\n[bold white]KẾT LUẬN ĐÁNH GIÁ MÃ HÓA ĐƯỜNG TRUYỀN:[/bold white]")
    console.print(f"  • Tổng số Cipher Suites hỗ trợ: [bold cyan]{len(results['ciphers'])}[/bold cyan]")
    if forbidden_count > 0:
        console.print(f"  • [bold red][FAIL] NGUY HIỂM: Phát hiện {forbidden_count} bộ mã bị CẤM (Forbidden - 3DES/RC4/MD5).[/bold red]")
    elif non_r_count > 0:
        console.print(f"  • [bold yellow][WARN] CẢNH BÁO: Phát hiện {non_r_count} bộ mã thuộc diện Legacy hoặc Not-Recommended theo SOGIS.[/bold yellow]")
    else:
        console.print("  • [bold green][PASS] TỐT: 100% các bộ mã đều thuộc chuẩn Khuyến nghị (Recommended 'R') trong SOGIS ACM.[/bold green]")

    pcap_file = results.get("pcap_file", "")
    filters = [
        ("Toàn bộ bắt tay TLS Handshake", f"tcp.port == {port} && tls.handshake"),
        ("Gói Client Hello (Đề xuất Cipher Suites)", f"tcp.port == {port} && tls.handshake.type == 1"),
        ("Gói Server Hello (Cipher Suite được chọn)", f"tcp.port == {port} && tls.handshake.type == 2"),
        ("Chứng thư số X.509 Certificate của Camera", f"tcp.port == {port} && tls.handshake.type == 11"),
        ("Lỗi / Cảnh báo TLS Handshake Alert", f"tcp.port == {port} && tls.record.content_type == 21")
    ]
    display_wireshark_panel(
        console,
        pcap_file,
        filters,
        is_tls=True,
        sort_tip="Click tiêu đề cột No. hoặc Time để xem trình tự bắt tay TLS (Client Hello → Server Hello → Certificate). Nhấn Ctrl + G đến frame Server Hello để kiểm tra trường tls.handshake.ciphersuite.",
        title=f"BẰNG CHỨNG GÓI TIN WIRESHARK TLS CỔNG {port}"
    )

if __name__ == '__main__':
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from toolkit_config import get_service_ports, get_target_info, load_config

    _cfg = load_config()
    dut_ip = get_target_info(_cfg)["ip"]
    port = int(get_service_ports(_cfg)["https"])

    if len(sys.argv) > 1:
        dut_ip = sys.argv[1]
    if len(sys.argv) > 2:
        port = int(sys.argv[2])

    res = audit_tls_endpoint(dut_ip, port)
    display_tls_audit(res)
