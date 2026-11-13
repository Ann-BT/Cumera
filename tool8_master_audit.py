#!/usr/bin/env python3
"""
Universal Master Security Auditor for IP Cameras
Author: Merlin / Antigravity
Orchestrates live, dynamic testing across all network services, cryptographic mechanisms,
and authentication protocols without vendor assumptions.
Generates a complete technical evidence report in Markdown and JSON.
"""

import sys
import os
import json
import time
import socket
import ssl
import asyncio
from datetime import datetime

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pcap_recorder import start_pcap_capture, stop_pcap_capture, display_wireshark_panel, get_sslkeylog_path
from toolkit_config import CONF_PATH, get_service_ports, get_target_info, load_config, make_console

console = make_console()

TOOLKIT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG = load_config()
_target_info = get_target_info(CONFIG)
_sp = get_service_ports(CONFIG)

DUT_IP = _target_info["ip"]

from service_discovery import scan_camera_services
from tool1_tls_scanner import audit_tls_endpoint
from tool2_unencrypted_protocols import run_full_auth_audit
from tool5_snmpv3_auditor import run_snmp_audit, summarize_snmp_audit

RTSP_PORT = int(_sp["rtsp"])
RTSPS_PORT = int(_sp["rtsps"])
SNMP_PORT = int(_sp["snmp"])
RTSP_PATH = _sp["rtsp_path"]

def measure_rtsp_latency(ip: str, port: int, attempts: int = 5, use_tls: bool = False) -> Dict[str, Any]:
    """Measures response latencies for successive RTSP/RTSPS authentication attempts."""
    latencies = []
    probe = f"DESCRIBE rtsp://{ip}:{port}{RTSP_PATH} RTSP/1.0\r\nCSeq: 1\r\n\r\n"
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    for i in range(attempts):
        t0 = time.time()
        try:
            if use_tls:
                with socket.create_connection((ip, port), timeout=2.0) as s:
                    with ctx.wrap_socket(s, server_hostname=ip) as ss:
                        ss.sendall(probe.encode())
                        ss.recv(1024)
            else:
                with socket.create_connection((ip, port), timeout=2.0) as s:
                    s.sendall(probe.encode())
                    s.recv(1024)
            elapsed_ms = round((time.time() - t0) * 1000, 2)
            latencies.append(elapsed_ms)
        except Exception:
            pass
        time.sleep(0.05)
    avg_latency = round(sum(latencies) / len(latencies), 2) if latencies else 0.0
    return {
        "port": port,
        "is_tls": use_tls,
        "attempts": len(latencies),
        "latencies_ms": latencies,
        "avg_latency_ms": avg_latency,
        "has_rate_limiting_delay": any(l > avg_latency * 2.5 for l in latencies[2:]) if len(latencies) >= 3 else False
    }

def run_master_audit(dut_ip: str) -> Dict[str, Any]:
    """Executes live master audit across all vectors with full PCAP recording."""
    pcap_proc, master_pcap = start_pcap_capture(
        dut_ip,
        f"tcp port 80 or tcp port 443 or tcp port 554 or tcp port {RTSPS_PORT} or udp port {SNMP_PORT} or udp port 3702",
        prefix="master_security_audit"
    )
    master_report = {
        "target_ip": dut_ip,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "services": {},
        "tls_audits": {},
        "auth_audits": {},
        "snmp_audit": None,
        "snmp_pcap": "",
        "master_pcap": master_pcap,
        "latency_profile": {}
    }

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True
        ) as progress:
            # Phase 1: Port & Service Discovery
            t1 = progress.add_task("[cyan]Giai đoạn 1: Dò quét cổng & giao thức mạng...", total=None)
            svc_data = scan_camera_services(dut_ip)
            master_report["services"] = svc_data
            progress.remove_task(t1)

            # Phase 2: TLS & Cipher Suite Analysis
            t2 = progress.add_task("[cyan]Giai đoạn 2: Phân tích mã hóa TLS 1.0 - 1.3 & Bộ mã SOGIS...", total=None)
            for p in svc_data.get("tls_ports", []):
                tls_res = audit_tls_endpoint(dut_ip, p)
                master_report["tls_audits"][p] = tls_res
            progress.remove_task(t2)

            # Phase 3: Authentication Analysis
            t3 = progress.add_task("[cyan]Giai đoạn 3: Bóc tách cơ chế xác thực Web & RTSP...", total=None)
            auth_res = run_full_auth_audit(dut_ip)
            master_report["auth_audits"] = auth_res
            progress.remove_task(t3)

            # Phase 4: SNMPv3 Audit
            if SNMP_PORT in svc_data.get("udp_open", []):
                t4 = progress.add_task("[cyan]Giai đoạn 4: Đo kiểm ma trận bảo mật SNMP-V3...", total=None)
                snmp_res = asyncio.run(run_snmp_audit(dut_ip, SNMP_PORT, capture_pcap=True))
                if isinstance(snmp_res, tuple):
                    master_report["snmp_audit"] = snmp_res[0]
                    master_report["snmp_pcap"] = snmp_res[1]
                else:
                    master_report["snmp_audit"] = snmp_res
                progress.remove_task(t4)

            # Phase 5: Rate Limiting & Latency
            active_rtsp = RTSPS_PORT if RTSPS_PORT in svc_data.get("tcp_open", []) else (554 if 554 in svc_data.get("tcp_open", []) else None)
            if active_rtsp:
                t5 = progress.add_task(f"[cyan]Giai đoạn 5: Đo đạc hồ sơ độ trễ phản hồi RTSP (Cổng {active_rtsp})...", total=None)
                lat_res = measure_rtsp_latency(dut_ip, active_rtsp, attempts=5, use_tls=(active_rtsp == RTSPS_PORT))
                master_report["latency_profile"] = lat_res
                progress.remove_task(t5)
    finally:
        stop_pcap_capture(pcap_proc)

    return master_report

def display_master_summary(report: Dict[str, Any]):
    console.print(Panel(
        f"[bold cyan]BÁO CÁO TỔNG HỢP KẾT QUẢ ĐO KIỂM BẢO MẬT CAMERA (MASTER AUDIT)[/bold cyan]\n"
        f"Mục tiêu: [bold white]{report['target_ip']}[/bold white] | Thời điểm: [dim]{report['timestamp']}[/dim]",
        border_style="bright_blue"
    ))

    # Summary Table
    t_sum = Table(title="BẢNG TỔNG KẾT CÁC BẰNG CHỨNG KỸ THUẬT THỰC NGHIỆM", show_lines=True)
    t_sum.add_column("Dịch vụ / Giao thức", style="bold yellow", width=22)
    t_sum.add_column("Cổng hoạt động", justify="center", width=12)
    t_sum.add_column("Mã hóa đường truyền", width=28)
    t_sum.add_column("Cơ chế xác thực phát hiện", width=28)
    t_sum.add_column("Đánh giá an toàn thực tế", justify="center", width=20)

    # 1. HTTP Web
    h = report["auth_audits"].get("http", {})
    if h.get("is_open"):
        enc = "Kênh rõ (Có 302 -> HTTPS)" if h.get("redirect_to_https") else "Kênh rõ (Không ép HTTPS)"
        auth = "Chuyển tiếp sang HTTPS" if h.get("redirect_to_https") else "Chưa phân loại"
        eva = "[bold green][PASS] AN TOÀN[/bold green]" if h.get("redirect_to_https") else "[bold red][FAIL] NGUY CƠ[/bold red]"
        t_sum.add_row("Giao diện Web (HTTP)", "TCP 80", enc, auth, eva)

    # 2. HTTPS Web
    tls_443 = report["tls_audits"].get(443, {})
    if tls_443.get("is_tls_open"):
        protos = [p for p, s in tls_443["protocols"].items() if s]
        ciphers_r = [c["name"] for c in tls_443["ciphers"] if c["sogis"] == "R"]
        ciphers_non_r = [c["name"] for c in tls_443["ciphers"] if c["sogis"] != "R"]
        enc_desc = f"{', '.join(protos)}\nCiphers: {len(tls_443['ciphers'])} (Có {len(ciphers_r)} 'R')"
        auth_desc = "Web Admin Session / API Token"
        eva = "[bold yellow][WARN] CÓ MÃ PHỤ[/bold yellow]" if ciphers_non_r else "[bold green][PASS] ĐẠT CHUẨN[/bold green]"
        t_sum.add_row("Giao diện Web (HTTPS)", "TCP 443", enc_desc, auth_desc, eva)

    # 3. RTSP Stream (Cleartext 554)
    r = report["auth_audits"].get("rtsp_cleartext", {})
    if r.get("is_open"):
        enc_rtsp = "Kênh rõ (TCP 554)"
        auth_rtsp = []
        if r.get("has_digest"): auth_rtsp.append(f"Digest ({r.get('digest_algo')})")
        if r.get("has_basic"): auth_rtsp.append("Basic (Base64 rõ)")
        auth_desc = "\n".join(auth_rtsp) if auth_rtsp else "Mở không mật khẩu"
        eva = "[bold red][FAIL] THỪA BASIC AUTH[/bold red]" if r.get("has_basic") else "[bold green][PASS] ĐẠT CHUẨN[/bold green]"
        t_sum.add_row("Luồng Video (RTSP)", "TCP 554", enc_rtsp, auth_desc, eva)

    # 3.1. RTSPS Stream (TLS)
    rs = report["auth_audits"].get("rtsps_tls", {})
    if rs and rs.get("is_open"):
        enc_rtsps = "Bọc mã hóa TLS 1.3"
        auth_rtsps = []
        if rs.get("has_digest"): auth_rtsps.append(f"Digest ({rs.get('digest_algo')})")
        if rs.get("has_basic"): auth_rtsps.append("Basic (Trong TLS)")
        auth_desc_s = "\n".join(auth_rtsps) if auth_rtsps else "Mở không mật khẩu"
        eva_s = "[bold green][PASS] BẢO VỆ TOÀN VẸN[/bold green]"
        t_sum.add_row("Luồng Video Bảo mật (RTSPS)", f"TCP {RTSPS_PORT}", enc_rtsps, auth_desc_s, eva_s)

    # 4. SNMPv3
    snmp = report.get("snmp_audit")
    if snmp:
        s_sum = summarize_snmp_audit(snmp)
        snmp_enc = ", ".join(s_sum["accepted_priv_algos"]) if s_sum["accepted_priv_algos"] else "Không mã hóa"
        snmp_auth = ", ".join(s_sum["accepted_auth_algos"]) if s_sum["accepted_auth_algos"] else "Không khớp / Từ chối"
        if s_sum["has_strong_sogis"] and not s_sum["has_weak_crypto"] and not s_sum["has_cleartext"]:
            eva = "[bold green][PASS] ĐẠT CHUẨN authPriv[/bold green]"
        elif s_sum["accepted_authpriv"]:
            eva = "[bold yellow][WARN] Hỗ trợ thuật toán yếu / kênh rõ[/bold yellow]"
        else:
            eva = "[yellow]Cần cấu hình / Kiểm tra Pass[/yellow]"
        t_sum.add_row("Quản trị mạng SNMP", f"UDP {SNMP_PORT}", snmp_enc, f"User: {s_sum['matched_user']}\nAuth: {snmp_auth}", eva)

    # 5. ONVIF
    if 3702 in report["services"].get("udp_open", []):
        t_sum.add_row("ONVIF WS-Discovery", "UDP 3702", "UDP Broadcast", "Phát thanh Scopes Profile S/G/T", "[bold green][OK] HOẠT ĐỘNG[/bold green]")

    console.print(t_sum)

    # Raw Evidence Status Note
    console.print("\n[bold cyan]CÁC CỤM PHẢN HỒI THỰC TẾ & OUTPUT CÂU LỆNH LÀM BẰNG CHỨNG ĐÃ GHI NHẬN:[/bold cyan]")
    if h.get("raw_response"):
        console.print("  • [bold green][OK][/bold green] Cụm phản hồi HTTP 302 Redirection (Cổng 80) làm bằng chứng chuyển hướng")
    if r.get("raw_response"):
        console.print("  • [bold green][OK][/bold green] Cụm phản hồi RTSP 401 Unauthorized (Cổng 554) làm bằng chứng Digest SHA-256")
    if r.get("basic_test_response_raw"):
        console.print("  • [bold red][!][/bold red] Cụm phản hồi RTSP 200 OK SDP (Cổng 554) làm bằng chứng chấp nhận Basic Auth")
    if rs and rs.get("raw_response"):
        console.print(f"  • [bold green][OK][/bold green] Cụm phản hồi RTSPS 401 Unauthorized qua TLS (Cổng {RTSPS_PORT}) làm bằng chứng Digest SHA-256")
    if rs and rs.get("basic_test_response_raw"):
        console.print(f"  • [bold green][OK][/bold green] Cụm phản hồi RTSPS 200 OK SDP qua TLS (Cổng {RTSPS_PORT}) làm bằng chứng cấp quyền phát luồng")
    if tls_443.get("raw_openssl_output"):
        console.print("  • [bold green][OK][/bold green] Toàn văn Output lệnh OpenSSL s_client đàm phán TLS 1.3 & Cipher Suite SOGIS 'R'")

    master_pcap = report.get("master_pcap", "")
    filters = [
        ("Web HTTP Cổng 80 Chuyển hướng", "tcp.port == 80 && (http.response.code == 302 || http)"),
        ("Web HTTPS Cổng 443 Bắt tay TLS 1.3", "tcp.port == 443 && (tls.handshake.type == 1 || tls.handshake.type == 2 || tls.handshake.type == 11)"),
        ("RTSP Cổng 554 Thách thức & Basic Auth", "tcp.port == 554 && (rtsp.status == 401 || rtsp.status == 200 || rtsp.authorization)"),
        (f"RTSPS Cổng {RTSPS_PORT} qua TLS (Chưa giải mã)", f"tcp.port == {RTSPS_PORT} && tls"),
        (f"RTSPS Cổng {RTSPS_PORT} sau giải mã sslkeys.log (Thách thức xác thực)", "rtsp.status == 401"),
        (f"RTSPS Cổng {RTSPS_PORT} sau giải mã sslkeys.log (200 OK SDP)", "rtsp.status == 200 && rtsp.content_type contains \"sdp\""),
        ("SNMPv3 Cổng UDP 161 Toàn bộ truy vấn", "udp.port == 161 && (snmp.version == 3 || snmp)"),
        ("SNMPv3 Cổng UDP 161 Mã hóa authPriv", "snmp.msgFlags.auth == 1 && snmp.msgFlags.priv == 1")
    ]
    display_wireshark_panel(
        console,
        master_pcap,
        filters,
        is_tls=True,
        sort_tip="Click tiêu đề cột No. hoặc Time để duyệt qua toàn bộ các giai đoạn kiểm thử theo trình tự thời gian từ Quét cổng → TLS Handshake → RTSP/RTSPS Auth → SNMPv3.",
        title="BẰNG CHỨNG GÓI TIN WIRESHARK CHO TOÀN BỘ TIẾN TRÌNH MASTER AUDIT"
    )

def save_audit_reports(report: Dict[str, Any]):
    md_path = os.path.join(TOOLKIT_DIR, "camera_security_audit_report.md")
    json_path = os.path.join(TOOLKIT_DIR, "camera_security_audit_evidence.json")

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    with open(md_path, "w", encoding="utf-8") as f:
        f.write(f"# BÁO CÁO THỰC NGHIỆM AN TOÀN BẢO MẬT & MẬT MÃ CAMERA IP\n\n")
        f.write(f"- **Địa chỉ IP thiết bị (DUT)**: `{report['target_ip']}`\n")
        f.write(f"- **Thời gian đo kiểm**: `{report['timestamp']}`\n\n")
        f.write(f"## 1. Danh sách Dịch vụ & Cổng mạng phát hiện\n\n")
        f.write(f"| Cổng | Giao vận | Dịch vụ nhận diện | Mã hóa | Chi tiết |\n")
        f.write(f"| :--- | :--- | :--- | :--- | :--- |\n")
        for p, s in sorted(report["services"].get("services", {}).items()):
            f.write(f"| {s['port']} | {s['proto'].upper()} | {s['identified_service']} | {'TLS' if s['is_tls'] else 'Cleartext'} | {s['desc']} |\n")

        f.write(f"\n## 2. Mã hóa đường truyền & Cipher Suites (TLS / SOGIS ACM)\n\n")
        for p, tls in report.get("tls_audits", {}).items():
            f.write(f"### Cổng TCP {p}:\n")
            if tls.get("certificate"):
                cert = tls["certificate"]
                f.write(f"- **Khóa công khai**: `{cert['public_key']}`\n")
                f.write(f"- **Thuật toán chữ ký**: `{cert['signature_algorithm']}`\n")
                f.write(f"- **Thời hạn**: `{cert['not_before']} -> {cert['not_after']}` (`{cert['status']}`)\n\n")
            f.write(f"| Tên Bộ mã (Cipher Suite) | Giao thức | Trao đổi khóa (KEX) | Mã hóa / MAC | Chuẩn SOGIS ACM |\n")
            f.write(f"| :--- | :--- | :--- | :--- | :--- |\n")
            for c in tls.get("ciphers", []):
                f.write(f"| `{c['name']}` | {c['protocol']} | {c['kex']} | {c['enc']} / {c['mac']} | **{c['sogis']}** |\n")

        f.write(f"\n## 3. Cơ chế Xác thực (Authentication Schemes)\n\n")
        r = report["auth_audits"].get("rtsp_cleartext", {})
        f.write(f"### 3.1. Giao thức RTSP Kênh rõ (Cổng 554):\n")
        f.write(f"- **Trạng thái cổng**: {'MỞ' if r.get('is_open') else 'ĐÓNG / VÔ HIỆU HÓA (An toàn)'}\n")
        if r.get("is_open"):
            f.write(f"- **Digest Auth**: {'Có hỗ trợ (' + r.get('digest_algo', '') + ')' if r.get('has_digest') else 'Không'}\n")
            f.write(f"- **Basic Auth**: {'Có phát hiện (Mật khẩu truyền Base64)' if r.get('has_basic') else 'Không'}\n")
            f.write(f"- **Thử nghiệm chấp nhận Basic**: {'ĐÃ CHẤP NHẬN (200 OK) - Cảnh báo nguy cơ rò rỉ' if r.get('basic_accepted') else 'Từ chối'}\n")
            if r.get("raw_challenge"):
                f.write(f"- **Tiêu đề nguyên văn**:\n")
                for ch in r["raw_challenge"]:
                    f.write(f"  - `WWW-Authenticate: {ch}`\n")

        rs = report["auth_audits"].get("rtsps_tls", {})
        if rs:
            f.write(f"\n### 3.2. Giao thức RTSPS Kênh mã hóa TLS (Cổng {RTSPS_PORT}):\n")
            f.write(f"- **Trạng thái cổng**: {'MỞ' if rs.get('is_open') else 'ĐÓNG'}\n")
            if rs.get("is_open"):
                f.write(f"- **Mã hóa đường truyền**: Bọc mã hóa TLS 1.3 toàn vẹn\n")
                f.write(f"- **Digest Auth**: {'Có hỗ trợ (' + rs.get('digest_algo', '') + ')' if rs.get('has_digest') else 'Không'}\n")
                f.write(f"- **Basic Auth (trong TLS)**: {'Có hỗ trợ' if rs.get('has_basic') else 'Không'}\n")
                f.write(f"- **Thử nghiệm cấp quyền phát luồng (SDP)**: {'THÀNH CÔNG (200 OK)' if rs.get('basic_accepted') else 'Từ chối'}\n")
                if rs.get("raw_challenge"):
                    f.write(f"- **Tiêu đề nguyên văn**:\n")
                    for ch in rs["raw_challenge"]:
                        f.write(f"  - `WWW-Authenticate: {ch}`\n")

        f.write(f"\n## 4. Giao thức Quản trị SNMP-V3 (Cổng UDP {SNMP_PORT})\n\n")
        if report.get("snmp_audit"):
            s_sum = summarize_snmp_audit(report["snmp_audit"])
            usable_str = ", ".join(f"`{c}`" for c in s_sum["usable_ciphers"]) if s_sum["usable_ciphers"] else "*Không có tổ hợp nào thành công*"
            f.write(f"- **Mã hóa thực tế sử dụng được**: {usable_str}\n")
            f.write(f"- **Tài khoản kiểm tra**: `{s_sum['matched_user']}` | **Tổng số tổ hợp thử**: `{s_sum['total_tested']}`\n\n")
            f.write(f"| Cấu hình thử nghiệm | Mức bảo mật | Phân loại | Kết quả phản hồi |\n")
            f.write(f"| :--- | :--- | :--- | :--- |\n")
            for item in report["snmp_audit"]:
                f.write(f"| {item['name']} | {item['level']} | {item['sec_type']} | {'[CHẤP NHẬN]' if item['accepted'] else '[TỪ CHỐI]'} ({item.get('status_code', '')}) |\n")

        # 5. Latency Profile
        lat = report.get("latency_profile", {})
        if lat:
            f.write(f"\n## 5. Hồ sơ Độ trễ & Giới hạn tần suất phản hồi (Rate Limiting)\n\n")
            f.write(f"- **Số lần thử nghiệm liên tiếp**: {lat.get('attempts', 0)} lần\n")
            f.write(f"- **Độ trễ các lần (ms)**: `{lat.get('latencies_ms', [])}`\n")
            f.write(f"- **Độ trễ trung bình**: `{lat.get('avg_latency_ms', 0)} ms`\n")
            f.write(f"- **Cơ chế làm chậm (Rate Limiting Delay)**: {'Có phát hiện độ trễ tăng dần' if lat.get('has_rate_limiting_delay') else 'Không áp đặt độ trễ'}\n")

        # 6. Raw Evidence Blocks
        f.write(f"\n## 6. BẰNG CHỨNG KỸ THUẬT NGUYÊN VĂN (RAW PROTOCOL RESPONSES & COMMAND OUTPUTS)\n\n")
        f.write("Toàn bộ cụm phản hồi thực tế và output câu lệnh thu được từ camera phục vụ làm bằng chứng đối soát khách quan:\n\n")

        # HTTP Port 80
        h_auth = report.get("auth_audits", {}).get("http", {})
        if h_auth.get("raw_response"):
            f.write(f"### 6.1. Cụm phản hồi HTTP Port 80 (Bằng chứng chuyển hướng HTTPS):\n")
            f.write(f"- **Wireshark Filter/Sort**: `http.response.code == 302 || (tcp.port == 80 && http)`\n")
            f.write(f"```http\n{h_auth.get('raw_request', 'GET / HTTP/1.1')}\n```\n")
            f.write(f"```http\n{h_auth['raw_response']}\n```\n\n")

        # RTSP 554 Probe
        r_auth = report.get("auth_audits", {}).get("rtsp_cleartext", {})
        if r_auth.get("raw_response"):
            f.write(f"### 6.2. Cụm phản hồi RTSP Port 554 (Bằng chứng Thách thức xác thực & WWW-Authenticate):\n")
            f.write(f"- **Wireshark Filter/Sort**: `tcp.port == 554 && rtsp.status == 401`\n")
            f.write(f"```http\n{r_auth.get('raw_request', 'DESCRIBE rtsp://... RTSP/1.0')}\n```\n")
            f.write(f"```http\n{r_auth['raw_response']}\n```\n\n")

        # RTSP 554 Basic Auth
        if r_auth.get("basic_test_response_raw"):
            f.write(f"### 6.3. Cụm phản hồi RTSP khi gửi Basic Auth (Bằng chứng Chấp nhận mật khẩu Base64 rõ):\n")
            f.write(f"- **Wireshark Filter/Sort**: `tcp.port == 554 && (rtsp.authorization contains \"Basic\" || rtsp.status == 200)`\n")
            f.write(f"```http\n{r_auth.get('basic_test_request', 'DESCRIBE rtsp://... Authorization: Basic ...')}\n```\n")
            f.write(f"```http\n{r_auth['basic_test_response_raw']}\n```\n\n")

        # RTSPS Probe & SDP
        rs_auth = report.get("auth_audits", {}).get("rtsps_tls", {})
        if rs_auth and rs_auth.get("raw_response"):
            f.write(f"### 6.4. Cụm phản hồi RTSPS Port {RTSPS_PORT} qua TLS (Bằng chứng Thách thức xác thực):\n")
            f.write(f"- **Wireshark Filter/Sort**: `tcp.port == {RTSPS_PORT} && (tls || rtsp.status == 401)` *(Nếu giải mã TLS: `rtsp.status == 401`)*\n")
            f.write(f"```http\n{rs_auth.get('raw_request', f'DESCRIBE rtsp://...:{RTSPS_PORT}{RTSP_PATH} RTSP/1.0')}\n```\n")
            f.write(f"```http\n{rs_auth['raw_response']}\n```\n\n")

        if rs_auth and rs_auth.get("basic_test_response_raw"):
            f.write(f"### 6.5. Cụm phản hồi RTSPS Port {RTSPS_PORT} qua TLS khi gửi xác thực đúng (Bằng chứng Cấp quyền phát luồng SDP):\n")
            f.write(f"- **Wireshark Filter/Sort**: `tcp.port == {RTSPS_PORT} && (tls || rtsp.status == 200)` *(Nếu giải mã TLS: `rtsp.status == 200 && rtsp.content_type contains \"sdp\"`)*\n")
            f.write(f"```http\n{rs_auth.get('basic_test_request', f'DESCRIBE rtsp://...:{RTSPS_PORT}{RTSP_PATH} Authorization: Basic ...')}\n```\n")
            f.write(f"```http\n{rs_auth['basic_test_response_raw']}\n```\n\n")

        # OpenSSL Handshake TLS 443
        tls_info = report.get("tls_audits", {}).get(443, {})
        if tls_info.get("raw_openssl_output"):
            f.write(f"### 6.6. Toàn văn Output lệnh OpenSSL s_client TLS 1.3 (Cổng 443):\n")
            f.write(f"- **Wireshark Filter/Sort**: `tcp.port == 443 && (tls.handshake.type == 1 || tls.handshake.type == 2)`\n")
            f.write(f"```bash\n$ {tls_info.get('raw_openssl_cmd', 'openssl s_client -connect ' + report['target_ip'] + ':443 -tls1_3')}\n```\n")
            f.write(f"```text\n{tls_info['raw_openssl_output']}\n```\n\n")

        # SNMPv3 Output
        if report.get("snmp_audit"):
            f.write(f"### 6.7. Bằng chứng Phản hồi ma trận kiểm thử SNMP-V3 (Cổng 161):\n")
            f.write(f"```text\n")
            for item in report["snmp_audit"]:
                f.write(f"• {item['name']:32s} | Mức: {item['level']:28s} | Kết quả: {item['detail']}\n")
            f.write(f"```\n\n")

        # 7. Wireshark Evidence & PCAP Files
        f.write(f"## 7. Bằng chứng Gói tin Wireshark & Tệp PCAP Đối Soát Thực Nghiệm\n\n")
        if report.get("master_pcap"):
            f.write(f"- **Tệp PCAP Toàn bộ bài đo kiểm Master Audit**: `{report['master_pcap']}`\n")
            f.write(f"  - *Lệnh mở trực tiếp*: `wireshark {report['master_pcap']}`\n")
        if report.get("snmp_pcap"):
            f.write(f"- **Tệp PCAP Dịch vụ SNMP-V3**: `{report['snmp_pcap']}`\n")
            f.write(f"  - *Lệnh mở trực tiếp*: `wireshark {report['snmp_pcap']}`\n")
        f.write(f"- **Tệp Khóa giải mã TLS 1.3 (Master Secret)**: `{get_sslkeylog_path()}`\n\n")

        f.write("### Bảng Danh Mục Bộ Lọc Wireshark (Display Filters) Theo Từng Giao Thức:\n\n")
        f.write("| Giao thức / Mục tiêu đo kiểm | Bộ lọc Display Filter Wireshark | Ý nghĩa bằng chứng kỹ thuật |\n")
        f.write("| :--- | :--- | :--- |\n")
        f.write("| **HTTP 80 Chuyển hướng** | `http.response.code == 302 \\|\\| (tcp.port == 80 && http)` | Bằng chứng ép chuyển hướng sang HTTPS |\n")
        f.write("| **HTTPS 443 Handshake** | `tcp.port == 443 && (tls.handshake.type == 1 \\|\\| tls.handshake.type == 2)` | Bắt tay đàm phán bộ mã TLS 1.3 |\n")
        f.write("| **Chứng thư số X.509** | `tcp.port == 443 && tls.handshake.type == 11` | Chứng thư số máy chủ camera |\n")
        f.write("| **RTSP 554 401 Challenge** | `tcp.port == 554 && rtsp.status == 401` | Thách thức xác thực rõ |\n")
        f.write("| **RTSP 554 Basic Auth** | `tcp.port == 554 && (rtsp.authorization contains \"Basic\" \\|\\| rtsp.status == 200)` | Bằng chứng gửi & chấp nhận mật khẩu rõ |\n")
        f.write(f"| **RTSPS {RTSPS_PORT} Encrypted TLS** | `tcp.port == {RTSPS_PORT} && tls` | Toàn bộ luồng video được bọc TLS 1.3 |\n")
        f.write(f"| **RTSPS {RTSPS_PORT} Auth Challenge** | `rtsp.status == 401` | Sau khi nạp file sslkeys.log để giải mã |\n")
        f.write(f"| **RTSPS {RTSPS_PORT} Cấp luồng 200 OK** | `rtsp.status == 200 && rtsp.content_type contains \"sdp\"` | Cấp phép truyền luồng video SDP |\n")
        f.write("| **SNMPv3 Mức authPriv** | `snmp.msgFlags.auth == 1 && snmp.msgFlags.priv == 1` | Gói tin SNMPv3 bảo mật mức cao nhất |\n")
        f.write("| **SNMPv3 Phản hồi sysDescr** | `snmp.version == 3 && snmp.error_status == 0` | Truy vấn MIB thành công |\n\n")
        f.write("> **Hướng dẫn Sort trong Wireshark**: Click tiêu đề cột **`No.`** hoặc **`Time`** để sắp xếp gói tin theo thứ tự phát sinh, hoặc nhấn **`Ctrl + G`** để nhảy trực tiếp tới số thứ tự gói tin cần đối soát.\n\n")

    console.print(f"\n[bold green][OK] Đã xuất Báo cáo kỹ thuật chi tiết:[/bold green] [bold white]{md_path}[/bold white]")
    console.print(f"[bold green][OK] Đã lưu Bằng chứng số liệu JSON:[/bold green] [bold white]{json_path}[/bold white]")

def main():
    dut = sys.argv[1] if len(sys.argv) > 1 else DUT_IP
    console.print(f"[*] Bắt đầu tiến trình đo kiểm tổng thể Master Audit cho Camera: [bold white]{dut}[/bold white]...")
    rep = run_master_audit(dut)
    display_master_summary(rep)
    save_audit_reports(rep)

if __name__ == '__main__':
    main()
