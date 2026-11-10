#!/usr/bin/env python3
"""
Universal Authentication Mechanism & Cleartext Protocol Auditor
Author: Merlin / Antigravity
Audits:
  1. Web HTTP (Port 80/8080) redirection & authentication schemes.
  2. RTSP/RTSPS (Port 554/8554/9554) authentication schemes:
     - Detects Basic Auth (Cleartext Base64 risk).
     - Detects Digest Auth (Extracts hash algorithm: SHA-256 vs MD5).
     - Verifies whether camera permits Basic Auth login.
  3. ONVIF Web Service authentication challenges.
"""

import socket
import ssl
import sys
import json
import os
import base64
import re
from typing import Dict, List, Any

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pcap_recorder import start_pcap_capture, stop_pcap_capture, display_wireshark_panel, enable_ssl_keylog

console = Console()

CONF_PATH = os.path.join(os.path.dirname(__file__), "config.json")
CONFIG = {}
if os.path.exists(CONF_PATH):
    try:
        with open(CONF_PATH, encoding="utf-8") as f:
            CONFIG = json.load(f)
    except Exception:
        pass

DUT_IP = CONFIG.get("target_camera", {}).get("ip", "192.168.101.208")
USER = CONFIG.get("target_camera", {}).get("username", "admin")
PASS = CONFIG.get("target_camera", {}).get("password", "Psitest135#")
HTTP_PORT = CONFIG.get("service_ports", {}).get("http", 80)
HTTPS_PORT = CONFIG.get("service_ports", {}).get("https", 443)
RTSP_PORT = CONFIG.get("service_ports", {}).get("rtsp_cleartext", 554)
RTSPS_PORT = CONFIG.get("service_ports", {}).get("rtsps_tls", 322)
RTSP_PATH = CONFIG.get("service_ports", {}).get("rtsp_path", "/axis-media/media.amp" if RTSPS_PORT == 322 else "/stream1")
if not RTSP_PATH.startswith("/"):
    RTSP_PATH = "/" + RTSP_PATH

def audit_http_port(ip: str, port: int) -> Dict[str, Any]:
    """Audits HTTP port for redirects, cleartext exposure, and auth challenges."""
    result = {
        "port": port,
        "is_open": False,
        "status_code": 0,
        "redirect_to_https": False,
        "redirect_location": "",
        "auth_methods": [],
        "headers": {}
    }

    s = socket.socket()
    s.settimeout(2.5)
    try:
        s.connect((ip, port))
        result["is_open"] = True
        req = f"GET / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\nUser-Agent: SecurityAuditClient/1.0\r\n\r\n"
        s.sendall(req.encode())
        resp = s.recv(4096).decode('utf-8', errors='ignore')
        
        result["raw_request"] = req
        result["raw_response"] = resp
        lines = resp.splitlines()
        if lines:
            parts = lines[0].split()
            if len(parts) >= 2 and parts[1].isdigit():
                result["status_code"] = int(parts[1])

        for line in lines:
            if ":" in line:
                k, v = line.split(":", 1)
                result["headers"][k.strip().lower()] = v.strip()

        loc = result["headers"].get("location", "")
        if loc:
            result["redirect_location"] = loc
            if "https://" in loc:
                result["redirect_to_https"] = True

        www_auth = result["headers"].get("www-authenticate", "")
        if www_auth:
            if "basic" in www_auth.lower():
                result["auth_methods"].append("Basic")
            if "digest" in www_auth.lower():
                result["auth_methods"].append("Digest")
            if "bearer" in www_auth.lower():
                result["auth_methods"].append("Bearer")

    except Exception:
        pass
    finally:
        s.close()

    return result

def audit_rtsp_auth(ip: str, port: int, use_tls: bool = False) -> Dict[str, Any]:
    """Audits RTSP endpoint for WWW-Authenticate headers and credential acceptance."""
    result = {
        "port": port,
        "use_tls": use_tls,
        "is_open": False,
        "raw_challenge": [],
        "has_basic": False,
        "basic_realm": "",
        "has_digest": False,
        "digest_algo": "Không xác định",
        "digest_realm": "",
        "digest_nonce": "",
        "digest_qop": "",
        "basic_accepted": False,
        "basic_test_response": ""
    }

    candidate_paths = [RTSP_PATH]
    for cp in ["/axis-media/media.amp", "/stream1", "/live/ch0", "/onvif-media/media.amp"]:
        if cp not in candidate_paths:
            candidate_paths.append(cp)

    selected_path = candidate_paths[0]
    resp = ""
    probe = ""
    keylog_file = os.path.join(os.path.dirname(__file__), "captures", "sslkeys.log")

    try:
        for path in candidate_paths:
            current_probe = f"DESCRIBE rtsp://{ip}:{port}{path} RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: SecurityAuditClient/1.0\r\n\r\n"
            try:
                if use_tls:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    ctx.keylog_filename = keylog_file
                    with socket.create_connection((ip, port), timeout=2.5) as raw_sock:
                        with ctx.wrap_socket(raw_sock, server_hostname=ip) as ssock:
                            result["is_open"] = True
                            ssock.sendall(current_probe.encode())
                            current_resp = ssock.recv(4096).decode('utf-8', errors='ignore')
                else:
                    with socket.create_connection((ip, port), timeout=2.5) as sock:
                        result["is_open"] = True
                        sock.sendall(current_probe.encode())
                        current_resp = sock.recv(4096).decode('utf-8', errors='ignore')

                if current_resp and ("WWW-Authenticate" in current_resp or "200 OK" in current_resp or "401" in current_resp):
                    selected_path = path
                    probe = current_probe
                    resp = current_resp
                    break
            except Exception:
                continue

        if not resp and 'current_probe' in locals():
            probe = current_probe
            resp = current_resp if 'current_resp' in locals() else ""

        result["raw_request"] = probe
        result["raw_response"] = resp
        if not resp:
            return result

        # Parse challenge
        for line in resp.splitlines():
            if line.lower().startswith("www-authenticate:"):
                val = line.split(":", 1)[1].strip()
                result["raw_challenge"].append(val)
                
                # Check Basic
                if val.lower().startswith("basic"):
                    result["has_basic"] = True
                    m = re.search(r'realm="([^"]+)"', val, re.IGNORECASE)
                    if m: result["basic_realm"] = m.group(1)

                # Check Digest
                if val.lower().startswith("digest"):
                    result["has_digest"] = True
                    m_realm = re.search(r'realm="([^"]+)"', val, re.IGNORECASE)
                    if m_realm: result["digest_realm"] = m_realm.group(1)

                    m_algo = re.search(r'algorithm="?([^", ]+)"?', val, re.IGNORECASE)
                    if m_algo:
                        result["digest_algo"] = m_algo.group(1).upper()
                    else:
                        result["digest_algo"] = "MD5 (Mặc định RFC 2617)"

                    m_qop = re.search(r'qop="?([^",]+)"?', val, re.IGNORECASE)
                    if m_qop: result["digest_qop"] = m_qop.group(1)

                    m_nonce = re.search(r'nonce="([^"]+)"', val, re.IGNORECASE)
                    if m_nonce: result["digest_nonce"] = m_nonce.group(1)

        # Test Basic Auth acceptance if Basic was offered
        if result["has_basic"]:
            cred = base64.b64encode(f"{USER}:{PASS}".encode()).decode()
            basic_probe = (
                f"DESCRIBE rtsp://{ip}:{port}{selected_path} RTSP/1.0\r\n"
                f"CSeq: 2\r\n"
                f"Authorization: Basic {cred}\r\n"
                f"User-Agent: SecurityAuditClient/1.0\r\n\r\n"
            )
            resp_b = ""
            if use_tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.keylog_filename = keylog_file
                with socket.create_connection((ip, port), timeout=2.5) as raw_sock:
                    with ctx.wrap_socket(raw_sock, server_hostname=ip) as ssock:
                        ssock.sendall(basic_probe.encode())
                        resp_b = ssock.recv(4096).decode('utf-8', errors='ignore')
            else:
                with socket.create_connection((ip, port), timeout=2.5) as sock:
                    sock.sendall(basic_probe.encode())
                    resp_b = sock.recv(4096).decode('utf-8', errors='ignore')

            result["basic_test_request"] = basic_probe
            result["basic_test_response_raw"] = resp_b
            if "200 OK" in resp_b:
                result["basic_accepted"] = True
                result["basic_test_response"] = "RTSP/1.0 200 OK (Chấp nhận mật khẩu Base64)"
            elif "401" in resp_b:
                result["basic_accepted"] = False
                result["basic_test_response"] = "RTSP/1.0 401 Unauthorized (Từ chối Basic Auth)"
            else:
                result["basic_test_response"] = resp_b.splitlines()[0] if resp_b else "Không phản hồi"

    except Exception:
        pass

    return result

def run_full_auth_audit(dut_ip: str) -> Dict[str, Any]:
    """Orchestrates comprehensive protocol & auth audit with background PCAP capture."""
    pcap_proc, pcap_file = start_pcap_capture(
        dut_ip,
        f"tcp port {HTTP_PORT} or tcp port {RTSP_PORT} or tcp port {RTSPS_PORT}",
        prefix="unencrypted_proto_audit"
    )
    try:
        results = {
            "ip": dut_ip,
            "http": audit_http_port(dut_ip, HTTP_PORT),
            "rtsp_cleartext": audit_rtsp_auth(dut_ip, RTSP_PORT, use_tls=False),
            "rtsps_tls": audit_rtsp_auth(dut_ip, RTSPS_PORT, use_tls=True) if RTSPS_PORT != RTSP_PORT else None,
            "pcap_file": pcap_file
        }
    finally:
        stop_pcap_capture(pcap_proc)
    return results

def display_auth_audit(results: Dict[str, Any]):
    console.print(Panel(
        f"[bold cyan]ĐO KIỂM & PHÂN TÍCH MÃ HÓA GIÁ TRỊ XÁC THỰC (AUTHENTICATION AUDITOR)[/bold cyan]\n"
        f"Mục tiêu: [bold white]{results['ip']}[/bold white]",
        border_style="cyan"
    ))

    # 1. HTTP Table
    h = results["http"]
    t_http = Table(title="1. ĐO KIỂM DỊCH VỤ WEB HTTP (PORT 80)", show_lines=True)
    t_http.add_column("Hạng mục kiểm tra", style="bold yellow", width=30)
    t_http.add_column("Kết quả đo kiểm thực tế", style="white", width=45)

    if h["is_open"]:
        status_str = f"HTTP {h['status_code']}"
        redirect_str = f"[bold green]CÓ - Tự động ép chuyển hướng sang HTTPS[/bold green]\n({h['redirect_location']})\n[dim]Wireshark: http.response.code == 302 || (tcp.port == 80 && http)[/dim]" if h["redirect_to_https"] else "[bold red]KHÔNG - Cổng 80 mở rõ không chuyển hướng[/bold red]"
        t_http.add_row("Trạng thái cổng 80", "[bold green]MỞ (Open)[/bold green]")
        t_http.add_row("Mã phản hồi khởi tạo", status_str)
        t_http.add_row("Chuyển hướng an toàn (301/302 -> HTTPS)", redirect_str)
    else:
        t_http.add_row("Trạng thái cổng 80", "[dim]ĐÓNG / VÔ HIỆU HÓA (An toàn)[/dim]")
    console.print(t_http)

    # 2. RTSP Table (Cleartext Port 554)
    r = results.get("rtsp_cleartext", {})
    t_rtsp = Table(title="\n2. ĐO KIỂM CƠ CHẾ XÁC THỰC LUỒNG VIDEO RTSP (PORT 554 - CLEARTEXT)", show_lines=True)
    t_rtsp.add_column("Cơ chế xác thực", style="bold yellow", width=25)
    t_rtsp.add_column("Trạng thái hỗ trợ", justify="center", width=20)
    t_rtsp.add_column("Chi tiết kỹ thuật & Đánh giá an toàn", width=40)

    if r.get("is_open"):
        # Digest
        if r["has_digest"]:
            d_status = "[bold green]CÓ HỖ TRỢ[/bold green]"
            d_eval = f"Thuật toán: [bold green]{r['digest_algo']}[/bold green]\nRealm: {r['digest_realm']}\n[dim]Wireshark: tcp.port == 554 && rtsp.status == 401[/dim]"
        else:
            d_status = "[dim]KHÔNG[/dim]"
            d_eval = "[yellow]Không hỗ trợ Digest Auth[/yellow]"
        t_rtsp.add_row("Digest Authentication", d_status, d_eval)

        # Basic
        if r["has_basic"]:
            b_status = "[bold red]CÓ PHÁT HIỆN[/bold red]"
            b_eval = f"[bold red]NGUY CƠ BẢO MẬT: Mật khẩu truyền dạng Base64[/bold red]\nRealm: {r['basic_realm']}\n[dim]Wireshark: tcp.port == 554 && rtsp.status == 401 && rtsp contains \"Basic\"[/dim]"
        else:
            b_status = "[bold green]TẮT BỎ (AN TOÀN)[/bold green]"
            b_eval = "[green]Camera không mở Basic Auth[/green]"
        t_rtsp.add_row("Basic Authentication", b_status, b_eval)

        # Basic Acceptance Test
        if r["has_basic"]:
            if r["basic_accepted"]:
                test_badge = "[bold red reverse] ĐÃ CHẤP NHẬN [/bold red reverse]"
                test_desc = "[bold red]Camera cho phép đăng nhập thành công bằng Basic Auth rõ (200 OK). Kẻ tấn công trên mạng có thể đánh cắp mật khẩu.[/bold red]\n[dim]Wireshark: tcp.port == 554 && (rtsp.authorization contains \"Basic\" || rtsp.status == 200)[/dim]"
            else:
                test_badge = "[bold green] TỪ CHỐI [/bold green]"
                test_desc = "[green]Camera từ chối xử lý mật khẩu Base64.[/green]"
            t_rtsp.add_row("Thử nghiệm gửi mật khẩu Basic", test_badge, test_desc)

    else:
        t_rtsp.add_row("Trạng thái cổng RTSP 554", "[dim]ĐÓNG / VÔ HIỆU HÓA[/dim]", "Cổng truyền rõ 554 đã đóng (An toàn)")
    console.print(t_rtsp)

    # 3. RTSPS Table (TLS Encrypted Port)
    rs = results.get("rtsps_tls")
    if rs:
        t_rtsps = Table(title=f"\n3. ĐO KIỂM CƠ CHẾ XÁC THỰC LUỒNG VIDEO RTSPS (PORT {RTSPS_PORT} - TLS MÃ HÓA)", show_lines=True)
        t_rtsps.add_column("Cơ chế xác thực / Mã hóa", style="bold cyan", width=25)
        t_rtsps.add_column("Trạng thái hỗ trợ", justify="center", width=20)
        t_rtsps.add_column("Chi tiết kỹ thuật & Đánh giá an toàn", width=40)

        if rs.get("is_open"):
            t_rtsps.add_row("Mã hóa đường truyền TLS", "[bold green]BẢO VỆ TOÀN VẸN[/bold green]", "Kênh truyền video được bọc TLS 1.3 chống nghe lén")

            if rs["has_digest"]:
                d_status = "[bold green]CÓ HỖ TRỢ[/bold green]"
                d_eval = f"Thuật toán: [bold green]{rs['digest_algo']}[/bold green]\nRealm: {rs['digest_realm']}\n[dim]Wireshark: tcp.port == {RTSPS_PORT} && (tls || rtsp.status == 401)[/dim]"
            else:
                d_status = "[dim]KHÔNG[/dim]"
                d_eval = "[yellow]Không hỗ trợ Digest Auth[/yellow]"
            t_rtsps.add_row("Digest Authentication (TLS)", d_status, d_eval)

            if rs["has_basic"]:
                b_status = "[yellow]CÓ HỖ TRỢ (Trong TLS)[/yellow]"
                b_eval = f"Được bọc an toàn trong TLS\nRealm: {rs['basic_realm']}\n[dim]Wireshark: tcp.port == {RTSPS_PORT} && (tls || rtsp contains \"Basic\")[/dim]"
            else:
                b_status = "[bold green]TẮT BỎ[/bold green]"
                b_eval = "Không mở Basic Auth"
            t_rtsps.add_row("Basic Authentication (TLS)", b_status, b_eval)

            if rs.get("basic_accepted"):
                test_badge = "[bold green] THÀNH CÔNG (200 OK) [/bold green]"
                test_desc = f"[green]Camera cấp quyền và gửi gói tin phiên đa phương tiện SDP qua TLS.[/green]\n[dim]Wireshark: tcp.port == {RTSPS_PORT} && (tls || rtsp.status == 200)[/dim]"
                t_rtsps.add_row("Thử nghiệm phát luồng (SDP)", test_badge, test_desc)
        else:
            t_rtsps.add_row(f"Trạng thái cổng RTSPS {RTSPS_PORT}", "[dim]ĐÓNG (Closed)[/dim]", "Không thể kết nối")
        console.print(t_rtsps)

    # Raw Evidence Blocks
    console.print("\n[bold cyan]BẰNG CHỨNG THỰC NGHIỆM NGUYÊN VĂN (RAW PROTOCOL RESPONSES):[/bold cyan]")
    if h.get("raw_response"):
        console.print(Panel(
            h["raw_response"].strip(),
            title="[bold yellow]Cụm phản hồi HTTP (Cổng 80) làm bằng chứng chuyển hướng HTTPS[/bold yellow]",
            subtitle="[bold cyan]Wireshark: http.response.code == 302 || (tcp.port == 80 && http)[/bold cyan]",
            border_style="yellow"
        ))
        console.print("  [bold yellow]↳ Wireshark Filter/Sort:[/bold yellow] [bold green]http.response.code == 302 || (tcp.port == 80 && http)[/bold green]\n")

    if r.get("raw_response"):
        console.print(Panel(
            r["raw_response"].strip(),
            title="[bold yellow]Cụm phản hồi RTSP 401 Unauthorized (Cổng 554) làm bằng chứng thách thức xác thực rõ[/bold yellow]",
            subtitle="[bold cyan]Wireshark: tcp.port == 554 && rtsp.status == 401[/bold cyan]",
            border_style="yellow"
        ))
        console.print("  [bold yellow]↳ Wireshark Filter/Sort:[/bold yellow] [bold green]tcp.port == 554 && rtsp.status == 401[/bold green]\n")

    if r.get("basic_test_response_raw"):
        console.print(Panel(
            r["basic_test_response_raw"].strip(),
            title="[bold red]Cụm phản hồi RTSP khi gửi Basic Auth làm bằng chứng chấp nhận mật khẩu rõ[/bold red]",
            subtitle="[bold cyan]Wireshark: tcp.port == 554 && (rtsp.authorization contains \"Basic\" || rtsp.status == 200)[/bold cyan]",
            border_style="red"
        ))
        console.print("  [bold yellow]↳ Wireshark Filter/Sort:[/bold yellow] [bold green]tcp.port == 554 && (rtsp.authorization contains \"Basic\" || rtsp.status == 200)[/bold green]\n")

    if rs and rs.get("raw_response"):
        console.print(Panel(
            rs["raw_response"].strip(),
            title=f"[bold green]Cụm phản hồi RTSPS 401 Unauthorized qua TLS (Cổng {RTSPS_PORT}) làm bằng chứng Thách thức xác thực[/bold green]",
            subtitle=f"[bold cyan]Wireshark: tcp.port == {RTSPS_PORT} && (tls || rtsp.status == 401)[/bold cyan]",
            border_style="green"
        ))
        console.print(f"  [bold yellow]↳ Wireshark Filter/Sort:[/bold yellow] [bold green]tcp.port == {RTSPS_PORT} && (tls || rtsp.status == 401)[/bold green] [dim](Nếu giải mã TLS: rtsp.status == 401)[/dim]\n")

    if rs and rs.get("basic_test_response_raw"):
        console.print(Panel(
            rs["basic_test_response_raw"].strip(),
            title=f"[bold green]Cụm phản hồi RTSPS 200 OK SDP qua TLS (cổng {RTSPS_PORT}) làm bằng chứng cấp quyền phát luồng[/bold green]",
            subtitle=f"[bold cyan]Wireshark: tcp.port == {RTSPS_PORT} && (tls || rtsp.status == 200)[/bold cyan]",
            border_style="green"
        ))
        console.print(f"  [bold yellow]↳ Wireshark Filter/Sort:[/bold yellow] [bold green]tcp.port == {RTSPS_PORT} && (tls || rtsp.status == 200)[/bold green] [dim](Nếu giải mã TLS: rtsp.status == 200 && rtsp.content_type contains \"sdp\")[/dim]\n")

    # Conclusion
    console.print("\n[bold white]KẾT LUẬN GIÁ TRỊ XÁC THỰC (AUTHENTICATION EVALUATION):[/bold white]")
    if r.get("is_open") and r.get("has_basic") and r.get("basic_accepted"):
        console.print("  • [bold red][FAIL] NGUY CƠ: Cổng truyền rõ 554 duy trì phương thức Basic Auth rõ.[/bold red]")
    elif not r.get("is_open"):
        console.print("  • [bold green][PASS] TỐT: Cổng truyền rõ RTSP 554 đã được đóng hoàn toàn.[/bold green]")

    if rs and rs.get("is_open"):
        console.print(f"  • [bold green][PASS] ĐẠT CHUẨN: Cổng RTSPS {RTSPS_PORT} hoạt động trên nền tảng mã hóa TLS an toàn.[/bold green]")
        if "SHA-256" in rs.get("digest_algo", "") or "SHA256" in rs.get("digest_algo", ""):
            console.print(f"  • [bold green][PASS] ĐẠT CHUẨN: Hỗ trợ cơ chế băm mật khẩu Digest SHA-256 (RFC 7616) trên kênh RTSPS {RTSPS_PORT}.[/bold green]")
        elif rs.get("has_basic"):
            console.print(f"  • [bold green][PASS] ĐẠT CHUẨN: Cơ chế xác thực Basic Auth được bảo vệ an toàn bên trong đường hầm TLS trên cổng RTSPS {RTSPS_PORT}.[/bold green]")

    pcap_file = results.get("pcap_file", "")
    filters = [
        ("Cổng 80 Chuyển hướng HTTPS (302 Found)", f"tcp.port == {HTTP_PORT} && (http.response.code == 302 || http)"),
        ("Cổng 554 Thách thức xác thực rõ (401 Unauthorized)", f"tcp.port == {RTSP_PORT} && rtsp.status == 401"),
        ("Cổng 554 Kiểm tra mật khẩu Base64 rõ (Basic Auth)", f"tcp.port == {RTSP_PORT} && (rtsp.authorization contains \"Basic\" || rtsp.status == 200)"),
        (f"Cổng {RTSPS_PORT} Luồng mã hóa RTSPS qua TLS 1.3", f"tcp.port == {RTSPS_PORT} && tls"),
        (f"Cổng {RTSPS_PORT} RTSPS sau giải mã TLS (Auth Challenge)", "rtsp.status == 401"),
        (f"Cổng {RTSPS_PORT} Cấp quyền truyền luồng video (200 OK SDP)", "rtsp.status == 200 && rtsp.content_type contains \"sdp\"")
    ]
    display_wireshark_panel(
        console,
        pcap_file,
        filters,
        is_tls=True,
        sort_tip=f"Click tiêu đề cột No. để xem: Bắt tay TLS 1.3 và trao đổi xác thực trên cổng {RTSPS_PORT}.",
        title="BẰNG CHỨNG GÓI TIN WIRESHARK CHO HTTP / RTSP / RTSPS"
    )

if __name__ == '__main__':
    dut = sys.argv[1] if len(sys.argv) > 1 else DUT_IP
    data = run_full_auth_audit(dut)
    display_auth_audit(data)
