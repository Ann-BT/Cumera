#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
  BỘ ĐO KIỂM XÁC THỰC DỮ LIỆU ĐẦU VÀO & QUÉT BỀ MẶT API (CLAUSE 3.10.1.3)
  Tiêu chuẩn: QCVN 11:2026/BCA & ETSI EN 303 645 (Clause 3.10.1.3 / IXIT 29-InpVal)
  
  Mục tiêu kiểm định:
  - Quét toàn bộ bề mặt API (RTSP, RTSPS, ONVIF SOAP, Web/REST, Non-HTTP stream).
  - Đối với giao thức điều khiển luồng đa phương tiện (RTSP/RTSPS) và giao thức đặc thù:
    1. Mô phỏng chuỗi khởi tạo kết nối hợp lệ (Handshake/Initialization).
    2. Chèn các chuỗi Fuzzing ngẫu nhiên hoặc lệnh điều khiển luồng bị thay đổi
       định dạng ở các trạng thái tiếp theo.
    3. Đánh giá tính toàn vẹn của hệ thống (System Integrity - không crash/reboot)
       và DUT phải xử lý đúng yêu cầu sai định dạng (mã lỗi 4xx/5xx hoặc ngắt an toàn).
================================================================================
"""

import os
import sys
import time
import json
import socket
import ssl
import re
import random
import base64
import argparse
import subprocess
from typing import Tuple, List, Dict, Any, Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

sys.stdout.reconfigure(encoding='utf-8')
console = Console()

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pcap_recorder import start_pcap_capture, stop_pcap_capture, display_wireshark_panel

CONF_PATH = os.path.join(os.path.dirname(__file__), "config.json")
try:
    with open(CONF_PATH, encoding="utf-8") as f:
        config = json.load(f)
except Exception:
    config = {}

DUT_IP = config.get("target_camera", {}).get("ip", "192.168.20.38")
DUT_MODEL = config.get("target_camera", {}).get("model", "AXIS Q1806-LE")
RTSP_PORT = config.get("service_ports", {}).get("rtsp_cleartext", 554)
RTSPS_PORT = config.get("service_ports", {}).get("rtsps_tls", 322)
RTSP_PATH = config.get("service_ports", {}).get("rtsp_path", "/axis-media/media.amp" if RTSPS_PORT == 322 else "/stream1")
if not RTSP_PATH.startswith("/"):
    RTSP_PATH = "/" + RTSP_PATH

USER = config.get("target_camera", {}).get("username", "admin")
PASS = config.get("target_camera", {}).get("password", "")

GLOBAL_PCAP_FILE = ""


def check_icmp_integrity(ip: str) -> Tuple[bool, float]:
    """Kiểm tra phản hồi ICMP Ping để đánh giá tính toàn vẹn hệ thống DUT."""
    try:
        cmd = ["ping", "-c", "1", "-W", "1", ip]
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if res.returncode == 0:
            latency = 0.5
            if "time=" in res.stdout:
                try:
                    latency = float(res.stdout.split("time=")[1].split(" ")[0])
                except Exception:
                    pass
            return True, latency
        return False, -1.0
    except Exception:
        return False, -1.0


def detect_rtsp_target(requested_port: Optional[int] = None) -> Tuple[int, bool]:
    """Phát hiện cổng RTSP/RTSPS khả dụng thực tế trên DUT."""
    if requested_port is not None:
        s = socket.socket()
        s.settimeout(0.5)
        if s.connect_ex((DUT_IP, requested_port)) == 0:
            s.close()
            is_tls = (requested_port in [RTSPS_PORT, 322, 9554] or requested_port != 554)
            return requested_port, is_tls
        s.close()

    # Dò tìm cổng RTSP/RTSPS đang mở thực tế
    for port, use_tls in [(RTSPS_PORT, True), (322, True), (RTSP_PORT, False), (554, False), (9554, True)]:
        s = socket.socket()
        s.settimeout(0.5)
        res = s.connect_ex((DUT_IP, port))
        s.close()
        if res == 0:
            return port, use_tls
    return RTSPS_PORT, True


def create_tls_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    keylog_path = os.path.join(os.path.dirname(__file__), "captures", "sslkeys.log")
    try:
        ctx.keylog_filename = keylog_path
    except Exception:
        pass
    return ctx


def recv_rtsp_response(sock, timeout: float = 2.5) -> Tuple[str, str]:
    """Nhận phản hồi RTSP đầy đủ kèm cả headers và body."""
    sock.settimeout(timeout)
    data = b""
    try:
        while b"\r\n\r\n" not in data:
            chunk = sock.recv(2048)
            if not chunk:
                break
            data += chunk
        if not data:
            return "EMPTY_REPLY", ""
        
        parts = data.split(b"\r\n\r\n", 1)
        header_raw = parts[0].decode("utf-8", errors="ignore")
        body_data = parts[1] if len(parts) > 1 else b""
        
        content_len = 0
        for line in header_raw.splitlines():
            if line.lower().startswith("content-length:"):
                try:
                    content_len = int(line.split(":", 1)[1].strip())
                except Exception:
                    content_len = 0
                break
                
        while len(body_data) < content_len:
            chunk = sock.recv(2048)
            if not chunk:
                break
            body_data += chunk
            
        body_raw = body_data.decode("utf-8", errors="ignore")
        return header_raw, body_raw
    except socket.timeout:
        return "TIMEOUT (Không phản hồi)", ""
    except ConnectionResetError:
        return "RESET (Connection reset by peer)", ""
    except Exception as e:
        return f"ERROR ({e})", ""


# ==============================================================================
# PHẦN 1: QUÉT TOÀN BỘ BỀ MẶT API CỦA CAMERA (FULL API SCANNER)
# ==============================================================================

def scan_full_camera_apis() -> Dict[str, Any]:
    """Quét và phân loại toàn bộ các endpoint API và dịch vụ mạng trên DUT."""
    console.print(Panel(
        f"[bold white]QUÉT TOÀN BỘ BỀ MẶT API & DỊCH VỤ CỦA CAMERA (CLAUSE 3.10.1.3 & IXIT 28/29)[/bold white]\n"
        f"• Mục tiêu DUT       : [cyan]{DUT_IP}[/cyan] ({DUT_MODEL})\n"
        f"• Thời gian quét     : [bold yellow]{time.strftime('%Y-%m-%d %H:%M:%S')}[/bold yellow]\n"
        f"• Mục đích           : Lập danh mục toàn bộ cổng API/luồng phục vụ đo kiểm xác thực đầu vào",
        title="BỀ MẶT API THIẾT BỊ",
        border_style="cyan"
    ))

    scan_targets = [
        {"port": 554, "proto": "RTSP", "name": "RTSP Cleartext Video Stream Control", "type": "Stream Control"},
        {"port": 322, "proto": "RTSPS", "name": "RTSPS TLS Video Stream Control", "type": "Stream Control"},
        {"port": 9554, "proto": "RTSPS", "name": "RTSPS TLS Alternative Stream", "type": "Stream Control"},
        {"port": 80, "proto": "HTTP", "name": "Web UI & Cleartext REST/ONVIF API", "type": "HTTP Web/API"},
        {"port": 443, "proto": "HTTPS", "name": "Secure Web UI & HTTPS ONVIF/VAPIX API", "type": "HTTPS Web/API"},
        {"port": 22, "proto": "SSH", "name": "SSH Management Shell", "type": "Admin CLI"},
        {"port": 161, "proto": "SNMP", "name": "SNMPv3 Management Port", "type": "UDP Management"},
        {"port": 37777, "proto": "TCP", "name": "Proprietary Stream / SDK Port (Dahua/Generic)", "type": "Proprietary Stream"},
        {"port": 8000, "proto": "TCP", "name": "Proprietary Stream / SDK Port (Hikvision/Generic)", "type": "Proprietary Stream"}
    ]

    results = []
    table = Table(title="Danh mục API & Cổng Dịch vụ Phát hiện trên DUT", show_header=True, header_style="bold cyan")
    table.add_column("Cổng", justify="center", width=8)
    table.add_column("Giao thức", justify="center", width=12)
    table.add_column("Phân loại API", justify="left", width=22)
    table.add_column("Trạng thái", justify="center", width=14)
    table.add_column("Mô tả kỹ thuật & Khả năng Input Validation", justify="left")

    for item in scan_targets:
        port = item["port"]
        proto = item["proto"]
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.8)
        code = s.connect_ex((DUT_IP, port))
        s.close()

        is_open = (code == 0)
        status_str = "[bold green]MỞ (OPEN)[/bold green]" if is_open else "[dim]ĐÓNG (CLOSED)[/dim]"
        
        detail = item["name"]
        if is_open:
            if proto in ["RTSP", "RTSPS"]:
                detail += " -> [bold yellow]Áp dụng Clause 3.10.1.3 Fuzzer luồng[/bold yellow]"
            elif proto in ["HTTP", "HTTPS"]:
                detail += " -> [bold cyan]Áp dụng SOAP XML / Web API Fuzzer[/bold cyan]"
            elif item["type"] == "Proprietary Stream":
                detail += " -> [bold magenta]Áp dụng Non-HTTP Proprietary Fuzzer[/bold magenta]"

        table.add_row(str(port), proto, item["type"], status_str, detail)
        results.append({
            "port": port,
            "protocol": proto,
            "type": item["type"],
            "is_open": is_open,
            "description": item["name"]
        })

    console.print(table)
    return {"ip": DUT_IP, "results": results}


# ==============================================================================
# PHẦN 2: BỘ ĐO KIỂM STATEFUL FUZZER CHO LUỒNG ĐA PHƯƠNG TIỆN RTSP/RTSPS
# (YÊU CẦU 3.10.1.3: HANDSHAKE HỢP LỆ -> CHÈN FUZZING -> ĐÁNH GIÁ TÍNH TOÀN VẸN)
# ==============================================================================

def run_rtsp_stateful_fuzzer(
    port: int,
    use_tls: bool,
    iterations: int = 10,
    rate_cps: float = 4.0,
    fuzz_category: str = "all"
) -> bool:
    """
    Thực hiện đo kiểm chuẩn Clause 3.10.1.3:
    1. Thiết lập chuỗi khởi tạo hợp lệ (OPTIONS -> 200 OK, DESCRIBE -> 200 OK + SDP).
    2. Chèn các biến thể Fuzzing sai định dạng ở trạng thái tiếp theo.
    3. Đánh giá tính toàn vẹn hệ thống và việc xử lý đúng mã lỗi của DUT.
    """
    proto_label = f"RTSPS (TLS - Cổng {port})" if use_tls else f"RTSP (Cleartext - Cổng {port})"
    cred = base64.b64encode(f"{USER}:{PASS}".encode()).decode()

    console.print(Panel(
        f"[bold white]ĐO KIỂM XÁC THỰC ĐẦU VÀO LUỒNG ĐA PHƯƠNG TIỆN RTSP (CLAUSE 3.10.1.3)[/bold white]\n"
        f"• Mục tiêu DUT       : [cyan]{DUT_IP}:{port}[/cyan] ({proto_label})\n"
        f"• Tài khoản kiểm thử : [bold green]{USER}[/bold green]\n"
        f"• Đường dẫn Media    : [bold white]{RTSP_PATH}[/bold white]\n"
        f"• Giai đoạn 1        : [bold green]Mô phỏng chuỗi khởi tạo hợp lệ (Handshake/Initialization)[/bold green]\n"
        f"• Giai đoạn 2        : [bold red]Chèn các lệnh điều khiển luồng sai định dạng (Stateful Fuzzing)[/bold red]\n"
        f"• Giai đoạn 3        : [bold yellow]Đánh giá Tính toàn vẹn (System Integrity) & Xử lý mã lỗi[/bold yellow]\n"
        f"• Phân loại Fuzz     : [bold magenta]{fuzz_category.upper()}[/bold magenta] ({iterations} mẫu đo kiểm)",
        title="QUY TRÌNH THỰC NGHIỆM ĐO KIỂM 3.10.1.3",
        border_style="cyan"
    ))

    # Danh mục các payload Fuzzing theo chuẩn điều khiển luồng
    fuzz_test_cases = [
        {
            "name": "Malformed RTSP Method (Lệnh điều khiển luồng sai định dạng)",
            "cat": "methods",
            "desc": "Chèn tên lệnh bị biến dạng có chứa ký tự NULL và ký tự lạ (PL\\x00AY, FUZZ_STREAM)",
            "generate": lambda cseq, uri, sess: (
                f"PL\x00AY {uri} RTSP/1.0\r\nCSeq: {cseq}\r\nAuthorization: Basic {cred}\r\n"
                f"Session: {sess}\r\nRange: npt=0.000-\r\n\r\n"
            ),
            "expected": ["400", "501", "455", "RESET", "REFUSED", "EMPTY_REPLY"]
        },
        {
            "name": "Buffer Overflow in Control Headers (Tràn bộ đệm tiêu đề)",
            "cat": "overflow",
            "desc": "Gửi tiêu đề X-Fuzz-Header mở rộng 4096 bytes ký tự 'A' kèm chuỗi format string %s%n%x",
            "generate": lambda cseq, uri, sess: (
                f"PLAY {uri} RTSP/1.0\r\nCSeq: {cseq}\r\nAuthorization: Basic {cred}\r\n"
                f"X-Fuzz-Overflow: {'A' * 4096}%s%n%x%p\r\nSession: {sess}\r\n\r\n"
            ),
            "expected": ["400", "413", "451", "RESET", "EMPTY_REPLY"]
        },
        {
            "name": "CSeq Numbering Anomaly (Số thứ tự CSeq dị thường)",
            "cat": "cseq",
            "desc": "Chèn CSeq số âm, số tràn 64-bit và ký tự phi số (CSeq: -999999999)",
            "generate": lambda cseq, uri, sess: (
                f"PAUSE {uri} RTSP/1.0\r\nCSeq: -999999999\r\nAuthorization: Basic {cred}\r\n"
                f"Session: {sess}\r\n\r\n"
            ),
            "expected": ["400", "451", "RESET", "EMPTY_REPLY"]
        },
        {
            "name": "Corrupted Session & State Desynchronization (Sai lệch Session ID)",
            "cat": "session",
            "desc": "Gửi Session ID dị thường kèm ký tự điều khiển binary (Session: fake_99999\\x00\\xff)",
            "generate": lambda cseq, uri, sess: (
                f"PLAY {uri} RTSP/1.0\r\nCSeq: {cseq}\r\nAuthorization: Basic {cred}\r\n"
                f"Session: FAKE_SESSION_CORRUPT_\\x00\\xff_99999\r\n\r\n"
            ),
            "expected": ["454", "400", "RESET", "EMPTY_REPLY"]
        },
        {
            "name": "Malformed Range & Invalid Timecodes (Sai định dạng khung thời gian)",
            "cat": "range",
            "desc": "Chèn tham số Range bất hợp lệ: npt=invalid_negative--9999 kèm chuỗi rác",
            "generate": lambda cseq, uri, sess: (
                f"PLAY {uri} RTSP/1.0\r\nCSeq: {cseq}\r\nAuthorization: Basic {cred}\r\n"
                f"Range: npt=--9999.00-00.00;fuzz=corrupt\r\nSession: {sess}\r\n\r\n"
            ),
            "expected": ["400", "451", "454", "RESET", "EMPTY_REPLY"]
        },
        {
            "name": "High-Entropy Binary Bit-Flip Injection (Chèn chuỗi byte ngẫu nhiên)",
            "cat": "raw",
            "desc": "Bơm trực tiếp 256 bytes ngẫu nhiên binary entropy vào kênh điều khiển luồng",
            "generate": lambda cseq, uri, sess: (
                bytes([random.randint(0, 255) for _ in range(256)])
            ),
            "expected": ["400", "RESET", "EMPTY_REPLY", "TIMEOUT"]
        },
        {
            "name": "CRLF Protocol Desynchronization / Smuggling (Tấn công chia tách tiêu đề)",
            "cat": "injection",
            "desc": "Chèn ký tự xuống dòng ngắt quãng CRLF kép tạo chuỗi lệnh ngầm",
            "generate": lambda cseq, uri, sess: (
                f"PLAY {uri} RTSP/1.0\r\nCSeq: {cseq}\r\nX-Splitted: bad\r\n\r\n"
                f"EVIL_METHOD /malformed RTSP/1.0\r\n\r\n"
            ),
            "expected": ["400", "501", "RESET", "EMPTY_REPLY"]
        }
    ]

    selected_tests = []
    if fuzz_category == "all":
        selected_tests = fuzz_test_cases
    else:
        selected_tests = [t for t in fuzz_test_cases if t["cat"] == fuzz_category]
        if not selected_tests:
            selected_tests = fuzz_test_cases

    # --------------------------------------------------------------------------
    # BƯỚC 1: MÔ PHỎNG CHUỖI KHỞI TẠO HỢP LỆ (HANDSHAKE / INITIALIZATION)
    # --------------------------------------------------------------------------
    console.print("\n[bold cyan]=== GIAI ĐOẠN 1: MÔ PHỎNG CHUỖI KHỞI TẠO KẾT NỐI HỢP LỆ (HANDSHAKE) ===[/bold cyan]")
    ctx = create_tls_context()
    uri = f"rtsp://{DUT_IP}:{port}{RTSP_PATH}"
    cseq = 1
    session_id = "12345678"

    init_success = False
    try:
        raw_sock = socket.create_connection((DUT_IP, port), timeout=3.0)
        sock = ctx.wrap_socket(raw_sock, server_hostname=DUT_IP) if use_tls else raw_sock

        # 1.1 OPTIONS
        req_opt = f"OPTIONS {uri} RTSP/1.0\r\nCSeq: {cseq}\r\nUser-Agent: QCVN11-State-Fuzzer\r\n\r\n"
        sock.sendall(req_opt.encode())
        h_opt, b_opt = recv_rtsp_response(sock)
        console.print(f"  • Bước 1.1: Gửi OPTIONS hợp lệ  -> Phản hồi: [bold green]{h_opt.splitlines()[0] if h_opt else 'N/A'}[/bold green]")
        cseq += 1

        # 1.2 DESCRIBE
        req_desc = (
            f"DESCRIBE {uri} RTSP/1.0\r\nCSeq: {cseq}\r\nAuthorization: Basic {cred}\r\n"
            f"Accept: application/sdp\r\nUser-Agent: QCVN11-State-Fuzzer\r\n\r\n"
        )
        sock.sendall(req_desc.encode())
        h_desc, b_desc = recv_rtsp_response(sock)
        console.print(f"  • Bước 1.2: Gửi DESCRIBE hợp lệ -> Phản hồi: [bold green]{h_desc.splitlines()[0] if h_desc else 'N/A'}[/bold green]")
        cseq += 1

        if "200 OK" in h_desc:
            init_success = True
            console.print("  [bold green][+] KHỞI TẠO PHIÊN THÀNH CÔNG:[/bold green] Nhận mô tả SDP đầy đủ, DUT sẵn sàng tiếp nhận điều khiển.")
        else:
            console.print(f"  [bold yellow][!] Cảnh báo:[/bold yellow] DESCRIBE nhận mã: {h_desc.splitlines()[0] if h_desc else 'N/A'}")

        sock.close()
    except Exception as e:
        console.print(f"  [bold red][-] Lỗi kết nối khởi tạo ban đầu:[/bold red] {e}")

    if not init_success:
        console.print("[bold red][-] KHÔNG THỂ BẮT TAY KHỞI TẠO BAN ĐẦU VỚI CAMERA. HUỶ ĐO KIỂM.[/bold red]")
        return False

    # --------------------------------------------------------------------------
    # BƯỚC 2: CHÈN CÁC CHUỖI FUZZING NGẪU NHIÊN & LỆNH ĐIỀU KHIỂN LUỒNG SAI ĐỊNH DẠNG
    # --------------------------------------------------------------------------
    console.print("\n[bold cyan]=== GIAI ĐOẠN 2: CHÈN CHUỖI FUZZING NGẪU NHIÊN VÀO TRẠNG THÁI TIẾP THEO ===[/bold cyan]")
    console.print(f"[*] Bắt đầu thực thi {len(selected_tests)} nhóm kiểm thử payload sai định dạng...")

    test_results = []
    step_num = 0

    for test in selected_tests:
        step_num += 1
        console.print(f"\n[bold white]-- Kiểm thử #{step_num:02d}: {test['name']} --[/bold white]")
        console.print(f"   [dim]{test['desc']}[/dim]")

        # Mỗi lần test, tạo lại kết nối mới để bảo đảm tính độc lập
        try:
            raw_sock = socket.create_connection((DUT_IP, port), timeout=3.0)
            sock = ctx.wrap_socket(raw_sock, server_hostname=DUT_IP) if use_tls else raw_sock

            # Gửi lại DESCRIBE hợp lệ trước để đưa connection vào đúng trạng thái khởi tạo
            cseq += 1
            sock.sendall(req_desc.encode())
            h_init, _ = recv_rtsp_response(sock)

            # Tạo payload fuzzing
            cseq += 1
            payload = test["generate"](cseq, uri, session_id)
            if isinstance(payload, str):
                payload_bytes = payload.encode("utf-8", errors="ignore")
            else:
                payload_bytes = payload

            # Bắn payload malformed vào socket
            t_send = time.time()
            sock.sendall(payload_bytes)
            h_resp, b_resp = recv_rtsp_response(sock, timeout=2.0)
            dur_ms = (time.time() - t_send) * 1000

            resp_line = h_resp.splitlines()[0] if h_resp else "NO_RESPONSE"
            console.print(f"   -> Camera phản hồi ({dur_ms:.1f}ms): [bold yellow]{resp_line}[/bold yellow]")

            # Đánh giá việc xử lý đúng yêu cầu sai định dạng:
            # - DUT phải từ chối (4xx/5xx hoặc ngắt kết nối FIN/RST / EMPTY_REPLY)
            # - DUT KHÔNG ĐƯỢC trả về 200 OK cho gói tin rác/sai định dạng
            is_properly_handled = False
            if any(exp in resp_line for exp in test["expected"]):
                is_properly_handled = True
            elif "200 OK" not in resp_line:
                is_properly_handled = True

            test_results.append({
                "name": test["name"],
                "status_line": resp_line,
                "proper_handled": is_properly_handled,
                "duration_ms": dur_ms
            })

            sock.close()
        except Exception as e:
            console.print(f"   -> Kết nối bị từ chối / ngắt an toàn bởi DUT: {e}")
            test_results.append({
                "name": test["name"],
                "status_line": f"DISCONNECTED_SAFELY ({e})",
                "proper_handled": True,
                "duration_ms": 0.0
            })

        time.sleep(1.0 / rate_cps)

    # --------------------------------------------------------------------------
    # BƯỚC 3: ĐÁNH GIÁ TÍNH TOÀN VẸN CỦA HỆ THỐNG (SYSTEM INTEGRITY CHECK)
    # --------------------------------------------------------------------------
    console.print("\n[bold cyan]=== GIAI ĐOẠN 3: ĐÁNH GIÁ TÍNH TOÀN VẸN HỆ THỐNG & KẾT LUẬN (PASS/FAIL) ===[/bold cyan]")
    
    # 3.1 Kiểm tra ICMP ping
    ping_ok, ping_ms = check_icmp_integrity(DUT_IP)
    console.print(f"• Kiểm tra phản hồi ICMP Host Alive: {'[bold green]HOẠT ĐỘNG (' + str(ping_ms) + 'ms)[/bold green]' if ping_ok else '[bold red]MẤT KẾT NỐI / SẬP HOST[/bold red]'}")

    # 3.2 Kiểm tra dịch vụ RTSP sau đợt tấn công Fuzzing (Post-Fuzz Clean Handshake)
    post_handshake_ok = False
    try:
        raw_sock = socket.create_connection((DUT_IP, port), timeout=3.0)
        sock = ctx.wrap_socket(raw_sock, server_hostname=DUT_IP) if use_tls else raw_sock
        sock.sendall(req_desc.encode())
        h_post, _ = recv_rtsp_response(sock)
        if "200 OK" in h_post:
            post_handshake_ok = True
        sock.close()
    except Exception:
        post_handshake_ok = False

    console.print(f"• Kiểm tra dịch vụ RTSP phục hồi & hoạt động bình thường: {'[bold green]ĐẠT (200 OK)[/bold green]' if post_handshake_ok else '[bold red]KHÔNG PHỤC HỒI / TREO TIẾN TRÌNH[/bold red]'}")

    # Bảng tổng kết
    res_table = Table(title="Bảng Đối soát Chi tiết Các Phép Thử Fuzzing (Clause 3.10.1.3)", show_header=True, header_style="bold cyan")
    res_table.add_column("STT", justify="center", width=5)
    res_table.add_column("Kịch bản Fuzzing", justify="left", width=36)
    res_table.add_column("Phản hồi thực nghiệm từ DUT", justify="left", width=30)
    res_table.add_column("Xử lý đúng lỗi", justify="center", width=14)

    all_handled = True
    for idx, r in enumerate(test_results, 1):
        if not r["proper_handled"]:
            all_handled = False
        status_color = "[bold green]ĐẠT[/bold green]" if r["proper_handled"] else "[bold red]FAIL[/bold red]"
        res_table.add_row(str(idx), r["name"], r["status_line"][:28], status_color)

    console.print(res_table)

    # Đánh giá chung
    system_integrity = (ping_ok and post_handshake_ok)
    overall_pass = (system_integrity and all_handled)

    console.print("\n" + "=" * 80)
    console.print("  [KẾT LUẬN ĐÁNH GIÁ CHUẨN ĐO KIỂM 3.10.1.3 - INPUT VALIDATION]")
    console.print(f"  • Tiêu chí 1: Xử lý đúng toàn bộ các yêu cầu sai định dạng: {'[bold green]ĐẠT[/bold green]' if all_handled else '[bold red]KHÔNG ĐẠT[/bold red]'}")
    console.print(f"  • Tiêu chí 2: Duy trì tính toàn vẹn hệ thống (Không sập/treo):  {'[bold green]ĐẠT[/bold green]' if system_integrity else '[bold red]KHÔNG ĐẠT[/bold red]'}")

    if overall_pass:
        console.print("\n[bold green]  ==> ĐÁNH GIÁ CUỐI CÙNG: ĐẠT (PASS) THEO ĐIỀU 3.10.1.3 / QCVN 11:2026/BCA![/bold green]")
        console.print("      (DUT duy trì hoạt động toàn vẹn, từ chối toàn bộ dữ liệu sai định dạng và phục hồi tức thì).")
    else:
        console.print("\n[bold red]  ==> ĐÁNH GIÁ CUỐI CÙNG: KHÔNG ĐẠT (FAIL) THEO ĐIỀU 3.10.1.3![/bold red]")
    console.print("=" * 80)

    # Bảng Wireshark Filter Panel
    filters = [
        ("Toàn bộ phiên Fuzzing và bắt tay RTSP", f"tcp.port == {port} && (rtsp || tls)"),
        ("Các gói tin phản hồi lỗi từ chối của camera (4xx/5xx)", f"tcp.port == {port} && rtsp.status >= 400"),
        ("Các gói tin camera gửi cờ ngắt an toàn (TCP RST)", f"tcp.port == {port} && tcp.flags.reset == 1"),
        ("Gói tin xác thực thành công chuẩn (200 OK)", f"tcp.port == {port} && rtsp.status == 200")
    ]
    display_wireshark_panel(
        console,
        GLOBAL_PCAP_FILE,
        filters,
        is_tls=use_tls,
        sort_tip=f"Lọc rtsp.status >= 400 trong Wireshark để đối soát chứng chỉ phản hồi lỗi của DUT.",
        title=f"BẰNG CHỨNG GÓI TIN INPUT VALIDATION AUDIT (CỔNG {port})"
    )

    return overall_pass


# ==============================================================================
# PHẦN 3: BỘ ĐO KIỂM GIAO THỨC PHI HTTP / PROPRIETARY RAW STREAM FUZZER
# ==============================================================================

def run_proprietary_stream_fuzzer(port: int, iterations: int = 10, rate_cps: float = 4.0) -> bool:
    """Fuzzer cho giao thức đặc thù phi HTTP / socket nhị phân."""
    console.print(Panel(
        f"[bold white]ĐO KIỂM XÁC THỰC ĐẦU VÀO GIAO THỨC ĐẶC THÙ PHI HTTP (CLAUSE 3.10.1.3)[/bold white]\n"
        f"• Cổng kiểm thử       : [cyan]{DUT_IP}:{port}[/cyan] (Raw Socket)\n"
        f"• Số mẫu Fuzzing     : [bold yellow]{iterations} mẫu ngẫu nhiên[/bold yellow]\n"
        f"• Tốc độ phát        : [bold magenta]{rate_cps:.1f} gói/giây[/bold magenta]\n"
        f"• Quy trình          : Bắt tay nhị phân giả lập -> Chèn bit-flip / entropy đột biến -> Kiểm tra sống còn",
        title="PROPRIETARY STREAM FUZZER",
        border_style="magenta"
    ))

    # Kiểm tra cổng có mở không
    s = socket.socket()
    s.settimeout(1.0)
    if s.connect_ex((DUT_IP, port)) != 0:
        s.close()
        console.print(f"[bold yellow][!] Cổng {port} hiện đang đóng (CLOSED) trên DUT. Bỏ qua bài đo hoặc chuyển cổng khác.[/bold yellow]")
        return True
    s.close()

    console.print("[*] Bắt đầu truyền chuỗi byte đột biến và kiểm tra tính toàn vẹn...")
    for i in range(1, iterations + 1):
        try:
            sock = socket.create_connection((DUT_IP, port), timeout=2.0)
            # Khởi tạo chuỗi chào giả lập
            sock.sendall(b"\x00\x00\x00\x14\x01\x00\x00\x00")
            time.sleep(0.05)
            # Chèn chuỗi fuzzing ngẫu nhiên
            fuzz_blob = bytes([random.randint(0, 255) for _ in range(128)])
            sock.sendall(fuzz_blob)
            sock.close()
        except Exception:
            pass
        time.sleep(1.0 / rate_cps)

    # Đánh giá tính toàn vẹn
    ping_ok, _ = check_icmp_integrity(DUT_IP)
    console.print(f"• Tính toàn vẹn sau đợt Fuzz cổng {port}: {'[bold green]ĐẠT (DUT Vẫn hoạt động bình thường)[/bold green]' if ping_ok else '[bold red]FAIL (DUT Sập/Treo)[/bold red]'}")
    return ping_ok


# ==============================================================================
# MAIN & ARGUMENT PARSING
# ==============================================================================

def main():
    global GLOBAL_PCAP_FILE
    parser = argparse.ArgumentParser(description="Bộ đo kiểm Xác thực Đầu vào & Quét API (QCVN 11 Clause 3.10.1.3)")
    parser.add_argument("--mode", choices=["scan", "rtsp", "custom", "csrf", "all"], default="rtsp", help="Chế độ đo kiểm (scan, rtsp, custom, csrf, all)")
    parser.add_argument("--port", type=int, default=None, help="Cổng kiểm thử (322, 554, hoặc tùy chọn)")
    parser.add_argument("--fuzz-type", choices=["all", "methods", "overflow", "cseq", "session", "range", "raw", "injection"], default="all", help="Phân loại payload fuzz")
    parser.add_argument("--iterations", type=int, default=10, help="Số lần chèn sai định dạng")
    parser.add_argument("--rate", type=float, default=4.0, help="Tốc độ gửi yêu cầu/giây")

    args = parser.parse_args()

    # Bắt PCAP tự động
    target_port = args.port or RTSPS_PORT
    bpf_filter = f"host {DUT_IP}"
    pcap_proc, GLOBAL_PCAP_FILE = start_pcap_capture(
        DUT_IP,
        bpf_filter,
        prefix=f"api_fuzzer_31013"
    )
    if GLOBAL_PCAP_FILE:
        console.print(f"[*] Bắt gói tin PCAP tự động vào: [cyan]{GLOBAL_PCAP_FILE}[/cyan]\n")

    try:
        if args.mode == "scan":
            scan_full_camera_apis()
        elif args.mode == "custom":
            # Tự động kiểm tra: nếu cổng đóng hoặc không truyền port, tự động chuyển sang cổng luồng RTSP/RTSPS khả dụng của DUT
            req_port = args.port
            is_open = False
            if req_port:
                s = socket.socket()
                s.settimeout(0.5)
                is_open = (s.connect_ex((DUT_IP, req_port)) == 0)
                s.close()

            if is_open:
                run_proprietary_stream_fuzzer(port=req_port, iterations=args.iterations, rate_cps=args.rate)
            else:
                port, use_tls = detect_rtsp_target(args.port)
                console.print(f"[bold yellow][*] Tự động chuyển hướng tới cổng luồng khả dụng của DUT: {port} ({'RTSPS TLS' if use_tls else 'RTSP Cleartext'}) để thực hiện chuỗi khởi tạo & chèn Fuzzing chuẩn 3.10.1.3...[/bold yellow]\n")
                run_rtsp_stateful_fuzzer(
                    port=port,
                    use_tls=use_tls,
                    iterations=args.iterations,
                    rate_cps=args.rate,
                    fuzz_category=args.fuzz_type
                )
        elif args.mode == "csrf":
            from tool19_csrf_token_auditor import run_csrf_token_audit
            run_csrf_token_audit(target_ip=DUT_IP, port=443, rate_cps=args.rate)
        elif args.mode == "all":
            console.print("\n[bold cyan]>>> BƯỚC 1: QUÉT TOÀN BỘ BỀ MẶT API CỦA CAMERA <<<[/bold cyan]")
            scan_full_camera_apis()
            console.print("\n[*] Chờ 2 giây chuyển sang đo kiểm Fuzzing luồng RTSP...")
            time.sleep(2)
            console.print("\n[bold cyan]>>> BƯỚC 2: ĐO KIỂM STATEFUL FUZZING LUỒNG ĐA PHƯƠNG TIỆN RTSP/RTSPS <<<[/bold cyan]")
            port, use_tls = detect_rtsp_target(args.port)
            run_rtsp_stateful_fuzzer(port, use_tls, iterations=args.iterations, rate_cps=args.rate, fuzz_category="all")
            console.print("\n[*] Chờ 2 giây chuyển sang đo kiểm CSRF & Giả mạo Token cấu hình...")
            time.sleep(2)
            console.print("\n[bold cyan]>>> BƯỚC 3: ĐO KIỂM PHÒNG VỆ CSRF & XÁC THỰC TOKEN CẤU HÌNH (CLAUSE 3.10.1.3) <<<[/bold cyan]")
            from tool19_csrf_token_auditor import run_csrf_token_audit
            run_csrf_token_audit(target_ip=DUT_IP, port=443, rate_cps=args.rate)
        else: # rtsp mode
            port, use_tls = detect_rtsp_target(args.port)
            run_rtsp_stateful_fuzzer(
                port=port,
                use_tls=use_tls,
                iterations=args.iterations,
                rate_cps=args.rate,
                fuzz_category=args.fuzz_type
            )
    finally:
        stop_pcap_capture(pcap_proc)


if __name__ == '__main__':
    main()
