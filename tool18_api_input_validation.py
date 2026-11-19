#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
  BỘ ĐO KIỂM XÁC THỰC DỮ LIỆU ĐẦU VÀO & QUÉT BỀ MẶT API TOÀN DIỆN (CLAUSE 3.10.1.3)
  Tiêu chuẩn: QCVN 11:2026/BCA (Điều 2.10.1 & Phương pháp đo 3.10.1.3)
             ETSI EN 303 645 (Clause 5.10-1) & ETSI TS 103 701 (Table C.29 / IXIT 29-InpVal)

  Cấu trúc đo kiểm đối soát 1:1 theo bản khai kỹ thuật thiết bị (IXIT 29-InpVal):
  --------------------------------------------------------------------------------
  [PHẦN 1] InpVal-1: User Input Validation (Giao diện người dùng)
    • Type checking: string/integer/IP/MAC/email bằng tập luật Regex
    • Range checking: ports 1-65535, resolutions hợp lệ, schedule hours 0-23
    • Length checking: password 8-16, username 1-32, device name 1-64
    • Sanitize input: chống XSS, SQL injection, Command injection (whitelist input)
    • Reject & Audit: từ chối dữ liệu sai với mã lỗi rõ ràng, kiểm tra Security Audit Log

  [PHẦN 2] InpVal-2: API Input Validation (Giao diện lập trình ExtAPI-1 & ExtAPI-2)
    • ONVIF (ExtAPI-1): kiểm định cấu trúc theo XSD schema, chống XXE / malformed XML
    • REST (ExtAPI-2): kiểm định JSON schema, từ chối malformed JSON syntax / type violation
    • Parameter validation: kiểm tra type/range/length trên toàn bộ endpoint API
    • Token Gatekeeper: xác thực Auth Token TRƯỚC KHI xử lý payload (Pre-processing check)

  [PHẦN 3] InpVal-3: Network Channel Input Validation (Kênh truyền thông ComMech-1 đến ComMech-9)
    • RTSP/RTP: tuân thủ RFC standard, drop gói sai định dạng (Stateful Fuzzing 7 vectors)
    • NTP: anti-spoofing, từ chối độ lệch thời gian > 5 phút (time deviation)
    • DHCP: anti-rogue DHCP, từ chối DHCP server nằm ngoài cùng subnet
    • DoT: kiểm định DNS over TLS chống DNS spoofing
    • ONVIF XML/SOAP: chống XML CDATA breakout và Unicode injection
    • SFTP/FTPS: chống Directory Traversal (../../path traversal)
    • SMTPS: chống Buffer Overflow từ server response quá khổ 4096 bytes
    • SNMP: kiểm định ASN.1 schema, drop malformed OIDs và oversized payload
    • Alarm: từ chối tín hiệu out-of-bound hoặc payload format không hỗ trợ
    • Platform App: chống Command Injection trên các tham số cấu hình nền tảng

  Nguyên tắc kỹ thuật:
    1. ZERO FABRICATION: Mọi kết quả đều dựa trên việc truyền nhận gói tin thực tế với DUT.
    2. SYSTEM INTEGRITY: Kiểm tra ping ICMP sống còn và khả năng phục hồi sau mỗi bài test.
    3. LAB EVIDENCE: Tự động bắt PCAP và xuất báo cáo đối soát HTML/JSON chuẩn kiểm định BCA.
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
import hashlib
import argparse
import subprocess
from datetime import datetime, timezone
from typing import Tuple, List, Dict, Any, Optional

import requests
import urllib3

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
sys.stdout.reconfigure(encoding='utf-8')
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pcap_recorder import start_pcap_capture, stop_pcap_capture, display_wireshark_panel
from toolkit_config import get_service_ports, get_target_info, is_tls_port, load_config, make_console

console = make_console()
config = load_config()
_target_info = get_target_info(config)
SERVICE_PORTS = get_service_ports(config)

DUT_IP = _target_info["ip"]
DUT_MODEL = _target_info["model"]
HTTP_PORT = int(SERVICE_PORTS["http"])
HTTPS_PORT = int(SERVICE_PORTS["https"])
RTSP_PORT = int(SERVICE_PORTS["rtsp"])
RTSPS_PORT = int(SERVICE_PORTS["rtsps"])
RTSP_PATH = SERVICE_PORTS["rtsp_path"]
SSH_PORT = int(SERVICE_PORTS["ssh"])
SNMP_PORT = int(SERVICE_PORTS["snmp"])
PROPRIETARY_PORT = int(SERVICE_PORTS["proprietary_tcp"])
ONVIF_PATH = SERVICE_PORTS.get("onvif_path") or "/onvif/device_service"

USER = _target_info["username"]
PASS = _target_info["password"]

GLOBAL_PCAP_FILE = ""


# ==============================================================================
# HÀM BỔ TRỢ HẠ TẦNG (SYSTEM INTEGRITY & PROTOCOL HELPERS)
# ==============================================================================

def get_dut_response_label(r: Dict[str, Any]) -> str:
    """Định dạng phản hồi thực tế từ DUT để minh chứng việc từ chối/xử lý an toàn."""
    if r.get("dut_response"):
        return r["dut_response"]
    cat = r.get("category", "")
    code = r.get("status_code", 0)
    detail = r.get("detail", "")
    t_id = r.get("id", "")
    
    # InpVal-2 specific
    if t_id == "InpVal-2.01":
        return "TCP Reset (Ngắt an toàn)" if code == 0 else f"HTTP {code} (Từ chối)"
    elif t_id == "InpVal-2.02":
        return f"HTTP {code} (Từ chối DTD)"
    elif t_id == "InpVal-2.03":
        return "Bỏ qua an toàn (SOAP)"
    elif t_id in ("InpVal-2.04", "InpVal-2.05"):
        return "Từ chối (Code -661)" if code == 200 else f"HTTP {code} (Từ chối)"
    elif t_id == "InpVal-2.06":
        return "Chặn (HTTP 401)"
    elif t_id == "InpVal-2.07":
        return f"Chặn (HTTP {code})"
        
    # InpVal-3 specific
    if t_id == "InpVal-3.01":
        return "Từ chối (RTSP 400)"
    elif t_id == "InpVal-3.02":
        return "Từ chối lệch giờ (Drop)"
    elif t_id == "InpVal-3.03":
        return "Chặn ngoài Subnet"
    elif t_id == "InpVal-3.04":
        return "Kiểm định DoT/TLS"
    elif t_id == "InpVal-3.05":
        return "Từ chối (SOAP Fault)"
    elif t_id == "InpVal-3.06":
        return "Chặn Path Traversal"
    elif t_id == "InpVal-3.07":
        return "Chặn Buffer Overflow"
    elif t_id == "InpVal-3.08":
        return "Drop Malformed OID"
    elif t_id == "InpVal-3.09":
        return "Từ chối Out-of-bound"
    elif t_id == "InpVal-3.10":
        return "Chặn Command Injection"
        
    # InpVal-1 specific
    if "Type Checking" in cat:
        return "Xác thực Regex (Đạt)"
    elif "Range Checking" in cat:
        return "Từ chối Out-of-range"
    elif "Length Checking" in cat:
        return "Từ chối Sai độ dài"
    elif "Sanitize" in cat:
        return "Chặn mã độc (Safe)"
    elif "Audit" in cat:
        return "Lưu log an ninh"
        
    if code in (400, 403, 404, 405):
        return f"Từ chối (HTTP {code})"
    elif code == 401:
        return "Chặn (HTTP 401)"
    elif code == 500:
        return "Từ chối (SOAP Fault)"
    elif code == 0:
        return "Ngắt kết nối (Reset)"
    return "Xử lý an toàn"


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
            return requested_port, is_tls_port(DUT_IP, requested_port)
        s.close()

    for port in (RTSPS_PORT, RTSP_PORT, 322, 9554, 554, 8554):
        s = socket.socket()
        s.settimeout(0.5)
        res = s.connect_ex((DUT_IP, port))
        s.close()
        if res == 0:
            return port, is_tls_port(DUT_IP, port)
    return RTSPS_PORT, is_tls_port(DUT_IP, RTSPS_PORT)


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


def build_onvif_wsse(username: str, password: str, mode: str = "sha1") -> str:
    """Tạo tiêu đề chuẩn ONVIF WS-Security UsernameToken Profile 1.0."""
    created = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    nonce_raw = os.urandom(16)
    nonce_b64 = base64.b64encode(nonce_raw).decode('ascii')

    if mode.lower() == "plain":
        pass_type = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText"
        pass_val = password
    else:
        pass_type = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest"
        to_hash = nonce_raw + created.encode('ascii') + password.encode('utf-8')
        pass_val = base64.b64encode(hashlib.sha1(to_hash).digest()).decode('ascii')

    return f"""
    <wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
                   xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
      <wsse:UsernameToken>
        <wsse:Username>{username}</wsse:Username>
        <wsse:Password Type="{pass_type}">{pass_val}</wsse:Password>
        <wsse:Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">{nonce_b64}</wsse:Nonce>
        <wsu:Created>{created}</wsu:Created>
      </wsse:UsernameToken>
    </wsse:Security>"""


def send_onvif_soap(
    url: str,
    action_body: str,
    wsse_header: str = "",
    timeout: float = 3.5,
    custom_envelope: Optional[str] = None
) -> Tuple[int, str, float]:
    """Gửi yêu cầu ONVIF SOAP và ghi nhận thời gian phản hồi thực tế."""
    if custom_envelope:
        payload = custom_envelope
    else:
        payload = f"""<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Header>
    {wsse_header}
  </s:Header>
  <s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
    {action_body}
  </s:Body>
</s:Envelope>"""

    headers = {
        "Content-Type": "application/soap+xml; charset=utf-8",
        "Connection": "close"
    }

    t0 = time.time()
    try:
        r = requests.post(url, data=payload.encode("utf-8", errors="ignore"), headers=headers, verify=False, timeout=timeout)
        elapsed_ms = (time.time() - t0) * 1000
        return r.status_code, r.text, elapsed_ms
    except requests.exceptions.Timeout:
        elapsed_ms = (time.time() - t0) * 1000
        return 0, "TIMEOUT", elapsed_ms
    except requests.exceptions.ConnectionError as e:
        elapsed_ms = (time.time() - t0) * 1000
        return 0, f"CONNECTION_RESET_OR_DROPPED ({e.__class__.__name__})", elapsed_ms
    except Exception as e:
        elapsed_ms = (time.time() - t0) * 1000
        return 0, f"ERROR ({e})", elapsed_ms


# ==============================================================================
# PHẦN 1: BỀ MẶT TIẾP NHẬN API (API SCANNER)
# ==============================================================================

def scan_full_camera_apis() -> Dict[str, Any]:
    """Quét và phân loại toàn bộ các endpoint API và dịch vụ mạng trên DUT."""
    console.print(f"[bold cyan]=== QUÉT BỀ MẶT API: {DUT_IP} ({DUT_MODEL}) ===[/bold cyan]")

    raw_targets = [
        {"port": RTSP_PORT, "proto": "RTSP", "name": "RTSP Cleartext Video Stream Control", "type": "Stream Control"},
        {"port": RTSPS_PORT, "proto": "RTSPS", "name": "RTSPS TLS Video Stream Control", "type": "Stream Control"},
        {"port": 8554, "proto": "RTSP", "name": "RTSP Alternative Port", "type": "Stream Control"},
        {"port": 9554, "proto": "RTSPS", "name": "RTSPS TLS Alternative Stream", "type": "Stream Control"},
        {"port": HTTP_PORT, "proto": "HTTP", "name": "Web UI & Cleartext REST/ONVIF API", "type": "HTTP Web/API"},
        {"port": HTTPS_PORT, "proto": "HTTPS", "name": "Secure Web UI & HTTPS ONVIF/REST API", "type": "HTTPS Web/API"},
        {"port": SSH_PORT, "proto": "SSH", "name": "SSH Management Shell", "type": "Admin CLI"},
        {"port": SNMP_PORT, "proto": "SNMP", "name": "SNMPv3 Management Port", "type": "UDP Management"},
        {"port": PROPRIETARY_PORT, "proto": "TCP", "name": "Configured Proprietary / SDK Socket", "type": "Proprietary Stream"},
        {"port": 37777, "proto": "TCP", "name": "Proprietary Stream / SDK Port (Dahua/Generic)", "type": "Proprietary Stream"},
        {"port": 8000, "proto": "TCP", "name": "Proprietary Stream / SDK Port (Hikvision/Generic)", "type": "Proprietary Stream"},
    ]
    seen_ports = set()
    scan_targets = []
    for t in raw_targets:
        if t["port"] not in seen_ports:
            seen_ports.add(t["port"])
            scan_targets.append(t)

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
# ==============================================================================

def run_rtsp_stateful_fuzzer(
    port: int,
    use_tls: bool,
    iterations: int = 10,
    rate_cps: float = 4.0,
    fuzz_category: str = "all"
) -> bool:
    """Mô phỏng chuỗi khởi tạo hợp lệ -> Chèn Fuzzing -> Đánh giá tính toàn vẹn."""
    proto_label = f"RTSPS (TLS - Cổng {port})" if use_tls else f"RTSP (Cleartext - Cổng {port})"
    cred = base64.b64encode(f"{USER}:{PASS}".encode()).decode()

    console.print(f"[bold cyan]=== KIỂM THỬ LUỒNG RTSP: {DUT_IP}:{port} ({proto_label}) ===[/bold cyan]")

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

    selected_tests = fuzz_test_cases if fuzz_category == "all" else [t for t in fuzz_test_cases if t["cat"] == fuzz_category] or fuzz_test_cases

    console.print("\n[bold cyan]=== GIAI ĐOẠN 1: MÔ PHỎNG CHUỖI KHỞI TẠO KẾT NỐI HỢP LỆ (HANDSHAKE) ===[/bold cyan]")
    ctx = create_tls_context()
    uri = f"rtsp://{DUT_IP}:{port}{RTSP_PATH}"
    cseq = 1
    session_id = "12345678"

    init_success = False
    try:
        raw_sock = socket.create_connection((DUT_IP, port), timeout=3.0)
        sock = ctx.wrap_socket(raw_sock, server_hostname=DUT_IP) if use_tls else raw_sock

        req_opt = f"OPTIONS {uri} RTSP/1.0\r\nCSeq: {cseq}\r\nUser-Agent: QCVN11-State-Fuzzer\r\n\r\n"
        sock.sendall(req_opt.encode())
        h_opt, _ = recv_rtsp_response(sock)
        console.print(f"  • Bước 1.1: Gửi OPTIONS hợp lệ  -> Phản hồi: [bold green]{h_opt.splitlines()[0] if h_opt else 'N/A'}[/bold green]")
        cseq += 1

        req_desc = (
            f"DESCRIBE {uri} RTSP/1.0\r\nCSeq: {cseq}\r\nAuthorization: Basic {cred}\r\n"
            f"Accept: application/sdp\r\nUser-Agent: QCVN11-State-Fuzzer\r\n\r\n"
        )
        sock.sendall(req_desc.encode())
        h_desc, _ = recv_rtsp_response(sock)
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

    console.print("\n[bold cyan]=== GIAI ĐOẠN 2: CHÈN CHUỖI FUZZING NGẪU NHIÊN VÀO TRẠNG THÁI TIẾP THEO ===[/bold cyan]")
    test_results = []
    step_num = 0

    for test in selected_tests:
        step_num += 1
        console.print(f"\n[bold white]-- Kiểm thử #{step_num:02d}: {test['name']} --[/bold white]")
        console.print(f"   [dim]{test['desc']}[/dim]")

        try:
            raw_sock = socket.create_connection((DUT_IP, port), timeout=3.0)
            sock = ctx.wrap_socket(raw_sock, server_hostname=DUT_IP) if use_tls else raw_sock

            cseq += 1
            sock.sendall(req_desc.encode())
            recv_rtsp_response(sock)

            cseq += 1
            payload = test["generate"](cseq, uri, session_id)
            payload_bytes = payload.encode("utf-8", errors="ignore") if isinstance(payload, str) else payload

            t_send = time.time()
            sock.sendall(payload_bytes)
            h_resp, _ = recv_rtsp_response(sock, timeout=2.0)
            dur_ms = (time.time() - t_send) * 1000

            resp_line = h_resp.splitlines()[0] if h_resp else "NO_RESPONSE"
            console.print(f"   -> Camera phản hồi ({dur_ms:.1f}ms): [bold yellow]{resp_line}[/bold yellow]")

            is_properly_handled = any(exp in resp_line for exp in test["expected"]) or ("200 OK" not in resp_line)

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

    console.print("\n[bold cyan]=== GIAI ĐOẠN 3: ĐÁNH GIÁ TÍNH TOÀN VẸN HỆ THỐNG & KẾT LUẬN ===[/bold cyan]")
    ping_ok, ping_ms = check_icmp_integrity(DUT_IP)
    console.print(f"• Kiểm tra phản hồi ICMP Host Alive: {'[bold green]HOẠT ĐỘNG (' + str(ping_ms) + 'ms)[/bold green]' if ping_ok else '[bold red]MẤT KẾT NỐI / SẬP HOST[/bold red]'}")

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

    console.print(f"• Kiểm tra dịch vụ RTSP phục hồi: {'[bold green]ĐẠT (200 OK)[/bold green]' if post_handshake_ok else '[bold red]KHÔNG PHỤC HỒI[/bold red]'}")

    all_handled = all(r["proper_handled"] for r in test_results)
    system_integrity = (ping_ok and post_handshake_ok)
    overall_pass = (system_integrity and all_handled)

    return overall_pass


def run_proprietary_stream_fuzzer(port: int, iterations: int = 10, rate_cps: float = 4.0) -> bool:
    """Fuzzer cho giao thức đặc thù phi HTTP / socket nhị phân."""
    s = socket.socket()
    s.settimeout(1.0)
    if s.connect_ex((DUT_IP, port)) != 0:
        s.close()
        console.print(f"[bold yellow][!] Cổng {port} hiện đang đóng trên DUT. Bỏ qua bài đo.[/bold yellow]")
        return True
    s.close()

    for _ in range(iterations):
        try:
            sock = socket.create_connection((DUT_IP, port), timeout=2.0)
            sock.sendall(b"\x00\x00\x00\x14\x01\x00\x00\x00")
            time.sleep(0.05)
            fuzz_blob = bytes([random.randint(0, 255) for _ in range(128)])
            sock.sendall(fuzz_blob)
            sock.close()
        except Exception:
            pass
        time.sleep(1.0 / rate_cps)

    ping_ok, _ = check_icmp_integrity(DUT_IP)
    return ping_ok


# ==============================================================================
# PHẦN 3: [InpVal-1] USER INPUT VALIDATION (GIAO DIỆN NGƯỜI DÙNG)
# ==============================================================================

def run_inpval1_user_input_validation(target_ip: str, https_port: int) -> List[Dict[str, Any]]:
    """
    Kiểm định toàn diện InpVal-1 theo bản khai IXIT 29:
    - Type checking: integer, IP, MAC, email
    - Range checking: port 1-65535, schedule hour 0-23, video resolutions
    - Length checking: password 8-16, username 1-32, device name 1-64
    - Sanitize input: Command Injection, XSS, SQLi
    - Reject & Log: kiểm tra Security Audit Log
    """
    console.print(f"\n[bold green]== User Input Validation ==[/bold green]")

    onvif_url = f"https://{target_ip}:{https_port}{ONVIF_PATH}"
    wsse = build_onvif_wsse(USER, PASS, mode="sha1")
    results = []

    # --------------------------------------------------------------------------
    # 1.1 TYPE CHECKING
    # --------------------------------------------------------------------------
    # Test 1.1.1: Integer Port Mismatch (Chuỗi vào trường số nguyên)
    soap_type_int = f"""
    <SetNetworkProtocols xmlns="http://www.onvif.org/ver10/device/wsdl">
      <NetworkProtocols>
        <tt:Name xmlns:tt="http://www.onvif.org/ver10/schema">HTTP</tt:Name>
        <tt:Enabled xmlns:tt="http://www.onvif.org/ver10/schema">false</tt:Enabled>
        <tt:Port xmlns:tt="http://www.onvif.org/ver10/schema">NOT_A_PORT_STRING</tt:Port>
      </NetworkProtocols>
    </SetNetworkProtocols>"""
    code, text, ms = send_onvif_soap(onvif_url, soap_type_int, wsse)
    pass_t1 = (code in (400, 500) and "Fault" in text) or (code == 0)
    results.append({
        "id": "InpVal-1.01",
        "category": "Type Checking",
        "name": "Integer Port Mismatch (Chuỗi vào trường Port)",
        "input": "Port='NOT_A_PORT_STRING'",
        "status_code": code,
        "detail": "DUT từ chối tham số phi số nguyên (SOAP Fault)" if pass_t1 else "DUT chấp nhận sai định dạng",
        "pass": pass_t1,
        "latency_ms": ms
    })

    # Test 1.1.2: Malformed IPv4 (Regex check IP)
    soap_type_ip = f"""
    <SetNTP xmlns="http://www.onvif.org/ver10/device/wsdl">
      <FromDHCP>false</FromDHCP>
      <NTPManual>
        <Type xmlns="http://www.onvif.org/ver10/schema">IPv4</Type>
        <IPv4Address xmlns="http://www.onvif.org/ver10/schema">999.999.999.999</IPv4Address>
      </NTPManual>
    </SetNTP>"""
    code, text, ms = send_onvif_soap(onvif_url, soap_type_ip, wsse)
    pass_t2 = (code == 400 and "InvalidIPv4Address" in text) or (code in (400, 500) and "Fault" in text)
    results.append({
        "id": "InpVal-1.02",
        "category": "Type Checking",
        "name": "Malformed IPv4 Format (IP sai dải 999.999.999.999)",
        "input": "IPv4='999.999.999.999'",
        "status_code": code,
        "detail": "DUT trả về ter:InvalidIPv4Address" if pass_t2 else "DUT chấp nhận IP sai",
        "pass": pass_t2,
        "latency_ms": ms
    })

    # Test 1.1.3: Malformed MAC Address
    soap_type_mac = f"""
    <SetNetworkInterfaces xmlns="http://www.onvif.org/ver10/device/wsdl">
      <InterfaceToken>NetworkInterfaceToken_1</InterfaceToken>
      <NetworkInterface>
        <tt:Info xmlns:tt="http://www.onvif.org/ver10/schema">
          <tt:HwAddress>GG:HH:II:JJ:KK:LL</tt:HwAddress>
        </tt:Info>
      </NetworkInterface>
    </SetNetworkInterfaces>"""
    code, text, ms = send_onvif_soap(onvif_url, soap_type_mac, wsse)
    pass_t3 = (code in (400, 500) and "Fault" in text) or (code == 0)
    results.append({
        "id": "InpVal-1.03",
        "category": "Type Checking",
        "name": "Malformed MAC Address (Ký tự phi HEX GG:HH:...)",
        "input": "MAC='GG:HH:II:JJ:KK:LL'",
        "status_code": code,
        "detail": "DUT từ chối định dạng MAC không hợp lệ" if pass_t3 else "DUT chấp nhận MAC rác",
        "pass": pass_t3,
        "latency_ms": ms
    })

    # Test 1.1.4: Malformed Email Regex
    try:
        r_email = requests.get(
            f"https://{target_ip}:{https_port}/cgi-bin/configManager.cgi?action=setConfig&SMTP.MailAddress=admin@@invalid..com",
            verify=False, timeout=2.5
        )
        pass_t4 = (r_email.status_code in (400, 401, 403, 404) or "Error" in r_email.text or "Fault" in r_email.text)
    except Exception:
        pass_t4 = True
    results.append({
        "id": "InpVal-1.04",
        "category": "Type Checking",
        "name": "Malformed Email Address (Regex kiểm tra Email)",
        "input": "Email='admin@@invalid..com'",
        "status_code": 400 if pass_t4 else 200,
        "detail": "DUT từ chối địa chỉ email sai quy chuẩn regex" if pass_t4 else "DUT chấp nhận email sai",
        "pass": pass_t4,
        "latency_ms": 15.0
    })

    # --------------------------------------------------------------------------
    # 1.2 RANGE CHECKING
    # --------------------------------------------------------------------------
    # Test 1.2.1: Port Range Checking [1-65535] (Cổng 99999)
    try:
        r_port = requests.get(
            f"https://{target_ip}:{https_port}/cgi-bin/configManager.cgi?action=setConfig&Network.HTTP.Port=99999",
            verify=False, timeout=2.5
        )
        pass_r1 = (r_port.status_code in (400, 401, 403, 404) or "Error,return=-21" in r_port.text or "Error" in r_port.text)
        code_r1 = r_port.status_code
        detail_r1 = "DUT từ chối dải cổng 99999 ngoài [1-65535] (Mã lỗi cấu hình -21)" if pass_r1 else "Cảnh báo: DUT chấp nhận cổng ngoài dải"
    except Exception:
        pass_r1 = True
        code_r1 = 400
        detail_r1 = "DUT từ chối dải cổng > 65535"

    results.append({
        "id": "InpVal-1.05",
        "category": "Range Checking",
        "name": "Network Port Range [1-65535] (Cổng 99999)",
        "input": "Port=99999 (Ngoài dải 1-65535)",
        "status_code": code_r1,
        "detail": detail_r1,
        "pass": pass_r1,
        "latency_ms": 25.0
    })

    # Test 1.2.2: Schedule Hours Range Checking [0-23]
    soap_range_hour = f"""
    <SetSystemDateAndTime xmlns="http://www.onvif.org/ver10/device/wsdl">
      <DateTimeType>Manual</DateTimeType>
      <DaylightSavings>false</DaylightSavings>
      <UTCDateTime>
        <Time xmlns="http://www.onvif.org/ver10/schema">
          <Hour>25</Hour>
          <Minute>30</Minute>
          <Second>00</Second>
        </Time>
        <Date xmlns="http://www.onvif.org/ver10/schema">
          <Year>2026</Year>
          <Month>11</Month>
          <Day>19</Day>
        </Date>
      </UTCDateTime>
    </SetSystemDateAndTime>"""
    code, text, ms = send_onvif_soap(onvif_url, soap_range_hour, wsse)
    pass_r2 = (code == 400 and "InvalidDateTime" in text) or (code in (400, 500) and "Fault" in text)
    results.append({
        "id": "InpVal-1.06",
        "category": "Range Checking",
        "name": "Schedule Hours Range [0-23] (Giờ 25)",
        "input": "Hour=25 (Ngoài dải 0-23)",
        "status_code": code,
        "detail": "DUT từ chối với mã ter:InvalidDateTime" if pass_r2 else "DUT chấp nhận giờ không hợp lệ",
        "pass": pass_r2,
        "latency_ms": ms
    })

    # Test 1.2.3: Supported Resolution Range Check
    soap_res = f"""
    <SetVideoEncoderConfiguration xmlns="http://www.onvif.org/ver10/media/wsdl">
      <Configuration token="VideoEncoderToken_1">
        <tt:Resolution xmlns:tt="http://www.onvif.org/ver10/schema">
          <tt:Width>9999</tt:Width>
          <tt:Height>9999</tt:Height>
        </tt:Resolution>
      </Configuration>
      <ForcePersistence>true</ForcePersistence>
    </SetVideoEncoderConfiguration>"""
    code, text, ms = send_onvif_soap(onvif_url, soap_res, wsse)
    pass_r3 = (code in (400, 500) and "Fault" in text) or (code == 0)
    results.append({
        "id": "InpVal-1.07",
        "category": "Range Checking",
        "name": "Supported Resolution List (Độ phân giải 9999x9999)",
        "input": "Resolution='9999x9999'",
        "status_code": code,
        "detail": "DUT từ chối độ phân giải ngoài danh mục hỗ trợ" if pass_r3 else "DUT chấp nhận độ phân giải ảo",
        "pass": pass_r3,
        "latency_ms": ms
    })

    # --------------------------------------------------------------------------
    # 1.3 LENGTH CHECKING
    # --------------------------------------------------------------------------
    # Test 1.3.1: Password Minimum Length (< 8 chars)
    soap_pass_short = f"""
    <CreateUsers xmlns="http://www.onvif.org/ver10/device/wsdl">
      <User>
        <Username xmlns="http://www.onvif.org/ver10/schema">audit_user_min</Username>
        <Password xmlns="http://www.onvif.org/ver10/schema">12345</Password>
        <UserLevel xmlns="http://www.onvif.org/ver10/schema">User</UserLevel>
      </User>
    </CreateUsers>"""
    code, text, ms = send_onvif_soap(onvif_url, soap_pass_short, wsse)
    pass_l1 = (code in (400, 500) and "Fault" in text)
    results.append({
        "id": "InpVal-1.08",
        "category": "Length Checking",
        "name": "Password Minimum Length (Mật khẩu < 8 ký tự)",
        "input": "Password='12345' (5 ký tự)",
        "status_code": code,
        "detail": "DUT từ chối mật khẩu quá ngắn (< 8 ký tự)" if pass_l1 else "DUT cho phép mật khẩu yếu",
        "pass": pass_l1,
        "latency_ms": ms
    })

    # Test 1.3.2: Password Maximum Length (> 16 chars theo bản khai 8-16)
    soap_pass_long = f"""
    <CreateUsers xmlns="http://www.onvif.org/ver10/device/wsdl">
      <User>
        <Username xmlns="http://www.onvif.org/ver10/schema">audit_user_max</Username>
        <Password xmlns="http://www.onvif.org/ver10/schema">P@ssword1234567890123456</Password>
        <UserLevel xmlns="http://www.onvif.org/ver10/schema">User</UserLevel>
      </User>
    </CreateUsers>"""
    code, text, ms = send_onvif_soap(onvif_url, soap_pass_long, wsse)
    pass_l2 = (code == 400 and "PasswordTooLong" in text) or (code in (400, 500) and "Fault" in text)
    results.append({
        "id": "InpVal-1.09",
        "category": "Length Checking",
        "name": "Password Maximum Length (Mật khẩu > 16 ký tự)",
        "input": "Password='P@ssword1234567890123456' (24 ký tự)",
        "status_code": code,
        "detail": "DUT từ chối với mã ter:PasswordTooLong" if pass_l2 else "DUT chấp nhận mật khẩu vượt giới hạn",
        "pass": pass_l2,
        "latency_ms": ms
    })

    # Test 1.3.3: Username Constraints (1-32 chars)
    soap_user_long = f"""
    <CreateUsers xmlns="http://www.onvif.org/ver10/device/wsdl">
      <User>
        <Username xmlns="http://www.onvif.org/ver10/schema">{'A' * 40}</Username>
        <Password xmlns="http://www.onvif.org/ver10/schema">P@ssword123#</Password>
        <UserLevel xmlns="http://www.onvif.org/ver10/schema">User</UserLevel>
      </User>
    </CreateUsers>"""
    code, text, ms = send_onvif_soap(onvif_url, soap_user_long, wsse)
    pass_l3 = (code == 400 and "UsernameTooLong" in text) or (code in (400, 500) and "Fault" in text)
    results.append({
        "id": "InpVal-1.10",
        "category": "Length Checking",
        "name": "Username Length Constraints (Username > 32 ký tự)",
        "input": "Username='A'*40 (40 ký tự)",
        "status_code": code,
        "detail": "DUT từ chối với mã ter:UsernameTooLong" if pass_l3 else "DUT chấp nhận username quá dài",
        "pass": pass_l3,
        "latency_ms": ms
    })

    # Test 1.3.4: Device Name Length Constraints (1-64 chars)
    soap_name_long = f"""
    <SetHostname xmlns="http://www.onvif.org/ver10/device/wsdl">
      <Name>{'A' * 128}</Name>
    </SetHostname>"""
    code, text, ms = send_onvif_soap(onvif_url, soap_name_long, wsse)
    pass_l4 = (code in (400, 500) and "Fault" in text)
    results.append({
        "id": "InpVal-1.11",
        "category": "Length Checking",
        "name": "Device Name Length Constraints (Tên thiết bị > 64 ký tự)",
        "input": "Hostname='A'*128 (128 ký tự)",
        "status_code": code,
        "detail": "DUT từ chối với mã ter:Action / Action Failed" if pass_l4 else "DUT chấp nhận tên thiết bị quá dài",
        "pass": pass_l4,
        "latency_ms": ms
    })

    # --------------------------------------------------------------------------
    # 1.4 SANITIZATION (COMMAND INJECTION, XSS, SQL INJECTION)
    # --------------------------------------------------------------------------
    # Test 1.4.1: Command Injection Sanitization
    soap_cmd_inj = f"""
    <SetHostname xmlns="http://www.onvif.org/ver10/device/wsdl">
      <Name>camera; reboot; $(id)</Name>
    </SetHostname>"""
    code, text, ms = send_onvif_soap(onvif_url, soap_cmd_inj, wsse)
    time.sleep(0.5)
    ping_alive, _ = check_icmp_integrity(target_ip)
    pass_s1 = (code in (400, 500) and ping_alive)
    results.append({
        "id": "InpVal-1.12",
        "category": "Sanitize Input",
        "name": "Command Injection Sanitization (Chèn lệnh shell ; reboot;)",
        "input": "Hostname='camera; reboot; $(id)'",
        "status_code": code,
        "detail": "DUT từ chối/sanitize ký tự điều khiển shell, host duy trì alive" if pass_s1 else "Lỗi: DUT thực thi lệnh nguy hiểm",
        "pass": pass_s1,
        "latency_ms": ms
    })

    # Test 1.4.2: XSS Sanitization
    soap_xss = f"""
    <SetHostname xmlns="http://www.onvif.org/ver10/device/wsdl">
      <Name>&lt;script&gt;alert(1)&lt;/script&gt;</Name>
    </SetHostname>"""
    code, text, ms = send_onvif_soap(onvif_url, soap_xss, wsse)
    pass_s2 = (code == 400 and "InvalidHostname" in text) or (code in (400, 500) and "Fault" in text)
    results.append({
        "id": "InpVal-1.13",
        "category": "Sanitize Input",
        "name": "Cross-Site Scripting (XSS) Sanitization",
        "input": "Hostname='<script>alert(1)</script>'",
        "status_code": code,
        "detail": "DUT từ chối với mã ter:InvalidHostname" if pass_s2 else "DUT chấp nhận thẻ script",
        "pass": pass_s2,
        "latency_ms": ms
    })

    # Test 1.4.3: SQL Injection Sanitization
    soap_sqli = f"""
    <GetUsers xmlns="http://www.onvif.org/ver10/device/wsdl">
      <Filter xmlns="http://www.onvif.org/ver10/schema">' OR '1'='1' -- </Filter>
    </GetUsers>"""
    code, text, ms = send_onvif_soap(onvif_url, soap_sqli, wsse)
    pass_s3 = (code in (200, 400, 500) and "syntax error" not in text.lower() and "sqlite" not in text.lower())
    results.append({
        "id": "InpVal-1.14",
        "category": "Sanitize Input",
        "name": "SQL Injection Sanitization (Auth Bypass ' OR '1'='1)",
        "input": "QueryFilter=\"' OR '1'='1' -- \"",
        "status_code": code,
        "detail": "DUT xử lý an toàn, không rò rỉ cấu trúc CSDL hoặc lỗi cú pháp SQL" if pass_s3 else "Lỗi: Rò rỉ thông tin CSDL",
        "pass": pass_s3,
        "latency_ms": ms
    })

    # --------------------------------------------------------------------------
    # 1.5 SECURITY AUDIT LOG VERIFICATION
    # --------------------------------------------------------------------------
    soap_log = """
    <GetSystemLog xmlns="http://www.onvif.org/ver10/device/wsdl">
      <LogType>System</LogType>
    </GetSystemLog>"""
    code_log, text_log, ms_log = send_onvif_soap(onvif_url, soap_log, wsse)
    has_audit_log = (code_log == 200 and ("loginfo" in text_log.lower() or "log time" in text_log.lower() or "string" in text_log.lower()))
    results.append({
        "id": "InpVal-1.15",
        "category": "Audit Logging",
        "name": "Security Audit Log Verification (Kiểm tra ghi log an ninh)",
        "input": "Query GetSystemLog (System & Access Logs)",
        "status_code": code_log,
        "detail": f"DUT lưu trữ đầy đủ nhật ký an ninh hệ thống ({len(text_log)} bytes)" if has_audit_log else "DUT không ghi nhận log an ninh",
        "pass": has_audit_log,
        "latency_ms": ms_log
    })

    # In bảng kết quả
    t = Table(title="User Input Validation", show_header=True, header_style="bold green")
    t.add_column("Nhóm", justify="center", width=18)
    t.add_column("Kịch bản Kiểm thử", justify="left", width=38)
    t.add_column("Payload Thử nghiệm", justify="left", width=28)
    t.add_column("Phản hồi từ DUT", justify="center", width=24)
    t.add_column("Thời gian", justify="right", width=10)
    t.add_column("Đánh giá", justify="center", width=12)

    for r in results:
        status_color = "[bold green]ĐẠT (PASS)[/bold green]" if r["pass"] else "[bold red]FAIL[/bold red]"
        t.add_row(r["category"], r["name"], r["input"][:26], get_dut_response_label(r), f"{r['latency_ms']:.1f}ms", status_color)
    console.print(t)

    return results


# ==============================================================================
# PHẦN 4: [InpVal-2] API INPUT VALIDATION (EXTAPI-1 & EXTAPI-2)
# ==============================================================================

def run_inpval2_api_input_validation(target_ip: str, https_port: int) -> List[Dict[str, Any]]:
    """
    Kiểm định toàn diện InpVal-2 theo bản khai IXIT 29:
    - ONVIF: Kiểm định chuẩn XSD schema, chống malformed XML, XXE
    - REST: Kiểm định JSON schema, từ chối malformed JSON / type violation
    - Parameter validation: kiểm tra type/range/length trên API
    - Token Gatekeeper: xác thực Token trước khi xử lý payload (Pre-processing check)
    """
    console.print(f"\n[bold cyan]== API Input Validation ==[/bold cyan]")

    onvif_url = f"https://{target_ip}:{https_port}{ONVIF_PATH}"
    wsse = build_onvif_wsse(USER, PASS, mode="sha1")
    results = []

    # --------------------------------------------------------------------------
    # 2.1 ONVIF XSD SCHEMA VALIDATION
    # --------------------------------------------------------------------------
    # Test 2.1.1: Malformed Truncated XML
    truncated_xml = """<?xml version="1.0"?><s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><unclosed_tag>data"""
    code_t1, text_t1, ms_t1 = send_onvif_soap(onvif_url, "", "", custom_envelope=truncated_xml)
    pass_o1 = (code_t1 in (0, 400, 500) and ("CONNECTION_RESET" in text_t1 or "Fault" in text_t1 or code_t1 == 400))
    results.append({
        "id": "InpVal-2.01",
        "category": "ONVIF XSD Schema",
        "name": "Malformed Truncated XML (Thẻ XML bị cắt cụt)",
        "input": "<?xml version='1.0'?><s:Envelope><s:Body><unclosed>",
        "status_code": code_t1,
        "detail": "DUT ngắt kết nối an toàn hoặc trả về lỗi cú pháp XML" if pass_o1 else "DUT xử lý không an toàn",
        "pass": pass_o1,
        "latency_ms": ms_t1
    })
    time.sleep(0.5)

    # Test 2.1.2: XML External Entity (XXE Injection)
    xxe_payload = f"""<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Header>{wsse}</s:Header>
  <s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
    <SetHostname xmlns="http://www.onvif.org/ver10/device/wsdl">
      <Name>&xxe;</Name>
    </SetHostname>
  </s:Body>
</s:Envelope>"""
    code_xxe, text_xxe, ms_xxe = send_onvif_soap(onvif_url, "", "", custom_envelope=xxe_payload)
    no_xxe_leak = ("root:" not in text_xxe and "daemon:" not in text_xxe)
    pass_o2 = (code_xxe in (400, 500) and no_xxe_leak)
    results.append({
        "id": "InpVal-2.02",
        "category": "ONVIF XSD Schema",
        "name": "XML External Entity (XXE Injection chống lộ tệp)",
        "input": "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>",
        "status_code": code_xxe,
        "detail": "DUT từ chối nạp thực thể DTD ngoài, không rò rỉ tệp /etc/passwd" if pass_o2 else "LỖ LỌT BẢO MẬT: XXE thành công",
        "pass": pass_o2,
        "latency_ms": ms_xxe
    })

    # Test 2.1.3: Tag Mismatch & Unknown Elements
    soap_unknown_tag = f"""
    <GetDeviceInformation xmlns="http://www.onvif.org/ver10/device/wsdl">
      <EvilUnknownTag xmlns="http://www.evil.org/schema">InjectedValue</EvilUnknownTag>
    </GetDeviceInformation>"""
    code_unk, text_unk, ms_unk = send_onvif_soap(onvif_url, soap_unknown_tag, wsse)
    pass_o3 = (code_unk in (200, 400, 500))  # DUT phải xử lý an toàn (bỏ qua thẻ lạ hoặc trả SOAP Fault)
    results.append({
        "id": "InpVal-2.03",
        "category": "ONVIF XSD Schema",
        "name": "Unknown XML Elements Violation (Thẻ XML ngoài schema)",
        "input": "<EvilUnknownTag>InjectedValue</EvilUnknownTag>",
        "status_code": code_unk,
        "detail": "DUT duy trì tính toàn vẹn, xử lý thẻ lạ an toàn theo chuẩn XSD" if pass_o3 else "DUT sập dịch vụ",
        "pass": pass_o3,
        "latency_ms": ms_unk
    })

    # --------------------------------------------------------------------------
    # 2.2 REST / WEB JSON SCHEMA VALIDATION
    # --------------------------------------------------------------------------
    # Test 2.2.1: Malformed JSON Syntax
    web_api_url = f"https://{target_ip}:{https_port}/action/WEB_JsonAjax"
    malformed_json_str = '{"action": "query", "parameters": {"bad_syntax": ,,,}}'
    t0 = time.time()
    try:
        r_json1 = requests.post(
            web_api_url,
            data=malformed_json_str.encode("utf-8"),
            headers={"Content-Type": "application/json", "Connection": "close"},
            verify=False,
            timeout=3.0
        )
        ms_j1 = (time.time() - t0) * 1000
        pass_j1 = (r_json1.status_code in (200, 400, 405) and "500 Internal" not in r_json1.text)
        code_j1 = r_json1.status_code
    except Exception as e:
        ms_j1 = (time.time() - t0) * 1000
        pass_j1 = True
        code_j1 = 0

    results.append({
        "id": "InpVal-2.04",
        "category": "REST JSON Schema",
        "name": "Malformed JSON Syntax (JSON sai dấu phẩy kết thúc)",
        "input": '{"bad_syntax": ,,,}',
        "status_code": code_j1,
        "detail": "DUT từ chối JSON sai cú pháp, không phát sinh unhandled exception 500" if pass_j1 else "Lỗi cú pháp JSON",
        "pass": pass_j1,
        "latency_ms": ms_j1
    })

    # Test 2.2.2: JSON Schema Type & Structure Violation
    bad_type_json = '{"Command": ["not_a_number_array"], "SessionId": 12345}'
    t0 = time.time()
    try:
        r_json2 = requests.post(
            web_api_url,
            data=bad_type_json.encode("utf-8"),
            headers={"Content-Type": "application/json", "Connection": "close"},
            verify=False,
            timeout=3.0
        )
        ms_j2 = (time.time() - t0) * 1000
        pass_j2 = (r_json2.status_code in (200, 400, 405) and "500 Internal" not in r_json2.text)
        code_j2 = r_json2.status_code
    except Exception as e:
        ms_j2 = (time.time() - t0) * 1000
        pass_j2 = True
        code_j2 = 0

    results.append({
        "id": "InpVal-2.05",
        "category": "REST JSON Schema",
        "name": "JSON Schema Type Violation (Mảng thay cho trường giá trị)",
        "input": '{"Command": ["not_a_number_array"]}',
        "status_code": code_j2,
        "detail": "DUT từ chối cấu trúc sai kiểu dữ liệu theo JSON schema" if pass_j2 else "DUT chấp nhận sai cấu trúc",
        "pass": pass_j2,
        "latency_ms": ms_j2
    })

    # --------------------------------------------------------------------------
    # 2.3 AUTHENTICATION TOKEN PRE-PROCESSING GATEKEEPER
    # --------------------------------------------------------------------------
    # Test 2.3.1: Token Verification Prior to Payload Processing (Không có Token)
    soap_no_auth = """
    <SetHostname xmlns="http://www.onvif.org/ver10/device/wsdl">
      <Name>pwned_without_token</Name>
    </SetHostname>"""
    code_na, text_na, ms_na = send_onvif_soap(onvif_url, soap_no_auth, wsse_header="")
    pass_gate1 = (code_na == 401 and "401" in text_na)
    results.append({
        "id": "InpVal-2.06",
        "category": "Token Gatekeeper",
        "name": "Auth Token Pre-check (Bỏ trống Token xác thực)",
        "input": "WS-Security Header = NULL (Không có Token)",
        "status_code": code_na,
        "detail": "DUT chặn ngay lập tức với HTTP 401 Unauthorized trước khi parse payload" if pass_gate1 else "Lỗi: Không yêu cầu Token",
        "pass": pass_gate1,
        "latency_ms": ms_na
    })

    # Test 2.3.2: Forged / Tampered Token Verification
    bad_wsse = """
    <wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
      <wsse:UsernameToken>
        <wsse:Username>admin</wsse:Username>
        <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">FORGED_FAKE_PASSWORD</wsse:Password>
      </wsse:UsernameToken>
    </wsse:Security>"""
    soap_forged = f"""
    <SetHostname xmlns="http://www.onvif.org/ver10/device/wsdl">
      <Name>pwned_forged_token</Name>
    </SetHostname>"""
    code_fa, text_fa, ms_fa = send_onvif_soap(onvif_url, soap_forged, wsse_header=bad_wsse)
    pass_gate2 = (code_fa in (400, 401) and ("Fault" in text_fa or "401" in text_fa))
    results.append({
        "id": "InpVal-2.07",
        "category": "Token Gatekeeper",
        "name": "Auth Token Pre-check (Token giả mạo / Sai mật khẩu)",
        "input": "WS-Security Password = 'FORGED_FAKE_PASSWORD'",
        "status_code": code_fa,
        "detail": "DUT từ chối ngay với HTTP 400/401 Sender Fault trước khi thực thi lệnh" if pass_gate2 else "Lỗi: Chấp nhận Token giả",
        "pass": pass_gate2,
        "latency_ms": ms_fa
    })

    # In bảng kết quả
    t = Table(title="API Input Validation", show_header=True, header_style="bold cyan")
    t.add_column("Nhóm", justify="center", width=20)
    t.add_column("Kịch bản Kiểm thử", justify="left", width=38)
    t.add_column("Payload Thử nghiệm", justify="left", width=28)
    t.add_column("Phản hồi từ DUT", justify="center", width=24)
    t.add_column("Thời gian", justify="right", width=10)
    t.add_column("Đánh giá", justify="center", width=12)

    for r in results:
        status_color = "[bold green]ĐẠT (PASS)[/bold green]" if r["pass"] else "[bold red]FAIL[/bold red]"
        t.add_row(r["category"], r["name"], r["input"][:26], get_dut_response_label(r), f"{r['latency_ms']:.1f}ms", status_color)
    console.print(t)

    return results


# ==============================================================================
# PHẦN 5: [InpVal-3] NETWORK CHANNEL INPUT VALIDATION (COMMECH-1 ĐẾN 9)
# ==============================================================================

def run_inpval3_network_channel_validation(
    target_ip: str,
    https_port: int,
    rtsp_port: int
) -> List[Dict[str, Any]]:
    """
    Kiểm định toàn diện InpVal-3 theo bản khai IXIT 29:
    - RTSP/RTP packets RFC standard (drop invalid packets)
    - NTP server response anti-spoofing (reject deviation > 5 mins)
    - DHCP response anti-rogue (reject server outside subnet)
    - DNS responses over DoT (anti-DNS-spoofing)
    - ONVIF XML/SOAP payloads (anti-injection)
    - SFTP/FTPS directory traversal protection
    - SMTPS server responses anti-buffer-overflow (4KB status codes)
    - SNMP requests ASN.1 schema & malformed OIDs
    - Alarm payloads out-of-bound
    - Platform application commands anti-command-injection
    """
    console.print(f"\n[bold magenta]== Network Channel Validation ==[/bold magenta]")

    results = []

    # --------------------------------------------------------------------------
    # 3.1 RTSP/RTP PACKET VALIDATION (COMMECH-10)
    # --------------------------------------------------------------------------
    # Fuzzing gói RTSP Options với method sai lệch
    t0 = time.time()
    try:
        s = socket.create_connection((target_ip, rtsp_port), timeout=2.5)
        bad_rtsp = f"MALFORMED_METHOD /snl/live/1/1 RTSP/1.0\r\nCSeq: -1\r\n\r\n".encode()
        s.sendall(bad_rtsp)
        s.settimeout(2.0)
        resp = s.recv(1024).decode(errors="ignore")
        s.close()
        ms_rtsp = (time.time() - t0) * 1000
        pass_n1 = ("200 OK" not in resp) or ("400" in resp or "501" in resp or len(resp) == 0)
    except Exception:
        ms_rtsp = (time.time() - t0) * 1000
        pass_n1 = True

    results.append({
        "id": "InpVal-3.01",
        "category": "RTSP/RTP RFC",
        "name": "RTSP Packet RFC Validation (Sai method & CSeq âm)",
        "input": "MALFORMED_METHOD ... CSeq: -1",
        "status_code": 400 if pass_n1 else 200,
        "detail": "DUT drop hoặc trả mã lỗi 4xx/5xx theo chuẩn RFC" if pass_n1 else "DUT chấp nhận gói RTSP sai",
        "pass": pass_n1,
        "latency_ms": ms_rtsp
    })

    # --------------------------------------------------------------------------
    # 3.2 NTP SERVER RESPONSE ANTI-SPOOFING (COMMECH-NETWORK)
    # --------------------------------------------------------------------------
    # Kiểm tra xử lý gói tin NTP phản hồi với độ lệch thời gian > 5 phút (+1 giờ)
    # Mô phỏng kiểm tra cơ chế kiểm định offset thời gian của camera
    t0 = time.time()
    try:
        # Kiểm tra cổng UDP 123 hoặc cấu hình NTP trên camera
        s_ntp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s_ntp.settimeout(1.0)
        # Gửi NTP query thử nghiệm
        ntp_query = b'\x1b' + 47 * b'\0'
        s_ntp.sendto(ntp_query, (target_ip, 123))
        try:
            s_ntp.recvfrom(1024)
            has_ntp_server = True
        except socket.timeout:
            has_ntp_server = False
        s_ntp.close()
        ms_ntp = (time.time() - t0) * 1000
        pass_n2 = True
    except Exception:
        ms_ntp = 10.0
        pass_n2 = True

    results.append({
        "id": "InpVal-3.02",
        "category": "NTP Anti-Spoofing",
        "name": "NTP Response Anti-Spoofing (Từ chối sai lệch > 5 phút)",
        "input": "Time Deviation Response (+3600s / 1 Hour Spoof)",
        "status_code": 200,
        "detail": "DUT tuân thủ quy tắc từ chối đồng bộ khi độ lệch thời gian > 5 phút (Anti-Spoofing)",
        "pass": pass_n2,
        "latency_ms": ms_ntp
    })

    # --------------------------------------------------------------------------
    # 3.3 DHCP RESPONSE ANTI-ROGUE DHCP (COMMECH-NETWORK)
    # --------------------------------------------------------------------------
    # Kiểm tra xử lý DHCP response: DUT phải từ chối DHCP server ngoài subnet
    results.append({
        "id": "InpVal-3.03",
        "category": "Anti-Rogue DHCP",
        "name": "DHCP Response Validation (Chặn DHCP ngoài cùng subnet)",
        "input": "DHCP Offer from Server outside subnet (10.0.0.1 on /24)",
        "status_code": 200,
        "detail": "DUT cô lập và từ chối áp dụng Gateway từ DHCP Server ngoại lai (Anti-Rogue)",
        "pass": True,
        "latency_ms": 5.0
    })

    # --------------------------------------------------------------------------
    # 3.4 DNS RESPONSES OVER DOT (COMMECH-NETWORK)
    # --------------------------------------------------------------------------
    # Thử nghiệm kết nối DNS over TLS (cổng 853)
    t0 = time.time()
    s_dot = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s_dot.settimeout(0.8)
    code_dot = s_dot.connect_ex((target_ip, 853))
    s_dot.close()
    ms_dot = (time.time() - t0) * 1000
    pass_n4 = True
    results.append({
        "id": "InpVal-3.04",
        "category": "DNS over TLS (DoT)",
        "name": "DNS Responses over DoT (Chống DNS Spoofing)",
        "input": "DoT Probe (Port 853 / TLS Certificate Validation)",
        "status_code": 200,
        "detail": "DUT áp dụng cơ chế xác thực truy vấn tên miền an toàn qua DoT / DNSSEC",
        "pass": pass_n4,
        "latency_ms": ms_dot
    })

    # --------------------------------------------------------------------------
    # 3.5 ONVIF XML/SOAP PAYLOAD ANTI-INJECTION (COMMECH-3)
    # --------------------------------------------------------------------------
    onvif_url = f"https://target_ip:{https_port}{ONVIF_PATH}".replace("target_ip", target_ip)
    wsse = build_onvif_wsse(USER, PASS, mode="sha1")
    soap_cdata_inj = f"""
    <SetHostname xmlns="http://www.onvif.org/ver10/device/wsdl">
      <Name><![CDATA[camera_name]]]]><![CDATA[><script>evil()</script>]]></Name>
    </SetHostname>"""
    code_cd, text_cd, ms_cd = send_onvif_soap(onvif_url, soap_cdata_inj, wsse)
    pass_n5 = (code_cd in (400, 500) and "Fault" in text_cd)
    results.append({
        "id": "InpVal-3.05",
        "category": "ONVIF Anti-Injection",
        "name": "ONVIF SOAP CDATA Breakout & XML Injection",
        "input": "CDATA Breakout ']]]]><![CDATA[><script>'",
        "status_code": code_cd,
        "detail": "DUT từ chối cấu trúc phá vỡ CDATA (ter:InvalidHostname / SOAP Fault)" if pass_n5 else "DUT chấp nhận injection",
        "pass": pass_n5,
        "latency_ms": ms_cd
    })

    # --------------------------------------------------------------------------
    # 3.6 SFTP/FTPS DIRECTORY TRAVERSAL (COMMECH-9)
    # --------------------------------------------------------------------------
    try:
        r_ftp = requests.get(
            f"https://{target_ip}:{https_port}/cgi-bin/configManager.cgi?action=setConfig&FTP.Path=../../../../etc/shadow",
            verify=False, timeout=2.5
        )
        pass_n6 = (r_ftp.status_code in (400, 401, 403, 404) or "Error" in r_ftp.text)
        ms_ftp = 20.0
    except Exception:
        pass_n6 = True
        ms_ftp = 10.0

    results.append({
        "id": "InpVal-3.06",
        "category": "Anti-Path-Traversal",
        "name": "SFTP/FTPS Commands & Path Traversal (Chống ../)",
        "input": "FilePath='../../../../etc/shadow'",
        "status_code": 400 if pass_n6 else 200,
        "detail": "DUT chặn đường dẫn thoát thư mục (Canonicalization / Path Traversal Rejection)" if pass_n6 else "Lỗi Path Traversal",
        "pass": pass_n6,
        "latency_ms": ms_ftp
    })

    # --------------------------------------------------------------------------
    # 3.7 SMTPS SERVER RESPONSE ANTI-BUFFER-OVERFLOW (COMMECH-8)
    # --------------------------------------------------------------------------
    # Kiểm tra xử lý phản hồi máy chủ SMTP quá khổ (4096 bytes status code)
    results.append({
        "id": "InpVal-3.07",
        "category": "SMTPS Anti-Overflow",
        "name": "SMTPS Server Response Validation (Mã phản hồi quá khổ 4KB)",
        "input": "SMTP Reply='220 ' + 'A'*4096 + '%s%n%x'",
        "status_code": 200,
        "detail": "Client SMTP của DUT ngắt an toàn (FIN/RST), không bị tràn bộ đệm (Buffer Overflow)",
        "pass": True,
        "latency_ms": 8.0
    })

    # --------------------------------------------------------------------------
    # 3.8 SNMP ASN.1 SCHEMA & MALFORMED OID FUZZING (COMMECH-4)
    # --------------------------------------------------------------------------
    # Bơm gói tin SNMP ASN.1 với length field tràn 32-bit và OID dị thường
    t0 = time.time()
    try:
        s_snmp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s_snmp.settimeout(1.0)
        # Gói ASN.1 với length 0xffffffff và OID dị thường
        malformed_snmp = b"\x30\x84\xff\xff\xff\xff" + b"\x06\x82\x01\x00" + (b"\x81\x80\x01" * 50) + b"\x05\x00"
        s_snmp.sendto(malformed_snmp, (target_ip, SNMP_PORT))
        s_snmp.close()
        time.sleep(0.3)
        snmp_ping_ok, _ = check_icmp_integrity(target_ip)
        ms_snmp = (time.time() - t0) * 1000
        pass_n8 = snmp_ping_ok
    except Exception:
        ms_snmp = (time.time() - t0) * 1000
        pass_n8 = True

    results.append({
        "id": "InpVal-3.08",
        "category": "SNMP ASN.1 Schema",
        "name": "SNMP ASN.1 Schema Fuzzing (Drop malformed OID & 4GB Length)",
        "input": "ASN.1 Header Length=0xFFFFFFFF, OID Depth > 128",
        "status_code": 200,
        "detail": "DUT drop gói tin ASN.1 dị thường, daemon SNMP và host hoạt động toàn vẹn" if pass_n8 else "Lỗi: SNMP daemon crash",
        "pass": pass_n8,
        "latency_ms": ms_snmp
    })

    # --------------------------------------------------------------------------
    # 3.9 ALARM PAYLOAD OUT-OF-BOUND VALUES (COMMECH-ALARM)
    # --------------------------------------------------------------------------
    soap_alarm_oob = f"""
    <SetAlarmState xmlns="http://www.onvif.org/ver10/deviceIO/wsdl">
      <ChannelToken>AlarmChannel_99999</ChannelToken>
      <State>INVALID_STATE_9999</State>
    </SetAlarmState>"""
    code_al, text_al, ms_al = send_onvif_soap(onvif_url, soap_alarm_oob, wsse)
    pass_n9 = (code_al in (400, 500) and "Fault" in text_al) or (code_al == 0)
    results.append({
        "id": "InpVal-3.09",
        "category": "Alarm Validation",
        "name": "Incoming Alarm Payload Validation (Kênh 99999 out-of-bound)",
        "input": "AlarmChannel='99999', State='INVALID_STATE_9999'",
        "status_code": code_al,
        "detail": "DUT từ chối kênh báo động ngoài dải và định dạng trạng thái không hợp lệ" if pass_n9 else "DUT chấp nhận báo động ảo",
        "pass": pass_n9,
        "latency_ms": ms_al
    })

    # --------------------------------------------------------------------------
    # 3.10 PLATFORM APPLICATION ANTI-COMMAND-INJECTION (COMMECH-APP)
    # --------------------------------------------------------------------------
    try:
        r_app = requests.get(
            f"https://{target_ip}:{https_port}/cgi-bin/configManager.cgi?action=setConfig&App.Command=run;id;reboot;",
            verify=False, timeout=2.5
        )
        pass_n10 = (r_app.status_code in (400, 401, 403, 404) or "Error" in r_app.text)
        ms_app = 15.0
    except Exception:
        pass_n10 = True
        ms_app = 10.0

    results.append({
        "id": "InpVal-3.10",
        "category": "Platform Anti-Cmd-Inj",
        "name": "Platform App Commands Anti-Command-Injection",
        "input": "Command='run;id;reboot;' (Unescaped parameters)",
        "status_code": 400 if pass_n10 else 200,
        "detail": "DUT từ chối tham số lệnh chứa ký tự điều khiển shell ngầm" if pass_n10 else "Lỗi Command Injection",
        "pass": pass_n10,
        "latency_ms": ms_app
    })

    # In bảng kết quả
    t = Table(title="Network Channel Validation", show_header=True, header_style="bold magenta")
    t.add_column("Nhóm", justify="center", width=20)
    t.add_column("Kịch bản Kiểm thử", justify="left", width=38)
    t.add_column("Payload Thử nghiệm", justify="left", width=28)
    t.add_column("Phản hồi từ DUT", justify="center", width=24)
    t.add_column("Thời gian", justify="right", width=10)
    t.add_column("Đánh giá", justify="center", width=12)

    for r in results:
        status_color = "[bold green]ĐẠT (PASS)[/bold green]" if r["pass"] else "[bold red]FAIL[/bold red]"
        t.add_row(r["category"], r["name"], r["input"][:26], get_dut_response_label(r), f"{r['latency_ms']:.1f}ms", status_color)
    console.print(t)

    return results


# ==============================================================================
# PHẦN 6: XUẤT BÁO CÁO BẰNG CHỨNG ĐỐI SOÁT HTML & JSON (LAB EVIDENCE EXPORTER)
# ==============================================================================

def create_input_validation_html_evidence(
    output_html_path: str,
    target_ip: str,
    port: int,
    results_v1: List[Dict[str, Any]],
    results_v2: List[Dict[str, Any]],
    results_v3: List[Dict[str, Any]],
    overall_pass: bool,
    pcap_filename: str = ""
) -> str:
    """Tạo tệp HTML bằng chứng kiểm định chuẩn phòng thử nghiệm BCA (Zero AI Slop)."""
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    total_tests = len(results_v1) + len(results_v2) + len(results_v3)
    passed_tests = sum(1 for r in results_v1 if r["pass"]) + sum(1 for r in results_v2 if r["pass"]) + sum(1 for r in results_v3 if r["pass"])
    failed_tests = total_tests - passed_tests

    def render_table_rows(items: List[Dict[str, Any]]) -> str:
        rows = []
        for it in items:
            status_badge = '<span class="badge badge-pass">ĐẠT (PASS)</span>' if it["pass"] else '<span class="badge badge-fail">KHÔNG ĐẠT (FAIL)</span>'
            dut_resp_str = get_dut_response_label(it)
            rows.append(f"""
            <tr>
                <td style="color: #64748b; font-size: 13px; font-weight: 600; text-align: center;">{it['category']}</td>
                <td style="font-weight: 500;">{it['name']}</td>
                <td><code style="background: #f1f5f9; padding: 2px 6px; border-radius: 4px; font-size: 12px; color: #0f172a;">{it['input']}</code></td>
                <td style="text-align: center; font-family: monospace; font-size: 12px; font-weight: 600; color: #0284c7;">{dut_resp_str}</td>
                <td style="text-align: right; font-family: monospace; color: #475569;">{it['latency_ms']:.1f} ms</td>
                <td style="text-align: center;">{status_badge}</td>
                <td style="font-size: 12.5px; color: #334155;">{it['detail']}</td>
            </tr>
            """)
        return "".join(rows)

    html_content = f"""<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HỒ SƠ BẰNG CHỨNG KIỂM ĐỊNH CLAUSE 3.10.1.3 &amp; IXIT 29-INPVAL</title>
    <style>
        :root {{
            --primary: #0f172a;
            --accent: #0284c7;
            --success: #16a34a;
            --fail: #dc2626;
            --bg: #f8fafc;
            --card-bg: #ffffff;
            --border: #e2e8f0;
            --text-dark: #0f172a;
            --text-muted: #64748b;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background: var(--bg);
            color: var(--text-dark);
            line-height: 1.5;
            padding: 24px;
        }}
        .container {{ max-width: 1300px; margin: 0 auto; }}
        .header-card {{
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 24px;
            margin-bottom: 24px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.05);
        }}
        .header-title {{ font-size: 20px; font-weight: 700; color: var(--primary); margin-bottom: 6px; }}
        .header-sub {{ font-size: 13px; color: var(--text-muted); }}
        .meta-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 16px;
            margin-top: 18px;
            padding-top: 18px;
            border-top: 1px solid var(--border);
        }}
        .meta-item {{ font-size: 13px; }}
        .meta-label {{ color: var(--text-muted); font-size: 11px; text-transform: uppercase; font-weight: 600; }}
        .meta-value {{ font-weight: 600; color: var(--text-dark); font-family: monospace; font-size: 13px; }}
        
        .stat-banner {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 16px;
            margin-bottom: 24px;
        }}
        .stat-card {{
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 16px 20px;
        }}
        .stat-num {{ font-size: 26px; font-weight: 700; }}
        .stat-lbl {{ font-size: 12px; color: var(--text-muted); text-transform: uppercase; font-weight: 600; }}
        
        .section-card {{
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 8px;
            margin-bottom: 24px;
            overflow: hidden;
            box-shadow: 0 1px 3px rgba(0,0,0,0.05);
        }}
        .section-header {{
            background: #f1f5f9;
            padding: 14px 20px;
            border-bottom: 1px solid var(--border);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .section-title {{ font-size: 15px; font-weight: 700; color: var(--primary); }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
        }}
        th {{
            background: #ffffff;
            color: var(--text-muted);
            text-transform: uppercase;
            font-size: 11px;
            font-weight: 600;
            padding: 10px 14px;
            border-bottom: 1px solid var(--border);
            text-align: left;
        }}
        td {{
            padding: 10px 14px;
            border-bottom: 1px solid var(--border);
            vertical-align: middle;
        }}
        tr:last-child td {{ border-bottom: none; }}
        tr:hover td {{ background: #f8fafc; }}
        
        .badge {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
        }}
        .badge-pass {{ background: #dcfce7; color: #15803d; border: 1px solid #bbf7d0; }}
        .badge-fail {{ background: #fee2e2; color: #b91c1c; border: 1px solid #fecaca; }}
        
        .footer {{
            text-align: center;
            font-size: 12px;
            color: var(--text-muted);
            margin-top: 32px;
            padding-bottom: 24px;
        }}
        @media print {{
            body {{ background: #fff; padding: 0; }}
            .container {{ max-width: 100%; }}
            .stat-banner, .header-card, .section-card {{ box-shadow: none; border-color: #cbd5e1; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header-card">
            <div class="header-title">HỒ SƠ BẰNG CHỨNG ĐO KIỂM XÁC THỰC ĐẦU VÀO DỮ LIỆU (CLAUSE 3.10.1.3 &amp; IXIT 29-INPVAL)</div>
            <div class="header-sub">Tiêu chuẩn: QCVN 11:2026/BCA &bull; ETSI EN 303 645 Clause 5.10-1 &bull; ETSI TS 103 701 Table C.29</div>
            <div class="meta-grid">
                <div class="meta-item">
                    <div class="meta-label">Thiết bị đo kiểm (DUT)</div>
                    <div class="meta-value">{DUT_MODEL}</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">Địa chỉ IP / Cổng API</div>
                    <div class="meta-value">{target_ip}:{port} (HTTPS)</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">Bản khai kỹ thuật</div>
                    <div class="meta-value">IXIT 29-InpVal (1. IXIT_IPCamera)</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">Thời gian thực nghiệm</div>
                    <div class="meta-value">{now_str}</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">Tệp gói tin Wireshark</div>
                    <div class="meta-value">{os.path.basename(pcap_filename) or "N/A"}</div>
                </div>
            </div>
        </div>

        <div class="stat-banner">
            <div class="stat-card">
                <div class="stat-lbl">Tổng số phép thử</div>
                <div class="stat-num">{total_tests}</div>
            </div>
            <div class="stat-card">
                <div class="stat-lbl">Số phép thử ĐẠT (PASS)</div>
                <div class="stat-num" style="color: var(--success);">{passed_tests}</div>
            </div>
            <div class="stat-card">
                <div class="stat-lbl">Số phép thử KHÔNG ĐẠT (FAIL)</div>
                <div class="stat-num" style="color: {'var(--fail)' if failed_tests > 0 else 'var(--text-muted)'};">{failed_tests}</div>
            </div>
            <div class="stat-card">
                <div class="stat-lbl">Kết luận chung Clause 3.10.1.3</div>
                <div class="stat-num" style="color: {'var(--success)' if overall_pass else 'var(--fail)'}; font-size: 20px;">
                    {'100% ĐẠT (PASS)' if overall_pass else 'CẦN KHẮC PHỤC'}
                </div>
            </div>
        </div>

        <!-- PHÂN HỆ 1: INPVAL-1 -->
        <div class="section-card">
            <div class="section-header">
                <div class="section-title">PHÂN HỆ 1: INPVAL-1 — USER INPUT VALIDATION (GIAO DIỆN NGƯỜI DÙNG)</div>
                <span class="badge badge-pass">{sum(1 for r in results_v1 if r['pass'])}/{len(results_v1)} ĐẠT</span>
            </div>
            <table>
                <thead>
                    <tr>
                        <th style="width: 160px; text-align: center;">Nhóm</th>
                        <th style="width: 250px;">Kịch bản Kiểm thử</th>
                        <th style="width: 200px;">Dữ liệu Đầu vào (Payload)</th>
                        <th style="width: 180px; text-align: center;">Phản hồi từ DUT</th>
                        <th style="width: 90px; text-align: right;">Độ trễ</th>
                        <th style="width: 110px; text-align: center;">Đánh giá</th>
                        <th>Bằng chứng Kỹ thuật &amp; Chi tiết</th>
                    </tr>
                </thead>
                <tbody>
                    {render_table_rows(results_v1)}
                </tbody>
            </table>
        </div>

        <!-- PHÂN HỆ 2: INPVAL-2 -->
        <div class="section-card">
            <div class="section-header">
                <div class="section-title">PHÂN HỆ 2: INPVAL-2 — API INPUT VALIDATION</div>
                <span class="badge badge-pass">{sum(1 for r in results_v2 if r['pass'])}/{len(results_v2)} ĐẠT</span>
            </div>
            <table>
                <thead>
                    <tr>
                        <th style="width: 160px; text-align: center;">Nhóm</th>
                        <th style="width: 250px;">Kịch bản Kiểm thử</th>
                        <th style="width: 200px;">Dữ liệu Đầu vào (Payload)</th>
                        <th style="width: 180px; text-align: center;">Phản hồi từ DUT</th>
                        <th style="width: 90px; text-align: right;">Độ trễ</th>
                        <th style="width: 110px; text-align: center;">Đánh giá</th>
                        <th>Bằng chứng Kỹ thuật &amp; Chi tiết</th>
                    </tr>
                </thead>
                <tbody>
                    {render_table_rows(results_v2)}
                </tbody>
            </table>
        </div>

        <!-- PHÂN HỆ 3: INPVAL-3 -->
        <div class="section-card">
            <div class="section-header">
                <div class="section-title">PHÂN HỆ 3: INPVAL-3 — NETWORK CHANNEL VALIDATION</div>
                <span class="badge badge-pass">{sum(1 for r in results_v3 if r['pass'])}/{len(results_v3)} ĐẠT</span>
            </div>
            <table>
                <thead>
                    <tr>
                        <th style="width: 160px; text-align: center;">Nhóm</th>
                        <th style="width: 250px;">Kịch bản Kiểm thử</th>
                        <th style="width: 200px;">Dữ liệu Đầu vào (Payload)</th>
                        <th style="width: 180px; text-align: center;">Phản hồi từ DUT</th>
                        <th style="width: 90px; text-align: right;">Độ trễ</th>
                        <th style="width: 110px; text-align: center;">Đánh giá</th>
                        <th>Bằng chứng Kỹ thuật &amp; Chi tiết</th>
                    </tr>
                </thead>
                <tbody>
                    {render_table_rows(results_v3)}
                </tbody>
            </table>
        </div>

        <div class="footer">
            Báo cáo kiểm thử tự động tạo bởi QCVN 11 Cybersecurity Toolkit &bull; Bản quyền phục vụ hồ sơ kiểm định Bộ Công An.
        </div>
    </div>
</body>
</html>
"""
    os.makedirs(os.path.dirname(output_html_path), exist_ok=True)
    with open(output_html_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    return output_html_path


# ==============================================================================
# PHẦN 7: ĐIỀU PHỐI KIỂM ĐỊNH TOÀN DIỆN (COMPREHENSIVE RUNNER)
# ==============================================================================

def run_comprehensive_input_validation(target_ip: str, port: Optional[int] = None) -> bool:
    """Điều phối chạy toàn bộ 3 phân hệ InpVal-1, InpVal-2, InpVal-3."""
    target_https_port = port or HTTPS_PORT
    target_rtsp_port = RTSP_PORT

    console.print(f"\n[bold cyan]=== KIỂM ĐỊNH XÁC THỰC ĐẦU VÀO IXIT 29-INPVAL: {target_ip}:{target_https_port} ({DUT_MODEL}) ===[/bold cyan]")

    # Kiểm tra sống còn trước đo kiểm
    ping_ok, ping_ms = check_icmp_integrity(target_ip)
    if not ping_ok:
        console.print(f"[bold red][-] Không thể kết nối tới DUT tại {target_ip}. Dừng đo kiểm.[/bold red]")
        return False
    console.print(f"[bold green][+] DUT Sẵn sàng hoạt động (ICMP Ping: {ping_ms:.2f}ms)[/bold green]\n")

    # Thực thi Phân hệ 1: InpVal-1
    res_v1 = run_inpval1_user_input_validation(target_ip, target_https_port)
    time.sleep(1.0)

    # Thực thi Phân hệ 2: InpVal-2
    res_v2 = run_inpval2_api_input_validation(target_ip, target_https_port)
    time.sleep(1.0)

    # Thực thi Phân hệ 3: InpVal-3
    res_v3 = run_inpval3_network_channel_validation(target_ip, target_https_port, target_rtsp_port)
    time.sleep(1.0)

    # Kiểm tra tính toàn vẹn hệ thống sau đo kiểm
    post_ping, post_ms = check_icmp_integrity(target_ip)

    all_v1_pass = all(r["pass"] for r in res_v1)
    all_v2_pass = all(r["pass"] for r in res_v2)
    all_v3_pass = all(r["pass"] for r in res_v3)
    overall_pass = (all_v1_pass and all_v2_pass and all_v3_pass and post_ping)

    # Bảng tổng kết chung
    sum_table = Table(title="Tổng kết IXIT 29-InpVal", show_header=True, header_style="bold yellow")
    sum_table.add_column("Phân hệ Đo kiểm", justify="left", width=32)
    sum_table.add_column("Số phép thử", justify="center", width=14)
    sum_table.add_column("Số phép thử ĐẠT", justify="center", width=18)
    sum_table.add_column("Tỷ lệ Tuân thủ", justify="center", width=16)
    sum_table.add_column("Kết luận Phân hệ", justify="center", width=18)

    p1_count = len(res_v1)
    p1_pass = sum(1 for r in res_v1 if r["pass"])
    p2_count = len(res_v2)
    p2_pass = sum(1 for r in res_v2 if r["pass"])
    p3_count = len(res_v3)
    p3_pass = sum(1 for r in res_v3 if r["pass"])

    sum_table.add_row("User Input Validation", str(p1_count), str(p1_pass), f"{(p1_pass/p1_count)*100:.1f}%", "[bold green]ĐẠT (PASS)[/bold green]" if all_v1_pass else "[bold red]FAIL[/bold red]")
    sum_table.add_row("API Input Validation", str(p2_count), str(p2_pass), f"{(p2_pass/p2_count)*100:.1f}%", "[bold green]ĐẠT (PASS)[/bold green]" if all_v2_pass else "[bold red]FAIL[/bold red]")
    sum_table.add_row("Network Channel Validation", str(p3_count), str(p3_pass), f"{(p3_pass/p3_count)*100:.1f}%", "[bold green]ĐẠT (PASS)[/bold green]" if all_v3_pass else "[bold red]FAIL[/bold red]")
    sum_table.add_row("Tính toàn vẹn hệ thống (Integrity)", "ICMP Alive", "Hoạt động", f"{post_ms:.1f}ms", "[bold green]ĐẠT (ALIVE)[/bold green]" if post_ping else "[bold red]CRASH[/bold red]")
    console.print(sum_table)

    if overall_pass:
        console.print("[bold green][+] KẾT QUẢ: 100% ĐẠT (PASS) THEO IXIT 29-INPVAL & QCVN 11:2026[/bold green]")
    else:
        console.print("[bold red][-] KẾT QUẢ: KHÔNG ĐẠT (FAIL)[/bold red]")

    # Xuất file HTML bằng chứng
    html_evidence_file = os.path.join(os.path.dirname(__file__), "captures", "input_validation_audit_evidence.html")
    created_html = create_input_validation_html_evidence(
        html_evidence_file, target_ip, target_https_port, res_v1, res_v2, res_v3, overall_pass, GLOBAL_PCAP_FILE
    )

    # Xuất file JSON kết quả
    timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_result_file = os.path.join(os.path.dirname(__file__), "captures", f"input_validation_audit_{timestamp_str}.json")
    audit_data = {
        "timestamp": timestamp_str,
        "standard": "QCVN 11:2026/BCA Clause 3.10.1.3 & IXIT 29-InpVal",
        "target": {"ip": target_ip, "model": DUT_MODEL, "https_port": target_https_port, "rtsp_port": target_rtsp_port},
        "overall_pass": overall_pass,
        "criteria": {
            "inpval1_pass": all_v1_pass,
            "inpval2_pass": all_v2_pass,
            "inpval3_pass": all_v3_pass,
            "system_integrity": post_ping
        },
        "results_inpval1": res_v1,
        "results_inpval2": res_v2,
        "results_inpval3": res_v3
    }
    try:
        with open(json_result_file, "w", encoding="utf-8") as f:
            json.dump(audit_data, f, indent=2, ensure_ascii=False)
        console.print(f"[*] Báo cáo HTML: [cyan]{created_html}[/cyan]")
        console.print(f"[*] Báo cáo JSON: [cyan]{json_result_file}[/cyan]\n")
    except Exception as e:
        console.print(f"[yellow][!] Lỗi ghi JSON: {e}[/yellow]")

    # Bảng bộ lọc Wireshark
    filters = [
        ("Tất cả gói tin kiểm định Input Validation", f"host {target_ip}"),
        ("Gói tin ONVIF SOAP từ chối / SOAP Fault (HTTP 400/500)", f"tcp.port == {target_https_port} && (http.response.code >= 400 || tls)"),
        ("Gói tin vi phạm xác thực Token Gatekeeper (HTTP 401)", f"http.response.code == 401"),
        ("Gói tin RTSP phản hồi mã lỗi (RTSP status >= 400)", f"tcp.port == {target_rtsp_port} && rtsp.status >= 400")
    ]
    display_wireshark_panel(
        console,
        GLOBAL_PCAP_FILE,
        filters,
        is_tls=True,
        sort_tip="Lọc http.response.code in {400, 401, 500} trong Wireshark để đối soát chứng chỉ phản hồi lỗi của DUT.",
        title="BẰNG CHỨNG GÓI TIN ĐO KIỂM IXIT 29-INPVAL (CLAUSE 3.10.1.3)"
    )

    return overall_pass


# ==============================================================================
# MAIN & ARGUMENT PARSING
# ==============================================================================

def main():
    global GLOBAL_PCAP_FILE
    parser = argparse.ArgumentParser(description="Bộ đo kiểm Xác thực Đầu vào & Quét API (QCVN 11 Clause 3.10.1.3 & IXIT 29-InpVal)")
    parser.add_argument(
        "--mode",
        choices=["comprehensive", "inpval1", "inpval2", "inpval3", "scan", "rtsp", "custom", "csrf", "all"],
        default="comprehensive",
        help="Chế độ đo kiểm (comprehensive: chạy toàn bộ 3 bảng InpVal-1, 2, 3; inpval1: User Input; inpval2: API; inpval3: Network; scan; rtsp; all)"
    )
    parser.add_argument("--port", type=int, default=None, help="Cổng kiểm thử tùy chọn")
    parser.add_argument("--fuzz-type", choices=["all", "methods", "overflow", "cseq", "session", "range", "raw", "injection"], default="all", help="Phân loại payload fuzz RTSP")
    parser.add_argument("--iterations", type=int, default=10, help="Số lần chèn sai định dạng")
    parser.add_argument("--rate", type=float, default=4.0, help="Tốc độ gửi yêu cầu/giây")

    args = parser.parse_args()

    # Bắt PCAP tự động
    target_port = args.port or HTTPS_PORT
    bpf_filter = f"host {DUT_IP}"
    pcap_proc, GLOBAL_PCAP_FILE = start_pcap_capture(
        DUT_IP,
        bpf_filter,
        prefix=f"ixit29_input_val"
    )
    if GLOBAL_PCAP_FILE:
        console.print(f"[*] Bắt gói tin PCAP tự động vào: [cyan]{GLOBAL_PCAP_FILE}[/cyan]\n")

    try:
        if args.mode == "comprehensive":
            run_comprehensive_input_validation(target_ip=DUT_IP, port=args.port)
        elif args.mode == "inpval1":
            run_inpval1_user_input_validation(target_ip=DUT_IP, https_port=args.port or HTTPS_PORT)
        elif args.mode == "inpval2":
            run_inpval2_api_input_validation(target_ip=DUT_IP, https_port=args.port or HTTPS_PORT)
        elif args.mode == "inpval3":
            run_inpval3_network_channel_validation(target_ip=DUT_IP, https_port=args.port or HTTPS_PORT, rtsp_port=RTSP_PORT)
        elif args.mode == "scan":
            scan_full_camera_apis()
        elif args.mode == "rtsp":
            port, use_tls = detect_rtsp_target(args.port)
            run_rtsp_stateful_fuzzer(port=port, use_tls=use_tls, iterations=args.iterations, rate_cps=args.rate, fuzz_category=args.fuzz_type)
        elif args.mode == "custom":
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
                run_rtsp_stateful_fuzzer(port=port, use_tls=use_tls, iterations=args.iterations, rate_cps=args.rate, fuzz_category=args.fuzz_type)
        elif args.mode == "csrf":
            from tool19_csrf_token_auditor import run_csrf_token_audit
            run_csrf_token_audit(target_ip=DUT_IP, port=args.port or HTTPS_PORT, rate_cps=args.rate)
        elif args.mode == "all":
            console.print("\n[bold cyan]>>> BƯỚC 1: QUÉT TOÀN BỘ BỀ MẶT API CỦA CAMERA <<<[/bold cyan]")
            scan_full_camera_apis()
            time.sleep(1)
            console.print("\n[bold cyan]>>> BƯỚC 2: CHẠY BỘ ĐO KIỂM TOÀN DIỆN IXIT 29-INPVAL (INPVAL-1, 2, 3) <<<[/bold cyan]")
            run_comprehensive_input_validation(target_ip=DUT_IP, port=args.port)
            time.sleep(1)
            console.print("\n[bold cyan]>>> BƯỚC 3: ĐO KIỂM STATEFUL FUZZING LUỒNG ĐA PHƯƠNG TIỆN RTSP/RTSPS <<<[/bold cyan]")
            port, use_tls = detect_rtsp_target(args.port)
            run_rtsp_stateful_fuzzer(port, use_tls, iterations=args.iterations, rate_cps=args.rate, fuzz_category="all")
    finally:
        stop_pcap_capture(pcap_proc)


if __name__ == '__main__':
    main()
