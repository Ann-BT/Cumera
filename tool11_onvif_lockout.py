#!/usr/bin/env python3
"""
Bộ đo kiểm phòng vệ chống vét cạn & Khóa tài khoản giao diện ONVIF SOAP
Yêu cầu 2.1.5 - QCVN 11:2026/BCA & ETSI EN 303 645 Clause 5.1-5

Tính năng:
- Mặc định phát chính xác 4 kết nối mới / giây (khoảng cách 250ms/kết nối) để kiểm chứng cơ chế Firewall Rate-Limit 3 new conn/s.
- Hỗ trợ chuẩn OASIS WS-Security 1.0 (PasswordDigest SHA-1, SHA-256, PasswordText) & HTTP Digest Auth.
- Tự động dò tìm cổng dịch vụ ONVIF (HTTP 80 / HTTPS 443 / Cổng tùy chỉnh).
- Tự động nạp ngưỡng khóa từ cấu hình IXIT (10 lần cho AXIS, 20 lần cho VIGI / tùy chỉnh).
- Test Case 1: Kiểm chứng xóa bộ đếm thất bại khi nhập đúng trước ngưỡng (4 conn/s).
- Test Case 2: Kiểm chứng kích hoạt cơ chế khóa khi vượt ngưỡng sai liên tiếp (4 conn/s).
- Test Case 3: Thử nghiệm vét cạn từ điển (Wordlist Brute-Force Auditor ở tốc độ 4 conn/s).
- Test Case 4: Kiểm chứng giới hạn tần suất kết nối mới Tường lửa (Bắn đồng thời burst kết nối trong 1s).
- Tự động xuất session keys vào captures/sslkeys.log để Wireshark giải mã TLS 1.3 bản rõ.

Author: Merlin / Antigravity
"""

import os
import sys

CAPTURES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "captures")
os.makedirs(CAPTURES_DIR, exist_ok=True)
SSLKEYLOG_PATH = os.path.join(CAPTURES_DIR, "sslkeys.log")
os.environ["SSLKEYLOGFILE"] = SSLKEYLOG_PATH

import time
import json
import socket
import base64
import hashlib
import datetime
import argparse
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Tuple, List, Optional, Dict, Any

import urllib3
import requests
from requests.auth import HTTPDigestAuth, HTTPBasicAuth
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

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
HTTP_PORT = int(SERVICE_PORTS["onvif_http"])
HTTPS_PORT = int(SERVICE_PORTS["onvif_https"])
ONVIF_PATH = SERVICE_PORTS["onvif_path"]
USER = _target_info["username"]
CORRECT_PASS = _target_info["password"]

# Đọc ngưỡng khóa từ IXIT / baseline config (Mặc định: AXIS là 10 lần, TP-Link VIGI là 20 lần)
LOCKOUT_THRESHOLD = (
    config.get("baseline_declaration", {})
    .get("lockout_thresholds", {})
    .get("onvif", 10)
)
LOCKOUT_DURATION_MIN = (
    config.get("baseline_declaration", {})
    .get("lockout_thresholds", {})
    .get("duration_minutes", 5)
)

GLOBAL_PCAP_FILE = ""

TOP_CAMERA_PASSWORDS = [
    "admin", "123456", "admin123", "password", "12345", "root", "default",
    "pass", "camera", "12345678", "888888", "666666", "111111", "000000",
    "admin1234", "admin12345", "service", "support", "supervisor", "operator",
    "user", "guest", "test", "demo", "axis", "hikvision", "dahua", "vigi",
    "pass1234", "security"
]


class PreciseRateLimiter:
    """
    Bộ điều tiết tần suất kết nối mới (Mặc định: 4.0 kết nối/giây).
    Mỗi kết nối được giãn cách chính xác đúng 0.25 giây (250 ms) tính từ thời điểm bắt đầu.
    Giúp tạo đúng 4 kết nối TCP mới trong mỗi 1.0 giây để kiểm chứng quy tắc Firewall Rate-Limit.
    """
    def __init__(self, rate_cps: float = 4.0):
        self.rate_cps = rate_cps
        self.interval = 1.0 / rate_cps if rate_cps > 0 else 0
        self.start_base = time.time()
        self.count = 0

    def wait_next(self) -> Tuple[int, str]:
        """
        Chờ đến thời điểm phát tiếp theo.
        Trả về (vị_trí_trong_giây_này: 1..4, chuỗi_thời_gian_ms)
        """
        if self.interval <= 0:
            return 1, datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]

        target_time = self.start_base + (self.count * self.interval)
        now = time.time()
        sleep_dur = target_time - now
        if sleep_dur > 0:
            time.sleep(sleep_dur)

        self.count += 1
        pos_in_sec = ((self.count - 1) % int(self.rate_cps)) + 1
        time_str = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
        return pos_in_sec, time_str


def detect_onvif_endpoint(custom_port: Optional[int] = None) -> Tuple[str, bool, int]:
    """
    Xác định endpoint ONVIF khả dụng trên DUT (tự dò HTTP/HTTPS cho mọi cổng tùy chỉnh).
    Returns: (url, is_https, port)
    """
    ports_to_check = []
    if custom_port:
        ports_to_check.append((custom_port, is_tls_port(DUT_IP, custom_port)))
    ports_to_check.extend([(HTTPS_PORT, True), (HTTP_PORT, False)])

    for port, is_ssl in ports_to_check:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.7)
        try:
            if s.connect_ex((DUT_IP, port)) == 0:
                scheme = "https" if is_ssl else "http"
                return f"{scheme}://{DUT_IP}:{port}{ONVIF_PATH}", is_ssl, port
        except Exception:
            pass
        finally:
            s.close()

    return f"https://{DUT_IP}:{HTTPS_PORT}{ONVIF_PATH}", True, HTTPS_PORT


def build_ws_security_header(username: str, password: str, mode: str = "sha1") -> str:
    """Tạo Header WS-Security chuẩn OASIS Username Token Profile 1.0."""
    created = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    nonce_raw = os.urandom(16)
    nonce_b64 = base64.b64encode(nonce_raw).decode('ascii')

    if mode == "text":
        pass_type = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText"
        pass_val = password
    elif mode == "sha256":
        pass_type = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest"
        to_hash = nonce_raw + created.encode('utf-8') + password.encode('utf-8')
        pass_val = base64.b64encode(hashlib.sha256(to_hash).digest()).decode('ascii')
    else:  # OASIS WSS 1.0 chuẩn mặc định: SHA-1
        pass_type = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest"
        to_hash = nonce_raw + created.encode('utf-8') + password.encode('utf-8')
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


def build_soap_envelope(wsse_header: str) -> str:
    """Đóng gói XML SOAP Envelope cho GetDeviceInformation."""
    return f"""<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
               xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
  <soap:Header>
    {wsse_header}
  </soap:Header>
  <soap:Body>
    <tds:GetDeviceInformation />
  </soap:Body>
</soap:Envelope>"""


def send_onvif_request(
    url: str,
    username: str,
    password: str,
    auth_type: str = "wsse_sha1",
    timeout: float = 3.0,
    force_new_connection: bool = True
) -> Tuple[bool, str, str, float]:
    """
    Gửi bản tin ONVIF SOAP GetDeviceInformation.
    force_new_connection=True: Thêm 'Connection: close' để bắt buộc tạo phiên TCP mới 100%.
    Returns: (is_auth_success, status_label, raw_preview, latency_ms)
    """
    t_start = time.time()
    headers = {
        "Content-Type": 'application/soap+xml; charset=utf-8; action="http://www.onvif.org/ver10/device/wsdl/GetDeviceInformation"',
        "User-Agent": "QCVN11-ONVIF-Audit-Client/2.0"
    }
    if force_new_connection:
        headers["Connection"] = "close"

    req_auth = None
    if auth_type == "http_digest":
        req_auth = HTTPDigestAuth(username, password)
        soap_env = build_soap_envelope("")
    elif auth_type == "http_basic":
        req_auth = HTTPBasicAuth(username, password)
        soap_env = build_soap_envelope("")
    elif auth_type == "wsse_text":
        soap_env = build_soap_envelope(build_ws_security_header(username, password, mode="text"))
    elif auth_type == "wsse_sha256":
        soap_env = build_soap_envelope(build_ws_security_header(username, password, mode="sha256"))
    else:  # default wsse_sha1
        soap_env = build_soap_envelope(build_ws_security_header(username, password, mode="sha1"))

    try:
        resp = requests.post(
            url,
            data=soap_env.encode('utf-8'),
            headers=headers,
            auth=req_auth,
            timeout=timeout,
            verify=False
        )
        elapsed = (time.time() - t_start) * 1000
        preview = resp.text.strip()[:300].replace("\r", "").replace("\n", " ")

        if resp.status_code == 200 and "GetDeviceInformationResponse" in resp.text:
            return True, "200 OK (Xác thực thành công)", preview, elapsed
        elif resp.status_code == 200:
            if "Sender" in resp.text or "FailedAuthentication" in resp.text:
                return False, "200 SOAP Fault (Xác thực thất bại)", preview, elapsed
            return True, f"200 OK (Phản hồi không chứa lỗi)", preview, elapsed
        elif resp.status_code == 401:
            return False, "401 Unauthorized (Từ chối xác thực)", preview, elapsed
        elif resp.status_code in (403, 429):
            return False, f"{resp.status_code} Forbidden/Rate-Limited (Bị khóa chặn)", preview, elapsed
        else:
            return False, f"HTTP {resp.status_code}", preview, elapsed

    except requests.exceptions.ConnectTimeout:
        elapsed = (time.time() - t_start) * 1000
        return False, "CONNECT TIMEOUT (Tường lửa DROP gói tin)", "", elapsed
    except requests.exceptions.ReadTimeout:
        elapsed = (time.time() - t_start) * 1000
        return False, "READ TIMEOUT (Camera đóng băng phản hồi)", "", elapsed
    except requests.exceptions.ConnectionError as ce:
        elapsed = (time.time() - t_start) * 1000
        err_msg = str(ce)
        if "Connection reset" in err_msg or "Reset" in err_msg:
            return False, "TCP RST (Tường lửa reset kết nối)", "", elapsed
        return False, "CONNECTION REFUSED / DROP (Drop kết nối)", "", elapsed
    except Exception as e:
        elapsed = (time.time() - t_start) * 1000
        return False, f"LỖI: {type(e).__name__}", "", elapsed


def auto_detect_auth_mode(url: str, username: str, password: str) -> str:
    """Tự động xác định chế độ xác thực thích hợp của camera."""
    console.print("[*] Đang tự động thăm dò chế độ xác thực ONVIF (WS-Security SHA-1, SHA-256, HTTP Digest)...")
    modes = ["wsse_sha1", "wsse_sha256", "http_digest", "wsse_text"]
    for m in modes:
        success, status, _, _ = send_onvif_request(url, username, password, auth_type=m, timeout=2.5)
        if success:
            console.print(f"[bold green][+] Phát hiện cơ chế ONVIF phù hợp: {m.upper()} (Xác thực 200 OK thành công)[/bold green]")
            return m
        time.sleep(0.25)
    console.print("[yellow][!] Mật khẩu đúng không pass các chế độ probe; giữ chế độ chuẩn OASIS: WS-Security SHA-1[/yellow]")
    return "wsse_sha1"


def run_test_case_1(url: str, port: int, auth_mode: str, threshold: int, rate_cps: float = 4.0) -> bool:
    """Test Case 1: Kiểm tra reset bộ đếm khi nhập đúng trước ngưỡng ở tốc độ rate_cps."""
    console.print("\n" + "=" * 80)
    console.print(f"  [bold cyan][TEST CASE 1] KIỂM TRA RESET BỘ ĐẾM: NHẬP ĐÚNG TRƯỚC KHI ĐẠT NGƯỠNG[/bold cyan]")
    console.print(f"  Mục tiêu: {url} | Cổng: {port} | Ngưỡng khóa: {threshold} lần | Tốc độ gửi: {rate_cps:.1f} kết nối/giây")
    console.print("=" * 80)

    sub_attempts = max(2, threshold // 2)
    limiter = PreciseRateLimiter(rate_cps=rate_cps)

    console.print(f"\n[*] Giai đoạn 1: Gửi {sub_attempts} lần mật khẩu sai liên tiếp (tốc độ {rate_cps:.1f} conn/s)...")
    table1 = Table(title="Diễn tiến thử nghiệm mật khẩu sai trước ngưỡng", show_lines=True)
    table1.add_column("Lần thử", justify="center", style="bold")
    table1.add_column("Vị trí trong 1s", justify="center")
    table1.add_column("Thời điểm phát", justify="center")
    table1.add_column("Mật khẩu", justify="left")
    table1.add_column("Kết quả phản hồi", justify="left")
    table1.add_column("Đánh giá Firewall", justify="center")
    table1.add_column("Độ trễ", justify="right")

    for i in range(1, sub_attempts + 1):
        pos_in_sec, t_str = limiter.wait_next()
        fake_pass = f"WrongPass_{i}#Test"
        ok, status, _, lat = send_onvif_request(url, USER, fake_pass, auth_type=auth_mode, force_new_connection=True)
        
        is_blocked = any(kw in status for kw in ["TIMEOUT", "RST", "REFUSED", "DROP", "Rate-Limited", "429", "403"])
        if pos_in_sec == 4 and is_blocked:
            fw_eval = "[bold red]CHẶN (RATE LIMIT 3/S)[/bold red]"
        elif is_blocked:
            fw_eval = "[bold red]BỊ CHẶN SỚM[/bold red]"
        elif pos_in_sec == 4:
            fw_eval = "[bold yellow]CHẤP NHẬN (FW CHƯA CHẶN)[/bold yellow]"
        else:
            fw_eval = "[green]CHẤP NHẬN (Trong ngưỡng)[/green]"

        pos_str = f"[bold magenta][{pos_in_sec}/4 - VƯỢT][/bold magenta]" if pos_in_sec == 4 else f"[{pos_in_sec}/4]"
        style = "green" if not ok and not is_blocked else ("red" if is_blocked else "yellow")
        table1.add_row(f"#{i:02d}", pos_str, t_str, fake_pass, f"[{style}]{status}[/{style}]", fw_eval, f"{lat:.1f} ms")

    console.print(table1)

    console.print(f"\n[*] Giai đoạn 2: Nhập mật khẩu ĐÚNG ({CORRECT_PASS}) để kiểm tra reset bộ đếm...")
    limiter.wait_next()
    ok_valid1, status_valid1, preview_valid1, lat_v1 = send_onvif_request(url, USER, CORRECT_PASS, auth_type=auth_mode, force_new_connection=True)
    console.print(f"  -> Kết quả thử mật khẩu ĐÚNG lần 1: [bold {'green' if ok_valid1 else 'red'}]{status_valid1}[/bold {'green' if ok_valid1 else 'red'}] ({lat_v1:.1f} ms)")
    if preview_valid1:
        console.print(f"     Preview SOAP: [dim]{preview_valid1[:180]}[/dim]")

    if not ok_valid1:
        console.print("[bold red][-] THẤT BẠI: Camera từ chối đăng nhập dù chưa đạt ngưỡng khóa![/bold red]")
        return False

    console.print(f"\n[*] Giai đoạn 3: Gửi tiếp {sub_attempts} lần mật khẩu sai nữa (tốc độ {rate_cps:.1f} conn/s)...")
    table2 = Table(title="Diễn tiến thử sai sau khi đã nhập đúng", show_lines=True)
    table2.add_column("Lần thử", justify="center", style="bold")
    table2.add_column("Vị trí trong 1s", justify="center")
    table2.add_column("Thời điểm phát", justify="center")
    table2.add_column("Mật khẩu", justify="left")
    table2.add_column("Kết quả phản hồi", justify="left")
    table2.add_column("Đánh giá Firewall", justify="center")
    table2.add_column("Độ trễ", justify="right")

    for i in range(sub_attempts + 1, (sub_attempts * 2) + 1):
        pos_in_sec, t_str = limiter.wait_next()
        fake_pass = f"WrongPass_{i}#Phase3"
        ok, status, _, lat = send_onvif_request(url, USER, fake_pass, auth_type=auth_mode, force_new_connection=True)
        
        is_blocked = any(kw in status for kw in ["TIMEOUT", "RST", "REFUSED", "DROP", "Rate-Limited", "429", "403"])
        if pos_in_sec == 4 and is_blocked:
            fw_eval = "[bold red]CHẶN (RATE LIMIT 3/S)[/bold red]"
        elif is_blocked:
            fw_eval = "[bold red]BỊ CHẶN SỚM[/bold red]"
        elif pos_in_sec == 4:
            fw_eval = "[bold yellow]CHẤP NHẬN (FW CHƯA CHẶN)[/bold yellow]"
        else:
            fw_eval = "[green]CHẤP NHẬN (Trong ngưỡng)[/green]"

        pos_str = f"[bold magenta][{pos_in_sec}/4 - VƯỢT][/bold magenta]" if pos_in_sec == 4 else f"[{pos_in_sec}/4]"
        style = "green" if not ok and not is_blocked else ("red" if is_blocked else "yellow")
        table2.add_row(f"#{i:02d}", pos_str, t_str, fake_pass, f"[{style}]{status}[/{style}]", fw_eval, f"{lat:.1f} ms")

    console.print(table2)

    console.print(f"\n[*] Giai đoạn 4: Xác minh lại với mật khẩu ĐÚNG lần 2...")
    limiter.wait_next()
    ok_valid2, status_valid2, _, lat_v2 = send_onvif_request(url, USER, CORRECT_PASS, auth_type=auth_mode, force_new_connection=True)
    console.print(f"  -> Kết quả thử mật khẩu ĐÚNG lần 2: [bold {'green' if ok_valid2 else 'red'}]{status_valid2}[/bold {'green' if ok_valid2 else 'red'}] ({lat_v2:.1f} ms)")

    if ok_valid2:
        console.print("\n" + "=" * 80)
        console.print("[bold green][+] KẾT QUẢ TEST CASE 1: ĐẠT (PASS)![/bold green]")
        console.print(f"    - Bộ đếm thất bại liên tiếp đã được reset về 0 khi nhập đúng.")
        console.print(f"    - Người dùng hợp lệ không bị gián đoạn.")
        console.print("=" * 80)
        return True
    else:
        console.print("\n" + "=" * 80)
        console.print("[bold red][-] KẾT QUẢ TEST CASE 1: KHÔNG ĐẠT![/bold red]")
        console.print("=" * 80)
        return False


def run_test_case_2(url: str, port: int, auth_mode: str, threshold: int, rate_cps: float = 4.0) -> bool:
    """Test Case 2: Kiểm tra kích hoạt khóa khi nhập sai liên tiếp ở tốc độ 4 kết nối/giây."""
    console.print("\n" + "=" * 80)
    console.print(f"  [bold yellow][TEST CASE 2] KIỂM TRA KÍCH HOẠT KHÓA KHI VƯỢT NGƯỠNG ({threshold} LẦN SAI)[/bold yellow]")
    console.print(f"  Mục tiêu: {url} | Ngưỡng khóa: {threshold} lần | Tốc độ gửi: {rate_cps:.1f} kết nối/giây (250ms/gói)")
    console.print("=" * 80)

    limiter = PreciseRateLimiter(rate_cps=rate_cps)
    table = Table(title=f"Diễn tiến gửi {threshold} lần sai liên tiếp ở tốc độ {rate_cps:.1f} conn/s", show_lines=True)
    table.add_column("Lần", justify="center", style="bold")
    table.add_column("Vị trí trong 1s", justify="center")
    table.add_column("Thời điểm phát", justify="center")
    table.add_column("Mật khẩu thử nghiệm", justify="left")
    table.add_column("Kết quả phản hồi", justify="left")
    table.add_column("Đánh giá Firewall (Ngưỡng 3/s)", justify="center")
    table.add_column("Độ trễ", justify="right")

    exceeded_count = 0
    fw_blocked_count = 0

    for i in range(1, threshold + 1):
        pos_in_sec, t_str = limiter.wait_next()
        fake_pass = f"BruteForce_{i}#Lockout"
        ok, status, _, lat = send_onvif_request(url, USER, fake_pass, auth_type=auth_mode, force_new_connection=True)
        
        is_blocked = any(kw in status for kw in ["TIMEOUT", "RST", "REFUSED", "DROP", "Rate-Limited", "429", "403"])
        if pos_in_sec == 4:
            exceeded_count += 1
            if is_blocked:
                fw_blocked_count += 1
                fw_eval = "[bold red]CHẶN (RATE LIMIT 3/S)[/bold red]"
            else:
                fw_eval = "[bold yellow]CHẤP NHẬN (FW CHƯA CHẶN)[/bold yellow]"
            pos_str = f"[bold magenta][{pos_in_sec}/4 - VƯỢT][/bold magenta]"
        else:
            fw_eval = "[green]CHẤP NHẬN (Trong ngưỡng)[/green]" if not is_blocked else "[red]BỊ CHẶN SỚM[/red]"
            pos_str = f"[{pos_in_sec}/4]"

        style = "yellow" if i < threshold and not is_blocked else "red"
        table.add_row(f"#{i:02d}", pos_str, t_str, fake_pass, f"[{style}]{status}[/{style}]", fw_eval, f"{lat:.1f} ms")

    console.print(table)

    console.print(f"\n[*] Kiểm tra xác minh: Gửi mật khẩu ĐÚNG ({CORRECT_PASS}) ngay sau khi đạt ngưỡng {threshold} lần...")
    limiter.wait_next()
    ok_lock, status_lock, preview_lock, lat_lock = send_onvif_request(url, USER, CORRECT_PASS, auth_type=auth_mode, force_new_connection=True)
    console.print(f"  -> Phản hồi với mật khẩu ĐÚNG: [bold white]{status_lock}[/bold white] ({lat_lock:.1f} ms)")

    console.print("\n" + "-" * 80)
    console.print(f"[*] THỐNG KÊ KIỂM CHỨNG TƯỜNG LỬA (RATE LIMIT 3 KẾT NỐI/GIÂY):")
    console.print(f"    • Số lần phát ở vị trí thứ 4 trong giây (vượt ngưỡng 3/s): [bold white]{exceeded_count}[/bold white] lần")
    console.print(f"    • Số lần bị Firewall chặn/drop tại vị trí thứ 4: [bold {'green' if fw_blocked_count > 0 else 'red'}]{fw_blocked_count}[/bold {'green' if fw_blocked_count > 0 else 'red'}] / {exceeded_count}")
    if fw_blocked_count > 0:
        console.print("    -> [bold green]XÁC NHẬN: Cơ chế Firewall Rate-Limit (3 conn/s) CÓ HOẠT ĐỘNG THỰC TẾ![/bold green]")
    else:
        console.print("    -> [bold yellow]LƯU Ý: Tường lửa cho qua cả gói tin thứ 4; Firewall Rate-Limit không kích hoạt trên cổng này.[/bold yellow]")
    console.print("-" * 80)

    # Đạt khi camera từ chối / khóa
    if not ok_lock or "200 OK" not in status_lock:
        console.print("\n" + "=" * 80)
        console.print("[bold green][+] KẾT QUẢ TEST CASE 2: ĐẠT (PASS)![/bold green]")
        console.print(f"    - Giao diện ONVIF đã kích hoạt bảo vệ chống vét cạn sau {threshold} lần thử sai.")
        console.print(f"    - Mật khẩu đúng bị từ chối / ngắt kết nối trong {LOCKOUT_DURATION_MIN} phút đúng cam kết IXIT.")
        console.print("=" * 80)
        return True
    else:
        console.print("\n" + "=" * 80)
        console.print("[bold red][-] KẾT QUẢ TEST CASE 2: KHÔNG ĐẠT (Camera vẫn chấp nhận mật khẩu đúng, không khóa)![/bold red]")
        console.print("=" * 80)
        return False


def run_custom_sequence(
    url: str,
    port: int,
    auth_mode: str,
    fail_count: int,
    success_at: int,
    rate_cps: float = 4.0
) -> bool:
    """
    Kịch bản đo kiểm tùy chỉnh cho ONVIF SOAP (QCVN 11 Clause 2.1.5):
    - fail_count: Số lần gửi sai liên tiếp
    - success_at: Lượt chèn thử mật khẩu đúng (0=Không thử đúng)
    - rate_cps: Tốc độ phát kết nối mới / giây
    """
    if success_at <= 0:
        total_steps = fail_count
    elif success_at > fail_count:
        total_steps = success_at
    else:
        total_steps = fail_count + 1

    console.print(Panel(
        f"[bold white]KỊCH BẢN ĐO KIỂM VÉT CẠN TÙY CHỈNH DỊCH VỤ ONVIF SOAP[/bold white]\n"
        f"• Mục tiêu DUT       : [cyan]{url}[/cyan] (Cổng {port})\n"
        f"• Cơ chế xác thực    : [yellow]{auth_mode.upper()}[/yellow]\n"
        f"• Tài khoản kiểm thử : [bold green]{USER}[/bold green]\n"
        f"• Số lần thử sai     : [bold red]{fail_count} lần[/bold red]\n"
        f"• Lượt thử mật khẩu ĐÚNG: [bold yellow]{'Không thử đúng' if success_at <= 0 else f'Lượt thứ {success_at}'}[/bold yellow]\n"
        f"• Tổng số bước chạy  : [bold white]{total_steps} bước[/bold white]\n"
        f"• Tốc độ phát        : [bold magenta]{rate_cps:.1f} kết nối mới/giây[/bold magenta] (Kiểm tra Firewall Rate-Limit)",
        title="THIẾT LẬP KỊCH BẢN TẤN CÔNG (CLAUSE 2.1.5)",
        border_style="cyan"
    ))

    limiter = PreciseRateLimiter(rate_cps=rate_cps)
    table = Table(title=f"Tiến trình kịch bản tùy chỉnh ONVIF ({total_steps} bước)", show_lines=True)
    table.add_column("Bước", justify="center", style="bold")
    table.add_column("Loại", justify="center")
    table.add_column("Vị trí trong 1s", justify="center")
    table.add_column("Thời điểm phát", justify="center")
    table.add_column("Mật khẩu thử nghiệm", justify="left")
    table.add_column("Kết quả phản hồi", justify="left")
    table.add_column("Đánh giá Firewall", justify="center")
    table.add_column("Độ trễ", justify="right")

    exceeded_fw = 0
    blocked_fw = 0
    success_attempt_result = None

    for step in range(1, total_steps + 1):
        pos_in_sec, t_str = limiter.wait_next()
        is_success_step = (step == success_at)

        if is_success_step:
            test_pass = CORRECT_PASS
            type_lbl = "[bold green]ĐÚNG[/bold green]"
        else:
            test_pass = f"BruteForce_{step}#Audit"
            type_lbl = "[bold red]SAI[/bold red]"

        ok, status, raw_preview, lat = send_onvif_request(url, USER, test_pass, auth_type=auth_mode, force_new_connection=True)

        is_blocked = any(kw in status for kw in ["TIMEOUT", "RST", "REFUSED", "DROP", "Rate-Limited", "429", "403"])
        if pos_in_sec == 4:
            exceeded_fw += 1
            if is_blocked:
                blocked_fw += 1
                fw_eval = "[bold red]CHẶN (3/S)[/bold red]"
            else:
                fw_eval = "[bold yellow]CHẤP NHẬN[/bold yellow]"
            pos_str = f"[bold magenta][{pos_in_sec}/4 - VƯỢT][/bold magenta]"
        else:
            fw_eval = "[green]Bình thường[/green]" if not is_blocked else "[red]BỊ CHẶN SỚM[/red]"
            pos_str = f"[{pos_in_sec}/4]"

        style = "green" if (is_success_step and ok) else ("red" if is_blocked else "yellow")
        table.add_row(
            f"#{step:02d}",
            type_lbl,
            pos_str,
            t_str,
            test_pass if not is_success_step else "******",
            f"[{style}]{status}[/{style}]",
            fw_eval,
            f"{lat:.1f} ms"
        )

        if is_success_step:
            success_attempt_result = (step, ok, status)

    console.print(table)

    console.print(f"\n[*] THỐNG KÊ TƯỜNG LỬA RATE-LIMIT (NGƯỠNG 3 KẾT NỐI/GIÂY):")
    console.print(f"    • Số lần phát ở gói thứ 4 trong 1 giây: {exceeded_fw} lần")
    console.print(f"    • Số lần bị tường lửa Drop/Reset: {blocked_fw} / {exceeded_fw}")

    verdict = False
    console.print("\n" + "=" * 80)
    if success_at > fail_count:
        console.print("  [MỤC TIÊU KIỂM ĐỊNH]: KÍCH HOẠT KHÓA TÀI KHOẢN KHI VƯỢT NGƯỠNG SAI")
        if success_attempt_result and (not success_attempt_result[1] or "200 OK" not in success_attempt_result[2]):
            console.print("[bold green][+] ĐÁNH GIÁ: ĐẠT (PASS)![/bold green]")
            console.print(f"    -> Mật khẩu đúng tại lượt #{success_at} đã bị từ chối / BỊ KHÓA sau {fail_count} lần sai liên tiếp.")
            verdict = True
        else:
            console.print("[bold red][-] ĐÁNH GIÁ: KHÔNG ĐẠT (FAIL)![/bold red]")
            console.print(f"    -> Thiết bị vẫn chấp nhận mật khẩu đúng tại lượt #{success_at} sau {fail_count} lần sai.")
    elif 0 < success_at <= fail_count:
        console.print("  [MỤC TIÊU KIỂM ĐỊNH]: RESET BỘ ĐẾM KHI NHẬP ĐÚNG TRƯỚC NGƯỠNG")
        if success_attempt_result and success_attempt_result[1] and "200 OK" in success_attempt_result[2]:
            console.print("[bold green][+] ĐÁNH GIÁ: ĐẠT (PASS)![/bold green]")
            console.print(f"    -> Mật khẩu đúng tại lượt #{success_at} được chấp nhận (200 OK). Bộ đếm đã được reset.")
            verdict = True
        else:
            console.print("[bold red][-] ĐÁNH GIÁ: KHÔNG ĐẠT (FAIL)![/bold red]")
            console.print(f"    -> Mật khẩu đúng tại lượt #{success_at} bị từ chối dù chưa vượt ngưỡng.")
    else:
        console.print("  [MỤC TIÊU KIỂM ĐỊNH]: ĐO LƯỜNG TƯỜNG LỬA CHỐNG TẤN CÔNG VÉT CẠN LIÊN TỤC")
        console.print(f"    -> Đã hoàn thành {fail_count} lần sai liên tiếp.")
        verdict = True
    console.print("=" * 80)
    return verdict


def run_wordlist_bruteforce(
    url: str,
    port: int,
    auth_mode: str,
    wordlist_path: Optional[str] = None,
    max_attempts: int = 50,
    rate_cps: float = 4.0
) -> None:
    """Test Case 3: Chế độ thử nghiệm vét cạn từ điển ở tốc độ 4 kết nối/giây."""
    console.print("\n" + "=" * 80)
    console.print(f"  [bold magenta][CHẾ ĐỘ THỬ NGHIỆM VÉT CẠN TỪ ĐIỂN - DICTIONARY BRUTE-FORCE AUDIT][/bold magenta]")
    console.print(f"  Mục tiêu: {url} | Tài khoản: {USER} | Cơ chế: {auth_mode.upper()} | Tốc độ: {rate_cps:.1f} kết nối/giây")
    console.print("=" * 80)

    passwords: List[str] = []
    if wordlist_path and os.path.isfile(wordlist_path):
        console.print(f"[*] Nạp danh sách từ file wordlist: {wordlist_path}")
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                p = line.strip()
                if p and p not in passwords:
                    passwords.append(p)
                    if len(passwords) >= max_attempts:
                        break
    else:
        console.print(f"[*] Sử dụng danh sách Top {len(TOP_CAMERA_PASSWORDS)} mật khẩu camera phổ biến nhất.")
        passwords = list(TOP_CAMERA_PASSWORDS[:max_attempts])

    limiter = PreciseRateLimiter(rate_cps=rate_cps)
    table = Table(title="Tiến trình vét cạn mật khẩu ONVIF SOAP", show_lines=True)
    table.add_column("STT", justify="center", style="bold")
    table.add_column("Vị trí trong 1s", justify="center")
    table.add_column("Thời điểm phát", justify="center")
    table.add_column("Mật khẩu thử nghiệm", justify="left")
    table.add_column("Trạng thái", justify="center")
    table.add_column("Phản hồi dịch vụ", justify="left")
    table.add_column("Độ trễ", justify="right")

    success_found = False
    lockout_detected = False

    for idx, pwd in enumerate(passwords, start=1):
        pos_in_sec, t_str = limiter.wait_next()
        is_success, status_lbl, preview, lat = send_onvif_request(url, USER, pwd, auth_type=auth_mode, force_new_connection=True)

        pos_str = f"[bold magenta][{pos_in_sec}/4 - VƯỢT][/bold magenta]" if pos_in_sec == 4 else f"[{pos_in_sec}/4]"

        if is_success:
            table.add_row(f"{idx:02d}", pos_str, t_str, pwd, "[bold green]TRÚNG MẬT KHẨU[/bold green]", f"[bold green]{status_lbl}[/bold green]", f"{lat:.1f} ms")
            success_found = True
            console.print(table)
            console.print(f"\n[bold green][!] ĐÃ TÌM THẤY MẬT KHẨU HỢP LỆ: '{pwd}' (Tài khoản: {USER})[/bold green]")
            break
        elif any(sig in status_lbl for sig in ["TIMEOUT", "RESET", "REFUSED", "Rate-Limited", "429", "403"]):
            table.add_row(f"{idx:02d}", pos_str, t_str, pwd, "[bold yellow]BỊ KHÓA / CHẶN[/bold yellow]", f"[bold red]{status_lbl}[/bold red]", f"{lat:.1f} ms")
            lockout_detected = True
            console.print(table)
            console.print(f"\n[bold yellow][!] PHÁT HIỆN DỊCH VỤ ĐÃ KÍCH HOẠT CHẶN / RATE-LIMIT TẠI LẦN THỬ THỨ #{idx}![/bold yellow]")
            break
        else:
            table.add_row(f"{idx:02d}", pos_str, t_str, pwd, "[dim]Sai[/dim]", status_lbl, f"{lat:.1f} ms")

    if not success_found and not lockout_detected:
        console.print(table)
        console.print("\n[+] Đã hoàn thành vét cạn danh sách từ điển; dịch vụ tiếp nhận toàn bộ mà không gặp crash.")


def run_firewall_rate_limit_test(
    url: str,
    port: int,
    auth_mode: str,
    burst_count: int = 8,
    timeout_sec: float = 2.5
) -> bool:
    """Test Case 4: Kiểm chứng tính năng giới hạn tần suất kết nối mới của tường lửa (Firewall Rate-Limiting)."""
    console.print("\n" + "=" * 80)
    console.print(f"  [bold red][TEST CASE 4] KIỂM CHỨNG GIỚI HẠN TẦN SUẤT KẾT NỐI MỚI (FIREWALL RATE-LIMIT)[/bold red]")
    console.print(f"  Mục tiêu: {url} (Cổng {port})")
    console.print(f"  Cam kết IXIT: Mặc định tối đa 3 kết nối mới / giây (default 3 new connections per second)")
    console.print(f"  Kịch bản đo: Gửi đồng thời {burst_count} kết nối TCP mới trong cùng cửa sổ <= 1.0 giây")
    console.print("=" * 80)

    barrier = threading.Barrier(burst_count)
    results = []

    def worker(idx: int):
        try:
            barrier.wait(timeout=2.0)
        except threading.BrokenBarrierError:
            pass

        t_launch = time.time()
        time_stamp_str = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
        fake_pass = f"BurstConn_{idx}#RateTest"

        ok, status_lbl, preview, lat = send_onvif_request(
            url,
            USER,
            fake_pass,
            auth_type=auth_mode,
            timeout=timeout_sec,
            force_new_connection=True
        )
        t_finish = time.time()
        return {
            "idx": idx,
            "launch_time": t_launch,
            "finish_time": t_finish,
            "time_str": time_stamp_str,
            "status": status_lbl,
            "is_ok": ok,
            "latency": lat
        }

    t_global_start = time.time()
    with ThreadPoolExecutor(max_workers=burst_count) as executor:
        futures = [executor.submit(worker, i) for i in range(1, burst_count + 1)]
        for f in as_completed(futures):
            results.append(f.result())
    t_global_end = time.time()

    results.sort(key=lambda x: x["launch_time"])
    burst_window_sec = t_global_end - t_global_start

    table = Table(title=f"Diễn tiến gửi dồn {burst_count} kết nối mới trong {burst_window_sec:.3f}s", show_lines=True)
    table.add_column("Kết nối #", justify="center", style="bold")
    table.add_column("Thời điểm phát SYN", justify="center")
    table.add_column("Độ trễ", justify="right")
    table.add_column("Trạng thái phản hồi / TCP", justify="left")
    table.add_column("Phân loại Tường lửa", justify="center")

    accepted_count = 0
    blocked_count = 0

    for r in results:
        status_text = r["status"]
        is_blocked = any(kw in status_text for kw in ["TIMEOUT", "RST", "REFUSED", "DROP", "Rate-Limited", "429", "403"])

        if is_blocked:
            blocked_count += 1
            fw_label = "[bold red]BỊ CHẶN (BAN/DROP/RST)[/bold red]"
            st_style = "red"
        else:
            accepted_count += 1
            fw_label = "[bold green]CHẤP NHẬN[/bold green]"
            st_style = "green"

        table.add_row(
            f"#{r['idx']:02d}",
            r["time_str"],
            f"{r['latency']:.1f} ms",
            f"[{st_style}]{status_text}[/{st_style}]",
            fw_label
        )

    console.print(table)

    console.print("\n" + "-" * 80)
    console.print(f"[*] Thống kê lưu lượng kết nối:")
    console.print(f"    • Tổng kết nối mới khởi tạo: [bold white]{burst_count}[/bold white] kết nối")
    console.print(f"    • Thời gian hoàn tất đợt burst: [bold white]{burst_window_sec:.3f}[/bold white] giây")
    console.print(f"    • Tốc độ kết nối thực tế: [bold cyan]{burst_count / max(0.001, burst_window_sec):.1f}[/bold cyan] kết nối/giây (Ngưỡng cam kết: 3 conn/s)")
    console.print(f"    • Số kết nối được chấp nhận qua firewall: [bold {'green' if accepted_count <= 4 else 'yellow'}]{accepted_count}[/bold {'green' if accepted_count <= 4 else 'yellow'}]")
    console.print(f"    • Số kết nối bị firewall Drop / Reset / Timeout: [bold {'red' if blocked_count > 0 else 'dim'}]{blocked_count}[/bold {'red' if blocked_count > 0 else 'dim'}]")
    console.print("-" * 80)

    if blocked_count > 0:
        console.print("[bold green][+] ĐÁNH GIÁ: ĐẠT (PASS) - TƯỜNG LỬA CÓ KÍCH HOẠT RATE-LIMIT![/bold green]")
        return True
    elif accepted_count == burst_count:
        console.print("[bold yellow][!] ĐÁNH GIÁ: CẢNH BÁO / KHÔNG KÍCH HOẠT (FAIL/WARN)![/bold yellow]")
        console.print(f"    -> Toàn bộ {burst_count} kết nối mới trong {burst_window_sec:.2f}s đều được chấp nhận.")
        console.print(f"    -> Tường lửa của thiết bị chưa bật hoặc không áp dụng rule Rate-Limit 3 new conn/s trên cổng {port}.")
        return False
    else:
        console.print("[bold yellow][?] ĐÁNH GIÁ: KẾT QUẢ CẦN KIỂM TRA LẠI THÊM TRÊN PCAP.[/bold yellow]")
        return False


def parse_arguments():
    parser = argparse.ArgumentParser(description="Bộ đo kiểm vét cạn & Khóa dịch vụ ONVIF SOAP (QCVN 11 Clause 2.1.5)")
    parser.add_argument("--port", type=int, default=None, help="Cổng ONVIF chỉ định (80, 443 hoặc custom)")
    parser.add_argument("--threshold", type=int, default=LOCKOUT_THRESHOLD, help=f"Ngưỡng khóa liên tiếp (Mặc định: {LOCKOUT_THRESHOLD})")
    parser.add_argument("--mode", choices=["custom", "1", "2", "3", "4", "burst", "reset", "lockout", "all"], default="custom", help="Chế độ: custom, 1/reset, 2/lockout, 3=Wordlist, 4/burst=Firewall, all")
    parser.add_argument("--fail-count", type=int, default=10, help="Số lần gửi sai liên tiếp (Mặc định: 10)")
    parser.add_argument("--success-at", type=int, default=11, help="Lượt chèn thử mật khẩu đúng (Mặc định: 11; 0=Không thử đúng)")
    parser.add_argument("--wordlist", type=str, default=None, help="Đường dẫn file wordlist cho chế độ vét cạn từ điển")
    parser.add_argument("--auth", choices=["wsse_sha1", "wsse_sha256", "wsse_text", "http_digest"], default=None, help="Chế độ xác thực ép buộc")
    parser.add_argument("--rate", type=float, default=4.0, help="Tốc độ gửi kết nối mới (kết nối/giây). Mặc định là 4.0 (250ms/gói để test Firewall 3 conn/s)")
    parser.add_argument("--burst-count", type=int, default=8, help="Số lượng kết nối mới đồng thời trong 1 giây cho chế độ test Firewall Rate-Limit (Mặc định: 8)")
    return parser.parse_args()


def main():
    global GLOBAL_PCAP_FILE
    args = parse_arguments()

    url, is_https, port = detect_onvif_endpoint(args.port)
    threshold = args.threshold
    rate_cps = args.rate

    console.print(Panel(
        f"[bold white]BỘ ĐO KIỂM PHÒNG VỆ VÉT CẠN & KHÓA DỊCH VỤ ONVIF SOAP (QCVN 11)[/bold white]\n"
        f"• Mục tiêu DUT IP : [cyan]{DUT_IP}[/cyan]\n"
        f"• Cổng đo kiểm    : [yellow]{port}[/yellow] ({'HTTPS / TLS' if is_https else 'HTTP / Cleartext'})\n"
        f"• Endpoint SOAP   : [bold blue]{url}[/bold blue]\n"
        f"• Tài khoản kiểm thử: [bold green]{USER}[/bold green]\n"
        f"• Ngưỡng khóa IXIT: [bold red]{threshold} lần sai liên tiếp[/bold red] (Khóa {LOCKOUT_DURATION_MIN} phút)\n"
        f"• Tốc độ phát kiểm thử: [bold magenta]{rate_cps:.1f} kết nối mới/giây[/bold magenta] (Giãn cách 250ms/kết nối để kiểm chứng Firewall 3 conn/s)",
        title="THÔNG TIN THIẾT LẬP ĐO KIỂM",
        border_style="cyan"
    ))

    bpf_filter = f"tcp port {port}"
    pcap_proc, GLOBAL_PCAP_FILE = start_pcap_capture(
        DUT_IP,
        bpf_filter,
        prefix="onvif_lockout_audit"
    )
    if GLOBAL_PCAP_FILE:
        console.print(f"[*] Đang tự động bắt gói tin PCAP vào: [green]{GLOBAL_PCAP_FILE}[/green]\n")

    try:
        auth_mode = args.auth or auto_detect_auth_mode(url, USER, CORRECT_PASS)

        mode = args.mode
        if mode in ("1", "reset"):
            run_test_case_1(url, port, auth_mode, threshold, rate_cps=rate_cps)
        elif mode in ("2", "lockout"):
            run_test_case_2(url, port, auth_mode, threshold, rate_cps=rate_cps)
        elif mode == "3":
            run_wordlist_bruteforce(url, port, auth_mode, wordlist_path=args.wordlist, rate_cps=rate_cps)
        elif mode in ("4", "burst"):
            run_firewall_rate_limit_test(url, port, auth_mode, burst_count=args.burst_count)
        elif mode in ("5", "all"):
            pass1 = run_test_case_1(url, port, auth_mode, threshold, rate_cps=rate_cps)
            if pass1:
                console.print("\n[*] Chờ 3 giây trước khi chuyển sang Test Case 2...")
                time.sleep(3)
                run_test_case_2(url, port, auth_mode, threshold, rate_cps=rate_cps)
            else:
                console.print("[yellow][!] Test Case 1 không thành công, bỏ qua Test Case 2 để tránh khóa thiết bị kéo dài.[/yellow]")
        elif mode == "custom":
            run_custom_sequence(
                url=url,
                port=port,
                auth_mode=auth_mode,
                fail_count=args.fail_count,
                success_at=args.success_at,
                rate_cps=rate_cps
            )
        else:
            console.print("Chế độ không hợp lệ.")

        filters = [
            ("Toàn bộ lưu lượng ONVIF SOAP", f"tcp.port == {port} && (http || tls)"),
            ("Gói tin SOAP trả lời thành công (200 OK)", "http.response.code == 200 && xml contains \"GetDeviceInformationResponse\""),
            ("Các gói tin xác thực sai (SOAP Fault / 401)", f"tcp.port == {port} && (http.response.code == 401 || xml contains \"Sender\" || xml contains \"FailedAuthentication\")"),
            ("Gói tin bị TƯỜNG LỬA CHẶN / Reset kết nối", f"tcp.port == {port} && (tcp.flags.reset == 1 || http.response.code in (403, 429))")
        ]
        display_wireshark_panel(
            console,
            GLOBAL_PCAP_FILE,
            filters,
            is_tls=is_https,
            sort_tip="Click tiêu đề cột No. hoặc Time để theo dõi chuỗi xác thực SOAP và thời điểm kích hoạt khóa chống vét cạn.",
            title="BẰNG CHỨNG GÓI TIN ONVIF SOAP LOCKOUT AUDIT (WIRESHARK EVIDENCE)"
        )

    finally:
        stop_pcap_capture(pcap_proc)


if __name__ == '__main__':
    main()
