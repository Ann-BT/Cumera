#!/usr/bin/env python3
"""
Bộ đo kiểm bảo vệ chống vét cạn luồng Video RTSP/RTSPS (Yêu cầu 2.1.5 - QCVN 11:2026/BCA & ETSI EN 303 645)
Hỗ trợ kiểm tra kịch bản tấn công tùy chỉnh (Custom Attack Sequence):
- Tùy biến số lần gửi sai liên tiếp (--fail-count)
- Tùy biến vị trí chèn lượt thử mật khẩu đúng (--success-at)
- Tùy biến tốc độ phát kết nối mới (--rate) để kiểm tra Tường lửa giới hạn tốc độ (3 new conn/s)
- Tùy biến cổng đo kiểm (--port 554, 443, 322, 9554)
- Tùy biến cơ chế xác thực (--auth-type auto, basic, digest, digest-md5, digest-sha256)
- Tự động nhận diện & bọc kênh đôi RTSP-over-HTTPS Tunneling (khi kiểm tra cổng 443 TLS) hoặc Raw Socket (554 / 322)
Author: Merlin / Antigravity
"""

import socket
import ssl
import sys
import base64
import time
import json
import os
import re
import hashlib
import datetime
import argparse
from typing import Tuple, List, Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

sys.stdout.reconfigure(encoding='utf-8')
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pcap_recorder import start_pcap_capture, stop_pcap_capture, display_wireshark_panel
from toolkit_config import get_service_ports, get_target_info, is_tls_port, load_config, make_console

console = make_console()
config = load_config()
_target_info = get_target_info(config)
SERVICE_PORTS = get_service_ports(config)

DUT_IP = _target_info["ip"]
RTSP_PORT = int(SERVICE_PORTS["rtsp"])
RTSPS_PORT = int(SERVICE_PORTS["rtsps"])
RTSP_PATH = SERVICE_PORTS["rtsp_path"]
CORRECT_PASS = _target_info["password"]
USER = _target_info["username"]
GLOBAL_PCAP_FILE = ""


def detect_rtsp_port(requested_port: Optional[int] = None, force_tunnel: bool = False, force_raw: bool = False) -> Tuple[int, bool, bool]:
    """
    Phát hiện hoặc kiểm tra cổng RTSP/RTSPS khả dụng thực tế.
    Trả về: (port, use_tls, use_tunnel)
    """
    if requested_port is not None:
        is_tunnel = False if force_raw else (force_tunnel or (requested_port == 443))
        is_tls = (requested_port == RTSPS_PORT) or (requested_port == 443) or is_tls_port(DUT_IP, requested_port)
        return requested_port, is_tls, is_tunnel

    for port, use_tls, is_tunnel in [
        (RTSPS_PORT, True, RTSPS_PORT == 443),
        (RTSP_PORT, False, False),
        (322, True, False),
        (9554, True, False),
        (554, False, False),
        (8554, False, False),
        (443, True, True),
    ]:
        s = socket.socket()
        s.settimeout(1.0)
        res = s.connect_ex((DUT_IP, port))
        s.close()
        if res == 0:
            tls_actual = (is_tls_port(DUT_IP, port) if port in (RTSPS_PORT, RTSP_PORT) else use_tls)
            tunnel_actual = False if force_raw else (force_tunnel or is_tunnel)
            return port, tls_actual, tunnel_actual

    fallback_tunnel = False if force_raw else (force_tunnel or (RTSPS_PORT == 443))
    return RTSPS_PORT, is_tls_port(DUT_IP, RTSPS_PORT), fallback_tunnel


class PreciseRateLimiter:
    """
    Điều tiết tốc độ gửi kết nối mới chính xác theo tốc độ rate_cps (Mặc định: 4.0 conn/s).
    Mỗi kết nối cách nhau đúng (1.0 / rate_cps) giây.
    """
    def __init__(self, rate_cps: float = 4.0):
        self.rate_cps = rate_cps
        self.interval = 1.0 / rate_cps if rate_cps > 0 else 0
        self.start_base = time.time()
        self.count = 0

    def wait_next(self) -> Tuple[int, str]:
        if self.interval <= 0:
            time_str = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
            return 1, time_str
        target_time = self.start_base + (self.count * self.interval)
        now = time.time()
        sleep_dur = target_time - now
        if sleep_dur > 0:
            time.sleep(sleep_dur)
        self.count += 1
        pos_in_sec = ((self.count - 1) % max(1, int(self.rate_cps))) + 1
        time_str = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
        return pos_in_sec, time_str


ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
ctx.keylog_filename = os.path.join(os.path.dirname(__file__), "captures", "sslkeys.log")


def compute_digest_auth(
    username: str,
    password: str,
    method: str,
    uri: str,
    auth_header: str,
    algorithm_override: Optional[str] = None
) -> str:
    """Tính toán tiêu đề Authorization Digest chuẩn RFC 2617 / RFC 7616."""
    m_realm = re.search(r'realm="([^"]*)"', auth_header)
    m_nonce = re.search(r'nonce="([^"]*)"', auth_header)
    m_qop = re.search(r'qop="([^"]*)"', auth_header)
    m_alg = re.search(r'algorithm="?([a-zA-Z0-9\-]+)"?', auth_header)

    realm = m_realm.group(1) if m_realm else ""
    nonce = m_nonce.group(1) if m_nonce else ""

    alg_str = algorithm_override or (m_alg.group(1) if m_alg else "")
    is_sha256 = ("sha-256" in alg_str.lower()) or ("sha256" in alg_str.lower())
    h_fn = hashlib.sha256 if is_sha256 else hashlib.md5
    alg_name = "SHA-256" if is_sha256 else "MD5"

    ha1 = h_fn(f"{username}:{realm}:{password}".encode("utf-8")).hexdigest()
    ha2 = h_fn(f"{method}:{uri}".encode("utf-8")).hexdigest()

    if m_qop and "auth" in m_qop.group(1):
        cnonce = base64.b16encode(os.urandom(8)).decode("ascii").lower()
        nc = "00000001"
        resp_hash = h_fn(f"{ha1}:{nonce}:{nc}:{cnonce}:auth:{ha2}".encode("utf-8")).hexdigest()
        return (
            f'Digest username="{username}", realm="{realm}", nonce="{nonce}", '
            f'uri="{uri}", qop=auth, nc={nc}, cnonce="{cnonce}", '
            f'response="{resp_hash}", algorithm={alg_name}'
        )
    else:
        resp_hash = h_fn(f"{ha1}:{nonce}:{ha2}".encode("utf-8")).hexdigest()
        return (
            f'Digest username="{username}", realm="{realm}", nonce="{nonce}", '
            f'uri="{uri}", response="{resp_hash}", algorithm={alg_name}'
        )


def _send_rtsp_tunnel(
    username: str,
    password: str,
    seq: int,
    port: int,
    auth_type: str = "auto",
    ua: str = "RTSP-Audit-Client",
    timeout: float = 3.0
) -> Tuple[bool, str, str]:
    """Gửi request RTSP qua cơ chế RTSP-over-HTTPS Tunneling (QuickTime RFC 2326 trên cổng 443)."""
    cookie = "tun_" + os.urandom(6).hex()
    rtsp_uri = f"rtsp://{DUT_IP}:{port}{RTSP_PATH}"
    s_get = None
    s_post = None
    try:
        # 1. Kênh GET downlink
        s_get_raw = socket.create_connection((DUT_IP, port), timeout=timeout)
        s_get = ctx.wrap_socket(s_get_raw, server_hostname=DUT_IP)
        get_req = (
            f"GET {RTSP_PATH} HTTP/1.0\r\n"
            f"Host: {DUT_IP}\r\n"
            f"x-sessioncookie: {cookie}\r\n"
            f"Accept: application/x-rtsp-tunnelled\r\n"
            f"Pragma: no-cache\r\n"
            f"Cache-Control: no-cache\r\n\r\n"
        )
        s_get.sendall(get_req.encode("ascii"))
        s_get.settimeout(timeout)
        _ = s_get.recv(1024)

        # 2. Kênh POST uplink
        s_post_raw = socket.create_connection((DUT_IP, port), timeout=timeout)
        s_post = ctx.wrap_socket(s_post_raw, server_hostname=DUT_IP)
        post_hdr = (
            f"POST {RTSP_PATH} HTTP/1.0\r\n"
            f"Host: {DUT_IP}\r\n"
            f"x-sessioncookie: {cookie}\r\n"
            f"Content-Type: application/x-rtsp-tunnelled\r\n"
            f"Pragma: no-cache\r\n"
            f"Cache-Control: no-cache\r\n"
            f"Content-Length: 32767\r\n\r\n"
        )
        s_post.sendall(post_hdr.encode("ascii"))

        # Nếu chọn Basic Auth trực tiếp
        if auth_type == "basic":
            cred = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
            cmd_basic = (
                f"DESCRIBE {rtsp_uri} RTSP/1.0\r\n"
                f"CSeq: {seq}\r\n"
                f"User-Agent: {ua}\r\n"
                f"Authorization: Basic {cred}\r\n\r\n"
            )
            s_post.sendall(base64.b64encode(cmd_basic.encode("ascii")))
            resp = s_get.recv(4096).decode("latin1", errors="ignore")
            line1 = resp.splitlines()[0] if resp else "EMPTY_REPLY"
            return True, line1, resp

        # Mặc định Auto / Digest: Bước 1 gửi DESCRIBE rỗng lấy 401 challenge
        cmd_init = (
            f"DESCRIBE {rtsp_uri} RTSP/1.0\r\n"
            f"CSeq: 1\r\n"
            f"User-Agent: {ua}\r\n\r\n"
        )
        s_post.sendall(base64.b64encode(cmd_init.encode("ascii")))
        resp1 = s_get.recv(4096).decode("latin1", errors="ignore")
        if not resp1:
            return True, "EMPTY_REPLY", ""

        if "401" not in resp1:
            line1 = resp1.splitlines()[0] if resp1 else "EMPTY_REPLY"
            return True, line1, resp1

        # Bước 2: Bóc tách WWW-Authenticate và gửi Authorization
        auth_lines = [l.strip() for l in resp1.splitlines() if "WWW-Authenticate" in l]
        auth_line = next((l for l in auth_lines if "Digest" in l), auth_lines[0] if auth_lines else "")

        use_digest = ("Digest" in auth_line) if auth_type == "auto" else (auth_type != "basic")
        if use_digest:
            alg_override = "sha-256" if auth_type == "digest-sha256" else ("md5" if auth_type == "digest-md5" else None)
            auth_val = compute_digest_auth(username, password, "DESCRIBE", rtsp_uri, auth_line, alg_override)
        else:
            cred = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
            auth_val = f"Basic {cred}"

        cmd_auth = (
            f"DESCRIBE {rtsp_uri} RTSP/1.0\r\n"
            f"CSeq: 2\r\n"
            f"User-Agent: {ua}\r\n"
            f"Authorization: {auth_val}\r\n\r\n"
        )
        s_post.sendall(base64.b64encode(cmd_auth.encode("ascii")))
        resp2 = s_get.recv(8192).decode("latin1", errors="ignore")
        line1 = resp2.splitlines()[0] if resp2 else "EMPTY_REPLY"
        return True, line1, resp2
    except socket.timeout:
        return False, "TIMEOUT (Server stopped responding)", ""
    except ConnectionResetError:
        return False, "RESET (Connection reset by peer)", ""
    except ConnectionRefusedError:
        return False, "REFUSED (Connection refused)", ""
    except Exception as e:
        return False, f"ERROR: {e}", ""
    finally:
        if s_get:
            try: s_get.close()
            except Exception: pass
        if s_post:
            try: s_post.close()
            except Exception: pass


def _send_rtsp_raw(
    username: str,
    password: str,
    seq: int,
    port: int,
    use_tls: bool,
    auth_type: str = "auto",
    ua: str = "RTSP-Audit-Client",
    timeout: float = 3.0
) -> Tuple[bool, str, str]:
    """Gửi request DESCRIBE RTSP/RTSPS qua kết nối TCP raw socket thuần."""
    rtsp_uri = f"rtsp://{DUT_IP}:{port}{RTSP_PATH}"
    sock_raw = None
    try:
        sock_raw = socket.create_connection((DUT_IP, port), timeout=timeout)
        s = ctx.wrap_socket(sock_raw, server_hostname=DUT_IP) if use_tls else sock_raw

        # Nếu chọn Basic Auth trực tiếp
        if auth_type == "basic":
            cred = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
            req = (
                f"DESCRIBE {rtsp_uri} RTSP/1.0\r\n"
                f"CSeq: {seq}\r\n"
                f"User-Agent: {ua}\r\n"
                f"Authorization: Basic {cred}\r\n\r\n"
            )
            s.sendall(req.encode("ascii"))
            resp = s.recv(4096).decode("latin1", errors="ignore")
            line1 = resp.splitlines()[0] if resp else "EMPTY_REPLY (Server closed connection)"
            return True, line1, resp

        # Mặc định Auto / Digest:
        # Bước 1: Gửi yêu cầu rỗng để lấy Challenge 401
        req1 = (
            f"DESCRIBE {rtsp_uri} RTSP/1.0\r\n"
            f"CSeq: {seq}\r\n"
            f"User-Agent: {ua}\r\n\r\n"
        )
        s.sendall(req1.encode("ascii"))
        resp1 = s.recv(4096).decode("latin1", errors="ignore")

        if not resp1:
            return True, "EMPTY_REPLY (Server closed connection)", ""

        if "401" not in resp1:
            line1 = resp1.splitlines()[0] if resp1 else "EMPTY_REPLY"
            return True, line1, resp1

        # Bước 2: Bóc tách WWW-Authenticate
        auth_lines = [l.strip() for l in resp1.splitlines() if "WWW-Authenticate" in l]
        auth_line = next((l for l in auth_lines if "Digest" in l), auth_lines[0] if auth_lines else "")

        use_digest = ("Digest" in auth_line) if auth_type == "auto" else (auth_type != "basic")
        if use_digest:
            alg_override = "sha-256" if auth_type == "digest-sha256" else ("md5" if auth_type == "digest-md5" else None)
            auth_val = compute_digest_auth(username, password, "DESCRIBE", rtsp_uri, auth_line, alg_override)
        else:
            cred = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
            auth_val = f"Basic {cred}"

        # Bước 3: Gửi request xác thực
        need_reconnect = "connection: close" in resp1.lower()
        if need_reconnect:
            try: s.close()
            except Exception: pass
            sock_raw = socket.create_connection((DUT_IP, port), timeout=timeout)
            s = ctx.wrap_socket(sock_raw, server_hostname=DUT_IP) if use_tls else sock_raw

        req2 = (
            f"DESCRIBE {rtsp_uri} RTSP/1.0\r\n"
            f"CSeq: {seq + 1}\r\n"
            f"User-Agent: {ua}\r\n"
            f"Authorization: {auth_val}\r\n\r\n"
        )
        s.sendall(req2.encode("ascii"))
        resp2 = s.recv(4096).decode("latin1", errors="ignore")
        line1 = resp2.splitlines()[0] if resp2 else "EMPTY_REPLY (Server closed connection)"
        return True, line1, resp2

    except socket.timeout:
        return False, "TIMEOUT (Server stopped responding)", ""
    except ConnectionResetError:
        return False, "RESET (Connection reset by peer)", ""
    except ConnectionRefusedError:
        return False, "REFUSED (Connection refused)", ""
    except Exception as e:
        return False, f"ERROR: {e}", ""
    finally:
        if sock_raw:
            try: sock_raw.close()
            except Exception: pass


def send_rtsp(
    username: str,
    password: str,
    seq: int,
    port: int,
    use_tls: bool,
    auth_type: str = "auto",
    use_tunnel: bool = False,
    ua: str = "RTSP-Audit-Client",
    timeout: float = 3.0
) -> Tuple[bool, str, str]:
    """Điều phối gửi request RTSP theo đúng phương thức mạng (Tunneling hoặc Raw Socket)."""
    if use_tunnel:
        return _send_rtsp_tunnel(username, password, seq, port, auth_type, ua, timeout)
    else:
        return _send_rtsp_raw(username, password, seq, port, use_tls, auth_type, ua, timeout)


def run_custom_sequence(
    port: int,
    use_tls: bool,
    fail_count: int,
    success_at: int,
    rate_cps: float = 4.0,
    stage: Optional[int] = None,
    threshold: int = 5,
    auth_type: str = "auto",
    use_tunnel: bool = False,
) -> bool:
    """
    Thực hiện kịch bản tấn công tùy chỉnh RTSP/RTSPS:
    - fail_count: Tổng số lần sai dự định
    - success_at: Vị trí chèn lượt thử mật khẩu đúng (0 = không thử đúng)
    - rate_cps: Tốc độ phát kết nối
    - auth_type: Cơ chế xác thực (auto, basic, digest, digest-md5, digest-sha256)
    - use_tunnel: Bọc kênh đôi RTSP-over-HTTPS Tunneling
    """
    if success_at <= 0:
        total_steps = fail_count
    elif success_at > fail_count:
        total_steps = success_at
    else:
        total_steps = fail_count + 1

    transport_label = "HTTPS Tunnel" if use_tunnel else ("TLS 1.3" if use_tls else "Cleartext")
    limiter = PreciseRateLimiter(rate_cps=rate_cps)
    table = Table(
        title=f"Tiến trình kịch bản tùy chỉnh RTSP ({total_steps} bước) [Cổng {port} | {auth_type.upper()} | {transport_label}]",
        show_lines=True
    )
    table.add_column("Bước", justify="center", style="bold")
    table.add_column("Loại", justify="center")
    table.add_column("Thời điểm phát", justify="center")
    table.add_column("Mật khẩu thử nghiệm", justify="left")
    table.add_column("Kết quả phản hồi", justify="left")
    table.add_column("Độ trễ", justify="right")

    success_attempt_result = None

    for step in range(1, total_steps + 1):
        pos, t_str = limiter.wait_next()
        is_success_step = (step == success_at)

        if is_success_step:
            test_pass = CORRECT_PASS
            type_lbl = "[bold green]ĐÚNG[/bold green]"
            display_pass = f"[bold green]{USER} : {CORRECT_PASS}[/bold green]"
        else:
            test_pass = f"WrongPass_{step}#Audit"
            type_lbl = "[bold red]SAI[/bold red]"
            display_pass = f"[yellow]{USER} : {test_pass}[/yellow]"

        t_req = time.time()
        ok, status, raw = send_rtsp(
            username=USER,
            password=test_pass,
            seq=100 + step,
            port=port,
            use_tls=use_tls,
            auth_type=auth_type,
            use_tunnel=use_tunnel
        )
        lat = (time.time() - t_req) * 1000

        is_blocked = any(kw in status for kw in ["TIMEOUT", "RESET", "REFUSED", "EMPTY_REPLY", "403 Forbidden", "429"])
        style = "green" if (is_success_step and ok and "200 OK" in status) else ("red" if is_blocked else "yellow")
        table.add_row(
            f"#{step:02d}",
            type_lbl,
            t_str,
            display_pass,
            f"[{style}]{status}[/{style}]",
            f"{lat:.1f} ms"
        )

        if is_success_step:
            success_attempt_result = (step, ok, status)

    console.print(table)

    is_reset_test = (stage == 1) if stage in (1, 2) else (fail_count < threshold or (0 < success_at <= fail_count and fail_count <= threshold))
    verdict = False
    console.print("")
    if is_reset_test:
        if success_attempt_result and "200 OK" in success_attempt_result[2]:
            console.print(f"[bold green][+] ĐÁNH GIÁ GĐ1: ĐẠT (PASS) - Mật khẩu đúng tại lượt #{success_at} được chấp nhận (200 OK). Bộ đếm đã reset.[/bold green]")
            verdict = True
        else:
            console.print(f"[bold red][-] ĐÁNH GIÁ GĐ1: KHÔNG ĐẠT (FAIL) - Mật khẩu đúng tại lượt #{success_at} bị từ chối dù chưa vượt ngưỡng.[/bold red]")
    else:
        if success_attempt_result and "200 OK" not in success_attempt_result[2]:
            console.print(f"[bold green][+] ĐÁNH GIÁ GĐ2: ĐẠT (PASS) - Mật khẩu đúng tại lượt #{success_at} đã bị từ chối / BỊ KHÓA sau {fail_count} lần sai liên tiếp.[/bold green]")
            verdict = True
        else:
            console.print(f"[bold red][-] ĐÁNH GIÁ GĐ2: KHÔNG ĐẠT (FAIL) - Thiết bị vẫn cho phép truy cập tại lượt #{success_at} sau {fail_count} lần sai.[/bold red]")

    return verdict


def run_matrix_sequence(
    port: int,
    use_tls: bool,
    g1_fail: int = 4,
    g1_pass: int = 5,
    g2_fail: int = 5,
    g2_pass: int = 6,
    rate_cps: float = 4.0,
    auth_type: str = "auto",
    use_tunnel: bool = False,
) -> bool:
    """Kiểm thử chuỗi ma trận duy nhất: GĐ1 (Reset trước ngưỡng) + GĐ2 (Khóa tài khoản sau ngưỡng)."""
    limiter = PreciseRateLimiter(rate_cps=rate_cps)
    total_steps = g1_fail + 1 + g2_fail + 1
    transport_label = "HTTPS Tunnel" if use_tunnel else ("TLS 1.3" if use_tls else "Cleartext")
    table = Table(
        title=f"Tiến trình kiểm thử ma trận RTSP ({total_steps} bước) [Cổng {port} | {auth_type.upper()} | {transport_label}]",
        show_lines=True
    )
    table.add_column("Bước", justify="center", style="bold")
    table.add_column("Loại", justify="center")
    table.add_column("Thời điểm phát", justify="center")
    table.add_column("Mật khẩu thử nghiệm", justify="left")
    table.add_column("Kết quả phản hồi", justify="left")
    table.add_column("Độ trễ", justify="right")

    step_num = 0
    g1_result = None
    g2_result = None

    for i in range(1, g1_fail + 1):
        step_num += 1
        pos, t_str = limiter.wait_next()
        test_pass = f"WrongPass_{step_num}#Audit"
        t0 = time.time()
        ok, status, raw = send_rtsp(
            username=USER,
            password=test_pass,
            seq=100 + step_num,
            port=port,
            use_tls=use_tls,
            auth_type=auth_type,
            use_tunnel=use_tunnel
        )
        lat = (time.time() - t0) * 1000
        is_blocked = any(kw in status for kw in ["TIMEOUT", "RESET", "REFUSED", "EMPTY_REPLY", "403 Forbidden", "429"])
        style = "red" if is_blocked else "yellow"
        table.add_row(f"#{step_num:02d}", "[bold red]SAI[/bold red]", t_str, f"[yellow]{USER} : {test_pass}[/yellow]", f"[{style}]{status}[/{style}]", f"{lat:.1f} ms")

    step_num += 1
    pos, t_str = limiter.wait_next()
    t0 = time.time()
    ok, status, raw = send_rtsp(
        username=USER,
        password=CORRECT_PASS,
        seq=100 + step_num,
        port=port,
        use_tls=use_tls,
        auth_type=auth_type,
        use_tunnel=use_tunnel
    )
    lat = (time.time() - t0) * 1000
    g1_result = (step_num, ok, status)
    style = "green" if (ok and "200 OK" in status) else "red"
    table.add_row(f"#{step_num:02d}", "[bold green]ĐÚNG[/bold green]", t_str, f"[bold green]{USER} : {CORRECT_PASS}[/bold green]", f"[{style}]{status}[/{style}]", f"{lat:.1f} ms")

    table.add_section()
    time.sleep(1.0)

    for i in range(1, g2_fail + 1):
        step_num += 1
        pos, t_str = limiter.wait_next()
        test_pass = f"WrongPass_{step_num}#Audit"
        t0 = time.time()
        ok, status, raw = send_rtsp(
            username=USER,
            password=test_pass,
            seq=100 + step_num,
            port=port,
            use_tls=use_tls,
            auth_type=auth_type,
            use_tunnel=use_tunnel
        )
        lat = (time.time() - t0) * 1000
        is_blocked = any(kw in status for kw in ["TIMEOUT", "RESET", "REFUSED", "EMPTY_REPLY", "403 Forbidden", "429"])
        style = "red" if is_blocked else "yellow"
        table.add_row(f"#{step_num:02d}", "[bold red]SAI[/bold red]", t_str, f"[yellow]{USER} : {test_pass}[/yellow]", f"[{style}]{status}[/{style}]", f"{lat:.1f} ms")

    step_num += 1
    pos, t_str = limiter.wait_next()
    t0 = time.time()
    ok, status, raw = send_rtsp(
        username=USER,
        password=CORRECT_PASS,
        seq=100 + step_num,
        port=port,
        use_tls=use_tls,
        auth_type=auth_type,
        use_tunnel=use_tunnel
    )
    lat = (time.time() - t0) * 1000
    g2_result = (step_num, ok, status)
    is_locked = (not ok or "200 OK" not in status)
    style = "green" if is_locked else "red"
    table.add_row(f"#{step_num:02d}", "[bold green]ĐÚNG[/bold green]", t_str, f"[bold green]{USER} : {CORRECT_PASS}[/bold green]", f"[{style}]{status}[/{style}]", f"{lat:.1f} ms")

    console.print(table)

    g1_ok = (g1_result and g1_result[1] and "200 OK" in g1_result[2])
    g2_ok = (g2_result and (not g2_result[1] or "200 OK" not in g2_result[2]))

    console.print("")
    if g1_ok and g2_ok:
        console.print("[bold green][+] ĐÁNH GIÁ: ĐẠT (PASS) - GĐ1 Reset bộ đếm: THÀNH CÔNG (200 OK) | GĐ2 Khóa luồng RTSP: ĐÃ KHÓA (Bị từ chối)[/bold green]")
        return True
    elif g1_ok and not g2_ok:
        console.print("[bold red][-] ĐÁNH GIÁ: KHÔNG ĐẠT (FAIL) - GĐ1 Reset bộ đếm: THÀNH CÔNG | GĐ2 Khóa luồng RTSP: KHÔNG KHÓA (Vẫn 200 OK)[/bold red]")
        return False
    else:
        console.print(f"[bold red][-] ĐÁNH GIÁ: KHÔNG ĐẠT (FAIL) - GĐ1 Reset: {'THÀNH CÔNG' if g1_ok else 'THẤT BẠI'} | GĐ2 Khóa: {'ĐÃ KHÓA' if g2_ok else 'THẤT BẠI'}[/bold red]")
        return False


def parse_arguments():
    parser = argparse.ArgumentParser(description="Bộ đo kiểm vét cạn luồng Video RTSP/RTSPS (QCVN 11 Clause 2.1.5)")
    parser.add_argument("port_pos", nargs="?", type=int, default=None, help="Cổng kiểm thử (vị trí tương thích ngược)")
    parser.add_argument("--port", type=int, default=None, help="Cổng RTSP (443, 554, 322, 9554)")
    parser.add_argument("--mode", choices=["matrix", "custom", "1", "2", "3", "reset", "lockout", "all"], default="custom", help="Chế độ: custom, reset, lockout, all")
    parser.add_argument("--fail-count", type=int, default=10, help="Số lần gửi sai liên tiếp (Mặc định: 10)")
    parser.add_argument("--success-at", type=int, default=11, help="Lượt chèn thử mật khẩu đúng (Mặc định: 11; 0=Không thử đúng)")
    parser.add_argument("--stage", type=int, choices=[1, 2], default=None, help="Giai đoạn kiểm thử (1: Reset trước ngưỡng, 2: Khóa sau ngưỡng)")
    parser.add_argument("--g1-fail", type=int, default=4, help="GĐ1: Số lần thử sai (Mặc định: 4)")
    parser.add_argument("--g1-pass", type=int, default=5, help="GĐ1: Lượt thử đúng (Mặc định: 5)")
    parser.add_argument("--g2-fail", type=int, default=5, help="GĐ2: Số lần thử sai (Mặc định: 5)")
    parser.add_argument("--g2-pass", type=int, default=6, help="GĐ2: Lượt thử đúng (Mặc định: 6)")
    parser.add_argument("--rate", type=float, default=4.0, help="Tốc độ gửi kết nối mới/giây (Mặc định: 4.0 conn/s)")
    parser.add_argument(
        "--auth-type",
        choices=["auto", "basic", "digest", "digest-md5", "digest-sha256"],
        default="auto",
        help="Cơ chế xác thực RTSP: auto (Tự động đàm phán), basic (Basic Base64), digest / digest-md5, digest-sha256 (Mặc định: auto)"
    )
    parser.add_argument("--tunnel", action="store_true", help="Bắt buộc sử dụng cơ chế RTSP-over-HTTPS Tunneling (kênh đôi GET/POST)")
    parser.add_argument("--raw", action="store_true", help="Bắt buộc sử dụng kết nối raw socket RTSP/RTSPS thuần")
    return parser.parse_args()


def main():
    global GLOBAL_PCAP_FILE
    args = parse_arguments()

    target_port = args.port or args.port_pos
    port, use_tls, use_tunnel = detect_rtsp_port(target_port, force_tunnel=args.tunnel, force_raw=args.raw)

    bpf_filter = f"tcp port {port}"
    pcap_proc, GLOBAL_PCAP_FILE = start_pcap_capture(
        DUT_IP,
        bpf_filter,
        prefix=f"rtsp_lockout_audit_{port}"
    )
    if GLOBAL_PCAP_FILE and args.mode not in ("matrix", "custom"):
        print(f"[*] Đang tự động bắt gói tin PCAP vào: {GLOBAL_PCAP_FILE}\n")

    try:
        if args.mode == "matrix":
            run_matrix_sequence(
                port=port,
                use_tls=use_tls,
                g1_fail=args.g1_fail,
                g1_pass=args.g1_pass,
                g2_fail=args.g2_fail,
                g2_pass=args.g2_pass,
                rate_cps=args.rate,
                auth_type=args.auth_type,
                use_tunnel=use_tunnel
            )
        elif args.mode in ("1", "reset"):
            run_custom_sequence(
                port=port,
                use_tls=use_tls,
                fail_count=4,
                success_at=5,
                rate_cps=args.rate,
                auth_type=args.auth_type,
                use_tunnel=use_tunnel
            )
        elif args.mode in ("2", "lockout"):
            run_custom_sequence(
                port=port,
                use_tls=use_tls,
                fail_count=10,
                success_at=11,
                rate_cps=args.rate,
                auth_type=args.auth_type,
                use_tunnel=use_tunnel
            )
        elif args.mode in ("3", "all"):
            console.print("\n[bold cyan]>>> GIAI ĐOẠN 1: KIỂM CHỨNG RESET BỘ ĐẾM TRƯỚC NGƯỠNG <<<[/bold cyan]")
            pass1 = run_custom_sequence(
                port=port,
                use_tls=use_tls,
                fail_count=4,
                success_at=5,
                rate_cps=args.rate,
                auth_type=args.auth_type,
                use_tunnel=use_tunnel
            )
            if pass1:
                console.print("\n[*] Chờ 3 giây trước khi chuyển sang giai đoạn kiểm thử kích hoạt khóa...")
                time.sleep(3)
                console.print("\n[bold cyan]>>> GIAI ĐOẠN 2: KIỂM CHỨNG KÍCH HOẠT KHÓA SAU 10 LẦN SAI <<<[/bold cyan]")
                run_custom_sequence(
                    port=port,
                    use_tls=use_tls,
                    fail_count=10,
                    success_at=11,
                    rate_cps=args.rate,
                    auth_type=args.auth_type,
                    use_tunnel=use_tunnel
                )
        else:
            run_custom_sequence(
                port=port,
                use_tls=use_tls,
                fail_count=args.fail_count,
                success_at=args.success_at,
                rate_cps=args.rate,
                stage=args.stage,
                auth_type=args.auth_type,
                use_tunnel=use_tunnel
            )
    finally:
        stop_pcap_capture(pcap_proc)


if __name__ == '__main__':
    main()
