#!/usr/bin/env python3
"""
Bộ đo kiểm phòng vệ chống vét cạn giao diện Web Quản trị (Web-Authmech - Cổng 443 HTTPS)
Yêu cầu 2.1.5 - QCVN 11:2026/BCA & ETSI EN 303 645 Clause 5.1-5
Cam kết IXIT:
- 6 lần sai liên tiếp trong 30 giây -> Khóa giao diện đăng nhập trong 5 phút.
- Tường lửa giới hạn tốc độ kết nối mới (Rate Limiting).
- Reset bộ đếm thất bại khi nhập đúng trước ngưỡng.
- Hỗ trợ Kịch bản Tấn công Tùy chỉnh (Custom Attack Sequence: --fail-count, --success-at, --rate).
- Bắt gói tin PCAP & Hiển thị bộ lọc, hướng dẫn Sort trong Wireshark.
Author: Merlin / Antigravity
"""

import requests
from requests.auth import HTTPBasicAuth, HTTPDigestAuth
import urllib3
import sys
import os
import time
import json
import datetime
import argparse
from typing import Tuple, List, Optional

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pcap_recorder import start_pcap_capture, stop_pcap_capture, display_wireshark_panel
from toolkit_config import get_service_ports, get_target_info, is_tls_port, load_config, make_console
from adapters import get_camera_adapter

console = make_console()
config = load_config()
adapter = get_camera_adapter(config)
_target_info = get_target_info(config)
SERVICE_PORTS = get_service_ports(config)

DUT_IP = _target_info["ip"]
HTTPS_PORT = int(SERVICE_PORTS["https"])
HTTP_PORT = int(SERVICE_PORTS["http"])
USER = _target_info["username"]
CORRECT_PASS = _target_info["password"]

GLOBAL_PCAP_FILE = ""
_WEB_TARGET_CACHE = {}


def _resolve_web_auth_target(port: int) -> Tuple[str, str]:
    """Auto-detect scheme (https/http) and protected auth endpoint across camera brands via adapter."""
    if port in _WEB_TARGET_CACHE:
        return _WEB_TARGET_CACHE[port]
    scheme = "https" if is_tls_port(DUT_IP, port) else "http"
    candidates = list(adapter.get_web_auth_endpoints())
    if "/" not in candidates:
        candidates.append("/")
    chosen_path = candidates[-1]
    for path in candidates:
        url = f"{scheme}://{DUT_IP}:{port}{path}"
        try:
            r = requests.get(url, verify=False, timeout=2.0, headers={"Connection": "close"})
            if r.status_code in (200, 401):
                chosen_path = path
                if r.status_code == 401:
                    break
        except Exception:
            continue
    _WEB_TARGET_CACHE[port] = (scheme, f"{scheme}://{DUT_IP}:{port}{chosen_path}")
    return _WEB_TARGET_CACHE[port]


class PreciseRateLimiter:
    """Điều tiết tốc độ gửi request Web theo rate_cps (Mặc định: 2.5 req/s)."""
    def __init__(self, rate_cps: float = 2.5):
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


def attempt_web_login(username: str, password: str, port: int = 443, timeout: float = 3.0, auth_type: str = "auto") -> Tuple[bool, str, float]:
    """
    Thực hiện 1 lần xác thực qua Web HTTPS/HTTP (đa hãng Camera).
    Returns: (is_success, status_str, latency_ms)
    """
    # 1. Thử qua adapter chuyên biệt của từng hãng (như Oryza/Tiandy XDigest SPA) nếu mode là auto hoặc adapter
    if auth_type in ("auto", "adapter"):
        try:
            adapter_res = adapter.attempt_web_login(username, password, port=port, timeout=timeout)
            if adapter_res is not None:
                return adapter_res
        except Exception:
            if auth_type == "adapter":
                return False, "ADAPTER_ERROR", 0.0

    # 2. HTTP Basic / Digest qua endpoints chuẩn
    _, auth_url = _resolve_web_auth_target(port)
    t_start = time.time()
    try:
        if auth_type == "digest":
            res = requests.get(
                auth_url,
                auth=HTTPDigestAuth(username, password),
                verify=False,
                timeout=timeout,
                headers={"Connection": "close"}
            )
            elapsed = (time.time() - t_start) * 1000
            if res.status_code == 200:
                return True, f"HTTP {res.status_code} OK (Digest thành công)", elapsed
            elif res.status_code in (403, 429):
                return False, f"HTTP {res.status_code} (BỊ KHÓA / Rate Limited)", elapsed
            return False, f"HTTP {res.status_code} Unauthorized", elapsed

        # Basic hoặc Auto
        res = requests.get(
            auth_url,
            auth=HTTPBasicAuth(username, password),
            verify=False,
            timeout=timeout,
            headers={"Connection": "close"}
        )
        elapsed = (time.time() - t_start) * 1000
        if res.status_code == 200:
            return True, f"HTTP {res.status_code} OK (Đăng nhập thành công)", elapsed
        elif res.status_code == 401 and auth_type == "auto":
            # Fallback HTTP Digest
            t_d_start = time.time()
            res_d = requests.get(
                auth_url,
                auth=HTTPDigestAuth(username, password),
                verify=False,
                timeout=timeout,
                headers={"Connection": "close"}
            )
            elapsed_d = (time.time() - t_d_start) * 1000
            if res_d.status_code == 200:
                return True, f"HTTP {res_d.status_code} OK (Digest thành công)", elapsed_d
            return False, f"HTTP {res_d.status_code} Unauthorized", elapsed_d
        elif res.status_code in (403, 429):
            return False, f"HTTP {res.status_code} (BỊ KHÓA / Rate Limited)", elapsed
        else:
            return False, f"HTTP {res.status_code}", elapsed
    except requests.exceptions.Timeout:
        elapsed = (time.time() - t_start) * 1000
        return False, "TIMEOUT (Mạng/Dịch vụ bị đóng băng - Bị khóa)", elapsed
    except requests.exceptions.ConnectionError as e:
        elapsed = (time.time() - t_start) * 1000
        return False, "CONN_REFUSED / DROPPED (Tường lửa ngắt kết nối)", elapsed
    except Exception as e:
        elapsed = (time.time() - t_start) * 1000
        return False, f"ERROR ({e})", elapsed


def run_custom_sequence(
    port: int,
    fail_count: int,
    success_at: int,
    rate_cps: float = 2.5,
    stage: Optional[int] = None,
    threshold: int = 5,
    auth_type: str = "auto"
) -> bool:
    """
    Chạy kịch bản tấn công tùy chỉnh cho Web HTTPS:
    - fail_count: Số lần thử sai liên tiếp
    - success_at: Lượt chèn thử mật khẩu đúng (0=Không thử đúng)
    - rate_cps: Tốc độ gửi request
    """
    if success_at <= 0:
        total_steps = fail_count
    elif success_at > fail_count:
        total_steps = success_at
    else:
        total_steps = fail_count + 1

    limiter = PreciseRateLimiter(rate_cps=rate_cps)
    table = Table(title=f"Tiến trình kịch bản tùy chỉnh Web HTTPS ({total_steps} bước)", show_lines=True)
    table.add_column("Bước", justify="center", style="bold")
    table.add_column("Loại", justify="center")
    table.add_column("Thời điểm", justify="center")
    table.add_column("Mật khẩu thử nghiệm", justify="left")
    table.add_column("Kết quả phản hồi Web", justify="left")
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
            test_pass = f"BruteForce_{step}#WebBad"
            type_lbl = "[bold red]SAI[/bold red]"
            display_pass = f"[yellow]{USER} : {test_pass}[/yellow]"

        ok, status, lat = attempt_web_login(USER, test_pass, port=port, timeout=2.5, auth_type=auth_type)

        is_blocked = any(kw in status for kw in ["TIMEOUT", "CONN_REFUSED", "DROPPED", "BỊ KHÓA", "403", "429"])
        style = "green" if (is_success_step and ok) else ("red" if is_blocked else "yellow")
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
        if success_attempt_result and success_attempt_result[1]:
            console.print(f"[bold green][+] ĐÁNH GIÁ GĐ1: ĐẠT (PASS) - Mật khẩu đúng tại lượt #{success_at} đăng nhập thành công (HTTP 200). Bộ đếm đã reset.[/bold green]")
            verdict = True
        else:
            console.print(f"[bold red][-] ĐÁNH GIÁ GĐ1: KHÔNG ĐẠT (FAIL) - Web từ chối mật khẩu đúng tại lượt #{success_at} dù chưa vượt ngưỡng.[/bold red]")
    else:
        if success_attempt_result and not success_attempt_result[1]:
            console.print(f"[bold green][+] ĐÁNH GIÁ GĐ2: ĐẠT (PASS) - Mật khẩu đúng tại lượt #{success_at} đã bị từ chối / BỊ KHÓA sau {fail_count} lần sai liên tiếp.[/bold green]")
            verdict = True
        else:
            console.print(f"[bold red][-] ĐÁNH GIÁ GĐ2: KHÔNG ĐẠT (FAIL) - Web vẫn cho phép truy cập tại lượt #{success_at} sau {fail_count} lần sai.[/bold red]")

    return verdict


def run_matrix_sequence(
    port: int,
    g1_fail: int = 4,
    g1_pass: int = 5,
    g2_fail: int = 5,
    g2_pass: int = 6,
    rate_cps: float = 2.5,
    auth_type: str = "auto"
) -> bool:
    """Kiểm thử chuỗi ma trận duy nhất: GĐ1 (Reset trước ngưỡng) + GĐ2 (Khóa tài khoản sau ngưỡng)."""
    limiter = PreciseRateLimiter(rate_cps=rate_cps)
    total_steps = g1_fail + 1 + g2_fail + 1
    table = Table(title=f"Tiến trình kiểm thử ma trận Web Admin ({total_steps} bước)", show_lines=True)
    table.add_column("Bước", justify="center", style="bold")
    table.add_column("Loại", justify="center")
    table.add_column("Thời điểm phát", justify="center")
    table.add_column("Mật khẩu thử nghiệm", justify="left")
    table.add_column("Kết quả phản hồi Web", justify="left")
    table.add_column("Độ trễ", justify="right")

    step_num = 0
    g1_result = None
    g2_result = None

    for i in range(1, g1_fail + 1):
        step_num += 1
        pos, t_str = limiter.wait_next()
        test_pass = f"BruteForce_{step_num}#WebBad"
        ok, status, lat = attempt_web_login(USER, test_pass, port=port, timeout=2.5, auth_type=auth_type)
        is_blocked = any(kw in status for kw in ["TIMEOUT", "CONN_REFUSED", "DROPPED", "BỊ KHÓA", "403", "429"])
        style = "red" if is_blocked else "yellow"
        table.add_row(f"#{step_num:02d}", "[bold red]SAI[/bold red]", t_str, f"[yellow]{USER} : {test_pass}[/yellow]", f"[{style}]{status}[/{style}]", f"{lat:.1f} ms")

    step_num += 1
    pos, t_str = limiter.wait_next()
    ok, status, lat = attempt_web_login(USER, CORRECT_PASS, port=port, timeout=2.5, auth_type=auth_type)
    g1_result = (step_num, ok, status)
    style = "green" if ok else "red"
    table.add_row(f"#{step_num:02d}", "[bold green]ĐÚNG[/bold green]", t_str, f"[bold green]{USER} : {CORRECT_PASS}[/bold green]", f"[{style}]{status}[/{style}]", f"{lat:.1f} ms")

    table.add_section()
    time.sleep(1.0)

    for i in range(1, g2_fail + 1):
        step_num += 1
        pos, t_str = limiter.wait_next()
        test_pass = f"BruteForce_{step_num}#WebBad"
        ok, status, lat = attempt_web_login(USER, test_pass, port=port, timeout=2.5, auth_type=auth_type)
        is_blocked = any(kw in status for kw in ["TIMEOUT", "CONN_REFUSED", "DROPPED", "BỊ KHÓA", "403", "429"])
        style = "red" if is_blocked else "yellow"
        table.add_row(f"#{step_num:02d}", "[bold red]SAI[/bold red]", t_str, f"[yellow]{USER} : {test_pass}[/yellow]", f"[{style}]{status}[/{style}]", f"{lat:.1f} ms")

    step_num += 1
    pos, t_str = limiter.wait_next()
    ok, status, lat = attempt_web_login(USER, CORRECT_PASS, port=port, timeout=2.5, auth_type=auth_type)
    g2_result = (step_num, ok, status)
    is_locked = not ok
    style = "green" if is_locked else "red"
    table.add_row(f"#{step_num:02d}", "[bold green]ĐÚNG[/bold green]", t_str, f"[bold green]{USER} : {CORRECT_PASS}[/bold green]", f"[{style}]{status}[/{style}]", f"{lat:.1f} ms")

    console.print(table)

    g1_ok = (g1_result and g1_result[1])
    g2_ok = (g2_result and not g2_result[1])

    console.print("")
    if g1_ok and g2_ok:
        console.print("[bold green][+] ĐÁNH GIÁ: ĐẠT (PASS) - GĐ1 Reset bộ đếm: THÀNH CÔNG (HTTP 200) | GĐ2 Khóa tài khoản: ĐÃ KHÓA (Bị từ chối)[/bold green]")
        return True
    elif g1_ok and not g2_ok:
        console.print("[bold red][-] ĐÁNH GIÁ: KHÔNG ĐẠT (FAIL) - GĐ1 Reset bộ đếm: THÀNH CÔNG | GĐ2 Khóa tài khoản: KHÔNG KHÓA (Vẫn truy cập được)[/bold red]")
        return False
    else:
        console.print(f"[bold red][-] ĐÁNH GIÁ: KHÔNG ĐẠT (FAIL) - GĐ1 Reset: {'THÀNH CÔNG' if g1_ok else 'THẤT BẠI'} | GĐ2 Khóa: {'ĐÃ KHÓA' if g2_ok else 'THẤT BẠI'}[/bold red]")
        return False



def parse_arguments():
    parser = argparse.ArgumentParser(description="Bộ đo kiểm vét cạn & Khóa giao diện Web (QCVN 11 Clause 2.1.5)")
    parser.add_argument("--port", type=int, default=HTTPS_PORT, help=f"Cổng HTTPS (Mặc định: {HTTPS_PORT})")
    parser.add_argument("--mode", choices=["matrix", "custom", "1", "2", "3", "reset", "lockout", "all"], default="custom", help="Chế độ chạy")
    parser.add_argument("--fail-count", type=int, default=6, help="Số lần gửi sai liên tiếp (Mặc định: 6 cho Web)")
    parser.add_argument("--success-at", type=int, default=7, help="Lượt chèn thử mật khẩu đúng (Mặc định: 7; 0=Không thử đúng)")
    parser.add_argument("--stage", type=int, choices=[1, 2], default=None, help="Giai đoạn kiểm thử (1: Reset trước ngưỡng, 2: Khóa sau ngưỡng)")
    parser.add_argument("--g1-fail", type=int, default=4, help="GĐ1: Số lần thử sai (Mặc định: 4)")
    parser.add_argument("--g1-pass", type=int, default=5, help="GĐ1: Lượt thử đúng (Mặc định: 5)")
    parser.add_argument("--g2-fail", type=int, default=5, help="GĐ2: Số lần thử sai (Mặc định: 5)")
    parser.add_argument("--g2-pass", type=int, default=6, help="GĐ2: Lượt thử đúng (Mặc định: 6)")
    parser.add_argument("--rate", type=float, default=2.5, help="Tốc độ gửi kết nối mới/giây (Mặc định: 2.5 req/s)")
    parser.add_argument("--auth", "--auth-type", dest="auth_type", choices=["auto", "basic", "digest", "adapter"], default="auto", help="Cơ chế xác thực Web (auto, basic, digest, adapter)")
    return parser.parse_args()


def main():
    global GLOBAL_PCAP_FILE
    args = parse_arguments()
    port = args.port

    pcap_proc, GLOBAL_PCAP_FILE = start_pcap_capture(
        DUT_IP,
        f"tcp port {port}",
        prefix=f"web_lockout_audit_{port}"
    )
    if GLOBAL_PCAP_FILE and args.mode not in ("matrix", "custom"):
        print(f"[*] Đang tự động bắt gói tin PCAP vào: {GLOBAL_PCAP_FILE}\n")

    try:
        if args.mode == "matrix":
            run_matrix_sequence(
                port=port,
                g1_fail=args.g1_fail,
                g1_pass=args.g1_pass,
                g2_fail=args.g2_fail,
                g2_pass=args.g2_pass,
                rate_cps=args.rate,
                auth_type=args.auth_type
            )
        elif args.mode in ("1", "reset"):
            run_custom_sequence(port, fail_count=3, success_at=4, rate_cps=args.rate, auth_type=args.auth_type)
        elif args.mode in ("2", "lockout"):
            run_custom_sequence(port, fail_count=6, success_at=7, rate_cps=args.rate, auth_type=args.auth_type)
        elif args.mode in ("3", "all"):
            console.print("\n[bold cyan]>>> GIAI ĐOẠN 1: KIỂM CHỨNG RESET BỘ ĐẾM WEB TRƯỚC NGƯỠNG <<<[/bold cyan]")
            pass1 = run_custom_sequence(port, fail_count=3, success_at=4, rate_cps=args.rate, auth_type=args.auth_type)
            if pass1:
                console.print("\n[*] Chờ 3 giây trước khi chuyển sang giai đoạn kiểm thử kích hoạt khóa...")
                time.sleep(3)
                console.print("\n[bold cyan]>>> GIAI ĐOẠN 2: KIỂM CHỨNG KÍCH HOẠT KHÓA WEB SAU 6 LẦN SAI <<<[/bold cyan]")
                run_custom_sequence(port, fail_count=6, success_at=7, rate_cps=args.rate, auth_type=args.auth_type)
        else:
            run_custom_sequence(
                port=port,
                fail_count=args.fail_count,
                success_at=args.success_at,
                rate_cps=args.rate,
                stage=args.stage,
                auth_type=args.auth_type
            )
    finally:
        stop_pcap_capture(pcap_proc)


if __name__ == '__main__':
    main()
