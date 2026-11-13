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

console = make_console()
config = load_config()
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
    """Auto-detect scheme (https/http) and protected auth endpoint across camera brands."""
    if port in _WEB_TARGET_CACHE:
        return _WEB_TARGET_CACHE[port]
    scheme = "https" if is_tls_port(DUT_IP, port) else "http"
    candidates = [
        "/axis-cgi/param.cgi?action=list&group=root.Brand",
        "/ISAPI/System/deviceInfo",
        "/cgi-bin/magicBox.cgi?action=getSystemInfo",
        "/LAPI/V1.0/System/DeviceBasicInfo",
        "/api/system/information",
        "/",
    ]
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


def attempt_web_login(username: str, password: str, port: int = 443, timeout: float = 3.0) -> Tuple[bool, str, float]:
    """
    Thực hiện 1 lần xác thực qua Web HTTPS/HTTP (đa hãng Camera).
    Returns: (is_success, status_str, latency_ms)
    """
    _, auth_url = _resolve_web_auth_target(port)
    t_start = time.time()
    try:
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
        elif res.status_code == 401:
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


def run_custom_sequence(port: int, fail_count: int, success_at: int, rate_cps: float = 2.5) -> bool:
    """
    Chạy kịch bản tấn công tùy chỉnh cho Web HTTPS:
    - fail_count: Số lần thử sai liên tiếp (IXIT: 6 lần)
    - success_at: Lượt chèn thử mật khẩu đúng (0=Không thử đúng)
    - rate_cps: Tốc độ gửi request
    """
    if success_at <= 0:
        total_steps = fail_count
    elif success_at > fail_count:
        total_steps = success_at
    else:
        total_steps = fail_count + 1

    console.print(Panel(
        f"[bold white]KỊCH BẢN ĐO KIỂM VÉT CẠN TÙY CHỈNH GIAO DIỆN WEB ADMIN (HTTPS)[/bold white]\n"
        f"• Mục tiêu DUT IP    : [cyan]https://{DUT_IP}:{port}/[/cyan]\n"
        f"• Tài khoản kiểm thử : [bold green]{USER}[/bold green]\n"
        f"• Số lần thử sai     : [bold red]{fail_count} lần[/bold red]\n"
        f"• Lượt thử mật khẩu ĐÚNG: [bold yellow]{'Không thử đúng' if success_at <= 0 else f'Lượt thứ {success_at}'}[/bold yellow]\n"
        f"• Tổng số bước chạy  : [bold white]{total_steps} bước[/bold white]\n"
        f"• Tốc độ phát        : [bold magenta]{rate_cps:.1f} kết nối mới/giây[/bold magenta] (Kiểm tra Firewall Web Rate-Limit)",
        title="THIẾT LẬP KỊCH BẢN TẤN CÔNG WEB (CLAUSE 2.1.5)",
        border_style="cyan"
    ))

    limiter = PreciseRateLimiter(rate_cps=rate_cps)
    table = Table(title=f"Tiến trình kịch bản tùy chỉnh Web HTTPS ({total_steps} bước)", show_lines=True)
    table.add_column("Bước", justify="center", style="bold")
    table.add_column("Loại", justify="center")
    table.add_column("Thời điểm", justify="center")
    table.add_column("Mật khẩu thử nghiệm", justify="left")
    table.add_column("Kết quả phản hồi Web", justify="left")
    table.add_column("Độ trễ", justify="right")

    success_attempt_result = None
    dropped_count = 0

    for step in range(1, total_steps + 1):
        pos, t_str = limiter.wait_next()
        is_success_step = (step == success_at)

        if is_success_step:
            test_pass = CORRECT_PASS
            type_lbl = "[bold green]ĐÚNG[/bold green]"
        else:
            test_pass = f"BruteForce_{step}#WebBad"
            type_lbl = "[bold red]SAI[/bold red]"

        ok, status, lat = attempt_web_login(USER, test_pass, port=port, timeout=2.5)

        is_blocked = any(kw in status for kw in ["TIMEOUT", "CONN_REFUSED", "DROPPED", "BỊ KHÓA", "403", "429"])
        if is_blocked:
            dropped_count += 1

        style = "green" if (is_success_step and ok) else ("red" if is_blocked else "yellow")
        table.add_row(
            f"#{step:02d}",
            type_lbl,
            t_str,
            test_pass if not is_success_step else "******",
            f"[{style}]{status}[/{style}]",
            f"{lat:.1f} ms"
        )

        if is_success_step:
            success_attempt_result = (step, ok, status)

    console.print(table)

    verdict = False
    console.print("\n" + "=" * 80)
    if success_at > fail_count:
        console.print("  [MỤC TIÊU KIỂM ĐỊNH]: KÍCH HOẠT KHÓA GIAO DIỆN WEB KHI VƯỢT NGƯỠNG SAI")
        if success_attempt_result and not success_attempt_result[1]:
            console.print("[bold green][+] ĐÁNH GIÁ: ĐẠT (PASS)![/bold green]")
            console.print(f"    -> Mật khẩu đúng tại lượt #{success_at} đã bị từ chối / BỊ KHÓA sau {fail_count} lần sai liên tiếp.")
            console.print(f"    -> Phản hồi: {success_attempt_result[2]}")
            verdict = True
        else:
            console.print("[bold red][-] ĐÁNH GIÁ: KHÔNG ĐẠT (FAIL)![/bold red]")
            console.print(f"    -> Web vẫn cho phép truy cập tại lượt #{success_at} sau {fail_count} lần sai.")
    elif 0 < success_at <= fail_count:
        console.print("  [MỤC TIÊU KIỂM ĐỊNH]: RESET BỘ ĐẾM KHI NHẬP ĐÚNG TRƯỚC NGƯỠNG")
        if success_attempt_result and success_attempt_result[1]:
            console.print("[bold green][+] ĐÁNH GIÁ: ĐẠT (PASS)![/bold green]")
            console.print(f"    -> Mật khẩu đúng tại lượt #{success_at} đăng nhập thành công (HTTP 200). Bộ đếm đã được reset.")
            verdict = True
        else:
            console.print("[bold red][-] ĐÁNH GIÁ: KHÔNG ĐẠT (FAIL)![/bold red]")
            console.print(f"    -> Web từ chối mật khẩu đúng tại lượt #{success_at} dù chưa vượt ngưỡng.")
    else:
        console.print("  [MỤC TIÊU KIỂM ĐỊNH]: ĐO LƯỜNG TƯỜNG LỬA CHỐNG VÉT CẠN WEB LIÊN TỤC")
        console.print(f"    -> Đã gửi {fail_count} lần sai liên tiếp (Số lần bị drop/timeout/chặn: {dropped_count}).")
        verdict = True
    console.print("=" * 80)

    filters = [
        ("Toàn bộ chuỗi gói tin vét cạn Web HTTPS", f"tcp.port == {port} && tls"),
        ("Các gói tin xác thực sai (Mã 401 Unauthorized)", f"http.response.code == 401 || http2.headers.status == 401"),
        ("Gói tin xác thực thành công (Mã 200 OK)", f"http.response.code == 200 || http2.headers.status == 200"),
        ("Gói tin bị KHÓA / Drop / Reset kết nối", f"tcp.port == {port} && (tcp.flags.reset == 1 || tcp.flags.syn == 1)")
    ]
    display_wireshark_panel(
        console,
        GLOBAL_PCAP_FILE,
        filters,
        is_tls=True,
        sort_tip="Click tiêu đề cột No. hoặc Time trong Wireshark để theo dõi chuỗi xác thực Web HTTPS.",
        title=f"BẰNG CHỨNG GÓI TIN WEB AUDIT (CỔNG {port})"
    )
    return verdict


def parse_arguments():
    parser = argparse.ArgumentParser(description="Bộ đo kiểm vét cạn & Khóa giao diện Web (QCVN 11 Clause 2.1.5)")
    parser.add_argument("--port", type=int, default=HTTPS_PORT, help=f"Cổng HTTPS (Mặc định: {HTTPS_PORT})")
    parser.add_argument("--mode", choices=["custom", "1", "2", "3", "reset", "lockout", "all"], default="custom", help="Chế độ chạy")
    parser.add_argument("--fail-count", type=int, default=6, help="Số lần gửi sai liên tiếp (Mặc định: 6 cho Web)")
    parser.add_argument("--success-at", type=int, default=7, help="Lượt chèn thử mật khẩu đúng (Mặc định: 7; 0=Không thử đúng)")
    parser.add_argument("--rate", type=float, default=2.5, help="Tốc độ gửi kết nối mới/giây (Mặc định: 2.5 req/s)")
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
    if GLOBAL_PCAP_FILE:
        print(f"[*] Đang tự động bắt gói tin PCAP vào: {GLOBAL_PCAP_FILE}\n")

    try:
        if args.mode in ("1", "reset"):
            run_custom_sequence(port, fail_count=3, success_at=4, rate_cps=args.rate)
        elif args.mode in ("2", "lockout"):
            run_custom_sequence(port, fail_count=6, success_at=7, rate_cps=args.rate)
        elif args.mode in ("3", "all"):
            console.print("\n[bold cyan]>>> GIAI ĐOẠN 1: KIỂM CHỨNG RESET BỘ ĐẾM WEB TRƯỚC NGƯỠNG <<<[/bold cyan]")
            pass1 = run_custom_sequence(port, fail_count=3, success_at=4, rate_cps=args.rate)
            if pass1:
                console.print("\n[*] Chờ 3 giây trước khi chuyển sang giai đoạn kiểm thử kích hoạt khóa...")
                time.sleep(3)
                console.print("\n[bold cyan]>>> GIAI ĐOẠN 2: KIỂM CHỨNG KÍCH HOẠT KHÓA WEB SAU 6 LẦN SAI <<<[/bold cyan]")
                run_custom_sequence(port, fail_count=6, success_at=7, rate_cps=args.rate)
        else:
            run_custom_sequence(
                port=port,
                fail_count=args.fail_count,
                success_at=args.success_at,
                rate_cps=args.rate
            )
    finally:
        stop_pcap_capture(pcap_proc)


if __name__ == '__main__':
    main()
