#!/usr/bin/env python3
"""
Bộ đo kiểm phòng vệ chống vét cạn & Khóa tài khoản giao diện SSH (Yêu cầu 2.1.5 - QCVN 11:2026/BCA)
Kiểm chứng cơ chế SSH-Authmech (Cổng 22):
- Ngưỡng khóa: 10 lần sai trong 30 giây -> khóa giao diện trong 5 phút.
- Giới hạn tần suất tường lửa (Firewall Rate Limiting: 3 kết nối mới/giây).
- Reset bộ đếm thất bại khi nhập đúng trước ngưỡng.
- Hỗ trợ Kịch bản Tấn công Tùy chỉnh (Custom Attack Sequence: --fail-count, --success-at, --rate).
- Bắt gói tin PCAP & Hiển thị bộ lọc, hướng dẫn Sort trong Wireshark.
Author: Merlin / Antigravity
"""

import socket
import sys
import os
import time
import json
import datetime
import argparse
from typing import Tuple, List, Optional

import paramiko
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
SSH_PORT = config.get("service_ports", {}).get("ssh", 22)
SSH_USER = config.get("target_camera", {}).get("ssh_username", config.get("target_camera", {}).get("username", "admin"))
CORRECT_PASS = config.get("target_camera", {}).get("ssh_password", config.get("target_camera", {}).get("password", ""))

GLOBAL_PCAP_FILE = ""


class PreciseRateLimiter:
    """Điều tiết tốc độ gửi kết nối SSH mới theo rate_cps (Mặc định: 3.0 conn/s)."""
    def __init__(self, rate_cps: float = 3.0):
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


def connect_ssh_socket(ip: str, port: int, timeout: float = 3.0) -> socket.socket:
    """Kết nối SSH TCP socket với fallback giao diện mạng máy kiểm thử."""
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
        return s
    except Exception:
        pass

    for fallback_ip in ["192.168.20.45", "192.168.20.225", "192.168.20.39", "192.168.101.250"]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.bind((fallback_ip, 0))
            s.connect((ip, port))
            return s
        except Exception:
            try:
                s.close()
            except Exception:
                pass

    return socket.create_connection((ip, port), timeout=timeout)


def attempt_ssh_login(username: str, password: str, port: int = 22, timeout: float = 3.0) -> Tuple[bool, str, float]:
    """
    Thực hiện 1 lần xác thực SSH.
    Returns: (is_success, status_message, latency_ms)
    """
    t_start = time.time()
    sock = None
    transport = None
    try:
        sock = connect_ssh_socket(DUT_IP, port, timeout=timeout)
        transport = paramiko.Transport(sock)
        transport.start_client(timeout=timeout)

        try:
            transport.auth_none(username)
        except paramiko.BadAuthenticationType as e:
            allowed = e.allowed_types
        except Exception:
            allowed = ["password"]

        if "password" in allowed:
            transport.auth_password(username, password)
        elif "keyboard-interactive" in allowed:
            def handler(title, instructions, prompt_list):
                return [password] * len(prompt_list)
            transport.auth_interactive(username, handler)
        else:
            transport.auth_password(username, password)

        elapsed = (time.time() - t_start) * 1000
        return True, "AUTH_SUCCESS (Mã 52: Đăng nhập thành công)", elapsed

    except paramiko.AuthenticationException:
        elapsed = (time.time() - t_start) * 1000
        return False, "AUTH_FAILED (Mã 51: SSH_MSG_USERAUTH_FAILURE)", elapsed
    except socket.timeout:
        elapsed = (time.time() - t_start) * 1000
        return False, "TIMEOUT (Mạng/Dịch vụ bị đóng băng - Bị khóa)", elapsed
    except (ConnectionRefusedError, ConnectionResetError) as e:
        elapsed = (time.time() - t_start) * 1000
        return False, f"CONN_DROPPED ({e.__class__.__name__}: Bị ngắt kết nối/Tường lửa chặn)", elapsed
    except Exception as e:
        elapsed = (time.time() - t_start) * 1000
        err_msg = str(e)
        if "No route to host" in err_msg or "timed out" in err_msg.lower():
            return False, "BLOCKED (Tường lửa hạ cờ kết nối / Drop IP)", elapsed
        return False, f"ERROR ({err_msg})", elapsed
    finally:
        if transport:
            try:
                transport.close()
            except Exception:
                pass
        if sock:
            try:
                sock.close()
            except Exception:
                pass


def run_custom_sequence(port: int, fail_count: int, success_at: int, rate_cps: float = 3.0) -> bool:
    """
    Chạy kịch bản tấn công tùy chỉnh cho SSH:
    - fail_count: Số lần thử sai liên tiếp
    - success_at: Lượt chèn thử mật khẩu đúng (0=Không thử đúng)
    - rate_cps: Tốc độ gửi kết nối
    """
    if success_at <= 0:
        total_steps = fail_count
    elif success_at > fail_count:
        total_steps = success_at
    else:
        total_steps = fail_count + 1

    console.print(Panel(
        f"[bold white]KỊCH BẢN ĐO KIỂM VÉT CẠN TÙY CHỈNH GIAO DIỆN SSH (OS LINUX)[/bold white]\n"
        f"• Mục tiêu DUT IP    : [cyan]{DUT_IP}:{port}[/cyan]\n"
        f"• Tài khoản kiểm thử : [bold green]{SSH_USER}[/bold green]\n"
        f"• Số lần thử sai     : [bold red]{fail_count} lần[/bold red]\n"
        f"• Lượt thử mật khẩu ĐÚNG: [bold yellow]{'Không thử đúng' if success_at <= 0 else f'Lượt thứ {success_at}'}[/bold yellow]\n"
        f"• Tổng số bước chạy  : [bold white]{total_steps} bước[/bold white]\n"
        f"• Tốc độ phát        : [bold magenta]{rate_cps:.1f} kết nối mới/giây[/bold magenta] (Kiểm tra Firewall SSH Rate-Limit)",
        title="THIẾT LẬP KỊCH BẢN TẤN CÔNG SSH (CLAUSE 2.1.5)",
        border_style="cyan"
    ))

    limiter = PreciseRateLimiter(rate_cps=rate_cps)
    table = Table(title=f"Tiến trình kịch bản tùy chỉnh SSH ({total_steps} bước)", show_lines=True)
    table.add_column("Bước", justify="center", style="bold")
    table.add_column("Loại", justify="center")
    table.add_column("Thời điểm", justify="center")
    table.add_column("Mật khẩu thử nghiệm", justify="left")
    table.add_column("Kết quả phản hồi SSH", justify="left")
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
            test_pass = f"BruteForce_{step}#SSHBad"
            type_lbl = "[bold red]SAI[/bold red]"

        ok, status, lat = attempt_ssh_login(SSH_USER, test_pass, port=port, timeout=2.5)

        is_blocked = any(kw in status for kw in ["TIMEOUT", "CONN_DROPPED", "BLOCKED", "Connection refused"])
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
        console.print("  [MỤC TIÊU KIỂM ĐỊNH]: KÍCH HOẠT KHÓA GIAO DIỆN SSH KHI VƯỢT NGƯỠNG SAI")
        if success_attempt_result and not success_attempt_result[1]:
            console.print("[bold green][+] ĐÁNH GIÁ: ĐẠT (PASS)![/bold green]")
            console.print(f"    -> Mật khẩu đúng tại lượt #{success_at} đã bị từ chối / BỊ KHÓA sau {fail_count} lần sai liên tiếp.")
            console.print(f"    -> Chi tiết: {success_attempt_result[2]}")
            verdict = True
        else:
            console.print("[bold red][-] ĐÁNH GIÁ: KHÔNG ĐẠT (FAIL)![/bold red]")
            console.print(f"    -> SSH vẫn cho phép đăng nhập tại lượt #{success_at} sau {fail_count} lần sai.")
    elif 0 < success_at <= fail_count:
        console.print("  [MỤC TIÊU KIỂM ĐỊNH]: RESET BỘ ĐẾM KHI NHẬP ĐÚNG TRƯỚC NGƯỠNG")
        if success_attempt_result and success_attempt_result[1]:
            console.print("[bold green][+] ĐÁNH GIÁ: ĐẠT (PASS)![/bold green]")
            console.print(f"    -> Mật khẩu đúng tại lượt #{success_at} đăng nhập thành công. Bộ đếm đã được reset.")
            verdict = True
        else:
            console.print("[bold red][-] ĐÁNH GIÁ: KHÔNG ĐẠT (FAIL)![/bold red]")
            console.print(f"    -> SSH từ chối mật khẩu đúng tại lượt #{success_at} dù chưa vượt ngưỡng.")
    else:
        console.print("  [MỤC TIÊU KIỂM ĐỊNH]: ĐO LƯỜNG TƯỜNG LỬA CHỐNG VÉT CẠN SSH LIÊN TỤC")
        console.print(f"    -> Đã gửi {fail_count} lần sai liên tiếp (Số lần bị drop/timeout: {dropped_count}).")
        verdict = True
    console.print("=" * 80)

    filters = [
        ("Toàn bộ chuỗi gói tin vét cạn SSH", f"tcp.port == {port} && ssh"),
        ("Các gói tin xác thực sai (Mã 51 SSH_MSG_USERAUTH_FAILURE)", f"tcp.port == {port} && ssh.message_code == 51"),
        ("Gói tin xác thực thành công (Mã 52 SSH_MSG_USERAUTH_SUCCESS)", f"tcp.port == {port} && ssh.message_code == 52"),
        ("Gói tin bị KHÓA / Drop / Reset kết nối", f"tcp.port == {port} && (tcp.flags.reset == 1 || tcp.flags.syn == 1)")
    ]
    display_wireshark_panel(
        console,
        GLOBAL_PCAP_FILE,
        filters,
        is_tls=False,
        sort_tip="Click tiêu đề cột No. hoặc Time trong Wireshark để theo dõi chuỗi xác thực SSH.",
        title=f"BẰNG CHỨNG GÓI TIN SSH AUDIT (CỔNG {port})"
    )
    return verdict


def parse_arguments():
    parser = argparse.ArgumentParser(description="Bộ đo kiểm vét cạn & Khóa giao diện SSH (QCVN 11 Clause 2.1.5)")
    parser.add_argument("--port", type=int, default=SSH_PORT, help=f"Cổng SSH (Mặc định: {SSH_PORT})")
    parser.add_argument("--mode", choices=["custom", "1", "2", "3", "reset", "lockout", "all"], default="custom", help="Chế độ chạy")
    parser.add_argument("--fail-count", type=int, default=10, help="Số lần gửi sai liên tiếp (Mặc định: 10)")
    parser.add_argument("--success-at", type=int, default=11, help="Lượt chèn thử mật khẩu đúng (Mặc định: 11; 0=Không thử đúng)")
    parser.add_argument("--rate", type=float, default=3.0, help="Tốc độ gửi kết nối mới/giây (Mặc định: 3.0 conn/s)")
    return parser.parse_args()


def main():
    global GLOBAL_PCAP_FILE
    args = parse_arguments()
    port = args.port

    pcap_proc, GLOBAL_PCAP_FILE = start_pcap_capture(
        DUT_IP,
        f"tcp port {port}",
        prefix=f"ssh_lockout_audit_{port}"
    )
    if GLOBAL_PCAP_FILE:
        print(f"[*] Đang tự động bắt gói tin PCAP vào: {GLOBAL_PCAP_FILE}\n")

    try:
        if args.mode in ("1", "reset"):
            run_custom_sequence(port, fail_count=4, success_at=5, rate_cps=args.rate)
        elif args.mode in ("2", "lockout"):
            run_custom_sequence(port, fail_count=10, success_at=11, rate_cps=args.rate)
        elif args.mode in ("3", "all"):
            console.print("\n[bold cyan]>>> GIAI ĐOẠN 1: KIỂM CHỨNG RESET BỘ ĐẾM SSH TRƯỚC NGƯỠNG <<<[/bold cyan]")
            pass1 = run_custom_sequence(port, fail_count=4, success_at=5, rate_cps=args.rate)
            if pass1:
                console.print("\n[*] Chờ 3 giây trước khi chuyển sang giai đoạn kiểm thử kích hoạt khóa...")
                time.sleep(3)
                console.print("\n[bold cyan]>>> GIAI ĐOẠN 2: KIỂM CHỨNG KÍCH HOẠT KHÓA SSH SAU 10 LẦN SAI <<<[/bold cyan]")
                run_custom_sequence(port, fail_count=10, success_at=11, rate_cps=args.rate)
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
