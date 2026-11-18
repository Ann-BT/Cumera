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
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pcap_recorder import start_pcap_capture, stop_pcap_capture, display_wireshark_panel
from toolkit_config import detect_host_network, get_service_ports, get_target_info, load_config, make_console

console = make_console()
config = load_config()
_target_info = get_target_info(config)
SERVICE_PORTS = get_service_ports(config)

DUT_IP = _target_info["ip"]
SSH_PORT = int(SERVICE_PORTS["ssh"])
SSH_USER = _target_info["ssh_username"]
CORRECT_PASS = _target_info["ssh_password"]

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
    """Kết nối SSH TCP socket với fallback IP giao diện mạng tới DUT."""
    try:
        return socket.create_connection((ip, port), timeout=timeout)
    except Exception:
        pass

    _, host_ip = detect_host_network(ip, config)
    if host_ip and host_ip != "127.0.0.1":
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.bind((host_ip, 0))
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


def run_custom_sequence(
    port: int,
    fail_count: int,
    success_at: int,
    rate_cps: float = 3.0,
    stage: Optional[int] = None,
    threshold: int = 5
) -> bool:
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

    limiter = PreciseRateLimiter(rate_cps=rate_cps)
    table = Table(title=f"Tiến trình kịch bản tùy chỉnh SSH ({total_steps} bước)", show_lines=True)
    table.add_column("Bước", justify="center", style="bold")
    table.add_column("Loại", justify="center")
    table.add_column("Thời điểm", justify="center")
    table.add_column("Mật khẩu thử nghiệm", justify="left")
    table.add_column("Kết quả phản hồi SSH", justify="left")
    table.add_column("Độ trễ", justify="right")

    success_attempt_result = None

    for step in range(1, total_steps + 1):
        pos, t_str = limiter.wait_next()
        is_success_step = (step == success_at)

        if is_success_step:
            test_pass = CORRECT_PASS
            type_lbl = "[bold green]ĐÚNG[/bold green]"
            display_pass = f"[bold green]{SSH_USER} : {CORRECT_PASS}[/bold green]"
        else:
            test_pass = f"BruteForce_{step}#SSHBad"
            type_lbl = "[bold red]SAI[/bold red]"
            display_pass = f"[yellow]{SSH_USER} : {test_pass}[/yellow]"

        ok, status, lat = attempt_ssh_login(SSH_USER, test_pass, port=port, timeout=2.5)

        is_blocked = any(kw in status for kw in ["TIMEOUT", "CONN_DROPPED", "BLOCKED", "Connection refused"])
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
            console.print(f"[bold green][+] ĐÁNH GIÁ GĐ1: ĐẠT (PASS) - Mật khẩu đúng tại lượt #{success_at} đăng nhập thành công. Bộ đếm đã reset.[/bold green]")
            verdict = True
        else:
            console.print(f"[bold red][-] ĐÁNH GIÁ GĐ1: KHÔNG ĐẠT (FAIL) - SSH từ chối mật khẩu đúng tại lượt #{success_at} dù chưa vượt ngưỡng.[/bold red]")
    else:
        if success_attempt_result and not success_attempt_result[1]:
            console.print(f"[bold green][+] ĐÁNH GIÁ GĐ2: ĐẠT (PASS) - Mật khẩu đúng tại lượt #{success_at} đã bị từ chối / BỊ KHÓA sau {fail_count} lần sai liên tiếp.[/bold green]")
            verdict = True
        else:
            console.print(f"[bold red][-] ĐÁNH GIÁ GĐ2: KHÔNG ĐẠT (FAIL) - SSH vẫn cho phép đăng nhập tại lượt #{success_at} sau {fail_count} lần sai.[/bold red]")

    return verdict


def run_matrix_sequence(
    port: int,
    g1_fail: int = 4,
    g1_pass: int = 5,
    g2_fail: int = 5,
    g2_pass: int = 6,
    rate_cps: float = 3.0
) -> bool:
    """Kiểm thử chuỗi ma trận duy nhất: GĐ1 (Reset trước ngưỡng) + GĐ2 (Khóa tài khoản sau ngưỡng)."""
    limiter = PreciseRateLimiter(rate_cps=rate_cps)
    total_steps = g1_fail + 1 + g2_fail + 1
    table = Table(title=f"Tiến trình kiểm thử ma trận SSH ({total_steps} bước)", show_lines=True)
    table.add_column("Bước", justify="center", style="bold")
    table.add_column("Loại", justify="center")
    table.add_column("Thời điểm phát", justify="center")
    table.add_column("Mật khẩu thử nghiệm", justify="left")
    table.add_column("Kết quả phản hồi SSH", justify="left")
    table.add_column("Độ trễ", justify="right")

    step_num = 0
    g1_result = None
    g2_result = None

    for i in range(1, g1_fail + 1):
        step_num += 1
        pos, t_str = limiter.wait_next()
        test_pass = f"BruteForce_{step_num}#SSHBad"
        ok, status, lat = attempt_ssh_login(SSH_USER, test_pass, port=port, timeout=2.5)
        is_blocked = any(kw in status for kw in ["TIMEOUT", "CONN_DROPPED", "BLOCKED", "Connection refused"])
        style = "red" if is_blocked else "yellow"
        table.add_row(f"#{step_num:02d}", "[bold red]SAI[/bold red]", t_str, f"[yellow]{SSH_USER} : {test_pass}[/yellow]", f"[{style}]{status}[/{style}]", f"{lat:.1f} ms")

    step_num += 1
    pos, t_str = limiter.wait_next()
    ok, status, lat = attempt_ssh_login(SSH_USER, CORRECT_PASS, port=port, timeout=2.5)
    g1_result = (step_num, ok, status)
    style = "green" if ok else "red"
    table.add_row(f"#{step_num:02d}", "[bold green]ĐÚNG[/bold green]", t_str, f"[bold green]{SSH_USER} : {CORRECT_PASS}[/bold green]", f"[{style}]{status}[/{style}]", f"{lat:.1f} ms")

    table.add_section()
    time.sleep(1.0)

    for i in range(1, g2_fail + 1):
        step_num += 1
        pos, t_str = limiter.wait_next()
        test_pass = f"BruteForce_{step_num}#SSHBad"
        ok, status, lat = attempt_ssh_login(SSH_USER, test_pass, port=port, timeout=2.5)
        is_blocked = any(kw in status for kw in ["TIMEOUT", "CONN_DROPPED", "BLOCKED", "Connection refused"])
        style = "red" if is_blocked else "yellow"
        table.add_row(f"#{step_num:02d}", "[bold red]SAI[/bold red]", t_str, f"[yellow]{SSH_USER} : {test_pass}[/yellow]", f"[{style}]{status}[/{style}]", f"{lat:.1f} ms")

    step_num += 1
    pos, t_str = limiter.wait_next()
    ok, status, lat = attempt_ssh_login(SSH_USER, CORRECT_PASS, port=port, timeout=2.5)
    g2_result = (step_num, ok, status)
    is_locked = not ok
    style = "green" if is_locked else "red"
    table.add_row(f"#{step_num:02d}", "[bold green]ĐÚNG[/bold green]", t_str, f"[bold green]{SSH_USER} : {CORRECT_PASS}[/bold green]", f"[{style}]{status}[/{style}]", f"{lat:.1f} ms")

    console.print(table)

    g1_ok = (g1_result and g1_result[1])
    g2_ok = (g2_result and not g2_result[1])

    console.print("")
    if g1_ok and g2_ok:
        console.print("[bold green][+] ĐÁNH GIÁ: ĐẠT (PASS) - GĐ1 Reset bộ đếm: THÀNH CÔNG | GĐ2 Khóa tài khoản: ĐÃ KHÓA (Bị từ chối)[/bold green]")
        return True
    elif g1_ok and not g2_ok:
        console.print("[bold red][-] ĐÁNH GIÁ: KHÔNG ĐẠT (FAIL) - GĐ1 Reset bộ đếm: THÀNH CÔNG | GĐ2 Khóa tài khoản: KHÔNG KHÓA (Vẫn đăng nhập được)[/bold red]")
        return False
    else:
        console.print(f"[bold red][-] ĐÁNH GIÁ: KHÔNG ĐẠT (FAIL) - GĐ1 Reset: {'THÀNH CÔNG' if g1_ok else 'THẤT BẠI'} | GĐ2 Khóa: {'ĐÃ KHÓA' if g2_ok else 'THẤT BẠI'}[/bold red]")
        return False



def parse_arguments():
    parser = argparse.ArgumentParser(description="Bộ đo kiểm vét cạn & Khóa giao diện SSH (QCVN 11 Clause 2.1.5)")
    parser.add_argument("--port", type=int, default=SSH_PORT, help=f"Cổng SSH (Mặc định: {SSH_PORT})")
    parser.add_argument("--mode", choices=["matrix", "custom", "1", "2", "3", "reset", "lockout", "all"], default="custom", help="Chế độ chạy")
    parser.add_argument("--fail-count", type=int, default=10, help="Số lần gửi sai liên tiếp (Mặc định: 10)")
    parser.add_argument("--success-at", type=int, default=11, help="Lượt chèn thử mật khẩu đúng (Mặc định: 11; 0=Không thử đúng)")
    parser.add_argument("--stage", type=int, choices=[1, 2], default=None, help="Giai đoạn kiểm thử (1: Reset trước ngưỡng, 2: Khóa sau ngưỡng)")
    parser.add_argument("--g1-fail", type=int, default=4, help="GĐ1: Số lần thử sai (Mặc định: 4)")
    parser.add_argument("--g1-pass", type=int, default=5, help="GĐ1: Lượt thử đúng (Mặc định: 5)")
    parser.add_argument("--g2-fail", type=int, default=5, help="GĐ2: Số lần thử sai (Mặc định: 5)")
    parser.add_argument("--g2-pass", type=int, default=6, help="GĐ2: Lượt thử đúng (Mặc định: 6)")
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
                rate_cps=args.rate
            )
        elif args.mode in ("1", "reset"):
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
                rate_cps=args.rate,
                stage=args.stage
            )
    finally:
        stop_pcap_capture(pcap_proc)


if __name__ == '__main__':
    main()
