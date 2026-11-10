#!/usr/bin/env python3
"""
Bộ đo kiểm bảo vệ chống vét cạn luồng Video RTSP/RTSPS (Yêu cầu 2.1.5 - QCVN 11:2026/BCA & ETSI EN 303 645)
Hỗ trợ kiểm tra kịch bản tấn công tùy chỉnh (Custom Attack Sequence):
- Tùy biến số lần gửi sai liên tiếp (--fail-count)
- Tùy biến vị trí chèn lượt thử mật khẩu đúng (--success-at)
- Tùy biến tốc độ phát kết nối mới (--rate) để kiểm tra Tường lửa giới hạn tốc độ (3 new conn/s)
- Tùy biến cổng đo kiểm (--port 322 RTSPS hoặc 554 RTSP)
Author: Merlin / Antigravity
"""

import socket
import ssl
import sys
import base64
import time
import json
import os
import datetime
import argparse
from typing import Tuple, List, Optional
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
RTSP_PORT = config.get("service_ports", {}).get("rtsp_cleartext", 554)
RTSPS_PORT = config.get("service_ports", {}).get("rtsps_tls", 322)
RTSP_PATH = config.get("service_ports", {}).get("rtsp_path", "/axis-media/media.amp" if RTSPS_PORT == 322 else "/stream1")
if not RTSP_PATH.startswith("/"):
    RTSP_PATH = "/" + RTSP_PATH
CORRECT_PASS = config.get("target_camera", {}).get("password", "")
USER = config.get("target_camera", {}).get("username", "admin")
GLOBAL_PCAP_FILE = ""


def detect_rtsp_port(requested_port: Optional[int] = None) -> Tuple[int, bool]:
    """Phát hiện hoặc kiểm tra cổng RTSP khả dụng (322 TLS hoặc 554 Cleartext)."""
    if requested_port is not None:
        is_tls = (requested_port in [RTSPS_PORT, 322, 9554] or requested_port != 554)
        return requested_port, is_tls

    for port, use_tls in [(RTSPS_PORT, True), (RTSP_PORT, False), (322, True), (9554, True), (554, False)]:
        s = socket.socket()
        s.settimeout(1.0)
        res = s.connect_ex((DUT_IP, port))
        s.close()
        if res == 0:
            return port, use_tls
    return RTSPS_PORT, (RTSPS_PORT != 554)


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


def send_rtsp(username: str, password: str, seq: int, port: int, use_tls: bool, ua: str = "RTSP-Audit-Client") -> Tuple[bool, str, str]:
    """Gửi một request DESCRIBE RTSP/RTSPS qua kết nối TCP mới."""
    cred = base64.b64encode(f"{username}:{password}".encode()).decode()
    req = (
        f"DESCRIBE rtsp://{DUT_IP}:{port}{RTSP_PATH} RTSP/1.0\r\n"
        f"CSeq: {seq}\r\n"
        f"User-Agent: {ua}\r\n"
        f"Authorization: Basic {cred}\r\n\r\n"
    )
    try:
        if use_tls:
            with socket.create_connection((DUT_IP, port), timeout=3) as sock:
                with ctx.wrap_socket(sock, server_hostname=DUT_IP) as ssock:
                    ssock.sendall(req.encode())
                    resp = ssock.recv(2048).decode('utf-8', errors='ignore')
                    line1 = resp.splitlines()[0] if resp else "EMPTY_REPLY (Server closed connection)"
                    return True, line1, resp
        else:
            with socket.create_connection((DUT_IP, port), timeout=3) as sock:
                sock.sendall(req.encode())
                resp = sock.recv(2048).decode('utf-8', errors='ignore')
                line1 = resp.splitlines()[0] if resp else "EMPTY_REPLY (Server closed connection)"
                return True, line1, resp
    except socket.timeout:
        return False, "TIMEOUT (Server stopped responding)", ""
    except ConnectionResetError:
        return False, "RESET (Connection reset by peer)", ""
    except ConnectionRefusedError:
        return False, "REFUSED (Connection refused)", ""
    except Exception as e:
        return False, f"ERROR: {e}", ""


def run_custom_sequence(port: int, use_tls: bool, fail_count: int, success_at: int, rate_cps: float = 4.0) -> bool:
    """
    Thực hiện kịch bản tấn công tùy chỉnh:
    - fail_count: Tổng số lần sai dự định
    - success_at: Vị trí chèn lần thử mật khẩu đúng (0 = không thử đúng)
    - rate_cps: Tốc độ phát kết nối
    """
    proto_label = f"RTSPS (TLS - Cổng {port})" if use_tls else f"RTSP (Cleartext - Cổng {port})"
    
    # Tính toán tổng số bước
    if success_at <= 0:
        total_steps = fail_count
    elif success_at > fail_count:
        total_steps = success_at
    else:
        total_steps = fail_count + 1

    console.print(Panel(
        f"[bold white]KỊCH BẢN ĐO KIỂM VÉT CẠN TÙY CHỈNH LUỒNG VIDEO RTSP/RTSPS[/bold white]\n"
        f"• Mục tiêu DUT       : [cyan]{DUT_IP}:{port}[/cyan] ({proto_label})\n"
        f"• Tài khoản kiểm thử : [bold green]{USER}[/bold green]\n"
        f"• Số lần thử sai     : [bold red]{fail_count} lần[/bold red]\n"
        f"• Lượt thử mật khẩu ĐÚNG: [bold yellow]{'Không thử đúng' if success_at <= 0 else f'Lượt thứ {success_at}'}[/bold yellow]\n"
        f"• Tổng số bước chạy  : [bold white]{total_steps} bước[/bold white]\n"
        f"• Tốc độ phát        : [bold magenta]{rate_cps:.1f} kết nối mới/giây[/bold magenta] (Kiểm tra Firewall Rate-Limit)",
        title="THIẾT LẬP KỊCH BẢN TẤN CÔNG (CLAUSE 2.1.5)",
        border_style="cyan"
    ))

    limiter = PreciseRateLimiter(rate_cps=rate_cps)
    history = []
    exceeded_fw = 0
    blocked_fw = 0
    success_attempt_result = None

    print("-" * 80)
    for step in range(1, total_steps + 1):
        pos, t_str = limiter.wait_next()
        is_success_step = (step == success_at)
        
        if is_success_step:
            test_pass = CORRECT_PASS
            type_label = "[bold green][ĐÚNG - KIỂM CHỨNG][/bold green]"
        else:
            test_pass = f"WrongPass_{step}#Audit"
            type_label = "[bold red][SAI - THỬ VÉT CẠN][/bold red]"

        ok, status, raw = send_rtsp(USER, test_pass, seq=100 + step, port=port, use_tls=use_tls)
        
        is_blocked = any(kw in status for kw in ["TIMEOUT", "RESET", "REFUSED", "EMPTY_REPLY"])
        if pos == 4:
            exceeded_fw += 1
            if is_blocked:
                blocked_fw += 1
            fw_label = f"[{pos}/4 - VƯỢT NGƯỠNG FW 3/S]"
        else:
            fw_label = f"[{pos}/4]"

        console.print(f"  Bước #{step:02d} {type_label} {fw_label:<28} | {t_str} | Phản hồi: {status}")

        if is_success_step:
            success_attempt_result = (step, ok, status)
            if raw:
                print("  --- BẰNG CHỨNG NGUYÊN VĂN PHẢN HỒI LƯỢT THỬ ĐÚNG ---")
                print("  " + raw.strip().replace("\n", "\n  "))
                print("  ----------------------------------------------------")

        history.append({
            "step": step,
            "is_correct": is_success_step,
            "status": status,
            "blocked": is_blocked
        })

    print("-" * 80)
    console.print(f"[*] THỐNG KÊ TƯỜNG LỬA RATE-LIMIT (NGƯỠNG 3 KẾT NỐI/GIÂY):")
    console.print(f"    • Số lần phát ở gói thứ 4 trong 1 giây: {exceeded_fw} lần")
    console.print(f"    • Số lần bị tường lửa Drop/Reset: {blocked_fw} / {exceeded_fw}")

    # Đánh giá kết quả kịch bản
    verdict = False
    console.print("\n" + "=" * 80)
    if success_at > fail_count:
        # Mục đích: Thử đúng sau khi đã vượt ngưỡng sai -> Kỳ vọng BỊ KHÓA
        console.print("  [MỤC TIÊU KIỂM ĐỊNH]: KÍCH HOẠT KHÓA TÀI KHOẢN KHI VƯỢT NGƯỠNG SAI")
        if success_attempt_result and "200 OK" not in success_attempt_result[2]:
            console.print("[bold green][+] ĐÁNH GIÁ: ĐẠT (PASS)![/bold green]")
            console.print(f"    -> Mật khẩu đúng tại lượt thứ {success_at} đã bị từ chối / BỊ KHÓA sau {fail_count} lần sai liên tiếp.")
            console.print(f"    -> Phản hồi: {success_attempt_result[2]}")
            verdict = True
        else:
            console.print("[bold red][-] ĐÁNH GIÁ: KHÔNG ĐẠT (FAIL)![/bold red]")
            console.print(f"    -> Thiết bị vẫn trả về 200 OK tại lượt thứ {success_at} sau {fail_count} lần sai.")
    elif 0 < success_at <= fail_count:
        # Mục đích: Thử đúng trước ngưỡng -> Kỳ vọng ĐĂNG NHẬP THÀNH CÔNG (Reset bộ đếm)
        console.print("  [MỤC TIÊU KIỂM ĐỊNH]: RESET BỘ ĐẾM KHI NHẬP ĐÚNG TRƯỚC NGƯỠNG")
        if success_attempt_result and "200 OK" in success_attempt_result[2]:
            console.print("[bold green][+] ĐÁNH GIÁ: ĐẠT (PASS)![/bold green]")
            console.print(f"    -> Mật khẩu đúng tại lượt thứ {success_at} được chấp nhận thành công (200 OK). Bộ đếm đã được reset.")
            verdict = True
        else:
            console.print("[bold red][-] ĐÁNH GIÁ: KHÔNG ĐẠT (FAIL)![/bold red]")
            console.print(f"    -> Mật khẩu đúng tại lượt thứ {success_at} bị từ chối dù chưa vượt ngưỡng.")
    else:
        # Chỉ gửi sai để đo kiểm tường lửa
        console.print("  [MỤC TIÊU KIỂM ĐỊNH]: ĐO LƯỜNG TƯỜNG LỬA CHỐNG TẤN CÔNG VÉT CẠN LIÊN TỤC")
        console.print(f"    -> Đã gửi {fail_count} lần sai liên tiếp.")
        verdict = True
    console.print("=" * 80)

    filters = [
        ("Toàn bộ lưu lượng phiên RTSP kiểm thử", f"tcp.port == {port} && (rtsp || tls)"),
        ("Các gói tin xác thực sai (401)", f"tcp.port == {port} && rtsp.status == 401"),
        ("Gói tin xác thực thành công (200 OK)", f"tcp.port == {port} && rtsp.status == 200"),
        ("Gói tin bị Tường lửa Reset (RST flag)", f"tcp.port == {port} && tcp.flags.reset == 1")
    ]
    display_wireshark_panel(
        console,
        GLOBAL_PCAP_FILE,
        filters,
        is_tls=use_tls,
        sort_tip=f"Click tiêu đề cột No. hoặc CSeq trong Wireshark để kiểm tra chuỗi xác thực tại cổng {port}.",
        title=f"BẰNG CHỨNG GÓI TIN RTSP AUDIT (CỔNG {port})"
    )
    return verdict


def parse_arguments():
    parser = argparse.ArgumentParser(description="Bộ đo kiểm vét cạn luồng Video RTSP/RTSPS (QCVN 11 Clause 2.1.5)")
    parser.add_argument("port_pos", nargs="?", type=int, default=None, help="Cổng kiểm thử (vị trí tương thích ngược)")
    parser.add_argument("--port", type=int, default=None, help="Cổng RTSP (322, 554)")
    parser.add_argument("--mode", choices=["custom", "1", "2", "3", "reset", "lockout", "all"], default="custom", help="Chế độ: custom, reset, lockout, all")
    parser.add_argument("--fail-count", type=int, default=10, help="Số lần gửi sai liên tiếp (Mặc định: 10)")
    parser.add_argument("--success-at", type=int, default=11, help="Lượt chèn thử mật khẩu đúng (Mặc định: 11; 0=Không thử đúng)")
    parser.add_argument("--rate", type=float, default=4.0, help="Tốc độ gửi kết nối mới/giây (Mặc định: 4.0 conn/s)")
    return parser.parse_args()


def main():
    global GLOBAL_PCAP_FILE
    args = parse_arguments()

    target_port = args.port or args.port_pos
    port, use_tls = detect_rtsp_port(target_port)

    bpf_filter = f"tcp port {port}"
    pcap_proc, GLOBAL_PCAP_FILE = start_pcap_capture(
        DUT_IP,
        bpf_filter,
        prefix=f"rtsp_lockout_audit_{port}"
    )
    if GLOBAL_PCAP_FILE:
        print(f"[*] Đang tự động bắt gói tin PCAP vào: {GLOBAL_PCAP_FILE}\n")

    try:
        # Nếu chỉ định rõ mode preset
        if args.mode in ("1", "reset"):
            run_custom_sequence(port, use_tls, fail_count=4, success_at=5, rate_cps=args.rate)
        elif args.mode in ("2", "lockout"):
            run_custom_sequence(port, use_tls, fail_count=10, success_at=11, rate_cps=args.rate)
        elif args.mode in ("3", "all"):
            console.print("\n[bold cyan]>>> GIAI ĐOẠN 1: KIỂM CHỨNG RESET BỘ ĐẾM TRƯỚC NGƯỠNG <<<[/bold cyan]")
            pass1 = run_custom_sequence(port, use_tls, fail_count=4, success_at=5, rate_cps=args.rate)
            if pass1:
                console.print("\n[*] Chờ 3 giây trước khi chuyển sang giai đoạn kiểm thử kích hoạt khóa...")
                time.sleep(3)
                console.print("\n[bold cyan]>>> GIAI ĐOẠN 2: KIỂM CHỨNG KÍCH HOẠT KHÓA SAU 10 LẦN SAI <<<[/bold cyan]")
                run_custom_sequence(port, use_tls, fail_count=10, success_at=11, rate_cps=args.rate)
        else:
            # Mode custom theo đúng tham số CLI
            run_custom_sequence(
                port=port,
                use_tls=use_tls,
                fail_count=args.fail_count,
                success_at=args.success_at,
                rate_cps=args.rate
            )
    finally:
        stop_pcap_capture(pcap_proc)


if __name__ == '__main__':
    main()
