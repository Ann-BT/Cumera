#!/usr/bin/env python3
"""
Universal IP Camera Security Audit Suite
Agnostic test suite for IP cameras across vendors (QCVN 11:2026/BCA & International Standards)
Author: Merlin / Antigravity
"""

import sys
import os
import subprocess
import json

TOOLKIT_DIR = os.path.dirname(os.path.abspath(__file__))

# Tự động nhận diện môi trường ảo (Linux / Windows, thư mục hiện tại hoặc thư mục cha)
candidate_venvs = [
    os.path.join(TOOLKIT_DIR, ".venv", "bin", "python"),
    os.path.join(TOOLKIT_DIR, ".venv", "Scripts", "python.exe"),
    os.path.join(os.path.dirname(TOOLKIT_DIR), ".venv", "bin", "python"),
    os.path.join(os.path.dirname(TOOLKIT_DIR), ".venv", "Scripts", "python.exe"),
]
VENV_PYTHON = sys.executable
for venv_path in candidate_venvs:
    if os.path.isfile(venv_path):
        VENV_PYTHON = venv_path
        if os.path.abspath(sys.executable) != os.path.abspath(venv_path):
            if sys.argv and sys.argv[0] != '-c':
                os.execv(venv_path, [venv_path] + sys.argv)
        break

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.prompt import Prompt
    console = Console()
except ImportError:
    console = None

CONFIG_PATH = os.path.join(TOOLKIT_DIR, "config.json")

def load_config():
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def run_script(script_name, *args):
    script_path = os.path.join(TOOLKIT_DIR, script_name)
    has_euid = hasattr(os, "geteuid")
    needs_root = script_name in ["tool3_sftp_receiver.py", "tool4_smtp_receiver.py", "tool_all_receivers.py", "cam_auto_link.py", "tool17_commech_auditor.py", "tool20_telemetry_geoip_auditor.py", "tool21_authmech_auditor.py"] and has_euid and os.geteuid() != 0
    py_bin = VENV_PYTHON if os.path.isfile(VENV_PYTHON) else sys.executable
    if needs_root:
        cmd = ["sudo", py_bin, script_path] + list(args)
    else:
        cmd = [py_bin, script_path] + list(args)

    if console:
        console.print(f"\n[bold yellow][*] Đang khởi chạy: {' '.join(cmd)}[/bold yellow]\n")
    else:
        print(f"\n[*] Đang khởi chạy: {' '.join(cmd)}\n")
    try:
        subprocess.run(cmd)
    except KeyboardInterrupt:
        print("\n[*] Đã dừng công cụ.")
    except Exception as e:
        print(f"[-] Lỗi thực thi: {e}")

def change_target_camera():
    if console:
        console.print("\n[bold cyan]=== PHƯƠNG THỨC NHẬN DIỆN & ĐỔI CAMERA MỤC TIÊU ===[/bold cyan]")
        console.print("  [bold yellow]1[/bold yellow]. [bold green]Tu dong nhan dien & Gan dai mang IP (Auto-Link)[/bold green] (Khuyen nghi: Cam cap la nhan)")
        console.print("  [bold yellow]2[/bold yellow]. [bold cyan]Quet ONVIF WS-Discovery[/bold cyan] (Do quet camera tren mang hien tai)")
        console.print("  [bold yellow]3[/bold yellow]. [bold white]Nhap thu cong IP & Mat khau[/bold white]")
        console.print("  [bold yellow]0[/bold yellow]. [dim]Quay lai[/dim]")
        method = Prompt.ask("Chọn phương thức", choices=["1", "2", "3", "0"], default="1").strip()
    else:
        print("\n=== PHƯƠNG THỨC NHẬN DIỆN & ĐỔI CAMERA MỤC TIÊU ===")
        print("  [1] Tu dong nhan dien & Gan dai mang IP (Auto-Link) (Cam cap la nhan)")
        print("  [2] Quet ONVIF WS-Discovery (Mang hien tai)")
        print("  [3] Nhap thu cong IP & Mat khau")
        print("  [0] Quay lai")
        method = input("Chọn phương thức [1]: ").strip() or "1"

    if method == "0":
        return
    elif method == "1":
        run_script("cam_auto_link.py", "--once")
        return
    elif method == "2":
        run_script("camera_manager.py")

    cfg = load_config()
    curr_ip = cfg.get("target_camera", {}).get("ip", "")
    ip = input(f"\nNhập IP camera mục tiêu muốn kiểm tra [Mặc định: {curr_ip}]: ").strip()
    if not ip:
        ip = curr_ip
    user = input(f"Nhập tài khoản (admin): ").strip() or "admin"
    pwd = input(f"Nhập mật khẩu: ").strip() or cfg.get("target_camera", {}).get("password", "")
    
    from camera_manager import set_target_camera
    set_target_camera(ip, username=user, password=pwd)
    if console:
        console.print(f"[bold green][OK] Da chuyen muc tieu sang camera: {ip}[/bold green]")
    else:
        print(f"[OK] Da chuyen muc tieu sang camera: {ip}")

def menu_cryptography_and_auth():
    """Đo kiểm mã hóa đường truyền & Giá trị xác thực (Yêu cầu 2.1.3)."""
    while True:
        cfg = load_config()
        ip = cfg.get("target_camera", {}).get("ip", "Chưa đặt")
        
        if console:
            console.clear()
            import receiver_daemon as rd
            rd.ensure_daemon_running()
            active_ips = rd.get_active_host_ips()
            primary_ip = active_ips[0][0] if active_ips else "127.0.0.1"
            console.print(Panel(
                f"[bold cyan]PHẦN 1: ĐO KIỂM MÃ HÓA ĐƯỜNG TRUYỀN & GIÁ TRỊ XÁC THỰC (YÊU CẦU 2.1.3)[/bold cyan]\n"
                f"[dim]Tiêu chuẩn QCVN 11:2026/BCA & SOGIS ACM | Thiết bị: [bold white]{ip}[/bold white][/dim]\n"
                f"[bold green][OK] Máy chủ thu nhận chạy ngầm sẵn sàng trên IP: {primary_ip}[/bold green] (SFTP 22, FTP 21, Mail 25/465/587, Alarm 8088/8443)",
                border_style="cyan"
            ))
            t = Table(show_header=True, header_style="bold magenta", expand=True)
            t.add_column("Mã", style="bold yellow", justify="center", no_wrap=True)
            t.add_column("Nội dung bài đo kiểm", style="bold white", ratio=2)
            t.add_column("Phương pháp & Chi tiết kỹ thuật", style="dim", ratio=3)

            rtsps_p = cfg.get("service_ports", {}).get("rtsps_tls", 322)
            t.add_row("1", "Phân tích mã hóa đường truyền (TLS & SOGIS ACM)", f"Quét phiên bản TLS 1.0 - 1.3, phân loại SOGIS R/L/NR/F & trích xuất X.509 cert trên cổng 443 / {rtsps_p}")
            t.add_row("2", "Phân tích mã hóa giá trị xác thực (HTTP / RTSP / RTSPS)", f"Bóc tách WWW-Authenticate: Digest SHA-256 vs Basic Auth trên cổng rõ 554 & TLS {rtsps_p}")
            t.add_row("3", "Bóc tách kết nối Client (SFTP / SMTP / Webhook)", "Server thu nhận bóc tách SSH KEXINIT, TLS Client Hello & headers cảnh báo")
            t.add_row("4", "Đo kiểm ma trận mật mã SNMP-V3", "Thử nghiệm 8 tổ hợp authPriv/authNoPriv, chống hạ cấp & chặn DES/MD5")
            t.add_row("5", "BÁO CÁO TỔNG HỢP TOÀN BỘ (Master Audit)", "Tự động chạy toàn bộ các bài test, xuất báo cáo Markdown & JSON")
            t.add_row("6", "Đo kiểm chuyên sâu bắt tay xác thực RTSP / RTSPS (Tool 12)", "Gửi request, bóc tách Digest SHA-256 & gói tin SDP 200 OK trên luồng video")
            t.add_row("7", "Kiểm tra kết nối & Bắt gói tin Wireshark (Tool 14)", "Bắt gói tin pcap, trích xuất dissection Wireshark & luồng RTP video thực tế")
            t.add_row("8", "Đo kiểm 4 Cơ chế xác thực AuthMech (Tool 21)", "Bắt gói tin PCAP & Liệt kê toàn bộ Ciphersuite/KEX Nmap Enum đối soát")
            t.add_row("9", "Đo kiểm 11 Cơ chế truyền thông ComMech (Tool 17)", "Đối soát 11 cơ chế truyền thông, thử tấn công hạ cấp TLS/SSH & xuất bằng chứng PCAP")
            t.add_row("0", "[bold red]Quay lại Menu chính[/bold red]", "")
            console.print(t)
            choice = Prompt.ask("\nNhập lựa chọn", default="1").strip()
        else:
            print("\n" + "=" * 80)
            print("  PHẦN 1: ĐO KIỂM MÃ HÓA ĐƯỜNG TRUYỀN & GIÁ TRỊ XÁC THỰC (YÊU CẦU 2.1.3)")
            print("=" * 80)
            print("  [1] Phân tích mã hóa đường truyền (TLS & SOGIS ACM)")
            print("  [2] Phân tích mã hóa giá trị xác thực (HTTP / RTSP / RTSPS: Basic vs Digest)")
            print("  [3] Bóc tách kết nối Client (SFTP / SMTP / Webhook)")
            print("  [4] Đo kiểm ma trận mật mã SNMP-V3")
            print("  [5] BÁO CÁO TỔNG HỢP TOÀN BỘ (Master Audit)")
            print("  [6] Đo kiểm chuyên sâu bắt tay xác thực RTSP / RTSPS (Tool 12)")
            print("  [7] Kiểm tra kết nối & Bắt gói tin Wireshark (Tool 14)")
            print("  [8] Đo kiểm 4 Cơ chế xác thực AuthMech (Tool 21)")
            print("  [9] Đo kiểm 11 Cơ chế truyền thông ComMech (Tool 17)")
            print("  [0] Quay lại Menu chính")
            choice = input("Nhập lựa chọn: ").strip()

        if choice == "0":
            break
        elif choice == "1":
            rtsps_p = cfg.get("service_ports", {}).get("rtsps_tls", 322)
            port = input(f"Nhập cổng TLS cần quét [443 HTTPS / {rtsps_p} RTSPS] (mặc định 443): ").strip() or "443"
            run_script("tool1_tls_scanner.py", ip, port)
            input("\nBấm Enter để tiếp tục...")
        elif choice == "2":
            run_script("tool2_unencrypted_protocols.py", ip)
            input("\nBấm Enter để tiếp tục...")
        elif choice == "3":
            import receiver_daemon as rd
            rd.ensure_daemon_running()
            active_ips = rd.get_active_host_ips()
            primary_ip = active_ips[0][0] if active_ips else "127.0.0.1"

            if console:
                console.print(f"\n[bold cyan]=== BÓC TÁCH KẾT NỐI CLIENT TỪ CAMERA (MÁY CHỦ CHẠY SẴN TRÊN IP {primary_ip}) ===[/bold cyan]")
                console.print("  [dim]Máy chủ ngầm đã mở sẵn các cổng: SFTP (22), FTP (21), Email (25, 465, 587), Alarm (8088, 8443)[/dim]")
                console.print("  [bold yellow]1[/bold yellow]. [bold green]Bóc tách SFTP / SSH (Cổng 22)[/bold green] (libssh2, KEXINIT, Ciphers, Wireshark sort)")
                console.print("  [bold yellow]2[/bold yellow]. [bold yellow]Bóc tách Plain FTP (Cổng 21)[/bold yellow] (Mật khẩu rõ, Passive Mode, Wireshark sort)")
                console.print("  [bold yellow]3[/bold yellow]. [bold cyan]Bóc tách SMTP Email (Cổng 25, 465, 587)[/bold cyan] (SMTPS, STARTTLS, AUTH LOGIN, Wireshark sort)")
                console.print("  [bold yellow]4[/bold yellow]. [bold magenta]Bóc tách Alarm Webhook (Cổng 8088 & 8443)[/bold magenta] (HTTP/HTTPS, Authorization, Wireshark sort)")
                console.print("  [bold yellow]5[/bold yellow]. [bold white]Xem toàn bộ lịch sử các gói tin Test vừa thu nhận[/bold white]")
                console.print("  [bold yellow]6[/bold yellow]. [dim]Mở máy chủ tương tác dòng lệnh trực tiếp (tool_all_receivers.py)[/dim]")
                console.print("  [bold yellow]0[/bold yellow]. [dim]Quay lại[/dim]")
                sub_choice = Prompt.ask("Chọn dịch vụ phân tích", choices=["1", "2", "3", "4", "5", "6", "0"], default="1").strip()
            else:
                print(f"\n=== BÓC TÁCH KẾT NỐI CLIENT TỪ CAMERA (IP {primary_ip}) ===")
                print("  [1] Bóc tách SFTP / SSH (Cổng 22)")
                print("  [2] Bóc tách Plain FTP (Cổng 21)")
                print("  [3] Bóc tách SMTP Email (Cổng 25, 465, 587)")
                print("  [4] Bóc tách Alarm Webhook (Cổng 8088 & 8443)")
                print("  [5] Xem toàn bộ lịch sử gói tin vừa thu nhận")
                print("  [6] Mở máy chủ tương tác trực tiếp")
                print("  [0] Quay lại")
                sub_choice = input("Chọn dịch vụ phân tích [1]: ").strip() or "1"

            if sub_choice == "1":
                rd.wait_and_analyze_service("sftp")
            elif sub_choice == "2":
                rd.wait_and_analyze_service("ftp")
            elif sub_choice == "3":
                rd.wait_and_analyze_service("smtp")
            elif sub_choice == "4":
                rd.wait_and_analyze_service("alarm")
            elif sub_choice == "5":
                if os.path.exists(rd.EVENTS_FILE):
                    try:
                        with open(rd.EVENTS_FILE, "r", encoding="utf-8") as ef:
                            evts = json.load(ef)
                        if not evts:
                            console.print("[yellow][!] Chưa có gói tin nào được ghi nhận. Hãy bấm [Test] trên camera trước.[/yellow]")
                        else:
                            t_ev = Table(title="LỊCH SỬ CÁC GÓI TIN TEST CAMERA ĐÃ THU NHẬN", expand=True)
                            t_ev.add_column("STT", width=5, justify="center")
                            t_ev.add_column("Dịch vụ", style="bold cyan", width=12)
                            t_ev.add_column("Thời gian", style="bold white", width=20)
                            t_ev.add_column("Địa chỉ Camera", style="yellow", width=22)
                            t_ev.add_column("Đánh giá QCVN 11", justify="center")
                            for idx, e in enumerate(evts, 1):
                                eva_badge = "[bold green][PASS][/bold green]" if e.get("data", {}).get("evaluation") == "PASS" else "[bold red][FAIL][/bold red]"
                                t_ev.add_row(str(idx), e.get("service", "").upper(), e.get("timestamp", ""), e.get("remote_addr", ""), eva_badge)
                            console.print(t_ev)
                            pick = Prompt.ask("\nNhập STT gói tin muốn xem phân tích chi tiết & Wireshark sort (Enter để bỏ qua)", default="").strip()
                            if pick.isdigit() and 1 <= int(pick) <= len(evts):
                                rd.analyze_and_display_event(evts[int(pick) - 1])
                    except Exception as e:
                        console.print(f"[-] Lỗi đọc sự kiện: {e}")
            elif sub_choice == "6":
                run_script("tool_all_receivers.py")

            if sub_choice != "0":
                input("\nBấm Enter để tiếp tục...")
        elif choice == "4":
            run_script("tool5_snmpv3_auditor.py", ip)
            input("\nBấm Enter để tiếp tục...")
        elif choice == "5":
            run_script("tool8_master_audit.py", ip)
            input("\nBấm Enter để tiếp tục...")
        elif choice == "6":
            rtsps_p = cfg.get("service_ports", {}).get("rtsps_tls", 322)
            rtsp_p = input(f"Nhập cổng RTSP/RTSPS cần đo kiểm [554 / {rtsps_p}] (Enter để tự động nhận diện): ").strip()
            if rtsp_p:
                run_script("tool12_rtsp_auth_auditor.py", rtsp_p)
            else:
                run_script("tool12_rtsp_auth_auditor.py")
            input("\nBấm Enter để tiếp tục...")
        elif choice == "7":
            run_script("tool14_rtsp_wireshark_verifier.py")
            input("\nBấm Enter để tiếp tục...")
        elif choice == "8":
            if console:
                console.print(f"\n[bold cyan]=== ĐO KIỂM 4 CƠ CHẾ XÁC THỰC AUTHMECH ===[/bold cyan]")
                console.print("  [bold yellow]1[/bold yellow]. [bold green]Chạy toàn bộ 4 AuthMech & bắt gói tin PCAP[/bold green]")
                console.print("  [bold yellow]2[/bold yellow]. [bold cyan]Bóc tách TOÀN BỘ Ciphersuite & KEX (Nmap Enum)[/bold cyan]")
                console.print("  [bold yellow]3[/bold yellow]. [bold white]Đo kiểm chỉ định 1 AuthMech (1, 2, 3 hoặc 4)[/bold white]")
                console.print("  [bold yellow]0[/bold yellow]. [dim]Quay lại[/dim]")
                sub8 = Prompt.ask("Chọn chế độ", choices=["1", "2", "3", "0"], default="1").strip()
            else:
                print("\n=== ĐO KIỂM 4 CƠ CHẾ XÁC THỰC AUTHMECH ===")
                print("  [1] Chạy toàn bộ 4 AuthMech & bắt gói tin PCAP")
                print("  [2] Bóc tách TOÀN BỘ Ciphersuite & KEX (Nmap Enum)")
                print("  [3] Đo kiểm chỉ định 1 AuthMech (1, 2, 3 hoặc 4)")
                print("  [0] Quay lại")
                sub8 = input("Chọn chế độ [1]: ").strip() or "1"

            if sub8 == "1":
                run_script("tool21_authmech_auditor.py")
            elif sub8 == "2":
                run_script("tool21_authmech_auditor.py", "--enum", "all")
            elif sub8 == "3":
                sub_id = input("Nhập ID cần kiểm (1, 2, 3, 4): ").strip() or "1"
                run_script("tool21_authmech_auditor.py", "--id", sub_id)
            input("\nBấm Enter để tiếp tục...")
        elif choice == "9":
            run_script("tool17_commech_auditor.py")
            input("\nBấm Enter để tiếp tục...")

def menu_bruteforce_defense():
    """Yêu cầu 2.1.5: Phòng vệ thử nghiệm vét cạn xác thực."""
    while True:
        cfg = load_config()
        ip = cfg.get("target_camera", {}).get("ip", "Chưa đặt")
        rtsps_p = cfg.get("service_ports", {}).get("rtsps_tls", 322)
        
        if console:
            console.clear()
            console.print(Panel(
                f"[bold cyan]PHẦN 2: PHÒNG VỆ THỬ NGHIỆM VÉT CẠN XÁC THỰC (YÊU CẦU 2.1.5)[/bold cyan]\n"
                f"[dim]Tiêu chuẩn QCVN 11:2026/BCA & ETSI EN 303 645 | Thiết bị: {ip}[/dim]",
                border_style="cyan"
            ))
            t = Table(show_header=True, header_style="bold magenta", expand=True)
            t.add_column("Mã", style="bold yellow", justify="center", no_wrap=True)
            t.add_column("Nội dung bài đo kiểm", style="bold white", ratio=2)
            t.add_column("Phương pháp & Chi tiết kỹ thuật", style="dim", ratio=3)

            t.add_row("1", "Hồ sơ độ trễ & Giới hạn tần suất (Rate Limiting)", "Đo lường thời gian phản hồi liên tiếp, kiểm tra cơ chế làm chậm")
            t.add_row("2", "Kiểm chứng Khóa luồng RTSP / RTSPS & Reset bộ đếm", f"Thử nghiệm gửi sai liên tiếp trên cổng 554 hoặc {rtsps_p} (TLS), kiểm tra khóa & reset")
            t.add_row("3", "Kiểm chứng Khóa dịch vụ ONVIF & Reset bộ đếm", "Gửi các gói tin WS-Security sai, kiểm tra hành vi ngắt kết nối")
            t.add_row("4", "Kiểm chứng Khóa dịch vụ SSH & Reset bộ đếm (Cổng 22)", "10 lần sai trong 30s -> Khóa 5 phút, firewall rate limit & reset bộ đếm")
            t.add_row("5", "Kiểm chứng Khóa giao diện Web & Reset bộ đếm (Cổng 443)", "6 lần sai trong 30s -> Khóa 5 phút, firewall rate limit & reset bộ đếm")
            t.add_row("0", "[bold red]Quay lại Menu chính[/bold red]", "")
            console.print(t)
            choice = Prompt.ask("\nNhập lựa chọn", default="1").strip()
        else:
            print("\n" + "=" * 80)
            print("  PHẦN 2: PHÒNG VỆ VÉT CẠN XÁC THỰC (YÊU CẦU 2.1.5)")
            print("=" * 80)
            print("  [1] Hồ sơ độ trễ & Giới hạn tần suất (Rate Limiting)")
            print("  [2] Kiểm chứng Khóa luồng RTSP / RTSPS & Reset bộ đếm")
            print("  [3] Kiểm chứng Khóa dịch vụ ONVIF & Reset bộ đếm")
            print("  [4] Kiểm chứng Khóa dịch vụ SSH & Reset bộ đếm (Cổng 22)")
            print("  [5] Kiểm chứng Khóa giao diện Web & Reset bộ đếm (Cổng 443)")
            print("  [0] Quay lại Menu chính")
            choice = input("Nhập lựa chọn: ").strip()

        if choice == "0":
            break
        elif choice == "1":
            run_script("tool9_bruteforce_checker.py")
            input("\nBấm Enter để tiếp tục...")
        elif choice == "2":
            p_lock = input(f"Nhập cổng RTSP/RTSPS cần đo kiểm [554 / {rtsps_p}] (Enter để tự động nhận diện): ").strip()
            if p_lock:
                run_script("tool10_rtsp_lockout.py", p_lock)
            else:
                run_script("tool10_rtsp_lockout.py")
            input("\nBấm Enter để tiếp tục...")
        elif choice == "3":
            run_script("tool11_onvif_lockout.py")
            input("\nBấm Enter để tiếp tục...")
        elif choice == "4":
            run_script("tool15_ssh_lockout.py")
            input("\nBấm Enter để tiếp tục...")
        elif choice == "5":
            run_script("tool16_web_lockout.py")
            input("\nBấm Enter để tiếp tục...")

def menu_security_parameters():
    """Đo kiểm an toàn bề mặt hệ thống, Path Traversal, Command Injection & Access Control."""
    cfg = load_config()
    ip = cfg.get("target_camera", {}).get("ip", "192.168.101.208")
    run_script("tool13_security_params_auditor.py")
    input("\nBấm Enter để tiếp tục...")

def menu_input_validation():
    """Đo kiểm Xác thực đầu vào & Quét API (Yêu cầu 3.10.1.3 - QCVN 11:2026/BCA)."""
    while True:
        if console:
            console.print("\n[bold cyan]=== PHÂN HỆ ĐO KIỂM XÁC THỰC ĐẦU VÀO & API FUZZER (3.10.1.3) ===[/bold cyan]")
            console.print("  [1] Quét toàn bộ bề mặt API Camera (Full API Surface Scan)")
            console.print("  [2] Stateful Fuzzing luồng Media RTSP/RTSPS (Handshake -> Malformed Control -> Integrity)")
            console.print("  [3] Fuzzer giao thức đặc thù phi HTTP (Raw Binary Socket Stream)")
            console.print("  [4] Đo kiểm CSRF & Giả mạo Token cấu hình (Tool 19)")
            console.print("  [5] Đo kiểm Xác thực Đầu vào Form Đăng nhập (SQLi & XSS - Tool 22)")
            console.print("  [6] Chạy trọn bộ Kiểm thử Xác thực Đầu vào (Quét API + Fuzz Luồng + CSRF + Login Audit)")
            console.print("  [0] Quay lại Menu chính")
            sub = Prompt.ask("\nChọn chức năng", choices=["1", "2", "3", "4", "5", "6", "0"], default="5")
        else:
            print("\n=== PHAN HE DO KIEM XAC THUC DAU VAO (3.10.1.3) ===")
            print("  [1] Quet toan bo be mat API")
            print("  [2] Fuzzing luong RTSP/RTSPS (Handshake -> Malformed Control)")
            print("  [3] Fuzzer giao thuc phi HTTP")
            print("  [4] Do kiem CSRF & Gia mao Token cau hinh (Tool 19)")
            print("  [5] Do kiem Xac thuc Dau vao Form Dang nhap (SQLi & XSS - Tool 22)")
            print("  [6] Chay tron bo 3.10.1.3")
            print("  [0] Quay lai")
            sub = input("Chon: ").strip()

        if sub == "1":
            run_script("tool18_api_input_validation.py", "--mode", "scan")
            input("\nBấm Enter để tiếp tục...")
        elif sub == "2":
            run_script("tool18_api_input_validation.py", "--mode", "rtsp")
            input("\nBấm Enter để tiếp tục...")
        elif sub == "3":
            run_script("tool18_api_input_validation.py", "--mode", "custom")
            input("\nBấm Enter để tiếp tục...")
        elif sub == "4":
            run_script("tool19_csrf_token_auditor.py")
            input("\nBấm Enter để tiếp tục...")
        elif sub == "5":
            run_script("tool22_login_input_validation.py")
            input("\nBấm Enter để tiếp tục...")
        elif sub == "6":
            run_script("tool18_api_input_validation.py", "--mode", "all")
            run_script("tool19_csrf_token_auditor.py")
            run_script("tool22_login_input_validation.py")
            input("\nBấm Enter để tiếp tục...")
        else:
            break

def menu_telemetry_geoip():
    """Đo kiểm Giám sát truyền tin quốc tế, Định vị GeoIP & Telemetry (Điều 2.11.4 & 2.11.5 - QCVN 11:2026/BCA)."""
    while True:
        if console:
            console.print("\n[bold cyan]=== PHÂN HỆ GIÁM SÁT TRUYỀN TIN QUỐC TẾ & TELEMETRY (3.11.4 & 3.11.5) ===[/bold cyan]")
            console.print("  [1] Giám sát trực tiếp lưu lượng mạng (Live Capture 20s + GeoIP + Thống kê luồng)")
            console.print("  [2] Giám sát chuyên sâu thời lượng dài (Live Capture 60s)")
            console.print("  [3] Giám sát thụ động không kích thích (Passive Sniff 30s)")
            console.print("  [4] Phân tích tệp PCAP lưu trữ sẵn (Offline PCAP Analysis)")
            console.print("  [5] Mở file PCAP gần nhất bằng Wireshark kèm bộ lọc 3.11")
            console.print("  [0] Quay lại Menu chính")
            sub = Prompt.ask("\nChọn chức năng", choices=["1", "2", "3", "4", "5", "0"], default="1")
        else:
            print("\n=== PHAN HE GIAM SAT TRUYEN TIN QUOC TE & TELEMETRY (3.11.4 & 3.11.5) ===")
            print("  [1] Giam sat truc tiep luu luong mang (20 giay)")
            print("  [2] Giam sat chuyen sau thoi luong dai (60 giay)")
            print("  [3] Giam sat thu dong khong kich thich (30 giay)")
            print("  [4] Phan tich tep PCAP luu tru san")
            print("  [5] Mo Wireshark voi bo loc 3.11")
            print("  [0] Quay lai")
            sub = input("Chon: ").strip()

        if sub == "1":
            run_script("tool20_telemetry_geoip_auditor.py", "--duration", "20")
            input("\nBấm Enter để tiếp tục...")
        elif sub == "2":
            run_script("tool20_telemetry_geoip_auditor.py", "--duration", "60")
            input("\nBấm Enter để tiếp tục...")
        elif sub == "3":
            run_script("tool20_telemetry_geoip_auditor.py", "--duration", "30", "--no-stim")
            input("\nBấm Enter để tiếp tục...")
        elif sub == "4":
            pcap_file = input("Nhập đường dẫn file PCAP (hoặc Enter để phân tích PCAP gần nhất): ").strip()
            if not pcap_file:
                pcap_file = os.path.join(TOOLKIT_DIR, "captures", "telemetry_geoip_audit_evidence.json")
                if os.path.exists(pcap_file):
                    try:
                        with open(pcap_file, "r") as f:
                            data = json.load(f)
                        pcap_file = data.get("metadata", {}).get("pcap_file", "")
                    except Exception:
                        pcap_file = ""
            if not pcap_file or not os.path.exists(pcap_file):
                pcap_file = os.path.join(TOOLKIT_DIR, "captures", "commech1_web_https_20261109_195116.pcap")
            run_script("tool20_telemetry_geoip_auditor.py", "--pcap", pcap_file)
            input("\nBấm Enter để tiếp tục...")
        elif sub == "5":
            pcap_evidence = os.path.join(TOOLKIT_DIR, "captures", "telemetry_geoip_audit_evidence.json")
            target_pcap = None
            if os.path.exists(pcap_evidence):
                try:
                    with open(pcap_evidence, "r") as f:
                        data = json.load(f)
                    target_pcap = data.get("metadata", {}).get("pcap_file")
                except Exception:
                    pass
            if not target_pcap or not os.path.exists(target_pcap):
                target_pcap = os.path.join(TOOLKIT_DIR, "captures", "commech1_web_https_20261109_195116.pcap")
            if target_pcap and os.path.exists(target_pcap):
                try:
                    subprocess.Popen(["wireshark", target_pcap], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    print(f"[OK] Đã mở Wireshark: {target_pcap}")
                except Exception as e:
                    print(f"[-] Lỗi mở Wireshark: {e}")
            input("\nBấm Enter để tiếp tục...")
        else:
            break

def main():
    if "--cli" not in sys.argv and "--menu" not in sys.argv and sys.stdin.isatty():
        try:
            from toolkit_app import ToolkitApp
            app = ToolkitApp()
            app.run()
            return
        except Exception as e:
            if console:
                console.print(f"[yellow][!] Chuyển sang chế độ Menu Console dự phòng: {e}[/yellow]\n")

    import receiver_daemon as rd
    rd.ensure_daemon_running()

    while True:
        active_ips = rd.get_active_host_ips()
        primary_ip = active_ips[0][0] if active_ips else "127.0.0.1"
        all_ips_str = ", ".join([h_ip for h_ip, _ in active_ips])

        cfg = load_config()
        t_cam = cfg.get("target_camera", {})
        ip = t_cam.get("ip", "Chưa đặt")
        model = t_cam.get("model", "Generic IP Camera")

        if console:
            console.clear()
            daemon_status = "[bold green][OK] MÁY CHỦ THU NHẬN CLIENT ĐANG CHẠY NGẦM TRÊN TOÀN BỘ CỔNG (SẴN SÀNG)[/bold green]" if rd.is_daemon_running() else "[bold yellow][!] Máy chủ thu nhận đang khởi động...[/bold yellow]"
            console.print(Panel(
                f"[bold cyan]CUMERA - BỘ CÔNG CỤ ĐO KIỂM AN TOÀN BẢO MẬT & MẬT MÃ CAMERA IP[/bold cyan]\n"
                f"[dim]Tiêu chuẩn QCVN 11:2026/BCA & Quốc tế | Thiết bị mục tiêu: [bold white]{ip} ({model})[/bold white][/dim]\n"
                f"{daemon_status}\n"
                f"[dim]↳ IP Máy tính điền trên Web Camera: [bold yellow]{primary_ip}[/bold yellow] ({all_ips_str}) | Cổng: SFTP(22), FTP(21), Mail(25/465/587), Alarm(8088/8443)[/dim]",
                border_style="bright_blue"
            ))

            table = Table(show_header=True, header_style="bold magenta", expand=True)
            table.add_column("Mục", style="bold yellow", justify="center", no_wrap=True)
            table.add_column("Hạng mục đo kiểm (QCVN 11:2026/BCA)", style="bold white", ratio=2)
            table.add_column("Mô tả chức năng & Kịch bản kỹ thuật", style="cyan", ratio=3)

            table.add_row("[bold green]L[/bold green]", "Nhan dien & Doi dai mang (Auto-Link)", "Tu dong bat IP camera khi cam cap va cau hinh da subnet")
            table.add_row("[bold green]D[/bold green]", "Do quet Cong & Nhan dien Dich vu", "Quet toan dien TCP/UDP, nhan dien dich vu & phat hien cong bat thuong")
            table.add_row("[bold green]C[/bold green]", "Quet mang tim Camera (WS-Discovery)", "Phat thanh UDP 3702 tim kiem va doi camera muc tieu")
            table.add_row("[bold magenta]S[/bold magenta]", "Cau hinh thong so Camera & Mat khau", "Thay doi IP, tai khoan admin, mat khau ket noi")
            table.add_section()
            table.add_row("[bold yellow]2.1.3[/bold yellow]", "YEU CAU 2.1.3: MAT MA & XAC THUC", "Ma hoa TLS 1.0-1.3, SOGIS ACM, Chung thu so, Digest SHA-256 vs Basic Auth")
            table.add_row("[bold yellow]2.1.5[/bold yellow]", "YEU CAU 2.1.5: PHONG VE VET CAN", "Ho so do tre (Rate limiting), Nguong khoa tai khoan & Reset bo dem")
            table.add_row("[bold yellow]2.4[/bold yellow]", "DIEU 2.4: THAM SO AN TOAN NHAY CAM", "Be mat tan cong dieu khien tu xa, Input Validation, Bao ve khoa mat ma")
            table.add_row("[bold yellow]3.10[/bold yellow]", "YEU CAU 3.10.1.3: XAC THUC DAU VAO", "Quet API, Fuzzing luong RTSP, Phong ve CSRF & Gia mao Token")
            table.add_row("[bold yellow]3.11[/bold yellow]", "YEU CAU 3.11: GIAM SAT QUOC TE & TELEMETRY", "Dinh vi GeoIP, Dem goi tin theo IP, Kiem tra Telemetry & Luu tru VN")
            table.add_section()
            table.add_row("[bold cyan]W[/bold cyan]", "BAT GOI TIN & KIEM TRA XAC THUC (WIRESHARK)", "Test tung phuong thuc xac thuc, xuat pcap & dissection")
            table.add_row("[bold cyan]A[/bold cyan]", "CHAY MASTER AUDIT 1-CLICK", "Tu dong chay toan bo cac bai test va xuat bao cao Markdown + JSON")
            table.add_row("[bold red]0[/bold red]", "Thoat chuong trinh", "Ket thuc phien lam viec")
            console.print(table)
            choice = Prompt.ask("\nNhập lựa chọn", default="2.1.3").strip()
        else:
            print("\n" + "=" * 80)
            print("  BO CONG CU DO KIEM AN TOAN BAO MAT & MAT MA CAMERA IP")
            print(f"  Thiet bi muc tieu: {ip} ({model})")
            print("=" * 80)
            print("  [L]     Nhan dien & Doi dai mang (Auto-Link)")
            print("  [D]     Do quet Cong & Nhan dien Dich vu")
            print("  [C]     Quet mang tim Camera (WS-Discovery)")
            print("  [S]     Cau hinh thong so Camera & Mat khau")
            print("  [2.1.3] YEU CAU 2.1.3: Do kiem Mat ma & Gia tri xac thuc")
            print("  [2.1.5] YEU CAU 2.1.5: Phong ve vet can xac thuc")
            print("  [2.4]   DIEU 2.4: Do kiem tham so an toan nhay cam")
            print("  [3.10]  YEU CAU 3.10.1.3: Xac thuc dau vao & API Fuzzer")
            print("  [3.11]  YEU CAU 3.11: Giam sat Quoc te, GeoIP & Telemetry")
            print("  [W]     BAT GOI TIN & KIEM TRA XAC THUC (WIRESHARK)")
            print("  [A]     CHAY MASTER AUDIT 1-CLICK")
            print("  [0]     Thoat")
            print("-" * 80)
            choice = input("Nhập lựa chọn: ").strip()

        if choice == "0":
            print("\n[*] Tạm biệt!")
            break
        elif choice.upper() == "L":
            run_script("cam_auto_link.py", "--once")
            input("\nBấm Enter để tiếp tục...")
        elif choice.upper() == "D":
            run_script("service_discovery.py", ip, "--auto")
            input("\nBấm Enter để tiếp tục...")
        elif choice.upper() == "C":
            change_target_camera()
            input("\nBấm Enter để tiếp tục...")
        elif choice.upper() == "S":
            run_script("configure_target.py")
            input("\nBấm Enter để tiếp tục...")
        elif choice == "2.1.3":
            menu_cryptography_and_auth()
        elif choice == "2.1.5":
            menu_bruteforce_defense()
        elif choice in ["2.4", "2.4.0"]:
            menu_security_parameters()
        elif choice in ["3.10", "3.10.1.3", "fuzz"]:
            menu_input_validation()
        elif choice in ["3.11", "3.11.4", "3.11.5", "geoip", "telemetry"]:
            menu_telemetry_geoip()
        elif choice.upper() in ["W", "7"]:
            run_script("tool14_rtsp_wireshark_verifier.py")
            input("\nBấm Enter để tiếp tục...")
        elif choice.upper() == "A":
            run_script("tool8_master_audit.py", ip)
            input("\nBấm Enter để tiếp tục...")
        else:
            print("[!] Lựa chọn không hợp lệ.")

if __name__ == '__main__':
    main()
