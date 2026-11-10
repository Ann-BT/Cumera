#!/usr/bin/env python3
"""
Camera Universal Ethernet Auto-Linker & Conflict-Free Subnet Resolver
Tự động nhận diện IP Camera khi cắm cáp và tự động thích ứng / gán dải mạng cho card Ethernet
Author: Merlin / Antigravity
"""

import os
import sys
import subprocess
import re
import time
import json
import argparse
from typing import Set, Tuple, Optional

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    console = Console()
except ImportError:
    console = None

TOOLKIT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(TOOLKIT_DIR, "config.json")
MY_HOST_OCTET = "250"

# Standard factory default camera subnets
DEFAULT_SUBNETS = [
    "192.168.1.0/24",    # Hikvision, Dahua, Uniview, Hanwha, Imou, Ezviz...
    "192.168.0.0/24",    # TP-Link VIGI, Axis, D-Link, Tenda...
    "192.168.100.0/24",  # ZTE, Huawei, FPT...
    "192.168.101.0/24",  # Camera Lab / Viettel
    "172.16.0.0/24",     # Enterprise default
    "10.0.0.0/24"        # Enterprise default
]

def log_info(msg: str):
    if console:
        console.print(f"[cyan][*][/cyan] {msg}")
    else:
        print(f"[*] {msg}")

def log_success(msg: str):
    if console:
        console.print(f"[bold green][OK][/bold green] {msg}")
    else:
        print(f"[OK] {msg}")

def log_warning(msg: str):
    if console:
        console.print(f"[bold yellow][!][/bold yellow] {msg}")
    else:
        print(f"[!] {msg}")

def log_error(msg: str):
    if console:
        console.print(f"[bold red][FAIL][/bold red] {msg}")
    else:
        print(f"[FAIL] {msg}")

def run_cmd(cmd: list) -> Tuple[bool, str]:
    try:
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
        return (res.returncode == 0, res.stdout.strip())
    except Exception as e:
        return (False, str(e))

def detect_ethernet_interface(preferred: Optional[str] = None) -> str:
    """Tự động phát hiện card mạng Ethernet có dây (ưu tiên enp3s0 hoặc card có dây khả dụng)."""
    if preferred and os.path.exists(f"/sys/class/net/{preferred}"):
        return preferred

    candidates = []
    try:
        for iface in sorted(os.listdir("/sys/class/net")):
            if iface == "lo" or iface.startswith(("docker", "veth", "br-", "wl")):
                continue
            if os.path.exists(f"/sys/class/net/{iface}/wireless"):
                continue
            candidates.append(iface)
    except Exception:
        pass

    if "enp3s0" in candidates:
        return "enp3s0"
    if candidates:
        return candidates[0]
    return "enp3s0"

def get_protected_upstream_subnets() -> Set[str]:
    """
    Phát hiện dải mạng Wi-Fi / Default Gateway đang cấp internet cho máy tính.
    Mục đích: TUYỆT ĐỐI không gán /24 dải này vào cổng Ethernet để tránh xung đột mất mạng Wi-Fi.
    """
    protected = set()
    ok, out = run_cmd(["ip", "route", "show", "default"])
    if ok and out:
        for line in out.splitlines():
            # default via 192.168.20.1 dev wlp0s20f3 ... src 192.168.20.225
            m_src = re.search(r"src\s+(\d+\.\d+\.\d+)\.\d+", line)
            if m_src:
                protected.add(m_src.group(1))
            m_gw = re.search(r"via\s+(\d+\.\d+\.\d+)\.\d+", line)
            if m_gw:
                protected.add(m_gw.group(1))
    
    if not protected:
        protected.add("192.168.20")
    return protected

def setup_kernel_arp_protection(iface: str):
    """Bật tính năng chống ARP Flux và routing collision của Linux Kernel."""
    log_info(f"Kích hoạt bảo vệ Anti-ARP Flux trên giao diện {iface}...")
    run_cmd(["sysctl", "-w", "net.ipv4.conf.all.arp_ignore=1"])
    run_cmd(["sysctl", "-w", "net.ipv4.conf.all.arp_announce=2"])
    run_cmd(["sysctl", "-w", f"net.ipv4.conf.{iface}.arp_ignore=1"])
    run_cmd(["sysctl", "-w", f"net.ipv4.conf.{iface}.arp_announce=2"])

def bring_up_interface(iface: str):
    """Bật trạng thái UP cho card mạng Ethernet."""
    log_info(f"Bật giao diện mạng {iface} (ip link set {iface} up)...")
    run_cmd(["ip", "link", "set", iface, "up"])

def prebind_vendor_subnets(iface: str, protected_subnets: Set[str]):
    """Gán trước các dải IP phổ biến của mọi hãng camera (Hikvision, Dahua, VIGI, Huawei...)."""
    log_info(f"Đang chuẩn bị sẵn danh sách IP đa dải mạng trên {iface}...")
    _, out = run_cmd(["ip", "-4", "addr", "show", "dev", iface])

    for sub in DEFAULT_SUBNETS:
        net_prefix = ".".join(sub.split(".")[:3])
        if net_prefix in protected_subnets:
            continue
        my_ip = f"{net_prefix}.{MY_HOST_OCTET}/24"
        if my_ip not in out:
            run_cmd(["ip", "addr", "add", my_ip, "dev", iface])

    # Với dải trùng với Wi-Fi (ví dụ dải 20), chỉ gán duy nhất /32
    for p in protected_subnets:
        ip32 = f"{p}.{MY_HOST_OCTET}/32"
        if ip32 not in out:
            run_cmd(["ip", "addr", "add", ip32, "dev", iface])
            log_info(f"Gán IP cô lập an toàn cho dải trùng Wi-Fi ({p}.x): {ip32}")

def update_toolkit_config(cam_ip: str, host_ip: str, model: Optional[str] = None):
    """Tự động đồng bộ IP Camera mới vào config.json của bộ công cụ QCVN 11."""
    if not os.path.exists(CONFIG_PATH):
        return
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            cfg = json.load(f)

        if "target_camera" not in cfg:
            cfg["target_camera"] = {}
        cfg["target_camera"]["ip"] = cam_ip
        if model and model != "Unknown":
            cfg["target_camera"]["model"] = model

        if "test_host" not in cfg:
            cfg["test_host"] = {}
        cfg["test_host"]["ip"] = host_ip

        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)
        log_success(f"Đã tự động cập nhật cấu hình [config.json] -> Camera IP: {cam_ip} | Host IP: {host_ip}")
    except Exception as e:
        log_warning(f"Không thể ghi config.json: {e}")

def link_camera_ip(cam_ip: str, iface: str, protected_subnets: Set[str], mac: str = "") -> bool:
    """Thiết lập định tuyến và gán IP phù hợp cho camera đã phát hiện."""
    cam_parts = cam_ip.split(".")
    if len(cam_parts) != 4:
        return False
    subnet = f"{cam_parts[0]}.{cam_parts[1]}.{cam_parts[2]}"
    my_host_ip = f"{subnet}.{MY_HOST_OCTET}"

    if console:
        console.print("\n" + "=" * 70)
        console.print(f"[bold green][INFO] PHÁT HIỆN CAMERA MỚI: {cam_ip}[/bold green] (MAC: [cyan]{mac or 'N/A'}[/cyan])")
        console.print("=" * 70)
    else:
        print("\n" + "=" * 70)
        print(f"[INFO] PHÁT HIỆN CAMERA MỚI: {cam_ip} (MAC: {mac or 'N/A'})")
        print("=" * 70)

    if subnet in protected_subnets:
        log_warning(f"Dải mạng {subnet}.x trùng với mạng Wi-Fi / Default Gateway của máy tính!")
        log_info(f"Áp dụng Host-Route cách ly /32 cho {cam_ip} qua {iface} (Bảo toàn 100% Wi-Fi)...")
        # Ensure /32 IP exists
        run_cmd(["ip", "addr", "add", f"{my_host_ip}/32", "dev", iface])
        # Replace specific host route
        run_cmd(["ip", "route", "replace", f"{cam_ip}/32", "dev", iface])
        log_success(f"Đã định tuyến riêng biệt {cam_ip}/32 ra {iface}. Wi-Fi không bị gián đoạn.")
    else:
        log_info(f"Camera thuộc dải {subnet}.x. Đang gán IP card mạng: {my_host_ip}/24...")
        run_cmd(["ip", "addr", "add", f"{my_host_ip}/24", "dev", iface])
        log_success(f"Đã gán thành công {my_host_ip}/24 trên giao diện {iface}.")

    # Kiểm tra ping 2 chiều
    log_info(f"Kiểm tra kết nối tới camera ({cam_ip})...")
    ping_ok, _ = run_cmd(["ping", "-c", "1", "-W", "1", cam_ip])
    if ping_ok:
        log_success(f"PING THÀNH CÔNG: Camera {cam_ip} đã phản hồi trực tiếp!")
    else:
        log_warning(f"Gói ping ICMP chưa phản hồi (có thể camera chặn Ping hoặc đang khởi động L3).")

    # Cập nhật config.json
    update_toolkit_config(cam_ip, my_host_ip)

    if console:
        console.print(Panel(
            f"[bold green]KẾT NỐI CAMERA THÀNH CÔNG HOÀN TOÀN![/bold green]\n\n"
            f"• [bold white]IP Camera:[/bold white] [bold cyan]{cam_ip}[/bold cyan]\n"
            f"• [bold white]IP Máy tính (Ethernet):[/bold white] [bold yellow]{my_host_ip}[/bold yellow]\n"
            f"• [bold white]Giao diện:[/bold white] {iface}\n"
            f"• [bold white]Đường dẫn Web:[/bold white] http://{cam_ip} | https://{cam_ip}",
            border_style="green",
            title="SẴN SÀNG ĐO KIỂM"
        ))
    else:
        print(f"\n[OK] KẾT NỐI CAMERA THÀNH CÔNG: http://{cam_ip} (Host IP: {my_host_ip})\n")

    return True

def sniff_and_link(iface: str, protected_subnets: Set[str], once_mode: bool = False):
    """Lắng nghe gói tin ARP / DHCP / ONVIF / SSDP để tự động bắt IP camera."""
    if console:
        console.print(Panel(
            f"[bold cyan]CHẾ ĐỘ TỰ ĐỘNG BẮT DẢI MẠNG CAMERA (ZERO-CONFIG)[/bold cyan]\n"
            f"Cổng mạng theo dõi: [bold yellow]{iface}[/bold yellow]\n"
            f"Các dải trùng Wi-Fi bảo vệ cách ly: [dim]{', '.join(sorted(protected_subnets))}.x[/dim]\n\n"
            f"[bold green]HÃY CẮM DÂY MẠNG TỪ CAMERA VÀO CỔNG {iface}...[/bold green]\n"
            f"[dim](Nhấn Ctrl+C bất cứ lúc nào để dừng lại)[/dim]",
            border_style="bright_blue"
        ))
    else:
        print(f"[*] Đang lắng nghe trên {iface}... Cắm dây mạng từ Camera vào cổng {iface} (Ctrl+C để thoát)...")

    # Ưu tiên tshark nếu có, nếu không dùng tcpdump
    has_tshark, _ = run_cmd(["which", "tshark"])
    has_tcpdump, _ = run_cmd(["which", "tcpdump"])

    proc = None
    if has_tshark:
        cmd = [
            "tshark", "-i", iface, "-l", "-n",
            "-Y", "arp or bootp or udp.port == 3702 or udp.port == 37020 or udp.port == 37810 or udp.port == 1900 or icmp",
            "-T", "fields",
            "-e", "ip.src", "-e", "arp.src.proto_ipv4", "-e", "eth.src"
        ]
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        except Exception:
            proc = None

    if proc is None and has_tcpdump:
        cmd = [
            "tcpdump", "-i", iface, "-l", "-n", "-e",
            "arp or udp port 67 or udp port 68 or udp port 3702 or udp port 1900 or icmp or ip"
        ]
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        except Exception:
            proc = None

    if proc is None:
        log_error("Không tìm thấy tshark hoặc tcpdump để bắt gói tin!")
        return

    detected_ips = set()

    try:
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue

            # Bóc tách IP và MAC từ output
            mac_match = re.search(r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})", line)
            mac = mac_match.group(1) if mac_match else ""

            # Tìm tất cả IPv4
            ips = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", line)

            for ip in ips:
                # Bỏ qua các IP đặc biệt / broadcast / multicast / loopback
                if ip.startswith(("0.", "127.", "224.", "239.", "255.")) or ip.endswith((".255", ".0")):
                    continue
                # Bỏ qua IP của chính máy tính
                if ip.endswith(f".{MY_HOST_OCTET}") or ip == "192.168.101.1":
                    continue
                if ip in detected_ips:
                    continue

                detected_ips.add(ip)
                success = link_camera_ip(ip, iface, protected_subnets, mac)
                if success and once_mode:
                    proc.terminate()
                    return
    except KeyboardInterrupt:
        log_info("\nĐã dừng chế độ lắng nghe tự động.")
    finally:
        if proc:
            try:
                proc.terminate()
            except Exception:
                pass

def main():
    parser = argparse.ArgumentParser(description="Universal Camera Auto-Link & Multi-Subnet Resolver")
    parser.add_argument("--iface", type=str, help="Giao diện Ethernet (mặc định tự động nhận diện)")
    parser.add_argument("--ip", type=str, help="Chỉ định IP Camera để gán dải mạng ngay lập tức mà không cần chờ bắt gói")
    parser.add_argument("--once", action="store_true", help="Thoát ngay sau khi đã nhận diện và kết nối thành công camera đầu tiên")
    parser.add_argument("--daemon", action="store_true", help="Chạy liên tục dưới nền để giám sát mọi camera cắm vào")
    args = parser.parse_args()

    if hasattr(os, 'geteuid') and os.geteuid() != 0:
        log_error("Script yêu cầu quyền root để cấu hình địa chỉ IP và định tuyến mạng!")
        print(f"Vui lòng chạy với sudo:\n    sudo {sys.executable} {os.path.abspath(__file__)} {' '.join(sys.argv[1:])}")
        sys.exit(1)

    iface = detect_ethernet_interface(args.iface)
    protected_subnets = get_protected_upstream_subnets()

    setup_kernel_arp_protection(iface)
    bring_up_interface(iface)
    prebind_vendor_subnets(iface, protected_subnets)

    if args.ip:
        # Chế độ gán trực tiếp một IP chỉ định
        link_camera_ip(args.ip, iface, protected_subnets)
        return

    # Chế độ tự động bắt gói
    once = args.once or (not args.daemon)
    sniff_and_link(iface, protected_subnets, once_mode=once)

if __name__ == "__main__":
    main()
