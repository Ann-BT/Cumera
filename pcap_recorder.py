#!/usr/bin/env python3
"""
Wireshark & PCAP Evidence Engine for QCVN 11 Security Audit Suite
Provides standardized background tshark capture, SSL keylogging, and rich Wireshark display filter panels.
"""

import os
import re
import sys
import time
import subprocess
from datetime import datetime
from typing import Tuple, Optional, List
from rich.console import Console
from rich.panel import Panel

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CAPTURES_DIR = os.path.join(BASE_DIR, "captures")
SSLKEYLOG_PATH = os.path.join(CAPTURES_DIR, "sslkeys.log")

os.makedirs(CAPTURES_DIR, exist_ok=True)
os.environ["SSLKEYLOGFILE"] = SSLKEYLOG_PATH

def _find_tshark_bin() -> str:
    """Resolve tshark executable across Linux, macOS, and Windows."""
    import shutil
    found = shutil.which("tshark")
    if found:
        return found
    if sys.platform == "win32":
        for p in [
            r"C:\Program Files\Wireshark\tshark.exe",
            r"C:\Program Files (x86)\Wireshark\tshark.exe",
        ]:
            if os.path.exists(p):
                return p
    return "tshark"


def detect_outbound_interface(dest_ip: str) -> str:
    """Detects the network interface used to route packets to dest_ip."""
    if sys.platform == "win32":
        try:
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((dest_ip, 80))
            local_ip = s.getsockname()[0]
            s.close()
            tshark_bin = _find_tshark_bin()
            extra_kw = {}
            if sys.platform == "win32":
                extra_kw["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
                si = subprocess.STARTUPINFO()
                si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                si.wShowWindow = 0
                extra_kw["startupinfo"] = si
            res = subprocess.run([tshark_bin, "-D"], capture_output=True, text=True, timeout=3, **extra_kw)
            if res.returncode == 0:
                for line in res.stdout.splitlines():
                    if local_ip in line:
                        return line.split(".", 1)[0].strip()
        except Exception:
            pass
        return "Ethernet"
    try:
        cmd = f"ip route get {dest_ip}"
        out = subprocess.check_output(cmd, shell=True, text=True)
        m = re.search(r'dev\s+([a-zA-Z0-9_\-]+)', out)
        if m:
            return m.group(1)
    except Exception:
        pass
    return "enp3s0"

def get_sslkeylog_path() -> str:
    """Returns absolute path to sslkeys.log."""
    return SSLKEYLOG_PATH

def enable_ssl_keylog(ssl_ctx) -> None:
    """Attaches the keylog_filename to an SSLContext instance for TLS decryption."""
    try:
        ssl_ctx.keylog_filename = SSLKEYLOG_PATH
    except Exception:
        pass

def start_pcap_capture(
    dest_ip: str,
    bpf_filter: str,
    prefix: str = "audit",
    net_iface: Optional[str] = None
) -> Tuple[Optional[subprocess.Popen], str]:
    """
    Spawns background packet capture on the appropriate interface.
    Uses tcpdump with -Z root and -U (unbuffered) for 100% reliable capture,
    with fallback to tshark.
    Returns (capture_process, pcap_file_path).
    """
    import shlex
    iface = net_iface or detect_outbound_interface(dest_ip)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    pcap_file = os.path.join(CAPTURES_DIR, f"{prefix}_{timestamp}.pcap")

    # Ưu tiên dùng tcpdump với -Z root để không bị rớt quyền và -U để ghi tức thì
    # Chuẩn hóa khoảng trắng quanh dấu ngoặc đơn để tcpdump hiểu đúng cú pháp BPF
    normalized_filter = bpf_filter.replace("(", " ( ").replace(")", " ) ")
    filter_tokens = [tok for tok in normalized_filter.split() if tok]
    
    use_sudo = hasattr(os, "geteuid") and os.geteuid() != 0
    sudo_prefix = ["sudo", "-n"] if use_sudo else []
    if sys.platform != "win32":
        # --immediate-mode: xả gói tin ngay khỏi TPACKET_V3 ring buffer, tránh mất gói tạo PCAP 0 pkt
        tcpdump_cmd = sudo_prefix + ["tcpdump", "-i", iface, "-s", "0", "-w", pcap_file, "-Z", "root", "-U", "--immediate-mode"] + filter_tokens
        try:
            proc = subprocess.Popen(tcpdump_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            proc.pcap_file = pcap_file
            proc.use_sudo = use_sudo
            time.sleep(0.8)  # Chờ tcpdump khởi tạo socket và sẵn sàng lắng nghe trên interface
            if proc.poll() is None:
                return proc, pcap_file
        except Exception:
            pass

    tshark_bin = _find_tshark_bin()
    tshark_cmd = sudo_prefix + [tshark_bin, "-i", iface, "-f", bpf_filter, "-w", pcap_file, "-q"]
    try:
        popen_kw = {"stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL}
        if sys.platform == "win32":
            popen_kw["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
            si = subprocess.STARTUPINFO()
            si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            si.wShowWindow = 0
            popen_kw["startupinfo"] = si
        proc = subprocess.Popen(tshark_cmd, **popen_kw)
        proc.pcap_file = pcap_file
        proc.use_sudo = use_sudo
        time.sleep(0.8)
        return proc, pcap_file
    except Exception:
        return None, pcap_file

def stop_pcap_capture(proc: Optional[subprocess.Popen], wait_sec: float = 1.5) -> None:
    """Gracefully flushes buffers and terminates background capture process via SIGINT."""
    if not proc:
        return
    import signal
    time.sleep(0.5)  # Đảm bảo toàn bộ gói tin cuối đã vào buffer
    use_sudo = getattr(proc, 'use_sudo', False)
    
    if use_sudo:
        try:
            # Gửi SIGINT tới tiến trình con của sudo (tcpdump) để xả buffer PCAP chuẩn xác
            res_c = subprocess.run(["pgrep", "-P", str(proc.pid)], capture_output=True, text=True)
            for cpid in res_c.stdout.strip().split():
                if cpid.isdigit():
                    subprocess.run(["sudo", "-n", "kill", "-2", cpid], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["sudo", "-n", "kill", "-2", str(proc.pid)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            proc.wait(timeout=wait_sec)
        except Exception:
            try:
                subprocess.run(["sudo", "-n", "kill", "-9", str(proc.pid)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                proc.wait(timeout=0.5)
            except Exception:
                pass
    else:
        try:
            if sys.platform == "win32":
                proc.terminate()
            else:
                proc.send_signal(signal.SIGINT)
            proc.wait(timeout=wait_sec)
        except Exception:
            try:
                proc.terminate()
                proc.wait(timeout=0.5)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass

    pcap_file = getattr(proc, 'pcap_file', None)
    if pcap_file and os.path.exists(pcap_file):
        try:
            if use_sudo:
                subprocess.run(["sudo", "-n", "chmod", "666", pcap_file], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                os.chmod(pcap_file, 0o666)
        except Exception:
            pass

def display_wireshark_panel(
    console: Console,
    pcap_file: str,
    filters: List[Tuple[str, str]],
    is_tls: bool = False,
    sort_tip: Optional[str] = None,
    title: str = "BẰNG CHỨNG GÓI TIN WIRESHARK & FILE PCAP ĐỐI SOÁT"
) -> None:
    """Minimal output: print only the PCAP file path if present (no redundant Wireshark manual)."""
    if pcap_file and os.path.exists(pcap_file) and os.path.getsize(pcap_file) > 0:
        console.print(f"[dim]↳ PCAP: {pcap_file}[/dim]")
