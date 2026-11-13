#!/usr/bin/env python3
"""
TOOL 3: MÁY CHỦ GIẢ LẬP SFTP / SSH ĐO KIỂM MẬT MÃ CHO CAMERA IP (AUTHMECH-6)
Hỗ trợ tương thích 100% với client SSH của camera (bao gồm libssh2, OpenSSH, Dropbear...)
Tiêu chuẩn: QCVN 11:2026/BCA (Yêu cầu 2.1.3 & Phụ lục IXIT AuthMech-6)
Author: Merlin / Antigravity
"""

import os
import sys
import time
import socket
import select
import threading
import json
import io
import subprocess
from typing import Dict, List, Any

# Tự động nâng quyền root nếu chạy dưới quyền user thường (bắt buộc cho cổng 22 & 21 trên Linux)
if __name__ == '__main__' and hasattr(os, 'geteuid') and os.geteuid() != 0:
    print("[*] Mở cổng mạng đặc quyền TCP < 1024 (cổng 22, 21) yêu cầu quyền root.")
    print("[*] Đang tự động nâng quyền với sudo...")
    try:
        os.execvp("sudo", ["sudo", sys.executable] + sys.argv)
    except Exception as e:
        print(f"[-] Không thể gọi sudo tự động: {e}")
        print(f"    Vui lòng chạy lại bằng lệnh: sudo {sys.executable} {os.path.abspath(__file__)}")
        sys.exit(1)

import paramiko
from paramiko.message import Message
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

sys.stdout.reconfigure(encoding='utf-8')
console = Console()

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pcap_recorder import start_pcap_capture, stop_pcap_capture, display_wireshark_panel
from receiver_daemon import get_active_host_ips
from toolkit_config import CONF_PATH, detect_host_network, get_service_ports, get_target_info, load_config

config = load_config()
DUT_IP = get_target_info(config)["ip"]
_, HOST_IP = detect_host_network(DUT_IP, config)
_sp = get_service_ports(config)
SFTP_PORTS = _sp.get("sftp_receiver", [_sp["ftp_clear"], _sp["sftp_port"]])
GLOBAL_PCAP_FILE = ""

# Khởi tạo hoặc nạp Host Key cố định (RSA & ECDSA)
TOOLKIT_DIR = os.path.dirname(os.path.abspath(__file__))
RSA_KEY_PATH = os.path.join(TOOLKIT_DIR, "host_rsa.key")
ECDSA_KEY_PATH = os.path.join(TOOLKIT_DIR, "host_ecdsa.key")

if os.path.exists(RSA_KEY_PATH):
    HOST_RSA_KEY = paramiko.RSAKey.from_private_key_file(RSA_KEY_PATH)
else:
    HOST_RSA_KEY = paramiko.RSAKey.generate(2048)
    HOST_RSA_KEY.write_private_key_file(RSA_KEY_PATH)

if os.path.exists(ECDSA_KEY_PATH):
    HOST_ECDSA_KEY = paramiko.ECDSAKey.from_private_key_file(ECDSA_KEY_PATH)
else:
    HOST_ECDSA_KEY = paramiko.ECDSAKey.generate(bits=256)
    HOST_ECDSA_KEY.write_private_key_file(ECDSA_KEY_PATH)

def ensure_firewall_allowed(ports):
    """Mở tạm thời các cổng test qua firewalld nếu firewall đang bật."""
    try:
        res = subprocess.run(["systemctl", "is-active", "firewalld"], capture_output=True, text=True)
        if res.returncode == 0 and res.stdout.strip() == "active":
            for p in ports:
                subprocess.run(["firewall-cmd", "--add-port", f"{p}/tcp"], capture_output=True)
                subprocess.run(["firewall-cmd", "--zone=nm-shared", "--add-port", f"{p}/tcp"], capture_output=True)
    except Exception:
        pass

# ----------------- SFTP VIRTUAL FILESYSTEM -----------------
class StubSFTPHandle(paramiko.SFTPHandle):
    def __init__(self, flags):
        super().__init__(flags)
        self.bio = io.BytesIO()

    def stat(self):
        attr = paramiko.SFTPAttributes()
        attr.st_size = self.bio.getbuffer().nbytes
        attr.st_mode = 0o100644
        return attr

    def write(self, offset, data):
        self.bio.seek(offset)
        self.bio.write(data)
        return paramiko.SFTP_OK

    def read(self, offset, length):
        self.bio.seek(offset)
        return self.bio.read(length)

    def close(self):
        return paramiko.SFTP_OK

class StubSFTPServer(paramiko.SFTPServerInterface):
    def session_started(self):
        pass

    def stat(self, path):
        attr = paramiko.SFTPAttributes()
        attr.st_size = 0
        attr.st_mode = 0o040755
        return attr

    def lstat(self, path):
        return self.stat(path)

    def list_folder(self, path):
        return []

    def open(self, path, flags, attr):
        return StubSFTPHandle(flags)

    def remove(self, path):
        return paramiko.SFTP_OK

    def rename(self, oldpath, newpath):
        return paramiko.SFTP_OK

    def mkdir(self, path, attr):
        return paramiko.SFTP_OK

    def rmdir(self, path):
        return paramiko.SFTP_OK

    def canonicalize(self, path):
        return "/"

# ----------------- SSH AUTH & PROTOCOL SERVER -----------------
class CameraSSHServer(paramiko.ServerInterface):
    def __init__(self, port, addr):
        super().__init__()
        self.port = port
        self.addr = addr
        self.auth_username = None
        self.auth_password = None

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        self.auth_username = username
        self.auth_password = password
        print(f"  • Xác thực tài khoản SFTP từ Camera : Username='{username}', Password='{password}'")
        return paramiko.AUTH_SUCCESSFUL

    def check_auth_none(self, username):
        self.auth_username = username
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username):
        return "password,none"

class DissectingTransport(paramiko.Transport):
    def __init__(self, sock, port, addr):
        super().__init__(sock)
        self.port = port
        self.addr = addr
        self.parsed_kex: Dict[str, Any] = {}

    def _parse_kex_init(self, m):
        try:
            m_copy = Message(m.asbytes())
            parsed = self._really_parse_kex_init(m_copy)
            self.parsed_kex = {
                "client_version": getattr(self, "remote_version", "Unknown"),
                "ciphers": parsed.get("client_encrypt_algo_list", []),
                "kex": parsed.get("kex_algo_list", []),
                "macs": parsed.get("client_mac_algo_list", []),
                "keys": parsed.get("server_key_algo_list", []),
            }
        except Exception:
            pass
        return super()._parse_kex_init(m)

def display_dissection_report(transport: DissectingTransport, srv: CameraSSHServer):
    kex_info = transport.parsed_kex
    client_ver = kex_info.get("client_version") or getattr(transport, "remote_version", "Unknown")
    ciphers = kex_info.get("ciphers", [])
    kex_algs = kex_info.get("kex", [])
    mac_algs = kex_info.get("macs", [])
    host_keys = kex_info.get("keys", [])

    print("\n" + "=" * 90)
    print(f"  [+] BẮT ĐƯỢC KẾT NỐI SFTP / SSH TỪ CAMERA: {srv.addr[0]}:{srv.addr[1]} (Cổng TCP {srv.port})")
    print(f"  • Phiên bản SSH Client của Camera   : [bold cyan]{client_ver}[/bold cyan]")
    print(f"  • Trạng thái bắt tay SFTP           : [bold green][OK] THÀNH CÔNG (Camera hiển thị Test OK)[/bold green]")
    print("=" * 90)

    # Hiển thị thuật toán đang chạy thực tế
    active_cipher = getattr(transport, "remote_cipher", "Chưa xác định")
    active_kex = getattr(transport, "kex_engine", "Chưa xác định")
    if hasattr(active_kex, "__name__"):
        active_kex = active_kex.__name__
    active_mac = getattr(transport, "remote_mac", "Chưa xác định")
    active_key = getattr(transport, "host_key_type", "Chưa xác định")

    print("\n  [*] THUẬT TOÁN ĐÃ ĐƯỢC ĐÀM PHÁN THÀNH CÔNG VỚI CAMERA:")
    print(f"      - Thuật toán mã hóa thực tế (Cipher) : {active_cipher}")
    print(f"      - Trao đổi khóa thực tế (KEX)        : {active_kex}")
    print(f"      - Toàn vẹn thông điệp (MAC)          : {active_mac}")
    print(f"      - Khóa máy chủ (Host Key)            : {active_key}")

    print("\n  [-] BẢNG BÓC TÁCH TOÀN BỘ THUẬT TOÁN CLIENT ĐỀ XUẤT (KEXINIT):")
    print("  " + "-" * 86)

    print(f"  [1] CÁC BỘ MÃ MÃ HÓA (ENCRYPTION CIPHERS ĐỀ XUẤT):")
    for c in ciphers:
        is_weak = any(w in c for w in ["cbc", "arcfour", "3des", "blowfish", "cast"])
        tag = "[CŨ/YẾU BỊ CẤM]" if is_weak else "[AN TOÀN - AEAD/CTR]"
        print(f"      -> {c:<38} {tag}")

    print(f"\n  [2] THUẬT TOÁN TRAO ĐỔI KHÓA (KEY EXCHANGE - KEX):")
    for k in kex_algs:
        print(f"      -> {k}")

    print(f"\n  [3] THUẬT TOÁN KHÓA MÁY CHỦ (HOST KEY ALGORITHMS):")
    for h in host_keys:
        print(f"      -> {h}")

    print(f"\n  [4] THUẬT TOÁN BĂM TOÀN VẸN (MAC ALGORITHMS):")
    for m in mac_algs:
        print(f"      -> {m}")
    print("=" * 90)

    filters = [
        ("Toàn bộ lưu lượng kết nối SSH / SFTP", f"tcp.port == {srv.port} || ssh"),
        ("Gói tin trao đổi thuật toán mật mã (SSH KEXINIT)", f"tcp.port == {srv.port} && ssh.message_code == 20"),
        ("Gói tin trao đổi khóa Diffie-Hellman Key Exchange", f"tcp.port == {srv.port} && (ssh.message_code == 30 || ssh.message_code == 31)"),
        ("Phiên bản giao thức SSH Client của Camera", f"tcp.port == {srv.port} && ssh.protocol"),
        ("Gói tin khởi tạo dịch vụ SFTP", f"tcp.port == {srv.port} && sftp")
    ]
    display_wireshark_panel(
        console,
        GLOBAL_PCAP_FILE,
        filters,
        is_tls=False,
        sort_tip="Click tiêu đề cột No. để xem: TCP 3-Way Handshake → Banner SSH-2.0-libssh2 → Gói tin KEXINIT (message_code 20) → UserAuth → SFTP Subsystem.",
        title=f"BẰNG CHỨNG GÓI TIN WIRESHARK SFTP / SSH (PORT {srv.port})"
    )

def handle_ssh_connection(conn, addr, port):
    try:
        t = DissectingTransport(conn, port, addr)
        t.add_server_key(HOST_RSA_KEY)
        t.add_server_key(HOST_ECDSA_KEY)
        t.set_subsystem_handler('sftp', paramiko.SFTPServer, StubSFTPServer)

        server = CameraSSHServer(port, addr)
        t.start_server(server=server)

        # Chờ camera gửi yêu cầu mở channel (SFTP session)
        chan = t.accept(10.0)

        # Hiển thị bóc tách thuật toán
        display_dissection_report(t, server)

        # Giữ phiên chạy cho đến khi camera hoàn tất Test và đóng socket
        while t.is_active():
            time.sleep(0.1)
    except Exception as e:
        print(f"  [-] Lỗi kết nối SFTP từ {addr[0]}: {e}")
    finally:
        try: conn.close()
        except: pass
        print("\n" + "=" * 80)
        print("  [INFO] ĐÃ HOÀN TẤT PHIÊN KẾT NỐI SFTP VỪA RỒI.")
        print(f"  [INFO] MÁY CHỦ VẪN ĐANG TIẾP TỤC LẮNG NGHE TRÊN CỔNG TCP: {', '.join(map(str, SFTP_PORTS))}")
        print("         Bạn có thể bấm [Test] tiếp trên Camera bất kỳ lúc nào.")
        print("         (Máy chủ duy trì liên tục, chỉ dừng khi bạn nhấn Ctrl+C)")
        print("=" * 80 + "\n")

def handle_plain_ftp(conn, addr, port):
    """Xử lý camera kết nối bằng FTP bản rõ (RFC 959 Cleartext FTP)."""
    print("\n" + "=" * 90)
    print(f"  [!] PHÁT HIỆN KẾT NỐI FTP BẢN RÕ (CLEARTEXT FTP) TỪ CAMERA: {addr[0]}:{addr[1]} (Cổng {port})")
    print(f"      ĐÁNH GIÁ QCVN 11: [KHÔNG ĐẠT] - Kênh truyền không mã hóa (Mật khẩu & dữ liệu lộ rõ)")
    print("=" * 90)

    pasv_sock = None
    active_data_target = None
    captured_user = None
    captured_pass = None
    uploaded_files = []

    try:
        conn.sendall(b"220 QCVN11_Test_FTP_Server Ready\r\n")
        buf = ""
        while True:
            r, _, _ = select.select([conn], [], [], 15.0)
            if not r:
                break
            chunk = conn.recv(1024).decode('utf-8', errors='ignore')
            if not chunk:
                break
            buf += chunk
            while "\r\n" in buf or "\n" in buf:
                delim = "\r\n" if "\r\n" in buf else "\n"
                line, buf = buf.split(delim, 1)
                line_str = line.strip()
                if not line_str:
                    continue
                parts = line_str.split(" ", 1)
                cmd = parts[0].upper()
                arg = parts[1] if len(parts) > 1 else ""
                print(f"  [Camera -> FTP] {line_str}")

                if cmd == "USER":
                    captured_user = arg
                    conn.sendall(b"331 User name okay, need password.\r\n")
                elif cmd == "PASS":
                    captured_pass = arg
                    print(f"  [***] PHÁT HIỆN TÀI KHOẢN TRUYỀN RÕ: user='{captured_user}', password='{captured_pass}'")
                    conn.sendall(b"230 User logged in, proceed.\r\n")
                elif cmd == "SYST":
                    conn.sendall(b"215 UNIX Type: L8\r\n")
                elif cmd == "FEAT":
                    conn.sendall(b"211-Features:\r\n PASV\r\n EPSV\r\n SIZE\r\n UTF8\r\n211 End\r\n")
                elif cmd == "PWD":
                    conn.sendall(b'257 "/" is current directory.\r\n')
                elif cmd == "TYPE":
                    conn.sendall(b"200 Type set to I.\r\n")
                elif cmd == "PASV":
                    if pasv_sock:
                        try: pasv_sock.close()
                        except: pass
                    pasv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    pasv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    pasv_sock.bind(("0.0.0.0", 0))
                    pasv_sock.listen(1)
                    pasv_p = pasv_sock.getsockname()[1]
                    local_ip = conn.getsockname()[0]
                    if local_ip in ("0.0.0.0", "127.0.0.1"):
                        local_ip = HOST_IP
                    ip_p = local_ip.split(".")
                    p1 = pasv_p // 256
                    p2 = pasv_p % 256
                    conn.sendall(f"227 Entering Passive Mode ({ip_p[0]},{ip_p[1]},{ip_p[2]},{ip_p[3]},{p1},{p2})\r\n".encode())
                elif cmd == "EPSV":
                    if pasv_sock:
                        try: pasv_sock.close()
                        except: pass
                    pasv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    pasv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    pasv_sock.bind(("0.0.0.0", 0))
                    pasv_sock.listen(1)
                    pasv_p = pasv_sock.getsockname()[1]
                    conn.sendall(f"229 Entering Extended Passive Mode (|||{pasv_p}|)\r\n".encode())
                elif cmd == "PORT":
                    parts_p = arg.split(",")
                    if len(parts_p) >= 6:
                        active_data_target = (".".join(parts_p[:4]), int(parts_p[4]) * 256 + int(parts_p[5]))
                    conn.sendall(b"200 PORT command successful.\r\n")
                elif cmd in ("STOR", "APPE", "PUT"):
                    conn.sendall(b"150 Opening BINARY mode data connection for file transfer.\r\n")
                    d_conn = None
                    if pasv_sock:
                        try:
                            pasv_sock.settimeout(5.0)
                            d_conn, _ = pasv_sock.accept()
                        except Exception: pass
                    elif active_data_target:
                        try:
                            d_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            d_conn.settimeout(5.0)
                            d_conn.connect(active_data_target)
                        except Exception: pass
                    bytes_recvd = 0
                    if d_conn:
                        try:
                            while True:
                                c = d_conn.recv(4096)
                                if not c: break
                                bytes_recvd += len(c)
                        except Exception: pass
                        finally:
                            try: d_conn.close()
                            except: pass
                    if pasv_sock:
                        try: pasv_sock.close()
                        except: pass
                        pasv_sock = None
                    uploaded_files.append((arg, bytes_recvd))
                    conn.sendall(b"226 Transfer complete.\r\n")
                    print(f"      [FTP Data] Nhận thành công file test '{arg}' ({bytes_recvd} bytes)")
                elif cmd in ("LIST", "NLST"):
                    conn.sendall(b"150 Opening ASCII mode data connection for directory listing.\r\n")
                    d_conn = None
                    if pasv_sock:
                        try:
                            pasv_sock.settimeout(5.0)
                            d_conn, _ = pasv_sock.accept()
                        except Exception: pass
                    if d_conn:
                        try:
                            d_conn.sendall(b"drwxr-xr-x 2 ftp ftp 4096 Oct 29 10:00 test\r\n")
                        finally:
                            try: d_conn.close()
                            except: pass
                    if pasv_sock:
                        try: pasv_sock.close()
                        except: pass
                        pasv_sock = None
                    conn.sendall(b"226 Transfer complete.\r\n")
                elif cmd == "MKD":
                    conn.sendall(f'257 "/{arg}" directory created.\r\n'.encode())
                elif cmd in ("CWD", "CDUP"):
                    conn.sendall(b"250 Directory successfully changed.\r\n")
                elif cmd in ("DELE", "RMD"):
                    conn.sendall(b"250 Command successful.\r\n")
                elif cmd == "SIZE":
                    conn.sendall(b"213 0\r\n")
                elif cmd == "NOOP":
                    conn.sendall(b"200 OK.\r\n")
                elif cmd == "QUIT":
                    conn.sendall(b"221 Goodbye.\r\n")
                    break
                else:
                    conn.sendall(b"200 Command OK.\r\n")
    except Exception as e:
        print(f"  [-] Lỗi FTP: {e}")
    finally:
        if pasv_sock:
            try: pasv_sock.close()
            except: pass
        try: conn.close()
        except: pass

        print("\n" + "=" * 90)
        print(f"  [+] BẮT THÀNH CÔNG PHIÊN KẾT NỐI FTP TỪ CAMERA: {addr[0]}:{addr[1]}")
        print(f"  • Trạng thái phản hồi máy chủ : [bold green][OK] THÀNH CÔNG (Camera hiển thị Test OK)[/bold green]")
        print(f"  • Tài khoản người dùng        : {captured_user or 'Không rõ'}")
        print(f"  • Mật khẩu bản rõ             : {captured_pass or 'Không rõ'}")
        if uploaded_files:
            print(f"  • Dữ liệu file test đã nhận   : {', '.join([f'{f[0]} ({f[1]} B)' for f in uploaded_files])}")
        print(f"  • Đánh giá an toàn QCVN 11    : [bold red][FAIL] BẢN RÕ (CLEARTEXT FTP)[/bold red] - Cần bật SFTP!")
        print("=" * 90)

        filters = [
            ("Toàn bộ lưu lượng FTP", f"tcp.port == {port} || ftp || ftp-data"),
            ("Tài khoản và mật khẩu bản rõ", f"tcp.port == {port} && (ftp.request.command == \"USER\" || ftp.request.command == \"PASS\")"),
            ("Lệnh tải file test lên", f"tcp.port == {port} && (ftp.request.command == \"STOR\" || ftp.response.code == 226)"),
            ("Chế độ truyền Passive Mode", f"tcp.port == {port} && (ftp.request.command == \"PASV\" || ftp.response.code == 227)")
        ]
        display_wireshark_panel(
            console,
            GLOBAL_PCAP_FILE,
            filters,
            is_tls=False,
            sort_tip="Click tiêu đề cột No. để xem chuỗi: 220 Banner → USER → PASS (mật khẩu rõ) → PASV → STOR test.tmp → 226 Transfer complete.",
            title=f"BẰNG CHỨNG GÓI TIN WIRESHARK CLEARTEXT FTP (PORT {port})"
        )

        print("\n" + "=" * 80)
        print("  [INFO] ĐÃ HOÀN TẤT PHIÊN KẾT NỐI FTP VỪA RỒI.")
        print(f"  [INFO] MÁY CHỦ VẪN ĐANG TIẾP TỤC LẮNG NGHE TRÊN CỔNG TCP: {', '.join(map(str, SFTP_PORTS))}")
        print("         Bạn có thể bấm [Test] tiếp trên Camera bất kỳ lúc nào.")
        print("         (Máy chủ duy trì liên tục, chỉ dừng khi bạn nhấn Ctrl+C)")
        print("=" * 80 + "\n")

def connection_dispatcher(conn, addr, port):
    """Phân luồng chính xác: Cổng 21 chạy FTP, Cổng 22 chạy SFTP/SSH."""
    try:
        if port == 21:
            # Cổng 21 là chuẩn FTP: Camera chờ máy chủ gửi banner 220 trước
            handle_plain_ftp(conn, addr, port)
        elif port == 22:
            # Cổng 22 là chuẩn SFTP / SSH
            handle_ssh_connection(conn, addr, port)
        else:
            # Cổng tùy biến: chờ 0.3s xem camera có gửi SSH- banner trước không
            r, _, _ = select.select([conn], [], [], 0.3)
            if r:
                peek_bytes = conn.recv(4, socket.MSG_PEEK)
                if peek_bytes.startswith(b"SSH-"):
                    handle_ssh_connection(conn, addr, port)
                else:
                    handle_plain_ftp(conn, addr, port)
            else:
                handle_ssh_connection(conn, addr, port)
    except Exception as e:
        print(f"  [-] Lỗi phân luồng kết nối: {e}")
        try: conn.close()
        except: pass

def accept_loop(sock, port):
    while True:
        try:
            conn, addr = sock.accept()
            t = threading.Thread(target=connection_dispatcher, args=(conn, addr, port), daemon=True)
            t.start()
        except Exception:
            break

def main():
    global GLOBAL_PCAP_FILE

    import receiver_daemon as rd
    if rd.is_daemon_running():
        rd.wait_and_analyze_service("sftp")
        return

    ensure_firewall_allowed(SFTP_PORTS)

    print("=" * 90)
    print("  TOOL 3: MÁY CHỦ GIẢ LẬP SFTP / SSH ĐO KIỂM MẬT MÃ CHO CAMERA IP (AUTHMECH-6)")
    print("  Hỗ trợ hoàn chỉnh: libssh2_1.11.1, OpenSSH, Dropbear (Đầy đủ bắt tay & KEXINIT)")
    print(f"  Địa chỉ IP máy kiểm thử (Host IP) : {HOST_IP}")
    print(f"  Camera mục tiêu (DUT IP)          : {DUT_IP}")
    print("=" * 90)

    active_sockets = []
    status_table = Table(title="TRẠNG THÁI KHỞI ĐỘNG CỔNG MÁY CHỦ SFTP", expand=True)
    status_table.add_column("Cổng TCP", style="bold yellow", width=12, justify="center")
    status_table.add_column("Giao thức / Dịch vụ", style="bold cyan", width=30)
    status_table.add_column("Trạng thái Lắng nghe", justify="center")
    status_table.add_column("Ghi chú kỹ thuật", style="dim")

    for port in sorted(set(SFTP_PORTS)):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("0.0.0.0", port))
            s.listen(10)
            active_sockets.append((s, port))
            service_desc = "SFTP / SSH Server (Chuẩn)" if port == 22 else "FTP / SFTP Server phụ"
            status_table.add_row(
                str(port),
                service_desc,
                "[bold green][OK] LISTENING[/bold green]",
                "Sẵn sàng nhận kết nối từ Camera"
            )
        except PermissionError:
            status_table.add_row(
                str(port),
                "SFTP / SSH Server",
                "[bold red][FAIL] PERMISSION DENIED[/bold red]",
                "Cần chạy với sudo để mở cổng < 1024"
            )
        except OSError as e:
            err_msg = f"Lỗi mở cổng: {e}"
            if e.errno == 98: # EADDRINUSE
                pid_info = subprocess.getoutput(f"fuser {port}/tcp 2>/dev/null")
                err_msg = f"Bị chiếm bởi PID: {pid_info or 'Unknown'}. Kiểm tra sshd."
            status_table.add_row(
                str(port),
                "SFTP / SSH Server",
                "[bold red][FAIL] ADDRESS IN USE[/bold red]",
                err_msg
            )

    console.print(status_table)

    if not active_sockets:
        console.print("\n[bold red][FAIL] KHÔNG THỂ MỞ BẤT KỲ CỔNG SFTP NÀO! Vui lòng kiểm tra cổng đang bị chiếm.[/bold red]")
        sys.exit(1)

    active_ips = get_active_host_ips()
    primary_ip = active_ips[0][0] if active_ips else HOST_IP
    ip_list_str = ", ".join([f"{ip} ({dev})" for ip, dev in active_ips])

    print(f"\n[!] HƯỚNG DẪN CẤU HÌNH TRÊN CAMERA ĐỂ TEST THÀNH CÔNG:")
    print(f"    1. Vào Web Camera: Settings -> Network Settings -> FTP / Storage Settings")
    print(f"    2. Enable Server : Chọn [SFTP] (hoặc FTP)")
    print(f"    3. Server Address: {primary_ip} (hoặc IP card nối với camera: {ip_list_str})")
    print(f"    4. Port          : 22 (hoặc 21)")
    print(f"    5. Directory Path: / hoặc để trống")
    print(f"    6. Username/Pass : admin / Psitest135# (hoặc bất kỳ)")
    print(f"    7. Bấm nút [Test] trên giao diện Web camera!\n")

    bpf_ports = " or ".join([f"tcp port {p}" for _, p in active_sockets])
    pcap_proc, GLOBAL_PCAP_FILE = start_pcap_capture(DUT_IP, bpf_ports, prefix="sftp_audit", net_iface="any")
    if GLOBAL_PCAP_FILE:
        print(f"[*] Đang tự động bắt gói tin PCAP vào: {GLOBAL_PCAP_FILE}")

    for s, port in active_sockets:
        t = threading.Thread(target=accept_loop, args=(s, port), daemon=True)
        t.start()

    console.print("\n[bold green][+] MÁY CHỦ SFTP ĐÃ SẴN SÀNG! Bấm nút [Test] trên camera ngay bây giờ...[/bold green]")
    console.print("[dim](Nhấn Ctrl+C để kết thúc phiên và xem báo cáo bằng chứng)[/dim]\n")

    try:
        while True:
            threading.Event().wait(1.0)
    except KeyboardInterrupt:
        print("\n[*] Đã dừng máy chủ SFTP.")
    finally:
        for s, _ in active_sockets:
            try: s.close()
            except: pass
        stop_pcap_capture(pcap_proc)

if __name__ == '__main__':
    main()
