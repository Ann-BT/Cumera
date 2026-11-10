#!/usr/bin/env python3
"""
ALL-IN-ONE CLIENT RECEIVER SUITE (QCVN 11:2026/BCA)
Chạy đồng thời toàn bộ các máy chủ thu nhận kết nối Client từ Camera:
  1. SFTP / SSH Server (Cổng TCP 22 & 21, hỗ trợ libssh2, OpenSSH, Dropbear)
  2. SMTP Email Server (Cổng TCP 25, 465, 587)
  3. Alarm Webhook Server (Cổng TCP 8088 HTTP & 8443 HTTPS ECDSA)
Author: Merlin / Antigravity
"""

import socket
import ssl
import sys
import struct
import select
import threading
import json
import os
import io
import time
import tempfile
import datetime
import subprocess
from typing import Dict, Any

# Nâng quyền root tự động trên Linux
if __name__ == '__main__' and hasattr(os, 'geteuid') and os.geteuid() != 0:
    print("[*] Mở đồng thời các cổng đặc quyền (21, 22, 25, 465, 587) yêu cầu quyền root.")
    print("[*] Đang tự động nâng quyền với sudo...")
    try:
        os.execvp("sudo", ["sudo", sys.executable] + sys.argv)
    except Exception as e:
        print(f"[-] Không thể gọi sudo tự động: {e}")
        print(f"    Vui lòng chạy lại bằng: sudo {sys.executable} {os.path.abspath(__file__)}")
        sys.exit(1)

import paramiko
from paramiko.message import Message
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec

sys.stdout.reconfigure(encoding='utf-8')
console = Console()

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pcap_recorder import start_pcap_capture, stop_pcap_capture, display_wireshark_panel, enable_ssl_keylog
from receiver_daemon import get_active_host_ips

CONF_PATH = os.path.join(os.path.dirname(__file__), "config.json")
with open(CONF_PATH, encoding="utf-8") as f:
    config = json.load(f)

DUT_IP = config.get("target_camera", {}).get("ip", "192.168.101.208")
HOST_IP = config.get("test_host", {}).get("ip", "192.168.101.250")
SFTP_PORTS = config.get("service_ports", {}).get("sftp_receiver", [21, 22])
SMTP_PORTS = config.get("service_ports", {}).get("smtp_receiver", [25, 465, 587])
PORT_HTTP = config.get("service_ports", {}).get("alarm_receiver_http", 8088)
PORT_HTTPS = config.get("service_ports", {}).get("alarm_receiver_https", 8443)

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

import ipaddress
from receiver_daemon import get_active_host_ips

# Tạo SSL Context cho HTTPS / SMTPS dùng chứng thư số RSA-2048 SHA-256 phổ quát
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, HOST_IP)])

san_entries = [
    x509.DNSName("localhost"),
    x509.DNSName("Camera-Audit-Host"),
    x509.DNSName("smtp.local"),
    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
]
try:
    active_ips = get_active_host_ips()
    for ip_str, _ in active_ips:
        try:
            san_entries.append(x509.IPAddress(ipaddress.ip_address(ip_str)))
        except Exception:
            pass
    for well_known_ip in [HOST_IP, "192.168.101.250", "192.168.0.250", "192.168.1.250"]:
        try:
            ipa = x509.IPAddress(ipaddress.ip_address(well_known_ip))
            if ipa not in san_entries:
                san_entries.append(ipa)
        except Exception:
            pass
except Exception:
    pass

cert = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(subject)
    .public_key(key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1))
    .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
    .sign(key, hashes.SHA256())
)
cert_file = tempfile.NamedTemporaryFile(delete=False, suffix=".crt")
cert_file.write(cert.public_bytes(serialization.Encoding.PEM))
cert_file.close()

key_file = tempfile.NamedTemporaryFile(delete=False, suffix=".key")
key_file.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
key_file.close()

ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
ssl_ctx.load_cert_chain(cert_file.name, key_file.name)
ssl_ctx.check_hostname = False
ssl_ctx.verify_mode = ssl.CERT_NONE
try:
    ssl_ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
except Exception:
    pass
try:
    ssl_ctx.set_ciphers('ALL:@SECLEVEL=0')
except Exception:
    pass
enable_ssl_keylog(ssl_ctx)

def ensure_firewall_allowed(ports):
    try:
        res = subprocess.run(["systemctl", "is-active", "firewalld"], capture_output=True, text=True)
        if res.returncode == 0 and res.stdout.strip() == "active":
            for p in ports:
                subprocess.run(["firewall-cmd", "--add-port", f"{p}/tcp"], capture_output=True)
                subprocess.run(["firewall-cmd", "--zone=nm-shared", "--add-port", f"{p}/tcp"], capture_output=True)
    except Exception:
        pass

# ----------------- 1. SFTP / SSH HANDLER -----------------
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
    def close(self): return paramiko.SFTP_OK

class StubSFTPServer(paramiko.SFTPServerInterface):
    def session_started(self): pass
    def stat(self, path):
        attr = paramiko.SFTPAttributes()
        attr.st_size = 0
        attr.st_mode = 0o040755
        return attr
    def lstat(self, path): return self.stat(path)
    def list_folder(self, path): return []
    def open(self, path, flags, attr): return StubSFTPHandle(flags)
    def remove(self, path): return paramiko.SFTP_OK
    def canonicalize(self, path): return "/"

class CameraSSHServer(paramiko.ServerInterface):
    def __init__(self, port, addr):
        super().__init__()
        self.port = port
        self.addr = addr
    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == 'session' else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
    def check_auth_password(self, u, p):
        print(f"  • [SFTP] Xác thực tài khoản: user='{u}', password='{p}'")
        return paramiko.AUTH_SUCCESSFUL
    def check_auth_none(self, u): return paramiko.AUTH_SUCCESSFUL
    def get_allowed_auths(self, u): return "password,none"

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

def handle_sftp_client(conn, addr, port):
    try:
        t = DissectingTransport(conn, port, addr)
        t.add_server_key(HOST_RSA_KEY)
        t.add_server_key(HOST_ECDSA_KEY)
        t.set_subsystem_handler('sftp', paramiko.SFTPServer, StubSFTPServer)
        server = CameraSSHServer(port, addr)
        t.start_server(server=server)
        chan = t.accept(10.0)

        c_ver = getattr(t, "remote_version", "Unknown")
        print("\n" + "=" * 90)
        print(f"  [+] [SFTP] BẮT ĐƯỢC KẾT NỐI SFTP TỪ CAMERA: {addr[0]}:{addr[1]} (Cổng {port})")
        print(f"  • Phiên bản SSH Client : {c_ver}")
        print(f"  • Trạng thái bắt tay   : [bold green][OK] THÀNH CÔNG (Camera hiển thị Test Thành Công)[/bold green]")
        print(f"  • Thuật toán Cipher    : {getattr(t, 'remote_cipher', 'N/A')}")
        print(f"  • Thuật toán KEX       : {getattr(t, 'kex_engine', 'N/A')}")
        print("=" * 90)

        while t.is_active():
            time.sleep(0.1)
    except Exception as e:
        print(f"  [-] Lỗi SFTP: {e}")
    finally:
        try: conn.close()
        except: pass
        print("\n" + "=" * 80)
        print("  [INFO] ĐÃ HOÀN TẤT PHIÊN KẾT NỐI SFTP.")
        print("  [INFO] MÁY CHỦ TIẾP TỤC DUY TRÌ LẮNG NGHE ĐỒNG THỜI TOÀN BỘ CỔNG (SFTP, SMTP, ALARM)...")
        print("         Bạn có thể bấm [Test] tiếp trên Camera bất kỳ lúc nào.")
        print("         (Máy chủ duy trì liên tục, chỉ dừng khi bạn nhấn Ctrl+C)")
        print("=" * 80 + "\n")

# ----------------- 1.1. PLAIN FTP HANDLER (RFC 959) -----------------
def handle_plain_ftp(conn, addr, port):
    """Xử lý camera kết nối bằng FTP bản rõ (RFC 959 Cleartext FTP)."""
    print("\n" + "=" * 90)
    print(f"  [!] [FTP] PHÁT HIỆN KẾT NỐI FTP BẢN RÕ (CLEARTEXT FTP) TỪ CAMERA: {addr[0]}:{addr[1]} (Cổng {port})")
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
            if not r: break
            chunk = conn.recv(1024).decode('utf-8', errors='ignore')
            if not chunk: break
            buf += chunk
            while "\r\n" in buf or "\n" in buf:
                delim = "\r\n" if "\r\n" in buf else "\n"
                line, buf = buf.split(delim, 1)
                line_str = line.strip()
                if not line_str: continue
                parts = line_str.split(" ", 1)
                cmd = parts[0].upper()
                arg = parts[1] if len(parts) > 1 else ""
                print(f"  [Camera -> FTP] {line_str}")

                if cmd == "USER":
                    captured_user = arg
                    conn.sendall(b"331 User name okay, need password.\r\n")
                elif cmd == "PASS":
                    captured_pass = arg
                    print(f"  [***] [FTP] PHÁT HIỆN TÀI KHOẢN TRUYỀN RÕ: user='{captured_user}', password='{captured_pass}'")
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
        print(f"  [+] [FTP] BẮT THÀNH CÔNG PHIÊN KẾT NỐI FTP TỪ CAMERA: {addr[0]}:{addr[1]}")
        print(f"  • Trạng thái phản hồi máy chủ : [bold green][OK] THÀNH CÔNG (Camera hiển thị Test OK)[/bold green]")
        print(f"  • Tài khoản người dùng        : {captured_user or 'Không rõ'}")
        print(f"  • Mật khẩu bản rõ             : {captured_pass or 'Không rõ'}")
        if uploaded_files:
            print(f"  • Dữ liệu file test đã nhận   : {', '.join([f'{f[0]} ({f[1]} B)' for f in uploaded_files])}")
        print(f"  • Đánh giá an toàn QCVN 11    : [bold red][FAIL] BẢN RÕ (CLEARTEXT FTP)[/bold red] - Cần bật SFTP!")
        print("=" * 90)
        print("\n" + "=" * 80)
        print("  [INFO] ĐÃ HOÀN TẤT PHIÊN KẾT NỐI FTP.")
        print("  [INFO] MÁY CHỦ TIẾP TỤC DUY TRÌ LẮNG NGHE ĐỒNG THỜI TOÀN BỘ CỔNG (SFTP, SMTP, ALARM)...")
        print("         Bạn có thể bấm [Test] tiếp trên Camera bất kỳ lúc nào.")
        print("         (Máy chủ duy trì liên tục, chỉ dừng khi bạn nhấn Ctrl+C)")
        print("=" * 80 + "\n")

def connection_dispatcher(conn, addr, port):
    """Phân luồng chính xác: Cổng 21 chạy FTP, Cổng 22 chạy SFTP/SSH."""
    try:
        if port == 21:
            handle_plain_ftp(conn, addr, port)
        elif port == 22:
            handle_sftp_client(conn, addr, port)
        else:
            r, _, _ = select.select([conn], [], [], 0.3)
            if r:
                peek_bytes = conn.recv(4, socket.MSG_PEEK)
                if peek_bytes.startswith(b"SSH-"):
                    handle_sftp_client(conn, addr, port)
                else:
                    handle_plain_ftp(conn, addr, port)
            else:
                handle_sftp_client(conn, addr, port)
    except Exception as e:
        print(f"  [-] Lỗi phân luồng: {e}")
        try: conn.close()
        except: pass

# ----------------- 2. SMTP HANDLER (RFC 5321, 3207, 4954) -----------------
import base64

def handle_smtp_dialogue(sock, addr, port, is_post_tls=False):
    buf = ""
    auth_step = None
    captured_user = None
    captured_pass = None
    sender = None
    rcpt = None
    email_subject = None
    active_tls = is_post_tls
    tls_cipher = None

    if isinstance(sock, ssl.SSLSocket):
        active_tls = True
        try:
            c = sock.cipher()
            tls_cipher = f"{c[0]} ({sock.version()})"
        except Exception:
            pass

    while True:
        try:
            has_pending = isinstance(sock, ssl.SSLSocket) and sock.pending() > 0
            if not has_pending:
                r, _, _ = select.select([sock], [], [], 15.0)
                if not r:
                    break
            chunk = sock.recv(2048)
            if not chunk:
                break
            buf += chunk.decode('utf-8', errors='ignore')
        except Exception:
            break

        while "\r\n" in buf or "\n" in buf:
            delim = "\r\n" if "\r\n" in buf else "\n"
            line, buf = buf.split(delim, 1)
            line_str = line.strip()
            if not line_str and not auth_step:
                continue
            print(f"  [Camera -> SMTP] {line_str}")

            if auth_step == "username":
                try:
                    captured_user = base64.b64decode(line_str).decode('utf-8', errors='ignore')
                except Exception:
                    captured_user = line_str
                auth_step = "password"
                sock.sendall(b"334 UGFzc3dvcmQ6\r\n")
                continue
            elif auth_step == "password":
                try:
                    captured_pass = base64.b64decode(line_str).decode('utf-8', errors='ignore')
                except Exception:
                    captured_pass = line_str
                auth_step = None
                print(f"  [***] [SMTP] XÁC THỰC THÀNH CÔNG: user='{captured_user}', password='{captured_pass}'")
                sock.sendall(b"235 2.7.0 Authentication successful\r\n")
                continue
            elif auth_step == "plain":
                try:
                    plain_dec = base64.b64decode(line_str).decode('utf-8', errors='ignore')
                    tokens = plain_dec.split('\x00')
                    captured_user = tokens[1] if len(tokens) > 1 else tokens[0]
                    captured_pass = tokens[2] if len(tokens) > 2 else ""
                    print(f"  [***] [SMTP] XÁC THỰC PLAIN: user='{captured_user}', password='{captured_pass}'")
                except Exception:
                    pass
                auth_step = None
                sock.sendall(b"235 2.7.0 Authentication successful\r\n")
                continue

            parts = line_str.split(" ", 1)
            cmd = parts[0].upper()
            arg = parts[1] if len(parts) > 1 else ""

            if cmd in ("EHLO", "HELO"):
                if active_tls:
                    caps = (
                        "250-QCVN11_Test_Mail_Server Hello\r\n"
                        "250-AUTH LOGIN PLAIN\r\n"
                        "250-AUTH=LOGIN PLAIN\r\n"
                        "250-SIZE 10485760\r\n"
                        "250-8BITMIME\r\n"
                        "250 OK\r\n"
                    )
                else:
                    caps = (
                        "250-QCVN11_Test_Mail_Server Hello\r\n"
                        "250-STARTTLS\r\n"
                        "250-AUTH LOGIN PLAIN\r\n"
                        "250-AUTH=LOGIN PLAIN\r\n"
                        "250-SIZE 10485760\r\n"
                        "250-8BITMIME\r\n"
                        "250 OK\r\n"
                    )
                sock.sendall(caps.encode())
            elif cmd == "STARTTLS":
                sock.sendall(b"220 2.0.0 Ready to start TLS\r\n")
                try:
                    tls_sock = ssl_ctx.wrap_socket(sock, server_side=True)
                    cipher_info = tls_sock.cipher()
                    print(f"  [+] [SMTP] BẮT TAY STARTTLS THÀNH CÔNG: Version {tls_sock.version()}, Cipher {cipher_info[0]}")
                    return handle_smtp_dialogue(tls_sock, addr, port, is_post_tls=True)
                except Exception as e:
                    print(f"  [-] Lỗi STARTTLS: {e}")
                    return None, None, None, None, None, False, None
            elif cmd == "AUTH":
                sub = arg.upper()
                if "LOGIN" in sub:
                    sub_parts = arg.split()
                    if len(sub_parts) > 1:
                        try:
                            captured_user = base64.b64decode(sub_parts[1]).decode('utf-8', errors='ignore')
                        except Exception:
                            captured_user = sub_parts[1]
                        auth_step = "password"
                        sock.sendall(b"334 UGFzc3dvcmQ6\r\n")
                    else:
                        auth_step = "username"
                        sock.sendall(b"334 VXNlcm5hbWU6\r\n")
                elif "PLAIN" in sub:
                    sub_parts = arg.split()
                    if len(sub_parts) > 1:
                        try:
                            plain_dec = base64.b64decode(sub_parts[1]).decode('utf-8', errors='ignore')
                            tokens = plain_dec.split('\x00')
                            captured_user = tokens[1] if len(tokens) > 1 else tokens[0]
                            captured_pass = tokens[2] if len(tokens) > 2 else ""
                            print(f"  [***] [SMTP] XÁC THỰC PLAIN: user='{captured_user}', password='{captured_pass}'")
                        except Exception:
                            pass
                        sock.sendall(b"235 2.7.0 Authentication successful\r\n")
                    else:
                        auth_step = "plain"
                        sock.sendall(b"334 \r\n")
                else:
                    sock.sendall(b"235 2.7.0 Authentication successful\r\n")
            elif cmd.startswith("MAIL"):
                sender = arg
                sock.sendall(b"250 2.1.0 Sender OK\r\n")
            elif cmd.startswith("RCPT"):
                rcpt = arg
                sock.sendall(b"250 2.1.5 Recipient OK\r\n")
            elif cmd == "DATA":
                sock.sendall(b"354 Start mail input; end with <CRLF>.<CRLF>\r\n")
                mail_body = ""
                data_start = time.time()
                while "\r\n.\r\n" not in buf and "\n.\n" not in buf:
                    if time.time() - data_start > 15.0:
                        break
                    try:
                        has_p = isinstance(sock, ssl.SSLSocket) and sock.pending() > 0
                        if not has_p:
                            r, _, _ = select.select([sock], [], [], 2.0)
                            if not r:
                                continue
                        more = sock.recv(4096).decode('utf-8', errors='ignore')
                        if not more:
                            break
                        buf += more
                    except Exception:
                        break
                delim_data = "\r\n.\r\n" if "\r\n.\r\n" in buf else "\n.\n"
                if delim_data in buf:
                    mail_body, buf = buf.split(delim_data, 1)
                for l in mail_body.splitlines():
                    if l.lower().startswith("subject:"):
                        email_subject = l[8:].strip()
                sock.sendall(b"250 2.0.0 OK: queued as test_email_001\r\n")
                print(f"  [+] [SMTP] ĐÃ NHẬN THÀNH CÔNG EMAIL TEST: Subject='{email_subject or 'Không tiêu đề'}'")
            elif cmd in ("RSET", "NOOP"):
                sock.sendall(b"250 2.0.0 OK\r\n")
            elif cmd == "QUIT":
                sock.sendall(b"221 2.0.0 Bye\r\n")
                break
            else:
                sock.sendall(b"250 OK\r\n")

    if isinstance(sock, ssl.SSLSocket):
        active_tls = True
        try:
            c = sock.cipher()
            tls_cipher = f"{c[0]} ({sock.version()})"
        except Exception:
            pass

    return captured_user, captured_pass, sender, rcpt, email_subject, active_tls, tls_cipher

def handle_smtp_client(conn, addr, port):
    conn.settimeout(20.0)
    print("\n" + "=" * 80)
    print(f"  [+] [SMTP] BẮT ĐƯỢC KẾT NỐI EMAIL TỪ CAMERA: {addr[0]}:{addr[1]} (Cổng {port})")
    print("=" * 80)
    sock_to_use = conn
    is_tls = False
    tls_cipher = "Không mã hóa (Plaintext)"

    # Tự động nhận diện Direct TLS (SMTPS) vs Plaintext / STARTTLS trên mọi cổng
    try:
        r, _, _ = select.select([conn], [], [], 0.6)
        if r:
            peek_data = conn.recv(5, socket.MSG_PEEK)
            if len(peek_data) >= 3 and peek_data[0] == 0x16 and peek_data[1] == 0x03:
                is_tls = True
    except Exception:
        pass

    try:
        if is_tls:
            try:
                wrapped = ssl_ctx.wrap_socket(conn, server_side=True)
                sock_to_use = wrapped
                c = wrapped.cipher()
                tls_cipher = f"{c[0]} ({wrapped.version()})"
                print(f"  • SMTPS Bắt tay TLS thành công : {tls_cipher}")
                sock_to_use.sendall(b"220 QCVN11_Test_Mail_Server ESMTP Ready (TLS Active)\r\n")
            except Exception as e:
                print(f"  [-] Lỗi bắt tay SMTPS: {e}")
                return
        else:
            sock_to_use.sendall(b"220 QCVN11_Test_Mail_Server ESMTP Ready\r\n")

        u, p, snd, rc, subj, is_tls_res, ciph_res = handle_smtp_dialogue(sock_to_use, addr, port, is_post_tls=is_tls)
        if is_tls_res:
            is_tls = True
            tls_cipher = ciph_res or tls_cipher

        print("\n" + "=" * 90)
        print(f"  [+] [SMTP] BẮT THÀNH CÔNG PHIÊN GỬI EMAIL TEST TỪ CAMERA: {addr[0]}:{addr[1]}")
        print(f"  • Trạng thái phản hồi máy chủ : [bold green][OK] THÀNH CÔNG (Camera hiển thị Test OK)[/bold green]")
        print(f"  • Kênh truyền mật mã          : [bold green]{tls_cipher}[/bold green]" if is_tls else "  • Kênh truyền mật mã          : [bold yellow]Bản rõ (Cleartext)[/bold yellow]")
        if u or p: print(f"  • Tài khoản xác thực          : user='{u}', pass='{p}'")
        if snd: print(f"  • Người gửi (Sender)          : {snd}")
        if rc: print(f"  • Người nhận (Recipient)       : {rc}")
        if subj: print(f"  • Tiêu đề thư (Subject)       : {subj}")
        print("=" * 90)
    except Exception as e:
        print(f"  [-] Lỗi SMTP: {e}")
    finally:
        try: sock_to_use.close()
        except: pass
        try: conn.close()
        except: pass
        print("\n" + "=" * 80)
        print("  [INFO] ĐÃ HOÀN TẤT PHIÊN KẾT NỐI SMTP.")
        print("  [INFO] MÁY CHỦ TIẾP TỤC DUY TRÌ LẮNG NGHE ĐỒNG THỜI TOÀN BỘ CỔNG (SFTP, SMTP, ALARM)...")
        print("         Bạn có thể bấm [Test] tiếp trên Camera bất kỳ lúc nào.")
        print("         (Máy chủ duy trì liên tục, chỉ dừng khi bạn nhấn Ctrl+C)")
        print("=" * 80 + "\n")

# ----------------- 3. ALARM HANDLER (HTTP & HTTPS) -----------------
def handle_alarm_client(conn, addr, is_ssl=False):
    # Tự động nhận diện HTTPS vs HTTP bằng MSG_PEEK
    try:
        r, _, _ = select.select([conn], [], [], 0.4)
        if r:
            peek = conn.recv(5, socket.MSG_PEEK)
            if len(peek) >= 3 and peek[0] == 0x16 and peek[1] == 0x03:
                is_ssl = True
            elif len(peek) >= 3 and peek[:3] in (b"GET", b"POS", b"OPT", b"HEA", b"PUT"):
                is_ssl = False
    except Exception:
        pass

    proto = "HTTPS" if is_ssl else "HTTP"
    print("\n" + "=" * 80)
    print(f"  [+] [ALARM] BẮT ĐƯỢC GÓI ALARM SERVER TỪ CAMERA: {addr[0]}:{addr[1]} ({proto})")
    print("=" * 80)
    sock = None
    try:
        sock = ssl_ctx.wrap_socket(conn, server_side=True) if is_ssl else conn
        if is_ssl:
            c_info = sock.cipher()
            print(f"  • Bắt tay TLS thành công: Version {sock.version()}, Cipher {c_info[0]}")

        buf = b""
        sock.settimeout(10.0)
        while b"\r\n\r\n" not in buf and b"\n\n" not in buf:
            chunk = sock.recv(2048)
            if not chunk: break
            buf += chunk

        if not buf: return

        delim = b"\r\n\r\n" if b"\r\n\r\n" in buf else b"\n\n"
        header_bytes, body_bytes = buf.split(delim, 1)
        header_text = header_bytes.decode('utf-8', errors='ignore')
        lines = header_text.splitlines()
        req_line = lines[0] if lines else "N/A"

        content_length = 0
        auth_header = None
        content_type = None

        print(f"  [-] TIÊU ĐỀ GÓI TIN {proto} GỬI TỪ CAMERA:")
        print(f"      | {req_line}")
        for l in lines[1:]:
            if ":" in l:
                k, v = l.split(":", 1)
                k_clean = k.strip().lower()
                v_clean = v.strip()
                if k_clean == "authorization":
                    auth_header = v_clean
                    print(f"      [***] PHÁT HIỆN TRƯỜNG XÁC THỰC: {l}")
                elif k_clean == "content-length":
                    try: content_length = int(v_clean)
                    except: pass
                elif k_clean == "content-type":
                    content_type = v_clean
                elif k_clean in ("host", "user-agent"):
                    print(f"      | {l}")

        # Đọc trọn vẹn body theo Content-Length
        while len(body_bytes) < content_length:
            needed = content_length - len(body_bytes)
            chunk = sock.recv(min(needed, 8192))
            if not chunk: break
            body_bytes += chunk

        if body_bytes:
            body_preview = body_bytes[:200].decode('utf-8', errors='ignore')
            print(f"      | Payload ({len(body_bytes)} bytes): {body_preview}")

        resp_body = b"{\"status\":\"success\",\"message\":\"Alarm received successfully\"}"
        resp = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: " + str(len(resp_body)).encode() + b"\r\n"
            b"Connection: close\r\n\r\n" + resp_body
        )
        sock.sendall(resp)
        try: sock.shutdown(socket.SHUT_WR)
        except: pass
        print(f"  [+] Đã trả lời webhook: 200 OK (Thành công - Camera hiển thị Test OK)")
    except Exception as e:
        print(f"  [-] Lỗi Alarm Webhook: {e}")
    finally:
        if sock:
            try: sock.close()
            except: pass
        try: conn.close()
        except: pass
        print("\n" + "=" * 80)
        print("  [INFO] ĐÃ HOÀN TẤT PHIÊN KẾT NỐI ALARM WEBHOOK.")
        print("  [INFO] MÁY CHỦ TIẾP TỤC DUY TRÌ LẮNG NGHE ĐỒNG THỜI TOÀN BỘ CỔNG (SFTP, SMTP, ALARM)...")
        print("         Bạn có thể bấm [Test] tiếp trên Camera bất kỳ lúc nào.")
        print("         (Máy chủ duy trì liên tục, chỉ dừng khi bạn nhấn Ctrl+C)")
        print("=" * 80 + "\n")

def accept_thread(sock, handler, *args):
    while True:
        try:
            c, a = sock.accept()
            t = threading.Thread(target=handler, args=(c, a, *args), daemon=True)
            t.start()
        except Exception:
            break

def main():
    all_ports = SFTP_PORTS + SMTP_PORTS + [PORT_HTTP, PORT_HTTPS]
    ensure_firewall_allowed(all_ports)

    active_ips = get_active_host_ips()
    primary_ip = active_ips[0][0] if active_ips else HOST_IP
    ip_list_str = ", ".join([f"{ip} ({dev})" for ip, dev in active_ips])

    print("=" * 90)
    print("  TRUNG TÂM THU NHẬN KẾT NỐI CLIENT ĐA GIAO THỨC (SFTP + SMTP + ALARM)")
    print(f"  Địa chỉ IP máy kiểm thử (Primary IP): {primary_ip}")
    print(f"  Các IP máy tính đang hoạt động      : {ip_list_str}")
    print(f"  Camera mục tiêu (DUT IP)            : {DUT_IP}")
    print("=" * 90)

    status_table = Table(title="DANH SÁCH CÁC CỔNG MÁY CHỦ ĐANG HOẠT ĐỘNG", expand=True)
    status_table.add_column("Cổng TCP", style="bold yellow", width=10, justify="center")
    status_table.add_column("Dịch vụ", style="bold cyan", width=25)
    status_table.add_column("Trạng thái", justify="center")
    status_table.add_column("Cấu hình trên Web Camera", style="white")

    active_listeners = []

    # Bind SFTP & FTP
    for p in SFTP_PORTS:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("0.0.0.0", p))
            s.listen(10)
            active_listeners.append((s, connection_dispatcher, (p,)))
            srv_title = "FTP Server (RFC 959)" if p == 21 else "SFTP Server (libssh2 OK)"
            cfg_tip = f"FTP Settings -> Plain FTP -> Port {p}" if p == 21 else f"FTP Settings -> Enable SFTP -> Port {p}"
            status_table.add_row(str(p), srv_title, "[bold green][OK] LISTENING[/bold green]", cfg_tip)
        except Exception as e:
            status_table.add_row(str(p), "SFTP/FTP Server", "[bold red][FAIL] ERROR[/bold red]", str(e))

    # Bind SMTP
    for p in SMTP_PORTS:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("0.0.0.0", p))
            s.listen(10)
            active_listeners.append((s, handle_smtp_client, (p,)))
            status_table.add_row(str(p), "SMTP Email Server", "[bold green][OK] LISTENING[/bold green]", f"Email Settings -> Port {p}")
        except Exception as e:
            status_table.add_row(str(p), "SMTP Email Server", "[bold red][FAIL] ERROR[/bold red]", str(e))

    # Bind Alarm HTTP / HTTPS
    for p, is_ssl, desc in [(PORT_HTTP, False, "Alarm Webhook HTTP"), (PORT_HTTPS, True, "Alarm Webhook HTTPS")]:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("0.0.0.0", p))
            s.listen(10)
            active_listeners.append((s, handle_alarm_client, (is_ssl,)))
            status_table.add_row(str(p), desc, "[bold green][OK] LISTENING[/bold green]", f"Alarm Server -> URL /alarm -> Port {p}")
        except Exception as e:
            status_table.add_row(str(p), desc, "[bold red][FAIL] ERROR[/bold red]", str(e))

    console.print(status_table)

    if not active_listeners:
        console.print("[bold red][FAIL] Không mở được cổng nào! Kiểm tra quyền root (sudo).[/bold red]")
        sys.exit(1)

    # Start PCAP
    bpf = " or ".join([f"tcp port {p}" for p in all_ports])
    pcap_proc, pcap_file = start_pcap_capture(DUT_IP, bpf, prefix="all_clients_audit", net_iface="any")
    if pcap_file:
        print(f"[*] Đang tự động bắt gói tin PCAP: {pcap_file}")

    for s, h, args in active_listeners:
        threading.Thread(target=accept_thread, args=(s, h, *args), daemon=True).start()

    console.print("\n[bold green][+] MÁY CHỦ ĐA NĂNG ĐÃ SẴN SÀNG! Bạn có thể bấm [Test] FTP, Email, hoặc Alarm bất cứ lúc nào...[/bold green]")
    console.print("[dim](Nhấn Ctrl+C để kết thúc phiên làm việc)[/dim]\n")

    try:
        while True:
            threading.Event().wait(1.0)
    except KeyboardInterrupt:
        print("\n[*] Đã dừng toàn bộ máy chủ.")
    finally:
        for s, _, _ in active_listeners:
            try: s.close()
            except: pass
        stop_pcap_capture(pcap_proc)

if __name__ == '__main__':
    main()
