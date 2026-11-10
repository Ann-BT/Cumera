#!/usr/bin/env python3
"""
RECEIVER DAEMON & EVENT ANALYZER (QCVN 11:2026/BCA)
Chạy ngầm liên tục toàn bộ các máy chủ thu nhận kết nối Client từ Camera:
  - Cổng 21: Plain FTP (RFC 959 đầy đủ với Passive Mode & upload file test)
  - Cổng 22: SFTP / SSH (RFC 4253, hỗ trợ libssh2_1.11.1, OpenSSH, Dropbear)
  - Cổng 25, 465, 587: SMTP Email (Hỗ trợ SMTPS bọc TLS và STARTTLS, AUTH LOGIN/PLAIN)
  - Cổng 8088 (HTTP), 8443 (HTTPS): Alarm Webhook (Bóc tách Header Authorization & Body)
Ghi nhận sự kiện thời gian thực và tự động phân tích đối soát với Wireshark.
Author: Merlin / Antigravity
"""

import os
import sys

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

import socket
import ssl
import ipaddress
import struct
import select
import threading
import json
import io
import time
import tempfile
import datetime
import subprocess
import base64
from typing import Dict, List, Any, Optional, Tuple

CAPTURES_DIR = os.path.join(TOOLKIT_DIR, "captures")
os.makedirs(CAPTURES_DIR, exist_ok=True)

PID_FILE = os.path.join(CAPTURES_DIR, "receiver_daemon.pid")
EVENTS_FILE = os.path.join(CAPTURES_DIR, "live_events.json")
DAEMON_PCAP_FILE = os.path.join(CAPTURES_DIR, "live_inbound_audit.pcap")
CONFIG_PATH = os.path.join(TOOLKIT_DIR, "config.json")

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    console = Console()
except ImportError:
    console = None

import paramiko
from paramiko.message import Message
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

sys.path.insert(0, TOOLKIT_DIR)
from pcap_recorder import display_wireshark_panel, enable_ssl_keylog

# Host Keys cho SFTP / SSH
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

def get_active_host_ips() -> List[Tuple[str, str]]:
    """Lấy danh sách toàn bộ các IP đang hoạt động trên máy tính (Wi-Fi, Ethernet)."""
    ips = []
    try:
        res = subprocess.run(["ip", "-4", "-o", "addr", "show", "up"], capture_output=True, text=True)
        if res.returncode == 0:
            for line in res.stdout.splitlines():
                parts = line.strip().split()
                if len(parts) >= 4:
                    iface = parts[1]
                    if iface == "lo" or iface.startswith(("docker", "veth")):
                        continue
                    ip_cidr = parts[3]
                    ip = ip_cidr.split("/")[0]
                    ips.append((ip, iface))
    except Exception:
        pass
    if not ips:
        ips.append(("127.0.0.1", "lo"))
    return ips

# Chứng thư số máy chủ TLS RSA-2048 SHA-256 phổ quát cho HTTPS & SMTPS (Đầy đủ SAN & hỗ trợ mọi phiên bản TLS)
def get_server_ssl_context():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Camera-Audit-Host")])

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
        for well_known_ip in ["192.168.101.250", "192.168.0.250", "192.168.1.250"]:
            try:
                san_entries.append(x509.IPAddress(ipaddress.ip_address(well_known_ip)))
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
    cfile = tempfile.NamedTemporaryFile(delete=False, suffix=".crt")
    cfile.write(cert.public_bytes(serialization.Encoding.PEM))
    cfile.close()

    kfile = tempfile.NamedTemporaryFile(delete=False, suffix=".key")
    kfile.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    kfile.close()

    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(cfile.name, kfile.name)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
    except Exception:
        pass
    try:
        ctx.set_ciphers('ALL:@SECLEVEL=0')
    except Exception:
        pass
    enable_ssl_keylog(ctx)
    return ctx

SSL_SERVER_CTX = get_server_ssl_context()

# ----------------- QUẢN LÝ SỰ KIỆN JSON -----------------
EVENTS_LOCK = threading.Lock()

def record_event(service: str, remote_addr: str, data: Dict[str, Any]):
    """Ghi nhận sự kiện client kết nối vào file JSON để các tool đọc ngay lập tức."""
    event_entry = {
        "id": int(time.time() * 1000),
        "service": service,
        "remote_addr": remote_addr,
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "pcap_file": DAEMON_PCAP_FILE,
        "data": data
    }
    with EVENTS_LOCK:
        events = []
        if os.path.exists(EVENTS_FILE):
            try:
                with open(EVENTS_FILE, "r", encoding="utf-8") as f:
                    events = json.load(f)
            except Exception:
                events = []
        events.append(event_entry)
        if len(events) > 50:
            events = events[-50:]
        try:
            with open(EVENTS_FILE, "w", encoding="utf-8") as f:
                json.dump(events, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"[-] Lỗi ghi live_events.json: {e}")

def get_latest_event(service: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Lấy sự kiện mới nhất (có thể lọc theo service: 'sftp', 'ftp', 'smtp', 'alarm')."""
    if not os.path.exists(EVENTS_FILE):
        return None
    with EVENTS_LOCK:
        try:
            with open(EVENTS_FILE, "r", encoding="utf-8") as f:
                events = json.load(f)
            if not events:
                return None
            if service:
                matching = [e for e in events if e.get("service") == service]
                return matching[-1] if matching else None
            return events[-1]
        except Exception:
            return None

def clear_events(service: Optional[str] = None):
    """Xóa bộ đệm sự kiện."""
    if not os.path.exists(EVENTS_FILE):
        return
    with EVENTS_LOCK:
        try:
            if service:
                with open(EVENTS_FILE, "r", encoding="utf-8") as f:
                    events = json.load(f)
                events = [e for e in events if e.get("service") != service]
                with open(EVENTS_FILE, "w", encoding="utf-8") as f:
                    json.dump(events, f, indent=2)
            else:
                with open(EVENTS_FILE, "w", encoding="utf-8") as f:
                    json.dump([], f)
        except Exception:
            pass

# ----------------- 1. SFTP / SSH SERVER HANDLER -----------------
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
        self.auth_username = None
        self.auth_password = None
    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == 'session' else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
    def check_auth_password(self, u, p):
        self.auth_username = u
        self.auth_password = p
        return paramiko.AUTH_SUCCESSFUL
    def check_auth_none(self, u):
        self.auth_username = u
        return paramiko.AUTH_SUCCESSFUL
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
        c_ciph = getattr(t, "remote_cipher", "Chưa xác định")
        c_kex = getattr(t, "kex_engine", "Chưa xác định")
        if hasattr(c_kex, "__name__"):
            c_kex = c_kex.__name__
        c_mac = getattr(t, "remote_mac", "Chưa xác định")
        c_key = getattr(t, "host_key_type", "Chưa xác định")

        evt_data = {
            "client_version": c_ver,
            "active_cipher": c_ciph,
            "active_kex": c_kex,
            "active_mac": c_mac,
            "active_key": c_key,
            "username": server.auth_username,
            "password": server.auth_password,
            "proposed_ciphers": t.parsed_kex.get("ciphers", []),
            "proposed_kex": t.parsed_kex.get("kex", []),
            "proposed_keys": t.parsed_kex.get("keys", []),
            "evaluation": "PASS"
        }
        record_event("sftp", f"{addr[0]}:{addr[1]}", evt_data)
        print(f"[*] [DAEMON SFTP] Thu nhận thành công kết nối SFTP từ {addr[0]}:{addr[1]} (Client: {c_ver})")

        while t.is_active():
            time.sleep(0.1)
    except Exception as e:
        pass
    finally:
        try: conn.close()
        except: pass

# ----------------- 2. PLAIN FTP SERVER HANDLER -----------------
def handle_plain_ftp(conn, addr, port):
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

                if cmd == "USER":
                    captured_user = arg
                    conn.sendall(b"331 User name okay, need password.\r\n")
                elif cmd == "PASS":
                    captured_pass = arg
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
                        local_ip = addr[0]
                    ip_p = local_ip.split(".")
                    conn.sendall(f"227 Entering Passive Mode ({ip_p[0]},{ip_p[1]},{ip_p[2]},{ip_p[3]},{pasv_p//256},{pasv_p%256})\r\n".encode())
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
                elif cmd in ("LIST", "NLST"):
                    conn.sendall(b"150 Opening ASCII mode data connection for directory listing.\r\n")
                    d_conn = None
                    if pasv_sock:
                        try:
                            pasv_sock.settimeout(5.0)
                            d_conn, _ = pasv_sock.accept()
                        except Exception: pass
                    if d_conn:
                        try: d_conn.sendall(b"drwxr-xr-x 2 ftp ftp 4096 Oct 29 10:00 test\r\n")
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
    except Exception:
        pass
    finally:
        if pasv_sock:
            try: pasv_sock.close()
            except: pass
        try: conn.close()
        except: pass

        evt_data = {
            "username": captured_user,
            "password": captured_pass,
            "uploaded_files": uploaded_files,
            "evaluation": "FAIL",
            "reason": "Cleartext FTP: Tài khoản và mật khẩu truyền rõ không được mã hóa (Vi phạm QCVN 11)."
        }
        record_event("ftp", f"{addr[0]}:{addr[1]}", evt_data)
        print(f"[*] [DAEMON FTP] Thu nhận kết nối Plain FTP từ {addr[0]}:{addr[1]} (user: {captured_user})")

def connection_dispatcher(conn, addr, port):
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
    except Exception:
        try: conn.close()
        except: pass

# ----------------- 3. SMTP EMAIL SERVER HANDLER -----------------
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
                sock.sendall(b"235 2.7.0 Authentication successful\r\n")
                continue
            elif auth_step == "plain":
                try:
                    plain_dec = base64.b64decode(line_str).decode('utf-8', errors='ignore')
                    tokens = plain_dec.split('\x00')
                    captured_user = tokens[1] if len(tokens) > 1 else tokens[0]
                    captured_pass = tokens[2] if len(tokens) > 2 else ""
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
                    tls_sock = SSL_SERVER_CTX.wrap_socket(sock, server_side=True)
                    return handle_smtp_dialogue(tls_sock, addr, port, is_post_tls=True)
                except Exception:
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
    sock_to_use = conn
    is_tls = False
    tls_cipher = None

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
                wrapped = SSL_SERVER_CTX.wrap_socket(conn, server_side=True)
                sock_to_use = wrapped
                c = wrapped.cipher()
                tls_cipher = f"{c[0]} ({wrapped.version()})"
                sock_to_use.sendall(b"220 QCVN11_Test_Mail_Server ESMTP Ready (TLS Active)\r\n")
            except Exception:
                return
        else:
            sock_to_use.sendall(b"220 QCVN11_Test_Mail_Server ESMTP Ready\r\n")

        u, p, snd, rc, subj, is_tls_res, ciph_res = handle_smtp_dialogue(sock_to_use, addr, port, is_post_tls=is_tls)
        if is_tls_res:
            is_tls = True
            tls_cipher = ciph_res or tls_cipher

        evt_data = {
            "port": port,
            "is_tls": is_tls,
            "tls_cipher": tls_cipher or ("Mã hóa TLS" if is_tls else "Bản rõ Cleartext"),
            "username": u,
            "password": p,
            "sender": snd,
            "recipient": rc,
            "subject": subj,
            "evaluation": "PASS" if is_tls else "WARN"
        }
        record_event("smtp", f"{addr[0]}:{addr[1]}", evt_data)
        print(f"[*] [DAEMON SMTP] Thu nhận kết nối SMTP từ {addr[0]}:{addr[1]} (Cổng {port}, TLS: {is_tls})")
    except Exception:
        pass
    finally:
        try: sock_to_use.close()
        except: pass
        try: conn.close()
        except: pass

# ----------------- 4. ALARM WEBHOOK SERVER HANDLER -----------------
def handle_alarm_client(conn, addr, is_ssl=False):
    sock = None
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

    try:
        sock = SSL_SERVER_CTX.wrap_socket(conn, server_side=True) if is_ssl else conn
        tls_cipher = None
        if is_ssl:
            try:
                c = sock.cipher()
                tls_cipher = f"{c[0]} ({sock.version()})"
            except Exception:
                pass

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

        for l in lines[1:]:
            if ":" in l:
                k, v = l.split(":", 1)
                k_clean = k.strip().lower()
                v_clean = v.strip()
                if k_clean == "authorization":
                    auth_header = v_clean
                elif k_clean == "content-length":
                    try: content_length = int(v_clean)
                    except: pass
                elif k_clean == "content-type":
                    content_type = v_clean

        # Đọc trọn vẹn body theo Content-Length
        while len(body_bytes) < content_length:
            needed = content_length - len(body_bytes)
            chunk = sock.recv(min(needed, 8192))
            if not chunk: break
            body_bytes += chunk

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

        evt_data = {
            "protocol": "HTTPS" if is_ssl else "HTTP",
            "request_line": req_line,
            "authorization": auth_header,
            "content_type": content_type,
            "body_length": len(body_bytes),
            "tls_cipher": tls_cipher,
            "evaluation": "PASS" if is_ssl else "WARN"
        }
        record_event("alarm", f"{addr[0]}:{addr[1]}", evt_data)
        print(f"[*] [DAEMON ALARM] Thu nhận webhook từ {addr[0]}:{addr[1]} ({'HTTPS' if is_ssl else 'HTTP'})")
    except Exception:
        pass
    finally:
        if sock:
            try: sock.close()
            except: pass
        try: conn.close()
        except: pass

# ----------------- VÒNG LẶP ACCEPT VÀ QUẢN LÝ TIẾN TRÌNH -----------------
def accept_thread(sock, handler, *args):
    while True:
        try:
            c, a = sock.accept()
            threading.Thread(target=handler, args=(c, a, *args), daemon=True).start()
        except Exception:
            break

def start_tcpdump_capture() -> Optional[subprocess.Popen]:
    """Khởi động tcpdump bắt toàn bộ gói tin đến các cổng máy chủ."""
    bpf = "tcp port 21 or tcp port 22 or tcp port 25 or tcp port 465 or tcp port 587 or tcp port 8088 or tcp port 8443"
    try:
        proc = subprocess.Popen(
            ["tcpdump", "-i", "any", "-nn", "-s", "0", "-w", DAEMON_PCAP_FILE, bpf],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return proc
    except Exception:
        return None

def run_daemon_server():
    """Hàm chạy chính của Daemon máy chủ thu nhận."""
    # Ghi PID
    with open(PID_FILE, "w") as f:
        f.write(str(os.getpid()))

    ports_config = [
        (21, connection_dispatcher, (21,)),
        (22, connection_dispatcher, (22,)),
        (25, handle_smtp_client, (25,)),
        (465, handle_smtp_client, (465,)),
        (587, handle_smtp_client, (587,)),
        (8088, handle_alarm_client, (False,)),
        (8443, handle_alarm_client, (True,))
    ]

    active_socks = []
    for port, handler, args in ports_config:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("0.0.0.0", port))
            s.listen(20)
            active_socks.append((s, handler, args))
        except Exception as e:
            print(f"[-] Không thể bind cổng {port}: {e}")

    pcap_proc = start_tcpdump_capture()

    for s, handler, args in active_socks:
        threading.Thread(target=accept_thread, args=(s, handler, *args), daemon=True).start()

    print(f"[OK] RECEIVER DAEMON ĐÃ HOẠT ĐỘNG (PID: {os.getpid()}). Đang lắng nghe trên toàn bộ interface...")

    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        pass
    finally:
        for s, _, _ in active_socks:
            try: s.close()
            except: pass
        if pcap_proc:
            try: pcap_proc.terminate()
            except: pass
        if os.path.exists(PID_FILE):
            try: os.remove(PID_FILE)
            except: pass

def is_daemon_running() -> bool:
    """Kiểm tra xem daemon có đang chạy không bằng cách kiểm tra port hoặc PID."""
    if os.path.exists(PID_FILE):
        try:
            with open(PID_FILE, "r") as f:
                pid = int(f.read().strip())
            # Check if process is alive
            os.kill(pid, 0)
            return True
        except Exception:
            pass
    # Thử kết nối tới port 8088 hoặc 22
    for p in [8088, 22, 21]:
        try:
            s = socket.socket()
            s.settimeout(0.2)
            s.connect(("127.0.0.1", p))
            s.close()
            return True
        except Exception:
            pass
    return False

def ensure_daemon_running():
    """Tự động đảm bảo daemon máy chủ đang chạy ngầm bằng sudo."""
    if is_daemon_running():
        return True
    # Khởi động daemon dưới nền
    py_bin = VENV_PYTHON if os.path.isfile(VENV_PYTHON) else sys.executable
    script_path = os.path.abspath(__file__)
    cmd = ["sudo", py_bin, script_path, "--run-daemon"]
    try:
        subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            preexec_fn=os.setpgrp
        )
        time.sleep(0.8)
        return is_daemon_running()
    except Exception as e:
        print(f"[-] Không thể khởi động daemon: {e}")
        return False

# ----------------- HÀM PHÂN TÍCH & HIỂN THỊ ĐỐI SOÁT WIRESHARK -----------------
def analyze_and_display_event(event: Dict[str, Any]):
    """Phân tích kỹ thuật chi tiết của sự kiện vừa thu nhận kèm hướng dẫn Wireshark."""
    if not console:
        return
    srv = event.get("service", "unknown").upper()
    ts = event.get("timestamp", "N/A")
    src = event.get("remote_addr", "N/A")
    d = event.get("data", {})

    console.print("\n" + "=" * 90)
    console.print(f"[bold green][OK] PHÂN TÍCH BẰNG CHỨNG KẾT NỐI CAMERA [{srv}][/bold green] - Thời gian: [bold white]{ts}[/bold white]")
    console.print(f"  • Địa chỉ Camera (Source) : [bold cyan]{src}[/bold cyan]")
    console.print("=" * 90)

    if srv == "SFTP":
        console.print(f"  • Phiên bản SSH Client của Camera   : [bold cyan]{d.get('client_version', 'N/A')}[/bold cyan]")
        console.print(f"  • Thuật toán mã hóa đã đàm phán     : [bold green]{d.get('active_cipher', 'N/A')}[/bold green]")
        console.print(f"  • Trao đổi khóa thực tế (KEX)       : [bold white]{d.get('active_kex', 'N/A')}[/bold white]")
        console.print(f"  • Khóa máy chủ (Host Key)           : {d.get('active_key', 'N/A')}")
        if d.get("username") or d.get("password"):
            console.print(f"  • Tài khoản xác thực                : user='{d.get('username')}', pass='{d.get('password')}'")
        console.print(f"  • Đánh giá QCVN 11                  : [bold green][PASS] ĐẠT CHUẨN[/bold green] (Mã hóa SFTP bảo mật cao)")

        ciphers = d.get("proposed_ciphers", [])
        if ciphers:
            console.print("\n  [-] CÁC BỘ MÃ CAMERA ĐỀ XUẤT (KEXINIT):")
            for c in ciphers:
                is_weak = any(w in c for w in ["cbc", "arcfour", "3des", "blowfish", "cast"])
                tag = "[CŨ/YẾU BỊ CẤM]" if is_weak else "[AN TOÀN - AEAD/CTR]"
                console.print(f"      -> {c:<38} {tag}")

        filters = [
            ("Toàn bộ lưu lượng SSH / SFTP", "tcp.port == 22 || ssh"),
            ("Gói tin trao đổi thuật toán (KEXINIT)", "tcp.port == 22 && ssh.message_code == 20"),
            ("Bắt tay trao đổi khóa Diffie-Hellman", "tcp.port == 22 && (ssh.message_code == 30 || ssh.message_code == 31)"),
            ("Khởi tạo dịch vụ SFTP Subsystem", "tcp.port == 22 && sftp")
        ]
        display_wireshark_panel(
            console,
            DAEMON_PCAP_FILE,
            filters,
            is_tls=False,
            sort_tip="Click tiêu đề cột No. để xem thứ tự: TCP 3-Way Handshake → Banner SSH-2.0-libssh2 → Gói tin KEXINIT (message_code 20) → UserAuth → SFTP Subsystem v3.",
            title="BẰNG CHỨNG GÓI TIN WIRESHARK SFTP / SSH (PORT 22)"
        )

    elif srv == "FTP":
        console.print(f"  • Tài khoản người dùng              : [bold yellow]{d.get('username', 'N/A')}[/bold yellow]")
        console.print(f"  • Mật khẩu bản rõ (Cleartext)       : [bold red]{d.get('password', 'N/A')}[/bold red]")
        files = d.get("uploaded_files", [])
        if files:
            console.print(f"  • File test tải lên (STOR)          : {', '.join([f'{f[0]} ({f[1]} bytes)' for f in files])}")
        console.print(f"  • Đánh giá QCVN 11                  : [bold red][FAIL] BẢN RÕ (CLEARTEXT FTP)[/bold red] - Cần bật SFTP!")

        filters = [
            ("Toàn bộ lưu lượng FTP", "tcp.port == 21 || ftp || ftp-data"),
            ("Tài khoản và mật khẩu bản rõ", "tcp.port == 21 && (ftp.request.command == \"USER\" || ftp.request.command == \"PASS\")"),
            ("Lệnh gửi file test lên máy chủ", "tcp.port == 21 && (ftp.request.command == \"STOR\" || ftp.response.code == 226)"),
            ("Chế độ truyền Passive Mode (PASV)", "tcp.port == 21 && (ftp.request.command == \"PASV\" || ftp.response.code == 227)")
        ]
        display_wireshark_panel(
            console,
            DAEMON_PCAP_FILE,
            filters,
            is_tls=False,
            sort_tip="Click tiêu đề cột No. để xem chuỗi: 220 Banner → USER → PASS (mật khẩu rõ) → PASV (cấp cổng data) → STOR test.tmp → 226 Transfer complete.",
            title="BẰNG CHỨNG GÓI TIN WIRESHARK CLEARTEXT FTP (PORT 21)"
        )

    elif srv == "SMTP":
        is_tls = d.get("is_tls", False)
        ciph = d.get("tls_cipher", "Bản rõ")
        console.print(f"  • Cổng kết nối                      : TCP {d.get('port', 25)}")
        console.print(f"  • Kênh truyền mật mã                : [bold green]{ciph}[/bold green]" if is_tls else f"  • Kênh truyền mật mã                : [bold yellow]{ciph}[/bold yellow]")
        if d.get("username") or d.get("password"):
            console.print(f"  • Tài khoản xác thực AUTH           : user='{d.get('username')}', pass='{d.get('password')}'")
        if d.get("sender"):
            console.print(f"  • Người gửi (MAIL FROM)             : {d.get('sender')}")
        if d.get("recipient"):
            console.print(f"  • Người nhận (RCPT TO)              : {d.get('recipient')}")
        if d.get("subject"):
            console.print(f"  • Tiêu đề thư (Subject)             : [bold white]{d.get('subject')}[/bold white]")
        console.print(f"  • Đánh giá QCVN 11                  : [bold green][PASS] ĐẠT CHUẨN MÃ HÓA TLS[/bold green]" if is_tls else "[bold red][FAIL] KHÔNG MÃ HÓA[/bold red]")

        filters = [
            ("Toàn bộ lưu lượng SMTP", "tcp.port in (25, 465, 587) || smtp"),
            ("Bắt tay STARTTLS / SMTPS", "tcp.port in (465, 587) && (tls.handshake.type == 1 || tls.handshake.type == 2)"),
            ("Lệnh gửi Email (MAIL FROM & RCPT TO)", "tcp.port in (25, 465, 587) && (smtp.req.command == \"MAIL\" || smtp.req.command == \"RCPT\")"),
            ("Xác thực tài khoản AUTH", "tcp.port in (25, 465, 587) && smtp.req.command == \"AUTH\"")
        ]
        display_wireshark_panel(
            console,
            DAEMON_PCAP_FILE,
            filters,
            is_tls=is_tls,
            sort_tip="Click tiêu đề cột No. để xem: EHLO → STARTTLS (hoặc SMTPS) → AUTH LOGIN → MAIL FROM → DATA → 250 OK: queued.",
            title=f"BẰNG CHỨNG GÓI TIN WIRESHARK SMTP / SMTPS (PORT {d.get('port', 25)})"
        )

    elif srv == "ALARM":
        proto = d.get("protocol", "HTTP")
        is_ssl = (proto == "HTTPS")
        console.print(f"  • Giao thức Webhook                 : [bold cyan]{proto}[/bold cyan]")
        if is_ssl:
            console.print(f"  • Bắt tay TLS                       : [bold green]{d.get('tls_cipher', 'TLSv1.3')}[/bold green]")
        console.print(f"  • Yêu cầu HTTP (Request Line)       : [bold white]{d.get('request_line', 'N/A')}[/bold white]")
        console.print(f"  • Tiêu đề xác thực (Authorization)  : [bold green]{d.get('authorization', 'Không có header Auth')}[/bold green]")
        console.print(f"  • Kiểu dữ liệu (Content-Type)       : {d.get('content_type', 'N/A')}")
        console.print(f"  • Đánh giá QCVN 11                  : [bold green][PASS] BẢO VỆ HTTPS[/bold green]" if is_ssl else "[bold yellow][WARN] KÊNH RÕ HTTP[/bold yellow]")

        filters = [
            ("Toàn bộ lưu lượng Alarm Webhook", "tcp.port in (8088, 8443)"),
            ("Webhook HTTP POST & Máy chủ 200 OK", "tcp.port == 8088 && (http.request.method == \"POST\" || http.response.code == 200)"),
            ("Tiêu đề Authorization xác thực", "tcp.port in (8088, 8443) && http.authorization"),
            ("Webhook HTTPS qua bắt tay TLS 1.3", "tcp.port == 8443 && (tls.handshake.type == 1 || tls.handshake.type == 2)")
        ]
        display_wireshark_panel(
            console,
            DAEMON_PCAP_FILE,
            filters,
            is_tls=is_ssl,
            sort_tip="Click tiêu đề cột No. hoặc Time để xem: Gói tin POST từ camera gửi tới kèm trường Authorization và phản hồi 200 OK của máy chủ.",
            title=f"BẰNG CHỨNG GÓI TIN WIRESHARK ALARM WEBHOOK ({proto})"
        )

def wait_and_analyze_service(service_name: str, timeout: int = 60):
    """
    Hàm chờ và bóc tách trực tiếp cho Menu:
    Nếu đã có gói tin vừa gửi, hiển thị ngay!
    Nếu chưa, chờ người dùng bấm [Test] trên web camera.
    """
    ensure_daemon_running()

    active_ips = get_active_host_ips()
    primary_ip = active_ips[0][0]

    port_map = {
        "sftp": "Cổng 22 (hoặc Cổng 21 nếu chọn FTP)",
        "ftp": "Cổng 21",
        "smtp": "Cổng 465 (SMTPS), 587 (STARTTLS), hoặc 25",
        "alarm": f"http://{primary_ip}:8088/alarm hoặc https://{primary_ip}:8443/alarm"
    }

    service_title = {
        "sftp": "SFTP / FTP SERVER",
        "ftp": "PLAIN FTP SERVER",
        "smtp": "SMTP EMAIL SERVER",
        "alarm": "ALARM WEBHOOK SERVER"
    }.get(service_name, service_name.upper())

    console.print("\n" + "=" * 80)
    console.print(f"  [bold cyan]CÔNG CỤ BÓC TÁCH & ĐỐI SOÁT WIRESHARK: {service_title}[/bold cyan]")
    console.print(f"  • Trạng thái máy chủ   : [bold green][OK] ĐANG CHẠY NGẦM & SẴN SÀNG NHẬN KẾT NỐI[/bold green]")
    console.print(f"  • IP Máy tính cần điền : [bold yellow]{primary_ip}[/bold yellow] (hoặc các IP khác: {', '.join([ip for ip, _ in active_ips])})")
    console.print(f"  • Cấu hình Cổng / URL  : [bold white]{port_map.get(service_name, '')}[/bold white]")
    console.print("=" * 80)

    # 1. Kiểm tra xem đã có gói tin nào vừa bắt được trong vòng 30s qua không
    latest = get_latest_event(service=service_name)
    if latest and (int(time.time() * 1000) - latest.get("id", 0)) < 30000:
        console.print(f"\n[bold green][+] PHÁT HIỆN GÓI TIN VỪA TEST THÀNH CÔNG TỪ CAMERA ({latest.get('remote_addr')})![/bold green]")
        analyze_and_display_event(latest)
        return

    # 2. Nếu chưa, chờ trực tiếp người dùng bấm nút [Test]
    console.print(f"\n[*] Đang chờ bạn bấm [bold green][Test][/bold green] trên giao diện Web của Camera...")
    console.print(f"[dim]    (Vào mục cấu hình tương ứng trên web camera, bấm nút [Test] hoặc [Send Test Mail])[/dim]")
    console.print(f"[dim]    (Nhấn Ctrl+C để quay lại bất cứ lúc nào)[/dim]\n")

    start_time = time.time()
    last_id = latest.get("id", 0) if latest else 0

    try:
        while time.time() - start_time < timeout:
            ev = get_latest_event(service=service_name)
            if ev and ev.get("id", 0) > last_id:
                console.print(f"[bold green][+] ĐÃ BẮT ĐƯỢC GÓI TIN TỪ CAMERA: {ev.get('remote_addr')}![/bold green]")
                analyze_and_display_event(ev)
                return
            time.sleep(0.5)
        console.print("[yellow][!] Hết thời gian chờ (60s). Máy chủ vẫn đang tiếp tục chạy ngầm.[/yellow]")
    except KeyboardInterrupt:
        console.print("\n[*] Đã quay lại menu.")

if __name__ == '__main__':
    if "--run-daemon" in sys.argv:
        run_daemon_server()
    elif "--stop" in sys.argv:
        if os.path.exists(PID_FILE):
            try:
                with open(PID_FILE, "r") as f:
                    pid = int(f.read().strip())
                os.kill(pid, 9)
                os.remove(PID_FILE)
                print("[OK] Đã dừng receiver daemon.")
            except Exception as e:
                print(f"[-] Lỗi dừng daemon: {e}")
        else:
            print("[!] Daemon không chạy.")
    elif "--status" in sys.argv:
        running = is_daemon_running()
        print(f"Daemon running: {running}")
    else:
        # Chạy trực tiếp foreground
        run_daemon_server()
