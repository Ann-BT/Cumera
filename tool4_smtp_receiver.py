#!/usr/bin/env python3
"""
TOOL 4: MÁY CHỦ BÓC TÁCH MẬT MÃ SMTP EMAIL CLIENT (AUTHMECH-5)
Tiêu chuẩn: QCVN 11:2026/BCA (Yêu cầu 2.1.3 & Phụ lục IXIT AuthMech-5)
Chức năng: Lắng nghe kết nối SMTP/SMTPS từ Camera trên cổng 25, 465, 587.
Author: Merlin / Antigravity
"""

import socket
import sys
import struct
import select
import threading
import json
import os
import base64
import tempfile
import datetime
import subprocess
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import ssl
import ipaddress

# Tự động nâng quyền root nếu chạy dưới quyền user thường (bắt buộc cho cổng 25, 465, 587 trên Linux)
if __name__ == '__main__' and hasattr(os, 'geteuid') and os.geteuid() != 0:
    print("[*] Mở cổng SMTP đặc quyền (< 1024) yêu cầu quyền root.")
    print("[*] Đang tự động nâng quyền với sudo...")
    try:
        os.execvp("sudo", ["sudo", sys.executable] + sys.argv)
    except Exception as e:
        print(f"[-] Không thể gọi sudo tự động: {e}")
        print(f"    Vui lòng chạy lại bằng lệnh: sudo {sys.executable} {os.path.abspath(__file__)}")
        sys.exit(1)

sys.stdout.reconfigure(encoding='utf-8')
console = Console()

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pcap_recorder import start_pcap_capture, stop_pcap_capture, display_wireshark_panel, enable_ssl_keylog
from receiver_daemon import get_active_host_ips
from toolkit_config import CONF_PATH, detect_host_network, get_service_ports, get_target_info, load_config

config = load_config()
DUT_IP = get_target_info(config)["ip"]
_, HOST_IP = detect_host_network(DUT_IP, config)
_sp = get_service_ports(config)
SMTP_PORTS = _sp.get("smtp_receiver", [_sp["smtp_clear"], _sp["smtps"], _sp["smtp_starttls"]])
GLOBAL_PCAP_FILE = ""

def ensure_firewall_allowed(ports):
    try:
        res = subprocess.run(["systemctl", "is-active", "firewalld"], capture_output=True, text=True)
        if res.returncode == 0 and res.stdout.strip() == "active":
            for p in ports:
                subprocess.run(["firewall-cmd", "--add-port", f"{p}/tcp"], capture_output=True)
                subprocess.run(["firewall-cmd", "--zone=nm-shared", "--add-port", f"{p}/tcp"], capture_output=True)
    except Exception:
        pass

# Tạo chứng thư số máy chủ TLS RSA-2048 SHA-256 phổ quát (Đầy đủ SAN & hỗ trợ mọi phiên bản TLS)
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
    for extra_ip in [HOST_IP]:
        try:
            ipa = x509.IPAddress(ipaddress.ip_address(extra_ip))
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

KNOWN_CIPHERS = {
    0x1301: "TLS_AES_128_GCM_SHA256 (TLS 1.3)",
    0x1302: "TLS_AES_256_GCM_SHA384 (TLS 1.3)",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256 (TLS 1.3)",
    0x1304: "TLS_AES_128_CCM_SHA256 (TLS 1.3)",
    0x1305: "TLS_AES_128_CCM_8_SHA256 (TLS 1.3)",
    0xc02f: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xc030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
}

def parse_client_hello(data):
    if len(data) < 45 or data[0] != 0x16 or data[5] != 0x01:
        return None
    idx = 43
    sess_id_len = data[idx]
    idx += 1 + sess_id_len
    if idx + 2 > len(data): return None
    cipher_len = struct.unpack("!H", data[idx:idx+2])[0]
    idx += 2
    ciphers = []
    for i in range(0, cipher_len, 2):
        if idx + i + 2 <= len(data):
            c_val = struct.unpack("!H", data[idx+i:idx+i+2])[0]
            ciphers.append((c_val, KNOWN_CIPHERS.get(c_val, f"Unknown (0x{c_val:04x})")))
    idx += cipher_len
    if idx < len(data):
        comp_len = data[idx]
        idx += 1 + comp_len
    exts = {}
    if idx + 2 <= len(data):
        ext_total_len = struct.unpack("!H", data[idx:idx+2])[0]
        idx += 2
        end_ext = idx + ext_total_len
        while idx + 4 <= end_ext and idx + 4 <= len(data):
            etype, elen = struct.unpack("!HH", data[idx:idx+4])
            idx += 4
            edata = data[idx:idx+elen]
            exts[etype] = edata
            idx += elen
    return ciphers, exts

def handle_smtp_dialogue(sock, addr, port, is_post_tls=False):
    """Xử lý hội thoại SMTP chuẩn RFC 5321 / RFC 3207 / RFC 4954."""
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
                print(f"  [***] XÁC THỰC SMTP THÀNH CÔNG: user='{captured_user}', password='{captured_pass}'")
                sock.sendall(b"235 2.7.0 Authentication successful\r\n")
                continue
            elif auth_step == "plain":
                try:
                    plain_dec = base64.b64decode(line_str).decode('utf-8', errors='ignore')
                    tokens = plain_dec.split('\x00')
                    captured_user = tokens[1] if len(tokens) > 1 else tokens[0]
                    captured_pass = tokens[2] if len(tokens) > 2 else ""
                    print(f"  [***] XÁC THỰC SMTP PLAIN: user='{captured_user}', password='{captured_pass}'")
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
                    print(f"  [+] BẮT TAY STARTTLS THÀNH CÔNG: Version {tls_sock.version()}, Cipher {cipher_info[0]}")
                    return handle_smtp_dialogue(tls_sock, addr, port, is_post_tls=True)
                except Exception as e:
                    print(f"  [-] Lỗi bắt tay STARTTLS: {e}")
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
                            print(f"  [***] XÁC THỰC SMTP PLAIN: user='{captured_user}', password='{captured_pass}'")
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
                print(f"  [+] ĐÃ NHẬN THÀNH CÔNG EMAIL TEST: Subject='{email_subject or 'Không tiêu đề'}'")
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
    print(f"  [+] BẮT ĐƯỢC KẾT NỐI TỪ EMAIL CLIENT CAMERA: {addr[0]}:{addr[1]} (Cổng kết nối TCP {port})")
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
                print(f"  • Giao thức : SMTPS (Mã hóa SSL/TLS trực tiếp)")
                print(f"  • Bắt tay TLS thành công : {tls_cipher}")
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
        print(f"  [+] BẮT THÀNH CÔNG PHIÊN GỬI EMAIL TEST TỪ CAMERA: {addr[0]}:{addr[1]}")
        print(f"  • Trạng thái phản hồi máy chủ : [bold green][OK] THÀNH CÔNG (Camera hiển thị Test OK)[/bold green]")
        print(f"  • Kênh truyền mật mã          : [bold green]{tls_cipher}[/bold green]" if is_tls else "  • Kênh truyền mật mã          : [bold yellow]Bản rõ (Cleartext)[/bold yellow]")
        if u or p:
            print(f"  • Tài khoản xác thực          : user='{u}', pass='{p}'")
        if snd:
            print(f"  • Người gửi (Sender)          : {snd}")
        if rc:
            print(f"  • Người nhận (Recipient)       : {rc}")
        if subj:
            print(f"  • Tiêu đề thư (Subject)       : {subj}")
        print("=" * 90)

        filters = [
            ("Toàn bộ lưu lượng SMTP", f"tcp.port in (25, 465, 587) || smtp"),
            ("Bắt tay STARTTLS / SMTPS", f"tcp.port in (25, 465, 587) && (tls.handshake.type == 1 || tls.handshake.type == 2)"),
            ("Lệnh gửi Email (MAIL FROM & RCPT TO)", f"tcp.port in (25, 465, 587) && (smtp.req.command == \"MAIL\" || smtp.req.command == \"RCPT\")"),
            ("Lệnh xác thực AUTH LOGIN", f"tcp.port in (25, 465, 587) && smtp.req.command == \"AUTH\"")
        ]
        display_wireshark_panel(
            console,
            GLOBAL_PCAP_FILE,
            filters,
            is_tls=is_tls,
            sort_tip="Click tiêu đề cột No. để xem: EHLO → STARTTLS (hoặc SMTPS) → AUTH LOGIN → MAIL FROM → DATA → 250 OK: queued.",
            title=f"BẰNG CHỨNG GÓI TIN WIRESHARK SMTP / SMTPS (PORT {port})"
        )
    except Exception as e:
        print(f"  [-] Lỗi phiên SMTP: {e}")
    finally:
        try: sock_to_use.close()
        except: pass
        try: conn.close()
        except: pass
        print("\n" + "=" * 80)
        print("  [INFO] ĐÃ HOÀN TẤT PHIÊN KẾT NỐI SMTP TỪ CAMERA.")
        print(f"  [INFO] MÁY CHỦ VẪN ĐANG TIẾP TỤC LẮNG NGHE TRÊN CÁC CỔNG TCP: {', '.join(map(str, SMTP_PORTS))}")
        print("         Bạn có thể bấm [Test] tiếp trên Camera bất kỳ lúc nào.")
        print("         (Máy chủ duy trì liên tục, chỉ dừng khi bạn nhấn Ctrl+C)")
        print("=" * 80 + "\n")

def accept_loop(sock, port):
    while True:
        try:
            c, a = sock.accept()
            t = threading.Thread(target=handle_smtp_client, args=(c, a, port), daemon=True)
            t.start()
        except Exception:
            break

def main():
    global GLOBAL_PCAP_FILE

    import receiver_daemon as rd
    if rd.is_daemon_running():
        rd.wait_and_analyze_service("smtp")
        return

    ensure_firewall_allowed(SMTP_PORTS)

    print("=" * 80)
    print("  TOOL 4: MÁY CHỦ BÓC TÁCH MẬT MÃ SMTP EMAIL CLIENT (AUTHMECH-5)")
    print(f"  Địa chỉ IP máy kiểm thử (Host IP) : {HOST_IP}")
    print(f"  Camera mục tiêu (DUT IP)          : {DUT_IP}")
    print("=" * 80)

    active_sockets = []
    status_table = Table(title="TRẠNG THÁI KHỞI ĐỘNG CỔNG MÁY CHỦ SMTP", expand=True)
    status_table.add_column("Cổng TCP", style="bold yellow", width=12, justify="center")
    status_table.add_column("Giao thức / Dịch vụ", style="bold cyan", width=30)
    status_table.add_column("Trạng thái Lắng nghe", justify="center")
    status_table.add_column("Ghi chú kỹ thuật", style="dim")

    for port in sorted(set(SMTP_PORTS)):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("0.0.0.0", port))
            s.listen(10)
            active_sockets.append((s, port))
            desc = "SMTPS (Direct TLS)" if port == 465 else ("SMTP STARTTLS" if port == 587 else "SMTP Standard")
            status_table.add_row(
                str(port),
                desc,
                "[bold green][OK] LISTENING[/bold green]",
                "Sẵn sàng nhận gói tin từ Camera"
            )
        except PermissionError:
            status_table.add_row(str(port), "SMTP Server", "[bold red][FAIL] PERMISSION DENIED[/bold red]", "Yêu cầu chạy với sudo")
        except OSError as e:
            status_table.add_row(str(port), "SMTP Server", "[bold red][FAIL] ADDRESS IN USE[/bold red]", str(e))

    console.print(status_table)

    if not active_sockets:
        console.print("\n[bold red][FAIL] KHÔNG THỂ MỞ BẤT KỲ CỔNG SMTP NÀO! Vui lòng kiểm tra quyền root.[/bold red]")
        sys.exit(1)

    active_ips = get_active_host_ips()
    primary_ip = active_ips[0][0] if active_ips else HOST_IP
    ip_list_str = ", ".join([f"{ip} ({dev})" for ip, dev in active_ips])

    print(f"\n[!] HƯỚNG DẪN CẤU HÌNH TRÊN CAMERA:")
    print(f"    1. Vào mục       : Settings -> Network Settings -> Advanced -> Email")
    print(f"    2. SMTP Server   : {primary_ip} (hoặc IP card nối với camera: {ip_list_str})")
    print(f"    3. SMTP Port     : 465, 587 hoặc 25 (Máy chủ tự thích ứng thông minh trên cả 3 cổng)")
    print(f"    4. SSL/TLS       : Tự do BẬT (SSL/TLS) hoặc TẮT (Bản rõ) - máy chủ đều tự động nhận diện!")
    print(f"    5. Authentication: Bật ON (username/password bất kỳ)")
    print(f"    6. Bấm [Apply], sau đó bấm [Test] ở dòng Recipient 1!\n")

    bpf_ports = " or ".join([f"tcp port {p}" for _, p in active_sockets])
    pcap_proc, GLOBAL_PCAP_FILE = start_pcap_capture(DUT_IP, bpf_ports, prefix="smtp_audit", net_iface="any")
    if GLOBAL_PCAP_FILE:
        print(f"[*] Đang tự động bắt gói tin PCAP vào: {GLOBAL_PCAP_FILE}")

    for s, port in active_sockets:
        t = threading.Thread(target=accept_loop, args=(s, port), daemon=True)
        t.start()

    console.print("\n[bold green][+] MÁY CHỦ SMTP ĐANG LẮNG NGHE! Bấm nút [Test] trên camera ngay bây giờ...[/bold green]")
    console.print("[dim](Nhấn Ctrl+C để kết thúc phiên)[/dim]\n")

    try:
        while True:
            threading.Event().wait(1.0)
    except KeyboardInterrupt:
        print("\n[*] Đã dừng máy chủ SMTP.")
    finally:
        for s, _ in active_sockets:
            try: s.close()
            except: pass
        stop_pcap_capture(pcap_proc)

if __name__ == '__main__':
    main()
