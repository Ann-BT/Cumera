#!/usr/bin/env python3
"""
TOOL 6: MÁY CHỦ THU NHẬN ALARM SERVER WEBHOOK (AUTHMECH-8)
Tiêu chuẩn: QCVN 11:2026/BCA (Yêu cầu 2.1.3 & Phụ lục IXIT AuthMech-8)
Chức năng: Lắng nghe HTTP (8088) và HTTPS (8443), bóc tách HTTP Authorization header và TLS 1.3.
Author: Merlin / Antigravity
"""

import socket
import ssl
import sys
import threading
import json
import os
import tempfile
import datetime
import subprocess
from rich.console import Console
from rich.table import Table
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec

sys.stdout.reconfigure(encoding='utf-8')
console = Console()

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pcap_recorder import start_pcap_capture, stop_pcap_capture, display_wireshark_panel, enable_ssl_keylog
from receiver_daemon import get_active_host_ips, SSL_SERVER_CTX
from toolkit_config import CONF_PATH, detect_host_network, get_service_ports, get_target_info, load_config

config = load_config()
DUT_IP = get_target_info(config)["ip"]
_, HOST_IP = detect_host_network(DUT_IP, config)
_sp = get_service_ports(config)
PORT_HTTP = int(_sp["alarm_receiver_http"])
PORT_HTTPS = int(_sp["alarm_receiver_https"])
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

# Dùng chung SSL Context toàn diện chuẩn QCVN 11 từ receiver_daemon (Đầy đủ SAN IP/DNS, SECLEVEL=0, mọi TLS)
ssl_ctx = SSL_SERVER_CTX

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
    print(f"  [+] BẮT ĐƯỢC GÓI TIN ALARM SERVER TỪ CAMERA: {addr[0]}:{addr[1]} ({proto})")
    print("=" * 80)
    sock = None
    try:
        sock = ssl_ctx.wrap_socket(conn, server_side=True) if is_ssl else conn
        if is_ssl:
            c_info = sock.cipher()
            print(f"  • Bắt tay TLS thành công: Version {sock.version()}, Cipher {c_info[0]}")

        # Đọc trọn vẹn HTTP Header
        buf = b""
        sock.settimeout(10.0)
        while b"\r\n\r\n" not in buf and b"\n\n" not in buf:
            chunk = sock.recv(2048)
            if not chunk:
                break
            buf += chunk

        if not buf:
            return

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

        # Đọc trọn vẹn body theo Content-Length để tránh tình trạng TCP RST
        while len(body_bytes) < content_length:
            needed = content_length - len(body_bytes)
            chunk = sock.recv(min(needed, 8192))
            if not chunk:
                break
            body_bytes += chunk

        if body_bytes:
            body_preview = body_bytes[:200].decode('utf-8', errors='ignore')
            print(f"      | Payload ({len(body_bytes)} bytes, {content_type or 'unknown'}): {body_preview}")

        # Phản hồi 200 OK chuẩn JSON
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

        filters = [
            ("Toàn bộ lưu lượng Alarm Webhook", f"tcp.port in ({PORT_HTTP}, {PORT_HTTPS})"),
            ("Webhook HTTP POST & Máy chủ 200 OK", f"tcp.port == {PORT_HTTP} && (http.request.method == \"POST\" || http.response.code == 200)"),
            ("Tiêu đề Authorization xác thực sự kiện", f"tcp.port in ({PORT_HTTP}, {PORT_HTTPS}) && http.authorization"),
            ("Webhook HTTPS qua bắt tay TLS 1.3", f"tcp.port == {PORT_HTTPS} && (tls.handshake.type == 1 || tls.handshake.type == 2)"),
            ("Webhook HTTPS sau giải mã TLS", "http.request.uri contains \"alarm\"")
        ]
        display_wireshark_panel(
            console,
            GLOBAL_PCAP_FILE,
            filters,
            is_tls=is_ssl,
            sort_tip="Click tiêu đề cột No. hoặc Time để xem: Gói tin POST /alarm từ camera gửi tới kèm trường Authorization và phản hồi 200 OK của máy chủ.",
            title=f"BẰNG CHỨNG GÓI TIN WIRESHARK ALARM WEBHOOK ({proto} - PORT {addr[1]})"
        )
    except Exception as e:
        print(f"  [-] Lỗi: {e}")
    finally:
        if sock:
            try: sock.close()
            except: pass
        try: conn.close()
        except: pass
        print("\n" + "=" * 80)
        print("  [INFO] ĐÃ HOÀN TẤT PHIÊN KẾT NỐI ALARM WEBHOOK TỪ CAMERA.")
        print(f"  [INFO] MÁY CHỦ VẪN ĐANG TIẾP TỤC LẮNG NGHE TRÊN CỔNG TCP: {PORT_HTTP} & {PORT_HTTPS}")
        print("         Bạn có thể bấm [Test] tiếp trên Camera bất kỳ lúc nào.")
        print("         (Máy chủ duy trì liên tục, chỉ dừng khi bạn nhấn Ctrl+C)")
        print("=" * 80 + "\n")

def accept_loop(sock, is_ssl):
    while True:
        try:
            c, a = sock.accept()
            t = threading.Thread(target=handle_alarm_client, args=(c, a, is_ssl), daemon=True)
            t.start()
        except Exception:
            break

def main():
    global GLOBAL_PCAP_FILE

    import receiver_daemon as rd
    if rd.is_daemon_running():
        rd.wait_and_analyze_service("alarm")
        return

    ensure_firewall_allowed([PORT_HTTP, PORT_HTTPS])

    print("=" * 80)
    print("  TOOL 6: MÁY CHỦ THU NHẬN ALARM SERVER WEBHOOK (AUTHMECH-8)")
    print(f"  Địa chỉ IP máy kiểm thử (Host IP) : {HOST_IP}")
    print(f"  Camera mục tiêu (DUT IP)          : {DUT_IP}")
    print("=" * 80)

    active_sockets = []
    status_table = Table(title="TRẠNG THÁI KHỞI ĐỘNG CỔNG ALARM SERVER", expand=True)
    status_table.add_column("Cổng TCP", style="bold yellow", width=12, justify="center")
    status_table.add_column("Giao thức / Dịch vụ", style="bold cyan", width=30)
    status_table.add_column("Trạng thái Lắng nghe", justify="center")
    status_table.add_column("Ghi chú kỹ thuật", style="dim")

    for port, is_ssl in [(PORT_HTTP, False), (PORT_HTTPS, True)]:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("0.0.0.0", port))
            s.listen(10)
            active_sockets.append((s, is_ssl))
            proto = "Alarm HTTPS (TLS 1.3 / ECDSA)" if is_ssl else "Alarm HTTP Webhook (Bản rõ)"
            status_table.add_row(str(port), proto, "[bold green][OK] LISTENING[/bold green]", "Sẵn sàng nhận sự kiện cảnh báo")
        except Exception as e:
            status_table.add_row(str(port), "Alarm Server", "[bold red][FAIL] ERROR[/bold red]", str(e))

    console.print(status_table)

    if not active_sockets:
        console.print("\n[bold red][FAIL] KHÔNG THỂ MỞ CỔNG ALARM SERVER! Vui lòng kiểm tra lại cổng đang bị chiếm.[/bold red]")
        sys.exit(1)

    active_ips = get_active_host_ips()
    primary_ip = active_ips[0][0] if active_ips else HOST_IP
    ip_list_str = ", ".join([f"{ip} ({dev})" for ip, dev in active_ips])

    print(f"\n[!] HƯỚNG DẪN CẤU HÌNH TRÊN CAMERA:")
    print(f"    1. Vào mục       : Settings -> Alarm Server -> Bấm Add")
    print(f"    2. Host IP/Domain: {primary_ip} (hoặc IP card nối với camera: {ip_list_str})")
    print(f"    3. URL            : /alarm")
    print(f"    4. Protocol       : Chọn HTTP (Port {PORT_HTTP}) hoặc HTTPS (Port {PORT_HTTPS})")
    print(f"    5. Bấm [Save], sau đó ở danh sách bên ngoài bấm [Test]!\n")

    pcap_proc, GLOBAL_PCAP_FILE = start_pcap_capture(
        DUT_IP,
        f"tcp port {PORT_HTTP} or tcp port {PORT_HTTPS}",
        prefix="alarm_webhook_audit",
        net_iface="any"
    )
    if GLOBAL_PCAP_FILE:
        print(f"[*] Đang tự động bắt gói tin PCAP vào: {GLOBAL_PCAP_FILE}")

    for s, is_ssl in active_sockets:
        threading.Thread(target=accept_loop, args=(s, is_ssl), daemon=True).start()

    console.print("\n[bold green][+] MÁY CHỦ ALARM SERVER ĐANG LẮNG NGHE! Bấm nút [Test] trên camera ngay bây giờ...[/bold green]")
    console.print("[dim](Nhấn Ctrl+C để kết thúc phiên)[/dim]\n")

    try:
        while True:
            threading.Event().wait(1.0)
    except KeyboardInterrupt:
        print("\n[*] Đã dừng máy chủ Alarm Server.")
    finally:
        for s, _ in active_sockets:
            try: s.close()
            except: pass
        stop_pcap_capture(pcap_proc)

if __name__ == '__main__':
    main()
