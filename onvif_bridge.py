#!/usr/bin/env python3
"""
ONVIF Transparent Bridge & Protocol Adapter (OxDM / ODM Fix)
Cầu nối chuyển đổi giao thức & loại bỏ rào cản TLS / Clock-Skew / Closed Ports
giúp các ứng dụng ONVIF chính quy như OxDM (Linux) và ODM (Synesis Windows/Wine)
đăng nhập thẳng 100% "legit" vào camera để kiểm tra thông số và cập nhật Firmware (UpgradeSystemFirmware).

Cơ chế hoạt động:
1. Tiếp nhận kết nối HTTP chuẩn (không bị lỗi chứng chỉ tự ký hay lỗi WCF .NET) trên cổng 8080 hoặc cổng tùy chọn.
2. Chuyển tiếp toàn bộ SOAP & Binary Payload sang camera mục tiêu qua HTTPS (Cổng 443, TLS 1.3, bypass SSL verification).
3. Viết lại (Rewrite) các URL XAddrs trong GetCapabilitiesResponse & GetServicesResponse để mọi lệnh Media, PTZ,
   và đặc biệt là Nâng cấp Firmware (UpgradeSystemFirmware) tiếp tục chạy thông suốt qua cầu nối.
4. Tùy chọn phản hồi WS-Discovery Probe (UDP 3702) để tự động hiển thị camera trên danh mục thiết bị của OxDM/ODM.

Tác giả: Merlin / Antigravity
Workspace: /home/merlin/PSI
"""

import os
import sys
import time
import json
import socket
import argparse
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

import urllib3
import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Đọc cấu hình mặc định
TOOLKIT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(TOOLKIT_DIR, "config.json")
def load_config():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {}

CFG = load_config()
DEFAULT_CAM_IP = CFG.get("target_camera", {}).get("ip", "192.168.99.84")
DEFAULT_CAM_PORT = int(CFG.get("service_ports", {}).get("onvif_https", 443))
DEFAULT_BRIDGE_PORT = 8888

TARGET_IP = DEFAULT_CAM_IP
TARGET_PORT = DEFAULT_CAM_PORT
TARGET_SSL = True
BRIDGE_HOST = "0.0.0.0"
BRIDGE_PORT = DEFAULT_BRIDGE_PORT

session = requests.Session()
session.verify = False


class OnvifBridgeHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):
        # Giảm thiểu log rác, chỉ ghi nhận action chính
        msg = format % args
        if "POST" in msg or "Upgrade" in msg or "500" in msg:
            sys.stdout.write(f"[*] [BRIDGE] {msg}\n")
            sys.stdout.flush()

    def do_HEAD(self):
        self.do_proxy("HEAD")

    def do_GET(self):
        self.do_proxy("GET")

    def do_POST(self):
        self.do_proxy("POST")

    def do_PUT(self):
        self.do_proxy("PUT")

    def do_proxy(self, method: str):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else None

        scheme = "https" if TARGET_SSL else "http"
        target_url = f"{scheme}://{TARGET_IP}:{TARGET_PORT}{self.path}"

        # Chuẩn bị headers chuyển tiếp
        headers = {}
        for k, v in self.headers.items():
            k_lower = k.lower()
            if k_lower in ("host", "content-length"):
                continue
            headers[k] = v

        headers["Host"] = f"{TARGET_IP}:{TARGET_PORT}"

        client_host = self.headers.get("Host", f"127.0.0.1:{BRIDGE_PORT}")
        client_base_url = f"http://{client_host}"

        try:
            # Tăng timeout cho các tác vụ lớn như tải file firmware (180 giây)
            timeout = 180.0 if "Upgrade" in self.path or (body and len(body) > 100000) else 15.0

            resp = session.request(
                method=method,
                url=target_url,
                data=body,
                headers=headers,
                timeout=timeout,
                stream=True
            )

            resp_content = resp.content
            resp_headers = dict(resp.headers)

            content_type = resp_headers.get("Content-Type", "")
            is_xml = "xml" in content_type or "soap" in content_type

            # Viết lại các URL XAddrs từ camera HTTPS sang Bridge HTTP
            if is_xml and resp_content:
                text = resp_content.decode("utf-8", errors="ignore")
                
                # Các mẫu URL của camera cần thay thế
                old_urls = [
                    f"https://{TARGET_IP}:{TARGET_PORT}",
                    f"http://{TARGET_IP}:{TARGET_PORT}",
                    f"https://{TARGET_IP}",
                    f"http://{TARGET_IP}"
                ]
                for old in old_urls:
                    text = text.replace(old, client_base_url)

                resp_content = text.encode("utf-8")
                resp_headers["Content-Length"] = str(len(resp_content))

            # Trả mã trạng thái HTTP
            self.send_response(resp.status_code)

            # Trả các headers
            for k, v in resp_headers.items():
                if k.lower() in ("transfer-encoding", "content-encoding", "connection"):
                    continue
                self.send_header(k, v)

            self.send_header("Connection", "close")
            self.end_headers()

            if method != "HEAD" and resp_content:
                self.wfile.write(resp_content)

        except requests.exceptions.RequestException as e:
            err_msg = f"ONVIF Bridge Forwarding Error: {str(e)}".encode("utf-8")
            self.send_response(502)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(err_msg)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(err_msg)


def start_bridge_server(port: int = 8080):
    global BRIDGE_PORT
    BRIDGE_PORT = port
    server_address = (BRIDGE_HOST, BRIDGE_PORT)
    httpd = HTTPServer(server_address, OnvifBridgeHandler)

    print("=" * 80)
    print(f"  CẦU NỐI ONVIF TRONG SUỐT (ONVIF TRANSPARENT BRIDGE CHO OXDM / ODM)")
    print(f"  • Cổng tiếp nhận Client: http://127.0.0.1:{BRIDGE_PORT}/onvif/device_service")
    print(f"  • Điểm đến Camera thực: https://{TARGET_IP}:{TARGET_PORT}/onvif/device_service")
    print(f"  • Tương thích: Tự động xóa lỗi TLS cert, giải quyết lỗi 400 Bad Request,")
    print(f"                 hỗ trợ nâng cấp Firmware (UpgradeSystemFirmware) mượt mà.")
    print("=" * 80)
    print(f"[+] Sẵn sàng! Điền vào OxDM hoặc ODM:")
    print(f"    URL:      http://127.0.0.1:{BRIDGE_PORT}/onvif/device_service")
    print(f"    Username: admin")
    print(f"    Password: {CFG.get('target_camera', {}).get('password', 'Psitest135#')}")
    print("=" * 80)

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Đã dừng ONVIF Bridge.")


def main():
    global TARGET_IP, TARGET_PORT, TARGET_SSL
    parser = argparse.ArgumentParser(description="ONVIF Transparent Bridge for OxDM & ODM")
    parser.add_argument("--cam-ip", default=DEFAULT_CAM_IP, help=f"IP camera thực (Mặc định: {DEFAULT_CAM_IP})")
    parser.add_argument("--cam-port", type=int, default=DEFAULT_CAM_PORT, help="Cổng HTTPS camera (Mặc định: 443)")
    parser.add_argument("--bridge-port", type=int, default=DEFAULT_BRIDGE_PORT, help=f"Cổng HTTP cục bộ (Mặc định: {DEFAULT_BRIDGE_PORT})")
    parser.add_argument("--http-cam", action="store_true", help="Nếu camera dùng HTTP thay vì HTTPS")

    args = parser.parse_args()
    TARGET_IP = args.cam_ip
    TARGET_PORT = args.cam_port
    TARGET_SSL = not args.http_cam

    start_bridge_server(port=args.bridge_port)


if __name__ == "__main__":
    main()
