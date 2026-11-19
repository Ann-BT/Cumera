#!/usr/bin/env python3
"""
ONVIF Device Manager & Auditor (OxDM-Linux)
Công cụ đăng nhập, quản lý, chẩn đoán và trích xuất thông tin camera qua chuẩn ONVIF SOAP.
Tương thích toàn diện với camera HTTPS-only, chứng chỉ tự ký, lệch giờ (clock skew),
và các thiết bị mà OxDM / ODM truyền thống trên Windows không đăng nhập được.

Tác giả: Merlin / Antigravity
Workspace: /home/merlin/PSI
"""

import os
import sys
import time
import json
import socket
import base64
import hashlib
import datetime
import argparse
import subprocess
import threading
import uuid
import re
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Tuple, Any

import urllib3
import requests
from requests.auth import HTTPDigestAuth, HTTPBasicAuth

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Kiểm tra thư viện rich
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.prompt import Prompt, Confirm
    from rich.syntax import Syntax
    from rich import print as rprint
    console = Console()
except ImportError:
    console = None

# Thư mục lưu snapshot & capture
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
SNAPSHOT_DIR = os.path.join(CURRENT_DIR, "snapshots")
os.makedirs(SNAPSHOT_DIR, exist_ok=True)

# Tải cấu hình mặc định từ config.json nếu có
DEFAULT_CONFIG_PATH = os.path.join(CURRENT_DIR, "config.json")
def load_default_config() -> dict:
    if os.path.exists(DEFAULT_CONFIG_PATH):
        try:
            with open(DEFAULT_CONFIG_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {}

CONF = load_default_config()
TARGET_CAM = CONF.get("target_camera", {})
DEFAULT_IP = TARGET_CAM.get("ip", "192.168.99.84")
DEFAULT_USER = TARGET_CAM.get("username", "admin")
DEFAULT_PASS = TARGET_CAM.get("password", "Psitest135#")
DEFAULT_PORTS = CONF.get("service_ports", {})
DEFAULT_HTTP_PORT = int(DEFAULT_PORTS.get("onvif_http", 80))
DEFAULT_HTTPS_PORT = int(DEFAULT_PORTS.get("onvif_https", 443))


class ONVIFClient:
    """
    ONVIF Client toàn diện hỗ trợ:
    - Tự động dò endpoint HTTP / HTTPS.
    - Bỏ qua kiểm tra chứng chỉ SSL tự ký (giải quyết lỗi crash của OxDM/ODM WCF).
    - Đồng bộ đồng hồ camera (GetSystemDateAndTime) trước khi tạo WS-Security digest.
    - Hỗ trợ đa dạng phương thức xác thực: WS-Security SHA-1, SHA-256, PasswordText, HTTP Digest, HTTP Basic.
    """

    def __init__(self, ip: str, port: Optional[int] = None, username: str = "admin", password: str = "", timeout: float = 6.0):
        self.ip = ip
        self.port = port
        self.username = username
        self.password = password
        self.timeout = timeout

        self.is_https = True
        self.active_port = 443
        self.device_service_url = ""
        self.auth_mode = "wsse_sha1"
        self.time_offset_sec = 0.0  # Chênh lệch camera - local (giây)

        self.device_info: Dict[str, str] = {}
        self.system_time_info: Dict[str, Any] = {}
        self.capabilities: Dict[str, str] = {}
        self.network_interfaces: List[Dict[str, Any]] = []
        self.gateway: str = ""
        self.dns_servers: List[str] = []
        self.ntp_servers: List[str] = []
        self.profiles: List[Dict[str, Any]] = []
        self.users: List[Dict[str, str]] = []
        self.session = requests.Session()
        self.session.verify = False

    def probe_and_connect(self) -> Tuple[bool, str]:
        """
        Dò tìm cổng ONVIF khả dụng (HTTPS 443 hoặc HTTP 80 hoặc cổng tùy chọn),
        kiểm tra dịch vụ GetSystemDateAndTime để tính clock skew.
        """
        ports_to_try = []
        if self.port:
            # Thử cả HTTPS và HTTP trên cổng chỉ định
            ports_to_try.extend([(self.port, True), (self.port, False)])
        else:
            ports_to_try.extend([
                (443, True),
                (80, False),
                (8080, False),
                (8000, False),
                (8899, False),
                (8443, True),
                (20001, False)
            ])

        for port, is_ssl in ports_to_try:
            scheme = "https" if is_ssl else "http"
            url = f"{scheme}://{self.ip}:{port}/onvif/device_service"
            try:
                # Gửi GetSystemDateAndTime (không yêu cầu chứng thực theo chuẩn ONVIF)
                body = """<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
  <soap:Body><tds:GetSystemDateAndTime /></soap:Body>
</soap:Envelope>"""
                headers = {
                    "Content-Type": 'application/soap+xml; charset=utf-8; action="http://www.onvif.org/ver10/device/wsdl/GetSystemDateAndTime"',
                    "Connection": "close"
                }
                resp = self.session.post(url, data=body.encode("utf-8"), headers=headers, timeout=2.5)
                if resp.status_code == 200 and ("GetSystemDateAndTimeResponse" in resp.text or "SystemDateAndTime" in resp.text):
                    self.is_https = is_ssl
                    self.active_port = port
                    self.device_service_url = url
                    self._parse_system_date_and_time(resp.text)
                    return True, f"Tìm thấy dịch vụ ONVIF tại: {url}"
            except Exception:
                continue

        return False, f"Không thể kết nối đến dịch vụ ONVIF trên {self.ip} qua các cổng chuẩn (80, 443, 8080, 8899)"

    def _parse_system_date_and_time(self, xml_text: str):
        """Phân tích thời gian của camera và tính chênh lệch so với đồng hồ máy tính."""
        try:
            # Lấy thông tin UTC
            year = re.search(r"<tt:UTCDateTime>.*?<tt:Date>.*?<tt:Year>(\d+)</tt:Year>.*?<tt:Month>(\d+)</tt:Month>.*?<tt:Day>(\d+)</tt:Day>.*?<tt:Time>.*?<tt:Hour>(\d+)</tt:Hour>.*?<tt:Minute>(\d+)</tt:Minute>.*?<tt:Second>(\d+)</tt:Second>", xml_text, re.DOTALL)
            tz_m = re.search(r"<tt:TimeZone>.*?<tt:TZ>([^<]+)</tt:TZ>", xml_text, re.DOTALL)
            dt_type_m = re.search(r"<tt:DateTimeType>([^<]+)</tt:DateTimeType>", xml_text)

            self.system_time_info["timezone"] = tz_m.group(1) if tz_m else "N/A"
            self.system_time_info["type"] = dt_type_m.group(1) if dt_type_m else "N/A"

            if year:
                cam_utc = datetime.datetime(
                    year=int(year.group(1)),
                    month=int(year.group(2)),
                    day=int(year.group(3)),
                    hour=int(year.group(4)),
                    minute=int(year.group(5)),
                    second=int(year.group(6)),
                    tzinfo=datetime.timezone.utc
                )
                local_utc = datetime.datetime.now(datetime.timezone.utc)
                self.time_offset_sec = (cam_utc - local_utc).total_seconds()
                self.system_time_info["camera_utc"] = cam_utc.isoformat()
                self.system_time_info["local_utc"] = local_utc.isoformat()
                self.system_time_info["offset_seconds"] = self.time_offset_sec
            else:
                self.time_offset_sec = 0.0
        except Exception:
            self.time_offset_sec = 0.0

    def _build_ws_security_header(self, mode: str = "wsse_sha1") -> str:
        """Tạo header WS-Security có bù trừ lệch giờ (clock skew compensation)."""
        # Áp dụng chênh lệch giờ camera để tránh lỗi NotAuthorized do lệch đồng hồ
        adjusted_time = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=self.time_offset_sec)
        created = adjusted_time.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        nonce_raw = os.urandom(16)
        nonce_b64 = base64.b64encode(nonce_raw).decode("ascii")

        if mode == "wsse_text":
            pass_type = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText"
            pass_val = self.password
        elif mode == "wsse_sha256":
            pass_type = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest"
            to_hash = nonce_raw + created.encode("utf-8") + self.password.encode("utf-8")
            pass_val = base64.b64encode(hashlib.sha256(to_hash).digest()).decode("ascii")
        else:  # OASIS WSS 1.0 SHA-1 (ONVIF standard)
            pass_type = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest"
            to_hash = nonce_raw + created.encode("utf-8") + self.password.encode("utf-8")
            pass_val = base64.b64encode(hashlib.sha1(to_hash).digest()).decode("ascii")

        return f"""
    <wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
                   xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
      <wsse:UsernameToken>
        <wsse:Username>{self.username}</wsse:Username>
        <wsse:Password Type="{pass_type}">{pass_val}</wsse:Password>
        <wsse:Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">{nonce_b64}</wsse:Nonce>
        <wsu:Created>{created}</wsu:Created>
      </wsse:UsernameToken>
    </wsse:Security>"""

    def send_soap(self, service_url: str, action: str, body_xml: str, auth_mode: Optional[str] = None) -> Tuple[int, str]:
        """Gửi bản tin SOAP ONVIF chuẩn với bảo vệ header & fallback."""
        mode = auth_mode or self.auth_mode
        wsse_hdr = ""
        req_auth = None

        if mode in ("wsse_sha1", "wsse_sha256", "wsse_text"):
            wsse_hdr = self._build_ws_security_header(mode)
        elif mode == "http_digest":
            req_auth = HTTPDigestAuth(self.username, self.password)
        elif mode == "http_basic":
            req_auth = HTTPBasicAuth(self.username, self.password)

        soap_env = f"""<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
               xmlns:tds="http://www.onvif.org/ver10/device/wsdl"
               xmlns:trt="http://www.onvif.org/ver10/media/wsdl"
               xmlns:timg="http://www.onvif.org/ver20/imaging/wsdl"
               xmlns:tptz="http://www.onvif.org/ver20/ptz/wsdl"
               xmlns:tt="http://www.onvif.org/ver10/schema">
  <soap:Header>{wsse_hdr}</soap:Header>
  <soap:Body>{body_xml}</soap:Body>
</soap:Envelope>"""

        headers = {
            "Content-Type": f'application/soap+xml; charset=utf-8; action="{action}"',
            "User-Agent": "OxDM-Linux/1.0 ONVIF Client",
            "Connection": "close"
        }

        resp = self.session.post(
            service_url,
            data=soap_env.encode("utf-8"),
            headers=headers,
            auth=req_auth,
            timeout=self.timeout
        )
        return resp.status_code, resp.text

    def authenticate(self) -> Tuple[bool, str]:
        """
        Thực hiện xác thực với camera bằng cách gửi GetDeviceInformation
        qua các phương thức xác thực khác nhau cho tới khi thành công.
        """
        modes_to_test = ["wsse_sha1", "wsse_text", "wsse_sha256", "http_digest", "http_basic"]
        action = "http://www.onvif.org/ver10/device/wsdl/GetDeviceInformation"
        body = "<tds:GetDeviceInformation />"

        last_error = ""
        for mode in modes_to_test:
            try:
                code, text = self.send_soap(self.device_service_url, action, body, auth_mode=mode)
                if code == 200 and "GetDeviceInformationResponse" in text:
                    self.auth_mode = mode
                    self._parse_device_information(text)
                    return True, f"Xác thực thành công bằng cơ chế: {mode.upper()}"
                elif "NotAuthorized" in text or "FailedAuthentication" in text or code == 401 or code == 400:
                    last_error = f"Từ chối quyền (Sai tài khoản/mật khẩu hoặc cơ chế {mode} không được hỗ trợ)"
                elif code in (403, 429):
                    return False, f"Camera đang KHÓA TÀI KHOẢN (HTTP {code} Lockout) do thử sai nhiều lần!"
            except Exception as e:
                last_error = f"Lỗi kết nối khi thử {mode}: {str(e)}"

        return False, last_error or "Xác thực thất bại với camera"

    def _parse_device_information(self, xml_text: str):
        """Trích xuất thông tin thiết bị (Manufacturer, Model, Firmware, Serial, HardwareId)."""
        tags = ["Manufacturer", "Model", "FirmwareVersion", "SerialNumber", "HardwareId"]
        for tag in tags:
            m = re.search(rf"<[^:>]*:{tag}>([^<]+)</[^:>]*:{tag}>", xml_text)
            self.device_info[tag] = m.group(1).strip() if m else "N/A"

    def fetch_capabilities(self) -> Dict[str, str]:
        """Lấy danh sách các service endpoints (Media, PTZ, Events, Imaging, Analytics)."""
        action = "http://www.onvif.org/ver10/device/wsdl/GetCapabilities"
        body = "<tds:GetCapabilities><tds:Category>All</tds:Category></tds:GetCapabilities>"
        code, text = self.send_soap(self.device_service_url, action, body)
        if code == 200:
            # Tìm các thẻ con trong Capabilities có chứa XAddr
            # Device, Media, Events, Imaging, PTZ, Analytics, DeviceIO
            services = ["Device", "Media", "Events", "Imaging", "PTZ", "Analytics", "DeviceIO"]
            for s in services:
                # Regex tìm block <tt:Media> ... <tt:XAddr>...</tt:XAddr>
                m = re.search(rf"<[^:>]*:{s}>.*?<[^:>]*:XAddr>([^<]+)</[^:>]*:XAddr>", text, re.DOTALL)
                if m:
                    self.capabilities[s] = m.group(1).strip()
                else:
                    # fallback tìm XAddr chung
                    pass
        return self.capabilities

    def get_service_endpoint(self, service_name: str) -> str:
        """Lấy URL endpoint của service, nếu không có thì suy luận từ device_service_url."""
        if service_name in self.capabilities:
            return self.capabilities[service_name]
        # Suy luận đường dẫn mặc định
        base = self.device_service_url.rsplit("/", 1)[0]
        service_map = {
            "Media": f"{base}/media_service",
            "PTZ": f"{base}/ptz_service",
            "Events": f"{base}/event_service",
            "Imaging": f"{base}/imaging_service",
            "Analytics": f"{base}/analytics_service",
            "DeviceIO": f"{base}/deviceio_service"
        }
        return service_map.get(service_name, self.device_service_url)

    def fetch_network_interfaces(self) -> List[Dict[str, Any]]:
        """Lấy thông tin card mạng camera (IP, MAC, MTU, Subnet, DHCP)."""
        action = "http://www.onvif.org/ver10/device/wsdl/GetNetworkInterfaces"
        body = "<tds:GetNetworkInterfaces />"
        code, text = self.send_soap(self.device_service_url, action, body)
        interfaces = []
        if code == 200:
            blocks = re.findall(r"<[^:>]*:NetworkInterfaces\b[^>]*>.*?</[^:>]*:NetworkInterfaces>", text, re.DOTALL)
            for b in blocks:
                name_m = re.search(r"<[^:>]*:Name>([^<]+)</[^:>]*:Name>", b)
                mac_m = re.search(r"<[^:>]*:HwAddress>([^<]+)</[^:>]*:HwAddress>", b)
                mtu_m = re.search(r"<[^:>]*:MTU>([^<]+)</[^:>]*:MTU>", b)
                ip_m = re.search(r"<[^:>]*:FromDHCP>.*?<[^:>]*:Address>([^<]+)</[^:>]*:Address>|<[^:>]*:Manual>.*?<[^:>]*:Address>([^<]+)</[^:>]*:Address>", b, re.DOTALL)
                dhcp_m = re.search(r"<[^:>]*:DHCP>([^<]+)</[^:>]*:DHCP>", b)

                ip_val = (ip_m.group(1) or ip_m.group(2)) if ip_m else self.ip
                interfaces.append({
                    "name": name_m.group(1) if name_m else "eth0",
                    "mac": mac_m.group(1) if mac_m else "N/A",
                    "mtu": mtu_m.group(1) if mtu_m else "1500",
                    "ip": ip_val,
                    "dhcp": dhcp_m.group(1) if dhcp_m else "N/A"
                })
        self.network_interfaces = interfaces
        return interfaces

    def fetch_profiles(self) -> List[Dict[str, Any]]:
        """Lấy danh sách các Video Profiles & thông số Video Encoder, RTSP Stream URI & Snapshot URI."""
        media_url = self.get_service_endpoint("Media")
        action = "http://www.onvif.org/ver10/media/wsdl/GetProfiles"
        body = "<trt:GetProfiles />"
        code, text = self.send_soap(media_url, action, body)

        profiles = []
        if code == 200:
            profile_blocks = re.findall(r"<[^:>]*:Profiles\b[^>]*token=\"([^\"]+)\"[^>]*>(.*?)</[^:>]*:Profiles>", text, re.DOTALL)
            idx = 1
            for token, p_content in profile_blocks:
                name_m = re.search(r"<[^:>]*:Name>([^<]+)</[^:>]*:Name>", p_content)
                name = name_m.group(1).strip() if name_m else token

                # Trích xuất video encoder nhúng trực tiếp trong Profile
                enc_m = re.search(r"<[^:>]*:Encoding>([^<]+)</[^:>]*:Encoding>", p_content)
                w_m = re.search(r"<[^:>]*:Width>([^<]+)</[^:>]*:Width>", p_content)
                h_m = re.search(r"<[^:>]*:Height>([^<]+)</[^:>]*:Height>", p_content)
                fps_m = re.search(r"<[^:>]*:FrameRateLimit>([^<]+)</[^:>]*:FrameRateLimit>", p_content)
                bit_m = re.search(r"<[^:>]*:BitrateLimit>([^<]+)</[^:>]*:BitrateLimit>", p_content)

                w = w_m.group(1) if w_m else ""
                h = h_m.group(1) if h_m else ""
                resolution = f"{w}x{h}" if (w and h) else "N/A"
                fps = fps_m.group(1) if fps_m else "N/A"
                bitrate = f"{bit_m.group(1)} kbps" if bit_m else "N/A"
                encoding = enc_m.group(1) if enc_m else "H.264"

                stream_uri = self.fetch_stream_uri(token)
                snapshot_uri = self.fetch_snapshot_uri(token)

                auth_stream_uri = stream_uri
                if stream_uri.startswith("rtsp://") and "@" not in stream_uri:
                    auth_stream_uri = stream_uri.replace("rtsp://", f"rtsp://{self.username}:{self.password}@")

                profiles.append({
                    "index": idx,
                    "token": token,
                    "name": name,
                    "stream_uri": stream_uri,
                    "auth_stream_uri": auth_stream_uri,
                    "snapshot_uri": snapshot_uri,
                    "encoding": encoding,
                    "resolution": resolution,
                    "fps": fps,
                    "bitrate": bitrate
                })
                idx += 1

        self.profiles = profiles
        return profiles

    def fetch_video_encoders(self) -> Dict[str, Dict[str, str]]:
        """Lấy cấu hình chi tiết bộ mã hóa (Độ phân giải, fps, bitrate)."""
        media_url = self.get_service_endpoint("Media")
        action = "http://www.onvif.org/ver10/media/wsdl/GetVideoEncoderConfigurations"
        body = "<trt:GetVideoEncoderConfigurations />"
        code, text = self.send_soap(media_url, action, body)

        encoders = {}
        if code == 200:
            configs = re.findall(r"<[^:>]*:Configurations\b[^>]*token=\"([^\"]+)\"[^>]*>(.*?)</[^:>]*:Configurations>", text, re.DOTALL)
            for token, content in configs:
                enc_m = re.search(r"<[^:>]*:Encoding>([^<]+)</[^:>]*:Encoding>", content)
                w_m = re.search(r"<[^:>]*:Width>([^<]+)</[^:>]*:Width>", content)
                h_m = re.search(r"<[^:>]*:Height>([^<]+)</[^:>]*:Height>", content)
                fps_m = re.search(r"<[^:>]*:FrameRateLimit>([^<]+)</[^:>]*:FrameRateLimit>", content)
                bit_m = re.search(r"<[^:>]*:BitrateLimit>([^<]+)</[^:>]*:BitrateLimit>", content)

                w = w_m.group(1) if w_m else ""
                h = h_m.group(1) if h_m else ""
                res = f"{w}x{h}" if (w and h) else "N/A"

                encoders[token] = {
                    "encoding": enc_m.group(1) if enc_m else "H.264",
                    "resolution": res,
                    "fps": fps_m.group(1) if fps_m else "N/A",
                    "bitrate": f"{bit_m.group(1)} kbps" if bit_m else "N/A"
                }
        return encoders

    def fetch_stream_uri(self, profile_token: str) -> str:
        """Lấy RTSP Stream URI cho một Profile."""
        media_url = self.get_service_endpoint("Media")
        action = "http://www.onvif.org/ver10/media/wsdl/GetStreamUri"
        body = f"""<trt:GetStreamUri>
  <trt:StreamSetup>
    <tt:Stream>RTP-Unicast</tt:Stream>
    <tt:Transport><tt:Protocol>RTSP</tt:Protocol></tt:Transport>
  </trt:StreamSetup>
  <trt:ProfileToken>{profile_token}</trt:ProfileToken>
</trt:GetStreamUri>"""
        code, text = self.send_soap(media_url, action, body)
        if code == 200:
            m = re.search(r"<[^:>]*:Uri>([^<]+)</[^:>]*:Uri>", text)
            if m:
                return m.group(1).strip()
        return "N/A"

    def fetch_snapshot_uri(self, profile_token: str) -> str:
        """Lấy Snapshot URI cho một Profile."""
        media_url = self.get_service_endpoint("Media")
        action = "http://www.onvif.org/ver10/media/wsdl/GetSnapshotUri"
        body = f"""<trt:GetSnapshotUri>
  <trt:ProfileToken>{profile_token}</trt:ProfileToken>
</trt:GetSnapshotUri>"""
        code, text = self.send_soap(media_url, action, body)
        if code == 200:
            m = re.search(r"<[^:>]*:Uri>([^<]+)</[^:>]*:Uri>", text)
            if m:
                return m.group(1).strip()
        return "N/A"

    def capture_snapshot(self, profile_token: Optional[str] = None, output_path: Optional[str] = None) -> Tuple[bool, str, Optional[bytes]]:
        """Tải một ảnh Snapshot JPEG từ camera."""
        if not self.profiles:
            self.fetch_profiles()

        target_uri = None
        if profile_token:
            for p in self.profiles:
                if p["token"] == profile_token:
                    target_uri = p["snapshot_uri"]
                    break
        if not target_uri and self.profiles:
            target_uri = self.profiles[0]["snapshot_uri"]

        if not target_uri or target_uri == "N/A":
            return False, "Không tìm thấy Snapshot URI trên Profile này", None

        # Thử tải ảnh qua HTTP Digest Auth, sau đó thử Basic Auth
        auths = [
            HTTPDigestAuth(self.username, self.password),
            HTTPBasicAuth(self.username, self.password),
            None
        ]

        for auth in auths:
            try:
                resp = self.session.get(target_uri, auth=auth, timeout=6.0)
                if resp.status_code == 200 and resp.content.startswith(b"\xff\xd8"):  # JPEG magic bytes
                    save_file = output_path
                    if not save_file:
                        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                        save_file = os.path.join(SNAPSHOT_DIR, f"snapshot_{self.ip.replace('.', '_')}_{timestamp}.jpg")

                    with open(save_file, "wb") as f:
                        f.write(resp.content)
                    return True, save_file, resp.content
            except Exception:
                continue

        return False, f"Không thể tải ảnh snapshot từ: {target_uri}", None

    def fetch_users(self) -> List[Dict[str, str]]:
        """Lấy danh sách tài khoản người dùng ONVIF (GetUsers)."""
        action = "http://www.onvif.org/ver10/device/wsdl/GetUsers"
        body = "<tds:GetUsers />"
        code, text = self.send_soap(self.device_service_url, action, body)
        users = []
        if code == 200:
            user_blocks = re.findall(r"<[^:>]*:User\b[^>]*>.*?</[^:>]*:User>", text, re.DOTALL)
            for b in user_blocks:
                u_m = re.search(r"<[^:>]*:Username>([^<]+)</[^:>]*:Username>", b)
                lvl_m = re.search(r"<[^:>]*:UserLevel>([^<]+)</[^:>]*:UserLevel>", b)
                if u_m:
                    users.append({
                        "username": u_m.group(1).strip(),
                        "level": lvl_m.group(1).strip() if lvl_m else "User"
                    })
        self.users = users
        return users

    def launch_vlc_stream(self, profile_index: int = 1) -> Tuple[bool, str]:
        """Khởi chạy VLC hoặc ffplay với URL RTSP có nhúng tài khoản xác thực."""
        if not self.profiles:
            self.fetch_profiles()

        target_p = None
        for p in self.profiles:
            if p["index"] == profile_index:
                target_p = p
                break
        if not target_p and self.profiles:
            target_p = self.profiles[0]

        if not target_p or target_p["stream_uri"] == "N/A":
            return False, "Không có RTSP Stream khả dụng để phát"

        rtsp_url = target_p["auth_stream_uri"]

        # Kiểm tra trình phát khả dụng
        players = ["vlc", "cvlc", "ffplay", "mpv"]
        found_player = None
        for pl in players:
            if subprocess.run(["which", pl], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
                found_player = pl
                break

        if not found_player:
            return False, f"Không tìm thấy trình phát video (vlc, ffplay, mpv). URL RTSP: {rtsp_url}"

        cmd = [found_player]
        if found_player in ("vlc", "cvlc"):
            cmd.extend(["--network-caching=300", "--rtsp-tcp"])
        cmd.append(rtsp_url)

        subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True, f"Đã mở luồng {target_p['name']} bằng {found_player}: {rtsp_url}"

    def reboot(self) -> Tuple[bool, str]:
        """Gửi lệnh khởi động lại camera (SystemReboot)."""
        action = "http://www.onvif.org/ver10/device/wsdl/SystemReboot"
        body = "<tds:SystemReboot />"
        code, text = self.send_soap(self.device_service_url, action, body)
        if code == 200 and "SystemRebootResponse" in text:
            m = re.search(r"<[^:>]*:Message>([^<]+)</[^:>]*:Message>", text)
            msg = m.group(1) if m else "Reboot command accepted"
            return True, f"Camera phản hồi: {msg}"
        return False, f"Lệnh reboot thất bại: HTTP {code}"


# ==============================================================================
# BỘ DÒ QUÉT THIẾT BỊ TỰ ĐỘNG (WS-DISCOVERY UDP 3702)
# ==============================================================================

def ws_discover(timeout: float = 2.5, target_ip: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Phát bản tin WS-Discovery Probe để phát hiện các camera ONVIF trong mạng nội bộ.
    Nếu có target_ip thì gửi trực tiếp (unicast probe), nếu không gửi broadcast/multicast (239.255.255.250).
    """
    msg_id = f"uuid:{uuid.uuid4()}"
    probe_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope"
            xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing"
            xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery"
            xmlns:dn="http://www.onvif.org/ver10/network/wsdl">
  <e:Header>
    <w:MessageID>{msg_id}</w:MessageID>
    <w:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>
    <w:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>
  </e:Header>
  <e:Body>
    <d:Probe>
      <d:Types>dn:NetworkVideoTransmitter</d:Types>
    </d:Probe>
  </e:Body>
</e:Envelope>"""

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.settimeout(timeout)

    dest = (target_ip, 3702) if target_ip else ("239.255.255.250", 3702)

    discovered = []
    seen_ips = set()

    try:
        sock.sendto(probe_xml.encode("utf-8"), dest)
        t_end = time.time() + timeout
        while time.time() < t_end:
            try:
                data, addr = sock.recvfrom(65535)
                text = data.decode("utf-8", errors="ignore")
                cam_ip = addr[0]
                if cam_ip in seen_ips:
                    continue
                seen_ips.add(cam_ip)

                # Trích xuất XAddrs, Scopes, Model, Manufacturer
                xaddrs = re.findall(r"<[^:>]*:XAddrs>([^<]+)</[^:>]*:XAddrs>", text)
                xaddr_str = xaddrs[0].strip() if xaddrs else f"http://{cam_ip}:80/onvif/device_service"

                # Trích xuất các trường từ onvif Scopes
                m_manuf = re.search(r"onvif://www\.onvif\.org/manufacturer/([^/\s]+)", text)
                m_model = re.search(r"onvif://www\.onvif\.org/model/([^/\s]+)", text)
                m_name = re.search(r"onvif://www\.onvif\.org/name/([^/\s]+)", text)
                m_mac = re.search(r"onvif://www\.onvif\.org/MAC/([^/\s]+)", text)

                discovered.append({
                    "ip": cam_ip,
                    "xaddr": xaddr_str,
                    "manufacturer": m_manuf.group(1).replace("%20", " ") if m_manuf else "Unknown",
                    "model": m_model.group(1).replace("%20", " ") if m_model else "Unknown",
                    "name": m_name.group(1).replace("%20", " ") if m_name else "Camera",
                    "mac": m_mac.group(1) if m_mac else "N/A"
                })
            except socket.timeout:
                break
            except Exception:
                continue
    finally:
        sock.close()

    return discovered


# ==============================================================================
# GIAO DIỆN TERMINAL / TUI (RICH CONSOLE)
# ==============================================================================

def display_camera_summary(client: ONVIFClient):
    """Hiển thị bảng tóm tắt chi tiết thông tin camera như giao diện OxDM."""
    if not console:
        print(f"[*] Camera: {client.ip}")
        print(f"[*] Info: {client.device_info}")
        return

    # Panel thông tin cơ bản
    info_tbl = Table(show_header=False, box=None, padding=(0, 2))
    info_tbl.add_column("Key", style="bold cyan")
    info_tbl.add_column("Value", style="green")

    info_tbl.add_row("Hãng sản xuất (Manufacturer):", client.device_info.get("Manufacturer", "N/A"))
    info_tbl.add_row("Dòng máy (Model):", client.device_info.get("Model", "N/A"))
    info_tbl.add_row("Phiên bản Firmware:", client.device_info.get("FirmwareVersion", "N/A"))
    info_tbl.add_row("Số Serial:", client.device_info.get("SerialNumber", "N/A"))
    info_tbl.add_row("Mã phần cứng (Hardware ID):", client.device_info.get("HardwareId", "N/A"))
    info_tbl.add_row("Địa chỉ ONVIF Service:", client.device_service_url)
    info_tbl.add_row("Giao thức kết nối:", "HTTPS (Bảo mật TLS)" if client.is_https else "HTTP (Không mã hóa)")
    info_tbl.add_row("Phương thức xác thực:", client.auth_mode.upper())

    # Lệch giờ
    skew = client.time_offset_sec
    skew_color = "green" if abs(skew) < 2 else ("yellow" if abs(skew) < 10 else "red")
    info_tbl.add_row("Độ lệch đồng hồ (Skew):", f"[{skew_color}]{skew:+.2f} giây[/{skew_color}] (Đã tự động bù trừ)")
    info_tbl.add_row("Múi giờ Camera:", client.system_time_info.get("timezone", "N/A"))

    console.print(Panel(info_tbl, title=f"[bold green]OxDM-Linux • Đăng nhập thành công [{client.ip}][/bold green]", border_style="green"))

    # Bảng Video Profiles & RTSP Streams
    if client.profiles:
        prof_tbl = Table(title="[bold yellow]Danh sách Video Profiles & Luồng RTSP[/bold yellow]", border_style="blue")
        prof_tbl.add_column("STT", justify="center", style="bold")
        prof_tbl.add_column("Profile Token", style="cyan")
        prof_tbl.add_column("Tên Luồng", style="magenta")
        prof_tbl.add_column("Chuẩn nén", justify="center")
        prof_tbl.add_column("Độ phân giải", justify="center", style="bold white")
        prof_tbl.add_column("FPS", justify="center")
        prof_tbl.add_column("Bitrate", justify="right")
        prof_tbl.add_column("RTSP Stream URI", style="green")

        for p in client.profiles:
            prof_tbl.add_row(
                str(p["index"]),
                p["token"],
                p["name"],
                p["encoding"],
                p["resolution"],
                str(p["fps"]),
                p["bitrate"],
                p["stream_uri"]
            )
        console.print(prof_tbl)

    # Bảng card mạng
    if client.network_interfaces:
        net_tbl = Table(title="[bold blue]Giao diện mạng (Network Interfaces)[/bold blue]", border_style="dim blue")
        net_tbl.add_column("Interface", style="cyan")
        net_tbl.add_column("Địa chỉ MAC", style="bold yellow")
        net_tbl.add_column("IP Camera", style="green")
        net_tbl.add_column("MTU", justify="center")
        net_tbl.add_column("DHCP", justify="center")

        for iface in client.network_interfaces:
            net_tbl.add_row(
                iface["name"],
                iface["mac"],
                iface["ip"],
                str(iface["mtu"]),
                str(iface["dhcp"])
            )
        console.print(net_tbl)

    # Bảng Users
    if client.users:
        u_tbl = Table(title="[bold magenta]Tài khoản quản trị ONVIF (Users)[/bold magenta]", border_style="dim magenta")
        u_tbl.add_column("Tên người dùng (Username)", style="bold cyan")
        u_tbl.add_column("Cấp độ quyền (UserLevel)", style="bold green")
        for u in client.users:
            u_tbl.add_row(u["username"], u["level"])
        console.print(u_tbl)


def run_interactive_tui(client: ONVIFClient):
    """Vòng lặp menu điều khiển tương tác TUI."""
    while True:
        console.print("\n[bold cyan]═══ MENU TÍNH NĂNG OXDM-LINUX ONVIF MANAGER ═══[/bold cyan]")
        console.print("  [1] Làm mới & Xem tóm tắt thông tin camera")
        console.print("  [2] Chụp Snapshot ảnh hiện tại (Xem & Lưu file JPG)")
        console.print("  [3] Mở xem trực tiếp luồng Video RTSP (Khởi chạy VLC)")
        console.print("  [4] Sao chép liên kết RTSP Stream (kèm mật khẩu xác thực)")
        console.print("  [5] Quét tự động mạng nội bộ (WS-Discovery UDP 3702)")
        console.print("  [6] Chuyển đổi camera / Đăng nhập IP khác")
        console.print("  [7] Kiểm tra danh sách quyền & Endpoint dịch vụ (Capabilities)")
        console.print("  [8] Khởi chạy Giao diện Web Trực quan (OxDM Web GUI)")
        console.print("  [9] Khởi động lại camera (SystemReboot)")
        console.print("  [0] Thoát chương trình")

        choice = Prompt.ask("\n[bold yellow]Chọn chức năng[/bold yellow]", default="1")

        if choice == "1":
            with console.status("[bold green]Đang tải thông tin từ camera...[/bold green]"):
                client.fetch_capabilities()
                client.fetch_network_interfaces()
                client.fetch_profiles()
                client.fetch_users()
            display_camera_summary(client)

        elif choice == "2":
            with console.status("[bold green]Đang chụp ảnh Snapshot từ camera...[/bold green]"):
                ok, path_or_err, img_bytes = client.capture_snapshot()
            if ok:
                console.print(f"[bold green]✔ Đã chụp & lưu thành công tại:[/bold green] [yellow]{path_or_err}[/yellow]")
                # Thử mở bằng trình xem ảnh nếu có
                for viewer in ["xdg-open", "display", "feh", "eog"]:
                    if subprocess.run(["which", viewer], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
                        subprocess.Popen([viewer, path_or_err], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                        break
            else:
                console.print(f"[bold red]✘ Lỗi chụp snapshot:[/bold red] {path_or_err}")

        elif choice == "3":
            idx = int(Prompt.ask("Chọn số thứ tự luồng (1: Luồng chính, 2: Luồng phụ)", default="1"))
            ok, msg = client.launch_vlc_stream(idx)
            if ok:
                console.print(f"[bold green]✔ {msg}[/bold green]")
            else:
                console.print(f"[bold red]✘ {msg}[/bold red]")

        elif choice == "4":
            console.print("\n[bold yellow]Danh sách RTSP Stream URLs (kèm mật khẩu để dán vào VLC/OBS/NVR):[/bold yellow]")
            for p in client.profiles:
                console.print(f"  • [bold cyan]{p['name']}[/bold cyan] ({p['resolution']}):")
                console.print(f"    [green]{p['auth_stream_uri']}[/green]")

        elif choice == "5":
            console.print("[*] Đang gửi gói tin WS-Discovery Probe trên cổng UDP 3702...")
            cams = ws_discover(timeout=3.0)
            if not cams:
                console.print("[yellow]Không tìm thấy camera nào phản hồi qua WS-Discovery.[/yellow]")
            else:
                t = Table(title="Danh sách Camera ONVIF tìm thấy", border_style="green")
                t.add_column("IP", style="bold cyan")
                t.add_column("Hãng", style="green")
                t.add_column("Dòng máy", style="magenta")
                t.add_column("MAC", style="yellow")
                t.add_column("ONVIF XAddr", style="dim white")
                for c in cams:
                    t.add_row(c["ip"], c["manufacturer"], c["model"], c["mac"], c["xaddr"])
                console.print(t)

        elif choice == "6":
            new_ip = Prompt.ask("Nhập IP Camera mới", default=client.ip)
            new_port_str = Prompt.ask("Nhập cổng (để trống để tự dò)", default="")
            new_port = int(new_port_str) if new_port_str.strip() else None
            new_user = Prompt.ask("Tài khoản (Username)", default=client.username)
            new_pass = Prompt.ask("Mật khẩu (Password)", default=client.password)

            new_client = ONVIFClient(new_ip, new_port, new_user, new_pass)
            with console.status("[bold green]Đang kết nối camera mới...[/bold green]"):
                c_ok, c_msg = new_client.probe_and_connect()
                if c_ok:
                    a_ok, a_msg = new_client.authenticate()
                    if a_ok:
                        client = new_client
                        client.fetch_capabilities()
                        client.fetch_network_interfaces()
                        client.fetch_profiles()
                        client.fetch_users()
                        display_camera_summary(client)
                    else:
                        console.print(f"[bold red]✘ Lỗi xác thực:[/bold red] {a_msg}")
                else:
                    console.print(f"[bold red]✘ Không kết nối được:[/bold red] {c_msg}")

        elif choice == "7":
            console.print("\n[bold cyan]Danh sách Capabilities & Endpoints của Camera:[/bold cyan]")
            for k, v in client.capabilities.items():
                console.print(f"  • [bold yellow]{k:12s}[/bold yellow] : [green]{v}[/green]")

        elif choice == "8":
            console.print("[*] Đang khởi chạy giao diện Web OxDM...")
            start_web_server(client, port=8899)

        elif choice == "9":
            if Confirm.ask("[bold red]Bạn có chắc chắn muốn khởi động lại camera này không?[/bold red]", default=False):
                ok, msg = client.reboot()
                console.print(f"[{'bold green' if ok else 'bold red'}]{msg}[/{'bold green' if ok else 'bold red'}]")

        elif choice == "0":
            console.print("[bold yellow]Tạm biệt![/bold yellow]")
            break


# ==============================================================================
# GIAO DIỆN WEB HIỆN ĐẠI (OxDM WEB DASHBOARD)
# ==============================================================================

def start_web_server(client: ONVIFClient, port: int = 8899):
    """Khởi chạy máy chủ Web cục bộ phục vụ giao diện OxDM Web Dashboard."""
    from fastapi import FastAPI, Response, Request
    from fastapi.responses import HTMLResponse, JSONResponse
    import uvicorn

    app = FastAPI(title="OxDM Web", docs_url=None, redoc_url=None)
    global_state = {"client": client}

    HTML_PAGE = """<!DOCTYPE html>
<html lang="vi" class="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>OxDM • ONVIF Device Manager</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script>
    tailwind.config = {
      darkMode: 'class',
      theme: {
        extend: {
          colors: {
            brand: { 500: '#3b82f6', 600: '#2563eb', 700: '#1d4ed8' },
            surface: { 800: '#1e293b', 900: '#0f172a', 950: '#020617' }
          }
        }
      }
    }
  </script>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
    ::-webkit-scrollbar { width: 6px; height: 6px; }
    ::-webkit-scrollbar-track { background: #0f172a; }
    ::-webkit-scrollbar-thumb { background: #334155; border-radius: 3px; }
  </style>
</head>
<body class="bg-surface-950 text-slate-100 flex flex-col h-screen overflow-hidden">

  <!-- Header -->
  <header class="bg-surface-900 border-b border-slate-800 px-5 py-3 flex items-center justify-between shadow-md">
    <div class="flex items-center space-x-3">
      <div class="w-8 h-8 rounded bg-blue-600 flex items-center justify-center font-bold text-white tracking-wider text-sm">
        Ox
      </div>
      <div>
        <h1 class="text-base font-semibold text-white tracking-tight flex items-center gap-2">
          OxDM <span class="text-xs px-2 py-0.5 rounded bg-blue-950 text-blue-400 border border-blue-800">Linux Edition</span>
        </h1>
        <p class="text-xs text-slate-400">Trình quản lý & Đăng nhập ONVIF Device Manager đa năng</p>
      </div>
    </div>
    <div class="flex items-center space-x-3">
      <span id="connStatus" class="inline-flex items-center px-2.5 py-1 rounded text-xs font-medium bg-emerald-950 text-emerald-400 border border-emerald-800">
        <span class="w-2 h-2 mr-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
        <span id="targetIpDisplay">Đang kết nối...</span>
      </span>
      <button onclick="refreshData()" class="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium rounded border border-slate-700 transition">
        Làm mới (F5)
      </button>
    </div>
  </header>

  <!-- Main Body Grid -->
  <div class="flex-1 flex overflow-hidden">

    <!-- Left Sidebar: Device Tree & Connection Form -->
    <aside class="w-80 bg-surface-900 border-r border-slate-800 flex flex-col">
      <div class="p-4 border-b border-slate-800">
        <div class="flex items-center justify-between mb-3">
          <h2 class="text-xs font-semibold uppercase tracking-wider text-slate-400">Đăng nhập thiết bị</h2>
          <button onclick="runDiscovery()" class="text-xs text-blue-400 hover:text-blue-300 font-medium">Dò quét mạng</button>
        </div>
        <form id="loginForm" onsubmit="handleLogin(event)" class="space-y-2.5 text-xs">
          <div>
            <label class="block text-slate-400 mb-1">Địa chỉ IP Camera</label>
            <input type="text" id="ipInput" required class="w-full bg-surface-950 border border-slate-700 rounded px-2.5 py-1.5 text-white focus:outline-none focus:border-blue-500 font-mono">
          </div>
          <div class="grid grid-cols-2 gap-2">
            <div>
              <label class="block text-slate-400 mb-1">Cổng (Port)</label>
              <input type="number" id="portInput" placeholder="Tự dò (443/80)" class="w-full bg-surface-950 border border-slate-700 rounded px-2.5 py-1.5 text-white focus:outline-none focus:border-blue-500 font-mono">
            </div>
            <div>
              <label class="block text-slate-400 mb-1">Tài khoản</label>
              <input type="text" id="userInput" required class="w-full bg-surface-950 border border-slate-700 rounded px-2.5 py-1.5 text-white focus:outline-none focus:border-blue-500">
            </div>
          </div>
          <div>
            <label class="block text-slate-400 mb-1">Mật khẩu</label>
            <input type="password" id="passInput" required class="w-full bg-surface-950 border border-slate-700 rounded px-2.5 py-1.5 text-white focus:outline-none focus:border-blue-500 font-mono">
          </div>
          <button type="submit" id="btnConnect" class="w-full py-2 bg-blue-600 hover:bg-blue-500 text-white font-medium rounded transition flex items-center justify-center space-x-1.5">
            <span>Đăng nhập ONVIF</span>
          </button>
        </form>
      </div>

      <!-- Discovered Devices List -->
      <div class="flex-1 overflow-y-auto p-3">
        <h3 class="text-xs font-semibold uppercase tracking-wider text-slate-400 px-1 mb-2">Thiết bị tìm thấy (WS-Discovery)</h3>
        <div id="deviceList" class="space-y-1.5 text-xs">
          <div class="text-slate-500 text-center py-4">Nhấn "Dò quét mạng" để tìm camera tự động</div>
        </div>
      </div>
    </aside>

    <!-- Right Content Area -->
    <main class="flex-1 flex flex-col bg-surface-950 overflow-hidden">

      <!-- Navigation Tabs -->
      <div class="bg-surface-900 border-b border-slate-800 px-4 flex space-x-1 text-xs font-medium">
        <button onclick="switchTab('live')" id="tab-live" class="tab-btn px-4 py-3 text-blue-400 border-b-2 border-blue-500">Xem trực tiếp & Snapshot</button>
        <button onclick="switchTab('info')" id="tab-info" class="tab-btn px-4 py-3 text-slate-400 hover:text-slate-200 border-b-2 border-transparent">Thông tin thiết bị</button>
        <button onclick="switchTab('network')" id="tab-network" class="tab-btn px-4 py-3 text-slate-400 hover:text-slate-200 border-b-2 border-transparent">Cấu hình mạng</button>
        <button onclick="switchTab('profiles')" id="tab-profiles" class="tab-btn px-4 py-3 text-slate-400 hover:text-slate-200 border-b-2 border-transparent">Video Profiles & Luồng</button>
        <button onclick="switchTab('users')" id="tab-users" class="tab-btn px-4 py-3 text-slate-400 hover:text-slate-200 border-b-2 border-transparent">Tài khoản (Users)</button>
        <button onclick="switchTab('capabilities')" id="tab-capabilities" class="tab-btn px-4 py-3 text-slate-400 hover:text-slate-200 border-b-2 border-transparent">Dịch vụ (Endpoints)</button>
      </div>

      <!-- Tab Contents -->
      <div class="flex-1 overflow-y-auto p-5">

        <!-- TAB 1: LIVE VIEW & SNAPSHOT -->
        <div id="content-live" class="space-y-4">
          <div class="grid grid-cols-1 lg:grid-cols-3 gap-5">
            <!-- Viewport Canvas -->
            <div class="lg:col-span-2 bg-surface-900 border border-slate-800 rounded-lg p-3 flex flex-col items-center">
              <div class="w-full flex items-center justify-between pb-2 mb-2 border-b border-slate-800 text-xs">
                <span class="text-slate-300 font-medium flex items-center gap-1.5">
                  <span class="w-2 h-2 rounded-full bg-red-500 animate-ping"></span> Live Snapshot View
                </span>
                <div class="flex items-center space-x-2">
                  <label class="text-slate-400">Tự làm mới:</label>
                  <select id="refreshRate" onchange="toggleAutoRefresh(this.value)" class="bg-surface-950 border border-slate-700 text-slate-200 text-xs rounded px-2 py-1">
                    <option value="0">Tắt (Thủ công)</option>
                    <option value="1000" selected>1 giây</option>
                    <option value="2000">2 giây</option>
                    <option value="5000">5 giây</option>
                  </select>
                  <button onclick="refreshSnapshot()" class="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-xs text-white rounded border border-slate-700">Chụp ngay</button>
                </div>
              </div>
              <div class="relative w-full aspect-video bg-black rounded overflow-hidden flex items-center justify-center border border-slate-800">
                <img id="snapshotImg" src="/api/snapshot" alt="Live View" class="w-full h-full object-contain" onerror="this.src='data:image/svg+xml,<svg xmlns=\\'http://www.w3.org/2000/svg\\' width=\\'400\\' height=\\'225\\' viewBox=\\'0 0 400 225\\'><rect fill=\\'%23111\\' width=\\'400\\' height=\\'225\\'/><text fill=\\'%23666\\' x=\\'50%\\' y=\\'50%\\' dominant-baseline=\\'middle\\' text-anchor=\\'middle\\' font-size=\\'14\\'>Chưa có tín hiệu Snapshot</text></svg>'">
              </div>
            </div>

            <!-- Controls & Stream Info -->
            <div class="space-y-3">
              <div class="bg-surface-900 border border-slate-800 rounded-lg p-4 text-xs space-y-3">
                <h3 class="font-semibold text-slate-200 uppercase tracking-wider text-xs border-b border-slate-800 pb-2">Điều khiển luồng trực tiếp</h3>
                <div class="space-y-2">
                  <button onclick="launchVlc(1)" class="w-full py-2 bg-emerald-600 hover:bg-emerald-500 text-white font-medium rounded flex items-center justify-center space-x-2 transition">
                    <svg class="w-4 h-4" fill="currentColor" viewBox="0 0 20 20"><path d="M4 4l12 6-12 6V4z"/></svg>
                    <span>Mở Luồng Chính (VLC)</span>
                  </button>
                  <button onclick="launchVlc(2)" class="w-full py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 font-medium rounded border border-slate-700 flex items-center justify-center space-x-2 transition">
                    <svg class="w-4 h-4" fill="currentColor" viewBox="0 0 20 20"><path d="M4 4l12 6-12 6V4z"/></svg>
                    <span>Mở Luồng Phụ (VLC)</span>
                  </button>
                  <a id="btnDownloadSnap" href="/api/snapshot" download="snapshot.jpg" class="w-full py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 font-medium rounded border border-slate-700 flex items-center justify-center space-x-2 transition text-center block">
                    <span>Tải ảnh Snapshot về máy</span>
                  </a>
                </div>
              </div>

              <!-- RTSP Links -->
              <div class="bg-surface-900 border border-slate-800 rounded-lg p-4 text-xs space-y-2">
                <h3 class="font-semibold text-slate-200 uppercase tracking-wider text-xs border-b border-slate-800 pb-2">Đường dẫn RTSP (Sao chép)</h3>
                <div id="rtspLinksContainer" class="space-y-2">
                  <div class="text-slate-500">Đang nạp luồng...</div>
                </div>
              </div>
            </div>
          </div>
        </div>

        <!-- TAB 2: DEVICE INFORMATION -->
        <div id="content-info" class="hidden space-y-4">
          <div class="bg-surface-900 border border-slate-800 rounded-lg p-5">
            <h3 class="font-semibold text-sm text-white mb-4 flex items-center gap-2">
              <span class="w-2.5 h-2.5 rounded-full bg-blue-500"></span> Thông số phần cứng & Định danh Camera
            </h3>
            <div class="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
              <div class="p-3 bg-surface-950 rounded border border-slate-800 space-y-1">
                <div class="text-slate-400">Nhà sản xuất (Manufacturer)</div>
                <div id="infoManufacturer" class="text-sm font-semibold text-emerald-400 font-mono">-</div>
              </div>
              <div class="p-3 bg-surface-950 rounded border border-slate-800 space-y-1">
                <div class="text-slate-400">Dòng sản phẩm (Model)</div>
                <div id="infoModel" class="text-sm font-semibold text-white font-mono">-</div>
              </div>
              <div class="p-3 bg-surface-950 rounded border border-slate-800 space-y-1">
                <div class="text-slate-400">Phiên bản Firmware</div>
                <div id="infoFirmware" class="text-sm font-semibold text-amber-300 font-mono">-</div>
              </div>
              <div class="p-3 bg-surface-950 rounded border border-slate-800 space-y-1">
                <div class="text-slate-400">Số Serial Number</div>
                <div id="infoSerial" class="text-sm font-semibold text-white font-mono">-</div>
              </div>
              <div class="p-3 bg-surface-950 rounded border border-slate-800 space-y-1">
                <div class="text-slate-400">Mã phần cứng (Hardware ID)</div>
                <div id="infoHardwareId" class="text-sm font-semibold text-white font-mono">-</div>
              </div>
              <div class="p-3 bg-surface-950 rounded border border-slate-800 space-y-1">
                <div class="text-slate-400">Cơ chế xác thực sử dụng</div>
                <div id="infoAuthMode" class="text-sm font-semibold text-blue-400 font-mono">-</div>
              </div>
              <div class="p-3 bg-surface-950 rounded border border-slate-800 space-y-1">
                <div class="text-slate-400">Độ lệch đồng hồ (Clock Skew)</div>
                <div id="infoClockSkew" class="text-sm font-semibold text-emerald-400 font-mono">-</div>
              </div>
              <div class="p-3 bg-surface-950 rounded border border-slate-800 space-y-1">
                <div class="text-slate-400">Múi giờ Camera</div>
                <div id="infoTimezone" class="text-sm font-semibold text-white font-mono">-</div>
              </div>
            </div>
          </div>
        </div>

        <!-- TAB 3: NETWORK -->
        <div id="content-network" class="hidden space-y-4">
          <div class="bg-surface-900 border border-slate-800 rounded-lg p-5">
            <h3 class="font-semibold text-sm text-white mb-4">Giao diện kết nối mạng</h3>
            <div id="netInterfaceContainer" class="space-y-3 text-xs">
              <div class="text-slate-500">Đang nạp cấu hình mạng...</div>
            </div>
          </div>
        </div>

        <!-- TAB 4: PROFILES -->
        <div id="content-profiles" class="hidden space-y-4">
          <div class="bg-surface-900 border border-slate-800 rounded-lg p-5">
            <h3 class="font-semibold text-sm text-white mb-4">Danh sách Profiles & Bộ mã hóa Video</h3>
            <div class="overflow-x-auto">
              <table class="w-full text-left text-xs border-collapse">
                <thead>
                  <tr class="border-b border-slate-800 text-slate-400">
                    <th class="py-2 px-3">STT</th>
                    <th class="py-2 px-3">Profile Token</th>
                    <th class="py-2 px-3">Chuẩn nén</th>
                    <th class="py-2 px-3">Độ phân giải</th>
                    <th class="py-2 px-3">FPS</th>
                    <th class="py-2 px-3">Bitrate</th>
                    <th class="py-2 px-3">Thao tác</th>
                  </tr>
                </thead>
                <tbody id="profilesTableBody" class="divide-y divide-slate-800 text-slate-200">
                  <tr><td colspan="7" class="py-3 px-3 text-center text-slate-500">Đang nạp dữ liệu profiles...</td></tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>

        <!-- TAB 5: USERS -->
        <div id="content-users" class="hidden space-y-4">
          <div class="bg-surface-900 border border-slate-800 rounded-lg p-5">
            <h3 class="font-semibold text-sm text-white mb-4">Danh sách tài khoản ONVIF được cấp phép</h3>
            <div id="usersContainer" class="space-y-2 text-xs">
              <div class="text-slate-500">Đang nạp danh sách users...</div>
            </div>
          </div>
        </div>

        <!-- TAB 6: CAPABILITIES -->
        <div id="content-capabilities" class="hidden space-y-4">
          <div class="bg-surface-900 border border-slate-800 rounded-lg p-5">
            <h3 class="font-semibold text-sm text-white mb-4">Dịch vụ & Endpoint URLs</h3>
            <div id="capsContainer" class="space-y-2 text-xs font-mono">
              <div class="text-slate-500">Đang nạp capabilities...</div>
            </div>
          </div>
        </div>

      </div>
    </main>
  </div>

  <script>
    let activeTab = 'live';
    let autoRefreshTimer = null;

    function switchTab(tab) {
      document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.remove('text-blue-400', 'border-blue-500');
        btn.classList.add('text-slate-400', 'border-transparent');
      });
      document.getElementById('tab-' + tab).classList.add('text-blue-400', 'border-blue-500');
      document.getElementById('tab-' + tab).classList.remove('text-slate-400', 'border-transparent');

      ['live', 'info', 'network', 'profiles', 'users', 'capabilities'].forEach(t => {
        const el = document.getElementById('content-' + t);
        if (el) el.classList.toggle('hidden', t !== tab);
      });
      activeTab = tab;
    }

    async function loadCurrentStatus() {
      try {
        const res = await fetch('/api/device_info');
        const data = await res.json();
        if (data.ip) {
          document.getElementById('targetIpDisplay').textContent = `${data.ip} (${data.manufacturer} ${data.model})`;
          document.getElementById('ipInput').value = data.ip;
          document.getElementById('userInput').value = data.username;
          document.getElementById('passInput').value = data.password;

          document.getElementById('infoManufacturer').textContent = data.manufacturer || '-';
          document.getElementById('infoModel').textContent = data.model || '-';
          document.getElementById('infoFirmware').textContent = data.firmware || '-';
          document.getElementById('infoSerial').textContent = data.serial || '-';
          document.getElementById('infoHardwareId').textContent = data.hardware_id || '-';
          document.getElementById('infoAuthMode').textContent = (data.auth_mode || '').toUpperCase();
          document.getElementById('infoClockSkew').textContent = (data.clock_skew || 0).toFixed(2) + ' giây (Đã đồng bộ)';
          document.getElementById('infoTimezone').textContent = data.timezone || '-';
        }
      } catch (e) {
        console.error(e);
      }
    }

    async function refreshData() {
      await loadCurrentStatus();
      await loadProfiles();
      await loadNetwork();
      await loadUsers();
      await loadCaps();
      refreshSnapshot();
    }

    async function loadProfiles() {
      try {
        const res = await fetch('/api/profiles');
        const list = await res.json();
        const tbody = document.getElementById('profilesTableBody');
        const rtspCont = document.getElementById('rtspLinksContainer');
        tbody.innerHTML = '';
        rtspCont.innerHTML = '';

        if (!list || list.length === 0) {
          tbody.innerHTML = '<tr><td colspan="7" class="py-3 px-3 text-center text-slate-500">Không tìm thấy video profiles</td></tr>';
          return;
        }

        list.forEach(p => {
          const row = document.createElement('tr');
          row.className = 'hover:bg-slate-800/40';
          row.innerHTML = `
            <td class="py-2.5 px-3 font-mono">${p.index}</td>
            <td class="py-2.5 px-3 font-medium text-blue-400 font-mono">${p.token}</td>
            <td class="py-2.5 px-3 font-mono">${p.encoding}</td>
            <td class="py-2.5 px-3 font-mono font-semibold text-emerald-400">${p.resolution}</td>
            <td class="py-2.5 px-3 font-mono">${p.fps} fps</td>
            <td class="py-2.5 px-3 font-mono">${p.bitrate}</td>
            <td class="py-2.5 px-3">
              <button onclick="launchVlc(${p.index})" class="px-2 py-1 bg-emerald-700 hover:bg-emerald-600 text-white rounded text-[11px] mr-1">VLC</button>
              <button onclick="navigator.clipboard.writeText('${p.auth_stream_uri}'); alert('Đã sao chép link RTSP!');" class="px-2 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded text-[11px] border border-slate-700">Copy RTSP</button>
            </td>
          `;
          tbody.appendChild(row);

          const rBox = document.createElement('div');
          rBox.className = 'p-2.5 bg-surface-950 rounded border border-slate-800';
          rBox.innerHTML = `
            <div class="flex items-center justify-between mb-1">
              <span class="font-semibold text-slate-300 font-mono">${p.name} (${p.resolution})</span>
              <button onclick="navigator.clipboard.writeText('${p.auth_stream_uri}'); alert('Đã sao chép link RTSP!');" class="text-blue-400 hover:text-blue-300 text-[11px]">Copy</button>
            </div>
            <div class="text-[11px] font-mono text-slate-400 break-all bg-slate-900 p-1.5 rounded">${p.stream_uri}</div>
          `;
          rtspCont.appendChild(rBox);
        });
      } catch (e) {
        console.error(e);
      }
    }

    async function loadNetwork() {
      try {
        const res = await fetch('/api/network');
        const ifaces = await res.json();
        const cont = document.getElementById('netInterfaceContainer');
        cont.innerHTML = '';
        ifaces.forEach(i => {
          const div = document.createElement('div');
          div.className = 'p-4 bg-surface-950 rounded border border-slate-800 grid grid-cols-2 md:grid-cols-4 gap-3';
          div.innerHTML = `
            <div><span class="text-slate-400 block">Tên Interface:</span> <span class="font-mono text-white font-bold">${i.name}</span></div>
            <div><span class="text-slate-400 block">Địa chỉ MAC:</span> <span class="font-mono text-amber-300 font-bold">${i.mac}</span></div>
            <div><span class="text-slate-400 block">IP Camera:</span> <span class="font-mono text-emerald-400 font-bold">${i.ip}</span></div>
            <div><span class="text-slate-400 block">DHCP:</span> <span class="font-mono text-slate-300">${i.dhcp}</span></div>
          `;
          cont.appendChild(div);
        });
      } catch (e) {
        console.error(e);
      }
    }

    async function loadUsers() {
      try {
        const res = await fetch('/api/users');
        const users = await res.json();
        const cont = document.getElementById('usersContainer');
        cont.innerHTML = '';
        users.forEach(u => {
          const div = document.createElement('div');
          div.className = 'p-3 bg-surface-950 rounded border border-slate-800 flex items-center justify-between';
          div.innerHTML = `
            <div class="flex items-center space-x-2">
              <span class="w-2 h-2 rounded-full bg-emerald-500"></span>
              <span class="font-mono font-bold text-white text-sm">${u.username}</span>
            </div>
            <span class="px-2 py-0.5 rounded text-xs font-semibold bg-blue-950 text-blue-400 border border-blue-800">${u.level}</span>
          `;
          cont.appendChild(div);
        });
      } catch (e) {
        console.error(e);
      }
    }

    async function loadCaps() {
      try {
        const res = await fetch('/api/capabilities');
        const caps = await res.json();
        const cont = document.getElementById('capsContainer');
        cont.innerHTML = '';
        for (const [k, v] of Object.entries(caps)) {
          const div = document.createElement('div');
          div.className = 'p-2.5 bg-surface-950 rounded border border-slate-800 flex items-center justify-between';
          div.innerHTML = `<span class="text-slate-300 font-semibold">${k}:</span> <span class="text-emerald-400 break-all text-xs">${v}</span>`;
          cont.appendChild(div);
        }
      } catch (e) {
        console.error(e);
      }
    }

    function refreshSnapshot() {
      const img = document.getElementById('snapshotImg');
      img.src = '/api/snapshot?t=' + new Date().getTime();
    }

    function toggleAutoRefresh(intervalMs) {
      if (autoRefreshTimer) clearInterval(autoRefreshTimer);
      const val = parseInt(intervalMs);
      if (val > 0) {
        autoRefreshTimer = setInterval(refreshSnapshot, val);
      }
    }

    async function launchVlc(index) {
      try {
        const res = await fetch(`/api/launch_vlc?index=${index}`, { method: 'POST' });
        const data = await res.json();
        alert(data.message);
      } catch (e) {
        alert('Lỗi khởi chạy VLC: ' + e);
      }
    }

    async function handleLogin(e) {
      e.preventDefault();
      const ip = document.getElementById('ipInput').value.trim();
      const port = document.getElementById('portInput').value.trim();
      const user = document.getElementById('userInput').value.trim();
      const pass = document.getElementById('passInput').value;
      const btn = document.getElementById('btnConnect');

      btn.disabled = true;
      btn.innerHTML = '<span class="animate-spin mr-2">⟳</span> Đang kết nối...';

      try {
        const res = await fetch('/api/connect', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ip, port: port ? parseInt(port) : null, username: user, password: pass })
        });
        const data = await res.json();
        if (data.success) {
          alert('Đăng nhập thành công: ' + data.message);
          await refreshData();
        } else {
          alert('Đăng nhập thất bại: ' + data.message);
        }
      } catch (err) {
        alert('Lỗi kết nối máy chủ: ' + err);
      } finally {
        btn.disabled = false;
        btn.innerHTML = '<span>Đăng nhập ONVIF</span>';
      }
    }

    async function runDiscovery() {
      const listDiv = document.getElementById('deviceList');
      listDiv.innerHTML = '<div class="text-center py-4 text-blue-400 animate-pulse">Đang phát sóng WS-Discovery UDP 3702...</div>';
      try {
        const res = await fetch('/api/discover');
        const cams = await res.json();
        listDiv.innerHTML = '';
        if (!cams || cams.length === 0) {
          listDiv.innerHTML = '<div class="text-slate-500 text-center py-4">Không tìm thấy camera nào</div>';
          return;
        }
        cams.forEach(c => {
          const item = document.createElement('div');
          item.className = 'p-2.5 bg-surface-950 hover:bg-slate-800 rounded border border-slate-800 cursor-pointer transition';
          item.onclick = () => {
            document.getElementById('ipInput').value = c.ip;
          };
          item.innerHTML = `
            <div class="font-semibold text-white font-mono">${c.ip}</div>
            <div class="text-slate-400 text-[11px]">${c.manufacturer} ${c.model}</div>
            <div class="text-slate-500 text-[10px] font-mono">${c.mac}</div>
          `;
          listDiv.appendChild(item);
        });
      } catch (e) {
        listDiv.innerHTML = '<div class="text-red-400 text-center py-4">Lỗi dò quét: ' + e + '</div>';
      }
    }

    window.onload = () => {
      refreshData();
      toggleAutoRefresh(1000);
    };
  </script>
</body>
</html>
"""

    @app.get("/", response_class=HTMLResponse)
    def index():
        return HTMLResponse(content=HTML_PAGE)

    @app.get("/api/device_info")
    def get_info():
        c: ONVIFClient = global_state["client"]
        return {
            "ip": c.ip,
            "port": c.active_port,
            "is_https": c.is_https,
            "username": c.username,
            "password": c.password,
            "manufacturer": c.device_info.get("Manufacturer", "N/A"),
            "model": c.device_info.get("Model", "N/A"),
            "firmware": c.device_info.get("FirmwareVersion", "N/A"),
            "serial": c.device_info.get("SerialNumber", "N/A"),
            "hardware_id": c.device_info.get("HardwareId", "N/A"),
            "auth_mode": c.auth_mode,
            "clock_skew": c.time_offset_sec,
            "timezone": c.system_time_info.get("timezone", "N/A")
        }

    @app.get("/api/profiles")
    def get_profiles():
        c: ONVIFClient = global_state["client"]
        if not c.profiles:
            c.fetch_profiles()
        return c.profiles

    @app.get("/api/network")
    def get_network():
        c: ONVIFClient = global_state["client"]
        if not c.network_interfaces:
            c.fetch_network_interfaces()
        return c.network_interfaces

    @app.get("/api/users")
    def get_users():
        c: ONVIFClient = global_state["client"]
        if not c.users:
            c.fetch_users()
        return c.users

    @app.get("/api/capabilities")
    def get_caps():
        c: ONVIFClient = global_state["client"]
        if not c.capabilities:
            c.fetch_capabilities()
        return c.capabilities

    @app.get("/api/snapshot")
    def get_snapshot():
        c: ONVIFClient = global_state["client"]
        ok, path, img_bytes = c.capture_snapshot()
        if ok and img_bytes:
            return Response(content=img_bytes, media_type="image/jpeg")
        return Response(status_code=404, content=b"No snapshot available")

    @app.post("/api/launch_vlc")
    def launch_vlc_api(index: int = 1):
        c: ONVIFClient = global_state["client"]
        ok, msg = c.launch_vlc_stream(index)
        return {"success": ok, "message": msg}

    @app.post("/api/connect")
    async def connect_camera(req: Request):
        data = await req.json()
        new_client = ONVIFClient(
            ip=data.get("ip"),
            port=data.get("port"),
            username=data.get("username", "admin"),
            password=data.get("password", "")
        )
        c_ok, c_msg = new_client.probe_and_connect()
        if not c_ok:
            return {"success": False, "message": c_msg}

        a_ok, a_msg = new_client.authenticate()
        if not a_ok:
            return {"success": False, "message": a_msg}

        new_client.fetch_capabilities()
        new_client.fetch_network_interfaces()
        new_client.fetch_profiles()
        new_client.fetch_users()
        global_state["client"] = new_client
        return {"success": True, "message": f"{c_msg} • {a_msg}"}

    @app.get("/api/discover")
    def discover_api():
        cams = ws_discover(timeout=2.5)
        return cams

    # Mở trình duyệt tự động
    server_url = f"http://127.0.0.1:{port}"
    print(f"\n[+] Khởi chạy OxDM Web Dashboard tại: {server_url}")

    def open_browser():
        time.sleep(1.0)
        browsers = ["/usr/bin/vivaldi", "/usr/bin/google-chrome", "/usr/bin/chromium", "xdg-open"]
        for b in browsers:
            if subprocess.run(["which", b.split()[0]], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
                subprocess.Popen([b, server_url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                break

    threading.Thread(target=open_browser, daemon=True).start()
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")


# ==============================================================================
# ENTRY POINT
# ==============================================================================

def main():
    parser = argparse.ArgumentParser(description="OxDM-Linux • ONVIF Device Manager & Security Auditor")
    parser.add_argument("--ip", default=DEFAULT_IP, help=f"Địa chỉ IP camera (Mặc định: {DEFAULT_IP})")
    parser.add_argument("--port", type=int, default=None, help="Cổng ONVIF (Mặc định tự động dò)")
    parser.add_argument("--user", default=DEFAULT_USER, help=f"Tài khoản xác thực (Mặc định: {DEFAULT_USER})")
    parser.add_argument("--pass", dest="password", default=DEFAULT_PASS, help="Mật khẩu camera")
    parser.add_argument("--discover", action="store_true", help="Dò quét thiết bị ONVIF qua WS-Discovery UDP 3702")
    parser.add_argument("--snapshot", nargs="?", const="default", help="Chụp ảnh snapshot từ camera và lưu ra file")
    parser.add_argument("--stream", type=int, nargs="?", const=1, help="Mở luồng video RTSP trong VLC")
    parser.add_argument("--web", action="store_true", help="Khởi chạy giao diện Web GUI (OxDM Web)")
    parser.add_argument("--web-port", type=int, default=8899, help="Cổng chạy Web GUI (Mặc định: 8899)")
    parser.add_argument("--json", action="store_true", help="Xuất toàn bộ thông số định danh dưới dạng JSON")

    args = parser.parse_args()

    # Chế độ phát hiện mạng
    if args.discover:
        print("[*] Đang gửi bản tin WS-Discovery Probe trên toàn mạng (UDP 3702)...")
        cams = ws_discover(timeout=3.0)
        if not cams:
            print("[-] Không tìm thấy thiết bị ONVIF nào phản hồi.")
        else:
            print(f"[+] Tìm thấy {len(cams)} thiết bị:")
            for c in cams:
                print(f"  • {c['ip']:15s} | {c['manufacturer']:15s} | {c['model']:25s} | {c['mac']}")
        return

    # Khởi tạo client kết nối camera
    client = ONVIFClient(
        ip=args.ip,
        port=args.port,
        username=args.user,
        password=args.password
    )

    if console:
        console.print(f"[bold cyan]OxDM-Linux • Đang kết nối tới Camera ONVIF [{args.ip}]...[/bold cyan]")
    else:
        print(f"[*] Đang kết nối tới Camera ONVIF [{args.ip}]...")

    # 1. Dò tìm endpoint và kiểm tra clock skew
    conn_ok, conn_msg = client.probe_and_connect()
    if not conn_ok:
        if console:
            console.print(f"[bold red]✘ {conn_msg}[/bold red]")
        else:
            print(f"[-] {conn_msg}")
        sys.exit(1)

    # 2. Xác thực (WS-Security Digest / Text / HTTP Digest)
    auth_ok, auth_msg = client.authenticate()
    if not auth_ok:
        if console:
            console.print(f"[bold red]✘ {auth_msg}[/bold red]")
        else:
            print(f"[-] {auth_msg}")
        sys.exit(1)

    # Tải trước các thông số
    client.fetch_capabilities()
    client.fetch_network_interfaces()
    client.fetch_profiles()
    client.fetch_users()

    # Xử lý các chế độ dòng lệnh trực tiếp
    if args.snapshot:
        out_file = None if args.snapshot == "default" else args.snapshot
        ok, path, _ = client.capture_snapshot(output_path=out_file)
        if ok:
            print(f"[+] Snapshot saved to: {path}")
        else:
            print(f"[-] Snapshot failed: {path}")
        return

    if args.stream:
        ok, msg = client.launch_vlc_stream(args.stream)
        print(f"[{'+' if ok else '-'}] {msg}")
        return

    if args.json:
        result = {
            "device": client.device_info,
            "system_time": client.system_time_info,
            "capabilities": client.capabilities,
            "network": client.network_interfaces,
            "profiles": client.profiles,
            "users": client.users
        }
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return

    if args.web:
        start_web_server(client, port=args.web_port)
        return

    # Chế độ tương tác TUI mặc định
    display_camera_summary(client)
    run_interactive_tui(client)


if __name__ == "__main__":
    main()
