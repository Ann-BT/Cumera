#!/usr/bin/env python3
"""
Universal Camera Service & Comprehensive Port Discovery Module
Author: Merlin / Antigravity
Scans network ports across TCP and UDP, identifies protocols, and audits against
declared baseline interfaces to detect undeclared / unauthorized ports.
"""

import socket
import ssl
import sys
import os
import time
import json
import struct
import urllib.request
import urllib.error
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Any, Optional, Tuple, Set

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt

console = Console()

TOOLKIT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(TOOLKIT_DIR, "config.json")
CAPTURES_DIR = os.path.join(TOOLKIT_DIR, "captures")

# --------------------------------------------------------------------------
# Database of Known Camera & IoT Ports across Vendors
# (Axis, Hikvision, Dahua, Uniview, TP-Link, Hanwha, Xiongmai, Tuya, V380, etc.)
# --------------------------------------------------------------------------
CAMERA_KNOWN_PORTS = {
    # Web & Management Interfaces
    80: ("HTTP", "Giao diện Web / ONVIF HTTP (Cleartext)", "tcp", "Web/Admin"),
    443: ("HTTPS", "Giao diện Web bảo mật / ONVIF HTTPS (TLS)", "tcp", "Web/Admin"),
    8080: ("HTTP-Alt", "Cổng Web thay thế / ONVIF HTTP", "tcp", "Web/Admin"),
    8443: ("HTTPS-Alt", "Cổng Web bảo mật thay thế / Alarm Webhook", "tcp", "Web/Admin"),
    8000: ("HTTP-Alt/HikSDK", "Cổng quản trị Hikvision SDK / Web Alt", "tcp", "Vendor SDK"),
    8081: ("HTTP-Proxy", "Cổng Web thứ cấp / Proxy", "tcp", "Web/Admin"),
    8088: ("HTTP-Alarm", "Cổng tiếp nhận cảnh báo Webhook / Event", "tcp", "Web/Admin"),
    8090: ("HTTP-Mgmt", "Cổng cấu hình thiết bị phụ trợ", "tcp", "Web/Admin"),
    8888: ("HTTP-Alt2", "Cổng Web thay thế thứ 2", "tcp", "Web/Admin"),
    9443: ("HTTPS-Alt2", "Cổng HTTPS quản trị nâng cao", "tcp", "Web/Admin"),
    10443: ("HTTPS-Alt3", "Cổng HTTPS thay thế", "tcp", "Web/Admin"),

    # Streaming & Media (RTSP / RTSPS / RTMP / RTP)
    554: ("RTSP", "Luồng video trực tuyến tiêu chuẩn (Cleartext)", "tcp", "Streaming"),
    322: ("RTSPS", "Luồng video mã hóa TLS (AXIS / RFC 2326)", "tcp", "Streaming"),
    332: ("RTSPS-Alt", "Luồng video mã hóa TLS thay thế (AXIS RTSPs)", "tcp", "Streaming"),
    8554: ("RTSP-Alt", "Cổng RTSP thay thế / Uniview RTSP", "tcp", "Streaming"),
    9554: ("RTSPS/TP-Link", "Luồng video mã hóa TLS (TP-Link VIGI / Tapo)", "tcp", "Streaming"),
    10554: ("RTSP-Alt2", "Cổng RTSP thay thế 2", "tcp", "Streaming"),
    1935: ("RTMP", "Giao thức truyền phát trực tiếp RTMP", "tcp", "Streaming"),
    5004: ("RTP", "Real-time Transport Protocol", "tcp", "Streaming"),
    5005: ("RTCP", "RTP Control Protocol", "tcp", "Streaming"),
    7070: ("RealMedia", "RealMedia / QuickTime Streaming Server", "tcp", "Streaming"),

    # Remote Administration & Debugging
    21: ("FTP", "Dịch vụ truyền tệp FTP (Cleartext)", "tcp", "Remote Access"),
    22: ("SSH/SFTP", "Dịch vụ dòng lệnh SSH / SFTP an toàn", "tcp", "Remote Access"),
    23: ("Telnet", "Dịch vụ dòng lệnh Telnet (Không mã hóa - RỦI RO CAO)", "tcp", "Remote Access"),
    2323: ("Telnet-Alt", "Cổng Telnet thay thế (Thường là backdoor/debug)", "tcp", "Remote Access"),
    5555: ("ADB", "Android Debug Bridge / Debug Shell (RỦI RO CAO)", "tcp", "Debug"),
    7777: ("Debug-Shell", "Cổng gỡ lỗi / Debug console", "tcp", "Debug"),
    9999: ("Debug-Port", "Cổng gỡ lỗi nhà sản xuất", "tcp", "Debug"),
    10001: ("Lantronix/Ubnt", "Cổng quản trị nhúng / Debug", "tcp", "Remote Access"),

    # Vendor Proprietary Protocols & Private SDKs
    8200: ("Hik-Data", "Hikvision Data Streaming Port", "tcp", "Vendor SDK"),
    9010: ("Hik-Mobile", "Hikvision Mobile Streaming Port", "tcp", "Vendor SDK"),
    9020: ("Hik-Stream", "Hikvision Secondary Stream Port", "tcp", "Vendor SDK"),
    37777: ("Dahua-SDK", "Cổng giao thức riêng Dahua Private SDK TCP", "tcp", "Vendor SDK"),
    38888: ("Dahua-Reg", "Dahua Auto-Registration Port", "tcp", "Vendor SDK"),
    35000: ("Dahua-Alt", "Cổng phụ Dahua / Imou", "tcp", "Vendor SDK"),
    3800: ("Dahua-Event", "Cổng cảnh báo sự kiện Dahua", "tcp", "Vendor SDK"),
    34567: ("XM-Sofia", "Xiongmai (XM) NetSurveillance / CMS Port", "tcp", "Vendor SDK"),
    34599: ("XM-Search", "Xiongmai Device Search / Config Port", "tcp", "Vendor SDK"),
    60001: ("UNV-SDK", "Uniview (UNV) Private Protocol Port", "tcp", "Vendor SDK"),
    6667: ("Tuya-LAN1", "Tuya SmartLife LAN Protocol Port 1", "tcp", "Vendor SDK"),
    6668: ("Tuya-LAN2", "Tuya SmartLife Encrypted Protocol Port 2", "tcp", "Vendor SDK"),
    2020: ("TP-Link-Ctrl", "TP-Link VIGI / Tapo Management Port", "tcp", "Vendor SDK"),
    8800: ("TP-Link-Media", "TP-Link Media Discovery Port", "tcp", "Vendor SDK"),
    4520: ("Hanwha-Ctrl", "Hanwha / Samsung Camera Control Port", "tcp", "Vendor SDK"),

    # Network Services, VoIP & IoT Protocols
    1883: ("MQTT", "Giao thức tin nhắn IoT MQTT (Cleartext)", "tcp", "IoT/Cloud"),
    8883: ("MQTTS", "Giao thức tin nhắn IoT MQTT qua TLS (Bảo mật)", "tcp", "IoT/Cloud"),
    5060: ("SIP", "Giao thức khởi tạo phiên thoại / video SIP", "tcp", "VoIP/SIP"),
    5061: ("SIPS", "Giao thức SIP mã hóa qua TLS", "tcp", "VoIP/SIP"),
    139: ("NetBIOS-SSN", "Dịch vụ chia sẻ tệp NetBIOS", "tcp", "File Share"),
    445: ("SMB", "Dịch vụ chia sẻ tệp SMB/CIFS (NAS recording)", "tcp", "File Share"),

    # UDP Services (Thăm dò bằng gói tin đặc hiệu)
    161: ("SNMP", "Giao thức quản lý mạng SNMP (Hỗ trợ SNMPv3)", "udp", "Network Service"),
    3702: ("WS-Discovery", "Dò tìm thiết bị ONVIF tự động (Profile S/G/T)", "udp", "Discovery"),
    5353: ("mDNS/Bonjour", "Dò tìm dịch vụ qua mDNS/Bonjour (Apple/Axis)", "udp", "Discovery"),
    1900: ("SSDP", "Simple Service Discovery Protocol (UPnP)", "udp", "Discovery"),
    123: ("NTP", "Giao thức đồng bộ thời gian mạng NTP", "udp", "Network Service"),
    53: ("DNS", "Dịch vụ phân giải tên miền DNS", "udp", "Network Service"),
    37020: ("Hik-SADP", "Hikvision SADP Device Search (UDP)", "udp", "Discovery"),
    37778: ("Dahua-UDP", "Dahua Discovery Protocol (UDP)", "udp", "Discovery"),
    8899: ("V380/ONVIF-UDP", "V380 / ONVIF Discovery (UDP)", "udp", "Discovery"),
}

# Compatibility alias for existing scripts
CAMERA_PORTS = {p: (v[0], v[1], v[2]) for p, v in CAMERA_KNOWN_PORTS.items()}

# Top 1000 commonly used TCP ports (well-known subset)
TOP_TCP_PORTS = [
    21, 22, 23, 25, 53, 80, 81, 88, 110, 111, 135, 139, 143, 161, 322, 332, 389, 443, 445, 465, 514, 554, 587,
    636, 873, 902, 993, 995, 1080, 1194, 1433, 1521, 1723, 1883, 1900, 1935, 2020, 2049, 2121, 2222, 2323,
    3000, 3128, 3268, 3306, 3389, 3702, 3800, 4000, 4443, 4520, 4521, 4522, 4523, 4524, 5000, 5004, 5005,
    5060, 5061, 5222, 5353, 5432, 5555, 5672, 5683, 5684, 5900, 5984, 6000, 6001, 6379, 6667, 6668, 7000,
    7070, 7777, 8000, 8008, 8080, 8081, 8088, 8090, 8181, 8200, 8443, 8554, 8800, 8883, 8888, 8899, 9000,
    9010, 9020, 9090, 9100, 9200, 9443, 9554, 9999, 10000, 10001, 10443, 10554, 11211, 27017, 34567, 34599,
    35000, 37777, 38888, 49152, 50000, 60001
]

def load_config() -> Dict[str, Any]:
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def get_declared_ixit_ports(cfg: Optional[Dict[str, Any]] = None) -> Set[int]:
    """
    Extracts all declared ports from config.json (service_ports, ixit_declared_ports, baseline).
    """
    if cfg is None:
        cfg = load_config()

    declared = set()

    # 1. Explicit ixit_declared_ports list if present (prioritize explicit declaration)
    if "ixit_declared_ports" in cfg and cfg["ixit_declared_ports"]:
        for p in cfg["ixit_declared_ports"]:
            if isinstance(p, int):
                declared.add(p)
            elif isinstance(p, str) and p.isdigit():
                declared.add(int(p))
        return declared

    # 2. Extract from camera inbound service_ports (exclude host receiver ports)
    srv_ports = cfg.get("service_ports", {})
    inbound_keys = ["http", "https", "rtsp", "rtsps", "rtsp_cleartext", "rtsps_tls", "ssh", "snmp", "snmp_udp", "onvif_ws_discovery_udp"]
    for k in inbound_keys:
        val = srv_ports.get(k)
        if isinstance(val, int):
            declared.add(val)
        elif isinstance(val, list):
            for p in val:
                if isinstance(p, int):
                    declared.add(p)

    # 3. Defaults based on camera model if not configured
    model = cfg.get("target_camera", {}).get("model", "")
    if "axis" in model.lower():
        # Standard Axis default declared interfaces (Web 80/443, RTSP 554/322, SSH 22, SNMP 161)
        declared.update([80, 443, 554, 322, 22, 161, 3702])
    elif "tp-link" in model.lower() or "vigi" in model.lower():
        declared.update([80, 443, 554, 9554, 3702])

    return declared

def probe_tcp_port(ip: str, port: int, timeout: float = 0.35) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        res = s.connect_ex((ip, port))
        return res == 0
    except Exception:
        return False
    finally:
        s.close()

def probe_tls(ip: str, port: int, timeout: float = 1.0) -> Tuple[bool, Optional[str], Optional[str]]:
    """Checks if a TCP port speaks TLS/SSL and extracts version and cipher."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
                ver = ssock.version()
                cipher = ssock.cipher()
                c_str = f"{cipher[0]} ({cipher[1]})" if cipher else "Unknown"
                return (True, ver, c_str)
    except Exception:
        return (False, None, None)

def identify_service(ip: str, port: int) -> Dict[str, Any]:
    """Probes the open port deeply to accurately identify the protocol and banner."""
    is_tls, tls_ver, tls_cipher = probe_tls(ip, port)
    info = {
        "is_tls": is_tls,
        "tls_version": tls_ver,
        "tls_cipher": tls_cipher,
        "service_name": "",
        "banner": "",
        "category": "Unknown",
        "details": ""
    }

    # 1. Probe RTSP / RTSPS
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0)
        s.connect((ip, port))
        req = f"DESCRIBE rtsp://{ip}:{port}/ RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: QCVN11-Scanner\r\n\r\n".encode()
        if is_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with ctx.wrap_socket(s, server_hostname=ip) as ssock:
                ssock.sendall(req)
                resp = ssock.recv(1024).decode('latin1', errors='ignore')
        else:
            s.sendall(req)
            resp = s.recv(1024).decode('latin1', errors='ignore')
            s.close()

        if "RTSP/1.0" in resp:
            info["is_tls"] = is_tls
            info["service_name"] = "RTSPS (TLS 1.3/RFC 2326)" if is_tls else "RTSP (Cleartext)"
            info["category"] = "Streaming"
            server_line = [l for l in resp.splitlines() if l.lower().startswith("server:")]
            if server_line:
                info["banner"] = server_line[0]
            info["details"] = resp.splitlines()[0] if resp else "RTSP Service"
            return info
    except Exception:
        pass

    # 2. Probe HTTP / HTTPS
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0)
        s.connect((ip, port))
        http_req = f"GET / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: QCVN11-Auditor\r\nConnection: close\r\n\r\n".encode()
        if is_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with ctx.wrap_socket(s, server_hostname=ip) as ssock:
                ssock.sendall(http_req)
                resp = ssock.recv(1024).decode('latin1', errors='ignore')
        else:
            s.sendall(http_req)
            resp = s.recv(1024).decode('latin1', errors='ignore')
            s.close()

        if "HTTP/" in resp:
            info["service_name"] = "HTTPS (Web/ONVIF)" if is_tls else "HTTP (Web/ONVIF)"
            info["category"] = "Web/Admin"
            first_line = resp.splitlines()[0] if resp else ""
            server_line = [l for l in resp.splitlines() if l.lower().startswith("server:")]
            location_line = [l for l in resp.splitlines() if l.lower().startswith("location:")]
            details = [first_line]
            if server_line:
                info["banner"] = server_line[0]
                details.append(server_line[0])
            if location_line:
                details.append(location_line[0])
            info["details"] = " | ".join(details)
            return info
    except Exception:
        pass

    # 3. Probe SSH banner
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0)
        s.connect((ip, port))
        banner = s.recv(512).decode('latin1', errors='ignore').strip()
        s.close()
        if banner.startswith("SSH-"):
            info["service_name"] = "SSH Service"
            info["category"] = "Remote Access"
            info["banner"] = banner
            info["details"] = f"SSH Server Protocol: {banner}"
            return info
    except Exception:
        pass

    # 4. Probe FTP banner
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0)
        s.connect((ip, port))
        banner = s.recv(512).decode('latin1', errors='ignore').strip()
        s.close()
        if banner.startswith("220"):
            info["service_name"] = "FTP Server (Cleartext)"
            info["category"] = "Remote Access"
            info["banner"] = banner
            info["details"] = banner
            return info
    except Exception:
        pass

    # 5. Probe Telnet (IAC check)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0)
        s.connect((ip, port))
        raw = s.recv(512)
        s.close()
        if b"\xff\xfd" in raw or b"\xff\xfb" in raw or b"login:" in raw.lower():
            info["service_name"] = "Telnet Server (RỦI RO CAO)"
            info["category"] = "Remote Access"
            info["banner"] = repr(raw[:40])
            info["details"] = "Telnet Shell / Unencrypted Remote Access"
            return info
    except Exception:
        pass

    # Fallback to known ports database
    known = CAMERA_KNOWN_PORTS.get(port)
    if known:
        info["service_name"] = known[0]
        info["category"] = known[3]
        info["details"] = known[1]
    else:
        info["service_name"] = "TLS Encrypted Service" if is_tls else "TCP Service (Unknown)"
        info["category"] = "Unknown"
        info["details"] = f"Cổng TCP {port} mở không xác định"

    return info

# --------------------------------------------------------------------------
# UDP Probes Engine
# --------------------------------------------------------------------------
def probe_udp_services(ip: str) -> Dict[int, Dict[str, Any]]:
    """Probes specific UDP services commonly found on IP cameras."""
    udp_results = {}

    # 1. ONVIF WS-Discovery (UDP 3702)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1.0)
        probe = (
            b'<?xml version="1.0" encoding="utf-8"?>'
            b'<Envelope xmlns="http://www.w3.org/2003/05/soap-envelope">'
            b'<Header><wsa:To xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing">urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>'
            b'<wsa:Action xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing">http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action>'
            b'<wsa:MessageID xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing">uuid:12345</wsa:MessageID></Header>'
            b'<Body><Probe xmlns="http://schemas.xmlsoap.org/ws/2005/04/discovery">'
            b'<Types xmlns:dp0="http://www.onvif.org/ver10/network/wsdl">dp0:NetworkVideoTransmitter</Types>'
            b'</Probe></Body></Envelope>'
        )
        s.sendto(probe, (ip, 3702))
        data, _ = s.recvfrom(2048)
        if b"ProbeMatches" in data:
            udp_results[3702] = {
                "port": 3702,
                "proto": "udp",
                "name": "WS-Discovery",
                "category": "Discovery",
                "desc": "Dò quét dịch vụ ONVIF Profile S/G/T (Active)",
                "details": "ONVIF WS-Discovery ProbeMatches received",
                "is_tls": False
            }
        s.close()
    except Exception:
        pass

    # 2. mDNS / Bonjour (UDP 5353) - Popular on Axis, Apple, IoT
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1.0)
        # Standard DNS-SD PTR query for _services._dns-sd._udp.local
        mdns_query = b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x09_services\x07_dns-sd\x04_udp\x05local\x00\x00\x0c\x00\x01"
        s.sendto(mdns_query, (ip, 5353))
        data, _ = s.recvfrom(2048)
        if len(data) > 0:
            # Extract advertised service strings
            text_resp = repr(data)
            services_found = []
            for kw in ["_axis-video", "_vapix", "_https", "_http", "_rtsp", "_printer", "_workstation"]:
                if kw in text_resp:
                    services_found.append(kw)
            srv_summary = ", ".join(services_found) if services_found else "mDNS Responder"
            udp_results[5353] = {
                "port": 5353,
                "proto": "udp",
                "name": "mDNS/Bonjour",
                "category": "Discovery",
                "desc": f"Dịch vụ multicast DNS / Bonjour ({srv_summary})",
                "details": f"Advertised Services: {srv_summary}",
                "is_tls": False
            }
        s.close()
    except Exception:
        pass

    # 3. SNMP (UDP 161) - SNMPv3 EngineID probe + v1/v2 fallback
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.8)
        v3_probe = b'\x30\x3a\x02\x01\x03\x30\x11\x02\x04\x00\x00\x00\x01\x02\x02\x10\x00\x04\x01\x04\x02\x01\x03\x04\x10\x30\x0e\x04\x00\x02\x01\x00\x02\x01\x00\x04\x00\x04\x00\x04\x00\x30\x10\x04\x00\x04\x00\xa0\x0a\x02\x04\x00\x00\x00\x00\x02\x01\x00\x02\x01\x00'
        s.sendto(v3_probe, (ip, 161))
        data, _ = s.recvfrom(2048)
        if len(data) > 0:
            udp_results[161] = {
                "port": 161,
                "proto": "udp",
                "name": "SNMP",
                "category": "Network Service",
                "desc": "Dịch vụ quản trị mạng SNMP (Hỗ trợ SNMPv3)",
                "details": "SNMPv3 EngineID Discovery Responded",
                "is_tls": False
            }
        s.close()
    except Exception:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0.6)
            snmp_probe = b"\x30\x29\x02\x01\x00\x04\x06\x70\x75\x62\x6c\x69\x63\xa0\x1c\x02\x04\x12\x34\x56\x78\x02\x01\x00\x02\x01\x00\x30\x0e\x30\x0c\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00\x05\x00"
            s.sendto(snmp_probe, (ip, 161))
            data, _ = s.recvfrom(2048)
            if len(data) > 0:
                udp_results[161] = {
                    "port": 161,
                    "proto": "udp",
                    "name": "SNMP",
                    "category": "Network Service",
                    "desc": "Dịch vụ quản trị mạng SNMP (v1/v2c)",
                    "details": "SNMP Community Response",
                    "is_tls": False
                }
            s.close()
        except Exception:
            pass

    # 4. SSDP / UPnP (UDP 1900)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.8)
        ssdp_probe = b'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n'
        s.sendto(ssdp_probe, (ip, 1900))
        data, _ = s.recvfrom(2048)
        if b"HTTP/1.1 200 OK" in data:
            udp_results[1900] = {
                "port": 1900,
                "proto": "udp",
                "name": "SSDP/UPnP",
                "category": "Discovery",
                "desc": "Giao thức dò tìm thiết bị SSDP/UPnP",
                "details": "SSDP 200 OK Response",
                "is_tls": False
            }
        s.close()
    except Exception:
        pass

    # 5. Hikvision SADP (UDP 37020)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.8)
        sadp_probe = b'<?xml version="1.0" encoding="utf-8"?><Probe><Uuid>1</Uuid><Types>inquiry</Types></Probe>'
        s.sendto(sadp_probe, (ip, 37020))
        data, _ = s.recvfrom(2048)
        if len(data) > 0 and b"Probe" in data:
            udp_results[37020] = {
                "port": 37020,
                "proto": "udp",
                "name": "Hik-SADP",
                "category": "Discovery",
                "desc": "Hikvision SADP Device Discovery",
                "details": "SADP Inquiry Response",
                "is_tls": False
            }
        s.close()
    except Exception:
        pass

    return udp_results

# --------------------------------------------------------------------------
# High-Speed Multi-Threaded Port Scanner
# --------------------------------------------------------------------------
def scan_tcp_ports_fast(ip: str, ports_to_scan: List[int], timeout: float = 0.35, max_workers: int = 120) -> List[int]:
    """Scans a list of TCP ports using ThreadPoolExecutor for high-speed scanning."""
    open_ports = []

    def check(p):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            if s.connect_ex((ip, p)) == 0:
                return p
        except Exception:
            pass
        finally:
            s.close()
        return None

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(check, p) for p in ports_to_scan]
        for f in as_completed(futures):
            res = f.result()
            if res is not None:
                open_ports.append(res)

    return sorted(open_ports)

# --------------------------------------------------------------------------
# External API & Web Interfaces Surface Scanner (QCVN 11 Khoản 2.6.2 & 2.10.1)
# --------------------------------------------------------------------------
API_PROBE_ENDPOINTS = [
    # ONVIF SOAP Services
    ("/onvif/device_service", "ONVIF SOAP", "Điểm vào dịch vụ thiết bị ONVIF Profile S/G/T (Device Management)", "POST"),
    ("/onvif/media_service", "ONVIF SOAP", "Dịch vụ quản lý cấu hình luồng phát Media ONVIF", "POST"),
    ("/onvif/ptz_service", "ONVIF SOAP", "Dịch vụ điều khiển xoay quét phóng to PTZ", "POST"),
    ("/onvif/imaging_service", "ONVIF SOAP", "Dịch vụ tinh chỉnh thông số cảm biến hình ảnh", "POST"),
    ("/onvif/events", "ONVIF SOAP", "Dịch vụ nhận thông báo sự kiện / cảnh báo", "POST"),

    # AXIS VAPIX Management & Media APIs
    ("/axis-cgi/basicdeviceinfo.cgi", "Axis VAPIX", "Thuộc tính cơ bản thiết bị (BasicDeviceInfo API)", "GET/POST"),
    ("/axis-cgi/param.cgi?action=list&group=root", "Axis VAPIX", "Quản lý toàn bộ tham số hệ thống VAPIX", "GET"),
    ("/axis-cgi/systeminfo.cgi", "Axis VAPIX", "Báo cáo trạng thái hệ điều hành & phần cứng", "GET"),
    ("/axis-cgi/firmwareversion.cgi", "Axis VAPIX", "Kiểm tra phiên bản Firmware hiện tại", "GET"),
    ("/axis-media/media.amp", "Axis Media", "Luồng phát Media RTSP qua HTTP/HTTPS", "GET"),
    ("/axis-cgi/jpg/image.cgi", "Axis Snapshot", "Trích xuất ảnh tĩnh Snapshot JPEG", "GET"),
    ("/axis-cgi/mjpg/video.mjpg", "Axis MJPEG", "Luồng video Motion-JPEG", "GET"),

    # Hikvision ISAPI
    ("/ISAPI/System/deviceInfo", "Hikvision ISAPI", "Thông tin định danh thiết bị ISAPI", "GET"),
    ("/ISAPI/Security/users", "Hikvision ISAPI", "Danh mục tài khoản người dùng ISAPI", "GET"),
    ("/ISAPI/Streaming/channels", "Hikvision ISAPI", "Kênh phát luồng ISAPI Video", "GET"),

    # Generic Web & Remote Management Interfaces
    ("/", "Web Portal", "Giao diện Web Quản trị chính (Web GUI Root)", "GET"),
    ("/index.html", "Web Portal", "Trang đăng nhập Web Admin", "GET"),
    ("/api/", "REST API", "Giao diện REST API gốc", "GET"),
    ("/api/v1/", "REST API", "Giao diện REST API v1", "GET"),
    ("/RPC2", "XML-RPC / Dahua", "Cổng điều khiển máy-với-máy XML-RPC", "POST"),
    ("/cgi-bin/", "CGI Gateway", "Giao diện cổng CGI hệ thống", "GET"),
    ("/swagger", "API Docs", "Tài liệu API Swagger / OpenAPI", "GET"),
    ("/openapi.json", "API Docs", "Đặc tả OpenAPI JSON", "GET"),
]

def scan_external_apis(ip: str, web_ports: List[int], tls_ports: List[int]) -> List[Dict[str, Any]]:
    """
    Probes standard IP Camera API endpoints across open web ports (80, 443, 8080, 8443...)
    to discover active management, video, and machine-to-machine interfaces.
    Audits against baseline external APIs and unauthenticated endpoints.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    discovered = []
    for port in web_ports:
        is_tls = port in tls_ports
        scheme = "https" if is_tls else "http"
        for path, svc_type, desc, expected_method in API_PROBE_ENDPOINTS:
            url = f"{scheme}://{ip}:{port}{path}"
            req = urllib.request.Request(url, headers={"User-Agent": "QCVN11-Auditor/2.4"})
            status_code = None
            resp_body = ""
            try:
                with urllib.request.urlopen(req, timeout=0.8, context=ctx if is_tls else None) as resp:
                    status_code = resp.status
                    raw = resp.read(256)
                    resp_body = raw.decode("latin1", errors="ignore").strip()
            except urllib.error.HTTPError as e:
                status_code = e.code
                try:
                    raw = e.read(256)
                    resp_body = raw.decode("latin1", errors="ignore").strip()
                except Exception:
                    resp_body = str(e.reason)
            except Exception:
                continue

            if status_code in [200, 301, 302, 401, 403, 405]:
                # Evaluate auth & security
                if status_code in [401, 403]:
                    auth_eval = "BẢO VỆ (Yêu cầu xác thực)"
                    eval_color = "green"
                    risk_note = "Chặn truy cập trái phép an toàn"
                elif status_code == 405:
                    auth_eval = "HOẠT ĐỘNG (Cần SOAP/POST)"
                    eval_color = "cyan"
                    risk_note = "Endpoint SOAP/RPC đang lắng nghe"
                elif status_code in [301, 302]:
                    auth_eval = "CHUYỂN HƯỚNG (Redirect)"
                    eval_color = "yellow"
                    risk_note = "Chuyển tiếp kênh bảo mật"
                elif status_code == 200:
                    auth_eval = "MỞ TRỰC TIẾP (Không xác thực)"
                    eval_color = "yellow"
                    if any(k in resp_body.lower() for k in ["apiversion", "version", "model", "serial", "mac", "firmware"]):
                        risk_note = "Tiết lộ phiên bản/API (Khoản 2.6.2)"
                    else:
                        risk_note = "Giao diện Web / Tài nguyên công khai"
                else:
                    auth_eval = f"HTTP {status_code}"
                    eval_color = "white"
                    risk_note = "Phản hồi dịch vụ"

                discovered.append({
                    "port": port,
                    "proto": "https" if is_tls else "http",
                    "path": path,
                    "url": url,
                    "service_type": svc_type,
                    "description": desc,
                    "status_code": status_code,
                    "auth_status": auth_eval,
                    "eval_color": eval_color,
                    "risk_note": risk_note,
                    "snippet": resp_body[:80].replace("\n", " ").replace("\r", " ")
                })

    return discovered

# --------------------------------------------------------------------------
# Main Scanner Function & Discrepancy Auditor
# --------------------------------------------------------------------------
def scan_camera_services(
    ip: str,
    scan_mode: str = "top_1000",
    custom_ports: Optional[List[int]] = None,
    declared_ixit_ports: Optional[Set[int]] = None
) -> Dict[str, Any]:
    """
    Exhaustively scans target ports, identifies services, discovers external APIs,
    and compares with baseline declarations.
    Scan modes:
      - 'camera_known': Standard known ports (~50 ports)
      - 'top_1000' / 'auto': Top common TCP ports + probes
      - 'full_range': Full TCP 1-65535 ports (high-speed) + UDP probes
      - 'custom': Custom port list specified by user
    """
    start_time = time.time()

    # Determine TCP ports to scan
    if scan_mode == "full_range":
        ports_list = list(range(1, 65536))
        max_workers = 250
    elif scan_mode in ["top_1000", "auto"]:
        ports_list = sorted(list(set(TOP_TCP_PORTS + list(CAMERA_KNOWN_PORTS.keys()))))
        max_workers = 150
    elif scan_mode == "custom" and custom_ports:
        ports_list = sorted(list(set(custom_ports)))
        max_workers = 150
    else: # Default: camera_known
        ports_list = sorted([p for p, v in CAMERA_KNOWN_PORTS.items() if v[2] == "tcp"])
        max_workers = 120

    # Load declared ports
    if declared_ixit_ports is None:
        declared_ixit_ports = get_declared_ixit_ports()

    results = {
        "ip": ip,
        "scan_time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "scan_mode": scan_mode,
        "ports_probed_count": len(ports_list),
        "tcp_open": [],
        "udp_open": [],
        "tls_ports": [],
        "cleartext_ports": [],
        "services": {},
        "external_apis": [],
        "ixit_audit": {
            "declared_ports": sorted(list(declared_ixit_ports)),
            "declared_and_open": [],
            "declared_but_closed": [],
            "undeclared_open_ports": [],
            "compliance_status": "ĐẠT"
        }
    }

    # 1. High-speed TCP Scan
    open_tcp = scan_tcp_ports_fast(ip, ports_list, timeout=0.25 if scan_mode == "full_range" else 0.35, max_workers=max_workers)
    results["tcp_open"] = open_tcp

    # 2. Deep Protocol & Banner Identification on Open TCP Ports
    for port in open_tcp:
        p_info = identify_service(ip, port)
        is_tls = p_info["is_tls"]
        if is_tls:
            results["tls_ports"].append(port)
        else:
            results["cleartext_ports"].append(port)

        results["services"][port] = {
            "port": port,
            "proto": "tcp",
            "name": p_info["service_name"],
            "category": p_info["category"],
            "desc": p_info["details"],
            "banner": p_info["banner"],
            "is_tls": is_tls,
            "tls_version": p_info["tls_version"],
            "tls_cipher": p_info["tls_cipher"],
            "ixit_declared": port in declared_ixit_ports
        }

    # 3. Probe UDP Services
    udp_svcs = probe_udp_services(ip)
    for u_port, u_info in udp_svcs.items():
        results["udp_open"].append(u_port)
        u_info["ixit_declared"] = u_port in declared_ixit_ports
        results["services"][u_port] = u_info

    # 4. Probe External APIs & Web Interfaces
    web_ports = [
        p for p in results["tcp_open"]
        if p in [80, 443, 8080, 8443, 8000, 8081, 8088, 8090, 8888, 9443, 10443]
        or "http" in results["services"].get(p, {}).get("name", "").lower()
        or "web" in results["services"].get(p, {}).get("category", "").lower()
    ]
    if web_ports:
        results["external_apis"] = scan_external_apis(ip, web_ports, results["tls_ports"])

    # 5. Perform Discrepancy Audit
    all_open_ports = set(results["tcp_open"] + results["udp_open"])

    for p in declared_ixit_ports:
        if p in all_open_ports:
            results["ixit_audit"]["declared_and_open"].append(p)
        else:
            results["ixit_audit"]["declared_but_closed"].append(p)

    for p in all_open_ports:
        if p not in declared_ixit_ports:
            results["ixit_audit"]["undeclared_open_ports"].append(p)

    # Compliance status
    if results["ixit_audit"]["undeclared_open_ports"]:
        results["ixit_audit"]["compliance_status"] = "CẢNH BÁO BẤT THƯỜNG (CÓ CỔNG NGOÀI DANH MỤC)"
    else:
        results["ixit_audit"]["compliance_status"] = "ĐẠT (HOÀN TOÀN HỢP LỆ)"

    results["elapsed_seconds"] = round(time.time() - start_time, 2)

    # Save evidence file automatically
    os.makedirs(CAPTURES_DIR, exist_ok=True)
    json_path = os.path.join(CAPTURES_DIR, "port_scan_ixit_audit.json")
    try:
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
    except Exception:
        pass

    return results

# --------------------------------------------------------------------------
# Terminal Display Functions
# --------------------------------------------------------------------------
def display_service_scan(results: Dict[str, Any]):
    ip = results["ip"]
    mode_str = results.get("scan_mode", "standard").upper()
    elapsed = results.get("elapsed_seconds", 0)
    probed = results.get("ports_probed_count", 0)

    console.print(f"\n[bold cyan]THỐNG KÊ QUÉT CỔNG, DỊCH VỤ & BỀ MẶT API - THIẾT BỊ: {ip}[/bold cyan]")
    console.print(f"[dim]Chế độ: {mode_str} | Số cổng thăm dò: {probed} | Thời gian quét: {elapsed}s[/dim]\n")

    # Table 1: Network Ports & Services (TCP & UDP)
    table = Table(title=f"BẢNG 1: CÁC CỔNG MẠNG & DỊCH VỤ PHÁT HIỆN TRÊN THIẾT BỊ ({ip})", show_lines=True, expand=True)
    table.add_column("Cổng (Port)", style="bold yellow", justify="center", width=12)
    table.add_column("Giao thức", justify="center", width=10)
    table.add_column("Dịch vụ nhận diện", style="bold white", width=22)
    table.add_column("Kênh truyền", justify="center", width=18)
    table.add_column("Trạng thái / Đánh giá", justify="center", width=26)
    table.add_column("Chi tiết / Banner", style="dim")

    if not results["services"]:
        console.print("[yellow][!] Không tìm thấy cổng mở nào trên camera trong dải quét đã chọn.[/yellow]")
    else:
        for p, info in sorted(results["services"].items()):
            port_str = str(info["port"])
            proto_str = info["proto"].upper()
            svc_str = info.get("name", "Unknown")
            is_tls = info.get("is_tls", False)

            enc_str = "[bold green]MÃ HÓA TLS[/bold green]" if is_tls else "[yellow]DẠNG RÕ[/yellow]"
            if info.get("tls_version"):
                enc_str += f"\n[dim]({info['tls_version']})[/dim]"

            # Status Column
            is_declared = info.get("ixit_declared", False)
            if is_declared:
                ixit_str = "[bold green][HỢP LỆ / CHO PHÉP][/bold green]"
            else:
                ixit_str = "[bold red blink][!] CỔNG MỞ NGOÀI DANH MỤC[/bold red blink]"

            desc_str = info.get("desc", "")
            if info.get("banner"):
                desc_str += f"\n[dim cyan]Banner: {info['banner']}[/dim cyan]"

            table.add_row(port_str, proto_str, svc_str, enc_str, ixit_str, desc_str)

        console.print(table)

    # Table 2: External APIs & Web Endpoints
    apis = results.get("external_apis", [])
    if apis:
        api_table = Table(title=f"BẢNG 2: BỀ MẶT GIAO DIỆN API & ĐIỂM VÀO ĐIỀU KHIỂN TỪ XA ({ip})", show_lines=True, expand=True)
        api_table.add_column("Cổng", style="bold yellow", justify="center", width=8)
        api_table.add_column("Endpoint API", style="bold cyan", width=32)
        api_table.add_column("Phân loại Giao diện", style="bold white", width=16)
        api_table.add_column("Mã HTTP", justify="center", width=10)
        api_table.add_column("Kiểm soát Truy cập", justify="center", width=24)
        api_table.add_column("Đánh giá An toàn / Tiết lộ", style="dim")

        for a in apis:
            port_txt = f"{a['port']}/{a['proto'].upper()}"
            status_txt = f"[bold white]{a['status_code']}[/bold white]"
            auth_txt = f"[{a['eval_color']}]{a['auth_status']}[/{a['eval_color']}]"
            risk_txt = a["risk_note"]
            if a["snippet"]:
                risk_txt += f"\n[dim]Trích xuất: {a['snippet'][:60]}[/dim]"

            api_table.add_row(
                port_txt,
                a["path"],
                a["service_type"],
                status_txt,
                auth_txt,
                risk_txt
            )

        console.print("\n")
        console.print(api_table)

    # Summary Panel
    audit = results.get("ixit_audit", {})
    undeclared = audit.get("undeclared_open_ports", [])
    declared_open = audit.get("declared_and_open", [])
    declared_closed = audit.get("declared_but_closed", [])

    panel_content = [
        f"[bold white]Tổng số cổng mở phát hiện:[/bold white] [bold yellow]{len(results['services'])}[/bold yellow] (TCP: {len(results['tcp_open'])}, UDP: {len(results['udp_open'])})",
        f"[bold white]Cổng khớp với danh mục cho phép (Baseline):[/bold white] [bold green]{declared_open}[/bold green]",
        f"[bold white]Cổng trong danh mục nhưng đang tắt (An toàn):[/bold white] [dim]{declared_closed}[/dim]",
        f"[bold white]Số Endpoint API bên ngoài phát hiện:[/bold white] [bold cyan]{len(apis)} điểm vào[/bold cyan]"
    ]

    if undeclared:
        panel_content.append(
            f"\n[bold red][CẢNH BÁO BẤT THƯỜNG] Phát hiện các cổng mở NGOÀI DANH MỤC CHO PHÉP:[/bold red] [bold red blink]{undeclared}[/bold red blink]\n"
            f"  - Thiết bị đang mở giao diện logic / dịch vụ mạng chưa được khai báo hoặc phê duyệt trong danh mục.\n"
            f"  - Tiềm ẩn nguy cơ tấn công qua giao diện không kiểm soát hoặc dịch vụ thừa.\n"
            f"  - [bold white]Khuyến nghị kiểm thử:[/bold white] Cần rà soát mục đích sử dụng hoặc vô hiệu hóa các cổng này."
        )
        border_col = "red"
    else:
        panel_content.append(
            f"\n[bold green][ĐẠT] 100% cổng mở trên thiết bị đều nằm trong danh mục dịch vụ được phép.[/bold green]"
        )
        border_col = "green"

    console.print(Panel("\n".join(panel_content), title="[bold cyan]KẾT QUẢ ĐỐI SOÁT DANH MỤC CỔNG DỊCH VỤ (BASELINE)[/bold cyan]", border_style=border_col))
    console.print(f"[dim]Bằng chứng đã được lưu tự động tại: captures/port_scan_ixit_audit.json[/dim]\n")

# --------------------------------------------------------------------------
# Interactive CLI Menu
# --------------------------------------------------------------------------
def interactive_menu(ip: str):
    cfg = load_config()
    model = cfg.get("target_camera", {}).get("model", "IP Camera")
    declared = get_declared_ixit_ports(cfg)

    while True:
        console.clear()
        console.print(Panel(
            f"[bold cyan]MÔ-ĐUN DÒ QUÉT CỔNG TOÀN DIỆN & NHẬN DIỆN DỊCH VỤ[/bold cyan]\n"
            f"Thiết bị mục tiêu: [bold white]{ip} ({model})[/bold white]\n"
            f"Cổng trong danh mục cho phép (Baseline): [bold yellow]{sorted(list(declared))}[/bold yellow]",
            border_style="cyan"
        ))

        t = Table(show_header=True, header_style="bold magenta", expand=True)
        t.add_column("Tùy chọn", style="bold yellow", width=10, justify="center")
        t.add_column("Chế độ quét cổng & Đối chiếu", style="bold white", width=38)
        t.add_column("Chi tiết kỹ thuật & Mục đích kiểm thử", style="dim")

        t.add_row("1", "Quét danh mục cổng dịch vụ mở rộng", "Quét ~50 cổng phổ biến (Web, RTSP, SSH, Telnet, Hik, Dahua, XM, Axis) & UDP")
        t.add_row("2", "Quét Top 1000 cổng TCP phổ biến", "Quét nhanh 1000 cổng phổ biến nhất mạng TCP bằng đa luồng socket")
        t.add_row("3", "Quét TOÀN DIỆN dải cổng 1 - 65535", "Quét vét cạn 100% không gian cổng 1-65535 siêu tốc (ThreadPool 250 luồng)")
        t.add_row("4", "Quét dải cổng tùy chỉnh", "Nhập danh sách cổng hoặc dải cổng cụ thể (ví dụ: 1-1024, 8000-9000)")
        t.add_row("5", "Cập nhật danh sách cổng cho phép (Baseline)", "Thay đổi danh sách cổng dùng để đối chiếu cho thiết bị này")
        t.add_row("0", "[bold red]Quay lại Menu chính[/bold red]", "")
        console.print(t)

        choice = Prompt.ask("\nNhập lựa chọn", default="1").strip()

        if choice == "0":
            break
        elif choice == "1":
            console.print(f"\n[*] Đang quét danh mục cổng dịch vụ mở rộng trên {ip}...")
            res = scan_camera_services(ip, scan_mode="camera_known", declared_ixit_ports=declared)
            display_service_scan(res)
            input("\nBấm Enter để tiếp tục...")
        elif choice == "2":
            console.print(f"\n[*] Đang quét Top 1000 cổng TCP phổ biến trên {ip}...")
            res = scan_camera_services(ip, scan_mode="top_1000", declared_ixit_ports=declared)
            display_service_scan(res)
            input("\nBấm Enter để tiếp tục...")
        elif choice == "3":
            console.print(f"\n[bold yellow][*] Đang khởi chạy quét toàn bộ 65.535 cổng TCP trên {ip}...[/bold yellow]")
            res = scan_camera_services(ip, scan_mode="full_range", declared_ixit_ports=declared)
            display_service_scan(res)
            input("\nBấm Enter để tiếp tục...")
        elif choice == "4":
            raw_ports = Prompt.ask("Nhập dải cổng (ví dụ: 1-1024 hoặc 80,443,554,8000,37777)", default="1-1024").strip()
            custom_list = []
            try:
                if "-" in raw_ports:
                    parts = raw_ports.split("-")
                    custom_list = list(range(int(parts[0]), int(parts[1]) + 1))
                else:
                    custom_list = [int(p.strip()) for p in raw_ports.split(",") if p.strip().isdigit()]
            except Exception as e:
                console.print(f"[red]Lỗi cú pháp dải cổng: {e}[/red]")
                input("\nBấm Enter để tiếp tục...")
                continue

            console.print(f"\n[*] Đang quét {len(custom_list)} cổng tùy chỉnh trên {ip}...")
            res = scan_camera_services(ip, scan_mode="custom", custom_ports=custom_list, declared_ixit_ports=declared)
            display_service_scan(res)
            input("\nBấm Enter để tiếp tục...")
        elif choice == "5":
            curr_str = ",".join([str(p) for p in sorted(list(declared))])
            new_str = Prompt.ask("Nhập danh sách cổng cho phép (phân tách bởi dấu phẩy)", default=curr_str).strip()
            try:
                new_ports = set([int(p.strip()) for p in new_str.split(",") if p.strip().isdigit()])
                declared = new_ports
                # Save to config.json
                cfg["ixit_declared_ports"] = sorted(list(new_ports))
                with open(CONFIG_PATH, "w", encoding="utf-8") as f:
                    json.dump(cfg, f, indent=2, ensure_ascii=False)
                console.print(f"[green][OK] Đã cập nhật danh sách cổng cho phép: {sorted(list(new_ports))}[/green]")
            except Exception as e:
                console.print(f"[red]Lỗi lưu cấu hình: {e}[/red]")
            input("\nBấm Enter để tiếp tục...")

def main():
    parser = argparse.ArgumentParser(description="Universal Service & Comprehensive Port Discovery Module")
    parser.add_argument("target_ip", nargs="?", default=None, help="Địa chỉ IP của Camera DUT")
    parser.add_argument("--ip", default=None, help="Địa chỉ IP của Camera DUT")
    parser.add_argument("--full", action="store_true", help="Quét toàn bộ 1 - 65535 cổng TCP + UDP + API endpoints (Toàn diện)")
    parser.add_argument("--fast", action="store_true", help="Quét danh mục cổng camera đặc thù (~50 cổng) + UDP + API")
    parser.add_argument("--auto", action="store_true", help="Tự động quét toàn diện không dừng tương tác (Mặc định)")
    parser.add_argument("-i", "--interactive", action="store_true", help="Mở menu dòng lệnh tương tác (CLI)")

    args = parser.parse_args()

    cfg = load_config()
    dut_ip = args.ip or args.target_ip or cfg.get("target_camera", {}).get("ip", "192.168.20.38")

    # If user explicitly requested interactive mode in terminal:
    if args.interactive and sys.stdin.isatty():
        interactive_menu(dut_ip)
        return

    # Non-interactive / Automated execution:
    if args.full:
        mode = "full_range"
    elif args.fast:
        mode = "camera_known"
    else:
        # Standard auto mode: scans all camera ports + top TCP ports + UDP + APIs
        mode = "top_1000"

    declared = get_declared_ixit_ports(cfg)
    console.print(f"\n[bold cyan][*] Khởi chạy Dò quét Toàn diện trên mục tiêu:[/bold cyan] [bold white]{dut_ip}[/bold white] [dim](Chế độ: {mode})[/dim]...")
    res = scan_camera_services(dut_ip, scan_mode=mode, declared_ixit_ports=declared)
    display_service_scan(res)

if __name__ == '__main__':
    main()
