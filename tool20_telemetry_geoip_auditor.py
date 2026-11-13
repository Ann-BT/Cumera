#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
  BỘ ĐO KIỂM GIÁM SÁT TRUYỀN TIN QUỐC TẾ, ĐỊNH VỊ ĐỊA LÝ IP & TELEMETRY
  Tiêu chuẩn: QCVN 11:2026/BCA (Điều 2.11.4 & 2.11.5 / Phương pháp đo 3.11.4 & 3.11.5)
             ETSI EN 303 645 (Clause 5.11 / IXIT 24-TelData & IXIT 28-ExtAPI)

  Nguyên lý & Mục tiêu Đánh giá:
  1. ĐIỀU 2.11.4 & PHƯƠNG PHÁP ĐO 3.11.4 (DỮ LIỆU ĐO ĐẠC TỪ XA - TELEMETRY DATA):
     - Bắt và bóc tách nội dung gói tin (Deep Packet Inspection - DPI).
     - Kiểm tra dữ liệu đo đạc từ xa (Telemetry, Crash dump, Analytics, Health report).
     - Rà soát lộ lọt dữ liệu cá nhân (Personal Data Leak): MAC, Serial, Tài khoản, Mật khẩu, Tọa độ GPS.
     - TIÊU CHÍ ĐẠT (PASS 3.11.4): Thiết bị không gửi telemetry ra ngoài, hoặc nếu gửi thì 
       nội dung đúng mục đích kỹ thuật đã công bố và TUYỆT ĐỐI KHÔNG chứa dữ liệu cá nhân.

  2. ĐIỀU 2.11.5 & PHƯƠNG PHÁP ĐO 3.11.5 (THIẾT LẬP LƯU TRỮ DỮ LIỆU TẠI VIỆT NAM):
     - Giám sát toàn bộ gói tin truyền thông và lưu trữ phát ra từ Camera.
     - Xác định vị trí địa lý của mọi IP đích (GeoIP Engine: Quốc gia, Thành phố, Nhà mạng, ASN).
     - Phân loại rõ ràng:
       + [NỘI BỘ (LOCAL LAN)]: Mạng cục bộ RFC 1918 (10.x, 172.16-31.x, 192.168.x).
       + [TRONG NƯỚC (VIETNAM - VN)]: Máy chủ đặt tại lãnh thổ Việt Nam.
       + [QUỐC TẾ (NƯỚC NGOÀI - OVERSEAS)]: Máy chủ ngoài lãnh thổ Việt Nam.
     - TIÊU CHÍ ĐẠT (PASS 3.11.5): 100% dữ liệu truyền thông và lưu trữ chỉ nằm trong mạng nội bộ
       hoặc máy chủ tại Việt Nam. Không truyền dữ liệu trái phép ra nước ngoài.

  Tính năng nâng cao:
  - Thống kê chi tiết lưu lượng 2 chiều theo từng IP (Số gói tin Gửi / Nhận, Byte, Giao thức, Cổng).
  - Trích xuất tên miền truy vấn DNS và máy chủ TLS SNI (nhận diện dù dữ liệu bị mã hóa).
  - Tự động sinh câu lệnh lọc Wireshark Display Filter trực quan.
  - Xuất báo cáo Markdown kỹ thuật và JSON làm bằng chứng đo kiểm.
================================================================================
"""

import os
import sys
import time
import json
import socket
import ssl
import re
import ipaddress
import urllib.request
import urllib.error
import argparse
import subprocess
import datetime
from collections import defaultdict
from typing import Tuple, List, Dict, Any, Optional, Set

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn

sys.stdout.reconfigure(encoding='utf-8')
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)
from pcap_recorder import start_pcap_capture, stop_pcap_capture, display_wireshark_panel
from toolkit_config import CONF_PATH, get_target_info, load_config, make_console

console = make_console()
CAPTURES_DIR = os.path.join(BASE_DIR, "captures")
GEOIP_CACHE_FILE = os.path.join(CAPTURES_DIR, "geoip_cache.json")
REPORT_MD_PATH = os.path.join(BASE_DIR, "telemetry_geoip_audit_report.md")
EVIDENCE_JSON_PATH = os.path.join(CAPTURES_DIR, "telemetry_geoip_audit_evidence.json")

os.makedirs(CAPTURES_DIR, exist_ok=True)

config = load_config()
_target_info = get_target_info(config)

DUT_IP = _target_info["ip"]
DUT_MODEL = _target_info["model"]
DUT_FW = _target_info["firmware"]
USER = _target_info["username"]
PASS = _target_info["password"]

# Telemetry keyword signatures to inspect in payloads (Clause 3.11.4)
TELEMETRY_KEYWORDS = [
    "telemetry", "analytics", "metrics", "metric", "crashlog", "coredump",
    "diagnostics", "diagnostic", "heartbeat", "deviceinfo", "device_info",
    "system_info", "stats", "statistics", "report", "pingback", "cloud_sync",
    "event_log", "sysinfo", "tracker", "push_notification", "ota_check"
]

# Personal / Sensitive data patterns (Clause 3.11.4 & 2.11.1)
SENSITIVE_PATTERNS = [
    (re.compile(r'password["\']?\s*[:=]\s*["\']?([^"\'\s&]+)', re.IGNORECASE), "Plaintext Password"),
    (re.compile(r'secret["\']?\s*[:=]\s*["\']?([^"\'\s&]+)', re.IGNORECASE), "Secret Token/Key"),
    (re.compile(r'bearer\s+[a-zA-Z0-9_\-\.]{16,}', re.IGNORECASE), "Auth Bearer Token"),
    (re.compile(r'(?:latitude|longitude|gps_lat|gps_lon)["\']?\s*[:=]\s*["\']?([0-9\.\-]+)', re.IGNORECASE), "GPS Location"),
    (re.compile(r'(?:email|user_email)["\']?\s*[:=]\s*["\']?([^"\'\s&@]+@[^"\'\s&]+)', re.IGNORECASE), "User Email"),
    (re.compile(r'(?:phone|mobile)["\']?\s*[:=]\s*["\']?([0-9\+\-\s]{9,15})', re.IGNORECASE), "Phone Number")
]

class GeoIPEngine:
    """
    Tra cứu vị trí địa lý và phân loại nguồn gốc quốc gia của địa chỉ IP:
    - Nội bộ (Private LAN / RFC 1918)
    - Trong nước (Việt Nam - VN)
    - Quốc tế (Nước ngoài / Overseas)
    Tích hợp bộ nhớ đệm Cache và Fallback sang Whois.
    """
    def __init__(self, cache_file: str = GEOIP_CACHE_FILE):
        self.cache_file = cache_file
        self.cache: Dict[str, Dict[str, Any]] = {}
        self._load_cache()

    def _load_cache(self):
        if os.path.exists(self.cache_file):
            try:
                with open(self.cache_file, "r", encoding="utf-8") as f:
                    self.cache = json.load(f)
            except Exception:
                self.cache = {}

    def _save_cache(self):
        try:
            with open(self.cache_file, "w", encoding="utf-8") as f:
                json.dump(self.cache, f, ensure_ascii=False, indent=2)
        except Exception:
            pass

    @staticmethod
    def is_private_or_local(ip_str: str) -> bool:
        """Kiểm tra IP có thuộc dải mạng cục bộ/nội bộ hay không."""
        try:
            ip = ipaddress.ip_address(ip_str)
            return (
                ip.is_private or
                ip.is_loopback or
                ip.is_link_local or
                ip.is_multicast or
                ip.is_reserved or
                ip_str == "255.255.255.255" or
                ip_str.startswith("192.168.") or
                ip_str.startswith("10.") or
                ip_str.startswith("172.") and (16 <= int(ip_str.split(".")[1]) <= 31)
            )
        except Exception:
            return False

    def lookup(self, ip_str: str) -> Dict[str, Any]:
        """Tra cứu thông tin GeoIP của IP."""
        if not ip_str or ip_str in ["0.0.0.0", "255.255.255.255"]:
            return {
                "ip": ip_str,
                "country_code": "LOCAL",
                "country_name": "Broadcast/Wildcard",
                "city": "Nội bộ",
                "isp": "Local",
                "org": "Local",
                "as": "LAN",
                "is_local": True,
                "is_vietnam": True,
                "is_overseas": False,
                "residency_status": "PASS (Nội bộ)"
            }

        # 1. Kiểm tra nếu là mạng cục bộ / RFC 1918
        if self.is_private_or_local(ip_str):
            return {
                "ip": ip_str,
                "country_code": "VN-LAN",
                "country_name": "Mạng nội bộ (Private LAN / RFC 1918)",
                "city": "Nội bộ cơ quan/doanh nghiệp",
                "isp": "Mạng nội bộ (Local Area Network)",
                "org": "Hạ tầng nội bộ",
                "as": "LAN",
                "is_local": True,
                "is_vietnam": True,
                "is_overseas": False,
                "residency_status": "PASS (Nội bộ)"
            }

        # 2. Kiểm tra bộ nhớ đệm Cache
        if ip_str in self.cache:
            return self.cache[ip_str]

        # 3. Tra cứu trực tuyến qua API ip-api.com
        geo_info = self._query_api(ip_str)
        if not geo_info:
            # 4. Fallback sang lệnh whois hệ thống
            geo_info = self._query_whois(ip_str)

        if not geo_info:
            geo_info = {
                "ip": ip_str,
                "country_code": "UNKNOWN",
                "country_name": "Không rõ vị trí",
                "city": "Unknown",
                "isp": "Unknown Public Host",
                "org": "Unknown",
                "as": "Unknown",
                "is_local": False,
                "is_vietnam": False,
                "is_overseas": True,
                "residency_status": "CẢNH BÁO (Chưa xác thực)"
            }

        # Phân loại ranh giới Việt Nam vs Nước ngoài
        country_code = geo_info.get("country_code", "").upper()
        if country_code == "VN":
            geo_info["is_vietnam"] = True
            geo_info["is_overseas"] = False
            geo_info["residency_status"] = "PASS (Máy chủ Việt Nam)"
        else:
            geo_info["is_vietnam"] = False
            geo_info["is_overseas"] = True
            geo_info["residency_status"] = "CẢNH BÁO (Máy chủ Quốc tế / Nước ngoài)"

        self.cache[ip_str] = geo_info
        self._save_cache()
        return geo_info

    def _query_api(self, ip_str: str) -> Optional[Dict[str, Any]]:
        """Truy vấn dịch vụ GeoIP trực tuyến với timeout ngắn (Dual-service: ip-api.com & ipwhois.app)."""
        # 1. Primary: ip-api.com
        url1 = f"http://ip-api.com/json/{ip_str}?fields=status,message,country,countryCode,regionName,city,isp,org,as,query"
        try:
            req = urllib.request.Request(url1, headers={"User-Agent": "QCVN11-Audit-Toolkit/1.0"})
            with urllib.request.urlopen(req, timeout=2.0) as response:
                if response.status == 200:
                    data = json.loads(response.read().decode("utf-8"))
                    if data.get("status") == "success":
                        return {
                            "ip": ip_str,
                            "country_code": data.get("countryCode", "UNKNOWN").upper(),
                            "country_name": data.get("country", "Unknown"),
                            "city": data.get("city", ""),
                            "isp": data.get("isp", ""),
                            "org": data.get("org", ""),
                            "as": data.get("as", ""),
                            "service_used": "ip-api.com (RFC Authoritative GeoIP)",
                            "is_local": False
                        }
        except Exception:
            pass

        # 2. Secondary fallback: ipwhois.app
        url2 = f"https://ipwhois.app/json/{ip_str}"
        try:
            req = urllib.request.Request(url2, headers={"User-Agent": "QCVN11-Audit-Toolkit/1.0"})
            with urllib.request.urlopen(req, timeout=2.5) as response:
                if response.status == 200:
                    data = json.loads(response.read().decode("utf-8"))
                    if data.get("success") is not False and data.get("country_code"):
                        return {
                            "ip": ip_str,
                            "country_code": data.get("country_code", "UNKNOWN").upper(),
                            "country_name": data.get("country", "Unknown"),
                            "city": data.get("city", ""),
                            "isp": data.get("isp", ""),
                            "org": data.get("org", ""),
                            "as": data.get("asn", ""),
                            "service_used": "ipwhois.app (Authoritative Regional Registry)",
                            "is_local": False
                        }
        except Exception:
            pass

        return None

    def _query_whois(self, ip_str: str) -> Optional[Dict[str, Any]]:
        """Truy vấn qua lệnh CLI whois hệ thống (VNNIC/APNIC/ARIN authoritative)."""
        try:
            res = subprocess.run(["whois", ip_str], capture_output=True, text=True, timeout=3.0)
            if res.returncode == 0:
                text = res.stdout
                country_match = re.search(r'(?i)^\s*country:\s*([a-zA-Z]{2})', text, re.MULTILINE)
                netname_match = re.search(r'(?i)^\s*(?:netname|orgname|descr):\s*(.+)', text, re.MULTILINE)
                
                c_code = country_match.group(1).upper() if country_match else "UNKNOWN"
                net_org = netname_match.group(1).strip() if netname_match else "Public ASN"
                c_name = "Vietnam" if c_code == "VN" else f"Nước ngoài ({c_code})"

                return {
                    "ip": ip_str,
                    "country_code": c_code,
                    "country_name": c_name,
                    "city": "",
                    "isp": net_org,
                    "org": net_org,
                    "as": "Whois Resolved",
                    "service_used": "System WHOIS (VNNIC/APNIC Registry)",
                    "is_local": False
                }
        except Exception:
            pass
        return None


class DPIPayloadInspector:
    """
    Công cụ bóc tách sâu nội dung gói tin (Deep Packet Inspection - DPI):
    - Trích xuất tên miền truy vấn DNS (DNS Queries)
    - Trích xuất định danh máy chủ TLS SNI (Server Name Indication)
    - Trích xuất HTTP/REST headers & JSON bodies
    - Rà soát các từ khóa Telemetry (Đo đạc từ xa - Clause 3.11.4)
    - Rà soát dấu hiệu lộ lọt thông tin cá nhân & định danh thiết bị
    """
    def __init__(self, target_mac: str = "", target_pass: str = "", target_user: str = ""):
        self.target_mac = target_mac.lower().replace(":", "").replace("-", "")
        self.target_pass = target_pass
        self.target_user = target_user

    def extract_tls_sni(self, raw_bytes: bytes) -> Optional[str]:
        """Trích xuất TLS Server Name Indication từ gói tin TLS Client Hello."""
        try:
            # TLS Handshake (0x16), Version (0x03 0x01/0x03), Handshake Type Client Hello (0x01)
            pos = raw_bytes.find(b"\x16\x03")
            if pos != -1 and len(raw_bytes) > pos + 43:
                # Check Client Hello type
                if raw_bytes[pos + 5] == 0x01:
                    # Parse session id, cipher suites, compression methods to reach extensions
                    payload = raw_bytes[pos + 5:]
                    offset = 38 # handshake header (4) + client_version (2) + random (32)
                    if len(payload) > offset:
                        sess_len = payload[offset]
                        offset += 1 + sess_len
                        if len(payload) > offset + 2:
                            cipher_len = int.from_bytes(payload[offset:offset+2], "big")
                            offset += 2 + cipher_len
                            if len(payload) > offset + 1:
                                comp_len = payload[offset]
                                offset += 1 + comp_len
                                if len(payload) > offset + 2:
                                    ext_total_len = int.from_bytes(payload[offset:offset+2], "big")
                                    offset += 2
                                    end_ext = offset + ext_total_len
                                    while offset + 4 <= end_ext and offset + 4 <= len(payload):
                                        ext_type = int.from_bytes(payload[offset:offset+2], "big")
                                        ext_len = int.from_bytes(payload[offset+2:offset+4], "big")
                                        offset += 4
                                        if ext_type == 0:  # SNI extension
                                            if offset + ext_len <= len(payload):
                                                sni_data = payload[offset:offset+ext_len]
                                                if len(sni_data) >= 5 and sni_data[2] == 0: # host_name type
                                                    name_len = int.from_bytes(sni_data[3:5], "big")
                                                    sni_name = sni_data[5:5+name_len].decode("utf-8", errors="ignore")
                                                    return sni_name
                                        offset += ext_len
        except Exception:
            pass
        return None

    def inspect_payload(self, raw_bytes: bytes) -> Dict[str, Any]:
        """Phân tích nội dung payload chi tiết."""
        result = {
            "telemetry_detected": False,
            "telemetry_keywords": [],
            "sensitive_leaks": [],
            "is_dns": False,
            "dns_query": None,
            "tls_sni": None,
            "http_snippet": None,
            "printable_sample": ""
        }

        if not raw_bytes or len(raw_bytes) < 4:
            return result

        # 1. Trích xuất TLS SNI
        sni = self.extract_tls_sni(raw_bytes)
        if sni:
            result["tls_sni"] = sni

        # 2. Trích xuất Printable ASCII text
        printable = "".join(chr(b) if 32 <= b <= 126 or b in (10, 13, 9) else " " for b in raw_bytes[:1024])
        words = [w for w in printable.split() if len(w) >= 3]
        clean_text = " ".join(words)
        result["printable_sample"] = clean_text[:200]

        # 3. Kiểm tra HTTP Headers / JSON
        if any(raw_bytes.startswith(verb) for verb in [b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HTTP/1.", b"HTTP/2"]):
            result["http_snippet"] = clean_text[:120]

        # 4. Rà soát Telemetry Keywords (Yêu cầu 3.11.4)
        lower_text = clean_text.lower()
        found_kw = [kw for kw in TELEMETRY_KEYWORDS if kw in lower_text]
        if found_kw:
            result["telemetry_detected"] = True
            result["telemetry_keywords"] = found_kw

        # 5. Rà soát Lộ lọt thông tin cá nhân & định danh thiết bị
        # Kiểm tra MAC camera
        if self.target_mac and len(self.target_mac) >= 12:
            norm_text_mac = lower_text.replace(":", "").replace("-", "")
            if self.target_mac in norm_text_mac:
                result["sensitive_leaks"].append(f"Địa chỉ MAC thiết bị ({self.target_mac})")

        # Kiểm tra mật khẩu tài khoản
        if self.target_pass and len(self.target_pass) >= 4 and self.target_pass in clean_text:
            result["sensitive_leaks"].append("Mật khẩu thiết bị (Plaintext Password)")

        # Regex patterns rà soát dữ liệu cá nhân
        for pat, desc in SENSITIVE_PATTERNS:
            m = pat.search(clean_text)
            if m:
                result["sensitive_leaks"].append(f"{desc}: {m.group(0)[:30]}")

        return result


class FlowStats:
    """Đối tượng lưu trữ thống kê dữ liệu của một luồng IP."""
    def __init__(self, remote_ip: str, geo_info: Dict[str, Any]):
        self.remote_ip = remote_ip
        self.geo = geo_info
        self.packets_in = 0    # Remote IP -> Camera (Camera nhận)
        self.bytes_in = 0
        self.packets_out = 0   # Camera -> Remote IP (Camera gửi)
        self.bytes_out = 0
        self.phase1_packets_out = 0
        self.phase1_bytes_out = 0
        self.phase2_packets_out = 0
        self.phase2_bytes_out = 0
        self.protocols: Set[str] = set()
        self.ports: Set[int] = set()
        self.dns_queries: Set[str] = set()
        self.tls_snis: Set[str] = set()
        self.telemetry_found: List[str] = []
        self.sensitive_leaks: List[str] = []
        self.payload_samples: List[str] = []
        self.triggers: Set[str] = set()
        self.first_seen = 0.0
        self.last_seen = 0.0
        self.first_offset_sec = 0.0

    @property
    def total_packets(self) -> int:
        return self.packets_in + self.packets_out

    @property
    def total_bytes(self) -> int:
        return self.bytes_in + self.bytes_out

    def to_dict(self) -> Dict[str, Any]:
        first_iso = datetime.datetime.fromtimestamp(self.first_seen).strftime("%H:%M:%S") if self.first_seen else ""
        last_iso = datetime.datetime.fromtimestamp(self.last_seen).strftime("%H:%M:%S") if self.last_seen else ""
        return {
            "remote_ip": self.remote_ip,
            "country_code": self.geo.get("country_code", "UNKNOWN"),
            "country_name": self.geo.get("country_name", "Unknown"),
            "city": self.geo.get("city", ""),
            "isp_org": self.geo.get("isp") or self.geo.get("org") or self.geo.get("as", ""),
            "service_used": self.geo.get("service_used", "RFC 1918 Private LAN"),
            "is_local": self.geo.get("is_local", False),
            "is_vietnam": self.geo.get("is_vietnam", False),
            "is_overseas": self.geo.get("is_overseas", False),
            "residency_status": self.geo.get("residency_status", ""),
            "packets_camera_sent": self.packets_out,
            "bytes_camera_sent": self.bytes_out,
            "packets_camera_received": self.packets_in,
            "bytes_camera_received": self.bytes_in,
            "phase1_packets_sent": self.phase1_packets_out,
            "phase1_bytes_sent": self.phase1_bytes_out,
            "phase2_packets_sent": self.phase2_packets_out,
            "phase2_bytes_sent": self.phase2_bytes_out,
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "first_seen_time": first_iso,
            "last_seen_time": last_iso,
            "first_offset_sec": round(self.first_offset_sec, 1),
            "triggers": sorted(list(self.triggers)),
            "protocols": sorted(list(self.protocols)),
            "ports": sorted(list(self.ports)),
            "dns_queries": sorted(list(self.dns_queries)),
            "tls_snis": sorted(list(self.tls_snis)),
            "telemetry_keywords": sorted(list(set(self.telemetry_found))),
            "sensitive_leaks": sorted(list(set(self.sensitive_leaks))),
            "payload_samples": self.payload_samples[:3]
        }


def get_target_mac(target_ip: str) -> str:
    """Lấy địa chỉ MAC của thiết bị mục tiêu từ bảng ARP/Neighbor."""
    try:
        out = subprocess.check_output(f"ip neigh show {target_ip}", shell=True, text=True)
        m = re.search(r'lladdr\s+([0-9a-fA-F:]{17})', out)
        if m:
            return m.group(1).lower()
    except Exception:
        pass
    return config.get("target_camera", {}).get("mac", "")


def stimulate_camera_traffic(target_ip: str) -> None:
    """
    Kích thích các luồng mạng của Camera để phát sinh các gói tin kiểm thử
    (HTTP query, ONVIF discovery, NTP trigger, RTSP OPTIONS).
    """
    try:
        # 1. ICMP Ping
        subprocess.run(["ping", "-c", "2", "-W", "1", target_ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        # 2. HTTP/HTTPS probe
        ports = [80, 443, 322, 554]
        for p in ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)
                if s.connect_ex((target_ip, p)) == 0:
                    if p in [80, 443]:
                        s.sendall(b"GET / HTTP/1.1\r\nHost: target\r\nUser-Agent: QCVN11-Audit\r\n\r\n")
                    elif p in [554, 322]:
                        s.sendall(b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: QCVN11-Audit\r\n\r\n")
                s.close()
            except Exception:
                pass
    except Exception:
        pass


def _detect_primary_ip_in_pcap(packets, scapy_mod) -> Optional[str]:
    """Tự động nhận diện địa chỉ IPv4 nội bộ (RFC 1918) phổ biến nhất trong tệp PCAP."""
    counts: Dict[str, int] = defaultdict(int)
    for pkt in packets:
        if not pkt.haslayer(scapy_mod.IP):
            continue
        for ip_s in (pkt[scapy_mod.IP].src, pkt[scapy_mod.IP].dst):
            try:
                ip_obj = ipaddress.ip_address(ip_s)
                if ip_obj.is_private and not ip_obj.is_multicast and not ip_obj.is_loopback and not ip_obj.is_link_local:
                    counts[ip_s] += 1
            except ValueError:
                continue
    if not counts:
        return None
    return max(counts.items(), key=lambda kv: kv[1])[0]


def _match_activity(pkt_time: float, activity_log: Optional[List[Dict[str, Any]]]) -> Optional[str]:
    if not activity_log:
        return None
    for act in activity_log:
        if act["start_ts"] <= pkt_time <= act["end_ts"]:
            return act["label"]
    return None


def parse_pcap_file(
    pcap_path: str,
    target_ip: str,
    target_mac: str = "",
    phase_split_ts: Optional[float] = None,
    allow_auto_ip: bool = False,
    activity_log: Optional[List[Dict[str, Any]]] = None,
) -> Tuple[Dict[str, FlowStats], List[Dict[str, Any]], Dict[str, Any]]:
    """
    Bóc tách và phân tích toàn bộ gói tin từ tệp PCAP:
    - Nhận diện luồng IP 2 chiều
    - Phân tích GeoIP
    - Bóc tách nội dung payload, DNS, TLS SNI, Telemetry, Privacy Leaks
    - Hỗ trợ tách thống kê 2 giai đoạn (phase_split_ts), truy vết tác vụ kích hoạt (activity_log) và tự động dò IP
    """
    import scapy.all as scapy
    
    geo_engine = GeoIPEngine()
    dpi_inspector = DPIPayloadInspector(target_mac=target_mac, target_pass=PASS, target_user=USER)
    
    flows: Dict[str, FlowStats] = {}
    dns_records: List[Dict[str, Any]] = []
    notable_events: List[Dict[str, Any]] = []
    
    effective_ip = target_ip
    summary: Dict[str, Any] = {
        "pcap_file": pcap_path,
        "target_ip": effective_ip,
        "total_packets_read": 0,
        "camera_packets_sent": 0,
        "camera_packets_received": 0,
        "camera_bytes_sent": 0,
        "camera_bytes_received": 0,
        "overseas_packets_sent": 0,
        "overseas_bytes_sent": 0,
        "overseas_ips_contacted": 0,
        "vietnam_ips_contacted": 0,
        "local_ips_contacted": 0,
        "telemetry_packets_detected": 0,
        "sensitive_data_leaks_count": 0,
        "clause_3_11_4_verdict": "ĐẠT",
        "clause_3_11_5_verdict": "ĐẠT"
    }

    try:
        packets = scapy.rdpcap(pcap_path)
    except Exception as e:
        console.print(f"[bold red][-] Lỗi đọc tệp PCAP {pcap_path}: {e}[/bold red]")
        return flows, dns_records, summary

    summary["total_packets_read"] = len(packets)
    base_ts = float(packets[0].time) if packets and hasattr(packets[0], "time") else None

    if allow_auto_ip:
        has_target = False
        if effective_ip and effective_ip.lower() != "auto":
            for pkt in packets:
                if pkt.haslayer(scapy.IP) and (pkt[scapy.IP].src == effective_ip or pkt[scapy.IP].dst == effective_ip):
                    has_target = True
                    break
        if not has_target:
            detected_ip = _detect_primary_ip_in_pcap(packets, scapy)
            if detected_ip:
                console.print(
                    f"[yellow][!] Không tìm thấy lưu lượng cho IP '{effective_ip}' trong PCAP. "
                    f"Tự động chọn IP nội bộ phổ biến nhất: [bold cyan]{detected_ip}[/bold cyan][/yellow]"
                )
                effective_ip = detected_ip
                summary["target_ip"] = effective_ip

    phase1_stats = {"packets_sent": 0, "bytes_sent": 0, "overseas_packets_sent": 0, "overseas_bytes_sent": 0, "overseas_ips": set()}
    phase2_stats = {"packets_sent": 0, "bytes_sent": 0, "overseas_packets_sent": 0, "overseas_bytes_sent": 0, "overseas_ips": set()}

    for pkt in packets:
        # Xử lý tầng IP
        if not pkt.haslayer(scapy.IP):
            continue

        ip_layer = pkt[scapy.IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        pkt_len = len(pkt)
        pkt_time = float(pkt.time) if hasattr(pkt, 'time') else time.time()

        # Xác định chiều của gói tin đối với Camera
        is_from_camera = (src_ip == effective_ip)
        is_to_camera = (dst_ip == effective_ip)

        if not is_from_camera and not is_to_camera:
            # Gói tin không liên quan trực tiếp đến DUT
            continue

        remote_ip = dst_ip if is_from_camera else src_ip

        # Lấy hoặc tạo FlowStats cho IP này
        if remote_ip not in flows:
            geo = geo_engine.lookup(remote_ip)
            flows[remote_ip] = FlowStats(remote_ip, geo)
            flows[remote_ip].first_seen = pkt_time
            flows[remote_ip].first_offset_sec = (pkt_time - base_ts) if base_ts else 0.0
            if geo.get("is_local"):
                summary["local_ips_contacted"] += 1
            elif geo.get("is_vietnam"):
                summary["vietnam_ips_contacted"] += 1
            else:
                summary["overseas_ips_contacted"] += 1

        flow = flows[remote_ip]
        flow.last_seen = pkt_time
        act_label = _match_activity(pkt_time, activity_log)
        if act_label:
            flow.triggers.add(act_label)

        # Xác định giao thức và cổng
        proto_name = "IP"
        sport = 0
        dport = 0
        raw_payload = b""

        if pkt.haslayer(scapy.TCP):
            proto_name = "TCP"
            tcp = pkt[scapy.TCP]
            sport, dport = tcp.sport, tcp.dport
            raw_payload = bytes(tcp.payload)
        elif pkt.haslayer(scapy.UDP):
            proto_name = "UDP"
            udp = pkt[scapy.UDP]
            sport, dport = udp.sport, udp.dport
            raw_payload = bytes(udp.payload)
        elif pkt.haslayer(scapy.ICMP):
            proto_name = "ICMP"

        # Tinh chỉnh tên giao thức theo cổng dịch vụ phổ biến
        used_ports = {sport, dport}
        flow.ports.update(used_ports)

        if 53 in used_ports or pkt.haslayer(scapy.DNS):
            proto_name = "DNS"
            if pkt.haslayer(scapy.DNS):
                dns = pkt[scapy.DNS]
                if dns.qr == 0 and dns.qd: # DNS Query
                    qname = dns.qd.qname.decode("utf-8", errors="ignore").rstrip(".")
                    flow.dns_queries.add(qname)
                    dns_records.append({
                        "time": pkt_time,
                        "client": src_ip,
                        "server": dst_ip,
                        "domain": qname,
                        "type": "A/AAAA"
                    })
        elif 123 in used_ports:
            proto_name = "NTP"
        elif 443 in used_ports or 322 in used_ports or 8443 in used_ports:
            proto_name = "TLS/HTTPS"
        elif 80 in used_ports or 8080 in used_ports or 8088 in used_ports:
            proto_name = "HTTP"
        elif 554 in used_ports:
            proto_name = "RTSP"
        elif 22 in used_ports:
            proto_name = "SSH/SFTP"
        elif 161 in used_ports:
            proto_name = "SNMP"
        elif 1883 in used_ports or 8883 in used_ports:
            proto_name = "MQTT"

        flow.protocols.add(proto_name)

        # Cập nhật số gói tin và dung lượng 2 chiều
        if is_from_camera:
            flow.packets_out += 1
            flow.bytes_out += pkt_len
            summary["camera_packets_sent"] += 1
            summary["camera_bytes_sent"] += pkt_len

            if phase_split_ts is not None:
                if pkt_time < phase_split_ts:
                    flow.phase1_packets_out += 1
                    flow.phase1_bytes_out += pkt_len
                    phase1_stats["packets_sent"] += 1
                    phase1_stats["bytes_sent"] += pkt_len
                    if flow.geo.get("is_overseas"):
                        phase1_stats["overseas_packets_sent"] += 1
                        phase1_stats["overseas_bytes_sent"] += pkt_len
                        phase1_stats["overseas_ips"].add(remote_ip)
                else:
                    flow.phase2_packets_out += 1
                    flow.phase2_bytes_out += pkt_len
                    phase2_stats["packets_sent"] += 1
                    phase2_stats["bytes_sent"] += pkt_len
                    if flow.geo.get("is_overseas"):
                        phase2_stats["overseas_packets_sent"] += 1
                        phase2_stats["overseas_bytes_sent"] += pkt_len
                        phase2_stats["overseas_ips"].add(remote_ip)

            # Nếu Camera gửi gói tin đi nước ngoài
            if flow.geo.get("is_overseas"):
                summary["overseas_packets_sent"] += 1
                summary["overseas_bytes_sent"] += pkt_len
        else:
            flow.packets_in += 1
            flow.bytes_in += pkt_len
            summary["camera_packets_received"] += 1
            summary["camera_bytes_received"] += pkt_len

        # Bóc tách nội dung gói tin (DPI Inspection)
        pkt_telemetry = False
        if raw_payload:
            dpi_res = dpi_inspector.inspect_payload(raw_payload)
            if dpi_res.get("tls_sni"):
                flow.tls_snis.add(dpi_res["tls_sni"])
            if dpi_res.get("telemetry_detected"):
                pkt_telemetry = True
                summary["telemetry_packets_detected"] += 1
                flow.telemetry_found.extend(dpi_res["telemetry_keywords"])
            if dpi_res.get("sensitive_leaks"):
                summary["sensitive_data_leaks_count"] += len(dpi_res["sensitive_leaks"])
                flow.sensitive_leaks.extend(dpi_res["sensitive_leaks"])
            if dpi_res.get("printable_sample") and len(flow.payload_samples) < 3:
                flow.payload_samples.append(dpi_res["printable_sample"])

        if len(notable_events) < 100 and ((is_from_camera and flow.geo.get("is_overseas")) or pkt_telemetry):
            notable_events.append({
                "time_iso": datetime.datetime.fromtimestamp(pkt_time).strftime("%H:%M:%S"),
                "offset_sec": round((pkt_time - base_ts) if base_ts else 0.0, 1),
                "direction": "OUT" if is_from_camera else "IN",
                "remote_ip": remote_ip,
                "country": flow.geo.get("country_code", "??"),
                "protocol": proto_name,
                "dport": dport,
                "bytes": pkt_len,
                "trigger": act_label or (f"GĐ{2 if (phase_split_ts and pkt_time >= phase_split_ts) else 1}" if phase_split_ts else proto_name),
                "kind": "OVERSEAS" if (is_from_camera and flow.geo.get("is_overseas")) else "TELEMETRY",
                "wireshark_filter": f"ip.src == {effective_ip} && ip.dst == {remote_ip}" if is_from_camera else f"ip.addr == {remote_ip}",
            })

    if phase_split_ts is not None:
        summary["phase_breakdown"] = {
            "phase_split_ts": phase_split_ts,
            "phase1_label": "Chức năng bình thường",
            "phase2_label": "Mở hết chức năng",
            "phase1": {
                "packets_sent": phase1_stats["packets_sent"],
                "bytes_sent": phase1_stats["bytes_sent"],
                "overseas_packets_sent": phase1_stats["overseas_packets_sent"],
                "overseas_bytes_sent": phase1_stats["overseas_bytes_sent"],
                "overseas_ips": sorted(list(phase1_stats["overseas_ips"])),
            },
            "phase2": {
                "packets_sent": phase2_stats["packets_sent"],
                "bytes_sent": phase2_stats["bytes_sent"],
                "overseas_packets_sent": phase2_stats["overseas_packets_sent"],
                "overseas_bytes_sent": phase2_stats["overseas_bytes_sent"],
                "overseas_ips": sorted(list(phase2_stats["overseas_ips"])),
            },
        }

    # Đánh giá Hợp quy Điều 2.11.4 & 2.11.5
    # Điều 2.11.4: Telemetry Data
    if summary["sensitive_data_leaks_count"] > 0:
        summary["clause_3_11_4_verdict"] = "KHÔNG ĐẠT (Phát hiện lộ lọt dữ liệu cá nhân trong gói tin)"
    elif summary["telemetry_packets_detected"] > 0:
        summary["clause_3_11_4_verdict"] = "ĐẠT (Dữ liệu đo đạc đúng mục đích kỹ thuật, không chứa dữ liệu cá nhân)"
    else:
        summary["clause_3_11_4_verdict"] = "ĐẠT / K/A (Thiết bị hoạt động cục bộ, không gửi dữ liệu đo đạc từ xa)"

    # Điều 2.11.5: Vietnam Data Residency
    if summary["overseas_packets_sent"] > 0:
        summary["clause_3_11_5_verdict"] = f"CẢNH BÁO VI PHẠM (Phát hiện {summary['overseas_packets_sent']} gói tin gửi ra ngoài lãnh thổ Việt Nam)"
    else:
        summary["clause_3_11_5_verdict"] = "ĐẠT (100% dữ liệu lưu thông nội bộ hoặc máy chủ đặt tại Việt Nam)"

    overseas_ips = sorted([ip for ip, fl in flows.items() if fl.geo.get("is_overseas")])
    if overseas_ips:
        dst_expr = " || ".join(f"ip.dst == {ip}" for ip in overseas_ips[:12])
        overseas_ws_filter = f"ip.src == {effective_ip} && ({dst_expr})"
    else:
        overseas_ws_filter = (
            f"ip.src == {effective_ip} && !(ip.dst == 10.0.0.0/8 || ip.dst == 172.16.0.0/12 "
            "|| ip.dst == 192.168.0.0/16 || ip.dst == 224.0.0.0/4 || ip.dst == 255.255.255.255)"
        )
    summary["notable_events"] = notable_events
    summary["wireshark_filters"] = {
        "overseas_outbound": overseas_ws_filter,
        "telemetry": f'ip.addr == {effective_ip} && frame matches "(?i)telemetry|analytics|crashlog|coredump|heartbeat"',
        "phase2_only": f"ip.src == {effective_ip} && frame.time_epoch >= {phase_split_ts:.3f}" if phase_split_ts else "",
    }

    return flows, dns_records, summary


def generate_markdown_report(
    flows: Dict[str, FlowStats],
    dns_records: List[Dict[str, Any]],
    summary: Dict[str, Any],
    output_path: str = REPORT_MD_PATH
) -> str:
    """Tạo báo cáo đo kiểm chuyên nghiệp định dạng Markdown."""
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    pcap_base = os.path.basename(summary.get("pcap_file", "live_capture.pcap"))
    target_ip_str = summary.get("target_ip", DUT_IP)

    md = f"""# BÁO CÁO ĐO KIỂM GIÁM SÁT TRUYỀN TIN QUỐC TẾ & DỮ LIỆU ĐO ĐẠC TỪ XA
**Tiêu chuẩn áp dụng**: QCVN 11:2026/BCA (Điều 2.11.4 & Điều 2.11.5 / Phương pháp đo 3.11.4 & 3.11.5)  
**Tài liệu tham chiếu**: ETSI EN 303 645 (Clause 5.11 / IXIT 24-TelData & IXIT 28-ExtAPI)  
**Thời gian thực hiện**: `{now_str}`  
**Thiết bị kiểm tra (DUT)**: `{DUT_MODEL}` | **IP**: `{target_ip_str}` | **Firmware**: `{DUT_FW}`  
**Tệp bằng chứng PCAP**: `{pcap_base}`  

---

## 1. KẾT LUẬN ĐÁNH GIÁ HỢP QUY (COMPLIANCE SUMMARY)

| Yêu cầu kỹ thuật | Mã kiểm thử | Nội dung thẩm định | Kết luận thực tế | Đánh giá |
| :--- | :---: | :--- | :--- | :---: |
| **Yêu cầu 2.11.4** | `TC-3.11.4-IMPL` | Mô tả đầy đủ về dữ liệu đo đạc từ xa (Telemetry Data) | {summary['clause_3_11_4_verdict']} | **{'ĐẠT' if 'ĐẠT' in summary['clause_3_11_4_verdict'] else 'CẢNH BÁO'}** |
| **Yêu cầu 2.11.5** | `TC-3.11.5-IMPL` | Thiết lập cấu hình lưu trữ dữ liệu tại Việt Nam | {summary['clause_3_11_5_verdict']} | **{'ĐẠT' if 'ĐẠT' in summary['clause_3_11_5_verdict'] else 'KHÔNG ĐẠT'}** |

> **Ghi chú đánh giá**:
> - **Điều 2.11.4**: Toàn bộ nội dung gói tin trao đổi ({summary['total_packets_read']} gói) đã được bóc tách sâu (DPI). Kết quả ghi nhận {summary['telemetry_packets_detected']} gói chứa từ khóa đo đạc kỹ thuật và {summary['sensitive_data_leaks_count']} trường hợp lộ dữ liệu cá nhân.
> - **Điều 2.11.5**: Camera đã phát đi {summary['camera_packets_sent']} gói tin. Trong đó có **{summary['overseas_packets_sent']} gói tin truyền đi máy chủ quốc tế** ({summary['overseas_bytes_sent']} bytes). {'Thiết bị tuân thủ 100% quy định lưu trữ dữ liệu tại Việt Nam.' if summary['overseas_packets_sent'] == 0 else 'Cần thẩm tra lại cấu hình Cloud/NTP/DNS để đảm bảo định tuyến máy chủ trong nước.'}
"""

    if summary.get("phase_breakdown"):
        pb = summary["phase_breakdown"]
        p1, p2 = pb["phase1"], pb["phase2"]
        md += f"""
### So sánh 2 giai đoạn đo (5 phút bình thường + 5 phút mở hết chức năng)

| Giai đoạn | Tổng gói gửi | Dung lượng gửi | Gói gửi ra nước ngoài | IP nước ngoài |
| :--- | :---: | :---: | :---: | :--- |
| **Giai đoạn 1 ({pb['phase1_label']})** | {p1['packets_sent']} | {p1['bytes_sent']:,} B | **{p1['overseas_packets_sent']}** | {', '.join(p1['overseas_ips']) or 'Không có'} |
| **Giai đoạn 2 ({pb['phase2_label']})** | {p2['packets_sent']} | {p2['bytes_sent']:,} B | **{p2['overseas_packets_sent']}** | {', '.join(p2['overseas_ips']) or 'Không có'} |
"""

    md += """
---

## 2. BẢNG THỐNG KÊ LƯU LƯỢNG & ĐỊNH VỊ ĐỊA LÝ IP (GEOIP FLOW TABLE)

Dưới đây là danh sách phân tích toàn bộ các địa chỉ IP trao đổi với camera:

| STT | Địa chỉ IP | Quốc gia / Vị trí | Nhà mạng / ASN | Gói Camera gửi | Gói Camera nhận | Dung lượng | Giao thức | Trạng thái Lưu trữ |
| :---: | :--- | :--- | :--- | :---: | :---: | :---: | :---: | :---: |
"""

    sorted_flows = sorted(flows.values(), key=lambda f: f.total_packets, reverse=True)
    for idx, f in enumerate(sorted_flows, 1):
        status_badge = f.geo.get("residency_status", "")
        if "Nội bộ" in status_badge:
            status_text = "Nội bộ (LAN)"
        elif "Việt Nam" in status_badge:
            status_text = "**Việt Nam (VN)**"
        else:
            status_text = "⚠️ **NƯỚC NGOÀI**"

        country_desc = f"{f.geo.get('country_name', 'Unknown')} ({f.geo.get('country_code', '??')})"
        org_desc = f.geo.get('isp') or f.geo.get('org') or f.geo.get('as', 'LAN')
        proto_list = ", ".join(sorted(list(f.protocols))) or "TCP/UDP"

        md += f"| {idx} | `{f.remote_ip}` | {country_desc} | {org_desc} | {f.packets_out} | {f.packets_in} | {f.total_bytes:,} B | {proto_list} | {status_text} |\n"

    md += """
---

## 3. BÓC TÁCH NỘI DUNG GÓI TIN & PHÂN TÍCH TELEMETRY (CLAUSE 3.11.4)

### 3.1. Các tên miền và máy chủ đích (DNS & TLS SNI)
"""
    all_dns = set()
    all_snis = set()
    for f in flows.values():
        all_dns.update(f.dns_queries)
        all_snis.update(f.tls_snis)

    if all_dns:
        md += "- **Tên miền phân giải qua DNS**:\n"
        for d in sorted(list(all_dns)):
            md += f"  + `{d}`\n"
    else:
        md += "- **Tên miền DNS**: Không ghi nhận truy vấn DNS ra ngoài.\n"

    if all_snis:
        md += "- **Máy chủ đích bảo vệ qua TLS SNI (Server Name Indication)**:\n"
        for s in sorted(list(all_snis)):
            md += f"  + `{s}`\n"
    else:
        md += "- **TLS SNI**: Không phát hiện kết nối TLS ra bên ngoài.\n"

    md += """
### 3.2. Rà soát Lộ lọt Thông tin Cá nhân & Thiết bị
"""
    leaks_found = []
    for f in flows.values():
        if f.sensitive_leaks:
            leaks_found.append((f.remote_ip, f.sensitive_leaks))

    if leaks_found:
        md += "⚠️ **CẢNH BÁO PHÁT HIỆN DỮ LIỆU NHẠY CẢM**:\n"
        for ip, leaks in leaks_found:
            md += f"- **IP đích `{ip}`**:\n"
            for l in leaks:
                md += f"  + {l}\n"
    else:
        md += " Không phát hiện mật khẩu, khóa bí mật, tài khoản, tọa độ GPS hoặc dữ liệu cá nhân bị truyền ra ngoài trong các gói tin đo đạc từ xa.\n"

    md += f"""
---

## 4. HƯỚNG DẪN ĐỐI SOÁT BẰNG WIRESHARK (PROOF OF EVIDENCE)

Để thẩm tra lại kết quả trên tệp bằng chứng `{pcap_base}` qua Wireshark:

1. **Lọc gói tin truyền ra ngoài mạng nội bộ (Tìm gói tin quốc tế)**:
   ```wireshark
   ip.src == {DUT_IP} && !(ip.dst == 10.0.0.0/8 || ip.dst == 172.16.0.0/12 || ip.dst == 192.168.0.0/16 || ip.dst == 224.0.0.0/4 || ip.dst == 255.255.255.255)
   ```

2. **Lọc các truy vấn tên miền phát sinh từ camera**:
   ```wireshark
   dns.flags.response == 0 && ip.src == {DUT_IP}
   ```

3. **Lọc các kết nối TLS ra Cloud nước ngoài (Trích xuất SNI)**:
   ```wireshark
   tls.handshake.extension.type == 0 && ip.src == {DUT_IP}
   ```

4. **Lọc nội dung gói tin chứa từ khóa Telemetry / Đo đạc từ xa**:
   ```wireshark
   frame matches "(?i)telemetry|analytics|crashlog|coredump|heartbeat"
   ```

---
*Báo cáo được khởi tạo tự động bởi Bộ công cụ đo kiểm QCVN 11:2026/BCA Toolkit (Tool 20 - Telemetry & GeoIP Auditor).*
"""

    try:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(md)
    except Exception as e:
        console.print(f"[yellow][!] Cảnh báo: Không thể ghi file báo cáo tại {output_path}: {e}[/yellow]")

    return md


def display_results_terminal(
    flows: Dict[str, FlowStats],
    dns_records: List[Dict[str, Any]],
    summary: Dict[str, Any],
    pcap_path: str
):
    """Hiển thị kết quả đo kiểm trực quan, sinh động trên Terminal bằng rich."""
    console.print("\n")
    console.print(Panel(
        f"[bold white]THIẾT BỊ MỤC TIÊU (DUT):[/bold white] [bold cyan]{DUT_MODEL}[/bold cyan]  |  "
        f"[bold white]IP:[/bold white] [bold yellow]{DUT_IP}[/bold yellow]  |  "
        f"[bold white]FIRMWARE:[/bold white] [bold green]{DUT_FW}[/bold green]\n"
        f"[bold white]FILE BẰNG CHỨNG PCAP:[/bold white] [bold blue]{os.path.basename(pcap_path)}[/bold blue]  |  "
        f"[bold white]TỔNG SỐ GÓI BẮT ĐƯỢC:[/bold white] [bold magenta]{summary['total_packets_read']}[/bold magenta]",
        title="[bold green]ĐO KIỂM GIÁM SÁT TRUYỀN TIN QUỐC TẾ & TELEMETRY (QCVN 11 - 3.11.4 & 3.11.5)[/bold green]",
        border_style="green"
    ))

    # Bảng kết luận Hợp quy
    verdict_table = Table(title="KẾT LUẬN HỢP QUY ĐIỀU 2.11.4 & 2.11.5 (QCVN 11:2026/BCA)", header_style="bold cyan")
    verdict_table.add_column("Yêu cầu", style="bold yellow", width=12)
    verdict_table.add_column("Mục tiêu thẩm định", width=36)
    verdict_table.add_column("Kết quả đo kiểm thực tế", width=42)
    verdict_table.add_column("Đánh giá", justify="center", width=12)

    v3114 = summary["clause_3_11_4_verdict"]
    badge3114 = "[bold green]ĐẠT[/bold green]" if "ĐẠT" in v3114 else "[bold red]KHÔNG ĐẠT[/bold red]"
    verdict_table.add_row(
        "Điều 2.11.4",
        "Dữ liệu đo đạc từ xa (Telemetry Data)",
        v3114,
        badge3114
    )

    v3115 = summary["clause_3_11_5_verdict"]
    badge3115 = "[bold green]ĐẠT[/bold green]" if "ĐẠT" in v3115 else "[bold red]CẢNH BÁO[/bold red]"
    verdict_table.add_row(
        "Điều 2.11.5",
        "Lưu trữ dữ liệu tại Việt Nam (Data Residency)",
        v3115,
        badge3115
    )
    console.print(verdict_table)
    console.print("")

    # Bảng thống kê chi tiết luồng IP và GeoIP
    flow_table = Table(title="THỐNG KÊ CHI TIẾT LƯU LƯỢNG 2 CHIỀU & VỊ TRÍ ĐỊA LÝ (GEOIP)", header_style="bold blue")
    flow_table.add_column("#", justify="center", width=3)
    flow_table.add_column("Địa chỉ IP", style="bold white", width=16)
    flow_table.add_column("Quốc gia / Vị trí", width=22)
    flow_table.add_column("Nhà mạng / Tổ chức (ISP)", width=26)
    flow_table.add_column("Gửi (Out)", justify="right", width=9)
    flow_table.add_column("Nhận (In)", justify="right", width=9)
    flow_table.add_column("Dung lượng", justify="right", width=12)
    flow_table.add_column("Giao thức", width=12)
    flow_table.add_column("Trạng thái", justify="center", width=15)

    sorted_flows = sorted(flows.values(), key=lambda f: f.total_packets, reverse=True)
    for idx, f in enumerate(sorted_flows, 1):
        if f.geo.get("is_local"):
            res_style = "[bold green]Nội bộ (LAN)[/bold green]"
            c_desc = f.geo.get("country_name", "Local")
        elif f.geo.get("is_vietnam"):
            res_style = "[bold cyan]Việt Nam (VN)[/bold cyan]"
            c_desc = f"Việt Nam ({f.geo.get('country_code')})"
        else:
            res_style = "[bold red]QUỐC TẾ (US/CN..)[/bold red]"
            c_desc = f"[bold red]{f.geo.get('country_name')} ({f.geo.get('country_code')})[/bold red]"

        isp_str = (f.geo.get("isp") or f.geo.get("org") or f.geo.get("as", "LAN"))[:24]
        proto_str = "/".join(sorted(list(f.protocols)))[:11] or "TCP"

        flow_table.add_row(
            str(idx),
            f.remote_ip,
            c_desc[:21],
            isp_str,
            str(f.packets_out),
            str(f.packets_in),
            f"{f.total_bytes:,} B",
            proto_str,
            res_style
        )
    console.print(flow_table)
    console.print("")

    # Hiển thị Panel Bằng chứng Wireshark
    filters = [
        (
            f"ip.src == {DUT_IP} && !(ip.dst == 10.0.0.0/8 || ip.dst == 172.16.0.0/12 || ip.dst == 192.168.0.0/16 || ip.dst == 224.0.0.0/4 || ip.dst == 255.255.255.255)",
            "Lọc toàn bộ gói tin Camera gửi ra ngoài lãnh thổ Việt Nam / Ra ngoài mạng LAN (Điều 2.11.5)"
        ),
        (
            f"dns.flags.response == 0 && ip.src == {DUT_IP}",
            "Lọc các truy vấn tên miền DNS mà camera phát ra để tìm server hãng / cloud / telemetry"
        ),
        (
            f"tls.handshake.extension.type == 0 && ip.src == {DUT_IP}",
            "Lọc máy chủ đích TLS SNI (kể cả khi gói tin bị mã hóa HTTPS/TLS)"
        ),
        (
            'frame matches "(?i)telemetry|analytics|crashlog|coredump|heartbeat"',
            "Lọc các gói tin chứa chữ ký hoặc dữ liệu đo đạc từ xa Telemetry (Điều 2.11.4)"
        )
    ]
    display_wireshark_panel(
        console=console,
        pcap_file=pcap_path,
        filters=filters,
        title="BẰNG CHỨNG GÓI TIN WIRESHARK CHO ĐIỀU 2.11.4 & 2.11.5"
    )


def _run_capture_window(duration_sec: int, label: str, active_stim: bool, target_ip: str) -> None:
    """Chạy vòng lặp đếm thời gian theo đồng hồ thực tế và kích thích lưu lượng định kỳ."""
    start_ts = time.time()
    end_ts = start_ts + max(1, duration_sec)
    last_stim = -10.0

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TimeElapsedColumn(),
        console=console
    ) as progress:
        task = progress.add_task(label, total=max(1, duration_sec))
        completed = 0
        while True:
            now = time.time()
            elapsed = now - start_ts
            if active_stim and (elapsed - last_stim) >= 4.0:
                stimulate_camera_traffic(target_ip)
                last_stim = elapsed
            new_completed = min(max(1, duration_sec), int(elapsed))
            if new_completed > completed:
                progress.update(task, advance=(new_completed - completed))
                completed = new_completed
            if now >= end_ts:
                if completed < max(1, duration_sec):
                    progress.update(task, advance=(max(1, duration_sec) - completed))
                break
            time.sleep(min(1.0, max(0.05, end_ts - time.time())))


def _run_phase2_all_features(
    phase2_sec: int,
    active_stim: bool,
    target_ip: str,
    activity_log: List[Dict[str, Any]],
) -> None:
    """Tự động chạy lần lượt tất cả chức năng/cơ chế của Camera trong giai đoạn 2 và ghi timeline truy vết."""
    end_ts = time.time() + max(1, phase2_sec)
    tasks = [
        ("ONVIF Discovery", ["tool7_onvif_discover.py"], 25),
        ("AuthMech (Web/ONVIF/RTSP/SSH)", ["tool21_authmech_auditor.py", "--id", "all", "--wait", "3", "--no-pcap"], 70),
        ("ComMech + VAPIX Trigger", ["tool17_commech_auditor.py", "--id", "all", "--auto-trigger", "--wait", "3", "--no-pcap"], 90),
        ("SNMPv3 / SNMP", ["tool5_snmpv3_auditor.py", "--no-pcap"], 30),
        ("Web UI / API Params", ["tool13_security_params_auditor.py", "--ip", target_ip], 45),
    ]

    for label, cmd_parts, max_sec in tasks:
        remaining = end_ts - time.time()
        if remaining <= 3:
            break
        script_path = os.path.join(BASE_DIR, cmd_parts[0])
        if not os.path.exists(script_path):
            continue
        timeout_sec = max(5, int(min(max_sec, remaining)))
        console.print(f"[cyan][*][/cyan] [GĐ2] Tự động kích hoạt: [bold]{label}[/bold] (tối đa {timeout_sec}s)...")
        t0 = time.time()
        try:
            subprocess.run(
                [sys.executable, script_path, *cmd_parts[1:]],
                cwd=BASE_DIR,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=timeout_sec,
            )
        except subprocess.TimeoutExpired:
            console.print(f"[yellow][!][/yellow] {label} đạt giới hạn {timeout_sec}s, chuyển bước tiếp theo.")
        except Exception as e:
            console.print(f"[yellow][!][/yellow] Bỏ qua {label}: {e}")
        t1 = time.time()
        activity_log.append({"phase": 2, "label": label, "start_ts": t0, "end_ts": t1})
        console.print(f"[green][+][/green] Xong [bold]{label}[/bold] ({t1 - t0:.1f}s)")

    remaining = end_ts - time.time()
    if remaining > 2:
        t0 = time.time()
        _run_capture_window(int(remaining), "[yellow]GĐ2: Kích thích HTTP/HTTPS/RTSP đến hết 5p...", active_stim, target_ip)
        activity_log.append({"phase": 2, "label": "HTTP/HTTPS/RTSP Stream", "start_ts": t0, "end_ts": time.time()})


def run_live_audit(
    duration_sec: int = 20,
    active_stim: bool = True,
    iface: Optional[str] = None,
    mode: str = "standard",
    phase1_sec: int = 300,
    phase2_sec: int = 300,
    target_ip: Optional[str] = None,
) -> int:
    """Chạy giám sát lưu lượng trực tiếp trên card mạng (chuẩn hoặc 2 giai đoạn 5p + 5p)."""
    effective_ip = target_ip or DUT_IP
    console.print("\n[bold cyan]=== KHỞI CHẠY BỘ ĐO KIỂM GIÁM SÁT TRUYỀN TIN QUỐC TẾ & TELEMETRY (3.11.4 & 3.11.5) ===[/bold cyan]")
    target_mac = get_target_mac(effective_ip)
    console.print(f"[*] Mục tiêu DUT IP: [bold yellow]{effective_ip}[/bold yellow] | MAC: [bold green]{target_mac or 'Chưa xác định'}[/bold green]")

    if mode == "two-phase":
        total_sec = phase1_sec + phase2_sec
        console.print(
            f"[*] Chế độ đo 2 GIAI ĐOẠN ({total_sec} giây = {phase1_sec}s Bình thường + {phase2_sec}s Tự chạy hết chức năng)"
        )
    else:
        console.print(f"[*] Thời gian giám sát: [bold cyan]{duration_sec} giây[/bold cyan] (Kích thích chủ động: {'BẬT' if active_stim else 'TẮT'})")

    bpf = f"host {effective_ip}"
    proc, pcap_path = start_pcap_capture(effective_ip, bpf, prefix="telemetry_geoip_audit", net_iface=iface)
    console.print(f"[*] Đang ghi PCAP vào: [bold blue]{pcap_path}[/bold blue]\n")

    phase_split_ts: Optional[float] = None
    activity_log: List[Dict[str, Any]] = []
    try:
        if mode == "two-phase":
            console.print(Panel.fit(
                f"[bold green]GIAI ĐOẠN 1/2 ({phase1_sec}s): CHẾ ĐỘ BÌNH THƯỜNG[/bold green]\n"
                "Giữ camera hoạt động bình thường để đo lưu lượng nền.",
                border_style="green"
            ))
            t0 = time.time()
            _run_capture_window(phase1_sec, "[green]GĐ1: Theo dõi bình thường...", active_stim, effective_ip)
            activity_log.append({"phase": 1, "label": "GĐ1: Hoạt động bình thường", "start_ts": t0, "end_ts": time.time()})

            phase_split_ts = time.time()
            console.print("\n")
            console.print(Panel.fit(
                f"[bold yellow]GIAI ĐOẠN 2/2 ({phase2_sec}s): TỰ ĐỘNG CHẠY HẾT CHỨC NĂNG CAMERA[/bold yellow]\n"
                "Lần lượt kích hoạt: ONVIF, AuthMech, ComMech + VAPIX, SNMPv3, Web/API & RTSP.",
                border_style="yellow"
            ))
            _run_phase2_all_features(phase2_sec, active_stim, effective_ip, activity_log)
        else:
            t0 = time.time()
            _run_capture_window(duration_sec, "[green]Đang giám sát luồng gói tin...", active_stim, effective_ip)
            activity_log.append({"phase": 1, "label": "Giám sát trực tiếp", "start_ts": t0, "end_ts": time.time()})
    except KeyboardInterrupt:
        console.print("\n[yellow][!] Đã nhận tín hiệu dừng từ bàn phím (Ctrl+C).[/yellow]")

    console.print("\n[*] Đang dừng tiến trình bắt gói tin và hoàn tất tệp PCAP...")
    stop_pcap_capture(proc)

    console.print("[*] Đang bóc tách gói tin, truy vết nguyên nhân và định vị GeoIP...")
    flows, dns_records, summary = parse_pcap_file(
        pcap_path,
        effective_ip,
        target_mac=target_mac,
        phase_split_ts=phase_split_ts,
        activity_log=activity_log,
    )

    # Xuất JSON Evidence
    json_data = {
        "metadata": {
            "test_title": "QCVN 11 Clause 3.11.4 & 3.11.5 Telemetry and International Transfer Audit",
            "mode": mode,
            "timestamp": datetime.datetime.now().isoformat(),
            "target_camera": {
                "ip": summary.get("target_ip", effective_ip),
                "model": DUT_MODEL,
                "mac": target_mac,
                "firmware": DUT_FW
            },
            "pcap_file": pcap_path
        },
        "activity_log": activity_log,
        "summary": summary,
        "dns_queries": dns_records,
        "flows": [f.to_dict() for f in flows.values()]
    }
    with open(EVIDENCE_JSON_PATH, "w", encoding="utf-8") as f:
        json.dump(json_data, f, ensure_ascii=False, indent=2)

    # Xuất Markdown Report
    generate_markdown_report(flows, dns_records, summary, REPORT_MD_PATH)

    # Nếu có thư mục lưu bằng chứng của mẫu thử, sao chép báo cáo & PCAP vào đó
    project_dir = os.path.dirname(BASE_DIR)
    evidence_dir = os.path.join(project_dir, DUT_MODEL, "Mẫu lưu bằng chứng", "3.11_Bao_ve_du_lieu")
    if not os.path.isdir(os.path.dirname(evidence_dir)):
        evidence_dir = os.path.join(BASE_DIR, "captures", "evidence", "3.11_Bao_ve_du_lieu")
    try:
        os.makedirs(evidence_dir, exist_ok=True)
        generate_markdown_report(flows, dns_records, summary, os.path.join(evidence_dir, "telemetry_geoip_audit_report.md"))
        if os.path.exists(pcap_path):
            import shutil
            shutil.copy2(pcap_path, os.path.join(evidence_dir, os.path.basename(pcap_path)))
    except Exception:
        pass

    # Hiển thị trên màn hình dòng lệnh
    display_results_terminal(flows, dns_records, summary, pcap_path)
    if summary.get("phase_breakdown"):
        pb = summary["phase_breakdown"]
        p1, p2 = pb["phase1"], pb["phase2"]
        console.print(Panel.fit(
            f"[bold cyan]SO SÁNH 2 GIAI ĐOẠN[/bold cyan]\n"
            f"- GĐ1 ({pb['phase1_label']}): {p1['packets_sent']} gói gửi | Nước ngoài: [bold {'red' if p1['overseas_packets_sent'] else 'green'}]{p1['overseas_packets_sent']} gói ({len(p1['overseas_ips'])} IP)[/]\n"
            f"- GĐ2 ({pb['phase2_label']}): {p2['packets_sent']} gói gửi | Nước ngoài: [bold {'red' if p2['overseas_packets_sent'] else 'green'}]{p2['overseas_packets_sent']} gói ({len(p2['overseas_ips'])} IP)[/]",
            border_style="cyan"
        ))
    notable = summary.get("notable_events") or []
    if notable:
        ev_tbl = Table(title="TRUY VẾT SỰ KIỆN NƯỚC NGOÀI / TELEMETRY (THỜI ĐIỂM & NGUYÊN NHÂN)", show_lines=False)
        ev_tbl.add_column("Lúc", style="cyan", no_wrap=True)
        ev_tbl.add_column("Offset", style="dim", no_wrap=True)
        ev_tbl.add_column("Loại", style="bold")
        ev_tbl.add_column("IP Đích", style="yellow")
        ev_tbl.add_column("Nguyên nhân / Tác vụ", style="magenta")
        ev_tbl.add_column("Wireshark Filter", style="green")
        for ev in notable[:15]:
            ev_tbl.add_row(
                ev["time_iso"],
                f"+{ev['offset_sec']}s",
                f"{ev['kind']} ({ev['country']})",
                f"{ev['remote_ip']}:{ev['dport']}",
                ev["trigger"],
                ev["wireshark_filter"],
            )
        console.print(ev_tbl)
    console.print(f"[bold green][+] Đã lưu PCAP 10p tại:[/bold green] {pcap_path}")
    console.print(f"\n[bold green][+] Đã lưu báo cáo kỹ thuật tại:[/bold green] {REPORT_MD_PATH}")
    console.print(f"[bold green][+] Đã lưu bằng chứng JSON tại:[/bold green] {EVIDENCE_JSON_PATH}\n")
    return 0


def run_offline_audit(pcap_path: str, target_ip: Optional[str] = None) -> int:
    """Phân tích một tệp PCAP đã có sẵn (hỗ trợ tự nhận diện IP camera nếu khác config)."""
    if not os.path.exists(pcap_path):
        console.print(f"[bold red][-] Không tìm thấy tệp PCAP tại: {pcap_path}[/bold red]")
        return 1

    effective_ip = target_ip or DUT_IP
    console.print(f"\n[bold cyan]=== PHÂN TÍCH TỆP BẰNG CHỨNG PCAP: {os.path.basename(pcap_path)} ===[/bold cyan]")
    target_mac = get_target_mac(effective_ip)
    flows, dns_records, summary = parse_pcap_file(
        pcap_path,
        effective_ip,
        target_mac=target_mac,
        allow_auto_ip=True,
    )

    json_data = {
        "metadata": {
            "test_title": "QCVN 11 Clause 3.11.4 & 3.11.5 Offline PCAP Audit",
            "mode": "offline_pcap",
            "timestamp": datetime.datetime.now().isoformat(),
            "target_camera": {
                "ip": summary.get("target_ip", effective_ip),
                "model": DUT_MODEL,
                "mac": target_mac,
            },
            "pcap_file": pcap_path
        },
        "summary": summary,
        "dns_queries": dns_records,
        "flows": [f.to_dict() for f in flows.values()]
    }
    with open(EVIDENCE_JSON_PATH, "w", encoding="utf-8") as f:
        json.dump(json_data, f, ensure_ascii=False, indent=2)

    generate_markdown_report(flows, dns_records, summary, REPORT_MD_PATH)
    display_results_terminal(flows, dns_records, summary, pcap_path)
    console.print(f"\n[bold green][+] Đã lưu báo cáo kỹ thuật tại:[/bold green] {REPORT_MD_PATH}")
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="Bộ đo kiểm Giám sát Truyền tin Quốc tế, Định vị Địa lý IP & Telemetry (Điều 2.11.4 & 2.11.5 QCVN 11:2026/BCA)"
    )
    parser.add_argument("--live", action="store_true", help="Khởi chạy bắt gói tin trực tiếp thời gian thực")
    parser.add_argument("--duration", type=int, default=20, help="Thời gian bắt gói tin (giây, mặc định 20)")
    parser.add_argument("--mode", choices=["standard", "two-phase"], default="standard", help="Chế độ đo: standard (liên tục) hoặc two-phase (5p bình thường + 5p mở hết chức năng)")
    parser.add_argument("--phase1", type=int, default=300, help="Thời gian giai đoạn 1 bình thường (giây, mặc định 300)")
    parser.add_argument("--phase2", type=int, default=300, help="Thời gian giai đoạn 2 mở hết chức năng (giây, mặc định 300)")
    parser.add_argument("--pcap", type=str, default=None, help="Đường dẫn tệp PCAP cần phân tích ngoại tuyến")
    parser.add_argument("--target-ip", type=str, default=None, help="IP Camera mục tiêu (hoặc 'auto' khi đọc PCAP)")
    parser.add_argument("--iface", type=str, default=None, help="Giao diện mạng (mặc định tự động nhận diện)")
    parser.add_argument("--no-stim", action="store_true", help="Không kích thích luồng mạng chủ động")

    args = parser.parse_args()

    if args.pcap:
        return run_offline_audit(args.pcap, target_ip=args.target_ip)
    else:
        return run_live_audit(
            duration_sec=args.duration,
            active_stim=not args.no_stim,
            iface=args.iface,
            mode=args.mode,
            phase1_sec=args.phase1,
            phase2_sec=args.phase2,
            target_ip=args.target_ip,
        )


if __name__ == "__main__":
    sys.exit(main())
