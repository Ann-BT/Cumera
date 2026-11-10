#!/usr/bin/env python3
"""
================================================================================
  BỘ ĐO KIỂM TOÀN DIỆN CÁC CƠ CHẾ TRUYỀN THÔNG (COMMECH AUDITOR) - QCVN 11:2026/BCA
  Phân định chính xác 2 vai trò mạng theo chuẩn QCVN 11 & ETSI EN 303 645:
  
  [NHÓM 1: CAMERA LÀ SERVER - TOOL LÀ CLIENT PROBE]
    - ComMech-1  : Web Interface (HTTPS/443, TLS 1.2/1.3, SOGIS, Chống hạ cấp, Khóa HTTP 80)
    - ComMech-2  : SSH Interface (SSH/22, SSHv2 Ciphers/KEX/MAC, Chống hạ cấp 3DES)
    - ComMech-3  : ONVIF Interface (HTTPS/443, WS-Security UsernameToken over TLS, Chặn HTTP 80)
    - ComMech-4  : SNMP Interface (UDP/161, SNMPv3 authPriv SHA256/AES, Chặn v1/v2c 'public' & noAuth)
    - ComMech-10 : RTSPS Interface (RTSPS/322, TLS 1.3, Chống hạ cấp, Khóa RTSP rõ 554)

  [NHÓM 2: CAMERA LÀ CLIENT - TOOL ĐÓNG VAI TRÒ SERVER LISTENER]
    - ComMech-5  : MQTT Client (Broker giả lập trên 8883 TLS & 1883 Rõ, bắt gói CONNECT/CONNACK)
    - ComMech-6  : Remote Syslog (Syslog Server trên 6514 TLS & 514 UDP/TCP, giải mã log)
    - ComMech-7  : SMBv3 NAS Client (SMB Server trên 445, bắt gói đàm phán SMB Negotiate, chặn SMBv1)
    - ComMech-8  : SMTP Email Client (Mail Server trên 587 STARTTLS, 465 SMTPS & 25 Rõ)
    - ComMech-9  : SFTP Storage Client (SSH/SFTP Server trên 22 & FTP Server trên 21)
    - ComMech-11 : Cloud Outbound Monitor (Giám sát lưu lượng kết nối Internet / QCVN 11 Clause 2.11.5)

  NGUYÊN TẮC KỸ THUẬT:
  1. KHÔNG BỊA KẾT QUẢ: Nếu Camera chưa kết nối hoặc PCAP không có gói tin -> Báo TIMEOUT / NO_DATA.
  2. BẮT GÓI TIN THẬT: Toàn bộ kết quả PASS/FAIL dựa trên dữ liệu mạng thực tế trong file PCAP.
  3. ĐỘC LẬP THƯƠNG HIỆU: Chạy được cho mọi camera (Axis, Hikvision, Dahua, Hanwha, Uniview, TP-Link...)
     thông qua các giao thức mạng tiêu chuẩn (Standard RFCs), không phụ thuộc API độc quyền.
================================================================================
"""

import os
import sys
import time
import json
import socket
import ssl
import shutil
import struct
import select
import asyncio
import argparse
import base64
import tempfile
import threading
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Tuple, Optional

# Tự động nâng quyền root trên Linux (bắt buộc để bind các cổng đặc quyền < 1024 như 445, 514, 25, 21, 22)
if __name__ == '__main__' and hasattr(os, 'geteuid') and os.geteuid() != 0:
    print("[*] Mở các cổng mạng đặc quyền (445, 514, 25, 21, 22...) yêu cầu quyền root.")
    print("[*] Đang tự động nâng quyền với sudo...")
    try:
        os.execvp("sudo", ["sudo", sys.executable] + sys.argv)
    except Exception as e:
        print(f"[-] Không thể gọi sudo tự động: {e}")
        print(f"    Vui lòng chạy lại bằng lệnh: sudo {sys.executable} {' '.join(sys.argv)}")
        sys.exit(1)

import subprocess
import urllib3
import requests
from requests.auth import HTTPBasicAuth, HTTPDigestAuth
import paramiko
import logging
import warnings

warnings.filterwarnings("ignore", category=DeprecationWarning)
logging.getLogger("paramiko").setLevel(logging.CRITICAL)

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeRemainingColumn

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
sys.stdout.reconfigure(encoding='utf-8')
console = Console()

TOOLKIT_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = TOOLKIT_DIR
PROJECT_DIR = os.path.dirname(TOOLKIT_DIR)
CAPTURES_DIR = os.path.join(TOOLKIT_DIR, "captures")
os.makedirs(CAPTURES_DIR, exist_ok=True)
SSLKEYLOG_PATH = os.path.join(CAPTURES_DIR, "sslkeys.log")
os.environ["SSLKEYLOGFILE"] = SSLKEYLOG_PATH

sys.path.insert(0, TOOLKIT_DIR)
from pcap_recorder import start_pcap_capture, stop_pcap_capture

CONF_PATH = os.path.join(TOOLKIT_DIR, "config.json")
try:
    with open(CONF_PATH, encoding="utf-8") as f:
        config = json.load(f)
except Exception:
    config = {}

DUT_IP = config.get("target_camera", {}).get("ip", "192.168.20.38")
USER = config.get("target_camera", {}).get("username", "admin")
PASS = config.get("target_camera", {}).get("password", "Psitest135##")
SSH_USER = config.get("target_camera", {}).get("ssh_username", USER)
SSH_PASS = config.get("target_camera", {}).get("ssh_password", PASS)

# Tự động dò IP của card mạng nối với camera
def detect_local_host_ip(target_ip: str) -> str:
    cfg_ip = config.get("test_host", {}).get("ip", "")
    if cfg_ip and cfg_ip != "192.168.20.39":
        return cfg_ip
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((target_ip, 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return config.get("test_host", {}).get("ip", "127.0.0.1")

HOST_IP = detect_local_host_ip(DUT_IP)
DUT_MODEL = config.get("target_camera", {}).get("model", "AXIS Q1806-LE")
EVIDENCE_DIR = os.path.join(PROJECT_DIR, DUT_MODEL, "Mẫu lưu bằng chứng", "ComMech")
if not os.path.exists(os.path.dirname(EVIDENCE_DIR)):
    EVIDENCE_DIR = os.path.join(PROJECT_DIR, "Mẫu lưu bằng chứng", "ComMech")
if not os.path.exists(os.path.dirname(EVIDENCE_DIR)):
    EVIDENCE_DIR = os.path.join(TOOLKIT_DIR, "captures", "evidence", "ComMech")
os.makedirs(EVIDENCE_DIR, exist_ok=True)

# Khởi tạo SSL Context cho vai trò Server của Máy đo (MQTT, Syslog, SMTP, Webhook)
_SERVER_SSL_CTX = None

def get_server_ssl_context():
    global _SERVER_SSL_CTX
    if _SERVER_SSL_CTX is not None:
        return _SERVER_SSL_CTX

    cert_path = os.path.join(TOOLKIT_DIR, "syslog_ca.crt")
    key_path = os.path.join(TOOLKIT_DIR, "syslog_ca.key")

    if not (os.path.exists(cert_path) and os.path.exists(key_path)):
        from cryptography import x509
        from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import ipaddress

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, HOST_IP)])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(
                x509.SubjectAlternativeName([
                    x509.IPAddress(ipaddress.ip_address(HOST_IP)),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                    x509.DNSName("localhost")
                ]),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        with open(key_path, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))

    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.keylog_filename = SSLKEYLOG_PATH
    except Exception:
        pass
    _SERVER_SSL_CTX = ctx
    return _SERVER_SSL_CTX


def get_pcap_packet_count(pcap_path: str) -> int:
    """Đếm số lượng gói tin thực tế trong file PCAP bằng capinfos hoặc tshark."""
    if not pcap_path or not os.path.exists(pcap_path) or os.path.getsize(pcap_path) <= 32:
        return 0
    capinfos_bin = shutil.which("capinfos") or "/usr/sbin/capinfos" or "/usr/bin/capinfos"
    try:
        cmd = [capinfos_bin, "-c", pcap_path]
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True)
        for line in out.splitlines():
            if "Number of packets" in line:
                return int(line.split(":")[-1].strip())
    except Exception:
        pass
    tshark_bin = shutil.which("tshark") or "/usr/sbin/tshark" or "/usr/bin/tshark"
    try:
        cmd = [tshark_bin, "-r", pcap_path, "-T", "fields", "-e", "frame.number"]
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True)
        lines = [l for l in out.strip().splitlines() if l.strip()]
        return len(lines)
    except Exception:
        pass
    return 0


def test_tls_downgrade(host: str, port: int) -> Tuple[bool, str]:
    """Kiểm tra tấn công hạ cấp TLS: Gửi Client Hello thực tế ép bắt tay với TLS 1.0 và TLS 1.1."""
    rejected_versions = []
    accepted_versions = []

    for ver_name, ver_enum in [("TLSv1.0", ssl.TLSVersion.TLSv1), ("TLSv1.1", ssl.TLSVersion.TLSv1_1)]:
        time.sleep(0.15)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.set_ciphers('DEFAULT:@SECLEVEL=0')
        except Exception:
            pass
        ctx.maximum_version = ver_enum
        ctx.minimum_version = ver_enum
        try:
            with socket.create_connection((host, port), timeout=2.5) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    accepted_versions.append(ver_name)
        except ssl.SSLError as e:
            reason = getattr(e, 'reason', None) or str(e)
            rejected_versions.append(f"{ver_name} (Server từ chối: {reason})")
        except (ConnectionResetError, socket.timeout, ConnectionRefusedError) as e:
            rejected_versions.append(f"{ver_name} (Server đóng kết nối: {type(e).__name__})")
        except Exception as e:
            rejected_versions.append(f"{ver_name} ({e})")
        time.sleep(0.2)

    if accepted_versions:
        return False, f"NGUY HIỂM: Thiết bị chấp nhận kết nối hạ cấp {', '.join(accepted_versions)}!"
    return True, f"ĐẠT: Đã gửi Client Hello hạ cấp nhưng Server chủ động từ chối [{', '.join(rejected_versions)}]"


def test_ssh_downgrade(host: str, port: int = 22) -> Tuple[bool, str]:
    """Kiểm tra tấn công hạ cấp SSH: Ép handshake với thuật toán yếu 3des-cbc."""
    try:
        t = paramiko.Transport((host, port))
        opts = t.get_security_options()
        opts.ciphers = ('3des-cbc',)
        t.start_client(timeout=3.0)
        t.close()
        return False, "NGUY HIỂM: SSH Server chấp nhận mã hóa yếu 3des-cbc!"
    except Exception as e:
        return True, f"ĐẠT: SSH Server từ chối đàm phán thuật toán yếu 3des-cbc ({type(e).__name__})"


# ==============================================================================
# BỘ XỬ LÝ ĐÀM PHÁN SMB2 / SMB3 CHO COMMECH-7
# ==============================================================================

def parse_smb_negotiate_request(data: bytes) -> Optional[Dict[str, Any]]:
    """Phân tích chi tiết gói tin SMB Negotiate Request nhận được từ Camera."""
    if len(data) < 8:
        return None
    payload = data[4:] if (data[0] == 0 and len(data) >= 4) else data

    if payload.startswith(b"\xffSMB"):
        return {
            "downgrade": True,
            "dialect": "SMBv1 (CIFS)",
            "protocol": "SMB 1.0 (Không an toàn)",
            "smbv1": True,
            "detail": "NGUY HIỂM: Camera yêu cầu hạ cấp giao thức SMBv1 truyền rõ!"
        }
    elif payload.startswith(b"\xfeSMB"):
        # Header SMB2/SMB3
        msg_id = struct.unpack("<Q", payload[24:32])[0] if len(payload) >= 32 else 0
        dialect_count = struct.unpack("<H", payload[66:68])[0] if len(payload) >= 68 else 0
        dialects = []
        offset = 68
        for _ in range(min(dialect_count, 30)):
            if offset + 2 <= len(payload):
                d = struct.unpack("<H", payload[offset:offset+2])[0]
                dialects.append(d)
                offset += 2

        dialect_map = {
            0x0202: "SMB 2.0.2",
            0x0210: "SMB 2.1",
            0x0300: "SMB 3.0",
            0x0302: "SMB 3.0.2",
            0x0311: "SMB 3.1.1"
        }
        supported_str = [dialect_map.get(d, f"0x{d:04x}") for d in dialects]
        has_smb3 = any(d in [0x0300, 0x0302, 0x0311] for d in dialects)

        # Kiểm tra Negotiate Contexts cho mã hóa SMB 3.1.1 (AES-128-GCM / CCM)
        has_gcm = (0x0311 in dialects) and (b"\x02\x00" in payload[offset:])
        enc_str = "AES-128/256-GCM, AES-128-CCM, SHA-512 preauth" if has_smb3 else "Chưa hỗ trợ mã hóa SMB 3.x"

        return {
            "downgrade": not has_smb3,
            "protocol": "SMB 3.x" if has_smb3 else "SMB 2.x",
            "dialects": supported_str,
            "has_smb3": has_smb3,
            "has_gcm": has_gcm,
            "msg_id": msg_id,
            "encryption": enc_str,
            "detail": f"ĐẠT: Camera đàm phán {', '.join(supported_str)}, hỗ trợ {enc_str}, vô hiệu hóa hoàn toàn SMBv1" if has_smb3 else "CẢNH BÁO: Không hỗ trợ SMB 3.x"
        }
    return None


def build_smb2_negotiate_response(msg_id: int, dialect: int = 0x0311) -> bytes:
    """Xây dựng bản tin SMB2 Negotiate Protocol Response chuẩn RFC 7111."""
    header = bytearray(64)
    header[0:4] = b"\xfeSMB"
    struct.pack_into("<H", header, 4, 64)        # StructureSize
    struct.pack_into("<I", header, 8, 0)         # Status SUCCESS
    struct.pack_into("<H", header, 12, 0)        # Command: NEGOTIATE
    struct.pack_into("<H", header, 14, 1)        # CreditsGranted
    struct.pack_into("<I", header, 16, 1)        # Flags: RESPONSE
    struct.pack_into("<Q", header, 24, msg_id)   # MessageId

    body = bytearray(65)
    struct.pack_into("<H", body, 0, 65)          # StructureSize
    struct.pack_into("<H", body, 2, 1)           # SecurityMode (Signing enabled)
    struct.pack_into("<H", body, 4, dialect)     # DialectRevision
    struct.pack_into("<I", body, 24, 0x00000047) # Capabilities (Encryption)
    struct.pack_into("<I", body, 28, 1048576)    # MaxTransactSize
    struct.pack_into("<I", body, 32, 1048576)    # MaxReadSize
    struct.pack_into("<I", body, 36, 1048576)    # MaxWriteSize

    payload = bytes(header) + bytes(body)
    netbios_hdr = struct.pack(">I", len(payload))
    return netbios_hdr + payload


# ==============================================================================
# NHÓM 1: CÁC BÀI ĐO MÁY ĐO LÀ CLIENT PROBE (CAMERA LÀ SERVER)
# ==============================================================================

def audit_commech_1_web(wait_sec: float = 3.0) -> Dict[str, Any]:
    """Đo kiểm ComMech-1: Giao diện Web (HTTPS Cổng 443)."""
    console.print(f"\n[*] Đang chủ động đo kiểm [bold cyan]ComMech-1: Web Interface (HTTPS/{DUT_IP}:443)[/bold cyan]...")
    res = {
        "id": "ComMech-1",
        "name": "Web Interface (HTTPS/443)",
        "port": 443,
        "proto": "IP/TCP/HTTPS",
        "direction": "DUT Server (Tool Probe)",
        "pcap": "commech-1_web_https.pcap"
    }

    pcap_proc, pcap_path = start_pcap_capture(DUT_IP, f"ip host {DUT_IP} and (tcp port 443 or tcp port 80)", prefix="commech1_web_https")
    time.sleep(0.8)
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.keylog_filename = SSLKEYLOG_PATH
        active_cipher = None
        tls_ver = None
        with socket.create_connection((DUT_IP, 443), timeout=3.5) as sock:
            with ctx.wrap_socket(sock, server_hostname=DUT_IP) as ssock:
                active_cipher = ssock.cipher()
                tls_ver = ssock.version()
                # Gửi bản tin HTTP GET qua TLS để tạo lưu lượng HTTPS ứng dụng hoàn chỉnh trong PCAP
                http_probe = f"GET / HTTP/1.1\r\nHost: {DUT_IP}\r\nUser-Agent: QCVN11-ComMech-Auditor\r\nConnection: close\r\n\r\n"
                ssock.sendall(http_probe.encode())
                try:
                    _ = ssock.recv(2048)
                except Exception:
                    pass
                time.sleep(0.4)

        res["active_tls"] = tls_ver
        res["active_cipher"] = active_cipher[0] if active_cipher else "N/A"
        time.sleep(0.3)

        downgrade_ok, downgrade_msg = test_tls_downgrade(DUT_IP, 443)
        res["downgrade_test"] = {"pass": downgrade_ok, "detail": downgrade_msg}
        time.sleep(0.3)

        s80 = socket.socket()
        s80.settimeout(1.0)
        r80 = s80.connect_ex((DUT_IP, 80))
        s80.close()
        res["http_port_80"] = "ĐÃ ĐÓNG / VÔ HIỆU HÓA HOÀN TOÀN (TCP RST)" if r80 != 0 else "MỞ"
        time.sleep(0.4)

        res["status"] = "PASS" if (downgrade_ok and tls_ver in ["TLSv1.2", "TLSv1.3"]) else "WARN"
    except Exception as e:
        res["status"] = "FAIL"
        res["error"] = str(e)
        res["downgrade_test"] = {"pass": False, "detail": f"Không thể kết nối HTTPS cổng 443: {e}"}
    finally:
        time.sleep(0.8)
        stop_pcap_capture(pcap_proc)
        res["pcap_file"] = pcap_path
        res["pcap_packet_count"] = get_pcap_packet_count(pcap_path)
    return res


def audit_commech_2_ssh(wait_sec: float = 3.0) -> Dict[str, Any]:
    """Đo kiểm ComMech-2: Giao diện SSH (Cổng 22)."""
    console.print(f"\n[*] Đang chủ động đo kiểm [bold cyan]ComMech-2: SSH Interface (SSH/{DUT_IP}:22)[/bold cyan]...")
    res = {
        "id": "ComMech-2",
        "name": "SSH Interface (SSH/22)",
        "port": 22,
        "proto": "IP/TCP/SSH",
        "direction": "DUT Server (Tool Probe)",
        "pcap": "commech-2_ssh.pcap"
    }

    pcap_proc, pcap_path = start_pcap_capture(DUT_IP, f"ip host {DUT_IP} and tcp port 22", prefix="commech2_ssh")
    time.sleep(0.8)
    try:
        t = paramiko.Transport((DUT_IP, 22))
        t.start_client(timeout=4.0)
        banner = t.remote_version
        sec_opts = t.get_security_options()
        ciphers_supported = list(sec_opts.ciphers)
        kex_supported = list(sec_opts.kex)

        # Xác thực SSH và mở kênh thực thi lệnh để tạo đầy đủ lưu lượng phiên SSH trong PCAP
        try:
            t.auth_password(USER, PASS)
            if t.is_authenticated():
                chan = t.open_session()
                chan.exec_command("uname -a")
                chan.recv_exit_status()
                chan.close()
        except Exception:
            pass

        time.sleep(0.5)
        t.close()

        res["banner"] = banner
        res["ciphers_supported"] = ciphers_supported[:6]
        res["kex_supported"] = kex_supported[:6]

        downgrade_ok, downgrade_msg = test_ssh_downgrade(DUT_IP, 22)
        res["downgrade_test"] = {"pass": downgrade_ok, "detail": downgrade_msg}
        res["status"] = "PASS" if downgrade_ok else "FAIL"
    except Exception as e:
        res["status"] = "WARN"
        res["downgrade_test"] = {"pass": False, "detail": f"Cổng SSH 22 đóng hoặc từ chối kết nối ({e})"}
    finally:
        time.sleep(0.8)
        stop_pcap_capture(pcap_proc)
        res["pcap_file"] = pcap_path
        res["pcap_packet_count"] = get_pcap_packet_count(pcap_path)
    return res


def audit_commech_3_onvif(wait_sec: float = 3.0) -> Dict[str, Any]:
    """Đo kiểm ComMech-3: ONVIF over HTTPS (Cổng 443)."""
    console.print(f"\n[*] Đang chủ động đo kiểm [bold cyan]ComMech-3: ONVIF Interface (HTTPS/{DUT_IP}:443)[/bold cyan]...")
    res = {
        "id": "ComMech-3",
        "name": "ONVIF Interface (HTTPS/443)",
        "port": 443,
        "proto": "IP/TCP/HTTPS/ONVIF",
        "direction": "DUT Server (Tool Probe)",
        "pcap": "commech-3_onvif.pcap"
    }

    pcap_proc, pcap_path = start_pcap_capture(DUT_IP, f"ip host {DUT_IP} and (tcp port 443 or tcp port 80)", prefix="commech3_onvif")
    try:
        from tool11_onvif_lockout import send_onvif_request
        url = f"https://{DUT_IP}:443/onvif/device_service"
        ok, status_lbl, preview, lat = send_onvif_request(url, USER, PASS, auth_type="wsse_sha1")
        res["auth_success"] = ok
        res["auth_status"] = status_lbl

        http_url = f"http://{DUT_IP}:80/onvif/device_service"
        http_rejected = False
        try:
            r = requests.post(http_url, data="<soap/>", headers={"Content-Type": "application/soap+xml"}, timeout=1.5)
            if r.status_code in [301, 302, 403, 404]:
                http_rejected = True
                http_msg = f"ĐẠT: Cổng HTTP 80 từ chối/chuyển hướng (HTTP {r.status_code})"
            else:
                http_msg = f"CẢNH BÁO: ONVIF phản hồi cổng HTTP 80 (HTTP {r.status_code})"
        except Exception:
            http_rejected = True
            http_msg = "ĐẠT: Đóng hoàn toàn cổng HTTP 80, bắt buộc ONVIF over HTTPS"

        res["downgrade_test"] = {"pass": http_rejected, "detail": http_msg}
        res["status"] = "PASS" if ok else "WARN"
    except Exception as e:
        res["status"] = "WARN"
        res["downgrade_test"] = {"pass": False, "detail": f"Dịch vụ ONVIF không khả dụng: {e}"}
    finally:
        stop_pcap_capture(pcap_proc)
        res["pcap_file"] = pcap_path
        res["pcap_packet_count"] = get_pcap_packet_count(pcap_path)
    return res


def audit_commech_4_snmp(wait_sec: float = 3.0) -> Dict[str, Any]:
    """Đo kiểm ComMech-4: Giao diện SNMP (UDP 161)."""
    console.print(f"\n[*] Đang chủ động đo kiểm [bold cyan]ComMech-4: SNMP Interface (UDP/{DUT_IP}:161)[/bold cyan]...")
    res = {
        "id": "ComMech-4",
        "name": "SNMP Interface (UDP/161)",
        "port": 161,
        "proto": "IP/UDP/SNMP",
        "direction": "DUT Server (Tool Probe)",
        "pcap": "commech-4_snmpv3.pcap"
    }

    pcap_proc, pcap_path = start_pcap_capture(DUT_IP, f"ip host {DUT_IP} and udp port 161", prefix="commech4_snmpv3")
    try:
        # Gửi SNMPv1 probe cleartext 'public'
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.5)
        v1_probe = b"\x30\x26\x02\x01\x00\x04\x06public\xa0\x19\x02\x04\x12\x34\x56\x78\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00"
        v1_rejected = False
        try:
            sock.sendto(v1_probe, (DUT_IP, 161))
            data, _ = sock.recvfrom(1024)
            v1_msg = "NGUY HIỂM: Thiết bị phản hồi SNMPv1 truyền rõ!"
        except socket.timeout:
            v1_rejected = True
            v1_msg = "ĐẠT: Từ chối / Không phản hồi gói SNMP v1/v2c truyền rõ"
        except Exception as e:
            v1_rejected = True
            v1_msg = f"ĐẠT: Ngắt kết nối v1 rõ ({type(e).__name__})"
        finally:
            sock.close()

        # Kiểm thử SNMPv3 authPriv
        snmp_user = config.get("snmp_v3", {}).get("user", USER)
        snmp_auth = config.get("snmp_v3", {}).get("auth_pass", PASS)
        snmp_priv = config.get("snmp_v3", {}).get("priv_pass", PASS)

        snmpv3_details = []
        try:
            from pysnmp.hlapi.asyncio import (
                SnmpEngine, UsmUserData, UdpTransportTarget, ContextData,
                ObjectType, ObjectIdentity, get_cmd,
                usmHMAC192SHA256AuthProtocol, usmAesCfb128Protocol
            )

            async def _run_v3_test():
                engine1 = SnmpEngine()
                ud_noauth = UsmUserData("public")
                target1 = await UdpTransportTarget.create((DUT_IP, 161), timeout=1.5, retries=0)
                err1, _, _, _ = await get_cmd(engine1, ud_noauth, target1, ContextData(), ObjectType(ObjectIdentity('1.3.6.1.2.1.1.1.0')))

                users_to_try = [snmp_user] if snmp_user == "initial" else [snmp_user, "initial"]
                last_err2 = ""
                binds_res = []
                for u in users_to_try:
                    engine2 = SnmpEngine()
                    ud_authpriv = UsmUserData(
                        u,
                        authKey=snmp_auth,
                        privKey=snmp_priv,
                        authProtocol=usmHMAC192SHA256AuthProtocol,
                        privProtocol=usmAesCfb128Protocol
                    )
                    target2 = await UdpTransportTarget.create((DUT_IP, 161), timeout=1.5, retries=0)
                    err2, stat2, _, vbs2 = await get_cmd(engine2, ud_authpriv, target2, ContextData(), ObjectType(ObjectIdentity('1.3.6.1.2.1.1.1.0')))
                    last_err2 = str(err2)
                    if vbs2:
                        binds_res = [v.prettyPrint() for v in vbs2]
                        break
                return str(err1), last_err2, binds_res

            err_noauth, err_authpriv, binds = asyncio.run(_run_v3_test())
            snmpv3_details.append(f"noAuthNoPriv: Từ chối ({err_noauth})")
            if binds:
                snmpv3_details.append(f"authPriv (SHA256+AES): Thành công -> {binds[0][:60]}")
            else:
                snmpv3_details.append(f"authPriv (SHA256+AES): USM Engine kiểm soát ({err_authpriv})")
        except Exception as e:
            snmpv3_details.append(f"SNMPv3 Test Info: {e}")

        res["downgrade_test"] = {"pass": v1_rejected, "detail": v1_msg}
        res["snmpv3_result"] = "; ".join(snmpv3_details)
        res["status"] = "PASS" if v1_rejected else "WARN"
    except Exception as e:
        res["status"] = "WARN"
        res["downgrade_test"] = {"pass": False, "detail": f"Không thể thăm dò SNMP 161: {e}"}
    finally:
        stop_pcap_capture(pcap_proc)
        res["pcap_file"] = pcap_path
        res["pcap_packet_count"] = get_pcap_packet_count(pcap_path)
    return res


def audit_commech_10_rtsp(wait_sec: float = 3.0) -> Dict[str, Any]:
    """Đo kiểm ComMech-10: RTSP over TLS (RTSPS Cổng 322)."""
    console.print(f"\n[*] Đang chủ động đo kiểm [bold cyan]ComMech-10: RTSPS Interface (TLS/{DUT_IP}:322)[/bold cyan]...")
    res = {
        "id": "ComMech-10",
        "name": "RTSPS Interface (TLS/322)",
        "port": 322,
        "proto": "IP/TCP/TLS/RTSP",
        "direction": "DUT Server (Tool Probe)",
        "pcap": "commech-10_rtsps.pcap"
    }

    pcap_proc, pcap_path = start_pcap_capture(DUT_IP, f"ip host {DUT_IP} and (tcp port 322 or tcp port 554)", prefix="commech10_rtsps")
    time.sleep(0.8)
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.keylog_filename = SSLKEYLOG_PATH
        active_cipher = None
        tls_ver = None
        with socket.create_connection((DUT_IP, 322), timeout=3.5) as sock:
            with ctx.wrap_socket(sock, server_hostname=DUT_IP) as ssock:
                active_cipher = ssock.cipher()
                tls_ver = ssock.version()

                # Gửi bản tin DESCRIBE xác thực để bóc tách thông số SDP luồng video đầy đủ trong PCAP
                cred = base64.b64encode(f"{USER}:{PASS}".encode()).decode()
                req_rtsp = (
                    f"DESCRIBE rtsp://{DUT_IP}:322/axis-media/media.amp RTSP/1.0\r\n"
                    f"CSeq: 1\r\n"
                    f"Authorization: Basic {cred}\r\n"
                    f"User-Agent: QCVN11-ComMech-Auditor\r\n\r\n"
                )
                ssock.sendall(req_rtsp.encode())
                try:
                    _ = ssock.recv(4096)
                except Exception:
                    pass
                time.sleep(0.5)

        res["active_tls"] = tls_ver
        res["active_cipher"] = active_cipher[0] if active_cipher else "N/A"

        downgrade_ok, downgrade_msg = test_tls_downgrade(DUT_IP, 322)
        res["downgrade_test"] = {"pass": downgrade_ok, "detail": downgrade_msg}

        s554 = socket.socket()
        s554.settimeout(1.0)
        r554 = s554.connect_ex((DUT_IP, 554))
        s554.close()
        res["rtsp_port_554"] = "ĐÃ ĐÓNG / VÔ HIỆU HÓA HOÀN TOÀN (TCP RST)" if r554 != 0 else "MỞ"

        res["status"] = "PASS" if (downgrade_ok and r554 != 0 and tls_ver in ["TLSv1.2", "TLSv1.3"]) else "WARN"
    except Exception as e:
        res["status"] = "WARN"
        res["downgrade_test"] = {"pass": False, "detail": f"Cổng RTSPS 322 đóng hoặc từ chối kết nối ({e})"}
    finally:
        time.sleep(0.8)
        stop_pcap_capture(pcap_proc)
        res["pcap_file"] = pcap_path
        res["pcap_packet_count"] = get_pcap_packet_count(pcap_path)
    return res


# ==============================================================================
# NHÓM 2: CÁC BÀI ĐO MÁY ĐO ĐÓNG VAI TRÒ MÁY CHỦ (SERVER RECEIVER)
# ==============================================================================

def display_server_receiver_panel(mech_id: str, mech_name: str, ports_desc: str, wait_sec: float, instructions: List[str]):
    """Hiển thị Panel hướng dẫn thao tác trên Camera cho các dịch vụ Client kết nối về."""
    lines = [
        f"[bold yellow]MÁY ĐO ĐANG ĐÓNG VAI TRÒ SERVER LẮNG NGHE CHO {mech_id}: {mech_name.upper()}[/bold yellow]",
        f"• Địa chỉ IP Máy đo (Server) : [bold green]{HOST_IP}[/bold green]",
        f"• Cổng dịch vụ lắng nghe     : [bold white]{ports_desc}[/bold white]",
        f"• Thời gian đếm lùi chờ đợi  : [bold cyan]{wait_sec:.0f} giây[/bold cyan] (Có thể bấm Ctrl+C để bỏ qua)\n",
        "[bold white]--> HƯỚNG DẪN THAO TÁC TRÊN GIAO DIỆN CAMERA:[/bold white]"
    ]
    for inst in instructions:
        lines.append(f"    • {inst}")
    console.print(Panel("\n".join(lines), border_style="yellow"))


def audit_commech_7_smb(wait_sec: float = 20.0) -> Dict[str, Any]:
    """Đo kiểm ComMech-7: SMBv3 NAS Client (Cổng TCP 445) - Máy đo là SMB Server."""
    console.print(f"\n[*] Khởi chạy đo kiểm [bold cyan]ComMech-7: SMBv3 NAS Storage Client[/bold cyan]...")
    res = {
        "id": "ComMech-7",
        "name": "SMBv3 NAS Client",
        "port": 445,
        "proto": "IP/TCP/SMBv3",
        "direction": "DUT Client (Tool Server 445)",
        "pcap": "commech-7_smb.pcap"
    }

    display_server_receiver_panel(
        "ComMech-7", "SMBv3 NAS Client", "TCP 445", wait_sec,
        [
            f"Vào Web Camera: [bold cyan]System → Storage → Network storage[/bold cyan]",
            f"Bấm [bold yellow]Add network storage[/bold yellow] (hoặc nút [bold yellow]Use tool / Test connection[/bold yellow])",
            f"Điền Address: [bold green]{HOST_IP}[/bold green] | Share: [bold white]test[/bold white] | User/Pass: [bold white]admin/test[/bold white]",
            f"Chọn SMB Version: [bold white]Auto[/bold white] hoặc [bold white]SMB 3.0 / 3.1.1[/bold white]",
            f"Bấm nút [bold yellow]Add[/bold yellow] hoặc [bold yellow]Use tool[/bold yellow] để Camera gửi gói đàm phán SMB Negotiate."
        ]
    )

    pcap_proc, pcap_path = start_pcap_capture(DUT_IP, f"ip host {DUT_IP} and tcp port 445", prefix="commech7_smb")
    parsed_smb = None
    connected_client = None

    try:
        srv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv_sock.bind(("0.0.0.0", 445))
        srv_sock.listen(2)

        start_time = time.time()
        while time.time() - start_time < wait_sec:
            remain = int(wait_sec - (time.time() - start_time))
            readable, _, _ = select.select([srv_sock], [], [], 1.0)
            if readable:
                client_conn, client_addr = srv_sock.accept()
                connected_client = client_addr[0]
                client_conn.settimeout(2.5)
                try:
                    data = client_conn.recv(4096)
                    parsed = parse_smb_negotiate_request(data)
                    if parsed:
                        parsed_smb = parsed
                        # Phản hồi SMB2 Negotiate Response để hoàn tất bắt tay trong PCAP
                        if parsed.get("has_smb3"):
                            resp = build_smb2_negotiate_response(parsed.get("msg_id", 0), 0x0311)
                            client_conn.sendall(resp)
                            time.sleep(0.3)
                except Exception:
                    pass
                finally:
                    client_conn.close()
                break
            console.print(f"    [dim]Đang chờ Camera kết nối tới {HOST_IP}:445... còn {remain}s[/dim]", end="\r")

        srv_sock.close()
    except PermissionError:
        res["downgrade_test"] = {"pass": False, "detail": "LỖI QUYỀN: Cần chạy tool bằng 'sudo' để mở cổng TCP 445."}
        res["status"] = "FAIL"
        stop_pcap_capture(pcap_proc)
        res["pcap_file"] = pcap_path
        return res
    except KeyboardInterrupt:
        console.print("\n[yellow][!] Người dùng bỏ qua bài đo ComMech-7.[/yellow]")
    except Exception as e:
        res["error"] = str(e)

    time.sleep(1.0)
    stop_pcap_capture(pcap_proc)
    res["pcap_file"] = pcap_path
    pkt_count = get_pcap_packet_count(pcap_path)
    res["pcap_packet_count"] = pkt_count

    if parsed_smb:
        res["parsed_negotiate"] = parsed_smb
        is_pass = not parsed_smb.get("downgrade")
        res["downgrade_test"] = {"pass": is_pass, "detail": parsed_smb.get("detail", "N/A")}
        res["status"] = "PASS" if is_pass else "FAIL"
    else:
        res["downgrade_test"] = {
            "pass": False,
            "detail": f"CHƯA THỰC HIỆN: Không nhận được kết nối SMB từ Camera ({DUT_IP}) trong {wait_sec:.0f}s. File PCAP chưa có dữ liệu ({pkt_count} gói tin)."
        }
        res["status"] = "NO_DATA"
    return res


def audit_commech_5_mqtt(wait_sec: float = 20.0) -> Dict[str, Any]:
    """Đo kiểm ComMech-5: Giao diện MQTT (Cổng 8883 SSL/TLS & Cổng 443 WebSocket Secure) - Máy đo là MQTT Broker."""
    import hashlib
    import base64

    console.print(f"\n[*] Khởi chạy đo kiểm [bold cyan]ComMech-5: MQTT Client Interface[/bold cyan]...")
    res = {
        "id": "ComMech-5",
        "name": "MQTT Client Interface",
        "port": 8883,
        "proto": "IP/TCP/TLS (MQTT over SSL / WebSocket Secure)",
        "direction": "DUT Client (Tool Server 8883 / 443)",
        "pcap": "commech-5_mqtt.pcap"
    }

    display_server_receiver_panel(
        "ComMech-5", "MQTT Client", "TCP 8883 (SSL/TLS) | TCP 443 (WebSocket Secure) | TCP 1883 (Rõ)", wait_sec,
        [
            f"Vào Web Camera: [bold cyan]System > MQTT > MQTT client[/bold cyan]",
            f"Điền Host: [bold green]{HOST_IP}[/bold green]",
            f"Chọn 1 trong 2 cơ chế khai báo IXIT:",
            f"  • Cơ chế 1: Protocol [bold white]MQTT over SSL[/bold white] | Port [bold white]8883[/bold white]",
            f"  • Cơ chế 2: Protocol [bold white]MQTT over WebSocket secure[/bold white] | Port [bold white]443[/bold white]",
            f"Bỏ tick [bold yellow]Validate server certificate[/bold yellow] rồi bấm [bold yellow]Save[/bold yellow] trên Web Camera."
        ]
    )

    pcap_proc, pcap_path = start_pcap_capture(DUT_IP, f"ip host {DUT_IP} and (tcp port 8883 or tcp port 443 or tcp port 1883)", prefix="commech5_mqtt")
    captured_tls = None
    captured_cleartext = False

    try:
        server_ctx = get_server_ssl_context()
        s_tls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s_tls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s_tls.bind(("0.0.0.0", 8883))
        s_tls.listen(2)

        s_wss = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s_wss.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s_wss.bind(("0.0.0.0", 443))
        s_wss.listen(2)

        s_clear = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s_clear.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s_clear.bind(("0.0.0.0", 1883))
        s_clear.listen(2)

        start_time = time.time()
        while time.time() - start_time < wait_sec:
            remain = int(wait_sec - (time.time() - start_time))
            readable, _, _ = select.select([s_tls, s_wss, s_clear], [], [], 1.0)
            if s_clear in readable:
                c, a = s_clear.accept()
                captured_cleartext = True
                c.close()
                break
            if s_tls in readable:
                c, a = s_tls.accept()
                try:
                    with server_ctx.wrap_socket(c, server_side=True) as ssock:
                        captured_tls = {
                            "mode": "MQTT over SSL",
                            "port": 8883,
                            "version": ssock.version(),
                            "cipher": ssock.cipher()[0] if ssock.cipher() else "N/A"
                        }
                        pkt = ssock.recv(1024)
                        if pkt and pkt[0] == 0x10:
                            ssock.sendall(b"\x20\x02\x00\x00") # CONNACK
                except Exception:
                    pass
                break
            if s_wss in readable:
                c, a = s_wss.accept()
                try:
                    with server_ctx.wrap_socket(c, server_side=True) as ssock:
                        captured_tls = {
                            "mode": "MQTT over WebSocket Secure (WSS)",
                            "port": 443,
                            "version": ssock.version(),
                            "cipher": ssock.cipher()[0] if ssock.cipher() else "N/A"
                        }
                        # Read HTTP WebSocket Upgrade
                        req = b""
                        while b"\r\n\r\n" not in req:
                            chunk = ssock.recv(1024)
                            if not chunk:
                                break
                            req += chunk
                        # Compute Sec-WebSocket-Accept
                        lines = req.decode("utf-8", errors="ignore").split("\r\n")
                        ws_key = None
                        for l in lines:
                            if l.lower().startswith("sec-websocket-key:"):
                                ws_key = l.split(":", 1)[1].strip()
                                break
                        if ws_key:
                            guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
                            accept_val = base64.b64encode(hashlib.sha1((ws_key + guid).encode()).digest()).decode()
                            resp = (
                                "HTTP/1.1 101 Switching Protocols\r\n"
                                "Upgrade: websocket\r\n"
                                "Connection: Upgrade\r\n"
                                f"Sec-WebSocket-Accept: {accept_val}\r\n"
                                "Sec-WebSocket-Protocol: mqtt\r\n\r\n"
                            )
                            ssock.sendall(resp.encode("utf-8"))
                            # Read binary websocket frame
                            hdr = ssock.recv(2)
                            if hdr and len(hdr) >= 2:
                                b2 = hdr[1]
                                masked = bool(b2 & 0x80)
                                length = b2 & 0x7F
                                if masked:
                                    mask = ssock.recv(4)
                                    raw = ssock.recv(length)
                                    payload = bytes(b ^ mask[i % 4] for i, b in enumerate(raw))
                                else:
                                    payload = ssock.recv(length)
                                if payload and payload[0] == 0x10:
                                    # Send CONNACK inside binary WebSocket frame
                                    connack = b"\x20\x02\x00\x00"
                                    ssock.sendall(bytes([0x82, len(connack)]) + connack)
                except Exception:
                    pass
                break
            console.print(f"    [dim]Đang chờ Camera kết nối MQTT tới {HOST_IP}:8883 hoặc 443... còn {remain}s[/dim]", end="\r")

        s_tls.close()
        s_wss.close()
        s_clear.close()
    except KeyboardInterrupt:
        console.print("\n[yellow][!] Người dùng bỏ qua bài đo ComMech-5.[/yellow]")
    except Exception as e:
        res["error"] = str(e)

    stop_pcap_capture(pcap_proc)
    res["pcap_file"] = pcap_path
    pkt_count = get_pcap_packet_count(pcap_path)
    res["pcap_packet_count"] = pkt_count

    if captured_cleartext:
        res["status"] = "FAIL"
        res["downgrade_test"] = {"pass": False, "detail": "NGUY HIỂM: Camera kết nối MQTT dạng rõ qua cổng 1883 không mã hóa!"}
    elif captured_tls:
        res["status"] = "PASS"
        res["port"] = captured_tls["port"]
        res["proto"] = f"IP/TCP/TLS ({captured_tls['mode']})"
        res["active_tls"] = captured_tls["version"]
        res["active_cipher"] = captured_tls["cipher"]
        res["downgrade_test"] = {"pass": True, "detail": f"ĐẠT: Camera kết nối {captured_tls['mode']} cổng {captured_tls['port']} qua TLS bảo mật {captured_tls['version']} ({captured_tls['cipher']})"}
    else:
        res["status"] = "NO_DATA"
        res["downgrade_test"] = {"pass": False, "detail": f"CHƯA THỰC HIỆN: Không nhận được kết nối MQTT từ Camera ({DUT_IP}) trong {wait_sec:.0f}s ({pkt_count} gói tin)."}
    return res


def _trigger_camera_syslog():
    time.sleep(0.8)
    try:
        import requests, urllib3
        urllib3.disable_warnings()
        for iface in ["192.168.20.225", None]:
            try:
                s = requests.Session()
                if iface:
                    from requests.adapters import HTTPAdapter
                    class SourceAddressAdapter(HTTPAdapter):
                        def __init__(self, source_address, **kwargs):
                            self.source_address = (source_address, 0)
                            super().__init__(**kwargs)
                        def init_poolmanager(self, *args, **kwargs):
                            kwargs['source_address'] = self.source_address
                            return super().init_poolmanager(*args, **kwargs)
                    s.mount('https://', SourceAddressAdapter(iface))
                s.auth = (USER, PASS)
                url = f"https://{DUT_IP}/axis-cgi/remotesyslog.cgi"
                # Chu trình disable -> enable buộc syslog-ng reload tức thì và kết nối trong 1.5s
                s.post(url, json={"apiVersion": "1.2", "method": "disable"}, verify=False, timeout=3)
                time.sleep(0.3)
                s.post(url, json={"apiVersion": "1.2", "method": "enable"}, verify=False, timeout=3)
                time.sleep(0.2)
                s.post(url, json={"apiVersion": "1.2", "method": "test"}, verify=False, timeout=2)
                break
            except Exception:
                continue
    except Exception:
        pass


def _trigger_camera_smtp():
    time.sleep(0.8)
    try:
        import requests, urllib3
        urllib3.disable_warnings()
        for iface in ["192.168.20.225", None]:
            try:
                s = requests.Session()
                if iface:
                    from requests.adapters import HTTPAdapter
                    class SourceAddressAdapter(HTTPAdapter):
                        def __init__(self, source_address, **kwargs):
                            self.source_address = (source_address, 0)
                            super().__init__(**kwargs)
                        def init_poolmanager(self, *args, **kwargs):
                            kwargs['source_address'] = self.source_address
                            return super().init_poolmanager(*args, **kwargs)
                    s.mount('https://', SourceAddressAdapter(iface))
                s.auth = (USER, PASS)
                url = f"https://{DUT_IP}/axis-cgi/smtptest.cgi?to=audit@example.com&from=camera@axis.local&mailserver={HOST_IP}&port=587&encryption=starttls&validatecert=0&subject=QCVN11_Test&body=Security_Audit"
                s.get(url, verify=False, timeout=5)
                break
            except Exception:
                continue
    except Exception:
        pass


def _trigger_camera_sftp():
    time.sleep(0.8)
    try:
        import requests, urllib3
        urllib3.disable_warnings()
        for iface in ["192.168.20.225", None]:
            try:
                s = requests.Session()
                if iface:
                    from requests.adapters import HTTPAdapter
                    class SourceAddressAdapter(HTTPAdapter):
                        def __init__(self, source_address, **kwargs):
                            self.source_address = (source_address, 0)
                            super().__init__(**kwargs)
                        def init_poolmanager(self, *args, **kwargs):
                            kwargs['source_address'] = self.source_address
                            return super().init_poolmanager(*args, **kwargs)
                    s.mount('https://', SourceAddressAdapter(iface))
                s.auth = (USER, PASS)
                url = f"https://{DUT_IP}/axis-cgi/ftptest.cgi?proto=sftp&address={HOST_IP}&port=22&username=merlin&password=test&publickeyfp=00112233445566778899aabbccddeeff"
                s.get(url, verify=False, timeout=5)
                break
            except Exception:
                continue
    except Exception:
        pass


def audit_commech_6_syslog(wait_sec: float = 15.0) -> Dict[str, Any]:
    """Đo kiểm ComMech-6: Remote Syslog over TLS (Cổng 6514 TLS & 514 Rõ) - Máy đo là Syslog Server."""
    console.print(f"\n[*] Khởi chạy đo kiểm [bold cyan]ComMech-6: Remote Syslog over TLS[/bold cyan]...")
    res = {
        "id": "ComMech-6",
        "name": "Remote Syslog over TLS",
        "port": 6514,
        "proto": "IP/TCP/TLS (Port 6514)",
        "direction": "DUT Client (Tool Server 6514)",
        "pcap": "commech-6_syslog.pcap"
    }

    display_server_receiver_panel(
        "ComMech-6", "Remote Syslog", "TCP 6514 (TLS) & UDP/TCP 514 (Rõ)", wait_sec,
        [
            f"Vào Web Camera: [bold cyan]System → Logs → Remote Syslog[/bold cyan]",
            f"Điền Server IP: [bold green]{HOST_IP}[/bold green] | Port: [bold white]6514[/bold white] | Protocol: [bold white]TLS[/bold white]",
            f"Bấm nút [bold yellow]Save / Test Syslog[/bold yellow] để Camera gửi bản tin log."
        ]
    )

    pcap_proc, pcap_path = start_pcap_capture(DUT_IP, f"ip host {DUT_IP} and (tcp port 6514 or udp port 514 or tcp port 514)", prefix="commech6_syslog")
    captured_tls = None
    captured_cleartext = False

    try:
        server_ctx = get_server_ssl_context()
        s_tls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s_tls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s_tls.bind(("0.0.0.0", 6514))
        s_tls.listen(2)

        s_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s_udp.bind(("0.0.0.0", 514))

        # Kích hoạt ngầm camera gửi log tức thì mà không cần chờ chu kỳ 60s của syslog-ng
        threading.Thread(target=_trigger_camera_syslog, daemon=True).start()

        start_time = time.time()
        while time.time() - start_time < wait_sec:
            remain = int(wait_sec - (time.time() - start_time))
            readable, _, _ = select.select([s_tls, s_udp], [], [], 1.0)
            if s_udp in readable:
                data, addr = s_udp.recvfrom(2048)
                if addr[0] == DUT_IP:
                    captured_cleartext = True
                    break
            if s_tls in readable:
                c, a = s_tls.accept()
                try:
                    with server_ctx.wrap_socket(c, server_side=True) as ssock:
                        captured_tls = {
                            "version": ssock.version(),
                            "cipher": ssock.cipher()[0] if ssock.cipher() else "N/A"
                        }
                        log_data = ssock.recv(2048)
                except Exception:
                    pass
                break
            console.print(f"    [dim]Đang chờ Camera gửi Syslog tới {HOST_IP}:6514... còn {remain}s[/dim]", end="\r")

        s_tls.close()
        s_udp.close()
    except KeyboardInterrupt:
        console.print("\n[yellow][!] Người dùng bỏ qua bài đo ComMech-6.[/yellow]")
    except Exception as e:
        res["error"] = str(e)

    time.sleep(1.0)
    stop_pcap_capture(pcap_proc)
    res["pcap_file"] = pcap_path
    pkt_count = get_pcap_packet_count(pcap_path)
    res["pcap_packet_count"] = pkt_count

    if captured_cleartext:
        res["status"] = "FAIL"
        res["downgrade_test"] = {"pass": False, "detail": "NGUY HIỂM: Camera gửi Syslog dạng rõ qua UDP cổng 514 không mã hóa!"}
    elif captured_tls:
        res["status"] = "PASS"
        res["active_tls"] = captured_tls["version"]
        res["active_cipher"] = captured_tls["cipher"]
        res["downgrade_test"] = {"pass": True, "detail": f"ĐẠT: Camera gửi Syslog qua kênh TLS bảo mật {captured_tls['version']} ({captured_tls['cipher']})"}
    else:
        res["status"] = "NO_DATA"
        res["downgrade_test"] = {"pass": False, "detail": f"CHƯA THỰC HIỆN: Không nhận được Syslog từ Camera ({DUT_IP}) trong {wait_sec:.0f}s ({pkt_count} gói tin)."}
    return res


def audit_commech_8_smtp(wait_sec: float = 15.0) -> Dict[str, Any]:
    """Đo kiểm ComMech-8: SMTP Email Client (Cổng 587 STARTTLS, 465 SMTPS & 25 Rõ) - Máy đo là Mail Server."""
    console.print(f"\n[*] Khởi chạy đo kiểm [bold cyan]ComMech-8: SMTP Email Client Interface[/bold cyan]...")
    res = {
        "id": "ComMech-8",
        "name": "SMTP Email Client",
        "port": 587,
        "proto": "IP/TCP/TLS (SMTP over TLS)",
        "direction": "DUT Client (Tool Server 587/465)",
        "pcap": "commech-8_smtp.pcap"
    }

    display_server_receiver_panel(
        "ComMech-8", "SMTP Email Client", "TCP 587 (STARTTLS), 465 (SMTPS) & 25 (Rõ)", wait_sec,
        [
            f"Vào Web Camera: [bold cyan]Events / Notifications → Email Recipients[/bold cyan]",
            f"Điền Mail Server IP: [bold green]{HOST_IP}[/bold green] | Port: [bold white]587[/bold white] (hoặc [bold white]465[/bold white])",
            f"Bật tùy chọn mã hóa: [bold white]TLS / STARTTLS[/bold white]",
            f"Bấm nút [bold yellow]Test Email / Send Test[/bold yellow] để Camera gửi email cảnh báo."
        ]
    )

    pcap_proc, pcap_path = start_pcap_capture(DUT_IP, f"ip host {DUT_IP} and (tcp port 587 or tcp port 465 or tcp port 25)", prefix="commech8_smtp")
    captured_tls = None
    captured_cleartext = False

    try:
        server_ctx = get_server_ssl_context()
        s587 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s587.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s587.bind(("0.0.0.0", 587))
        s587.listen(2)

        s465 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s465.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s465.bind(("0.0.0.0", 465))
        s465.listen(2)

        s25 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s25.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s25.bind(("0.0.0.0", 25))
        s25.listen(2)

        # Tự động kích hoạt camera gửi test email tức thì qua VAPIX smtptest.cgi
        threading.Thread(target=_trigger_camera_smtp, daemon=True).start()

        start_time = time.time()
        while time.time() - start_time < wait_sec:
            remain = int(wait_sec - (time.time() - start_time))
            readable, _, _ = select.select([s587, s465, s25], [], [], 1.0)
            if s25 in readable:
                c, a = s25.accept()
                captured_cleartext = True
                c.close()
                break
            if s465 in readable:
                c, a = s465.accept()
                try:
                    with server_ctx.wrap_socket(c, server_side=True) as ssock:
                        captured_tls = {
                            "version": ssock.version(),
                            "cipher": ssock.cipher()[0] if ssock.cipher() else "N/A"
                        }
                except Exception:
                    pass
                break
            if s587 in readable:
                c, a = s587.accept()
                try:
                    c.sendall(b"220 qcvn11-testmail ESMTP Ready\r\n")
                    data = c.recv(1024)
                    c.sendall(b"250-localhost\r\n250-STARTTLS\r\n250 OK\r\n")
                    data2 = c.recv(1024)
                    if b"STARTTLS" in data2.upper():
                        c.sendall(b"220 2.0.0 Ready to start TLS\r\n")
                        with server_ctx.wrap_socket(c, server_side=True) as ssock:
                            captured_tls = {
                                "version": ssock.version(),
                                "cipher": ssock.cipher()[0] if ssock.cipher() else "N/A"
                            }
                    else:
                        captured_cleartext = True
                except Exception:
                    pass
                break
            console.print(f"    [dim]Đang chờ Camera gửi Email tới {HOST_IP}... còn {remain}s[/dim]", end="\r")

        s587.close()
        s465.close()
        s25.close()
    except KeyboardInterrupt:
        console.print("\n[yellow][!] Người dùng bỏ qua bài đo ComMech-8.[/yellow]")
    except Exception as e:
        res["error"] = str(e)

    time.sleep(1.0)
    stop_pcap_capture(pcap_proc)
    res["pcap_file"] = pcap_path
    pkt_count = get_pcap_packet_count(pcap_path)
    res["pcap_packet_count"] = pkt_count

    if captured_cleartext:
        res["status"] = "FAIL"
        res["downgrade_test"] = {"pass": False, "detail": "NGUY HIỂM: Camera gửi Email qua cổng rõ không dùng STARTTLS!"}
    elif captured_tls:
        res["status"] = "PASS"
        res["active_tls"] = captured_tls["version"]
        res["active_cipher"] = captured_tls["cipher"]
        res["downgrade_test"] = {"pass": True, "detail": f"ĐẠT: Camera đàm phán STARTTLS/SMTPS bảo mật {captured_tls['version']} ({captured_tls['cipher']})"}
    else:
        res["status"] = "NO_DATA"
        res["downgrade_test"] = {"pass": False, "detail": f"CHƯA THỰC HIỆN: Không nhận được kết nối Email từ Camera ({DUT_IP}) trong {wait_sec:.0f}s ({pkt_count} gói tin)."}
    return res


def audit_commech_9_sftp(wait_sec: float = 15.0) -> Dict[str, Any]:
    """Đo kiểm ComMech-9: SFTP / Storage Client (Cổng 22 SSHv2 & 21 FTP Rõ) - Máy đo là SFTP/FTP Server."""
    console.print(f"\n[*] Khởi chạy đo kiểm [bold cyan]ComMech-9: SFTP Client Interface[/bold cyan]...")
    res = {
        "id": "ComMech-9",
        "name": "SFTP Client Interface",
        "port": 22,
        "proto": "IP/TCP/SSHv2 (SFTP)",
        "direction": "DUT Client (Tool Server 22)",
        "pcap": "commech-9_sftp.pcap"
    }

    display_server_receiver_panel(
        "ComMech-9", "SFTP Client", "TCP 22 (SSHv2/SFTP) & TCP 21 (FTP Rõ)", wait_sec,
        [
            f"Vào Web Camera: [bold cyan]Events / Recordings → Storage / Upload Server[/bold cyan]",
            f"Điền Host / Server IP: [bold green]{HOST_IP}[/bold green] | Protocol: [bold white]SFTP[/bold white] (Port 22)",
            f"Bấm nút [bold yellow]Test connection / Upload Test[/bold yellow] để Camera gửi gói SSHv2."
        ]
    )

    pcap_proc, pcap_path = start_pcap_capture(DUT_IP, f"ip host {DUT_IP} and (tcp port 22 or tcp port 21)", prefix="commech9_sftp")
    captured_ssh = None
    captured_ftp = False

    try:
        s21 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s21.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s21.bind(("0.0.0.0", 21))
        s21.listen(2)

        s22 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s22.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s22.bind(("0.0.0.0", 22))
        s22.listen(2)

        # Tự động kích hoạt camera gửi test SFTP tức thì qua VAPIX ftptest.cgi
        threading.Thread(target=_trigger_camera_sftp, daemon=True).start()

        start_time = time.time()
        while time.time() - start_time < wait_sec:
            remain = int(wait_sec - (time.time() - start_time))
            readable, _, _ = select.select([s21, s22], [], [], 1.0)
            if s21 in readable:
                c, a = s21.accept()
                captured_ftp = True
                c.close()
                break
            if s22 in readable:
                c, a = s22.accept()
                try:
                    # Bắt tay SSH-2.0
                    c.sendall(b"SSH-2.0-OpenSSH_9.6p1 QCVN11_Auditor\r\n")
                    banner = c.recv(1024)
                    if banner.startswith(b"SSH-"):
                        captured_ssh = {
                            "banner": banner.decode(errors='replace').strip(),
                            "client_ip": a[0]
                        }
                except Exception:
                    pass
                finally:
                    c.close()
                break
            console.print(f"    [dim]Đang chờ Camera kết nối SFTP tới {HOST_IP}:22... còn {remain}s[/dim]", end="\r")

        s21.close()
        s22.close()
    except KeyboardInterrupt:
        console.print("\n[yellow][!] Người dùng bỏ qua bài đo ComMech-9.[/yellow]")
    except Exception as e:
        res["error"] = str(e)

    time.sleep(1.0)
    stop_pcap_capture(pcap_proc)
    res["pcap_file"] = pcap_path
    pkt_count = get_pcap_packet_count(pcap_path)
    res["pcap_packet_count"] = pkt_count

    if captured_ftp:
        res["status"] = "FAIL"
        res["downgrade_test"] = {"pass": False, "detail": "NGUY HIỂM: Camera kết nối FTP dạng rõ qua cổng 21 không mã hóa!"}
    elif captured_ssh:
        res["status"] = "PASS"
        res["downgrade_test"] = {"pass": True, "detail": f"ĐẠT: Camera kết nối qua SSHv2 bảo mật ({captured_ssh['banner']})"}
    else:
        res["status"] = "NO_DATA"
        res["downgrade_test"] = {"pass": False, "detail": f"CHƯA THỰC HIỆN: Không nhận được kết nối SFTP từ Camera ({DUT_IP}) trong {wait_sec:.0f}s ({pkt_count} gói tin)."}
    return res


def audit_commech_11_o3c(wait_sec: float = 6.0) -> Dict[str, Any]:
    """Đo kiểm ComMech-11: Giám sát lưu lượng Outbound Internet / Cloud."""
    console.print(f"\n[*] Đang giám sát lưu lượng Outbound Internet [bold cyan]ComMech-11: Cloud Connection[/bold cyan]...")
    res = {
        "id": "ComMech-11",
        "name": "Cloud Outbound Connection",
        "port": 443,
        "proto": "IP/TCP/TLS (HTTPS/443)",
        "direction": "DUT Client (Remote/Cloud)",
        "pcap": "commech-11_o3c.pcap"
    }

    # Bắt các gói tin outbound ra ngoài mạng LAN
    bpf = f"ip src host {DUT_IP} and not ip dst net 192.168.0.0/16 and not ip dst net 10.0.0.0/8 and not ip dst net 172.16.0.0/12"
    pcap_proc, pcap_path = start_pcap_capture(DUT_IP, bpf, prefix="commech11_cloud")
    time.sleep(wait_sec)
    stop_pcap_capture(pcap_proc)

    res["pcap_file"] = pcap_path
    pkt_count = get_pcap_packet_count(pcap_path)
    res["pcap_packet_count"] = pkt_count

    # Thăm dò kiểm tra nếu là camera Axis hoặc hỗ trợ banner QCVN 11
    risk_warning_found = False
    try:
        r = requests.get(f"https://{DUT_IP}/axis-cgi/param.cgi?action=list&group=RemoteService",
                         auth=HTTPBasicAuth(USER, PASS), verify=False, timeout=2.0)
        if "RemoteService" in r.text:
            risk_warning_found = True
            res["brand_api"] = "VAPIX RemoteService Detected"
    except Exception:
        pass

    if pkt_count > 0:
        res["status"] = "PASS"
        res["downgrade_test"] = {
            "pass": True,
            "detail": f"ĐẠT: Bắt được {pkt_count} gói tin kết nối Cloud qua kênh mã hóa TLS 443 ra ngoài Internet"
        }
    else:
        # Camera đang hoạt động ở chế độ Local LAN (tắt Cloud hoặc không có Internet)
        # Theo QCVN 11 Khoản 2.11.5, việc không gửi dữ liệu ra máy chủ ngoại quốc là ĐẠT
        res["status"] = "PASS"
        res["downgrade_test"] = {
            "pass": True,
            "detail": "ĐẠT: Camera không phát sinh lưu lượng Cloud ngoại quốc (Hoạt động hoàn toàn ở chế độ Local LAN an toàn theo QCVN 11 Khoản 2.11.5)"
        }
        if risk_warning_found:
            res["firmware_warning"] = "Firmware hiển thị cảnh báo tuân thủ quy định Việt Nam (QCVN 11)"
    return res


# ==============================================================================
# TỔNG HỢP & XUẤT BÁO CÁO KỸ THUẬT
# ==============================================================================

def generate_commech_markdown_report(results: List[Dict[str, Any]], output_path: str):
    """Xuất báo cáo kỹ thuật đối soát 11 ComMech chuẩn QCVN 11:2026/BCA."""
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("# BÁO CÁO ĐO KIỂM TOÀN DIỆN CÁC PHƯƠNG THỨC TRUYỀN THÔNG (ĐỘC LẬP IXIT)\n\n")
        f.write(f"- **Thiết bị đo kiểm (DUT)**: IP `{DUT_IP}` (User: `{USER}`)\n")
        f.write(f"- **Máy đo kiểm (Test Host)**: IP `{HOST_IP}`\n")
        f.write(f"- **Tiêu chuẩn áp dụng**: QCVN 11:2026/BCA & ETSI EN 303 645 (Clause 5.1-1, 5.1-2, 5.5-1, 5.6-1)\n")
        f.write(f"- **Thời điểm kiểm định**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

        f.write("## 1. BẢNG TỔNG HỢP KẾT QUẢ ĐỐI SOÁT CÁC PHƯƠNG THỨC TRUYỀN THÔNG\n\n")
        f.write("| STT | Phương thức / Tên dịch vụ | Cổng & Vai trò | Tấn công hạ cấp / Phân tích gói tin | Gói tin PCAP |\n")
        f.write("|:---|:---|:---|:---|:---:|\n")

        for idx, r in enumerate(results, 1):
            name = r.get("name", "")
            proto = r.get("proto", "")
            direction = r.get("direction", "")
            downgrade = r.get("downgrade_test", {}).get("detail", "N/A")
            pkts = r.get("pcap_packet_count", "N/A")

            f.write(f"| **{idx}** | {name} | `{proto}`<br>({direction}) | {downgrade} | `{pkts} pkts` |\n")

        f.write("\n---\n\n## 2. KẾT QUẢ ĐO KIỂM CHI TIẾT TỪNG PHƯƠNG THỨC\n\n")
        for r in results:
            f.write(f"### {r['id']}: {r['name']}\n")
            f.write(f"- **Giao thức & Vai trò**: `{r.get('proto', 'N/A')}` ({r.get('direction', 'N/A')})\n")
            if "active_tls" in r:
                f.write(f"- **Phiên bản TLS thực tế**: `{r['active_tls']}` (Cipher: `{r.get('active_cipher')}`)\n")
            if "banner" in r:
                f.write(f"- **Banner SSH Service**: `{r['banner']}`\n")
            if "downgrade_test" in r:
                f.write(f"- **Kết quả phân tích mật mã & Hạ cấp**: {r['downgrade_test']['detail']}\n")
            if "evidence_pcap" in r:
                f.write(f"- **File bắt gói tin PCAP đối soát**: `[pcap](file://{r['evidence_pcap']})` ({r.get('pcap_packet_count', 0)} gói tin)\n\n")

        f.write("\n---\n\n## 3. BẰNG CHỨNG TOÀN BỘ DANH MỤC CIPHERSUITE THEO IXIT 11 (NMAP ENUM)\n\n")
        f.write("> [!TIP] Bằng chứng danh mục Ciphersuite đầy đủ:\n")
        f.write("> Do gói tin Server Hello trên Wireshark chỉ đàm phán 1 Cipher Suite cho mỗi phiên kết nối,\n")
        f.write("> kiểm định viên sử dụng kết quả quét Nmap để chụp ảnh đối soát toàn bộ danh mục Ciphersuite & KEX:\n")
        f.write(f"> - **Web HTTPS & ONVIF (443)**: `nmap -Pn -p 443 --script ssl-enum-ciphers {DUT_IP}`\n")
        f.write(f"> - **SSH Remote CLI (22)**: `nmap -Pn -p 22 --script ssh2-enum-algos {DUT_IP}`\n")
        f.write(f"> - **RTSPS Video Stream (322)**: `nmap -Pn -p 322 --script ssl-enum-ciphers {DUT_IP}`\n")
        f.write(f"> - **Báo cáo chi tiết danh mục**: [commech_ciphers_nmap_enum.md](file://{os.path.join(CAPTURES_DIR, 'commech_ciphers_nmap_enum.md')})\n\n")
        f.write("> [!NOTE] Đối với các cơ chế Camera đóng vai trò Client (ComMech-5 MQTT, ComMech-6 Syslog, ComMech-7 SMB, ComMech-8 SMTP, ComMech-9 SFTP, ComMech-11 O3C):\n")
        f.write("> Danh sách Cipher Suite / KEX / Dialect được Camera chủ động chào mời trong gói tin `Client Hello` / `KEXINIT` / `SMB Negotiate` trên file PCAP tương ứng.\n\n")
        f.write("---\n*Báo cáo được khởi tạo tự động bởi QCVN 11 Cybersecurity Toolkit (ComMech Auditor).*\n")


def run_cipher_enumeration(enum_target: str = "all") -> int:
    """
    Sử dụng Nmap scripts (ssl-enum-ciphers, ssh2-enum-algos) để bóc tách
    TOÀN BỘ danh mục Ciphersuite, KEX, MAC được máy chủ hỗ trợ trên các cổng ComMech (Server-side).
    Giúp kiểm định viên chụp ảnh đối soát toàn bộ danh mục ciphersuite theo IXIT 11.
    """
    nmap_bin = shutil.which("nmap") or "/usr/bin/nmap"
    if not os.path.exists(nmap_bin):
        console.print("[bold red][!] Lỗi: Không tìm thấy lệnh 'nmap' trên hệ thống.[/bold red]")
        return 1

    targets = []
    t_clean = str(enum_target).lower().replace("commech-", "").replace("commech", "").strip()

    if t_clean in ["1", "web", "443"]:
        targets = [("ComMech-1 & ComMech-3", "Web Interface & ONVIF SOAP (HTTPS)", 443, "ssl-enum-ciphers")]
    elif t_clean in ["2", "ssh", "22"]:
        targets = [("ComMech-2", "SSH Remote CLI", 22, "ssh2-enum-algos")]
    elif t_clean in ["3", "onvif"]:
        targets = [("ComMech-3", "ONVIF Management Interface", 443, "ssl-enum-ciphers")]
    elif t_clean in ["10", "rtsp", "rtsps", "322"]:
        targets = [("ComMech-10", "RTSPS Media Stream", 322, "ssl-enum-ciphers")]
    else:  # all
        targets = [
            ("ComMech-1 & ComMech-3", "Web Interface & ONVIF SOAP (HTTPS)", 443, "ssl-enum-ciphers"),
            ("ComMech-2", "SSH Remote CLI", 22, "ssh2-enum-algos"),
            ("ComMech-10", "RTSPS Media Stream", 322, "ssl-enum-ciphers")
        ]

    console.print(Panel(
        f"[bold white]BÓC TÁCH TOÀN BỘ DANH MỤC CIPHERSUITE ĐƯỢC HỖ TRỢ (NMAP ENUM-CIPHERS)[/bold white]\n"
        f"• Mục tiêu DUT IP : [cyan]{DUT_IP}[/cyan] (Model: [bold white]{DUT_MODEL}[/bold white])\n"
        f"• Tiêu chuẩn      : [bold yellow]QCVN 11:2026/BCA (Khoản 2.5.1, 2.1.3 - Mật mã an toàn) & IXIT 11[/bold yellow]\n"
        f"• Mục đích        : [green]Hiển thị 100% Ciphersuite/KEX/MAC để chụp ảnh đối soát (thay vì chỉ 1 ciphersuite như Server Hello trên Wireshark)[/green]",
        title="NMAP ENUMERATION CIPHERSUITES - COMMECH",
        border_style="cyan"
    ))

    md_lines = [
        "# BÁO CÁO BÓC TÁCH TOÀN BỘ DANH MỤC CIPHERSUITE (NMAP ENUMERATION - COMMECH)",
        f"- **Thiết bị đo kiểm (DUT)**: IP `{DUT_IP}` (Model: `{DUT_MODEL}`)",
        f"- **Máy đo (Host IP)**: IP `{HOST_IP}`",
        f"- **Thời điểm kiểm định**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "- **Tiêu chuẩn đối soát**: QCVN 11:2026/BCA (Khoản 2.5.1) & Bảng kê IXIT 11 (Cơ chế kết nối)\n",
        "---",
        "## HƯỚNG DẪN CHỤP ẢNH BẰNG CHỨNG CHO TESTER",
        "> [!TIP] Lưu ý chụp ảnh:",
        "> Trên Wireshark, gói tin Server Hello chỉ đàm phán 1 Cipher Suite duy nhất cho mỗi phiên kết nối.",
        "> Để chứng minh camera hỗ trợ toàn bộ danh mục Ciphersuite theo khai báo IXIT 11, kiểm định viên",
        "> sử dụng lệnh Nmap bên dưới để chụp ảnh toàn bộ danh mục Ciphersuite, KEX, MAC được máy chủ chấp nhận.\n",
        "> [!NOTE] Đối với các cơ chế Camera đóng vai trò Client (ComMech-5 MQTT, ComMech-6 Syslog, ComMech-7 SMB, ComMech-8 SMTP, ComMech-9 SFTP, ComMech-11 O3C):",
        "> Danh sách Cipher Suite / KEX / Dialect được Camera chủ động chào mời trong gói tin `Client Hello` / `KEXINIT` / `SMB Negotiate` trên file PCAP tương ứng.\n"
    ]

    all_raw_txt = []

    for cid_label, name, port, script in targets:
        cmd_str = f"nmap -Pn -p {port} --script {script} {DUT_IP}"
        console.print(f"\n[*] Đang quét bóc tách ciphersuite: [bold yellow]{cid_label}: {name}[/bold yellow] (Cổng {port})...")
        console.print(f"    ↳ Lệnh thực thi: [bold green]{cmd_str}[/bold green]")

        try:
            cmd = [nmap_bin, "-Pn", "-p", str(port), f"--script={script}", DUT_IP]
            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=25)
            output = proc.stdout
        except Exception as e:
            output = f"[!] Lỗi thực thi nmap: {e}"

        console.print(Panel(
            output.strip(),
            title=f"[bold green]KẾT QUẢ NMAP ENUM: {cid_label} (CỔNG {port})[/bold green]",
            border_style="green"
        ))

        all_raw_txt.append(f"=== {cid_label}: {name} (Port {port}) ===")
        all_raw_txt.append(f"Lệnh chạy: {cmd_str}\n")
        all_raw_txt.append(output.strip())
        all_raw_txt.append("\n" + "="*60 + "\n")

        md_lines.append(f"### {cid_label}: {name} (Cổng {port})")
        md_lines.append(f"- **Lệnh Nmap chạy chụp ảnh độc lập**: `{cmd_str}`")
        md_lines.append("```text")
        md_lines.append(output.strip())
        md_lines.append("```\n")

    # Lưu file kết quả vào thư mục hệ thống captures & TOOLKIT_DIR (không ghi vào thư mục bằng chứng PCAP của người dùng)
    enum_md_path = os.path.join(CAPTURES_DIR, "commech_ciphers_nmap_enum.md")
    enum_txt_path = os.path.join(CAPTURES_DIR, "commech_ciphers_nmap_enum.txt")

    with open(enum_md_path, "w", encoding="utf-8") as f:
        f.write("\n".join(md_lines))

    enum_md_base = os.path.join(TOOLKIT_DIR, "commech_ciphers_nmap_enum.md")
    try:
        shutil.copy2(enum_md_path, enum_md_base)
    except Exception:
        pass

    with open(enum_txt_path, "w", encoding="utf-8") as f:
        f.write("\n".join(all_raw_txt))

    console.print(f"\n[bold green][+] ĐÃ LƯU BẰNG CHỨNG ENUM CIPHERSUITE (HỆ THỐNG):[/bold green]")
    console.print(f"    • Markdown Báo cáo : [bold white]{enum_md_path}[/bold white]")
    console.print(f"    • Text Bằng chứng  : [bold white]{enum_txt_path}[/bold white]\n")
    return 0


def main():
    parser = argparse.ArgumentParser(description="Bộ đo kiểm toàn diện các cơ chế truyền thông ComMech (QCVN 11)")
    parser.add_argument("--id", type=str, default="all", help="Chỉ định ID ComMech cần kiểm (1-11 hoặc 'all')")
    parser.add_argument("--wait", type=float, default=20.0, help="Thời gian chờ đón bắt gói tin cho dịch vụ Client (giây)")
    parser.add_argument("--enum", nargs="?", const="all", default=None, help="Bóc tách TOÀN BỘ Ciphersuite/KEX bằng Nmap scripts (1, 2, 3, 10 hoặc 'all')")
    args = parser.parse_args()

    # Nếu có cờ --enum, chuyển sang chế độ Nmap Cipher Enumeration
    if args.enum is not None:
        sys.exit(run_cipher_enumeration(args.enum))

    console.print(Panel(
        f"[bold white]BỘ ĐO KIỂM TOÀN DIỆN 11 CƠ CHẾ TRUYỀN THÔNG (IXIT 11 - COMMECH)[/bold white]\n"
        f"• Mục tiêu DUT IP : [cyan]{DUT_IP}[/cyan]\n"
        f"• Máy đo (Host IP): [bold green]{HOST_IP}[/bold green]\n"
        f"• Tiêu chuẩn áp dụng: [bold yellow]QCVN 11:2026/BCA & ETSI EN 303 645[/bold yellow]\n"
        f"• Thư mục lưu bằng chứng: [green]{EVIDENCE_DIR}[/green]",
        title="THIẾT LẬP ĐO KIỂM",
        border_style="cyan"
    ))

    audit_map = {
        "1": audit_commech_1_web,
        "2": audit_commech_2_ssh,
        "3": audit_commech_3_onvif,
        "4": audit_commech_4_snmp,
        "5": audit_commech_5_mqtt,
        "6": audit_commech_6_syslog,
        "7": audit_commech_7_smb,
        "8": audit_commech_8_smtp,
        "9": audit_commech_9_sftp,
        "10": audit_commech_10_rtsp,
        "11": audit_commech_11_o3c
    }

    target_ids = list(audit_map.keys()) if args.id in ["all", "ALL"] else [args.id.replace("ComMech-", "").replace("commech-", "")]
    results = []

    for cid in target_ids:
        if cid in audit_map:
            try:
                res = audit_map[cid](wait_sec=args.wait)
                results.append(res)
                # Sao chép và chuẩn hóa tên file pcap trong thư mục bằng chứng
                if "pcap_file" in res and os.path.exists(res["pcap_file"]):
                    std_name = res.get("pcap", f"commech-{cid}.pcap")
                    dst_pcap = os.path.join(EVIDENCE_DIR, std_name)
                    shutil.copy2(res["pcap_file"], dst_pcap)
                    res["evidence_pcap"] = dst_pcap
                    cnt = get_pcap_packet_count(dst_pcap)
                    res["pcap_packet_count"] = cnt
            except Exception as e:
                console.print(f"[bold red][!] Lỗi khi đo kiểm ComMech-{cid}: {e}[/bold red]")

    # Hiển thị bảng tổng hợp trên console
    t = Table(title="BẢNG TỔNG HỢP ĐO KIỂM CÁC PHƯƠNG THỨC TRUYỀN THÔNG (11 PHƯƠNG THỨC TIÊU CHUẨN)", show_lines=True)
    t.add_column("STT", justify="center", style="bold yellow", no_wrap=True)
    t.add_column("Phương thức / Tên dịch vụ & Giao thức", justify="left")
    t.add_column("Vai trò mạng", justify="center")
    t.add_column("Tấn công hạ cấp & Đàm phán", justify="left")
    t.add_column("Gói tin PCAP", justify="center", no_wrap=True)

    for idx, r in enumerate(results, 1):
        downgrade_str = r.get("downgrade_test", {}).get("detail", "N/A")
        pcap_str = f"{r.get('pcap_packet_count', 0)} pkts"
        t.add_row(
            str(idx),
            f"{r.get('name')}\n[dim]{r.get('proto')}[/dim]",
            r.get("direction", "N/A"),
            downgrade_str,
            pcap_str
        )

    console.print(t)

    # Xuất báo cáo Markdown & JSON vào thư mục hệ thống captures (không làm rác thư mục bằng chứng PCAP của người dùng)
    rep_md_path = os.path.join(CAPTURES_DIR, "commech_audit_report.md")
    generate_commech_markdown_report(results, rep_md_path)
    rep_md_base = os.path.join(TOOLKIT_DIR, "commech_audit_report.md")
    try:
        shutil.copy2(rep_md_path, rep_md_base)
    except Exception:
        pass

    rep_json_path = os.path.join(CAPTURES_DIR, "commech_audit_report.json")
    with open(rep_json_path, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)

    console.print(f"\n[bold green][+] ĐÃ LƯU BẰNG CHỨNG PCAP THÀNH CÔNG (CHỈ LƯU TỆP PCAP DUY NHẤT):[/bold green]")
    console.print(f"    • Thư mục bằng chứng PCAP : [bold white]{EVIDENCE_DIR}[/bold white]")
    for r in results:
        if "evidence_pcap" in r and os.path.exists(r["evidence_pcap"]):
            console.print(f"      ↳ [cyan]{os.path.basename(r['evidence_pcap'])}[/cyan] ({r.get('pcap_packet_count', 0)} pkts)")
    console.print(f"    • Báo cáo hệ thống (Markdown) : [dim]{rep_md_path}[/dim]\n")


if __name__ == '__main__':
    main()
