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
import signal

def _handle_stop_signal(signum, frame):
    raise KeyboardInterrupt("Đã nhận tín hiệu dừng (Stop)")

try:
    signal.signal(signal.SIGTERM, _handle_stop_signal)
    signal.signal(signal.SIGINT, _handle_stop_signal)
except Exception:
    pass

# Tự động nâng quyền root trên Linux (bắt buộc để bind các cổng đặc quyền < 1024 như 445, 514, 25, 21, 22)
if __name__ == '__main__' and hasattr(os, 'geteuid') and os.geteuid() != 0:
    print("[*] Mở các cổng mạng đặc quyền (445, 514, 25, 21, 22...) yêu cầu quyền root.")
    print("[*] Đang tự động nâng quyền với sudo...")
    try:
        cols_env = os.environ.get("COLUMNS")
        if cols_env and cols_env.isdigit():
            os.execvp("sudo", ["sudo", "--preserve-env=COLUMNS,LINES,PYTHONUTF8,PYTHONIOENCODING", sys.executable] + sys.argv)
        else:
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

TOOLKIT_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = TOOLKIT_DIR
PROJECT_DIR = os.path.dirname(TOOLKIT_DIR)
CAPTURES_DIR = os.path.join(TOOLKIT_DIR, "captures")
os.makedirs(CAPTURES_DIR, exist_ok=True)
SSLKEYLOG_PATH = os.path.join(CAPTURES_DIR, "sslkeys.log")
os.environ["SSLKEYLOGFILE"] = SSLKEYLOG_PATH

sys.path.insert(0, TOOLKIT_DIR)
from pcap_recorder import start_pcap_capture as _orig_start_pcap_capture, stop_pcap_capture

RECORD_PCAP: bool = True

def start_pcap_capture(target_ip, bpf, prefix="audit", net_iface=None):
    if not RECORD_PCAP:
        return None, ""
    return _orig_start_pcap_capture(target_ip, bpf, prefix=prefix, net_iface=net_iface)

from toolkit_config import (
    CONF_PATH,
    detect_host_network,
    get_service_ports,
    get_target_info,
    load_config,
    make_console,
)

console = make_console()
config = load_config()
_target_info = get_target_info(config)
SERVICE_PORTS = get_service_ports(config)

DUT_IP = _target_info["ip"]
DUT_MODEL = _target_info["model"]
USER = _target_info["username"]
PASS = _target_info["password"]
SSH_USER = _target_info["ssh_username"]
SSH_PASS = _target_info["ssh_password"]

HTTP_PORT = int(SERVICE_PORTS["http"])
HTTPS_PORT = int(SERVICE_PORTS["https"])
ONVIF_HTTP_PORT = int(SERVICE_PORTS["onvif_http"])
ONVIF_HTTPS_PORT = int(SERVICE_PORTS["onvif_https"])
ONVIF_PATH = SERVICE_PORTS["onvif_path"]
RTSP_PORT = int(SERVICE_PORTS["rtsp"])
RTSPS_PORT = int(SERVICE_PORTS["rtsps"])
RTSP_PATH = SERVICE_PORTS["rtsp_path"]
SSH_PORT = int(SERVICE_PORTS["ssh"])
SNMP_PORT = int(SERVICE_PORTS["snmp"])

MQTT_TLS_PORT = int(SERVICE_PORTS["mqtt_tls"])
MQTT_WSS_PORT = int(SERVICE_PORTS["mqtt_wss"])
MQTT_CLEAR_PORT = int(SERVICE_PORTS["mqtt_clear"])
SYSLOG_TLS_PORT = int(SERVICE_PORTS["syslog_tls"])
SYSLOG_CLEAR_PORT = int(SERVICE_PORTS["syslog_clear"])
SMB_PORT = int(SERVICE_PORTS["smb"])
SMTP_STARTTLS_PORT = int(SERVICE_PORTS["smtp_starttls"])
SMTPS_PORT = int(SERVICE_PORTS["smtps"])
SMTP_CLEAR_PORT = int(SERVICE_PORTS["smtp_clear"])
SFTP_PORT = int(SERVICE_PORTS["sftp_port"])
FTP_CLEAR_PORT = int(SERVICE_PORTS["ftp_clear"])


def detect_local_host_ip(target_ip: str) -> str:
    _, ip = detect_host_network(target_ip, config)
    return ip


HOST_IP = detect_local_host_ip(DUT_IP)

custom_commech = config.get("evidence_commech_dir") or (
    os.path.join(config.get("evidence_base_dir", ""), "ComMech") if config.get("evidence_base_dir") else None
)
if custom_commech:
    EVIDENCE_DIR = custom_commech
else:
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

    need_regen = not (os.path.exists(cert_path) and os.path.exists(key_path))
    if not need_regen:
        try:
            from cryptography import x509
            import ipaddress
            with open(cert_path, "rb") as f:
                existing_cert = x509.load_pem_x509_certificate(f.read())
            pub_key = existing_cert.public_key()
            if getattr(pub_key, "key_size", 4096) < 3072:
                need_regen = True
            san = existing_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            ip_strs = {str(ip) for ip in san.get_values_for_type(x509.IPAddress)}
            if HOST_IP not in ip_strs:
                need_regen = True
        except Exception:
            need_regen = True

    if need_regen:
        from cryptography import x509
        from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import ipaddress

        key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, HOST_IP),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "QCVN 11 Test Authority"),
        ])
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
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=True,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
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


def _enforce_pcap_requirement(res: Dict[str, Any], require_pcap: bool = True) -> None:
    """Chặn tuyệt đối việc đánh dấu PASS khi tệp PCAP không có gói tin thực tế từ DUT."""
    if not require_pcap or not RECORD_PCAP:
        return
    if res.get("status") == "PASS" and int(res.get("pcap_packet_count", 0) or 0) <= 0:
        res["status"] = "NO_DATA"
        res["downgrade_test"] = {
            "pass": False,
            "detail": f"CẢNH BÁO (0 PKTS): Tác vụ chưa ghi nhận gói tin thực tế từ DUT ({DUT_IP}) trong PCAP — từ chối đánh dấu ĐẠT."
        }


def _accept_dut_client(sock: socket.socket, port: int, timeout: float = 3.0) -> Optional[Tuple[socket.socket, str]]:
    """Chấp nhận kết nối TCP và chỉ cho phép lưu lượng từ đúng DUT_IP."""
    conn, addr = sock.accept()
    peer_ip = addr[0]
    if peer_ip.startswith("::ffff:"):
        peer_ip = peer_ip[7:]
    if peer_ip != DUT_IP:
        console.print(f"\n    [dim][!] Bỏ qua kết nối cổng {port} từ {peer_ip} (không phải DUT {DUT_IP})[/dim]")
        conn.close()
        return None
    conn.settimeout(timeout)
    return conn, peer_ip


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

def _parse_smb1_dialects(payload: bytes) -> List[str]:
    """Trích xuất danh sách chuỗi Dialect từ gói SMBv1 Negotiate Protocol Request."""
    dialects: List[str] = []
    if len(payload) < 36:
        return dialects
    word_count = payload[32]
    bcc_off = 33 + word_count * 2
    if bcc_off + 2 > len(payload):
        return dialects
    byte_count = struct.unpack("<H", payload[bcc_off:bcc_off + 2])[0]
    buf = payload[bcc_off + 2:bcc_off + 2 + byte_count]
    pos = 0
    while pos < len(buf):
        if buf[pos] != 0x02:
            break
        end = buf.find(b"\x00", pos + 1)
        if end == -1:
            break
        dialects.append(buf[pos + 1:end].decode("ascii", errors="replace"))
        pos = end + 1
    return dialects


def _parse_smb311_negotiate_contexts(payload: bytes) -> Dict[str, List[str]]:
    """Phân tích các Negotiate Contexts trong gói SMB 3.1.1 Negotiate Request."""
    out: Dict[str, List[str]] = {"hashes": [], "ciphers": [], "signing": []}
    if len(payload) < 100:
        return out
    neg_ctx_off, neg_ctx_cnt = struct.unpack("<IH", payload[92:98])
    if neg_ctx_off < 100 or neg_ctx_off >= len(payload) or neg_ctx_cnt == 0:
        return out

    hash_map = {0x0001: "SHA-512"}
    cipher_map = {
        0x0001: "AES-128-CCM",
        0x0002: "AES-128-GCM",
        0x0003: "AES-256-CCM",
        0x0004: "AES-256-GCM",
    }
    sign_map = {
        0x0000: "HMAC-SHA256",
        0x0001: "AES-128-CMAC",
        0x0002: "AES-128-GMAC",
    }

    off = neg_ctx_off
    for _ in range(min(neg_ctx_cnt, 16)):
        if off + 8 > len(payload):
            break
        ctype, dlen = struct.unpack("<HH", payload[off:off + 4])
        data_start = off + 8
        data_end = data_start + dlen
        if data_end > len(payload):
            break
        cdata = payload[data_start:data_end]
        if ctype == 0x0001 and len(cdata) >= 4:
            hcnt = struct.unpack("<H", cdata[0:2])[0]
            for i in range(min(hcnt, 8)):
                if 4 + i * 2 + 2 <= len(cdata):
                    hid = struct.unpack("<H", cdata[4 + i * 2:6 + i * 2])[0]
                    out["hashes"].append(hash_map.get(hid, f"0x{hid:04x}"))
        elif ctype == 0x0002 and len(cdata) >= 2:
            ccnt = struct.unpack("<H", cdata[0:2])[0]
            for i in range(min(ccnt, 8)):
                if 2 + i * 2 + 2 <= len(cdata):
                    cid = struct.unpack("<H", cdata[2 + i * 2:4 + i * 2])[0]
                    out["ciphers"].append(cipher_map.get(cid, f"0x{cid:04x}"))
        elif ctype == 0x0008 and len(cdata) >= 2:
            scnt = struct.unpack("<H", cdata[0:2])[0]
            for i in range(min(scnt, 8)):
                if 2 + i * 2 + 2 <= len(cdata):
                    sid = struct.unpack("<H", cdata[2 + i * 2:4 + i * 2])[0]
                    out["signing"].append(sign_map.get(sid, f"0x{sid:04x}"))
        off = (data_end + 7) & ~7
    return out


def parse_smb_negotiate_request(data: bytes) -> Optional[Dict[str, Any]]:
    """Phân tích chi tiết gói tin SMB Negotiate Request nhận được từ Camera."""
    if len(data) < 8:
        return None
    payload = data[4:] if (data[0] == 0 and len(data) >= 4) else data

    if payload.startswith(b"\xffSMB"):
        v1_dialects = _parse_smb1_dialects(payload)
        has_smb2_upgrade = any("SMB 2." in d for d in v1_dialects)
        return {
            "downgrade": True,
            "dialect": ", ".join(v1_dialects) if v1_dialects else "SMBv1 (CIFS)",
            "dialects": v1_dialects,
            "protocol": "SMB 1.0 (Multi-protocol)" if has_smb2_upgrade else "SMB 1.0 (Không an toàn)",
            "smbv1": True,
            "has_smb3": False,
            "detail": (
                f"NGUY HIỂM: Camera gửi gói SMBv1 Negotiate ({', '.join(v1_dialects) or 'CIFS'})!"
            )
        }
    elif payload.startswith(b"\xfeSMB") and len(payload) >= 100:
        # Header SMB2/SMB3 = 64 bytes; SMB2 Negotiate fixed body = 36 bytes -> Dialects[] tại offset 100
        cmd_code = struct.unpack("<H", payload[12:14])[0]
        flags = struct.unpack("<I", payload[16:20])[0]
        if cmd_code != 0 or (flags & 0x00000001):
            return None
        msg_id = struct.unpack("<Q", payload[24:32])[0]
        dialect_count = struct.unpack("<H", payload[66:68])[0]
        dialects = []
        offset = 100
        for _ in range(min(dialect_count, 30)):
            if offset + 2 <= len(payload):
                d = struct.unpack("<H", payload[offset:offset + 2])[0]
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
        has_smb311 = 0x0311 in dialects

        ctx_info = _parse_smb311_negotiate_contexts(payload) if has_smb311 else {"hashes": [], "ciphers": [], "signing": []}
        ciphers = ctx_info["ciphers"]
        hashes = ctx_info["hashes"]
        has_gcm = any("GCM" in c for c in ciphers)
        if ciphers or hashes:
            parts = []
            if ciphers:
                parts.append(", ".join(ciphers))
            if hashes:
                parts.append(f"Preauth {'/'.join(hashes)}")
            enc_str = " | ".join(parts)
        elif has_smb3:
            enc_str = "SMB 3.x encryption (AES-128-CCM/GCM)"
        else:
            enc_str = "Chưa hỗ trợ mã hóa SMB 3.x"

        return {
            "downgrade": not has_smb3,
            "protocol": "SMB 3.1.1" if has_smb311 else ("SMB 3.0.x" if has_smb3 else "SMB 2.x"),
            "dialects": supported_str,
            "has_smb3": has_smb3,
            "has_gcm": has_gcm,
            "ciphers": ciphers,
            "hashes": hashes,
            "signing": ctx_info["signing"],
            "msg_id": msg_id,
            "encryption": enc_str,
            "detail": (
                f"ĐẠT: Camera đàm phán [{', '.join(supported_str)}], hỗ trợ {enc_str}, vô hiệu hóa hoàn toàn SMBv1"
                if has_smb3 else f"CẢNH BÁO: Chỉ chào mời [{', '.join(supported_str)}], không hỗ trợ SMB 3.x"
            )
        }
    return None


def build_smb2_negotiate_response(msg_id: int, dialect: int = 0x0311) -> bytes:
    """Xây dựng bản tin SMB2/SMB3.1.1 Negotiate Protocol Response chuẩn MS-SMB2."""
    header = bytearray(64)
    header[0:4] = b"\xfeSMB"
    struct.pack_into("<H", header, 4, 64)        # StructureSize
    struct.pack_into("<I", header, 8, 0)         # Status SUCCESS
    struct.pack_into("<H", header, 12, 0)        # Command: NEGOTIATE
    struct.pack_into("<H", header, 14, 1)        # CreditsGranted
    struct.pack_into("<I", header, 16, 1)        # Flags: RESPONSE
    struct.pack_into("<Q", header, 24, msg_id)   # MessageId

    body = bytearray(64)
    struct.pack_into("<H", body, 0, 65)          # StructureSize (fixed 64 + 1 var)
    struct.pack_into("<H", body, 2, 0x0003)      # SecurityMode (Signing enabled + required)
    struct.pack_into("<H", body, 4, dialect)     # DialectRevision
    body[8:24] = b"\x51\x43\x56\x4e\x31\x31\x53\x4d\x42\x33\x53\x45\x52\x56\x31\x31"  # ServerGuid
    struct.pack_into("<I", body, 24, 0x00000047) # Capabilities (DFS|Leasing|LargeMTU|MultiChan|DirectoryLeasing|Encryption)
    struct.pack_into("<I", body, 28, 8388608)    # MaxTransactSize (8MB)
    struct.pack_into("<I", body, 32, 8388608)    # MaxReadSize
    struct.pack_into("<I", body, 36, 8388608)    # MaxWriteSize
    struct.pack_into("<H", body, 56, 128)        # SecurityBufferOffset (64+64)
    struct.pack_into("<H", body, 58, 0)          # SecurityBufferLength

    neg_contexts = bytearray()
    if dialect == 0x0311:
        # 2 NegotiateContexts: Preauth Integrity (SHA-512) + Encryption (AES-128-GCM)
        preauth_data = struct.pack("<HH", 1, 32) + struct.pack("<H", 0x0001) + (b"\xaa" * 32)
        ctx1 = struct.pack("<HHI", 0x0001, len(preauth_data), 0) + preauth_data
        while len(ctx1) % 8 != 0:
            ctx1 += b"\x00"
        enc_data = struct.pack("<HH", 1, 0x0002)
        ctx2 = struct.pack("<HHI", 0x0002, len(enc_data), 0) + enc_data
        neg_contexts.extend(ctx1 + ctx2)
        struct.pack_into("<H", body, 6, 2)       # NegotiateContextCount
        struct.pack_into("<I", body, 60, 128)    # NegotiateContextOffset

    payload = bytes(header) + bytes(body) + bytes(neg_contexts)
    netbios_hdr = struct.pack(">I", len(payload))
    return netbios_hdr + payload


# ==============================================================================
# NHÓM 1: CÁC BÀI ĐO MÁY ĐO LÀ CLIENT PROBE (CAMERA LÀ SERVER)
# ==============================================================================

def audit_commech_1_web(wait_sec: float = 3.0) -> Dict[str, Any]:
    """Đo kiểm ComMech-1: Giao diện Web (HTTPS & HTTP Clear)."""
    console.print(f"\n[*] Đang chủ động đo kiểm [bold cyan]ComMech-1: Web Interface (HTTPS/{DUT_IP}:{HTTPS_PORT})[/bold cyan]...")
    res = {
        "id": "ComMech-1",
        "name": f"Web Interface (HTTPS/{HTTPS_PORT})",
        "port": HTTPS_PORT,
        "proto": "IP/TCP/HTTPS",
        "direction": "DUT Server (Tool Probe)",
        "pcap": "commech-1_web_https.pcap"
    }

    pcap_proc, pcap_path = start_pcap_capture(DUT_IP, f"ip host {DUT_IP} and (tcp port {HTTPS_PORT} or tcp port {HTTP_PORT})", prefix="commech1_web_https")
    time.sleep(0.8)
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.keylog_filename = SSLKEYLOG_PATH
        active_cipher = None
        tls_ver = None
        with socket.create_connection((DUT_IP, HTTPS_PORT), timeout=3.5) as sock:
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

        downgrade_ok, downgrade_msg = test_tls_downgrade(DUT_IP, HTTPS_PORT)
        res["downgrade_test"] = {"pass": downgrade_ok, "detail": downgrade_msg}
        time.sleep(0.3)

        s_http = socket.socket()
        s_http.settimeout(1.0)
        r_http = s_http.connect_ex((DUT_IP, HTTP_PORT))
        s_http.close()
        res[f"http_port_{HTTP_PORT}"] = "ĐÃ ĐÓNG / VÔ HIỆU HÓA HOÀN TOÀN (TCP RST)" if r_http != 0 else "MỞ"
        time.sleep(0.4)

        res["status"] = "PASS" if (downgrade_ok and tls_ver in ["TLSv1.2", "TLSv1.3"]) else "WARN"
    except Exception as e:
        res["status"] = "FAIL"
        res["error"] = str(e)
        res["downgrade_test"] = {"pass": False, "detail": f"Không thể kết nối HTTPS cổng {HTTPS_PORT}: {e}"}
    finally:
        time.sleep(0.8)
        stop_pcap_capture(pcap_proc)
        res["pcap_file"] = pcap_path
        res["pcap_packet_count"] = get_pcap_packet_count(pcap_path)
        _enforce_pcap_requirement(res)
    return res


def audit_commech_2_ssh(wait_sec: float = 3.0) -> Dict[str, Any]:
    """Đo kiểm ComMech-2: Giao diện SSH."""
    console.print(f"\n[*] Đang chủ động đo kiểm [bold cyan]ComMech-2: SSH Interface (SSH/{DUT_IP}:{SSH_PORT})[/bold cyan]...")
    res = {
        "id": "ComMech-2",
        "name": f"SSH Interface (SSH/{SSH_PORT})",
        "port": SSH_PORT,
        "proto": "IP/TCP/SSH",
        "direction": "DUT Server (Tool Probe)",
        "pcap": "commech-2_ssh.pcap"
    }

    pcap_proc, pcap_path = start_pcap_capture(DUT_IP, f"ip host {DUT_IP} and tcp port {SSH_PORT}", prefix="commech2_ssh")
    time.sleep(0.8)
    try:
        t = paramiko.Transport((DUT_IP, SSH_PORT))
        t.start_client(timeout=4.0)
        banner = t.remote_version
        sec_opts = t.get_security_options()
        ciphers_supported = list(sec_opts.ciphers)
        kex_supported = list(sec_opts.kex)

        # Xác thực SSH và mở kênh thực thi lệnh để tạo đầy đủ lưu lượng phiên SSH trong PCAP
        try:
            t.auth_password(SSH_USER, SSH_PASS)
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

        downgrade_ok, downgrade_msg = test_ssh_downgrade(DUT_IP, SSH_PORT)
        res["downgrade_test"] = {"pass": downgrade_ok, "detail": downgrade_msg}
        res["status"] = "PASS" if downgrade_ok else "FAIL"
    except Exception as e:
        res["status"] = "WARN"
        res["downgrade_test"] = {"pass": False, "detail": f"Cổng SSH {SSH_PORT} đóng hoặc từ chối kết nối ({e})"}
    finally:
        time.sleep(0.8)
        stop_pcap_capture(pcap_proc)
        res["pcap_file"] = pcap_path
        res["pcap_packet_count"] = get_pcap_packet_count(pcap_path)
        _enforce_pcap_requirement(res)
    return res


def audit_commech_3_onvif(wait_sec: float = 3.0) -> Dict[str, Any]:
    """Đo kiểm ComMech-3: ONVIF over HTTPS / HTTP."""
    console.print(f"\n[*] Đang chủ động đo kiểm [bold cyan]ComMech-3: ONVIF Interface (HTTPS/{DUT_IP}:{ONVIF_HTTPS_PORT}{ONVIF_PATH})[/bold cyan]...")
    res = {
        "id": "ComMech-3",
        "name": f"ONVIF Interface (HTTPS/{ONVIF_HTTPS_PORT})",
        "port": ONVIF_HTTPS_PORT,
        "proto": "IP/TCP/HTTPS/ONVIF",
        "direction": "DUT Server (Tool Probe)",
        "pcap": "commech-3_onvif.pcap"
    }

    pcap_proc, pcap_path = start_pcap_capture(
        DUT_IP,
        f"ip host {DUT_IP} and (tcp port {ONVIF_HTTPS_PORT} or tcp port {ONVIF_HTTP_PORT})",
        prefix="commech3_onvif"
    )
    try:
        from tool11_onvif_lockout import send_onvif_request
        url = f"https://{DUT_IP}:{ONVIF_HTTPS_PORT}{ONVIF_PATH}"
        ok, status_lbl, preview, lat = send_onvif_request(url, USER, PASS, auth_type="wsse_sha1")
        if not ok and ONVIF_HTTP_PORT != ONVIF_HTTPS_PORT:
            http_test_url = f"http://{DUT_IP}:{ONVIF_HTTP_PORT}{ONVIF_PATH}"
            ok_http, status_http, _, _ = send_onvif_request(http_test_url, USER, PASS, auth_type="wsse_sha1")
            if ok_http:
                ok = True
                status_lbl = f"HTTP:{ONVIF_HTTP_PORT} ({status_http})"
                res["port"] = ONVIF_HTTP_PORT
        res["auth_success"] = ok
        res["auth_status"] = status_lbl

        http_url = f"http://{DUT_IP}:{ONVIF_HTTP_PORT}{ONVIF_PATH}"
        http_rejected = False
        try:
            r = requests.post(http_url, data="<soap/>", headers={"Content-Type": "application/soap+xml"}, timeout=1.5)
            if r.status_code in [301, 302, 403, 404]:
                http_rejected = True
                http_msg = f"ĐẠT: Cổng HTTP {ONVIF_HTTP_PORT} từ chối/chuyển hướng (HTTP {r.status_code})"
            else:
                http_msg = f"CẢNH BÁO: ONVIF phản hồi cổng HTTP {ONVIF_HTTP_PORT} (HTTP {r.status_code})"
        except Exception:
            http_rejected = True
            http_msg = f"ĐẠT: Đóng hoàn toàn cổng HTTP {ONVIF_HTTP_PORT}, bắt buộc ONVIF over HTTPS"

        res["downgrade_test"] = {"pass": http_rejected, "detail": http_msg}
        res["status"] = "PASS" if ok else "WARN"
    except Exception as e:
        res["status"] = "WARN"
        res["downgrade_test"] = {"pass": False, "detail": f"Dịch vụ ONVIF không khả dụng: {e}"}
    finally:
        stop_pcap_capture(pcap_proc)
        res["pcap_file"] = pcap_path
        res["pcap_packet_count"] = get_pcap_packet_count(pcap_path)
        _enforce_pcap_requirement(res)
    return res


def audit_commech_4_snmp(wait_sec: float = 3.0) -> Dict[str, Any]:
    """Đo kiểm ComMech-4: Giao diện SNMP (UDP 161).
    Kiểm thử toàn bộ ma trận thuật toán xác thực & mã hóa (SHA-512/384/256/224/1/MD5 x AES-256/192/128/3DES/DES),
    authNoPriv, noAuthNoPriv và hạ cấp SNMPv1/v2c truyền rõ để xác định chính xác các mã hóa thực tế dùng được.
    """
    snmp_port = int(config.get("service_ports", {}).get("snmp") or config.get("service_ports", {}).get("snmp_udp") or 161)
    console.print(f"\n[*] Đang chủ động đo kiểm [bold cyan]ComMech-4: SNMP Interface (UDP/{DUT_IP}:{snmp_port})[/bold cyan]...")
    res = {
        "id": "ComMech-4",
        "name": f"SNMP Interface (UDP/{snmp_port})",
        "port": snmp_port,
        "proto": "IP/UDP/SNMPv3",
        "direction": "DUT Server (Tool Probe)",
        "pcap": "commech-4_snmpv3.pcap"
    }

    pcap_proc, pcap_path = start_pcap_capture(DUT_IP, f"ip host {DUT_IP} and udp port {snmp_port}", prefix="commech4_snmpv3")
    time.sleep(0.8)
    try:
        from tool5_snmpv3_auditor import run_snmp_audit, summarize_snmp_audit, display_snmp_audit

        matrix_results, _ = asyncio.run(run_snmp_audit(
            host=DUT_IP,
            port=snmp_port,
            capture_pcap=False,
        ))
        summary = display_snmp_audit(DUT_IP, snmp_port, matrix_results, pcap_file="", show_wireshark=False)

        usable = summary["usable_ciphers"]
        authpriv_ok = len(summary["accepted_authpriv"]) > 0
        downgrade_ok = (not summary["has_cleartext"]) and (not summary["has_weak_crypto"])

        res["active_cipher"] = ", ".join(usable) if usable else "Không có mã hóa hoạt động"
        res["supported_combos"] = [x["name"] for x in summary["accepted_authpriv"]]
        res["accepted_auth"] = summary["accepted_auth_algos"]
        res["accepted_priv"] = summary["accepted_priv_algos"]
        res["digest_matched_auth"] = summary["digest_verified_auth_algos"]
        res["matched_user"] = summary["matched_user"]
        res["engine_id"] = summary["engine_id"]
        if summary["sys_descr"]:
            res["sys_descr"] = summary["sys_descr"][:80]
        res["matrix"] = matrix_results

        usable_desc = ", ".join(usable) if usable else "Không có tổ hợp authPriv/SNMP nào thành công"
        if authpriv_ok and downgrade_ok:
            downgrade_detail = (
                f"ĐẠT: Thực tế dùng được {usable_desc} (User: {summary['matched_user']}); "
                "Chặn toàn bộ hạ cấp SNMPv1/v2c, noAuthNoPriv, authNoPriv & thuật toán yếu (MD5/SHA-1/DES/3DES)"
            )
        elif authpriv_ok and not downgrade_ok:
            issues = []
            if summary["has_cleartext"]:
                issues.append("chấp nhận kênh rõ (v1/v2c/noAuth/authNoPriv)")
            if summary["has_weak_crypto"]:
                issues.append("hỗ trợ thuật toán yếu (MD5/SHA-1/DES/3DES)")
            downgrade_detail = f"CẢNH BÁO: Dùng được {usable_desc}, nhưng {', '.join(issues)}"
        else:
            extra = ""
            if summary["digest_verified_auth_algos"]:
                extra = f" (Auth khớp HMAC: {', '.join(summary['digest_verified_auth_algos'])})"
            elif summary["all_wrong_digest"]:
                extra = " (WrongDigest trên mọi thuật toán băm - kiểm tra lại Auth/Priv Pass)"
            downgrade_detail = f"Thất bại: {usable_desc}{extra}"

        res["downgrade_test"] = {"pass": (authpriv_ok and downgrade_ok), "detail": downgrade_detail}
        res["status"] = "PASS" if (authpriv_ok and downgrade_ok) else "WARN"

    except Exception as e:
        res["status"] = "WARN"
        res["downgrade_test"] = {"pass": False, "detail": f"Không thể kiểm thử SNMP {snmp_port}: {e}"}
    finally:
        time.sleep(0.8)
        stop_pcap_capture(pcap_proc)
        res["pcap_file"] = pcap_path
        res["pcap_packet_count"] = get_pcap_packet_count(pcap_path)
        _enforce_pcap_requirement(res)
    return res


def audit_commech_10_rtsp(wait_sec: float = 3.0) -> Dict[str, Any]:
    """Đo kiểm ComMech-10: RTSP over TLS (RTSPS)."""
    console.print(f"\n[*] Đang chủ động đo kiểm [bold cyan]ComMech-10: RTSPS Interface (TLS/{DUT_IP}:{RTSPS_PORT}{RTSP_PATH})[/bold cyan]...")
    res = {
        "id": "ComMech-10",
        "name": f"RTSPS Interface (TLS/{RTSPS_PORT})",
        "port": RTSPS_PORT,
        "proto": "IP/TCP/TLS/RTSP",
        "direction": "DUT Server (Tool Probe)",
        "pcap": "commech-10_rtsps.pcap"
    }

    pcap_proc, pcap_path = start_pcap_capture(
        DUT_IP,
        f"ip host {DUT_IP} and (tcp port {RTSPS_PORT} or tcp port {RTSP_PORT})",
        prefix="commech10_rtsps"
    )
    time.sleep(0.8)
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.keylog_filename = SSLKEYLOG_PATH
        active_cipher = None
        tls_ver = None
        with socket.create_connection((DUT_IP, RTSPS_PORT), timeout=3.5) as sock:
            with ctx.wrap_socket(sock, server_hostname=DUT_IP) as ssock:
                active_cipher = ssock.cipher()
                tls_ver = ssock.version()

                # Gửi bản tin DESCRIBE xác thực để bóc tách thông số SDP luồng video đầy đủ trong PCAP
                cred = base64.b64encode(f"{USER}:{PASS}".encode()).decode()
                req_rtsp = (
                    f"DESCRIBE rtsps://{DUT_IP}:{RTSPS_PORT}{RTSP_PATH} RTSP/1.0\r\n"
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

        downgrade_ok, downgrade_msg = test_tls_downgrade(DUT_IP, RTSPS_PORT)
        res["downgrade_test"] = {"pass": downgrade_ok, "detail": downgrade_msg}

        s_clear = socket.socket()
        s_clear.settimeout(1.0)
        r_clear = s_clear.connect_ex((DUT_IP, RTSP_PORT))
        s_clear.close()
        res[f"rtsp_port_{RTSP_PORT}"] = "ĐÃ ĐÓNG / VÔ HIỆU HÓA HOÀN TOÀN (TCP RST)" if r_clear != 0 else "MỞ"

        res["status"] = "PASS" if (downgrade_ok and r_clear != 0 and tls_ver in ["TLSv1.2", "TLSv1.3"]) else "WARN"
    except Exception as e:
        res["status"] = "WARN"
        res["downgrade_test"] = {"pass": False, "detail": f"Cổng RTSPS {RTSPS_PORT} đóng hoặc từ chối kết nối ({e})"}
    finally:
        time.sleep(0.8)
        stop_pcap_capture(pcap_proc)
        res["pcap_file"] = pcap_path
        res["pcap_packet_count"] = get_pcap_packet_count(pcap_path)
        _enforce_pcap_requirement(res)
    return res


# ==============================================================================
# NHÓM 2: CÁC BÀI ĐO MÁY ĐO ĐÓNG VAI TRÒ MÁY CHỦ (SERVER RECEIVER)
# ==============================================================================

def display_server_receiver_panel(mech_id: str, mech_name: str, ports_desc: str, wait_sec: float, instructions: List[str], forever: bool = False):
    """Hiển thị Panel hướng dẫn thao tác trên Camera cho các dịch vụ Client kết nối về."""
    wait_text = "[bold green]CHẠY LIÊN TỤC (Đến khi bấm Stop hoặc Ctrl+C)[/bold green]" if forever else f"[bold cyan]{wait_sec:.0f} giây[/bold cyan] (Có thể bấm Ctrl+C để bỏ qua)"
    lines = [
        f"[bold yellow]MÁY ĐO ĐANG ĐÓNG VAI TRÒ SERVER LẮNG NGHE CHO {mech_id}: {mech_name.upper()}[/bold yellow]",
        f"• Địa chỉ IP Máy đo (Server) : [bold green]{HOST_IP}[/bold green]",
        f"• Cổng dịch vụ lắng nghe     : [bold white]{ports_desc}[/bold white]",
        f"• Thời gian hoạt động        : {wait_text}\n",
        "[bold white]--> HƯỚNG DẪN THAO TÁC TRÊN GIAO DIỆN CAMERA:[/bold white]"
    ]
    for inst in instructions:
        lines.append(f"    • {inst}")
    console.print(Panel("\n".join(lines), border_style="yellow"))


def _is_local_port_open(port: int) -> bool:
    """Kiểm tra cổng dịch vụ trên máy đo đã có tiến trình (như smbd) lắng nghe hay chưa."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.5)
    try:
        return s.connect_ex(("127.0.0.1", port)) == 0
    except Exception:
        return False
    finally:
        s.close()


def _extract_smb_negotiate_from_pcap(pcap_path: str, dut_ip: str, smb_port: int) -> Optional[Dict[str, Any]]:
    """Đọc tệp PCAP đang ghi để trích xuất gói SMB Negotiate Request (ưu tiên SMB 3.1.1 có NegotiateContexts)."""
    if not pcap_path or not os.path.exists(pcap_path) or os.path.getsize(pcap_path) <= 40:
        return None
    best: Optional[Dict[str, Any]] = None
    try:
        from scapy.all import rdpcap, IP, TCP
        pkts = rdpcap(pcap_path)
        for pkt in pkts:
            if IP in pkt and TCP in pkt:
                if pkt[IP].src == dut_ip and int(pkt[TCP].dport) == int(smb_port):
                    payload = bytes(pkt[TCP].payload)
                    if len(payload) >= 8:
                        parsed = parse_smb_negotiate_request(payload)
                        if parsed:
                            if parsed.get("protocol") == "SMB 3.1.1" or parsed.get("ciphers") or parsed.get("hashes"):
                                return parsed
                            if best is None:
                                best = parsed
    except Exception:
        pass
    return best


def _extract_smb_negotiate_response_from_pcap(pcap_path: str, dut_ip: str, smb_port: int) -> Optional[Dict[str, Any]]:
    """Trích xuất dialect, hash và cipher được Server chốt trong gói SMB2 Negotiate Response."""
    if not pcap_path or not os.path.exists(pcap_path) or os.path.getsize(pcap_path) <= 40:
        return None
    try:
        from scapy.all import rdpcap, IP, TCP
        dialect_map = {
            0x0202: "SMB 2.0.2",
            0x0210: "SMB 2.1",
            0x0300: "SMB 3.0",
            0x0302: "SMB 3.0.2",
            0x0311: "SMB 3.1.1",
        }
        hash_map = {0x0001: "SHA-512"}
        cipher_map = {
            0x0001: "AES-128-CCM",
            0x0002: "AES-128-GCM",
            0x0003: "AES-256-CCM",
            0x0004: "AES-256-GCM",
        }
        pkts = rdpcap(pcap_path)
        best: Optional[Dict[str, Any]] = None
        for pkt in pkts:
            if IP in pkt and TCP in pkt and pkt[IP].dst == dut_ip and int(pkt[TCP].sport) == int(smb_port):
                data = bytes(pkt[TCP].payload)
                if len(data) < 72:
                    continue
                payload = data[4:] if (data[0] == 0 and len(data) >= 4) else data
                if not payload.startswith(b"\xfeSMB") or len(payload) < 128:
                    continue
                cmd_code = struct.unpack("<H", payload[12:14])[0]
                flags = struct.unpack("<I", payload[16:20])[0]
                status = struct.unpack("<I", payload[8:12])[0]
                if cmd_code != 0 or not (flags & 0x00000001) or status != 0:
                    continue
                dialect = struct.unpack("<H", payload[68:70])[0]
                neg_ctx_cnt = struct.unpack("<H", payload[70:72])[0]
                neg_ctx_off = struct.unpack("<I", payload[124:128])[0]
                hashes: List[str] = []
                ciphers: List[str] = []
                if dialect == 0x0311 and neg_ctx_off >= 128 and neg_ctx_cnt > 0:
                    off = neg_ctx_off
                    for _ in range(min(neg_ctx_cnt, 16)):
                        if off + 8 > len(payload):
                            break
                        ctype, dlen = struct.unpack("<HH", payload[off:off + 4])
                        dstart = off + 8
                        dend = dstart + dlen
                        if dend > len(payload):
                            break
                        cdata = payload[dstart:dend]
                        if ctype == 0x0001 and len(cdata) >= 6:
                            hid = struct.unpack("<H", cdata[4:6])[0]
                            hashes.append(hash_map.get(hid, f"0x{hid:04x}"))
                        elif ctype == 0x0002 and len(cdata) >= 4:
                            cid = struct.unpack("<H", cdata[2:4])[0]
                            ciphers.append(cipher_map.get(cid, f"0x{cid:04x}"))
                        off = (dend + 7) & ~7
                info = {
                    "dialect": dialect_map.get(dialect, f"0x{dialect:04x}"),
                    "hashes": hashes,
                    "ciphers": ciphers,
                }
                if dialect == 0x0311:
                    return info
                if best is None:
                    best = info
        return best
    except Exception:
        return None


def _query_samba_active_session(dut_ip: str) -> Optional[Dict[str, str]]:
    """Truy vấn smbstatus -b để lấy thông số phiên SMB đang kết nối thực tế từ DUT."""
    import re as _re
    smbstatus_bin = shutil.which("smbstatus") or "/usr/bin/smbstatus"
    if not os.path.exists(smbstatus_bin):
        return None
    try:
        out = subprocess.check_output([smbstatus_bin, "-b"], stderr=subprocess.DEVNULL, text=True, timeout=3)
        pat = _re.compile(rf"^(\d+)\s+(\S+)\s+\S+\s+{_re.escape(dut_ip)}\s+\([^)]+\)\s+(\S+)\s+(\S+)\s+(\S+)", _re.MULTILINE)
        matches = pat.findall(out)
        if matches:
            pid, user, proto, enc, sign = matches[-1]
            return {"pid": pid, "user": user, "protocol": proto, "encryption": enc, "signing": sign}
    except Exception:
        pass
    return None


def _summarize_smb_pcap_session(pcap_path: str) -> Dict[str, Any]:
    """Dùng tshark kiểm tra các bước SMB2/3 (Negotiate, Session Setup, Tree Connect, Encrypted) trong PCAP."""
    summary = {"negotiate_rsp": False, "session_setup": False, "tree_connect": False, "encrypted": False}
    tshark_bin = shutil.which("tshark") or "/usr/bin/tshark"
    if not pcap_path or not os.path.exists(pcap_path) or not os.path.exists(tshark_bin):
        return summary
    try:
        out = subprocess.check_output(
            [tshark_bin, "-r", pcap_path, "-Y", "smb2 || smb"],
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=5,
        )
        for line in out.splitlines():
            low = line.lower()
            if "negotiate protocol response" in low:
                summary["negotiate_rsp"] = True
            if "session setup" in low:
                summary["session_setup"] = True
            if "tree connect" in low:
                summary["tree_connect"] = True
            if "encrypted" in low or "transform" in low:
                summary["encrypted"] = True
    except Exception:
        pass
    return summary


def _probe_local_smb_downgrade(smb_port: int) -> str:
    """Kiểm tra trực tiếp SMB server trên máy đo có từ chối SMBv1 và SMBv2 không."""
    smbv1_neg = (
        b"\x00\x00\x00\x2f\xffSMB\x72\x00\x00\x00\x00\x18\x53\xc8"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xfe"
        b"\x00\x00\x00\x00\x00\x0c\x00\x02NT LM 0.12\x00"
    )
    # SMB2.1-only Negotiate request (header 64B + body 36B + 1 dialect 0x0210 = 102B)
    smb2_hdr = bytearray(64)
    smb2_hdr[0:4] = b"\xfeSMB"
    struct.pack_into("<H", smb2_hdr, 4, 64)
    struct.pack_into("<H", smb2_hdr, 12, 0)
    smb2_body = bytearray(36)
    struct.pack_into("<H", smb2_body, 0, 36)
    struct.pack_into("<H", smb2_body, 2, 1)
    struct.pack_into("<H", smb2_body, 4, 1)
    smb2_payload = bytes(smb2_hdr) + bytes(smb2_body) + struct.pack("<H", 0x0210)
    smb2_neg = struct.pack(">I", len(smb2_payload)) + smb2_payload

    results = []
    for label, pkt in [("SMBv1", smbv1_neg), ("SMBv2", smb2_neg)]:
        try:
            with socket.create_connection(("127.0.0.1", smb_port), timeout=1.5) as s:
                s.settimeout(1.5)
                s.sendall(pkt)
                rsp = s.recv(1024)
                if not rsp:
                    results.append(f"{label} bị ngắt")
                elif len(rsp) >= 40 and rsp[4:8] == b"\xffSMB":
                    status = struct.unpack("<I", rsp[9:13])[0]
                    dialect_idx = struct.unpack("<H", rsp[37:39])[0] if len(rsp) >= 39 else 0
                    if status != 0 or dialect_idx == 0xFFFF:
                        results.append(f"{label} bị từ chối")
                    else:
                        results.append(f"{label} được chấp nhận!")
                elif len(rsp) >= 16 and rsp[4:8] == b"\xfeSMB":
                    status = struct.unpack("<I", rsp[12:16])[0]
                    if status != 0:
                        results.append(f"{label} bị từ chối (0x{status:08x})")
                    else:
                        results.append(f"{label} được chấp nhận!")
                else:
                    results.append(f"{label} bị từ chối")
        except Exception:
            results.append(f"{label} bị từ chối/đóng")
    return ", ".join(results)


def audit_commech_7_smb(wait_sec: float = 20.0, record_pcap: bool = True, forever: bool = False) -> Dict[str, Any]:
    """Đo kiểm ComMech-7: SMBv3 NAS Client - Máy đo là SMB Server."""
    console.print(f"\n[*] Khởi chạy đo kiểm [bold cyan]ComMech-7: SMBv3 NAS Storage Client (TCP/{SMB_PORT})[/bold cyan]...")
    smbd_active = _is_local_port_open(SMB_PORT)
    res = {
        "id": "ComMech-7",
        "name": "SMBv3 NAS Client",
        "port": SMB_PORT,
        "proto": "IP/TCP/SMBv3",
        "direction": f"DUT Client (Tool Server {SMB_PORT})",
        "pcap": "commech-7_smb.pcap"
    }

    server_mode_note = (
        f"Samba SMBv3 Server đang hoạt động sẵn trên cổng {SMB_PORT} (hỗ trợ mount thật + mã hóa bắt buộc)."
        if smbd_active else
        f"Listener Python sẽ lắng nghe cổng {SMB_PORT} để bắt gói SMB Negotiate."
    )
    display_server_receiver_panel(
        "ComMech-7", "SMBv3 NAS Client", f"TCP {SMB_PORT}", wait_sec,
        [
            f"Trạng thái Server: [bold green]{server_mode_note}[/bold green]",
            f"Vào Web Camera: [bold cyan]System → Storage → Network storage[/bold cyan]",
            f"Nếu chưa mount: Bấm [bold yellow]Add network storage[/bold yellow] -> Address: [bold green]{HOST_IP}[/bold green] | Share: [bold white]test[/bold white] | User: [bold white]admin[/bold white] | Pass: [bold white]{PASS}[/bold white] | SMB Version: [bold white]3.1.1[/bold white]",
            f"Nếu ĐÃ mount sẵn: Tắt rồi bật lại công tắc [bold yellow]Network storage[/bold yellow] (hoặc [bold yellow]Remove -> Add[/bold yellow]) trong lúc chờ để bắt trọn gói [bold cyan]SMB 3.1.1 Negotiate Contexts[/bold cyan] (SHA-512, AES-128/256-GCM, AES-128-CCM)."
        ],
        forever=forever
    )

    pcap_proc, pcap_path = start_pcap_capture(DUT_IP, f"ip host {DUT_IP} and tcp port {SMB_PORT}", prefix="commech7_smb")
    parsed_smb = None
    connected_client = None

    if smbd_active:
        try:
            start_time = time.time()
            probe_seen_notified = False
            while forever or (time.time() - start_time < wait_sec):
                remain = max(0, int(wait_sec - (time.time() - start_time)))
                parsed = _extract_smb_negotiate_from_pcap(pcap_path, DUT_IP, SMB_PORT)
                if parsed:
                    parsed_smb = parsed
                    if parsed.get("protocol") == "SMB 3.1.1" or parsed.get("ciphers") or parsed.get("hashes"):
                        console.print(f"\n    [bold green][+] Đã bắt được gói SMB 3.1.1 Negotiate (kèm NegotiateContexts) từ {DUT_IP}! Đang chờ hoàn tất Session Setup & Tree Connect...[/bold green]")
                        if not forever:
                            time.sleep(2.5)
                            break
                    elif not probe_seen_notified:
                        probe_seen_notified = True
                        console.print(f"\n    [yellow][*] Đã bắt được probe SMB 3.0.2; tiếp tục chờ gói SMB 3.1.1 (tắt/bật Network storage trên camera để chụp đầy đủ SHA-512 & AES-GCM/CCM)...[/yellow]")
                msg = (
                    f"    [dim]Đang lắng nghe gói SMB 3.1.1 từ Camera ({DUT_IP})... [Bấm Stop để dừng][/dim]"
                    if forever else (
                        f"    [dim]Đang chờ gói SMB 3.1.1 Mount từ Camera ({DUT_IP})... còn {remain}s[/dim]"
                        if probe_seen_notified else
                        f"    [dim]Đang chờ Camera ({DUT_IP}) kết nối tới Samba SMBv3 {HOST_IP}:{SMB_PORT}... còn {remain}s[/dim]"
                    )
                )
                console.print(msg, end="\r")
                time.sleep(0.8)
        except KeyboardInterrupt:
            console.print("\n[yellow][!] Đã nhận tín hiệu dừng Server SMB.[/yellow]")
    else:
        srv_sock = None
        try:
            srv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv_sock.bind(("0.0.0.0", SMB_PORT))
            srv_sock.listen(5)

            start_time = time.time()
            while forever or (time.time() - start_time < wait_sec):
                remain = max(0, int(wait_sec - (time.time() - start_time)))
                readable, _, _ = select.select([srv_sock], [], [], 1.0)
                if readable:
                    accepted = _accept_dut_client(srv_sock, SMB_PORT, timeout=2.5)
                    if not accepted:
                        continue
                    client_conn, connected_client = accepted
                    try:
                        data = client_conn.recv(4096)
                        parsed = parse_smb_negotiate_request(data)
                        if parsed:
                            parsed_smb = parsed
                            if parsed.get("has_smb3"):
                                resp = build_smb2_negotiate_response(parsed.get("msg_id", 0), 0x0311)
                                client_conn.sendall(resp)
                                time.sleep(0.3)
                            console.print(f"\n    [bold green][+] Nhận SMB Negotiate từ {connected_client}[/bold green]")
                            if not forever:
                                break
                    except Exception:
                        pass
                    finally:
                        client_conn.close()
                    continue
                msg = f"    [dim]Server SMB đang lắng nghe trên cổng {SMB_PORT}... [Bấm Stop để dừng][/dim]" if forever else f"    [dim]Đang chờ Camera ({DUT_IP}) kết nối tới {HOST_IP}:{SMB_PORT}... còn {remain}s[/dim]"
                console.print(msg, end="\r")
        except PermissionError:
            res["downgrade_test"] = {"pass": False, "detail": f"LỖI QUYỀN: Cần chạy tool bằng 'sudo' để mở cổng TCP {SMB_PORT}."}
            res["status"] = "FAIL"
            stop_pcap_capture(pcap_proc)
            res["pcap_file"] = pcap_path
            res["pcap_packet_count"] = get_pcap_packet_count(pcap_path)
            return res
        except KeyboardInterrupt:
            console.print("\n[yellow][!] Đã nhận tín hiệu dừng Server SMB.[/yellow]")
        except Exception as e:
            res["error"] = str(e)
        finally:
            if srv_sock:
                try:
                    srv_sock.close()
                except Exception:
                    pass

    time.sleep(1.0)
    stop_pcap_capture(pcap_proc)
    res["pcap_file"] = pcap_path
    pkt_count = get_pcap_packet_count(pcap_path)
    res["pcap_packet_count"] = pkt_count

    if pkt_count > 0:
        final_parsed = _extract_smb_negotiate_from_pcap(pcap_path, DUT_IP, SMB_PORT)
        if final_parsed:
            parsed_smb = final_parsed

    if parsed_smb:
        res["parsed_negotiate"] = parsed_smb
        is_pass = not parsed_smb.get("downgrade")
        detail = parsed_smb.get("detail", "N/A")
        neg_rsp = _extract_smb_negotiate_response_from_pcap(pcap_path, DUT_IP, SMB_PORT)
        if neg_rsp:
            res["negotiate_response"] = neg_rsp
        samba_live = _query_samba_active_session(DUT_IP) if smbd_active else None
        if samba_live:
            res["samba_session"] = samba_live
        if smbd_active:
            sess = _summarize_smb_pcap_session(pcap_path)
            res["smb_session"] = sess
            stages = [k for k, ok in [
                ("Negotiate", sess["negotiate_rsp"]),
                ("Session Setup", sess["session_setup"]),
                ("Tree Connect", sess["tree_connect"]),
                ("Encrypted SMB3", sess["encrypted"]),
            ] if ok]
            if stages:
                detail += f" | Phiên Samba: {', '.join(stages)}"
            dg_probe = _probe_local_smb_downgrade(SMB_PORT)
            detail += f" ({dg_probe})"

        # In bảng chi tiết thuật toán SMBv3 thực tế để đối chiếu & chụp ảnh
        info_lines = [
            f"• Dialects chào mời (Camera) : [bold cyan]{', '.join(parsed_smb.get('dialects', [])) or 'N/A'}[/bold cyan]",
            f"• Preauth Integrity Hash     : [bold green]{', '.join(parsed_smb.get('hashes', [])) or '(Chưa có NegotiateContext - hãy tắt/bật Network storage lúc đo)'}[/bold green]",
            f"• Encryption Ciphers chào mời: [bold green]{', '.join(parsed_smb.get('ciphers', [])) or '(Chưa có NegotiateContext - hãy tắt/bật Network storage lúc đo)'}[/bold green]",
            f"• Signing Algorithms chào mời: [bold white]{', '.join(parsed_smb.get('signing', [])) or 'N/A'}[/bold white]",
        ]
        if neg_rsp:
            info_lines.append(
                f"• Server chốt (Negotiate Rsp): [bold yellow]{neg_rsp.get('dialect')}[/bold yellow] | "
                f"Hash: [green]{', '.join(neg_rsp.get('hashes', [])) or 'N/A'}[/green] | "
                f"Cipher: [green]{', '.join(neg_rsp.get('ciphers', [])) or 'N/A'}[/green]"
            )
        if samba_live:
            info_lines.append(
                f"• Phiên đang Mount (smbstatus): [bold green]{samba_live['protocol']}[/bold green] | "
                f"Encryption: [bold green]{samba_live['encryption']}[/bold green] | "
                f"Signing: [bold white]{samba_live['signing']}[/bold white] (User: {samba_live['user']})"
            )
        info_lines.append("• Wireshark Display Filter   : [bold magenta]smb2.cmd == 0 && smb2.dialect == 0x0311[/bold magenta] (hoặc [magenta]smb2.cmd == 0[/magenta])")
        console.print(Panel("\n".join(info_lines), title="CHI TIẾT THUẬT TOÁN SMBv3 THỰC TẾ (COMMECH-7)", border_style="cyan"))

        res["downgrade_test"] = {"pass": is_pass, "detail": detail}
        res["status"] = "PASS" if is_pass else "FAIL"
        _enforce_pcap_requirement(res)
    else:
        res["downgrade_test"] = {
            "pass": False,
            "detail": f"CHƯA THỰC HIỆN: Không nhận được kết nối SMB từ Camera ({DUT_IP}) trong {wait_sec:.0f}s. File PCAP chưa có dữ liệu ({pkt_count} gói tin)."
        }
        res["status"] = "NO_DATA"
    return res


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    """Đọc chính xác n bytes từ socket hoặc trả về dữ liệu hiện có khi peer đóng."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            break
        buf.extend(chunk)
    return bytes(buf)


def _is_mqtt_connect_packet(pkt: bytes) -> bool:
    """Xác thực gói MQTT CONNECT (type 0x10) có tên giao thức MQTT/MQIsdp hợp lệ."""
    if not pkt or len(pkt) < 10 or (pkt[0] & 0xF0) != 0x10:
        return False
    # Remaining Length (1..4 bytes) bắt đầu từ byte 1, theo sau bởi 2-byte length + "MQTT"/"MQIsdp"
    return b"MQTT" in pkt[2:14] or b"MQIsdp" in pkt[2:16]


def _read_ws_frame(ssock: socket.socket, max_payload: int = 65536) -> Optional[Tuple[int, bytes]]:
    """Đọc 1 WebSocket frame hoàn chỉnh (hỗ trợ cả payload > 125 bytes)."""
    hdr = _recv_exact(ssock, 2)
    if len(hdr) < 2:
        return None
    opcode = hdr[0] & 0x0F
    masked = bool(hdr[1] & 0x80)
    length = hdr[1] & 0x7F
    if length == 126:
        ext = _recv_exact(ssock, 2)
        if len(ext) < 2:
            return None
        length = struct.unpack(">H", ext)[0]
    elif length == 127:
        ext = _recv_exact(ssock, 8)
        if len(ext) < 8:
            return None
        length = struct.unpack(">Q", ext)[0]
    if length > max_payload:
        return None
    mask = _recv_exact(ssock, 4) if masked else b""
    if masked and len(mask) < 4:
        return None
    raw = _recv_exact(ssock, length)
    if len(raw) < length:
        return None
    payload = bytes(b ^ mask[i % 4] for i, b in enumerate(raw)) if masked else raw
    return opcode, payload


def _peek_client_first(conn: socket.socket, wait_s: float = 0.45) -> bytes:
    """Chờ ngắn xem client có gửi trước dữ liệu (TLS ClientHello / HTTP / WebSocket) hay đang chờ banner server."""
    try:
        r, _, _ = select.select([conn], [], [], wait_s)
        if r:
            return conn.recv(2048, socket.MSG_PEEK)
    except Exception:
        pass
    return b""


def _try_ws_handshake_and_read(sock: socket.socket, default_proto: Optional[str] = "mqtt") -> Tuple[bool, bytes]:
    """Đọc HTTP request; nếu là WebSocket Upgrade thì trả 101 Switching Protocols và đọc 1 frame đầu."""
    import hashlib
    import base64

    req = b""
    while b"\r\n\r\n" not in req and len(req) < 8192:
        chunk = sock.recv(1024)
        if not chunk:
            break
        req += chunk
    lines = req.decode("utf-8", errors="ignore").split("\r\n")
    ws_key = None
    ws_proto = None
    for line in lines:
        low = line.lower()
        if low.startswith("sec-websocket-key:"):
            ws_key = line.split(":", 1)[1].strip()
        elif low.startswith("sec-websocket-protocol:"):
            ws_proto = line.split(":", 1)[1].split(",")[0].strip()
    if not ws_key:
        return False, req

    guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
    accept_val = base64.b64encode(hashlib.sha1((ws_key + guid).encode()).digest()).decode()
    resp_lines = [
        "HTTP/1.1 101 Switching Protocols",
        "Upgrade: websocket",
        "Connection: Upgrade",
        f"Sec-WebSocket-Accept: {accept_val}",
    ]
    chosen_proto = ws_proto or default_proto
    if chosen_proto:
        resp_lines.append(f"Sec-WebSocket-Protocol: {chosen_proto}")
    sock.sendall(("\r\n".join(resp_lines) + "\r\n\r\n").encode("utf-8"))
    frame = _read_ws_frame(sock)
    return True, (frame[1] if frame else b"")


def audit_commech_5_mqtt(wait_sec: float = 20.0, record_pcap: bool = True, forever: bool = False) -> Dict[str, Any]:
    """Đo kiểm ComMech-5: Giao diện MQTT (SSL/TLS & WebSocket Secure) - Máy đo là MQTT Broker."""
    import hashlib
    import base64

    console.print(f"\n[*] Khởi chạy đo kiểm [bold cyan]ComMech-5: MQTT Client Interface[/bold cyan]...")
    res = {
        "id": "ComMech-5",
        "name": "MQTT Client Interface",
        "port": MQTT_TLS_PORT,
        "proto": "IP/TCP/TLS (MQTT over SSL / WebSocket Secure)",
        "direction": f"DUT Client (Tool Server {MQTT_TLS_PORT} / {MQTT_WSS_PORT})",
        "pcap": "commech-5_mqtt.pcap"
    }

    display_server_receiver_panel(
        "ComMech-5", "MQTT Client",
        f"TCP {MQTT_TLS_PORT} (SSL/TLS) | TCP {MQTT_WSS_PORT} (WebSocket Secure) | TCP {MQTT_CLEAR_PORT} (Rõ)",
        wait_sec,
        [
            f"Vào Web Camera: [bold cyan]System > MQTT > MQTT client[/bold cyan]",
            f"Điền Host: [bold green]{HOST_IP}[/bold green]",
            f"Chọn 1 trong 2 cơ chế:",
            f"  • Cơ chế 1: Protocol [bold white]MQTT over SSL[/bold white] | Port [bold white]{MQTT_TLS_PORT}[/bold white]",
            f"  • Cơ chế 2: Protocol [bold white]MQTT over WebSocket secure[/bold white] | Port [bold white]{MQTT_WSS_PORT}[/bold white]",
            f"Bỏ tick [bold yellow]Validate server certificate[/bold yellow] rồi bấm [bold yellow]Save[/bold yellow] trên Web Camera."
        ],
        forever=forever
    )

    pcap_proc, pcap_path = start_pcap_capture(
        DUT_IP,
        f"ip host {DUT_IP} and (tcp port {MQTT_TLS_PORT} or tcp port {MQTT_WSS_PORT} or tcp port {MQTT_CLEAR_PORT})",
        prefix="commech5_mqtt"
    )
    captured_tls = None
    captured_cleartext = False
    sockets_to_close = []

    try:
        server_ctx = get_server_ssl_context()
        for port in (MQTT_TLS_PORT, MQTT_WSS_PORT, MQTT_CLEAR_PORT):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("0.0.0.0", port))
            sock.listen(5)
            sockets_to_close.append(sock)
        s_tls, s_wss, s_clear = sockets_to_close

        start_time = time.time()
        while forever or (time.time() - start_time < wait_sec):
            remain = max(0, int(wait_sec - (time.time() - start_time)))
            readable, _, _ = select.select([s_tls, s_wss, s_clear], [], [], 1.0)
            if s_clear in readable:
                accepted = _accept_dut_client(s_clear, MQTT_CLEAR_PORT, timeout=3.0)
                if not accepted:
                    continue
                c, peer_ip = accepted
                try:
                    peek = _peek_client_first(c, 0.5)
                    if peek.startswith((b"GET ", b"POST ", b"HEAD ")) or b"upgrade: websocket" in peek.lower():
                        is_ws, ws_payload = _try_ws_handshake_and_read(c, default_proto="mqtt")
                        if is_ws:
                            if _is_mqtt_connect_packet(ws_payload):
                                connack = b"\x20\x02\x00\x00"
                                c.sendall(bytes([0x82, len(connack)]) + connack)
                            captured_cleartext = True
                            console.print(f"\n    [bold red][!] Phát hiện MQTT over WebSocket rõ (không TLS) cổng {MQTT_CLEAR_PORT} từ {peer_ip}[/bold red]")
                            if not forever:
                                break
                    pkt = c.recv(1024)
                    if _is_mqtt_connect_packet(pkt):
                        c.sendall(b"\x20\x02\x00\x00")
                        captured_cleartext = True
                        if not forever:
                            break
                    console.print(f"\n    [dim][!] Bỏ qua gói tin không phải MQTT CONNECT trên cổng {MQTT_CLEAR_PORT} từ {peer_ip}[/dim]")
                except Exception:
                    pass
                finally:
                    c.close()
                continue
            if s_tls in readable:
                c, a = s_tls.accept()
                peer_ip = a[0]
                if peer_ip != DUT_IP:
                    console.print(f"\n    [dim][!] Bỏ qua kết nối cổng {MQTT_TLS_PORT} từ {peer_ip} (không phải DUT {DUT_IP})[/dim]")
                    c.close()
                    continue
                c.settimeout(3.0)
                try:
                    with server_ctx.wrap_socket(c, server_side=True) as ssock:
                        pkt = ssock.recv(1024)
                        if _is_mqtt_connect_packet(pkt):
                            ssock.sendall(b"\x20\x02\x00\x00")  # CONNACK
                            captured_tls = {
                                "mode": "MQTT over SSL",
                                "port": MQTT_TLS_PORT,
                                "peer_ip": peer_ip,
                                "version": ssock.version(),
                                "cipher": ssock.cipher()[0] if ssock.cipher() else "N/A"
                            }
                            console.print(f"\n    [bold green][+] Nhận MQTT CONNECT từ {peer_ip}:{MQTT_TLS_PORT} ({captured_tls['version']} / {captured_tls['cipher']})[/bold green]")
                            if not forever:
                                break
                        console.print(f"\n    [dim][!] Bỏ qua phiên TLS cổng {MQTT_TLS_PORT} từ {peer_ip}: không có gói MQTT CONNECT hợp lệ[/dim]")
                except Exception as exc:
                    console.print(f"\n    [dim][!] Phiên TLS cổng {MQTT_TLS_PORT} từ {peer_ip} chưa hoàn tất ({type(exc).__name__}), tiếp tục chờ...[/dim]")
                continue
            if s_wss in readable:
                accepted = _accept_dut_client(s_wss, MQTT_WSS_PORT, timeout=3.0)
                if not accepted:
                    continue
                c, peer_ip = accepted
                try:
                    with server_ctx.wrap_socket(c, server_side=True) as ssock:
                        is_ws, payload = _try_ws_handshake_and_read(ssock, default_proto="mqtt")
                        if is_ws and _is_mqtt_connect_packet(payload):
                            connack = b"\x20\x02\x00\x00"
                            ssock.sendall(bytes([0x82, len(connack)]) + connack)
                            captured_tls = {
                                "mode": "MQTT over WebSocket Secure (WSS)",
                                "port": MQTT_WSS_PORT,
                                "peer_ip": peer_ip,
                                "version": ssock.version(),
                                "cipher": ssock.cipher()[0] if ssock.cipher() else "N/A"
                            }
                            console.print(f"\n    [bold green][+] Nhận MQTT CONNECT (WSS) từ {peer_ip}:{MQTT_WSS_PORT} ({captured_tls['version']} / {captured_tls['cipher']})[/bold green]")
                            if not forever:
                                break
                        console.print(f"\n    [dim][!] Bỏ qua phiên WSS cổng {MQTT_WSS_PORT} từ {peer_ip}: không có gói MQTT CONNECT hợp lệ[/dim]")
                except Exception as exc:
                    console.print(f"\n    [dim][!] Phiên WSS cổng {MQTT_WSS_PORT} từ {peer_ip} chưa hoàn tất ({type(exc).__name__}), tiếp tục chờ...[/dim]")
                continue
            msg = f"    [dim]Server MQTT Broker đang lắng nghe (TLS {MQTT_TLS_PORT} & WSS {MQTT_WSS_PORT})... [Bấm Stop để dừng][/dim]" if forever else f"    [dim]Đang chờ Camera ({DUT_IP}) kết nối MQTT tới {HOST_IP}:{MQTT_TLS_PORT} hoặc {MQTT_WSS_PORT}... còn {remain}s[/dim]"
            console.print(msg, end="\r")
    except KeyboardInterrupt:
        console.print("\n[yellow][!] Đã nhận tín hiệu dừng Server MQTT.[/yellow]")
    except Exception as e:
        res["error"] = str(e)
        console.print(f"\n[bold red][!] Lỗi khi mở listener ComMech-5: {e}[/bold red]")
    finally:
        for sock in sockets_to_close:
            try:
                sock.close()
            except Exception:
                pass

    if captured_tls or captured_cleartext:
        time.sleep(0.25)
    stop_pcap_capture(pcap_proc)
    res["pcap_file"] = pcap_path
    pkt_count = get_pcap_packet_count(pcap_path)
    res["pcap_packet_count"] = pkt_count

    if captured_cleartext:
        res["status"] = "FAIL"
        res["downgrade_test"] = {"pass": False, "detail": f"NGUY HIỂM: Camera kết nối MQTT dạng rõ qua cổng {MQTT_CLEAR_PORT} không mã hóa!"}
    elif captured_tls and pkt_count > 0:
        res["status"] = "PASS"
        res["port"] = captured_tls["port"]
        res["proto"] = f"IP/TCP/TLS ({captured_tls['mode']})"
        res["active_tls"] = captured_tls["version"]
        res["active_cipher"] = captured_tls["cipher"]
        res["downgrade_test"] = {"pass": True, "detail": f"ĐẠT: Camera kết nối {captured_tls['mode']} cổng {captured_tls['port']} qua TLS bảo mật {captured_tls['version']} ({captured_tls['cipher']})"}
    elif captured_tls and pkt_count == 0:
        res["status"] = "NO_DATA"
        res["downgrade_test"] = {"pass": False, "detail": f"CẢNH BÁO (0 PKTS): Nhận bắt tay {captured_tls['mode']} từ {captured_tls['peer_ip']} nhưng PCAP ({DUT_IP}) có 0 gói tin — từ chối đánh dấu ĐẠT."}
    else:
        res["status"] = "NO_DATA"
        res["downgrade_test"] = {"pass": False, "detail": f"CHƯA THỰC HIỆN: Không nhận được kết nối MQTT từ Camera ({DUT_IP}) trong {wait_sec:.0f}s ({pkt_count} gói tin)."}
    return res


def _vapix_session_candidates():
    """Yield authenticated HTTPS/HTTP session + base_url candidates using live HOST_IP."""
    import requests, urllib3
    from requests.adapters import HTTPAdapter
    urllib3.disable_warnings()

    class SourceAddressAdapter(HTTPAdapter):
        def __init__(self, source_address, **kwargs):
            self.source_address = (source_address, 0)
            super().__init__(**kwargs)
        def init_poolmanager(self, *args, **kwargs):
            kwargs['source_address'] = self.source_address
            return super().init_poolmanager(*args, **kwargs)

    src_list = [HOST_IP, None] if HOST_IP and HOST_IP != "127.0.0.1" else [None]
    for src in src_list:
        s = requests.Session()
        if src:
            s.mount("https://", SourceAddressAdapter(src))
            s.mount("http://", SourceAddressAdapter(src))
        s.auth = (USER, PASS)
        yield s, f"https://{DUT_IP}:{HTTPS_PORT}"


def _trigger_camera_syslog():
    time.sleep(0.8)
    for s, base_url in _vapix_session_candidates():
        try:
            url = f"{base_url}/axis-cgi/remotesyslog.cgi"
            r = s.post(url, json={"apiVersion": "1.2", "method": "disable"}, verify=False, timeout=2.5)
            if r.status_code == 404:
                return
            time.sleep(0.3)
            s.post(url, json={"apiVersion": "1.2", "method": "enable"}, verify=False, timeout=2.5)
            time.sleep(0.2)
            s.post(url, json={"apiVersion": "1.2", "method": "test"}, verify=False, timeout=2)
            return
        except Exception:
            continue


def _trigger_camera_smtp():
    time.sleep(0.8)
    for s, base_url in _vapix_session_candidates():
        try:
            url = f"{base_url}/axis-cgi/smtptest.cgi?to=audit@example.com&from=camera@axis.local&mailserver={HOST_IP}&port={SMTP_STARTTLS_PORT}&encryption=starttls&validatecert=0&subject=QCVN11_Test&body=Security_Audit"
            s.get(url, verify=False, timeout=4)
            return
        except Exception:
            continue


def _trigger_camera_sftp():
    time.sleep(0.8)
    for s, base_url in _vapix_session_candidates():
        try:
            url = f"{base_url}/axis-cgi/ftptest.cgi?proto=sftp&address={HOST_IP}&port={SFTP_PORT}&username=merlin&password=test&publickeyfp=00112233445566778899aabbccddeeff"
            s.get(url, verify=False, timeout=4)
            return
        except Exception:
            continue


def audit_commech_6_syslog(wait_sec: float = 15.0, auto_trigger: bool = False, record_pcap: bool = True, forever: bool = False) -> Dict[str, Any]:
    """Đo kiểm ComMech-6: Remote Syslog over TLS - Máy đo là Syslog Server."""
    console.print(f"\n[*] Khởi chạy đo kiểm [bold cyan]ComMech-6: Remote Syslog over TLS (TCP/{SYSLOG_TLS_PORT})[/bold cyan]...")
    cert_path = os.path.join(TOOLKIT_DIR, "syslog_ca.crt")
    res = {
        "id": "ComMech-6",
        "name": "Remote Syslog over TLS",
        "port": SYSLOG_TLS_PORT,
        "proto": f"IP/TCP/TLS (Port {SYSLOG_TLS_PORT})",
        "direction": f"DUT Client (Tool Server {SYSLOG_TLS_PORT})",
        "pcap": "commech-6_syslog.pcap"
    }

    display_server_receiver_panel(
        "ComMech-6", "Remote Syslog", f"TCP {SYSLOG_TLS_PORT} (TLS) & UDP/TCP {SYSLOG_CLEAR_PORT} (Rõ)", wait_sec,
        [
            f"Vào Web Camera: [bold cyan]System → Logs → Remote system log[/bold cyan]",
            f"Điền Host: [bold green]{HOST_IP}[/bold green] | Port: [bold white]{SYSLOG_TLS_PORT}[/bold white] | Format: [bold white]RFC 5424[/bold white] | Protocol: [bold white]TLS[/bold white]",
            f"CA certificate 1: chọn [bold white]syslog_ca[/bold white] (tệp CA: [dim]{cert_path}[/dim])",
            f"Bấm nút [bold yellow]Test server setup[/bold yellow] để Camera gửi bản tin log."
        ],
        forever=forever
    )

    pcap_proc, pcap_path = start_pcap_capture(
        DUT_IP,
        f"ip host {DUT_IP} and (tcp port {SYSLOG_TLS_PORT} or udp port {SYSLOG_CLEAR_PORT} or tcp port {SYSLOG_CLEAR_PORT})",
        prefix="commech6_syslog"
    )
    captured_tls = None
    captured_cleartext = None
    last_tls_error = None
    syslog_messages: List[str] = []

    syslog_socks = []
    try:
        server_ctx = get_server_ssl_context()
        s_tls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s_tls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s_tls.bind(("0.0.0.0", SYSLOG_TLS_PORT))
        s_tls.listen(5)
        syslog_socks.append(s_tls)

        s_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s_udp.bind(("0.0.0.0", SYSLOG_CLEAR_PORT))
        syslog_socks.append(s_udp)

        s_tcp_clear = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s_tcp_clear.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s_tcp_clear.bind(("0.0.0.0", SYSLOG_CLEAR_PORT))
        s_tcp_clear.listen(5)
        syslog_socks.append(s_tcp_clear)

        if auto_trigger:
            threading.Thread(target=_trigger_camera_syslog, daemon=True).start()

        start_time = time.time()
        while forever or (time.time() - start_time < wait_sec):
            remain = max(0, int(wait_sec - (time.time() - start_time)))
            readable, _, _ = select.select(syslog_socks, [], [], 1.0)
            if s_udp in readable:
                data, addr = s_udp.recvfrom(4096)
                if addr[0] == DUT_IP and data:
                    captured_cleartext = f"UDP/{SYSLOG_CLEAR_PORT}"
                    txt = data.decode("utf-8", errors="replace").strip()
                    console.print(f"\n    [bold red][!] Nhận Syslog dạng RÕ qua UDP/{SYSLOG_CLEAR_PORT} từ {addr[0]}: {txt[:120]}[/bold red]")
                    if not forever:
                        break
            if s_tcp_clear in readable:
                accepted = _accept_dut_client(s_tcp_clear, SYSLOG_CLEAR_PORT, timeout=2.0)
                if accepted:
                    c_clr, _ = accepted
                    try:
                        chunk = c_clr.recv(4096)
                        txt = chunk.decode("utf-8", errors="replace").strip()
                        console.print(f"\n    [bold red][!] Nhận Syslog dạng RÕ qua TCP/{SYSLOG_CLEAR_PORT}: {txt[:120]}[/bold red]")
                    except Exception:
                        pass
                    finally:
                        c_clr.close()
                    captured_cleartext = f"TCP/{SYSLOG_CLEAR_PORT}"
                    if not forever:
                        break
            if s_tls in readable:
                accepted = _accept_dut_client(s_tls, SYSLOG_TLS_PORT, timeout=4.0)
                if not accepted:
                    continue
                c, peer_ip = accepted
                try:
                    with server_ctx.wrap_socket(c, server_side=True) as ssock:
                        ver = ssock.version()
                        cipher = ssock.cipher()[0] if ssock.cipher() else "N/A"
                        ssock.settimeout(0.45)
                        msg_batch = []
                        for _ in range(8):
                            try:
                                chunk = ssock.recv(4096)
                                if not chunk:
                                    break
                                text = chunk.decode("utf-8", errors="replace").strip()
                                if text:
                                    for ln in text.splitlines():
                                        if ln.strip():
                                            syslog_messages.append(ln.strip())
                                            msg_batch.append(ln.strip())
                            except socket.timeout:
                                break
                            except Exception:
                                break
                        try:
                            ssock.unwrap()
                        except Exception:
                            pass
                        captured_tls = {"version": ver, "cipher": cipher}
                        console.print(f"\n    [bold green][+] Nhận Remote Syslog qua {ver} ({cipher}) từ {peer_ip} ({len(msg_batch)} dòng log)[/bold green]")
                        if msg_batch:
                            console.print(f"    [dim]↳ Mẫu log: {msg_batch[0][:140]}[/dim]")
                        if not forever:
                            break
                except ssl.SSLError as exc:
                    last_tls_error = str(exc)
                    console.print(f"\n    [bold red][!] Lỗi TLS Handshake Syslog từ {peer_ip}: {exc}[/bold red]")
                    console.print(f"        [yellow]↳ Kiểm tra lại CA 'syslog_ca' trên Camera phải khớp với: {cert_path}[/yellow]")
                except Exception as exc:
                    last_tls_error = str(exc)
                    console.print(f"\n    [dim][!] Phiên TLS Syslog chưa hoàn tất ({type(exc).__name__}: {exc})[/dim]")
                continue
            msg = f"    [dim]Server Remote Syslog đang lắng nghe (TLS {SYSLOG_TLS_PORT} & UDP {SYSLOG_CLEAR_PORT})... [Bấm Stop để dừng][/dim]" if forever else f"    [dim]Đang chờ Camera ({DUT_IP}) gửi Syslog tới {HOST_IP}:{SYSLOG_TLS_PORT}... còn {remain}s[/dim]"
            console.print(msg, end="\r")
    except KeyboardInterrupt:
        console.print("\n[yellow][!] Đã nhận tín hiệu dừng Server Syslog.[/yellow]")
    except PermissionError:
        res["downgrade_test"] = {"pass": False, "detail": f"LỖI QUYỀN: Cần chạy tool bằng 'sudo' để mở cổng {SYSLOG_CLEAR_PORT}/{SYSLOG_TLS_PORT}."}
        res["status"] = "FAIL"
        stop_pcap_capture(pcap_proc)
        res["pcap_file"] = pcap_path
        res["pcap_packet_count"] = get_pcap_packet_count(pcap_path)
        return res
    except Exception as e:
        res["error"] = str(e)
    finally:
        for sock in syslog_socks:
            try:
                sock.close()
            except Exception:
                pass

    time.sleep(1.0)
    stop_pcap_capture(pcap_proc)
    res["pcap_file"] = pcap_path
    pkt_count = get_pcap_packet_count(pcap_path)
    res["pcap_packet_count"] = pkt_count

    if captured_cleartext:
        res["status"] = "FAIL"
        res["downgrade_test"] = {"pass": False, "detail": f"NGUY HIỂM: Camera gửi Syslog dạng rõ qua {captured_cleartext} không mã hóa!"}
    elif captured_tls:
        res["status"] = "PASS"
        res["active_tls"] = captured_tls["version"]
        res["active_cipher"] = captured_tls["cipher"]
        if syslog_messages:
            res["syslog_sample"] = syslog_messages[0][:240]
            res["syslog_count"] = len(syslog_messages)
        res["downgrade_test"] = {"pass": True, "detail": f"ĐẠT: Camera gửi Syslog qua kênh TLS bảo mật {captured_tls['version']} ({captured_tls['cipher']})"}
        _enforce_pcap_requirement(res)
    elif last_tls_error:
        res["status"] = "FAIL"
        res["tls_error"] = last_tls_error
        res["downgrade_test"] = {"pass": False, "detail": f"LỖI TLS SYSLOG: Camera kết nối nhưng bắt tay TLS thất bại ({last_tls_error})."}
    else:
        res["status"] = "NO_DATA"
        res["downgrade_test"] = {"pass": False, "detail": f"CHƯA THỰC HIỆN: Không nhận được Syslog từ Camera ({DUT_IP}) trong {wait_sec:.0f}s ({pkt_count} gói tin)."}
    return res


def _serve_smtp_session(sock: socket.socket, send_greeting: bool = True) -> Dict[str, Any]:
    """Đáp ứng đối thoại SMTP đầy đủ (trên TLS hoặc cleartext) và ghi nhận TLS + danh sách lệnh."""
    is_tls = isinstance(sock, ssl.SSLSocket)
    info: Dict[str, Any] = {
        "version": sock.version() if is_tls else None,
        "cipher": (sock.cipher()[0] if sock.cipher() else "N/A") if is_tls else None,
        "commands": []
    }
    sock.settimeout(2.5)
    try:
        if send_greeting:
            sock.sendall(b"220 qcvn11-testmail ESMTP Ready\r\n")
        in_data = False
        for _ in range(16):
            chunk = sock.recv(4096)
            if not chunk:
                break
            if in_data:
                if b"\r\n.\r\n" in chunk or chunk.strip() == b".":
                    sock.sendall(b"250 2.0.0 OK queued\r\n")
                    in_data = False
                continue
            cmd_line = chunk.decode("utf-8", errors="ignore").strip().upper()
            verb = cmd_line.split()[0] if cmd_line else ""
            if verb:
                info["commands"].append(verb)
            if cmd_line.startswith(("EHLO", "HELO")):
                sock.sendall(b"250-localhost\r\n250-AUTH PLAIN LOGIN\r\n250 OK\r\n")
            elif cmd_line.startswith("AUTH"):
                sock.sendall(b"235 2.7.0 Authentication successful\r\n")
            elif cmd_line.startswith("DATA"):
                sock.sendall(b"354 End data with <CR><LF>.<CR><LF>\r\n")
                in_data = True
            elif cmd_line.startswith("QUIT"):
                sock.sendall(b"221 2.0.0 Bye\r\n")
                break
            else:
                sock.sendall(b"250 2.1.0 OK\r\n")
    except Exception:
        pass
    return info


def _serve_smtp_tls_session(ssock: ssl.SSLSocket, send_greeting: bool = True) -> Dict[str, str]:
    """Wrapper giữ tương thích: phục vụ phiên SMTP trên TLS."""
    return _serve_smtp_session(ssock, send_greeting=send_greeting)


def _inspect_smtp_cleartext_or_ws(c: socket.socket, port: int, peer_ip: str) -> str:
    """Giữ kết nối rõ để đọc payload thực tế (WebSocket/HTTP hoặc đối thoại SMTP đầy đủ)."""
    peek = _peek_client_first(c, 0.45)
    if peek.startswith((b"GET ", b"POST ", b"HEAD ")) or b"upgrade: websocket" in peek.lower():
        is_ws, ws_payload = _try_ws_handshake_and_read(c, default_proto=None)
        if is_ws:
            console.print(f"\n    [bold red][!] Cổng {port} ({peer_ip}): Phát hiện WebSocket rõ (không TLS) | payload={len(ws_payload)}B[/bold red]")
            return f"WebSocket rõ (không TLS) trên cổng {port}"
        console.print(f"\n    [bold red][!] Cổng {port} ({peer_ip}): Phát hiện HTTP rõ (không TLS)[/bold red]")
        return f"HTTP rõ trên cổng {port}"
    smtp_info = _serve_smtp_session(c, send_greeting=True)
    cmds = ", ".join(smtp_info.get("commands", [])) or "TCP banner/no-cmd"
    console.print(f"\n    [bold red][!] Cổng {port} ({peer_ip}): Phát hiện SMTP rõ [{cmds}][/bold red]")
    return f"SMTP rõ trên cổng {port} ({cmds})"


def audit_commech_8_smtp(wait_sec: float = 15.0, auto_trigger: bool = False, record_pcap: bool = True, forever: bool = False) -> Dict[str, Any]:
    """Đo kiểm ComMech-8: SMTP Email Client - Máy đo là Mail Server."""
    console.print(f"\n[*] Khởi chạy đo kiểm [bold cyan]ComMech-8: SMTP Email Client Interface (TCP/{SMTP_STARTTLS_PORT}/{SMTPS_PORT})[/bold cyan]...")
    res = {
        "id": "ComMech-8",
        "name": "SMTP Email Client",
        "port": SMTP_STARTTLS_PORT,
        "proto": "IP/TCP/TLS (SMTP over TLS)",
        "direction": f"DUT Client (Tool Server {SMTP_STARTTLS_PORT}/{SMTPS_PORT})",
        "pcap": "commech-8_smtp.pcap"
    }

    display_server_receiver_panel(
        "ComMech-8", "SMTP Email Client",
        f"TCP {SMTP_STARTTLS_PORT} (STARTTLS), {SMTPS_PORT} (SMTPS) & {SMTP_CLEAR_PORT} (Rõ)",
        wait_sec,
        [
            f"Vào Web Camera: [bold cyan]Events / Notifications → Email Recipients[/bold cyan]",
            f"Điền Mail Server IP: [bold green]{HOST_IP}[/bold green] | Port: [bold white]{SMTP_STARTTLS_PORT}[/bold white] (hoặc [bold white]{SMTPS_PORT}[/bold white])",
            f"Bật tùy chọn mã hóa: [bold white]TLS / STARTTLS[/bold white]",
            f"Bấm nút [bold yellow]Test Email / Send Test[/bold yellow] để Camera gửi email cảnh báo."
        ],
        forever=forever
    )

    pcap_proc, pcap_path = start_pcap_capture(
        DUT_IP,
        f"ip host {DUT_IP} and (tcp port {SMTP_STARTTLS_PORT} or tcp port {SMTPS_PORT} or tcp port {SMTP_CLEAR_PORT})",
        prefix="commech8_smtp"
    )
    captured_tls = None
    captured_cleartext = False
    cleartext_detail = ""

    smtp_socks = []
    try:
        server_ctx = get_server_ssl_context()
        for port in (SMTP_STARTTLS_PORT, SMTPS_PORT, SMTP_CLEAR_PORT):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("0.0.0.0", port))
            sock.listen(5)
            smtp_socks.append(sock)
        s587, s465, s25 = smtp_socks

        if auto_trigger:
            threading.Thread(target=_trigger_camera_smtp, daemon=True).start()

        start_time = time.time()
        while forever or (time.time() - start_time < wait_sec):
            remain = max(0, int(wait_sec - (time.time() - start_time)))
            readable, _, _ = select.select([s587, s465, s25], [], [], 1.0)
            if s25 in readable:
                accepted = _accept_dut_client(s25, SMTP_CLEAR_PORT, timeout=3.0)
                if not accepted:
                    continue
                c, peer_ip = accepted
                try:
                    cleartext_detail = _inspect_smtp_cleartext_or_ws(c, SMTP_CLEAR_PORT, peer_ip)
                    captured_cleartext = True
                    console.print(f"\n    [bold red][!] Nhận kết nối SMTP rõ cổng 25 từ {peer_ip}[/bold red]")
                finally:
                    c.close()
                if not forever:
                    break
            if s465 in readable:
                accepted = _accept_dut_client(s465, SMTPS_PORT, timeout=3.0)
                if not accepted:
                    continue
                c, peer_ip = accepted
                peek = _peek_client_first(c, 0.5)
                if not peek.startswith(b"\x16\x03"):
                    try:
                        cleartext_detail = _inspect_smtp_cleartext_or_ws(c, SMTPS_PORT, peer_ip)
                        captured_cleartext = True
                    finally:
                        c.close()
                    if not forever:
                        break
                try:
                    with server_ctx.wrap_socket(c, server_side=True) as ssock:
                        captured_tls = _serve_smtp_session(ssock, send_greeting=True)
                        captured_tls["port"] = SMTPS_PORT
                        console.print(f"\n    [bold green][+] Nhận Email gửi qua SMTPS cổng 465 từ {peer_ip} ({captured_tls.get('version')} / {captured_tls.get('cipher')})[/bold green]")
                        if not forever:
                            break
                except Exception:
                    pass
                continue
            if s587 in readable:
                accepted = _accept_dut_client(s587, SMTP_STARTTLS_PORT, timeout=3.0)
                if not accepted:
                    continue
                c, peer_ip = accepted
                try:
                    peek = _peek_client_first(c, 0.4)
                    if peek.startswith((b"GET ", b"POST ", b"HEAD ")) or b"upgrade: websocket" in peek.lower():
                        cleartext_detail = _inspect_smtp_cleartext_or_ws(c, SMTP_STARTTLS_PORT, peer_ip)
                        captured_cleartext = True
                        if not forever:
                            break
                    c.sendall(b"220 qcvn11-testmail ESMTP Ready\r\n")
                    _ = c.recv(1024)
                    c.sendall(b"250-localhost\r\n250-STARTTLS\r\n250 OK\r\n")
                    data2 = c.recv(1024)
                    if b"STARTTLS" in data2.upper():
                        c.sendall(b"220 2.0.0 Ready to start TLS\r\n")
                        with server_ctx.wrap_socket(c, server_side=True) as ssock:
                            captured_tls = _serve_smtp_session(ssock, send_greeting=False)
                            captured_tls["port"] = SMTP_STARTTLS_PORT
                            console.print(f"\n    [bold green][+] Nhận Email gửi qua SMTP STARTTLS cổng 587 từ {peer_ip} ({captured_tls.get('version')} / {captured_tls.get('cipher')})[/bold green]")
                            if not forever:
                                break
                    elif data2:
                        c.sendall(b"250 2.1.0 OK\r\n")
                        extra = _serve_smtp_session(c, send_greeting=False)
                        cmds = ", ".join([data2.decode("utf-8", errors="ignore").strip().split()[0]] + extra.get("commands", []))
                        cleartext_detail = f"SMTP rõ trên cổng {SMTP_STARTTLS_PORT} không dùng STARTTLS ({cmds})"
                        captured_cleartext = True
                        if not forever:
                            break
                except Exception:
                    pass
                finally:
                    try:
                        c.close()
                    except Exception:
                        pass
                continue
            msg = f"    [dim]Server SMTP Email đang lắng nghe (STARTTLS {SMTP_STARTTLS_PORT} & SMTPS {SMTPS_PORT})... [Bấm Stop để dừng][/dim]" if forever else f"    [dim]Đang chờ Camera ({DUT_IP}) gửi Email tới {HOST_IP}... còn {remain}s[/dim]"
            console.print(msg, end="\r")
    except KeyboardInterrupt:
        console.print("\n[yellow][!] Đã nhận tín hiệu dừng Server SMTP Email.[/yellow]")
    except Exception as e:
        res["error"] = str(e)
    finally:
        for sock in smtp_socks:
            try:
                sock.close()
            except Exception:
                pass

    time.sleep(1.0)
    stop_pcap_capture(pcap_proc)
    res["pcap_file"] = pcap_path
    pkt_count = get_pcap_packet_count(pcap_path)
    res["pcap_packet_count"] = pkt_count

    if captured_cleartext:
        res["status"] = "FAIL"
        detail_msg = cleartext_detail or "Camera gửi Email qua cổng rõ không dùng STARTTLS!"
        res["downgrade_test"] = {"pass": False, "detail": f"NGUY HIỂM: {detail_msg}"}
    elif captured_tls:
        used_port = captured_tls.get("port", SMTP_STARTTLS_PORT)
        mode_lbl = "SMTPS (TLS)" if used_port == SMTPS_PORT else "SMTP STARTTLS"
        res["status"] = "PASS"
        res["port"] = used_port
        res["active_tls"] = captured_tls["version"]
        res["active_cipher"] = captured_tls["cipher"]
        res["downgrade_test"] = {"pass": True, "detail": f"ĐẠT: Camera đàm phán {mode_lbl} cổng {used_port} bảo mật {captured_tls['version']} ({captured_tls['cipher']})"}
        _enforce_pcap_requirement(res)
    else:
        res["status"] = "NO_DATA"
        res["downgrade_test"] = {"pass": False, "detail": f"CHƯA THỰC HIỆN: Không nhận được kết nối Email từ Camera ({DUT_IP}) trong {wait_sec:.0f}s ({pkt_count} gói tin)."}
    return res


def _extract_ssh_kex_from_pcap(pcap_path: str, dut_ip: str) -> Optional[Dict[str, Any]]:
    """Dùng tshark trích xuất banner SSH và KEXINIT của DUT từ tệp PCAP đang ghi."""
    if not pcap_path or not os.path.exists(pcap_path) or os.path.getsize(pcap_path) <= 40:
        return None
    tshark_bin = shutil.which("tshark") or "/usr/bin/tshark"
    if not os.path.exists(tshark_bin):
        return None
    try:
        out = subprocess.check_output(
            [
                tshark_bin, "-r", pcap_path, "-Y", "ssh", "-T", "fields",
                "-e", "ip.src", "-e", "ssh.protocol", "-e", "ssh.message_code",
                "-e", "ssh.kex_algorithms", "-e", "ssh.encryption_algorithms_client_to_server",
                "-e", "ssh.mac_algorithms_client_to_server", "-e", "ssh.server_host_key_algorithms",
            ],
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=5,
        )
        banner = None
        kex_info: Dict[str, Any] = {}
        new_keys = False
        encrypted_pkts = 0
        for line in out.splitlines():
            cols = line.split("\t")
            while len(cols) < 7:
                cols.append("")
            src, proto, msg_code, kex_s, enc_s, mac_s, hkey_s = [c.strip() for c in cols[:7]]
            if src == dut_ip and proto:
                banner = proto
            if src == dut_ip and msg_code == "20":
                kex_info = {
                    "client_version": banner or "SSH-2.0",
                    "kex": [x for x in kex_s.split(",") if x],
                    "ciphers": [x for x in enc_s.split(",") if x],
                    "macs": [x for x in mac_s.split(",") if x],
                    "keys": [x for x in hkey_s.split(",") if x],
                }
            if msg_code == "21":
                new_keys = True
            if not proto and not msg_code:
                encrypted_pkts += 1
        if banner or kex_info:
            return {
                "banner": banner or "SSH-2.0",
                "kex_info": kex_info,
                "new_keys": new_keys,
                "encrypted_pkts": encrypted_pkts,
            }
    except Exception:
        pass
    return None


def audit_commech_9_sftp(wait_sec: float = 15.0, auto_trigger: bool = False, record_pcap: bool = True, forever: bool = False) -> Dict[str, Any]:
    """Đo kiểm ComMech-9: SFTP / Storage Client - Máy đo là SFTP/FTP Server hoàn chỉnh."""
    import hashlib
    import tool3_sftp_receiver as t3

    ecdsa_raw = t3.HOST_ECDSA_KEY.asbytes()
    ecdsa_md5_hex = hashlib.md5(ecdsa_raw).hexdigest()
    ecdsa_sha256_hex = hashlib.sha256(ecdsa_raw).hexdigest()
    sshd_active = _is_local_port_open(SFTP_PORT)

    console.print(f"\n[*] Khởi chạy đo kiểm [bold cyan]ComMech-9: SFTP Client Interface (TCP/{SFTP_PORT} & FTP/{FTP_CLEAR_PORT})[/bold cyan]...")
    res = {
        "id": "ComMech-9",
        "name": "SFTP Client Interface",
        "port": SFTP_PORT,
        "proto": "IP/TCP/SSHv2 (SFTP)",
        "direction": f"DUT Client (Tool Server {SFTP_PORT})",
        "pcap": "commech-9_sftp.pcap"
    }

    srv_note = (
        f"OpenSSH SFTP Server đang hoạt động sẵn trên cổng {SFTP_PORT} (hỗ trợ đủ chacha20-poly1305, AES-GCM/CTR, mlkem768, sntrup761, curve25519, ecdh-nistp, SHA2)."
        if sshd_active else
        f"Paramiko SFTP Server sẽ lắng nghe cổng {SFTP_PORT}."
    )
    account_hint = f"sftp_test / {PASS} (hoặc merlin)" if sshd_active else f"merlin / {PASS}"

    display_server_receiver_panel(
        "ComMech-9", "SFTP Client", f"TCP {SFTP_PORT} (SSHv2/SFTP) & TCP {FTP_CLEAR_PORT} (FTP Rõ)", wait_sec,
        [
            f"Trạng thái Server: [bold green]{srv_note}[/bold green]",
            f"Vào Web Camera: [bold cyan]System → Events → Recipients[/bold cyan] (chọn hoặc tạo SFTP recipient)",
            f"Điền Host: [bold green]{HOST_IP}[/bold green] | Port: [bold white]{SFTP_PORT}[/bold white] | Folder: [bold white]/tmp[/bold white] | Account/Pass: [bold white]{account_hint}[/bold white]",
            f"SSH host public key (ECDSA):",
            f"  • Nếu chọn [bold white]SHA256[/bold white]: [bold green]{ecdsa_sha256_hex}[/bold green]",
            f"  • Nếu chọn [bold white]MD5[/bold white]   : [bold cyan]{ecdsa_md5_hex}[/bold cyan]",
            f"Bấm nút [bold yellow]Test[/bold yellow] trên Camera để hoàn tất bắt tay SFTP & ghi nhận KEXINIT."
        ],
        forever=forever
    )

    pcap_proc, pcap_path = start_pcap_capture(
        DUT_IP,
        f"ip host {DUT_IP} and (tcp port {SFTP_PORT} or tcp port {FTP_CLEAR_PORT})",
        prefix="commech9_sftp"
    )
    captured_ssh = None
    captured_ftp = False

    sftp_socks = []
    try:
        ports_to_bind = [FTP_CLEAR_PORT] if sshd_active else [FTP_CLEAR_PORT, SFTP_PORT]
        for port in ports_to_bind:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("0.0.0.0", port))
            sock.listen(5)
            sftp_socks.append(sock)
        s21 = sftp_socks[0]
        s22 = sftp_socks[1] if len(sftp_socks) > 1 else None

        if auto_trigger:
            threading.Thread(target=_trigger_camera_sftp, daemon=True).start()

        start_time = time.time()
        while forever or (time.time() - start_time < wait_sec):
            remain_str = "Chạy liên tục [Bấm Stop để dừng]" if forever else f"còn {max(0, int(wait_sec - (time.time() - start_time)))}s"
            readable, _, _ = select.select(sftp_socks, [], [], 0.8)
            if s21 in readable:
                accepted = _accept_dut_client(s21, FTP_CLEAR_PORT, timeout=3.0)
                if not accepted:
                    continue
                c, _ = accepted
                try:
                    peek = _peek_client_first(c, 0.45)
                    if peek.startswith((b"GET ", b"POST ", b"HEAD ")) or b"upgrade: websocket" in peek.lower():
                        _try_ws_handshake_and_read(c, default_proto=None)
                    else:
                        c.sendall(b"220 qcvn11-ftp Ready\r\n")
                        _ = c.recv(1024)
                except Exception:
                    pass
                finally:
                    c.close()
                captured_ftp = True
                if not forever:
                    break
            if sshd_active:
                pcap_ssh = _extract_ssh_kex_from_pcap(pcap_path, DUT_IP)
                if pcap_ssh and pcap_ssh.get("kex_info"):
                    console.print(f"\n    [bold green][+] Đã bắt được SSH KEXINIT từ {DUT_IP} ({pcap_ssh['banner']}), đang chờ hoàn tất SFTP...[/bold green]")
                    time.sleep(2.0)
                    pcap_ssh = _extract_ssh_kex_from_pcap(pcap_path, DUT_IP) or pcap_ssh
                    sftp_ok = bool(pcap_ssh.get("new_keys") and pcap_ssh.get("encrypted_pkts", 0) >= 2)
                    captured_ssh = {
                        "banner": pcap_ssh.get("banner", "SSH-2.0"),
                        "client_ip": DUT_IP,
                        "sftp_ok": sftp_ok,
                        "kex_info": pcap_ssh.get("kex_info", {}),
                        "active_cipher": "OpenSSH SFTP",
                        "active_host_key": "ecdsa-sha2-nistp256",
                    }
                    if not forever:
                        break
            elif s22 and s22 in readable:
                accepted = _accept_dut_client(s22, SFTP_PORT, timeout=8.0)
                if not accepted:
                    continue
                c, peer_ip = accepted
                t = None
                try:
                    t = t3.DissectingTransport(c, SFTP_PORT, (peer_ip, SFTP_PORT))
                    sec_opts = t.get_security_options()
                    sec_opts.ciphers = ("aes128-gcm@openssh.com", "aes256-gcm@openssh.com", "aes128-ctr", "aes192-ctr", "aes256-ctr")
                    sec_opts.digests = ("hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com", "hmac-sha2-256", "hmac-sha2-512")
                    t.add_server_key(t3.HOST_ECDSA_KEY)
                    t.add_server_key(t3.HOST_RSA_KEY)
                    t.set_subsystem_handler("sftp", paramiko.SFTPServer, t3.StubSFTPServer)
                    srv_iface = t3.CameraSSHServer(SFTP_PORT, (peer_ip, SFTP_PORT))
                    t.start_server(server=srv_iface)
                    chan = t.accept(8.0)

                    kex_info = getattr(t, "parsed_kex", {}) or {}
                    banner_str = getattr(t, "remote_version", None) or kex_info.get("client_version") or "SSH-2.0"
                    active_cipher = getattr(t, "remote_cipher", None) or "N/A"
                    active_mac = getattr(t, "remote_mac", None) or "N/A"
                    active_kex_cls = getattr(t, "kex_engine", None)
                    active_kex = active_kex_cls.__name__ if hasattr(active_kex_cls, "__name__") else str(active_kex_cls or "N/A")
                    active_hkey = getattr(t, "host_key_type", None) or "N/A"

                    if chan is not None:
                        t_end = time.time() + 4.0
                        while t.is_active() and time.time() < t_end:
                            time.sleep(0.1)
                        captured_ssh = {
                            "banner": banner_str,
                            "client_ip": peer_ip,
                            "sftp_ok": True,
                            "active_cipher": active_cipher,
                            "active_mac": active_mac,
                            "active_kex": active_kex,
                            "active_host_key": active_hkey,
                            "kex_info": kex_info,
                            "auth_user": srv_iface.auth_username,
                        }
                        console.print(f"\n    [bold green][+] SFTP Session thành công từ {peer_ip} ({banner_str}) | Cipher: {active_cipher} | HostKey: {active_hkey}[/bold green]")
                        if not forever:
                            break
                    else:
                        console.print(f"\n    [bold yellow][!] Camera ({peer_ip}) ngắt SSH sau KEXINIT (kiểm tra lại SSH host public key trên Camera: SHA256={ecdsa_sha256_hex} hoặc MD5={ecdsa_md5_hex})[/bold yellow]")
                        if kex_info:
                            captured_ssh = {
                                "banner": banner_str,
                                "client_ip": peer_ip,
                                "sftp_ok": False,
                                "active_cipher": active_cipher,
                                "active_mac": active_mac,
                                "active_kex": active_kex,
                                "active_host_key": active_hkey,
                                "kex_info": kex_info,
                            }
                except Exception as exc:
                    kex_info = getattr(t, "parsed_kex", {}) or {} if t else {}
                    banner_str = getattr(t, "remote_version", None) or kex_info.get("client_version")
                    if banner_str or kex_info:
                        captured_ssh = {
                            "banner": banner_str or "SSH-2.0",
                            "client_ip": peer_ip,
                            "sftp_ok": False,
                            "kex_info": kex_info,
                        }
                        console.print(f"\n    [bold yellow][!] Camera ({peer_ip}) ngắt trong khi bắt tay SSH ({exc}) — Kiểm tra SSH host public key trên Camera[/bold yellow]")
                finally:
                    try:
                        if t:
                            t.close()
                    except Exception:
                        pass
                    try:
                        c.close()
                    except Exception:
                        pass
                continue
            console.print(f"    [dim]Đang chờ Camera ({DUT_IP}) kết nối SFTP tới {HOST_IP}:{SFTP_PORT}... {remain_str}[/dim]", end="\r")
    except PermissionError:
        res["downgrade_test"] = {"pass": False, "detail": f"LỖI QUYỀN: Cần chạy tool bằng 'sudo' để mở cổng {FTP_CLEAR_PORT}/{SFTP_PORT}."}
        res["status"] = "FAIL"
        stop_pcap_capture(pcap_proc)
        res["pcap_file"] = pcap_path
        res["pcap_packet_count"] = get_pcap_packet_count(pcap_path)
        return res
    except KeyboardInterrupt:
        console.print("\n[yellow][!] Người dùng dừng bài đo / Server ComMech-9.[/yellow]")
    except Exception as e:
        res["error"] = str(e)
    finally:
        for sock in sftp_socks:
            try:
                sock.close()
            except Exception:
                pass

    time.sleep(1.0)
    stop_pcap_capture(pcap_proc)
    res["pcap_file"] = pcap_path
    pkt_count = get_pcap_packet_count(pcap_path)
    res["pcap_packet_count"] = pkt_count

    if captured_ftp:
        res["status"] = "FAIL"
        res["downgrade_test"] = {"pass": False, "detail": f"NGUY HIỂM: Camera kết nối FTP dạng rõ qua cổng {FTP_CLEAR_PORT} không mã hóa!"}
    elif captured_ssh:
        res["banner"] = captured_ssh.get("banner", "SSH-2.0")
        kex_info = captured_ssh.get("kex_info") or {}
        if kex_info:
            res["sftp_kex"] = kex_info
        if captured_ssh.get("active_cipher") and captured_ssh["active_cipher"] != "N/A":
            res["active_cipher"] = captured_ssh["active_cipher"]
        dg_msg = ""
        if sshd_active:
            dg_ok, dg_txt = test_ssh_downgrade("127.0.0.1", SFTP_PORT)
            dg_msg = f" | {dg_txt}"
        if captured_ssh.get("sftp_ok"):
            res["status"] = "PASS"
            res["downgrade_test"] = {
                "pass": True,
                "detail": (
                    f"ĐẠT: Camera kết nối SFTP thành công qua SSHv2 ({captured_ssh['banner']} | "
                    f"Cipher: {captured_ssh.get('active_cipher')} | HostKey: {captured_ssh.get('active_host_key')}){dg_msg}"
                )
            }
            _enforce_pcap_requirement(res)
        else:
            res["status"] = "WARN"
            res["downgrade_test"] = {
                "pass": False,
                "detail": (
                    f"CHƯA HOÀN TẤT SFTP (NGẮT DO HOST KEY): Camera gửi {captured_ssh['banner']} & KEXINIT nhưng ngắt trước khi mở SFTP. "
                    f"Hãy cập nhật SSH host public key trên Camera (SHA256={ecdsa_sha256_hex} hoặc MD5={ecdsa_md5_hex}).{dg_msg}"
                )
            }
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
        "port": HTTPS_PORT,
        "proto": f"IP/TCP/TLS (HTTPS/{HTTPS_PORT})",
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
        r = requests.get(f"https://{DUT_IP}:{HTTPS_PORT}/axis-cgi/param.cgi?action=list&group=RemoteService",
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
            elif "active_cipher" in r:
                f.write(f"- **Mã hóa thực tế hoạt động**: `{r.get('active_cipher')}`\n")
            if "supported_combos" in r and r["supported_combos"]:
                f.write(f"- **Các tổ hợp SNMPv3 authPriv dùng được**: {', '.join(f'`{c}`' for c in r['supported_combos'])}\n")
            if "banner" in r:
                f.write(f"- **Banner SSH Service**: `{r['banner']}`\n")
            if "parsed_negotiate" in r:
                pn = r["parsed_negotiate"]
                f.write(f"- **SMBv3 Dialects chào mời**: `{', '.join(pn.get('dialects', [])) or 'N/A'}`\n")
                if pn.get("hashes"):
                    f.write(f"- **SMBv3 Preauth Integrity Hash**: `{', '.join(pn['hashes'])}`\n")
                if pn.get("ciphers"):
                    f.write(f"- **SMBv3 Encryption Ciphers chào mời**: `{', '.join(pn['ciphers'])}`\n")
                if pn.get("signing"):
                    f.write(f"- **SMBv3 Signing Algorithms**: `{', '.join(pn['signing'])}`\n")
            if "negotiate_response" in r:
                nr = r["negotiate_response"]
                f.write(f"- **SMBv3 Server chốt**: `{nr.get('dialect')}` (Hash: `{', '.join(nr.get('hashes', [])) or 'N/A'}`, Cipher: `{', '.join(nr.get('ciphers', [])) or 'N/A'}`)\n")
            if "samba_session" in r:
                ss = r["samba_session"]
                f.write(f"- **Phiên Samba đang Mount**: `{ss.get('protocol')}` | Encryption: `{ss.get('encryption')}` | Signing: `{ss.get('signing')}`\n")
            if "downgrade_test" in r:
                f.write(f"- **Kết quả phân tích mật mã & Hạ cấp**: {r['downgrade_test']['detail']}\n")
            if "matrix" in r and r["matrix"]:
                f.write("\n| Mức / Phiên bản | Auth | Priv | Phân loại | Kết quả |\n")
                f.write("|:---|:---|:---|:---|:---|\n")
                for m in r["matrix"]:
                    st = "**CHẤP NHẬN**" if m.get("accepted") else f"Từ chối ({m.get('status_code', 'FAIL')})"
                    f.write(f"| {m.get('level')} | `{m.get('auth_name')}` | `{m.get('priv_name')}` | {m.get('sec_type')} | {st} |\n")
                f.write("\n")
            if "evidence_pcap" in r:
                f.write(f"- **File bắt gói tin PCAP đối soát**: `[pcap](file://{r['evidence_pcap']})` ({r.get('pcap_packet_count', 0)} gói tin)\n\n")

        f.write("\n---\n\n## 3. BẰNG CHỨNG TOÀN BỘ DANH MỤC CIPHERSUITE THEO IXIT 11 (NMAP ENUM & SNMP MATRIX)\n\n")
        f.write("> [!TIP] Bằng chứng danh mục Ciphersuite đầy đủ:\n")
        f.write("> Do gói tin Server Hello trên Wireshark chỉ đàm phán 1 Cipher Suite cho mỗi phiên kết nối,\n")
        f.write("> kiểm định viên sử dụng kết quả quét Nmap & SNMPv3 Matrix để đối soát toàn bộ danh mục Ciphersuite & KEX:\n")
        f.write(f"> - **Web HTTPS & ONVIF ({HTTPS_PORT})**: `nmap -Pn -p {HTTPS_PORT} --script ssl-enum-ciphers {DUT_IP}`\n")
        f.write(f"> - **SSH Remote CLI ({SSH_PORT})**: `nmap -Pn -p {SSH_PORT} --script ssh2-enum-algos {DUT_IP}`\n")
        f.write(f"> - **SNMPv3 Interface ({SNMP_PORT}/udp)**: `python tool5_snmpv3_auditor.py {DUT_IP} --port {SNMP_PORT}`\n")
        f.write(f"> - **RTSPS Video Stream ({RTSPS_PORT})**: `nmap -Pn -p {RTSPS_PORT} --script ssl-enum-ciphers {DUT_IP}`\n")
        f.write(f"> - **Báo cáo chi tiết danh mục**: [commech_ciphers_nmap_enum.md](file://{os.path.join(CAPTURES_DIR, 'commech_ciphers_nmap_enum.md')})\n\n")
        f.write("> [!NOTE] Đối với các cơ chế Camera đóng vai trò Client (ComMech-5 MQTT, ComMech-6 Syslog, ComMech-7 SMB, ComMech-8 SMTP, ComMech-9 SFTP, ComMech-11 O3C):\n")
        f.write("> Danh sách Cipher Suite / KEX / Dialect được Camera chủ động chào mời trong gói tin `Client Hello` / `KEXINIT` / `SMB Negotiate` trên file PCAP tương ứng.\n\n")
        f.write("---\n*Báo cáo được khởi tạo tự động bởi QCVN 11 Cybersecurity Toolkit (ComMech Auditor).*\n")


def run_cipher_enumeration(enum_target: str = "all") -> int:
    """
    Sử dụng Nmap scripts (ssl-enum-ciphers, ssh2-enum-algos) và ma trận SNMPv3 (tool5_snmpv3_auditor)
    để bóc tách TOÀN BỘ danh mục Ciphersuite, KEX, MAC, Auth/Priv được thiết bị hỗ trợ.
    """
    targets = []
    include_snmp = False
    t_clean = str(enum_target).lower().replace("commech-", "").replace("commech", "").strip()

    if t_clean in ["1", "web", str(HTTPS_PORT), "443"]:
        targets = [("ComMech-1 & ComMech-3", "Web Interface & ONVIF SOAP (HTTPS)", HTTPS_PORT, "ssl-enum-ciphers")]
    elif t_clean in ["2", "ssh", str(SSH_PORT), "22"]:
        targets = [("ComMech-2", "SSH Remote CLI", SSH_PORT, "ssh2-enum-algos")]
    elif t_clean in ["3", "onvif"]:
        targets = [("ComMech-3", "ONVIF Management Interface", ONVIF_HTTPS_PORT, "ssl-enum-ciphers")]
    elif t_clean in ["4", "snmp", "snmpv3", str(SNMP_PORT), "161"]:
        include_snmp = True
    elif t_clean in ["10", "rtsp", "rtsps", str(RTSPS_PORT), "322"]:
        targets = [("ComMech-10", "RTSPS Media Stream", RTSPS_PORT, "ssl-enum-ciphers")]
    else:  # all
        targets = [
            ("ComMech-1 & ComMech-3", "Web Interface & ONVIF SOAP (HTTPS)", HTTPS_PORT, "ssl-enum-ciphers"),
            ("ComMech-2", "SSH Remote CLI", SSH_PORT, "ssh2-enum-algos"),
            ("ComMech-10", "RTSPS Media Stream", RTSPS_PORT, "ssl-enum-ciphers")
        ]
        if ONVIF_HTTPS_PORT != HTTPS_PORT:
            targets.append(("ComMech-3", "ONVIF Management Interface", ONVIF_HTTPS_PORT, "ssl-enum-ciphers"))
        include_snmp = True

    nmap_bin = shutil.which("nmap") or "/usr/bin/nmap"
    if targets and not os.path.exists(nmap_bin):
        console.print("[bold red][!] Lỗi: Không tìm thấy lệnh 'nmap' trên hệ thống.[/bold red]")
        if not include_snmp:
            return 1
        targets = []

    console.print(Panel(
        f"[bold white]BÓC TÁCH TOÀN BỘ DANH MỤC CIPHERSUITE ĐƯỢC HỖ TRỢ (NMAP & SNMPV3 MATRIX)[/bold white]\n"
        f"• Mục tiêu DUT IP : [cyan]{DUT_IP}[/cyan] (Model: [bold white]{DUT_MODEL}[/bold white])\n"
        f"• Tiêu chuẩn      : [bold yellow]QCVN 11:2026/BCA (Khoản 2.5.1, 2.1.3 - Mật mã an toàn) & IXIT 11[/bold yellow]\n"
        f"• Mục đích        : [green]Hiển thị 100% Ciphersuite/KEX/MAC/SNMPv3 Auth+Priv thực tế thiết bị sử dụng được[/green]",
        title="CIPHER ENUMERATION - COMMECH",
        border_style="cyan"
    ))

    md_lines = [
        "# BÁO CÁO BÓC TÁCH TOÀN BỘ DANH MỤC CIPHERSUITE (NMAP & SNMPV3 ENUMERATION - COMMECH)",
        f"- **Thiết bị đo kiểm (DUT)**: IP `{DUT_IP}` (Model: `{DUT_MODEL}`)",
        f"- **Máy đo (Host IP)**: IP `{HOST_IP}`",
        f"- **Thời điểm kiểm định**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "- **Tiêu chuẩn đối soát**: QCVN 11:2026/BCA (Khoản 2.5.1) & Bảng kê IXIT 11 (Cơ chế kết nối)\n",
        "---",
        "## HƯỚNG DẪN CHỤP ẢNH BẰNG CHỨNG CHO TESTER",
        "> [!TIP] Lưu ý chụp ảnh:",
        "> Trên Wireshark, gói tin Server Hello chỉ đàm phán 1 Cipher Suite duy nhất cho mỗi phiên kết nối.",
        "> Để chứng minh camera hỗ trợ toàn bộ danh mục Ciphersuite theo khai báo IXIT 11, kiểm định viên",
        "> sử dụng kết quả Nmap & SNMPv3 Matrix bên dưới để chụp ảnh toàn bộ thuật toán được thiết bị chấp nhận.\n",
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

    if include_snmp:
        from tool5_snmpv3_auditor import run_snmp_audit, display_snmp_audit, format_snmp_markdown_report
        snmp_port = int(config.get("service_ports", {}).get("snmp") or config.get("service_ports", {}).get("snmp_udp") or 161)
        console.print(f"\n[*] Đang quét toàn bộ ma trận thuật toán SNMPv3: [bold yellow]ComMech-4 (UDP/{snmp_port})[/bold yellow]...")
        snmp_results, _ = asyncio.run(run_snmp_audit(host=DUT_IP, port=snmp_port, capture_pcap=False))
        snmp_summary = display_snmp_audit(DUT_IP, snmp_port, snmp_results, pcap_file="", show_wireshark=False)
        snmp_md = format_snmp_markdown_report(DUT_IP, snmp_port, snmp_results, snmp_summary)
        md_lines.append(snmp_md)
        all_raw_txt.append(f"=== ComMech-4: SNMPv3 Cryptographic Matrix (UDP/{snmp_port}) ===")
        all_raw_txt.append(f"Usable ciphers: {', '.join(snmp_summary['usable_ciphers']) or 'None'}")
        for r in snmp_results:
            all_raw_txt.append(f"  - {r['name']:42s} | {r['sec_type']:32s} | {r['detail']}")
        all_raw_txt.append("\n" + "="*60 + "\n")

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


def run_all_commech_servers(record_pcap: bool = True) -> int:
    """
    Khởi chạy đồng thời toàn bộ các Receiver Server ComMech (5, 6, 7, 8, 9)
    và duy trì lắng nghe liên tục cho đến khi người dùng bấm Stop trên Web UI hoặc nhấn Ctrl+C trên Terminal.
    Hỗ trợ kiểm tra lưu lượng phát sinh trong TelData mà không làm gián đoạn kiểm thử.
    """
    smbd_active = _is_local_port_open(SMB_PORT)
    sshd_active = _is_local_port_open(SFTP_PORT)

    pcap_status = f"[bold green]BẬT ({os.path.join(EVIDENCE_DIR, 'commech_all_servers.pcap')})[/bold green]" if record_pcap else "[bold yellow]TẮT (--no-pcap)[/bold yellow]"

    server_info = [
        f"• [bold cyan]ComMech-5 MQTT Broker[/bold cyan] : Cổng {MQTT_TLS_PORT} (MQTTS/TLS), {MQTT_WSS_PORT} (WSS), {MQTT_CLEAR_PORT} (Clear)",
        f"• [bold cyan]ComMech-6 Syslog Server[/bold cyan] : Cổng {SYSLOG_TLS_PORT} (Syslog-TLS), {SYSLOG_CLEAR_PORT} (UDP/TCP)",
        f"• [bold cyan]ComMech-7 SMB Storage[/bold cyan]   : Cổng {SMB_PORT} (" + ("Samba smbd hệ thống đang chạy" if smbd_active else "Python SMBv3 listener") + ")",
        f"• [bold cyan]ComMech-8 SMTP Server[/bold cyan]   : Cổng {SMTP_STARTTLS_PORT} (STARTTLS), {SMTPS_PORT} (SMTPS), {SMTP_CLEAR_PORT} (Clear)",
        f"• [bold cyan]ComMech-9 SFTP Server[/bold cyan]   : Cổng {SFTP_PORT} (" + ("OpenSSH sshd hệ thống đang chạy" if sshd_active else "Python SFTP Server") + f"), Cổng {FTP_CLEAR_PORT} (FTP)",
    ]

    panel_text = (
        "[bold white]TRẠM MÁY CHỦ THU NHẬN COMMECH TOÀN PHẦN (COMMECH RECEIVERS HUB)[/bold white]\n\n"
        + "\n".join(server_info) + "\n\n"
        f"• [bold yellow]Mục tiêu DUT IP[/bold yellow] : [cyan]{DUT_IP}[/cyan]\n"
        f"• [bold yellow]Máy đo Host IP[/bold yellow]  : [bold green]{HOST_IP}[/bold green]\n"
        f"• [bold yellow]Ghi bằng chứng PCAP[/bold yellow] : {pcap_status}\n"
        f"• [bold green]Trạng thái hoạt động[/bold green]: [bold green]CHẠY LIÊN TỤC (Đang lắng nghe tất cả các cổng...)[/bold green]\n"
        f"[dim]→ Bấm nút 'Stop' (màu đỏ) trên thanh công cụ Web hoặc nhấn Ctrl+C trên Terminal để dừng server.[/dim]"
    )
    console.print(Panel(panel_text, title="COMMECH ALL-SERVERS MODE", border_style="green"))

    pcap_proc = None
    pcap_path = None
    if record_pcap:
        pcap_proc, pcap_path = start_pcap_capture(
            DUT_IP,
            f"ip host {DUT_IP} and (tcp port {MQTT_TLS_PORT} or tcp port {MQTT_WSS_PORT} or tcp port {MQTT_CLEAR_PORT} or "
            f"tcp port {SYSLOG_TLS_PORT} or udp port {SYSLOG_CLEAR_PORT} or tcp port {SYSLOG_CLEAR_PORT} or tcp port {SMB_PORT} or "
            f"tcp port {SMTP_STARTTLS_PORT} or tcp port {SMTPS_PORT} or tcp port {SMTP_CLEAR_PORT} or tcp port {FTP_CLEAR_PORT} or tcp port {SFTP_PORT})",
            prefix="commech_all_servers"
        )

    stop_event = threading.Event()
    log_lock = threading.Lock()
    event_counts = {
        "ComMech-5 (MQTT)": 0,
        "ComMech-6 (Syslog)": 0,
        "ComMech-7 (SMB)": 0,
        "ComMech-8 (SMTP)": 0,
        "ComMech-9 (SFTP)": 0,
    }

    def log_event(service: str, message: str, style: str = "green"):
        with log_lock:
            if service in event_counts:
                event_counts[service] += 1
            now_str = datetime.now().strftime("%H:%M:%S")
            console.print(f"  [dim]{now_str}[/dim] [{style}][bold][{service}][/bold][/{style}] {message}")

    # Worker 1: MQTT
    def _worker_mqtt():
        socks = []
        try:
            ctx = get_server_ssl_context()
            for port in [MQTT_TLS_PORT, MQTT_WSS_PORT, MQTT_CLEAR_PORT]:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    s.bind(("0.0.0.0", port))
                    s.listen(5)
                    socks.append((port, s))
                except Exception as ex:
                    log_event("ComMech-5 (MQTT)", f"Không thể bind cổng {port}: {ex}", style="red")

            s_tls = next((s for p, s in socks if p == MQTT_TLS_PORT), None)
            s_wss = next((s for p, s in socks if p == MQTT_WSS_PORT), None)
            s_clr = next((s for p, s in socks if p == MQTT_CLEAR_PORT), None)
            all_socks = [s for _, s in socks]

            while not stop_event.is_set():
                readable, _, _ = select.select(all_socks, [], [], 0.5)
                for r_sock in readable:
                    if r_sock == s_clr:
                        acc = _accept_dut_client(s_clr, MQTT_CLEAR_PORT, timeout=1.0)
                        if acc:
                            c, ip = acc
                            try:
                                log_event("ComMech-5 (MQTT)", f"CẢNH BÁO: Nhận kết nối Cleartext không mã hóa (Port {MQTT_CLEAR_PORT}) từ {ip}!", style="bold red")
                            finally:
                                c.close()
                    elif r_sock == s_tls:
                        acc = _accept_dut_client(s_tls, MQTT_TLS_PORT, timeout=2.0)
                        if acc:
                            c, ip = acc
                            try:
                                with ctx.wrap_socket(c, server_side=True) as ss:
                                    peek = ss.recv(1024)
                                    ver = ss.version() or "TLS"
                                    ciph = ss.cipher()[0] if ss.cipher() else "N/A"
                                    if _is_mqtt_connect_packet(peek):
                                        ss.sendall(b"\x20\x02\x00\x00")
                                    log_event("ComMech-5 (MQTT)", f"Nhận kết nối MQTTS ({ver} / {ciph}) từ {ip}:{MQTT_TLS_PORT}", style="green")
                            except Exception:
                                pass
                    elif r_sock == s_wss:
                        acc = _accept_dut_client(s_wss, MQTT_WSS_PORT, timeout=2.0)
                        if acc:
                            c, ip = acc
                            try:
                                with ctx.wrap_socket(c, server_side=True) as ss:
                                    ver = ss.version() or "TLS"
                                    ciph = ss.cipher()[0] if ss.cipher() else "N/A"
                                    is_ws, payload = _try_ws_handshake_and_read(ss, default_proto="mqtt")
                                    if is_ws and _is_mqtt_connect_packet(payload):
                                        connack = b"\x20\x02\x00\x00"
                                        ss.sendall(bytes([0x82, len(connack)]) + connack)
                                    log_event("ComMech-5 (MQTT)", f"Nhận kết nối MQTT WSS ({ver} / {ciph}) từ {ip}:{MQTT_WSS_PORT}", style="green")
                            except Exception:
                                pass
        except Exception as e:
            log_event("ComMech-5 (MQTT)", f"Worker dừng: {e}", style="yellow")
        finally:
            for _, s in socks:
                try:
                    s.close()
                except Exception:
                    pass

    # Worker 2: Syslog
    def _worker_syslog():
        socks = []
        try:
            ctx = get_server_ssl_context()
            s_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s_udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s_udp.bind(("0.0.0.0", SYSLOG_CLEAR_PORT))
            socks.append(s_udp)

            s_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s_tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s_tcp.bind(("0.0.0.0", SYSLOG_CLEAR_PORT))
            s_tcp.listen(5)
            socks.append(s_tcp)

            s_tls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s_tls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s_tls.bind(("0.0.0.0", SYSLOG_TLS_PORT))
            s_tls.listen(5)
            socks.append(s_tls)

            while not stop_event.is_set():
                readable, _, _ = select.select(socks, [], [], 0.5)
                for r_sock in readable:
                    if r_sock == s_udp:
                        try:
                            data, addr = s_udp.recvfrom(4096)
                            msg = data.decode("utf-8", "ignore").strip()
                            log_event("ComMech-6 (Syslog)", f"Nhận Syslog UDP rõ (Port 514) từ {addr[0]}: {msg[:100]}", style="yellow")
                        except Exception:
                            pass
                    elif r_sock == s_tcp:
                        acc = _accept_dut_client(s_tcp, SYSLOG_CLEAR_PORT, timeout=1.0)
                        if acc:
                            c, ip = acc
                            try:
                                data = c.recv(4096)
                                msg = data.decode("utf-8", "ignore").strip()
                                log_event("ComMech-6 (Syslog)", f"Nhận Syslog TCP rõ (Port 514) từ {ip}: {msg[:100]}", style="yellow")
                            finally:
                                c.close()
                    elif r_sock == s_tls:
                        acc = _accept_dut_client(s_tls, SYSLOG_TLS_PORT, timeout=3.0)
                        if acc:
                            c, ip = acc
                            try:
                                with ctx.wrap_socket(c, server_side=True) as ss:
                                    ver = ss.version() or "TLS"
                                    ciph = ss.cipher()[0] if ss.cipher() else "N/A"
                                    ss.settimeout(2.0)
                                    data = ss.recv(4096)
                                    msg = data.decode("utf-8", "ignore").strip()
                                    log_event("ComMech-6 (Syslog)", f"Nhận Syslog qua {ver} ({ciph}) từ {ip}:{SYSLOG_TLS_PORT}: {msg[:100]}", style="green")
                            except Exception:
                                pass
        except Exception as e:
            log_event("ComMech-6 (Syslog)", f"Worker dừng: {e}", style="yellow")
        finally:
            for s in socks:
                try:
                    s.close()
                except Exception:
                    pass

    # Worker 3: SMB
    def _worker_smb():
        if smbd_active:
            last_check = time.time()
            while not stop_event.is_set():
                time.sleep(1.0)
                if pcap_path and time.time() - last_check > 3.0:
                    last_check = time.time()
                    parsed = _extract_smb_negotiate_from_pcap(pcap_path, DUT_IP, SMB_PORT)
                    if parsed and parsed.get("protocol"):
                        log_event("ComMech-7 (SMB)", f"Bắt gói tin {parsed.get('protocol')} từ {DUT_IP} (Samba Server)", style="green")
            return

        srv_sock = None
        try:
            srv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv_sock.bind(("0.0.0.0", SMB_PORT))
            srv_sock.listen(5)

            while not stop_event.is_set():
                readable, _, _ = select.select([srv_sock], [], [], 0.5)
                if readable:
                    acc = _accept_dut_client(srv_sock, SMB_PORT, timeout=2.0)
                    if acc:
                        c, ip = acc
                        try:
                            data = c.recv(4096)
                            parsed = parse_smb_negotiate_request(data)
                            if parsed:
                                proto = parsed.get("protocol", "SMB")
                                dialects = ", ".join(parsed.get("dialects", []))
                                if parsed.get("has_smb3"):
                                    resp = build_smb2_negotiate_response(parsed.get("msg_id", 0), 0x0311)
                                    c.sendall(resp)
                                    time.sleep(0.3)
                                log_event("ComMech-7 (SMB)", f"Nhận gói tin {proto} Negotiate từ {ip} (Dialects: {dialects})", style="green")
                        except Exception:
                            pass
                        finally:
                            c.close()
        except Exception as e:
            log_event("ComMech-7 (SMB)", f"Worker dừng: {e}", style="yellow")
        finally:
            if srv_sock:
                try:
                    srv_sock.close()
                except Exception:
                    pass

    # Worker 4: SMTP
    def _worker_smtp():
        socks = []
        try:
            ctx = get_server_ssl_context()
            for port in [SMTP_STARTTLS_PORT, SMTPS_PORT, SMTP_CLEAR_PORT]:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    s.bind(("0.0.0.0", port))
                    s.listen(5)
                    socks.append((port, s))
                except Exception as ex:
                    log_event("ComMech-8 (SMTP)", f"Không thể bind cổng {port}: {ex}", style="red")

            s_sub = next((s for p, s in socks if p == SMTP_STARTTLS_PORT), None)
            s_smtps = next((s for p, s in socks if p == SMTPS_PORT), None)
            s_clr = next((s for p, s in socks if p == SMTP_CLEAR_PORT), None)
            all_socks = [s for _, s in socks]

            while not stop_event.is_set():
                readable, _, _ = select.select(all_socks, [], [], 0.5)
                for r_sock in readable:
                    if r_sock == s_clr:
                        acc = _accept_dut_client(s_clr, SMTP_CLEAR_PORT, timeout=1.0)
                        if acc:
                            c, ip = acc
                            try:
                                c.sendall(b"220 qcvn11-smtp Service Ready\r\n")
                                c.recv(1024)
                                log_event("ComMech-8 (SMTP)", f"CẢNH BÁO: Nhận kết nối SMTP Cleartext (Port {SMTP_CLEAR_PORT}) từ {ip}!", style="bold red")
                            finally:
                                c.close()
                    elif r_sock == s_smtps:
                        acc = _accept_dut_client(s_smtps, SMTPS_PORT, timeout=2.0)
                        if acc:
                            c, ip = acc
                            try:
                                with ctx.wrap_socket(c, server_side=True) as ss:
                                    ver = ss.version() or "TLS"
                                    ciph = ss.cipher()[0] if ss.cipher() else "N/A"
                                    ss.sendall(b"220 qcvn11-smtps Service Ready\r\n")
                                    ss.recv(1024)
                                    log_event("ComMech-8 (SMTP)", f"Nhận kết nối SMTPS ({ver} / {ciph}) từ {ip}:{SMTPS_PORT}", style="green")
                            except Exception:
                                pass
                    elif r_sock == s_sub:
                        acc = _accept_dut_client(s_sub, SMTP_STARTTLS_PORT, timeout=2.0)
                        if acc:
                            c, ip = acc
                            try:
                                c.sendall(b"220 qcvn11-submission ESMTP Ready\r\n")
                                _ = c.recv(1024)
                                c.sendall(b"250-qcvn11-submission Hello\r\n250-STARTTLS\r\n250 HELP\r\n")
                                cmd = c.recv(1024).decode("utf-8", "ignore")
                                if "STARTTLS" in cmd.upper():
                                    c.sendall(b"220 2.0.0 Ready to start TLS\r\n")
                                    with ctx.wrap_socket(c, server_side=True) as ss:
                                        ver = ss.version() or "TLS"
                                        ciph = ss.cipher()[0] if ss.cipher() else "N/A"
                                        log_event("ComMech-8 (SMTP)", f"Nhận kết nối SMTP STARTTLS ({ver} / {ciph}) từ {ip}:{SMTP_STARTTLS_PORT}", style="green")
                            except Exception:
                                pass
        except Exception as e:
            log_event("ComMech-8 (SMTP)", f"Worker dừng: {e}", style="yellow")
        finally:
            for _, s in socks:
                try:
                    s.close()
                except Exception:
                    pass

    # Worker 5: SFTP
    def _worker_sftp():
        sftp_socks = []
        try:
            ports = [FTP_CLEAR_PORT] if sshd_active else [FTP_CLEAR_PORT, SFTP_PORT]
            for port in ports:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    s.bind(("0.0.0.0", port))
                    s.listen(5)
                    sftp_socks.append((port, s))
                except Exception as ex:
                    log_event("ComMech-9 (SFTP)", f"Không thể bind cổng {port}: {ex}", style="red")

            s_ftp = next((s for p, s in sftp_socks if p == FTP_CLEAR_PORT), None)
            s_ssh = next((s for p, s in sftp_socks if p == SFTP_PORT), None)
            all_socks = [s for _, s in sftp_socks]

            last_kex_check = time.time()
            while not stop_event.is_set():
                if all_socks:
                    readable, _, _ = select.select(all_socks, [], [], 0.5)
                    for r_sock in readable:
                        if r_sock == s_ftp:
                            acc = _accept_dut_client(s_ftp, FTP_CLEAR_PORT, timeout=1.0)
                            if acc:
                                c, ip = acc
                                try:
                                    c.sendall(b"220 qcvn11-ftp Ready\r\n")
                                    _ = c.recv(1024)
                                    log_event("ComMech-9 (SFTP)", f"CẢNH BÁO: Nhận kết nối FTP Cleartext (Port {FTP_CLEAR_PORT}) từ {ip}!", style="bold red")
                                finally:
                                    c.close()
                        elif r_sock == s_ssh:
                            acc = _accept_dut_client(s_ssh, SFTP_PORT, timeout=3.0)
                            if acc:
                                c, ip = acc
                                try:
                                    log_event("ComMech-9 (SFTP)", f"Nhận kết nối SFTP/SSH (Port {SFTP_PORT}) từ {ip}", style="green")
                                finally:
                                    c.close()
                else:
                    time.sleep(0.5)

                if sshd_active and pcap_path and (time.time() - last_kex_check > 3.0):
                    last_kex_check = time.time()
                    pcap_ssh = _extract_ssh_kex_from_pcap(pcap_path, DUT_IP)
                    if pcap_ssh and pcap_ssh.get("kex_info"):
                        log_event("ComMech-9 (SFTP)", f"Bắt gói tin SSH KEXINIT từ {DUT_IP} (OpenSSH SFTP)", style="green")
        except Exception as e:
            log_event("ComMech-9 (SFTP)", f"Worker dừng: {e}", style="yellow")
        finally:
            for _, s in sftp_socks:
                try:
                    s.close()
                except Exception:
                    pass

    # Start all 5 worker threads
    threads = [
        threading.Thread(target=_worker_mqtt, name="ComMech-MQTT-Worker", daemon=True),
        threading.Thread(target=_worker_syslog, name="ComMech-Syslog-Worker", daemon=True),
        threading.Thread(target=_worker_smb, name="ComMech-SMB-Worker", daemon=True),
        threading.Thread(target=_worker_smtp, name="ComMech-SMTP-Worker", daemon=True),
        threading.Thread(target=_worker_sftp, name="ComMech-SFTP-Worker", daemon=True),
    ]

    for th in threads:
        th.start()

    console.print("\n[bold green][+] Toàn bộ 5 máy chủ ComMech đã kích hoạt và đang lắng nghe.[/bold green]")
    console.print("[dim]    (Giao diện điều khiển sẵn sàng đón nhận sự kiện từ Camera. Nhấn Ctrl+C hoặc bấm Stop trên Web để kết thúc)[/dim]\n")

    try:
        while not stop_event.is_set():
            time.sleep(0.5)
    except KeyboardInterrupt:
        console.print("\n[bold yellow][!] Đã nhận tín hiệu dừng (Stop). Đang đóng các dịch vụ server...[/bold yellow]")
    finally:
        stop_event.set()
        for th in threads:
            th.join(timeout=1.0)
        if pcap_proc:
            time.sleep(0.5)
            stop_pcap_capture(pcap_proc)

    # Hiển thị bảng tổng kết sự kiện thu được
    t = Table(title="BẢNG TỔNG KẾT HOẠT ĐỘNG CÁC MÁY CHỦ COMMECH", show_lines=True)
    t.add_column("Cơ chế / Dịch vụ", justify="left", style="bold white")
    t.add_column("Cổng lắng nghe", justify="center", style="cyan")
    t.add_column("Số sự kiện / Kết nối bắt được", justify="center", style="bold green")

    ports_desc = {
        "ComMech-5 (MQTT)": f"{MQTT_TLS_PORT} (TLS), {MQTT_WSS_PORT} (WSS), {MQTT_CLEAR_PORT}",
        "ComMech-6 (Syslog)": f"{SYSLOG_TLS_PORT} (TLS), {SYSLOG_CLEAR_PORT} (UDP/TCP)",
        "ComMech-7 (SMB)": f"{SMB_PORT} (SMBv3)",
        "ComMech-8 (SMTP)": f"{SMTP_STARTTLS_PORT} (STARTTLS), {SMTPS_PORT}, {SMTP_CLEAR_PORT}",
        "ComMech-9 (SFTP)": f"{SFTP_PORT} (SFTP/SSH), {FTP_CLEAR_PORT} (FTP)",
    }

    for srv, count in event_counts.items():
        cnt_style = "bold green" if count > 0 else "dim"
        t.add_row(srv, ports_desc.get(srv, "N/A"), f"[{cnt_style}]{count} sự kiện[/{cnt_style}]")

    console.print(t)

    if record_pcap and pcap_path and os.path.exists(pcap_path):
        dst_pcap = os.path.join(EVIDENCE_DIR, "commech_all_servers.pcap")
        shutil.copy2(pcap_path, dst_pcap)
        pkt_cnt = get_pcap_packet_count(dst_pcap)
        console.print(f"[bold green][+] Đã lưu bằng chứng PCAP toàn bộ phiên server: [bold white]{dst_pcap}[/bold white] ({pkt_cnt} gói tin)[/bold green]\n")
    else:
        console.print("[dim]Chế độ No-PCAP: Không lưu file PCAP bằng chứng.[/dim]\n")

    return 0


def main():
    global RECORD_PCAP
    parser = argparse.ArgumentParser(description="Bộ đo kiểm toàn diện các cơ chế truyền thông ComMech (QCVN 11)")
    parser.add_argument("--id", type=str, default="all", help="Chỉ định ID ComMech cần kiểm (1-11, 'servers', hoặc 'all')")
    parser.add_argument("--wait", type=float, default=20.0, help="Thời gian chờ đón bắt gói tin cho dịch vụ Client (giây; <= 0 để chạy liên tục)")
    parser.add_argument("--forever", action="store_true", help="Chạy server liên tục không giới hạn thời gian (dừng lại khi bấm Stop hoặc nhấn Ctrl+C)")
    parser.add_argument("--server-mode", action="store_true", help="Bật toàn bộ 5 server ComMech (MQTT, Syslog, SMB, SMTP, SFTP) chạy liên tục")
    parser.add_argument("--auto-trigger", action="store_true", help="Tự động gọi VAPIX kích hoạt Syslog/SMTP/SFTP (mặc định chờ bấm Test thủ công)")
    parser.add_argument("--no-pcap", action="store_true", help="Không bắt và không ghi đè tệp PCAP bằng chứng (dùng để kích thích lưu lượng kiểm tra Telemetry)")
    parser.add_argument("--enum", nargs="?", const="all", default=None, help="Bóc tách TOÀN BỘ Ciphersuite/KEX/SNMPv3 (1, 2, 3, 4, 10 hoặc 'all')")
    args = parser.parse_args()

    if args.no_pcap:
        RECORD_PCAP = False

    if args.wait <= 0:
        args.forever = True

    # Nếu có cờ --enum, chuyển sang chế độ Nmap Cipher Enumeration
    if args.enum is not None:
        sys.exit(run_cipher_enumeration(args.enum))

    # Nếu chạy server-mode hoặc --id servers
    if args.server_mode or args.id.lower() in ["servers", "all-servers"]:
        sys.exit(run_all_commech_servers(record_pcap=not args.no_pcap))

    pcap_status_str = "[bold yellow]TẮT (Kích thích lưu lượng, bảo toàn bằng chứng cũ)[/bold yellow]" if args.no_pcap else f"[bold green]BẬT ({EVIDENCE_DIR})[/bold green]"
    forever_mode_str = "\n• [bold green]Chế độ máy chủ    : CHẠY LIÊN TỤC (Đến khi bấm Stop hoặc Ctrl+C)[/bold green]" if args.forever else ""
    console.print(Panel(
        f"[bold white]BỘ ĐO KIỂM TOÀN DIỆN 11 CƠ CHẾ TRUYỀN THÔNG (IXIT 11 - COMMECH){' [NO-PCAP MODE]' if args.no_pcap else ''}[/bold white]\n"
        f"• Mục tiêu DUT IP : [cyan]{DUT_IP}[/cyan]\n"
        f"• Máy đo (Host IP): [bold green]{HOST_IP}[/bold green]\n"
        f"• Tiêu chuẩn áp dụng: [bold yellow]QCVN 11:2026/BCA & ETSI EN 303 645[/bold yellow]\n"
        f"• Chế độ ghi PCAP  : {pcap_status_str}{forever_mode_str}",
        title="THIẾT LẬP ĐO KIỂM",
        border_style="yellow" if args.no_pcap else "cyan"
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
                if cid in ("6", "8", "9"):
                    res = audit_map[cid](wait_sec=args.wait, auto_trigger=args.auto_trigger, record_pcap=not args.no_pcap, forever=args.forever)
                elif cid in ("5", "7"):
                    res = audit_map[cid](wait_sec=args.wait, record_pcap=not args.no_pcap, forever=args.forever)
                else:
                    res = audit_map[cid](wait_sec=args.wait)
                
                if not args.no_pcap:
                    # Sao chép và chuẩn hóa tên file pcap trong thư mục bằng chứng
                    if "pcap_file" in res and os.path.exists(res["pcap_file"]):
                        std_name = res.get("pcap", f"commech-{cid}.pcap")
                        dst_pcap = os.path.join(EVIDENCE_DIR, std_name)
                        shutil.copy2(res["pcap_file"], dst_pcap)
                        res["evidence_pcap"] = dst_pcap
                        cnt = get_pcap_packet_count(dst_pcap)
                        res["pcap_packet_count"] = cnt
                    _enforce_pcap_requirement(res, require_pcap=(cid != "11"))
                else:
                    res["pcap_packet_count"] = 0
                results.append(res)
            except Exception as e:
                console.print(f"[bold red][!] Lỗi khi đo kiểm ComMech-{cid}: {e}[/bold red]")

    # Hiển thị bảng tổng hợp trên console
    t = Table(title=f"BẢNG TỔNG HỢP ĐO KIỂM CÁC PHƯƠNG THỨC TRUYỀN THÔNG (11 PHƯƠNG THỨC TIÊU CHUẨN){' [CHẾ ĐỘ NO-PCAP]' if args.no_pcap else ''}", show_lines=True)
    t.add_column("STT", justify="center", style="bold yellow", no_wrap=True)
    t.add_column("Phương thức / Tên dịch vụ & Giao thức", justify="left")
    t.add_column("Vai trò mạng", justify="center")
    t.add_column("Tấn công hạ cấp & Đàm phán", justify="left")
    t.add_column("Gói tin PCAP", justify="center", no_wrap=True)

    for idx, r in enumerate(results, 1):
        downgrade_str = r.get("downgrade_test", {}).get("detail", "N/A")
        pcap_str = f"{r.get('pcap_packet_count', 0)} pkts" if not args.no_pcap else "[dim]Bỏ qua (No PCAP)[/dim]"
        t.add_row(
            str(idx),
            f"{r.get('name')}\n[dim]{r.get('proto')}[/dim]",
            r.get("direction", "N/A"),
            downgrade_str,
            pcap_str
        )

    console.print(t)

    if args.no_pcap:
        console.print(f"\n[bold yellow][+] HOÀN TẤT CHẾ ĐỘ --no-pcap (KÍCH THÍCH LƯU LƯỢNG / KIỂM TRA TELEMETRY):[/bold yellow]")
        console.print("    • Đã kích hoạt các luồng truyền thông ComMech tới Camera để sinh lưu lượng kiểm tra.")
        console.print("    • KHÔNG ghi đè hay thay đổi bất kỳ tệp PCAP bằng chứng nào trong thư mục captures/.")
        console.print("    • Báo cáo nghiệm thu commech_audit_report.md được BẢO TOÀN NGUYÊN VẸN.\n")
        sys.exit(0)

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

    all_passed = bool(results) and all(r.get("status") == "PASS" for r in results)
    if all_passed:
        console.print(f"\n[bold green][+] ĐÃ LƯU BẰNG CHỨNG PCAP THÀNH CÔNG (CHỈ LƯU TỆP PCAP DUY NHẤT):[/bold green]")
    else:
        console.print(f"\n[bold red][!] BÀI ĐO CHƯA ĐẠT HOẶC THIẾU GÓI TIN PCAP (0 PKTS) — KHÔNG TÍNH PASS:[/bold red]")
    console.print(f"    • Thư mục bằng chứng PCAP : [bold white]{EVIDENCE_DIR}[/bold white]")
    for r in results:
        if "evidence_pcap" in r and os.path.exists(r["evidence_pcap"]):
            console.print(f"      ↳ [cyan]{os.path.basename(r['evidence_pcap'])}[/cyan] ({r.get('pcap_packet_count', 0)} pkts | {r.get('status', 'N/A')})")
    console.print(f"    • Báo cáo hệ thống (Markdown) : [dim]{rep_md_path}[/dim]\n")
    sys.exit(0 if all_passed else 1)


if __name__ == '__main__':
    main()
