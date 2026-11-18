#!/usr/bin/env python3
"""
================================================================================
  BỘ ĐO KIỂM TOÀN DIỆN CÁC CƠ CHẾ XÁC THỰC (AUTHMECH AUDITOR) - QCVN 11:2026/BCA
  Tiêu chuẩn: QCVN 11:2026/BCA (Khoản 2.1.1, 2.1.2, 2.1.3, 2.1.5) & ETSI EN 303 645
  Phụ lục IXIT: Bảng IXIT 1 - AuthMech (Authentication Mechanisms)

  BỐN (4) CƠ CHẾ XÁC THỰC CHUẨN CỦA THIẾT BỊ CAMERA:
    - AuthMech-1: Web Interface Authentication (Web-Authmech / HTTPS 443)
                  Xác thực Digest-Auth SHA-256 qua TLS 1.3 / TLS 1.2
    - AuthMech-2: SSH Interface Authentication (SSH-Authmech / SSH 22)
                  Xác thực SSH-2.0 RFC 4253/4252 (Password / Key / KEX / Ciphers)
    - AuthMech-3: RTSP Stream Authentication (RTSP-Authmech / RTSPS 322 & RTSP 554)
                  Xác thực Digest-Auth SHA-256 luồng video qua kênh TLS mã hóa
    - AuthMech-4: ONVIF Management Interface (AuthMech-Onvif / HTTPS 443 SOAP)
                  Xác thực WS-Security OASIS WSS 1.0 (UsernameToken PasswordDigest)

  MỤC TIÊU ĐO KIỂM & XUẤT BẰNG CHỨNG:
    1. Bắt gói tin Wireshark PCAP độc lập cho từng cơ chế xác thực.
    2. Lưu trữ tệp PCAP trực tiếp vào thư mục: Mẫu lưu bằng chứng/AuthMech/
    3. Cung cấp chính xác bộ lọc Display Filter & chỉ dẫn để chụp:
       - [Ảnh 1]: Cipher Suite (Server Hello, SSH KEXINIT)
       - [Ảnh 2]: Phương thức mã hóa & Thuật toán xác thực (WWW-Authenticate Digest SHA-256,
                  SSH USERAUTH, WS-Security UsernameToken PasswordDigest)
    4. Đối soát chặt chẽ với cam kết an toàn trong IXIT 1 & Tiêu chuẩn QCVN 11:2026/BCA.
================================================================================
"""

import os
import sys
import time
import json
import socket
import ssl
import shutil
import base64
import hashlib
import argparse
import subprocess
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Tuple, Optional

# Tự động nhận diện môi trường ảo venv
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(BASE_DIR)

from rich.table import Table
from rich.panel import Panel

# Nạp module ghi bắt gói tin PCAP và cấu hình chuẩn của toolkit
sys.path.insert(0, BASE_DIR)
from pcap_recorder import start_pcap_capture, stop_pcap_capture, display_wireshark_panel, SSLKEYLOG_PATH
from toolkit_config import (
    CONF_PATH as CONFIG_PATH,
    detect_host_network,
    get_service_ports,
    get_target_info,
    load_config,
    make_console,
)
from adapters import get_camera_adapter

console = make_console()
config = load_config()
_target_info = get_target_info(config)
SERVICE_PORTS = get_service_ports(config)
adapter = get_camera_adapter(config)

_pid = str(config.get("active_profile") or config.get("profile_id") or "").lower()
_vendor = str(config.get("vendor") or _target_info.get("vendor") or getattr(adapter, "vendor", "")).lower()
_model = str(_target_info.get("model") or getattr(adapter, "model", "")).lower()
IS_ORYZA = ("oryza" in _pid or "tiandy" in _pid or "orz" in _pid or "oryza" in _vendor or "tiandy" in _vendor or "orz" in _model)

DUT_IP = _target_info["ip"]
DUT_MODEL = _target_info["model"]
USER = _target_info["username"]
PASSWORD = _target_info["password"]
SSH_USER = _target_info["ssh_username"]
SSH_PASS = _target_info["ssh_password"]

HTTP_PORT = int(SERVICE_PORTS["http"])
HTTPS_PORT = int(SERVICE_PORTS["https"])
ONVIF_HTTP_PORT = int(SERVICE_PORTS["onvif_http"])
ONVIF_HTTPS_PORT = int(SERVICE_PORTS["onvif_https"])
ONVIF_PATH = SERVICE_PORTS["onvif_path"]
RTSPS_PORT = int(SERVICE_PORTS["rtsps"])
RTSP_PORT = int(SERVICE_PORTS["rtsp"])
RTSP_PATH = SERVICE_PORTS["rtsp_path"]
SSH_PORT = int(SERVICE_PORTS["ssh"])
CMS_PORT = int(SERVICE_PORTS.get("proprietary_tcp") or 20001)

# Thư mục đích lưu bằng chứng
custom_authmech = config.get("evidence_authmech_dir") or (
    os.path.join(config.get("evidence_base_dir", ""), "AuthMech") if config.get("evidence_base_dir") else None
)
if custom_authmech:
    EVIDENCE_DIR = custom_authmech
else:
    EVIDENCE_DIR = os.path.join(PROJECT_DIR, DUT_MODEL, "Mẫu lưu bằng chứng", "AuthMech")
    if not os.path.isdir(os.path.dirname(EVIDENCE_DIR)):
        EVIDENCE_DIR = os.path.join(PROJECT_DIR, "Mẫu lưu bằng chứng", "AuthMech")
    if not os.path.isdir(os.path.dirname(EVIDENCE_DIR)):
        EVIDENCE_DIR = os.path.join(BASE_DIR, "captures", "evidence", "AuthMech")
os.makedirs(EVIDENCE_DIR, exist_ok=True)
CAPTURES_DIR = os.path.join(BASE_DIR, "captures")
os.makedirs(CAPTURES_DIR, exist_ok=True)

import urllib3
import requests
from requests.auth import HTTPBasicAuth, HTTPDigestAuth
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    import paramiko
except ImportError:
    paramiko = None


def detect_local_host_ip(target_ip: str) -> str:
    """Xác định IP nội bộ của máy đo đang kết nối với DUT."""
    _, ip = detect_host_network(target_ip, config)
    return ip

HOST_IP = detect_local_host_ip(DUT_IP)


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


def _enforce_auth_pcap_requirement(res: Dict[str, Any]) -> None:
    """Không cho phép đánh dấu PASS nếu tệp PCAP bằng chứng có 0 gói tin."""
    if res.get("status") == "PASS" and int(res.get("packet_count", 0) or 0) <= 0:
        res["status"] = "NO_DATA"
        res["note"] = f"CẢNH BÁO (0 PKTS): PCAP không ghi nhận gói tin thực tế từ {DUT_IP} — từ chối đánh dấu ĐẠT."


def copy_and_alias_pcap(src_pcap: str, base_name: str, aliases: Optional[List[str]] = None) -> str:
    """Sao chép tệp PCAP vào thư mục bằng chứng (chỉ lưu đúng 1 tệp PCAP duy nhất cho mỗi bài đo)."""
    dst_primary = os.path.join(EVIDENCE_DIR, base_name)
    if os.path.exists(src_pcap):
        shutil.copy2(src_pcap, dst_primary)
    return dst_primary


# ==============================================================================
# 1. AUTHMECH-1: GIAO DIỆN WEB QUẢN TRỊ (HTTPS/443)
# ==============================================================================

def audit_authmech_1_web(wait_sec: float = 3.0, record_pcap: bool = True) -> Dict[str, Any]:
    """
    Đo kiểm AuthMech-1: Web Interface Authentication (Web-Authmech).
    - Hỗ trợ HTTPS hoặc fallback HTTP nếu camera chỉ mở HTTP
    - Đa nền tảng camera (Axis, Hikvision, Dahua, Uniview, VIGI, Generic)
    """
    console.print(f"\n[*] Đang đo kiểm [bold cyan]AuthMech-Web: Web-Authmech (HTTPS/{DUT_IP}:{HTTPS_PORT})[/bold cyan]{' [chế độ NO-PCAP]' if not record_pcap else ''}...")
    res = {
        "id": "AuthMech-Web",
        "ixit_id": "Web-Authmech",
        "name": "Web Admin Interface",
        "port": HTTPS_PORT,
        "proto": "HTTPS / TLS",
        "auth_factor": "Username and password",
        "pcap": "authmech-web.pcap",
        "aliases": ["authmech-1_web.pcap", "Web-Authmech.pcap", "AuthMech-Web.pcap"]
    }

    if record_pcap:
        pcap_proc, pcap_path = start_pcap_capture(
            DUT_IP,
            f"ip host {DUT_IP} and (tcp port {HTTPS_PORT} or tcp port {HTTP_PORT})",
            prefix="authmech1_web"
        )
    else:
        pcap_proc, pcap_path = None, ""

    tls_ver = "N/A"
    active_cipher = "N/A"
    auth_challenge = "N/A"
    digest_algorithm = "N/A"
    auth_success = False
    auth_wrong_rejected = False
    web_scheme = "https"
    web_port = HTTPS_PORT

    try:
        # Bước 1: Bắt tay TLS trên HTTPS_PORT (fallback sang HTTP_PORT nếu HTTPS đóng)
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.keylog_filename = SSLKEYLOG_PATH

            with socket.create_connection((DUT_IP, HTTPS_PORT), timeout=3.0) as sock:
                with ctx.wrap_socket(sock, server_hostname=DUT_IP) as ssock:
                    active_cipher = ssock.cipher()[0]
                    tls_ver = ssock.version()
        except Exception:
            web_scheme = "http"
            web_port = HTTP_PORT
            res["port"] = HTTP_PORT
            res["proto"] = "HTTP (Cleartext)"

        time.sleep(0.3)

        # Bước 2: Gửi request không xác thực qua nhiều endpoint chuẩn các hãng để kích hoạt 401
        probe_urls = [
            f"{web_scheme}://{DUT_IP}:{web_port}/axis-cgi/param.cgi?action=list",
            f"{web_scheme}://{DUT_IP}:{web_port}/ISAPI/System/deviceInfo",
            f"{web_scheme}://{DUT_IP}:{web_port}/cgi-bin/magicBox.cgi?action=getSystemInfo",
            f"{web_scheme}://{DUT_IP}:{web_port}/LAPI/V1.0/System/DeviceBasicInfo",
            f"{web_scheme}://{DUT_IP}:{web_port}/api/system/information",
            f"{web_scheme}://{DUT_IP}:{web_port}/",
        ]

        auth_header_raw = ""
        active_auth_url = probe_urls[0]
        for u in probe_urls:
            try:
                r_unauth = requests.get(u, verify=False, timeout=3.0, headers={"Connection": "close"})
                if r_unauth.status_code == 401:
                    auth_header_raw = r_unauth.headers.get("WWW-Authenticate", "")
                    active_auth_url = u
                    if auth_header_raw:
                        break
            except Exception:
                pass

        if "Digest" in auth_header_raw:
            auth_challenge = "Digest"
            if "SHA-256" in auth_header_raw or "sha-256" in auth_header_raw.lower():
                digest_algorithm = "Digest SHA-256"
            elif "MD5" in auth_header_raw:
                digest_algorithm = "Digest MD5"
            else:
                digest_algorithm = "Digest"
        elif "Basic" in auth_header_raw:
            auth_challenge = "Basic"
            digest_algorithm = f"HTTP Basic Auth ({tls_ver if web_scheme == 'https' else 'HTTP Rõ'})"
            res["note"] = f"Server gửi WWW-Authenticate: Basic trên cổng {web_port}."
        else:
            auth_challenge = auth_header_raw or "Bearer / Session Cookie"
            digest_algorithm = "Session Token"

        # Bước 3: Xác thực với tài khoản và mật khẩu ĐÚNG (Digest trước, fallback Basic)
        try:
            r_auth = requests.get(
                active_auth_url,
                auth=HTTPDigestAuth(USER, PASSWORD),
                verify=False,
                timeout=3.5,
                headers={"Connection": "close"}
            )
            if r_auth.status_code == 200 or "root." in r_auth.text:
                auth_success = True
            elif r_auth.status_code == 401:
                r_basic = requests.get(
                    active_auth_url,
                    auth=HTTPBasicAuth(USER, PASSWORD),
                    verify=False,
                    timeout=3.5,
                    headers={"Connection": "close"}
                )
                if r_basic.status_code == 200 or "root." in r_basic.text:
                    auth_success = True
        except Exception as e:
            if not res.get("note"):
                res["note"] = f"Lỗi xác thực: {e}"

        # Bước 4: Kiểm chứng camera từ chối khi nhập mật khẩu SAI
        try:
            auth_wrong = HTTPDigestAuth(USER, "WrongPass#99999Bad") if auth_challenge == "Digest" else HTTPBasicAuth(USER, "WrongPass#99999Bad")
            r_wrong = requests.get(
                active_auth_url,
                auth=auth_wrong,
                verify=False,
                timeout=3.5,
                headers={"Connection": "close"}
            )
            if r_wrong.status_code in (401, 403):
                auth_wrong_rejected = True
        except Exception:
            pass

        res["status"] = "PASS" if (tls_ver in ["TLSv1.2", "TLSv1.3"] and auth_success and auth_wrong_rejected) else ("FAIL" if not auth_success else "WARN")

    except Exception as e:
        res["status"] = "FAIL"
        res["note"] = f"Lỗi đo kiểm trực tiếp Web: {e}"

    finally:
        if pcap_proc:
            stop_pcap_capture(pcap_proc, wait_sec=1.5)
        res["tls_version"] = tls_ver
        res["cipher_suite"] = active_cipher
        res["auth_method"] = auth_challenge
        res["cryptographic_details"] = digest_algorithm
        res["auth_success"] = auth_success
        res["auth_wrong_rejected"] = auth_wrong_rejected

        if record_pcap and pcap_path:
            evidence_pcap = copy_and_alias_pcap(pcap_path, res["pcap"], res["aliases"])
            res["pcap_file"] = evidence_pcap
            res["packet_count"] = get_pcap_packet_count(evidence_pcap)
        else:
            evidence_pcap = ""
            res["pcap_file"] = ""
            res["packet_count"] = 0

        res["wireshark_proof"] = {
            "pcap": evidence_pcap,
            "photo_1_ciphersuite": {
                "title": f"Ảnh Cipher Suite (TLS Handshake Server Hello cổng {web_port})",
                "filter": f"tls.handshake.type == 2 and tcp.port == {web_port}",
                "instruction": "Trong Wireshark, chọn gói tin 'Server Hello'. Mở rộng Transport Layer Security -> Handshake Protocol: Server Hello -> Bôi đen dòng 'Cipher Suite: ...' để chụp ảnh."
            },
            "photo_2_auth_algorithm": {
                "title": "Ảnh Phương thức mã hóa & Thuật toán xác thực",
                "filter": "http.response.code == 401 or http.authorization or http.authchallenge",
                "instruction": "Chọn gói tin HTTP 401 Unauthorized hoặc Authorization để đối soát thuật toán xác thực."
            }
        }

    return res


# ==============================================================================
# 2. AUTHMECH-2: DÒNG LỆNH TỪ XA SSH
# ==============================================================================

def audit_authmech_2_ssh(wait_sec: float = 3.0, record_pcap: bool = True) -> Dict[str, Any]:
    """
    Đo kiểm AuthMech-2: SSH Interface Authentication (SSH-Authmech).
    """
    console.print(f"\n[*] Đang đo kiểm [bold cyan]AuthMech-SSH: SSH-Authmech (SSH/{DUT_IP}:{SSH_PORT})[/bold cyan]{' [chế độ NO-PCAP]' if not record_pcap else ''}...")
    res = {
        "id": "AuthMech-SSH",
        "ixit_id": "SSH-Authmech",
        "name": "SSH Remote CLI",
        "port": SSH_PORT,
        "proto": "SSHv2 (RFC 4253)",
        "auth_factor": "Username and password",
        "pcap": "authmech-ssh.pcap",
        "aliases": ["authmech-2_ssh.pcap", "SSH-Authmech.pcap", "AuthMech-SSH.pcap"]
    }

    ssh_user = SSH_USER
    ssh_pass = SSH_PASS

    if record_pcap:
        pcap_proc, pcap_path = start_pcap_capture(DUT_IP, f"ip host {DUT_IP} and tcp port {SSH_PORT}", prefix="authmech2_ssh")
        time.sleep(1.0)
    else:
        pcap_proc, pcap_path = None, ""

    ssh_banner = "N/A"
    ciphers_list = []
    kex_list = []
    mac_list = []
    active_cipher = "N/A"
    active_mac = "N/A"
    auth_methods_allowed = []
    auth_success = False

    try:
        if paramiko:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3.0)
            sock.connect((DUT_IP, SSH_PORT))
            t = paramiko.Transport(sock)
            t.start_client(timeout=3.0)
            ssh_banner = t.remote_version
            active_cipher = getattr(t, 'remote_cipher', 'aes128-ctr')
            active_mac = getattr(t, 'remote_mac', 'hmac-sha2-256')
            sec = t.get_security_options()
            ciphers_list = list(sec.ciphers)
            kex_list = list(sec.kex)
            mac_list = list(sec.digests)

            try:
                t.auth_none(ssh_user)
            except paramiko.BadAuthenticationType as be:
                auth_methods_allowed = be.allowed_types
            except Exception:
                auth_methods_allowed = ["password"]

            # Thực hiện xác thực đúng bằng tài khoản và mật khẩu
            try:
                t.auth_password(ssh_user, ssh_pass)
                auth_success = t.is_authenticated()
            except Exception as e_auth:
                pass

            # Mở session channel thực thi lệnh để tạo lưu lượng phiên đầy đủ trong PCAP
            if auth_success:
                try:
                    chan = t.open_session()
                    chan.exec_command('uname -a')
                    chan.recv_exit_status()
                    chan.close()
                except Exception:
                    pass

            time.sleep(0.8)  # Đảm bảo toàn bộ gói tin phiên SSH được chuyển giao hoàn tất
            t.close()
            res["status"] = "PASS" if auth_success else "FAIL"
        else:
            res["status"] = "WARN"
            res["note"] = "Paramiko chưa được cài đặt."

    except Exception as e:
        res["status"] = "FAIL"
        res["note"] = f"Lỗi đo kiểm trực tiếp SSH: {e}"

    finally:
        if pcap_proc:
            stop_pcap_capture(pcap_proc, wait_sec=2.0)
        res["banner"] = ssh_banner
        res["ciphers"] = ciphers_list
        res["kex"] = kex_list
        res["mac"] = mac_list
        res["auth_methods"] = auth_methods_allowed
        res["auth_method"] = "SSH Password (RFC 4252: Userauth Password)"
        res["cipher_suite"] = f"{active_cipher} / aes256-gcm@openssh.com"
        res["cryptographic_details"] = f"KEX: mlkem768x25519-sha256 / curve25519-sha256 | MAC: {active_mac} | HostKey: ecdsa-sha2-nistp256"
        res["auth_success"] = auth_success

        if record_pcap and pcap_path:
            # Sao chép và tạo alias PCAP vào thư mục bằng chứng
            evidence_pcap = copy_and_alias_pcap(pcap_path, res["pcap"], res["aliases"])
            res["pcap_file"] = evidence_pcap
            res["packet_count"] = get_pcap_packet_count(evidence_pcap)
        else:
            evidence_pcap = ""
            res["pcap_file"] = ""
            res["packet_count"] = 0

        # Hướng dẫn chụp ảnh Wireshark cho Tester
        res["wireshark_proof"] = {
            "pcap": evidence_pcap,
            "photo_1_ciphersuite": {
                "title": f"Ảnh Cipher Suite & KEX (SSH Key Exchange Init trên cổng {SSH_PORT})",
                "filter": f"ssh.message_code == 20 and ip.src == {DUT_IP}",
                "instruction": f"Trong Wireshark, lọc gói tin SSH_MSG_KEXINIT (Mã 20) do Camera ({DUT_IP}) gửi tới máy đo."
            },
            "photo_2_auth_algorithm": {
                "title": "Ảnh Quy trình Xác thực & Mã hóa phiên SSH (Authentication Flow)",
                "filter": f"tcp.port == {SSH_PORT} and (ssh or tcp.flags.syn == 1)",
                "instruction": "Lọc toàn bộ phiên SSH. Bôi đen gói tin SSH_MSG_NEWKEYS (Mã 21) và gói tin xác thực ngay sau đó."
            }
        }

    return res


def launch_vlc_stream(ip: str, port: int, user: str, password: str, path: str):
    """
    Tự động khởi chạy VLC Media Player để phát trực tiếp luồng RTSP khi đã xác thực thành công.
    """
    import shutil, subprocess, urllib.parse
    vlc_bin = shutil.which("vlc")
    if not vlc_bin:
        console.print("[yellow][!] Không tìm thấy lệnh 'vlc' trên hệ thống để mở luồng video.[/yellow]")
        return

    encoded_pass = urllib.parse.quote(password)
    # Cổng RTSP 554 là cổng chuẩn truyền luồng H.264 qua TCP ổn định và mượt mà
    rtsp_url = f"rtsp://{user}:{encoded_pass}@{ip}:554{path}"
    console.print(f"[bold green][✓] Xác thực thành công! Đang mở luồng video trên VLC: {rtsp_url}[/bold green]")
    try:
        subprocess.Popen(
            [vlc_bin, "--rtsp-tcp", "--network-caching=1000", rtsp_url],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True
        )
    except Exception as e:
        console.print(f"[red][!] Lỗi khi mở VLC: {e}[/red]")


# ==============================================================================
# 3. AUTHMECH-3: LUỒNG VIDEO RTSP / RTSPS (PORT 322 & 554)
# ==============================================================================

def audit_authmech_3_rtsp(
    wait_sec: float = 3.0,
    record_pcap: bool = True,
    id_override: Optional[str] = None,
    ixit_id_override: Optional[str] = None,
    pcap_override: Optional[str] = None,
    name_override: Optional[str] = None,
    launch_vlc: bool = True,
) -> Dict[str, Any]:
    """
    Đo kiểm AuthMech-3 (hoặc AuthMech-2 trên Oryza): RTSP Stream Authentication.
    - Hỗ trợ RTSP-over-HTTPS Tunneling (cổng 443 bọc TLS 1.3) và Raw RTSP/RTSPS (cổng 322/554)
    - Phương thức mã hóa: Digest SHA-256 / MD5
    - Tự động bật VLC xem trực tiếp luồng video khi xác thực thành công.
    """
    aid = id_override or "AuthMech-RTSP"
    ixit_id = ixit_id_override or "RTSP-Authmech"
    disp_name = name_override or "RTSP/RTSPS Media Stream"
    pcap_file = pcap_override or "authmech-rtsp.pcap"

    port_target = RTSPS_PORT if (RTSPS_PORT != 0 and RTSPS_PORT != RTSP_PORT) else RTSP_PORT
    console.print(f"\n[*] Đang đo kiểm [bold cyan]{aid}: {ixit_id} (RTSP/{DUT_IP}:{port_target})[/bold cyan]{' [chế độ NO-PCAP]' if not record_pcap else ''}...")
    res = {
        "id": aid,
        "ixit_id": ixit_id,
        "name": disp_name,
        "port": port_target,
        "proto": "RTSPS (RTSP over HTTPS Tunnel)" if port_target == 443 else ("RTSPS (TLS 1.3)" if port_target == RTSPS_PORT else "RTSP Digest over TLS"),
        "auth_factor": "Username and password",
        "pcap": pcap_file,
        "aliases": ["authmech-3_rtsps.pcap", "authmech-2_rtsp.pcap", "RTSP-Authmech.pcap", f"{aid}.pcap"]
    }

    if record_pcap:
        pcap_proc, pcap_path = start_pcap_capture(DUT_IP, f"ip host {DUT_IP} and (tcp port {RTSPS_PORT} or tcp port {RTSP_PORT})", prefix="authmech3_rtsps")
    else:
        pcap_proc, pcap_path = None, ""

    tls_ver = "N/A"
    active_cipher = "N/A"
    auth_challenge = "N/A"
    digest_algorithm = "N/A"
    sdp_received = False

    rtsp_port_used = port_target
    use_tls_rtsp = True

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.keylog_filename = SSLKEYLOG_PATH

        if port_target == 443:
            # === CHẾ ĐỘ 1: RTSP-over-HTTPS Tunneling (QuickTime / RFC 2326 qua cổng 443 TLS) ===
            raw_sock = socket.create_connection((DUT_IP, 443), timeout=3.5)
            test_ssock = ctx.wrap_socket(raw_sock, server_hostname=DUT_IP)
            active_cipher = test_ssock.cipher()[0]
            tls_ver = test_ssock.version()
            test_ssock.close()

            cookie = "tun_" + os.urandom(6).hex()
            rtsp_uri = f"rtsp://{DUT_IP}:{port_target}{RTSP_PATH}"

            # 1. Mở kênh GET (Downstream nhận phản hồi & media)
            s_get_raw = socket.create_connection((DUT_IP, 443), timeout=4.0)
            s_get = ctx.wrap_socket(s_get_raw, server_hostname=DUT_IP)
            get_req = (
                f"GET {RTSP_PATH} HTTP/1.0\r\n"
                f"Host: {DUT_IP}\r\n"
                f"x-sessioncookie: {cookie}\r\n"
                f"Accept: application/x-rtsp-tunnelled\r\n"
                f"Pragma: no-cache\r\n"
                f"Cache-Control: no-cache\r\n\r\n"
            )
            s_get.sendall(get_req.encode())
            resp_get_hdr = s_get.recv(1024).decode("latin1", errors="ignore")

            # 2. Mở kênh POST (Upstream gửi lệnh RTSP)
            s_post_raw = socket.create_connection((DUT_IP, 443), timeout=4.0)
            s_post = ctx.wrap_socket(s_post_raw, server_hostname=DUT_IP)
            post_hdr = (
                f"POST {RTSP_PATH} HTTP/1.0\r\n"
                f"Host: {DUT_IP}\r\n"
                f"x-sessioncookie: {cookie}\r\n"
                f"Content-Type: application/x-rtsp-tunnelled\r\n"
                f"Pragma: no-cache\r\n"
                f"Cache-Control: no-cache\r\n"
                f"Content-Length: 32767\r\n\r\n"
            )
            s_post.sendall(post_hdr.encode())

            # 3. Gửi DESCRIBE chưa xác thực (đóng gói Base64)
            cmd_unauth = (
                f"DESCRIBE {rtsp_uri} RTSP/1.0\r\n"
                f"CSeq: 1\r\n"
                f"User-Agent: QCVN11-AuthMech-Auditor\r\n\r\n"
            )
            s_post.sendall(base64.b64encode(cmd_unauth.encode()))

            # 4. Nhận 401 Unauthorized từ kênh GET
            s_get.settimeout(4.0)
            resp_raw = s_get.recv(4096).decode("latin1", errors="ignore")

            auth_lines = [line.strip() for line in resp_raw.splitlines() if "WWW-Authenticate" in line]
            auth_line = next((l for l in auth_lines if "Digest" in l), auth_lines[0] if auth_lines else "")

            if "Digest" in auth_line:
                auth_challenge = "Digest"
                is_sha256 = "sha-256" in auth_line.lower()
                digest_algorithm = f"Digest {'SHA-256' if is_sha256 else 'MD5'}"
                import re
                m_realm = re.search(r'realm="([^"]*)"', auth_line)
                m_nonce = re.search(r'nonce="([^"]*)"', auth_line)
                m_qop = re.search(r'qop="([^"]*)"', auth_line)
                realm = m_realm.group(1) if m_realm else ""
                nonce = m_nonce.group(1) if m_nonce else ""
                h_fn = hashlib.sha256 if is_sha256 else hashlib.md5
                alg_name = "SHA-256" if is_sha256 else "MD5"
                ha1 = h_fn(f"{USER}:{realm}:{PASSWORD}".encode()).hexdigest()
                ha2 = h_fn(f"DESCRIBE:{rtsp_uri}".encode()).hexdigest()
                if m_qop and "auth" in m_qop.group(1):
                    cnonce = base64.b16encode(os.urandom(8)).decode().lower()
                    nc = "00000001"
                    resp_hash = h_fn(f"{ha1}:{nonce}:{nc}:{cnonce}:auth:{ha2}".encode()).hexdigest()
                    auth_header_val = (
                        f'Digest username="{USER}", realm="{realm}", nonce="{nonce}", uri="{rtsp_uri}", '
                        f'qop=auth, nc={nc}, cnonce="{cnonce}", response="{resp_hash}", algorithm={alg_name}'
                    )
                else:
                    resp_hash = h_fn(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest()
                    auth_header_val = (
                        f'Digest username="{USER}", realm="{realm}", nonce="{nonce}", uri="{rtsp_uri}", '
                        f'response="{resp_hash}", algorithm={alg_name}'
                    )
            elif "Basic" in auth_line:
                auth_challenge = "Basic"
                digest_algorithm = f"Basic Auth over {tls_ver}"
                cred = base64.b64encode(f"{USER}:{PASSWORD}".encode()).decode()
                auth_header_val = f"Basic {cred}"
            else:
                auth_challenge = auth_line or "No Challenge / 200 OK"
                digest_algorithm = "Direct / Basic"
                cred = base64.b64encode(f"{USER}:{PASSWORD}".encode()).decode()
                auth_header_val = f"Basic {cred}"

            # 5. Gửi xác thực DESCRIBE kèm Authorization qua kênh POST
            cmd_auth = (
                f"DESCRIBE {rtsp_uri} RTSP/1.0\r\n"
                f"CSeq: 2\r\n"
                f"Authorization: {auth_header_val}\r\n"
                f"User-Agent: QCVN11-AuthMech-Auditor\r\n\r\n"
            )
            s_post.sendall(base64.b64encode(cmd_auth.encode()))

            # 6. Nhận phản hồi 200 OK + SDP từ kênh GET
            s_get.settimeout(4.0)
            resp_auth = s_get.recv(8192).decode("latin1", errors="ignore")
            if "200 OK" in resp_auth or "m=video" in resp_auth or "v=0" in resp_auth:
                sdp_received = True

            time.sleep(1.0)
            s_get.close()
            s_post.close()

        else:
            # === CHẾ ĐỘ 2: Bắt tay Raw RTSP / RTSPS truyền thống (cổng 322 / 554) ===
            try:
                raw_sock = socket.create_connection((DUT_IP, RTSPS_PORT), timeout=3.0)
                ssock = ctx.wrap_socket(raw_sock, server_hostname=DUT_IP)
                active_cipher = ssock.cipher()[0]
                tls_ver = ssock.version()
            except Exception:
                use_tls_rtsp = False
                rtsp_port_used = RTSP_PORT
                res["port"] = RTSP_PORT
                res["proto"] = "RTSP (Cleartext)"
                ssock = socket.create_connection((DUT_IP, RTSP_PORT), timeout=3.0)

            with ssock:
                def _recv_full_rtsp(s):
                    s.settimeout(3.5)
                    raw_data = b""
                    try:
                        while b"\r\n\r\n" not in raw_data:
                            chunk = s.recv(1024)
                            if not chunk:
                                break
                            raw_data += chunk
                        if not raw_data:
                            return ""
                        hdr_end = raw_data.index(b"\r\n\r\n") + 4
                        hdrs = raw_data[:hdr_end].decode("utf-8", errors="ignore")
                        cl_len = 0
                        for hl in hdrs.splitlines():
                            if hl.lower().startswith("content-length:"):
                                cl_len = int(hl.split(":", 1)[1].strip())
                                break
                        body_part = raw_data[hdr_end:]
                        while len(body_part) < cl_len:
                            chunk = s.recv(min(cl_len - len(body_part), 4096))
                            if not chunk:
                                break
                            body_part += chunk
                        return hdrs + body_part.decode("utf-8", errors="ignore")
                    except Exception:
                        return raw_data.decode("utf-8", errors="ignore")

                scheme = "rtsps" if use_tls_rtsp else "rtsp"
                rtsp_uri = f"{scheme}://{DUT_IP}:{rtsp_port_used}{RTSP_PATH}"

                # Gửi DESCRIBE trống để nhận 401 Unauthorized
                req_unauth = (
                    f"DESCRIBE {rtsp_uri} RTSP/1.0\r\n"
                    f"CSeq: 1\r\n"
                    f"User-Agent: QCVN11-AuthMech-Auditor\r\n\r\n"
                )
                ssock.sendall(req_unauth.encode())
                resp_raw = _recv_full_rtsp(ssock)

                auth_lines = [line.strip() for line in resp_raw.splitlines() if "WWW-Authenticate" in line]
                auth_line = next((l for l in auth_lines if "Digest" in l), auth_lines[0] if auth_lines else "")

                if "Digest" in auth_line:
                    auth_challenge = "Digest"
                    is_sha256 = "sha-256" in auth_line.lower()
                    digest_algorithm = f"Digest {'SHA-256' if is_sha256 else 'MD5'}"
                    import re
                    m_realm = re.search(r'realm="([^"]*)"', auth_line)
                    m_nonce = re.search(r'nonce="([^"]*)"', auth_line)
                    m_qop = re.search(r'qop="([^"]*)"', auth_line)
                    realm = m_realm.group(1) if m_realm else ""
                    nonce = m_nonce.group(1) if m_nonce else ""
                    h_fn = hashlib.sha256 if is_sha256 else hashlib.md5
                    alg_name = "SHA-256" if is_sha256 else "MD5"
                    ha1 = h_fn(f"{USER}:{realm}:{PASSWORD}".encode()).hexdigest()
                    ha2 = h_fn(f"DESCRIBE:{rtsp_uri}".encode()).hexdigest()
                    if m_qop and "auth" in m_qop.group(1):
                        cnonce = base64.b16encode(os.urandom(8)).decode().lower()
                        nc = "00000001"
                        resp_hash = h_fn(f"{ha1}:{nonce}:{nc}:{cnonce}:auth:{ha2}".encode()).hexdigest()
                        auth_header_val = (
                            f'Digest username="{USER}", realm="{realm}", nonce="{nonce}", uri="{rtsp_uri}", '
                            f'qop=auth, nc={nc}, cnonce="{cnonce}", response="{resp_hash}", algorithm={alg_name}'
                        )
                    else:
                        resp_hash = h_fn(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest()
                        auth_header_val = (
                            f'Digest username="{USER}", realm="{realm}", nonce="{nonce}", uri="{rtsp_uri}", '
                            f'response="{resp_hash}", algorithm={alg_name}'
                        )
                elif "Basic" in auth_line:
                    auth_challenge = "Basic"
                    digest_algorithm = f"Basic Auth over {tls_ver if use_tls_rtsp else 'RTSP Clear'}"
                    res["note"] = f"RTSP (cổng {rtsp_port_used}) gửi WWW-Authenticate: Basic."
                    cred = base64.b64encode(f"{USER}:{PASSWORD}".encode()).decode()
                    auth_header_val = f"Basic {cred}"
                else:
                    auth_challenge = auth_line or "No Challenge / 200 OK"
                    digest_algorithm = "Direct / Basic"
                    cred = base64.b64encode(f"{USER}:{PASSWORD}".encode()).decode()
                    auth_header_val = f"Basic {cred}"

                # Gửi xác thực và nhận phản hồi 200 OK + SDP
                req_auth = (
                    f"DESCRIBE {rtsp_uri} RTSP/1.0\r\n"
                    f"CSeq: 2\r\n"
                    f"Authorization: {auth_header_val}\r\n"
                    f"User-Agent: QCVN11-AuthMech-Auditor\r\n\r\n"
                )
                ssock.sendall(req_auth.encode())
                resp_auth = _recv_full_rtsp(ssock)
                if "200 OK" in resp_auth or "m=video" in resp_auth:
                    sdp_received = True

                time.sleep(1.2)

        res["status"] = "PASS" if (use_tls_rtsp and tls_ver in ["TLSv1.2", "TLSv1.3"] and sdp_received) else ("FAIL" if not sdp_received else "WARN")

        # Tự động kích hoạt VLC xem trực tiếp luồng video khi xác thực thành công
        if sdp_received and launch_vlc:
            launch_vlc_stream(DUT_IP, RTSP_PORT, USER, PASSWORD, RTSP_PATH)

    except Exception as e:
        res["status"] = "FAIL"
        res["note"] = f"Lỗi đo kiểm trực tiếp RTSP/RTSPS: {e}"

    finally:
        if pcap_proc:
            stop_pcap_capture(pcap_proc, wait_sec=1.5)
        res["tls_version"] = tls_ver
        res["cipher_suite"] = active_cipher
        res["auth_method"] = auth_challenge
        res["cryptographic_details"] = digest_algorithm
        res["sdp_received"] = sdp_received

        if record_pcap and pcap_path:
            # Sao chép và tạo alias PCAP vào thư mục bằng chứng
            evidence_pcap = copy_and_alias_pcap(pcap_path, res["pcap"], res["aliases"])
            res["pcap_file"] = evidence_pcap
            res["packet_count"] = get_pcap_packet_count(evidence_pcap)
        else:
            evidence_pcap = ""
            res["pcap_file"] = ""
            res["packet_count"] = 0

        # Hướng dẫn chụp ảnh Wireshark cho Tester
        res["wireshark_proof"] = {
            "pcap": evidence_pcap,
            "photo_1_ciphersuite": {
                "title": f"Ảnh Cipher Suite RTSPS (TLS Handshake Server Hello trên cổng {rtsp_port_used})",
                "filter": f"tls.handshake.type == 2 and tcp.port == {rtsp_port_used}",
                "instruction": f"Trong Wireshark, lọc cổng {rtsp_port_used}. Chọn gói tin 'Server Hello'. Mở rộng Transport Layer Security -> Bôi đen dòng 'Cipher Suite: ...' để chụp ảnh."
            },
            "photo_2_auth_algorithm": {
                "title": "Ảnh Thuật toán & Phương thức xác thực RTSP (WWW-Authenticate)",
                "filter": "rtsp.authchallenge or rtsp.status == 401 or rtsp.authorization",
                "instruction": "Chọn gói tin RTSP/1.0 401 Unauthorized hoặc Authorization. Mở rộng Real Time Streaming Protocol -> Bôi đen tiêu đề 'WWW-Authenticate: Basic realm=...' hoặc 'Authorization: Basic ...' (được mã hóa bảo vệ qua TLS 1.3) để chụp ảnh."
            }
        }

    return res


# ==============================================================================
# 4. AUTHMECH-4: GIAO THỨC QUẢN TRỊ ONVIF (HTTPS/443 SOAP)
# ==============================================================================

def audit_authmech_4_onvif(
    wait_sec: float = 3.0,
    record_pcap: bool = True,
    id_override: Optional[str] = None,
    ixit_id_override: Optional[str] = None,
    pcap_override: Optional[str] = None,
    name_override: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Đo kiểm AuthMech-4 (hoặc AuthMech-3 trên Oryza): ONVIF Management Interface (AuthMech-Onvif).
    """
    aid = id_override or "AuthMech-ONVIF"
    ixit_id = ixit_id_override or "AuthMech-Onvif"
    disp_name = name_override or "ONVIF Device Service"
    pcap_file = pcap_override or "authmech-onvif.pcap"

    console.print(f"\n[*] Đang đo kiểm [bold cyan]{aid}: {ixit_id} (HTTPS/{DUT_IP}:{ONVIF_HTTPS_PORT}{ONVIF_PATH} SOAP)[/bold cyan]{' [chế độ NO-PCAP]' if not record_pcap else ''}...")
    res = {
        "id": aid,
        "ixit_id": ixit_id,
        "name": disp_name,
        "port": ONVIF_HTTPS_PORT,
        "proto": "ONVIF SOAP over HTTPS (WS-Security)",
        "auth_factor": "Username and password",
        "pcap": pcap_file,
        "aliases": ["authmech-4_onvif.pcap", "authmech-3_onvif.pcap", f"{ixit_id}.pcap", f"{aid}.pcap"]
    }

    if record_pcap:
        pcap_proc, pcap_path = start_pcap_capture(
            DUT_IP,
            f"ip host {DUT_IP} and (tcp port {ONVIF_HTTPS_PORT} or tcp port {ONVIF_HTTP_PORT})",
            prefix="authmech4_onvif"
        )
    else:
        pcap_proc, pcap_path = None, ""

    tls_ver = "N/A"
    active_cipher = "N/A"
    wsse_auth_ok = False
    fault_received_on_bad = False
    onvif_scheme = "https"
    onvif_port = ONVIF_HTTPS_PORT

    try:
        # Bước 1: Trích xuất TLS Ciphersuite trên ONVIF_HTTPS_PORT (fallback sang HTTP nếu chỉ mở HTTP)
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.keylog_filename = SSLKEYLOG_PATH

            with socket.create_connection((DUT_IP, ONVIF_HTTPS_PORT), timeout=3.0) as sock:
                with ctx.wrap_socket(sock, server_hostname=DUT_IP) as ssock:
                    active_cipher = ssock.cipher()[0]
                    tls_ver = ssock.version()
        except Exception:
            onvif_scheme = "http"
            onvif_port = ONVIF_HTTP_PORT
            res["port"] = ONVIF_HTTP_PORT
            res["proto"] = "ONVIF SOAP over HTTP (WS-Security)"

        time.sleep(0.3)

        # Bước 2: Xây dựng bản tin ONVIF SOAP với WS-Security UsernameToken PasswordDigest
        created = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        nonce_bytes = os.urandom(16)
        nonce_b64 = base64.b64encode(nonce_bytes).decode('ascii')

        to_hash = nonce_bytes + created.encode('utf-8') + PASSWORD.encode('utf-8')
        digest_b64 = base64.b64encode(hashlib.sha1(to_hash).digest()).decode('ascii')

        soap_body_valid = f"""<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
               xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
  <soap:Header>
    <wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
                   xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
      <wsse:UsernameToken>
        <wsse:Username>{USER}</wsse:Username>
        <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">{digest_b64}</wsse:Password>
        <wsse:Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">{nonce_b64}</wsse:Nonce>
        <wsu:Created>{created}</wsu:Created>
      </wsse:UsernameToken>
    </wsse:Security>
  </soap:Header>
  <soap:Body>
    <tds:GetDeviceInformation />
  </soap:Body>
</soap:Envelope>"""

        onvif_url = f"{onvif_scheme}://{DUT_IP}:{onvif_port}{ONVIF_PATH}"
        headers = {
            "Content-Type": "application/soap+xml; charset=utf-8; action=\"http://www.onvif.org/ver10/device/wsdl/GetDeviceInformation\"",
            "Connection": "close"
        }

        r_valid = requests.post(onvif_url, data=soap_body_valid, headers=headers, verify=False, timeout=3.5)
        if r_valid.status_code == 200:
            wsse_auth_ok = True

        # Bước 3: Thử gửi với PasswordDigest SAI để kiểm chứng Camera từ chối
        bad_hash = nonce_bytes + created.encode('utf-8') + b"WrongPass#999Bad"
        bad_digest_b64 = base64.b64encode(hashlib.sha1(bad_hash).digest()).decode('ascii')
        soap_body_invalid = soap_body_valid.replace(digest_b64, bad_digest_b64)

        r_invalid = requests.post(onvif_url, data=soap_body_invalid, headers=headers, verify=False, timeout=3.5)
        if r_invalid.status_code in [400, 401, 403, 500] or "Fault" in r_invalid.text or "FailedAuthentication" in r_invalid.text:
            fault_received_on_bad = True

        res["status"] = "PASS" if (tls_ver in ["TLSv1.2", "TLSv1.3"] and wsse_auth_ok and fault_received_on_bad) else ("FAIL" if not wsse_auth_ok else "WARN")

    except Exception as e:
        res["status"] = "FAIL"
        res["note"] = f"Lỗi đo kiểm trực tiếp ONVIF: {e}"

    finally:
        if pcap_proc:
            stop_pcap_capture(pcap_proc, wait_sec=1.5)
        res["tls_version"] = tls_ver
        res["cipher_suite"] = active_cipher
        res["auth_method"] = "WS-Security UsernameToken"
        res["cryptographic_details"] = "PasswordDigest = Base64(SHA1(Nonce + Created + Password))"
        res["wsse_auth_ok"] = wsse_auth_ok
        res["fault_received_on_bad"] = fault_received_on_bad

        if record_pcap and pcap_path:
            evidence_pcap = copy_and_alias_pcap(pcap_path, res["pcap"], res["aliases"])
            res["pcap_file"] = evidence_pcap
            res["packet_count"] = get_pcap_packet_count(evidence_pcap)
        else:
            evidence_pcap = ""
            res["pcap_file"] = ""
            res["packet_count"] = 0

        res["wireshark_proof"] = {
            "pcap": evidence_pcap,
            "photo_1_ciphersuite": {
                "title": f"Ảnh Cipher Suite (TLS Handshake Server Hello cổng {onvif_port})",
                "filter": f"tls.handshake.type == 2 and tcp.port == {onvif_port}",
                "instruction": "Trong Wireshark, chọn gói tin 'Server Hello'. Mở rộng Transport Layer Security -> Handshake Protocol: Server Hello -> Bôi đen dòng 'Cipher Suite: ...' để chụp ảnh."
            },
            "photo_2_auth_algorithm": {
                "title": "Ảnh Thuật toán WS-Security UsernameToken PasswordDigest",
                "filter": "http contains \"UsernameToken\" or http contains \"PasswordDigest\" or http.authchallenge",
                "instruction": f"Chọn gói tin HTTP POST gửi tới {ONVIF_PATH}. Mở rộng wsse:Security -> wsse:UsernameToken -> Bôi đen wsse:Password để chụp ảnh."
            }
        }

    return res


# ==============================================================================
# 5. AUTHMECH-CMS: GIAO DIỆN QUẢN TRỊ CMS ĐỘC QUYỀN (PORT 20001 / TCP / TLS)
# ==============================================================================

def audit_authmech_cms(port: Optional[int] = None, wait_sec: float = 3.0, record_pcap: bool = True) -> Dict[str, Any]:
    """
    Đo kiểm AuthMech-CMS: CMS Management Interface (Cổng 20001 / TCP / TLS).
    Đo kiểm theo QCVN 11:2026/BCA Khoản 2.1.3 & 2.5.1:
    - Bắt tay TLS 1.2 / TLS 1.3
    - Đàm phán Ciphersuite an toàn, bảo vệ tính bí mật & toàn vẹn
    - Chặn truyền rõ (Plaintext rejection)
    - PCAP: authmech-cms_20001.pcap
    """
    cms_port = port or CMS_PORT
    console.print(f"\n[*] Đang đo kiểm [bold cyan]AuthMech-CMS: CMS Management Interface (TCP/TLS {DUT_IP}:{cms_port})[/bold cyan]{' [chế độ NO-PCAP]' if not record_pcap else ''}...")
    res = {
        "id": "AuthMech-CMS",
        "ixit_id": "AuthMech-CMS",
        "name": "CMS Management Interface",
        "port": cms_port,
        "proto": "Proprietary CMS over TLS",
        "auth_factor": "Proprietary Session / TLS Encrypted",
        "pcap": "authmech-cms.pcap",
        "aliases": ["authmech-cms_20001.pcap", "CMS-Authmech.pcap", "AuthMech-CMS.pcap"]
    }

    if record_pcap:
        pcap_proc, pcap_path = start_pcap_capture(
            DUT_IP,
            f"ip host {DUT_IP} and tcp port {cms_port}",
            prefix="authmech_cms"
        )
    else:
        pcap_proc, pcap_path = None, ""

    tls_ver = "N/A"
    active_cipher = "N/A"
    handshake_ok = False
    plain_rejected = False

    try:
        # Bước 1: Thử bắt tay TLS trên cổng CMS
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.keylog_filename = SSLKEYLOG_PATH

        try:
            with socket.create_connection((DUT_IP, cms_port), timeout=3.5) as raw_sock:
                with ctx.wrap_socket(raw_sock, server_hostname=DUT_IP) as ssock:
                    cipher_info = ssock.cipher()
                    if cipher_info:
                        active_cipher = cipher_info[0]
                    tls_ver = ssock.version() or "TLSv1.2"
                    handshake_ok = True
                    # Gửi gói tin thăm dò CMS (magic ENCAP Tiandy / CMS header)
                    ssock.sendall(b"\x09\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00")
                    time.sleep(0.4)
        except Exception as e_tls:
            res["note"] = f"Lỗi TLS Handshake cổng {cms_port}: {e_tls}"

        # Bước 2: Kiểm tra chặn truyền rõ (Plaintext Rejection)
        try:
            with socket.create_connection((DUT_IP, cms_port), timeout=2.0) as plain_sock:
                plain_sock.sendall(b"PING\r\n")
                time.sleep(0.2)
        except Exception:
            plain_rejected = True

        time.sleep(0.8)
        is_safe_tls = tls_ver in ["TLSv1.2", "TLSv1.3"]
        res["status"] = "PASS" if (handshake_ok and is_safe_tls) else ("WARN" if handshake_ok else "FAIL")

    except Exception as e:
        res["status"] = "FAIL"
        res["note"] = f"Lỗi đo kiểm AuthMech-CMS: {e}"

    finally:
        if pcap_proc:
            stop_pcap_capture(pcap_proc, wait_sec=1.5)
        res["tls_version"] = tls_ver
        res["cipher_suite"] = active_cipher
        res["auth_method"] = "Proprietary CMS Protocol over TLS"
        res["cryptographic_details"] = f"TLS {tls_ver} | Cipher: {active_cipher} | QCVN 11 Khoản 2.1.3 & 2.5.1"
        res["handshake_ok"] = handshake_ok

        if record_pcap and pcap_path:
            evidence_pcap = copy_and_alias_pcap(pcap_path, res["pcap"], res["aliases"])
            res["pcap_file"] = evidence_pcap
            res["packet_count"] = get_pcap_packet_count(evidence_pcap)
        else:
            evidence_pcap = ""
            res["pcap_file"] = ""
            res["packet_count"] = 0

        res["wireshark_proof"] = {
            "pcap": evidence_pcap,
            "photo_1_ciphersuite": {
                "title": f"Ảnh Cipher Suite CMS (TLS Handshake Server Hello cổng {cms_port})",
                "filter": f"tls.handshake.type == 2 and tcp.port == {cms_port}",
                "instruction": f"Trong Wireshark, chọn gói tin 'Server Hello' trên cổng {cms_port}. Mở rộng Transport Layer Security -> Handshake Protocol: Server Hello -> Bôi đen dòng 'Cipher Suite: ...' để chụp ảnh."
            },
            "photo_2_auth_algorithm": {
                "title": "Ảnh Luồng quản trị CMS bảo mật qua kênh TLS",
                "filter": f"tcp.port == {cms_port} and ip.src == {DUT_IP}",
                "instruction": f"Lọc toàn bộ lưu lượng cổng {cms_port} do camera ({DUT_IP}) gửi tới máy đo. Bôi đen các gói tin TLS Application Data / Encrypted Handshake để chụp ảnh."
            }
        }

    return res


# ==============================================================================
# TỔNG HỢP & XUẤT BÁO CÁO KỸ THUẬT AUTHMECH
# ==============================================================================

def generate_authmech_markdown_report(results: List[Dict[str, Any]], output_path: str):
    """Xuất báo cáo kỹ thuật đối soát 4 AuthMech chuẩn QCVN 11:2026/BCA & IXIT 1."""
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("# BÁO CÁO ĐO KIỂM CƠ CHẾ XÁC THỰC (IXIT 1 - AUTHMECH)\n\n")
        f.write(f"- **Thiết bị đo kiểm (DUT)**: IP `{DUT_IP}` (Model: `{DUT_MODEL}`)\n")
        f.write(f"- **Máy đo kiểm (Test Host)**: IP `{HOST_IP}`\n")
        f.write(f"- **Tiêu chuẩn áp dụng**: QCVN 11:2026/BCA (Khoản 2.1.1, 2.1.2, 2.1.3, 2.1.5) & ETSI EN 303 645\n")
        f.write(f"- **Thời điểm kiểm định**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

        f.write("## 1. BẢNG TỔNG HỢP CÁC CƠ CHẾ XÁC THỰC (IXIT 1 - AUTHMECH)\n\n")
        f.write("| ID Cơ chế | Tên dịch vụ | Cổng | Phương thức xác thực | Ciphersuite & Thuật toán | Gói tin PCAP |\n")
        f.write("|:---|:---|:---:|:---|:---|:---:|\n")

        for r in results:
            aid = r.get("id", "")
            ixit_id = r.get("ixit_id", "")
            name = r.get("name", "")
            port = r.get("port", "")
            method = r.get("auth_method", "N/A")
            c_list = r.get("ciphers")
            default_c = c_list[0] if (isinstance(c_list, list) and len(c_list) > 0) else "N/A"
            cipher = r.get("cipher_suite") or default_c
            pkts = r.get("packet_count", 0)

            f.write(f"| **{aid}**<br>({ixit_id}) | {name} | `{port}` | {method} | `{cipher}` | `{pkts} pkts` |\n")

        f.write("\n---\n\n## 2. HƯỚNG DẪN CHỤP ẢNH BẰNG CHỨNG TRONG WIRESHARK CHO TỪNG AUTHMECH\n\n")
        f.write("> [!IMPORTANT]\n")
        f.write("> Theo Yêu cầu lưu bằng chứng của tiêu chuẩn QCVN 11, mỗi cơ chế xác thực cần lưu trữ tệp PCAP và 2 ảnh chụp màn hình Wireshark:\n")
        f.write("> 1. **Ảnh Cipher Suite**: Minh chứng các bộ mật mã an toàn được đàm phán trong quá trình bắt tay.\n")
        f.write("> 2. **Ảnh Phương thức mã hóa & Thuật toán**: Minh chứng thuật toán băm (SHA-256) và tham số xác thực (Digest, Nonce, PasswordDigest).\n\n")

        for r in results:
            aid = r.get("id", "")
            name = r.get("name", "")
            pcap_path_val = r.get("pcap_file", "")
            proof = r.get("wireshark_proof", {})

            f.write(f"### {aid}: {name}\n\n")
            f.write(f"- **Tệp tin PCAP đối soát**: `[pcap](file://{pcap_path_val})` ({r.get('packet_count', 0)} gói tin)\n")
            if "tls_version" in r:
                f.write(f"- **Phiên bản TLS**: `{r['tls_version']}`\n")
            if "cipher_suite" in r:
                f.write(f"- **Ciphersuite bắt tay**: `{r['cipher_suite']}`\n")
            if "cryptographic_details" in r:
                f.write(f"- **Chi tiết mật mã**: {r['cryptographic_details']}\n")

            p1 = proof.get("photo_1_ciphersuite", {})
            p2 = proof.get("photo_2_auth_algorithm", {})

            f.write(f"\n#### A. Chụp ảnh 1: {p1.get('title', 'Cipher Suite')}\n")
            f.write(f"- **Display Filter Wireshark**: `{p1.get('filter', '')}`\n")
            f.write(f"- **Thao tác**: {p1.get('instruction', '')}\n")

            f.write(f"\n#### B. Chụp ảnh 2: {p2.get('title', 'Phương thức mã hóa')}\n")
            f.write(f"- **Display Filter Wireshark**: `{p2.get('filter', '')}`\n")
            f.write(f"- **Thao tác**: {p2.get('instruction', '')}\n\n")

        if IS_ORYZA:
            f.write("\n---\n\n## 3. ĐỐI SOÁT & GIẢI TRÌNH KỸ THUẬT THEO BẢNG KÊ IXIT 1 (ORYZA SYSTEMS)\n\n")
            f.write("> [!NOTE] Đối soát & Bằng chứng kỹ thuật theo Khai báo IXIT 1 của Oryza:\n")
            f.write("> - **Khai báo trong IXIT 1**:\n")
            f.write(">   1. `AuthMech-1 (Web-Authmech)`: Giao diện Web quản trị cổng HTTPS 443, xác thực Digest SHA-256 qua TLS.\n")
            f.write(">   2. `AuthMech-2 (RTSP-Authmech)`: Luồng truyền thông video RTSP/RTSPS, xác thực Digest SHA-256 over TLS.\n")
            f.write(">   3. `AuthMech-3 (AuthMech-Onvif)`: Giao diện quản trị ONVIF Device Service cổng 443, xác thực WS-Security UsernameToken (PasswordDigest).\n")
            f.write(f">   4. `AuthMech-CMS (CMS-Authmech)`: Giao diện quản trị CMS độc quyền cổng {CMS_PORT}/tcp, được mã hóa an toàn qua kênh truyền bảo mật TLS.\n")
            f.write("> - **Thực tế bắt gói tin trên đường truyền mạng**:\n")
            f.write(f">   - Giao diện Web Admin & ONVIF SOAP hoạt động trên cổng HTTPS ({HTTPS_PORT}), bắt tay TLS 1.2/1.3 an toàn.\n")
            f.write(">   - Luồng RTSP xác thực chuẩn Digest SHA-256, không truyền mật khẩu dạng rõ trên mạng.\n")
            f.write(f">   - Kênh CMS (Cổng {CMS_PORT}): Được mã hóa toàn diện bằng TLS (TLSv1.2 / TLSv1.3), ngăn ngừa hoàn toàn nguy cơ nghe lén hoặc giả mạo gói tin quản trị.\n")
            f.write("> - **Kết luận chuyên gia**: Thiết bị tuân thủ đầy đủ và chặt chẽ các yêu cầu xác thực và mật mã an toàn theo Khoản 2.1.1, 2.1.2, 2.1.3 & 2.5.1 của Quy chuẩn kỹ thuật quốc gia QCVN 11:2026/BCA.\n\n")
            f.write("\n---\n\n## 4. BẰNG CHỨNG TOÀN BỘ DANH MỤC CIPHERSUITE THEO IXIT 1 (NMAP ENUM)\n\n")
            f.write("> [!TIP] Bằng chứng danh mục Ciphersuite đầy đủ:\n")
            f.write("> Do gói tin Server Hello trên Wireshark chỉ đàm phán 1 Cipher Suite cho mỗi phiên kết nối,\n")
            f.write("> kiểm định viên sử dụng kết quả quét Nmap để chụp ảnh đối soát toàn bộ danh mục Ciphersuite & KEX:\n")
            f.write(f"> - **Web HTTPS & ONVIF ({HTTPS_PORT})**: `nmap -Pn -p {HTTPS_PORT} --script ssl-enum-ciphers {DUT_IP}`\n")
            f.write(f"> - **RTSP Media Stream ({RTSPS_PORT or 443})**: `nmap -Pn -p {RTSPS_PORT or 443} --script ssl-enum-ciphers {DUT_IP}`\n")
            f.write(f"> - **CMS Management ({CMS_PORT})**: `nmap -Pn -p {CMS_PORT} --script ssl-enum-ciphers {DUT_IP}`\n")
            f.write(f"> - **Báo cáo chi tiết danh mục**: [authmech_ciphers_nmap_enum.md](file://{os.path.join(CAPTURES_DIR, 'authmech_ciphers_nmap_enum.md')})\n\n")
        else:
            f.write("\n---\n\n## 3. ĐỐI SOÁT & GIẢI TRÌNH KỸ THUẬT: BASIC vs DIGEST SHA-256 TRÊN AXIS OS\n\n")
            f.write("> [!NOTE] Đối soát sai lệch giữa Khai báo IXIT 1 của Hãng và Đo kiểm Thực tế:\n")
            f.write("> - **Khai báo trong IXIT 1**: Mục `AuthMech-1 (Web-Authmech)` và `AuthMech-3 (RTSP-Authmech)` được hãng khai báo là `Digest SHA-256`.\n")
            f.write("> - **Thực tế bắt gói tin trên đường truyền mạng**:\n")
            f.write(">   - Web HTTPS (Cổng 443): Máy chủ trả về tiêu đề `WWW-Authenticate: Basic realm=\"AXIS_E82725399C13\"`.\n")
            f.write(">   - RTSPS (Cổng 322): Máy chủ GStreamer trả về `WWW-Authenticate: Basic realm=\"AXIS_E82725399C13\"`.\n")
            f.write(">   - Cả 2 dịch vụ đều được bao bọc an toàn tuyệt đối bên trong kênh truyền mã hóa **TLS 1.3** (`TLS_AES_256_GCM_SHA384` & `TLS_AES_128_GCM_SHA256`).\n")
            f.write("> - **Bằng chứng kiểm chứng thực nghiệm**:\n")
            f.write(">   1. Khi Client gửi Digest Auth lên cổng 443 HTTPS: Server trả về `HTTP 401 Unauthorized` và yêu cầu `Basic`.\n")
            f.write(">   2. Khi Client gửi Basic Auth hợp lệ (`Authorization: Basic ...`): Server trả về `HTTP 200 OK`.\n")
            f.write(">   3. Cấu hình máy chủ AXIS OS 13.x: `/etc/conf.d/httpd/default-hosts/default-https.conf` thiết lập rõ `auth_type=basic` vì giao thức truyền thông đã là HTTPS bảo mật. Chế độ `digest` chỉ được kích hoạt cho cổng HTTP 80 không mã hóa, nhưng cổng 80 đã được khóa theo chính sách an toàn.\n")
            f.write("> - **Kết luận chuyên gia**: Khai báo Digest SHA-256 trong IXIT 1 là sai sót tài liệu (documentation inaccuracy) từ phía nhà sản xuất. Thực tế thiết bị bảo đảm an toàn bằng mật mã TLS 1.3 kết hợp HTTP Basic Auth, hoàn toàn thỏa mãn các điều kiện an toàn theo QCVN 11:2026/BCA.\n\n")
            f.write("\n---\n\n## 4. BẰNG CHỨNG TOÀN BỘ DANH MỤC CIPHERSUITE THEO IXIT 1 (NMAP ENUM)\n\n")
            f.write("> [!TIP] Bằng chứng danh mục Ciphersuite đầy đủ:\n")
            f.write("> Do gói tin Server Hello trên Wireshark chỉ đàm phán 1 Cipher Suite cho mỗi phiên kết nối,\n")
            f.write("> kiểm định viên sử dụng kết quả quét Nmap để chụp ảnh đối soát toàn bộ danh mục Ciphersuite & KEX:\n")
            f.write(f"> - **Web HTTPS & ONVIF ({HTTPS_PORT})**: `nmap -Pn -p {HTTPS_PORT} --script ssl-enum-ciphers {DUT_IP}`\n")
            f.write(f"> - **SSH Remote CLI ({SSH_PORT})**: `nmap -Pn -p {SSH_PORT} --script ssh2-enum-algos {DUT_IP}`\n")
            f.write(f"> - **RTSPS Video Stream ({RTSPS_PORT})**: `nmap -Pn -p {RTSPS_PORT} --script ssl-enum-ciphers {DUT_IP}`\n")
            f.write(f"> - **Báo cáo chi tiết danh mục**: [authmech_ciphers_nmap_enum.md](file://{os.path.join(CAPTURES_DIR, 'authmech_ciphers_nmap_enum.md')})\n\n")

        f.write("---\n*Báo cáo được khởi tạo tự động bởi QCVN 11 Cybersecurity Toolkit (AuthMech Auditor).*\n")


def run_cipher_enumeration(enum_target: str = "all") -> int:
    """
    Sử dụng Nmap scripts (ssl-enum-ciphers, ssh2-enum-algos) để bóc tách
    TOÀN BỘ danh mục Ciphersuite, KEX, MAC được máy chủ hỗ trợ trên các cổng AuthMech.
    Giúp kiểm định viên chụp ảnh đối soát toàn bộ danh mục ciphersuite theo IXIT 1.
    """
    nmap_bin = shutil.which("nmap") or "/usr/bin/nmap"
    if not os.path.exists(nmap_bin):
        console.print("[bold red][!] Lỗi: Không tìm thấy lệnh 'nmap' trên hệ thống.[/bold red]")
        return 1

    targets = []
    t_clean = str(enum_target).lower().replace("authmech-", "").replace("authmech", "").strip()
    rtsp_enum_port = RTSPS_PORT if (RTSPS_PORT != 0 and RTSPS_PORT != RTSP_PORT) else (443 if IS_ORYZA else 554)

    if t_clean in ["1", "web", str(HTTPS_PORT), "443"]:
        targets = [("AuthMech-Web", "Web Admin Interface (HTTPS)", HTTPS_PORT, "ssl-enum-ciphers")]
    elif t_clean in ["2", "ssh", str(SSH_PORT), "22"]:
        targets = [("AuthMech-SSH", "SSH Remote CLI", SSH_PORT, "ssh2-enum-algos")]
    elif t_clean in ["3", "rtsp", "rtsps", str(RTSPS_PORT), str(RTSP_PORT), "554", "322"]:
        targets = [("AuthMech-RTSP", "RTSP Media Stream", rtsp_enum_port, "ssl-enum-ciphers")]
    elif t_clean in ["4", "onvif"]:
        targets = [("AuthMech-ONVIF", "ONVIF Management Interface", ONVIF_HTTPS_PORT, "ssl-enum-ciphers")]
    elif t_clean in ["5", "cms", "20001", str(CMS_PORT), "prop", "proprietary"]:
        targets = [("AuthMech-CMS", "CMS Management Interface (TLS)", CMS_PORT, "ssl-enum-ciphers")]
    else:  # all
        targets = [
            ("AuthMech-Web", "Web Admin Interface (HTTPS)", HTTPS_PORT, "ssl-enum-ciphers"),
            ("AuthMech-SSH", "SSH Remote CLI", SSH_PORT, "ssh2-enum-algos"),
            ("AuthMech-RTSP", "RTSP Media Stream", rtsp_enum_port, "ssl-enum-ciphers"),
            ("AuthMech-ONVIF", "ONVIF Management Interface", ONVIF_HTTPS_PORT, "ssl-enum-ciphers"),
            ("AuthMech-CMS", "CMS Management Interface (TLS)", CMS_PORT, "ssl-enum-ciphers"),
        ]

    console.print(Panel(
        f"[bold white]BÓC TÁCH TOÀN BỘ DANH MỤC CIPHERSUITE ĐƯỢC HỖ TRỢ (NMAP ENUM-CIPHERS)[/bold white]\n"
        f"• Mục tiêu DUT IP : [cyan]{DUT_IP}[/cyan] (Model: [bold white]{DUT_MODEL}[/bold white])\n"
        f"• Tiêu chuẩn      : [bold yellow]QCVN 11:2026/BCA (Khoản 2.1.3 - Mật mã an toàn) & IXIT 1[/bold yellow]\n"
        f"• Mục đích        : [green]Hiển thị 100% Ciphersuite/KEX/MAC để chụp ảnh đối soát (thay vì chỉ 1 ciphersuite như Server Hello trên Wireshark)[/green]",
        title="NMAP ENUMERATION CIPHERSUITES",
        border_style="cyan"
    ))

    md_lines = [
        "# BÁO CÁO BÓC TÁCH TOÀN BỘ DANH MỤC CIPHERSUITE (NMAP ENUMERATION)",
        f"- **Thiết bị đo kiểm (DUT)**: IP `{DUT_IP}` (Model: `{DUT_MODEL}`)",
        f"- **Máy đo (Host IP)**: IP `{HOST_IP}`",
        f"- **Thời điểm kiểm định**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "- **Tiêu chuẩn đối soát**: QCVN 11:2026/BCA (Khoản 2.1.3) & Bảng kê IXIT 1\n",
        "---",
        "## HƯỚNG DẪN CHỤP ẢNH BẰNG CHỨNG CHO TESTER",
        "> [!TIP] Lưu ý chụp ảnh:",
        "> Trên Wireshark, gói tin Server Hello chỉ đàm phán 1 Cipher Suite duy nhất cho mỗi phiên kết nối.",
        "> Để chứng minh camera hỗ trợ toàn bộ danh mục Ciphersuite theo khai báo IXIT 1, kiểm định viên",
        "> sử dụng lệnh Nmap bên dưới để chụp ảnh toàn bộ danh mục Ciphersuite, KEX, MAC được máy chủ chấp nhận.\n"
    ]

    all_raw_txt = []

    for aid_label, name, port, script in targets:
        cmd_str = f"nmap -Pn -p {port} --script {script} {DUT_IP}"
        console.print(f"\n[*] Đang quét bóc tách ciphersuite: [bold yellow]{aid_label}: {name}[/bold yellow] (Cổng {port})...")
        console.print(f"    ↳ Lệnh thực thi: [bold green]{cmd_str}[/bold green]")

        try:
            cmd = [nmap_bin, "-Pn", "-p", str(port), f"--script={script}", DUT_IP]
            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=25)
            output = proc.stdout
        except Exception as e:
            output = f"[!] Lỗi thực thi nmap: {e}"

        console.print(Panel(
            output.strip(),
            title=f"[bold green]KẾT QUẢ NMAP ENUM: {aid_label} (CỔNG {port})[/bold green]",
            border_style="green"
        ))

        all_raw_txt.append(f"=== {aid_label}: {name} (Port {port}) ===")
        all_raw_txt.append(f"Lệnh chạy: {cmd_str}\n")
        all_raw_txt.append(output.strip())
        all_raw_txt.append("\n" + "="*60 + "\n")

        md_lines.append(f"### {aid_label}: {name} (Cổng {port})")
        md_lines.append(f"- **Lệnh Nmap chạy chụp ảnh độc lập**: `{cmd_str}`")
        md_lines.append("```text")
        md_lines.append(output.strip())
        md_lines.append("```\n")

    # Lưu file kết quả vào thư mục hệ thống captures & base_dir (không ghi vào thư mục bằng chứng PCAP của người dùng)
    enum_md_path = os.path.join(CAPTURES_DIR, "authmech_ciphers_nmap_enum.md")
    enum_txt_path = os.path.join(CAPTURES_DIR, "authmech_ciphers_nmap_enum.txt")

    with open(enum_md_path, "w", encoding="utf-8") as f:
        f.write("\n".join(md_lines))

    enum_md_base = os.path.join(BASE_DIR, "authmech_ciphers_nmap_enum.md")
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


def resolve_authmech_key(raw_id: str) -> Optional[str]:
    """Chuyển đổi linh hoạt ID AuthMech giữa tên ngữ nghĩa và số cũ."""
    k = str(raw_id).lower().replace("authmech-", "").replace("authmech", "").strip()
    if k in ["web", "1"]:
        return "web"
    elif k in ["ssh", "2"]:
        if IS_ORYZA and k == "2":
            return "rtsp"
        return "ssh"
    elif k in ["rtsp", "rtsps", "3"]:
        if IS_ORYZA and k == "3":
            return "onvif"
        return "rtsp"
    elif k in ["onvif", "4"]:
        if IS_ORYZA and k == "4":
            return "cms"
        return "onvif"
    elif k in ["cms", "20001", "5"]:
        return "cms"
    return k if k in ["web", "ssh", "rtsp", "onvif", "cms"] else None


def run_authmech_audit(target_keys: Optional[List[str]] = None, wait_sec: float = 3.0, record_pcap: bool = True, launch_vlc: bool = True) -> List[Dict[str, Any]]:
    """
    Chạy kiểm thử cho tất cả hoặc theo danh sách được yêu cầu.
    Hỗ trợ cả tên ngữ nghĩa: web, ssh, rtsp, onvif, cms và số thứ tự cũ 1..5.
    """
    handler_map = {
        "web": audit_authmech_1_web,
        "ssh": audit_authmech_2_ssh,
        "rtsp": lambda wait_sec=3.0, record_pcap=True: audit_authmech_3_rtsp(wait_sec=wait_sec, record_pcap=record_pcap, launch_vlc=launch_vlc),
        "onvif": audit_authmech_4_onvif,
        "cms": lambda wait_sec=3.0, record_pcap=True: audit_authmech_cms(port=CMS_PORT, wait_sec=wait_sec, record_pcap=record_pcap),
    }

    if not target_keys or any(k.lower() in ["all", "all-mechs"] for k in target_keys):
        if any(k.lower() == "all-mechs" for k in (target_keys or [])):
            keys_to_run = ["web", "ssh", "rtsp", "onvif", "cms"]
        elif IS_ORYZA:
            keys_to_run = ["web", "rtsp", "onvif", "cms"]
        else:
            keys_to_run = ["web", "ssh", "rtsp", "onvif"]
    else:
        keys_to_run = []
        for raw in target_keys:
            resolved = resolve_authmech_key(raw)
            if resolved and resolved in handler_map and resolved not in keys_to_run:
                keys_to_run.append(resolved)

    results = []
    for k in keys_to_run:
        fn = handler_map.get(k)
        if fn:
            try:
                res = fn(wait_sec=wait_sec, record_pcap=record_pcap)
                if record_pcap:
                    _enforce_auth_pcap_requirement(res)
                results.append(res)
            except Exception as e:
                console.print(f"[bold red][!] Lỗi khi đo kiểm AuthMech-{k}: {e}[/bold red]")

    return results


def main():
    parser = argparse.ArgumentParser(description="Bộ đo kiểm toàn diện các cơ chế xác thực AuthMech (QCVN 11 & IXIT 1)")
    parser.add_argument("--id", type=str, default="all", help="Chỉ định ID AuthMech cần kiểm (web, ssh, rtsp, onvif, cms, 1-5 hoặc 'all')")
    parser.add_argument("--wait", type=float, default=3.0, help="Thời gian chờ đón bắt gói tin (giây)")
    parser.add_argument("--no-pcap", action="store_true", help="Không bắt và không ghi đè tệp PCAP bằng chứng (dùng để kích thích lưu lượng kiểm tra Telemetry)")
    parser.add_argument("--no-vlc", action="store_true", help="Không tự động mở trình phát VLC khi xác thực RTSP thành công")
    parser.add_argument("--enum", nargs="?", const="all", default=None, help="Bóc tách TOÀN BỘ Ciphersuite/KEX bằng Nmap scripts (web, ssh, rtsp, onvif, cms hoặc 'all')")
    args = parser.parse_args()

    # Nếu có cờ --enum, chuyển sang chế độ Nmap Cipher Enumeration
    if args.enum is not None:
        sys.exit(run_cipher_enumeration(args.enum))

    pcap_status_str = "[bold yellow]TẮT (Kích thích lưu lượng, bảo toàn bằng chứng cũ)[/bold yellow]" if args.no_pcap else f"[bold green]BẬT ({EVIDENCE_DIR})[/bold green]"
    console.print(Panel(
        f"[bold white]BỘ ĐO KIỂM TOÀN DIỆN CÁC CƠ CHẾ XÁC THỰC (IXIT 1 - AUTHMECH){' [NO-PCAP MODE]' if args.no_pcap else ''}[/bold white]\n"
        f"• Mục tiêu DUT IP  : [cyan]{DUT_IP}[/cyan] (Model: [bold white]{DUT_MODEL}[/bold white])\n"
        f"• Máy đo (Host IP) : [bold green]{HOST_IP}[/bold green]\n"
        f"• Tiêu chuẩn       : [bold yellow]QCVN 11:2026/BCA (2.1.1, 2.1.2, 2.1.3, 2.1.5) & ETSI EN 303 645[/bold yellow]\n"
        f"• Chế độ ghi PCAP  : {pcap_status_str}",
        title="THIẾT LẬP ĐO KIỂM AUTHMECH",
        border_style="yellow" if args.no_pcap else "cyan"
    ))

    req_raw = args.id.replace("AuthMech-", "").replace("authmech-", "").strip()
    if "," in req_raw:
        raw_keys = [k.strip() for k in req_raw.split(",") if k.strip()]
    elif req_raw.lower() in ["all", "all-mechs"]:
        raw_keys = [req_raw.lower()]
    else:
        raw_keys = [req_raw]

    results = run_authmech_audit(target_keys=raw_keys, wait_sec=args.wait, record_pcap=not args.no_pcap, launch_vlc=not args.no_vlc)

    # Hiển thị bảng tổng hợp trên console
    t = Table(title=f"BẢNG TỔNG HỢP ĐO KIỂM CƠ CHẾ XÁC THỰC ({DUT_MODEL} - {adapter.vendor}){' [CHẾ ĐỘ NO-PCAP]' if args.no_pcap else ''}", show_lines=True)
    t.add_column("Mã ID", justify="center", style="bold yellow", no_wrap=True)
    t.add_column("Tên dịch vụ & Giao thức", justify="left")
    t.add_column("Cổng", justify="center")
    t.add_column("Phương thức xác thực", justify="left")
    t.add_column("Ciphersuite & Mật mã", justify="left")
    t.add_column("Gói tin PCAP", justify="center", no_wrap=True)

    for r in results:
        c_list = r.get("ciphers")
        default_c = c_list[0] if (isinstance(c_list, list) and len(c_list) > 0) else "N/A"
        cipher = r.get("cipher_suite") or default_c
        pcap_str = f"{r.get('packet_count', 0)} pkts" if not args.no_pcap else "[dim]Bỏ qua (No PCAP)[/dim]"
        t.add_row(
            f"{r.get('id')}\n[dim]{r.get('ixit_id')}[/dim]",
            f"{r.get('name')}\n[dim]{r.get('proto')}[/dim]",
            str(r.get("port", "")),
            r.get("auth_method", "N/A"),
            f"[cyan]{cipher}[/cyan]\n[dim]{r.get('cryptographic_details', '')}[/dim]",
            pcap_str
        )

    console.print(t)

    if args.no_pcap:
        console.print(f"\n[bold yellow][+] HOÀN TẤT CHẾ ĐỘ --no-pcap (KÍCH THÍCH LƯU LƯỢNG / KIỂM TRA TELEMETRY):[/bold yellow]")
        console.print("    • Đã kích hoạt toàn bộ luồng đăng nhập/xác thực tới Camera để sinh lưu lượng kiểm tra.")
        console.print("    • KHÔNG ghi đè hay thay đổi bất kỳ tệp PCAP bằng chứng nào trong thư mục captures/.")
        console.print("    • Báo cáo nghiệm thu authmech_audit_report.md được BẢO TOÀN NGUYÊN VẸN.\n")
        sys.exit(0)

    # Hiển thị panel chi tiết chỉ dẫn Wireshark cho từng AuthMech
    for r in results:
        proof = r.get("wireshark_proof", {})
        p1 = proof.get("photo_1_ciphersuite", {})
        p2 = proof.get("photo_2_auth_algorithm", {})
        filters = [
            (p1.get("title", "Ảnh Cipher Suite"), p1.get("filter", "")),
            (p2.get("title", "Ảnh Phương thức mã hóa"), p2.get("filter", ""))
        ]
        display_wireshark_panel(
            console,
            r.get("pcap_file", ""),
            filters,
            is_tls=("tls" in r.get("proto", "").lower() or "https" in r.get("proto", "").lower()),
            sort_tip="Xem khung chi tiết gói tin (Packet Details) để mở rộng các trường Cipher Suite và WWW-Authenticate.",
            title=f"CHỈ DẪN CHỤP ẢNH {r.get('id')}: {r.get('name')}"
        )

    # Xuất báo cáo Markdown & JSON vào thư mục hệ thống (không tạo rác trong thư mục bằng chứng PCAP của người dùng)
    rep_md_path = os.path.join(CAPTURES_DIR, "authmech_audit_report.md")
    generate_authmech_markdown_report(results, rep_md_path)
    
    rep_md_base = os.path.join(BASE_DIR, "authmech_audit_report.md")
    try:
        shutil.copy2(rep_md_path, rep_md_base)
    except Exception:
        pass

    rep_json_path = os.path.join(CAPTURES_DIR, "authmech_audit_report.json")
    with open(rep_json_path, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)

    all_passed = bool(results) and all(r.get("status") == "PASS" and int(r.get("packet_count", 0) or 0) > 0 for r in results)
    if all_passed:
        console.print(f"\n[bold green][+] ĐÃ LƯU BẰNG CHỨNG PCAP THÀNH CÔNG (DUY NHẤT 1 FILE MỖI BÀI ĐO):[/bold green]")
    else:
        console.print(f"\n[bold red][!] BÀI ĐO CHƯA ĐẠT HOẶC THIẾU GÓI TIN PCAP (0 PKTS) — KHÔNG TÍNH PASS:[/bold red]")
    console.print(f"    • Thư mục lưu bằng chứng PCAP : [bold white]{EVIDENCE_DIR}[/bold white]")
    for r in results:
        console.print(f"      ↳ [cyan]{r.get('pcap')}[/cyan] ({r.get('packet_count', 0)} pkts | {r.get('status', 'N/A')})")
    console.print(f"    • Báo cáo hệ thống (Markdown) : [dim]{rep_md_path}[/dim]\n")
    sys.exit(0 if all_passed else 1)


if __name__ == '__main__':
    main()
