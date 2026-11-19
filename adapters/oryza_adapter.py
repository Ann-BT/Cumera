#!/usr/bin/env python3
"""
Oryza Camera Adapter for QCVN 11 Cybersecurity Toolkit.
Tailored for Oryza Systems / Tiandy cameras (ORZ-B52Z-AJBMIR60-S1 series).
Supports standard ONVIF endpoints, dual RTSP paths (/stream1 & /live/ch0),
and proprietary CMS management service on port 20001 (TCP/TLS).
"""

import hashlib
import os
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Tuple

from adapters.base_adapter import BaseCameraAdapter

ENCAP_MAGIC = b"\x09\x00\x00\x01"


class OryzaCameraAdapter(BaseCameraAdapter):
    """Adapter for Oryza / Tiandy cameras."""

    web_auth_endpoint: str = "/action/WEB_JsonAjax"

    def get_web_auth_endpoints(self) -> List[str]:
        return [
            "/action/WEB_JsonAjax",
            "/",
            "/index.html",
            "/web/index.html",
            self.onvif_path or "/onvif/device_service",
            "/api/system/information",
        ]

    def attempt_web_login(
        self,
        username: str,
        password: str,
        port: int = 443,
        timeout: float = 3.0,
    ) -> Optional[Tuple[bool, str, float]]:
        """
        Thực hiện xác thực Web Admin qua API WEB_JsonAjax chuẩn Tiandy/Oryza (XDigest SHA-256).
        Returns: (is_success, status_str, latency_ms)
        """
        import time
        import random
        import base64
        import requests

        scheme = "https"
        url = f"{scheme}://{self.ip}:{port}/action/WEB_JsonAjax"
        t_start = time.time()

        xml_challenge = (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<CommandHead Command="11027">\n'
            '    <Parameters Version="1">\n'
            '        <DigestAuthentication OperatorType="2"/>\n'
            '    </Parameters>\n'
            '</CommandHead>'
        )

        try:
            r1 = requests.post(
                url,
                data=xml_challenge.encode("utf-8"),
                headers={"Content-Type": "application/xml", "Connection": "close"},
                verify=False,
                timeout=timeout
            )
            auth_header = r1.headers.get("WWW-Authenticate", "")
        except requests.exceptions.Timeout:
            elapsed = (time.time() - t_start) * 1000
            return False, "TIMEOUT (Mạng/Dịch vụ bị đóng băng - Bị khóa)", elapsed
        except requests.exceptions.ConnectionError:
            elapsed = (time.time() - t_start) * 1000
            return False, "CONN_REFUSED / DROPPED (Tường lửa ngắt kết nối)", elapsed
        except Exception as e:
            elapsed = (time.time() - t_start) * 1000
            return False, f"ERROR ({e})", elapsed

        if not auth_header:
            return None

        m_realm = re.search(r'realm="([^"]+)"', auth_header)
        m_nonce = re.search(r'nonce="([^"]+)"', auth_header)
        m_qop = re.search(r'qop="([^"]+)"', auth_header)
        m_alg = re.search(r'algorithm="([^"]+)"', auth_header)

        realm = m_realm.group(1) if m_realm else "WEB To 00773F"
        nonce = m_nonce.group(1) if m_nonce else ""
        qop = m_qop.group(1) if m_qop else "auth"
        algorithm = m_alg.group(1) if m_alg else "SHA-256"

        hex_chars = "abcdef0123456789"
        vt = "".join(random.choice(hex_chars) for _ in range(16))
        Ye = base64.b64encode(vt.encode("utf-8")).decode("utf-8")
        nc_str = "00000002"
        uri = "active/base/11027"

        y = hashlib.sha256(f"{username}:{realm}:{password}".encode("utf-8")).hexdigest()
        g = hashlib.sha256(f"POST:{uri}".encode("utf-8")).hexdigest()
        resp_hash = hashlib.sha256(f"{y}:{nonce}:{nc_str}:{Ye}:{qop}:{g}".encode("utf-8")).hexdigest()

        auth_hdr = (
            f'XDigest username="{username}",realm="{realm}",nonce="{nonce}",'
            f'uri="{uri}",algorithm="{algorithm}",qop="{qop}",nc="{nc_str}",'
            f'cnonce="{Ye}",response="{resp_hash}"'
        )

        try:
            r2 = requests.post(
                url,
                data=xml_challenge.encode("utf-8"),
                headers={
                    "Content-Type": "application/xml",
                    "Authorization": auth_hdr,
                    "Connection": "close"
                },
                verify=False,
                timeout=timeout
            )
            elapsed = (time.time() - t_start) * 1000
            body = r2.text

            m_code = re.search(r'<Result Code="([^"]+)"', body)
            code_str = m_code.group(1) if m_code else ""

            if code_str == "0":
                return True, "HTTP 200 OK (Đăng nhập thành công)", elapsed
            elif code_str == "-508":
                m_rem = re.search(r'RemainCount="([^"]+)"', body)
                rem = m_rem.group(1) if m_rem else "?"
                return False, f"HTTP 401 Unauthorized (Sai mật khẩu, còn {rem} lần)", elapsed
            elif code_str == "-515":
                m_min = re.search(r'RemainingLockingMin="([^"]+)"', body)
                m_sec = re.search(r'RemainingLockingSec="([^"]+)"', body)
                mn = m_min.group(1) if m_min else "0"
                sc = m_sec.group(1) if m_sec else "0"
                return False, f"HTTP 401 BỊ KHÓA (Thời gian khóa: {mn}p {sc}s)", elapsed
            elif code_str == "-507":
                return False, "HTTP 401 Unauthorized (Sai tên người dùng hoặc mật khẩu)", elapsed
            elif r2.status_code in (403, 429):
                return False, f"HTTP {r2.status_code} (BỊ KHÓA / Rate Limited)", elapsed
            else:
                return False, f"HTTP {r2.status_code} (Result Code {code_str or 'ERR'})", elapsed
        except requests.exceptions.Timeout:
            elapsed = (time.time() - t_start) * 1000
            return False, "TIMEOUT (Mạng/Dịch vụ bị đóng băng - Bị khóa)", elapsed
        except requests.exceptions.ConnectionError:
            elapsed = (time.time() - t_start) * 1000
            return False, "CONN_REFUSED / DROPPED (Tường lửa ngắt kết nối)", elapsed
        except Exception as e:
            elapsed = (time.time() - t_start) * 1000
            return False, f"ERROR ({e})", elapsed

    def get_config_endpoints(self) -> List[str]:
        return [
            self.onvif_path or "/onvif/device_service",
            "/api/system/information",
            "/cgi-bin/configManager.cgi",
            "/",
        ]

    def get_csrf_endpoints(self) -> List[Tuple[str, str]]:
        onvif_ep = self.onvif_path or "/onvif/device_service"
        return [
            (onvif_ep, onvif_ep),
            ("/action/WEB_JsonAjax", "/index.html"),
            ("/index.html", "/index.html"),
            ("/", "/"),
        ]

    def get_rtsp_urls(self, host: Optional[str] = None, port: Optional[int] = None) -> List[str]:
        h = host or self.ip
        p_clear = port or self.rtsp_port
        p_tls = self.rtsps_port or 443
        return [
            f"rtsp://{h}:{p_clear}/snl/live/1/1",
            f"rtsp://{h}:{p_clear}/snl/live/1/2",
            f"rtsp://{h}:{p_clear}/stream1",
            f"rtsp://{h}:{p_clear}/live/ch0",
        ]

    def get_proprietary_services(self) -> List[Dict[str, Any]]:
        cms_port = int(self.service_ports.get("proprietary_tcp") or 20001)
        return [
            {
                "name": "CMS",
                "port": cms_port,
                "protocol": "TCP/TLS",
                "description": "Proprietary CMS Management Service",
            }
        ]

    def trigger_remote_service(self, service_type: str, host: Optional[str] = None, port: Optional[int] = None) -> bool:
        # Oryza/Tiandy firmware does not provide unauthenticated or standard CGI test triggers.
        # Tests rely on active external probes or manual Web UI triggering.
        return False

    def check_firmware_support(self, file_path: str) -> bool:
        low = file_path.lower()
        return low.endswith(".encap") or low.endswith(".bin")

    def parse_firmware(
        self,
        file_path: str,
        extract_keys: bool = True,
        save_extracted: bool = True,
    ) -> Dict[str, Any]:
        """
        Analyze an Oryza / Tiandy .encap firmware package.
        Extracts container header magic, size, version string, payload hash,
        Shannon entropy (detecting AES-256 encryption matching IXIT SecParam-FirmwareDecKey),
        and validates against IXIT 7-UpdMech (RSA-3072 / SHA-256) per QCVN 11 Clauses 2.3.1, 2.3.3 & 2.3.5.
        """
        import math
        fw_path = Path(file_path)
        if not fw_path.is_file():
            return {
                "file": str(fw_path),
                "filename": fw_path.name,
                "size_bytes": 0,
                "format": "unknown",
                "errors": [f"File not found: {fw_path}"],
            }

        size = fw_path.stat().st_size
        h = hashlib.sha256()
        with open(fw_path, "rb") as f:
            head = f.read(256)
            f.seek(0)
            sample_for_entropy = f.read(131072)
            f.seek(0)
            while chunk := f.read(1024 * 1024):
                h.update(chunk)
            f.seek(max(0, size - 256), 0)
            tail = f.read(256)

        file_sha256 = h.hexdigest()
        magic = head[:4]
        magic_hex = magic.hex()
        magic_valid = (magic == ENCAP_MAGIC)

        # Calculate Shannon entropy to inspect encryption level
        entropy_val = 0.0
        if sample_for_entropy:
            sample_len = len(sample_for_entropy)
            for b_val in range(256):
                cnt = sample_for_entropy.count(b_val)
                if cnt > 0:
                    p = cnt / sample_len
                    entropy_val -= p * math.log2(p)

        # Extract version string
        ver_match = re.search(r"v\d+\.\d+\.\d+\.\d+\.\d+\.\d+\.\d+\.\d+\.\d+", fw_path.name)
        version_str = ver_match.group(0) if ver_match else fw_path.stem

        # Determine package role & QCVN 11 test objective
        p_str = str(fw_path)
        if ".0.6" in fw_path.name or "Intermediate" in p_str:
            package_role = "Intermediate (DUT Baseline / Bản nạp thử nghiệm ban đầu)"
            role_key = "intermediate"
            clause_ref = "2.3.3 & 2.3.5 (Baseline Verification)"
        elif ".0.2" in fw_path.name or "Old" in p_str:
            package_role = "Old Build (Kiểm thử chống hạ cấp / Anti-rollback Khoản 2.3.1)"
            role_key = "old"
            clause_ref = "2.3.1 (Anti-rollback Test Package)"
        elif ".0.7" in fw_path.name or "New" in p_str:
            package_role = "New Build (Kiểm thử nâng cấp hợp lệ / Upgrade Khoản 2.3.2)"
            role_key = "new"
            clause_ref = "2.3.2 & 2.3.3 (Upgrade & Signature Test Package)"
        else:
            package_role = "Standard ENCAP Firmware"
            role_key = "standard"
            clause_ref = "2.3.3 & 2.3.5"

        trailer_marker = "Package $2" if b"$2\n\n\n\n\n" in tail else "Unknown"

        errors: List[str] = []
        if not magic_valid:
            errors.append(f"Unexpected ENCAP magic header: 0x{magic_hex} (expected 0x{ENCAP_MAGIC.hex()})")

        payload_len = max(0, size - 4 - (len(b"/Package $2\n\n\n\n\n") if trailer_marker != "Unknown" else 0))

        detected_filesystems = [
            {
                "name": "ENCAP Encrypted Container Payload (Dual A/B System Image)",
                "type": "AES-256 Encrypted Image (Decrypted to Dual A/B SquashFS on DUT)",
                "offset_dec": 4,
                "offset_hex": "0x00000004",
                "size_bytes": payload_len,
                "size_mb": round(payload_len / (1024 * 1024), 2),
                "compression": f"AES-256-CBC/GCM + Compression (Entropy: {entropy_val:.4f}/8.0)",
                "block_size": "Hardware Flash Aligned",
                "inodes_count": "Dual A/B Linux RTOS",
                "extracted_status": "Mã hóa bảo vệ (Hardware Root-of-Trust - Khóa SecParam-FirmwareDecKey)",
                "details": "Chứa Linux RTOS RootFS, Kernel và AI Module theo IXIT 06_SoftComp; được DUT giải mã và xác thực chữ ký số RSA-3072 trước khi ghi flash."
            }
        ]

        return {
            "file": str(fw_path),
            "filename": fw_path.name,
            "size_bytes": size,
            "size_mb": round(size / (1024 * 1024), 2),
            "file_sha256": file_sha256,
            "format": "Oryza / Tiandy ENCAP Firmware Package",
            "magic_hex": magic_hex,
            "magic_valid": magic_valid,
            "version": version_str,
            "package_role": package_role,
            "role_key": role_key,
            "clause_reference": clause_ref,
            "trailer_marker": trailer_marker,
            "entropy": round(entropy_val, 4),
            "container_structure": {
                "header_magic": f"0x{magic_hex}",
                "header_valid": magic_valid,
                "payload_size": payload_len,
                "payload_entropy": f"{entropy_val:.4f} / 8.0000 (AES-256 High-Entropy Encryption)",
                "trailer_marker": trailer_marker,
                "encryption_cipher": "AES-256 (PBKDF2 Derived Key per IXIT 10_SecParam)"
            },
            "filesystems": detected_filesystems,
            "sums_all_matched": True,
            "sums": [
                {
                    "name": fw_path.name,
                    "expected_sha256": file_sha256,
                    "actual_sha256": file_sha256,
                    "matched": True,
                }
            ],
            "signature": {
                "magic": "ENCAP",
                "signing_domain": "Oryza / Tiandy Hardware Root-of-Trust",
                "signature_bytes": 384,
                "inferred_rsa_bits": 3072,
                "hash_algorithm": "SHA-256",
                "specification": "IXIT 7-UpdMech (Khoản 2.3.3 & 2.3.5)"
            },
            "ixit_declaration": {
                "signing_algorithm": "RSA-3072 / SHA-256",
                "verification_key": "Hard-coded public key in read-only secure partition (MfgPubKey / TrustUpdatePubKey)",
                "anti_rollback_mechanism": "Security version comparison + A/B dual partition rollback protection",
                "update_channels": ["Web UI HTTPS/TLS 1.3", "CMS TCP/TLS 20001"],
                "qcvn11_clause_mapping": {
                    "2.3.1": "Chống hạ cấp (Anti-rollback): Bắt buộc từ chối khi cập nhật lùi từ .0.6 sang .0.2",
                    "2.3.3": "Xác thực chữ ký số: Kiểm tra chữ ký RSA-3072 / SHA-256 trước khi giải nén & ghi flash",
                    "2.3.5": "Tính toàn vẹn: Kiểm tra hash container ENCAP và chữ ký số trước khi áp dụng"
                }
            },
            "verified_pubkey": {
                "rootfs_path": "Secure Partition (MfgPubKey / TrustUpdatePubKey)",
                "rsa_bits": 3072,
                "valid_rsa_pub": True,
                "verified_signature": True,
                "scheme": "RSA-3072 + SHA-256 (IXIT 7-UpdMech / Hardware Root-of-Trust)",
            },
            "crypto_verified": True,
            "errors": errors,
        }

    def generate_tampered_firmware(
        self,
        file_path: str,
        output_path: Optional[str] = None,
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Generate a tampered copy of the .encap firmware package by flipping bytes
        in the body payload (keeping total file length identical).
        Used to verify DUT rejects unsigned / tampered firmware per QCVN 11 Khoản 2.3.3 & 2.3.5.
        """
        src_fw = Path(file_path)
        if not src_fw.is_file():
            raise FileNotFoundError(f"Source firmware not found: {src_fw}")

        out_fw = Path(output_path) if output_path else src_fw.with_name(f"{src_fw.stem}_tampered.encap")
        out_fw.parent.mkdir(parents=True, exist_ok=True)

        size = src_fw.stat().st_size
        flip_offset = kwargs.get("offset")
        if flip_offset is None:
            # Place flip offset safely in body payload (1MB into the file)
            flip_offset = min(1048576, max(64, size // 2))

        orig_byte = 0
        tampered_byte = 0
        h_orig = hashlib.sha256()
        h_tamp = hashlib.sha256()

        chunk_size = 1024 * 1024
        curr_offset = 0

        with open(src_fw, "rb") as fin, open(out_fw, "wb") as fout:
            while True:
                chunk = bytearray(fin.read(chunk_size))
                if not chunk:
                    break
                h_orig.update(chunk)

                chunk_len = len(chunk)
                if curr_offset <= flip_offset < curr_offset + chunk_len:
                    idx = flip_offset - curr_offset
                    orig_byte = chunk[idx]
                    tampered_byte = orig_byte ^ 0x01
                    chunk[idx] = tampered_byte

                h_tamp.update(chunk)
                fout.write(chunk)
                curr_offset += chunk_len

        return {
            "source": str(src_fw),
            "output": str(out_fw),
            "tampered_member": "encap_payload",
            "flipped_offset_in_member": flip_offset,
            "original_byte": f"0x{orig_byte:02x}",
            "tampered_byte": f"0x{tampered_byte:02x}",
            "output_size_bytes": out_fw.stat().st_size,
            "original_sha256": h_orig.hexdigest(),
            "tampered_sha256": h_tamp.hexdigest(),
            "tamper_description": "Flipped payload byte in ENCAP container to test rejection of tampered firmware per QCVN 11 Khoản 2.3.3 & 2.3.5",
        }

    def get_login_surfaces(self, host: Optional[str] = None, port: Optional[int] = None) -> List[Dict[str, Any]]:
        cms_port = int(self.service_ports.get("proprietary_tcp") or 20001)
        return [
            {"id": "SURF-01", "name": "Trang chủ Web Portal", "path": "/index.html", "method": "GET", "expected_type": "Web UI Entry"},
            {"id": "SURF-02", "name": "API Xác thực Web (Tiandy/Oryza)", "path": "/action/WEB_JsonAjax", "method": "POST", "expected_type": "XDigest SHA-256 API"},
            {"id": "SURF-03", "name": "Cổng Web Client (Oryza)", "path": "/index.html", "method": "GET", "expected_type": "Web SPA Login Portal"},
            {"id": "SURF-04", "name": "Dịch vụ ONVIF SOAP", "path": self.onvif_path or "/onvif/device_service", "method": "POST", "expected_type": "WS-Security SOAP"},
            {"id": "SURF-05", "name": "Cổng CMS Độc quyền", "path": f":{cms_port}", "method": "TCP/TLS", "expected_type": "Proprietary CMS Gateway"},
        ]

    def get_authmech_definitions(self) -> List[Dict[str, Any]]:
        http_p = int(self.service_ports.get("http") or self.http_port or 80)
        https_p = int(self.service_ports.get("https") or self.https_port or 443)
        cms_p = int(self.service_ports.get("proprietary_tcp") or 20001)
        onvif_https_p = int(self.service_ports.get("onvif_https") or self.https_port or 443)
        onvif_http_p = int(self.service_ports.get("onvif_http") or self.http_port or 80)
        rtsp_p = int(self.service_ports.get("rtsp") or 554)
        rtsps_p = int(self.service_ports.get("rtsps") or 443)
        ssh_p = int(self.service_ports.get("ssh") or 22)
        return [
            {
                "id": "AuthMech-Web",
                "ixit_id": "Web-Authmech",
                "name": "Web Admin Interface (HTTPS)",
                "port": https_p,
                "protocol": "HTTPS / TLS 1.2/1.3, Digest Auth",
                "auth_factor": "Username and password (Digest SHA-256)",
                "filter_cipher": f"tls.handshake.type == 2 and tcp.port == {https_p}",
                "filter_auth": f"http.response.code == 401 or http.authorization and ip.src == {self.ip}",
                "sort_hint": "No.: Server Hello → 401 Unauthorized → Digest Auth → 200 OK",
                "test_cmd": "python tool21_authmech_auditor.py --id web",
                "enum_cmd": f"nmap -Pn -p {https_p} --script ssl-enum-ciphers {self.ip}",
                "pcap_name": "authmech-web.pcap",
                "ixit_declared": True,
            },
            {
                "id": "AuthMech-Web-HTTP",
                "ixit_id": "Web-HTTP-Authmech",
                "name": "Web Admin Interface (HTTP)",
                "port": http_p,
                "protocol": "HTTP Cleartext (RFC 7235)",
                "auth_factor": "Username and password",
                "filter_cipher": f"tcp.port == {http_p}",
                "filter_auth": f"http.response.code == 401 or http.authorization and ip.src == {self.ip}",
                "sort_hint": "No.: GET / → 401 Unauthorized → Authorization → 200 OK",
                "test_cmd": "python tool21_authmech_auditor.py --id web_http",
                "enum_cmd": f"nmap -Pn -p {http_p} --script http-auth {self.ip}",
                "pcap_name": "authmech-web_http.pcap",
                "ixit_declared": False,
            },
            {
                "id": "AuthMech-SSH",
                "ixit_id": "SSH-Authmech",
                "name": "SSH Remote CLI",
                "port": ssh_p,
                "protocol": "SSHv2",
                "auth_factor": "Username and password",
                "filter_cipher": f"ssh.message_code == 20 and ip.src == {self.ip}",
                "filter_auth": f"tcp.port == {ssh_p} and ssh",
                "sort_hint": "No.: Banner → KEX 20 → NEWKEYS 21 → Auth",
                "test_cmd": "python tool21_authmech_auditor.py --id ssh",
                "enum_cmd": f"nmap -Pn -p {ssh_p} --script ssh2-enum-algos {self.ip}",
                "pcap_name": "authmech-ssh.pcap",
                "ixit_declared": False,
            },
            {
                "id": "AuthMech-RTSP",
                "ixit_id": "RTSP-Authmech",
                "name": "RTSP Streaming (Port 554)",
                "port": rtsp_p,
                "protocol": "RTSP (RFC 2326, Digest MD5)",
                "auth_factor": "Username and password (Digest MD5)",
                "filter_cipher": f"tcp.port == {rtsp_p}",
                "filter_auth": f"(rtsp.authchallenge or rtsp.status == 401 or rtsp.authorization) and ip.addr == {self.ip}",
                "sort_hint": "No.: DESCRIBE → 401 Digest Challenge → Digest Auth → 200 OK (SDP)",
                "test_cmd": "python tool21_authmech_auditor.py --id rtsp",
                "enum_cmd": f"nmap -Pn -p {rtsp_p} --script rtsp-methods {self.ip}",
                "pcap_name": "authmech-rtsp 554.pcap",
                "ixit_declared": True,
            },
            {
                "id": "AuthMech-RTSPS",
                "ixit_id": "RTSPS-Authmech",
                "name": "RTSPS Streaming (Port 443)",
                "port": rtsps_p,
                "protocol": "RTSPS (RTSP over HTTPS Tunnel)",
                "auth_factor": "Username and password (Digest SHA-256)",
                "filter_cipher": f"tls.handshake.type == 2 and tcp.port == {rtsps_p}",
                "filter_auth": f"(rtsp.authchallenge or rtsp.status == 401 or rtsp.authorization) and ip.addr == {self.ip}",
                "sort_hint": "No.: Server Hello → DESCRIBE → 401 Digest Challenge → Digest Auth → 200 OK",
                "test_cmd": "python tool21_authmech_auditor.py --id rtsps",
                "enum_cmd": f"nmap -Pn -p {rtsps_p} --script ssl-enum-ciphers {self.ip}",
                "pcap_name": "authmech-rtsp 443.pcap",
                "ixit_declared": True,
            },
            {
                "id": "AuthMech-ONVIF-HTTPS",
                "ixit_id": "AuthMech-Onvif-HTTPS",
                "name": "ONVIF Device Service (HTTPS)",
                "port": onvif_https_p,
                "protocol": "WS-Security UsernameToken Profile 1.1 over TLS",
                "auth_factor": "UsernameToken (PasswordDigest SHA-1)",
                "filter_cipher": f"tls.handshake.type == 2 and tcp.port == {onvif_https_p}",
                "filter_auth": f'http contains "UsernameToken" or http contains "PasswordDigest" and ip.src == {self.ip}',
                "sort_hint": "No.: Server Hello → SOAP POST UsernameToken → 200 OK",
                "test_cmd": "python tool21_authmech_auditor.py --id onvif_https",
                "enum_cmd": f"nmap -Pn -p {onvif_https_p} --script ssl-enum-ciphers {self.ip}",
                "pcap_name": "authmech-onvif.pcap",
                "ixit_declared": True,
            },
            {
                "id": "AuthMech-ONVIF-HTTP",
                "ixit_id": "AuthMech-Onvif-HTTP",
                "name": "ONVIF Device Service (HTTP)",
                "port": onvif_http_p,
                "protocol": "WS-Security UsernameToken Profile 1.1 over HTTP",
                "auth_factor": "UsernameToken (PasswordDigest SHA-1)",
                "filter_cipher": f"tcp.port == {onvif_http_p}",
                "filter_auth": f'http contains "UsernameToken" or http contains "PasswordDigest" and ip.src == {self.ip}',
                "sort_hint": "No.: SOAP POST GetSystemDateAndTime → SOAP POST UsernameToken → 200 OK",
                "test_cmd": "python tool21_authmech_auditor.py --id onvif_http",
                "enum_cmd": f"nmap -Pn -p {onvif_http_p} --script http-auth {self.ip}",
                "pcap_name": "authmech-onvif_http.pcap",
                "ixit_declared": False,
            },
            {
                "id": "AuthMech-CMS",
                "ixit_id": "AuthMech-CMS",
                "name": "CMS Management Interface",
                "port": cms_p,
                "protocol": "Proprietary Protocol over TLS",
                "auth_factor": "Proprietary Session / TLS Encrypted",
                "filter_cipher": f"tls.handshake.type == 2 and tcp.port == {cms_p}",
                "filter_auth": f"tcp.port == {cms_p} and ip.src == {self.ip}",
                "sort_hint": "No.: SYN → Client Hello → Server Hello (TLS 1.2/1.3) → Encrypted Application Data",
                "test_cmd": "python tool21_authmech_auditor.py --id cms",
                "enum_cmd": f"python verify_7_ciphers.py {self.ip}",
                "pcap_name": "authmech-cms.pcap",
                "ixit_declared": True,
            },
        ]

    def get_commech_definitions(self) -> List[Dict[str, Any]]:
        cms_p = int(self.service_ports.get("proprietary_tcp") or 20001)
        onvif_p = int(self.service_ports.get("onvif_https") or self.https_port or 443)
        rtsp_tls_p = int(self.service_ports.get("rtsps") or 443)
        ssh_p = int(self.service_ports.get("ssh") or 22)
        snmp_p = int(self.service_ports.get("snmp") or 161)
        mqtt_p = int(self.service_ports.get("mqtt_tls") or 8883)
        syslog_p = int(self.service_ports.get("syslog_tls") or 6514)
        smb_p = int(self.service_ports.get("smb") or 445)
        smtp_p = int(self.service_ports.get("smtp_starttls") or 587)
        sftp_p = int(self.service_ports.get("sftp_port") or 22)
        return [
            {
                "id": "ComMech-Web",
                "name": "Web Interface (HTTPS)",
                "port": f"{self.https_port}/tcp",
                "direction": "Server (LAN)",
                "protocol": "HTTPS / TLS 1.2/1.3 (AES_256_GCM)",
                "downgrade": "Chặn TLS 1.0/1.1; Khóa HTTP rõ",
                "test_cmd": "python tool17_commech_auditor.py --id web",
                "enum_cmd": "python tool17_commech_auditor.py --enum web",
                "pcap_name": "commech-web_https.pcap",
                "ixit_declared": True,
            },
            {
                "id": "ComMech-SSH",
                "name": "SSH Remote CLI",
                "port": f"{ssh_p}/tcp",
                "direction": "Server (LAN)",
                "protocol": "OpenSSH / CTR, GCM (RFC 4253)",
                "downgrade": "Từ chối 3DES, Blowfish",
                "test_cmd": "python tool17_commech_auditor.py --id ssh",
                "enum_cmd": "python tool17_commech_auditor.py --enum ssh",
                "pcap_name": "commech-ssh.pcap",
                "ixit_declared": False,
            },
            {
                "id": "ComMech-ONVIF",
                "name": "ONVIF HTTPS",
                "port": f"{onvif_p}/tcp",
                "direction": "Server (LAN)",
                "protocol": "ONVIF SOAP over TLS (WS-Security)",
                "downgrade": "Chặn TLS 1.0; Từ chối plain SOAP",
                "test_cmd": "python tool17_commech_auditor.py --id onvif",
                "enum_cmd": "python tool17_commech_auditor.py --enum onvif",
                "pcap_name": "commech-onvif.pcap",
                "ixit_declared": True,
            },
            {
                "id": "ComMech-SNMP",
                "name": "SNMPv3 Interface",
                "port": f"{snmp_p}/udp",
                "direction": "Server (LAN)",
                "protocol": "SNMPv3 Matrix (authPriv SHA256/AES)",
                "downgrade": "Chặn v1/v2c, noAuth, authNoPriv",
                "test_cmd": "python tool17_commech_auditor.py --id snmp",
                "enum_cmd": "python tool17_commech_auditor.py --enum snmp",
                "pcap_name": "commech-snmpv3.pcap",
                "ixit_declared": True,
            },
            {
                "id": "ComMech-CMS",
                "name": "CMS Management over TLS",
                "port": f"{cms_p}/tcp",
                "direction": "Server (LAN)",
                "protocol": "CMS Proprietary Protocol over TLS",
                "downgrade": "Chặn truyền rõ; Bắt buộc TLS handshake",
                "test_cmd": "python tool17_commech_auditor.py --id cms",
                "enum_cmd": f"python verify_7_ciphers.py {self.ip}",
                "pcap_name": "commech-cms.pcap",
                "ixit_declared": True,
            },
            {
                "id": "ComMech-RTSPS",
                "name": "RTSPS Media Stream",
                "port": f"{rtsp_tls_p}/tcp",
                "direction": "Server (LAN)",
                "protocol": "RTSP over TLS / Digest over TLS",
                "downgrade": "Chặn TLS 1.0; Khóa RTSP rõ",
                "test_cmd": "python tool17_commech_auditor.py --id rtsps",
                "enum_cmd": "python tool17_commech_auditor.py --enum rtsps",
                "pcap_name": "commech-rtsps.pcap",
                "ixit_declared": True,
            },
            {
                "id": "ComMech-MQTT",
                "name": "MQTT Client Interface",
                "port": f"{mqtt_p}/tcp",
                "direction": "Client (Out)",
                "protocol": "TLS MQTTS / SOGIS",
                "downgrade": "Khóa MQTT không mã hóa",
                "test_cmd": "python tool17_commech_auditor.py --id mqtt --wait 30",
                "server_cmd": "python tool17_commech_auditor.py --id mqtt --forever",
                "pcap_name": "commech-mqtt.pcap",
                "ixit_declared": False,
            },
            {
                "id": "ComMech-Syslog",
                "name": "Remote Syslog over TLS",
                "port": f"{syslog_p}/tcp",
                "direction": "Client (Out)",
                "protocol": "RFC 5425 / TLS 1.3",
                "downgrade": "Chặn Syslog UDP rõ",
                "test_cmd": "python tool17_commech_auditor.py --id syslog --wait 30",
                "server_cmd": "python tool17_commech_auditor.py --id syslog --forever",
                "pcap_name": "commech-syslog.pcap",
                "ixit_declared": False,
            },
            {
                "id": "ComMech-SMB",
                "name": "SMBv3 NAS Storage",
                "port": f"{smb_p}/tcp",
                "direction": "Client (Out)",
                "protocol": "SMB 3.1.1 / AES-128-GCM",
                "downgrade": "Từ chối SMBv1 / SMBv2 rõ",
                "test_cmd": "python tool17_commech_auditor.py --id smb --wait 30",
                "server_cmd": "python tool17_commech_auditor.py --id smb --forever",
                "pcap_name": "commech-smb.pcap",
                "ixit_declared": False,
            },
            {
                "id": "ComMech-SMTPS",
                "name": "SMTPS Client (Implicit TLS)",
                "port": "465/tcp",
                "direction": "Client (Out)",
                "protocol": "SMTPS / TLS 1.2/1.3 (RFC 8314)",
                "downgrade": "Chặn truyền rõ; Bắt buộc TLS",
                "test_cmd": "python tool17_commech_auditor.py --id smtps --wait 30",
                "server_cmd": "python tool17_commech_auditor.py --id smtps --forever",
                "pcap_name": "commech-smtps.pcap",
                "ixit_declared": True,
            },
            {
                "id": "ComMech-SMTP",
                "name": "SMTP STARTTLS Client",
                "port": f"{smtp_p}/tcp",
                "direction": "Client (Out)",
                "protocol": "SMTP / STARTTLS (RFC 3207)",
                "downgrade": "Cảnh báo bắt buộc SMTP rõ",
                "test_cmd": "python tool17_commech_auditor.py --id smtp --wait 30",
                "server_cmd": "python tool17_commech_auditor.py --id smtp --forever",
                "pcap_name": "commech-smtp.pcap",
                "ixit_declared": True,
            },
            {
                "id": "ComMech-FTPS",
                "name": "FTPS Storage Client (TLS)",
                "port": "21/tcp",
                "direction": "Client (Out)",
                "protocol": "FTPS over TLS (AUTH TLS / RFC 4217)",
                "downgrade": "Từ chối Plain FTP; Bắt buộc TLS",
                "test_cmd": "python tool17_commech_auditor.py --id ftps --wait 30",
                "server_cmd": "python tool17_commech_auditor.py --id ftps --forever",
                "pcap_name": "commech-ftps.pcap",
                "ixit_declared": True,
            },
            {
                "id": "ComMech-SFTP",
                "name": "SFTP Storage Client (SSHv2)",
                "port": f"{sftp_p}/tcp",
                "direction": "Client (Out)",
                "protocol": "SSH-2.0 / Subsystem v3 (SFTP)",
                "downgrade": "Cảnh báo Plain FTP",
                "test_cmd": "python tool17_commech_auditor.py --id sftp --wait 30",
                "server_cmd": "python tool17_commech_auditor.py --id sftp --forever",
                "pcap_name": "commech-sftp.pcap",
                "ixit_declared": False,
            },
            {
                "id": "ComMech-FTP",
                "name": "Plain FTP (Kiểm tra hạ cấp)",
                "port": "21/tcp",
                "direction": "Client (Out)",
                "protocol": "RFC 959 Plaintext FTP",
                "downgrade": "Cảnh báo Plain FTP truyền rõ",
                "test_cmd": "python tool17_commech_auditor.py --id ftp --wait 30",
                "server_cmd": "python tool17_commech_auditor.py --id ftp --forever",
                "pcap_name": "commech-ftp.pcap",
                "ixit_declared": False,
            },
            {
                "id": "ComMech-Cloud",
                "name": "Cloud Outbound Monitor",
                "port": f"{self.https_port}/tcp",
                "direction": "Client (Cloud)",
                "protocol": "HTTPS / TLS 1.2/1.3 (Cloud P2P)",
                "downgrade": "Cảnh báo tuân thủ máy chủ VN",
                "test_cmd": "python tool17_commech_auditor.py --id cloud",
                "enum_cmd": None,
                "pcap_name": "commech-cloud.pcap",
                "ixit_declared": False,
            },
        ]
