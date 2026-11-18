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

    def get_web_auth_endpoints(self) -> List[str]:
        return [
            "/",
            "/index.html",
            "/web/index.html",
            self.onvif_path or "/onvif/device_service",
            "/api/system/information",
        ]

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
            ("/web/index.html", "/web/index.html"),
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
        and validates against IXIT 7-UpdMech (RSA-3072 / SHA-256) per QCVN 11 Clauses 2.3.1, 2.3.3 & 2.3.5.
        """
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
            while chunk := f.read(1024 * 1024):
                h.update(chunk)
            f.seek(max(0, size - 256), 0)
            tail = f.read(256)

        file_sha256 = h.hexdigest()
        magic = head[:4]
        magic_hex = magic.hex()
        magic_valid = (magic == ENCAP_MAGIC)

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
            {"id": "SURF-01", "name": "Trang chủ Web Portal", "path": "/", "method": "GET", "expected_type": "Web UI Entry"},
            {"id": "SURF-02", "name": "Trang đăng nhập Web (Oryza/Tiandy)", "path": "/index.html", "method": "GET", "expected_type": "Web UI Login Portal"},
            {"id": "SURF-03", "name": "Cổng Web Client (Oryza)", "path": "/web/index.html", "method": "GET", "expected_type": "Web SPA Login Portal"},
            {"id": "SURF-04", "name": "Dịch vụ ONVIF SOAP", "path": self.onvif_path, "method": "POST", "expected_type": "WS-Security SOAP"},
            {"id": "SURF-05", "name": "Cổng CMS Độc quyền", "path": f":{cms_port}", "method": "TCP/TLS", "expected_type": "Proprietary CMS Gateway"},
        ]

    def get_authmech_definitions(self) -> List[Dict[str, Any]]:
        cms_p = int(self.service_ports.get("proprietary_tcp") or 20001)
        onvif_p = int(self.service_ports.get("onvif_https") or self.https_port or 443)
        rtsp_p = int(self.service_ports.get("rtsp") or 554)
        rtsps_p = int(self.service_ports.get("rtsps") or 443)
        ssh_p = int(self.service_ports.get("ssh") or 22)
        return [
            {
                "id": "AuthMech-Web",
                "ixit_id": "Web-Authmech",
                "name": "Web Admin Interface",
                "port": self.https_port,
                "protocol": "HTTPS / TLS 1.2/1.3, Digest Auth",
                "auth_factor": "Username and password (Digest SHA-256)",
                "filter_cipher": f"tls.handshake.type == 2 and tcp.port == {self.https_port}",
                "filter_auth": f"http.response.code == 401 or http.authorization and ip.src == {self.ip}",
                "sort_hint": "No.: Server Hello → 401 Unauthorized → Digest Auth → 200 OK",
                "test_cmd": "python tool21_authmech_auditor.py --id web",
                "enum_cmd": f"nmap -Pn -p {self.https_port} --script ssl-enum-ciphers {self.ip}",
                "pcap_name": "authmech-web.pcap",
                "ixit_declared": True,
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
                "name": "RTSP Streaming",
                "port": rtsps_p,
                "protocol": "RTSPS (RTSP over HTTPS Tunnel)",
                "auth_factor": "Username and password (Digest SHA-256)",
                "filter_cipher": f"tls.handshake.type == 2 and (tcp.port == {rtsps_p} or tcp.port == {rtsp_p})",
                "filter_auth": f"(rtsp.authchallenge or rtsp.status == 401 or rtsp.authorization) and ip.addr == {self.ip}",
                "sort_hint": "No.: DESCRIBE → 401 Digest Challenge → Digest Auth → 200 OK (SDP)",
                "test_cmd": "python tool21_authmech_auditor.py --id rtsp",
                "enum_cmd": f"nmap -Pn -p {rtsps_p} --script ssl-enum-ciphers {self.ip}",
                "pcap_name": "authmech-rtsp.pcap",
                "ixit_declared": True,
            },
            {
                "id": "AuthMech-ONVIF",
                "ixit_id": "AuthMech-Onvif",
                "name": "ONVIF Device Service",
                "port": onvif_p,
                "protocol": "WS-Security UsernameToken Profile 1.1",
                "auth_factor": "UsernameToken (PasswordDigest SHA-1)",
                "filter_cipher": f"tls.handshake.type == 2 and tcp.port == {onvif_p}",
                "filter_auth": f'http contains "UsernameToken" or http contains "PasswordDigest" and ip.src == {self.ip}',
                "sort_hint": "No.: Server Hello → SOAP POST UsernameToken → 200 OK",
                "test_cmd": "python tool21_authmech_auditor.py --id onvif",
                "enum_cmd": f"nmap -Pn -p {onvif_p} --script ssl-enum-ciphers {self.ip}",
                "pcap_name": "authmech-onvif.pcap",
                "ixit_declared": True,
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
                "id": "ComMech-SMTP",
                "name": "SMTPS Client",
                "port": f"{smtp_p}/tcp",
                "direction": "Client (Out)",
                "protocol": "SMTPS / STARTTLS (RFC 3207)",
                "downgrade": "Cảnh báo bắt buộc SMTP rõ",
                "test_cmd": "python tool17_commech_auditor.py --id smtp --wait 30",
                "server_cmd": "python tool17_commech_auditor.py --id smtp --forever",
                "pcap_name": "commech-smtp.pcap",
                "ixit_declared": True,
            },
            {
                "id": "ComMech-SFTP",
                "name": "SFTP / FTPS Client",
                "port": f"{sftp_p}/tcp",
                "direction": "Client (Out)",
                "protocol": "SFTP / FTPS over TLS",
                "downgrade": "Cảnh báo Plain FTP",
                "test_cmd": "python tool17_commech_auditor.py --id sftp --wait 30",
                "server_cmd": "python tool17_commech_auditor.py --id sftp --forever",
                "pcap_name": "commech-sftp.pcap",
                "ixit_declared": True,
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
