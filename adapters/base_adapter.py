#!/usr/bin/env python3
"""
Base Camera Adapter for QCVN 11 Cybersecurity Toolkit.
Defines the standard interface for vendor-specific camera behaviors, endpoints, and protocol extensions.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Tuple


class BaseCameraAdapter(ABC):
    """Abstract Base Class for vendor-specific camera adapters."""

    web_auth_endpoint: str = "/"

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        if config is None:
            try:
                from toolkit_config import load_config
                self.config = load_config()
            except Exception:
                self.config = {}
        else:
            self.config = config

        # Cached camera info
        tc = self.config.get("target_camera", {})
        self.ip = tc.get("ip") or self.config.get("ip") or "127.0.0.1"
        self.username = tc.get("username") or self.config.get("username") or "admin"
        self.password = tc.get("password") or self.config.get("password") or ""
        self.model = tc.get("model") or self.config.get("model") or "Generic"
        self.firmware = tc.get("firmware") or self.config.get("firmware") or ""
        self.profile_id = self.config.get("active_profile") or self.config.get("profile_id") or "generic"
        self.vendor = self.config.get("vendor") or "Generic"

        # Service ports
        sp = self.config.get("service_ports", {})
        self.service_ports = sp
        self.http_port = int(sp.get("http") or 80)
        self.https_port = int(sp.get("https") or 443)
        self.rtsp_port = int(sp.get("rtsp") or 554)
        self.rtsps_port = int(sp.get("rtsps") or 322)
        self.onvif_path = sp.get("onvif_path") or "/onvif/device_service"

    @abstractmethod
    def get_web_auth_endpoints(self) -> List[str]:
        """Return list of candidate URL paths for HTTP/HTTPS authentication & lockout auditing."""
        pass

    def attempt_web_login(
        self,
        username: str,
        password: str,
        port: int = 443,
        timeout: float = 3.0,
    ) -> Optional[Tuple[bool, str, float]]:
        """
        Optional vendor-specific web login implementation.
        Returns (is_success, status_str, latency_ms), or None to use default Basic/Digest auth.
        """
        return None

    @abstractmethod
    def get_config_endpoints(self) -> List[str]:
        """Return list of URL paths for configuration management challenge/reading."""
        pass

    @abstractmethod
    def get_csrf_endpoints(self) -> List[Tuple[str, str]]:
        """Return list of (config_endpoint, query_url) candidate tuples for CSRF auditing."""
        pass

    @abstractmethod
    def get_rtsp_urls(self, host: Optional[str] = None, port: Optional[int] = None) -> List[str]:
        """Return list of RTSP/RTSPS stream URLs supported by the camera."""
        pass

    @abstractmethod
    def get_proprietary_services(self) -> List[Dict[str, Any]]:
        """
        Return list of proprietary services declared or discovered.
        Each entry has keys: name, port, protocol, description.
        """
        pass

    @abstractmethod
    def trigger_remote_service(self, service_type: str, host: Optional[str] = None, port: Optional[int] = None) -> bool:
        """
        Actively trigger a client-role service (syslog, smtp, sftp) on the camera.
        Returns True if trigger command was successfully sent and accepted.
        """
        pass

    @abstractmethod
    def check_firmware_support(self, file_path: str) -> bool:
        """Check if the given firmware package file is supported by this adapter's camera platform."""
        pass

    @abstractmethod
    def parse_firmware(
        self,
        file_path: str,
        extract_keys: bool = True,
        save_extracted: bool = True,
    ) -> Dict[str, Any]:
        """
        Parse and analyze a firmware package for hash, signature, and metadata.
        Returns a dictionary containing cryptographic verification results and metadata.
        """
        pass

    @abstractmethod
    def generate_tampered_firmware(
        self,
        file_path: str,
        output_path: Optional[str] = None,
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Generate a tampered copy of the firmware package for negative signature verification testing.
        Returns details of the tampered file and byte modifications.
        """
        pass

    def get_login_surfaces(self, host: Optional[str] = None, port: Optional[int] = None) -> List[Dict[str, Any]]:
        """Return list of login surfaces for input validation (SQLi/XSS) testing."""
        return [
            {"id": "SURF-01", "name": "Trang chủ Web Portal", "path": "/", "method": "GET", "expected_type": "Web UI Entry"},
            {"id": "SURF-02", "name": "Dịch vụ ONVIF SOAP", "path": self.onvif_path, "method": "POST", "expected_type": "WS-Security SOAP"},
        ]

    def get_authmech_definitions(self) -> List[Dict[str, Any]]:
        """Return unified list of AuthMech test definitions (Web, Web-HTTP, SSH, RTSP, RTSPS, ONVIF-HTTPS, ONVIF-HTTP, CMS)."""
        http_p = int(self.service_ports.get("http") or self.http_port or 80)
        https_p = int(self.service_ports.get("https") or self.https_port or 443)
        ssh_p = int(self.service_ports.get("ssh") or 22)
        onvif_https_p = int(self.service_ports.get("onvif_https") or self.https_port or 443)
        onvif_http_p = int(self.service_ports.get("onvif_http") or self.http_port or 80)
        rtsp_p = int(self.service_ports.get("rtsp") or 554)
        rtsps_p = int(self.service_ports.get("rtsps") or self.rtsps_port or 443)
        cms_p = int(self.service_ports.get("proprietary_tcp") or 20001)

        return [
            {
                "id": "AuthMech-Web",
                "ixit_id": "Web-Authmech",
                "name": "Web Admin Interface (HTTPS)",
                "port": https_p,
                "protocol": "HTTPS / TLS 1.2/1.3",
                "auth_factor": "Username and password",
                "filter_cipher": f"tls.handshake.type == 2 and tcp.port == {https_p}",
                "filter_auth": "http.response.code == 401 or http.authorization",
                "sort_hint": "No.: Server Hello → 401 → Auth → 200",
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
                "filter_auth": "http.response.code == 401 or http.authorization",
                "sort_hint": "No.: GET / → 401 Unauthorized → Auth → 200",
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
                "protocol": "SSHv2 (RFC 4253)",
                "auth_factor": "Username and password",
                "filter_cipher": f"ssh.message_code == 20 and ip.src == {self.ip}",
                "filter_auth": f"tcp.port == {ssh_p} and ssh",
                "sort_hint": "No.: Banner → KEX 20 → NEWKEYS 21 → Auth",
                "test_cmd": "python tool21_authmech_auditor.py --id ssh",
                "enum_cmd": f"nmap -Pn -p {ssh_p} --script ssh2-enum-algos {self.ip}",
                "pcap_name": "authmech-ssh.pcap",
                "ixit_declared": True,
            },
            {
                "id": "AuthMech-RTSP",
                "ixit_id": "RTSP-Authmech",
                "name": "RTSP Streaming (RFC 2326)",
                "port": rtsp_p,
                "protocol": "RTSP Cleartext / Digest Auth",
                "auth_factor": "Username and password (Digest)",
                "filter_cipher": f"tcp.port == {rtsp_p}",
                "filter_auth": "rtsp.authchallenge or rtsp.status == 401 or rtsp.authorization",
                "sort_hint": "No.: DESCRIBE → 401 Challenge → Auth → 200 OK",
                "test_cmd": "python tool21_authmech_auditor.py --id rtsp",
                "enum_cmd": f"nmap -Pn -p {rtsp_p} --script rtsp-methods {self.ip}",
                "pcap_name": "authmech-rtsp 554.pcap",
                "ixit_declared": True,
            },
            {
                "id": "AuthMech-RTSPS",
                "ixit_id": "RTSPS-Authmech",
                "name": "RTSPS Media Stream",
                "port": rtsps_p,
                "protocol": "RTSPS / RTSP over TLS",
                "auth_factor": "Username and password (Digest)",
                "filter_cipher": f"tls.handshake.type == 2 and tcp.port == {rtsps_p}",
                "filter_auth": "rtsp.authchallenge or rtsp.status == 401 or rtsp.authorization",
                "sort_hint": "No.: Server Hello → DESCRIBE → 401 Challenge → 200 OK",
                "test_cmd": "python tool21_authmech_auditor.py --id rtsps",
                "enum_cmd": f"nmap -Pn -p {rtsps_p} --script ssl-enum-ciphers {self.ip}",
                "pcap_name": "authmech-rtsp.pcap",
                "ixit_declared": True,
            },
            {
                "id": "AuthMech-ONVIF-HTTPS",
                "ixit_id": "AuthMech-Onvif-HTTPS",
                "name": "ONVIF Device Service (HTTPS)",
                "port": onvif_https_p,
                "protocol": "HTTPS SOAP (WS-Security over TLS)",
                "auth_factor": "UsernameToken (PasswordDigest/Text)",
                "filter_cipher": f"tls.handshake.type == 2 and tcp.port == {onvif_https_p}",
                "filter_auth": 'http contains "UsernameToken" or http contains "PasswordDigest"',
                "sort_hint": "No.: Server Hello → SOAP POST → 200 OK",
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
                "protocol": "HTTP SOAP (WS-Security)",
                "auth_factor": "UsernameToken (PasswordDigest/Text)",
                "filter_cipher": f"tcp.port == {onvif_http_p}",
                "filter_auth": 'http contains "UsernameToken" or http contains "PasswordDigest"',
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
                "protocol": "CMS Proprietary Protocol over TLS",
                "auth_factor": "Proprietary Session / TLS Encrypted",
                "filter_cipher": f"tls.handshake.type == 2 and tcp.port == {cms_p}",
                "filter_auth": f"tcp.port == {cms_p} and ip.src == {self.ip}",
                "sort_hint": "No.: SYN → Client Hello → Server Hello → Encrypted App Data",
                "test_cmd": "python tool21_authmech_auditor.py --id cms",
                "enum_cmd": f"python verify_7_ciphers.py {self.ip}",
                "pcap_name": "authmech-cms.pcap",
                "ixit_declared": True,
            },
        ]

    def get_commech_definitions(self) -> List[Dict[str, Any]]:
        """Return unified list of 12 ComMech test definitions."""
        ssh_p = int(self.service_ports.get("ssh") or 22)
        onvif_p = int(self.service_ports.get("onvif_https") or self.https_port or 443)
        snmp_p = int(self.service_ports.get("snmp") or 161)
        cms_p = int(self.service_ports.get("proprietary_tcp") or 20001)
        rtsp_tls_p = int(self.service_ports.get("rtsps") or self.rtsps_port or 443)
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
                "protocol": "TLSv1.3 / AES_256_GCM",
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
                "ixit_declared": True,
            },
            {
                "id": "ComMech-ONVIF",
                "name": "ONVIF Interface (HTTPS)",
                "port": f"{onvif_p}/tcp",
                "direction": "Server (LAN)",
                "protocol": "TLSv1.3 / WS-Security",
                "downgrade": "Từ chối TLS 1.0; Digest Auth",
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
                "protocol": "SNMPv3 Matrix (SHA2/1/MD5 + AES/3DES/DES)",
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
                "protocol": "TLSv1.3 / AES_128_GCM",
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
                "ixit_declared": True,
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
                "ixit_declared": True,
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
                "ixit_declared": True,
            },
            {
                "id": "ComMech-SMTPS",
                "name": "SMTPS Client (Implicit TLS)",
                "port": "465/tcp",
                "direction": "Client (Out)",
                "protocol": "SMTPS / TLS 1.3 (RFC 8314)",
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
                "protocol": "STARTTLS / TLS 1.3",
                "downgrade": "Cảnh báo bắt buộc SMTP rõ",
                "test_cmd": "python tool17_commech_auditor.py --id smtp --wait 30",
                "server_cmd": "python tool17_commech_auditor.py --id smtp --forever",
                "pcap_name": "commech-smtp.pcap",
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
                "ixit_declared": True,
            },
            {
                "id": "ComMech-FTPS",
                "name": "FTPS Storage Client (TLS)",
                "port": "21/tcp",
                "direction": "Client (Out)",
                "protocol": "FTP over TLS (AUTH TLS / RFC 4217)",
                "downgrade": "Từ chối Plain FTP; Bắt buộc TLS",
                "test_cmd": "python tool17_commech_auditor.py --id ftps --wait 30",
                "server_cmd": "python tool17_commech_auditor.py --id ftps --forever",
                "pcap_name": "commech-ftps.pcap",
                "ixit_declared": True,
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
                "protocol": "HTTPS / TLS 1.3",
                "downgrade": "Cảnh báo tuân thủ máy chủ VN",
                "test_cmd": "python tool17_commech_auditor.py --id cloud",
                "enum_cmd": None,
                "pcap_name": "commech-cloud.pcap",
                "ixit_declared": True,
            },
        ]
