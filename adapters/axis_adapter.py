#!/usr/bin/env python3
"""
Axis Camera Adapter for QCVN 11 Cybersecurity Toolkit.
Implements Axis OS & VAPIX-specific endpoints, RTSPS media paths, and remote triggers.
"""

import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
import time
from typing import Any, Dict, List, Optional, Tuple

import requests
import urllib3
from requests.adapters import HTTPAdapter

from adapters.base_adapter import BaseCameraAdapter

urllib3.disable_warnings()

SIGN_HEADER_MAGIC = b"pgnf"
SIGN_HEADER_LEN = 72
SUMS_RECORD_LEN = 64
SUMS_NAME_LEN = 32


def parse_sums_bin(data: bytes) -> List[Dict[str, str]]:
    """Parse 64-byte records (32B filename + 32B SHA-256 digest) from sums.bin."""
    records: List[Dict[str, str]] = []
    if len(data) % SUMS_RECORD_LEN != 0:
        return records
    for offset in range(0, len(data), SUMS_RECORD_LEN):
        rec = data[offset : offset + SUMS_RECORD_LEN]
        name = rec[:SUMS_NAME_LEN].split(b"\x00", 1)[0].decode("utf-8", errors="replace")
        digest = rec[SUMS_NAME_LEN:].hex()
        records.append({"name": name, "expected_sha256": digest})
    return records


def parse_sign_bin(data: bytes) -> Dict[str, Any]:
    """Parse AXIS pgnf signature header and raw RSA signature bytes."""
    if len(data) < SIGN_HEADER_LEN:
        return {"valid_header": False, "error": f"sign.bin too short ({len(data)} bytes)"}

    magic = data[:4]
    key_id = data[4:8].hex()
    domain = data[8:SIGN_HEADER_LEN].split(b"\x00", 1)[0].decode("utf-8", errors="replace")
    sig_bytes = data[SIGN_HEADER_LEN:]
    sig_bits = len(sig_bytes) * 8

    return {
        "valid_header": magic == SIGN_HEADER_MAGIC,
        "magic": magic.decode("ascii", errors="replace"),
        "key_id_hex": key_id,
        "signing_domain": domain,
        "signature_bytes": len(sig_bytes),
        "inferred_rsa_bits": sig_bits if sig_bits in (2048, 3072, 4096) else None,
        "signature_raw": sig_bytes,
    }


def inspect_rsa_pubkey_pem(pem_path: str) -> Dict[str, Any]:
    """Use openssl to inspect an RSA public key PEM file and return bit length."""
    res = subprocess.run(
        ["openssl", "rsa", "-pubin", "-in", pem_path, "-text", "-noout"],
        capture_output=True,
        text=True,
    )
    if res.returncode != 0:
        return {"ok": False, "error": res.stderr.strip()}
    match = re.search(r"Public-Key:\s*\((\d+)\s+bit\)", res.stdout)
    bits = int(match.group(1)) if match else None
    return {"ok": True, "bits": bits}


def verify_signature_openssl(pem_path: str, sig_path: str, data_path: str) -> Dict[str, Any]:
    """Verify SHA-256 RSA signature using OpenSSL (tries PSS then PKCS#1 v1.5)."""
    attempts = [
        ("RSA-PSS + SHA-256", ["openssl", "dgst", "-sha256", "-sigopt", "rsa_padding_mode:pss", "-verify", pem_path, "-signature", sig_path, data_path]),
        ("RSA-PKCS1v1.5 + SHA-256", ["openssl", "dgst", "-sha256", "-verify", pem_path, "-signature", sig_path, data_path]),
    ]
    for scheme, cmd in attempts:
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode == 0 and "Verified OK" in res.stdout:
            return {"verified": True, "scheme": scheme, "output": res.stdout.strip()}
    return {"verified": False, "scheme": None, "output": "Verification failed under PSS and PKCS#1 v1.5"}


def find_candidate_pubkeys_in_squashfs(rootfs_path: str, signing_domain: str) -> List[str]:
    """List candidate PEM public key paths inside an unencrypted SquashFS image."""
    res = subprocess.run(
        ["unsquashfs", "-ll", rootfs_path],
        capture_output=True,
        text=True,
    )
    if res.returncode != 0:
        return []

    candidates: List[str] = []
    for line in res.stdout.splitlines():
        parts = line.split()
        if not parts:
            continue
        path = parts[-1]
        if not path.startswith("squashfs-root/"):
            continue
        rel = path[len("squashfs-root/") :]
        low = rel.lower()
        if "/etc/ssl/certs/" in low or "/usr/lib/python" in low:
            continue
        if low.endswith(".pem") and ("upgrade/" in low or "public" in low or "signdomain" in low):
            candidates.append(rel)

    def sort_key(p: str) -> Tuple[int, str]:
        name = os.path.basename(p).lower()
        if signing_domain and signing_domain.lower() in name and "firmware" in name:
            return (0, p)
        if signing_domain and signing_domain.lower() in name:
            return (1, p)
        if "upgrade/" in p.lower():
            return (2, p)
        return (3, p)

    return sorted(candidates, key=sort_key)


class _SourceAddressAdapter(HTTPAdapter):
    def __init__(self, source_address, **kwargs):
        self.source_address = (source_address, 0)
        super().__init__(**kwargs)

    def init_poolmanager(self, *args, **kwargs):
        kwargs["source_address"] = self.source_address
        return super().init_poolmanager(*args, **kwargs)


class AxisCameraAdapter(BaseCameraAdapter):
    """Adapter for Axis Communications cameras (Axis OS / VAPIX)."""

    def get_web_auth_endpoints(self) -> List[str]:
        return [
            "/axis-cgi/param.cgi?action=list&group=root.Brand",
            "/axis-cgi/login.cgi",
            "/camera/index.html",
            "/",
        ]

    def get_config_endpoints(self) -> List[str]:
        return [
            "/axis-cgi/param.cgi",
            "/axis-cgi/param.cgi?action=list&group=root.Brand",
            "/axis-cgi/basicdeviceinfo.cgi",
        ]

    def get_csrf_endpoints(self) -> List[Tuple[str, str]]:
        return [
            ("/axis-cgi/param.cgi", "/axis-cgi/param.cgi?action=list&group=root.Brand"),
            ("/axis-cgi/basicdeviceinfo.cgi", "/axis-cgi/basicdeviceinfo.cgi"),
            ("/", "/"),
        ]

    def get_rtsp_urls(self, host: Optional[str] = None, port: Optional[int] = None) -> List[str]:
        h = host or self.ip
        p_clear = port or self.rtsp_port
        p_tls = self.rtsps_port or 322
        rtsp_path = self.service_ports.get("rtsp_path") or "/axis-media/media.amp"
        if not rtsp_path.startswith("/"):
            rtsp_path = "/" + rtsp_path
        return [
            f"rtsp://{h}:{p_clear}{rtsp_path}",
            f"rtsps://{h}:{p_tls}{rtsp_path}",
        ]

    def get_proprietary_services(self) -> List[Dict[str, Any]]:
        # Axis uses standard IANA/RFC protocols (HTTPS, SSH, RTSPS, SNMPv3, MQTT, Syslog, SMB, SMTP, SFTP)
        return []

    def _get_authenticated_sessions(self, host_bind_ip: Optional[str] = None):
        """Yield (requests.Session, base_url) candidates for VAPIX."""
        src_list = [host_bind_ip, None] if host_bind_ip and host_bind_ip != "127.0.0.1" else [None]
        for src in src_list:
            s = requests.Session()
            if src:
                s.mount("https://", _SourceAddressAdapter(src))
                s.mount("http://", _SourceAddressAdapter(src))
            s.auth = (self.username, self.password)
            yield s, f"https://{self.ip}:{self.https_port}"
            yield s, f"http://{self.ip}:{self.http_port}"

    def trigger_remote_service(self, service_type: str, host: Optional[str] = None, port: Optional[int] = None) -> bool:
        """Trigger remote service connection from Axis camera using VAPIX CGI commands."""
        st = service_type.lower().strip()
        target_host = host or "127.0.0.1"

        if st == "syslog":
            for s, base_url in self._get_authenticated_sessions(target_host):
                try:
                    url = f"{base_url}/axis-cgi/remotesyslog.cgi"
                    r = s.post(url, json={"apiVersion": "1.2", "method": "disable"}, verify=False, timeout=2.5)
                    if r.status_code == 404:
                        return False
                    time.sleep(0.3)
                    s.post(url, json={"apiVersion": "1.2", "method": "enable"}, verify=False, timeout=2.5)
                    time.sleep(0.2)
                    s.post(url, json={"apiVersion": "1.2", "method": "test"}, verify=False, timeout=2.0)
                    return True
                except Exception:
                    continue
            return False

        elif st == "smtp":
            smtp_port = port or 587
            for s, base_url in self._get_authenticated_sessions(target_host):
                try:
                    url = (
                        f"{base_url}/axis-cgi/smtptest.cgi?to=audit@example.com&from=camera@axis.local"
                        f"&mailserver={target_host}&port={smtp_port}&encryption=starttls&validatecert=0"
                        f"&subject=QCVN11_Test&body=Security_Audit"
                    )
                    r = s.get(url, verify=False, timeout=4.0)
                    if r.status_code in (200, 204):
                        return True
                except Exception:
                    continue
            return False

        elif st == "sftp":
            sftp_port = port or 22
            for s, base_url in self._get_authenticated_sessions(target_host):
                try:
                    url = (
                        f"{base_url}/axis-cgi/ftptest.cgi?proto=sftp&address={target_host}"
                        f"&port={sftp_port}&username=merlin&password=test"
                        f"&publickeyfp=00112233445566778899aabbccddeeff"
                    )
                    r = s.get(url, verify=False, timeout=4.0)
                    if r.status_code in (200, 204):
                        return True
                except Exception:
                    continue
            return False

        return False

    def check_firmware_support(self, file_path: str) -> bool:
        low = file_path.lower()
        return low.endswith(".bin")

    def parse_firmware(
        self,
        file_path: str,
        extract_keys: bool = True,
        save_extracted: bool = True,
    ) -> Dict[str, Any]:
        """Analyze a single Axis .bin firmware package (tar.gz container with sums.bin, sign.bin)."""
        fw_path = Path(file_path)
        result: Dict[str, Any] = {
            "file": str(fw_path),
            "filename": fw_path.name,
            "size_bytes": fw_path.stat().st_size,
            "file_sha256": hashlib.sha256(fw_path.read_bytes()).hexdigest() if fw_path.stat().st_size < 1024 else None,
            "format": "unknown",
            "extracted_dir": None,
            "info": {},
            "sums": [],
            "sums_all_matched": False,
            "signature": {},
            "rootfs_keys": [],
            "verified_pubkey": None,
            "crypto_verified": False,
            "errors": [],
        }

        if not tarfile.is_tarfile(str(fw_path)):
            try:
                with tarfile.open(fw_path, "r:gz") as tf:
                    tf.getmembers()
            except Exception as exc:
                result["errors"].append(f"Not a valid tar.gz firmware archive: {exc}")
                return result

        result["format"] = "AXIS tar.gz fimage"
        persist_dir: Optional[Path] = None
        if save_extracted:
            persist_dir = fw_path.parent / f"extracted_{fw_path.stem}"
            persist_dir.mkdir(parents=True, exist_ok=True)
            result["extracted_dir"] = str(persist_dir)

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            actual_hashes: Dict[str, str] = {}
            rootfs_extracted: Optional[Path] = None

            with tarfile.open(fw_path, "r:gz") as tf:
                members = tf.getmembers()
                result["members"] = [{"name": m.name, "size": m.size} for m in members]

                for m in members:
                    if not m.isfile():
                        continue
                    fobj = tf.extractfile(m)
                    if fobj is None:
                        continue
                    if m.name in ("fwinfo.bin", "info.json", "boot.img", "rootfs.img"):
                        if m.name == "rootfs.img" and extract_keys:
                            rootfs_path = tmp / "rootfs.img"
                            h = hashlib.sha256()
                            with open(rootfs_path, "wb") as out_f:
                                while True:
                                    buf = fobj.read(1024 * 1024)
                                    if not buf:
                                        break
                                    h.update(buf)
                                    out_f.write(buf)
                            actual_hashes[m.name] = h.hexdigest()
                            rootfs_extracted = rootfs_path
                        else:
                            data = fobj.read()
                            actual_hashes[m.name] = hashlib.sha256(data).hexdigest()
                            if persist_dir and m.name in ("fwinfo.bin", "info.json"):
                                (persist_dir / m.name).write_bytes(data)
                            if m.name == "info.json":
                                try:
                                    result["info"] = json.loads(data.decode("utf-8"))
                                except Exception as exc:
                                    result["errors"].append(f"Failed to parse info.json: {exc}")
                    elif m.name in ("sums.bin", "sign.bin"):
                        raw_meta = fobj.read()
                        (tmp / m.name).write_bytes(raw_meta)
                        if persist_dir:
                            (persist_dir / m.name).write_bytes(raw_meta)

            sums_path = tmp / "sums.bin"
            sign_path = tmp / "sign.bin"

            if sums_path.exists():
                records = parse_sums_bin(sums_path.read_bytes())
                for rec in records:
                    actual = actual_hashes.get(rec["name"])
                    rec["actual_sha256"] = actual
                    rec["matched"] = actual == rec["expected_sha256"]
                result["sums"] = records
                result["sums_all_matched"] = bool(records) and all(r["matched"] for r in records)
            else:
                result["errors"].append("sums.bin missing from firmware archive")

            if sign_path.exists():
                sig_info = parse_sign_bin(sign_path.read_bytes())
                sig_raw = sig_info.pop("signature_raw", b"")
                result["signature"] = sig_info
                sig_raw_path = tmp / "sig.raw"
                sig_raw_path.write_bytes(sig_raw)
            else:
                result["errors"].append("sign.bin missing from firmware archive")
                sig_raw_path = None

            # Inspect rootfs.img for hard-coded public key & verify signature
            if extract_keys and rootfs_extracted and rootfs_extracted.exists():
                with open(rootfs_extracted, "rb") as rf:
                    magic = rf.read(4)
                if magic != b"hsqs":
                    result["errors"].append(f"rootfs.img is not unencrypted SquashFS (magic={magic.hex()})")
                else:
                    domain = result["signature"].get("signing_domain") or result["info"].get("SigningDomain", "")
                    candidates = find_candidate_pubkeys_in_squashfs(str(rootfs_extracted), domain)
                    if candidates:
                        sq_out = (persist_dir / "rootfs_keys") if persist_dir else (tmp / "sq_keys")
                        subprocess.run(
                            ["unsquashfs", "-f", "-d", str(sq_out), str(rootfs_extracted), *candidates],
                            capture_output=True,
                        )
                        for rel in candidates:
                            pem_file = sq_out / rel
                            if not pem_file.exists():
                                continue
                            key_meta = inspect_rsa_pubkey_pem(str(pem_file))
                            entry: Dict[str, Any] = {
                                "rootfs_path": "/" + rel,
                                "rsa_bits": key_meta.get("bits"),
                                "valid_rsa_pub": key_meta.get("ok", False),
                                "verified_signature": False,
                                "scheme": None,
                            }
                            if key_meta.get("ok") and sig_raw_path and sums_path.exists():
                                ver = verify_signature_openssl(str(pem_file), str(sig_raw_path), str(sums_path))
                                entry["verified_signature"] = ver["verified"]
                                entry["scheme"] = ver["scheme"]
                                if ver["verified"] and not result["crypto_verified"]:
                                    result["crypto_verified"] = True
                                    result["verified_pubkey"] = entry
                            result["rootfs_keys"].append(entry)

        return result

    def generate_tampered_firmware(
        self,
        file_path: str,
        output_path: Optional[str] = None,
        target_member: str = "sign.bin",
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Create a valid .tar.gz copy of src_fw with exactly 1 byte flipped inside
        target_member (default: sign.bin) so the device rejects it at signature/hash verification.
        """
        src_fw = Path(file_path)
        out_fw = Path(output_path) if output_path else src_fw.with_name(f"{src_fw.stem}_TAMPERED_1BYTE.bin")

        modified_info: Dict[str, Any] = {
            "source": str(src_fw),
            "output": str(out_fw),
            "tampered_member": target_member,
            "flipped_offset_in_member": 0,
            "original_byte": "0x00",
            "tampered_byte": "0x01",
            "tamper_description": f"Flipped 1 byte in {target_member} to test QCVN 11 signature/integrity rejection",
        }

        # Inspect members first to see if target_member exists
        with tarfile.open(src_fw, "r:gz") as src_tf:
            existing_members = [m.name for m in src_tf.getmembers() if m.isfile()]

        if target_member not in existing_members:
            # Fallback to another existing member
            for fallback in ("sign.bin", "sums.bin", "info.json", "fwinfo.bin", "boot.img"):
                if fallback in existing_members:
                    target_member = fallback
                    break
            else:
                if existing_members:
                    target_member = existing_members[0]
            modified_info["tampered_member"] = target_member

        with tarfile.open(src_fw, "r:gz") as src_tf, tarfile.open(out_fw, "w:gz") as dst_tf:
            for member in src_tf.getmembers():
                if not member.isfile():
                    dst_tf.addfile(member)
                    continue

                fobj = src_tf.extractfile(member)
                if fobj is None:
                    continue

                if member.name != target_member:
                    dst_tf.addfile(member, fobj)
                    continue

                raw = bytearray(fobj.read())
                if target_member == "sign.bin" and len(raw) > SIGN_HEADER_LEN:
                    flip_idx = SIGN_HEADER_LEN + (len(raw) - SIGN_HEADER_LEN) // 2
                elif target_member == "sums.bin" and len(raw) > SUMS_NAME_LEN:
                    flip_idx = SUMS_NAME_LEN
                else:
                    flip_idx = max(0, len(raw) // 2)

                orig_byte = raw[flip_idx]
                new_byte = orig_byte ^ 0x01
                raw[flip_idx] = new_byte

                new_member = tarfile.TarInfo(name=member.name)
                new_member.size = len(raw)
                new_member.mode = member.mode
                new_member.mtime = member.mtime
                new_member.uid = member.uid
                new_member.gid = member.gid
                new_member.uname = member.uname
                new_member.gname = member.gname
                dst_tf.addfile(new_member, io.BytesIO(bytes(raw)))

                modified_info.update(
                    {
                        "flipped_offset_in_member": flip_idx,
                        "original_byte": f"0x{orig_byte:02x}",
                        "tampered_byte": f"0x{new_byte:02x}",
                    }
                )

        modified_info["output_size_bytes"] = out_fw.stat().st_size
        return modified_info

    def get_login_surfaces(self, host: Optional[str] = None, port: Optional[int] = None) -> List[Dict[str, Any]]:
        return [
            {"id": "SURF-01", "name": "Trang chủ Web Portal", "path": "/", "method": "GET", "expected_type": "Web UI Entry"},
            {"id": "SURF-02", "name": "Giao diện Web SPA (Axis)", "path": "/camera/index.html", "method": "GET", "expected_type": "Web SPA Login Portal"},
            {"id": "SURF-03", "name": "Cổng HTTP Auth (Axis CGI)", "path": "/axis-cgi/login.cgi", "method": "GET/POST", "expected_type": "HTTP Basic/Digest Auth Gateway"},
            {"id": "SURF-04", "name": "Cổng Tham số (Axis CGI)", "path": "/axis-cgi/param.cgi", "method": "GET", "expected_type": "Config Management Challenge"},
            {"id": "SURF-05", "name": "Dịch vụ ONVIF SOAP", "path": self.onvif_path, "method": "POST", "expected_type": "WS-Security SOAP"},
        ]

    def get_authmech_definitions(self) -> List[Dict[str, Any]]:
        ssh_p = int(self.service_ports.get("ssh") or 22)
        onvif_p = int(self.service_ports.get("onvif_https") or self.https_port)
        cms_p = int(self.service_ports.get("proprietary_tcp") or 8000)
        return [
            {
                "id": "AuthMech-Web",
                "ixit_id": "Web-Authmech",
                "name": "Web Admin Interface",
                "port": self.https_port,
                "protocol": "HTTPS / TLS 1.3",
                "auth_factor": "Username and password",
                "filter_cipher": f"tls.handshake.type == 2 and tcp.port == {self.https_port}",
                "filter_auth": "http.response.code == 401 or http.authorization",
                "sort_hint": "No.: Server Hello → 401 → Auth → 200",
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
                "name": "RTSPS Media Stream",
                "port": self.rtsps_port,
                "protocol": "RTSP over TLS 1.3",
                "auth_factor": "Username and password",
                "filter_cipher": f"tls.handshake.type == 2 and tcp.port == {self.rtsps_port}",
                "filter_auth": "rtsp.authchallenge or rtsp.status == 401 or rtsp.authorization",
                "sort_hint": "No.: 401 Challenge → Basic Auth → 200 OK",
                "test_cmd": "python tool21_authmech_auditor.py --id rtsp",
                "enum_cmd": f"nmap -Pn -p {self.rtsps_port} --script ssl-enum-ciphers {self.ip}",
                "pcap_name": "authmech-rtsp.pcap",
                "ixit_declared": True,
            },
            {
                "id": "AuthMech-ONVIF",
                "ixit_id": "AuthMech-Onvif",
                "name": "ONVIF Device Service",
                "port": onvif_p,
                "protocol": "HTTPS SOAP (WS-Security)",
                "auth_factor": "Username and password",
                "filter_cipher": f"tls.handshake.type == 2 and tcp.port == {onvif_p}",
                "filter_auth": 'http contains "UsernameToken" or "PasswordDigest"',
                "sort_hint": "No.: Server Hello → SOAP POST → 200 OK",
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
                "sort_hint": "No.: SYN → Client Hello → Server Hello (TLS 1.2/1.3) → Encrypted App Data",
                "test_cmd": "python tool21_authmech_auditor.py --id cms",
                "enum_cmd": f"nmap -Pn -p {cms_p} --script ssl-enum-ciphers {self.ip}",
                "pcap_name": "authmech-cms.pcap",
                "ixit_declared": False,
            },
        ]

    def get_commech_definitions(self) -> List[Dict[str, Any]]:
        ssh_p = int(self.service_ports.get("ssh") or 22)
        onvif_p = int(self.service_ports.get("onvif_https") or self.https_port)
        snmp_p = int(self.service_ports.get("snmp") or 161)
        cms_p = int(self.service_ports.get("proprietary_tcp") or 8000)
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
                "name": "SSH Interface (SSHv2)",
                "port": f"{ssh_p}/tcp",
                "direction": "Server (LAN)",
                "protocol": "OpenSSH / CTR, GCM",
                "downgrade": "Từ chối 3DES, Blowfish",
                "test_cmd": "python tool17_commech_auditor.py --id ssh",
                "enum_cmd": "python tool17_commech_auditor.py --enum ssh",
                "pcap_name": "commech-ssh.pcap",
                "ixit_declared": True,
            },
            {
                "id": "ComMech-ONVIF",
                "name": "ONVIF over HTTPS",
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
                "name": "SNMP Interface (SNMPv3)",
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
                "enum_cmd": f"python tool17_commech_auditor.py --enum cms",
                "pcap_name": "commech-cms.pcap",
                "ixit_declared": False,
            },
            {
                "id": "ComMech-RTSPS",
                "name": "RTSPS Media Stream",
                "port": f"{self.rtsps_port}/tcp",
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
                "id": "ComMech-SMTP",
                "name": "SMTP Email Client",
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
                "name": "SFTP Storage Client",
                "port": f"{sftp_p}/tcp",
                "direction": "Client (Out)",
                "protocol": "SSH-2.0 / Subsystem v3",
                "downgrade": "Cảnh báo Plain FTP",
                "test_cmd": "python tool17_commech_auditor.py --id sftp --wait 30",
                "server_cmd": "python tool17_commech_auditor.py --id sftp --forever",
                "pcap_name": "commech-sftp.pcap",
                "ixit_declared": True,
            },
            {
                "id": "ComMech-Cloud",
                "name": "Cloud Management (O3C / P2P)",
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
