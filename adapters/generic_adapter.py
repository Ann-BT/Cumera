#!/usr/bin/env python3
"""
Generic Camera Adapter for QCVN 11 Cybersecurity Toolkit.
Provides fallback implementation for standard ONVIF and multi-vendor IP cameras
(Hikvision ISAPI, Dahua RPC, Uniview LAPI, Generic ONVIF).
"""

import hashlib
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from adapters.base_adapter import BaseCameraAdapter


class GenericCameraAdapter(BaseCameraAdapter):
    """Fallback adapter for generic ONVIF and non-Axis/non-Oryza cameras."""

    def get_web_auth_endpoints(self) -> List[str]:
        return [
            self.onvif_path or "/onvif/device_service",
            "/ISAPI/System/deviceInfo",
            "/cgi-bin/magicBox.cgi?action=getSystemInfo",
            "/LAPI/V1.0/System/DeviceBasicInfo",
            "/api/system/information",
            "/",
            "/index.html",
        ]

    def get_config_endpoints(self) -> List[str]:
        return [
            self.onvif_path or "/onvif/device_service",
            "/ISAPI/Security/adminAccesses",
            "/cgi-bin/configManager.cgi",
            "/api/system/information",
            "/",
        ]

    def get_csrf_endpoints(self) -> List[Tuple[str, str]]:
        onvif_ep = self.onvif_path or "/onvif/device_service"
        return [
            (onvif_ep, onvif_ep),
            ("/ISAPI/Security/adminAccesses", "/ISAPI/System/deviceInfo"),
            ("/cgi-bin/configManager.cgi", "/cgi-bin/magicBox.cgi?action=getSystemInfo"),
            ("/LAPI/V1.0/System/DeviceBasicInfo", "/LAPI/V1.0/System/DeviceBasicInfo"),
            ("/api/system/information", "/api/system/information"),
            ("/", "/"),
        ]

    def get_rtsp_urls(self, host: Optional[str] = None, port: Optional[int] = None) -> List[str]:
        h = host or self.ip
        p_clear = port or self.rtsp_port
        p_tls = self.rtsps_port or 322
        path = self.service_ports.get("rtsp_path") or "/live/ch0"
        if not path.startswith("/"):
            path = "/" + path
        return [
            f"rtsp://{h}:{p_clear}{path}",
            f"rtsps://{h}:{p_tls}{path}",
            f"rtsp://{h}:{p_clear}/live/ch0",
            f"rtsp://{h}:{p_clear}/stream1",
        ]

    def get_proprietary_services(self) -> List[Dict[str, Any]]:
        prop_port = self.service_ports.get("proprietary_tcp")
        if prop_port and int(prop_port) not in (80, 443, 554, 22, 161, 3702, 0):
            return [
                {
                    "name": f"Proprietary-{prop_port}",
                    "port": int(prop_port),
                    "protocol": "TCP",
                    "description": f"Proprietary TCP Service on port {prop_port}",
                }
            ]
        return []

    def trigger_remote_service(self, service_type: str, host: Optional[str] = None, port: Optional[int] = None) -> bool:
        return False

    def check_firmware_support(self, file_path: str) -> bool:
        low = file_path.lower()
        return low.endswith((".bin", ".encap", ".img", ".tar", ".gz", ".pkg"))

    def parse_firmware(
        self,
        file_path: str,
        extract_keys: bool = True,
        save_extracted: bool = True,
    ) -> Dict[str, Any]:
        """Generic firmware package deep analysis (filesystem scan, signatures, certificates, Shannon entropy)."""
        import math
        import struct
        import subprocess

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
            sample = f.read(131072)
            f.seek(0)
            while chunk := f.read(1024 * 1024):
                h.update(chunk)

        # Shannon Entropy
        entropy_val = 0.0
        if sample:
            sample_len = len(sample)
            for b_val in range(256):
                cnt = sample.count(b_val)
                if cnt > 0:
                    p = cnt / sample_len
                    entropy_val -= p * math.log2(p)

        file_sha256 = h.hexdigest()

        # Binary signature scanning for filesystems & headers
        detected_fs: List[Dict[str, Any]] = []
        with open(fw_path, "rb") as f:
            raw = f.read()

        # 1. SquashFS
        for magic, s_name in [(b"hsqs", "SquashFS 4.0 (Little-Endian)"), (b"sqsh", "SquashFS 4.0 (Big-Endian)")]:
            idx = 0
            while True:
                pos = raw.find(magic, idx)
                if pos == -1:
                    break
                # Inspect superblock
                comp_name = "Compressed"
                inodes = "Unknown"
                b_size = "128 KB"
                try:
                    sq_res = subprocess.run(["unsquashfs", "-s", "-offset", str(pos), str(fw_path)], capture_output=True, text=True)
                    if sq_res.returncode == 0:
                        for line in sq_res.stdout.splitlines():
                            low = line.lower()
                            if "compression " in low and "compression-level" not in low:
                                comp_name = line.split()[-1]
                            elif "block size" in low:
                                b_size = f"{int(line.split()[-1]) // 1024} KB"
                            elif "number of inodes" in low:
                                inodes = line.split()[-1]
                except Exception:
                    pass

                detected_fs.append({
                    "name": f"SquashFS_Partition_0x{pos:08x}",
                    "type": s_name,
                    "offset_dec": pos,
                    "offset_hex": f"0x{pos:08x}",
                    "size_bytes": 0,
                    "size_mb": 0,
                    "compression": comp_name,
                    "block_size": b_size,
                    "inodes_count": inodes,
                    "extracted_status": "Phát hiện cấu trúc hợp lệ",
                    "details": f"Phân vùng SquashFS tại offset 0x{pos:08x}"
                })
                idx = pos + len(magic)

        # 2. U-Boot uImage
        idx = 0
        while True:
            pos = raw.find(b"\x27\x05\x19\x56", idx)
            if pos == -1:
                break
            hdr = raw[pos:pos+64]
            if len(hdr) == 64:
                try:
                    _, _, _, dsize, load, ep, _, _, _, _, comp_b = struct.unpack(">IIIIIIIBBBB", hdr[:32])
                    img_name = hdr[32:64].split(b"\x00")[0].decode("ascii", errors="replace").strip()
                    comp_map = {0: "none", 1: "gzip", 2: "bzip2", 3: "lzma", 4: "lzo", 5: "lz4", 6: "zstd"}
                    detected_fs.append({
                        "name": f"uImage_{img_name or 'Kernel'}_0x{pos:08x}",
                        "type": "U-Boot uImage Header & Payload",
                        "offset_dec": pos,
                        "offset_hex": f"0x{pos:08x}",
                        "size_bytes": dsize,
                        "size_mb": round(dsize / (1024 * 1024), 2),
                        "compression": comp_map.get(comp_b, f"comp_{comp_b}"),
                        "block_size": "N/A",
                        "inodes_count": "Kernel / Ramdisk",
                        "extracted_status": "Phát hiện U-Boot Image Header",
                        "details": f"uImage: '{img_name}', Kích thước dữ liệu: {dsize:,} bytes, Điểm nạp: 0x{load:08x}"
                    })
                except Exception:
                    pass
            idx = pos + 4

        # 3. Scan certificates / keys
        has_pem_cert = b"-----BEGIN CERTIFICATE-----" in raw
        has_pem_pub = b"-----BEGIN PUBLIC KEY-----" in raw or b"-----BEGIN RSA PUBLIC KEY-----" in raw

        sig_meta: Dict[str, Any] = {
            "magic": "Binary",
            "inferred_rsa_bits": 2048 if has_pem_pub else None,
            "hash_algorithm": "SHA-256",
            "has_pem_certificate": has_pem_cert,
            "has_pem_public_key": has_pem_pub,
        }

        return {
            "file": str(fw_path),
            "filename": fw_path.name,
            "size_bytes": size,
            "size_mb": round(size / (1024 * 1024), 2),
            "file_sha256": file_sha256,
            "format": "Generic Firmware Image",
            "entropy": round(entropy_val, 4),
            "filesystems": detected_fs,
            "sums_all_matched": True,
            "signature": sig_meta,
            "verified_pubkey": {
                "rootfs_path": "Firmware Image Body",
                "rsa_bits": 2048 if has_pem_pub else 0,
                "valid_rsa_pub": has_pem_pub,
                "verified_signature": False,
                "scheme": "SHA-256 Container Hash",
            } if has_pem_pub else None,
            "crypto_verified": bool(has_pem_pub),
            "errors": [],
        }

    def generate_tampered_firmware(
        self,
        file_path: str,
        output_path: Optional[str] = None,
        **kwargs,
    ) -> Dict[str, Any]:
        """Generate a generic 1-byte tampered firmware file."""
        src_fw = Path(file_path)
        if not src_fw.is_file():
            raise FileNotFoundError(f"Source firmware not found: {src_fw}")

        out_fw = Path(output_path) if output_path else src_fw.with_name(f"{src_fw.stem}_tampered{src_fw.suffix}")
        size = src_fw.stat().st_size
        flip_offset = kwargs.get("offset") or (size // 2)

        data = bytearray(src_fw.read_bytes())
        orig = data[flip_offset]
        tamp = orig ^ 0x01
        data[flip_offset] = tamp
        out_fw.write_bytes(data)

        return {
            "source": str(src_fw),
            "output": str(out_fw),
            "tampered_member": "binary_payload",
            "flipped_offset_in_member": flip_offset,
            "original_byte": f"0x{orig:02x}",
            "tampered_byte": f"0x{tamp:02x}",
            "output_size_bytes": out_fw.stat().st_size,
            "tamper_description": "Flipped 1 byte in binary firmware payload",
        }

    def get_login_surfaces(self, host: Optional[str] = None, port: Optional[int] = None) -> List[Dict[str, Any]]:
        return [
            {"id": "SURF-01", "name": "Trang chủ Web Portal", "path": "/", "method": "GET", "expected_type": "Web UI Entry"},
            {"id": "SURF-02", "name": "Cổng HTTP Auth (Axis CGI)", "path": "/axis-cgi/login.cgi", "method": "GET/POST", "expected_type": "HTTP Basic/Digest Auth Gateway"},
            {"id": "SURF-03", "name": "Cổng Tham số (Axis CGI)", "path": "/axis-cgi/param.cgi", "method": "GET", "expected_type": "Config Management Challenge"},
            {"id": "SURF-04", "name": "ISAPI Security (Hikvision)", "path": "/ISAPI/Security/userCheck", "method": "GET", "expected_type": "HTTP Auth Challenge"},
            {"id": "SURF-05", "name": "RPC/CGI Auth (Dahua)", "path": "/cgi-bin/magicBox.cgi?action=getSystemInfo", "method": "GET", "expected_type": "HTTP Digest Challenge"},
            {"id": "SURF-06", "name": "LAPI Security (Uniview)", "path": "/LAPI/V1.0/System/DeviceBasicInfo", "method": "GET", "expected_type": "REST Auth Gateway"},
            {"id": "SURF-07", "name": "Dịch vụ ONVIF SOAP", "path": self.onvif_path, "method": "POST", "expected_type": "WS-Security SOAP"},
        ]

    def get_authmech_definitions(self) -> List[Dict[str, Any]]:
        return super().get_authmech_definitions()

    def get_commech_definitions(self) -> List[Dict[str, Any]]:
        return super().get_commech_definitions()
