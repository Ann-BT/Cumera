#!/usr/bin/env python3
"""
Unit test for Vendor Camera Adapters & Profile Integration in QCVN 11 Toolkit.
"""

import sys
import unittest

from adapters import (
    AxisCameraAdapter,
    BaseCameraAdapter,
    GenericCameraAdapter,
    OryzaCameraAdapter,
    get_camera_adapter,
)
from toolkit_config import (
    get_active_profile,
    get_adapter,
    load_config,
    switch_profile,
)


class TestCameraAdapters(unittest.TestCase):
    def setUp(self):
        # Save initial active profile to restore later
        self.initial_profile = get_active_profile()

    def tearDown(self):
        # Restore initial profile
        if get_active_profile() != self.initial_profile:
            switch_profile(self.initial_profile)

    def test_factory_with_axis_config(self):
        axis_cfg = {
            "active_profile": "axis_q1806_le",
            "vendor": "Axis Communications",
            "model": "Q1806-LE",
            "target_camera": {"ip": "192.168.99.132"},
            "service_ports": {"rtsp": 554, "rtsps": 322, "rtsp_path": "/axis-media/media.amp"},
        }
        adapter = get_camera_adapter(axis_cfg)
        self.assertIsInstance(adapter, AxisCameraAdapter)
        self.assertTrue(issubclass(type(adapter), BaseCameraAdapter))

        # Check Axis Web Auth endpoints
        auth_eps = adapter.get_web_auth_endpoints()
        self.assertEqual(auth_eps[0], "/axis-cgi/param.cgi?action=list&group=root.Brand")

        # Check Axis Config & CSRF endpoints
        cfg_eps = adapter.get_config_endpoints()
        self.assertIn("/axis-cgi/param.cgi", cfg_eps)

        csrf_eps = adapter.get_csrf_endpoints()
        self.assertEqual(csrf_eps[0], ("/axis-cgi/param.cgi", "/axis-cgi/param.cgi?action=list&group=root.Brand"))

        # Check RTSP URLs
        rtsp_urls = adapter.get_rtsp_urls()
        self.assertTrue(any("/axis-media/media.amp" in u for u in rtsp_urls))

        # Check Proprietary Services (Axis has none)
        self.assertEqual(adapter.get_proprietary_services(), [])

        # Check Firmware support
        self.assertTrue(adapter.check_firmware_support("firmware.bin"))
        self.assertFalse(adapter.check_firmware_support("firmware.encap"))

    def test_factory_with_oryza_config(self):
        oryza_cfg = {
            "active_profile": "oryza_orz_b52z",
            "vendor": "Oryza Systems",
            "hardware_heritage": "Tiandy",
            "model": "ORZ-B52Z-AJBMIR60-S1",
            "target_camera": {"ip": "192.168.1.100"},
            "service_ports": {"rtsp": 554, "rtsps": 443, "proprietary_tcp": 20001},
        }
        adapter = get_camera_adapter(oryza_cfg)
        self.assertIsInstance(adapter, OryzaCameraAdapter)

        # Check Oryza Web Auth endpoints
        auth_eps = adapter.get_web_auth_endpoints()
        self.assertIn("/", auth_eps)
        self.assertIn("/index.html", auth_eps)
        self.assertIn("/onvif/device_service", auth_eps)

        # Check Oryza RTSP endpoints
        rtsp_urls = adapter.get_rtsp_urls()
        self.assertTrue(any("/stream1" in u for u in rtsp_urls))
        self.assertTrue(any("/live/ch0" in u for u in rtsp_urls))

        # Check Proprietary CMS Port 20001
        prop_services = adapter.get_proprietary_services()
        self.assertEqual(len(prop_services), 1)
        self.assertEqual(prop_services[0]["name"], "CMS")
        self.assertEqual(prop_services[0]["port"], 20001)
        self.assertEqual(prop_services[0]["protocol"], "TCP/TLS")

        # Check Firmware support (.encap and .bin)
        self.assertTrue(adapter.check_firmware_support("update.encap"))
        self.assertTrue(adapter.check_firmware_support("update.bin"))
        self.assertFalse(adapter.check_firmware_support("update.iso"))

    def test_oryza_firmware_parse_and_tamper(self):
        import os, tempfile
        oryza_adapter = OryzaCameraAdapter()
        real_encap = "/home/merlin/PSI/Version 3 - 261109/FW-2/Intermediate Version/v5.2.1615.2412.514.0.1.0.6.encap"
        if os.path.isfile(real_encap):
            parsed = oryza_adapter.parse_firmware(real_encap)
            self.assertEqual(parsed["format"], "Oryza / Tiandy ENCAP Firmware Package")
            self.assertEqual(parsed["magic_hex"], "09000001")
            self.assertTrue(parsed["magic_valid"])
            self.assertEqual(parsed["version"], "v5.2.1615.2412.514.0.1.0.6")
            self.assertIn("Intermediate", parsed["package_role"])
            self.assertEqual(parsed["ixit_declaration"]["signing_algorithm"], "RSA-3072 / SHA-256")
            self.assertTrue(parsed["crypto_verified"])

            # Test tampering in tempdir
            with tempfile.TemporaryDirectory() as tmpdir:
                out_path = os.path.join(tmpdir, "test_tampered.encap")
                tr = oryza_adapter.generate_tampered_firmware(real_encap, out_path)
                self.assertTrue(os.path.isfile(out_path))
                self.assertEqual(os.path.getsize(out_path), parsed["size_bytes"])
                self.assertNotEqual(tr["original_sha256"], tr["tampered_sha256"])
                self.assertEqual(tr["flipped_offset_in_member"], 1048576)

    def test_generic_fallback(self):
        generic_cfg = {
            "active_profile": "custom_cam",
            "vendor": "Unknown Cam Corp",
            "model": "IPC-100",
            "service_ports": {"proprietary_tcp": 9999},
        }
        adapter = get_camera_adapter(generic_cfg)
        self.assertIsInstance(adapter, GenericCameraAdapter)
        prop = adapter.get_proprietary_services()
        self.assertEqual(len(prop), 1)
        self.assertEqual(prop[0]["port"], 9999)

    def test_live_profile_switching(self):
        # 1. Switch to axis
        switch_profile("axis_q1806_le")
        self.assertEqual(get_active_profile(), "axis_q1806_le")
        axis_adapter = get_adapter()
        self.assertIsInstance(axis_adapter, AxisCameraAdapter)
        self.assertEqual(axis_adapter.get_web_auth_endpoints()[0], "/axis-cgi/param.cgi?action=list&group=root.Brand")
        self.assertEqual(axis_adapter.get_proprietary_services(), [])

        # 2. Switch to oryza
        switch_profile("oryza_orz_b52z")
        self.assertEqual(get_active_profile(), "oryza_orz_b52z")
        oryza_adapter = get_adapter()
        self.assertIsInstance(oryza_adapter, OryzaCameraAdapter)
        self.assertEqual(oryza_adapter.get_proprietary_services()[0]["port"], 20001)
        self.assertEqual(oryza_adapter.get_proprietary_services()[0]["name"], "CMS")

        # 3. Restore axis
        switch_profile("axis_q1806_le")
        self.assertEqual(get_active_profile(), "axis_q1806_le")


if __name__ == "__main__":
    unittest.main()
