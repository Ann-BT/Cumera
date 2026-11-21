#!/usr/bin/env python3
"""
hotspot_manager.py - Wi-Fi Hotspot Bridge Manager for Camera DUT Testing
Enables seamless AP hotspot bridging for IP cameras without Ethernet ports.
"""

import os
import re
import sys
import time
import subprocess
from typing import Dict, Any, List, Optional

HOTSPOT_CON = "Camera-Hotspot"
ORIGINAL_WIFI = "PSI_Xuan"
DEFAULT_IFACE = "wlp0s20f3"


def get_hotspot_status() -> Dict[str, Any]:
    """Retrieve the current state of Wi-Fi Hotspot, interface IP, and connected clients."""
    is_active = False
    current_con = ""
    ip_addr = ""

    # Check active connections via nmcli
    try:
        res = subprocess.run(
            ["nmcli", "-t", "-f", "NAME,DEVICE,STATE", "connection", "show", "--active"],
            capture_output=True,
            text=True,
            timeout=3,
        )
        for line in res.stdout.strip().splitlines():
            parts = line.split(":")
            if len(parts) >= 2:
                name, dev = parts[0], parts[1]
                if dev == DEFAULT_IFACE:
                    current_con = name
                    if name == HOTSPOT_CON:
                        is_active = True
    except Exception:
        pass

    # Get IP on DEFAULT_IFACE
    try:
        ip_res = subprocess.run(
            ["ip", "-4", "-o", "addr", "show", DEFAULT_IFACE],
            capture_output=True,
            text=True,
            timeout=2,
        )
        m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)", ip_res.stdout)
        if m:
            ip_addr = m.group(1)
    except Exception:
        pass

    # Retrieve profile settings (SSID)
    ssid = "Merlin_2.4G"
    try:
        cfg_res = subprocess.run(
            ["nmcli", "-s", "-g", "802-11-wireless.ssid", "connection", "show", HOTSPOT_CON],
            capture_output=True,
            text=True,
            timeout=2,
        )
        if cfg_res.stdout.strip():
            ssid = cfg_res.stdout.strip()
    except Exception:
        pass

    # Connected clients on DEFAULT_IFACE
    clients: List[Dict[str, str]] = []
    if is_active:
        try:
            neigh_res = subprocess.run(
                ["ip", "-4", "neigh", "show", "dev", DEFAULT_IFACE],
                capture_output=True,
                text=True,
                timeout=2,
            )
            for line in neigh_res.stdout.strip().splitlines():
                parts = line.split()
                if len(parts) >= 4 and "lladdr" in parts:
                    client_ip = parts[0]
                    ll_idx = parts.index("lladdr")
                    if ll_idx + 1 < len(parts):
                        client_mac = parts[ll_idx + 1]
                        state = parts[-1]
                        if client_ip != ip_addr and not client_ip.endswith(".255"):
                            clients.append({
                                "ip": client_ip,
                                "mac": client_mac,
                                "state": state
                            })
        except Exception:
            pass

    return {
        "active": is_active,
        "current_connection": current_con,
        "original_wifi": ORIGINAL_WIFI,
        "interface": DEFAULT_IFACE,
        "gateway_ip": ip_addr or ("10.42.0.1" if is_active else ""),
        "ssid": ssid,
        "band": "2.4GHz (bg)",
        "clients": clients,
    }


def start_hotspot(ssid: Optional[str] = None, password: Optional[str] = None) -> Dict[str, Any]:
    """Activate the Camera-Hotspot connection, updating credentials if provided."""
    try:
        chk = subprocess.run(["nmcli", "connection", "show", HOTSPOT_CON], capture_output=True)
        if chk.returncode != 0:
            subprocess.run([
                "nmcli", "connection", "add", "type", "wifi",
                "ifname", DEFAULT_IFACE, "con-name", HOTSPOT_CON,
                "autoconnect", "no", "ssid", ssid or "Merlin_2.4G"
            ], check=True, timeout=5)

        if ssid:
            subprocess.run(["nmcli", "connection", "modify", HOTSPOT_CON, "802-11-wireless.ssid", ssid], timeout=3)
        if password:
            subprocess.run(["nmcli", "connection", "modify", HOTSPOT_CON, "wifi-sec.psk", password], timeout=3)

        subprocess.run([
            "nmcli", "connection", "modify", HOTSPOT_CON,
            "802-11-wireless.mode", "ap",
            "802-11-wireless.band", "bg",
            "802-11-wireless.channel", "6",
            "ipv4.method", "shared",
            "wifi-sec.key-mgmt", "wpa-psk"
        ], timeout=3)

        up_res = subprocess.run(["nmcli", "connection", "up", HOTSPOT_CON], capture_output=True, text=True, timeout=10)
        if up_res.returncode != 0:
            return {"status": "error", "message": f"Không thể bật Hotspot: {up_res.stderr.strip()}"}

        # Đảm bảo NAT Forwarding từ wlp0s20f3 sang enp3s0 không bị chặn bởi Docker / Firewalld
        try:
            subprocess.run(["sudo", "-n", "iptables", "-I", "FORWARD", "1", "-i", DEFAULT_IFACE, "-o", "enp3s0", "-j", "ACCEPT"], capture_output=True)
            subprocess.run(["sudo", "-n", "iptables", "-I", "FORWARD", "2", "-i", "enp3s0", "-o", DEFAULT_IFACE, "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"], capture_output=True)
            subprocess.run(["sudo", "-n", "iptables", "-t", "nat", "-I", "POSTROUTING", "1", "-s", "10.42.0.0/24", "-o", "enp3s0", "-j", "MASQUERADE"], capture_output=True)
        except Exception:
            pass

        time.sleep(1)
        return {"status": "ok", "message": "Đã kích hoạt Hotspot thành công", "data": get_hotspot_status()}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def stop_hotspot() -> Dict[str, Any]:
    """Deactivate Hotspot and immediately restore the original Wi-Fi connection."""
    try:
        subprocess.run(["nmcli", "connection", "down", HOTSPOT_CON], capture_output=True, timeout=5)
        subprocess.run(["nmcli", "connection", "up", ORIGINAL_WIFI], capture_output=True, timeout=10)
        time.sleep(1)
        return {"status": "ok", "message": f"Đã tắt Hotspot và kết nối lại {ORIGINAL_WIFI}", "data": get_hotspot_status()}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def ping_client(ip: str) -> Dict[str, Any]:
    """Quick ICMP ping probe against a connected camera IP."""
    try:
        res = subprocess.run(["ping", "-c", "2", "-W", "1", ip], capture_output=True, text=True, timeout=3)
        return {
            "status": "ok" if res.returncode == 0 else "unreachable",
            "ip": ip,
            "alive": res.returncode == 0,
            "output": res.stdout
        }
    except Exception as e:
        return {"status": "error", "ip": ip, "alive": False, "message": str(e)}
