#!/usr/bin/env python3
"""
Camera Discovery & Universal QCVN 11 Auditor CLI
Author: Merlin / Antigravity
"""

import argparse
import os
import platform
import re
import select
import socket
import subprocess
import sys
import time
import urllib.parse
import uuid
from typing import Any, Dict, List

TOOLKIT_DIR = os.path.dirname(os.path.abspath(__file__))
if TOOLKIT_DIR not in sys.path:
    sys.path.insert(0, TOOLKIT_DIR)

from rich.panel import Panel
from rich.table import Table

from toolkit_config import (
    CONF_PATH,
    get_service_ports,
    list_local_ipv4_interfaces,
    load_config,
    make_console,
    parse_onvif_xaddr,
    save_config,
)

console = make_console()
CONFIG_PATH = CONF_PATH


def _build_ws_probe_xml(with_types: bool = False) -> bytes:
    types_block = (
        '<d:Types xmlns:dn="http://www.onvif.org/ver10/network/wsdl">dn:NetworkVideoTransmitter</d:Types>'
        if with_types
        else ""
    )
    xml = (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope" '
        'xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
        'xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery">'
        '<e:Header>'
        f'<w:MessageID>uuid:{uuid.uuid4()}</w:MessageID>'
        '<w:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>'
        '<w:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>'
        '</e:Header>'
        f'<e:Body><d:Probe>{types_block}</d:Probe></e:Body>'
        '</e:Envelope>'
    )
    return xml.encode("utf-8")


def _get_arp_neighbors() -> Dict[str, str]:
    """Return mapping {ip: mac} from OS ARP/neighbor cache for unicast WS-Discovery fallback."""
    neighbors: Dict[str, str] = {}
    if platform.system() == "Linux":
        try:
            proc = subprocess.run(["ip", "-o", "-4", "neigh", "show"], capture_output=True, text=True, timeout=2)
            for line in proc.stdout.splitlines():
                m = re.match(
                    r"^(\d+\.\d+\.\d+\.\d+)\s+dev\s+\S+(?:\s+lladdr\s+([0-9a-fA-F:]+))?\s+(\S+)$",
                    line.strip(),
                )
                if m and m.group(3) in ("REACHABLE", "STALE", "DELAY", "PROBE"):
                    neighbors[m.group(1)] = (m.group(2) or "Unknown MAC").upper()
        except Exception:
            pass
    elif platform.system() == "Windows":
        try:
            proc = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=2)
            for line in proc.stdout.splitlines():
                m = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})\s+dynamic", line)
                if m:
                    neighbors[m.group(1)] = m.group(2).replace("-", ":").upper()
        except Exception:
            pass
    return neighbors


def _parse_probe_match(ip: str, data: bytes, arp_map: Dict[str, str]) -> Dict[str, Any]:
    text = data.decode(errors="ignore")
    model = "Unknown Model"
    mac = arp_map.get(ip, "Unknown MAC")
    scopes = ""
    xaddrs = ""

    m_scopes = re.search(r"<[^:>]*:?Scopes[^>]*>(.*?)</[^:>]*:?Scopes>", text, re.DOTALL | re.IGNORECASE)
    if m_scopes:
        scopes = m_scopes.group(1).strip()
        hw_val = ""
        name_val = ""
        for item in scopes.split():
            dec = urllib.parse.unquote(item)
            if "/hardware/" in dec:
                hw_val = dec.split("/hardware/")[-1].strip("/")
            elif "/name/" in dec:
                name_val = dec.split("/name/")[-1].strip("/")
            elif "/MAC/" in dec:
                mac = dec.split("/MAC/")[-1].strip("/").upper()
        model = name_val or hw_val or model

    m_xaddrs = re.search(r"<[^:>]*:?XAddrs[^>]*>(.*?)</[^:>]*:?XAddrs>", text, re.DOTALL | re.IGNORECASE)
    if m_xaddrs:
        xaddrs = re.sub(r"\s+", " ", m_xaddrs.group(1)).strip()

    parsed_x = parse_onvif_xaddr(xaddrs)
    return {
        "ip": ip,
        "model": model,
        "mac": mac,
        "xaddrs": parsed_x["url"] or xaddrs,
        "all_xaddrs": xaddrs,
        "onvif_scheme": parsed_x["scheme"],
        "onvif_port": parsed_x["port"],
        "onvif_path": parsed_x["path"],
        "raw_scopes": scopes,
    }


def discover_onvif_cameras(timeout: float = 2.5) -> List[Dict[str, Any]]:
    """
    Discover ONVIF cameras across all active IPv4 NICs using:
    1) Per-interface multicast WS-Discovery (generic + NetworkVideoTransmitter),
    2) Subnet/global broadcast, and
    3) Unicast UDP WS-Discovery probe to reachable ARP neighbors & configured DUT IP.
    """
    cfg = load_config()
    sp = get_service_ports(cfg)
    ws_port = int(sp.get("onvif_ws_discovery_udp", 3702))
    arp_map = _get_arp_neighbors()

    # Build candidate sockets bound to each active interface + wildcard socket
    sockets: List[socket.socket] = []
    local_ifaces = list_local_ipv4_interfaces()
    for _, local_ip in local_ifaces:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(local_ip))
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            s.bind((local_ip, 0))
            s.setblocking(False)
            sockets.append(s)
        except Exception:
            pass

    if not sockets:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.setblocking(False)
        sockets.append(s)

    cameras: Dict[str, Dict[str, Any]] = {}
    unicast_targets = set(arp_map.keys())
    cur_dut = str(cfg.get("target_camera", {}).get("ip") or "").strip()
    if cur_dut:
        unicast_targets.add(cur_dut)

    try:
        for sock in sockets:
            # Multicast & broadcast generic + NVT probes (fresh UUID each time)
            for with_types in (False, True):
                payload = _build_ws_probe_xml(with_types=with_types)
                for dst in (("239.255.255.250", ws_port), ("255.255.255.255", ws_port)):
                    try:
                        sock.sendto(payload, dst)
                    except Exception:
                        pass

        # Unicast WS-Discovery fallback via primary/first socket for wired Ethernet cameras
        probe_sock = sockets[0]
        for u_ip in unicast_targets:
            # Skip obvious virtual/gateway .1 or .2? Keep .1 only if it replies with ONVIF XAddrs
            for dst_sock in sockets:
                try:
                    dst_sock.sendto(_build_ws_probe_xml(with_types=False), (u_ip, ws_port))
                    break
                except Exception:
                    continue
        del probe_sock

        deadline = time.monotonic() + max(0.8, timeout)
        while time.monotonic() < deadline:
            remaining = max(0.05, deadline - time.monotonic())
            readable, _, _ = select.select(sockets, [], [], min(0.25, remaining))
            if not readable:
                continue
            for rs in readable:
                try:
                    data, addr = rs.recvfrom(16384)
                    text = data.decode(errors="ignore")
                    if "ProbeMatches" not in text and "XAddrs" not in text:
                        continue
                    # Ignore non-camera Windows WSD host services (:5357 without ONVIF/NVT signatures)
                    if (
                        "onvif" not in text.lower()
                        and "networkvideotransmitter" not in text.lower()
                        and ":5357/" in text
                    ):
                        continue
                    ip = addr[0]
                    cameras[ip] = _parse_probe_match(ip, data, arp_map)
                except Exception:
                    pass
    finally:
        for sock in sockets:
            try:
                sock.close()
            except Exception:
                pass

    return list(cameras.values())


def set_target_camera(
    ip: str,
    model: str = None,
    username: str = None,
    password: str = None,
    xaddrs: str = None,
):
    cfg = load_config()
    if "target_camera" not in cfg:
        cfg["target_camera"] = {}

    cfg["target_camera"]["ip"] = ip.strip()
    if model:
        cfg["target_camera"]["model"] = model.strip()
    if username:
        cfg["target_camera"]["username"] = username
    if password:
        cfg["target_camera"]["password"] = password

    if xaddrs:
        parsed_x = parse_onvif_xaddr(xaddrs)
        sp = cfg.setdefault("service_ports", {})
        if parsed_x.get("path"):
            sp["onvif_path"] = parsed_x["path"]
        if parsed_x.get("scheme") == "https" and parsed_x.get("port"):
            sp["onvif_https"] = parsed_x["port"]
        elif parsed_x.get("scheme") == "http" and parsed_x.get("port"):
            sp["onvif_http"] = parsed_x["port"]

    save_config(cfg)


def show_camera_table(cameras: List[Dict[str, Any]], active_ip: str = ""):
    table = Table(title="[bold cyan]DANH SÁCH CAMERA PHÁT HIỆN TRÊN MẠNG (WS-Discovery)[/bold cyan]")
    table.add_column("STT", style="bold yellow", justify="center")
    table.add_column("IP Address", style="bold green")
    table.add_column("Model / Tên thiết bị", style="white")
    table.add_column("Địa chỉ MAC", style="cyan")
    table.add_column("XAddrs (Service URL)", style="magenta")
    table.add_column("Trạng thái", justify="center")

    for idx, cam in enumerate(cameras, start=1):
        status = "[bold green][ACTIVE][/bold green]" if cam["ip"] == active_ip else "[dim]Sẵn sàng[/dim]"
        table.add_row(
            str(idx),
            cam["ip"],
            cam["model"],
            cam["mac"],
            cam.get("xaddrs") or "N/A",
            status,
        )

    console.print(table)


def main():
    parser = argparse.ArgumentParser(description="Camera Multi-Device Manager & Scanner")
    parser.add_argument("--scan", action="store_true", help="Quét nhanh toàn bộ camera trên subnet")
    parser.add_argument("--set-target", type=str, help="Chọn IP camera làm mục tiêu kiểm thử")
    parser.add_argument("--user", type=str, help="Username camera")
    parser.add_argument("--pwd", type=str, help="Password camera")
    args = parser.parse_args()

    cfg = load_config()
    current_ip = cfg.get("target_camera", {}).get("ip", "")

    if args.set_target:
        set_target_camera(args.set_target, username=args.user, password=args.pwd)
        console.print(f"[bold green][OK] Đã cập nhật mục tiêu đo kiểm sang: {args.set_target}[/bold green]")
        return

    console.print(
        Panel.fit(
            "[bold blue]PSI CAMERA DISCOVERY & AUDIT TOOLKIT (QCVN 11:2026/BCA)[/bold blue]\n"
            "[dim]Quét mạng tự động phát hiện thiết bị và chuyển đổi camera một chạm[/dim]"
        )
    )

    with console.status("[bold green]Đang phát sóng WS-Discovery trên các giao diện mạng..."):
        cameras = discover_onvif_cameras()

    if not cameras:
        console.print("[yellow][!] Không tìm thấy camera nào phản hồi qua WS-Discovery.[/yellow]")
        console.print(f"[dim]Mục tiêu hiện tại trong config.json: {current_ip}[/dim]")
        console.print(
            "[bold cyan][*] Gợi ý:[/bold cyan] Nếu camera ở dải IP khác hoặc vừa cắm dây, "
            "hãy dùng mục [bold green][L] Auto-Link[/bold green] để tự động bắt IP và đổi dải card mạng."
        )
        return

    show_camera_table(cameras, active_ip=current_ip)


if __name__ == "__main__":
    main()
