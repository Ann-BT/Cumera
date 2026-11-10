#!/usr/bin/env python3
"""
Camera Discovery & Universal QCVN 11 Auditor CLI
Author: Merlin / Antigravity
"""

import sys
import os
import json
import socket
import argparse
from typing import List, Dict, Any

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt

console = Console()
TOOLKIT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(TOOLKIT_DIR, "config.json")

def discover_onvif_cameras(timeout: float = 2.5) -> List[Dict[str, str]]:
    """Broadcast WS-Discovery to find all ONVIF cameras on the subnet."""
    probe_xml = """<?xml version="1.0" encoding="utf-8"?>
<Envelope xmlns="http://www.w3.org/2003/05/soap-envelope">
  <Header>
    <wsa:To xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing">urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>
    <wsa:Action xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing">http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action>
    <wsa:MessageID xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing">uuid:psi-discovery-probe</wsa:MessageID>
  </Header>
  <Body>
    <Probe xmlns="http://schemas.xmlsoap.org/ws/2005/04/discovery">
      <Types xmlns:dp0="http://www.onvif.org/ver10/network/wsdl">dp0:NetworkVideoTransmitter</Types>
    </Probe>
  </Body>
</Envelope>"""

    cameras = {}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.settimeout(timeout)

    try:
        sock.sendto(probe_xml.encode('utf-8'), ('239.255.255.250', 3702))
        while True:
            try:
                data, addr = sock.recvfrom(8192)
                ip = addr[0]
                text = data.decode(errors='ignore')
                
                # Extract hardware model / name
                model = "Unknown Model"
                mac = "Unknown MAC"
                scopes = ""
                
                if "<d:Scopes>" in text:
                    scopes_part = text.split("<d:Scopes>")[1].split("</d:Scopes>")[0]
                    scopes = scopes_part
                    for item in scopes_part.split():
                        if "hardware/" in item:
                            model = item.split("hardware/")[-1]
                        elif "name/" in item and model == "Unknown Model":
                            model = item.split("name/")[-1]
                        elif "MAC/" in item:
                            mac = item.split("MAC/")[-1]

                xaddrs = ""
                if "<d:XAddrs>" in text:
                    xaddrs = text.split("<d:XAddrs>")[1].split("</d:XAddrs>")[0].strip()

                cameras[ip] = {
                    "ip": ip,
                    "model": model,
                    "mac": mac,
                    "xaddrs": xaddrs,
                    "raw_scopes": scopes
                }
            except socket.timeout:
                break
    finally:
        sock.close()

    return list(cameras.values())

def load_config() -> Dict[str, Any]:
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}

def save_config(cfg: Dict[str, Any]):
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)

def set_target_camera(ip: str, model: str = None, username: str = None, password: str = None):
    cfg = load_config()
    if "target_camera" not in cfg:
        cfg["target_camera"] = {}
    
    cfg["target_camera"]["ip"] = ip
    if model:
        cfg["target_camera"]["model"] = model
    if username:
        cfg["target_camera"]["username"] = username
    if password:
        cfg["target_camera"]["password"] = password
    
    save_config(cfg)

def show_camera_table(cameras: List[Dict[str, str]], active_ip: str = ""):
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
            cam["xaddrs"].split()[0] if cam["xaddrs"] else "N/A",
            status
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

    console.print(Panel.fit("[bold blue]PSI CAMERA DISCOVERY & AUDIT TOOLKIT (QCVN 11:2026/BCA)[/bold blue]\n[dim]Quét mạng tự động phát hiện thiết bị và chuyển đổi camera một chạm[/dim]"))

    with console.status("[bold green]Đang phát sóng WS-Discovery trên mạng cục bộ..."):
        cameras = discover_onvif_cameras()

    if not cameras:
        console.print("[yellow][!] Không tìm thấy camera nào phản hồi qua WS-Discovery.[/yellow]")
        console.print(f"[dim]Mục tiêu hiện tại trong config.json: {current_ip}[/dim]")
        console.print("[bold cyan][*] Gợi ý:[/bold cyan] Nếu camera ở dải IP khác hoặc vừa cắm dây, hãy dùng mục [bold green][L] Auto-Link[/bold green] để tự động bắt IP và đổi dải card mạng.")
        return

    show_camera_table(cameras, active_ip=current_ip)

if __name__ == '__main__':
    main()
