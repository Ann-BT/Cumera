#!/usr/bin/env python3
"""
Universal SNMP-V3 Security & Cryptographic Auditor
Author: Merlin / Antigravity
Exhaustively tests SNMPv3 security levels and cryptographic cipher combinations:
  - noAuthNoPriv (Unauthenticated query)
  - authNoPriv (Integrity without Privacy) with MD5, SHA-1, SHA-256
  - authPriv (Integrity + Privacy) with AES-256, AES-128, DES-56
Evaluates anti-downgrade defenses and cryptographic strength.
"""

import asyncio
import sys
import json
import os
import subprocess
import re
import time
from datetime import datetime
from typing import Dict, List, Any, Tuple

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

CONF_PATH = os.path.join(os.path.dirname(__file__), "config.json")
CONFIG = {}
if os.path.exists(CONF_PATH):
    try:
        with open(CONF_PATH, encoding="utf-8") as f:
            CONFIG = json.load(f)
    except Exception:
        pass

DUT_IP = CONFIG.get("target_camera", {}).get("ip", "192.168.101.208")
SNMP_PORT = CONFIG.get("service_ports", {}).get("snmp", 161)
USER = CONFIG.get("snmp_v3", {}).get("user", "admin")
AUTH_PASS = CONFIG.get("snmp_v3", {}).get("auth_pass", "Psitest135#")
PRIV_PASS = CONFIG.get("snmp_v3", {}).get("priv_pass", "Psitest135#")

from pysnmp.hlapi.asyncio import (
    SnmpEngine, UsmUserData, UdpTransportTarget, ContextData,
    ObjectType, ObjectIdentity, get_cmd,
    usmHMAC192SHA256AuthProtocol, usmHMACSHAAuthProtocol, usmHMACMD5AuthProtocol,
    usmNoAuthProtocol,
    usmAesCfb256Protocol, usmAesCfb128Protocol, usmDESPrivProtocol, usmNoPrivProtocol
)

TEST_COMBINATIONS = [
    {
        "name": "authPriv (SHA-256 + AES-256)",
        "level": "authPriv (Bảo mật tối đa)",
        "auth_proto": usmHMAC192SHA256AuthProtocol,
        "priv_proto": usmAesCfb256Protocol,
        "use_auth": True,
        "use_priv": True,
        "sec_type": "Recommended (SOGIS 'R')"
    },
    {
        "name": "authPriv (SHA-256 + AES-128)",
        "level": "authPriv (Tiêu chuẩn)",
        "auth_proto": usmHMAC192SHA256AuthProtocol,
        "priv_proto": usmAesCfb128Protocol,
        "use_auth": True,
        "use_priv": True,
        "sec_type": "Recommended (SOGIS 'R')"
    },
    {
        "name": "authPriv (SHA-1 + AES-128)",
        "level": "authPriv (Hạ cấp Auth SHA-1)",
        "auth_proto": usmHMACSHAAuthProtocol,
        "priv_proto": usmAesCfb128Protocol,
        "use_auth": True,
        "use_priv": True,
        "sec_type": "Legacy (Cần thay thế)"
    },
    {
        "name": "authPriv (SHA-256 + DES-56)",
        "level": "authPriv (Hạ cấp Priv DES)",
        "auth_proto": usmHMAC192SHA256AuthProtocol,
        "priv_proto": usmDESPrivProtocol,
        "use_auth": True,
        "use_priv": True,
        "sec_type": "Forbidden (Mã DES yếu)"
    },
    {
        "name": "authPriv (MD5 + DES-56)",
        "level": "authPriv (MD5 băm yếu + DES)",
        "auth_proto": usmHMACMD5AuthProtocol,
        "priv_proto": usmDESPrivProtocol,
        "use_auth": True,
        "use_priv": True,
        "sec_type": "Forbidden (Bị cấm)"
    },
    {
        "name": "authNoPriv (SHA-256 không mã hóa)",
        "level": "authNoPriv (Hạ cấp kênh rõ)",
        "auth_proto": usmHMAC192SHA256AuthProtocol,
        "priv_proto": usmNoPrivProtocol,
        "use_auth": True,
        "use_priv": False,
        "sec_type": "Insecure (Lộ dữ liệu rõ)"
    },
    {
        "name": "authNoPriv (MD5 không mã hóa)",
        "level": "authNoPriv (MD5 rõ)",
        "auth_proto": usmHMACMD5AuthProtocol,
        "priv_proto": usmNoPrivProtocol,
        "use_auth": True,
        "use_priv": False,
        "sec_type": "Insecure (Lộ dữ liệu rõ)"
    },
    {
        "name": "noAuthNoPriv (Không xác thực / Không mã hóa)",
        "level": "noAuthNoPriv (Vô hiệu hóa toàn bộ)",
        "auth_proto": usmNoAuthProtocol,
        "priv_proto": usmNoPrivProtocol,
        "use_auth": False,
        "use_priv": False,
        "sec_type": "High Risk (Nguy hiểm)"
    }
]

async def probe_snmpv3_combo(combo: Dict[str, Any], host: str, port: int) -> Dict[str, Any]:
    snmp_engine = SnmpEngine()
    transport = await UdpTransportTarget.create((host, port), timeout=1.8, retries=0)
    
    if combo["use_auth"] and combo["use_priv"]:
        user_data = UsmUserData(USER, authKey=AUTH_PASS, privKey=PRIV_PASS,
                                authProtocol=combo["auth_proto"], privProtocol=combo["priv_proto"])
    elif combo["use_auth"] and not combo["use_priv"]:
        user_data = UsmUserData(USER, authKey=AUTH_PASS,
                                authProtocol=combo["auth_proto"], privProtocol=usmNoPrivProtocol)
    else:
        user_data = UsmUserData(USER, authProtocol=usmNoAuthProtocol, privProtocol=usmNoPrivProtocol)

    try:
        errorIndication, errorStatus, errorIndex, varBinds = await get_cmd(
            snmp_engine,
            user_data,
            transport,
            ContextData(),
            ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0))
        )
        if errorIndication:
            return {"accepted": False, "detail": f"Từ chối ({errorIndication})"}
        elif errorStatus:
            return {"accepted": False, "detail": f"Từ chối ({errorStatus.prettyPrint()})"}
        else:
            val = str(varBinds[0][1]) if varBinds else "OK"
            return {"accepted": True, "detail": f"Chấp nhận (sysDescr: {val[:50]}...)"}
    except Exception as e:
        return {"accepted": False, "detail": f"Lỗi ({type(e).__name__})"}

def detect_outbound_interface(dest_ip: str) -> str:
    """Finds the network interface routed to dest_ip."""
    try:
        cmd = f"ip route get {dest_ip}"
        out = subprocess.check_output(cmd, shell=True, text=True)
        m = re.search(r'dev\s+([a-zA-Z0-9_\-]+)', out)
        if m:
            return m.group(1)
    except Exception:
        pass
    return "enp3s0"

async def run_snmp_audit(host: str, port: int, capture_pcap: bool = True) -> Tuple[List[Dict[str, Any]], str]:
    captures_dir = os.path.join(os.path.dirname(__file__), "captures")
    os.makedirs(captures_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    pcap_file = os.path.join(captures_dir, f"snmpv3_audit_{timestamp}.pcap")
    iface = detect_outbound_interface(host)

    tshark_proc = None
    if capture_pcap:
        try:
            tshark_cmd = [
                "tshark", "-i", iface,
                "-f", f"udp port {port}",
                "-w", pcap_file,
                "-q"
            ]
            tshark_proc = subprocess.Popen(tshark_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            await asyncio.sleep(0.4)
        except Exception:
            tshark_proc = None

    results = []
    try:
        for c in TEST_COMBINATIONS:
            r = await probe_snmpv3_combo(c, host, port)
            results.append({**c, **r})
    finally:
        if tshark_proc:
            try:
                tshark_proc.terminate()
                tshark_proc.wait(timeout=2.0)
            except Exception:
                pass

    return results, pcap_file

def display_snmp_audit(host: str, port: int, results: List[Dict[str, Any]], pcap_file: str = ""):
    console.print(Panel(
        f"[bold cyan]ĐO KIỂM & PHÂN TÍCH MẬT MÃ DỊCH VỤ SNMP-V3[/bold cyan]\n"
        f"Mục tiêu: [bold white]{host}:{port}[/bold white] | Tài khoản: [bold green]{USER}[/bold green]",
        border_style="cyan"
    ))

    table = Table(title="MA TRẬN KIỂM THỬ MỨC ĐỘ BẢO MẬT & THUẬT TOÁN SNMP-V3", show_lines=True)
    table.add_column("Cấu hình kiểm tra", style="bold white", width=32)
    table.add_column("Mức bảo mật", width=22)
    table.add_column("Phân loại an toàn", justify="center", width=22)
    table.add_column("Kết quả phản hồi của Camera", width=35)

    for item in results:
        if item["accepted"]:
            status_badge = f"[bold green][PASS] CHẤP NHẬN[/bold green]\n{item['detail']}"
        else:
            status_badge = f"[bold red][BLOCKED] TỪ CHỐI / CHẶN[/bold red]\n[dim]{item['detail']}[/dim]"
        
        table.add_row(item["name"], item["level"], item["sec_type"], status_badge)

    console.print(table)

    # Conclude
    accepted_combos = [i for i in results if i["accepted"]]
    console.print("\n[bold white]KẾT LUẬN ĐỐI SOÁT KỸ THUẬT SNMP-V3:[/bold white]")
    if any("noAuth" in a["name"] or "authNoPriv" in a["name"] for a in accepted_combos):
        console.print("  • [bold red][FAIL] NGUY CƠ: Thiết bị chấp nhận kết nối SNMP không mã hóa (kênh truyền rõ).[/bold red]")
    else:
        console.print("  • [bold green][PASS] AN TOÀN: Thiết bị chặn đứng hoàn toàn các yêu cầu không mã hóa (noAuthNoPriv / authNoPriv).[/bold green]")

    if any("DES" in a["name"] or "MD5" in a["name"] for a in accepted_combos):
        console.print("  • [bold red][WARN] CẢNH BÁO: Thiết bị hỗ trợ các thuật toán mật mã yếu bị cấm (DES-56 / MD5).[/bold red]")
    else:
        console.print("  • [bold green][PASS] AN TOÀN: Thiết bị từ chối các thuật toán lỗi thời DES và MD5.[/bold green]")

    strong_combos = [a for a in accepted_combos if "AES" in a["name"] and "SHA-256" in a["name"]]
    if strong_combos:
        console.print(f"  • [bold green][PASS] ĐẠT CHUẨN: Hoạt động chính xác ở mức authPriv với thuật toán chuẩn SOGIS: {strong_combos[0]['name']}.[/bold green]")

    if pcap_file and os.path.exists(pcap_file) and os.path.getsize(pcap_file) > 0:
        console.print(f"\n[bold yellow][OK] File bắt gói tin chuẩn Wireshark đã lưu tại:[/bold yellow] [bold white]{pcap_file}[/bold white]")
        console.print(f"  (Mở trực tiếp bằng lệnh: [bold green]wireshark {pcap_file}[/bold green])\n")

    console.print(Panel(
        "[bold yellow][WIRESHARK FILTERS] BỘ LỌC & CÂU LỆNH SORT ĐỐI SOÁT GÓI TIN SNMP-V3 TRONG WIRESHARK:[/bold yellow]\n"
        "  • [bold cyan]1. Lọc toàn bộ gói tin SNMPv3:[/bold cyan] [bold green]snmp.version == 3 || (udp.port == 161 && snmp)[/bold green]\n"
        "  • [bold cyan]2. Lọc gói tin đăng nhập thành công (Trả về dữ liệu sysDescr):[/bold cyan] [bold green]snmp.version == 3 && snmp.error_status == 0[/bold green]\n"
        "  • [bold cyan]3. Lọc gói tin mã hóa mức tối đa (authPriv):[/bold cyan] [bold green]snmp.msgFlags.auth == 1 && snmp.msgFlags.priv == 1[/bold green]\n"
        "  • [bold cyan]4. Lọc gói tin theo tài khoản đăng nhập:[/bold cyan] [bold green]snmp.msgUserName == \"admin\"[/bold green]\n"
        "  • [bold cyan]5. Lọc gói tin bị từ chối / lỗi xác thực:[/bold cyan] [bold green]snmp.usmStatsWrongDigests || snmp.usmStatsUnknownUserNames[/bold green]\n\n"
        "[dim][NOTE] Hướng dẫn Sort: Click tiêu đề cột [bold white]No.[/bold white] để sắp xếp tăng/giảm theo thứ tự phát sinh gói tin, hoặc bấm [bold white]Ctrl + G[/bold white] để nhảy trực tiếp đến số gói tin.[/dim]",
        border_style="yellow"
    ))

if __name__ == '__main__':
    h = sys.argv[1] if len(sys.argv) > 1 else DUT_IP
    p = int(sys.argv[2]) if len(sys.argv) > 2 else SNMP_PORT
    res, pcap = asyncio.run(run_snmp_audit(h, p, capture_pcap=True))
    display_snmp_audit(h, p, res, pcap)
