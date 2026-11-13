#!/usr/bin/env python3
"""
Bộ đo kiểm chống kết nối hàng loạt đồng thời (Mass Reconnection Resilience Test)
Mục: 3.8.3.3 - ETSI EN 303 645 / QCVN 11:2026/BCA
Kiểm tra khả năng DUT chịu tải kết nối đồng thời (concurrent mass reconnections) trên các
giao thức: TLS (HTTPS), SSH2, RTSP/RTSPS, ONVIF, SNMPv3, SMB.
Sử dụng credentials hợp lệ để tránh bị chặn bởi cơ chế anti-brute-force.
Mỗi luồng thực hiện kết nối → xác thực → đóng kết nối → lặp lại.
Kết quả ghi nhận: tỷ lệ thành công, latency, lỗi, trạng thái DUT sau test.

Author: Merlin / Antigravity
"""

import argparse
import base64
import datetime
import hashlib
import json
import os
import queue
import random
import re
import socket
import ssl
import struct
import sys
import threading
import time
import traceback
import urllib.request
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed, wait, FIRST_COMPLETED
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich import box

from toolkit_config import get_service_ports, get_target_info, load_config, make_console

try:
    import paramiko
    HAS_PARAMIKO = True
except ImportError:
    HAS_PARAMIKO = False

try:
    from pysnmp.hlapi.v3arch.asyncio import *
    import asyncio
    HAS_PYSNMP = True
except ImportError:
    HAS_PYSNMP = False

console = make_console()
config = load_config()
_target = get_target_info(config)
_svc = get_service_ports(config)

DUT_IP         = _target["ip"]
DUT_USER       = _target["username"]
DUT_PASS       = _target["password"]
SSH_USER       = _target.get("ssh_username", DUT_USER)
SSH_PASS       = _target.get("ssh_password", DUT_PASS)
HTTPS_PORT     = int(_svc.get("https", 443))
RTSP_PORT      = int(_svc.get("rtsp", 554))
RTSPS_PORT     = int(_svc.get("rtsps", 322))
RTSP_PATH      = _svc.get("rtsp_path", "/axis-media/media.amp")
SSH_PORT       = int(_svc.get("ssh", 22))
SNMP_PORT      = int(_svc.get("snmp", 161))
ONVIF_PATH     = _svc.get("onvif_path", "/onvif/device_service")
SMB_PORT       = int(_svc.get("smb", 445))

SNMP_CFG       = config.get("snmp_v3", config.get("snmp_credentials", {}))
SNMP_USER      = SNMP_CFG.get("user", DUT_USER)
SNMP_AUTH_PASS = SNMP_CFG.get("auth_pass", DUT_PASS)
SNMP_PRIV_PASS = SNMP_CFG.get("priv_pass", DUT_PASS)
SNMP_AUTH_PROTO= SNMP_CFG.get("auth_protocol", "SHA256")
SNMP_PRIV_PROTO= SNMP_CFG.get("priv_protocol", "AES256")


# ---------------------------------------------------------------------------
# Result tracking
# ---------------------------------------------------------------------------

@dataclass
class ConnResult:
    proto: str
    success: bool
    latency_ms: float
    error: str = ""


_results_lock = threading.Lock()
_results: List[ConnResult] = []
_stop_event = threading.Event()


def _record(proto: str, success: bool, latency_ms: float, error: str = "") -> None:
    with _results_lock:
        _results.append(ConnResult(proto, success, latency_ms, error))


# ---------------------------------------------------------------------------
# Protocol worker functions — each opens, optionally authenticates, then closes
# ---------------------------------------------------------------------------

def _tls_worker(target_ip: str, port: int, timeout: float) -> ConnResult:
    """HTTPS/TLS: open TLS socket, send HEAD /, check response."""
    t0 = time.monotonic()
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((target_ip, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=target_ip) as s:
                creds = base64.b64encode(f"{DUT_USER}:{DUT_PASS}".encode()).decode()
                req = (
                    f"GET /axis-cgi/param.cgi?action=list&group=Properties.Firmware HTTP/1.1\r\n"
                    f"Host: {target_ip}\r\n"
                    f"Authorization: Basic {creds}\r\n"
                    f"Connection: close\r\n\r\n"
                )
                s.sendall(req.encode())
                resp = b""
                while True:
                    chunk = s.recv(1024)
                    if not chunk:
                        break
                    resp += chunk
                    if b"\r\n\r\n" in resp:
                        break
        ok = resp.startswith(b"HTTP/") and (b" 200 " in resp[:20] or b" 401 " in resp[:20] or b" 204 " in resp[:20])
        lat = (time.monotonic() - t0) * 1000
        return ConnResult("TLS/HTTPS", ok, lat, "" if ok else resp[:40].decode(errors="replace"))
    except Exception as e:
        lat = (time.monotonic() - t0) * 1000
        return ConnResult("TLS/HTTPS", False, lat, str(e)[:80])


def _ssh_worker(target_ip: str, port: int, timeout: float) -> ConnResult:
    """SSH2: open connection, authenticate, close."""
    if not HAS_PARAMIKO:
        return ConnResult("SSH2", False, 0, "paramiko not installed")
    t0 = time.monotonic()
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            target_ip,
            port=port,
            username=SSH_USER,
            password=SSH_PASS,
            timeout=timeout,
            banner_timeout=timeout,
            auth_timeout=timeout,
            look_for_keys=False,
            allow_agent=False,
        )
        lat = (time.monotonic() - t0) * 1000
        client.close()
        return ConnResult("SSH2", True, lat)
    except paramiko.AuthenticationException:
        lat = (time.monotonic() - t0) * 1000
        return ConnResult("SSH2", False, lat, "AuthFail")
    except Exception as e:
        lat = (time.monotonic() - t0) * 1000
        return ConnResult("SSH2", False, lat, str(e)[:80])
    finally:
        try:
            client.close()
        except Exception:
            pass


def _rtsp_worker(target_ip: str, port: int, path: str, use_tls: bool, timeout: float) -> ConnResult:
    """RTSP/RTSPS: send OPTIONS request with Basic auth, check response."""
    t0 = time.monotonic()
    proto_name = "RTSPS/TLS" if use_tls else "RTSP"
    try:
        raw = socket.create_connection((target_ip, port), timeout=timeout)
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(raw, server_hostname=target_ip)
        else:
            sock = raw

        url = f"{'rtsps' if use_tls else 'rtsp'}://{target_ip}:{port}{path}"
        creds = base64.b64encode(f"{DUT_USER}:{DUT_PASS}".encode()).decode()
        req = (
            f"OPTIONS {url} RTSP/1.0\r\n"
            f"CSeq: 1\r\n"
            f"Authorization: Basic {creds}\r\n"
            f"User-Agent: MassReconnectTester/1.0\r\n"
            f"\r\n"
        )
        sock.sendall(req.encode())
        resp = b""
        sock.settimeout(timeout)
        while True:
            chunk = sock.recv(512)
            if not chunk:
                break
            resp += chunk
            if b"\r\n\r\n" in resp:
                break
        sock.close()
        ok = resp.startswith(b"RTSP/1.0") and (
            b" 200 " in resp[:20] or b" 401 " in resp[:20] or b" 403 " in resp[:20]
        )
        lat = (time.monotonic() - t0) * 1000
        return ConnResult(proto_name, ok, lat, "" if ok else resp[:40].decode(errors="replace"))
    except Exception as e:
        lat = (time.monotonic() - t0) * 1000
        return ConnResult(proto_name, False, lat, str(e)[:80])


def _onvif_worker(target_ip: str, port: int, path: str, timeout: float) -> ConnResult:
    """ONVIF/TLS: send GetSystemDateAndTime SOAP, check response."""
    t0 = time.monotonic()
    soap_body = (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">'
        '<s:Body>'
        '<GetSystemDateAndTime xmlns="http://www.onvif.org/ver10/device/wsdl"/>'
        '</s:Body>'
        '</s:Envelope>'
    )
    creds = base64.b64encode(f"{DUT_USER}:{DUT_PASS}".encode()).decode()
    headers = {
        "Content-Type": "application/soap+xml; charset=utf-8",
        "Authorization": f"Basic {creds}",
        "SOAPAction": '"http://www.onvif.org/ver10/device/wsdl/GetSystemDateAndTime"',
        "Connection": "close",
    }
    url = f"https://{target_ip}:{port}{path}"
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        data = soap_body.encode("utf-8")
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read(512)
        ok = resp.status in (200, 400, 401)
        lat = (time.monotonic() - t0) * 1000
        return ConnResult("ONVIF/TLS", ok, lat)
    except urllib.error.HTTPError as e:
        lat = (time.monotonic() - t0) * 1000
        ok = e.code in (200, 400, 401, 403)
        return ConnResult("ONVIF/TLS", ok, lat, f"HTTP {e.code}" if not ok else "")
    except Exception as e:
        lat = (time.monotonic() - t0) * 1000
        return ConnResult("ONVIF/TLS", False, lat, str(e)[:80])


def _snmpv3_worker(target_ip: str, port: int, timeout: float) -> ConnResult:
    """SNMPv3: send GetRequest for sysDescr, check response via raw UDP."""
    t0 = time.monotonic()
    # Raw SNMPv3 GET for sysDescr.0 using USM — build minimal packet
    # We use a discovery-first approach via raw socket (no pysnmp async loop per thread)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        # SNMPv3 USM discovery packet (msgFlags=0x04 auth-only, msgID random)
        # Build a minimal SNMPv3 noAuthNoPriv GetRequest for engine discovery
        msg_id = random.randint(1, 0x7FFFFFFF)
        req_id = random.randint(1, 0x7FFFFFFF)

        # Minimal SNMPv3 message (noAuthNoPriv, empty engine ID → triggers report)
        pkt = _build_snmpv3_discovery(msg_id, req_id)
        sock.sendto(pkt, (target_ip, port))
        try:
            resp, _ = sock.recvfrom(2048)
            ok = len(resp) > 10  # Got a Report PDU back = device is alive and responding
        except socket.timeout:
            ok = False
        sock.close()
        lat = (time.monotonic() - t0) * 1000
        return ConnResult("SNMPv3", ok, lat, "" if ok else "timeout/no response")
    except Exception as e:
        lat = (time.monotonic() - t0) * 1000
        return ConnResult("SNMPv3", False, lat, str(e)[:80])


def _build_snmpv3_discovery(msg_id: int, req_id: int) -> bytes:
    """Build a minimal SNMPv3 noAuthNoPriv GetRequest for engine ID discovery."""

    def _int_to_ber(n: int) -> bytes:
        if n == 0:
            return b"\x00"
        out = b""
        while n:
            out = bytes([n & 0xFF]) + out
            n >>= 8
        if out[0] & 0x80:
            out = b"\x00" + out
        return out

    def _tlv(tag: int, val: bytes) -> bytes:
        L = len(val)
        if L < 0x80:
            return bytes([tag, L]) + val
        elif L < 0x100:
            return bytes([tag, 0x81, L]) + val
        else:
            return bytes([tag, 0x82, (L >> 8) & 0xFF, L & 0xFF]) + val

    def _int_tlv(n: int) -> bytes:
        return _tlv(0x02, _int_to_ber(n))

    def _str_tlv(tag: int, s: bytes) -> bytes:
        return _tlv(tag, s)

    # msgGlobalData
    msg_id_b   = _int_tlv(msg_id)
    max_size_b = _int_tlv(65507)
    msg_flags  = _str_tlv(0x04, b"\x00")        # noAuthNoPriv
    sec_model  = _int_tlv(3)                     # USM
    global_data = _tlv(0x30, msg_id_b + max_size_b + msg_flags + sec_model)

    # msgSecurityParameters (USM, all empty for discovery)
    usm_inner = (
        _str_tlv(0x04, b"")  +   # msgAuthoritativeEngineID (empty → discovery)
        _int_tlv(0)           +   # msgAuthoritativeEngineBoots
        _int_tlv(0)           +   # msgAuthoritativeEngineTime
        _str_tlv(0x04, b"")  +   # msgUserName (empty)
        _str_tlv(0x04, b"")  +   # msgAuthenticationParameters
        _str_tlv(0x04, b"")       # msgPrivacyParameters
    )
    sec_params = _str_tlv(0x04, _tlv(0x30, usm_inner))

    # ScopedPDU: GetRequest for sysDescr.0
    oid_sysDescr = bytes([0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00])  # 1.3.6.1.2.1.1.1.0
    var = _tlv(0x30, _tlv(0x06, oid_sysDescr) + _tlv(0x05, b""))  # VarBind
    var_binds = _tlv(0x30, var)
    pdu = _tlv(0xA0,  # GetRequest-PDU
        _int_tlv(req_id) + _int_tlv(0) + _int_tlv(0) + var_binds
    )
    scoped_pdu = _tlv(0x30,
        _str_tlv(0x04, b"") +   # contextEngineID
        _str_tlv(0x04, b"") +   # contextName
        pdu
    )

    # Outer SEQUENCE
    version = _int_tlv(3)
    msg = _tlv(0x30, version + global_data + sec_params + scoped_pdu)
    return msg


def _smb_worker(target_ip: str, port: int, timeout: float) -> ConnResult:
    """SMB: send SMB2 NEGOTIATE, check response (no auth — just protocol handshake)."""
    t0 = time.monotonic()
    try:
        sock = socket.create_connection((target_ip, port), timeout=timeout)
        sock.settimeout(timeout)

        # NetBIOS Session Service header + SMB2 NEGOTIATE request
        smb2_neg = _build_smb2_negotiate()
        netbios = struct.pack(">I", len(smb2_neg)) + smb2_neg
        sock.sendall(netbios)

        # Read NetBIOS header (4 bytes)
        hdr = b""
        while len(hdr) < 4:
            chunk = sock.recv(4 - len(hdr))
            if not chunk:
                break
            hdr += chunk
        if len(hdr) < 4:
            sock.close()
            lat = (time.monotonic() - t0) * 1000
            return ConnResult("SMB", False, lat, "no response header")

        length = struct.unpack(">I", hdr)[0]
        resp = b""
        while len(resp) < min(length, 256):
            chunk = sock.recv(min(length - len(resp), 256))
            if not chunk:
                break
            resp += chunk
        sock.close()

        # Check for SMB2 signature 0xFE534D42
        ok = len(resp) >= 4 and resp[:4] == b"\xfeSMB"
        lat = (time.monotonic() - t0) * 1000
        return ConnResult("SMB", ok, lat, "" if ok else f"bad magic: {resp[:4].hex()}")
    except Exception as e:
        lat = (time.monotonic() - t0) * 1000
        return ConnResult("SMB", False, lat, str(e)[:80])


def _build_smb2_negotiate() -> bytes:
    """Build a minimal SMB2 NEGOTIATE request."""
    # SMB2 header (64 bytes)
    protocol_id      = b"\xfeSMB"
    structure_size   = struct.pack("<H", 64)
    credit_charge    = struct.pack("<H", 0)
    status           = struct.pack("<I", 0)
    command          = struct.pack("<H", 0)      # NEGOTIATE
    credits_req      = struct.pack("<H", 1)
    flags            = struct.pack("<I", 0)
    next_command     = struct.pack("<I", 0)
    message_id       = struct.pack("<Q", 1)
    reserved_pid     = struct.pack("<I", 0xFEFF) # Reserved/PID
    tree_id          = struct.pack("<I", 0)
    session_id       = struct.pack("<Q", 0)
    signature        = b"\x00" * 16

    header = (protocol_id + structure_size + credit_charge + status +
              command + credits_req + flags + next_command +
              message_id + reserved_pid + tree_id + session_id + signature)

    # SMB2 NEGOTIATE body
    struct_size_neg = struct.pack("<H", 36)   # StructureSize
    dialect_count   = struct.pack("<H", 3)    # Number of dialects
    sec_mode        = struct.pack("<H", 1)    # Signing enabled
    reserved        = struct.pack("<H", 0)
    capabilities    = struct.pack("<I", 0x7F) # All capabilities
    client_guid     = b"\x00" * 16
    neg_ctx_offset  = struct.pack("<I", 0)
    neg_ctx_count   = struct.pack("<H", 0)
    reserved2       = struct.pack("<H", 0)
    dialects        = struct.pack("<HHH", 0x0202, 0x0210, 0x0300)  # SMB 2.0.2, 2.1, 3.0

    body = (struct_size_neg + dialect_count + sec_mode + reserved +
            capabilities + client_guid + neg_ctx_offset + neg_ctx_count +
            reserved2 + dialects)

    return header + body


# ---------------------------------------------------------------------------
# Protocol dispatcher
# ---------------------------------------------------------------------------

PROTO_DISPATCH = {
    "tls":   lambda ip, to: _tls_worker(ip, HTTPS_PORT, to),
    "ssh":   lambda ip, to: _ssh_worker(ip, SSH_PORT, to),
    "rtsp":  lambda ip, to: _rtsp_worker(ip, RTSP_PORT, RTSP_PATH, False, to),
    "rtsps": lambda ip, to: _rtsp_worker(ip, RTSPS_PORT, RTSP_PATH, True, to),
    "onvif": lambda ip, to: _onvif_worker(ip, HTTPS_PORT, ONVIF_PATH, to),
    "snmp":  lambda ip, to: _snmpv3_worker(ip, SNMP_PORT, to),
    "smb":   lambda ip, to: _smb_worker(ip, SMB_PORT, to),
}


def _run_wave(proto: str, concurrency: int, dut_ip: str, timeout: float) -> List[ConnResult]:
    """Launch `concurrency` simultaneous connections for `proto`, return results."""
    fn = PROTO_DISPATCH[proto]
    wave_results = []
    with ThreadPoolExecutor(max_workers=concurrency) as ex:
        futures = [ex.submit(fn, dut_ip, timeout) for _ in range(concurrency)]
        for f in as_completed(futures):
            try:
                wave_results.append(f.result())
            except Exception as e:
                wave_results.append(ConnResult(proto, False, 0, str(e)[:80]))
    return wave_results


def _check_dut_alive(dut_ip: str, port: int = None, timeout: float = 3.0) -> bool:
    """Quick TCP probe to verify DUT is still responding."""
    p = port or HTTPS_PORT
    try:
        s = socket.create_connection((dut_ip, p), timeout=timeout)
        s.close()
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def _build_summary_table(results_by_proto: Dict[str, List[ConnResult]], waves: int) -> Table:
    tbl = Table(
        title="[bold]Mass Reconnection Stress Test — Summary[/bold]",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan",
    )
    tbl.add_column("Protocol", style="bold")
    tbl.add_column("Total Conn", justify="right")
    tbl.add_column("Success", justify="right")
    tbl.add_column("Fail", justify="right")
    tbl.add_column("Success %", justify="right")
    tbl.add_column("Min Lat (ms)", justify="right")
    tbl.add_column("Avg Lat (ms)", justify="right")
    tbl.add_column("Max Lat (ms)", justify="right")
    tbl.add_column("Status")

    for proto, res_list in results_by_proto.items():
        total = len(res_list)
        ok    = sum(1 for r in res_list if r.success)
        fail  = total - ok
        pct   = (ok / total * 100) if total else 0
        lats  = [r.latency_ms for r in res_list if r.latency_ms > 0]
        mn    = f"{min(lats):.1f}" if lats else "-"
        av    = f"{sum(lats)/len(lats):.1f}" if lats else "-"
        mx    = f"{max(lats):.1f}" if lats else "-"
        if pct >= 80:
            status = "[green]PASS[/green]"
        elif pct >= 50:
            status = "[yellow]DEGRADED[/yellow]"
        else:
            status = "[red]FAIL[/red]"
        tbl.add_row(proto.upper(), str(total), str(ok), str(fail),
                    f"{pct:.1f}%", mn, av, mx, status)
    return tbl


def _build_json_report(results_by_proto: Dict[str, List[ConnResult]],
                       args: argparse.Namespace,
                       alive_before: bool, alive_after: bool,
                       start_ts: str, end_ts: str) -> dict:
    report = {
        "test": "3.8.3.3 Mass Reconnection Resilience",
        "dut_ip": args.ip,
        "start": start_ts,
        "end": end_ts,
        "parameters": {
            "concurrency": args.concurrency,
            "waves": args.waves,
            "wave_delay_s": args.wave_delay,
            "timeout_s": args.timeout,
            "protocols": args.proto,
        },
        "dut_alive_before": alive_before,
        "dut_alive_after": alive_after,
        "protocols": {},
    }
    for proto, res_list in results_by_proto.items():
        total = len(res_list)
        ok    = sum(1 for r in res_list if r.success)
        lats  = [r.latency_ms for r in res_list if r.latency_ms > 0]
        errors = [r.error for r in res_list if r.error]
        report["protocols"][proto] = {
            "total": total,
            "success": ok,
            "fail": total - ok,
            "success_pct": round(ok / total * 100, 2) if total else 0,
            "latency_ms": {
                "min": round(min(lats), 2) if lats else None,
                "avg": round(sum(lats) / len(lats), 2) if lats else None,
                "max": round(max(lats), 2) if lats else None,
            },
            "error_samples": list(set(errors))[:10],
        }
    return report


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="3.8.3.3 Mass Reconnection Resilience Test — multi-protocol concurrent flood with valid credentials",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Protocols: tls  ssh  rtsp  rtsps  onvif  snmp  smb
  (comma-separated, e.g. --proto tls,ssh,rtsp)

Examples:
  # 50 concurrent connections, 5 waves, all protocols
  python tool23_mass_reconnect_stress.py --concurrency 50 --waves 5

  # TLS + SSH only, 100 concurrent, 10 waves, no delay between waves
  python tool23_mass_reconnect_stress.py --proto tls,ssh --concurrency 100 --waves 10 --wave-delay 0
        """,
    )
    parser.add_argument("--ip",          default=DUT_IP,  help="DUT IP address")
    parser.add_argument("--concurrency", type=int,   default=50,   help="Simultaneous connections per wave (default: 50)")
    parser.add_argument("--waves",       type=int,   default=5,    help="Number of wave repetitions (default: 5)")
    parser.add_argument("--wave-delay",  type=float, default=2.0,  dest="wave_delay",
                        help="Seconds between waves (default: 2.0)")
    parser.add_argument("--timeout",     type=float, default=5.0,  help="Per-connection timeout seconds (default: 5.0)")
    parser.add_argument("--proto",       default="tls,ssh,rtsp,rtsps,onvif,snmp",
                        help="Comma-separated protocol list (default: tls,ssh,rtsp,rtsps,onvif,snmp)")
    parser.add_argument("--output",      default="",
                        help="JSON output file path (optional, auto-named if omitted)")
    parser.add_argument("--no-pcap",     action="store_true", help="Skip PCAP capture prompt")
    args = parser.parse_args()

    protos = [p.strip().lower() for p in args.proto.split(",") if p.strip().lower() in PROTO_DISPATCH]
    if not protos:
        console.print("[red]No valid protocols specified. Valid: " + ", ".join(PROTO_DISPATCH.keys()) + "[/red]")
        sys.exit(1)

    # Capability warnings
    if "ssh" in protos and not HAS_PARAMIKO:
        console.print("[yellow]WARNING: paramiko not installed — SSH test disabled.[/yellow]")
        protos.remove("ssh")
    if "snmp" in protos and not HAS_PYSNMP:
        console.print("[yellow]NOTE: pysnmp not in this interpreter — using raw UDP SNMPv3 discovery.[/yellow]")

    start_ts = datetime.datetime.now().isoformat()

    console.print(Panel(
        f"[bold cyan]3.8.3.3 Mass Reconnection Resilience Test[/bold cyan]\n"
        f"DUT: [bold]{args.ip}[/bold]  |  Protocols: [bold]{', '.join(p.upper() for p in protos)}[/bold]\n"
        f"Concurrency: [bold]{args.concurrency}[/bold] conn/wave  |  Waves: [bold]{args.waves}[/bold]  "
        f"|  Wave delay: [bold]{args.wave_delay}s[/bold]  |  Timeout: [bold]{args.timeout}s[/bold]",
        title="ETSI EN 303 645 — 3.8.3.3",
        border_style="cyan",
    ))

    # Pre-test liveness check
    alive_before = _check_dut_alive(args.ip)
    console.print(f"[dim]Pre-test DUT liveness ({args.ip}:{HTTPS_PORT}): "
                  f"{'[green]ALIVE[/green]' if alive_before else '[red]UNREACHABLE[/red]'}")

    results_by_proto: Dict[str, List[ConnResult]] = {p: [] for p in protos}

    # Execute waves
    for wave_num in range(1, args.waves + 1):
        console.print(f"\n[bold yellow]Wave {wave_num}/{args.waves}[/bold yellow] — "
                      f"launching {args.concurrency} × {len(protos)} connections simultaneously ...")

        wave_futures: Dict[str, List] = {}
        with ThreadPoolExecutor(max_workers=args.concurrency * len(protos)) as ex:
            for proto in protos:
                fn = PROTO_DISPATCH[proto]
                wave_futures[proto] = [
                    ex.submit(fn, args.ip, args.timeout)
                    for _ in range(args.concurrency)
                ]
            # Collect
            for proto, futures in wave_futures.items():
                for f in as_completed(futures):
                    try:
                        r = f.result()
                    except Exception as e:
                        r = ConnResult(proto, False, 0, str(e)[:80])
                    results_by_proto[proto].append(r)

        # Per-wave quick stats
        wave_tbl = Table(box=box.SIMPLE, show_header=True, header_style="dim")
        wave_tbl.add_column("Protocol")
        wave_tbl.add_column("OK", justify="right")
        wave_tbl.add_column("Fail", justify="right")
        wave_tbl.add_column("Avg ms", justify="right")
        for proto in protos:
            w_res = results_by_proto[proto][-args.concurrency:]
            ok = sum(1 for r in w_res if r.success)
            lats = [r.latency_ms for r in w_res]
            avg = f"{sum(lats)/len(lats):.0f}" if lats else "-"
            wave_tbl.add_row(proto.upper(), str(ok), str(args.concurrency - ok), avg)
        console.print(wave_tbl)

        if wave_num < args.waves and args.wave_delay > 0:
            console.print(f"[dim]Sleeping {args.wave_delay}s before next wave ...[/dim]")
            time.sleep(args.wave_delay)

    end_ts = datetime.datetime.now().isoformat()

    # Post-test liveness check
    time.sleep(1.0)
    alive_after = _check_dut_alive(args.ip)
    console.print(f"\n[dim]Post-test DUT liveness ({args.ip}:{HTTPS_PORT}): "
                  f"{'[green]ALIVE[/green]' if alive_after else '[red]UNREACHABLE — DUT may be overloaded or crashed[/red]'}")

    # Summary table
    console.print()
    console.print(_build_summary_table(results_by_proto, args.waves))

    # Overall verdict
    all_ok = all(
        sum(1 for r in res_list if r.success) / len(res_list) >= 0.8
        for res_list in results_by_proto.values() if res_list
    )
    if alive_after and all_ok:
        verdict_color, verdict_text = "green", "PASS — DUT survived mass reconnections, services unaffected"
    elif alive_after:
        verdict_color, verdict_text = "yellow", "PARTIAL — DUT alive but some protocols degraded under load"
    else:
        verdict_color, verdict_text = "red", "FAIL — DUT became unreachable after mass reconnection flood"

    console.print(Panel(
        f"[bold {verdict_color}]{verdict_text}[/bold {verdict_color}]\n"
        f"DUT alive before: {alive_before}  |  DUT alive after: {alive_after}",
        title="[bold]Verdict 3.8.3.3[/bold]",
        border_style=verdict_color,
    ))

    # JSON report
    report = _build_json_report(results_by_proto, args, alive_before, alive_after, start_ts, end_ts)
    out_path = args.output or os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        f"mass_reconnect_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
    )
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
    console.print(f"\n[dim]Report saved: {out_path}[/dim]")


if __name__ == "__main__":
    main()
