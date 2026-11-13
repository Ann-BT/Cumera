#!/usr/bin/env python3
"""
Centralized configuration, dynamic host-network resolution, port normalization,
multi-vendor camera port/path probing, and full-width Rich console helpers.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import os
import platform
import re
import socket
import ssl
import subprocess
import sys
import urllib.request
import uuid
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from rich.console import Console

TOOLKIT_DIR = os.path.dirname(os.path.abspath(__file__))
CONF_PATH = os.path.join(TOOLKIT_DIR, "config.json")

DEFAULT_HOST_FALLBACK_IP = "127.0.0.1"
DEFAULT_DUT_FALLBACK_IP = "192.168.1.100"

DEFAULT_SERVICE_PORTS: Dict[str, Any] = {
    # Inbound DUT ports (Camera acts as Server)
    "http": 80,
    "https": 443,
    "onvif_http": 80,
    "onvif_https": 443,
    "onvif_path": "/onvif/device_service",
    "onvif_ws_discovery_udp": 3702,
    "rtsp": 554,
    "rtsp_cleartext": 554,
    "rtsps": 322,
    "rtsps_tls": 322,
    "rtsp_path": "/stream1",
    "ssh": 22,
    "snmp": 161,
    "snmp_udp": 161,
    "proprietary_tcp": 8000,
    # Outbound Host receiver ports (Camera acts as Client)
    "mqtt_tls": 8883,
    "mqtt_wss": 443,
    "mqtt_clear": 1883,
    "syslog_tls": 6514,
    "syslog_clear": 514,
    "smb": 445,
    "smtp_starttls": 587,
    "smtps": 465,
    "smtp_clear": 25,
    "smtp_receiver": [25, 465, 587],
    "sftp_port": 22,
    "ftp_clear": 21,
    "sftp_receiver": [21, 22],
    "alarm_receiver_http": 8088,
    "alarm_receiver_https": 8443,
}

COMMON_RTSP_PATHS: List[str] = [
    "/axis-media/media.amp",
    "/Streaming/Channels/101",
    "/cam/realmonitor?channel=1&subtype=0",
    "/stream1",
    "/live/ch00_0",
    "/media/video1",
    "/h264Preview_01_main",
    "/MediaInput/h264",
    "/profile1",
]


def _safe_port(val: Any, default: int) -> int:
    try:
        p = int(val)
        return p if 1 <= p <= 65535 else default
    except (TypeError, ValueError):
        return default


def _normalize_path(val: Any, default: str) -> str:
    if not isinstance(val, str) or not val.strip():
        return default
    p = val.strip()
    return p if p.startswith("/") else "/" + p


def normalize_service_ports(sp: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Return a complete, normalized service_ports dictionary preserving user overrides."""
    raw = dict(sp) if isinstance(sp, dict) else {}
    out = dict(DEFAULT_SERVICE_PORTS)

    # Preserve single/alias pairs cleanly (prefer explicit primary key if present, else alias)
    out["http"] = _safe_port(raw.get("http"), DEFAULT_SERVICE_PORTS["http"])
    out["https"] = _safe_port(raw.get("https"), DEFAULT_SERVICE_PORTS["https"])
    out["onvif_http"] = _safe_port(raw.get("onvif_http"), out["http"])
    out["onvif_https"] = _safe_port(raw.get("onvif_https"), out["https"])
    out["onvif_path"] = _normalize_path(raw.get("onvif_path"), DEFAULT_SERVICE_PORTS["onvif_path"])
    out["onvif_ws_discovery_udp"] = _safe_port(
        raw.get("onvif_ws_discovery_udp"), DEFAULT_SERVICE_PORTS["onvif_ws_discovery_udp"]
    )

    rtsp_val = _safe_port(raw.get("rtsp", raw.get("rtsp_cleartext")), DEFAULT_SERVICE_PORTS["rtsp"])
    rtsps_val = _safe_port(raw.get("rtsps", raw.get("rtsps_tls")), DEFAULT_SERVICE_PORTS["rtsps"])
    out["rtsp"] = rtsp_val
    out["rtsp_cleartext"] = _safe_port(raw.get("rtsp_cleartext", rtsp_val), rtsp_val)
    out["rtsps"] = rtsps_val
    out["rtsps_tls"] = _safe_port(raw.get("rtsps_tls", rtsps_val), rtsps_val)
    out["rtsp_path"] = _normalize_path(raw.get("rtsp_path"), DEFAULT_SERVICE_PORTS["rtsp_path"])

    out["ssh"] = _safe_port(raw.get("ssh"), DEFAULT_SERVICE_PORTS["ssh"])
    snmp_val = _safe_port(raw.get("snmp", raw.get("snmp_udp")), DEFAULT_SERVICE_PORTS["snmp"])
    out["snmp"] = snmp_val
    out["snmp_udp"] = _safe_port(raw.get("snmp_udp", snmp_val), snmp_val)
    out["proprietary_tcp"] = _safe_port(raw.get("proprietary_tcp"), DEFAULT_SERVICE_PORTS["proprietary_tcp"])

    out["mqtt_tls"] = _safe_port(raw.get("mqtt_tls"), DEFAULT_SERVICE_PORTS["mqtt_tls"])
    out["mqtt_wss"] = _safe_port(raw.get("mqtt_wss"), out["https"])
    out["mqtt_clear"] = _safe_port(raw.get("mqtt_clear"), DEFAULT_SERVICE_PORTS["mqtt_clear"])
    out["syslog_tls"] = _safe_port(raw.get("syslog_tls"), DEFAULT_SERVICE_PORTS["syslog_tls"])
    out["syslog_clear"] = _safe_port(raw.get("syslog_clear"), DEFAULT_SERVICE_PORTS["syslog_clear"])
    out["smb"] = _safe_port(raw.get("smb"), DEFAULT_SERVICE_PORTS["smb"])

    # Sync scalar receiver ports with legacy list keys if list keys exist without scalar keys
    smtp_list = raw.get("smtp_receiver") if isinstance(raw.get("smtp_receiver"), list) else []
    smtp_clear_def = _safe_port(smtp_list[0], 25) if len(smtp_list) >= 1 else 25
    smtps_def = _safe_port(smtp_list[1], 465) if len(smtp_list) >= 2 else 465
    smtp_starttls_def = _safe_port(smtp_list[2], 587) if len(smtp_list) >= 3 else 587

    out["smtp_clear"] = _safe_port(raw.get("smtp_clear"), smtp_clear_def)
    out["smtps"] = _safe_port(raw.get("smtps"), smtps_def)
    out["smtp_starttls"] = _safe_port(raw.get("smtp_starttls"), smtp_starttls_def)
    out["smtp_receiver"] = [out["smtp_clear"], out["smtps"], out["smtp_starttls"]]

    sftp_list = raw.get("sftp_receiver") if isinstance(raw.get("sftp_receiver"), list) else []
    ftp_def = _safe_port(sftp_list[0], 21) if len(sftp_list) >= 1 else 21
    sftp_def = _safe_port(sftp_list[1], 22) if len(sftp_list) >= 2 else 22

    out["ftp_clear"] = _safe_port(raw.get("ftp_clear"), ftp_def)
    out["sftp_port"] = _safe_port(raw.get("sftp_port"), sftp_def)
    out["sftp_receiver"] = [out["ftp_clear"], out["sftp_port"]]

    out["alarm_receiver_http"] = _safe_port(
        raw.get("alarm_receiver_http"), DEFAULT_SERVICE_PORTS["alarm_receiver_http"]
    )
    out["alarm_receiver_https"] = _safe_port(
        raw.get("alarm_receiver_https"), DEFAULT_SERVICE_PORTS["alarm_receiver_https"]
    )

    # Keep any extra user-defined custom keys intact
    for k, v in raw.items():
        if k not in out:
            out[k] = v
    return out


def load_config(path: Optional[str] = None) -> Dict[str, Any]:
    """Load toolkit config.json safely."""
    target_path = path or CONF_PATH
    if not os.path.exists(target_path):
        return {}
    try:
        with open(target_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save_config(cfg: Dict[str, Any], path: Optional[str] = None) -> Dict[str, Any]:
    """Persist config.json with normalized service_ports."""
    target_path = path or CONF_PATH
    data = dict(cfg)
    data["service_ports"] = normalize_service_ports(data.get("service_ports"))
    with open(target_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    return data


def get_target_info(cfg: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
    """Return normalized target_camera dict without stale hardcoded test IPs."""
    data = cfg if cfg is not None else load_config()
    tc = data.get("target_camera", {}) if isinstance(data, dict) else {}
    user = str(tc.get("username") or "admin")
    passwd = str(tc.get("password") or "")
    return {
        "ip": str(tc.get("ip") or DEFAULT_DUT_FALLBACK_IP).strip(),
        "model": str(tc.get("model") or "Generic IP Camera").strip(),
        "firmware": str(tc.get("firmware") or "Unknown").strip(),
        "username": user,
        "password": passwd,
        "ssh_username": str(tc.get("ssh_username") or user),
        "ssh_password": str(tc.get("ssh_password") or passwd),
    }


def get_service_ports(cfg: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Return normalized service_ports dict from config or defaults."""
    data = cfg if cfg is not None else load_config()
    sp = data.get("service_ports") if isinstance(data, dict) else None
    return normalize_service_ports(sp)


def list_local_ipv4_interfaces() -> List[Tuple[str, str]]:
    """Return list of (interface_name, ipv4_addr) for active non-loopback IPv4 interfaces."""
    results: List[Tuple[str, str]] = []
    if platform.system() == "Linux":
        try:
            proc = subprocess.run(
                ["ip", "-o", "-4", "addr", "show", "up", "scope", "global"],
                capture_output=True,
                text=True,
                timeout=3,
            )
            for line in proc.stdout.splitlines():
                m = re.search(r"^\d+:\s+(\S+)\s+inet\s+(\d+\.\d+\.\d+\.\d+)/\d+", line)
                if m:
                    results.append((m.group(1), m.group(2)))
        except Exception:
            pass
    elif platform.system() == "Windows":
        try:
            proc = subprocess.run(["ipconfig"], capture_output=True, text=True, timeout=3)
            cur_iface = "Ethernet"
            for line in proc.stdout.splitlines():
                if line and not line.startswith(" ") and line.strip().endswith(":"):
                    cur_iface = line.strip().rstrip(":")
                elif "IPv4" in line and ":" in line:
                    ip = line.split(":")[-1].strip()
                    if ip and not ip.startswith("127."):
                        results.append((cur_iface, ip))
        except Exception:
            pass
    return results


def _iface_for_ip(ip: str) -> str:
    for iface, addr in list_local_ipv4_interfaces():
        if addr == ip:
            return iface
    return "unknown"


def detect_host_network(target_ip: Optional[str] = None, cfg: Optional[Dict[str, Any]] = None) -> Tuple[str, str]:
    """
    Resolve (host_iface, host_ip) dynamically using live OS routing to target_ip first,
    never returning a stale offline test_host.ip.
    """
    data = cfg if cfg is not None else load_config()
    if not target_ip:
        target_ip = get_target_info(data)["ip"]

    local_ifaces = list_local_ipv4_interfaces()
    local_ips = {ip for _, ip in local_ifaces}

    # 1. Linux kernel route lookup for target_ip
    if platform.system() == "Linux" and target_ip:
        try:
            proc = subprocess.run(
                ["ip", "-o", "route", "get", target_ip],
                capture_output=True,
                text=True,
                timeout=2,
            )
            m_dev = re.search(r"\bdev\s+(\S+)", proc.stdout)
            m_src = re.search(r"\bsrc\s+(\d+\.\d+\.\d+\.\d+)", proc.stdout)
            if m_src:
                src_ip = m_src.group(1)
                dev = m_dev.group(1) if m_dev else _iface_for_ip(src_ip)
                if not src_ip.startswith("127."):
                    return dev, src_ip
        except Exception:
            pass

    # 2. Cross-platform UDP socket source address lookup toward target_ip
    if target_ip:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((target_ip, 80))
            ip = s.getsockname()[0]
            s.close()
            if ip and not ip.startswith("127."):
                return _iface_for_ip(ip), ip
        except Exception:
            pass

    # 3. Same /24 local interface heuristic
    if target_ip and "." in target_ip:
        prefix = ".".join(target_ip.split(".")[:3]) + "."
        for iface, addr in local_ifaces:
            if addr.startswith(prefix):
                return iface, addr

    # 4. Configured test_host only if actually assigned to a local interface right now
    th = data.get("test_host", {}) if isinstance(data, dict) else {}
    cfg_ip = str(th.get("ip") or "").strip()
    if cfg_ip and cfg_ip in local_ips:
        return _iface_for_ip(cfg_ip), cfg_ip

    # 5. Any active non-loopback wired interface, then general local interface
    for iface, addr in local_ifaces:
        if iface.startswith(("en", "eth", "Ethernet")):
            return iface, addr
    if local_ifaces:
        return local_ifaces[0]

    # 6. Last-resort public-route UDP socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return _iface_for_ip(ip), ip
    except Exception:
        return "unknown", DEFAULT_HOST_FALLBACK_IP


def make_console() -> Console:
    """Create a Rich Console sized to COLUMNS or full width instead of 80-col dumb fallback."""
    cols = os.environ.get("COLUMNS", "")
    lines = os.environ.get("LINES", "")
    h = int(lines) if (lines.isdigit() and int(lines) >= 24) else 50
    if cols.isdigit() and int(cols) >= 80:
        return Console(width=int(cols), height=h)
    if not sys.stdout.isatty() or os.environ.get("TERM", "") in ("", "dumb"):
        return Console(width=145, height=h)
    return Console()


def _tcp_open(ip: str, port: int, timeout: float = 0.45) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except Exception:
        return False


def is_tls_port(ip: str, port: int, timeout: float = 1.5) -> bool:
    """Detect dynamically whether a TCP port speaks TLS (regardless of port number)."""
    try:
        ctx = ssl._create_unverified_context()
        with socket.create_connection((ip, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=ip):
                return True
    except Exception:
        return port in (443, 8443, 9443, 322, 332, 9554, 8883, 6514, 465)


def _probe_http_endpoint(ip: str, port: int, use_tls: bool, timeout: float = 1.2) -> Dict[str, Any]:
    """Inspect an HTTP/HTTPS port for vendor clues and ONVIF availability."""
    scheme = "https" if use_tls else "http"
    info: Dict[str, Any] = {"port": port, "scheme": scheme, "vendor": None, "onvif": False}
    ctx = ssl._create_unverified_context() if use_tls else None

    for path in ("/onvif/device_service", "/"):
        url = f"{scheme}://{ip}:{port}{path}"
        try:
            if path == "/onvif/device_service":
                soap_body = (
                    b'<?xml version="1.0" encoding="utf-8"?>'
                    b'<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">'
                    b'<s:Body><GetSystemDateAndTime xmlns="http://www.onvif.org/ver10/device/wsdl"/>'
                    b'</s:Body></s:Envelope>'
                )
                req = urllib.request.Request(
                    url,
                    data=soap_body,
                    headers={"Content-Type": "application/soap+xml; charset=utf-8"},
                    method="POST",
                )
            else:
                req = urllib.request.Request(url, method="GET")

            try:
                resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
                headers = dict(resp.headers)
                body = resp.read(8192).decode("utf-8", errors="ignore")
                status = resp.status
            except urllib.error.HTTPError as he:
                headers = dict(he.headers)
                body = he.read(8192).decode("utf-8", errors="ignore")
                status = he.code

            blob = (json.dumps(headers) + " " + body).lower()
            if path == "/onvif/device_service" and (status in (200, 400, 401, 500) and ("onvif" in blob or "envelope" in blob or "unauthorized" in blob or status in (200, 401))):
                info["onvif"] = True

            if not info["vendor"]:
                if "axis" in blob or "vapix" in blob:
                    info["vendor"] = "Axis"
                elif "hikvision" in blob or "isapi" in blob or "app-webs" in blob or "hik" in blob:
                    info["vendor"] = "Hikvision"
                elif "dahua" in blob or "dh_" in blob or "webservice" in blob:
                    info["vendor"] = "Dahua"
                elif "tp-link" in blob or "vigi" in blob:
                    info["vendor"] = "TP-Link VIGI"
                elif "uniview" in blob or "unv" in blob or "lapi" in blob:
                    info["vendor"] = "Uniview"
                elif "hanwha" in blob or "wisenet" in blob or "samsung" in blob:
                    info["vendor"] = "Hanwha / Wisenet"
        except Exception:
            pass
    return info


def _probe_rtsp_path(ip: str, port: int, use_tls: bool, timeout: float = 0.8) -> str:
    """Detect the first accepted RTSP path via DESCRIBE (200 or 401/403 means valid path)."""
    for path in COMMON_RTSP_PATHS:
        try:
            raw = socket.create_connection((ip, port), timeout=timeout)
            sock = raw
            if use_tls:
                ctx = ssl._create_unverified_context()
                sock = ctx.wrap_socket(raw, server_hostname=ip)
            scheme = "rtsps" if use_tls else "rtsp"
            req = f"DESCRIBE {scheme}://{ip}:{port}{path} RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: PSI-Probe/1.0\r\n\r\n"
            sock.sendall(req.encode("ascii"))
            resp = sock.recv(1024).decode("utf-8", errors="ignore")
            sock.close()
            first_line = resp.splitlines()[0] if resp else ""
            if any(code in first_line for code in (" 200 ", " 401 ", " 403 ")):
                return path
        except Exception:
            pass
    return "/stream1"


def parse_onvif_xaddr(xaddrs: str) -> Dict[str, Any]:
    """Extract preferred IPv4 ONVIF scheme, port, and service path from WS-Discovery XAddrs."""
    out: Dict[str, Any] = {"url": "", "scheme": "", "port": None, "path": "/onvif/device_service"}
    if not xaddrs:
        return out
    tokens = xaddrs.split()
    chosen = ""
    for t in tokens:
        if re.match(r"^https?://\d+\.\d+\.\d+\.\d+", t):
            chosen = t
            break
    if not chosen and tokens:
        chosen = tokens[0]
    if not chosen:
        return out
    parsed = urlparse(chosen)
    scheme = (parsed.scheme or "http").lower()
    port = parsed.port or (443 if scheme == "https" else 80)
    path = _normalize_path(parsed.path, "/onvif/device_service")
    out.update({"url": chosen, "scheme": scheme, "port": port, "path": path})
    return out


def probe_common_camera_ports(ip: str, timeout: float = 0.45) -> Dict[str, Any]:
    """Concurrently scan common IP camera TCP ports, UDP 3702, vendor hints, and RTSP path."""
    tcp_candidates = [21, 22, 23, 80, 322, 332, 443, 554, 1883, 2222, 3702, 8000, 8080, 8443, 8554, 8883, 34567, 37777]
    open_tcp: List[int] = []
    with ThreadPoolExecutor(max_workers=len(tcp_candidates)) as ex:
        futs = {ex.submit(_tcp_open, ip, p, timeout): p for p in tcp_candidates}
        for f in as_completed(futs):
            if f.result():
                open_tcp.append(futs[f])
    open_tcp.sort()

    # Probe UDP 3702 WS-Discovery unicast (fresh UUID avoids duplicate suppression)
    udp_3702_open = False
    ws_xaddr_ipv4 = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1.2)
        probe = (
            '<?xml version="1.0" encoding="utf-8"?>'
            '<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope" '
            'xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
            'xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery">'
            f'<e:Header><w:MessageID>uuid:{uuid.uuid4()}</w:MessageID>'
            '<w:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>'
            '<w:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action></e:Header>'
            '<e:Body><d:Probe/></e:Body></e:Envelope>'
        ).encode("utf-8")
        s.sendto(probe, (ip, 3702))
        data, _ = s.recvfrom(8192)
        text = data.decode("utf-8", errors="ignore")
        if "ProbeMatches" in text or "XAddrs" in text:
            udp_3702_open = True
            m_xa = re.search(r"<[^:>]*:?XAddrs>(.*?)</[^:>]*:?XAddrs>", text, re.DOTALL)
            if m_xa:
                for token in m_xa.group(1).split():
                    if re.match(r"^https?://\d+\.\d+\.\d+\.\d+", token):
                        ws_xaddr_ipv4 = token
                        break
        s.close()
    except Exception:
        pass

    # Suggest effective ports
    suggested: Dict[str, Any] = {}
    if 80 in open_tcp:
        suggested["http"] = 80
        suggested["onvif_http"] = 80
    elif 8080 in open_tcp:
        suggested["http"] = 8080
        suggested["onvif_http"] = 8080

    if 443 in open_tcp:
        suggested["https"] = 443
        suggested["onvif_https"] = 443
    elif 8443 in open_tcp:
        suggested["https"] = 8443
        suggested["onvif_https"] = 8443

    if 554 in open_tcp:
        suggested["rtsp"] = 554
        suggested["rtsp_cleartext"] = 554
    elif 8554 in open_tcp:
        suggested["rtsp"] = 8554
        suggested["rtsp_cleartext"] = 8554

    if 322 in open_tcp:
        suggested["rtsps"] = 322
        suggested["rtsps_tls"] = 322
    elif 332 in open_tcp:
        suggested["rtsps"] = 332
        suggested["rtsps_tls"] = 332

    if 22 in open_tcp:
        suggested["ssh"] = 22
    elif 2222 in open_tcp:
        suggested["ssh"] = 2222

    for prop_p in (8000, 37777, 34567):
        if prop_p in open_tcp:
            suggested["proprietary_tcp"] = prop_p
            break

    vendor = None
    http_p = suggested.get("http")
    https_p = suggested.get("https")
    if https_p:
        hinfo = _probe_http_endpoint(ip, https_p, True)
        vendor = vendor or hinfo.get("vendor")
    if http_p and not vendor:
        hinfo = _probe_http_endpoint(ip, http_p, False)
        vendor = vendor or hinfo.get("vendor")

    # Detect best RTSP path if RTSP or RTSPS is open
    rtsp_p = suggested.get("rtsp")
    rtsps_p = suggested.get("rtsps")
    if rtsp_p:
        suggested["rtsp_path"] = _probe_rtsp_path(ip, rtsp_p, False)
    elif rtsps_p:
        suggested["rtsp_path"] = _probe_rtsp_path(ip, rtsps_p, True)
    elif vendor == "Axis":
        suggested["rtsp_path"] = "/axis-media/media.amp"
    elif vendor == "Hikvision":
        suggested["rtsp_path"] = "/Streaming/Channels/101"
    elif vendor == "Dahua":
        suggested["rtsp_path"] = "/cam/realmonitor?channel=1&subtype=0"

    if udp_3702_open:
        suggested["onvif_ws_discovery_udp"] = 3702
    if ws_xaddr_ipv4:
        parsed_x = parse_onvif_xaddr(ws_xaddr_ipv4)
        if parsed_x.get("path"):
            suggested["onvif_path"] = parsed_x["path"]
        if parsed_x.get("scheme") == "https" and parsed_x.get("port"):
            suggested["onvif_https"] = parsed_x["port"]
        elif parsed_x.get("scheme") == "http" and parsed_x.get("port"):
            suggested["onvif_http"] = parsed_x["port"]

    return {
        "ip": ip,
        "open_tcp_ports": open_tcp,
        "udp_3702_open": udp_3702_open,
        "ws_xaddr": ws_xaddr_ipv4 or "",
        "detected_vendor": vendor or "Generic / Unknown",
        "suggested_ports": suggested,
    }
