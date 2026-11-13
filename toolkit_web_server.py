#!/usr/bin/env python3
"""
toolkit_web_server.py - FastAPI Web Server & WebSocket Streaming Backend
Camera Cybersecurity Audit Suite (QCVN 11:2026/BCA & ETSI EN 303 645)
"""

import os
import sys
import json
import time
import asyncio
import subprocess
import shlex
import shutil
import urllib.request
import zipfile
import io
from pathlib import Path
from typing import Optional

if sys.platform == "win32":
    try:
        if sys.stdout and hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if sys.stderr and hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Request, Query
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
import uvicorn

BASE_DIR = Path(__file__).resolve().parent
PROJECT_DIR = BASE_DIR.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from toolkit_config import (
    detect_host_network,
    get_service_ports,
    get_target_info,
    load_config as tc_load_config,
    normalize_service_ports,
    probe_common_camera_ports,
    save_config as tc_save_config,
)

# Tự động nhận diện môi trường ảo .venv (ưu tiên trong thư mục hiện tại, rồi thư mục cha)
VENV_PYTHON = BASE_DIR / ".venv" / "bin" / "python"
if not VENV_PYTHON.exists():
    VENV_PYTHON = PROJECT_DIR / ".venv" / "bin" / "python"
if sys.platform == "win32":
    win_py = BASE_DIR / ".venv" / "Scripts" / "python.exe"
    if not win_py.exists():
        win_py = PROJECT_DIR / ".venv" / "Scripts" / "python.exe"
    if win_py.exists():
        VENV_PYTHON = win_py
if not VENV_PYTHON.exists():
    VENV_PYTHON = Path(sys.executable)

CAPTURES_DIR = BASE_DIR / "captures"
CAPTURES_DIR.mkdir(parents=True, exist_ok=True)
CONFIG_FILE = BASE_DIR / "config.json"
EXAMPLE_CONFIG_FILE = BASE_DIR / "config.example.json"
if not CONFIG_FILE.exists() and EXAMPLE_CONFIG_FILE.exists():
    shutil.copyfile(EXAMPLE_CONFIG_FILE, CONFIG_FILE)
HTML_FILE = BASE_DIR / "ui_dashboard.html"

def get_current_model() -> str:
    if CONFIG_FILE.exists():
        try:
            cfg = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
            return cfg.get("target_camera", {}).get("model", "Generic IP Camera")
        except Exception:
            pass
    return "Generic IP Camera"

def get_evidence_dirs():
    cfg = {}
    if CONFIG_FILE.exists():
        try:
            cfg = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass

    current_model = cfg.get("target_camera", {}).get("model", "AXIS Q1806-LE")
    base_custom = cfg.get("evidence_base_dir", "").strip()

    # ComMech directory
    custom_c = cfg.get("evidence_commech_dir", "").strip()
    if custom_c:
        c_dir = Path(custom_c)
    elif base_custom:
        c_dir = Path(base_custom) / "ComMech"
    else:
        candidates_commech = [
            PROJECT_DIR / current_model / "Mẫu lưu bằng chứng" / "ComMech",
            PROJECT_DIR / "AXIS Q1806-LE" / "Mẫu lưu bằng chứng" / "ComMech",
            PROJECT_DIR / "Mẫu lưu bằng chứng" / "ComMech",
            CAPTURES_DIR / "evidence" / "ComMech",
            CAPTURES_DIR
        ]
        c_dir = next((d for d in candidates_commech if d.exists()), CAPTURES_DIR)

    # AuthMech directory
    custom_a = cfg.get("evidence_authmech_dir", "").strip()
    if custom_a:
        a_dir = Path(custom_a)
    elif base_custom:
        a_dir = Path(base_custom) / "AuthMech"
    else:
        candidates_authmech = [
            PROJECT_DIR / current_model / "Mẫu lưu bằng chứng" / "AuthMech",
            PROJECT_DIR / "AXIS Q1806-LE" / "Mẫu lưu bằng chứng" / "AuthMech",
            PROJECT_DIR / "Mẫu lưu bằng chứng" / "AuthMech",
            CAPTURES_DIR / "evidence" / "AuthMech",
            CAPTURES_DIR
        ]
        a_dir = next((d for d in candidates_authmech if d.exists()), CAPTURES_DIR)

    try:
        c_dir.mkdir(parents=True, exist_ok=True)
        a_dir.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass

    return c_dir, a_dir

EVIDENCE_DIR, EVIDENCE_AUTHMECH_DIR = get_evidence_dirs()

app = FastAPI(title="Cumera Security Auditor Backend", version="2.2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

os.makedirs(CAPTURES_DIR, exist_ok=True)
app.mount("/captures", StaticFiles(directory=str(CAPTURES_DIR)), name="captures")

ASSETS_DIR = BASE_DIR / "assets"
if ASSETS_DIR.exists():
    app.mount("/assets", StaticFiles(directory=str(ASSETS_DIR)), name="assets")

# Active execution tracking
active_process: Optional[asyncio.subprocess.Process] = None


@app.get("/favicon.ico", include_in_schema=False)
async def get_favicon():
    ico = BASE_DIR / "favicon.ico"
    if ico.exists():
        return FileResponse(str(ico), media_type="image/x-icon")
    return Response(status_code=404)


@app.get("/icon.png", include_in_schema=False)
async def get_icon():
    png = BASE_DIR / "icon.png"
    if png.exists():
        return FileResponse(str(png), media_type="image/png")
    return Response(status_code=404)


@app.get("/", response_class=HTMLResponse)
async def get_index():
    if HTML_FILE.exists():
        return HTMLResponse(content=HTML_FILE.read_text(encoding="utf-8"))
    return HTMLResponse("<h1>UI Dashboard file (ui_dashboard.html) not found</h1>", status_code=404)


@app.get("/api/status")
async def get_target_status():
    """Check DUT camera ping status, model, firmware, latency, and active host network interface."""
    cfg = tc_load_config(str(CONFIG_FILE))
    target = get_target_info(cfg)
    ip = target["ip"]
    host_iface, host_ip = detect_host_network(ip, cfg)

    # Lệnh ping tương thích đa nền tảng (Windows: -n 1 -w 1000, Linux/macOS: -c 1 -W 1)
    if sys.platform == "win32":
        cmd = ["ping", "-n", "1", "-w", "1000", ip]
    else:
        cmd = ["ping", "-c", "1", "-W", "1", ip]

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    stdout, _ = await proc.communicate()
    out = stdout.decode("utf-8", errors="ignore")

    online = (proc.returncode == 0)
    latency_ms = None
    if online:
        if "time<" in out:
            latency_ms = 0.5
        elif "time=" in out:
            try:
                time_part = out.split("time=")[1].split(" ")[0].lower().replace("ms", "")
                latency_ms = float(time_part)
            except Exception:
                latency_ms = 0.5

    return {
        "ip": ip,
        "model": target["model"],
        "firmware": target["firmware"],
        "host_iface": host_iface,
        "host_ip": host_ip,
        "online": online,
        "latency_ms": latency_ms,
        "checked_at": time.time()
    }


@app.get("/api/config")
async def get_config():
    """Retrieve current target configuration with normalized service ports and live host network info."""
    try:
        cfg = tc_load_config(str(CONFIG_FILE))
        if not cfg and CONFIG_FILE.exists():
            cfg = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
        cfg["service_ports"] = normalize_service_ports(cfg.get("service_ports"))
        target_ip = get_target_info(cfg)["ip"]
        host_iface, host_ip = detect_host_network(target_ip, cfg)
        cfg["host_info"] = {"interface": host_iface, "ip": host_ip}
        return cfg
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


_CONFIG_PORT_FIELD_MAP = {
    "http_port": ("http",),
    "https_port": ("https",),
    "onvif_http_port": ("onvif_http",),
    "onvif_https_port": ("onvif_https",),
    "ws_discovery_port": ("onvif_ws_discovery_udp",),
    "rtsp_port": ("rtsp", "rtsp_cleartext"),
    "rtsps_port": ("rtsps", "rtsps_tls"),
    "ssh_port": ("ssh",),
    "snmp_port": ("snmp", "snmp_udp"),
    "proprietary_port": ("proprietary_tcp",),
    "mqtt_tls_port": ("mqtt_tls",),
    "mqtt_wss_port": ("mqtt_wss",),
    "mqtt_clear_port": ("mqtt_clear",),
    "syslog_tls_port": ("syslog_tls",),
    "syslog_clear_port": ("syslog_clear",),
    "smb_port": ("smb",),
    "smtp_starttls_port": ("smtp_starttls",),
    "smtps_port": ("smtps",),
    "smtp_clear_port": ("smtp_clear",),
    "sftp_port": ("sftp_port",),
    "ftp_port": ("ftp_clear",),
    "alarm_http_port": ("alarm_receiver_http",),
    "alarm_https_port": ("alarm_receiver_https",),
}


@app.post("/api/config")
async def save_config(data: dict):
    """Save updated target configuration, all service ports, and auto-resolved host network."""
    try:
        current = tc_load_config(str(CONFIG_FILE))
        current.setdefault("target_camera", {})
        current.setdefault("service_ports", {})

        tc = current["target_camera"]
        if "ip" in data and data["ip"]:
            tc["ip"] = str(data["ip"]).strip()
        if "username" in data and data["username"]:
            tc["username"] = str(data["username"]).strip()
        if "password" in data and data["password"]:
            tc["password"] = str(data["password"]).strip()
            if "ssh_password" not in data:
                tc["ssh_password"] = str(data["password"]).strip()
        if "ssh_username" in data and data["ssh_username"]:
            tc["ssh_username"] = str(data["ssh_username"]).strip()
        if "ssh_password" in data and data["ssh_password"]:
            tc["ssh_password"] = str(data["ssh_password"]).strip()
        if "model" in data and data["model"]:
            tc["model"] = str(data["model"]).strip()
        if "firmware" in data and data["firmware"]:
            tc["firmware"] = str(data["firmware"]).strip()

        sp = current["service_ports"]
        if isinstance(data.get("service_ports"), dict):
            sp.update(data["service_ports"])

        for req_key, port_keys in _CONFIG_PORT_FIELD_MAP.items():
            if req_key in data and data[req_key] not in (None, ""):
                val = int(data[req_key])
                for pk in port_keys:
                    sp[pk] = val

        if "rtsp_path" in data and data["rtsp_path"]:
            sp["rtsp_path"] = str(data["rtsp_path"]).strip()
        if "onvif_path" in data and data["onvif_path"]:
            sp["onvif_path"] = str(data["onvif_path"]).strip()

        if any(k in data for k in ("snmp_user", "snmp_auth_pass", "snmp_priv_pass")):
            current.setdefault("snmp_v3", {})
            current.setdefault("snmp_credentials", {})
            for dst in (current["snmp_v3"], current["snmp_credentials"]):
                if "snmp_user" in data and data["snmp_user"]:
                    dst["user"] = str(data["snmp_user"]).strip()
                if "snmp_auth_pass" in data and data["snmp_auth_pass"]:
                    dst["auth_pass"] = str(data["snmp_auth_pass"]).strip()
                if "snmp_priv_pass" in data and data["snmp_priv_pass"]:
                    dst["priv_pass"] = str(data["snmp_priv_pass"]).strip()

        if "evidence_base_dir" in data:
            current["evidence_base_dir"] = str(data["evidence_base_dir"]).strip()
        if "evidence_authmech_dir" in data:
            current["evidence_authmech_dir"] = str(data["evidence_authmech_dir"]).strip()
        if "evidence_commech_dir" in data:
            current["evidence_commech_dir"] = str(data["evidence_commech_dir"]).strip()

        # Re-resolve dynamic host network interface/IP toward target camera
        target_ip = tc.get("ip") or get_target_info(current)["ip"]
        host_iface, host_ip = detect_host_network(target_ip, current)
        current["test_host"] = {"ip": host_ip, "interface": host_iface}

        saved = tc_save_config(current, str(CONFIG_FILE))
        saved_with_host = dict(saved)
        saved_with_host["host_info"] = {"interface": host_iface, "ip": host_ip}
        return {
            "status": "ok",
            "message": f"Đã lưu cấu hình thiết bị: {tc.get('ip')} | Host: {host_iface} ({host_ip})",
            "config": saved_with_host,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/target/discover")
async def discover_cameras_api():
    """Discover ONVIF cameras on the local network using WS-Discovery."""
    try:
        sub_env = os.environ.copy()
        sub_env["PYTHONUTF8"] = "1"
        sub_env["PYTHONIOENCODING"] = "utf-8"
        proc = await asyncio.create_subprocess_exec(
            str(VENV_PYTHON),
            "-c",
            f"import sys, json; sys.path.insert(0, {repr(str(BASE_DIR))}); "
            "from camera_manager import discover_onvif_cameras; "
            "print(json.dumps(discover_onvif_cameras(timeout=1.8)))",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=sub_env
        )
        stdout, stderr = await proc.communicate()
        out = stdout.decode("utf-8", errors="ignore").strip()
        cameras = json.loads(out) if out else []

        current_ip = get_target_info(tc_load_config(str(CONFIG_FILE)))["ip"]
        for c in cameras:
            c["selected"] = (c.get("ip") == current_ip)

        return {"status": "ok", "cameras": cameras, "current_target": current_ip}
    except Exception as e:
        return {"status": "error", "message": str(e), "cameras": []}


@app.post("/api/target/probe_ports")
async def probe_ports_api(data: dict = None):
    """Probe open TCP/UDP camera ports, vendor hints, ONVIF path, and RTSP path for any DUT IP."""
    try:
        cfg = tc_load_config(str(CONFIG_FILE))
        ip = str((data or {}).get("ip") or get_target_info(cfg)["ip"]).strip()
        result = await asyncio.to_thread(probe_common_camera_ports, ip)
        return {"status": "ok", **result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/target/auto_link")
async def auto_link_api():
    """Execute Auto-Link multi-subnet network interface configuration."""
    try:
        script = BASE_DIR / "cam_auto_link.py"
        if not script.exists():
            script = PROJECT_DIR / "cam_auto_link.py"
        sub_env = os.environ.copy()
        sub_env["PYTHONUTF8"] = "1"
        sub_env["PYTHONIOENCODING"] = "utf-8"
        proc = await asyncio.create_subprocess_exec(
            str(VENV_PYTHON),
            str(script),
            "--once",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(BASE_DIR),
            env=sub_env
        )
        stdout, stderr = await proc.communicate()
        out = stdout.decode("utf-8", errors="ignore")
        return {"status": "ok", "output": out, "code": proc.returncode}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/evidence_folders")
async def get_evidence_folders():
    """Retrieve current resolved evidence folders and presets."""
    c_dir, a_dir = get_evidence_dirs()
    cfg = {}
    if CONFIG_FILE.exists():
        try:
            cfg = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass

    current_model = cfg.get("target_camera", {}).get("model", "AXIS Q1806-LE")
    base_custom = cfg.get("evidence_base_dir", "").strip()

    presets = [
        {
            "id": "model",
            "name": f"Theo Model ({current_model})",
            "path": str(PROJECT_DIR / current_model / "Mẫu lưu bằng chứng"),
            "exists": (PROJECT_DIR / current_model / "Mẫu lưu bằng chứng").exists()
        },
        {
            "id": "common",
            "name": "Mẫu lưu bằng chứng Chung",
            "path": str(PROJECT_DIR / "Mẫu lưu bằng chứng"),
            "exists": (PROJECT_DIR / "Mẫu lưu bằng chứng").exists()
        },
        {
            "id": "captures",
            "name": "Nội bộ Toolkit (captures/)",
            "path": str(CAPTURES_DIR),
            "exists": CAPTURES_DIR.exists()
        }
    ]

    return {
        "evidence_base_dir": base_custom or str(c_dir.parent if c_dir.name in ["ComMech", "AuthMech"] else c_dir),
        "commech_dir": str(c_dir),
        "authmech_dir": str(a_dir),
        "presets": presets
    }


@app.post("/api/open_folder")
async def open_folder(data: dict):
    """Open folder in native desktop file manager (Linux/Windows/macOS)."""
    folder_type = data.get("type", "base")
    custom_path = data.get("path", "").strip()

    c_dir, a_dir = get_evidence_dirs()
    if custom_path and os.path.exists(custom_path):
        target = Path(custom_path)
    elif folder_type == "authmech":
        target = a_dir
    elif folder_type == "commech":
        target = c_dir
    else:
        cfg = {}
        if CONFIG_FILE.exists():
            try:
                cfg = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
            except Exception:
                pass
        base_dir = cfg.get("evidence_base_dir", "").strip()
        if base_dir and os.path.exists(base_dir):
            target = Path(base_dir)
        else:
            target = c_dir.parent if c_dir.name in ["ComMech", "AuthMech"] else c_dir

    target.mkdir(parents=True, exist_ok=True)
    try:
        if sys.platform == "win32":
            os.startfile(str(target))
        elif sys.platform == "darwin":
            subprocess.Popen(["open", str(target)])
        else:
            subprocess.Popen(["xdg-open", str(target)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return {"status": "ok", "message": f"Đã mở thư mục: {target}", "path": str(target)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Không thể mở thư mục: {e}")


@app.get("/api/evidence")
async def get_evidence():
    """List all captured PCAP files and compliance reports."""
    files = []
    c_dir, a_dir = get_evidence_dirs()
    
    # Check Evidence Dir (ComMech)
    if c_dir.exists():
        for p in sorted(c_dir.glob("*.pcap")):
            stat = p.stat()
            files.append({
                "name": p.name,
                "path": str(p),
                "size_bytes": stat.st_size,
                "size_formatted": f"{stat.st_size / 1024:.1f} KB" if stat.st_size >= 1024 else f"{stat.st_size} B",
                "modified": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(stat.st_mtime)),
                "category": "ComMech Evidence",
                "status": "PASS"
            })

    # Check AuthMech Evidence Dir
    if a_dir.exists():
        for p in sorted(a_dir.glob("*.pcap")):
            stat = p.stat()
            files.append({
                "name": p.name,
                "path": str(p),
                "size_bytes": stat.st_size,
                "size_formatted": f"{stat.st_size / 1024:.1f} KB" if stat.st_size >= 1024 else f"{stat.st_size} B",
                "modified": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(stat.st_mtime)),
                "category": "AuthMech Evidence",
                "status": "PASS"
            })

    # Check Captures Dir
    if CAPTURES_DIR.exists():
        for p in sorted(CAPTURES_DIR.glob("*.pcap"), key=lambda x: x.stat().st_mtime, reverse=True):
            if any(f["name"] == p.name for f in files):
                continue
            stat = p.stat()
            files.append({
                "name": p.name,
                "path": str(p),
                "size_bytes": stat.st_size,
                "size_formatted": f"{stat.st_size / 1024:.1f} KB" if stat.st_size >= 1024 else f"{stat.st_size} B",
                "modified": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(stat.st_mtime)),
                "category": "Capture Workspace",
                "status": "RECORDED"
            })

    return {
        "files": files, 
        "total": len(files),
        "commech_dir": str(c_dir),
        "authmech_dir": str(a_dir),
        "base_dir": str(c_dir.parent if c_dir.name in ["ComMech", "AuthMech"] else c_dir)
    }


@app.get("/api/report/{report_name}")
async def get_report(report_name: str):
    """Retrieve technical markdown audit reports."""
    reports_map = {
        "authmech": (BASE_DIR / "authmech_audit_report.md") if (BASE_DIR / "authmech_audit_report.md").exists() else (CAPTURES_DIR / "authmech_audit_report.md"),
        "authmech_ciphers": (BASE_DIR / "authmech_ciphers_nmap_enum.md") if (BASE_DIR / "authmech_ciphers_nmap_enum.md").exists() else (CAPTURES_DIR / "authmech_ciphers_nmap_enum.md"),
        "commech": (BASE_DIR / "commech_audit_report.md") if (BASE_DIR / "commech_audit_report.md").exists() else (CAPTURES_DIR / "commech_audit_report.md"),
        "commech_ciphers": (BASE_DIR / "commech_ciphers_nmap_enum.md") if (BASE_DIR / "commech_ciphers_nmap_enum.md").exists() else (CAPTURES_DIR / "commech_ciphers_nmap_enum.md"),
        "master": BASE_DIR / "camera_security_audit_report.md",
        "params": BASE_DIR / "security_params_audit_report.md",
        "telemetry_geoip": BASE_DIR / "telemetry_geoip_audit_report.md",
        "firmware_signing": BASE_DIR / "firmware_signing_audit_report.md",
    }
    target = reports_map.get(report_name)
    if not target or not target.exists():
        raise HTTPException(status_code=404, detail="Báo cáo không tồn tại.")
    
    return {
        "name": report_name,
        "path": str(target),
        "content": target.read_text(encoding="utf-8")
    }


@app.get("/api/telemetry_geoip/evidence")
async def get_telemetry_geoip_evidence():
    """Retrieve the latest Telemetry and GeoIP audit evidence JSON."""
    ev_path = CAPTURES_DIR / "telemetry_geoip_audit_evidence.json"
    if not ev_path.exists():
        return {"status": "none", "message": "Chưa có dữ liệu đo kiểm 3.11"}
    try:
        data = json.loads(ev_path.read_text(encoding="utf-8"))
        return {"status": "ok", "data": data}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Lỗi đọc dữ liệu: {e}")


@app.get("/api/firmware_signing/result")
async def get_firmware_signing_result():
    """Retrieve the latest Firmware Signing & Public Key audit result JSON."""
    res_path = BASE_DIR / "firmware_signing_audit_result.json"
    if not res_path.exists():
        return {"status": "none", "message": "Chưa có dữ liệu phân tích firmware."}
    try:
        data = json.loads(res_path.read_text(encoding="utf-8"))
        return {"status": "ok", "data": data}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Lỗi đọc dữ liệu firmware: {e}")


@app.get("/api/firmware_signing/download_tampered")
async def download_tampered_firmware(path: str):
    """Download a generated 1-byte tampered firmware .bin file."""
    target = Path(path).resolve()
    workspace_root = BASE_DIR.parent.resolve()
    if not target.exists() or not target.is_file():
        raise HTTPException(status_code=404, detail="Không tìm thấy file tampered firmware.")
    if "_TAMPERED_1BYTE" not in target.name or not target.name.endswith(".bin"):
        raise HTTPException(status_code=400, detail="Chỉ cho phép tải file *_TAMPERED_1BYTE.bin.")
    if workspace_root not in target.parents:
        raise HTTPException(status_code=403, detail="Đường dẫn nằm ngoài workspace.")
    return FileResponse(path=str(target), filename=target.name, media_type="application/octet-stream")


@app.post("/api/telemetry_geoip/upload_pcap")
async def upload_telemetry_geoip_pcap(request: Request, filename: str = "uploaded.pcap"):
    """Upload a PCAP/PCAPNG file to captures/uploads for offline GeoIP & Telemetry inspection."""
    raw_name = os.path.basename(filename or "uploaded.pcap").strip()
    safe_name = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in raw_name)
    if not safe_name.lower().endswith((".pcap", ".pcapng", ".cap")):
        raise HTTPException(status_code=400, detail="Chỉ hỗ trợ tệp .pcap, .pcapng hoặc .cap")

    body = await request.body()
    if not body:
        raise HTTPException(status_code=400, detail="Tệp PCAP rỗng.")
    if len(body) > 250 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="Tệp PCAP vượt quá giới hạn 250MB.")

    uploads_dir = CAPTURES_DIR / "uploads"
    uploads_dir.mkdir(parents=True, exist_ok=True)
    ts_prefix = time.strftime("%Y%m%d_%H%M%S")
    dest_path = uploads_dir / f"{ts_prefix}_{safe_name}"
    dest_path.write_bytes(body)

    return {
        "status": "ok",
        "filename": dest_path.name,
        "pcap_path": str(dest_path),
        "size_bytes": len(body),
    }


def get_current_model() -> str:
    try:
        if CONFIG_FILE.exists():
            cfg = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
            return cfg.get("target_camera", {}).get("model", "AXIS Q1806-LE")
    except Exception:
        pass
    return "AXIS Q1806-LE"


@app.post("/api/open_wireshark")
async def open_wireshark(data: dict):
    """Launch Wireshark on the specified PCAP file in background."""
    pcap_path = data.get("pcap_path", "")
    target_file = None

    if pcap_path and os.path.exists(pcap_path):
        target_file = pcap_path
    else:
        filename = os.path.basename(pcap_path) if pcap_path else ""
        current_model = get_current_model()
        c_dir, a_dir = get_evidence_dirs()
        candidates = [
            c_dir / filename,
            a_dir / filename,
            PROJECT_DIR / current_model / "Mẫu lưu bằng chứng" / "ComMech" / filename,
            PROJECT_DIR / current_model / "Mẫu lưu bằng chứng" / "AuthMech" / filename,
            PROJECT_DIR / "AXIS Q1806-LE" / "Mẫu lưu bằng chứng" / "ComMech" / filename,
            PROJECT_DIR / "AXIS Q1806-LE" / "Mẫu lưu bằng chứng" / "AuthMech" / filename,
            PROJECT_DIR / "Mẫu lưu bằng chứng" / "ComMech" / filename,
            PROJECT_DIR / "Mẫu lưu bằng chứng" / "AuthMech" / filename,
            CAPTURES_DIR / "evidence" / "ComMech" / filename,
            CAPTURES_DIR / "evidence" / "AuthMech" / filename,
            CAPTURES_DIR / filename,
            BASE_DIR / filename,
        ]
        for c in candidates:
            if c.exists() and c.is_file():
                target_file = str(c)
                break

        if not target_file and filename:
            stem = filename.replace("commech-", "commech").replace("authmech-", "authmech").split(".")[0].split("_")[0]
            matches = sorted(CAPTURES_DIR.glob(f"*{stem}*.pcap"), key=os.path.getmtime, reverse=True)
            if matches:
                target_file = str(matches[0])

    if not target_file:
        raise HTTPException(status_code=404, detail="Chưa có tệp tin PCAP cho phương thức này. Vui lòng bấm 'Test' để ghi nhận gói tin trước!")

    # Tự động phân giải đường dẫn Wireshark trên cả Linux và Windows
    wireshark_bin = "wireshark"
    if sys.platform == "win32":
        for possible_path in [
            r"C:\Program Files\Wireshark\Wireshark.exe",
            r"C:\Program Files (x86)\Wireshark\Wireshark.exe",
        ]:
            if os.path.exists(possible_path):
                wireshark_bin = possible_path
                break

    try:
        if sys.platform == "win32":
            subprocess.Popen([wireshark_bin, str(target_file)], creationflags=subprocess.DETACHED_PROCESS)
        else:
            subprocess.Popen(
                [wireshark_bin, str(target_file)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True
            )
        return {"status": "ok", "message": f"Đã khởi chạy Wireshark mở tệp: {os.path.basename(target_file)}"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Không thể khởi chạy Wireshark: {str(e)}")


REPO_NAME = "Ann-BT/Cumera"
GITHUB_REPO_API = f"https://api.github.com/repos/{REPO_NAME}"
COMMIT_STAMP_FILE = BASE_DIR / ".cumera_commit"


def _get_local_commit() -> str:
    git_dir = BASE_DIR / ".git"
    if git_dir.exists():
        try:
            proc = subprocess.run(["git", "-C", str(BASE_DIR), "rev-parse", "HEAD"], capture_output=True, text=True, encoding="utf-8", errors="ignore")
            if proc.returncode == 0 and proc.stdout.strip():
                return proc.stdout.strip()
        except Exception:
            pass
    if COMMIT_STAMP_FILE.exists():
        try:
            val = COMMIT_STAMP_FILE.read_text(encoding="utf-8").strip()
            if val:
                return val
        except Exception:
            pass
    return "unknown"


@app.get("/api/app/version")
async def get_version():
    """Lấy phiên bản và thông tin Git commit hiện tại của Cumera."""
    ver_file = BASE_DIR / "version.json"
    ver_data = {"app_name": "Cumera", "version": "2.2.0", "repo": REPO_NAME}
    if ver_file.exists():
        try:
            ver_data = json.loads(ver_file.read_text(encoding="utf-8"))
        except Exception:
            pass

    commit_hash = _get_local_commit()
    ver_data["commit"] = commit_hash[:7] if commit_hash != "unknown" else "ZIP"
    ver_data["platform"] = sys.platform
    return ver_data


@app.get("/api/app/check_update")
async def check_update():
    """Kiểm tra bản cập nhật mới trên GitHub repository Ann-BT/Cumera."""
    current_commit = _get_local_commit()

    req = urllib.request.Request(
        f"{GITHUB_REPO_API}/commits/main",
        headers={"User-Agent": "Cumera-App-Updater"}
    )
    try:
        with urllib.request.urlopen(req, timeout=6) as response:
            if response.status == 200:
                data = json.loads(response.read().decode())
                latest_sha = data.get("sha", "")
                commit_msg = data.get("commit", {}).get("message", "").split("\n")[0]
                commit_date = data.get("commit", {}).get("author", {}).get("date", "")

                has_update = True if current_commit == "unknown" else (bool(latest_sha) and current_commit != latest_sha)

                return {
                    "status": "ok",
                    "has_update": has_update,
                    "current_commit": current_commit[:7] if current_commit != "unknown" else "ZIP",
                    "latest_commit": latest_sha[:7],
                    "commit_message": commit_msg,
                    "commit_date": commit_date,
                    "repo": REPO_NAME
                }
    except Exception as e:
        return {"status": "error", "message": f"Không thể kiểm tra GitHub: {e}", "has_update": False}


@app.post("/api/app/update")
async def perform_update():
    """Tự động kéo mã nguồn mới nhất từ GitHub và cập nhật dependencies."""
    git_dir = BASE_DIR / ".git"
    logs = []

    if git_dir.exists() and shutil.which("git"):
        try:
            proc = subprocess.run(
                ["git", "-C", str(BASE_DIR), "pull", "origin", "main"],
                capture_output=True, text=True, encoding="utf-8", errors="ignore", check=True
            )
            logs.append(proc.stdout)
        except Exception as e:
            return {"status": "error", "message": f"Lỗi git pull: {e}"}
    else:
        # Tải ZIP từ GitHub và giải nén (nếu người dùng Windows không cài git)
        zip_url = f"https://github.com/{REPO_NAME}/archive/refs/heads/main.zip"
        try:
            req = urllib.request.Request(zip_url, headers={"User-Agent": "Cumera-App-Updater"})
            with urllib.request.urlopen(req, timeout=20) as resp:
                zip_bytes = resp.read()
            with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
                for member in zf.infolist():
                    parts = member.filename.split("/", 1)
                    if len(parts) > 1 and parts[1]:
                        rel_path = parts[1]
                        # Bảo toàn config.json và thư mục captures của người dùng
                        if rel_path == "config.json" and (BASE_DIR / "config.json").exists():
                            continue
                        if rel_path.startswith("captures/") and not rel_path.endswith(".gitkeep"):
                            continue
                        dest_path = BASE_DIR / rel_path
                        if member.is_dir():
                            dest_path.mkdir(parents=True, exist_ok=True)
                        else:
                            dest_path.parent.mkdir(parents=True, exist_ok=True)
                            with zf.open(member) as src, open(dest_path, "wb") as dst:
                                shutil.copyfileobj(src, dst)
                zip_sha = (zf.comment or b"").decode("utf-8", errors="ignore").strip()
                if len(zip_sha) == 40:
                    COMMIT_STAMP_FILE.write_text(zip_sha, encoding="utf-8")
            logs.append("[OK] Đã tải và cập nhật toàn bộ tệp mới nhất từ GitHub.")
        except Exception as e:
            return {"status": "error", "message": f"Lỗi tải cập nhật: {e}"}

    # Cập nhật các thư viện phụ thuộc nếu có thay đổi trong requirements.txt
    try:
        pip_cmd = [str(VENV_PYTHON), "-m", "pip", "install", "--prefer-binary", "-r", str(BASE_DIR / "requirements.txt")]
        proc = subprocess.run(pip_cmd, capture_output=True, text=True, encoding="utf-8", errors="ignore")
        if proc.returncode == 0:
            logs.append("[OK] Đã kiểm tra và đồng bộ thư viện requirements.txt.")
        else:
            logs.append(f"[!] Cảnh báo pip install: {proc.stderr[:200]}")
    except Exception as e:
        logs.append(f"[!] Lỗi pip: {e}")

    return {
        "status": "ok",
        "message": "Cập nhật ứng dụng Cumera thành công! Vui lòng khởi động lại app.",
        "logs": "\n".join(logs)
    }


# ==============================================================================
# MULTI-CHANNEL TERMINAL RUNNER (DUAL TERMINAL & RELIABLE SUDO STOP ENGINE)
# ==============================================================================

class TerminalChannel:
    def __init__(self, channel_id: str):
        self.channel_id = channel_id
        self.process: Optional[asyncio.subprocess.Process] = None
        self.task: Optional[asyncio.Task] = None
        self.tool_name: str = ""
        self.cmd_str: str = ""

channels: Dict[str, TerminalChannel] = {
    "term1": TerminalChannel("term1"),
    "term2": TerminalChannel("term2"),
}

async def kill_process_tree(proc: Optional[asyncio.subprocess.Process], channel_id: str = "term1"):
    """Dừng tiến trình và toàn bộ tiến trình con (hỗ trợ cả tiến trình sudo/root)."""
    if not proc or proc.returncode is not None:
        return
    pid = proc.pid

    # 1. Gửi SIGINT (Ctrl+C) tới Process Group và PID để kích hoạt dọn dẹp socket/PCAP
    try:
        if sys.platform != "win32":
            subprocess.run(["sudo", "-n", "kill", "-INT", f"-{pid}"], capture_output=True)
            subprocess.run(["sudo", "-n", "kill", "-INT", str(pid)], capture_output=True)
    except Exception:
        pass
    try:
        proc.send_signal(signal.SIGINT)
    except Exception:
        pass

    # Chờ tối đa 1.2s cho tiến trình dọn dẹp sạch
    for _ in range(12):
        if proc.returncode is not None:
            return
        await asyncio.sleep(0.1)

    # 2. Nếu vẫn chưa dừng, gửi SIGTERM
    try:
        if sys.platform != "win32":
            subprocess.run(["sudo", "-n", "kill", "-TERM", f"-{pid}"], capture_output=True)
            subprocess.run(["sudo", "-n", "kill", "-TERM", str(pid)], capture_output=True)
    except Exception:
        pass
    try:
        proc.terminate()
    except Exception:
        pass

    for _ in range(8):
        if proc.returncode is not None:
            return
        await asyncio.sleep(0.1)

    # 3. Cưỡng bức dừng với SIGKILL và pkill toàn bộ tiến trình con
    try:
        if sys.platform != "win32":
            subprocess.run(["sudo", "-n", "kill", "-KILL", f"-{pid}"], capture_output=True)
            subprocess.run(["sudo", "-n", "kill", "-KILL", str(pid)], capture_output=True)
            subprocess.run(["sudo", "-n", "pkill", "-KILL", "-P", str(pid)], capture_output=True)
    except Exception:
        pass
    try:
        proc.kill()
    except Exception:
        pass


@app.post("/api/process/stop")
async def api_stop_process(channel: str = Query("all")):
    """REST endpoint dừng ngay lập tức tiến trình trên kênh chỉ định (term1, term2, hoặc all)."""
    stopped = []
    for cid, ch in channels.items():
        if channel in ["all", cid] and ch.process and ch.process.returncode is None:
            await kill_process_tree(ch.process, cid)
            if ch.task and not ch.task.done():
                ch.task.cancel()
            stopped.append(cid)
    return {"status": "ok", "stopped_channels": stopped}


@app.websocket("/ws/run")
async def websocket_run(websocket: WebSocket):
    """
    WebSocket stream đa luồng hỗ trợ Dual Terminal (term1 & term2)
    Không bị block khi lệnh đang chạy, nhận lệnh 'stop' tức thì.
    """
    global active_process
    await websocket.accept()

    send_queue: asyncio.Queue = asyncio.Queue()

    async def sender_worker():
        while True:
            try:
                out_msg = await send_queue.get()
                await websocket.send_json(out_msg)
                send_queue.task_done()
            except asyncio.CancelledError:
                break
            except Exception:
                break

    sender_task = asyncio.create_task(sender_worker())

    async def run_command_pipeline(ch_id: str, cmd_str: str, tool_name: str, cols_val: Any):
        global active_process
        ch = channels[ch_id]
        final_exit_code = 0
        sub_cmds = [c.strip() for c in cmd_str.split(" && ") if c.strip()]

        env = os.environ.copy()
        env["PYTHONUNBUFFERED"] = "1"
        env["PYTHONUTF8"] = "1"
        env["PYTHONIOENCODING"] = "utf-8"
        try:
            term_cols = max(95, min(220, int(cols_val or 145)))
        except Exception:
            term_cols = 145
        env["COLUMNS"] = str(term_cols)
        env["LINES"] = "50"
        if env.get("TERM", "") in ("", "dumb"):
            env["TERM"] = "xterm-256color"

        try:
            for sub_cmd in sub_cmds:
                try:
                    parts = shlex.split(sub_cmd, posix=(sys.platform != "win32"))
                except Exception:
                    parts = sub_cmd.split(" ")

                if sys.platform == "win32":
                    parts = [p[1:-1] if (len(p) >= 2 and p[0] == p[-1] and p[0] in ('"', "'")) else p for p in parts]
                    if parts and parts[0] == "sudo":
                        parts = parts[1:]

                if not parts:
                    continue

                if parts[0] in ["python", "python3"]:
                    exec_cmd = [str(VENV_PYTHON)] + parts[1:]
                elif parts[0] == "sudo":
                    if len(parts) > 1 and parts[1] in ["python", "python3"]:
                        exec_cmd = ["sudo", str(VENV_PYTHON)] + parts[2:]
                    else:
                        exec_cmd = parts
                elif parts[0] == "ping":
                    if sys.platform == "win32":
                        win_ping = ["ping"]
                        i = 1
                        while i < len(parts):
                            if parts[i] == "-c" and i + 1 < len(parts):
                                win_ping.extend(["-n", parts[i + 1]])
                                i += 2
                            elif parts[i] == "-W" and i + 1 < len(parts):
                                win_ping.extend(["-w", str(int(float(parts[i + 1]) * 1000))])
                                i += 2
                            else:
                                win_ping.append(parts[i])
                                i += 1
                        exec_cmd = win_ping
                    else:
                        exec_cmd = parts
                else:
                    exec_cmd = [str(VENV_PYTHON)] + parts

                proc_kwargs = {
                    "stdout": asyncio.subprocess.PIPE,
                    "stderr": asyncio.subprocess.STDOUT,
                    "cwd": str(BASE_DIR),
                    "env": env,
                }
                if sys.platform != "win32":
                    proc_kwargs["preexec_fn"] = os.setsid

                proc = await asyncio.create_subprocess_exec(*exec_cmd, **proc_kwargs)
                ch.process = proc
                if ch_id == "term1":
                    active_process = proc

                while True:
                    line = await proc.stdout.readline()
                    if not line:
                        break
                    decoded = line.decode("utf-8", errors="replace")
                    await send_queue.put({
                        "type": "stdout",
                        "terminal_id": ch_id,
                        "data": decoded
                    })

                final_exit_code = await proc.wait()
                if final_exit_code != 0:
                    break

            await send_queue.put({
                "type": "exit",
                "terminal_id": ch_id,
                "code": final_exit_code,
                "timestamp": time.strftime("%H:%M:%S")
            })

        except asyncio.CancelledError:
            await send_queue.put({
                "type": "exit",
                "terminal_id": ch_id,
                "code": -15,
                "timestamp": time.strftime("%H:%M:%S")
            })
        except Exception as e:
            await send_queue.put({
                "type": "error",
                "terminal_id": ch_id,
                "message": f"Lỗi thực thi trên {ch_id}: {str(e)}"
            })
        finally:
            ch.process = None
            if ch_id == "term1":
                active_process = None

    try:
        while True:
            raw = await websocket.receive_text()
            msg = json.loads(raw)
            action = msg.get("action")
            ch_id = msg.get("terminal_id") or msg.get("terminal") or "term1"
            if ch_id not in channels:
                ch_id = "term1"

            if action == "stop":
                target = msg.get("terminal_id") or msg.get("terminal") or "all"
                for cid, ch in channels.items():
                    if target in ["all", cid] and ch.process and ch.process.returncode is None:
                        await kill_process_tree(ch.process, cid)
                        if ch.task and not ch.task.done():
                            ch.task.cancel()
                        await send_queue.put({
                            "type": "log",
                            "terminal_id": cid,
                            "data": f"\n\033[1;31m[!] ĐÃ DỪNG TIẾN TRÌNH TRÊN [{cid.upper()}] (SIGINT/SIGTERM)\033[0m\n"
                        })
                continue

            cmd_str = msg.get("cmd")
            tool_name = msg.get("tool_name", "Security Task")

            if not cmd_str:
                await send_queue.put({"type": "error", "terminal_id": ch_id, "message": "Command is required."})
                continue

            # Dừng lệnh cũ trên kênh này nếu đang chạy
            ch = channels[ch_id]
            if ch.process and ch.process.returncode is None:
                await kill_process_tree(ch.process, ch_id)
            if ch.task and not ch.task.done():
                ch.task.cancel()

            ch.cmd_str = cmd_str
            ch.tool_name = tool_name

            await send_queue.put({
                "type": "start",
                "terminal_id": ch_id,
                "tool_name": tool_name,
                "cmd": cmd_str,
                "timestamp": time.strftime("%H:%M:%S")
            })

            ch.task = asyncio.create_task(
                run_command_pipeline(ch_id, cmd_str, tool_name, msg.get("cols"))
            )

    except WebSocketDisconnect:
        pass
    except Exception as e:
        try:
            await send_queue.put({"type": "error", "terminal_id": "term1", "message": str(e)})
        except Exception:
            pass
    finally:
        sender_task.cancel()


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8765))
    print(f"[*] Starting Camera Security Auditor Web Server on http://127.0.0.1:{port}")
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")
