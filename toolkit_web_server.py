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

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
import uvicorn

BASE_DIR = Path(__file__).resolve().parent
PROJECT_DIR = BASE_DIR.parent

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
HTML_FILE = BASE_DIR / "ui_dashboard.html"

def get_current_model() -> str:
    if CONFIG_FILE.exists():
        try:
            cfg = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
            return cfg.get("target_camera", {}).get("model", "AXIS Q1806-LE")
        except Exception:
            pass
    return "AXIS Q1806-LE"

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

app = FastAPI(title="Cumera Security Auditor Backend", version="2.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

os.makedirs(CAPTURES_DIR, exist_ok=True)
app.mount("/captures", StaticFiles(directory=str(CAPTURES_DIR)), name="captures")

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
    """Check DUT camera ping status and network latency."""
    ip = "192.168.1.100"
    if CONFIG_FILE.exists():
        try:
            cfg = json.loads(CONFIG_FILE.read_text())
            ip = cfg.get("target_camera", {}).get("ip", ip)
        except Exception:
            pass

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
    if online and "time=" in out:
        try:
            time_part = out.split("time=")[1].split(" ")[0]
            latency_ms = float(time_part)
        except Exception:
            latency_ms = 0.5

    return {
        "ip": ip,
        "online": online,
        "latency_ms": latency_ms,
        "checked_at": time.time()
    }


@app.get("/api/config")
async def get_config():
    """Retrieve current target configuration."""
    if CONFIG_FILE.exists():
        try:
            return json.loads(CONFIG_FILE.read_text())
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    return {}


@app.post("/api/config")
async def save_config(data: dict):
    """Save updated target configuration."""
    try:
        current = {}
        if CONFIG_FILE.exists():
            current = json.loads(CONFIG_FILE.read_text())
        current.setdefault("target_camera", {})
        current.setdefault("service_ports", {})

        tc = current["target_camera"]
        if "ip" in data and data["ip"]:
            tc["ip"] = str(data["ip"]).strip()
        if "username" in data and data["username"]:
            tc["username"] = str(data["username"]).strip()
        if "password" in data and data["password"]:
            tc["password"] = str(data["password"]).strip()
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
        if "https_port" in data:
            sp["https"] = int(data["https_port"])
        if "rtsps_port" in data:
            sp["rtsps"] = int(data["rtsps_port"])
            sp["rtsps_tls"] = int(data["rtsps_port"])
        if "rtsp_port" in data:
            sp["rtsp"] = int(data["rtsp_port"])
            sp["rtsp_cleartext"] = int(data["rtsp_port"])
        if "ssh_port" in data:
            sp["ssh"] = int(data["ssh_port"])
        if "snmp_port" in data:
            sp["snmp"] = int(data["snmp_port"])
            sp["snmp_udp"] = int(data["snmp_port"])
        if "rtsp_path" in data and data["rtsp_path"]:
            sp["rtsp_path"] = str(data["rtsp_path"]).strip()

        if "evidence_base_dir" in data:
            current["evidence_base_dir"] = str(data["evidence_base_dir"]).strip()
        if "evidence_authmech_dir" in data:
            current["evidence_authmech_dir"] = str(data["evidence_authmech_dir"]).strip()
        if "evidence_commech_dir" in data:
            current["evidence_commech_dir"] = str(data["evidence_commech_dir"]).strip()

        CONFIG_FILE.write_text(json.dumps(current, indent=2, ensure_ascii=False))
        return {
            "status": "ok", 
            "message": f"Đã lưu cấu hình thiết bị: {tc.get('ip')}",
            "config": current
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/target/discover")
async def discover_cameras_api():
    """Discover ONVIF cameras on the local network using WS-Discovery."""
    try:
        proc = await asyncio.create_subprocess_exec(
            str(VENV_PYTHON),
            "-c",
            f"import sys, json; sys.path.insert(0, {repr(str(BASE_DIR))}); "
            "from camera_manager import discover_onvif_cameras; "
            "print(json.dumps(discover_onvif_cameras(timeout=1.8)))",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await proc.communicate()
        out = stdout.decode("utf-8", errors="ignore").strip()
        if out:
            cameras = json.loads(out)
        else:
            cameras = []

        # Read current target to mark selected
        current_ip = "192.168.20.38"
        if CONFIG_FILE.exists():
            try:
                cfg = json.loads(CONFIG_FILE.read_text())
                current_ip = cfg.get("target_camera", {}).get("ip", current_ip)
            except Exception:
                pass

        for c in cameras:
            c["selected"] = (c.get("ip") == current_ip)

        return {"status": "ok", "cameras": cameras, "current_target": current_ip}
    except Exception as e:
        return {"status": "error", "message": str(e), "cameras": []}


@app.post("/api/target/auto_link")
async def auto_link_api():
    """Execute Auto-Link multi-subnet network interface configuration."""
    try:
        script = BASE_DIR / "cam_auto_link.py"
        if not script.exists():
            script = PROJECT_DIR / "cam_auto_link.py"
        proc = await asyncio.create_subprocess_exec(
            str(VENV_PYTHON),
            str(script),
            "--once",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(BASE_DIR)
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

@app.get("/api/app/version")
async def get_version():
    """Lấy phiên bản và thông tin Git commit hiện tại của Cumera."""
    ver_file = BASE_DIR / "version.json"
    ver_data = {"app_name": "Cumera", "version": "2.1.0", "repo": REPO_NAME}
    if ver_file.exists():
        try:
            ver_data = json.loads(ver_file.read_text(encoding="utf-8"))
        except Exception:
            pass

    commit_hash = "unknown"
    git_dir = BASE_DIR / ".git"
    if git_dir.exists():
        try:
            proc = subprocess.run(["git", "-C", str(BASE_DIR), "rev-parse", "--short", "HEAD"], capture_output=True, text=True)
            if proc.returncode == 0:
                commit_hash = proc.stdout.strip()
        except Exception:
            pass
    ver_data["commit"] = commit_hash
    ver_data["platform"] = sys.platform
    return ver_data


@app.get("/api/app/check_update")
async def check_update():
    """Kiểm tra bản cập nhật mới trên GitHub repository Ann-BT/Cumera."""
    current_commit = "unknown"
    git_dir = BASE_DIR / ".git"
    if git_dir.exists():
        try:
            proc = subprocess.run(["git", "-C", str(BASE_DIR), "rev-parse", "HEAD"], capture_output=True, text=True)
            if proc.returncode == 0:
                current_commit = proc.stdout.strip()
        except Exception:
            pass

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

                has_update = False
                if current_commit != "unknown" and latest_sha:
                    has_update = (current_commit != latest_sha)

                return {
                    "status": "ok",
                    "has_update": has_update,
                    "current_commit": current_commit[:7] if current_commit != "unknown" else "v2.1.0",
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
                capture_output=True, text=True, check=True
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
            logs.append("[OK] Đã tải và cập nhật toàn bộ tệp mới nhất từ GitHub.")
        except Exception as e:
            return {"status": "error", "message": f"Lỗi tải cập nhật: {e}"}

    # Cập nhật các thư viện phụ thuộc nếu có thay đổi trong requirements.txt
    try:
        pip_cmd = [str(VENV_PYTHON), "-m", "pip", "install", "-r", str(BASE_DIR / "requirements.txt")]
        proc = subprocess.run(pip_cmd, capture_output=True, text=True)
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


@app.websocket("/ws/run")
async def websocket_run(websocket: WebSocket):
    """WebSocket stream for real-time tool execution logs."""
    global active_process
    await websocket.accept()

    try:
        while True:
            raw = await websocket.receive_text()
            msg = json.loads(raw)
            action = msg.get("action")

            if action == "stop":
                if active_process and active_process.returncode is None:
                    try:
                        active_process.terminate()
                        await websocket.send_json({
                            "type": "log",
                            "data": "\n\033[1;31m[!] ĐÃ NHẬN TÍN HIỆU DỪNG TỪ NGƯỜI DÙNG (SIGTERM)\033[0m\n"
                        })
                    except Exception as e:
                        pass
                continue

            cmd_str = msg.get("cmd")
            tool_name = msg.get("tool_name", "Security Task")

            if not cmd_str:
                await websocket.send_json({"type": "error", "message": "Command is required."})
                continue

            # Ensure previous process is terminated
            if active_process and active_process.returncode is None:
                try:
                    active_process.terminate()
                    await active_process.wait()
                except Exception:
                    pass

            await websocket.send_json({
                "type": "start",
                "tool_name": tool_name,
                "cmd": cmd_str,
                "timestamp": time.strftime("%H:%M:%S")
            })

            # Parse and transform command
            # If command starts with python, substitute with venv python
            try:
                parts = shlex.split(cmd_str, posix=(sys.platform != "win32"))
            except Exception:
                parts = cmd_str.split(" ")

            # On Windows, strip sudo if present
            if sys.platform == "win32" and parts and parts[0] == "sudo":
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
                exec_cmd = parts
            else:
                exec_cmd = [str(VENV_PYTHON)] + parts

            # Start asynchronous subprocess
            try:
                env = os.environ.copy()
                env["PYTHONUNBUFFERED"] = "1"
                active_process = await asyncio.create_subprocess_exec(
                    *exec_cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.STDOUT,
                    cwd=str(BASE_DIR),
                    env=env
                )

                # Stream stdout chunks line by line
                while True:
                    line = await active_process.stdout.readline()
                    if not line:
                        break
                    decoded = line.decode("utf-8", errors="replace")
                    await websocket.send_json({
                        "type": "stdout",
                        "data": decoded
                    })

                exit_code = await active_process.wait()
                await websocket.send_json({
                    "type": "exit",
                    "code": exit_code,
                    "timestamp": time.strftime("%H:%M:%S")
                })

            except Exception as e:
                await websocket.send_json({
                    "type": "error",
                    "message": f"Lỗi khởi chạy tiến trình: {str(e)}"
                })

    except WebSocketDisconnect:
        pass
    except Exception as e:
        try:
            await websocket.send_json({"type": "error", "message": str(e)})
        except Exception:
            pass


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8765))
    print(f"[*] Starting Camera Security Auditor Web Server on http://127.0.0.1:{port}")
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")
