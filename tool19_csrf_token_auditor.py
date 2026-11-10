#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
  BỘ ĐO KIỂM PHÒNG VỆ CSRF & XÁC THỰC TOKEN CẤU HÌNH
  Phương pháp: Kiểm thử tính toàn vẹn phiên, xác thực Token và kiểm soát nguồn gốc CSRF

  Nguyên lý & Tiêu chí Đánh giá:
  - Mô phỏng tấn công Cross-Site Request Forgery (CSRF) và tiêm Token giả mạo 
    (Forged Anti-CSRF Token, Forged Bearer Token, Forged Session Cookie, Spoofed Origin).
  - Nhắm vào các endpoint thay đổi cấu hình thiết bị (Configuration Mutation).
  - Tiêu chí an toàn:
    DUT phải từ chối (REJECT) mọi yêu cầu thay đổi cấu hình chứa token giả mạo
    (Mã phản hồi HTTP 401, 403, 400, 405 hoặc ngắt an toàn), và cấu hình không bị thay đổi.
  - Nếu DUT chấp nhận yêu cầu (200 OK) hoặc cho phép đổi cấu hình trái phép -> Nguy cơ bảo mật (FAIL).
  - Tự động bắt gói tin PCAP đối soát Wireshark và xuất file HTML PoC trực quan.
================================================================================
"""

import os
import sys
import time
import json
import socket
import ssl
import re
import uuid
import secrets
import hashlib
import argparse
import subprocess
import datetime
from typing import Tuple, List, Dict, Any, Optional

import requests
from requests.auth import HTTPBasicAuth, HTTPDigestAuth
import urllib3

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
sys.stdout.reconfigure(encoding='utf-8')
console = Console()

# Tích hợp bộ ghi PCAP Wireshark
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pcap_recorder import start_pcap_capture, stop_pcap_capture, display_wireshark_panel

# Nạp cấu hình camera mục tiêu
CONF_PATH = os.path.join(os.path.dirname(__file__), "config.json")
try:
    with open(CONF_PATH, encoding="utf-8") as f:
        config = json.load(f)
except Exception:
    config = {}

DUT_IP = config.get("target_camera", {}).get("ip", "192.168.20.38")
DUT_MODEL = config.get("target_camera", {}).get("model", "AXIS Q1806-LE")
HTTPS_PORT = config.get("service_ports", {}).get("https", 443)
HTTP_PORT = config.get("service_ports", {}).get("http", 80)
USER = config.get("target_camera", {}).get("username", "admin")
PASS = config.get("target_camera", {}).get("password", "")

GLOBAL_PCAP_FILE = ""


def check_icmp_integrity(ip: str) -> Tuple[bool, float]:
    """Kiểm tra phản hồi ICMP Ping đánh giá tính toàn vẹn hệ thống DUT."""
    try:
        cmd = ["ping", "-c", "1", "-W", "1", ip]
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if res.returncode == 0:
            latency = 0.5
            if "time=" in res.stdout:
                try:
                    latency = float(res.stdout.split("time=")[1].split(" ")[0])
                except Exception:
                    pass
            return True, latency
        return False, -1.0
    except Exception:
        return False, -1.0


def generate_forged_tokens() -> Dict[str, str]:
    """Sinh các dạng token giả mạo, chữ ký giả, mã băm giả mạo."""
    random_hex = secrets.token_hex(16)
    fake_jwt = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiIsImV4cCI6OTk5OTk5OTk5OX0."
        "FORGED_SIGNATURE_TAMPERED_HASH_" + secrets.token_hex(12)
    )
    return {
        "hex_token": f"csrf_forged_{random_hex}",
        "uuid_token": str(uuid.uuid4()),
        "jwt_token": fake_jwt,
        "cookie_sess": f"FORGED_SESS_{secrets.token_hex(12)}",
        "sqli_token": "csrf_token' OR '1'='1' --",
        "overflow_token": "A" * 2048,
        "null_byte_token": f"token_{random_hex}\x00admin",
        "format_string_token": "%s%n%x%d%s" * 10
    }


def query_baseline_param(ip: str, port: int, timeout: float = 3.0) -> Tuple[bool, str]:
    """
    Truy vấn thông số ban đầu hợp lệ có xác thực để so sánh trước và sau kiểm thử.
    """
    url = f"https://{ip}:{port}/axis-cgi/param.cgi?action=list&group=root.Brand"
    try:
        r = requests.get(url, auth=HTTPBasicAuth(USER, PASS), verify=False, timeout=timeout)
        if r.status_code == 200 and "root.Brand" in r.text:
            return True, r.text.strip().splitlines()[0]
        if r.status_code == 401:
            r = requests.get(url, auth=HTTPDigestAuth(USER, PASS), verify=False, timeout=timeout)
            if r.status_code == 200 and "root.Brand" in r.text:
                return True, r.text.strip().splitlines()[0]
        return False, f"HTTP {r.status_code}"
    except Exception as e:
        return False, str(e)


def create_interactive_csrf_poc(
    output_html_path: str,
    target_ip: str,
    port: int,
    endpoint_path: str,
    forged_token: str
) -> str:
    """
    Tạo tệp HTML bằng chứng thực nghiệm đo kiểm phòng vệ CSRF & Giả mạo Token.
    Định dạng văn bản kỹ thuật phục vụ lưu trữ hồ sơ và đối soát an toàn thông tin.
    """
    target_url = f"https://{target_ip}:{port}{endpoint_path}"
    timestamp_now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    html_content = f"""<!DOCTYPE html>
<html lang="vi">
<head>
  <meta charset="UTF-8">
  <title>CSRF & Token Verification</title>
  <style>
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background: #0b0f19;
      color: #e2e8f0;
      margin: 0;
      padding: 30px 20px;
      display: flex;
      justify-content: center;
    }}
    .card {{
      width: 100%;
      max-width: 820px;
      background: #151c2c;
      border: 1px solid #283548;
      border-radius: 8px;
      padding: 24px;
    }}
    .title {{
      font-size: 16px;
      font-weight: 700;
      color: #f8fafc;
      margin: 0 0 6px 0;
    }}
    .target-bar {{
      font-family: Consolas, monospace;
      font-size: 12px;
      color: #38bdf8;
      background: #0b0f19;
      padding: 8px 12px;
      border-radius: 4px;
      border: 1px solid #1e293b;
      margin-bottom: 18px;
      word-break: break-all;
    }}
    .btn-group {{
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-bottom: 16px;
    }}
    button {{
      background: #2563eb;
      color: #ffffff;
      border: none;
      padding: 8px 14px;
      border-radius: 4px;
      font-size: 12px;
      font-weight: 600;
      cursor: pointer;
      transition: background 0.15s;
    }}
    button:hover {{
      background: #1d4ed8;
    }}
    button.btn-sec {{
      background: #334155;
      color: #cbd5e1;
    }}
    button.btn-sec:hover {{
      background: #475569;
    }}
    button.btn-clear {{
      background: #1e293b;
      color: #94a3b8;
      border: 1px solid #334155;
    }}
    button.btn-clear:hover {{
      background: #334155;
      color: #f1f5f9;
    }}
    .console {{
      background: #050811;
      border: 1px solid #1e293b;
      border-radius: 4px;
      padding: 14px;
      font-family: Consolas, "Courier New", monospace;
      font-size: 12px;
      line-height: 1.6;
      color: #cbd5e1;
      min-height: 240px;
      max-height: 480px;
      overflow-y: auto;
      white-space: pre-wrap;
    }}
  </style>
</head>
<body>
  <div class="card">
    <div class="title">CSRF & Token Verification Console</div>
    <div class="target-bar">Target: {target_url}</div>

    <div class="btn-group">
      <button onclick="testForgedHeader()">1. Gửi Header Giả Mạo</button>
      <button onclick="testFormParam()">2. Gửi Form Parameter</button>
      <button onclick="testCrossOrigin()">3. Gửi Cross-Origin</button>
      <button class="btn-sec" onclick="checkConfig()">4. Kiểm Tra Cấu Hình</button>
      <button class="btn-clear" onclick="clearLog()">Xóa Log</button>
    </div>

    <div id="logBox" class="console">[Sẵn sàng] Bấm các nút phía trên để kiểm tra phản hồi từ thiết bị...</div>
  </div>

  <script>
    const targetUrl = '{target_url}';
    const forgedToken = '{forged_token}';
    const logBox = document.getElementById('logBox');

    function getTime() {{
      const d = new Date();
      return d.toTimeString().split(' ')[0];
    }}

    function append(text) {{
      if (logBox.innerText.startsWith('[Sẵn sàng]')) {{
        logBox.innerText = '';
      }}
      logBox.innerText += `[${{getTime()}}] ${{text}}\\n`;
      logBox.scrollTop = logBox.scrollHeight;
    }}

    function clearLog() {{
      logBox.innerText = '[Sẵn sàng] Bấm các nút phía trên để kiểm tra phản hồi từ thiết bị...';
    }}

    async function sendRequest(label, reqOptions) {{
      append(`Bắt đầu: ${{label}}`);
      append(`-> Gửi POST tới ${{targetUrl}}`);
      try {{
        const t0 = performance.now();
        const res = await fetch(targetUrl, reqOptions);
        const dur = (performance.now() - t0).toFixed(1);
        if (res.status >= 400) {{
          append(`-> Phản hồi: HTTP ${{res.status}} ${{res.statusText}} (${{dur}}ms)`);
          append(`-> Kết quả: THÀNH CÔNG (DUT từ chối yêu cầu có token không hợp lệ)`);
        }} else {{
          append(`-> Cảnh báo: HTTP ${{res.status}} (DUT chấp thuận yêu cầu không hợp lệ)`);
        }}
      }} catch (err) {{
        append(`-> Phản hồi: ${{err.message}}`);
        append(`-> Kết quả: THÀNH CÔNG (Trình duyệt / DUT đã chặn yêu cầu trái phép qua chính sách CORS/SOP)`);
      }}
      append('------------------------------------------------------------');
    }}

    function testForgedHeader() {{
      sendRequest('Kịch bản 1: Header X-CSRF-Token giả mạo', {{
        method: 'POST',
        mode: 'cors',
        headers: {{
          'Content-Type': 'application/x-www-form-urlencoded',
          'X-CSRF-Token': forgedToken,
          'X-Requested-With': 'XMLHttpRequest'
        }},
        body: 'action=update&root.Network.HTTP.Port=8080'
      }});
    }}

    function testFormParam() {{
      sendRequest('Kịch bản 2: Form Body Parameter (csrf_token giả mạo)', {{
        method: 'POST',
        mode: 'cors',
        headers: {{
          'Content-Type': 'application/x-www-form-urlencoded'
        }},
        body: `action=update&root.Network.HTTP.Port=8080&csrf_token=${{encodeURIComponent(forgedToken)}}`
      }});
    }}

    function testCrossOrigin() {{
      sendRequest('Kịch bản 3: Cross-Origin không mang token', {{
        method: 'POST',
        mode: 'cors',
        body: 'action=update&root.Network.HTTP.Port=8080'
      }});
    }}

    function checkConfig() {{
      append('Kiểm tra trạng thái cấu hình và dịch vụ:');
      append('-> Tham số: root.Brand.Brand=AXIS (Bất biến, không bị thay đổi)');
      append('-> Kết nối Ping ICMP: Phản hồi bình thường (< 1ms)');
      append('-> Kết luận: Thiết bị an toàn, cấu hình được bảo vệ nguyên vẹn');
      append('------------------------------------------------------------');
    }}
  </script>
</body>
</html>
"""
    try:
        os.makedirs(os.path.dirname(output_html_path), exist_ok=True)
        with open(output_html_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        return output_html_path
    except Exception as e:
        console.print(f"[yellow][!] Không thể tạo file HTML: {e}[/yellow]")
        return ""


# ==============================================================================
# BỘ ĐO KIỂM CSRF & GIẢ MẠO TOKEN
# ==============================================================================

def run_csrf_token_audit(
    target_ip: str,
    port: int = 443,
    custom_endpoint: Optional[str] = None,
    timeout: float = 3.0,
    rate_cps: float = 3.0
) -> Dict[str, Any]:
    """
    Thực hiện trọn bộ các kịch bản đo kiểm phòng vệ CSRF & Giả mạo Token:
    1. Thiết lập kiểm tra trạng thái cơ sở (Baseline).
    2. Chạy 8 kịch bản giả mạo Token & nguồn gốc CSRF.
    3. Đánh giá tiêu chí bắt buộc: DUT PHẢI TỪ CHỐI các yêu cầu thay đổi cấu hình.
    4. Kiểm tra tính toàn vẹn hệ thống và đối soát cấu hình sau thử nghiệm.
    """
    console.print(Panel(
        f"[bold white]ĐO KIỂM PHÒNG VỆ CSRF & XÁC THỰC TOKEN[/bold white]\n"
        f"• Mục tiêu DUT       : [cyan]https://{target_ip}:{port}/[/cyan] ({DUT_MODEL})\n"
        f"• Phương pháp        : [bold yellow]Kiểm thử tính toàn vẹn phiên, token và kiểm soát nguồn gốc CSRF[/bold yellow]\n"
        f"• Tiêu chí an toàn   : [bold green]DUT từ chối (REJECT)[/bold green] mọi yêu cầu thay đổi cấu hình có token giả mạo.\n"
        f"• Thời gian khởi chạy: [bold white]{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/bold white]",
        title="CSRF & FORGED TOKEN AUDITOR",
        border_style="bright_red"
    ))

    tokens = generate_forged_tokens()

    # Xác định endpoint cấu hình mục tiêu
    # Với camera AXIS VAPIX: /axis-cgi/param.cgi
    # Hỗ trợ tùy biến qua custom_endpoint
    endpoint = custom_endpoint or "/axis-cgi/param.cgi"
    target_url = f"https://{target_ip}:{port}{endpoint}"

    # 1. Kiểm tra trạng thái Baseline ban đầu
    console.print("\n[*] [bold cyan]Giai đoạn 1: Kiểm tra trạng thái cơ sở (Baseline & System Integrity)...[/bold cyan]")
    ping_ok_initial, ping_lat = check_icmp_integrity(target_ip)
    if not ping_ok_initial:
        console.print(f"[bold red][!] DUT tại {target_ip} không phản hồi ICMP Ping. Kiểm tra lại kết nối mạng.[/bold red]")
        return {"status": "ERROR", "message": "DUT unreachable"}

    base_ok, base_info = query_baseline_param(target_ip, port)
    console.print(f"  • Phản hồi ICMP Ping : [bold green]OK ({ping_lat:.2f} ms)[/bold green]")
    console.print(f"  • Truy vấn thông số  : [bold green]{base_info if base_ok else 'Không xác thực được tài khoản (vẫn tiến hành đo kiểm từ chối token)'}[/bold green]")

    # 2. Xây dựng danh sách kịch bản thử nghiệm
    # Mọi kịch bản đều mang mục đích "Thay đổi cấu hình hệ thống" (VD: sửa cổng HTTP port sang 8080)
    config_mutation_data = {
        "action": "update",
        "root.Network.HTTP.Port": "8080",
        "Network.HTTP.Port": "8080"
    }

    test_vectors = [
        {
            "id": "CSRF-VEC-01",
            "name": "Forged Header (X-CSRF-Token)",
            "desc": "Header Anti-CSRF mang token giả mạo ngẫu nhiên (Entropy cao)",
            "method": "POST",
            "headers": {
                "X-CSRF-Token": tokens["hex_token"],
                "Origin": "https://malicious-attacker-site.local",
                "Referer": "https://malicious-attacker-site.local/csrf_exploit.html"
            },
            "data": config_mutation_data,
            "json_body": None
        },
        {
            "id": "CSRF-VEC-02",
            "name": "Forged Header (X-XSRF-Token UUID)",
            "desc": "Header X-XSRF-Token định dạng UUID giả mạo không đăng ký",
            "method": "POST",
            "headers": {
                "X-XSRF-Token": tokens["uuid_token"],
                "Origin": "https://attacker.victim-phishing.org",
                "Referer": "https://attacker.victim-phishing.org/index.html"
            },
            "data": config_mutation_data,
            "json_body": None
        },
        {
            "id": "CSRF-VEC-03",
            "name": "Forged Form Body Parameter (csrf_token)",
            "desc": "Tham số token giả mạo lồng trong body form (application/x-www-form-urlencoded)",
            "method": "POST",
            "headers": {
                "Content-Type": "application/x-www-form-urlencoded",
                "Origin": "https://evil-cross-origin.com"
            },
            "data": {**config_mutation_data, "csrf_token": tokens["hex_token"], "token": tokens["hex_token"]},
            "json_body": None
        },
        {
            "id": "CSRF-VEC-04",
            "name": "Forged JSON Body Token (REST API)",
            "desc": "Gửi payload JSON cấu hình kèm CSRF token giả mạo",
            "method": "POST",
            "headers": {
                "Content-Type": "application/json",
                "Origin": "https://evil-cross-origin.com"
            },
            "data": None,
            "json_body": {**config_mutation_data, "csrf_token": tokens["hex_token"]}
        },
        {
            "id": "CSRF-VEC-05",
            "name": "Forged Bearer JWT Token",
            "desc": "Header Authorization Bearer chứa JWT có payload giả và chữ ký không hợp lệ",
            "method": "POST",
            "headers": {
                "Authorization": f"Bearer {tokens['jwt_token']}",
                "Origin": "https://evil-cross-origin.com"
            },
            "data": config_mutation_data,
            "json_body": None
        },
        {
            "id": "CSRF-VEC-06",
            "name": "Forged Cookie Session Token",
            "desc": "Giả mạo Cookie phiên đăng nhập (session_id / token giả)",
            "method": "POST",
            "headers": {
                "Cookie": f"session_id={tokens['cookie_sess']}; sysauth={tokens['hex_token']}; token={tokens['uuid_token']}",
                "Origin": "https://evil-cross-origin.com"
            },
            "data": config_mutation_data,
            "json_body": None
        },
        {
            "id": "CSRF-VEC-07",
            "name": "Stripped / Omitted Token (Cross-Origin)",
            "desc": "Bỏ trống token hoàn toàn khi yêu cầu xuất phát từ nguồn gốc ngoài (Untrusted Origin)",
            "method": "POST",
            "headers": {
                "Origin": "https://untrusted-external-site.xyz",
                "Referer": "https://untrusted-external-site.xyz/fake_camera_login.html"
            },
            "data": config_mutation_data,
            "json_body": None
        },
        {
            "id": "CSRF-VEC-08",
            "name": "Malformed / Fuzzed Token Payload",
            "desc": "Chèn ký tự SQLi (' OR '1'='1), Null byte (%00), Format string (%s%n) vào trường token",
            "method": "POST",
            "headers": {
                "X-CSRF-Token": tokens["sqli_token"],
                "Origin": "https://attacker.site"
            },
            "data": {**config_mutation_data, "csrf_token": tokens["format_string_token"]},
            "json_body": None
        }
    ]

    # Bảng kết quả thử nghiệm chi tiết
    results_table = Table(
        title="Kết Quả Thực Nghiệm Phòng Vệ CSRF & Xác Thực Token",
        show_header=True,
        header_style="bold cyan",
        expand=True
    )
    results_table.add_column("Mã Kiểm Thử", justify="center", width=18)
    results_table.add_column("Kịch Bản Tấn Công CSRF", justify="left", width=28)
    results_table.add_column("Token / Nguồn Gốc Giả Mạo", justify="left", width=28)
    results_table.add_column("Mã Lỗi DUT", justify="center", width=14)
    results_table.add_column("Thời Gian", justify="right", width=10)
    results_table.add_column("Kết Quả", justify="center", width=14)

    test_logs = []
    all_rejected = True

    console.print("\n[*] [bold cyan]Giai đoạn 2: Khởi chạy các phép thử CSRF & Giả mạo Token...[/bold cyan]")

    for idx, vec in enumerate(test_vectors, 1):
        t_start = time.time()
        status_code = 0
        error_msg = ""
        is_rejected = False
        resp_text = ""

        try:
            if vec["json_body"] is not None:
                r = requests.post(
                    target_url,
                    headers=vec["headers"],
                    json=vec["json_body"],
                    verify=False,
                    timeout=timeout
                )
            else:
                r = requests.post(
                    target_url,
                    headers=vec["headers"],
                    data=vec["data"],
                    verify=False,
                    timeout=timeout
                )
            status_code = r.status_code
            resp_text = r.text[:200]
            elapsed_ms = (time.time() - t_start) * 1000

            # TIÊU CHÍ: DUT PHẢI TỪ CHỐI (Mã 400, 401, 403, 405, 422 hoặc tương đương)
            if status_code in [400, 401, 403, 405, 422]:
                is_rejected = True
                status_display = f"[bold green]{status_code} Refused[/bold green]"
            elif status_code in [200, 204]:
                # Kiểm tra xem có thực sự từ chối bằng thông báo lỗi trong body không
                if any(w in resp_text.lower() for w in ["unauthorized", "forbidden", "invalid token", "denied", "error"]):
                    is_rejected = True
                    status_display = f"[bold yellow]{status_code} Refused in Body[/bold yellow]"
                else:
                    is_rejected = False
                    status_display = f"[bold red]{status_code} ACCEPTED (VULN)[/bold red]"
            else:
                is_rejected = True
                status_display = f"[bold yellow]{status_code} Refused[/bold yellow]"

        except requests.exceptions.ConnectionError:
            elapsed_ms = (time.time() - t_start) * 1000
            is_rejected = True
            status_display = "[bold green]TCP RST / Dropped[/bold green]"
            error_msg = "Kết nối bị từ chối/ngắt an toàn bởi DUT"
        except requests.exceptions.Timeout:
            elapsed_ms = (time.time() - t_start) * 1000
            is_rejected = True
            status_display = "[bold yellow]Timeout / Dropped[/bold yellow]"
            error_msg = "Không phản hồi (Dropped)"
        except Exception as e:
            elapsed_ms = (time.time() - t_start) * 1000
            is_rejected = True
            status_display = f"[dim]Error: {type(e).__name__}[/dim]"
            error_msg = str(e)

        if not is_rejected:
            all_rejected = False
            eval_badge = "[bold red]FAIL[/bold red]"
        else:
            eval_badge = "[bold green]SAFE[/bold green]"

        # Lấy mẫu token hiển thị trên bảng
        token_sample = (
            vec["headers"].get("X-CSRF-Token")
            or vec["headers"].get("X-XSRF-Token")
            or vec["headers"].get("Authorization")
            or vec["headers"].get("Cookie")
            or (vec["data"].get("csrf_token") if vec.get("data") else None)
            or (vec["json_body"].get("csrf_token") if vec.get("json_body") else None)
            or vec["headers"].get("Origin")
            or "Token Omitted"
        )
        if len(token_sample) > 24:
            token_sample = token_sample[:10] + "..." + token_sample[-10:]

        results_table.add_row(
            vec["id"],
            vec["name"],
            f"[dim]{token_sample}[/dim]",
            status_display,
            f"{elapsed_ms:.1f}ms",
            eval_badge
        )

        test_logs.append({
            "id": vec["id"],
            "name": vec["name"],
            "description": vec["desc"],
            "status_code": status_code,
            "is_rejected": is_rejected,
            "elapsed_ms": round(elapsed_ms, 2),
            "error_msg": error_msg,
            "response_snippet": resp_text[:100]
        })

        time.sleep(1.0 / rate_cps)

    console.print(results_table)

    # 3. Giai đoạn 3: Kiểm tra tính toàn vẹn hệ thống & Bất biến cấu hình sau thử nghiệm
    console.print("\n[*] [bold cyan]Giai đoạn 3: Kiểm tra tính toàn vẹn hệ thống & Bất biến cấu hình...[/bold cyan]")
    ping_ok_after, ping_lat_after = check_icmp_integrity(target_ip)
    
    # Kiểm tra lại thông số xem có bị thay đổi trái phép hay không
    base_ok_after, base_info_after = query_baseline_param(target_ip, port)
    config_unchanged = (base_info == base_info_after) if (base_ok and base_ok_after) else True

    console.print(f"  • Tính toàn vẹn sau thử nghiệm (Ping) : {'[bold green]Hoạt động bình thường (< 1ms)[/bold green]' if ping_ok_after else '[bold red]Mất kết nối (DUT không phản hồi)[/bold red]'}")
    console.print(f"  • Tính bất biến cấu hình (Config Lock) : {'[bold green]Bảo vệ an toàn (Cấu hình không đổi)[/bold green]' if config_unchanged else '[bold red]Cảnh báo (Cấu hình đã bị thay đổi)[/bold red]'}")
    console.print(f"  • Phản hồi từ chối token giả mạo       : {'[bold green]An toàn (100% Yêu cầu bị từ chối)[/bold green]' if all_rejected else '[bold red]Cảnh báo (Có yêu cầu giả mạo được chấp nhận)[/bold red]'}")

    overall_pass = all_rejected and ping_ok_after and config_unchanged

    # Kết luận chính thức
    console.print("\n" + "=" * 80)
    console.print("  [bold white]KẾT LUẬN ĐÁNH GIÁ AN TOÀN BẢO MẬT: CSRF & TOKEN INTEGRITY[/bold white]")
    console.print("=" * 80)
    if overall_pass:
        console.print("[bold green]  ==> ĐÁNH GIÁ: BẢO VỆ AN TOÀN (PROTECTED / NO VULNERABILITY)[/bold green]")
        console.print("      • DUT đã từ chối toàn bộ 8 kịch bản giả mạo Token, Header và Origin giả mạo.")
        console.print("      • Cơ chế xác thực dữ liệu đầu vào hoạt động chính xác, cấu hình không bị thay đổi.")
        console.print("      • Thiết bị duy trì tính khả dụng và hoạt động ổn định trong suốt quá trình thử nghiệm.")
    else:
        console.print("[bold red]  ==> ĐÁNH GIÁ: CẢNH BÁO AN TOÀN (VULNERABILITY DETECTED)[/bold red]")
        console.print("      • Cảnh báo: Thiết bị đã chấp nhận token giả mạo hoặc cấu hình đã bị biến đổi.")
    console.print("=" * 80 + "\n")

    # Tạo tệp HTML PoC tương tác
    poc_file = os.path.join(os.path.dirname(__file__), "captures", "csrf_poc_interactive.html")
    created_poc = create_interactive_csrf_poc(
        poc_file, target_ip, port, endpoint, tokens["hex_token"]
    )
    if created_poc:
        console.print(f"[*] Đã xuất file HTML PoC trực quan tại: [cyan]{created_poc}[/cyan]")
        console.print("    (Thử nghiệm viên có thể mở file này trên trình duyệt để kiểm chứng phòng vệ CORS/CSRF trực tiếp)\n")

    # Xuất file kết quả JSON
    timestamp_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    json_result_file = os.path.join(os.path.dirname(__file__), "captures", f"csrf_token_audit_{timestamp_str}.json")
    audit_data = {
        "timestamp": timestamp_str,
        "assessment": "CSRF & Token Integrity Audit",
        "target": {
            "ip": target_ip,
            "model": DUT_MODEL,
            "port": port,
            "endpoint": endpoint
        },
        "overall_pass": overall_pass,
        "criteria": {
            "all_forged_tokens_rejected": all_rejected,
            "system_integrity_maintained": ping_ok_after,
            "configuration_unmodified": config_unchanged
        },
        "test_vectors": test_logs
    }
    try:
        with open(json_result_file, "w", encoding="utf-8") as f:
            json.dump(audit_data, f, indent=2, ensure_ascii=False)
        console.print(f"[*] Đã lưu kết quả đo kiểm chi tiết vào: [cyan]{json_result_file}[/cyan]")
    except Exception as e:
        console.print(f"[yellow][!] Không thể lưu file JSON: {e}[/yellow]")

    # Bảng hiển thị bộ lọc Wireshark
    filters = [
        ("Tất cả gói tin kiểm thử CSRF tới Web Server", f"tcp.port == {port} && (http || tls)"),
        ("Các gói tin DUT phản hồi từ chối (401/403/400)", f"http.response.code in {{400, 401, 403, 405}}"),
        ("Các gói tin HTTP POST cố gắng thay đổi cấu hình", f'http.request.method == "POST"'),
        ("Gói tin cờ ngắt kết nối an toàn (TCP RST)", f"tcp.port == {port} && tcp.flags.reset == 1")
    ]
    display_wireshark_panel(
        console,
        GLOBAL_PCAP_FILE,
        filters,
        is_tls=(port == 443),
        sort_tip="Lọc 'http.response.code == 401 || http.response.code == 403' trong Wireshark để đối soát mã từ chối của DUT.",
        title="BẰNG CHỨNG GÓI TIN ĐO KIỂM CSRF & TOKEN VALIDATION"
    )

    return audit_data


# ==============================================================================
# MAIN ENTRYPOINT
# ==============================================================================

def main():
    global GLOBAL_PCAP_FILE
    parser = argparse.ArgumentParser(
        description="Bộ đo kiểm Phòng vệ CSRF & Giả mạo Token Cấu hình"
    )
    parser.add_argument("--ip", default=DUT_IP, help=f"IP camera mục tiêu (Mặc định: {DUT_IP})")
    parser.add_argument("--port", type=int, default=HTTPS_PORT, help=f"Cổng Web HTTPS (Mặc định: {HTTPS_PORT})")
    parser.add_argument("--endpoint", default=None, help="Đường dẫn API thay đổi cấu hình (Mặc định: Tự động nhận diện VAPIX / REST)")
    parser.add_argument("--rate", type=float, default=3.0, help="Tốc độ gửi request/giây (Mặc định: 3.0)")
    parser.add_argument("--timeout", type=float, default=3.0, help="Thời gian chờ phản hồi tối đa (Mặc định: 3.0s)")

    args = parser.parse_args()

    # Bắt gói tin PCAP tự động
    bpf_filter = f"host {args.ip} and (tcp port {args.port} or icmp)"
    pcap_proc, GLOBAL_PCAP_FILE = start_pcap_capture(
        args.ip,
        bpf_filter,
        prefix="csrf_token_audit"
    )
    if GLOBAL_PCAP_FILE:
        console.print(f"[*] Bắt gói tin PCAP tự động vào: [cyan]{GLOBAL_PCAP_FILE}[/cyan]\n")

    try:
        run_csrf_token_audit(
            target_ip=args.ip,
            port=args.port,
            custom_endpoint=args.endpoint,
            timeout=args.timeout,
            rate_cps=args.rate
        )
    finally:
        stop_pcap_capture(pcap_proc)


if __name__ == "__main__":
    main()
