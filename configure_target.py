#!/usr/bin/env python3
"""
Baseline & Target Configuration Wizard for Camera Security Audit
Allows the user to input DUT info, test ports, and declared security baselines.
"""

import os
import json
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt

console = Console()
CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.json")

def load_config():
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}

def save_config(cfg):
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)

def configure_target_and_baseline():
    cfg = load_config()
    target = cfg.setdefault("target_camera", {})
    ports = cfg.setdefault("service_ports", {})
    baseline = cfg.setdefault("baseline_declaration", {})

    console.print(Panel("[bold cyan]THIẾT LẬP THÔNG TIN MỤC TIÊU & DANH SÁCH THAM CHIẾU (BASELINE)[/bold cyan]"))

    # 1. Target camera
    target["ip"] = Prompt.ask("1. IP Camera", default=target.get("ip", "192.168.1.100"))
    target["username"] = Prompt.ask("2. Tài khoản", default=target.get("username", "admin"))
    target["password"] = Prompt.ask("3. Mật khẩu", default=target.get("password", "Psitest135#"))

    # 2. Ports
    ports["https"] = int(Prompt.ask("4. Cổng HTTPS", default=str(ports.get("https", 443))))
    ports["rtsp"] = int(Prompt.ask("5. Cổng RTSP", default=str(ports.get("rtsp", 554))))

    # 3. Declared Baseline
    console.print("\n[bold yellow]--- THÔNG TIN THAM CHIẾU CẦN ĐỐI SOÁT ---[/bold yellow]")
    baseline["tls_version_expected"] = Prompt.ask(
        "6. Phiên bản TLS chuẩn (ví dụ TLSv1.3 hoặc TLSv1.2)",
        default=baseline.get("tls_version_expected", "TLSv1.3")
    )
    
    current_ciphers = ",".join(baseline.get("tls_ciphers_declared", ["TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"]))
    input_ciphers = Prompt.ask(
        "7. Danh sách Cipher suites được phép (ngăn cách bởi dấu phẩy)",
        default=current_ciphers
    )
    baseline["tls_ciphers_declared"] = [c.strip() for c in input_ciphers.split(",") if c.strip()]

    current_auth = ",".join(baseline.get("auth_value_mechanisms_declared", ["Digest-SHA256"]))
    input_auth = Prompt.ask(
        "8. Cơ chế giá trị xác thực cho phép (ví dụ: Digest-SHA256, Bearer)",
        default=current_auth
    )
    baseline["auth_value_mechanisms_declared"] = [a.strip() for a in input_auth.split(",") if a.strip()]

    save_config(cfg)
    console.print("[bold green]\n[OK] Đã lưu cấu hình đối soát thành công![/bold green]")

if __name__ == '__main__':
    configure_target_and_baseline()
