#!/usr/bin/env python3
"""
================================================================================
  BỘ ĐO KIỂM AN TOÀN BẢO MẬT & MẬT MÃ CAMERA IP (QCVN 11:2026/BCA)
  Giao diện App điều khiển hiện đại, đáp ứng (Modern Responsive TUI Application).
  
  Cấu trúc 6 phân hệ chuyên biệt:
  1. [MỤC TIÊU & MẠNG]        : Quản lý IP DUT, Auto-Link đa subnet, WS-Discovery, Dò cổng.
  2. [2.1.3: MẬT MÃ & XÁC THỰC]: SOGIS ACM, TLS 1.0-1.3, Digest vs Basic, SNMPv3, 11 ComMech.
  3. [2.1.5: PHÒNG VỆ VÉT CẠN]: Điều tốc 4 conn/s, Khóa ONVIF SOAP, RTSP/RTSPS, SSH, Web.
  4. [2.4: BỀ MẶT HỆ THỐNG]   : Tham số nhạy cảm, Path Traversal, Access Control, Wireshark.
  5. [BẰNG CHỨNG & BÁO CÁO]   : Danh mục PCAP, Xem trực tiếp báo cáo Markdown đối soát.
  6. [NHẬT KÝ THỰC THI]       : Bảng điều khiển live streaming output dòng lệnh ANSI, dừng an toàn.

  Author: Merlin / Antigravity
================================================================================
"""

import os
import sys
import json
import asyncio
import subprocess
from datetime import datetime
from typing import Optional, List, Dict, Any

from rich.text import Text

from textual.app import App, ComposeResult
from textual import work
from textual.events import Resize
from textual.containers import Container, Horizontal, Vertical, VerticalScroll, Grid
from textual.widgets import (
    Header, Footer, Static, Button, TabbedContent, TabPane,
    Label, Input, DataTable, RichLog, Markdown
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(BASE_DIR)
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")

EVIDENCE_COMMECH_DIR = os.path.join(PROJECT_DIR, "AXIS Q1806-LE", "Mẫu lưu bằng chứng", "ComMech")
if not os.path.isdir(EVIDENCE_COMMECH_DIR):
    EVIDENCE_COMMECH_DIR = os.path.join(PROJECT_DIR, "Mẫu lưu bằng chứng", "ComMech")
if not os.path.isdir(EVIDENCE_COMMECH_DIR):
    EVIDENCE_COMMECH_DIR = os.path.join(BASE_DIR, "captures", "evidence", "ComMech")

EVIDENCE_AUTHMECH_DIR = os.path.join(PROJECT_DIR, "AXIS Q1806-LE", "Mẫu lưu bằng chứng", "AuthMech")
if not os.path.isdir(EVIDENCE_AUTHMECH_DIR):
    EVIDENCE_AUTHMECH_DIR = os.path.join(PROJECT_DIR, "Mẫu lưu bằng chứng", "AuthMech")
if not os.path.isdir(EVIDENCE_AUTHMECH_DIR):
    EVIDENCE_AUTHMECH_DIR = os.path.join(BASE_DIR, "captures", "evidence", "AuthMech")

CAPTURES_DIR = os.path.join(BASE_DIR, "captures")
os.makedirs(CAPTURES_DIR, exist_ok=True)

# Tự động nhận diện môi trường ảo .venv
VENV_PYTHON = os.path.join(BASE_DIR, ".venv", "bin", "python")
if not os.path.isfile(VENV_PYTHON):
    VENV_PYTHON = os.path.join(PROJECT_DIR, ".venv", "bin", "python")
if sys.platform == "win32":
    win_py = os.path.join(BASE_DIR, ".venv", "Scripts", "python.exe")
    if not os.path.isfile(win_py):
        win_py = os.path.join(PROJECT_DIR, ".venv", "Scripts", "python.exe")
    if os.path.isfile(win_py):
        VENV_PYTHON = win_py
if not os.path.isfile(VENV_PYTHON):
    VENV_PYTHON = sys.executable


def load_config() -> Dict[str, Any]:
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def save_config(cfg: Dict[str, Any]) -> bool:
    try:
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2)
        return True
    except Exception:
        return False


class ToolkitApp(App):
    """Ứng dụng đo kiểm an toàn bảo mật camera IP chuyên nghiệp & đáp ứng."""

    TITLE = "CUMERA - BỘ CÔNG CỤ ĐO KIỂM AN TOÀN BẢO MẬT & MẬT MÃ CAMERA IP (QCVN 11:2026/BCA)"
    SUB_TITLE = "Tiêu chuẩn QCVN 11:2026/BCA & ETSI EN 303 645 | Author: Merlin"

    CSS = """
    Screen {
        background: #080b14;
        color: #f1f5f9;
    }

    #top_ribbon {
        height: 3;
        background: #0d1527;
        border-bottom: heavy #0284c7;
        padding: 0 2;
    }

    #ribbon_dut_info {
        width: 1fr;
        content-align: left middle;
    }

    #ribbon_daemon_info {
        width: auto;
        content-align: right middle;
    }

    Tabs {
        background: #090e1c;
        border-bottom: solid #1e293b;
    }

    Tab {
        padding: 0 2;
        color: #94a3b8;
    }

    Tab:hover {
        color: #38bdf8;
        background: #0f1d38;
    }

    Tab.-active {
        color: #ffffff;
        background: #0369a1;
        text-style: bold;
        border-bottom: heavy #38bdf8;
    }

    TabbedContent {
        height: 1fr;
    }

    TabPane {
        padding: 1 2;
    }

    .card {
        background: #0d1527;
        border: round #1e293b;
        border-title-color: #38bdf8;
        border-title-style: bold;
        border-subtitle-color: #64748b;
        padding: 1 2;
        margin-bottom: 1;
    }

    .card:hover {
        border: round #38bdf8;
    }

    .card-highlight {
        background: #0a1b38;
        border: round #0284c7;
        border-title-color: #38bdf8;
        border-title-style: bold;
        border-subtitle-color: #94a3b8;
        padding: 1 2;
        margin-bottom: 1;
    }

    .card-warn {
        background: #241407;
        border: round #d97706;
        border-title-color: #fbbf24;
        border-title-style: bold;
        border-subtitle-color: #94a3b8;
        padding: 1 2;
        margin-bottom: 1;
    }

    .card-success {
        background: #052418;
        border: round #059669;
        border-title-color: #34d399;
        border-title-style: bold;
        border-subtitle-color: #94a3b8;
        padding: 1 2;
        margin-bottom: 1;
    }

    .desc-text {
        color: #94a3b8;
        margin-bottom: 1;
    }

    .info-label {
        color: #cbd5e1;
        text-style: bold;
    }

    /* RESPONSIVE GRIDS */
    .grid-1 {
        layout: grid;
        grid-size: 1;
        grid-gutter: 1;
        width: 100%;
    }

    .grid-2 {
        layout: grid;
        grid-size: 2;
        grid-gutter: 1;
        width: 100%;
    }

    .grid-3 {
        layout: grid;
        grid-size: 3;
        grid-gutter: 1;
        width: 100%;
    }

    .grid-4 {
        layout: grid;
        grid-size: 4;
        grid-gutter: 1;
        width: 100%;
    }

    .grid-6 {
        layout: grid;
        grid-size: 6;
        grid-gutter: 1;
        width: 100%;
    }

    /* RESPONSIVE BREAKPOINT BEHAVIOR */
    .-narrow .grid-2, .-narrow .grid-3, .-narrow .grid-4, .-narrow .grid-6 {
        grid-size: 1;
    }

    .-medium .grid-3, .-medium .grid-4 {
        grid-size: 2;
    }

    .-medium .grid-6 {
        grid-size: 3;
    }

    .-wide .grid-3 {
        grid-size: 3;
    }

    .-wide .grid-4 {
        grid-size: 4;
    }

    .-wide .grid-6 {
        grid-size: 6;
    }

    Button {
        width: 100%;
        height: 3;
        background: #1e293b;
        color: #f1f5f9;
        border: round #334155;
        text-style: bold;
        padding: 0 1;
    }

    Button:hover {
        background: #0284c7;
        color: #ffffff;
        border: round #38bdf8;
    }

    Button:focus {
        border: heavy #00e5ff;
    }

    Button.btn-primary {
        background: #0369a1;
        border: round #38bdf8;
        color: #ffffff;
    }

    Button.btn-primary:hover {
        background: #0284c7;
    }

    Button.btn-success {
        background: #065f46;
        border: round #10b981;
        color: #ffffff;
    }

    Button.btn-success:hover {
        background: #059669;
    }

    Button.btn-danger {
        background: #991b1b;
        border: round #ef4444;
        color: #ffffff;
    }

    Button.btn-danger:hover {
        background: #dc2626;
    }

    Button.btn-warn {
        background: #92400e;
        border: round #f59e0b;
        color: #ffffff;
    }

    Button.btn-warn:hover {
        background: #b45309;
    }

    #log_view {
        background: #030611;
        color: #f1f5f9;
        border: round #1e293b;
        height: 1fr;
        padding: 1;
    }

    #status_banner {
        background: #0f1d38;
        padding: 1;
        margin-bottom: 1;
        border: round #0284c7;
        height: auto;
    }

    DataTable {
        background: #0b1120;
        border: round #1e293b;
        height: 14;
        margin-bottom: 1;
    }

    #report_markdown_view {
        background: #090e1c;
        border: round #1e293b;
        padding: 1 2;
        height: 24;
    }

    Input {
        background: #0b1120;
        border: round #334155;
        color: #38bdf8;
        height: 3;
        padding: 0 1;
    }

    Input:focus {
        border: round #38bdf8;
    }
    """

    BINDINGS = [
        ("q", "quit", "Thoát ứng dụng"),
        ("1", "switch_tab('tab_target')", "1. Mục tiêu"),
        ("2", "switch_tab('tab_crypto')", "2. Mật mã 2.1.3"),
        ("3", "switch_tab('tab_brute')", "3. Vét cạn 2.1.5"),
        ("4", "switch_tab('tab_surface')", "4. Bề mặt 2.4"),
        ("5", "switch_tab('tab_evidence')", "5. Bằng chứng"),
        ("6", "switch_tab('tab_console')", "6. Nhật ký chạy"),
        ("x", "stop_task", "Dừng tiến trình"),
        ("escape", "back_to_previous_tab", "Quay lại"),
    ]

    def __init__(self):
        super().__init__()
        self.current_process: Optional[asyncio.subprocess.Process] = None
        self.task_running = False
        self.previous_tab = "tab_target"

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)

        with Container(id="top_ribbon"):
            with Horizontal():
                yield Static("DUT: 192.168.20.38 (AXIS Q1806-LE) | Auth: admin | RTSPS: 322", id="ribbon_dut_info")
                yield Static("Receiver Daemon: [ONLINE]", id="ribbon_daemon_info")

        with TabbedContent(id="main_tabs"):
            # TAB 1: MỤC TIÊU & MẠNG
            with TabPane("1. Mục tiêu & Mạng", id="tab_target"):
                with VerticalScroll():
                    with Container(classes="card-highlight") as c1:
                        c1.border_title = " [THÔNG TIN THIẾT BỊ MỤC TIÊU - DUT] "
                        c1.border_subtitle = " AXIS Q1806-LE / Subnet 20 "
                        yield Static(id="target_summary_text", classes="desc-text")
                        with Grid(classes="grid-4"):
                            yield Button("Auto-Link Đa Subnet", id="btn_autolink", classes="btn-success")
                            yield Button("Quét WS-Discovery (3702)", id="btn_discovery", classes="btn-primary")
                            yield Button("Dò quét cổng dịch vụ", id="btn_scan_services")
                            yield Button("Kiểm tra Ping & Kết nối", id="btn_ping_check")

                    with Container(classes="card") as c2:
                        c2.border_title = " [CẬP NHẬT CẤU HÌNH CAMERA MỤC TIÊU] "
                        with Grid(classes="grid-4"):
                            yield Input(placeholder="Địa chỉ IP (192.168.20.38)", id="input_cam_ip")
                            yield Input(placeholder="Tài khoản (admin)", id="input_cam_user")
                            yield Input(placeholder="Mật khẩu", password=True, id="input_cam_pass")
                            yield Button("Lưu cấu hình", id="btn_save_config", classes="btn-primary")

                    with Container(classes="card") as c3:
                        c3.border_title = " [MÁY CHỦ THU NHẬN CLIENT NGẦM - RECEIVER DAEMON] "
                        c3.border_subtitle = " Ports: 21, 22, 25, 465, 587, 8088, 8443 "
                        yield Static(id="host_network_summary", classes="desc-text")
                        with Grid(classes="grid-2"):
                            yield Button("Khởi động lại Receiver Daemon", id="btn_restart_daemon")
                            yield Button("Mở All Receivers tương tác", id="btn_open_all_receivers")

            # TAB 2: ĐIỀU KHOẢN 2.1.3 - MẬT MÃ ĐƯỜNG TRUYỀN & GIÁ TRỊ XÁC THỰC
            with TabPane("2. Mật mã & Xác thực (2.1.3)", id="tab_crypto"):
                with VerticalScroll():
                    with Container(classes="card-highlight") as c_am:
                        c_am.border_title = " [TOOL 21: ĐO KIỂM 4 CƠ CHẾ XÁC THỰC (AUTHMECH 1 - 4)] "
                        c_am.border_subtitle = " Bắt gói tin PCAP, trích xuất ciphersuite, Digest SHA-256 & WS-Security "
                        yield Static("Đối soát toàn diện AuthMech-1 đến AuthMech-4 theo bảng IXIT 1, xuất bằng chứng PCAP & chỉ dẫn chụp ảnh Wireshark.", classes="desc-text")
                        with Grid(classes="grid-1"):
                            yield Button("ĐO KIỂM TOÀN BỘ 4 CƠ CHẾ XÁC THỰC (1-CLICK)", id="btn_authmech_all", classes="btn-primary")
                            yield Button("BÓC TÁCH TOÀN BỘ CIPHERSUITE & KEX (NMAP ENUM)", id="btn_authmech_enum", classes="btn-success")
                        with Grid(classes="grid-4"):
                            yield Button("AuthMech-1: Web HTTPS (443)", id="btn_authmech_1")
                            yield Button("AuthMech-2: SSH (22)", id="btn_authmech_2")
                            yield Button("AuthMech-3: RTSPS (322)", id="btn_authmech_3")
                            yield Button("AuthMech-4: ONVIF (443)", id="btn_authmech_4")

                    with Container(classes="card-highlight") as c_cm:
                        c_cm.border_title = " [TOOL 17: ĐO KIỂM 11 PHƯƠNG THỨC TRUYỀN THÔNG (ĐỘC LẬP IXIT)] "
                        c_cm.border_subtitle = " Tấn công hạ cấp TLS/SSH & Xuất 11 PCAP "
                        yield Static("Đo kiểm trực tiếp 11 phương thức mạng tiêu chuẩn (Web, SSH, ONVIF, SNMP, MQTT, Syslog, SMB, SMTP, SFTP, RTSPS, Cloud), độc lập khai báo IXIT.", classes="desc-text")
                        with Grid(classes="grid-1"):
                            yield Button("ĐO KIỂM TOÀN BỘ 11 PHƯƠNG THỨC TRUYỀN THÔNG (1-CLICK)", id="btn_commech_all", classes="btn-primary")
                        
                        with Grid(classes="grid-4"):
                            yield Button("Web HTTPS (443)", id="btn_commech_1")
                            yield Button("SSH (22)", id="btn_commech_2")
                            yield Button("ONVIF (443)", id="btn_commech_3")
                            yield Button("SNMPv3 (161)", id="btn_commech_4")
                        with Grid(classes="grid-4"):
                            yield Button("MQTT Client (8883)", id="btn_commech_5")
                            yield Button("Remote Syslog (6514)", id="btn_commech_6")
                            yield Button("SMBv3 NAS (445)", id="btn_commech_7")
                            yield Button("SMTP Email (587)", id="btn_commech_8")
                        with Grid(classes="grid-3"):
                            yield Button("SFTP Client (22)", id="btn_commech_9")
                            yield Button("RTSPS (322)", id="btn_commech_10")
                            yield Button("Cloud / O3C (443)", id="btn_commech_11")

                    with Container(classes="card") as c_sub:
                        c_sub.border_title = " [CÁC BỘ ĐO KIỂM THÀNH PHẦN CHUYÊN SÂU] "
                        with Grid(classes="grid-3"):
                            yield Button("Tool 1: Quét TLS Web (443)", id="btn_tool1_tls_443")
                            yield Button("Tool 1: Quét TLS RTSPS (322)", id="btn_tool1_tls_322")
                            yield Button("Tool 2: Phân tích Giao thức rõ", id="btn_tool2_clear")
                        with Grid(classes="grid-2"):
                            yield Button("Tool 4: Ma trận mật mã SNMPv3", id="btn_tool5_snmp")
                            yield Button("Tool 12: Bắt tay RTSP Auth & SDP 200 OK", id="btn_tool12_rtsp_auth")

                    with Container(classes="card") as c_rec:
                        c_rec.border_title = " [BÓC TÁCH KẾT NỐI CLIENT TỪ CAMERA] "
                        c_rec.border_subtitle = " Máy chủ ngầm phân tích một chạm "
                        with Grid(classes="grid-4"):
                            yield Button("SFTP / SSH (Cổng 22)", id="btn_recv_sftp")
                            yield Button("Plain FTP rõ (Cổng 21)", id="btn_recv_ftp")
                            yield Button("SMTP Email TLS (25/465/587)", id="btn_recv_smtp")
                            yield Button("Alarm Webhook (8088/8443)", id="btn_recv_alarm")

            # TAB 3: ĐIỀU KHOẢN 2.1.5 - PHÒNG VỆ VÉT CẠN XÁC THỰC
            with TabPane("3. Phòng vệ Vét cạn (2.1.5)", id="tab_brute"):
                with VerticalScroll():
                    with Container(classes="card-warn") as c_onvif:
                        c_onvif.border_title = " [TOOL 11: PHÒNG VỆ VÉT CẠN ONVIF SOAP (WS-SECURITY)] "
                        c_onvif.border_subtitle = " Điều tốc chuẩn xác 4 conn/s (Firewall Limit: 3 conn/s) "
                        yield Static("Gửi các yêu cầu xác thực WS-Security SHA-1/SHA-256, kiểm tra ngưỡng khóa 10 lần sai và reset bộ đếm.", classes="desc-text")
                        with Grid(classes="grid-4"):
                            yield Button("Mode 1: Reset bộ đếm ONVIF", id="btn_onvif_reset", classes="btn-success")
                            yield Button("Mode 2: Kích hoạt Khóa ONVIF", id="btn_onvif_lockout", classes="btn-danger")
                            yield Button("Mode 3: Vét cạn Từ điển", id="btn_onvif_dict")
                            yield Button("Mode 4: Burst kiểm chứng Firewall", id="btn_onvif_burst", classes="btn-primary")

                    with Container(classes="card") as c_rtsp:
                        c_rtsp.border_title = " [TOOL 10: PHÒNG VỆ VÉT CẠN RTSP / RTSPS] "
                        c_rtsp.border_subtitle = " Cổng TLS 322 & Cổng rõ 554 "
                        with Grid(classes="grid-3"):
                            yield Button("Khóa RTSPS bảo mật (Cổng 322)", id="btn_rtsp_lockout_322", classes="btn-primary")
                            yield Button("Khóa RTSP truyền rõ (Cổng 554)", id="btn_rtsp_lockout_554")
                            yield Button("Đo hồ sơ độ trễ (Rate Limit)", id="btn_tool9_latency")

                    with Container(classes="card") as c_os:
                        c_os.border_title = " [DỊCH VỤ HỆ ĐIỀU HÀNH (SSH & WEB HTTPS)] "
                        with Grid(classes="grid-2"):
                            yield Button("Tool 15: Khóa SSH (Cổng 22 - 10 lần/30s)", id="btn_ssh_lockout")
                            yield Button("Tool 16: Khóa Web HTTPS (Cổng 443 - 6 lần/30s)", id="btn_web_lockout")

            # TAB 4: ĐIỀU KHOẢN 2.4 & MASTER AUDIT
            with TabPane("4. Bề mặt & Tổng hợp (2.4)", id="tab_surface"):
                with VerticalScroll():
                    with Container(classes="card-success") as c_mast:
                        c_mast.border_title = " [TOOL 8: MASTER SECURITY AUDIT 1-CLICK] "
                        c_mast.border_subtitle = " Tự động toàn diện & Xuất báo cáo Markdown/JSON "
                        yield Static("Chạy tuần tự toàn bộ các bài đo kiểm chính trong một lần bấm, tự động trích xuất bảng Wireshark.", classes="desc-text")
                        with Grid(classes="grid-1"):
                            yield Button("KHỞI CHẠY MASTER AUDIT TOÀN DIỆN (TẤT CẢ TESTCASE)", id="btn_master_audit", classes="btn-success")

                    with Container(classes="card") as c_sec:
                        c_sec.border_title = " [TOOL 13: ĐO KIỂM THAM SỐ AN TOÀN NHẠY CẢM (ĐIỀU 2.4/2.6)] "
                        with Grid(classes="grid-1"):
                            yield Button("Chạy đo kiểm Tham số an toàn bề mặt hệ thống (Tool 13)", id="btn_tool13_secparams", classes="btn-primary")

                    with Container(classes="card") as c_wire:
                        c_wire.border_title = " [TOOL 14: ĐỐI SOÁT & GIẢI MÃ WIRESHARK (RTSPS 322 / 554)] "
                        with Grid(classes="grid-1"):
                            yield Button("Chạy đối soát Wireshark & Tự nạp sslkeys.log (Tool 14)", id="btn_tool14_wireshark")

                    with Container(classes="card") as c_fuzz:
                        c_fuzz.border_title = " [TOOL 18/19/22: XÁC THỰC ĐẦU VÀO, FUZZER, CSRF & SQLI/XSS (CLAUSE 3.10.1.3)] "
                        with Grid(classes="grid-4"):
                            yield Button("Fuzzing luồng RTSP (Tool 18)", id="btn_tool18_fuzz_rtsp", classes="btn-primary")
                            yield Button("Quét bề mặt API (Tool 18)", id="btn_tool18_scan_api")
                            yield Button("CSRF & Forged Token (Tool 19)", id="btn_tool19_csrf_audit", classes="btn-success")
                            yield Button("Login: SQLi & XSS (Tool 22)", id="btn_tool22_login_audit", classes="btn-primary")

            # TAB 5: BẰNG CHỨNG & BÁO CÁO
            with TabPane("5. Bằng chứng & Báo cáo", id="tab_evidence"):
                with VerticalScroll():
                    with Container(classes="card-highlight") as c_ev_top:
                        c_ev_top.border_title = " [QUẢN LÝ BẰNG CHỨNG & ĐỐI SOÁT] "
                        with Grid(classes="grid-4"):
                            yield Button("Tải lại danh sách tệp", id="btn_refresh_evidence")
                            yield Button("Xem Báo cáo AuthMech", id="btn_view_report_authmech", classes="btn-primary")
                            yield Button("Xem Báo cáo ComMech", id="btn_view_report_commech", classes="btn-primary")
                            yield Button("Xem Báo cáo Master", id="btn_view_report_master", classes="btn-primary")
                            yield Button("Mở thư mục Bằng chứng", id="btn_open_evidence_folder", classes="btn-success")

                    with Container(classes="card") as c_tbl:
                        c_tbl.border_title = " [DANH MỤC FILE PCAP & BẰNG CHỨNG] (Click vào dòng để xem chi tiết) "
                        yield DataTable(id="evidence_table")

                    with Container(classes="card") as c_rep:
                        c_rep.border_title = " [TRÌNH XEM BÁO CÁO KỸ THUẬT CHI TIẾT] "
                        yield Markdown(id="report_markdown_view")

            # TAB 6: NHẬT KÝ THỰC THI (CONSOLE LOG)
            with TabPane("6. Bảng điều khiển & Nhật ký", id="tab_console"):
                with Vertical():
                    with Container(id="status_banner"):
                        with Horizontal():
                            yield Static("TRẠNG THÁI: [IDLE] Sẵn sàng", id="exec_status_text")
                            yield Button("DỪNG CHẠY (ABORT)", id="btn_stop_process", classes="btn-danger")
                            yield Button("Xóa màn hình log", id="btn_clear_log")
                            yield Button("Quay lại bài đo", id="btn_back_to_tool")

                    yield RichLog(id="log_view", highlight=False, markup=True)

        yield Footer()

    def update_responsive_classes(self, width: int) -> None:
        """Cập nhật các lớp CSS đáp ứng theo độ rộng thực tế của terminal."""
        if hasattr(self, "screen") and self.screen:
            self.screen.set_class(width < 110, "-narrow")
            self.screen.set_class(110 <= width < 155, "-medium")
            self.screen.set_class(width >= 155, "-wide")

    def on_resize(self, event: Resize) -> None:
        """Sự kiện thay đổi kích thước cửa sổ Kitty / Terminal."""
        self.update_responsive_classes(event.size.width)

    def on_mount(self) -> None:
        """Khởi tạo trạng thái giao diện ban đầu."""
        self.update_responsive_classes(self.size.width)
        self.update_target_info()
        self.init_evidence_table()
        self.refresh_evidence_files()
        self.load_default_report()

    def update_target_info(self) -> None:
        """Cập nhật thông tin camera và máy tính kiểm định lên thẻ hiển thị."""
        cfg = load_config()
        t_cam = cfg.get("target_camera", {})
        ip = t_cam.get("ip", "Chưa đặt")
        model = t_cam.get("model", "AXIS Q1806-LE")
        fw = t_cam.get("firmware", "13.1.23")
        user = t_cam.get("username", "admin")

        text = (
            f"• Thiết bị mục tiêu: [bold white]{ip}[/bold white] ({model}) | Firmware: {fw}\n"
            f"• Tài khoản quản trị: [bold yellow]{user}[/bold yellow] | Cổng RTSPS: 322 | Cổng HTTPS: 443 | SSH: 22"
        )
        self.query_one("#target_summary_text", Static).update(text)
        self.query_one("#ribbon_dut_info", Static).update(f"DUT: [bold cyan]{ip}[/bold cyan] ({model}) | User: [bold yellow]{user}[/bold yellow] | RTSPS: 322")

        # Điền vào input
        self.query_one("#input_cam_ip", Input).value = ip
        self.query_one("#input_cam_user", Input).value = user

        # Cập nhật thông tin host network
        try:
            import receiver_daemon as rd
            active_ips = rd.get_active_host_ips()
            primary_ip = active_ips[0][0] if active_ips else "127.0.0.1"
            daemon_ok = rd.is_daemon_running()
            badge = "[bold green][ONLINE][/bold green]" if daemon_ok else "[bold yellow][OFFLINE][/bold yellow]"

            host_text = (
                f"• IP Card mạng kiểm tra (Điền trên camera): [bold yellow]{primary_ip}[/bold yellow]\n"
                f"• Trạng thái máy chủ thu nhận Client: {badge} (Mở sẵn các cổng 21, 22, 25, 465, 587, 8088, 8443)"
            )
            self.query_one("#host_network_summary", Static).update(host_text)
            self.query_one("#ribbon_daemon_info", Static).update(f"Receiver Daemon: {badge} ({primary_ip})")
        except Exception:
            pass

    def init_evidence_table(self) -> None:
        """Thiết lập cấu trúc cột cho bảng danh mục bằng chứng."""
        table = self.query_one("#evidence_table", DataTable)
        table.cursor_type = "row"
        table.add_columns("Mã", "Tên tệp tin bằng chứng", "Loại", "Kích thước", "Thời điểm tạo")

    def refresh_evidence_files(self) -> None:
        """Quét và liệt kê toàn bộ file PCAP và báo cáo Markdown."""
        table = self.query_one("#evidence_table", DataTable)
        table.clear()

        dirs_to_scan = [
            (EVIDENCE_COMMECH_DIR, "ComMech"),
            (CAPTURES_DIR, "Captures")
        ]

        row_idx = 1
        for d_path, cat in dirs_to_scan:
            if os.path.exists(d_path):
                for fname in sorted(os.listdir(d_path)):
                    if fname.endswith((".pcap", ".pcapng", ".md", ".json")):
                        f_full = os.path.join(d_path, fname)
                        st = os.stat(f_full)
                        sz_str = f"{st.st_size / 1024:.1f} KB" if st.st_size >= 1024 else f"{st.st_size} B"
                        mtime = datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
                        f_type = "PCAP Gói tin" if fname.endswith((".pcap", ".pcapng")) else ("Báo cáo MD" if fname.endswith(".md") else "Dữ liệu JSON")
                        table.add_row(f"{cat}-{row_idx}", fname, f_type, sz_str, mtime, key=f_full)
                        row_idx += 1

    def load_default_report(self) -> None:
        """Tải báo cáo mặc định vào trình xem Markdown."""
        rep_path = os.path.join(EVIDENCE_COMMECH_DIR, "commech_audit_report.md")
        if os.path.exists(rep_path):
            try:
                with open(rep_path, "r", encoding="utf-8") as f:
                    content = f.read()
                self.query_one("#report_markdown_view", Markdown).update(content)
            except Exception:
                pass

    def action_switch_tab(self, tab_id: str) -> None:
        """Chuyển đổi tab thông qua phím tắt."""
        tabbed = self.query_one("#main_tabs", TabbedContent)
        self.previous_tab = tabbed.active
        tabbed.active = tab_id

    def action_back_to_previous_tab(self) -> None:
        """Quay lại tab trước đó."""
        tabbed = self.query_one("#main_tabs", TabbedContent)
        tabbed.active = self.previous_tab

    def action_stop_task(self) -> None:
        """Dừng tiến trình đang thực thi."""
        if self.current_process and self.task_running:
            try:
                self.current_process.kill()
                self.query_one("#log_view", RichLog).write("[bold red][!] ĐÃ HỦY TIẾN TRÌNH THEO YÊU CẦU NGƯỜI DÙNG[/bold red]")
            except Exception:
                pass

    @work(exclusive=True)
    async def run_audit_command(self, cmd: List[str], tool_name: str = "") -> None:
        """Khởi chạy công cụ đo kiểm và truyền trực tiếp output vào bảng nhật ký."""
        if self.task_running:
            self.query_one("#log_view", RichLog).write("[yellow][!] Một tác vụ khác đang chạy. Vui lòng dừng hoặc chờ tác vụ hoàn thành.[/yellow]")
            return

        self.task_running = True
        tabbed = self.query_one("#main_tabs", TabbedContent)
        self.previous_tab = tabbed.active
        tabbed.active = "tab_console"

        log_view = self.query_one("#log_view", RichLog)
        status_banner = self.query_one("#exec_status_text", Static)

        status_banner.update(f"TRẠNG THÁI: [bold yellow][ĐANG CHẠY...][/bold yellow] {tool_name}")
        log_view.write(f"\n[bold cyan]================================================================================[/bold cyan]")
        log_view.write(f"[bold cyan]>> BẮT ĐẦU: {tool_name}[/bold cyan]")
        log_view.write(f"[dim]Lệnh thực thi: {' '.join(cmd)}[/dim]")
        log_view.write(f"[dim]Thời điểm: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/dim]")
        log_view.write(f"[bold cyan]================================================================================[/bold cyan]\n")

        has_euid = hasattr(os, "geteuid")
        needs_root = any(s in cmd[1] if len(cmd) > 1 else False for s in ["tool17", "tool3", "tool4", "tool_all_receivers", "cam_auto_link"]) and has_euid and os.geteuid() != 0
        final_cmd = ["sudo"] + cmd if needs_root else cmd

        try:
            self.current_process = await asyncio.create_subprocess_exec(
                *final_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                cwd=BASE_DIR,
                env={**os.environ, "PYTHONUNBUFFERED": "1"}
            )

            while True:
                line = await self.current_process.stdout.readline()
                if not line:
                    break
                decoded = line.decode("utf-8", errors="replace").rstrip()
                log_view.write(Text.from_ansi(decoded))

            rc = await self.current_process.wait()
            if rc == 0:
                status_banner.update("TRẠNG THÁI: [bold green][HOÀN THÀNH - THÀNH CÔNG][/bold green]")
                log_view.write("\n[bold green][PASS] BÀI ĐO KIỂM HOÀN TẤT VỚI KẾT QUẢ ĐẠT YÊU CẦU![/bold green]\n")
            else:
                status_banner.update(f"TRẠNG THÁI: [bold red][KẾT THÚC VỚI MÃ LỖI {rc}][/bold red]")
                log_view.write(f"\n[bold red][!] Tiến trình kết thúc với mã lỗi: {rc}[/bold red]\n")
        except Exception as e:
            status_banner.update("TRẠNG THÁI: [bold red][LỖI THỰC THI][/bold red]")
            log_view.write(f"\n[bold red][-] Lỗi ngoại lệ trong quá trình chạy: {e}[/bold red]\n")
        finally:
            self.task_running = False
            self.current_process = None
            self.refresh_evidence_files()

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """Xử lý sự kiện khi người dùng click chọn dòng trong bảng bằng chứng."""
        f_path = str(event.row_key.value) if hasattr(event.row_key, "value") else str(event.row_key)
        if os.path.exists(f_path):
            if f_path.endswith(".md"):
                try:
                    with open(f_path, "r", encoding="utf-8") as f:
                        content = f.read()
                    self.query_one("#report_markdown_view", Markdown).update(content)
                except Exception:
                    pass
            elif f_path.endswith((".pcap", ".pcapng")):
                # Hiển thị thông tin đối soát Wireshark
                pcap_name = os.path.basename(f_path)
                wireshark_info = f"""
# BẰNG CHỨNG GÓI TIN WIRESHARK: `{pcap_name}`

- **Đường dẫn tệp tin**: `{f_path}`
- **Kích thước**: `{os.path.getsize(f_path)} bytes`
- **Lệnh mở trực tiếp trong Wireshark**:
  ```bash
  wireshark -r "{f_path}"
  ```
- **Nạp Session Key giải mã TLS 1.3**:
  Vào `Edit` -> `Preferences` -> `Protocols` -> `TLS` -> nạp file `captures/sslkeys.log` (hoặc đường dẫn tuyệt đối tại máy đo).
                """
                self.query_one("#report_markdown_view", Markdown).update(wireshark_info)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Xử lý sự kiện bấm nút cho toàn bộ các công cụ."""
        btn_id = event.button.id
        cfg = load_config()
        ip = cfg.get("target_camera", {}).get("ip", "192.168.20.38")
        rtsps_p = str(cfg.get("service_ports", {}).get("rtsps_tls", 322))

        # Điều khiển chung
        if btn_id == "btn_clear_log":
            self.query_one("#log_view", RichLog).clear()
            return
        elif btn_id == "btn_stop_process":
            self.action_stop_task()
            return
        elif btn_id == "btn_back_to_tool":
            self.action_back_to_previous_tab()
            return
        elif btn_id == "btn_refresh_evidence":
            self.refresh_evidence_files()
            return
        elif btn_id == "btn_open_evidence_folder":
            subprocess.Popen(["xdg-open", EVIDENCE_COMMECH_DIR], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return
        elif btn_id == "btn_view_report_authmech":
            rep_path = os.path.join(EVIDENCE_AUTHMECH_DIR, "authmech_audit_report.md")
            if not os.path.exists(rep_path):
                rep_path = os.path.join(BASE_DIR, "authmech_audit_report.md")
            if os.path.exists(rep_path):
                with open(rep_path, "r", encoding="utf-8") as f:
                    self.query_one("#report_markdown_view", Markdown).update(f.read())
            return
        elif btn_id == "btn_view_report_commech":
            rep_path = os.path.join(EVIDENCE_COMMECH_DIR, "commech_audit_report.md")
            if os.path.exists(rep_path):
                with open(rep_path, "r", encoding="utf-8") as f:
                    self.query_one("#report_markdown_view", Markdown).update(f.read())
            return
        elif btn_id == "btn_view_report_master":
            rep_path = os.path.join(BASE_DIR, "camera_security_audit_report.md")
            if os.path.exists(rep_path):
                with open(rep_path, "r", encoding="utf-8") as f:
                    self.query_one("#report_markdown_view", Markdown).update(f.read())
            return
        elif btn_id == "btn_save_config":
            new_ip = self.query_one("#input_cam_ip", Input).value.strip()
            new_user = self.query_one("#input_cam_user", Input).value.strip() or "admin"
            new_pass = self.query_one("#input_cam_pass", Input).value.strip()
            if new_ip:
                cfg.setdefault("target_camera", {})
                cfg["target_camera"]["ip"] = new_ip
                cfg["target_camera"]["username"] = new_user
                if new_pass:
                    cfg["target_camera"]["password"] = new_pass
                save_config(cfg)
                self.update_target_info()
                self.query_one("#log_view", RichLog).write(f"[bold green][OK] Đã cập nhật mục tiêu: {new_ip} ({new_user})[/bold green]")
            return

        # Nhóm Mục tiêu & Mạng
        if btn_id == "btn_autolink":
            self.run_audit_command([VENV_PYTHON, "cam_auto_link.py", "--once"], "Tự động nhận diện Auto-Link")
        elif btn_id == "btn_discovery":
            self.run_audit_command([VENV_PYTHON, "camera_manager.py"], "Dò quét Camera WS-Discovery")
        elif btn_id == "btn_scan_services":
            self.run_audit_command([VENV_PYTHON, "service_discovery.py", ip], "Dò quét cổng dịch vụ mạng")
        elif btn_id == "btn_ping_check":
            self.run_audit_command(["ping", "-c", "4", ip], f"Kiểm tra Ping đến Camera {ip}")
        elif btn_id == "btn_restart_daemon":
            self.run_audit_command([VENV_PYTHON, "receiver_daemon.py", "--kill-daemon"], "Khởi động lại Receiver Daemon")
        elif btn_id == "btn_open_all_receivers":
            self.run_audit_command([VENV_PYTHON, "tool_all_receivers.py"], "Máy chủ thu nhận đa giao thức")

        # Nhóm 2.1.3: AuthMech 1 - 4
        elif btn_id == "btn_authmech_all":
            self.run_audit_command([VENV_PYTHON, "tool21_authmech_auditor.py", "--id", "all", "--wait", "3.0"], "Đo kiểm toàn bộ 4 Cơ chế xác thực AuthMech")
        elif btn_id == "btn_authmech_enum":
            self.run_audit_command([VENV_PYTHON, "tool21_authmech_auditor.py", "--enum", "all"], "Nmap Bóc tách Toàn bộ Danh mục Ciphersuite")
        elif btn_id.startswith("btn_authmech_"):
            aid = btn_id.replace("btn_authmech_", "")
            self.run_audit_command([VENV_PYTHON, "tool21_authmech_auditor.py", "--id", aid, "--wait", "3.0"], f"Đo kiểm AuthMech-{aid}")

        # Nhóm 2.1.3: ComMech 1 - 11
        elif btn_id == "btn_commech_all":
            self.run_audit_command([VENV_PYTHON, "tool17_commech_auditor.py", "--id", "all", "--wait", "3.0"], "Đo kiểm toàn bộ 11 Cơ chế truyền thông ComMech")
        elif btn_id.startswith("btn_commech_"):
            cid = btn_id.replace("btn_commech_", "")
            self.run_audit_command([VENV_PYTHON, "tool17_commech_auditor.py", "--id", cid, "--wait", "5.0"], f"Đo kiểm ComMech-{cid}")

        # Nhóm 2.1.3: Thành phần chuyên sâu
        elif btn_id == "btn_tool1_tls_443":
            self.run_audit_command([VENV_PYTHON, "tool1_tls_scanner.py", ip, "443"], "Quét TLS Web HTTPS (Cổng 443)")
        elif btn_id == "btn_tool1_tls_322":
            self.run_audit_command([VENV_PYTHON, "tool1_tls_scanner.py", ip, rtsps_p], f"Quét TLS RTSPS (Cổng {rtsps_p})")
        elif btn_id == "btn_tool2_clear":
            self.run_audit_command([VENV_PYTHON, "tool2_unencrypted_protocols.py", ip], "Phân tích giao thức rõ & Giá trị xác thực")
        elif btn_id == "btn_tool5_snmp":
            self.run_audit_command([VENV_PYTHON, "tool5_snmpv3_auditor.py", ip], "Đo kiểm ma trận mật mã SNMPv3")
        elif btn_id == "btn_tool12_rtsp_auth":
            self.run_audit_command([VENV_PYTHON, "tool12_rtsp_auth_auditor.py", rtsps_p], "Bắt tay xác thực RTSP & SDP")

        # Nhóm 2.1.3: Bóc tách Client
        elif btn_id == "btn_recv_sftp":
            self.run_audit_command([VENV_PYTHON, "receiver_daemon.py", "--service", "sftp"], "Bóc tách SFTP / SSH Client")
        elif btn_id == "btn_recv_ftp":
            self.run_audit_command([VENV_PYTHON, "receiver_daemon.py", "--service", "ftp"], "Bóc tách Plain FTP rõ")
        elif btn_id == "btn_recv_smtp":
            self.run_audit_command([VENV_PYTHON, "receiver_daemon.py", "--service", "smtp"], "Bóc tách SMTP Email TLS")
        elif btn_id == "btn_recv_alarm":
            self.run_audit_command([VENV_PYTHON, "receiver_daemon.py", "--service", "alarm"], "Bóc tách Alarm Webhook")

        # Nhóm 2.1.5: Phòng vệ vét cạn
        elif btn_id == "btn_onvif_reset":
            self.run_audit_command([VENV_PYTHON, "tool11_onvif_lockout.py", "--mode", "1"], "Reset bộ đếm ONVIF")
        elif btn_id == "btn_onvif_lockout":
            self.run_audit_command([VENV_PYTHON, "tool11_onvif_lockout.py", "--mode", "2"], "Kích hoạt Khóa ONVIF (10 lần sai)")
        elif btn_id == "btn_onvif_dict":
            self.run_audit_command([VENV_PYTHON, "tool11_onvif_lockout.py", "--mode", "3"], "Vét cạn từ điển ONVIF")
        elif btn_id == "btn_onvif_burst":
            self.run_audit_command([VENV_PYTHON, "tool11_onvif_lockout.py", "--mode", "4", "--burst-count", "8"], "Kiểm chứng Firewall Rate-Limit (4 conn/s)")
        elif btn_id == "btn_rtsp_lockout_322":
            self.run_audit_command([VENV_PYTHON, "tool10_rtsp_lockout.py", rtsps_p], f"Khóa luồng RTSPS Cổng {rtsps_p}")
        elif btn_id == "btn_rtsp_lockout_554":
            self.run_audit_command([VENV_PYTHON, "tool10_rtsp_lockout.py", "554"], "Khóa luồng RTSP Cổng 554")
        elif btn_id == "btn_tool9_latency":
            self.run_audit_command([VENV_PYTHON, "tool9_bruteforce_checker.py"], "Đo hồ sơ độ trễ (Rate Limiting)")
        elif btn_id == "btn_ssh_lockout":
            self.run_audit_command([VENV_PYTHON, "tool15_ssh_lockout.py"], "Khóa SSH (Cổng 22)")
        elif btn_id == "btn_web_lockout":
            self.run_audit_command([VENV_PYTHON, "tool16_web_lockout.py"], "Khóa Web HTTPS (Cổng 443)")

        # Nhóm 2.4 & Tổng hợp
        elif btn_id == "btn_master_audit":
            self.run_audit_command([VENV_PYTHON, "tool8_master_audit.py", ip], "Master Security Audit 1-Click")
        elif btn_id == "btn_tool13_secparams":
            self.run_audit_command([VENV_PYTHON, "tool13_security_params_auditor.py"], "Đo kiểm tham số an toàn nhạy cảm")
        elif btn_id == "btn_tool14_wireshark":
            self.run_audit_command([VENV_PYTHON, "tool14_rtsp_wireshark_verifier.py"], "Bắt gói tin & Đối soát Wireshark")
        elif btn_id == "btn_tool18_fuzz_rtsp":
            self.run_audit_command([VENV_PYTHON, "tool18_api_input_validation.py", "--mode", "rtsp"], "Fuzzing luồng Media RTSP 3.10.1.3")
        elif btn_id == "btn_tool18_scan_api":
            self.run_audit_command([VENV_PYTHON, "tool18_api_input_validation.py", "--mode", "scan"], "Quét toàn bộ bề mặt API Camera")
        elif btn_id == "btn_tool19_csrf_audit":
            self.run_audit_command([VENV_PYTHON, "tool19_csrf_token_auditor.py"], "Đo kiểm CSRF & Giả mạo Token")
        elif btn_id == "btn_tool22_login_audit":
            self.run_audit_command([VENV_PYTHON, "tool22_login_input_validation.py"], "Đo kiểm Form Login: SQLi & XSS 3.10.1.3")


def main():
    app = ToolkitApp()
    app.run()


if __name__ == '__main__':
    main()
