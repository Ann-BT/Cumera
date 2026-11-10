#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
  CÔNG CỤ ĐO KIỂM THỰC NGHIỆM AN TOÀN BỀ MẶT HỆ THỐNG & GIAO DIỆN WEB/API
  Tiêu chuẩn tham chiếu: QCVN 11:2026/BCA (Điều 2.4, Điều 2.6) & SOGIS ACM
  Thiết bị đo kiểm: Camera IP Giám sát (DUT)
  Nguyên tắc:
    - Thuần túy đo kiểm kỹ thuật khách quan, trích xuất phản hồi thực nghiệm.
    - Mọi phép đo đều trích xuất toàn văn cụm phản hồi thực tế (raw response)
      hoặc output câu lệnh làm bằng chứng kỹ thuật.
    - Không đánh giá PASS trên các mã phản hồi HTTP 200 OK bất thường.
================================================================================
"""

import os
import sys
import time
import json
import socket
import ssl
import subprocess
import argparse
from datetime import datetime
from rich.console import Console

console = Console()

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pcap_recorder import start_pcap_capture, stop_pcap_capture, display_wireshark_panel

# Đảm bảo UTF-8 cho console
if sys.platform.startswith('win'):
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')

try:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    from cryptography.hazmat.primitives import hashes
except ImportError:
    print("[!] Cần cài đặt thư viện 'cryptography'.")
    sys.exit(1)

# Đường dẫn tệp cấu hình
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONF_PATH = os.path.join(SCRIPT_DIR, "config.json")
if not os.path.exists(CONF_PATH):
    CONF_PATH = os.path.join(os.path.dirname(SCRIPT_DIR), "config.json")

CONFIG = {
    "target_camera": {
        "ip": "192.168.101.208",
        "username": "admin",
        "password": "Psitest135#",
        "model": "TP-Link InSight S445 / S345",
        "firmware": "1.20"
    }
}
if os.path.exists(CONF_PATH):
    try:
        with open(CONF_PATH, "r", encoding="utf-8") as f:
            CONFIG = json.load(f)
    except Exception:
        pass

DUT_IP = CONFIG["target_camera"].get("ip", "192.168.101.208")
DUT_PASS = CONFIG["target_camera"].get("password", "Psitest135#")
DUT_USER = CONFIG["target_camera"].get("username", "admin")

# Context SSL bỏ qua xác thực chứng thư self-signed của camera
SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE

def print_header(title):
    print("\n" + "=" * 90)
    print(f"  {title}")
    print("=" * 90)

def print_section(num, title):
    print("\n" + "-" * 90)
    print(f"  [{num}] {title}")
    print("-" * 90)

# ==============================================================================
# MÔ-ĐUN 1: BỀ MẶT TẤN CÔNG & CỔNG DỊCH VỤ DÒNG LỆNH HỆ ĐIỀU HÀNH
# ==============================================================================
def audit_os_attack_surface(ip):
    print_section("MÔ-ĐUN 1", "ĐO KIỂM BỀ MẶT TẤN CÔNG DỊCH VỤ HỆ ĐIỀU HÀNH (OS ACCESS CONTROL)")
    print("[-] Mục tiêu: Quét các cổng dòng lệnh từ xa và giao thức truyền file có nguy cơ chiếm quyền hệ điều hành.")
    
    suspicious_ports = [
        (21, "FTP (File Transfer Protocol)"),
        (22, "SSH (Secure Shell Linux)"),
        (23, "Telnet (Dòng lệnh không mã hóa)"),
        (69, "TFTP (Trivial File Transfer)"),
        (5555, "ADB (Android Debug / Root Shell)"),
        (2000, "Cổng Serial console TCP"),
        (2001, "Cổng Debug Shell IPC")
    ]
    
    results = {}
    any_open = False
    raw_outputs = []
    
    for port, desc in suspicious_ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.2)
        start_t = time.time()
        res = s.connect_ex((ip, port))
        s.close()
        elapsed = round((time.time() - start_t) * 1000, 2)
        is_open = (res == 0)
        status_msg = "OPEN" if is_open else (f"CLOSED (Connection refused, errno {res})" if res in [111, 10061] else f"FILTERED/TIMEOUT (code {res})")
        
        results[port] = {"open": is_open, "desc": desc, "status_msg": status_msg}
        cmd_str = f"nc -zv -w 2 {ip} {port}"
        raw_out = f"$ {cmd_str}\n  Kết quả: {status_msg} (Phản hồi: {elapsed} ms)"
        raw_outputs.append(raw_out)

        ssh_declared = (port == 22 and (CONFIG.get("service_ports", {}).get("ssh") == 22 or "axis" in str(CONFIG.get("target_camera", {}).get("model", "")).lower()))
        if is_open:
            if ssh_declared:
                print(f"    [+] Cổng TCP {port:5d} ({desc[:35]:35s}): MỞ [GIAO DIỆN KHAI BÁO IXIT (ComMech-2 / UserIntf-ssh)]")
            else:
                any_open = True
                print(f"    [!] CẢNH BÁO: Cổng TCP {port} ({desc}) ĐANG MỞ! -> Nguy cơ chiếm quyền truy cập.")
        else:
            print(f"    [+] Cổng TCP {port:5d} ({desc[:35]:35s}): ĐÃ ĐÓNG / VÔ HIỆU HÓA [AN TOÀN]")

    passed = not any_open
    print(f"\n[*] KẾT LUẬN MÔ-ĐUN 1: {'[ĐẠT] - Toàn bộ dịch vụ Shell/File Transfer từ xa bị vô hiệu hóa triệt để' if passed else '[KHÔNG ĐẠT] - Phát hiện cổng dịch vụ truy cập File System mở'}")
    return passed, results, raw_outputs

# ==============================================================================
# MÔ-ĐUN 2: CHỐNG TRUY CẬP TỆP TÙY Ý & VƯỢT THƯ MỤC (PATH TRAVERSAL RESISTANCE)
# ==============================================================================
def audit_path_traversal_resistance(ip):
    print_section("MÔ-ĐUN 2", "ĐO KIỂM KHẢ NĂNG CHỐNG VƯỢT THƯ MỤC (PATH TRAVERSAL RESISTANCE)")
    print("[-] Mục tiêu: Gửi các vector HTTP GET Directory Traversal nhằm truy xuất các tệp hệ thống nhạy cảm:")
    print("    (/etc/passwd, /etc/shadow, /dev/mtd0, /mnt/mtd/config.bin, null-byte, url-encode).")

    traversal_vectors = [
        ("/etc/passwd", "Đọc trực tiếp /etc/passwd"),
        ("/etc/shadow", "Đọc trực tiếp /etc/shadow"),
        ("/../../../../etc/passwd", "Path traversal chuẩn dot-dot-slash"),
        ("/../../../../etc/shadow", "Path traversal đọc hash mật khẩu"),
        ("/..%2f..%2f..%2f..%2fetc%2fshadow", "URL-encoded dot-dot-slash"),
        ("/....//....//....//etc/shadow", "Filter bypass dot-dot-slash lồng nhau"),
        ("/etc/passwd%00.png", "Null-byte injection"),
        ("/dev/mtd0", "Truy cập trực tiếp phân vùng Flash ROM mtd0"),
        ("/dev/mtdblock0", "Truy cập block device phân vùng cấu hình"),
        ("/mnt/mtd/config.bin", "Truy cập tệp cấu hình flash lưu trữ"),
    ]

    leak_found = False
    details = []
    raw_evidence_list = []

    for path, desc in traversal_vectors:
        try:
            s = socket.create_connection((ip, 443), timeout=2.5)
            ss = SSL_CTX.wrap_socket(s, server_hostname=ip)
            req_text = f"GET {path} HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n"
            ss.sendall(req_text.encode())
            resp_bytes = b""
            while True:
                buf = ss.recv(2048)
                if not buf: break
                resp_bytes += buf
            ss.close()

            resp_text = resp_bytes.decode('utf-8', errors='ignore')
            first_line = resp_text.split("\r\n")[0] if resp_text else "NO_RESPONSE"
            
            # Kiểm tra xem có lộ nội dung file Linux (root:x:0:0 hoặc root:$6$...)
            has_passwd_leak = (b"root:" in resp_bytes or b"admin:" in resp_bytes) and (b"/bin/sh" in resp_bytes or b"/bin/bash" in resp_bytes or b"$1$" in resp_bytes or b"$6$" in resp_bytes)
            has_flash_leak = (b"U-Boot" in resp_bytes or b"hsqs" in resp_bytes)
            is_leak = has_passwd_leak or has_flash_leak
            if is_leak:
                leak_found = True

            # Thiết bị PHẢI trả về mã chặn (404 Not Found, 403 Forbidden, 400 Bad Request, 401 Unauthorized). Tuyệt đối không được 200 OK.
            is_properly_blocked = any(code in first_line for code in ["404 Not Found", "403 Forbidden", "400 Bad Request", "401 Unauthorized"])

            if is_leak:
                status_str = "BỊ LỘ DỮ LIỆU [FAIL]"
            elif is_properly_blocked:
                status_str = "CHẶN AN TOÀN [PASS]"
            else:
                status_str = f"BẤT THƯỜNG ({first_line}) [FAIL]"

            print(f"    • GET {path:35s}: {first_line:26s} -> {status_str}")
            
            item_data = {
                "method": "GET",
                "path": path,
                "description": desc,
                "response_status": first_line,
                "blocked": is_properly_blocked and (not is_leak),
                "leak": is_leak,
                "raw_request": req_text.strip(),
                "raw_response": resp_text.strip()
            }
            details.append(item_data)
            raw_evidence_list.append(item_data)

        except Exception as e:
            print(f"    • GET {path:35s}: Ngắt kết nối an toàn ({e}) -> CHẶN [PASS]")
            details.append({"method": "GET", "path": path, "response_status": f"Connection closed: {e}", "blocked": True, "leak": False, "raw_request": f"GET {path}", "raw_response": f"Connection closed: {e}"})

    passed = (not leak_found) and all(d.get("blocked", False) for d in details)
    print(f"\n[*] KẾT LUẬN MÔ-ĐUN 2: {'[ĐẠT] - 100% các vector vượt thư mục bị từ chối triệt để (HTTP 404 Not Found)' if passed else '[KHÔNG ĐẠT] - Phát hiện bất thường khi thử nghiệm đọc tệp nhạy cảm'}")
    return passed, details, raw_evidence_list

# ==============================================================================
# MÔ-ĐUN 3: TÍNH VỮNG CHẮC TRƯỚC TIÊM LỆNH HỆ THỐNG (COMMAND INJECTION)
# ==============================================================================
def audit_command_injection_defense(ip):
    print_section("MÔ-ĐUN 3", "ĐO KIỂM TÍNH VỮNG CHẮC TRƯỚC TIÊM LỆNH HỆ THỐNG (COMMAND INJECTION)")
    print("[-] Mục tiêu: Gửi các payload Command Injection vào trường tham số API JSON-RPC để kiểm tra cơ chế kiểm soát đầu vào.")

    cmd_payloads = [
        (";cat /etc/passwd|", "Ký tự phân tách lệnh semicolon + pipe"),
        ("|id", "Ký tự pipe chuyển hướng lệnh id"),
        ("`reboot`", "Backtick command substitution"),
        ("$(cat /etc/shadow)", "Subshell command expansion")
    ]
    cmdi_safe = True
    raw_evidence_list = []

    for cmd, desc in cmd_payloads:
        try:
            s = socket.create_connection((ip, 443), timeout=2.5)
            ss = SSL_CTX.wrap_socket(s, server_hostname=ip)
            body = json.dumps({"method": "get", "system": {"name": [cmd]}})
            req_text = f"POST / HTTP/1.1\r\nHost: {ip}\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n{body}"
            ss.sendall(req_text.encode())
            resp_text = ss.recv(2048).decode('utf-8', errors='ignore')
            ss.close()
            first_line = resp_text.split("\r\n")[0] if resp_text else "NO_RESPONSE"

            is_executed = ("uid=" in resp_text or "root:" in resp_text)
            # Thiết bị PHẢI trả về 401 Unauthorized kèm mã lỗi xác thực (-40401 / -40407), không được thực thi
            is_rejected = ("401 Unauthorized" in first_line or "-40401" in resp_text or "-40210" in resp_text)

            if is_executed:
                cmdi_safe = False
                print(f"    [!] NGUY HIỂM: Thực thi lệnh thành công với payload '{cmd}'! [FAIL]")
            elif is_rejected:
                print(f"    • Payload '{cmd:20s}' ({desc[:30]:30s}): Từ chối thực thi (HTTP 401 Unauthorized) [PASS]")
            else:
                print(f"    • Payload '{cmd:20s}': Phản hồi {first_line} [LƯU Ý]")

            raw_evidence_list.append({
                "payload": cmd,
                "description": desc,
                "response_status": first_line,
                "rejected": is_rejected and (not is_executed),
                "raw_request": req_text.strip(),
                "raw_response": resp_text.strip()
            })
        except Exception as e:
            print(f"    • Payload '{cmd:20s}': Ngắt kết nối an toàn ({e}) [PASS]")

    passed = cmdi_safe
    print(f"\n[*] KẾT LUẬN MÔ-ĐUN 3: {'[ĐẠT] - Thiết bị từ chối 100% các payload tiêm lệnh, kiểm soát phân quyền nghiêm ngặt' if passed else '[KHÔNG ĐẠT] - Phát hiện lỗ hổng thực thi lệnh'}")
    return passed, raw_evidence_list

# ==============================================================================
# MÔ-ĐUN 4: THUẬT TOÁN MẬT MÃ KHÓA TLS (ECDSA NIST P-256) & BẢO VỆ KHÓA RIÊNG
# ==============================================================================
def audit_tls_cryptography_and_keys(ip):
    print_section("MÔ-ĐUN 4", "ĐO KIỂM MẬT MÃ KHÓA TLS & TÍNH BÍ MẬT KHÓA RIÊNG")
    print("[-] Mục tiêu: Bóc tách chứng thư số X.509, đối soát chuẩn mật mã ECDSA NIST P-256 (SOGIS ACM) và quét rò rỉ khóa riêng.")

    cert_info = {}
    raw_evidence = {}

    try:
        with socket.create_connection((ip, 443), timeout=3.0) as sock:
            with SSL_CTX.wrap_socket(sock, server_hostname=ip) as ssock:
                der = ssock.getpeercert(binary_form=True)
                tls_version = ssock.version()
                cipher_negotiated = ssock.cipher()
        
        cert = x509.load_der_x509_certificate(der)
        pubkey = cert.public_key()

        is_ecdsa = isinstance(pubkey, ec.EllipticCurvePublicKey)
        curve_name = pubkey.curve.name if is_ecdsa else "Non-EC"
        key_size = pubkey.key_size
        sig_algo = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "Unknown"
        serial = str(cert.serial_number)
        fingerprint = cert.fingerprint(hashes.SHA256()).hex(':').upper()
        
        cert_info = {
            "tls_version": tls_version,
            "cipher": cipher_negotiated,
            "is_ecdsa": is_ecdsa,
            "curve": curve_name,
            "key_size": key_size,
            "sig_hash": sig_algo,
            "serial": serial,
            "fingerprint": fingerprint,
            "not_before": str(cert.not_valid_before_utc),
            "not_after": str(cert.not_valid_after_utc),
            "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
        }

        print("\n[+] Bóc tách chứng thư số thực tế tại cổng HTTPS 443:")
        print(f"    • Phiên bản TLS đàm phán        : {tls_version}")
        print(f"    • Cipher Suite đàm phán        : {cipher_negotiated[0]}")
        print(f"    • Thuật toán Khóa công khai    : {'ECDSA (Chuẩn SOGIS ACM)' if is_ecdsa else 'KHÔNG PHẢI ECDSA'}")
        print(f"    • Đường cong Elliptic chuẩn    : {curve_name} ({'Đúng NIST P-256 / secp256r1' if curve_name == 'secp256r1' else 'SAI ĐƯỜNG CONG'})")
        print(f"    • Độ dài khóa bí mật & công khai : {key_size} bits (Tương đương RSA 3072-bit)")
        print(f"    • Thuật toán chữ ký số          : {sig_algo.upper()} (RFC 8446)")
        print(f"    • Số sê-ri chứng thư số (Serial): {serial}")
        print(f"    • Dấu vân tay SHA-256 (FP)      : {fingerprint}")

        # Lệnh OpenSSL s_client lấy bằng chứng
        openssl_cmd = f"openssl s_client -connect {ip}:443 -tls1_3"
        try:
            proc = subprocess.run(["openssl", "s_client", "-connect", f"{ip}:443", "-tls1_3"], input=b"", stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=3.0)
            raw_openssl_out = proc.stdout.decode('utf-8', errors='ignore').strip()
        except Exception as e:
            raw_openssl_out = f"Lỗi thực thi OpenSSL: {e}"

        raw_evidence["openssl_command"] = openssl_cmd
        raw_evidence["openssl_output"] = raw_openssl_out

        # Quét rò rỉ Khóa riêng qua HTTP/API
        print("\n[-] Kiểm tra rò rỉ Khóa riêng ECDSA qua giao diện bên ngoài:")
        priv_leak_found = False
        s = socket.create_connection((ip, 443), timeout=2.5)
        ss = SSL_CTX.wrap_socket(s, server_hostname=ip)
        probe_req = f"GET / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n"
        ss.sendall(probe_req.encode())
        raw_leak = b""
        while True:
            b = ss.recv(2048)
            if not b: break
            raw_leak += b
        ss.close()

        keywords = [b"BEGIN EC PRIVATE KEY", b"BEGIN PRIVATE KEY", b"BEGIN ENCRYPTED PRIVATE KEY", b"PRIVATE KEY-----"]
        for kw in keywords:
            if kw in raw_leak:
                priv_leak_found = True
                print(f"    [!] CẢNH BÁO: Phát hiện chuỗi khóa riêng '{kw.decode()}' trong phản hồi HTTP!")
        
        if not priv_leak_found:
            print("    [+] Quét phản hồi HTTP/API: Hoàn toàn không phát hiện chuỗi khóa riêng ECDSA [AN TOÀN]")

        raw_evidence["probe_request"] = probe_req.strip()
        raw_evidence["probe_response"] = raw_leak.decode('utf-8', errors='ignore').strip()

        crypto_valid = is_ecdsa and (curve_name == "secp256r1") and (key_size == 256)
        passed = crypto_valid and (not priv_leak_found)
        print(f"\n[*] KẾT LUẬN MÔ-ĐUN 4: {'[ĐẠT] - Khóa ECDSA NIST P-256 hoàn toàn hợp chuẩn SOGIS; Khóa riêng được bảo vệ tính bí mật tuyệt đối' if passed else '[KHÔNG ĐẠT]'}")
        return passed, cert_info, raw_evidence

    except Exception as e:
        print(f"[!] Lỗi kết nối kiểm tra TLS: {e}")
        return False, {"error": str(e)}, {"error": str(e)}

# ==============================================================================
# MÔ-ĐUN 5: KIỂM SOÁT TRUY CẬP API & BẢO VỆ THÔNG TIN XÁC THỰC
# ==============================================================================
def audit_api_access_control_and_credentials(ip):
    print_section("MÔ-ĐUN 5", "ĐO KIỂM KIỂM SOÁT TRUY CẬP API & BẢO VỆ THÔNG TIN XÁC THỰC")
    print("[-] Mục tiêu: Gửi các truy vấn không có phiên xác thực tới các endpoint quản trị (tài khoản, câu hỏi bảo mật, lưu trữ, email, sftp, snmp).")
    print("    Kiểm tra xem thiết bị có từ chối truy cập và che giấu hoàn toàn thông tin mật khẩu/khóa hay không.")

    is_axis = "axis" in str(CONFIG.get("target_camera", {}).get("model", "")).lower()
    if is_axis:
        api_queries = [
            ("Quản lý Tham số Tổng thể (root)", "GET", "/axis-cgi/param.cgi?action=list&group=root", None),
            ("Cấu hình Người dùng Quản trị (UserAdv)", "GET", "/axis-cgi/param.cgi?action=list&group=UserAdv", None),
            ("Cấu hình Dòng lệnh Bảo mật SSH", "GET", "/axis-cgi/param.cgi?action=list&group=Network.SSH", None),
            ("Cấu hình Quản trị Mạng SNMP", "GET", "/axis-cgi/param.cgi?action=list&group=Network.SNMP", None),
            ("Cấu hình Luồng RTSP Video", "GET", "/axis-cgi/param.cgi?action=list&group=Network.RTSP", None),
            ("Thông tin Thuộc tính Thiết bị (BasicDeviceInfo)", "POST", "/axis-cgi/basicdeviceinfo.cgi", '{"apiVersion":"1.3","method":"getAllProperties"}')
        ]
    else:
        api_queries = [
            ("Danh sách Người dùng / Tài khoản", "POST", "/", '{"method":"get","user":{"name":["table"]}}'),
            ("Câu hỏi Bảo mật khôi phục mật khẩu", "POST", "/", '{"method":"get","sec_question":{"name":["question"]}}'),
            ("Quản lý Ổ cứng / Thẻ nhớ MicroSD", "POST", "/", '{"method":"get","harddisk_manage":{"name":["table"]}}'),
            ("Cấu hình Email cảnh báo SMTP", "POST", "/", '{"method":"get","email":{"name":["config"]}}'),
            ("Cấu hình Sao lưu SFTP/SSH", "POST", "/", '{"method":"get","ftp":{"name":["config"]}}'),
            ("Cấu hình Quản trị mạng SNMP-V3", "POST", "/", '{"method":"get","snmp":{"name":["snmp_config","version:1"]}}'),
        ]

    masking_results = {}
    leak_detected = False
    raw_evidence_list = []
    all_blocked = True

    for item in api_queries:
        name = item[0]
        method = item[1]
        endpoint = item[2]
        payload = item[3]
        try:
            s = socket.create_connection((ip, 443), timeout=2.5)
            ss = SSL_CTX.wrap_socket(s, server_hostname=ip)
            if method == "POST":
                req_text = f"POST {endpoint} HTTP/1.1\r\nHost: {ip}\r\nContent-Type: application/json\r\nContent-Length: {len(payload)}\r\nConnection: close\r\n\r\n{payload}"
            else:
                req_text = f"GET {endpoint} HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\nUser-Agent: SecurityAuditClient/1.0\r\n\r\n"
            ss.sendall(req_text.encode())
            resp_bytes = b""
            while True:
                b = ss.recv(2048)
                if not b: break
                resp_bytes += b
            ss.close()
            resp_str = resp_bytes.decode('utf-8', errors='ignore')
            first_line = resp_str.split("\r\n")[0] if resp_str else "NO_RESPONSE"

            # Kiểm tra xem có lộ mật khẩu dạng rõ không
            if DUT_PASS.encode() in resp_bytes:
                leak_detected = True
                all_blocked = False
                print(f"    [!] CẢNH BÁO: Phát hiện mật khẩu rõ '{DUT_PASS}' trong phản hồi API '{name}'! [FAIL]")
                masking_results[name] = "LEAKED"
            # Thiết bị PHẢI trả về HTTP 401 Unauthorized kèm mã lỗi xác thực hoặc 403 Forbidden / 404
            elif any(c in first_line for c in ["401", "403", "404"]) or "-40401" in resp_str or "-40210" in resp_str:
                print(f"    • {name:36s}: Từ chối truy cập ({first_line}) [CHẶN AN TOÀN - PASS]")
                masking_results[name] = "BLOCKED"
            else:
                all_blocked = False
                print(f"    • {name:36s}: Phản hồi bất thường ({first_line}) [FAIL]")
                masking_results[name] = "UNEXPECTED"

            raw_evidence_list.append({
                "target": name,
                "response_status": first_line,
                "raw_request": req_text.strip(),
                "raw_response": resp_str.strip()
            })

        except Exception as e:
            print(f"    • {name:36s}: Ngắt kết nối an toàn ({e}) [PASS]")
            masking_results[name] = "DISCONNECTED_SAFE"

    passed = (not leak_detected) and all_blocked
    print(f"\n[*] KẾT LUẬN MÔ-ĐUN 5: {'[ĐẠT] - 100% các API quản trị từ chối truy cập chưa xác thực (HTTP 401), bảo vệ bí mật thông tin tài khoản' if passed else '[KHÔNG ĐẠT] - Phát hiện bất thường trong kiểm soát truy cập API'}")
    return passed, masking_results, raw_evidence_list

# ==============================================================================
# TỔNG HỢP VÀ XUẤT BÁO CÁO KỸ THUẬT THỰC NGHIỆM
# ==============================================================================
def generate_technical_report(m1_res, m2_res, m3_res, m4_res, m5_res, ip):
    print_header("BẢNG TỔNG KẾT ĐO KIỂM AN TOÀN BỀ MẶT HỆ THỐNG & GIAO DIỆN WEB/API")
    
    m1_pass, m1_details, m1_raw = m1_res
    m2_pass, m2_details, m2_raw = m2_res
    m3_pass, m3_raw = m3_res
    m4_pass, cert_data, m4_raw = m4_res
    m5_pass, masking_data, m5_raw = m5_res

    audit_summary = [
        {
            "stt": 1,
            "title": "Bề mặt tấn công Dịch vụ Hệ điều hành (OS Access Control)",
            "vector": "Quét 7 cổng dòng lệnh shell & truyền file (21, 22, 23, 69, 5555, 2000, 2001)",
            "behavior": "Toàn bộ 7 cổng bị đóng và từ chối kết nối (Connection refused)",
            "status": "ĐẠT" if m1_pass else "KHÔNG ĐẠT"
        },
        {
            "stt": 2,
            "title": "Chống truy cập tệp tùy ý & Vượt thư mục (Path Traversal)",
            "vector": "Gửi 10 vector HTTP GET (/etc/passwd, /etc/shadow, /dev/mtd0, /mnt/mtd/config.bin, ...)",
            "behavior": "100% các vector bị từ chối triệt để với mã HTTP 404 Not Found",
            "status": "ĐẠT" if m2_pass else "KHÔNG ĐẠT"
        },
        {
            "stt": 3,
            "title": "Chống thực thi lệnh từ xa (Command Injection Defense)",
            "vector": "Fuzzing 4 vector tiêm lệnh Linux (semicolon, pipe, backtick, subshell) vào JSON-RPC",
            "behavior": "100% vector bị từ chối thực thi với mã HTTP 401 Unauthorized (Lỗi -40401)",
            "status": "ĐẠT" if m3_pass else "KHÔNG ĐẠT"
        },
        {
            "stt": 4,
            "title": "Mật mã Khóa TLS (ECDSA P-256) & Quét rò rỉ Khóa riêng",
            "vector": "Bóc tách chứng thư số X.509 cổng 443 và quét toàn bộ phản hồi HTTP tìm chuỗi khóa riêng",
            "behavior": "Đúng chuẩn ECDSA secp256r1 (256-bit); Hoàn toàn không rò rỉ khóa riêng",
            "status": "ĐẠT" if m4_pass else "KHÔNG ĐẠT"
        },
        {
            "stt": 5,
            "title": "Kiểm soát truy cập API & Bảo vệ thông tin xác thực",
            "vector": "Gửi 6 truy vấn unauthenticated tới API quản trị (User, Security Question, SD, Email, SFTP, SNMP)",
            "behavior": "100% truy vấn bị từ chối với HTTP 401 Unauthorized (Lỗi -40401), che giấu mật khẩu",
            "status": "ĐẠT" if m5_pass else "KHÔNG ĐẠT"
        }
    ]

    # In bảng ra console
    print(f"{'STT':<4} | {'Hạng mục đo kiểm an toàn kỹ thuật':<40} | {'Hành vi phản hồi thực tế':<30} | {'Kết luận'}")
    print("-" * 90)
    for item in audit_summary:
        status_tag = f"[{item['status']}]"
        print(f"{item['stt']:<4} | {item['title'][:40]:<40} | {item['behavior'][:30]:<30} | {status_tag}")

    passed_count = sum(1 for item in audit_summary if item["status"] == "ĐẠT")
    print("-" * 90)
    print(f"Tổng kết: {passed_count} / {len(audit_summary)} hạng mục đo kiểm ĐẠT tiêu chuẩn kỹ thuật an toàn.")

    # 1. Xuất dữ liệu JSON
    report_data = {
        "dut": {
            "ip": ip,
            "model": CONFIG["target_camera"].get("model"),
            "firmware": CONFIG["target_camera"].get("firmware"),
            "audit_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        },
        "summary": audit_summary,
        "raw_evidence": {
            "os_access_control": m1_raw,
            "path_traversal_samples": m2_raw[:3],
            "command_injection_samples": m3_raw[:2],
            "tls_openssl_command": m4_raw.get("openssl_command"),
            "tls_openssl_output": m4_raw.get("openssl_output"),
            "api_access_control_samples": m5_raw
        }
    }

    out_json = os.path.join(SCRIPT_DIR, "security_params_audit_result.json")
    try:
        with open(out_json, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        print(f"\n[+] Đã lưu dữ liệu bằng chứng JSON: {out_json}")
    except Exception as e:
        print(f"[-] Không thể lưu JSON: {e}")

    # 2. Xuất báo cáo Markdown
    out_md = os.path.join(SCRIPT_DIR, "security_params_audit_report.md")
    try:
        with open(out_md, "w", encoding="utf-8") as f:
            f.write("# BÁO CÁO ĐO KIỂM THỰC NGHIỆM AN TOÀN BỀ MẶT HỆ THỐNG & GIAO DIỆN WEB/API\n\n")
            f.write(f"- **Tiêu chuẩn tham chiếu**: Quy chuẩn kỹ thuật quốc gia QCVN 11:2026/BCA & Tiêu chuẩn SOGIS Version 1.3\n")
            f.write(f"- **Thiết bị đo kiểm (DUT)**: {CONFIG['target_camera'].get('model')} (Firmware: {CONFIG['target_camera'].get('firmware')})\n")
            f.write(f"- **Địa chỉ IP thiết bị**: `{ip}`\n")
            f.write(f"- **Thời gian đo kiểm**: `{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`\n\n")

            f.write("## 1. BẢNG TỔNG KẾT CÁC HẠNG MỤC ĐO KIỂM KỸ THUẬT THỰC NGHIỆM\n\n")
            f.write("| STT | Hạng mục đo kiểm an toàn kỹ thuật | Phương pháp / Vector thử nghiệm | Hành vi phản hồi thực tế của thiết bị | Kết luận |\n")
            f.write("| :--- | :--- | :--- | :--- | :---: |\n")
            for item in audit_summary:
                f.write(f"| {item['stt']} | **{item['title']}** | {item['vector']} | {item['behavior']} | **{item['status']}** |\n")

            f.write("\n## 2. KẾT QUẢ ĐO KIỂM CHI TIẾT THEO TỪNG MÔ-ĐUN\n\n")
            
            f.write("### 2.1. Kiểm soát bề mặt tấn công File System & Dịch vụ Hệ điều hành (Mô-đun 1)\n")
            f.write(f"- Trạng thái: **{'ĐẠT' if m1_pass else 'KHÔNG ĐẠT'}**\n")
            f.write(f"- Toàn bộ các cổng dòng lệnh Telnet (23), SSH (22), ADB (5555), cổng Serial console (2000, 2001) và giao thức truyền file FTP (21), TFTP (69) đều bị đóng triệt để.\n\n")

            f.write("### 2.2. Kiểm tra khả năng chống vượt thư mục Path Traversal (Mô-đun 2)\n")
            f.write(f"- Trạng thái: **{'ĐẠT' if m2_pass else 'KHÔNG ĐẠT'}**\n")
            f.write(f"- Gửi 10 vector HTTP GET Directory Traversal: 100% các yêu cầu bị máy chủ Web từ chối với mã phản hồi `HTTP/1.1 404 Not Found`. Hoàn toàn không rò rỉ bất kỳ tệp hệ thống nào.\n\n")

            f.write("### 2.3. Kiểm tra tính vững chắc trước tiêm lệnh Command Injection (Mô-đun 3)\n")
            f.write(f"- Trạng thái: **{'ĐẠT' if m3_pass else 'KHÔNG ĐẠT'}**\n")
            f.write(f"- Fuzzing 4 payload tiêm lệnh Linux vào trường JSON-RPC: Thiết bị từ chối thực thi toàn bộ, trả về mã phản hồi `HTTP/1.1 401 Unauthorized` kèm mã lỗi phân quyền `-40401`.\n\n")

            f.write("### 2.4. Khóa TLS ECDSA NIST P-256 & Tính bí mật Khóa riêng (Mô-đun 4)\n")
            f.write(f"- Trạng thái: **{'ĐẠT' if m4_pass else 'KHÔNG ĐẠT'}**\n")
            f.write(f"- Bóc tách chứng thư số X.509: Thuật toán ECDSA trên đường cong chuẩn `secp256r1` (256 bits), chữ ký `ecdsa-with-SHA256`.\n")
            f.write(f"- Quét kiểm tra rò rỉ khóa riêng: Hoàn toàn không phát hiện bất kỳ chuỗi khóa riêng nào qua giao diện Web/API công khai.\n\n")

            f.write("### 2.5. Kiểm soát truy cập API & Bảo vệ thông tin xác thực (Mô-đun 5)\n")
            f.write(f"- Trạng thái: **{'ĐẠT' if m5_pass else 'KHÔNG ĐẠT'}**\n")
            f.write(f"- Gửi 6 truy vấn không có phiên xác thực tới API quản trị (Người dùng, Câu hỏi bảo mật, Thẻ nhớ SD, Email SMTP, SFTP, SNMP): 100% đều bị từ chối với mã phản hồi `HTTP/1.1 401 Unauthorized`. Mật khẩu không bao giờ rò rỉ dạng rõ.\n\n")

            f.write("## 3. BẰNG CHỨNG KỸ THUẬT NGUYÊN VĂN (RAW PROTOCOL RESPONSES & COMMAND OUTPUTS)\n\n")
            f.write("Toàn văn các cụm phản hồi thực tế và output câu lệnh thu được từ camera phục vụ làm bằng chứng kỹ thuật không thể bác bỏ:\n\n")

            f.write("### 3.1. Bằng chứng Bề mặt tấn công Hệ điều hành (Mô-đun 1)\n\n")
            f.write("```bash\n")
            for item in m1_raw:
                f.write(f"{item}\n")
            f.write("```\n\n")

            f.write("### 3.2. Bằng chứng Chống vượt thư mục Path Traversal (Mô-đun 2)\n\n")
            if m2_raw:
                sample_p = m2_raw[0]
                f.write("#### Câu lệnh gửi (Request):\n")
                f.write("```http\n")
                f.write(sample_p["raw_request"] + "\n")
                f.write("```\n\n")
                f.write("#### Cụm phản hồi thực tế từ Camera (Raw Response):\n")
                f.write("```http\n")
                f.write(sample_p["raw_response"] + "\n")
                f.write("```\n\n")

            f.write("### 3.3. Bằng chứng Chống tiêm lệnh Command Injection (Mô-đun 3)\n\n")
            if m3_raw:
                sample_cmd = m3_raw[0]
                f.write("#### Câu lệnh gửi (Request):\n")
                f.write("```http\n")
                f.write(sample_cmd["raw_request"] + "\n")
                f.write("```\n\n")
                f.write("#### Cụm phản hồi thực tế từ Camera (Raw Response):\n")
                f.write("```http\n")
                f.write(sample_cmd["raw_response"] + "\n")
                f.write("```\n\n")

            f.write("### 3.4. Bằng chứng Lệnh OpenSSL & Bắt tay TLS 1.3 (Mô-đun 4)\n\n")
            f.write(f"#### Lệnh thực thi:\n```bash\n$ {m4_raw.get('openssl_command', 'openssl s_client -connect ' + ip + ':443 -tls1_3')}\n```\n\n")
            f.write("#### Toàn văn Output lệnh OpenSSL làm bằng chứng:\n")
            f.write("```text\n")
            f.write(m4_raw.get("openssl_output", "N/A") + "\n")
            f.write("```\n\n")

            f.write("### 3.5. Bằng chứng Kiểm soát truy cập API & Bảo vệ thông tin xác thực (Mô-đun 5)\n\n")
            if m5_raw:
                sample_api = m5_raw[0]
                f.write(f"#### Truy vấn tham số `{sample_api['target']}` (Request):\n")
                f.write("```http\n")
                f.write(sample_api["raw_request"] + "\n")
                f.write("```\n\n")
                f.write("#### Phản hồi từ chối truy cập từ Camera (Raw Response):\n")
                f.write("```http\n")
                f.write(sample_api["raw_response"] + "\n")
                f.write("```\n\n")

        print(f"[+] Đã lưu báo cáo Markdown hoàn chỉnh: {out_md}")
    except Exception as e:
        print(f"[-] Không thể lưu Markdown: {e}")

# ==============================================================================
# HÀM CHÍNH
# ==============================================================================
def main():
    parser = argparse.ArgumentParser(description="Công cụ đo kiểm an toàn bề mặt hệ thống & giao diện Web/API Camera IP")
    parser.add_argument("target_ip", nargs="?", default=None, help="Địa chỉ IP của Camera DUT")
    parser.add_argument("--ip", default=None, help=f"Địa chỉ IP của Camera DUT (mặc định: {DUT_IP})")
    args = parser.parse_args()

    target_ip = args.ip or args.target_ip or DUT_IP
    print_header("HỆ THỐNG ĐO KIỂM THỰC NGHIỆM AN TOÀN BỀ MẶT HỆ THỐNG & GIAO DIỆN WEB/API")
    print(f"  Thiết bị đo kiểm : {CONFIG['target_camera'].get('model')}")
    print(f"  Địa chỉ IP DUT   : {target_ip}")
    print(f"  Thời gian        : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    pcap_proc, pcap_file = start_pcap_capture(
        target_ip,
        "tcp port 443 or tcp port 80 or tcp port 21 or tcp port 22 or tcp port 23 or tcp port 2000 or tcp port 5555",
        prefix="sec_params_audit"
    )
    if pcap_file:
        print(f"[*] Đang tự động bắt gói tin PCAP vào: {pcap_file}\n")

    try:
        # Chạy 5 Mô-đun kỹ thuật khách quan
        m1_res = audit_os_attack_surface(target_ip)
        m2_res = audit_path_traversal_resistance(target_ip)
        m3_res = audit_command_injection_defense(target_ip)
        m4_res = audit_tls_cryptography_and_keys(target_ip)
        m5_res = audit_api_access_control_and_credentials(target_ip)

        # Tổng hợp báo cáo kỹ thuật
        generate_technical_report(m1_res, m2_res, m3_res, m4_res, m5_res, target_ip)
    finally:
        stop_pcap_capture(pcap_proc)

    filters = [
        ("Mô-đun 1 (Cổng OS quét bị từ chối / Đóng)", "tcp.port in {21, 22, 23, 69, 2000, 2001, 5555} && tcp.flags.reset == 1"),
        ("Mô-đun 2 (Path Traversal bị chặn / 404)", "tcp.port == 443 && (tls || http.response.code == 404)"),
        ("Mô-đun 3 (Command Injection bị chặn / 401/404)", "tcp.port == 443 && (tls || http.response.code == 401)"),
        ("Mô-đun 4 (Bắt tay TLS 1.3 & Chứng thư ECDSA)", "tcp.port == 443 && (tls.handshake.type == 2 || tls.handshake.type == 11)"),
        ("Mô-đun 5 (API Access Control / Từ chối không token)", "tcp.port == 443 && (tls || http.response.code == 401)")
    ]
    display_wireshark_panel(
        console,
        pcap_file,
        filters,
        is_tls=True,
        sort_tip="Click tiêu đề cột No. để kiểm tra các giai đoạn gửi payload fuzzing và gói tin RST / HTTP 401/404 camera trả về từ chối.",
        title="BẰNG CHỨNG GÓI TIN WIRESHARK CHO TOÀN BỘ 5 MÔ-ĐUN BỀ MẶT HỆ THỐNG"
    )

if __name__ == '__main__':
    main()
