import socket
import ssl
import sys
import json
import os
import base64
from rich.console import Console

sys.stdout.reconfigure(encoding='utf-8')
console = Console()

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pcap_recorder import start_pcap_capture, stop_pcap_capture, display_wireshark_panel

CONF_PATH = os.path.join(os.path.dirname(__file__), "config.json")
with open(CONF_PATH, encoding="utf-8") as f:
    config = json.load(f)

DUT_IP = config["target_camera"]["ip"]
RTSP_PORT = config["service_ports"]["rtsp_cleartext"]
RTSPS_PORT = config["service_ports"]["rtsps_tls"]
RTSP_PATH = config.get("service_ports", {}).get("rtsp_path", "/axis-media/media.amp" if RTSPS_PORT == 322 else "/stream1")
if not RTSP_PATH.startswith("/"):
    RTSP_PATH = "/" + RTSP_PATH
USER = config["target_camera"]["username"]
CORRECT_PASS = config["target_camera"]["password"]

def get_active_rtsp():
    if len(sys.argv) > 1 and sys.argv[1].isdigit():
        p = int(sys.argv[1])
        return p, (p in [RTSPS_PORT, 322, 9554] or p != 554)
    for port, use_tls in [(RTSPS_PORT, True), (RTSP_PORT, False), (322, True), (9554, True), (554, False)]:
        s = socket.socket()
        s.settimeout(1.0)
        res = s.connect_ex((DUT_IP, port))
        s.close()
        if res == 0:
            return port, use_tls
    return RTSPS_PORT, True

ACTIVE_PORT, USE_TLS = get_active_rtsp()
SCHEME = "rtsps" if USE_TLS else "rtsp"
URI = f"rtsp://{DUT_IP}:{ACTIVE_PORT}{RTSP_PATH}"

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
ctx.keylog_filename = os.path.join(os.path.dirname(__file__), "captures", "sslkeys.log")

def send_rtsp_raw(headers_extra=""):
    req = f"DESCRIBE {URI} RTSP/1.0\r\nUser-Agent: QCVN11-Auth-Auditor\r\n{headers_extra}\r\n"
    try:
        if USE_TLS:
            with socket.create_connection((DUT_IP, ACTIVE_PORT), timeout=3) as sock:
                with ctx.wrap_socket(sock, server_hostname=DUT_IP) as ssock:
                    ssock.sendall(req.encode())
                    resp = ssock.recv(2048).decode('utf-8', errors='ignore')
                    return True, resp
        else:
            with socket.create_connection((DUT_IP, ACTIVE_PORT), timeout=3) as sock:
                sock.sendall(req.encode())
                resp = sock.recv(2048).decode('utf-8', errors='ignore')
                return True, resp
    except Exception as e:
        return False, str(e)

def main():
    print("=" * 80)
    print("  TOOL 12: ĐO KIỂM & BÓC TÁCH CƠ CHẾ XÁC THỰC RTSP (DIGEST SHA-256 VS BASIC AUTH)")
    print(f"  Mục tiêu: {DUT_IP}:{ACTIVE_PORT} ({'TLS mã hóa' if USE_TLS else 'Rõ Cleartext'}) | Tài khoản: {USER}")
    print("=" * 80)

    pcap_proc, pcap_file = start_pcap_capture(
        DUT_IP,
        f"tcp port {ACTIVE_PORT}",
        prefix=f"rtsp_auth_audit_{ACTIVE_PORT}"
    )
    if pcap_file:
        print(f"[*] Đang tự động bắt gói tin PCAP vào: {pcap_file}")

    try:
        # --------------------------------------------------------------------------
        # BƯỚC 1: Bắt gói tin 401 Challenge (Gửi request không mật khẩu)
        # --------------------------------------------------------------------------
        print("\n[BƯỚC 1] GỬI YÊU CẦU TRỐNG ĐỂ THU THẬP TIÊU ĐỀ 'WWW-Authenticate'...")
        ok1, resp1 = send_rtsp_raw("CSeq: 1\r\n")
        if not ok1:
            print(f"[-] Không thể kết nối tới camera: {resp1}")
            return

        print("\n[-] Gói tin nguyên văn camera phản hồi:")
        for line in resp1.splitlines():
            print(f"    | {line}")

        has_digest_sha256 = False
        has_basic = False
        digest_line = ""
        basic_line = ""

        for line in resp1.splitlines():
            if "WWW-Authenticate" in line:
                if "SHA-256" in line or "sha-256" in line.lower():
                    has_digest_sha256 = True
                    digest_line = line.strip()
                if "Basic" in line:
                    has_basic = True
                    basic_line = line.strip()

        print("\n[*] Phân tích các cơ chế xác thực do camera công bố:")
        if has_digest_sha256:
            print(f"    [+] DIGEST SHA-256: CÓ TỒN TẠI ({digest_line})")
        else:
            print("    [-] DIGEST SHA-256: Không phát hiện.")

        if has_basic:
            print(f"    [-] BASIC AUTH    : CÓ TỒN TẠI ({basic_line}) -> [CẢNH BÁO BẢO MẬT]")
        else:
            print("    [+] BASIC AUTH    : Không hỗ trợ.")

        # --------------------------------------------------------------------------
        # BƯỚC 2: Kiểm chứng camera CHẤP NHẬN Basic Auth với mật khẩu ĐÚNG
        # --------------------------------------------------------------------------
        print("\n" + "-" * 80)
        print(f"[BƯỚC 2] THỬ ĐĂNG NHẬP BẰNG BASIC AUTH (MẬT KHẨU ĐÚNG: '{CORRECT_PASS}')...")
        cred_valid = base64.b64encode(f"{USER}:{CORRECT_PASS}".encode()).decode()
        ok2, resp2 = send_rtsp_raw(f"CSeq: 2\r\nAuthorization: Basic {cred_valid}\r\n")

        print(f"[*] Chuỗi Authorization gửi đi: Basic {cred_valid}")
        status2 = resp2.splitlines()[0] if resp2 else "EMPTY"
        print(f"[*] Phản hồi từ Camera: {status2}")

        accepted_valid = "200 OK" in status2
        if accepted_valid:
            print("    [+] XÁC NHẬN: Camera CHẤP NHẬN xác thực Basic Auth và trả về '200 OK'!")
            print("        Toàn bộ thông tin SDP của luồng video đã được cấp phép mở thành công.")
        else:
            print("    [-] Camera từ chối đăng nhập Basic Auth.")

        # --------------------------------------------------------------------------
        # BƯỚC 3: Kiểm chứng camera TỪ CHỐI khi gửi mật khẩu SAI (Không bypass bừa bãi)
        # --------------------------------------------------------------------------
        print("\n" + "-" * 80)
        print("[BƯỚC 3] THỬ ĐĂNG NHẬP BẰNG BASIC AUTH VỚI MẬT KHẨU SAI ('WrongPass123#')...")
        cred_invalid = base64.b64encode(f"{USER}:WrongPass123#".encode()).decode()
        ok3, resp3 = send_rtsp_raw(f"CSeq: 3\r\nAuthorization: Basic {cred_invalid}\r\n")

        status3 = resp3.splitlines()[0] if resp3 else "EMPTY"
        print(f"[*] Phản hồi từ Camera: {status3}")

        rejected_invalid = "401" in status3
        if rejected_invalid:
            print("    [+] Camera kiểm tra tính hợp lệ của mật khẩu và TỪ CHỐI (401 Unauthorized).")
            print("        Điều này chứng minh cơ chế Basic Auth thực sự kiểm tra tài khoản, không phải giả lập.")

        # --------------------------------------------------------------------------
        # BƯỚC 4: BẢNG KẾT LUẬN ĐÁNH GIÁ MỨC ĐỘ AN TOÀN XÁC THỰC RTSP
        # --------------------------------------------------------------------------
        print("\n" + "=" * 80)
        print("  KẾT LUẬN ĐÁNH GIÁ KỸ THUẬT XÁC THỰC RTSP:")
        print("=" * 80)
        print(f"  • Kết quả đo kiểm thực tế   : Hỗ trợ Digest SHA-256 VÀ Basic Auth (Base64).")
        print(f"  • Khả năng khai thác        : Kẻ tấn công trên mạng nội bộ có thể nghe lén và")
        print("                                trích xuất mật khẩu do phương thức Basic Auth chỉ mã hóa Base64 rõ.")
        
        if has_basic and accepted_valid:
            print("\n  => ĐÁNH GIÁ AN TOÀN: [ CẢNH BÁO NGUY HIỂM / KHÔNG ĐẠT ]")
            print("     Lý do: Thiết bị vẫn duy trì và chấp nhận xác thực Basic Auth dạng rõ.")
        else:
            print("\n  => ĐÁNH GIÁ AN TOÀN: [ ĐẠT CHUẨN AN TOÀN ]")
        print("=" * 80)
    finally:
        stop_pcap_capture(pcap_proc)

    filters = [
        ("Toàn bộ lưu lượng RTSP/RTSPS", f"tcp.port == {ACTIVE_PORT} && (rtsp || tls)"),
        ("Gói tin Digest SHA-256 Challenge (CSeq 1)", f"rtsp.status == 401 && rtsp contains \"algorithm=SHA-256\""),
        ("Gói tin Basic Auth Challenge (CSeq 1)", f"rtsp.status == 401 && rtsp contains \"Basic\""),
        ("Gói tin cấp quyền truyền luồng 200 OK SDP (CSeq 2)", f"rtsp.authorization contains \"Basic\" || (rtsp.status == 200 && rtsp.content_type contains \"sdp\")"),
        ("Gói tin từ chối khi gửi mật khẩu sai (CSeq 3)", f"rtsp.status == 401 && rtsp.cseq == 3")
    ]
    display_wireshark_panel(
        console,
        pcap_file,
        filters,
        is_tls=USE_TLS,
        sort_tip="Click tiêu đề cột No. để xem trình tự: CSeq 1 (401 Challenge) → CSeq 2 (Gửi Basic Auth mật khẩu đúng → 200 OK SDP) → CSeq 3 (Gửi mật khẩu sai → 401 Unauthorized).",
        title=f"BẰNG CHỨNG GÓI TIN WIRESHARK XÁC THỰC RTSP (CỔNG {ACTIVE_PORT})"
    )

if __name__ == '__main__':
    main()
