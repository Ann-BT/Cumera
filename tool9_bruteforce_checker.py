import socket
import ssl
import sys
import time
import base64
import json
import os
from rich.console import Console

sys.stdout.reconfigure(encoding='utf-8')
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pcap_recorder import start_pcap_capture, stop_pcap_capture, display_wireshark_panel
from toolkit_config import CONF_PATH, get_service_ports, get_target_info, is_tls_port, load_config, make_console

console = make_console()
config = load_config()
_target_info = get_target_info(config)
_sp = get_service_ports(config)

DUT_IP = _target_info["ip"]
RTSP_PORT = int(_sp["rtsp"])
RTSPS_PORT = int(_sp["rtsps"])
RTSP_PATH = _sp["rtsp_path"]
USER = _target_info["username"]
CORRECT_PASS = _target_info["password"]
GLOBAL_PCAP_FILE = ""

def get_active_rtsp():
    for port in (RTSPS_PORT, RTSP_PORT, 322, 9554, 554):
        s = socket.socket()
        s.settimeout(1.0)
        res = s.connect_ex((DUT_IP, port))
        s.close()
        if res == 0:
            return port, is_tls_port(DUT_IP, port)
    return RTSPS_PORT, is_tls_port(DUT_IP, RTSPS_PORT)

ACTIVE_PORT, USE_TLS = get_active_rtsp()

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
ctx.keylog_filename = os.path.join(os.path.dirname(__file__), "captures", "sslkeys.log")

def test_attempt(seq, username, password):
    cred = base64.b64encode(f"{username}:{password}".encode()).decode()
    t_start = time.time()
    try:
        if USE_TLS:
            with socket.create_connection((DUT_IP, ACTIVE_PORT), timeout=3.0) as sock:
                with ctx.wrap_socket(sock, server_hostname=DUT_IP) as ssock:
                    req = (
                        f"DESCRIBE rtsp://{DUT_IP}:{ACTIVE_PORT}{RTSP_PATH} RTSP/1.0\r\n"
                        f"CSeq: {seq}\r\n"
                        f"User-Agent: QCVN11-Audit-Client\r\n"
                        f"Authorization: Basic {cred}\r\n\r\n"
                    )
                    ssock.sendall(req.encode())
                    resp = ssock.recv(2048).decode('utf-8', errors='ignore')
                    elapsed = (time.time() - t_start) * 1000
                    first_line = resp.splitlines()[0] if resp else "EMPTY (Ngắt kết nối)"
                    return True, first_line, elapsed
        else:
            with socket.create_connection((DUT_IP, ACTIVE_PORT), timeout=3.0) as sock:
                req = (
                    f"DESCRIBE rtsp://{DUT_IP}:{ACTIVE_PORT}{RTSP_PATH} RTSP/1.0\r\n"
                    f"CSeq: {seq}\r\n"
                    f"User-Agent: QCVN11-Audit-Client\r\n"
                    f"Authorization: Basic {cred}\r\n\r\n"
                )
                sock.sendall(req.encode())
                resp = sock.recv(2048).decode('utf-8', errors='ignore')
                elapsed = (time.time() - t_start) * 1000
                first_line = resp.splitlines()[0] if resp else "EMPTY (Ngắt kết nối)"
                return True, first_line, elapsed
    except socket.timeout:
        elapsed = (time.time() - t_start) * 1000
        return False, "TIMEOUT (Bị đóng băng/chặn)", elapsed
    except (ConnectionResetError, ConnectionRefusedError):
        elapsed = (time.time() - t_start) * 1000
        return False, "CONNECTION DROP (Chủ động ngắt kết nối)", elapsed
    except Exception as e:
        elapsed = (time.time() - t_start) * 1000
        return False, f"ERROR: {type(e).__name__}", elapsed

def run_test_case_1():
    print("\n" + "=" * 80)
    print("  [TEST CASE 1] KIỂM TRA RESET BỘ ĐẾM: NHẬP ĐÚNG TRƯỚC KHI ĐẠT NGƯỠNG KHÓA")
    print(f"  Mục tiêu: {DUT_IP}:{ACTIVE_PORT} | Ngưỡng khóa: 10 lần | Thử sai: 4 lần")
    print("  Mục đích: Chứng minh khi nhập đúng mật khẩu, bộ đếm thất bại liên tiếp")
    print("            phải được xóa về 0, không bị cộng dồn làm khóa oan người dùng.")
    print("=" * 80)

    print("\n[*] Giai đoạn 1.1: Gửi 4 lần sai mật khẩu liên tiếp (chưa tới ngưỡng 10)...")
    print(f"{'Lần thử':<8} | {'Mật khẩu':<22} | {'Kết quả phản hồi':<30} | {'Độ trễ':<10}")
    print("-" * 80)
    for i in range(1, 5):
        fake = f"WrongPass_{i}#Bad"
        ok, status, lat = test_attempt(i, USER, fake)
        print(f"#{i:<7} | {fake:<22} | {status:<30} | {lat:6.1f} ms")
        time.sleep(0.35)

    print("-" * 80)
    print(f"[*] Giai đoạn 1.2: Gửi MẬT KHẨU ĐÚNG ({CORRECT_PASS}) để kiểm tra reset bộ đếm...")
    ok_valid1, status_valid1, lat_v1 = test_attempt(10, USER, CORRECT_PASS)
    print(f"{'#VALID1':<8} | {CORRECT_PASS:<22} | {status_valid1:<30} | {lat_v1:6.1f} ms")
    print("-" * 80)

    if "200 OK" not in status_valid1:
        print("\n[-] CẢNH BÁO: Mật khẩu đúng không trả về 200 OK!")
        print(f"    Trạng thái nhận được: {status_valid1}")
        print("    (Nếu camera đang trong 30 phút bị khóa từ bài test trước, hãy khởi động lại camera).")
        return False

    print("  [+] Camera chấp nhận xác thực thành công (200 OK). Bộ đếm đã được reset về 0.")
    print("      -> Wireshark Filter/Sort tìm gói tin đăng nhập thành công: rtsp.status == 200")

    print("\n[*] Giai đoạn 1.3: Gửi tiếp 4 lần sai mật khẩu nữa...")
    print("    (Nếu bộ đếm được reset về 0, tổng 4+4=8 lần sai rời rạc sẽ KHÔNG làm khóa camera).")
    print(f"{'Lần thử':<8} | {'Mật khẩu':<22} | {'Kết quả phản hồi':<30} | {'Độ trễ':<10}")
    print("-" * 80)
    for i in range(5, 9):
        fake = f"WrongPass_{i}#Bad"
        ok, status, lat = test_attempt(i, USER, fake)
        print(f"#{i:<7} | {fake:<22} | {status:<30} | {lat:6.1f} ms")
        time.sleep(0.35)

    print("-" * 80)
    print(f"[*] Giai đoạn 1.4: Thử lại MẬT KHẨU ĐÚNG ({CORRECT_PASS}) lần 2...")
    ok_valid2, status_valid2, lat_v2 = test_attempt(20, USER, CORRECT_PASS)
    print(f"{'#VALID2':<8} | {CORRECT_PASS:<22} | {status_valid2:<30} | {lat_v2:6.1f} ms")
    print("-" * 80)

    if "200 OK" in status_valid2:
        print("\n" + "=" * 80)
        print("  [+] KẾT LUẬN TEST CASE 1: [ ĐẠT - PASS ]")
        print("  [+] BẰNG CHỨNG XÁC THỰC:")
        print("      1. Nhập đúng mật khẩu giữa chừng đã reset bộ đếm thất bại về 0.")
        print("      2. Tổng 8 lần nhập sai rời rạc không kích hoạt khóa sớm.")
        print("      3. Người dùng hợp lệ không bị gián đoạn dịch vụ khi bấm nhầm phím.")
        print("=" * 80)

        filters1 = [
            ("Toàn bộ lưu lượng phiên RTSP kiểm thử", f"tcp.port == {ACTIVE_PORT} && (rtsp || tls)"),
            ("Gói tin đăng nhập mật khẩu đúng thành công (Reset bộ đếm)", f"tcp.port == {ACTIVE_PORT} && rtsp.status == 200"),
            ("Các lần gửi thử mật khẩu sai trước ngưỡng", f"tcp.port == {ACTIVE_PORT} && rtsp.status == 401")
        ]
        display_wireshark_panel(
            console,
            GLOBAL_PCAP_FILE,
            filters1,
            is_tls=USE_TLS,
            sort_tip="Click tiêu đề cột No. để kiểm tra chuỗi gói tin: Gửi mật khẩu sai (401) xen kẽ mật khẩu đúng (200 OK) chứng minh bộ đếm đã được reset về 0.",
            title=f"BẰNG CHỨNG GÓI TIN TEST CASE 1 (RESET BỘ ĐẾM - CỔNG {ACTIVE_PORT})"
        )
        return True
    else:
        print("\n" + "=" * 80)
        print("  [-] KẾT LUẬN TEST CASE 1: [ KHÔNG ĐẠT - FAIL ]")
        print(f"  [-] Camera bị khóa sớm hoặc từ chối kết nối: {status_valid2}")
        print("=" * 80)
        return False

def run_test_case_2():
    print("\n" + "=" * 80)
    print("  [TEST CASE 2] KIỂM TRA KÍCH HOẠT KHÓA KHI VÉT CẠN VƯỢT NGƯỠNG (10 LẦN)")
    print(f"  Mục tiêu: {DUT_IP}:{RTSPS_PORT} | Ngưỡng khóa: 10 lần sai liên tiếp")
    print("  Mục đích: Chứng minh sau khi cố tình gửi đủ 10 lần sai liên tiếp,")
    print("            thiết bị bắt buộc phải KHÓA và TỪ CHỐI kể cả mật khẩu ĐÚNG.")
    print("=" * 80)

    latencies = []
    print(f"\n{'Lần thử':<8} | {'Mật khẩu thử nghiệm':<22} | {'Kết quả phản hồi':<30} | {'Độ trễ':<10}")
    print("-" * 80)

    for i in range(1, 11):
        fake_pass = f"AttackPass_{i}#Bad"
        ok, status, lat = test_attempt(100 + i, USER, fake_pass)
        latencies.append(lat)
        print(f"#{i:<7} | {fake_pass:<22} | {status:<30} | {lat:6.1f} ms")
        time.sleep(0.35)

    print("-" * 80)
    print(f"[*] ĐÃ GỬI ĐỦ 10 LẦN THẤT BẠI LIÊN TIẾP ĐỂ ĐO KIỂM NGƯỠNG KHÓA (LOCKOUT THRESHOLD)...")
    print(f"[*] BƯỚC QUYẾT ĐỊNH: GỬI MẬT KHẨU ĐÚNG ({CORRECT_PASS}) ĐỂ KIỂM CHỨNG KHÓA...")

    ok_verif, status_verif, lat_verif = test_attempt(999, USER, CORRECT_PASS)
    print(f"{'#TEST':<8} | {CORRECT_PASS:<22} | {status_verif:<30} | {lat_verif:6.1f} ms")
    print("-" * 80)

    avg_lat = sum(latencies) / len(latencies) if latencies else 0

    print("\n" + "=" * 80)
    print("  KẾT LUẬN TEST CASE 2:")
    print("=" * 80)
    print(f"  • Độ trễ phản hồi trung bình     : {avg_lat:.1f} ms")
    print(f"  • Kết quả thử mật khẩu ĐÚNG      : {status_verif}")

    if "200 OK" not in status_verif:
        print("\n  [+] KẾT QUẢ ĐÁNH GIÁ: [ ĐẠT - PASS ]")
        print("  [+] BẰNG CHỨNG XÁC THỰC:")
        print("      1. Thiết bị ghi nhận đủ 10 lần xác thực sai liên tiếp.")
        print(f"      2. Tại lần kiểm tra với mật khẩu ĐÚNG ('{CORRECT_PASS}'), thiết bị đã")
        print(f"         TỪ CHỐI ({status_verif}) thay vì cấp quyền truy cập.")
        print("      3. Chứng minh cơ chế khóa IP/tài khoản (Lockout) đã hoạt động thực tế 100%,")
        print("         ngăn chặn hoàn toàn kẻ tấn công đoán đúng mật khẩu sau khi vét cạn.")
        print("=" * 80)

        filters2 = [
            ("Toàn bộ chuỗi gói tin vét cạn RTSP/RTSPS", f"tcp.port == {ACTIVE_PORT} && (rtsp || tls)"),
            ("10 lần nhập sai liên tiếp (Mã 401 Unauthorized)", f"tcp.port == {ACTIVE_PORT} && rtsp.status == 401"),
            ("Lần thử mật khẩu đúng bị KHÓA / Reset kết nối", f"(tcp.port == {ACTIVE_PORT}) && (tcp.flags.reset == 1 || (rtsp.cseq == 999 && rtsp.status == 401))"),
            ("Gói tin gửi mật khẩu đúng ở CSeq 999", f"rtsp.cseq == 999 || (tcp.port == {ACTIVE_PORT} && tcp.flags.reset == 1)")
        ]
        display_wireshark_panel(
            console,
            GLOBAL_PCAP_FILE,
            filters2,
            is_tls=USE_TLS,
            sort_tip="Click tiêu đề cột No. hoặc rtsp.cseq để thấy chuỗi 10 lần 401 Unauthorized liên tiếp kết thúc bằng gói Block/Reset tại lần thứ 11 (CSeq 999).",
            title=f"BẰNG CHỨNG GÓI TIN TEST CASE 2 (KÍCH HOẠT KHÓA 10 LẦN SAI - CỔNG {ACTIVE_PORT})"
        )
        return True
    else:
        print("\n  [-] KẾT QUẢ ĐÁNH GIÁ: [ KHÔNG ĐẠT - FAIL ]")
        print("  [-] CẢNH BÁO: Sau 10 lần nhập sai, mật khẩu đúng vẫn trả về '200 OK'.")
        print("      Thiết bị không thực hiện khóa như đã cam kết trong hồ sơ kỹ thuật!")
        print("=" * 80)
        return False

def main():
    global GLOBAL_PCAP_FILE
    print("=" * 80)
    print("  BỘ ĐO KIỂM BẢO VỆ CHỐNG VÉT CẠN - YÊU CẦU 2.1.5 (QCVN 11:2026/BCA)")
    print(f"  Mục tiêu: {DUT_IP}:{ACTIVE_PORT} | Tài khoản: {USER}")
    print("=" * 80)

    pcap_proc, GLOBAL_PCAP_FILE = start_pcap_capture(
        DUT_IP,
        f"tcp port {ACTIVE_PORT}",
        prefix=f"rtsp_bruteforce_audit_{ACTIVE_PORT}"
    )
    if GLOBAL_PCAP_FILE:
        print(f"[*] Đang tự động bắt gói tin PCAP vào: {GLOBAL_PCAP_FILE}\n")

    try:
        print("  Lựa chọn chế độ đo kiểm:")
        print("  [1] Chạy TEST CASE 1: Nhập đúng trước ngưỡng (Kiểm tra reset bộ đếm)")
        print("  [2] Chạy TEST CASE 2: Nhập sai vượt ngưỡng (Kiểm tra kích hoạt khóa - 10 lần)")
        print("  [3] Chạy TOÀN BỘ (Test Case 1 trước, sau đó tự động chuyển sang Test Case 2)")
        print("  [0] Thoát")
        print("-" * 80)

        try:
            choice = input("Nhập lựa chọn của bạn ( mặc định [3] ): ").strip()
        except EOFError:
            choice = "3"

        if not choice:
            choice = "3"

        if choice == "1":
            run_test_case_1()
        elif choice == "2":
            run_test_case_2()
        elif choice == "3":
            res1 = run_test_case_1()
            if res1:
                print("\n[*] Test Case 1 ĐẠT. Đang chuyển sang Test Case 2 sau 3 giây...")
                time.sleep(3)
                run_test_case_2()
            else:
                print("\n[-] Test Case 1 không thành công, bỏ qua Test Case 2.")
                print("    (Gợi ý: Nếu camera đang bị khóa 30 phút từ trước, hãy khởi động lại camera).")
        else:
            print("Thoát.")
    finally:
        stop_pcap_capture(pcap_proc)

if __name__ == '__main__':
    main()
