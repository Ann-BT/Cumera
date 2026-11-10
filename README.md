# CUMERA - BỘ CÔNG CỤ TỰ ĐỘNG ĐO KIỂM BẢO MẬT & MẬT MÃ CAMERA IP (QCVN 11:2026/BCA)

<img src="assets/icon.png" width="96" alt="Cumera Logo" align="right">

**Cumera** là bộ công cụ chuyên dụng kiểm thử an toàn thực nghiệm, đánh giá các cơ chế mạng, giao thức xác thực, thuật toán mật mã và bề mặt tham số an toàn trên thiết bị Camera IP (DUT) theo quy chuẩn kỹ thuật quốc gia **QCVN 11:2026/BCA** (Thông tư 48/2026/TT-BCA) và tiêu chuẩn mật mã **SOGIS Version 1.3**.

> [!NOTE]
> **Nguyên tắc đo kiểm khách quan & Chuẩn Bằng chứng Wireshark**:
> - Hoạt động độc lập theo phương pháp Black-box / Gray-box testing.
> - Thuần túy đo kiểm thực nghiệm khách quan trên thiết bị (DUT).
> - Ghi lại toàn văn cả cụm phản hồi (raw responses) hoặc output câu lệnh làm bằng chứng kỹ thuật không thể bác bỏ.
> - **Chuẩn bằng chứng gói tin Wireshark (PCAP)**: Mọi output/báo cáo từ Wireshark/tshark bắt buộc chỉ rõ:
>   - **Số thứ tự gói tin (Packet # / `frame.number`)** làm mốc bằng chứng.
>   - **Bộ lọc Wireshark (Display Filter)**: Cú pháp tìm nhanh (ví dụ: `frame.number == 9` hoặc `rtsp.status == 401`).
>   - **Cách tìm & sort trong Wireshark**: Nhấn `Ctrl + G` (Go to packet) hoặc click tiêu đề cột `No.` để sắp xếp theo trình tự thời gian.

---

## 1. YÊU CẦU HỆ THỐNG & CÀI ĐẶT NHANH (QUICK START)

### Yêu cầu tiên quyết:
- **Hệ điều hành**: Windows 10/11, Linux (Ubuntu, Debian, Fedora, Arch...), hoặc macOS.
- **Python**: Phiên bản >= 3.9 (đã bật tùy chọn thêm vào PATH khi cài đặt).
- **Công cụ mạng bổ trợ (khuyến nghị)**:
  - `Wireshark` / `tshark` (để tự động bắt và lưu file `.pcap`).
  - `openssl` (để đo kiểm bắt tay TLS nâng cao).

### Cài đặt & Khởi chạy trên Windows:
1. **Cài đặt lần đầu**:
   - Nhấp đúp chuột vào file `setup.bat`.
   - Script sẽ tự động tạo môi trường ảo `.venv`, cài đặt đầy đủ thư viện, khởi tạo `config.json` và tạo icon Cumera trên màn hình Desktop.
2. **Khởi chạy ứng dụng**:
   - **Giao diện Ứng dụng Desktop (Khuyên dùng)**: Nhấp đúp vào `run_app.bat` (hoặc icon Cumera trên Desktop). Tự động mở cửa sổ độc lập (Native Window Mode qua Microsoft Edge / Google Chrome).
   - **Giao diện Dòng lệnh CLI Menu**: Nhấp đúp vào `run_suite.bat`.
3. **Cập nhật ứng dụng khi có tính năng mới**:
   - Bấm trực tiếp nút **[Cập nhật]** ngay trên thanh công cụ của Web Dashboard.
   - Hoặc nhấp đúp file `update.bat` để tự động kéo mã nguồn mới nhất từ GitHub.

### Cài đặt & Khởi chạy trên Linux / macOS:
1. **Cài đặt**:
   ```bash
   ./setup.sh
   ```
2. **Khởi chạy**:
   - **Giao diện Đồ họa Desktop**: `./run_app.sh`
   - **Giao diện Terminal TUI**: `./run_app.sh --cli`
   - **Giao diện Menu Dòng lệnh**: `./run_suite.sh`
3. **Cập nhật**:
   - Bấm nút **[Cập nhật]** trong Web Dashboard hoặc chạy `git pull origin main && .venv/bin/pip install -r requirements.txt`.

---

## 2. CẤU TRÚC BỘ CÔNG CỤ

| File / Module | Chức năng kỹ thuật | Giao thức / Mục tiêu |
| :--- | :--- | :--- |
| **`ui_dashboard.html`** | Giao diện đồ họa Desktop kỹ thuật chuyên sâu (Single-Page App) | Bảng điều khiển Web Dashboard |
| **`toolkit_web_server.py`** | Máy chủ Backend FastAPI + WebSocket Realtime Log Streaming & Cập nhật | Port 8765 |
| **`run_app.bat` / `run_app.sh`** | Trình khởi chạy Native App Window không thanh URL (Edge/Chrome/Vivaldi) | Khởi chạy 1-click |
| **`update.bat`** | Kịch bản tự động kiểm tra và tải cập nhật mới từ GitHub cho Windows | Cập nhật tự động |

| File / Module | Chức năng kỹ thuật | Giao thức / Mục tiêu |
| :--- | :--- | :--- |
| **`config.json`** | File cấu hình trung tâm (IP camera, tài khoản, các cổng dịch vụ) | Dùng chung cho toàn bộ toolkit |
| **`toolkit_menu.py`** | Giao diện tương tác CLI Menu chọn chạy từng bài kiểm thử | Menu điều khiển trung tâm |
| **`run_suite.sh` / `run_suite.bat`** | Kịch bản khởi chạy nhanh trên Linux và Windows | Khởi chạy tự động |
| **`setup.sh` / `setup.bat`** | Kịch bản tự động khởi tạo môi trường ảo và cài đặt thư viện | Cài đặt tự động |
| **`receiver_daemon.py`** | Máy chủ thu nhận ngầm đa dịch vụ (SFTP, SMTP, Alarm Webhook) | Phân tích một chạm Zero-Wait |
| **`service_discovery.py`** | Dò quét toàn diện cổng camera IP/IoT (>50 cổng đặc thù, Top 1000, Full 1-65535 đa luồng), nhận diện dịch vụ/banner (TLS, HTTP, RTSP, SSH, Telnet, UDP mDNS/SNMP/SSDP) & đối chiếu với hồ sơ khai báo IXIT (QCVN 11 Khoản 2.6.1) | Cổng 80, 443, 322, 554, 22, 161, 5353, 3702, ... |
| **`tool21_authmech_auditor.py`** | Đo kiểm 4 Cơ chế xác thực AuthMech (Web HTTPS 443, SSH 22, RTSPS 322, ONVIF 443 WS-Security), xuất 4 tệp PCAP vào `Mẫu lưu bằng chứng/AuthMech/` & Tích hợp Nmap Enum Ciphers (`--enum`) bóc tách 100% Cipher Suites/KEX đối soát IXIT 1 | IXIT 1 - AuthMech (Clause 2.1.3 & 2.1.1) |
| **`tool17_commech_auditor.py`** | Đo kiểm toàn diện 11 Cơ chế truyền thông ComMech (Web, SSH, ONVIF, SNMPv3, MQTT, Syslog, SMBv3, SMTP, SFTP, RTSPS, Cloud Outbound), thử tấn công hạ cấp & xuất 11 tệp PCAP | IXIT 11 - ComMech (Clause 2.1.3) |
| **`tool18_api_input_validation.py`** | Fuzzing & Kiểm chứng xác thực đầu vào API (RTSP, ONVIF, Web VAPIX) chống tràn bộ đệm & Injection | QCVN 11 Khoản 3.10.1.3 |
| **`tool19_csrf_token_auditor.py`** | Đo kiểm CSRF & Giả mạo Token phiên làm việc | QCVN 11 Khoản 3.10.1.3 |
| **`tool20_telemetry_geoip_auditor.py`** | Giám sát lưu lượng quốc tế GeoIP & Đo đạc từ xa (Telemetry) | QCVN 11 Khoản 3.11 |
| **`tool1_tls_scanner.py`** | Phân tích phiên bản TLS 1.0-1.3, đối soát Cipher Suites chuẩn SOGIS ACM & X.509 Cert | HTTPS (443), RTSPS (9554/322) |
| **`tool2_unencrypted_protocols.py`** | Bóc tách phản hồi HTTP (80), RTSP (554) & RTSPS (9554), trích xuất tiêu đề xác thực và thử nghiệm Basic Auth | Chuyển hướng HTTPS & RTSP/RTSPS Digest/Basic |
| **`tool3_sftp_receiver.py`** | Máy chủ thu nhận SSH/SFTP bóc tách toàn bộ gói tin `SSH_MSG_KEXINIT` | SFTP Client |
| **`tool4_smtp_receiver.py`** | Máy chủ thu nhận SMTP (25, 465, 587) bóc tách gói tin TLS Client Hello | SMTP Email Client |
| **`tool5_snmpv3_auditor.py`** | Truy vấn thực tế 8 tổ hợp `authPriv` (SHA-256 + AES) & kiểm tra chống hạ cấp | SNMP-V3 (UDP 161) |
| **`tool6_alarm_receiver.py`** | Máy chủ thu nhận Webhook HTTP/HTTPS bóc tách headers và mã hóa | Alarm Server Webhook Client |
| **`tool7_onvif_discover.py`** | Gửi gói tin WS-Discovery Probe (UDP 3702) bóc tách ONVIF Profiles & XAddrs | ONVIF Profile S/G/T |
| **`tool8_master_audit.py`** | Chạy tổng hợp toàn bộ các bài đo kiểm 1-click, trích xuất báo cáo kỹ thuật & bằng chứng raw | Báo cáo Markdown & JSON |
| **`tool9_bruteforce_checker.py`** | Đo đạc hồ sơ độ trễ (Rate limiting curve) qua các lượt đăng nhập liên tiếp | Yêu cầu 2.1.5 (Phòng vệ vét cạn) |
| **`tool10_rtsp_lockout.py`** | Kiểm chứng ngưỡng khóa luồng RTSP / RTSPS và reset bộ đếm khi đăng nhập đúng | RTSP (554) & RTSPS (9554) |
| **`tool11_onvif_lockout.py`** | Kiểm chứng ngưỡng khóa dịch vụ ONVIF và reset bộ đếm khi đăng nhập đúng | ONVIF SOAP (Cổng 80/443) |
| **`tool15_ssh_lockout.py`** | Kiểm chứng phòng vệ vét cạn SSH (Cổng 22): 10 lần sai trong 30s -> khóa 5 phút, firewall rate limit, reset bộ đếm & xuất Wireshark sort proof | SSH-Authmech (Cổng 22) |
| **`tool16_web_lockout.py`** | Kiểm chứng phòng vệ vét cạn Web (Cổng 443 HTTPS): 6 lần sai trong 30s -> khóa 5 phút, firewall rate limit, reset bộ đếm & xuất Wireshark sort proof | Web-Authmech (Cổng 443) |
| **`tool12_rtsp_auth_auditor.py`** | Đo kiểm xác thực RTSP / RTSPS: Bóc tách SHA-256 & Bắt quả tang chấp nhận Basic Auth | Luồng video RTSP (554) & RTSPS (9554) |
| **`tool13_security_params_auditor.py`** | Đo kiểm thực nghiệm bảo vệ các tham số an toàn nhạy cảm | QCVN 11 Điều 2.4 |
| **`tool14_rtsp_wireshark_verifier.py`** | Bắt gói tin Wireshark pcap, đối soát xác thực và bóc tách luồng RTP video | Luồng RTSP (554) / RTSPS (9554) |
| **`tool_all_receivers.py`** | Trung tâm giám sát và thu nhận đa giao thức (SFTP, SMTP, Alarm) | Thu nhận đồng thời đa cổng |
| **`cam_auto_link.py`** | Tự động nhận diện dải IP camera và định tuyến chống xung đột ARP | Zero-Config Ethernet Auto-Link |

---

## 3. HƯỚNG DẪN ĐO KIỂM CHI TIẾT

### Bước 1: Cấu hình thông tin Camera mục tiêu
Có 2 cách:
1. **Cách 1 (Khuyên dùng)**: Mở menu chính (`./run_suite.sh` hoặc `run_suite.bat`), nhấn phím **`[C]`** (Change target) để:
   - Tự động nhận diện camera qua cáp mạng (Auto-Link).
   - Hoặc quét qua giao thức ONVIF WS-Discovery.
   - Hoặc nhập địa chỉ IP thủ công.
2. **Cách 2**: Chỉnh sửa trực tiếp file `config.json`:
   ```json
   {
     "target_camera": {
       "ip": "192.168.1.100",
       "username": "admin",
       "password": "Password123#",
       "model": "Camera Model",
       "firmware": "1.0.0"
     }
   }
   ```

### Bước 2: Chạy kiểm thử
- **Menu tương tác đầy đủ**:
  Chạy `./run_suite.sh` (Linux) hoặc `run_suite.bat` (Windows).
- **Chạy Master Audit 1-Click (Tự động toàn bộ bài đo)**:
  ```bash
  python tool8_master_audit.py
  ```
- **Chạy đo kiểm 9 Tham số an toàn nhạy cảm**:
  ```bash
  python tool13_security_params_auditor.py
  ```

---

## 4. DỮ LIỆU BẰNG CHỨNG THU THẬP ĐƯỢC (EVIDENCE & CAPTURES)

Khi chạy các bài đo kiểm, dữ liệu sẽ tự động được ghi nhận tại:
- Thư mục **`captures/`**: Lưu trữ các file gói tin bắt được (`.pcap`) và file nhật ký khóa TLS (`sslkeys.log`) phục vụ đối soát trên Wireshark.
- **`camera_security_audit_report.md`**: Báo cáo tổng hợp kết quả đo kiểm bảo mật.
- **`camera_security_audit_evidence.json`**: Tập dữ liệu thô (raw responses, headers, cipher lists) phục vụ lưu trữ hồ sơ thử nghiệm.
- **`security_params_audit_report.md`**: Báo cáo đo kiểm bề mặt tham số an toàn.
