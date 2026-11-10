# BÁO CÁO ĐO KIỂM GIÁM SÁT TRUYỀN TIN QUỐC TẾ & DỮ LIỆU ĐO ĐẠC TỪ XA
**Tiêu chuẩn áp dụng**: QCVN 11:2026/BCA (Điều 2.11.4 & Điều 2.11.5 / Phương pháp đo 3.11.4 & 3.11.5)  
**Tài liệu tham chiếu**: ETSI EN 303 645 (Clause 5.11 / IXIT 24-TelData & IXIT 28-ExtAPI)  
**Thời gian thực hiện**: `2026-11-10 08:56:27`  
**Thiết bị kiểm tra (DUT)**: `AXIS Q1806-LE` | **IP**: `192.168.1.100` | **Firmware**: `13.1.23`  
**Tệp bằng chứng PCAP**: `commech1_web_https_20261109_195116.pcap`  

---

## 1. KẾT LUẬN ĐÁNH GIÁ HỢP QUY (COMPLIANCE SUMMARY)

| Yêu cầu kỹ thuật | Mã kiểm thử | Nội dung thẩm định | Kết luận thực tế | Đánh giá |
| :--- | :---: | :--- | :--- | :---: |
| **Yêu cầu 2.11.4** | `TC-3.11.4-IMPL` | Mô tả đầy đủ về dữ liệu đo đạc từ xa (Telemetry Data) | ĐẠT / K/A (Thiết bị hoạt động cục bộ, không gửi dữ liệu đo đạc từ xa) | **ĐẠT** |
| **Yêu cầu 2.11.5** | `TC-3.11.5-IMPL` | Thiết lập cấu hình lưu trữ dữ liệu tại Việt Nam | ĐẠT (100% dữ liệu lưu thông nội bộ hoặc máy chủ đặt tại Việt Nam) | **ĐẠT** |

> **Ghi chú đánh giá**:
> - **Điều 2.11.4**: Toàn bộ nội dung gói tin trao đổi (40 gói) đã được bóc tách sâu (DPI). Kết quả ghi nhận 0 gói chứa từ khóa đo đạc kỹ thuật và 0 trường hợp lộ dữ liệu cá nhân.
> - **Điều 2.11.5**: Camera đã phát đi 17 gói tin. Trong đó có **0 gói tin truyền đi máy chủ quốc tế** (0 bytes). Thiết bị tuân thủ 100% quy định lưu trữ dữ liệu tại Việt Nam.

---

## 2. BẢNG THỐNG KÊ LƯU LƯỢNG & ĐỊNH VỊ ĐỊA LÝ IP (GEOIP FLOW TABLE)

Dưới đây là danh sách phân tích toàn bộ các địa chỉ IP trao đổi với camera:

| STT | Địa chỉ IP | Quốc gia / Vị trí | Nhà mạng / ASN | Gói Camera gửi | Gói Camera nhận | Dung lượng | Giao thức | Trạng thái Lưu trữ |
| :---: | :--- | :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| 1 | `192.168.1.200` | Mạng nội bộ (Private LAN / RFC 1918) (VN-LAN) | Mạng nội bộ (Local Area Network) | 17 | 23 | 7,896 B | HTTP, TLS/HTTPS | Nội bộ (LAN) |

---

## 3. BÓC TÁCH NỘI DUNG GÓI TIN & PHÂN TÍCH TELEMETRY (CLAUSE 3.11.4)

### 3.1. Các tên miền và máy chủ đích (DNS & TLS SNI)
- **Tên miền DNS**: Không ghi nhận truy vấn DNS ra ngoài.
- **TLS SNI**: Không phát hiện kết nối TLS ra bên ngoài.

### 3.2. Rà soát Lộ lọt Thông tin Cá nhân & Thiết bị
 Không phát hiện mật khẩu, khóa bí mật, tài khoản, tọa độ GPS hoặc dữ liệu cá nhân bị truyền ra ngoài trong các gói tin đo đạc từ xa.

---

## 4. HƯỚNG DẪN ĐỐI SOÁT BẰNG WIRESHARK (PROOF OF EVIDENCE)

Để thẩm tra lại kết quả trên tệp bằng chứng `commech1_web_https_20261109_195116.pcap` qua Wireshark:

1. **Lọc gói tin truyền ra ngoài mạng nội bộ (Tìm gói tin quốc tế)**:
   ```wireshark
   ip.src == 192.168.1.100 && !(ip.dst == 10.0.0.0/8 || ip.dst == 172.16.0.0/12 || ip.dst == 192.168.0.0/16 || ip.dst == 224.0.0.0/4 || ip.dst == 255.255.255.255)
   ```

2. **Lọc các truy vấn tên miền phát sinh từ camera**:
   ```wireshark
   dns.flags.response == 0 && ip.src == 192.168.1.100
   ```

3. **Lọc các kết nối TLS ra Cloud nước ngoài (Trích xuất SNI)**:
   ```wireshark
   tls.handshake.extension.type == 0 && ip.src == 192.168.1.100
   ```

4. **Lọc nội dung gói tin chứa từ khóa Telemetry / Đo đạc từ xa**:
   ```wireshark
   frame matches "(?i)telemetry|analytics|crashlog|coredump|heartbeat"
   ```

---
*Báo cáo được khởi tạo tự động bởi Bộ công cụ đo kiểm QCVN 11:2026/BCA Toolkit (Tool 20 - Telemetry & GeoIP Auditor).*
