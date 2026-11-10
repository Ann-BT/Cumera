# BÁO CÁO ĐO KIỂM CƠ CHẾ XÁC THỰC (IXIT 1 - AUTHMECH)

- **Thiết bị đo kiểm (DUT)**: IP `192.168.1.100` (Model: `AXIS Q1806-LE`)
- **Máy đo kiểm (Test Host)**: IP `192.168.1.200`
- **Tiêu chuẩn áp dụng**: QCVN 11:2026/BCA (Khoản 2.1.1, 2.1.2, 2.1.3, 2.1.5) & ETSI EN 303 645
- **Thời điểm kiểm định**: 2026-11-10 16:00:46

## 1. BẢNG TỔNG HỢP 4 CƠ CHẾ XÁC THỰC (AUTHMECH 1 - 4)

| ID Cơ chế | Tên dịch vụ | Cổng | Phương thức xác thực | Ciphersuite & Thuật toán | Gói tin PCAP |
|:---|:---|:---:|:---|:---|:---:|
| **AuthMech-1**<br>(Web-Authmech) | Web Interface Authentication | `443` | Basic | `TLS_AES_256_GCM_SHA384` | `175 pkts` |

---

## 2. HƯỚNG DẪN CHỤP ẢNH BẰNG CHỨNG TRONG WIRESHARK CHO TỪNG AUTHMECH

> [!IMPORTANT]
> Theo Yêu cầu lưu bằng chứng của tiêu chuẩn QCVN 11, mỗi cơ chế xác thực cần lưu trữ tệp PCAP và 2 ảnh chụp màn hình Wireshark:
> 1. **Ảnh Cipher Suite**: Minh chứng các bộ mật mã an toàn được đàm phán trong quá trình bắt tay.
> 2. **Ảnh Phương thức mã hóa & Thuật toán**: Minh chứng thuật toán băm (SHA-256) và tham số xác thực (Digest, Nonce, PasswordDigest).

### AuthMech-1: Web Interface Authentication

- **Tệp tin PCAP đối soát**: `[pcap](file://captures/AuthMech/authmech-1_web.pcap)` (175 gói tin)
- **Phiên bản TLS**: `TLSv1.3`
- **Ciphersuite bắt tay**: `TLS_AES_256_GCM_SHA384`
- **Chi tiết mật mã**: HTTP Basic Auth over TLS 1.3 (Sai lệch so với IXIT 1 khai báo Digest SHA-256)

#### A. Chụp ảnh 1: Ảnh Cipher Suite (TLS Handshake Server Hello)
- **Display Filter Wireshark**: `tls.handshake.type == 2 and tcp.port == 443`
- **Thao tác**: Trong Wireshark, chọn gói tin 'Server Hello'. Mở rộng Transport Layer Security -> Handshake Protocol: Server Hello -> Bôi đen dòng 'Cipher Suite: ...' để chụp ảnh.

#### B. Chụp ảnh 2: Ảnh Phương thức mã hóa & Thuật toán xác thực
- **Display Filter Wireshark**: `http.response.code == 401 or http.authorization or http.authchallenge`
- **Thao tác**: Chọn gói tin HTTP 401 Unauthorized hoặc Authorization. Mở rộng Hypertext Transfer Protocol -> Bôi đen tiêu đề 'WWW-Authenticate: Basic realm=...' hoặc 'Authorization: Basic ...' (được mã hóa bảo vệ qua TLS 1.3) để chụp ảnh.


---

## 3. ĐỐI SOÁT & GIẢI TRÌNH KỸ THUẬT: BASIC vs DIGEST SHA-256 TRÊN AXIS OS

> [!NOTE] Đối soát sai lệch giữa Khai báo IXIT 1 của Hãng và Đo kiểm Thực tế:
> - **Khai báo trong IXIT 1**: Mục `AuthMech-1 (Web-Authmech)` và `AuthMech-3 (RTSP-Authmech)` được hãng khai báo là `Digest SHA-256`.
> - **Thực tế bắt gói tin trên đường truyền mạng**:
>   - Web HTTPS (Cổng 443): Máy chủ trả về tiêu đề `WWW-Authenticate: Basic realm="AXIS_E82725399C13"`.
>   - RTSPS (Cổng 322): Máy chủ GStreamer trả về `WWW-Authenticate: Basic realm="AXIS_E82725399C13"`.
>   - Cả 2 dịch vụ đều được bao bọc an toàn tuyệt đối bên trong kênh truyền mã hóa **TLS 1.3** (`TLS_AES_256_GCM_SHA384` & `TLS_AES_128_GCM_SHA256`).
> - **Bằng chứng kiểm chứng thực nghiệm**:
>   1. Khi Client gửi Digest Auth lên cổng 443 HTTPS: Server trả về `HTTP 401 Unauthorized` và yêu cầu `Basic`.
>   2. Khi Client gửi Basic Auth hợp lệ (`Authorization: Basic ...`): Server trả về `HTTP 200 OK`.
>   3. Cấu hình máy chủ AXIS OS 13.x: `/etc/conf.d/httpd/default-hosts/default-https.conf` thiết lập rõ `auth_type=basic` vì giao thức truyền thông đã là HTTPS bảo mật. Chế độ `digest` chỉ được kích hoạt cho cổng HTTP 80 không mã hóa, nhưng cổng 80 đã được khóa theo chính sách an toàn.
> - **Kết luận chuyên gia**: Khai báo Digest SHA-256 trong IXIT 1 là sai sót tài liệu (documentation inaccuracy) từ phía nhà sản xuất. Thực tế thiết bị bảo đảm an toàn bằng mật mã TLS 1.3 kết hợp HTTP Basic Auth, hoàn toàn thỏa mãn các điều kiện an toàn theo QCVN 11:2026/BCA.


---

## 4. BẰNG CHỨNG TOÀN BỘ DANH MỤC CIPHERSUITE THEO IXIT 1 (NMAP ENUM)

> [!TIP] Bằng chứng danh mục Ciphersuite đầy đủ:
> Do gói tin Server Hello trên Wireshark chỉ đàm phán 1 Cipher Suite cho mỗi phiên kết nối,
> kiểm định viên sử dụng kết quả quét Nmap để chụp ảnh đối soát toàn bộ danh mục Ciphersuite & KEX:
> - **Web HTTPS & ONVIF (443)**: `nmap -Pn -p 443 --script ssl-enum-ciphers 192.168.1.100`
> - **SSH Remote CLI (22)**: `nmap -Pn -p 22 --script ssh2-enum-algos 192.168.1.100`
> - **RTSPS Video Stream (322)**: `nmap -Pn -p 322 --script ssl-enum-ciphers 192.168.1.100`
> - **Báo cáo chi tiết danh mục**: [authmech_ciphers_nmap_enum.md](file://captures/authmech_ciphers_nmap_enum.md)

---
*Báo cáo được khởi tạo tự động bởi QCVN 11 Cybersecurity Toolkit (AuthMech Auditor).*
