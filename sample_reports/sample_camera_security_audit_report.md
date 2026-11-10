# BÁO CÁO THỰC NGHIỆM AN TOÀN BẢO MẬT & MẬT MÃ CAMERA IP

- **Địa chỉ IP thiết bị (DUT)**: `192.168.1.100`
- **Thời gian đo kiểm**: `2026-11-03 10:36:37`

## 1. Danh sách Dịch vụ & Cổng mạng phát hiện

| Cổng | Giao vận | Dịch vụ nhận diện | Mã hóa | Chi tiết |
| :--- | :--- | :--- | :--- | :--- |
| 22 | TCP | SSH/SFTP | Cleartext | Dịch vụ dòng lệnh SSH / SFTP |
| 322 | TCP | RTSPS (TLS) | TLS | Luồng video mã hóa TLS (AXIS / Chuẩn RFC 2326) |
| 443 | TCP | HTTPS (Web/ONVIF) | TLS | Giao diện Web bảo mật / ONVIF HTTPS |

## 2. Mã hóa đường truyền & Cipher Suites (TLS / SOGIS ACM)

### Cổng TCP 443:
- **Khóa công khai**: `ECC secp256r1 (256 bits)`
- **Thuật toán chữ ký**: `ecdsa-with-SHA256`
- **Thời hạn**: `2025-10-01 19:50:33 UTC -> 9999-12-31 23:59:59 UTC` (`HỢP LỆ (Còn hạn)`)

| Tên Bộ mã (Cipher Suite) | Giao thức | Trao đổi khóa (KEX) | Mã hóa / MAC | Chuẩn SOGIS ACM |
| :--- | :--- | :--- | :--- | :--- |
| `TLS_AES_128_GCM_SHA256` | TLSv1.3 | ECDHE/DHE | AES-128-GCM / AEAD | **R** |
| `TLS_AES_256_GCM_SHA384` | TLSv1.3 | ECDHE/DHE | AES-256-GCM / AEAD | **R** |
| `TLS_AES_128_CCM_SHA256` | TLSv1.3 | ECDHE/DHE | AES-128-CCM / AEAD | **L** |
| `ECDHE-ECDSA-AES256-GCM-SHA384` | TLSv1.2 | ECDHE | AES-256-GCM / AEAD | **R** |
| `ECDHE-ECDSA-AES256-CCM` | TLSv1.2 | ECDHE | CBC/GCM / AEAD | **NR** |
| `ECDHE-ECDSA-AES128-GCM-SHA256` | TLSv1.2 | ECDHE | AES-128-GCM / AEAD | **R** |
| `ECDHE-ECDSA-AES128-CCM` | TLSv1.2 | ECDHE | CBC/GCM / AEAD | **NR** |
### Cổng TCP 322:
- **Khóa công khai**: `ECC secp256r1 (256 bits)`
- **Thuật toán chữ ký**: `ecdsa-with-SHA256`
- **Thời hạn**: `2025-10-01 19:50:33 UTC -> 9999-12-31 23:59:59 UTC` (`HỢP LỆ (Còn hạn)`)

| Tên Bộ mã (Cipher Suite) | Giao thức | Trao đổi khóa (KEX) | Mã hóa / MAC | Chuẩn SOGIS ACM |
| :--- | :--- | :--- | :--- | :--- |
| `TLS_AES_128_GCM_SHA256` | TLSv1.3 | ECDHE/DHE | AES-128-GCM / AEAD | **R** |
| `TLS_AES_256_GCM_SHA384` | TLSv1.3 | ECDHE/DHE | AES-256-GCM / AEAD | **R** |
| `TLS_AES_128_CCM_SHA256` | TLSv1.3 | ECDHE/DHE | AES-128-CCM / AEAD | **L** |
| `ECDHE-ECDSA-AES256-GCM-SHA384` | TLSv1.2 | ECDHE | AES-256-GCM / AEAD | **R** |
| `ECDHE-ECDSA-AES256-CCM` | TLSv1.2 | ECDHE | CBC/GCM / AEAD | **NR** |
| `ECDHE-ECDSA-AES128-GCM-SHA256` | TLSv1.2 | ECDHE | AES-128-GCM / AEAD | **R** |
| `ECDHE-ECDSA-AES128-CCM` | TLSv1.2 | ECDHE | CBC/GCM / AEAD | **NR** |

## 3. Cơ chế Xác thực (Authentication Schemes)

### 3.1. Giao thức RTSP Kênh rõ (Cổng 554):
- **Trạng thái cổng**: ĐÓNG / VÔ HIỆU HÓA (An toàn)

### 3.2. Giao thức RTSPS Kênh mã hóa TLS (Cổng 322):
- **Trạng thái cổng**: MỞ
- **Mã hóa đường truyền**: Bọc mã hóa TLS 1.3 toàn vẹn
- **Digest Auth**: Không
- **Basic Auth (trong TLS)**: Có hỗ trợ
- **Thử nghiệm cấp quyền phát luồng (SDP)**: THÀNH CÔNG (200 OK)
- **Tiêu đề nguyên văn**:
  - `WWW-Authenticate: Basic realm="AXIS_E82725399C13"`

## 4. Giao thức Quản trị SNMP-V3 (Cổng UDP 161)


## 5. Hồ sơ Độ trễ & Giới hạn tần suất phản hồi (Rate Limiting)

- **Số lần thử nghiệm liên tiếp**: 5 lần
- **Độ trễ các lần (ms)**: `[188.9, 189.21, 189.3, 188.45, 188.06]`
- **Độ trễ trung bình**: `188.78 ms`
- **Cơ chế làm chậm (Rate Limiting Delay)**: Không áp đặt độ trễ

## 6. BẰNG CHỨNG KỸ THUẬT NGUYÊN VĂN (RAW PROTOCOL RESPONSES & COMMAND OUTPUTS)

Toàn bộ cụm phản hồi thực tế và output câu lệnh thu được từ camera phục vụ làm bằng chứng đối soát khách quan:

### 6.4. Cụm phản hồi RTSPS Port 322 qua TLS (Bằng chứng Thách thức xác thực):
- **Wireshark Filter/Sort**: `tcp.port == 322 && (tls || rtsp.status == 401)` *(Nếu giải mã TLS: `rtsp.status == 401`)*
```http
DESCRIBE rtsp://192.168.1.100:322/axis-media/media.amp RTSP/1.0
CSeq: 1
User-Agent: SecurityAuditClient/1.0


```
```http
RTSP/1.0 401 Unauthorized
CSeq: 1
WWW-Authenticate: Basic realm="AXIS_E82725399C13"
Server: GStreamer RTSP server
Date: Tue, 03 Nov 2026 03:36:48 GMT


```

### 6.5. Cụm phản hồi RTSPS Port 322 qua TLS khi gửi xác thực đúng (Bằng chứng Cấp quyền phát luồng SDP):
- **Wireshark Filter/Sort**: `tcp.port == 322 && (tls || rtsp.status == 200)` *(Nếu giải mã TLS: `rtsp.status == 200 && rtsp.content_type contains "sdp"`)*
```http
DESCRIBE rtsp://192.168.1.100:322/axis-media/media.amp RTSP/1.0
CSeq: 2
Authorization: Basic YWRtaW46UHNpdGVzdDEzNSMj
User-Agent: SecurityAuditClient/1.0


```
```http
RTSP/1.0 200 OK
CSeq: 2
Content-Type: application/sdp
Content-Base: rtsp://192.168.1.100:322/axis-media/media.amp/
Server: GStreamer RTSP server
Date: Tue, 03 Nov 2026 03:36:49 GMT
Content-Length: 1034


```

### 6.6. Toàn văn Output lệnh OpenSSL s_client TLS 1.3 (Cổng 443):
- **Wireshark Filter/Sort**: `tcp.port == 443 && (tls.handshake.type == 1 || tls.handshake.type == 2)`
```bash
$ openssl s_client -connect 192.168.1.100:443 -tls1_3
```
```text
Connecting to 192.168.1.100
Can't use SSL_get_servername
depth=2 O=Axis Communications AB, CN=Axis device ID Root CA ECC
verify error:num=19:self-signed certificate in certificate chain
verify return:1
depth=2 O=Axis Communications AB, CN=Axis device ID Root CA ECC
verify return:1
depth=1 O=Axis Communications AB, CN=Axis device ID Intermediate CA ECC 2
verify return:1
depth=0 C=SE, L=Lund, O=Axis Communications AB, CN=axis-e82725399c13-eccp256-1, serialNumber=e82725399c13
verify return:1
CONNECTED(00000003)
---
Certificate chain
 0 s:C=SE, L=Lund, O=Axis Communications AB, CN=axis-e82725399c13-eccp256-1, serialNumber=e82725399c13
   i:O=Axis Communications AB, CN=Axis device ID Intermediate CA ECC 2
   a:PKEY: EC, (prime256v1); sigalg: ecdsa-with-SHA256
   v:NotBefore: Oct  1 19:50:33 2025 GMT; NotAfter: Dec 31 23:59:59 9999 GMT
 1 s:O=Axis Communications AB, CN=Axis device ID Intermediate CA ECC 2
   i:O=Axis Communications AB, CN=Axis device ID Root CA ECC
   a:PKEY: EC, (prime256v1); sigalg: ecdsa-with-SHA256
   v:NotBefore: Oct 26 09:08:53 2020 GMT; NotAfter: Jun  1 12:00:00 2055 GMT
 2 s:O=Axis Communications AB, CN=Axis device ID Root CA ECC
   i:O=Axis Communications AB, CN=Axis device ID Root CA ECC
   a:PKEY: EC, (prime256v1); sigalg: ecdsa-with-SHA256
   v:NotBefore: Apr 29 15:16:33 2020 GMT; NotAfter: Jun  1 12:00:00 2060 GMT
---
Server certificate
-----BEGIN CERTIFICATE-----
MIICLzCCAdWgAwIBAgIUNhr1ofLYqMII3V79Pa+xwPGXJ1owCgYIKoZIzj0EAwIw
UDEfMB0GA1UEChMWQXhpcyBDb21tdW5pY2F0aW9ucyBBQjEtMCsGA1UEAxMkQXhp
cyBkZXZpY2UgSUQgSW50ZXJtZWRpYXRlIENBIEVDQyAyMCAXDTI1MTAwMTE5NTAz
M1oYDzk5OTkxMjMxMjM1OTU5WjB6MQswCQYDVQQGEwJTRTENMAsGA1UEBxMETHVu
ZDEfMB0GA1UEChMWQXhpcyBDb21tdW5pY2F0aW9ucyBBQjEkMCIGA1UEAxMbYXhp
cy1lODI3MjUzOTljMTMtZWNjcDI1Ni0xMRUwEwYDVQQFEwxlODI3MjUzOTljMTMw
WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAR4/i8lkTbn+lX1nbWEOA+9mW6LtpxR
qhisaKUqXbirE+UAwptQpdy7Mx7Es+cbYIK4PtVhwRYoiq94NylkcFBWo2EwXzA8
BgNVHREENTAzoDEGCCsGAQUFBwgEoCUwIwYNKwYBBAGB22mm8SUIAgQSBABQAfHd
NK6uzBIEZDmCvyKQMB8GA1UdIwQYMBaAFBL0rsfryC41V2rGN/sLEpzpA6HsMAoG
CCqGSM49BAMCA0gAMEUCIBlPtCRZRHc7wg2KbFduNIREvzh51F1wV1f8CfwMkM32
AiEAtcpkRIt+P0W/aB0LbJyUXpykBrjSZf02qbFUNxB8OXM=
-----END CERTIFICATE-----
subject=C=SE, L=Lund, O=Axis Communications AB, CN=axis-e82725399c13-eccp256-1, serialNumber=e82725399c13
issuer=O=Axis Communications AB, CN=Axis device ID Intermediate CA ECC 2
---
No client certificate CA names sent
Peer signing digest: SHA256
Peer signature type: ecdsa_secp256r1_sha256
Negotiated TLS1.3 group: X25519MLKEM768
---
SSL handshake has read 3047 bytes and written 1544 bytes
Verification error: self-signed certificate in certificate chain
---
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
Protocol: TLSv1.3
Server public key is 256 bit
This TLS version forbids renegotiation.
Compression: NONE
Expansion: NONE
No ALPN negotiated
Early data was not sent
Verify return code: 19 (self-signed certificate in certificate chain)
---
DONE
```

## 7. Bằng chứng Gói tin Wireshark & Tệp PCAP Đối Soát Thực Nghiệm

- **Tệp PCAP Toàn bộ bài đo kiểm Master Audit**: `captures/master_security_audit_20261103_103636.pcap`
  - *Lệnh mở trực tiếp*: `wireshark captures/master_security_audit_20261103_103636.pcap`
- **Tệp Khóa giải mã TLS 1.3 (Master Secret)**: `captures/sslkeys.log`

### Bảng Danh Mục Bộ Lọc Wireshark (Display Filters) Theo Từng Giao Thức:

| Giao thức / Mục tiêu đo kiểm | Bộ lọc Display Filter Wireshark | Ý nghĩa bằng chứng kỹ thuật |
| :--- | :--- | :--- |
| **HTTP 80 Chuyển hướng** | `http.response.code == 302 \|\| (tcp.port == 80 && http)` | Bằng chứng ép chuyển hướng sang HTTPS |
| **HTTPS 443 Handshake** | `tcp.port == 443 && (tls.handshake.type == 1 \|\| tls.handshake.type == 2)` | Bắt tay đàm phán bộ mã TLS 1.3 |
| **Chứng thư số X.509** | `tcp.port == 443 && tls.handshake.type == 11` | Chứng thư số máy chủ camera |
| **RTSP 554 401 Challenge** | `tcp.port == 554 && rtsp.status == 401` | Thách thức xác thực rõ |
| **RTSP 554 Basic Auth** | `tcp.port == 554 && (rtsp.authorization contains "Basic" \|\| rtsp.status == 200)` | Bằng chứng gửi & chấp nhận mật khẩu rõ |
| **RTSPS 322 Encrypted TLS** | `tcp.port == 322 && tls` | Toàn bộ luồng video được bọc TLS 1.3 |
| **RTSPS 322 Auth Challenge** | `rtsp.status == 401` | Sau khi nạp file sslkeys.log để giải mã |
| **RTSPS 322 Cấp luồng 200 OK** | `rtsp.status == 200 && rtsp.content_type contains "sdp"` | Cấp phép truyền luồng video SDP |
| **SNMPv3 Mức authPriv** | `snmp.msgFlags.auth == 1 && snmp.msgFlags.priv == 1` | Gói tin SNMPv3 bảo mật mức cao nhất |
| **SNMPv3 Phản hồi sysDescr** | `snmp.version == 3 && snmp.error_status == 0` | Truy vấn MIB thành công |

> **Hướng dẫn Sort trong Wireshark**: Click tiêu đề cột **`No.`** hoặc **`Time`** để sắp xếp gói tin theo thứ tự phát sinh, hoặc nhấn **`Ctrl + G`** để nhảy trực tiếp tới số thứ tự gói tin cần đối soát.

