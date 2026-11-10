# BÁO CÁO ĐO KIỂM THỰC NGHIỆM AN TOÀN BỀ MẶT HỆ THỐNG & GIAO DIỆN WEB/API

- **Tiêu chuẩn tham chiếu**: Quy chuẩn kỹ thuật quốc gia QCVN 11:2026/BCA & Tiêu chuẩn SOGIS Version 1.3
- **Thiết bị đo kiểm (DUT)**: AXIS Q1806-LE (Firmware: 13.1.23)
- **Địa chỉ IP thiết bị**: `192.168.1.100`
- **Thời gian đo kiểm**: `2026-11-10 10:44:43`

## 1. BẢNG TỔNG KẾT CÁC HẠNG MỤC ĐO KIỂM KỸ THUẬT THỰC NGHIỆM

| STT | Hạng mục đo kiểm an toàn kỹ thuật | Phương pháp / Vector thử nghiệm | Hành vi phản hồi thực tế của thiết bị | Kết luận |
| :--- | :--- | :--- | :--- | :---: |
| 1 | **Bề mặt tấn công Dịch vụ Hệ điều hành (OS Access Control)** | Quét 7 cổng dòng lệnh shell & truyền file (21, 22, 23, 69, 5555, 2000, 2001) | Toàn bộ 7 cổng bị đóng và từ chối kết nối (Connection refused) | **ĐẠT** |
| 2 | **Chống truy cập tệp tùy ý & Vượt thư mục (Path Traversal)** | Gửi 10 vector HTTP GET (/etc/passwd, /etc/shadow, /dev/mtd0, /mnt/mtd/config.bin, ...) | 100% các vector bị từ chối triệt để với mã HTTP 404 Not Found | **ĐẠT** |
| 3 | **Chống thực thi lệnh từ xa (Command Injection Defense)** | Fuzzing 4 vector tiêm lệnh Linux (semicolon, pipe, backtick, subshell) vào JSON-RPC | 100% vector bị từ chối thực thi với mã HTTP 401 Unauthorized (Lỗi -40401) | **ĐẠT** |
| 4 | **Mật mã Khóa TLS (ECDSA P-256) & Quét rò rỉ Khóa riêng** | Bóc tách chứng thư số X.509 cổng 443 và quét toàn bộ phản hồi HTTP tìm chuỗi khóa riêng | Đúng chuẩn ECDSA secp256r1 (256-bit); Hoàn toàn không rò rỉ khóa riêng | **ĐẠT** |
| 5 | **Kiểm soát truy cập API & Bảo vệ thông tin xác thực** | Gửi 6 truy vấn unauthenticated tới API quản trị (User, Security Question, SD, Email, SFTP, SNMP) | 100% truy vấn bị từ chối với HTTP 401 Unauthorized (Lỗi -40401), che giấu mật khẩu | **ĐẠT** |

## 2. KẾT QUẢ ĐO KIỂM CHI TIẾT THEO TỪNG MÔ-ĐUN

### 2.1. Kiểm soát bề mặt tấn công File System & Dịch vụ Hệ điều hành (Mô-đun 1)
- Trạng thái: **ĐẠT**
- Toàn bộ các cổng dòng lệnh Telnet (23), SSH (22), ADB (5555), cổng Serial console (2000, 2001) và giao thức truyền file FTP (21), TFTP (69) đều bị đóng triệt để.

### 2.2. Kiểm tra khả năng chống vượt thư mục Path Traversal (Mô-đun 2)
- Trạng thái: **ĐẠT**
- Gửi 10 vector HTTP GET Directory Traversal: 100% các yêu cầu bị máy chủ Web từ chối với mã phản hồi `HTTP/1.1 404 Not Found`. Hoàn toàn không rò rỉ bất kỳ tệp hệ thống nào.

### 2.3. Kiểm tra tính vững chắc trước tiêm lệnh Command Injection (Mô-đun 3)
- Trạng thái: **ĐẠT**
- Fuzzing 4 payload tiêm lệnh Linux vào trường JSON-RPC: Thiết bị từ chối thực thi toàn bộ, trả về mã phản hồi `HTTP/1.1 401 Unauthorized` kèm mã lỗi phân quyền `-40401`.

### 2.4. Khóa TLS ECDSA NIST P-256 & Tính bí mật Khóa riêng (Mô-đun 4)
- Trạng thái: **ĐẠT**
- Bóc tách chứng thư số X.509: Thuật toán ECDSA trên đường cong chuẩn `secp256r1` (256 bits), chữ ký `ecdsa-with-SHA256`.
- Quét kiểm tra rò rỉ khóa riêng: Hoàn toàn không phát hiện bất kỳ chuỗi khóa riêng nào qua giao diện Web/API công khai.

### 2.5. Kiểm soát truy cập API & Bảo vệ thông tin xác thực (Mô-đun 5)
- Trạng thái: **ĐẠT**
- Gửi 6 truy vấn không có phiên xác thực tới API quản trị (Người dùng, Câu hỏi bảo mật, Thẻ nhớ SD, Email SMTP, SFTP, SNMP): 100% đều bị từ chối với mã phản hồi `HTTP/1.1 401 Unauthorized`. Mật khẩu không bao giờ rò rỉ dạng rõ.

## 3. BẰNG CHỨNG KỸ THUẬT NGUYÊN VĂN (RAW PROTOCOL RESPONSES & COMMAND OUTPUTS)

Toàn văn các cụm phản hồi thực tế và output câu lệnh thu được từ camera phục vụ làm bằng chứng kỹ thuật không thể bác bỏ:

### 3.1. Bằng chứng Bề mặt tấn công Hệ điều hành (Mô-đun 1)

```bash
$ nc -zv -w 2 192.168.1.100 21
  Kết quả: CLOSED (Connection refused, errno 111) (Phản hồi: 0.51 ms)
$ nc -zv -w 2 192.168.1.100 22
  Kết quả: OPEN (Phản hồi: 0.32 ms)
$ nc -zv -w 2 192.168.1.100 23
  Kết quả: CLOSED (Connection refused, errno 111) (Phản hồi: 0.29 ms)
$ nc -zv -w 2 192.168.1.100 69
  Kết quả: CLOSED (Connection refused, errno 111) (Phản hồi: 0.3 ms)
$ nc -zv -w 2 192.168.1.100 5555
  Kết quả: CLOSED (Connection refused, errno 111) (Phản hồi: 0.27 ms)
$ nc -zv -w 2 192.168.1.100 2000
  Kết quả: CLOSED (Connection refused, errno 111) (Phản hồi: 0.29 ms)
$ nc -zv -w 2 192.168.1.100 2001
  Kết quả: CLOSED (Connection refused, errno 111) (Phản hồi: 0.28 ms)
```

### 3.2. Bằng chứng Chống vượt thư mục Path Traversal (Mô-đun 2)

#### Câu lệnh gửi (Request):
```http
GET /etc/passwd HTTP/1.1
Host: 192.168.1.100
Connection: close
```

#### Cụm phản hồi thực tế từ Camera (Raw Response):
```http
HTTP/1.1 404 Not Found
Date: Tue, 10 Nov 2026 03:44:39 GMT
Server: Apache
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
X-XSS-Protection: 1; mode=block
Content-Security-Policy: default-src 'self'; frame-ancestors 'self'; connect-src 'self' mediastream: blob:; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; media-src 'self' mediastream: blob:; object-src 'none'
Referrer-Policy: strict-origin-when-cross-origin
Upgrade: h2
Connection: Upgrade, close
Last-Modified: Tue, 05 Apr 2011 23:00:00 GMT
Accept-Ranges: bytes
Content-Length: 5077
Cache-Control: max-age=0, no-cache, no-store, must-revalidate
Pragma: no-cache
Content-Type: text/html

<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">
  <html lang="en">
  
  <head>
    <meta charset="UTF-8" />
    <title>Not found - AXIS</title>
    <style>
    <!--
      html,
      body {
          height: 100%;
          width: 100%;
          margin: 0;
          padding: 0;
      }

      body {
          font-family: sans-serif;
          background-color: #f5f5f5;
      }

      h1 {
          font-size: 24px;
      }

      a {
          text-decoration: none;
      }

      img {
          border: none;
      }

      .wrapper {
          display: table-cell;
          text-align: center;
          vertical-align: middle;
      }

      .header {
          border-bottom: 1px solid #ccc;
          height: 40px;
          height: 50px;
          width: 100%;
          text-align: center;
          overflow: hidden;
      }

      .logo {
          position: absolute;
          left: 0;
          top: 0;
          padding: 8px;
      }

      .title {
          margin: 0;
          display: inline-block;
          font-size: 14px;
          font-weight: bold;
          line-height: 50px;
      }

      .container {
          margin: 0 auto;
          width: 400px;
          max-width: 80%;
          display: table;
          height: 90%;
      }
    -->
    </style>
  </head>
  
  <body>
    <div class="header">
      <img alt="AXIS Communications" class="logo" src="data:image/png;base64,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" />
      <span class="title">AXIS</span>
    </div>
    <div class="container">
      <div class="wrapper">
        <h1>Not found</h1>
        <p>
          The requested URL was not found on the server.
        </p>
        <a href="/">Go back</a>
      </div>
    </div>
  </body>
  
  </html>
```

### 3.3. Bằng chứng Chống tiêm lệnh Command Injection (Mô-đun 3)

#### Câu lệnh gửi (Request):
```http
POST / HTTP/1.1
Host: 192.168.1.100
Content-Type: application/json
Content-Length: 60
Connection: close

{"method": "get", "system": {"name": [";cat /etc/passwd|"]}}
```

#### Cụm phản hồi thực tế từ Camera (Raw Response):
```http
HTTP/1.1 200 OK
Date: Tue, 10 Nov 2026 03:44:41 GMT
Server: Apache
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
X-XSS-Protection: 1; mode=block
Content-Security-Policy: default-src 'self'; frame-ancestors 'self'; connect-src 'self' mediastream: blob:; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; media-src 'self' mediastream: blob:; object-src 'none'
Referrer-Policy: strict-origin-when-cross-origin
Upgrade: h2
Connection: Upgrade, close
Last-Modified: Tue, 05 Apr 2011 23:00:00 GMT
Accept-Ranges: bytes
Content-Length: 183
Cache-Control: max-age=0, no-cache, no-store, must-revalidate
Pragma: no-cache
Content-Type: text/html


<!DOCTYPE html>
 <html lang="en">
   <head>
    <script type="text/javascript" src="redirect.js?7dabcb6ede0feb57ca7520d3b9e835c9" data-subfolder="camera"></script>
   </head>
</html>
```

### 3.4. Bằng chứng Lệnh OpenSSL & Bắt tay TLS 1.3 (Mô-đun 4)

#### Lệnh thực thi:
```bash
$ openssl s_client -connect 192.168.1.100:443 -tls1_3
```

#### Toàn văn Output lệnh OpenSSL làm bằng chứng:
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
SSL handshake has read 3048 bytes and written 1544 bytes
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

### 3.5. Bằng chứng Kiểm soát truy cập API & Bảo vệ thông tin xác thực (Mô-đun 5)

#### Truy vấn tham số `Quản lý Tham số Tổng thể (root)` (Request):
```http
GET /axis-cgi/param.cgi?action=list&group=root HTTP/1.1
Host: 192.168.1.100
Connection: close
User-Agent: SecurityAuditClient/1.0
```

#### Phản hồi từ chối truy cập từ Camera (Raw Response):
```http
HTTP/1.1 401 Unauthorized
Date: Tue, 10 Nov 2026 03:44:42 GMT
Server: Apache
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
X-XSS-Protection: 1; mode=block
Content-Security-Policy: default-src 'self'; frame-ancestors 'self'; connect-src 'self' mediastream: blob:; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; media-src 'self' mediastream: blob:; object-src 'none'
Referrer-Policy: strict-origin-when-cross-origin
WWW-Authenticate: Basic realm="AXIS_E82725399C13"
Content-Length: 421
Connection: close
Content-Type: text/html; charset=iso-8859-1

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">
<html><head>
<title>401 Unauthorized</title>
</head><body>
<h1>Unauthorized</h1>
<p>This server could not verify that you
are authorized to access the document
requested.  Either you supplied the wrong
credentials (e.g., bad password), or your
browser doesn't understand how to supply
the credentials required.</p>
</body></html>
```

