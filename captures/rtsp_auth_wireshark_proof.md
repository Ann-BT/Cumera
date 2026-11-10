# BÁO CÁO THỰC NGHIỆM KẾT NỐI & XÁC THỰC LUỒNG VIDEO RTSP/RTSPS

- **Mục tiêu đo kiểm (DUT)**: `192.168.20.38`
- **Thời gian**: `2026-11-10 17:28:04`
- **Tiêu chuẩn**: QCVN 11:2026/BCA & RFC 7616 / RFC 2326

## 1. Bảng Tổng Hợp Kết Quả Đo Kiểm Các Phương Thức Xác Thực

| STT | Phương thức xác thực | Cổng / Kênh truyền | Mã trạng thái | Luồng RTP Video | File Bắt Gói Tin PCAP | Đánh giá |
| :--- | :--- | :--- | :---: | :---: | :--- | :---: |
| 1 | **DIGEST_SHA256** | TCP 322 (TLS) | `200 OK` | Nhận SDP | `rtsp_digest_sha256_port322_20261110_172759.pcap` | **TỪ CHỐI** |
| 2 | **BASIC** | TCP 322 (TLS) | `200 OK` | Nhận SDP | `rtsp_basic_port322_20261110_172759.pcap` | **ĐẠT (PASS)** |
| 3 | **DIGEST_MD5** | TCP 322 (TLS) | `200 OK` | Nhận SDP | `rtsp_digest_md5_port322_20261110_172759.pcap` | **TỪ CHỐI** |

## 2. Toàn Văn Bóc Tách Gói Tin Wireshark (Packet Dissection Proof)

### 2.1. Phương thức: DIGEST_SHA256 (Cổng 322)

#### Các cụm phản hồi nguyên văn làm bằng chứng kỹ thuật:
**[OPTIONS]**
```http
OPTIONS rtsp://192.168.20.38:322/axis-media/media.amp RTSP/1.0
CSeq: 1
User-Agent: QCVN11-Wireshark-Verifier/1.0


```
```http
RTSP/1.0 200 OK
CSeq: 1
Public: OPTIONS, DESCRIBE, ANNOUNCE, GET_PARAMETER, PAUSE, PLAY, RECORD, SETUP, SET_PARAMETER, TEARDOWN
Server: GStreamer RTSP server
Date: Tue, 10 Nov 2026 10:28:00 GMT
```

**[DESCRIBE (Thăm dò không mật khẩu)]**
```http
DESCRIBE rtsp://192.168.20.38:322/axis-media/media.amp RTSP/1.0
CSeq: 2
User-Agent: QCVN11-Wireshark-Verifier/1.0


```
```http
RTSP/1.0 401 Unauthorized
CSeq: 2
WWW-Authenticate: Basic realm="AXIS_E82725399C13"
Server: GStreamer RTSP server
Date: Tue, 10 Nov 2026 10:28:00 GMT
```

**[DESCRIBE (Xác thực digest_sha256)]**
```http
DESCRIBE rtsp://192.168.20.38:322/axis-media/media.amp RTSP/1.0
CSeq: 3
Authorization: Digest username="admin", realm="AXIS_E82725399C13", nonce="", uri="rtsp://192.168.20.38:322/axis-media/media.amp", response="3c1aa81962c18650f708b88f191a37065fa108583111fe04d1c84508e68109c3", algorithm="SHA-256"
User-Agent: QCVN11-Wireshark-Verifier/1.0


```
```http
RTSP/1.0 401 Unauthorized
CSeq: 3
WWW-Authenticate: Basic realm="AXIS_E82725399C13"
Server: GStreamer RTSP server
Date: Tue, 10 Nov 2026 10:28:00 GMT
```

### 2.2. Phương thức: BASIC (Cổng 322)

#### Bảng Chỉ Mục Bằng Chứng Gói Tin & Câu Lệnh Filter/Sort Wireshark:

| Gói tin (Frame #) | Hành vi / Bằng chứng đo kiểm | Bộ lọc Wireshark (Display Filter) | Câu lệnh tshark CLI |
| :---: | :--- | :--- | :--- |
| **Packet #12** | Client gửi yêu cầu OPTIONS | `frame.number == 12 || rtsp.method == "OPTIONS"` | `tshark -r rtsp_basic_port322_20261110_172759.pcap -Y "frame.number == 12" -V` |
| **Packet #17** | Camera phản hồi OPTIONS 200 OK (Public methods) | `frame.number == 17 || (rtsp.status == 200 && rtsp.cseq == 1)` | `tshark -r rtsp_basic_port322_20261110_172759.pcap -Y "frame.number == 17" -V` |
| **Packet #18** | Client gửi DESCRIBE thăm dò (không auth) | `frame.number == 18 || (rtsp.method == "DESCRIBE" && rtsp.cseq == 2)` | `tshark -r rtsp_basic_port322_20261110_172759.pcap -Y "frame.number == 18" -V` |
| **Packet #19** | Camera thách thức 401 Unauthorized (Chứa Nonce/Realm/Digest) | `frame.number == 19 || rtsp.status == 401` | `tshark -r rtsp_basic_port322_20261110_172759.pcap -Y "frame.number == 19" -V` |
| **Packet #20** | Client gửi DESCRIBE kèm Authorization Header (Digest SHA-256/Basic) | `frame.number == 20 || (rtsp.method == "DESCRIBE" && rtsp.cseq == 3)` | `tshark -r rtsp_basic_port322_20261110_172759.pcap -Y "frame.number == 20" -V` |

> [!TIP]
> **Cách kiểm tra & sắp xếp trong Wireshark**:
> - **Nhảy đến gói tin**: Bấm `Ctrl + G` và nhập số gói tin (ví dụ: `9`).
> - **Lọc bằng Display Filter**: Dán cú pháp vào thanh filter (ví dụ: `frame.number == 9` hoặc `rtsp.status == 401`).
> - **Sắp xếp theo thứ tự (Sort)**: Click chuột vào tiêu đề cột **`No.`** để sắp xếp tăng/giảm dần theo thứ tự phát sinh gói tin.

```text
No.   Time           Source           Destination      Protocol Length Info
-------------------------------------------------------------------------------------
12	0.181387589	192.168.20.45	192.168.20.38	RTSP	206	OPTIONS rtsp://192.168.20.38:322/axis-media/media.amp RTSP/1.0
17	0.185670917	192.168.20.38	192.168.20.45	RTSP	289	Reply: RTSP/1.0 200 OK
18	0.185855957	192.168.20.45	192.168.20.38	RTSP	207	DESCRIBE rtsp://192.168.20.38:322/axis-media/media.amp RTSP/1.0
19	0.188853048	192.168.20.38	192.168.20.45	RTSP	245	Reply: RTSP/1.0 401 Unauthorized
20	0.189123009	192.168.20.45	192.168.20.38	RTSP	254	DESCRIBE rtsp://192.168.20.38:322/axis-media/media.amp RTSP/1.0
```

#### Các cụm phản hồi nguyên văn làm bằng chứng kỹ thuật:
**[OPTIONS]**
```http
OPTIONS rtsp://192.168.20.38:322/axis-media/media.amp RTSP/1.0
CSeq: 1
User-Agent: QCVN11-Wireshark-Verifier/1.0


```
```http
RTSP/1.0 200 OK
CSeq: 1
Public: OPTIONS, DESCRIBE, ANNOUNCE, GET_PARAMETER, PAUSE, PLAY, RECORD, SETUP, SET_PARAMETER, TEARDOWN
Server: GStreamer RTSP server
Date: Tue, 10 Nov 2026 10:28:01 GMT
```

**[DESCRIBE (Thăm dò không mật khẩu)]**
```http
DESCRIBE rtsp://192.168.20.38:322/axis-media/media.amp RTSP/1.0
CSeq: 2
User-Agent: QCVN11-Wireshark-Verifier/1.0


```
```http
RTSP/1.0 401 Unauthorized
CSeq: 2
WWW-Authenticate: Basic realm="AXIS_E82725399C13"
Server: GStreamer RTSP server
Date: Tue, 10 Nov 2026 10:28:01 GMT
```

**[DESCRIBE (Xác thực basic)]**
```http
DESCRIBE rtsp://192.168.20.38:322/axis-media/media.amp RTSP/1.0
CSeq: 3
Authorization: Basic YWRtaW46UHNpdGVzdDEzNSMj
User-Agent: QCVN11-Wireshark-Verifier/1.0


```
```http
RTSP/1.0 200 OK
CSeq: 3
Content-Type: application/sdp
Content-Base: rtsp://192.168.20.38:322/axis-media/media.amp/
Server: GStreamer RTSP server
Date: Tue, 10 Nov 2026 10:28:02 GMT
Content-Length: 1035

v=0
o=- 15920754599928482188 1 IN IP4 192.168.20.38
s=Session streamed with GStreamer
i=rtsp-server
t=0 0
a=tool:GStreamer
a=type:broadcast
a=range:npt=now-
a=control:rtsp://192.168.20.38:322/axis-media/media.amp
m=video 0 RTP/SAVP 96
c=IN IP4 0.0.0.0
b=AS:135000
a=rtpmap:96 H264/90000
a=framerate:30
a=fmtp:96 packetization-mode=1;sprop-parameter-sets=Z2QAMq0AxSALQDN+ebgICA0oADbugAzf5gB4QCFQ,aO48sA==;profile-level-id=640032;level-asymmetry-allowed=1
a=key-mgmt:mikey AQAFABCZICoBAACnM68fAAAAAAsA7p1wMnRIjGAKEIlxgdXc3rSpnvYMIGZDr9QBAAAAFQABAQEBEAIBAQMBCgcBAQgBAQoBAQAAACIAIAAelUkW3Km4Lw+GwalcqIPlNk2UDNRXQwMM9iDLm3+NAA==
a=ts-refclk:local
a=mediaclk:sender
a=ssrc:2805182239 cname:user3912074090@host-6c0ba70a
a=x-onvif-track:VIDEO000
a=recvonly
a=control:rtsp://192.168.20.38:322/axis-media/media.amp/stream=0
a=transform:1.000000,0.000000,0.000000;0.000000,1.000000,0.000000;0.000000,0.000000,1.000000
a=x-sensor-transform:-1.000000,0.000000,0.000000;0.000000,-1.000000,0.000000;0.000000,0.000000,1.000000
```

**[SETUP (Kênh Interleaved TCP)]**
```http
SETUP rtsp://192.168.20.38:322/axis-media/media.amp/track1 RTSP/1.0
CSeq: 4
Authorization: Basic YWRtaW46UHNpdGVzdDEzNSMj
Transport: RTP/AVP/TCP;unicast;interleaved=0-1
User-Agent: QCVN11-Wireshark-Verifier/1.0


```
```http
RTSP/1.0 404 Not Found
CSeq: 4
Server: GStreamer RTSP server
Date: Tue, 10 Nov 2026 10:28:02 GMT
```

### 2.3. Phương thức: DIGEST_MD5 (Cổng 322)

#### Các cụm phản hồi nguyên văn làm bằng chứng kỹ thuật:
**[OPTIONS]**
```http
OPTIONS rtsp://192.168.20.38:322/axis-media/media.amp RTSP/1.0
CSeq: 1
User-Agent: QCVN11-Wireshark-Verifier/1.0


```
```http
RTSP/1.0 200 OK
CSeq: 1
Public: OPTIONS, DESCRIBE, ANNOUNCE, GET_PARAMETER, PAUSE, PLAY, RECORD, SETUP, SET_PARAMETER, TEARDOWN
Server: GStreamer RTSP server
Date: Tue, 10 Nov 2026 10:28:03 GMT
```

**[DESCRIBE (Thăm dò không mật khẩu)]**
```http
DESCRIBE rtsp://192.168.20.38:322/axis-media/media.amp RTSP/1.0
CSeq: 2
User-Agent: QCVN11-Wireshark-Verifier/1.0


```
```http
RTSP/1.0 401 Unauthorized
CSeq: 2
WWW-Authenticate: Basic realm="AXIS_E82725399C13"
Server: GStreamer RTSP server
Date: Tue, 10 Nov 2026 10:28:03 GMT
```

**[DESCRIBE (Xác thực digest_md5)]**
```http
DESCRIBE rtsp://192.168.20.38:322/axis-media/media.amp RTSP/1.0
CSeq: 3
Authorization: Digest username="admin", realm="AXIS_E82725399C13", nonce="", uri="rtsp://192.168.20.38:322/axis-media/media.amp", response="5f8a8dba1b0ffe67a3b3c9815eb45bc9", algorithm="MD5"
User-Agent: QCVN11-Wireshark-Verifier/1.0


```
```http
RTSP/1.0 401 Unauthorized
CSeq: 3
WWW-Authenticate: Basic realm="AXIS_E82725399C13"
Server: GStreamer RTSP server
Date: Tue, 10 Nov 2026 10:28:03 GMT
```

