# BÁO CÁO THỰC NGHIỆM KẾT NỐI & XÁC THỰC LUỒNG VIDEO RTSP/RTSPS

- **Mục tiêu đo kiểm (DUT)**: `192.168.20.38`
- **Thời gian**: `2026-11-10 14:45:40`
- **Tiêu chuẩn**: QCVN 11:2026/BCA & RFC 7616 / RFC 2326

## 1. Bảng Tổng Hợp Kết Quả Đo Kiểm Các Phương Thức Xác Thực

| STT | Phương thức xác thực | Cổng / Kênh truyền | Mã trạng thái | Luồng RTP Video | File Bắt Gói Tin PCAP | Đánh giá |
| :--- | :--- | :--- | :---: | :---: | :--- | :---: |
| 1 | **BASIC** | TCP 322 (TLS) | `200 OK` | Nhận SDP | `rtsp_basic_port322_20261110_144538.pcap` | **ĐẠT (PASS)** |

## 2. Toàn Văn Bóc Tách Gói Tin Wireshark (Packet Dissection Proof)

### 2.1. Phương thức: BASIC (Cổng 322)

#### Bảng Chỉ Mục Bằng Chứng Gói Tin & Câu Lệnh Filter/Sort Wireshark:

| Gói tin (Frame #) | Hành vi / Bằng chứng đo kiểm | Bộ lọc Wireshark (Display Filter) | Câu lệnh tshark CLI |
| :---: | :--- | :--- | :--- |
| **Packet #11** | Client gửi yêu cầu OPTIONS | `frame.number == 11 || rtsp.method == "OPTIONS"` | `tshark -r rtsp_basic_port322_20261110_144538.pcap -Y "frame.number == 11" -V` |
| **Packet #16** | Camera phản hồi OPTIONS 200 OK (Public methods) | `frame.number == 16 || (rtsp.status == 200 && rtsp.cseq == 1)` | `tshark -r rtsp_basic_port322_20261110_144538.pcap -Y "frame.number == 16" -V` |
| **Packet #17** | Client gửi DESCRIBE thăm dò (không auth) | `frame.number == 17 || (rtsp.method == "DESCRIBE" && rtsp.cseq == 2)` | `tshark -r rtsp_basic_port322_20261110_144538.pcap -Y "frame.number == 17" -V` |
| **Packet #18** | Camera thách thức 401 Unauthorized (Chứa Nonce/Realm/Digest) | `frame.number == 18 || rtsp.status == 401` | `tshark -r rtsp_basic_port322_20261110_144538.pcap -Y "frame.number == 18" -V` |
| **Packet #19** | Client gửi DESCRIBE kèm Authorization Header (Digest SHA-256/Basic) | `frame.number == 19 || (rtsp.method == "DESCRIBE" && rtsp.cseq == 3)` | `tshark -r rtsp_basic_port322_20261110_144538.pcap -Y "frame.number == 19" -V` |

> [!TIP]
> **Cách kiểm tra & sắp xếp trong Wireshark**:
> - **Nhảy đến gói tin**: Bấm `Ctrl + G` và nhập số gói tin (ví dụ: `9`).
> - **Lọc bằng Display Filter**: Dán cú pháp vào thanh filter (ví dụ: `frame.number == 9` hoặc `rtsp.status == 401`).
> - **Sắp xếp theo thứ tự (Sort)**: Click chuột vào tiêu đề cột **`No.`** để sắp xếp tăng/giảm dần theo thứ tự phát sinh gói tin.

```text
No.   Time           Source           Destination      Protocol Length Info
-------------------------------------------------------------------------------------
11	0.184783689	192.168.20.45	192.168.20.38	RTSP	206	OPTIONS rtsp://192.168.20.38:322/axis-media/media.amp RTSP/1.0
16	0.188734016	192.168.20.38	192.168.20.45	RTSP	289	Reply: RTSP/1.0 200 OK
17	0.189252962	192.168.20.45	192.168.20.38	RTSP	207	DESCRIBE rtsp://192.168.20.38:322/axis-media/media.amp RTSP/1.0
18	0.192215798	192.168.20.38	192.168.20.45	RTSP	245	Reply: RTSP/1.0 401 Unauthorized
19	0.192887753	192.168.20.45	192.168.20.38	RTSP	254	DESCRIBE rtsp://192.168.20.38:322/axis-media/media.amp RTSP/1.0
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
Date: Tue, 10 Nov 2026 07:45:39 GMT
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
Date: Tue, 10 Nov 2026 07:45:39 GMT
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
Date: Tue, 10 Nov 2026 07:45:39 GMT
Content-Length: 1034

v=0
o=- 14380002297575571726 1 IN IP4 192.168.20.38
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
a=key-mgmt:mikey AQAFAOXr/NIBAADGbOPUAAAAAAsA7p1KI8+l41MKEEE7u0nm35r9kiVBTxrFJNUBAAAAFQABAQEBEAIBAQMBCgcBAQgBAQoBAQAAACIAIAAeVafz6/59NNZqWyCrvLD1q7kw3I7PO0pTUrsdlCerAA==
a=ts-refclk:local
a=mediaclk:sender
a=ssrc:3329024980 cname:user3006422813@host-8f717dd
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
Date: Tue, 10 Nov 2026 07:45:39 GMT
```

