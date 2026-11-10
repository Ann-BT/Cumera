# BÁO CÁO ĐO KIỂM TOÀN DIỆN CÁC PHƯƠNG THỨC TRUYỀN THÔNG (ĐỘC LẬP IXIT)

- **Thiết bị đo kiểm (DUT)**: IP `192.168.1.100` (User: `admin`)
- **Máy đo kiểm (Test Host)**: IP `192.168.1.200`
- **Tiêu chuẩn áp dụng**: QCVN 11:2026/BCA & ETSI EN 303 645 (Clause 5.1-1, 5.1-2, 5.5-1, 5.6-1)
- **Thời điểm kiểm định**: 2026-11-10 16:53:31

## 1. BẢNG TỔNG HỢP KẾT QUẢ ĐỐI SOÁT CÁC PHƯƠNG THỨC TRUYỀN THÔNG

| STT | Phương thức / Tên dịch vụ | Cổng & Vai trò | Tấn công hạ cấp / Phân tích gói tin | Gói tin PCAP |
|:---|:---|:---|:---|:---:|
| **1** | SNMP Interface (UDP/161) | `IP/UDP/SNMP`<br>(DUT Server (Tool Probe)) | ĐẠT: Từ chối / Không phản hồi gói SNMP v1/v2c truyền rõ | `12 pkts` |

---

## 2. KẾT QUẢ ĐO KIỂM CHI TIẾT TỪNG PHƯƠNG THỨC

### ComMech-4: SNMP Interface (UDP/161)
- **Giao thức & Vai trò**: `IP/UDP/SNMP` (DUT Server (Tool Probe))
- **Kết quả phân tích mật mã & Hạ cấp**: ĐẠT: Từ chối / Không phản hồi gói SNMP v1/v2c truyền rõ
- **File bắt gói tin PCAP đối soát**: `[pcap](file://captures/ComMech/commech-4_snmpv3.pcap)` (12 gói tin)


---

## 3. BẰNG CHỨNG TOÀN BỘ DANH MỤC CIPHERSUITE THEO IXIT 11 (NMAP ENUM)

> [!TIP] Bằng chứng danh mục Ciphersuite đầy đủ:
> Do gói tin Server Hello trên Wireshark chỉ đàm phán 1 Cipher Suite cho mỗi phiên kết nối,
> kiểm định viên sử dụng kết quả quét Nmap để chụp ảnh đối soát toàn bộ danh mục Ciphersuite & KEX:
> - **Web HTTPS & ONVIF (443)**: `nmap -Pn -p 443 --script ssl-enum-ciphers 192.168.1.100`
> - **SSH Remote CLI (22)**: `nmap -Pn -p 22 --script ssh2-enum-algos 192.168.1.100`
> - **RTSPS Video Stream (322)**: `nmap -Pn -p 322 --script ssl-enum-ciphers 192.168.1.100`
> - **Báo cáo chi tiết danh mục**: [commech_ciphers_nmap_enum.md](file://captures/commech_ciphers_nmap_enum.md)

> [!NOTE] Đối với các cơ chế Camera đóng vai trò Client (ComMech-5 MQTT, ComMech-6 Syslog, ComMech-7 SMB, ComMech-8 SMTP, ComMech-9 SFTP, ComMech-11 O3C):
> Danh sách Cipher Suite / KEX / Dialect được Camera chủ động chào mời trong gói tin `Client Hello` / `KEXINIT` / `SMB Negotiate` trên file PCAP tương ứng.

---
*Báo cáo được khởi tạo tự động bởi QCVN 11 Cybersecurity Toolkit (ComMech Auditor).*
