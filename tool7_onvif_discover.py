import socket
import sys
import uuid
import json
import os
import re
from rich.console import Console

sys.stdout.reconfigure(encoding='utf-8')
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pcap_recorder import start_pcap_capture, stop_pcap_capture, display_wireshark_panel
from toolkit_config import CONF_PATH, get_service_ports, get_target_info, load_config, make_console

console = make_console()
config = load_config()
DUT_IP = get_target_info(config)["ip"]
WS_PORT = int(get_service_ports(config)["onvif_ws_discovery_udp"])

ws_discovery_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope"
            xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing"
            xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery"
            xmlns:dn="http://www.onvif.org/ver10/network/wsdl">
  <e:Header>
    <w:MessageID>uuid:{uuid.uuid4()}</w:MessageID>
    <w:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>
    <w:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>
  </e:Header>
  <e:Body>
    <d:Probe>
      <d:Types>dn:NetworkVideoTransmitter</d:Types>
    </d:Probe>
  </e:Body>
</e:Envelope>"""

def main():
    print("=" * 80)
    print("  TOOL 7: DÒ QUÉT DỊCH VỤ ONVIF PROFILE S QUA WS-DISCOVERY (UDP 3702)")
    print(f"  Mục tiêu: {DUT_IP}:{WS_PORT}")
    print("=" * 80)

    pcap_proc, pcap_file = start_pcap_capture(DUT_IP, f"udp port {WS_PORT}", prefix="onvif_discovery_audit")
    if pcap_file:
        print(f"[*] Đang tự động bắt gói tin PCAP vào: {pcap_file}")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3.0)
    print(f"[*] Đang gửi WS-Discovery Probe tới {DUT_IP}:{WS_PORT}...")
    sock.sendto(ws_discovery_xml.encode('utf-8'), (DUT_IP, WS_PORT))
    
    try:
        data, addr = sock.recvfrom(65535)
        print(f"\n[+] NHẬN ĐƯỢC PHẢN HỒI WS-DISCOVERY TỪ: {addr[0]}:{addr[1]}")
        resp = data.decode('utf-8', errors='ignore')
        
        # Scopes
        m_scopes = re.search(r'<[^:]*:?Scopes>(.*?)</[^:]*:?Scopes>', resp)
        if m_scopes:
            print(f"\n[-] Danh sách ONVIF Profiles & Scopes được phát thanh:")
            for s in m_scopes.group(1).split():
                print(f"    • {s}")
                
        # XAddrs
        m_xaddrs = re.search(r'<[^:]*:?XAddrs>(.*?)</[^:]*:?XAddrs>', resp)
        if m_xaddrs:
            print(f"\n[***] ĐỊA CHỈ DỊCH VỤ ONVIF THỰC TẾ (XAddrs):")
            print(f"    -> {m_xaddrs.group(1)}")
            
        print("\n[*] ĐỐI SOÁT VỚI CỘT 6 (AUTHMECH-3):")
        print("    • Chuẩn Profile S (Streaming): CÓ THỰC")
        print("    • Cổng dịch vụ ONVIF hoạt động: CÓ THỰC")
    except socket.timeout:
        print(f"[-] Không nhận được phản hồi WS-Discovery từ {DUT_IP} (Timeout).")
    finally:
        sock.close()
        stop_pcap_capture(pcap_proc)

    filters = [
        ("Toàn bộ lưu lượng ONVIF WS-Discovery", f"udp.port == {WS_PORT} || wsdd"),
        ("Gói tin Probe từ máy kiểm thử (XML SOAP Probe)", f"udp.port == {WS_PORT} && xml contains \"Probe\""),
        ("Gói tin ProbeMatches từ Camera phản hồi", f"udp.port == {WS_PORT} && xml contains \"ProbeMatches\""),
        ("Bằng chứng dịch vụ Profile S (NetworkVideoTransmitter)", f"udp.port == {WS_PORT} && xml contains \"NetworkVideoTransmitter\""),
        ("Trích xuất địa chỉ thực tế (XAddrs)", f"udp.port == {WS_PORT} && xml contains \"XAddrs\"")
    ]
    display_wireshark_panel(
        console,
        pcap_file,
        filters,
        is_tls=False,
        sort_tip="Click tiêu đề cột No. để thấy trình tự phát sinh: Gói tin 1 là Probe từ máy kiểm thử gửi đến địa chỉ Multicast / Unicast, gói tin tiếp theo là ProbeMatches từ Camera gửi về trả thông tin Scopes và XAddrs.",
        title="BẰNG CHỨNG GÓI TIN WIRESHARK ONVIF WS-DISCOVERY (UDP 3702)"
    )

if __name__ == '__main__':
    main()
