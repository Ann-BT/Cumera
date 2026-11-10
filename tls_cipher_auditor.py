import socket
import ssl
import struct
import os
import json
from typing import Dict, List, Tuple, Optional

# SOGIS Classification according to SOGIS Agreed Cryptographic Mechanisms
# 'R' = Recommended, 'L' = Legacy, 'NR' = Not Recommended, 'F' = Forbidden / Insecure
CIPHER_DB = {
    # TLS 1.3
    0x1301: {"name": "TLS_AES_128_GCM_SHA256", "version": "TLSv1.3", "sogis": "R", "key_size": 128},
    0x1302: {"name": "TLS_AES_256_GCM_SHA384", "version": "TLSv1.3", "sogis": "R", "key_size": 256},
    0x1303: {"name": "TLS_CHACHA20_POLY1305_SHA256", "version": "TLSv1.3", "sogis": "R", "key_size": 256},
    0x1304: {"name": "TLS_AES_128_CCM_SHA256", "version": "TLSv1.3", "sogis": "L", "key_size": 128},
    0x1305: {"name": "TLS_AES_128_CCM_8_SHA256", "version": "TLSv1.3", "sogis": "NR", "key_size": 128},

    # TLS 1.2 ECDHE GCM
    0xC02B: {"name": "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "version": "TLSv1.2", "sogis": "R", "key_size": 128},
    0xC02C: {"name": "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "version": "TLSv1.2", "sogis": "R", "key_size": 256},
    0xC02F: {"name": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "version": "TLSv1.2", "sogis": "R", "key_size": 128},
    0xC030: {"name": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "version": "TLSv1.2", "sogis": "R", "key_size": 256},
    0xCCA8: {"name": "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", "version": "TLSv1.2", "sogis": "R", "key_size": 256},
    0xCCA9: {"name": "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", "version": "TLSv1.2", "sogis": "R", "key_size": 256},

    # TLS 1.2 DHE GCM
    0x009E: {"name": "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", "version": "TLSv1.2", "sogis": "L", "key_size": 128},
    0x009F: {"name": "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", "version": "TLSv1.2", "sogis": "L", "key_size": 256},

    # TLS 1.2 CBC (SHA256 / SHA384)
    0xC023: {"name": "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", "version": "TLSv1.2", "sogis": "L", "key_size": 128},
    0xC024: {"name": "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384", "version": "TLSv1.2", "sogis": "L", "key_size": 256},
    0xC027: {"name": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", "version": "TLSv1.2", "sogis": "L", "key_size": 128},
    0xC028: {"name": "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", "version": "TLSv1.2", "sogis": "L", "key_size": 256},
    0x0067: {"name": "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256", "version": "TLSv1.2", "sogis": "L", "key_size": 128},
    0x006B: {"name": "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256", "version": "TLSv1.2", "sogis": "L", "key_size": 256},
    0x003C: {"name": "TLS_RSA_WITH_AES_128_CBC_SHA256", "version": "TLSv1.2", "sogis": "NR", "key_size": 128},
    0x003D: {"name": "TLS_RSA_WITH_AES_256_CBC_SHA256", "version": "TLSv1.2", "sogis": "NR", "key_size": 256},

    # Legacy SHA-1 / 3DES / RC4 (Forbidden or Not Recommended in SOGIS)
    0x002F: {"name": "TLS_RSA_WITH_AES_128_CBC_SHA", "version": "TLSv1.0-1.2", "sogis": "NR", "key_size": 128},
    0x0035: {"name": "TLS_RSA_WITH_AES_256_CBC_SHA", "version": "TLSv1.0-1.2", "sogis": "NR", "key_size": 256},
    0xC013: {"name": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "version": "TLSv1.0-1.2", "sogis": "NR", "key_size": 128},
    0xC014: {"name": "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", "version": "TLSv1.0-1.2", "sogis": "NR", "key_size": 256},
    0x000A: {"name": "TLS_RSA_WITH_3DES_EDE_CBC_SHA", "version": "SSLv3-TLSv1.2", "sogis": "F", "key_size": 112},
    0x0005: {"name": "TLS_RSA_WITH_RC4_128_SHA", "version": "SSLv3-TLSv1.2", "sogis": "F", "key_size": 128},
    0x0004: {"name": "TLS_RSA_WITH_RC4_128_MD5", "version": "SSLv3-TLSv1.2", "sogis": "F", "key_size": 128},
}

def build_client_hello(ciphers: List[int], max_tls_version: str = "TLSv1.3", sni: str = "") -> bytes:
    # TLS Record Header
    record_version = (0x03, 0x01) # TLS 1.0 record for maximum compatibility
    
    # Handshake Header
    client_version = (0x03, 0x03) # TLS 1.2 wire version
    random_bytes = os.urandom(32)
    session_id = b""
    
    # Cipher suites
    cipher_bytes = b"".join(struct.pack(">H", c) for c in ciphers)
    ciphers_len = struct.pack(">H", len(cipher_bytes))
    
    # Compression methods (0 = null)
    comp_methods = b"\x01\x00"
    
    # Extensions
    extensions = b""
    
    # 1. Server Name Indication (SNI)
    if sni:
        sni_bytes = sni.encode('utf-8')
        sni_entry = b"\x00" + struct.pack(">H", len(sni_bytes)) + sni_bytes
        sni_list = struct.pack(">H", len(sni_entry)) + sni_entry
        extensions += struct.pack(">H", 0x0000) + struct.pack(">H", len(sni_list)) + sni_list
    
    # 2. Supported Versions (for TLS 1.3)
    if max_tls_version == "TLSv1.3":
        supp_versions = b"\x02\x03\x04" # len 2, TLS 1.3 (0x0304)
        extensions += struct.pack(">H", 0x002B) + struct.pack(">H", len(supp_versions)) + supp_versions
    elif max_tls_version == "TLSv1.2":
        supp_versions = b"\x02\x03\x03" # len 2, TLS 1.2 (0x0303)
        extensions += struct.pack(">H", 0x002B) + struct.pack(">H", len(supp_versions)) + supp_versions
    
    # 3. Supported Groups (Elliptic Curves)
    curves = struct.pack(">H", 0x001D) + struct.pack(">H", 0x0017) + struct.pack(">H", 0x0018) # X25519, secp256r1, secp384r1
    curves_payload = struct.pack(">H", len(curves)) + curves
    extensions += struct.pack(">H", 0x000A) + struct.pack(">H", len(curves_payload)) + curves_payload
    
    # 4. Signature Algorithms
    sig_algs = (
        b"\x04\x03" # ecdsa_secp256r1_sha256
        b"\x08\x04" # rsa_pss_rsae_sha256
        b"\x04\x01" # rsa_pkcs1_sha256
        b"\x05\x03" # ecdsa_secp384r1_sha384
        b"\x08\x05" # rsa_pss_rsae_sha384
        b"\x05\x01" # rsa_pkcs1_sha384
    )
    sig_payload = struct.pack(">H", len(sig_algs)) + sig_algs
    extensions += struct.pack(">H", 0x000D) + struct.pack(">H", len(sig_payload)) + sig_payload
    
    # Extension wrapper
    ext_wrapper = struct.pack(">H", len(extensions)) + extensions
    
    # Handshake body
    body = (
        bytes(client_version) +
        random_bytes +
        struct.pack("B", len(session_id)) + session_id +
        ciphers_len + cipher_bytes +
        comp_methods +
        ext_wrapper
    )
    
    # Handshake wrapper (Type 1 = Client Hello)
    handshake = b"\x01" + struct.pack(">I", len(body))[1:] + body
    
    # Record wrapper (Type 22 = Handshake)
    record = b"\x16" + bytes(record_version) + struct.pack(">H", len(handshake)) + handshake
    return record

def probe_cipher(host: str, port: int, cipher_code: int, max_tls_version: str = "TLSv1.3", timeout: float = 2.0) -> Optional[int]:
    """Sends a ClientHello with a single cipher suite. Returns negotiated cipher or None."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        req = build_client_hello([cipher_code], max_tls_version=max_tls_version, sni=host)
        s.sendall(req)
        resp = s.recv(4096)
        if len(resp) >= 5 and resp[0] == 0x16: # Handshake record
            # Parse ServerHello
            # resp[0] = 0x16, resp[1:3] = version, resp[3:5] = length
            hs_body = resp[5:]
            if len(hs_body) > 4 and hs_body[0] == 0x02: # ServerHello
                # Server version (2) + random (32) + session_id_len (1)
                sid_len = hs_body[34]
                idx = 35 + sid_len
                if len(hs_body) >= idx + 2:
                    selected_cipher = struct.unpack(">H", hs_body[idx:idx+2])[0]
                    return selected_cipher
    except Exception:
        pass
    finally:
        try: s.close()
        except: pass
    return None

def test_single_cipher(host: str, port: int, cipher_code: int, max_tls_version: str = "TLSv1.3") -> bool:
    res = probe_cipher(host, port, cipher_code, max_tls_version=max_tls_version)
    return res == cipher_code

def enumerate_ciphers(host: str, port: int) -> Dict[str, Any]:
    """Enumerates supported TLS versions and cipher suites, classifying SOGIS status."""
    results = {
        "host": host,
        "port": port,
        "tls13_ciphers": [],
        "tls12_ciphers": [],
        "legacy_ciphers": [],
        "sogis_recommended": [],
        "sogis_non_compliant": [],
        "summary": "UNKNOWN"
    }

    # 1. Test TLS 1.3 Ciphers
    tls13_list = [0x1301, 0x1302, 0x1303, 0x1304, 0x1305]
    for code in tls13_list:
        if test_single_cipher(host, port, code, max_tls_version="TLSv1.3"):
            info = CIPHER_DB.get(code, {"name": f"UNKNOWN_0x{code:04X}", "sogis": "NR", "version": "TLSv1.3"})
            results["tls13_ciphers"].append(info)
            if info["sogis"] == "R":
                results["sogis_recommended"].append(info)
            else:
                results["sogis_non_compliant"].append(info)

    # 2. Test TLS 1.2 Ciphers
    tls12_candidates = [k for k, v in CIPHER_DB.items() if v["version"].startswith("TLSv1.2")]
    for code in tls12_candidates:
        if test_single_cipher(host, port, code, max_tls_version="TLSv1.2"):
            info = CIPHER_DB[code]
            results["tls12_ciphers"].append(info)
            if info["sogis"] == "R":
                results["sogis_recommended"].append(info)
            else:
                results["sogis_non_compliant"].append(info)

    return results
