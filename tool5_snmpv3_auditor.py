#!/usr/bin/env python3
"""
Universal SNMPv3 & Legacy SNMP Cryptographic Matrix Auditor
Author: Merlin / Antigravity

Exhaustively probes all SNMPv3 security levels, authentication hashes, privacy ciphers,
and SNMPv1/v2c cleartext fallbacks against a target UDP port, then reports exactly which
cryptographic algorithms and protocols the device actually accepts in practice.
"""

import argparse
import asyncio
import json
import os
import socket
import sys
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

TOOLKIT_DIR = os.path.dirname(os.path.abspath(__file__))
if TOOLKIT_DIR not in sys.path:
    sys.path.insert(0, TOOLKIT_DIR)

from pyasn1.codec.ber import decoder
from pysnmp.carrier.base import AbstractTransportDispatcher
from pysnmp.hlapi.asyncio import (
    CommunityData,
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    UsmUserData,
    get_cmd,
    usm3DESEDEPrivProtocol,
    usmAesBlumenthalCfb192Protocol,
    usmAesBlumenthalCfb256Protocol,
    usmAesCfb128Protocol,
    usmAesCfb192Protocol,
    usmAesCfb256Protocol,
    usmDESPrivProtocol,
    usmHMAC128SHA224AuthProtocol,
    usmHMAC192SHA256AuthProtocol,
    usmHMAC256SHA384AuthProtocol,
    usmHMAC384SHA512AuthProtocol,
    usmHMACMD5AuthProtocol,
    usmHMACSHAAuthProtocol,
    usmNoAuthProtocol,
    usmNoPrivProtocol,
)
from pysnmp.proto.mpmod.rfc3412 import SNMPv3Message
from pysnmp.proto.secmod.rfc3414.service import UsmSecurityParameters
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from pcap_recorder import start_pcap_capture, stop_pcap_capture

# Patch pysnmp to safely ignore late/stray UDP datagrams arriving after dispatcher/transport close
_orig_cb_fun = AbstractTransportDispatcher._callback_function

def _safe_callback_function(self, incomingTransport, transportAddress, incomingMessage):
    try:
        return _orig_cb_fun(self, incomingTransport, transportAddress, incomingMessage)
    except Exception as exc:
        if "Unregistered transport" in str(exc):
            return None
        raise

AbstractTransportDispatcher._callback_function = _safe_callback_function

def _make_console() -> Console:
    """Create a Rich Console sized to COLUMNS or full width instead of 80-col dumb/non-TTY fallback."""
    cols = os.environ.get("COLUMNS", "")
    lines = os.environ.get("LINES", "")
    h = int(lines) if (lines.isdigit() and int(lines) >= 24) else 50
    if cols.isdigit() and int(cols) >= 80:
        return Console(width=int(cols), height=h)
    if not sys.stdout.isatty() or os.environ.get("TERM", "") in ("", "dumb"):
        return Console(width=145, height=h)
    return Console()


console = _make_console()
CONF_PATH = os.path.join(TOOLKIT_DIR, "config.json")
SYS_DESCR_OID = "1.3.6.1.2.1.1.1.0"

# Ordered strongest -> weakest
AUTH_PROTOCOLS: List[Dict[str, Any]] = [
    {"name": "SHA-512", "proto": usmHMAC384SHA512AuthProtocol, "digest_bytes": 64, "tier": "strong"},
    {"name": "SHA-384", "proto": usmHMAC256SHA384AuthProtocol, "digest_bytes": 48, "tier": "strong"},
    {"name": "SHA-256", "proto": usmHMAC192SHA256AuthProtocol, "digest_bytes": 32, "tier": "strong"},
    {"name": "SHA-224", "proto": usmHMAC128SHA224AuthProtocol, "digest_bytes": 28, "tier": "standard"},
    {"name": "SHA-1", "proto": usmHMACSHAAuthProtocol, "digest_bytes": 20, "tier": "legacy"},
    {"name": "MD5", "proto": usmHMACMD5AuthProtocol, "digest_bytes": 16, "tier": "forbidden"},
]

PRIV_PROTOCOLS: List[Dict[str, Any]] = [
    {"name": "AES-256", "proto": usmAesCfb256Protocol, "key_bytes": 32, "blumenthal": False, "tier": "strong"},
    {"name": "AES-256-Blumenthal", "proto": usmAesBlumenthalCfb256Protocol, "key_bytes": 32, "blumenthal": True, "tier": "strong"},
    {"name": "AES-192", "proto": usmAesCfb192Protocol, "key_bytes": 24, "blumenthal": False, "tier": "strong"},
    {"name": "AES-192-Blumenthal", "proto": usmAesBlumenthalCfb192Protocol, "key_bytes": 24, "blumenthal": True, "tier": "strong"},
    {"name": "AES-128", "proto": usmAesCfb128Protocol, "key_bytes": 16, "blumenthal": False, "tier": "strong"},
    {"name": "3DES", "proto": usm3DESEDEPrivProtocol, "key_bytes": 24, "blumenthal": False, "tier": "legacy"},
    {"name": "DES-56", "proto": usmDESPrivProtocol, "key_bytes": 8, "blumenthal": False, "tier": "forbidden"},
]


def load_snmp_config() -> Dict[str, Any]:
    """Load current DUT IP, port, and SNMPv3 credentials dynamically from config.json."""
    cfg: Dict[str, Any] = {}
    if os.path.exists(CONF_PATH):
        try:
            with open(CONF_PATH, encoding="utf-8") as f:
                cfg = json.load(f)
        except Exception:
            cfg = {}

    tc = cfg.get("target_camera", {})
    sp = cfg.get("service_ports", {})
    s3 = cfg.get("snmp_v3") or cfg.get("snmp_credentials") or {}

    cam_user = tc.get("username") or "admin"
    cam_pass = tc.get("password") or "Psitest135##"
    snmp_user = s3.get("user") or cam_user
    auth_pass = s3.get("auth_pass") or cam_pass
    priv_pass = s3.get("priv_pass") or auth_pass

    return {
        "host": tc.get("ip") or "192.168.99.132",
        "port": int(sp.get("snmp") or sp.get("snmp_udp") or 161),
        "user": snmp_user,
        "auth_pass": auth_pass,
        "priv_pass": priv_pass,
        "cam_user": cam_user,
        "cam_pass": cam_pass,
    }


def _classify_authpriv(auth_tier: str, priv_tier: str) -> str:
    if auth_tier == "forbidden" or priv_tier == "forbidden":
        return "Forbidden (Thuật toán yếu)"
    if auth_tier == "legacy" or priv_tier == "legacy":
        return "Legacy (Cần nâng cấp)"
    if auth_tier == "standard":
        return "Standard (RFC 7860)"
    return "Recommended (SOGIS 'R')"


def build_test_combinations() -> List[Dict[str, Any]]:
    """Build the exhaustive test matrix covering authPriv, authNoPriv, noAuthNoPriv, and v1/v2c."""
    combos: List[Dict[str, Any]] = []

    # 1. Exhaustive authPriv (Auth x Priv)
    for auth in AUTH_PROTOCOLS:
        for priv in PRIV_PROTOCOLS:
            # Blumenthal vs Reeder key extension produces identical bytes when digest >= key size.
            if priv["blumenthal"] and auth["digest_bytes"] >= priv["key_bytes"]:
                continue
            combos.append({
                "name": f"authPriv ({auth['name']} + {priv['name']})",
                "level": "authPriv",
                "proto_family": "SNMPv3",
                "auth_name": auth["name"],
                "priv_name": priv["name"],
                "auth_proto": auth["proto"],
                "priv_proto": priv["proto"],
                "use_auth": True,
                "use_priv": True,
                "community": None,
                "mp_model": 3,
                "sec_type": _classify_authpriv(auth["tier"], priv["tier"]),
            })

    # 2. authNoPriv across all Auth hashes
    for auth in AUTH_PROTOCOLS:
        combos.append({
            "name": f"authNoPriv ({auth['name']})",
            "level": "authNoPriv",
            "proto_family": "SNMPv3",
            "auth_name": auth["name"],
            "priv_name": "None",
            "auth_proto": auth["proto"],
            "priv_proto": usmNoPrivProtocol,
            "use_auth": True,
            "use_priv": False,
            "community": None,
            "mp_model": 3,
            "sec_type": "Insecure (Không mã hóa kênh)",
        })

    # 3. noAuthNoPriv
    combos.append({
        "name": "noAuthNoPriv (Không Auth / Không Priv)",
        "level": "noAuthNoPriv",
        "proto_family": "SNMPv3",
        "auth_name": "None",
        "priv_name": "None",
        "auth_proto": usmNoAuthProtocol,
        "priv_proto": usmNoPrivProtocol,
        "use_auth": False,
        "use_priv": False,
        "community": None,
        "mp_model": 3,
        "sec_type": "High Risk (Vô hiệu hóa bảo mật)",
    })

    # 4. Legacy SNMPv1 / SNMPv2c cleartext communities
    for label, mp_model in [("SNMPv1", 0), ("SNMPv2c", 1)]:
        for comm in ("public", "private"):
            combos.append({
                "name": f"{label} (community: {comm})",
                "level": label,
                "proto_family": label,
                "auth_name": f"Community:{comm}",
                "priv_name": "Cleartext",
                "auth_proto": None,
                "priv_proto": None,
                "use_auth": False,
                "use_priv": False,
                "community": comm,
                "mp_model": mp_model,
                "sec_type": "High Risk (Truyền rõ v1/v2c)",
            })

    return combos


TEST_COMBINATIONS = build_test_combinations()


def probe_v3_engine(host: str, port: int, timeout: float = 1.2) -> Dict[str, Any]:
    """Send RFC 3414 empty-username EngineID discovery probe to test SNMPv3 reachability."""
    v3_probe = (
        b"\x30\x3a\x02\x01\x03\x30\x11\x02\x04\x00\x00\x00\x01\x02\x02\x10\x00"
        b"\x04\x01\x04\x02\x01\x03\x04\x10\x30\x0e\x04\x00\x02\x01\x00\x02\x01"
        b"\x00\x04\x00\x04\x00\x04\x00\x30\x10\x04\x00\x04\x00\xa0\x0a\x02\x04"
        b"\x00\x00\x00\x00\x02\x01\x00\x02\x01\x00"
    )
    info: Dict[str, Any] = {"reachable": False, "engine_id": "", "boots": None, "time": None}
    for _ in range(2):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.sendto(v3_probe, (host, port))
            data, _ = sock.recvfrom(4096)
            if data:
                info["reachable"] = True
                try:
                    msg, _ = decoder.decode(data, asn1Spec=SNMPv3Message())
                    usm, _ = decoder.decode(bytes(msg["msgSecurityParameters"]), asn1Spec=UsmSecurityParameters())
                    info["engine_id"] = usm[0].asOctets().hex()
                    info["boots"] = int(usm[1])
                    info["time"] = int(usm[2])
                except Exception:
                    pass
                break
        except Exception:
            continue
        finally:
            sock.close()
    return info


async def probe_single_combo(
    combo: Dict[str, Any],
    host: str,
    port: int,
    user: str,
    auth_pass: str,
    priv_pass: str,
    timeout: float = 0.9,
) -> Dict[str, Any]:
    """Execute one isolated SNMP probe using a fresh SnmpEngine and return structured outcome."""
    snmp_engine = SnmpEngine()
    try:
        transport = await UdpTransportTarget.create((host, port), timeout=timeout, retries=0)
        if combo["community"] is not None:
            cred = CommunityData(combo["community"], mpModel=combo["mp_model"])
        elif combo["use_auth"] and combo["use_priv"]:
            cred = UsmUserData(
                user,
                authKey=auth_pass,
                privKey=priv_pass,
                authProtocol=combo["auth_proto"],
                privProtocol=combo["priv_proto"],
            )
        elif combo["use_auth"]:
            cred = UsmUserData(
                user,
                authKey=auth_pass,
                authProtocol=combo["auth_proto"],
                privProtocol=usmNoPrivProtocol,
            )
        else:
            cred = UsmUserData(user, authProtocol=usmNoAuthProtocol, privProtocol=usmNoPrivProtocol)

        error_indication, error_status, _, var_binds = await get_cmd(
            snmp_engine,
            cred,
            transport,
            ContextData(),
            ObjectType(ObjectIdentity(SYS_DESCR_OID)),
        )

        if error_indication:
            err_type = type(error_indication).__name__
            short_reason = "Timeout (Không phản hồi)" if err_type == "RequestTimedOut" else str(error_indication)
            return {
                "accepted": False,
                "digest_matched": err_type in ("DecryptionError", "UnsupportedSecLevel"),
                "status_code": err_type,
                "detail": short_reason,
                "tested_user": user if combo["community"] is None else combo["community"],
            }

        if error_status:
            stat_str = error_status.prettyPrint() if hasattr(error_status, "prettyPrint") else str(error_status)
            return {
                "accepted": False,
                "digest_matched": combo["use_auth"] and stat_str == "authorizationError",
                "status_code": stat_str,
                "detail": stat_str,
                "tested_user": user if combo["community"] is None else combo["community"],
            }

        val = str(var_binds[0][1]) if var_binds else "OK"
        return {
            "accepted": True,
            "digest_matched": bool(combo["use_auth"]),
            "status_code": "ACCEPTED",
            "detail": f"sysDescr: {val[:60]}",
            "sys_descr": val,
            "tested_user": user if combo["community"] is None else combo["community"],
        }
    except Exception as e:
        return {
            "accepted": False,
            "digest_matched": False,
            "status_code": type(e).__name__,
            "detail": f"Lỗi ({type(e).__name__}: {e})",
            "tested_user": user if combo["community"] is None else combo["community"],
        }
    finally:
        try:
            snmp_engine.close_dispatcher()
        except Exception:
            pass


async def resolve_active_user(
    host: str,
    port: int,
    candidates: List[str],
    auth_pass: str,
    timeout: float = 0.9,
) -> str:
    """Detect the valid SNMPv3 username if the primary configured user returns UnknownUserName."""
    probe_combo = {
        "community": None,
        "mp_model": 3,
        "use_auth": True,
        "use_priv": False,
        "auth_proto": usmHMAC192SHA256AuthProtocol,
        "priv_proto": usmNoPrivProtocol,
    }
    for cand in candidates:
        res = await probe_single_combo(probe_combo, host, port, cand, auth_pass, auth_pass, timeout=timeout)
        if res["status_code"] != "UnknownUserName":
            return cand
        await asyncio.sleep(0.03)
    return candidates[0]


async def _detect_matching_password(
    host: str,
    port: int,
    user: str,
    candidate_pass: str,
    timeout: float = 0.9,
) -> bool:
    """Quickly check whether candidate_pass matches any SNMPv3 auth hash on the target."""
    for auth in AUTH_PROTOCOLS:
        probe_combo = {
            "community": None,
            "mp_model": 3,
            "use_auth": True,
            "use_priv": False,
            "auth_proto": auth["proto"],
            "priv_proto": usmNoPrivProtocol,
        }
        res = await probe_single_combo(probe_combo, host, port, user, candidate_pass, candidate_pass, timeout=timeout)
        if res["accepted"] or res["digest_matched"]:
            return True
        await asyncio.sleep(0.02)
    return False


async def run_snmp_audit(
    host: Optional[str] = None,
    port: Optional[int] = None,
    capture_pcap: bool = True,
    user: Optional[str] = None,
    auth_pass: Optional[str] = None,
    priv_pass: Optional[str] = None,
    timeout: float = 0.9,
    force_full: bool = False,
) -> Tuple[List[Dict[str, Any]], str]:
    """
    Run the exhaustive SNMP cryptographic matrix audit against host:port.
    Returns (results_list, pcap_file_path).
    """
    try:
        loop = asyncio.get_running_loop()
        def _exc_handler(l, c):
            exc = c.get("exception")
            if exc and "Unregistered transport" in str(exc):
                return
            l.default_exception_handler(c)
        loop.set_exception_handler(_exc_handler)
    except Exception:
        pass

    cfg = load_snmp_config()
    target_host = host or cfg["host"]
    target_port = int(port or cfg["port"])
    primary_user = user or cfg["user"]
    explicit_auth_pass = auth_pass is not None
    active_auth_pass = auth_pass if auth_pass is not None else cfg["auth_pass"]
    active_priv_pass = priv_pass if priv_pass is not None else (auth_pass if auth_pass is not None else cfg["priv_pass"])

    pcap_proc = None
    pcap_file = ""
    if capture_pcap:
        try:
            pcap_proc, pcap_file = start_pcap_capture(
                target_host,
                f"ip host {target_host} and udp port {target_port}",
                prefix="snmpv3_audit",
            )
        except Exception:
            pcap_proc, pcap_file = None, ""

    results: List[Dict[str, Any]] = []
    try:
        engine_info = probe_v3_engine(target_host, target_port, timeout=max(timeout, 1.0))

        # Resolve active username only when SNMPv3 responds
        user_candidates = []
        for u in [primary_user, cfg["cam_user"], "admin", "initial"]:
            if u and u not in user_candidates:
                user_candidates.append(u)

        active_user = primary_user
        if engine_info["reachable"]:
            active_user = await resolve_active_user(
                target_host, target_port, user_candidates, active_auth_pass, timeout=timeout
            )

        # If target_camera.password differs from snmp_v3.auth_pass and auth_pass wasn't forced on CLI,
        # check if primary auth_pass fails every hash while cam_pass matches.
        if (
            engine_info["reachable"]
            and not explicit_auth_pass
            and cfg["cam_pass"]
            and cfg["cam_pass"] != active_auth_pass
        ):
            primary_matched = await _detect_matching_password(
                target_host, target_port, active_user, active_auth_pass, timeout=timeout
            )
            if not primary_matched:
                cam_matched = await _detect_matching_password(
                    target_host, target_port, active_user, cfg["cam_pass"], timeout=timeout
                )
                if cam_matched:
                    console.print(
                        "[yellow][!] Mật khẩu snmp_v3 trong config không khớp digest; "
                        "tự động sử dụng mật khẩu target_camera.password.[/yellow]"
                    )
                    active_auth_pass = cfg["cam_pass"]
                    active_priv_pass = cfg["cam_pass"]

        combos = build_test_combinations()
        if not engine_info["reachable"] and not force_full:
            # Port did not respond to EngineID discovery: test v1/v2c, noAuthNoPriv, and 1 sanity authPriv
            # instead of waiting ~40s timing out every SNMPv3 combination.
            sanity_names = {"authPriv (SHA-256 + AES-256)", "authPriv (SHA-1 + AES-128)", "noAuthNoPriv (Không Auth / Không Priv)"}
            selected_combos = [c for c in combos if c["community"] is not None or c["name"] in sanity_names]
        else:
            selected_combos = combos

        for combo in selected_combos:
            outcome = await probe_single_combo(
                combo,
                target_host,
                target_port,
                active_user,
                active_auth_pass,
                active_priv_pass,
                timeout=timeout,
            )
            results.append({
                **{k: v for k, v in combo.items() if k not in ("auth_proto", "priv_proto")},
                **outcome,
                "engine_id": engine_info.get("engine_id", ""),
                "engine_boots": engine_info.get("boots"),
                "engine_time": engine_info.get("time"),
                "v3_reachable": engine_info["reachable"],
            })
            await asyncio.sleep(0.03)
    finally:
        if pcap_proc:
            try:
                stop_pcap_capture(pcap_proc)
            except Exception:
                pass

    return results, pcap_file


def summarize_snmp_audit(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Compute exact supported algorithms, downgrade status, and security posture from probe results."""
    accepted_authpriv = [r for r in results if r.get("level") == "authPriv" and r.get("accepted")]
    accepted_authnopriv = [r for r in results if r.get("level") == "authNoPriv" and r.get("accepted")]
    accepted_noauth = any(r.get("level") == "noAuthNoPriv" and r.get("accepted") for r in results)
    accepted_cleartext_v1v2 = [
        r for r in results if r.get("proto_family") in ("SNMPv1", "SNMPv2c") and r.get("accepted")
    ]

    accepted_auth_algos: List[str] = []
    for r in accepted_authpriv + accepted_authnopriv:
        an = r.get("auth_name")
        if an and an not in accepted_auth_algos:
            accepted_auth_algos.append(an)

    accepted_priv_algos: List[str] = []
    for r in accepted_authpriv:
        pn = r.get("priv_name")
        if pn and pn not in accepted_priv_algos:
            accepted_priv_algos.append(pn)

    digest_verified_auth_algos: List[str] = []
    for r in results:
        if r.get("proto_family") == "SNMPv3" and r.get("digest_matched"):
            an = r.get("auth_name")
            if an and an not in ("None", "") and an not in digest_verified_auth_algos:
                digest_verified_auth_algos.append(an)

    usable_ciphers: List[str] = []
    for r in accepted_authpriv:
        usable_ciphers.append(f"authPriv: {r['auth_name']} + {r['priv_name']}")
    for r in accepted_authnopriv:
        usable_ciphers.append(f"authNoPriv: {r['auth_name']}")
    if accepted_noauth:
        usable_ciphers.append("noAuthNoPriv (Cleartext)")
    for r in accepted_cleartext_v1v2:
        usable_ciphers.append(r["name"])

    weak_auths = {"MD5", "SHA-1"}
    weak_privs = {"DES-56", "3DES"}
    has_weak_crypto = any(
        (r.get("auth_name") in weak_auths or r.get("priv_name") in weak_privs)
        for r in (accepted_authpriv + accepted_authnopriv)
    )
    has_cleartext = bool(accepted_authnopriv or accepted_noauth or accepted_cleartext_v1v2)
    has_strong_sogis = any(
        (r.get("auth_name") in ("SHA-512", "SHA-384", "SHA-256") and r.get("priv_name", "").startswith("AES-"))
        for r in accepted_authpriv
    )

    matched_user = next(
        (r.get("tested_user") for r in results if r.get("proto_family") == "SNMPv3" and r.get("tested_user")),
        "admin",
    )
    v3_reachable = any(r.get("v3_reachable") for r in results)
    engine_id = next((r.get("engine_id") for r in results if r.get("engine_id")), "")
    sys_descr = next((r.get("sys_descr") for r in results if r.get("sys_descr")), "")
    all_wrong_digest = (
        v3_reachable
        and not accepted_authpriv
        and not accepted_authnopriv
        and not digest_verified_auth_algos
        and any(r.get("status_code") == "WrongDigest" for r in results)
    )

    return {
        "v3_reachable": v3_reachable,
        "engine_id": engine_id,
        "matched_user": matched_user,
        "sys_descr": sys_descr,
        "accepted_authpriv": accepted_authpriv,
        "accepted_authnopriv": accepted_authnopriv,
        "accepted_noauth": accepted_noauth,
        "accepted_cleartext_v1v2": accepted_cleartext_v1v2,
        "accepted_auth_algos": accepted_auth_algos,
        "accepted_priv_algos": accepted_priv_algos,
        "digest_verified_auth_algos": digest_verified_auth_algos,
        "usable_ciphers": usable_ciphers,
        "has_weak_crypto": has_weak_crypto,
        "has_cleartext": has_cleartext,
        "has_strong_sogis": has_strong_sogis,
        "all_wrong_digest": all_wrong_digest,
        "total_tested": len(results),
    }


def format_snmp_markdown_report(
    host: str,
    port: int,
    results: List[Dict[str, Any]],
    summary: Optional[Dict[str, Any]] = None,
    pcap_file: str = "",
) -> str:
    """Format exhaustive SNMPv3 matrix results and usable cipher summary as Markdown."""
    s = summary or summarize_snmp_audit(results)
    lines = [
        f"### Kiểm thử Toàn diện Thuật toán Mật mã SNMPv3 / SNMP (UDP/{port})",
        f"- **Mục tiêu**: `{host}:{port}` | **User kiểm tra**: `{s['matched_user']}` | **Tổng số tổ hợp thử**: `{s['total_tested']}`",
    ]
    if s["engine_id"]:
        lines.append(f"- **SNMPv3 Authoritative EngineID**: `{s['engine_id']}`")
    if s["sys_descr"]:
        lines.append(f"- **sysDescr phản hồi**: `{s['sys_descr']}`")

    lines.append("")
    lines.append("#### Thực tế thiết bị sử dụng được các mã hóa & giao thức sau:")
    if s["usable_ciphers"]:
        for c in s["usable_ciphers"]:
            lines.append(f"- `{c}`")
    else:
        lines.append("- *Không có tổ hợp mã hóa/giao thức nào trả về dữ liệu thành công.*")
        if s["digest_verified_auth_algos"]:
            lines.append(
                f"- **Auth Digest khớp USM (nhưng bị chặn mức bảo mật)**: `{', '.join(s['digest_verified_auth_algos'])}`"
            )

    lines.append("")
    lines.append("| Giao thức / Mức | Xác thực (Auth) | Mã hóa (Priv) | Phân loại | Kết quả thực tế |")
    lines.append("|:---|:---|:---|:---|:---|")
    for item in results:
        status = "**CHẤP NHẬN**" if item["accepted"] else f"Từ chối ({item.get('status_code', 'FAIL')})"
        lines.append(
            f"| {item['level']} | `{item['auth_name']}` | `{item['priv_name']}` | {item['sec_type']} | {status} |"
        )

    if pcap_file:
        lines.append(f"\n- **File PCAP**: `{pcap_file}`")

    return "\n".join(lines) + "\n"


def _short_sec_label(sec_type: str) -> str:
    if "SOGIS" in sec_type:
        return "SOGIS 'R'"
    if "RFC 7860" in sec_type:
        return "RFC 7860"
    if "Legacy" in sec_type:
        return "Legacy"
    if "Forbidden" in sec_type:
        return "Forbidden"
    if "Insecure" in sec_type:
        return "Insecure"
    if "Truyền rõ" in sec_type:
        return "High Risk (v1/v2c)"
    if "High Risk" in sec_type:
        return "High Risk"
    return sec_type


def display_snmp_audit(
    host: str,
    port: int,
    results: List[Dict[str, Any]],
    pcap_file: str = "",
    user: Optional[str] = None,
    show_wireshark: bool = True,
) -> Dict[str, Any]:
    """Render the full probe matrix table and the practical usable-ciphers summary panel."""
    out = _make_console()
    summary = summarize_snmp_audit(results)
    active_user = user or summary["matched_user"]
    engine_str = f" | EngineID: [dim]{summary['engine_id']}[/dim]" if summary["engine_id"] else ""

    out.print(Panel(
        f"[bold cyan]ĐO KIỂM TOÀN DIỆN MA TRẬN MẬT MÃ SNMP-V3 & HẠ CẤP (EXHAUSTIVE CIPHER MATRIX)[/bold cyan]\n"
        f"Mục tiêu: [bold white]{host}:{port}[/bold white] | Tài khoản: [bold green]{active_user}[/bold green] "
        f"| Số tổ hợp đã thử: [bold yellow]{summary['total_tested']}[/bold yellow]{engine_str}",
        border_style="cyan",
    ))

    table = Table(
        title="MA TRẬN KIỂM THỬ THUẬT TOÁN XÁC THỰC & MÃ HÓA SNMP",
        show_lines=False,
        expand=True,
        row_styles=["", "dim"],
    )
    table.add_column("Mức", style="bold white", no_wrap=True)
    table.add_column("Auth", style="cyan", no_wrap=True)
    table.add_column("Priv", style="magenta", no_wrap=True)
    table.add_column("Phân loại", no_wrap=True)
    table.add_column("Kết quả phản hồi thực tế", overflow="fold")

    for item in results:
        detail_txt = item["detail"].lstrip("; ").strip()
        if item["accepted"]:
            badge = f"[bold green][CHẤP NHẬN][/bold green] {detail_txt}"
        elif item.get("digest_matched"):
            badge = f"[yellow][KHỚP DIGEST / CHẶN MỨC][/yellow] {detail_txt}"
        else:
            badge = f"[dim][TỪ CHỐI] {detail_txt}[/dim]"
        table.add_row(item["level"], item["auth_name"], item["priv_name"], _short_sec_label(item["sec_type"]), badge)

    out.print(table)

    # Prominent answer to "which ciphers actually work in practice"
    summary_lines: List[str] = []
    if not summary["v3_reachable"] and not summary["accepted_cleartext_v1v2"]:
        summary_lines.append(
            f"[bold red][!] Cổng UDP {port} không phản hồi SNMPv3 EngineID discovery hoặc SNMPv1/v2c (Closed / Filtered / SNMP đang tắt).[/bold red]"
        )

    if summary["accepted_authpriv"]:
        combos_str = "\n".join(
            f"    • [bold green]{r['auth_name']} + {r['priv_name']}[/bold green] ({r['sec_type']})"
            for r in summary["accepted_authpriv"]
        )
        summary_lines.append(f"[bold white]1. authPriv (Xác thực + Mã hóa) hoạt động thực tế:[/bold white]\n{combos_str}")
    else:
        summary_lines.append("[bold white]1. authPriv (Xác thực + Mã hóa) hoạt động thực tế:[/bold white] [red]Không có tổ hợp nào thành công[/red]")

    if summary["accepted_auth_algos"]:
        summary_lines.append(
            f"[bold white]2. Thuật toán Xác thực (Auth) dùng được:[/bold white] [bold cyan]{', '.join(summary['accepted_auth_algos'])}[/bold cyan]"
        )
    elif summary["digest_verified_auth_algos"]:
        summary_lines.append(
            f"[bold white]2. Thuật toán Xác thực (Auth) khớp HMAC:[/bold white] [yellow]{', '.join(summary['digest_verified_auth_algos'])}[/yellow] "
            "[dim](Khớp hash nhưng bị chặn ở authNoPriv / không khớp priv)[/dim]"
        )
    else:
        summary_lines.append("[bold white]2. Thuật toán Xác thực (Auth) dùng được:[/bold white] [dim]Không phát hiện[/dim]")

    if summary["accepted_priv_algos"]:
        summary_lines.append(
            f"[bold white]3. Thuật toán Mã hóa (Priv) dùng được:[/bold white] [bold cyan]{', '.join(summary['accepted_priv_algos'])}[/bold cyan]"
        )
    else:
        summary_lines.append("[bold white]3. Thuật toán Mã hóa (Priv) dùng được:[/bold white] [dim]Không phát hiện[/dim]")

    # Downgrade / Cleartext status
    if summary["accepted_authnopriv"]:
        anp_str = ", ".join(r["auth_name"] for r in summary["accepted_authnopriv"])
        summary_lines.append(f"[bold red]4. Hạ cấp authNoPriv (Không mã hóa):[/bold red] [bold red]CHẤP NHẬN ({anp_str})[/bold red]")
    else:
        summary_lines.append("[bold green]4. Hạ cấp authNoPriv (Không mã hóa):[/bold green] Bị từ chối toàn bộ")

    if summary["accepted_noauth"]:
        summary_lines.append("[bold red]5. Hạ cấp noAuthNoPriv:[/bold red] [bold red]CHẤP NHẬN (Nguy hiểm)[/bold red]")
    else:
        summary_lines.append("[bold green]5. Hạ cấp noAuthNoPriv:[/bold green] Bị từ chối")

    if summary["accepted_cleartext_v1v2"]:
        v12_str = ", ".join(r["name"] for r in summary["accepted_cleartext_v1v2"])
        summary_lines.append(f"[bold red]6. Hạ cấp SNMPv1 / SNMPv2c truyền rõ:[/bold red] [bold red]CHẤP NHẬN ({v12_str})[/bold red]")
    else:
        summary_lines.append("[bold green]6. Hạ cấp SNMPv1 / SNMPv2c truyền rõ:[/bold green] Bị từ chối / Drop (Timeout)")

    if summary["all_wrong_digest"]:
        summary_lines.append(
            f"\n[bold yellow][!] Gợi ý: Tất cả các hàm băm đều trả về WrongDigest cho user '{active_user}'. "
            "Hãy kiểm tra lại Auth Pass / Priv Pass SNMPv3 trong Target Config.[/bold yellow]"
        )

    if summary["has_weak_crypto"]:
        summary_lines.append("[bold red][WARN] Thiết bị chấp nhận thuật toán mật mã yếu / lỗi thời (MD5 / SHA-1 / DES-56 / 3DES).[/bold red]")
    if summary["has_strong_sogis"] and not summary["has_weak_crypto"] and not summary["has_cleartext"]:
        summary_lines.append("[bold green][PASS] ĐẠT CHUẨN SOGIS & CHỐNG HẠ CẤP: Chỉ chấp nhận SNMPv3 authPriv mạnh và chặn toàn bộ kênh rõ / thuật toán yếu.[/bold green]")
    if summary["accepted_authpriv"]:
        summary_lines.append(
            "[dim][NOTE] SNMPv3 USM gắn cố định 1 Auth + 1 Priv cho từng user (không đàm phán đa cipher như TLS). "
            "Các thuật toán Priv khác bị Timeout là do user '" + active_user + "' hiện đang cấu hình riêng thuật toán trên.[/dim]"
        )

    out.print(Panel(
        "\n".join(summary_lines),
        title="[bold yellow]KẾT QUẢ THỰC TẾ: THIẾT BỊ DÙNG ĐƯỢC NHỮNG MÃ HÓA NÀO[/bold yellow]",
        border_style="yellow",
    ))

    if pcap_file and os.path.exists(pcap_file) and os.path.getsize(pcap_file) > 0:
        out.print(f"\n[bold yellow][OK] File bắt gói tin Wireshark đã lưu tại:[/bold yellow] [bold white]{pcap_file}[/bold white]")
        out.print(f"  (Mở trực tiếp bằng lệnh: [bold green]wireshark {pcap_file}[/bold green])\n")

    if show_wireshark:
        out.print(Panel(
            "[bold yellow][WIRESHARK FILTERS] BỘ LỌC ĐỐI SOÁT GÓI TIN SNMP-V3 TRONG WIRESHARK:[/bold yellow]\n"
            f"  • [bold cyan]1. Lọc toàn bộ gói tin SNMP:[/bold cyan] [bold green]udp.port == {port} && snmp[/bold green]\n"
            "  • [bold cyan]2. Lọc gói tin truy vấn thành công (sysDescr):[/bold cyan] [bold green]snmp.version == 3 && snmp.error_status == 0[/bold green]\n"
            "  • [bold cyan]3. Lọc gói tin mã hóa authPriv:[/bold cyan] [bold green]snmp.msgFlags.auth == 1 && snmp.msgFlags.priv == 1[/bold green]\n"
            f"  • [bold cyan]4. Lọc gói tin theo tài khoản:[/bold cyan] [bold green]snmp.msgUserName == \"{active_user}\"[/bold green]\n"
            "  • [bold cyan]5. Lọc lỗi xác thực / hạ cấp:[/bold cyan] [bold green]snmp.usmStatsWrongDigests || snmp.usmStatsUnknownUserNames || snmp.error_status == 16[/bold green]",
            border_style="yellow",
        ))

    return summary


def main():
    try:
        loop = asyncio.get_running_loop()
        def _exc_handler(l, c):
            exc = c.get("exception")
            if exc and "Unregistered transport" in str(exc):
                return
            l.default_exception_handler(c)
        loop.set_exception_handler(_exc_handler)
    except Exception:
        pass

    cfg = load_snmp_config()
    parser = argparse.ArgumentParser(
        description="Universal SNMPv3 & Legacy SNMP Cryptographic Matrix Auditor"
    )
    parser.add_argument("target_pos", nargs="?", help="IP mục tiêu (tùy chọn, mặc định lấy từ config.json)")
    parser.add_argument("port_pos", nargs="?", type=int, help="Cổng UDP SNMP (mặc định 161)")
    parser.add_argument("--ip", dest="ip_opt", help="IP mục tiêu (ghi đè config.json)")
    parser.add_argument("--port", dest="port_opt", type=int, help="Cổng UDP SNMP (ghi đè config.json)")
    parser.add_argument("--user", help="SNMPv3 username")
    parser.add_argument("--auth-pass", dest="auth_pass", help="SNMPv3 Auth passphrase")
    parser.add_argument("--priv-pass", dest="priv_pass", help="SNMPv3 Priv passphrase")
    parser.add_argument("--timeout", type=float, default=0.9, help="Timeout mỗi probe (giây)")
    parser.add_argument("--no-pcap", action="store_true", help="Không chạy bắt gói tin PCAP")
    parser.add_argument("--force-full", action="store_true", help="Ép chạy toàn bộ ma trận kể cả khi không thấy EngineID")
    parser.add_argument("--json", dest="json_out", help="Xuất kết quả chi tiết ra tệp JSON")
    parser.add_argument("--save-md", dest="md_out", help="Xuất báo cáo Markdown ra đường dẫn chỉ định")
    args = parser.parse_args()

    target_host = args.ip_opt or args.target_pos or cfg["host"]
    target_port = args.port_opt or args.port_pos or cfg["port"]

    res, pcap = asyncio.run(run_snmp_audit(
        host=target_host,
        port=target_port,
        capture_pcap=not args.no_pcap,
        user=args.user,
        auth_pass=args.auth_pass,
        priv_pass=args.priv_pass,
        timeout=args.timeout,
        force_full=args.force_full,
    ))
    summary = display_snmp_audit(target_host, target_port, res, pcap)

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump({"host": target_host, "port": target_port, "summary": summary, "matrix": res}, f, ensure_ascii=False, indent=2)
    if args.md_out:
        with open(args.md_out, "w", encoding="utf-8") as f:
            f.write(format_snmp_markdown_report(target_host, target_port, res, summary, pcap))


if __name__ == "__main__":
    main()
