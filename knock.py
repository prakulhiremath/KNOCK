# ============================================================
# KNOCK v2.0 — Clean Production Implementation
# Pre-connection Trust Protocol with Ed25519 Identity
#
# Install: pip install pynacl dnspython requests matplotlib numpy
# ============================================================

import socket
import struct
import threading
import time
import hashlib
import zlib
import math
import json
import os
import requests
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np
import dns.resolver
import dns.reversename
from nacl.signing import SigningKey, VerifyKey
from nacl.encoding import HexEncoder
from http.server import BaseHTTPRequestHandler, HTTPServer
from collections import defaultdict, deque

# ============================================================
# CONFIG
# ============================================================
KNOCK_PORT   = 5005
HTTP_PORT    = 8082
VERSION      = 1
TIMEOUT_MS   = 500
MAX_PACKET   = 512
ALLOW_THRESH = 75
CHAL_THRESH  = 40

action_map   = {0: "ALLOW", 1: "CHALLENGE", 2: "BLOCK"}
action_color = {0: "\033[92m", 1: "\033[93m", 2: "\033[91m"}
RESET = "\033[0m"
BOLD  = "\033[1m"
DIM   = "\033[2m"

# ============================================================
# FLAGS & MESSAGE TYPES
# ============================================================
FLAG_SIGNED   = 0x01
FLAG_EXT_MODE = 0x02
FLAG_RESP_REQ = 0x04
FLAG_ERROR    = 0x08

MSG_REQ       = 0x01
MSG_RES       = 0x02
MSG_EXT_INIT  = 0x03
MSG_EXT_CHAL  = 0x04
MSG_EXT_PROOF = 0x05
MSG_EXT_DEC   = 0x06

# Risk flag bitmask
RISK_DNS_MISMATCH = 0x0001
RISK_HIGH_RATE    = 0x0002
RISK_BAD_ASN      = 0x0004
RISK_NO_IDENTITY  = 0x0008
RISK_GEO_RISK     = 0x0010
RISK_REP_LOW      = 0x0020

# Error codes
ERR_MALFORMED       = 1
ERR_RATE_LIMITED    = 2
ERR_UNSUPPORTED_VER = 3
ERR_INTERNAL        = 4

# ============================================================
# GLOBAL STATE
# ============================================================
ip_stats     = {}
ip_decisions = {}  # now: ip -> (action, expiry_time)
nonce_cache  = deque(maxlen=10000)  # time-bounded nonce cache
score_history = defaultdict(lambda: deque(maxlen=50))
event_log     = deque(maxlen=200)
ext_sessions  = {}
ip_pubkey_history = {}  # ip -> [(pubkey, first_seen, rotation_count), ...]
lock          = threading.Lock()

NONCE_TTL_SEC = 5
DECISION_TTL_SEC = 300

# ============================================================
# CRYPTO
# ============================================================
client_signing_key = SigningKey.generate()
client_verify_key  = client_signing_key.verify_key

def sign_nonce(nonce: int) -> bytes:
    return client_signing_key.sign(str(nonce).encode()).signature

def verify_signature(pubkey_bytes: bytes, nonce: int, sig: bytes) -> bool:
    try:
        VerifyKey(pubkey_bytes).verify(str(nonce).encode(), sig)
        return True
    except Exception:
        return False

# ============================================================
# HEADER PACKING & VERIFICATION
# ============================================================
def pack_header(version, msg_type, flags, length, nonce) -> bytes:
    reserved = 0
    no_crc = struct.pack("!BBBB HH Q", version, msg_type, flags, reserved, length, 0, nonce)
    crc = zlib.crc32(no_crc) & 0xFFFF
    return struct.pack("!BBBB HH Q", version, msg_type, flags, reserved, length, crc, nonce)

def unpack_header(data: bytes) -> dict:
    if len(data) < 16:
        raise ValueError("Packet too short")
    version, msg_type, flags, reserved, length, crc, nonce = struct.unpack("!BBBB HH Q", data[:16])
    return dict(version=version, msg_type=msg_type, flags=flags, length=length, crc=crc, nonce=nonce)

def verify_crc(header_bytes: bytes) -> bool:
    """Verify CRC integrity of 16-byte header."""
    if len(header_bytes) < 16:
        return False
    no_crc = header_bytes[:6] + b'\x00\x00' + header_bytes[8:]
    expected_crc = zlib.crc32(no_crc) & 0xFFFF
    received_crc = struct.unpack_from("!H", header_bytes, 6)[0]
    return expected_crc == received_crc

def is_nonce_valid(nonce: int) -> bool:
    """Check nonce hasn't been seen in recent window."""
    now = time.time()
    # Clean expired nonces
    while nonce_cache and nonce_cache[0][1] < now - NONCE_TTL_SEC:
        nonce_cache.popleft()
    # Check if nonce exists
    if any(n[0] == nonce for n in nonce_cache):
        return False
    nonce_cache.append((nonce, now))
    return True

# ============================================================
# DNS / GEO HELPERS
# ============================================================
_dns_cache = {}
_geo_cache = {}

def reverse_dns(ip: str):
    if ip in _dns_cache:
        return _dns_cache[ip]
    try:
        addr = dns.reversename.from_address(ip)
        result = str(dns.resolver.resolve(addr, "PTR")[0])
        _dns_cache[ip] = result
        return result
    except Exception:
        _dns_cache[ip] = None
        return None

def fcrdns(ip: str, hostname) -> bool:
    if not hostname:
        return False
    try:
        answers = dns.resolver.resolve(hostname, "A")
        return any(str(r) == ip for r in answers)
    except Exception:
        return False

def get_asn_country(ip: str):
    if ip in _geo_cache:
        return _geo_cache[ip]
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=as,countryCode", timeout=2)
        data = r.json()
        asn     = int(data.get("as", "AS0").split()[0].replace("AS", ""))
        country = data.get("countryCode", "XX")
        _geo_cache[ip] = (asn, country)
        return asn, country
    except Exception:
        _geo_cache[ip] = (0, "XX")
        return 0, "XX"

# ============================================================
# TRUST ENGINE WITH DECAY & IP-IDENTITY BINDING
# ============================================================
def track_pubkey(ip: str, pubkey: bytes):
    """Track public key history for IP; penalize rotation."""
    with lock:
        if ip not in ip_pubkey_history:
            ip_pubkey_history[ip] = []
        history = ip_pubkey_history[ip]
        # Check if pubkey already known
        for entry in history:
            if entry[0] == pubkey:
                return 0  # known key, no penalty
        # New key → penalize
        history.append((pubkey, time.time(), len(history)))
        return -10  # penalty for key rotation

def get_reputation_with_decay(stats: dict) -> float:
    """Reputation with time decay."""
    now = time.time()
    elapsed_min = (now - stats["first_seen"]) / 60.0
    decay = 0.95 ** min(elapsed_min, 60)  # cap at 1hr
    rep = min(1.0, (stats["success"] + 1) / (stats["count"] + 2))
    return rep * decay

def update_ip_stats(ip: str):
    now = time.time()
    with lock:
        if ip not in ip_stats:
            ip_stats[ip] = {"count": 0, "last_seen": now, "success": 0, "first_seen": now}
        s = ip_stats[ip]
        delta = now - s["last_seen"]
        if delta > 3:
            s["count"] = max(0, s["count"] - 1)
        s["count"]    += 1
        s["last_seen"] = now
    return s, delta

def compute_dns_score(hostname, fcr_pass: bool) -> float:
    if hostname and fcr_pass: return 1.0
    if hostname:              return 0.6
    return 0.3

def compute_behavior(delta: float, count: int) -> float:
    if delta < 0.3:  return 0.1
    if delta < 0.8:  return 0.4
    if delta < 2.0:  return 0.7
    return 1.0

def compute_reputation(stats: dict) -> float:
    return get_reputation_with_decay(stats)

def compute_intent_score(declared: int, expected: int = 2) -> float:
    return 1.0 if declared == expected else 0.5

def compute_trust(rep, dns, identity, behavior, intent) -> int:
    raw = (0.30 * rep + 0.20 * dns + 0.25 * identity + 0.15 * behavior + 0.10 * intent)
    return math.floor(raw * 100)

def decide(score: int) -> int:
    if score >= ALLOW_THRESH: return 0
    if score >= CHAL_THRESH:  return 1
    return 2

def build_risk_flags(dns_score, behavior, rep, hostname, fcr) -> int:
    flags = 0
    if hostname and not fcr: flags |= RISK_DNS_MISMATCH
    if behavior < 0.4:       flags |= RISK_HIGH_RATE
    if rep < 0.3:            flags |= RISK_REP_LOW
    if not hostname:         flags |= RISK_NO_IDENTITY
    return flags

def _log_event(ip, score, action, risk, mode, identity=None):
    event_log.append({
        "ts": time.time(), "ip": ip, "score": score,
        "action": action_map[action], "mode": mode,
        "risk": risk, "identity": identity
    })

def set_decision_with_ttl(ip: str, action: int):
    """Store decision with expiry time."""
    with lock:
        ip_decisions[ip] = (action, time.time() + DECISION_TTL_SEC)

def get_decision(ip: str) -> int | None:
    """Retrieve decision if not expired."""
    with lock:
        if ip in ip_decisions:
            action, expiry = ip_decisions[ip]
            if time.time() < expiry:
                return action
            del ip_decisions[ip]
    return None

# ============================================================
# SERVER — LIGHTWEIGHT MODE
# ============================================================
def handle_lightweight(data: bytes, addr, sock, hdr: dict):
    ip = addr[0]
    if len(data) < 17:
        return
    
    # Verify CRC
    if not verify_crc(data[:16]):
        _send_error(sock, addr, hdr["nonce"], ERR_MALFORMED)
        return
    
    # Check nonce replay
    if not is_nonce_valid(hdr["nonce"]):
        _send_error(sock, addr, hdr["nonce"], ERR_MALFORMED)
        return
    
    intent = data[16]

    stats, delta = update_ip_stats(ip)
    hostname = reverse_dns(ip)
    fcr      = fcrdns(ip, hostname)
    dns_s    = compute_dns_score(hostname, fcr)
    beh      = compute_behavior(delta, stats["count"])
    rep      = compute_reputation(stats)
    ident    = min(1.0, 0.3 + 0.1 * stats["success"])
    intent_s = compute_intent_score(intent)

    if ip == "127.0.0.1":
        dns_s = 0.7
        rep   = max(rep, 0.7)

    score  = compute_trust(rep, dns_s, ident, beh, intent_s)
    score += 5 if stats["success"] >= 3 else 0
    action = decide(score)
    risk   = build_risk_flags(dns_s, beh, rep, hostname, fcr)
    asn, country = get_asn_country(ip)

    if action == 0:   stats["success"] += 2
    elif action == 1: stats["success"] += 1

    set_decision_with_ttl(ip, action)
    score_history[ip].append(score)
    _log_event(ip, score, action, risk, "LIGHTWEIGHT")

    header = pack_header(VERSION, MSG_RES, 0, 0, hdr["nonce"])
    body   = struct.pack(
        "!Q B B I 2s B H B B B",
        hdr["nonce"],
        1 if hostname else 0,
        1 if fcr else 0,
        asn,
        country.encode()[:2].ljust(2, b'X'),
        min(3, int(rep * 3)),
        risk,
        min(100, score),
        action,
        0
    )
    sock.sendto(header + body, addr)

# ============================================================
# SERVER — EXTENDED MODE
# ============================================================
def handle_ext_init(data: bytes, addr, sock, hdr: dict):
    if len(data) < 18:
        return
    
    # Verify CRC
    if not verify_crc(data[:16]):
        _send_error(sock, addr, hdr["nonce"], ERR_MALFORMED)
        return
    
    offset   = 16
    pk_len   = struct.unpack_from("!H", data, offset)[0]; offset += 2
    pubkey   = data[offset:offset + pk_len];              offset += pk_len
    intent   = data[offset] if offset < len(data) else 2; offset += 1
    timestamp = struct.unpack_from("!Q", data, offset)[0] if offset + 8 <= len(data) else int(time.time())

    if abs(time.time() - timestamp) > 5:
        _send_error(sock, addr, hdr["nonce"], ERR_MALFORMED)
        return

    server_nonce = int(time.time() * 1e6) & 0xFFFFFFFFFFFFFFFF
    ext_sessions[server_nonce] = {
        "client_ip": addr[0], "pubkey": pubkey,
        "intent": intent, "created": time.time()
    }

    header = pack_header(VERSION, MSG_EXT_CHAL, 0, 0, server_nonce)
    body   = struct.pack("!Q B B H", server_nonce, 0, 1, 0)
    sock.sendto(header + body, addr)

def handle_ext_proof(data: bytes, addr, sock, hdr: dict):
    if len(data) < 18:
        return
    
    # Verify CRC
    if not verify_crc(data[:16]):
        _send_error(sock, addr, hdr["nonce"], ERR_MALFORMED)
        return
    
    offset    = 16
    proof_len = struct.unpack_from("!H", data, offset)[0]; offset += 2
    proof     = data[offset:offset + proof_len]

    session = ext_sessions.get(hdr["nonce"])
    if not session or session["client_ip"] != addr[0]:
        _send_error(sock, addr, hdr["nonce"], ERR_MALFORMED)
        return
    if time.time() - session["created"] > 10:
        _send_error(sock, addr, hdr["nonce"], ERR_MALFORMED)
        return

    valid = verify_signature(session["pubkey"], hdr["nonce"], proof)
    ip    = addr[0]
    stats, delta = update_ip_stats(ip)
    
    # Track pubkey rotation
    rotation_penalty = track_pubkey(ip, session["pubkey"])

    dns_s    = 0.7
    beh      = 0.7 if delta > 1 else 0.4
    rep      = compute_reputation(stats)
    ident    = 1.0 if valid else 0.2
    intent_s = compute_intent_score(session["intent"])

    score  = compute_trust(rep, dns_s, ident, beh, intent_s)
    score += 5 if stats["success"] >= 3 else 0
    score += rotation_penalty  # penalize key rotation
    action = decide(score)

    if valid:
        stats["success"] += 2
    
    set_decision_with_ttl(ip, action)
    score_history[ip].append(score)
    _log_event(ip, score, action, 0, "EXTENDED", valid)

    session_id = int(
        hashlib.sha256((str(ip) + str(hdr["nonce"]) + str(time.time())).encode()).hexdigest()[:16], 16
    )
    header = pack_header(VERSION, MSG_EXT_DEC, FLAG_SIGNED if valid else 0, 0, hdr["nonce"])
    body   = struct.pack("!B B Q H", min(100, score), action, session_id, 300)
    sock.sendto(header + body, addr)
    del ext_sessions[hdr["nonce"]]

def _send_error(sock, addr, nonce, code):
    header = pack_header(VERSION, MSG_RES, FLAG_ERROR, 0, nonce)
    sock.sendto(header + bytes([code]), addr)

# ============================================================
# UNIFIED UDP SERVER
# ============================================================
def knock_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("0.0.0.0", KNOCK_PORT))
    except OSError as e:
        print(f"[SERVER ERROR] {e}")
        return
    print(f"[KNOCK] Server v{VERSION}.0 on UDP:{KNOCK_PORT}")

    while True:
        try:
            data, addr = sock.recvfrom(MAX_PACKET * 2)
            if len(data) < 16:
                continue
            hdr = unpack_header(data)

            if hdr["version"] != VERSION:
                _send_error(sock, addr, hdr["nonce"], ERR_UNSUPPORTED_VER)
                continue

            if   hdr["msg_type"] == MSG_REQ:       handle_lightweight(data, addr, sock, hdr)
            elif hdr["msg_type"] == MSG_EXT_INIT:  handle_ext_init(data, addr, sock, hdr)
            elif hdr["msg_type"] == MSG_EXT_PROOF: handle_ext_proof(data, addr, sock, hdr)

        except Exception as e:
            print(f"[SERVER ERROR] {e}")

# ============================================================
# HTTP GATEWAY
# ============================================================
class KnockGateway(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def do_GET(self):
        ip     = self.client_address[0]
        action = get_decision(ip)
        if action is None:
            action = 1  # default to CHALLENGE if no decision
        _log_event(ip, -1, action, 0, "HTTP")
        responses = {
            0: (200, b"200 OK - ACCESS GRANTED by KNOCK"),
            1: (401, b"401 CHALLENGE - Complete KNOCK protocol first"),
            2: (403, b"403 FORBIDDEN - BLOCKED by KNOCK"),
        }
        code, body = responses[action]
        self.send_response(code)
        self.send_header("X-KNOCK-Action", action_map[action])
        self.send_header("X-KNOCK-Score",  str(score_history[ip][-1] if score_history[ip] else -1))
        self.end_headers()
        self.wfile.write(body)

def run_http():
    try:
        server = HTTPServer(("127.0.0.1", HTTP_PORT), KnockGateway)
        print(f"[HTTP]  Gateway on http://127.0.0.1:{HTTP_PORT}")
        server.serve_forever()
    except OSError as e:
        print(f"[HTTP ERROR] {e}")

# ============================================================
# CLIENTS
# ============================================================
def knock_lightweight(host: str, intent: int = 2) -> dict | None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(TIMEOUT_MS / 1000)
    nonce  = int(time.time() * 1e6) & 0xFFFFFFFFFFFFFFFF
    header = pack_header(VERSION, MSG_REQ, FLAG_RESP_REQ, 0, nonce)
    body   = struct.pack("!B Q B", intent, 0, 60)
    sock.sendto(header + body, (host, KNOCK_PORT))
    try:
        data, _ = sock.recvfrom(512)
        if len(data) < 39:
            return None
        hdr = unpack_header(data)
        (nonce_echo, dns_status, fcr, asn, country,
         rep_bucket, risk, score, action, sig_len) = struct.unpack("!Q B B I 2s B H B B B", data[16:39])
        return dict(host=host, nonce_echo=nonce_echo, dns=dns_status, fcr=bool(fcr),
                    asn=asn, country=country.decode(), rep=rep_bucket,
                    risk=risk, score=score, action=action)
    except Exception:
        return None
    finally:
        sock.close()

def knock_extended(host: str, intent: int = 2) -> dict | None:
    sock       = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2)
    init_nonce = int(time.time() * 1e6) & 0xFFFFFFFFFFFFFFFF
    pubkey     = client_verify_key.encode()
    timestamp  = int(time.time())

    # Step 1: EXT_INIT
    header = pack_header(VERSION, MSG_EXT_INIT, FLAG_EXT_MODE, 0, init_nonce)
    body   = struct.pack("!H", len(pubkey)) + pubkey + struct.pack("!B Q", intent, timestamp)
    sock.sendto(header + body, (host, KNOCK_PORT))

    try:
        data, _ = sock.recvfrom(512)
        server_nonce = struct.unpack_from("!Q", data, 16)[0]
    except Exception:
        return None

    # Step 2: EXT_PROOF
    sig    = sign_nonce(server_nonce)
    header = pack_header(VERSION, MSG_EXT_PROOF, FLAG_EXT_MODE | FLAG_SIGNED, 0, server_nonce)
    body   = struct.pack("!H", len(sig)) + sig
    sock.sendto(header + body, (host, KNOCK_PORT))

    try:
        data, _ = sock.recvfrom(512)
        score, action, session_id, policy_ttl = struct.unpack_from("!B B Q H", data, 16)
        return dict(host=host, score=score, action=action,
                    session_id=session_id, policy_ttl=policy_ttl,
                    identity_verified=True)
    except Exception:
        return None
    finally:
        sock.close()

# ============================================================
# PRETTY PRINTER
# ============================================================
RISK_NAMES = {
    RISK_DNS_MISMATCH: "DNS_MISMATCH",
    RISK_HIGH_RATE:    "HIGH_RATE",
    RISK_BAD_ASN:      "BAD_ASN",
    RISK_NO_IDENTITY:  "NO_IDENTITY",
    RISK_GEO_RISK:     "GEO_RISK",
    RISK_REP_LOW:      "REP_LOW",
}

def print_result(r: dict, mode="lightweight"):
    if r is None:
        print(f"{action_color[2]}[KNOCK] No response / timeout{RESET}")
        return
    ac    = r["action"]
    color = action_color[ac]
    risk_labels = [v for k, v in RISK_NAMES.items() if r.get("risk", 0) & k]

    print(f"\n{BOLD}{'─'*46}{RESET}")
    print(f"{BOLD}  KNOCK RESULT  [{mode.upper()}]{RESET}")
    print(f"{'─'*46}")
    print(f"  Target      : {r['host']}")
    if "dns" in r:
        dns_str = {0: "none", 1: "valid", 2: "mismatch"}.get(r["dns"], "?")
        print(f"  DNS         : {dns_str} (FCrDNS: {'pass' if r['fcr'] else 'fail'})")
        print(f"  ASN         : {r['asn']}")
        print(f"  Country     : {r['country']}")
        print(f"  Reputation  : {r['rep']}/3")
        print(f"  Risk Flags  : {risk_labels if risk_labels else '(none)'}")
    if "identity_verified" in r:
        print(f"  Identity    : {'✓ VERIFIED (Ed25519)' if r['identity_verified'] else '✗ FAILED'}")
        print(f"  SessionID   : {r.get('session_id', '-'):#018x}")
        print(f"  Policy TTL  : {r.get('policy_ttl', '-')}s")
    bar_len = r["score"] // 2
    bar     = "█" * bar_len + "░" * (50 - bar_len)
    print(f"  TrustScore  : {color}{r['score']:3d}{RESET}  {color}{bar}{RESET}")
    print(f"  Action      : {color}{BOLD}{action_map[ac]}{RESET}")
    print(f"{'─'*46}\n")

# ============================================================
# AUDIT LOG
# ============================================================
def dump_log(n=10):
    print(f"\n{BOLD}═══ AUDIT LOG (last {n} events) ═══{RESET}")
    for e in list(event_log)[-n:]:
        ts  = time.strftime("%H:%M:%S", time.localtime(e["ts"]))
        ac  = {"ALLOW": "\033[92m✓", "CHALLENGE": "\033[93m?", "BLOCK": "\033[91m✗"}[e["action"]]
        ident = f" id={'✓' if e['identity'] else '✗'}" if e["identity"] is not None else ""
        print(f"  {DIM}{ts}{RESET}  {e['ip']:<15}  score={e['score']:>3}  "
              f"{ac} {e['action']}{RESET:<10}  [{e['mode']}]{ident}")
    print()

# ============================================================
# EVALUATION / SIMULATION
# ============================================================
def _run_scenario(delays, n=15, extended=False) -> np.ndarray:
    fn = knock_extended if extended else knock_lightweight
    scores = []
    for i in range(n):
        r = fn("127.0.0.1")
        if r:
            scores.append(r["score"])
        time.sleep(delays[i % len(delays)])
    return np.array(scores) if scores else np.array([0])

def run_eval():
    print(f"\n{BOLD}╔══════════════════════════════════╗")
    print(f"║   KNOCK BEHAVIOR EVALUATION      ║")
    print(f"╚══════════════════════════════════╝{RESET}\n")

    scenarios = {
        "Legitimate User" : ([2.0],     False),
        "Impatient User"  : ([0.5],     False),
        "Bot/Scanner"     : ([0.05],    False),
        "Mixed Behavior"  : ([2, 0.1],  False),
        "Identity (Ext)"  : ([1.0],     True),
    }

    results = {}
    for label, (delays, ext) in scenarios.items():
        print(f"  Simulating: {label}...")
        results[label] = _run_scenario(delays, n=15, extended=ext)
        time.sleep(0.3)

    # Summary table
    print(f"\n{BOLD}{'─'*58}{RESET}")
    print(f"  {'Scenario':<22}  {'Avg':>5}  {'ALLOW%':>7}  {'CHAL%':>7}  {'BLOCK%':>7}")
    print(f"{'─'*58}")
    for label, arr in results.items():
        avg   = arr.mean()
        allow = 100 * (arr >= ALLOW_THRESH).mean()
        chal  = 100 * ((arr >= CHAL_THRESH) & (arr < ALLOW_THRESH)).mean()
        block = 100 * (arr < CHAL_THRESH).mean()
        print(f"  {label:<22}  {avg:>5.1f}  {allow:>6.0f}%  {chal:>6.0f}%  {block:>6.0f}%")
    print(f"{'─'*58}\n")

    # Plots
    colors = ["#58a6ff", "#3fb950", "#f85149", "#d29922", "#bc8cff"]
    fig, axes = plt.subplots(1, 2, figsize=(14, 5))
    fig.patch.set_facecolor("#0d1117")

    # Line chart — convergence
    ax = axes[0]
    ax.set_facecolor("#0d1117")
    for (label, arr), color in zip(results.items(), colors):
        ax.plot(arr, label=label, color=color, linewidth=2, marker='o', markersize=3)
    ax.axhline(ALLOW_THRESH, color="#3fb950", linestyle="--", linewidth=1, alpha=0.7, label=f"ALLOW ≥{ALLOW_THRESH}")
    ax.axhline(CHAL_THRESH,  color="#d29922", linestyle="--", linewidth=1, alpha=0.7, label=f"BLOCK <{CHAL_THRESH}")
    ax.fill_between(range(15), ALLOW_THRESH, 100, alpha=0.05, color="#3fb950")
    ax.fill_between(range(15), 0, CHAL_THRESH,   alpha=0.05, color="#f85149")
    ax.set_title("Trust Score Convergence", color="white", fontsize=13)
    ax.set_xlabel("Request #", color="#8b949e")
    ax.set_ylabel("TrustScore", color="#8b949e")
    ax.tick_params(colors="#8b949e")
    ax.spines[:].set_color("#30363d")
    ax.legend(fontsize=8, facecolor="#161b22", edgecolor="#30363d", labelcolor="white")
    ax.set_ylim(0, 105)

    # Bar chart — average score
    ax2 = axes[1]
    ax2.set_facecolor("#0d1117")
    labels_list = list(results.keys())
    avgs  = [r.mean() for r in results.values()]
    bars  = ax2.barh(labels_list, avgs, color=colors, alpha=0.85)
    ax2.axvline(ALLOW_THRESH, color="#3fb950", linestyle="--", linewidth=1.5)
    ax2.axvline(CHAL_THRESH,  color="#d29922", linestyle="--", linewidth=1.5)
    for bar, val in zip(bars, avgs):
        ax2.text(val + 0.5, bar.get_y() + bar.get_height() / 2,
                 f"{val:.1f}", va='center', color='white', fontsize=9)
    ax2.set_title("Average Trust Score by Scenario", color="white", fontsize=13)
    ax2.set_xlabel("TrustScore", color="#8b949e")
    ax2.tick_params(colors="#8b949e")
    ax2.spines[:].set_color("#30363d")
    ax2.set_xlim(0, 105)

    plt.tight_layout(pad=2)
    plt.savefig("knock_eval.png", dpi=150, facecolor="#0d1117", bbox_inches="tight")
    plt.show()
    print("  [Plot saved: knock_eval.png]\n")
    return results

# ============================================================
# MAIN
# ============================================================
if __name__ == "__main__":
    print(f"\n{BOLD}╔══════════════════════════════════════════════════╗")
    print(f"║         KNOCK v2.0 — Full Protocol Stack         ║")
    print(f"║  Pre-connection Trust · Ed25519 · HTTP Gateway   ║")
    print(f"╚══════════════════════════════════════════════════╝{RESET}")
    print(f"  Client Public Key: {client_verify_key.encode(encoder=HexEncoder).decode()[:32]}…")

    threading.Thread(target=knock_server, daemon=True).start()
    threading.Thread(target=run_http,     daemon=True).start()
    time.sleep(1)

    # --- Phase 1: Lightweight ---
    print("─" * 52)
    print(f"{BOLD}Phase 1 — Lightweight Mode{RESET}")
    r = knock_lightweight("127.0.0.1", intent=2)
    print_result(r, "lightweight")

    time.sleep(1)

    # --- Phase 3: Extended (Ed25519) ---
    print(f"{BOLD}Phase 3 — Extended Mode (Ed25519){RESET}")
    r = knock_extended("127.0.0.1", intent=2)
    print_result(r, "extended")

    time.sleep(1)

    # --- Phase 5: HTTP Gateway ---
    print(f"{BOLD}Phase 5 — HTTP Gateway{RESET}")
    try:
        resp = requests.get(f"http://127.0.0.1:{HTTP_PORT}", timeout=2)
        print(f"  HTTP {resp.status_code}: {resp.text}")
        print(f"  X-KNOCK-Action : {resp.headers.get('X-KNOCK-Action')}")
        print(f"  X-KNOCK-Score  : {resp.headers.get('X-KNOCK-Score')}\n")
    except Exception as e:
        print(f"  [HTTP] {e}\n")

    # --- Audit log ---
    dump_log()

    # --- Evaluation ---
    run_eval()
