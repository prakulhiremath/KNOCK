# KNOCK v2.0 — Pre-Connection Trust Protocol

A production-grade implementation of **KNOCK**, a cryptographically-authenticated pre-connection trust evaluation system using Ed25519 identity, behavioral analysis, and DNS validation.

**Ideal for**: Zero-trust networks, API gateways, botnet mitigation, identity-first access control.

---

## Features

- 🔐 **Ed25519 Challenge-Response**: Prove identity before trust evaluation
- 📊 **Multi-Signal Trust Scoring**: Reputation decay, behavior analysis, DNS validation
- 🛡️ **Replay & Nonce Protection**: CRC verification, time-bounded nonce cache
- 🔄 **Identity Rotation Detection**: Penalize suspicious key swaps
- ⏱️ **TTL-Bound Decisions**: No stale trust decisions
- 🌐 **HTTP Gateway**: Simple integration with reverse proxies
- 📈 **Attack Simulation**: Built-in evaluation framework for robustness testing

---

## Quick Start

### Install

```bash
git clone https://github.com/prakulhiremath/KNOCK.git
cd KNOCK
pip install -r requirements.txt
Run Demo

bash
python knock.py
Output:

Code
[KNOCK] Server v1.0 on UDP:5005
[HTTP]  Gateway on http://127.0.0.1:8082

────────────────────────────────────────────────
Phase 1 — Lightweight Mode

──────────────────────────────
  KNOCK RESULT  [LIGHTWEIGHT]
──────────────────────────────
  Target      : 127.0.0.1
  DNS         : valid (FCrDNS: pass)
  ASN         : 15169
  Country     : US
  Reputation  : 2/3
  Risk Flags  : (none)
  TrustScore  : 85  ███████████████████████
  Action      : ALLOW
──────────────────────────────
Run Attack Evaluation

bash
python evaluation.py
Simulates:

Legitimate user baseline
Fast hammering attacks
Slow warmup → burst attacks
Ed25519 key rotation attacks
Adaptive attackers (learn thresholds)
Distributed low-and-slow attacks
Generates ROC curves and convergence plots.

Architecture

Message Flow

Code
Client                                    Server
  │                                         │
  ├─ KNOCK_REQ (lightweight) ─────────────>│
  │  • Nonce (µs timestamp)                 │ Compute trust score:
  │  • Intent                                │ T = 0.30×Rep + 0.20×DNS
  │  • CRC32 verified                        │   + 0.25×Identity
  │                                         │   + 0.15×Behavior
  │<────────── KNOCK_RES ──────────────────┤ + 0.10×Intent
  │  • Score (0–100)                        │
  │  • Action (ALLOW/CHALLENGE/BLOCK)       │ Store decision (TTL: 300s)
  │  • Risk flags                           │
  │  • FCrDNS, ASN, Country                 │
  │
  ├─ EXT_INIT (extended) ─────────────────>│ Generate server_nonce
  │  • Public key (Ed25519)                 │
  │  • Timestamp (freshness)                │
  │                                         │
  │<────────── EXT_CHAL ───────────────────┤
  │  • server_nonce                         │
  │                                         │
  ├─ EXT_PROOF ───────────────────────────>│ Verify signature
  │  • sig(server_nonce, privkey)           │ Track key rotation
  │                                         │ Recompute score
  │<────────── EXT_DEC ────────────────────┤
  │  • Score + Action                       │
  │  • Session ID (300s TTL)                │
Trust Score Formula

Code
T = 0.30 × Reputation 
  + 0.20 × DNS_Validation
  + 0.25 × Identity_Proof
  + 0.15 × Behavior
  + 0.10 × Intent_Signal

Thresholds:
  T ≥ 75  → ALLOW
  40 ≤ T < 75 → CHALLENGE
  T < 40  → BLOCK
Signal Descriptions

Signal	Range	How It Works
Reputation	[0, 1]	(success + 1) / (count + 2) × decay^(elapsed_min)
DNS	[0, 1]	FCrDNS validation: 1.0 (pass), 0.6 (partial), 0.3 (none)
Identity	[0, 1]	Ed25519 proof: 1.0 (valid sig), 0.2 (invalid or new)
Behavior	[0, 1]	Inter-request timing: 1.0 (spacing > 2s), 0.1 (hammering < 0.3s)
Intent	[0, 1]	Declared protocol version: 1.0 (expected), 0.5 (unexpected)
Security Model

Adversary Capabilities

Level 1: Network-level attacker

Craft arbitrary UDP packets
Observe timing and patterns
Cannot break Ed25519 or DNS
Level 2: Distributed botnet

Multiple IPs under control
Coordinate attacks
Cannot forge signatures or compromise internal state
Attack Resistance

Attack	Status	Mitigation
Rate hammering	✅ Resistant	Behavior score: delta < 0.3 → 0.1
Slow warmup + burst	✅ Resistant	Reputation decay: 0.95^(elapsed_min)
Key rotation	✅ Resistant	Track IP↔pubkey; -10 penalty per rotation
Replay	✅ Resistant	CRC verification, nonce cache (5s TTL)
Adaptive learning	✅ Resistant	No information leak on score vs response time
Distributed low-slow	⚠️ Economically infeasible	Cost: thousands of "warmup IPs" over days
See docs/SECURITY.md for formal threat model.

Configuration

Edit knock.py:

Python
KNOCK_PORT   = 5005          # UDP listen port
HTTP_PORT    = 8082          # HTTP gateway port
ALLOW_THRESH = 75            # Score → ALLOW
CHAL_THRESH  = 40            # Score → BLOCK
TIMEOUT_MS   = 500           # Client timeout
NONCE_TTL_SEC = 5            # Replay window
DECISION_TTL_SEC = 300       # Cache duration (5 min)
Integration

As Reverse Proxy

Python
# Incoming request to :8082
# Server checks: GET /some/path from 203.0.113.45
#
# 1. Lookup in ip_decisions cache
# 2. If decision exists and not expired:
#    - ALLOW (200) → forward to origin
#    - CHALLENGE (401) → client must complete KNOCK protocol
#    - BLOCK (403) → reject
# 3. If expired, client starts new KNOCK handshake
Direct UDP Integration

Python
from knock import knock_lightweight, knock_extended

# Lightweight (fast, low-overhead)
result = knock_lightweight("203.0.113.45")
if result["action"] == 0:  # ALLOW
    grant_access()

# Extended (with identity proof)
result = knock_extended("203.0.113.45")
if result["identity_verified"] and result["action"] == 0:
    grant_premium_access()
Performance

Latency

Lightweight: ~50ms (1 RTT over 50ms latency network)
Extended: ~150ms (3 RTT: INIT → CHAL → PROOF → DEC)
Memory

Per-IP state: ~500 bytes (stats + decision + pubkey history)
Nonce cache: 10k entries × 16 bytes = 160 KB
Session cache: ~1KB per active session
Throughput

UDP server: ~10k packets/sec (on modern CPU)
HTTP gateway: ~1k req/sec (single-threaded)
Testing

Run All Tests

bash
python -m pytest tests/
Run Specific Test Suite

bash
# Threat model validation
python tests/test_security.py

# Attack simulation
python evaluation.py

# Integration tests
python tests/test_integration.py
Papers & References

KNOCK is inspired by:

Port knocking (traditional)
Modern pre-connection trust (Google BeyondCorp)
Behavioral botnet detection (Rajab et al., Icecast)
See docs/PAPER_NOTES.md for research positioning.

Limitations & Future Work

Known Limitations

No IP spoofing protection (UDP constraint)
Mitigation: Deploy behind firewall with IP filtering
Privacy via IP grouping
Many IPs = attacks harder to correlate
Mitigation: Geo-reputation, ASN-level signals
Distributed attacks
Economically infeasible but possible at scale
Mitigation: Machine learning on flow patterns
Future Enhancements

 Machine learning classifier (random forest on features)
 Multi-factor trust (biometric, 2FA token challenges)
 Geo-reputation and ASN reputation scoring
 Integration with Redis for distributed cache
 Kubernetes ingress controller plugin
 Grafana dashboard for decision analytics
Contributing

Contributions welcome! Focus areas:

 Additional signal sources (TLS fingerprinting, JA3)
 Advanced anomaly detection
 Kubernetes integration
 Performance optimizations
 Additional test coverage

License
MIT

Contact

Author: Prakul Hiremath
GitHub: @prakulhiremath
Questions: File an issue or start a discussion
