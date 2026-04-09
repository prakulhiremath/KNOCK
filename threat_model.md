# KNOCK v2.0 — Threat Model & Security Analysis

## 1. Adversary Model

### Capability Levels

**Level 1: Network-level attacker**
- Can craft and send arbitrary UDP packets
- Can observe timing, packet loss, and response patterns
- Cannot break cryptography or DNS

**Level 2: Distributed botnet**
- Multiple IPs under attacker control
- Can coordinate timing and volume
- No access to victim's private keys

**Level 3: Adaptive attacker**
- Observes system behavior
- Learns trust thresholds
- Adapts attack strategy in real-time
- No ability to compromise internal state

### Constraints

- Cannot forge Ed25519 signatures (pre-shared public key model)
- Cannot intercept SSL/TLS after KNOCK clears
- Cannot forge DNS records (assuming DNSSEC or FCrDNS validation)
- Cannot directly access server state or logs

---

## 2. Threat Scenarios

### 2.1 Rate-Based Attack (Hammering)

**Attack**: Send requests as fast as possible

**Goal**: Exhaust capacity, bypass behavioral throttling

**Mitigation**:
- Behavior score: `delta < 0.3 → 0.1` (low confidence)
- Decision TTL prevents decision reuse
- UDP rate limiting at OS level

**Status**: ✅ Resistant

---

### 2.2 Slow Warmup Attack

**Attack**: Send legitimate-looking traffic for days to build reputation, then burst attack

**Goal**: Bypass reputation-based defenses

**Mitigation**:
- Reputation decay: `rep = rep_raw × 0.95^(elapsed_min)`
- Success credits expire (cap decay at 60 min)
- Behavior score still evaluates recent patterns
- Even with rep=0.7, behavior=0.1 → score ≈ 40 (CHALLENGE)

**Analysis**:
