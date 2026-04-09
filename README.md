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
