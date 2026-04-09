# KNOCK v2.0 Production Implementation

import hashlib
import time
import json

class KNOCK:
    def __init__(self):
        self.reputation = {}

    def crc_verification(self, data):
        # Generate CRC for verification
        return hashlib.md5(data.encode()).hexdigest()

    def verify_nonce(self, nonce, expiry_time):
        # Check if nonce has expired
        return time.time() < expiry_time

    def bind_ip_pubkey(self, ip, pubkey):
        # Simulates IP-Pubkey binding
        binding = {"ip": ip, "pubkey": pubkey}
        return json.dumps(binding)

    def decision_with_ttl(self, decision, ttl):
        # Store decision with a TTL
        expiry = time.time() + ttl
        return {"decision": decision, "expiry": expiry}

    def reputation_decay(self, user):
        # Decay reputation over time
        if user in self.reputation:
            self.reputation[user] *= 0.9  # Decay factor is 10%
            return self.reputation[user]
        return None
