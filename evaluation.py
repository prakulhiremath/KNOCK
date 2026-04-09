# ============================================================
# KNOCK v2.0 — Attack Simulation & Evaluation
# ============================================================

import time
import numpy as np
from collections import defaultdict
import matplotlib.pyplot as plt
import socket
import struct
import math

# Import KNOCK server components
# (In production, this would be: from knock import *)
# For now, we'll simulate the trust scoring logic

ALLOW_THRESH = 75
CHAL_THRESH = 40

def compute_trust_score(rep, dns, identity, behavior, intent):
    """Replicate KNOCK trust formula."""
    raw = (0.30 * rep + 0.20 * dns + 0.25 * identity + 0.15 * behavior + 0.10 * intent)
    return math.floor(raw * 100)

def decide(score):
    if score >= ALLOW_THRESH: return 0  # ALLOW
    if score >= CHAL_THRESH:  return 1  # CHALLENGE
    return 2  # BLOCK

# ============================================================
# ATTACK SIMULATORS
# ============================================================

class AttackSimulator:
    """Base class for attack simulations."""
    
    def __init__(self, name, num_requests=50):
        self.name = name
        self.num_requests = num_requests
        self.scores = []
        self.decisions = []
        self.timeline = []
    
def run(self):
        raise NotImplementedError
    
def stats(self):
        arr = np.array(self.scores)
        return {
            "mean": arr.mean(),
            "std": arr.std(),
            "min": arr.min(),
            "max": arr.max(),
            "allow_pct": 100 * (arr >= ALLOW_THRESH).mean(),
            "chal_pct": 100 * ((arr >= CHAL_THRESH) & (arr < ALLOW_THRESH)).mean(),
            "block_pct": 100 * (arr < CHAL_THRESH).mean(),
        }


class LegitimateUser(AttackSimulator):
    """Baseline: legitimate user with slow, spacing requests."""
    
    def run(self):
        rep = 0.3
        dns = 0.7
        identity = 0.5
        intent = 1.0
        
        for i in range(self.num_requests):
            # Improve reputation over time
            rep = min(1.0, rep + 0.02)
            
            # Good behavior (spacing)
            behavior = 0.8
            
            score = compute_trust_score(rep, dns, identity, behavior, intent)
            self.scores.append(score)
            self.decisions.append(decide(score))
            self.timeline.append(("legit", score))


class FastAttacker(AttackSimulator):
    """Attack: Hammer server with requests (high rate)."""
    
    def run(self):
        rep = 0.3
        dns = 0.2  # attacker has poor DNS
        identity = 0.2
        intent = 1.0
        
        for i in range(self.num_requests):
            # Rate attack detection
            behavior = 0.05  # very fast
            
            score = compute_trust_score(rep, dns, identity, behavior, intent)
            self.scores.append(score)
            self.decisions.append(decide(score))
            self.timeline.append(("fast_attack", score))


class SlowWarmupAttack(AttackSimulator):
    """Attack: Slow warmup over N requests, then burst."""
    
    def __init__(self, name="SlowWarmupAttack", warmup_pct=0.6):
        super().__init__(name)
        self.warmup_pct = warmup_pct
        self.warmup_len = int(self.num_requests * warmup_pct)
    
def run(self):
        rep = 0.3
        dns = 0.7
        identity = 0.4
        intent = 1.0
        
        # Phase 1: Warmup (legitimate-looking)
        for i in range(self.warmup_len):
            rep = min(1.0, rep + 0.01)
            behavior = 0.7  # slow & steady
            decay = max(0.3, 0.95 ** (i / 10))  # decay simulation
            rep_decayed = rep * decay
            
            score = compute_trust_score(rep_decayed, dns, identity, behavior, intent)
            self.scores.append(score)
            self.decisions.append(decide(score))
            self.timeline.append(("warmup", score))
        
        # Phase 2: Attack (high rate after buildup)
        for i in range(self.num_requests - self.warmup_len):
            behavior = 0.05  # sudden rate increase
            rep_decayed = rep * max(0.3, 0.95 ** ((self.warmup_len + i) / 10))
            
            score = compute_trust_score(rep_decayed, dns, identity, behavior, intent)
            self.scores.append(score)
            self.decisions.append(decide(score))
            self.timeline.append(("burst", score))


class KeyRotationAttack(AttackSimulator):
    """Attack: Change Ed25519 key every request."""
    
    def run(self):
        rep = 0.3
        dns = 0.7
        identity = 0.5
        intent = 1.0
        
        for i in range(self.num_requests):
            # Penalize key rotation
            rotation_penalty = -10 if i > 0 else 0
            
            # Identity degrades with each new key
            identity = max(0.1, 0.5 - (i * 0.05))
            
            behavior = 0.8
            
            score = compute_trust_score(rep, dns, identity, behavior, intent)
            score += rotation_penalty
            score = max(0, min(100, score))
            
            self.scores.append(score)
            self.decisions.append(decide(score))
            self.timeline.append(("key_rotation", score))


class AdaptiveAttacker(AttackSimulator):
    """Attack: Learn thresholds and adapt."""
    
    def run(self):
        rep = 0.3
        dns = 0.2
        identity = 0.2
        intent = 1.0
        
        threshold_estimate = None
        
        for i in range(self.num_requests):
            # Phase 1: Probe (requests 0-15)
            if i < 15:
                behavior = 0.7 - (i * 0.01)  # gradually increase rate
            # Phase 2: Learn from feedback (requests 15-30)
            elif i < 30:
                # Estimate based on observed scores
                if threshold_estimate is None and i > 20:
                    avg_recent = np.mean(self.scores[-5:])
                    threshold_estimate = avg_recent
                behavior = 0.5
            # Phase 3: Attack (requests 30+)
            else:
                # Just below threshold to stay in CHALLENGE
                behavior = 0.1
            
            # Slowly improve reputation
            rep = min(1.0, rep + 0.005)
            
            score = compute_trust_score(rep, dns, identity, behavior, intent)
            self.scores.append(score)
            self.decisions.append(decide(score))
            self.timeline.append(("adaptive", score))


class DistributedLowSlowAttack(AttackSimulator):
    """Attack: Multiple IPs, each slow & low-volume."""
    
    def __init__(self, name="DistributedLowSlowAttack", num_ips=10):
        super().__init__(name)
        self.num_ips = num_ips
    
def run(self):
        # Each IP simulated independently
        ip_scores = defaultdict(list)
        
        for ip_id in range(self.num_ips):
            rep = 0.3
            dns = 0.7
            identity = 0.4
            
            for req in range(self.num_requests // self.num_ips):
                rep = min(1.0, rep + 0.02)
                behavior = 0.8  # slow on each IP
                intent = 1.0
                
                score = compute_trust_score(rep, dns, identity, behavior, intent)
                ip_scores[ip_id].append(score)
                self.scores.append(score)
        
        # Aggregate decisions
        for score in self.scores:
            self.decisions.append(decide(score))
            self.timeline.append(("distributed", score))


# ============================================================
# EVALUATION FRAMEWORK
# ============================================================

def run_evaluation_suite():
    """Run all attack simulations and generate report."""
    
    print("\n" + "="*70)
    print("  KNOCK v2.0 — Attack Simulation & Robustness Evaluation")
    print("="*70 + "\n")
    
    attacks = [
        LegitimateUser(name="Legitimate User", num_requests=50),
        FastAttacker(name="Fast Attacker (Hammering)", num_requests=50),
        SlowWarmupAttack(name="Slow Warmup Attack", warmup_pct=0.6),
        KeyRotationAttack(name="Key Rotation Attack", num_requests=50),
        AdaptiveAttacker(name="Adaptive Attacker (Learning)", num_requests=50),
        DistributedLowSlowAttack(name="Distributed Low&Slow (10 IPs)", num_ips=10),
    ]
    
    results = {}
    
    print("Running attack simulations...\n")
    for attack in attacks:
        attack.run()
        results[attack.name] = attack
        stats = attack.stats()
        
        print(f"  {attack.name}")
        print(f"    Mean Score  : {stats['mean']:.1f}")
        print(f"    Std Dev     : {stats['std']:.1f}")
        print(f"    Range       : [{stats['min']:.0f}, {stats['max']:.0f}]")
        print(f"    ALLOW %     : {stats['allow_pct']:.1f}%")
        print(f"    CHALLENGE % : {stats['chal_pct']:.1f}%")
        print(f"    BLOCK %     : {stats['block_pct']:.1f}%")
        print()
    
    # Generate summary table
    print("-" * 70)
    print(f"  {'Attack Scenario':<35} {'Avg Score':>10} {'ALLOW%':>10} {'BLOCK%':>10}")
    print("-" * 70)
    for attack in attacks:
        stats = attack.stats()
        print(f"  {attack.name:<35} {stats['mean']:>10.1f} {stats['allow_pct']:>9.1f}% {stats['block_pct']:>9.1f}%")
    print("-" * 70 + "\n")
    
    return results


def generate_roc_curves(results):
    """Generate ROC curves (FPR vs TPR)."""
    
    # True positive: legit user marked ALLOW
    legit_allow = np.array(results["Legitimate User"].decisions)
    legit_tpr = (legit_allow == 0).mean()  # Should be high
    
    # False positive: attacker marked ALLOW
    attack_scores = []
    attack_names = []
    for name, sim in results.items():
        if "Attack" in name or "Adaptive" in name or "Distributed" in name:
            attack_arr = np.array(sim.decisions)
            fpr = (attack_arr == 0).mean()
            attack_scores.append(fpr)
            attack_names.append(name)
    
    print("ROC Analysis:")
    print(f"  Legitimate User TPR (ALLOW rate): {legit_tpr:.1%}")
    print(f"  Attacker FPRs (false ALLOWs):")
    for name, fpr in zip(attack_names, attack_scores):
        print(f"    {name:<40} : {fpr:.1%}")
    
    return legit_tpr, attack_scores


def generate_plots(results):
    """Generate visualization plots."""
    
    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    fig.patch.set_facecolor("#0d1117")
    
    # Plot 1: Score distributions (box plot)
    ax = axes[0, 0]
    ax.set_facecolor("#0d1117")
    
    data = [np.array(sim.scores) for sim in results.values()]
    labels = [name for name in results.keys()]
    
    bp = ax.boxplot(data, labels=labels, patch_artist=True)
    for patch in bp['boxes']:
        patch.set_facecolor("#58a6ff")
    ax.axhline(ALLOW_THRESH, color="#3fb950", linestyle="--", linewidth=1.5, label=f"ALLOW ≥ {ALLOW_THRESH}")
    ax.axhline(CHAL_THRESH, color="#d29922", linestyle="--", linewidth=1.5, label=f"BLOCK < {CHAL_THRESH}")
    ax.set_title("Score Distribution by Attack", color="white", fontsize=12)
    ax.set_ylabel("Trust Score", color="#8b949e")
    ax.tick_params(axis='x', rotation=45, colors="#8b949e")
    ax.tick_params(axis='y', colors="#8b949e")
    ax.spines[:].set_color("#30363d")
    ax.legend(fontsize=9, facecolor="#161b22", edgecolor="#30363d", labelcolor="white")
    
    # Plot 2: Convergence (line chart)
    ax = axes[0, 1]
    ax.set_facecolor("#0d1117")
    
    colors = ["#58a6ff", "#3fb950", "#f85149", "#d29922", "#bc8cff", "#79c0ff"]
    for (name, sim), color in zip(results.items(), colors):
        ax.plot(sim.scores, label=name, color=color, linewidth=1.5, alpha=0.8)
    
    ax.axhline(ALLOW_THRESH, color="#3fb950", linestyle="--", linewidth=1, alpha=0.5)
    ax.axhline(CHAL_THRESH, color="#d29922", linestyle="--", linewidth=1, alpha=0.5)
    ax.fill_between(range(len(sim.scores)), ALLOW_THRESH, 100, alpha=0.05, color="#3fb950")
    ax.fill_between(range(len(sim.scores)), 0, CHAL_THRESH, alpha=0.05, color="#f85149")
    ax.set_title("Score Convergence Over Time", color="white", fontsize=12)
    ax.set_xlabel("Request #", color="#8b949e")
    ax.set_ylabel("Trust Score", color="#8b949e")
    ax.tick_params(colors="#8b949e")
    ax.spines[:].set_color("#30363d")
    ax.legend(fontsize=7, loc="best", facecolor="#161b22", edgecolor="#30363d", labelcolor="white")
    
    # Plot 3: Decision distribution (stacked bar)
    ax = axes[1, 0]
    ax.set_facecolor("#0d1117")
    
    allow_pcts = []
    chal_pcts = []
    block_pcts = []
    
    for sim in results.values():
        stats = sim.stats()
        allow_pcts.append(stats["allow_pct"])
        chal_pcts.append(stats["chal_pct"])
        block_pcts.append(stats["block_pct"])
    
    x_pos = np.arange(len(results))
    ax.bar(x_pos, allow_pcts, label="ALLOW", color="#3fb950", alpha=0.8)
    ax.bar(x_pos, chal_pcts, bottom=allow_pcts, label="CHALLENGE", color="#d29922", alpha=0.8)
    ax.bar(x_pos, block_pcts, bottom=np.array(allow_pcts) + np.array(chal_pcts), 
           label="BLOCK", color="#f85149", alpha=0.8)
    
    ax.set_title("Decision Distribution", color="white", fontsize=12)
    ax.set_ylabel("Percentage", color="#8b949e")
    ax.set_xticks(x_pos)
    ax.set_xticklabels(results.keys(), rotation=45, ha='right')
    ax.tick_params(colors="#8b949e")
    ax.spines[:].set_color("#30363d")
    ax.legend(fontsize=9, facecolor="#161b22", edgecolor="#30363d", labelcolor="white")
    
    # Plot 4: FPR vs TPR (ROC-like)
    ax = axes[1, 1]
    ax.set_facecolor("#0d1117")
    
    legit_tpr, attack_fprs = generate_roc_curves(results)
    
    # Plot points
    attack_names_short = [name.split("(")[0].strip() for name in results.keys() if "Attack" in name or "Adaptive" in name or "Distributed" in name]
    
    ax.scatter([0], [legit_tpr], s=200, color="#3fb950", marker='o', label="Legit User (TPR)", zorder=5)
    for i, (name, fpr) in enumerate(zip(attack_names_short, attack_fprs)):
        ax.scatter([fpr], [0.5], s=150, color="#f85149", marker='x', linewidth=2)
        ax.annotate(name, (fpr, 0.5), xytext=(5, 5), textcoords='offset points', 
                   fontsize=7, color="#8b949e")
    
    # ROC reference line (random classifier)
    ax.plot([0, 1], [0, 1], "--", color="#8b949e", alpha=0.5, label="Random")
    
    ax.set_xlim(-0.05, 1.05)
    ax.set_ylim(-0.05, 1.05)
    ax.set_title("ROC-like Analysis (FPR vs TPR)", color="white", fontsize=12)
    ax.set_xlabel("False Positive Rate (Attacker ALLOW %)", color="#8b949e")
    ax.set_ylabel("True Positive Rate (Legit ALLOW %)", color="#8b949e")
    ax.tick_params(colors="#8b949e")
    ax.spines[:].set_color("#30363d")
    ax.legend(fontsize=9, facecolor="#161b22", edgecolor="#30363d", labelcolor="white")
    
    plt.tight_layout()
    plt.savefig("knock_attack_evaluation.png", dpi=150, facecolor="#0d1117", bbox_inches="tight")
    print("  [Plot saved: knock_attack_evaluation.png]")
    plt.show()


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":
    results = run_evaluation_suite()
    generate_roc_curves(results)
    generate_plots(results)
