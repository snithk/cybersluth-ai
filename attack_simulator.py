"""
╔══════════════════════════════════════════════════════════════════╗
║   CyberSleuth AI — Fake Attack Simulator                         ║
║   Generates realistic attack traffic to test the dashboard       ║
║                                                                   ║
║   Usage:                                                          ║
║     python attack_simulator.py                                    ║
║                                                                   ║
║   Outputs:                                                        ║
║     attack_simulation.csv  → Upload this to the dashboard        ║
║     attack_sim.log         → Auto-detected by the log analyzer   ║
╚══════════════════════════════════════════════════════════════════╝
"""

import csv
import random
import time
import os
from datetime import datetime, timedelta

# ── Configuration ──────────────────────────────────────────────────────────────
OUTPUT_CSV  = "attack_simulation.csv"
OUTPUT_LOG  = "attack_sim.log"
TOTAL_ROWS  = 500          # total packets to generate

# Attack wave schedule  (label, start%, end%, description)
# The simulator cycles through benign + attack bursts
ATTACK_WAVES = [
    # Warm-up: normal traffic
    {"type": "Benign",     "start": 0.00, "end": 0.12, "desc": "Normal baseline traffic"},
    # First wave: Port Scan
    {"type": "PortScan",   "start": 0.12, "end": 0.25, "desc": "Attacker reconnaissance scan"},
    # Return to normal
    {"type": "Benign",     "start": 0.25, "end": 0.32, "desc": "Normal traffic resumes"},
    # Second wave: Brute Force attack on SSH
    {"type": "BruteForce", "start": 0.32, "end": 0.48, "desc": "SSH brute-force login attempt"},
    # Brief calm
    {"type": "Benign",     "start": 0.48, "end": 0.54, "desc": "Normal traffic"},
    # Third wave: DDoS flood
    {"type": "DDoS",       "start": 0.54, "end": 0.75, "desc": "DDoS volumetric flood attack"},
    # Slight recovery
    {"type": "Benign",     "start": 0.75, "end": 0.80, "desc": "Partial recovery"},
    # Mixed attack (worst phase)
    {"type": "DDoS",       "start": 0.80, "end": 0.90, "desc": "Sustained DDoS flood"},
    {"type": "BruteForce", "start": 0.90, "end": 0.95, "desc": "Follow-up brute force"},
    # System secured
    {"type": "Benign",     "start": 0.95, "end": 1.00, "desc": "Attack stopped — system secured"},
]

# ── IP pools ───────────────────────────────────────────────────────────────────
INTERNAL_IPS = [f"10.0.0.{i}"       for i in range(1, 20)]
ATTACKER_IPS = [f"185.220.{r}.{e}"  for r in range(100, 110) for e in range(1, 6)]
BOT_IPS      = [f"45.155.{r}.{e}"   for r in range(200, 210) for e in range(1, 6)]
SERVER_IPS   = ["10.0.0.1", "10.0.0.2", "10.0.0.5", "192.168.1.1"]

# ── Traffic templates ──────────────────────────────────────────────────────────
def make_benign(ts):
    src = random.choice(INTERNAL_IPS)
    dst = random.choice(SERVER_IPS)
    proto = random.choice(["TCP", "TCP", "TCP", "UDP", "ICMP"])
    flags = random.choice(["SYN", "ACK", "PSH", "FIN"])
    return {
        "timestamp":     ts.strftime("%Y-%m-%d %H:%M:%S"),
        "src_ip":        src,
        "dst_ip":        dst,
        "src_port":      random.randint(49152, 65535),
        "dst_port":      random.choice([80, 443, 8080, 53]),
        "protocol":      proto,
        "packet_length": random.randint(64, 512),
        "duration":      round(random.uniform(0.1, 1.5), 3),
        "flags":         flags,
        "label":         "Benign",
    }

def make_port_scan(ts):
    """One attacker probing many ports — short duration, small packets, SYN."""
    attacker = random.choice(ATTACKER_IPS)
    target   = random.choice(SERVER_IPS)
    return {
        "timestamp":     ts.strftime("%Y-%m-%d %H:%M:%S"),
        "src_ip":        attacker,
        "dst_ip":        target,
        "src_port":      random.randint(1024, 65535),
        "dst_port":      random.randint(1, 1024),   # scanning well-known ports
        "protocol":      "TCP",
        "packet_length": random.randint(40, 80),    # tiny probe packets
        "duration":      round(random.uniform(0.001, 0.02), 4),
        "flags":         "SYN",
        "label":         "PortScan",
    }

def make_brute_force(ts):
    """Repeated login attempts against SSH (port 22) or RDP (port 3389)."""
    attacker  = random.choice(ATTACKER_IPS)
    target    = random.choice(SERVER_IPS)
    dst_port  = random.choice([22, 22, 22, 3389])  # mostly SSH
    return {
        "timestamp":     ts.strftime("%Y-%m-%d %H:%M:%S"),
        "src_ip":        attacker,
        "dst_ip":        target,
        "src_port":      random.randint(1024, 65535),
        "dst_port":      dst_port,
        "protocol":      "TCP",
        "packet_length": random.randint(100, 300),
        "duration":      round(random.uniform(0.05, 0.3), 3),
        "flags":         random.choice(["SYN", "ACK", "SYN"]),
        "label":         "BruteForce",
    }

def make_ddos(ts):
    """Volumetric flood — many bots, huge packets, short duration, UDP."""
    bot    = random.choice(BOT_IPS + ATTACKER_IPS)
    target = random.choice(SERVER_IPS)
    proto  = random.choice(["UDP", "UDP", "UDP", "TCP", "ICMP"])
    return {
        "timestamp":     ts.strftime("%Y-%m-%d %H:%M:%S"),
        "src_ip":        bot,
        "dst_ip":        target,
        "src_port":      random.randint(1024, 65535),
        "dst_port":      random.choice([80, 443, 53, 123]),
        "protocol":      proto,
        "packet_length": random.randint(900, 1500),  # large flood packets
        "duration":      round(random.uniform(0.001, 0.05), 4),
        "flags":         random.choice(["SYN", "ACK", "SYN-ACK", "SYN"]),
        "label":         "DDoS",
    }

GENERATORS = {
    "Benign":     make_benign,
    "PortScan":   make_port_scan,
    "BruteForce": make_brute_force,
    "DDoS":       make_ddos,
}

# ── Log message templates ──────────────────────────────────────────────────────
LOG_TEMPLATES = {
    "PortScan": [
        "ALERT: nmap -sS port scan detected from {ip} at {ts}",
        "WARNING: network scan activity from {ip} — multiple ports probed",
        "SECURITY: port scan detected — source {ip} scanning {port}",
    ],
    "BruteForce": [
        "ALERT: hydra SSH brute force — failed login from {ip} at {ts}",
        "SECURITY: authentication failure — brute force attempt from {ip} on port 22",
        "WARNING: failed login attempt #{n} from {ip} — possible brute force detected",
    ],
    "DDoS": [
        "CRITICAL: hping3 ddos flood detected — {ip} sending {pkt} packets/sec",
        "ALERT: excessive traffic detected from {ip} — DDoS flood in progress",
        "CRITICAL: ddos attack — high packet rate from {ip} targeting {target}",
    ],
}

def write_log_entry(logfile, attack_type, src_ip, target_ip, ts):
    """Write a realistic log line for the log analyzer to detect."""
    templates = LOG_TEMPLATES.get(attack_type, [])
    if not templates:
        return
    msg = random.choice(templates).format(
        ip=src_ip,
        ts=ts.strftime("%Y-%m-%d %H:%M:%S"),
        port=random.randint(1, 1024),
        n=random.randint(5, 200),
        pkt=random.randint(10000, 100000),
        target=target_ip,
    )
    logfile.write(f"{ts.strftime('%Y-%m-%d %H:%M:%S')} [ATTACK-SIM] {msg}\n")
    logfile.flush()

# ── Main simulator ─────────────────────────────────────────────────────────────
def get_attack_type_for_row(row_index, total):
    progress = row_index / total
    for wave in ATTACK_WAVES:
        if wave["start"] <= progress < wave["end"]:
            return wave["type"], wave["desc"]
    return "Benign", "Normal traffic"

def run_simulation():
    print("=" * 65)
    print("  CyberSleuth AI — Fake Attack Simulator")
    print("=" * 65)
    print(f"\n  Generating {TOTAL_ROWS} packets across {len(ATTACK_WAVES)} attack waves...\n")

    fieldnames = [
        "timestamp", "src_ip", "dst_ip",
        "src_port", "dst_port", "protocol",
        "packet_length", "duration", "flags", "label"
    ]

    # Starting timestamp — now
    current_ts = datetime.now() - timedelta(seconds=TOTAL_ROWS)

    rows_written  = 0
    attack_counts = {"Benign": 0, "PortScan": 0, "BruteForce": 0, "DDoS": 0}
    current_wave  = None

    with open(OUTPUT_CSV, "w", newline="") as csvfile, \
         open(OUTPUT_LOG, "w") as logfile:

        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        logfile.write(f"# CyberSleuth Attack Simulation Log — {datetime.now()}\n")
        logfile.write("# This file is monitored by the log analyzer\n\n")

        for i in range(TOTAL_ROWS):
            attack_type, wave_desc = get_attack_type_for_row(i, TOTAL_ROWS)

            # Print wave transition
            if wave_desc != current_wave:
                current_wave = wave_desc
                pct = int(i / TOTAL_ROWS * 100)
                tag = f"[{attack_type}]"
                print(f"  {pct:>3}%  {tag:<13}  {wave_desc}")

            # Generate the packet row
            generator = GENERATORS.get(attack_type, make_benign)
            row = generator(current_ts)
            writer.writerow(row)
            attack_counts[attack_type] = attack_counts.get(attack_type, 0) + 1

            # Write log entries for attack traffic (every few packets)
            if attack_type != "Benign" and i % 3 == 0:
                write_log_entry(
                    logfile, attack_type,
                    row["src_ip"], row["dst_ip"], current_ts
                )

            current_ts += timedelta(seconds=1)
            rows_written += 1

    # ── Summary ────────────────────────────────────────────────────────────────
    print("\n" + "=" * 65)
    print("  ✅  Simulation complete!")
    print("=" * 65)
    print(f"\n  📄  CSV  →  {OUTPUT_CSV}  ({rows_written} rows)")
    print(f"  📋  Log  →  {OUTPUT_LOG}")
    print(f"\n  Traffic breakdown:")
    total = sum(attack_counts.values())
    for label, count in attack_counts.items():
        bar = "█" * int(count / total * 30)
        pct = count / total * 100
        print(f"    {label:<12} {bar:<30}  {count:>4} packets  ({pct:.1f}%)")

    print(f"""
  ─────────────────────────────────────────────────────────────
  HOW TO TEST YOUR DASHBOARD:
  ─────────────────────────────────────────────────────────────
  1. Start the dashboard:
       streamlit run app.py

  2. In the sidebar:
       • Uncheck  "Use built-in dataset"
       • Upload   "{OUTPUT_CSV}"
       • Enable   "Auto-block attacking IPs"
       • Click    ▶️ Start

  3. Watch the alarms fire as the attack waves arrive!
     The log analyzer will also detect entries in {OUTPUT_LOG}
  ─────────────────────────────────────────────────────────────
""")

if __name__ == "__main__":
    run_simulation()
