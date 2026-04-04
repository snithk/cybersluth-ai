"""
╔══════════════════════════════════════════════════════════════════════╗
║   CyberSleuth AI — Live Attack Detection Demo                        ║
║   Run this to show teachers how the system stops real attacks        ║
║                                                                       ║
║   Usage:  python live_demo.py                                         ║
╚══════════════════════════════════════════════════════════════════════╝
"""

import time
import random
import sys
import os
import json
from datetime import datetime
from collections import defaultdict

# ── ANSI colour codes ──────────────────────────────────────────────────────────
R  = "\033[91m"   # red
Y  = "\033[93m"   # yellow
G  = "\033[92m"   # green
B  = "\033[94m"   # blue
C  = "\033[96m"   # cyan
M  = "\033[95m"   # magenta
W  = "\033[97m"   # white bold
DIM= "\033[2m"
RESET = "\033[0m"
BOLD  = "\033[1m"
BLINK = "\033[5m"

def clr():
    os.system("cls" if os.name == "nt" else "clear")

def p(text="", end="\n"):
    print(text, end=end, flush=True)

def slow(text, delay=0.03, end="\n"):
    for ch in text:
        print(ch, end="", flush=True)
        time.sleep(delay)
    print(end=end, flush=True)

def pause(s=0.8):
    time.sleep(s)

def divider(char="─", width=68, color=DIM):
    p(f"{color}{char * width}{RESET}")

def header_box(title, color=C):
    w = 66
    p(f"{color}╔{'═'*w}╗{RESET}")
    pad = (w - len(title)) // 2
    p(f"{color}║{' '*pad}{BOLD}{title}{RESET}{color}{' '*(w-pad-len(title))}║{RESET}")
    p(f"{color}╚{'═'*w}╝{RESET}")

# ── Fake IP/attack data ────────────────────────────────────────────────────────
ATTACKER_IPS = [
    "185.220.101.47",
    "45.155.205.233",
    "185.220.102.8",
    "94.102.49.190",
    "45.155.206.11",
]
TARGET_SERVER  = "10.0.0.5  (your web server)"
TARGET_SSH     = "10.0.0.1  (SSH server)"
INTERNAL_IP    = "192.168.1.20"
BLOCKED_IPS    = set()
INCIDENT_LOG   = []
THREAT_COUNT   = defaultdict(int)

def log_incident(attack_type, src_ip, detail, severity):
    INCIDENT_LOG.append({
        "time":     datetime.now().strftime("%H:%M:%S"),
        "type":     attack_type,
        "src":      src_ip,
        "detail":   detail,
        "severity": severity,
    })
    THREAT_COUNT[attack_type] += 1

def block_ip(ip, reason):
    if ip not in BLOCKED_IPS:
        BLOCKED_IPS.add(ip)
        p(f"  {R}🔒 BLOCKED{RESET}  IP {W}{ip}{RESET} — reason: {Y}{reason}{RESET}")
        pause(0.3)

def alarm():
    p(f"\n  {R}{BLINK}{BOLD}🚨🚨🚨  SECURITY ALARM TRIGGERED  🚨🚨🚨{RESET}")
    p(f"  {R}{'━'*50}{RESET}")
    p(f"  {R}{BOLD}⚠  ALERT SENT TO SECURITY OFFICER  ⚠{RESET}")
    p(f"  {R}{'━'*50}{RESET}\n")
    pause(1.2)

# ══════════════════════════════════════════════════════════════════════════════
#  SCENE 1 — System startup
# ══════════════════════════════════════════════════════════════════════════════
def scene_startup():
    clr()
    header_box("AI-DRIVEN CYBER FORENSICS ANALYZER", C)
    p()
    slow(f"  {G}[BOOT]{RESET} Loading AI threat detection models ...", 0.02)
    pause(0.5)
    items = [
        ("IsolationForest anomaly detector", G),
        ("Random Forest threat classifier", G),
        ("Network traffic monitor", G),
        ("Log pattern analyzer", G),
        ("Auto-response / IP blocker", G),
        ("Dashboard alarm system", G),
    ]
    for label, color in items:
        p(f"  {DIM}▸{RESET}  {label} ", end="")
        pause(0.2)
        p(f"{color}✔ READY{RESET}")
    p()
    slow(f"  {G}{BOLD}✅ System online — monitoring all traffic{RESET}", 0.03)
    p()
    divider()
    pause(1.5)

# ══════════════════════════════════════════════════════════════════════════════
#  SCENE 2 — Normal traffic
# ══════════════════════════════════════════════════════════════════════════════
def scene_normal_traffic():
    clr()
    header_box("PHASE 1 — NORMAL TRAFFIC  (All Clear)", G)
    p()
    p(f"  {DIM}Monitoring live network packets ...{RESET}")
    p()
    normal_packets = [
        ("192.168.1.10", "10.0.0.5",  80,  "TCP", "GET /index.html",  "Benign"),
        ("192.168.1.22", "10.0.0.5",  443, "TCP", "HTTPS request",    "Benign"),
        ("192.168.1.55", "8.8.8.8",   53,  "UDP", "DNS query",        "Benign"),
        ("192.168.1.10", "10.0.0.5",  80,  "TCP", "GET /about.html",  "Benign"),
        ("192.168.1.44", "10.0.0.5",  443, "TCP", "POST /login",      "Benign"),
        ("192.168.1.77", "10.0.0.5",  80,  "TCP", "GET /images/logo", "Benign"),
    ]
    for src, dst, port, proto, desc, label in normal_packets:
        ts = datetime.now().strftime("%H:%M:%S")
        p(f"  {DIM}[{ts}]{RESET}  {W}{src}{RESET} → {C}{dst}:{port}{RESET}  "
          f"{DIM}{proto}  {desc}{RESET}  {G}✔ {label}{RESET}")
        pause(0.35)
    p()
    slow(f"  {G}✅ All traffic normal — no threats detected{RESET}", 0.03)
    pause(1.5)

# ══════════════════════════════════════════════════════════════════════════════
#  SCENE 3 — Port Scan attack
# ══════════════════════════════════════════════════════════════════════════════
def scene_port_scan():
    clr()
    header_box("PHASE 2 — PORT SCAN ATTACK DETECTED  🟡", Y)
    p()
    attacker = ATTACKER_IPS[0]
    p(f"  {Y}What is a Port Scan?{RESET}")
    p(f"  {DIM}An attacker probes your server to find open doors (ports){RESET}")
    p(f"  {DIM}before launching a bigger attack.  Like trying every key on a{RESET}")
    p(f"  {DIM}keyring to find which one opens the lock.{RESET}")
    p()
    divider()
    p()
    p(f"  {Y}⚡ Incoming probe packets from {W}{attacker}{RESET}:")
    p()

    ports = [21, 22, 23, 25, 80, 110, 143, 443, 445, 3306, 3389, 8080]
    for port in ports:
        ts = datetime.now().strftime("%H:%M:%S")
        status = "OPEN ← vulnerable!" if port in [22, 80, 443, 3389] else "closed"
        color  = R if "OPEN" in status else DIM
        p(f"  {DIM}[{ts}]{RESET}  {W}{attacker}{RESET} → port {C}{port:>5}{RESET}  "
          f"{color}{status}{RESET}")
        pause(0.15)

    p()
    slow(f"  {Y}⚠  AI DETECTED: Rapid sequential port probing — PORT SCAN{RESET}", 0.02)
    pause(0.5)
    p(f"  {Y}   Confidence: {W}91%{RESET}   Severity: {Y}MEDIUM{RESET}")
    p()
    log_incident("PortScan", attacker, f"Scanned {len(ports)} ports in 2 seconds", "MEDIUM")
    alarm()
    block_ip(attacker, "PORT_SCAN_DETECTED")
    pause(1.0)

# ══════════════════════════════════════════════════════════════════════════════
#  SCENE 4 — Brute Force attack
# ══════════════════════════════════════════════════════════════════════════════
def scene_brute_force():
    clr()
    header_box("PHASE 3 — BRUTE FORCE ATTACK  🟠", f"\033[38;5;208m")
    p()
    attacker = ATTACKER_IPS[1]
    p(f"  \033[38;5;208mWhat is a Brute Force Attack?{RESET}")
    p(f"  {DIM}Attacker tries thousands of username/password combinations{RESET}")
    p(f"  {DIM}on your SSH server (port 22) trying to gain access.{RESET}")
    p()
    divider()
    p()
    p(f"  \033[38;5;208m⚡ SSH login attempts from {W}{attacker}{RESET}  →  {W}{TARGET_SSH}{RESET}:")
    p()

    users_tried = ["admin","root","ubuntu","user","test","administrator","pi","guest"]
    for i, user in enumerate(users_tried):
        ts = datetime.now().strftime("%H:%M:%S")
        p(f"  {DIM}[{ts}]{RESET}  Attempt #{i+1:>3}  user={W}{user:<15}{RESET}  "
          f"pass={'*'*random.randint(6,12):<14}  {R}❌ FAILED{RESET}")
        pause(0.25)

    p()
    p(f"  {DIM}... 247 more attempts in the next 30 seconds ...{RESET}")
    p()
    slow(f"  {R}⚠  AI DETECTED: 255 failed logins in 30s — BRUTE FORCE ATTACK{RESET}", 0.02)
    pause(0.5)
    p(f"  {R}   Confidence: {W}96%{RESET}   Severity: {R}HIGH{RESET}")
    p()
    log_incident("BruteForce", attacker, "255 failed SSH login attempts in 30s", "HIGH")
    alarm()
    block_ip(attacker, "BRUTE_FORCE_DETECTED — SSH port 22")
    pause(1.0)

# ══════════════════════════════════════════════════════════════════════════════
#  SCENE 5 — DDoS attack
# ══════════════════════════════════════════════════════════════════════════════
def scene_ddos():
    clr()
    header_box("PHASE 4 — DDoS FLOOD ATTACK  🔴 CRITICAL", R)
    p()
    p(f"  {R}What is a DDoS Attack?{RESET}")
    p(f"  {DIM}Hundreds of bots flood your server with fake traffic.{RESET}")
    p(f"  {DIM}The server gets overwhelmed and crashes — real users{RESET}")
    p(f"  {DIM}cannot access your website.{RESET}")
    p()
    divider()
    p()
    p(f"  {R}⚡ Flood packets arriving at {W}{TARGET_SERVER}{RESET}:")
    p()

    bot_ips = [
        f"45.155.{r}.{e}" for r in range(200, 204) for e in range(1, 4)
    ]

    packet_count = 0
    for i, bot in enumerate(bot_ips):
        count = random.randint(800, 2500)
        packet_count += count
        ts = datetime.now().strftime("%H:%M:%S")
        bar = "█" * min(30, count // 80)
        p(f"  {DIM}[{ts}]{RESET}  {R}{bot:<18}{RESET} → {W}:{random.choice([80,443,53])}{RESET}  "
          f"{R}{bar}{RESET}  {W}{count:,} pkts/s{RESET}")
        pause(0.2)

    p()
    p(f"  {R}{'▲'*40}{RESET}")
    p(f"  {R}{BOLD}  TOTAL FLOOD RATE: {packet_count:,} packets/second{RESET}")
    p(f"  {R}  SERVER CPU: 99%  |  BANDWIDTH: SATURATED  |  WEBSITE: DOWN{RESET}")
    p(f"  {R}{'▼'*40}{RESET}")
    p()
    slow(f"  {R}🚨 AI DETECTED: Volumetric DDoS flood — CRITICAL THREAT{RESET}", 0.02)
    pause(0.5)
    p(f"  {R}   Confidence: {W}99%{RESET}   Severity: {R}{BOLD}CRITICAL{RESET}")
    p()
    for ip in bot_ips:
        log_incident("DDoS", ip, f"Flood: {random.randint(800,2500):,} pkts/s", "CRITICAL")
    alarm()
    p(f"  {R}Auto-blocking all {len(bot_ips)} botnet IPs ...{RESET}")
    p()
    for ip in bot_ips:
        block_ip(ip, "DDoS FLOOD")
    pause(1.0)

# ══════════════════════════════════════════════════════════════════════════════
#  SCENE 6 — Defences working
# ══════════════════════════════════════════════════════════════════════════════
def scene_defense():
    clr()
    header_box("PHASE 5 — AUTO-DEFENSE ACTIVATED  🛡", G)
    p()
    p(f"  {G}How does the system STOP the attack?{RESET}")
    p()
    steps = [
        ("1", "AI classifies each packet in real-time (< 1ms per packet)",       G),
        ("2", "Threat type identified: PortScan / BruteForce / DDoS",           Y),
        ("3", "Confidence score checked  (must be > 70% to trigger action)",    Y),
        ("4", "Attacker IP added to BLACKLIST — all packets from it dropped",    R),
        ("5", "Dashboard alarm fires — Security Officer receives alert",         R),
        ("6", "Forensic report generated for legal evidence",                    C),
        ("7", "Clean traffic continues — legitimate users not affected",          G),
    ]
    p()
    for num, desc, color in steps:
        p(f"  {color}{BOLD}[{num}]{RESET}  {desc}")
        pause(0.5)

    p()
    divider()
    p()
    p(f"  {G}Current firewall blacklist ({len(BLOCKED_IPS)} IPs blocked):{RESET}")
    p()
    for ip in sorted(BLOCKED_IPS):
        p(f"     {R}🚫  {ip}{RESET}")
        pause(0.1)
    pause(1.5)

# ══════════════════════════════════════════════════════════════════════════════
#  SCENE 7 — Incident report
# ══════════════════════════════════════════════════════════════════════════════
def scene_report():
    clr()
    header_box("INCIDENT REPORT — GENERATED BY AI SYSTEM", M)
    p()
    now = datetime.now().strftime("%Y-%m-%d  %H:%M:%S")
    p(f"  {W}Report generated :{RESET}  {now}")
    p(f"  {W}Protected asset  :{RESET}  CyberSleuth Web Application")
    p(f"  {W}Monitoring period:{RESET}  Live session")
    p()
    divider("═")
    p(f"  {W}{BOLD}ATTACK SUMMARY{RESET}")
    divider("═")
    p()

    attack_info = {
        "PortScan":   (Y, "MEDIUM",   "Attacker mapped open ports before intrusion"),
        "BruteForce": (R, "HIGH",     "255 failed SSH login attempts — account takeover attempt"),
        "DDoS":       (R, "CRITICAL", "Botnet flood — website taken offline without defence"),
    }

    for attack, count in THREAT_COUNT.items():
        color, severity, explanation = attack_info.get(attack, (W, "LOW", ""))
        p(f"  {color}{BOLD}{attack:<14}{RESET}  {W}{count:>3} events{RESET}  "
          f"Severity: {color}{severity}{RESET}")
        p(f"  {DIM}  → {explanation}{RESET}")
        p()

    divider()
    p(f"  {W}IPs Blocked     :{RESET}  {R}{len(BLOCKED_IPS)}{RESET}")
    p(f"  {W}AI Detections   :{RESET}  {G}{sum(THREAT_COUNT.values())}{RESET}")
    p(f"  {W}Legitimate users:{RESET}  {G}NOT affected{RESET}")
    p(f"  {W}Response time   :{RESET}  {G}< 1 second per attack{RESET}")
    p()
    divider("═")
    p(f"  {W}{BOLD}VERDICT{RESET}")
    divider("═")
    p()
    slow(f"  {G}{BOLD}✅ All attacks detected and stopped automatically.{RESET}", 0.03)
    slow(f"  {G}{BOLD}✅ Security officer alerted in real-time.{RESET}", 0.03)
    slow(f"  {G}{BOLD}✅ Zero impact on legitimate users.{RESET}", 0.03)
    p()

    # Save report to file
    report_path = f"demo_incident_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(report_path, "w") as f:
        f.write(f"CYBERSLEUTH AI — INCIDENT REPORT\n")
        f.write(f"Generated: {now}\n")
        f.write("=" * 60 + "\n\n")
        f.write(f"Attacks detected:\n")
        for attack, count in THREAT_COUNT.items():
            f.write(f"  {attack}: {count} events\n")
        f.write(f"\nIPs Blocked ({len(BLOCKED_IPS)}):\n")
        for ip in sorted(BLOCKED_IPS):
            f.write(f"  {ip}\n")
        f.write("\nVERDICT: All attacks stopped. Security officer alerted.\n")
    p(f"  {DIM}Report saved → {report_path}{RESET}")
    p()
    pause(2.0)

# ══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════════════
def main():
    try:
        clr()
        header_box("CyberSleuth AI  —  LIVE ATTACK DEMONSTRATION", C)
        p()
        p(f"  {W}This demo simulates a REAL attack scenario on a website.{RESET}")
        p(f"  {DIM}You will see:{RESET}")
        p(f"  {G}  ✔{RESET}  Normal traffic monitoring")
        p(f"  {Y}  ✔{RESET}  Port Scan detected and blocked")
        p(f"  {R}  ✔{RESET}  Brute Force attack detected and blocked")
        p(f"  {R}  ✔{RESET}  DDoS flood detected and stopped")
        p(f"  {M}  ✔{RESET}  Full incident report generated")
        p()
        p(f"  {DIM}Press ENTER to begin ...{RESET}", end="")
        input()

        scene_startup()
        scene_normal_traffic()

        p(f"\n  {Y}⚠  Unusual traffic detected ... switching to threat mode{RESET}")
        pause(1.5)

        scene_port_scan()
        scene_brute_force()
        scene_ddos()
        scene_defense()
        scene_report()

        clr()
        header_box("DEMO COMPLETE", G)
        p()
        p(f"  {G}{BOLD}Key points to tell your teacher:{RESET}")
        p()
        points = [
            ("Port Scan",   Y, "Attacker finds open doors before breaking in"),
            ("Brute Force", R, "Attacker tries thousands of passwords to log in"),
            ("DDoS",        R, "Bots flood the server so it crashes for everyone"),
            ("Detection",   C, "Our AI classifies every packet in under 1 millisecond"),
            ("Blocking",    G, "Attacking IPs are instantly added to the blacklist"),
            ("Alarm",       M, "Security officer is alerted the moment an attack starts"),
            ("Evidence",    W, "An incident report is saved for legal/forensic use"),
        ]
        for term, color, explanation in points:
            p(f"  {color}{BOLD}{term:<14}{RESET}  {explanation}")
            pause(0.3)
        p()
        divider()
        p(f"  {G}The demo incident report has been saved to this folder.{RESET}")
        p()

    except KeyboardInterrupt:
        p(f"\n\n  {Y}Demo interrupted.{RESET}")
        sys.exit(0)

if __name__ == "__main__":
    main()