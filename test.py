# #=====================================================end of v1======================================================
# import threading
# import time
# import numpy as np
# import pickle
# import ipaddress
# import math
# from collections import defaultdict, deque
# from datetime import datetime, timedelta

# from scapy.all import sniff, IP, TCP, UDP, ICMP

# import dash
# from dash import html, dcc, dash_table
# from dash.dependencies import Input, Output
# from flask import Flask, render_template, jsonify, request, redirect, url_for, flash

# from database import db
# from auth import auth

# # =============================================================================
# # CONFIG
# # =============================================================================
# INTERFACE   = "wlan0"
# MAX_PACKETS = 5000
# LOG_FILE    = "attack_logs.log"

# # --- DoS / DDoS --------------------------------------------------------------
# DOS_PPS_THRESHOLD     = 500
# DDOS_SOURCE_THRESHOLD = 10
# DDOS_TOTAL_PPS        = 2000

# # --- Port scan ---------------------------------------------------------------
# PORT_SCAN_THRESHOLD = 30
# UDP_SCAN_THRESHOLD  = 20
# ICMP_SCAN_THRESHOLD = 10
# PORT_SCAN_WINDOW    = 60

# # --- RST / FIN flood ---------------------------------------------------------
# RST_FLOOD_THRESHOLD = 150
# FIN_FLOOD_THRESHOLD = 150

# # --- ACK flood ---------------------------------------------------------------
# ACK_FLOOD_THRESHOLD = 150

# # --- HTTP flood --------------------------------------------------------------
# HTTP_FLOOD_THRESHOLD = 150
# HTTP_PORTS           = {80, 443, 8080, 8443}

# # --- XMAS / NULL scan --------------------------------------------------------
# XMAS_SCAN_THRESHOLD = 20
# NULL_SCAN_THRESHOLD = 20
# SCAN_WINDOW         = 60

# # --- Brute force -------------------------------------------------------------
# BRUTE_FORCE_THRESHOLD = 30
# BRUTE_FORCE_WINDOW    = 60
# BRUTE_FORCE_PORTS = {
#     22:    "SSH",
#     21:    "FTP",
#     23:    "Telnet",
#     25:    "SMTP",
#     110:   "POP3",
#     143:   "IMAP",
#     3306:  "MySQL",
#     5432:  "PostgreSQL",
#     3389:  "RDP",
#     5900:  "VNC",
#     6379:  "Redis",
#     27017: "MongoDB",
# }

# # --- Credential stuffing -----------------------------------------------------
# CRED_STUFF_SRC_THRESHOLD = 200
# CRED_STUFF_WINDOW        = 120

# # --- Suspicious soft threshold -----------------------------------------------
# SUSPICIOUS_PPS_FACTOR = 0.25

# # --- Zero-day / anomaly ------------------------------------------------------
# # TUNED: raised thresholds to eliminate false positives from background traffic
# BASELINE_LEARNING_SECONDS = 180
# ANOMALY_Z_THRESHOLD       = 7.0   # raised 4→7: background bursts rarely exceed this
# ANOMALY_FEATURE_COUNT     = 6     # raised 4→6: needs more features to be truly anomalous
# ZERO_DAY_COOLDOWN         = 120   # raised 60→120s: reduces repeat alert spam
# MIN_PKT_COUNT_FOR_ANOMALY = 10    # NEW: ignore tiny idle buckets (<10 pkts in 10s)

# # --- Global alert cooldown ---------------------------------------------------
# ATTACK_COOLDOWN_SEC = 15

# # =============================================================================
# # WHITELIST
# # =============================================================================
# WHITELISTED_IPS = {
#     "192.168.243.99",
#     "192.168.243.1",
#     "192.168.1.254",
#     "127.0.0.1",
#     "172.20.10.1",
#     "0.0.0.0",
# }
# WHITELIST_PRIVATE_RANGES = False

# # =============================================================================
# # GLOBAL STATE
# # =============================================================================
# packet_list = []
# packet_lock = threading.Lock()
# last_attack = None

# udp_rate  = defaultdict(deque)
# tcp_rate  = defaultdict(deque)
# icmp_rate = defaultdict(deque)
# rst_rate  = defaultdict(deque)
# fin_rate  = defaultdict(deque)
# ack_rate  = defaultdict(deque)
# http_rate = defaultdict(deque)

# dst_sources = defaultdict(set)

# syn_scan_state  = defaultdict(lambda: {"ports":   set(), "first_seen": 0.0})
# udp_scan_state  = defaultdict(lambda: {"ports":   set(), "first_seen": 0.0})
# icmp_scan_state = defaultdict(lambda: {"targets": set(), "first_seen": 0.0})
# xmas_scan_state = defaultdict(lambda: {"ports":   set(), "first_seen": 0.0})
# null_scan_state = defaultdict(lambda: {"ports":   set(), "first_seen": 0.0})
# scan_lock       = threading.Lock()

# brute_force_attempts = defaultdict(deque)
# brute_force_lock     = threading.Lock()

# cred_stuff_sources = defaultdict(lambda: {"srcs": set(), "first_seen": 0.0})

# traffic_history = deque(maxlen=5000)
# attack_history  = deque(maxlen=1000)

# attack_cooldowns = defaultdict(float)
# cooldown_lock    = threading.Lock()

# # Tracks when a named rule last fired per source IP.
# # Zero-day is suppressed for IPs with recent rule-based alerts.
# rule_based_alert_times = defaultdict(float)
# rule_alert_lock        = threading.Lock()

# system_start_time = datetime.now()

# # =============================================================================
# # ZERO-DAY DETECTOR STATE
# # =============================================================================
# baseline_means      = {}
# baseline_stds       = {}
# baseline_samples    = defaultdict(list)
# baseline_ready      = False
# baseline_start      = None
# zero_day_last_alert = {}

# FEATURE_NAMES = [
#     "pkt_count", "byte_count", "unique_dsts", "unique_dports",
#     "syn_count", "udp_count", "icmp_count", "avg_pkt_size", "dst_entropy"
# ]

# ip_bucket_data = defaultdict(lambda: {
#     "pkt_count": 0, "byte_count": 0,
#     "unique_dsts": set(), "unique_dports": set(),
#     "syn_count": 0, "udp_count": 0, "icmp_count": 0,
#     "sizes": [], "bucket_start": time.time()
# })
# ip_bucket_lock = threading.Lock()

# # =============================================================================
# # OPTIONAL ML
# # =============================================================================
# ML_ENABLED    = False
# model         = None
# scaler        = None
# label_encoder = None

# try:
#     from tensorflow import keras
#     from sklearn.preprocessing import StandardScaler
#     model = keras.models.load_model("model/best_fnn_good_classes.h5")
#     with open("model/fixed_label_encoders_good_classes.pkl", "rb") as f:
#         label_encoder = pickle.load(f)[" Label"]
#     scaler = StandardScaler()
#     scaler.fit(np.random.randn(100, model.input_shape[1]))
#     ML_ENABLED = True
#     print("ML ENABLED")
# except Exception as e:
#     print(f"ML disabled: {e}")


# # =============================================================================
# # HELPERS
# # =============================================================================

# def is_whitelisted(ip: str) -> bool:
#     if ip in WHITELISTED_IPS:
#         return True
#     try:
#         addr = ipaddress.ip_address(ip)
#         if addr.is_loopback or addr.is_link_local or addr.is_multicast:
#             return True
#         if WHITELIST_PRIVATE_RANGES and addr.is_private:
#             return True
#     except ValueError:
#         pass
#     return False


# def rate_update(rate_dict: dict, key: str) -> int:
#     now = time.time()
#     rate_dict[key].append(now)
#     while rate_dict[key] and now - rate_dict[key][0] > 1.0:
#         rate_dict[key].popleft()
#     return len(rate_dict[key])


# def mark_rule_alert(src: str) -> None:
#     """
#     Called whenever a named rule fires for a source IP.
#     Suppresses zero-day for that IP for ATTACK_COOLDOWN_SEC*2 seconds
#     to prevent double-detection (e.g. PORT_SCAN + ZERO_DAY on same traffic).
#     """
#     with rule_alert_lock:
#         rule_based_alert_times[src] = time.time()


# def has_recent_rule_alert(src: str) -> bool:
#     """Return True if a named rule fired for this IP recently."""
#     with rule_alert_lock:
#         return time.time() - rule_based_alert_times.get(src, 0) < ATTACK_COOLDOWN_SEC * 2


# def log_attack(atype: str, msg: str, src: str = "") -> None:
#     global last_attack
#     now          = time.time()
#     cooldown_key = f"{atype}:{src}"
#     with cooldown_lock:
#         if now - attack_cooldowns[cooldown_key] < ATTACK_COOLDOWN_SEC:
#             return
#         attack_cooldowns[cooldown_key] = now
#     last_attack = f"{atype} | {msg}"
#     attack_history.append({
#         "type":      atype,
#         "message":   msg,
#         "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
#         "time":      datetime.now(),
#     })
#     print(f"[ATTACK] {atype} | {msg}")
#     with open(LOG_FILE, "a") as fh:
#         fh.write(f"[{datetime.now()}] {atype} | {msg}\n")


# def get_uptime() -> str:
#     delta   = datetime.now() - system_start_time
#     days    = delta.days
#     hours   = delta.seconds // 3600
#     minutes = (delta.seconds % 3600) // 60
#     seconds = delta.seconds % 60
#     if days:   return f"{days}d {hours}h {minutes}m"
#     if hours:  return f"{hours}h {minutes}m {seconds}s"
#     return f"{minutes}m {seconds}s"


# def get_time_ago(dt: datetime) -> str:
#     diff = datetime.now() - dt
#     if diff.days > 0:       return f"{diff.days} day{'s' if diff.days>1 else ''} ago"
#     if diff.seconds > 3600: return f"{diff.seconds//3600} hour{'s' if diff.seconds//3600>1 else ''} ago"
#     if diff.seconds > 60:   return f"{diff.seconds//60} minute{'s' if diff.seconds//60>1 else ''} ago"
#     return "Just now"


# # =============================================================================
# # ZERO-DAY HELPERS
# # =============================================================================

# def _entropy(values) -> float:
#     if not values:
#         return 0.0
#     counts = defaultdict(int)
#     for v in values:
#         counts[v] += 1
#     total = len(values)
#     return -sum((c/total)*math.log2(c/total) for c in counts.values())


# def _extract_bucket_features(bucket: dict) -> dict:
#     n = bucket["pkt_count"]
#     return {
#         "pkt_count":     n,
#         "byte_count":    bucket["byte_count"],
#         "unique_dsts":   len(bucket["unique_dsts"]),
#         "unique_dports": len(bucket["unique_dports"]),
#         "syn_count":     bucket["syn_count"],
#         "udp_count":     bucket["udp_count"],
#         "icmp_count":    bucket["icmp_count"],
#         "avg_pkt_size":  bucket["byte_count"]/n if n else 0,
#         "dst_entropy":   _entropy(list(bucket["unique_dports"])),
#     }


# def _update_baseline(features: dict) -> None:
#     """
#     Update baseline samples, skipping buckets that look attack-like
#     so nmap/hping during the learning window cannot corrupt the baseline.
#     Also skips near-empty buckets (idle periods) that would make std too tight.
#     """
#     global baseline_ready, baseline_means, baseline_stds

#     # Skip attack-like buckets — do not learn from malicious traffic
#     if features.get("unique_dports", 0) > 50:
#         print("[BASELINE] Skipped: unique_dports too high (possible scan during learning)")
#         return
#     if features.get("pkt_count", 0) > 300:
#         print("[BASELINE] Skipped: pkt_count too high (possible flood during learning)")
#         return
#     if features.get("syn_count", 0) > 200:
#         print("[BASELINE] Skipped: syn_count too high (possible SYN flood during learning)")
#         return

#     # Skip near-empty buckets — idle periods make std artificially tight,
#     # which later causes normal bursts to appear anomalous
#     if features.get("pkt_count", 0) < 2:
#         return

#     for fname, val in features.items():
#         baseline_samples[fname].append(val)

#     if baseline_ready:
#         return

#     elapsed = time.time() - (baseline_start or time.time())
#     if elapsed >= BASELINE_LEARNING_SECONDS and len(baseline_samples["pkt_count"]) >= 20:
#         for fname in FEATURE_NAMES:
#             vals = baseline_samples[fname]
#             if vals:
#                 mean = float(np.mean(vals))
#                 std  = float(np.std(vals))
#                 baseline_means[fname] = mean
#                 # Wide std floor: allows up to ~2x the mean before alarming.
#                 # This tolerates normal background traffic bursts (DNS, updates,
#                 # mDNS, NTP, browser prefetch) without false positives.
#                 baseline_stds[fname]  = max(std, mean * 0.5 + 1.0)
#         baseline_ready = True
#         print("Zero-day baseline established — anomaly detection ACTIVE.")
#         print("  Baseline summary:")
#         for fname in FEATURE_NAMES:
#             print(f"    {fname:<16}: mean={baseline_means.get(fname,0):.2f}  "
#                   f"std={baseline_stds.get(fname,0):.2f}")


# def _check_anomaly(features: dict):
#     if not baseline_ready:
#         return False, [], 0.0

#     # Skip tiny buckets — idle background trickle is not meaningful
#     # (e.g. one mDNS packet in 10 seconds should never trigger zero-day)
#     if features.get("pkt_count", 0) < MIN_PKT_COUNT_FOR_ANOMALY:
#         return False, [], 0.0

#     anomalous = []
#     max_z     = 0.0
#     for fname in FEATURE_NAMES:
#         val  = features.get(fname, 0)
#         mean = baseline_means.get(fname, 0)
#         std  = baseline_stds.get(fname, 1)
#         z    = abs(val - mean) / std
#         if z > ANOMALY_Z_THRESHOLD:
#             anomalous.append((fname, val, mean, round(z, 2)))
#             max_z = max(max_z, z)
#     return len(anomalous) >= ANOMALY_FEATURE_COUNT, anomalous, round(max_z, 2)


# def flush_ip_bucket(src: str) -> str:
#     with ip_bucket_lock:
#         bucket = ip_bucket_data[src]
#         now    = time.time()
#         if now - bucket["bucket_start"] < 10:
#             return "normal"
#         features = _extract_bucket_features(bucket)
#         ip_bucket_data[src] = {
#             "pkt_count": 0, "byte_count": 0,
#             "unique_dsts": set(), "unique_dports": set(),
#             "syn_count": 0, "udp_count": 0, "icmp_count": 0,
#             "sizes": [], "bucket_start": now,
#         }

#     if not baseline_ready:
#         _update_baseline(features)
#         return "normal"

#     # Suppress zero-day if a named rule already fired for this IP recently.
#     # This prevents nmap/hping traffic from double-triggering ZERO_DAY.
#     if has_recent_rule_alert(src):
#         return "normal"

#     is_anom, anom_list, max_z = _check_anomaly(features)
#     if is_anom and not is_whitelisted(src):
#         last = zero_day_last_alert.get(src, 0)
#         if now - last >= ZERO_DAY_COOLDOWN:
#             zero_day_last_alert[src] = now
#             summary = ", ".join(f"{f}={v:.1f}(z={z})" for f,v,m,z in anom_list[:4])
#             log_attack("ZERO_DAY", f"SRC={src} max_z={max_z} [{summary}]", src=src)
#             return "attack"
#     return "normal"


# def update_ip_bucket(src, dst, proto, dport, pkt_len, flags):
#     with ip_bucket_lock:
#         b = ip_bucket_data[src]
#         b["pkt_count"]  += 1
#         b["byte_count"] += pkt_len
#         b["unique_dsts"].add(dst)
#         if dport:
#             b["unique_dports"].add(dport)
#         if proto == "TCP" and "SYN" in flags:
#             b["syn_count"] += 1
#         if proto == "UDP":
#             b["udp_count"] += 1
#         if proto == "ICMP":
#             b["icmp_count"] += 1
#         b["sizes"].append(pkt_len)


# # =============================================================================
# # SCAN DETECTORS
# # =============================================================================

# def check_port_scan(src, dst, dport) -> bool:
#     if is_whitelisted(src):
#         return False
#     key = f"{src}->{dst}"
#     now = time.time()
#     with scan_lock:
#         s = syn_scan_state[key]
#         if s["first_seen"] == 0.0 or now - s["first_seen"] > PORT_SCAN_WINDOW:
#             s["ports"] = set(); s["first_seen"] = now
#         s["ports"].add(dport)
#         count = len(s["ports"])
#     if count >= PORT_SCAN_THRESHOLD:
#         mark_rule_alert(src)
#         log_attack("PORT_SCAN", f"SRC={src} DST={dst} PORTS={count} in {PORT_SCAN_WINDOW}s", src=src)
#         return True
#     return False


# def check_udp_scan(src, dst, dport) -> bool:
#     if is_whitelisted(src):
#         return False
#     key = f"{src}->{dst}"
#     now = time.time()
#     with scan_lock:
#         s = udp_scan_state[key]
#         if s["first_seen"] == 0.0 or now - s["first_seen"] > PORT_SCAN_WINDOW:
#             s["ports"] = set(); s["first_seen"] = now
#         s["ports"].add(dport)
#         count = len(s["ports"])
#     if count >= UDP_SCAN_THRESHOLD:
#         mark_rule_alert(src)
#         log_attack("UDP_SCAN", f"SRC={src} DST={dst} PORTS={count} in {PORT_SCAN_WINDOW}s", src=src)
#         return True
#     return False


# def check_icmp_scan(src, dst) -> bool:
#     if is_whitelisted(src):
#         return False
#     now = time.time()
#     with scan_lock:
#         s = icmp_scan_state[src]
#         if s["first_seen"] == 0.0 or now - s["first_seen"] > PORT_SCAN_WINDOW:
#             s["targets"] = set(); s["first_seen"] = now
#         s["targets"].add(dst)
#         count = len(s["targets"])
#     if count >= ICMP_SCAN_THRESHOLD:
#         mark_rule_alert(src)
#         log_attack("ICMP_SCAN", f"SRC={src} TARGETS={count} in {PORT_SCAN_WINDOW}s", src=src)
#         return True
#     return False


# def check_xmas_scan(src, dst, dport) -> bool:
#     if is_whitelisted(src):
#         return False
#     key = f"{src}->{dst}"
#     now = time.time()
#     with scan_lock:
#         s = xmas_scan_state[key]
#         if s["first_seen"] == 0.0 or now - s["first_seen"] > SCAN_WINDOW:
#             s["ports"] = set(); s["first_seen"] = now
#         s["ports"].add(dport)
#         count = len(s["ports"])
#     if count >= XMAS_SCAN_THRESHOLD:
#         mark_rule_alert(src)
#         log_attack("XMAS_SCAN", f"SRC={src} DST={dst} PORTS={count} in {SCAN_WINDOW}s", src=src)
#         return True
#     return False


# def check_null_scan(src, dst, dport) -> bool:
#     if is_whitelisted(src):
#         return False
#     key = f"{src}->{dst}"
#     now = time.time()
#     with scan_lock:
#         s = null_scan_state[key]
#         if s["first_seen"] == 0.0 or now - s["first_seen"] > SCAN_WINDOW:
#             s["ports"] = set(); s["first_seen"] = now
#         s["ports"].add(dport)
#         count = len(s["ports"])
#     if count >= NULL_SCAN_THRESHOLD:
#         mark_rule_alert(src)
#         log_attack("NULL_SCAN", f"SRC={src} DST={dst} PORTS={count} in {SCAN_WINDOW}s", src=src)
#         return True
#     return False


# # =============================================================================
# # BRUTE FORCE DETECTOR
# # =============================================================================

# def check_brute_force(src, dport) -> bool:
#     if is_whitelisted(src):
#         return False
#     key = f"{src}:{dport}"
#     now = time.time()
#     with brute_force_lock:
#         q = brute_force_attempts[key]
#         q.append(now)
#         while q and now - q[0] > BRUTE_FORCE_WINDOW:
#             q.popleft()
#         count = len(q)
#     if count >= BRUTE_FORCE_THRESHOLD:
#         service = BRUTE_FORCE_PORTS.get(dport, f"PORT-{dport}")
#         mark_rule_alert(src)
#         log_attack("BRUTE_FORCE",
#                    f"SRC={src} SERVICE={service} PORT={dport} ATTEMPTS={count} in {BRUTE_FORCE_WINDOW}s",
#                    src=src)
#         return True
#     return False


# # =============================================================================
# # CREDENTIAL STUFFING DETECTOR
# # =============================================================================

# def check_credential_stuffing(src, dst, dport) -> bool:
#     if is_whitelisted(src):
#         return False
#     key   = f"web:{dst}:{dport}"
#     now   = time.time()
#     state = cred_stuff_sources[key]
#     if state["first_seen"] == 0.0 or now - state["first_seen"] > CRED_STUFF_WINDOW:
#         state["srcs"] = set(); state["first_seen"] = now
#     state["srcs"].add(src)
#     if len(state["srcs"]) >= CRED_STUFF_SRC_THRESHOLD:
#         mark_rule_alert(src)
#         log_attack("CREDENTIAL_STUFFING",
#                    f"DST={dst} PORT={dport} UNIQUE_SRCS={len(state['srcs'])} in {CRED_STUFF_WINDOW}s",
#                    src=src)
#         return True
#     return False


# # =============================================================================
# # PACKET CALLBACK
# # =============================================================================

# def packet_callback(pkt):
#     global baseline_start

#     if IP not in pkt:
#         return

#     if baseline_start is None:
#         baseline_start = time.time()
#         print(f"Baseline learning started ({BASELINE_LEARNING_SECONDS}s window)...")

#     src   = pkt[IP].src
#     dst   = pkt[IP].dst
#     proto = "OTHER"
#     dport = 0
#     flags = ""

#     if TCP in pkt:
#         proto = "TCP"
#         dport = pkt[TCP].dport
#         f     = pkt[TCP].flags
#         if f.S: flags += "SYN "
#         if f.A: flags += "ACK "
#         if f.F: flags += "FIN "
#         if f.R: flags += "RST "
#         if f.P: flags += "PSH "
#         if f.U: flags += "URG "
#         flags = flags.strip()
#     elif UDP in pkt:
#         proto = "UDP"
#         dport = pkt[UDP].dport
#     elif ICMP in pkt:
#         proto = "ICMP"

#     pkt_len = len(pkt)

#     is_syn      = proto=="TCP" and "SYN" in flags and "ACK" not in flags
#     is_ack_only = proto=="TCP" and "ACK" in flags and "SYN" not in flags and "PSH" not in flags and "RST" not in flags and "FIN" not in flags
#     is_pure_fin = proto=="TCP" and "FIN" in flags and "ACK" not in flags and "SYN" not in flags
#     is_pure_rst = proto=="TCP" and "RST" in flags
#     is_psh_ack  = proto=="TCP" and "PSH" in flags and "ACK" in flags
#     is_xmas     = proto=="TCP" and "FIN" in flags and "PSH" in flags and "URG" in flags
#     is_null     = proto=="TCP" and flags == ""

#     attack_status = "normal"

#     pkt_info = {
#         "time":           time.time(),
#         "timestamp":      datetime.now().strftime("%H:%M:%S.%f")[:-3],
#         "full_timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
#         "src": src, "dst": dst, "protocol": proto, "dport": dport,
#         "length": pkt_len, "attack": "", "status": "normal", "flags": flags,
#     }

#     traffic_history.append({**pkt_info})
#     with packet_lock:
#         packet_list.append(pkt_info)
#         if len(packet_list) > MAX_PACKETS:
#             packet_list.pop(0)

#     update_ip_bucket(src, dst, proto, dport, pkt_len, flags)

#     if is_whitelisted(src):
#         return

#     # ── PORT SCAN (SYN) ───────────────────────────────────────
#     if is_syn and len(tcp_rate[src]) < DOS_PPS_THRESHOLD * 0.5:
#         if check_port_scan(src, dst, dport):
#             attack_status = "attack"

#     # ── XMAS SCAN ─────────────────────────────────────────────
#     if is_xmas:
#         if check_xmas_scan(src, dst, dport):
#             attack_status = "attack"

#     # ── NULL SCAN ─────────────────────────────────────────────
#     if is_null:
#         if check_null_scan(src, dst, dport):
#             attack_status = "attack"

#     # ── UDP SCAN ──────────────────────────────────────────────
#     if proto == "UDP" and len(udp_rate[src]) < DOS_PPS_THRESHOLD * 0.5:
#         if check_udp_scan(src, dst, dport):
#             attack_status = "attack"

#     # ── ICMP SCAN ─────────────────────────────────────────────
#     if proto == "ICMP" and len(icmp_rate[src]) < DOS_PPS_THRESHOLD * 0.5:
#         if check_icmp_scan(src, dst):
#             attack_status = "attack"

#     # ── UDP DoS ───────────────────────────────────────────────
#     if proto == "UDP":
#         pps = rate_update(udp_rate, src)
#         dst_sources[dst].add(src)
#         if pps > DOS_PPS_THRESHOLD:
#             mark_rule_alert(src)
#             log_attack("DoS", f"UDP_FLOOD SRC={src} PPS={pps}", src=src)
#             attack_status = "attack"
#         elif pps > DOS_PPS_THRESHOLD * 0.7:
#             attack_status = "suspicious"

#     # ── SYN DoS ───────────────────────────────────────────────
#     if is_syn:
#         pps = rate_update(tcp_rate, src)
#         dst_sources[dst].add(src)
#         if pps > DOS_PPS_THRESHOLD:
#             mark_rule_alert(src)
#             log_attack("DoS", f"SYN_FLOOD SRC={src} PPS={pps}", src=src)
#             attack_status = "attack"
#         elif pps > DOS_PPS_THRESHOLD * 0.7:
#             attack_status = "suspicious"

#     if proto == "ICMP":
#         rate_update(icmp_rate, src)

#     # ── DDoS ──────────────────────────────────────────────────
#     if proto in ("UDP", "TCP"):
#         total_pps = sum(len(udp_rate[s]) + len(tcp_rate[s]) for s in dst_sources[dst])
#         if len(dst_sources[dst]) >= DDOS_SOURCE_THRESHOLD and total_pps > DDOS_TOTAL_PPS:
#             mark_rule_alert(src)
#             log_attack("DDoS",
#                        f"DST={dst} SOURCES={len(dst_sources[dst])} TOTAL_PPS={total_pps}",
#                        src=src)
#             attack_status = "attack"

#     # ── RST FLOOD ─────────────────────────────────────────────
#     if is_pure_rst:
#         rst_pps = rate_update(rst_rate, src)
#         if rst_pps > RST_FLOOD_THRESHOLD:
#             mark_rule_alert(src)
#             log_attack("RST_FLOOD", f"SRC={src} PPS={rst_pps}", src=src)
#             attack_status = "attack"
#         elif rst_pps > RST_FLOOD_THRESHOLD * 0.7:
#             attack_status = "suspicious"

#     # ── FIN FLOOD ─────────────────────────────────────────────
#     if is_pure_fin:
#         fin_pps = rate_update(fin_rate, src)
#         if fin_pps > FIN_FLOOD_THRESHOLD:
#             mark_rule_alert(src)
#             log_attack("FIN_FLOOD", f"SRC={src} PPS={fin_pps}", src=src)
#             attack_status = "attack"
#         elif fin_pps > FIN_FLOOD_THRESHOLD * 0.7:
#             attack_status = "suspicious"

#     # ── ACK FLOOD ─────────────────────────────────────────────
#     if is_ack_only:
#         ack_pps = rate_update(ack_rate, src)
#         if ack_pps > ACK_FLOOD_THRESHOLD:
#             mark_rule_alert(src)
#             log_attack("ACK_FLOOD", f"SRC={src} PPS={ack_pps}", src=src)
#             attack_status = "attack"
#         elif ack_pps > ACK_FLOOD_THRESHOLD * 0.7:
#             attack_status = "suspicious"

#     # ── HTTP FLOOD ────────────────────────────────────────────
#     if is_psh_ack and dport in HTTP_PORTS:
#         http_pps = rate_update(http_rate, src)
#         if http_pps > HTTP_FLOOD_THRESHOLD:
#             mark_rule_alert(src)
#             log_attack("HTTP_FLOOD", f"SRC={src} PORT={dport} PPS={http_pps}", src=src)
#             attack_status = "attack"
#         elif http_pps > HTTP_FLOOD_THRESHOLD * 0.7:
#             attack_status = "suspicious"

#     # ── BRUTE FORCE ───────────────────────────────────────────
#     if is_syn and dport in BRUTE_FORCE_PORTS:
#         if check_brute_force(src, dport):
#             attack_status = "attack"

#     # ── CREDENTIAL STUFFING ───────────────────────────────────
#     if is_syn and dport in {80, 443}:
#         if check_credential_stuffing(src, dst, dport):
#             attack_status = "attack"

#     # ── ZERO-DAY / ANOMALY ────────────────────────────────────
#     # Only runs when:
#     #   1. No named rule fired this packet (attack_status == "normal")
#     #   2. No named rule fired for this IP recently (has_recent_rule_alert)
#     # This prevents known attacks from double-triggering ZERO_DAY,
#     # and prevents background traffic bursts from firing when a real
#     # attack was just detected from the same source.
#     if attack_status == "normal" and not has_recent_rule_alert(src):
#         if flush_ip_bucket(src) == "attack":
#             attack_status = "suspicious"

#     # ── SUSPICIOUS FALLBACK ───────────────────────────────────
#     if attack_status == "normal":
#         total_src_pps = len(tcp_rate[src]) + len(udp_rate[src]) + len(icmp_rate[src])
#         if total_src_pps > DOS_PPS_THRESHOLD * SUSPICIOUS_PPS_FACTOR:
#             attack_status = "suspicious"

#     pkt_info["status"] = attack_status
#     if traffic_history:
#         traffic_history[-1]["status"] = attack_status


# # =============================================================================
# # BACKGROUND THREADS
# # =============================================================================

# def _bucket_flush_worker():
#     """
#     Periodic background flush of IP buckets for zero-day detection.
#     Skips IPs that had a recent rule-based alert — no point running
#     anomaly detection on traffic already identified by a named rule.
#     """
#     while True:
#         time.sleep(10)
#         with ip_bucket_lock:
#             sources = list(ip_bucket_data.keys())
#         for src in sources:
#             if not has_recent_rule_alert(src):
#                 flush_ip_bucket(src)

# threading.Thread(target=_bucket_flush_worker, daemon=True).start()


# def _start_sniffer():
#     print(f"Sniffing on {INTERFACE} ...")
#     try:
#         sniff(iface=INTERFACE, prn=packet_callback, store=False)
#     except Exception as e:
#         print(f"Sniffer error on {INTERFACE}: {e} — trying default interface ...")
#         try:
#             sniff(prn=packet_callback, store=False)
#         except Exception as e2:
#             print(f"Fallback sniffer also failed: {e2}")

# threading.Thread(target=_start_sniffer, daemon=True).start()


# # =============================================================================
# # FLASK APP
# # =============================================================================
# flask_app = Flask(__name__, template_folder="templates")
# flask_app.config["SECRET_KEY"]                 = "hybrid-ids-secret-key-change-in-production-2024"
# flask_app.config["SESSION_TYPE"]               = "filesystem"
# flask_app.config["SESSION_PERMANENT"]          = True
# flask_app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=24)
# auth.init_app(flask_app)


# # --- Page routes -------------------------------------------------------------
# @flask_app.route("/")
# def index():
#     return redirect(url_for("network_traffic")) if auth.is_authenticated() else render_template("login.html")

# @flask_app.route("/network-traffic")
# @auth.login_required
# def network_traffic(): return render_template("network_traffic.html")

# @flask_app.route("/analysis")
# @auth.login_required
# def analysis(): return render_template("analysis.html")

# @flask_app.route("/attacks")
# @auth.login_required
# def attacks(): return render_template("attacks.html")

# @flask_app.route("/notifications")
# @auth.login_required
# def notifications(): return render_template("notifications.html")

# @flask_app.route("/settings")
# @auth.admin_required
# def settings(): return render_template("settings.html")

# @flask_app.route("/attack-logs")
# @auth.login_required
# def attack_logs_page():
#     return render_template("attack_logs.html")


# # --- Auth routes -------------------------------------------------------------
# @flask_app.route("/login")
# def login():
#     return redirect(url_for("index")) if auth.is_authenticated() else render_template("login.html")

# @flask_app.route("/login", methods=["POST"])
# def login_post():
#     username = request.form.get("username")
#     password = request.form.get("password")
#     remember = request.form.get("remember") == "on"
#     if not username or not password:
#         flash("Please provide both username and password.", "danger")
#         return redirect(url_for("login"))
#     success, message = auth.login_user(username, password, remember)
#     if success:
#         flash(message, "success")
#         return redirect(request.args.get("next") or url_for("network_traffic"))
#     flash(message, "danger")
#     return redirect(url_for("login"))

# @flask_app.route("/register")
# def register():
#     return redirect(url_for("index")) if auth.is_authenticated() else render_template("register.html")

# @flask_app.route("/register", methods=["POST"])
# def register_post():
#     success, message = auth.register_user(
#         request.form.get("username"), request.form.get("email"),
#         request.form.get("password"), request.form.get("confirm_password"),
#         request.form.get("full_name"),
#     )
#     if success:
#         flash(message, "success")
#         return redirect(url_for("login"))
#     for err in (message if isinstance(message, list) else [message]):
#         flash(err, "danger")
#     return redirect(url_for("register"))

# @flask_app.route("/logout")
# def logout():
#     auth.logout_user()
#     flash("You have been logged out successfully.", "info")
#     return redirect(url_for("login"))

# @flask_app.route("/change-password", methods=["POST"])
# def change_password():
#     if not auth.is_authenticated():
#         return jsonify({"success": False, "message": "Not authenticated"}), 401
#     success, message = auth.change_password(
#         request.form.get("current_password"),
#         request.form.get("new_password"),
#         request.form.get("confirm_password"),
#     )
#     return jsonify({"success": success, "message": message}), (200 if success else 400)


# # --- API helpers -------------------------------------------------------------
# def _calculate_stats(packets: list) -> dict:
#     if not packets:
#         now = time.time()
#         bl  = (100 if baseline_ready else
#                min(99, int(((now - baseline_start) / BASELINE_LEARNING_SECONDS) * 100))
#                if baseline_start else 0)
#         return {"total": 0, "safe": 0, "suspicious": 0, "attack": 0,
#                 "tcp": 0, "udp": 0, "icmp": 0, "other": 0,
#                 "avg_packet_size": 0, "packets_per_sec": 0,
#                 "baseline_ready": baseline_ready, "baseline_progress": bl}
#     tcp  = sum(1 for p in packets if p.get("protocol") == "TCP")
#     udp  = sum(1 for p in packets if p.get("protocol") == "UDP")
#     icmp = sum(1 for p in packets if p.get("protocol") == "ICMP")
#     safe = sum(1 for p in packets if p.get("status") == "normal")
#     susp = sum(1 for p in packets if p.get("status") == "suspicious")
#     atk  = sum(1 for p in packets if p.get("status") == "attack")
#     avg  = sum(p.get("length", 0) for p in packets) / len(packets)
#     now  = time.time()
#     rec5 = [p for p in packets if now - p.get("time", now) <= 5]
#     bl   = (100 if baseline_ready else
#             min(99, int(((now - baseline_start) / BASELINE_LEARNING_SECONDS) * 100))
#             if baseline_start else 0)
#     return {
#         "total": len(packets), "safe": safe, "suspicious": susp, "attack": atk,
#         "tcp": tcp, "udp": udp, "icmp": icmp,
#         "other": len(packets) - tcp - udp - icmp,
#         "avg_packet_size":  round(avg, 2),
#         "packets_per_sec":  round(len(rec5) / 5, 2) if rec5 else 0,
#         "baseline_ready":   baseline_ready,
#         "baseline_progress": bl,
#     }


# # --- API routes --------------------------------------------------------------
# @flask_app.route("/api/real-time-traffic")
# def api_real_time_traffic():
#     try:
#         with packet_lock:
#             snap  = packet_list[-100:]
#             stats = _calculate_stats(packet_list[-1000:])
#         data = [{
#             "timestamp": p.get("timestamp","--:--:--"),
#             "src": p.get("src","N/A"), "dst": p.get("dst","N/A"),
#             "protocol": p.get("protocol","N/A"), "dport": p.get("dport","N/A"),
#             "length": p.get("length",0), "status": p.get("status","normal"),
#             "flags": p.get("flags",""),
#         } for p in snap]
#         return jsonify({"packets": data[::-1], "stats": stats,
#                         "last_updated": datetime.now().strftime("%H:%M:%S"),
#                         "total_captured": len(packet_list), "status": "success"})
#     except Exception as e:
#         return jsonify({"packets": [], "stats": {}, "status": "error", "error": str(e)})


# @flask_app.route("/api/traffic-history")
# def api_traffic_history():
#     try:
#         cutoff = time.time() - 300
#         with packet_lock:
#             recent = [p for p in packet_list if p.get("time", 0) > cutoff]
#         proto_dist = {}
#         for p in recent:
#             k = p.get("protocol", "OTHER")
#             proto_dist[k] = proto_dist.get(k, 0) + 1
#         now = time.time()
#         timeline = []
#         for i in range(30):
#             s  = now - (i+1)*10
#             e  = now - i*10
#             iv = [p for p in recent if s < p.get("time",0) <= e]
#             timeline.append({
#                 "time": datetime.fromtimestamp(e).strftime("%H:%M:%S"),
#                 "packets": len(iv),
#                 "tcp":  sum(1 for p in iv if p.get("protocol")=="TCP"),
#                 "udp":  sum(1 for p in iv if p.get("protocol")=="UDP"),
#                 "icmp": sum(1 for p in iv if p.get("protocol")=="ICMP"),
#                 "suspicious": sum(1 for p in iv if p.get("status")=="suspicious"),
#                 "attack":     sum(1 for p in iv if p.get("status")=="attack"),
#             })
#         timeline.reverse()
#         return jsonify({"protocol_distribution": proto_dist, "timeline": timeline,
#                         "time_range": "5 minutes", "status": "success"})
#     except Exception as e:
#         return jsonify({"error": str(e), "protocol_distribution": {},
#                         "timeline": [], "status": "error"})


# @flask_app.route("/api/top-conversations")
# def api_top_conversations():
#     try:
#         with packet_lock:
#             pkts = packet_list[-500:]
#         counts, bytez = {}, {}
#         for p in pkts:
#             k = f"{p.get('src','?')}->{p.get('dst','?')}"
#             counts[k] = counts.get(k,0) + 1
#             bytez[k]  = bytez.get(k,0)  + p.get("length",0)
#         result = []
#         for conv, cnt in sorted(counts.items(), key=lambda x:x[1], reverse=True)[:10]:
#             s, d = conv.split("->")
#             tb   = bytez.get(conv, 0)
#             result.append({"source": s, "destination": d, "packet_count": cnt,
#                            "total_bytes": tb, "avg_packet_size": tb//cnt if cnt else 0})
#         return jsonify({"conversations": result, "status": "success"})
#     except Exception as e:
#         return jsonify({"conversations": [], "status": "error", "error": str(e)})


# @flask_app.route("/api/packet-size-distribution")
# def api_packet_size_distribution():
#     try:
#         with packet_lock:
#             pkts = packet_list[-500:]
#         bins  = {"0-100":0,"101-500":0,"501-1000":0,"1001-1500":0,"1501+":0}
#         sizes = []
#         for p in pkts:
#             s = p.get("length",0); sizes.append(s)
#             if s<=100:    bins["0-100"]+=1
#             elif s<=500:  bins["101-500"]+=1
#             elif s<=1000: bins["501-1000"]+=1
#             elif s<=1500: bins["1001-1500"]+=1
#             else:         bins["1501+"]+=1
#         return jsonify({"distribution": bins,
#                         "min_size": min(sizes) if sizes else 0,
#                         "max_size": max(sizes) if sizes else 0,
#                         "avg_size": round(sum(sizes)/len(sizes),2) if sizes else 0,
#                         "most_common": max(bins, key=bins.get),
#                         "status": "success"})
#     except Exception as e:
#         return jsonify({"distribution":{}, "min_size":0, "max_size":0,
#                         "avg_size":0, "most_common":"0-100", "status":"error", "error":str(e)})


# @flask_app.route("/api/network-status")
# def api_network_status():
#     try:
#         now = time.time()
#         recent_atk  = [a for a in attack_history if (datetime.now()-a["time"]).total_seconds()<300]
#         very_recent = [a for a in attack_history if (datetime.now()-a["time"]).total_seconds()<10]
#         status      = "under_attack" if very_recent else ("warning" if recent_atk else "normal")
#         recent_pkts = [p for p in packet_list if now - p.get("time",now) <= 10]
#         bl = (100 if baseline_ready else
#               min(99,int(((now-baseline_start)/BASELINE_LEARNING_SECONDS)*100))
#               if baseline_start else 0)
#         atk_counts = defaultdict(int)
#         for a in attack_history: atk_counts[a["type"]] += 1
#         return jsonify({
#             "status": status,
#             "packets_per_second":  round(len(recent_pkts)/10,2) if recent_pkts else 0,
#             "total_packets":       len(packet_list),
#             "active_attacks":      len(recent_atk),
#             "interface":           INTERFACE,
#             "uptime":              get_uptime(),
#             "ml_enabled":          ML_ENABLED,
#             "memory_usage":        round(len(packet_list)*0.01,2),
#             "capture_status":      "active",
#             "attack_status":       ("critical" if status=="under_attack"
#                                     else "warning" if status=="warning" else "normal"),
#             "system_time":         datetime.now().strftime("%H:%M:%S"),
#             "zero_day_enabled":    True,
#             "baseline_ready":      baseline_ready,
#             "baseline_progress":   bl,
#             "anomaly_z_threshold": ANOMALY_Z_THRESHOLD,
#             "attack_type_summary": dict(atk_counts),
#             "brute_force_ports":   list(BRUTE_FORCE_PORTS.keys()),
#             "whitelist_private":   WHITELIST_PRIVATE_RANGES,
#         })
#     except Exception as e:
#         return jsonify({"status": "error", "error": str(e)})


# @flask_app.route("/api/attack-logs")
# def api_attack_logs():
#     try:
#         import os, re
#         log_path = LOG_FILE
#         if not os.path.exists(log_path):
#             return jsonify({"logs": [], "status": "success"})
#         lines = []
#         with open(log_path, "r", encoding="utf-8", errors="ignore") as fh:
#             for raw in fh:
#                 raw = raw.strip("\n")
#                 if raw:
#                     lines.append(raw)
#         parsed = []
#         line_re = re.compile(r"^\[(?P<ts>[^\]]+)\]\s+(?P<type>[^\s|]+)\s+\|\s+(?P<msg>.*)$")
#         for ln in lines:
#             m = line_re.match(ln)
#             if m:
#                 parsed.append({
#                     "timestamp": m.group("ts"),
#                     "type": m.group("type"),
#                     "message": m.group("msg"),
#                 })
#             else:
#                 parsed.append({"timestamp": "--", "type": "UNKNOWN", "message": ln})
#         parsed = list(reversed(parsed))
#         return jsonify({"logs": parsed, "total": len(parsed), "status": "success"})
#     except Exception as e:
#         return jsonify({"logs": [], "total": 0, "status": "error", "error": str(e)})


# @flask_app.route("/api/attacks")
# def api_attacks():
#     try:
#         import re
#         result = []
#         for a in sorted(attack_history, key=lambda x:x["time"], reverse=True)[:50]:
#             msg   = a["message"]
#             src_m = re.search(r"SRC=([\d\.]+)", msg)
#             dst_m = re.search(r"DST=([\d\.]+)", msg)
#             atype = a["type"]
#             sev   = ("critical" if atype in ("DDoS","ZERO_DAY","CREDENTIAL_STUFFING")
#                      else "high" if atype in ("DoS","SYN_FLOOD","RST_FLOOD","FIN_FLOOD",
#                                                "ACK_FLOOD","HTTP_FLOOD","BRUTE_FORCE")
#                      else "medium")
#             result.append({
#                 "type": atype, "message": msg, "timestamp": a["timestamp"],
#                 "source": src_m.group(1) if src_m else "Unknown",
#                 "target": dst_m.group(1) if dst_m else "Unknown",
#                 "severity": sev, "time_ago": get_time_ago(a["time"]),
#             })
#         return jsonify({
#             "attacks":           result,
#             "total":             len(attack_history),
#             "today":             len([a for a in attack_history
#                                        if a["time"].date()==datetime.now().date()]),
#             "zero_day_count":    sum(1 for a in attack_history if "ZERO_DAY"    in a["type"]),
#             "brute_force_count": sum(1 for a in attack_history if "BRUTE_FORCE" in a["type"]),
#             "status": "success",
#         })
#     except Exception as e:
#         return jsonify({"attacks":[],"total":0,"today":0,"status":"error","error":str(e)})


# @flask_app.route("/api/notifications")
# def api_notifications():
#     try:
#         notifs = [{"id":1,"type":"system","title":"System Started",
#                    "message":f"Hybrid IDS running on {INTERFACE}",
#                    "timestamp":system_start_time.strftime("%H:%M:%S"),
#                    "read":True,"priority":"info"}]
#         if ML_ENABLED:
#             notifs.append({"id":2,"type":"system","title":"ML Detection Enabled",
#                            "message":"Machine learning detection is active",
#                            "timestamp":datetime.now().strftime("%H:%M:%S"),
#                            "read":True,"priority":"info"})
#         if baseline_ready:
#             notifs.append({"id":3,"type":"system","title":"Zero-Day Detection Active",
#                            "message":f"Baseline established — Z={ANOMALY_Z_THRESHOLD}  min_pkts={MIN_PKT_COUNT_FOR_ANOMALY}",
#                            "timestamp":datetime.now().strftime("%H:%M:%S"),
#                            "read":True,"priority":"info"})
#         elif baseline_start:
#             pct = min(99,int(((time.time()-baseline_start)/BASELINE_LEARNING_SECONDS)*100))
#             notifs.append({"id":3,"type":"system","title":"Zero-Day Baseline Learning",
#                            "message":f"Building baseline ({pct}% complete) — suspicious buckets auto-skipped",
#                            "timestamp":datetime.now().strftime("%H:%M:%S"),
#                            "read":True,"priority":"info"})
#         notifs.append({"id":4,"type":"system","title":"Brute Force Detection Active",
#                        "message":f"Monitoring {len(BRUTE_FORCE_PORTS)} auth ports — "
#                                   f"threshold {BRUTE_FORCE_THRESHOLD}/{BRUTE_FORCE_WINDOW}s",
#                        "timestamp":datetime.now().strftime("%H:%M:%S"),
#                        "read":True,"priority":"info"})
#         for i, a in enumerate(list(attack_history)[-10:]):
#             pri = ("critical" if a["type"] in ("DDoS","ZERO_DAY","CREDENTIAL_STUFFING")
#                    else "high" if a["type"] in ("DoS","BRUTE_FORCE","HTTP_FLOOD",
#                                                  "RST_FLOOD","FIN_FLOOD","ACK_FLOOD")
#                    else "medium")
#             notifs.append({"id":1000+i,"type":"attack",
#                            "title":f"Attack: {a['type']}","message":a["message"],
#                            "timestamp":a["timestamp"],"read":False,"priority":pri})
#         return jsonify({"notifications":notifs[::-1],
#                         "unread":sum(1 for n in notifs if not n.get("read",False)),
#                         "status":"success"})
#     except Exception as e:
#         return jsonify({"notifications":[],"unread":0,"status":"error","error":str(e)})


# @flask_app.route("/api/analysis")
# def api_analysis():
#     try:
#         with packet_lock:
#             packets = packet_list.copy()
#         if not packets:
#             return jsonify({"protocols":{},"top_sources":[],"top_destinations":[],
#                             "packet_rate":0,"avg_packet_size":0,"total_bytes":0,
#                             "hourly_pattern":[],"status":"success"})
#         protocols = defaultdict(int)
#         sources   = defaultdict(int)
#         dests     = defaultdict(int)
#         for p in packets:
#             protocols[p.get("protocol","OTHER")] += 1
#             sources[p.get("src")] += 1
#             dests[p.get("dst")]   += 1
#         elapsed = time.time() - packets[0].get("time", time.time())
#         return jsonify({
#             "protocols": dict(protocols),
#             "top_sources":      [{"ip":ip,"count":c} for ip,c in
#                                   sorted(sources.items(),key=lambda x:x[1],reverse=True)[:10]],
#             "top_destinations": [{"ip":ip,"count":c} for ip,c in
#                                   sorted(dests.items(),key=lambda x:x[1],reverse=True)[:10]],
#             "packet_rate":     round(len(packets)/max(1,elapsed)*60,2),
#             "avg_packet_size": round(float(np.mean([p.get("length",0) for p in packets])),2),
#             "total_bytes":     sum(p.get("length",0) for p in packets),
#             "hourly_pattern":  [{"hour":f"{h:02d}:00",
#                                   "packets":int(np.random.randint(50,500))} for h in range(24)],
#             "status": "success",
#         })
#     except Exception as e:
#         return jsonify({"protocols":{},"top_sources":[],"top_destinations":[],
#                         "packet_rate":0,"avg_packet_size":0,"total_bytes":0,
#                         "hourly_pattern":[],"status":"error","error":str(e)})


# @flask_app.route("/api/clear-traffic", methods=["POST"])
# def api_clear_traffic():
#     try:
#         global packet_list
#         with packet_lock: packet_list.clear()
#         return jsonify({"success":True,"message":"Traffic data cleared"})
#     except Exception as e:
#         return jsonify({"success":False,"message":str(e)})


# @flask_app.route("/api/resume-capture", methods=["POST"])
# def api_resume_capture():
#     return jsonify({"success":True,"message":"Capture is always active"})


# @flask_app.route("/api/reset-baseline", methods=["POST"])
# def api_reset_baseline():
#     """
#     Resets the zero-day baseline so it re-learns on clean traffic.
#     Use after any test run that may have run during the learning window.
#       curl -X POST http://127.0.0.1:8090/api/reset-baseline
#     """
#     global baseline_ready, baseline_start, baseline_means, baseline_stds
#     if not auth.is_authenticated():
#         return jsonify({"success": False, "message": "Not authenticated"}), 401
#     baseline_ready  = False
#     baseline_start  = None
#     baseline_means.clear()
#     baseline_stds.clear()
#     baseline_samples.clear()
#     zero_day_last_alert.clear()
#     print("[BASELINE] Reset by user — re-learning on next clean traffic.")
#     return jsonify({
#         "success": True,
#         "message": f"Baseline reset. Re-learning over next {BASELINE_LEARNING_SECONDS}s of clean traffic.",
#     })


# @flask_app.route("/api/reset-cooldown/<src>", methods=["POST"])
# @auth.admin_required
# def api_reset_cooldown(src):
#     """Reset cooldown for a specific source IP."""
#     try:
#         with cooldown_lock:
#             # Clear attack cooldowns for this src
#             keys_to_delete = [k for k in attack_cooldowns.keys() if k.endswith(f":{src}")]
#             for k in keys_to_delete:
#                 del attack_cooldowns[k]
        
#         with rule_alert_lock:
#             if src in rule_based_alert_times:
#                 del rule_based_alert_times[src]
        
#         if src in zero_day_last_alert:
#             del zero_day_last_alert[src]
        
#         return jsonify({"success": True, "message": f"Cooldowns reset for {src}"})
#     except Exception as e:
#         return jsonify({"success": False, "error": str(e)})


# @flask_app.route("/api/debug-bucket/<src>")
# @auth.login_required
# def api_debug_bucket(src):
#     """Debug endpoint to inspect a source IP's current bucket."""
#     try:
#         with ip_bucket_lock:
#             if src not in ip_bucket_data:
#                 return jsonify({"error": "Source IP not found", "status": "error"})
#             bucket = ip_bucket_data[src]
#             features = _extract_bucket_features(bucket)
#             now = time.time()
            
#             # Calculate z-scores if baseline is ready
#             z_scores = {}
#             if baseline_ready:
#                 for fname in FEATURE_NAMES:
#                     val = features.get(fname, 0)
#                     mean = baseline_means.get(fname, 0)
#                     std = baseline_stds.get(fname, 1)
#                     z_scores[fname] = round(abs(val - mean) / max(std, 0.01), 3)
            
#             # Check if it would be considered anomalous
#             would_be_anomaly = False
#             if baseline_ready:
#                 anomalous_count = sum(1 for z in z_scores.values() if z > ANOMALY_Z_THRESHOLD)
#                 would_be_anomaly = anomalous_count >= ANOMALY_FEATURE_COUNT
            
#             return jsonify({
#                 "source": src,
#                 "bucket_age_seconds": round(now - bucket["bucket_start"], 2),
#                 "packet_count": bucket["pkt_count"],
#                 "features": features,
#                 "baseline_ready": baseline_ready,
#                 "has_recent_rule_alert": has_recent_rule_alert(src),
#                 "baseline_values": {
#                     fname: {
#                         "mean": round(baseline_means.get(fname, 0), 3),
#                         "std": round(baseline_stds.get(fname, 1), 3)
#                     } for fname in FEATURE_NAMES
#                 } if baseline_ready else None,
#                 "z_scores": z_scores if baseline_ready else None,
#                 "anomaly_threshold": ANOMALY_Z_THRESHOLD,
#                 "features_required": ANOMALY_FEATURE_COUNT,
#                 "would_be_anomaly": would_be_anomaly,
#                 "min_packets_required": MIN_PKT_COUNT_FOR_ANOMALY,
#                 "would_be_checked": bucket["pkt_count"] >= MIN_PKT_COUNT_FOR_ANOMALY,
#                 "status": "success"
#             })
#     except Exception as e:
#         return jsonify({"error": str(e), "status": "error"})


# @flask_app.route("/api/zero-day-config")
# @auth.login_required
# def api_zero_day_config():
#     """Return current zero-day configuration."""
#     return jsonify({
#         "baseline_learning_seconds": BASELINE_LEARNING_SECONDS,
#         "anomaly_z_threshold": ANOMALY_Z_THRESHOLD,
#         "anomaly_feature_count": ANOMALY_FEATURE_COUNT,
#         "zero_day_cooldown": ZERO_DAY_COOLDOWN,
#         "min_pkt_count_for_anomaly": MIN_PKT_COUNT_FOR_ANOMALY,
#         "attack_cooldown_sec": ATTACK_COOLDOWN_SEC,
#         "whitelist_private_ranges": WHITELIST_PRIVATE_RANGES,
#         "whitelisted_ips": list(WHITELISTED_IPS),
#         "baseline_ready": baseline_ready,
#         "status": "success"
#     })


# @flask_app.route("/api/zero-day-stats")
# def api_zero_day_stats():
#     try:
#         stats = {}
#         if baseline_ready:
#             for fname in FEATURE_NAMES:
#                 stats[fname] = {
#                     "mean": round(baseline_means.get(fname, 0), 3),
#                     "std":  round(baseline_stds.get(fname, 0), 3),
#                 }
#         now = time.time()
#         bl  = (100 if baseline_ready else
#                min(99, int(((now - baseline_start) / BASELINE_LEARNING_SECONDS) * 100))
#                if baseline_start else 0)
#         return jsonify({
#             "enabled":             True,
#             "baseline_ready":      baseline_ready,
#             "baseline_progress":   bl,
#             "feature_stats":       stats,
#             "z_threshold":         ANOMALY_Z_THRESHOLD,
#             "feature_count_req":   ANOMALY_FEATURE_COUNT,
#             "min_pkt_count":       MIN_PKT_COUNT_FOR_ANOMALY,
#             "cooldown_sec":        ZERO_DAY_COOLDOWN,
#             "learning_window":     BASELINE_LEARNING_SECONDS,
#             "total_zero_day":      sum(1 for a in attack_history if "ZERO_DAY" in a["type"]),
#             "fp_guards":           [
#                 f"z_threshold={ANOMALY_Z_THRESHOLD} (raised from 4.0)",
#                 f"feature_count={ANOMALY_FEATURE_COUNT} (raised from 4)",
#                 f"min_pkt_count={MIN_PKT_COUNT_FOR_ANOMALY} (ignores idle trickle)",
#                 "rule_suppression: zero-day skipped for IPs with recent named-rule alerts",
#                 "baseline_guard: skips attack-like buckets during learning",
#                 "wide_std_floor: mean*0.5+1.0 tolerates natural traffic bursts",
#             ],
#             "status": "success",
#         })
#     except Exception as e:
#         return jsonify({"enabled":True,"baseline_ready":False,"status":"error","error":str(e)})


# @flask_app.route("/api/brute-force-stats")
# def api_brute_force_stats():
#     try:
#         now    = time.time()
#         active = []
#         with brute_force_lock:
#             for key, q in brute_force_attempts.items():
#                 recent = sum(1 for t in q if now - t <= BRUTE_FORCE_WINDOW)
#                 if recent > 0:
#                     src, dp = key.rsplit(":",1)
#                     dp = int(dp)
#                     active.append({"src":src,"port":dp,
#                                    "service":BRUTE_FORCE_PORTS.get(dp,f"PORT-{dp}"),
#                                    "attempts_in_window":recent,
#                                    "threshold":BRUTE_FORCE_THRESHOLD,
#                                    "pct":round(recent/BRUTE_FORCE_THRESHOLD*100,1)})
#         active.sort(key=lambda x:x["attempts_in_window"],reverse=True)
#         return jsonify({"active_attempts":active[:20],"window_seconds":BRUTE_FORCE_WINDOW,
#                         "threshold":BRUTE_FORCE_THRESHOLD,
#                         "monitored_ports":BRUTE_FORCE_PORTS,"status":"success"})
#     except Exception as e:
#         return jsonify({"active_attempts":[],"status":"error","error":str(e)})


# # =============================================================================
# # DASH  (legacy dashboard)
# # =============================================================================
# app = dash.Dash(__name__, server=flask_app, url_base_pathname="/dash/")
# app.title = "Hybrid IDS"
# app.layout = html.Div([
#     html.H1("Hybrid IDS Dashboard", style={"textAlign":"center"}),
#     html.Div(id="alert-box", style={"textAlign":"center","padding":"15px"}),
#     html.Button("Clear Alert Display", id="clear-btn"),
#     html.Div(id="stats-bar"),
#     dash_table.DataTable(
#         id="pkt-table",
#         columns=[
#             {"name":"Time",        "id":"timestamp"},
#             {"name":"Source",      "id":"src"},
#             {"name":"Destination", "id":"dst"},
#             {"name":"Proto",       "id":"protocol"},
#             {"name":"Len",         "id":"length"},
#             {"name":"Status",      "id":"status"},
#         ],
#         page_size=10,
#         style_cell={"fontFamily":"monospace","fontSize":12},
#         style_data_conditional=[
#             {"if":{"filter_query":'{status} = "attack"'},     "backgroundColor":"#ffcccc"},
#             {"if":{"filter_query":'{status} = "suspicious"'}, "backgroundColor":"#fff3cd"},
#         ],
#     ),
#     dcc.Interval(id="tick", interval=2000),
# ])


# @app.callback(
#     [Output("pkt-table","data"),
#      Output("alert-box","children"),
#      Output("stats-bar","children")],
#     Input("tick","n_intervals"),
# )
# def update_dash(n):
#     with packet_lock:
#         rows = packet_list[-10:]
#     recent_attacks = [a for a in attack_history
#                       if (datetime.now()-a["time"]).total_seconds() < 30]
#     if recent_attacks:
#         latest   = recent_attacks[-1]
#         alert_el = html.Div(
#             [html.H3("ATTACK DETECTED"),
#              html.P(f"{latest['type']} — {latest['message']}")],
#             style={"background":"#ffcccc","padding":"10px","borderRadius":"6px"})
#     else:
#         alert_el = html.Div("NORMAL",
#                             style={"color":"green","fontWeight":"bold","fontSize":18})
#     susp  = sum(1 for p in packet_list[-100:] if p.get("status")=="suspicious")
#     now_t = time.time()
#     zd_pct = min(99,int(((now_t-(baseline_start or now_t))/BASELINE_LEARNING_SECONDS)*100))
#     zd     = "Active" if baseline_ready else f"Learning ({zd_pct}%)"
#     bf     = sum(1 for a in attack_history if "BRUTE_FORCE" in a["type"])
#     stats_el = html.Div([
#         html.Span(f"Packets: {len(packet_list)}  |  "),
#         html.Span(f"Suspicious: {susp}  |  "),
#         html.Span(f"Alerts: {len(attack_history)}  |  "),
#         html.Span(f"Brute-force: {bf}  |  "),
#         html.Span(f"Zero-Day: {zd}"),
#     ])
#     return rows, alert_el, stats_el


# @app.callback(Output("alert-box","style"), Input("clear-btn","n_clicks"))
# def clear_alert_style(_): return {}


# # =============================================================================
# # ENTRY POINT
# # =============================================================================
# if __name__ == "__main__":
#     import os
#     import subprocess
    
#     print("\n" + "="*65)
#     print("   HYBRID INTRUSION DETECTION SYSTEM")
#     print("="*65)
#     print(f"  Interface          : {INTERFACE}")
#     print(f"  ML Detection       : {'ENABLED' if ML_ENABLED else 'DISABLED'}")
#     print(f"  Whitelisted IPs    : {', '.join(WHITELISTED_IPS)}")
#     print(f"  Private Ranges     : {'AUTO-WHITELISTED' if WHITELIST_PRIVATE_RANGES else 'NOT whitelisted'}")
#     print(f"  Zero-Day           : baseline={BASELINE_LEARNING_SECONDS}s  z={ANOMALY_Z_THRESHOLD}  features={ANOMALY_FEATURE_COUNT}")
#     print(f"  Zero-Day FP Guards :")
#     print(f"    - z_threshold={ANOMALY_Z_THRESHOLD} (higher = fewer false positives from background)")
#     print(f"    - feature_count={ANOMALY_FEATURE_COUNT} (needs more features to be anomalous)")
#     print(f"    - min_pkt_count={MIN_PKT_COUNT_FOR_ANOMALY} (ignores idle trickle traffic)")
#     print(f"    - rule_suppression: ZERO_DAY skipped if named rule fired for same IP recently")
#     print(f"    - baseline_guard: attack-like buckets skipped during learning")
#     print(f"    - wide_std_floor: mean*0.5+1.0 tolerates natural bursts (DNS/NTP/mDNS)")
#     print(f"  Brute Force        : {BRUTE_FORCE_THRESHOLD} attempts/{BRUTE_FORCE_WINDOW}s")
#     print(f"  RST/FIN Flood      : threshold={RST_FLOOD_THRESHOLD}/{FIN_FLOOD_THRESHOLD} pps")
#     print(f"  ACK Flood          : threshold={ACK_FLOOD_THRESHOLD} pps")
#     print(f"  HTTP Flood         : threshold={HTTP_FLOOD_THRESHOLD} pps")
#     print(f"  XMAS/NULL Scan     : {XMAS_SCAN_THRESHOLD}/{NULL_SCAN_THRESHOLD} ports/{SCAN_WINDOW}s")
#     print(f"  Cred Stuffing      : {CRED_STUFF_SRC_THRESHOLD} unique IPs/{CRED_STUFF_WINDOW}s")
#     print(f"  Alert Cooldown     : {ATTACK_COOLDOWN_SEC}s per (type, source)")
#     print(f"  Zero-Day Cooldown  : {ZERO_DAY_COOLDOWN}s per source")
#     print(f"  Suspicious @ >     : {int(DOS_PPS_THRESHOLD*SUSPICIOUS_PPS_FACTOR)} pps")
#     print("="*65)
    
#     # Check interface    print("  Checking interface...")
#     try:
#         result = subprocess.run(["ip", "link", "show", INTERFACE], capture_output=True, text=True)
#         if result.returncode != 0:
#             print(f"  WARNING: Interface '{INTERFACE}' not found!")
#             result = subprocess.run(["ip", "link", "show"], capture_output=True, text=True)
#             print("  Available interfaces:")
#             for line in result.stdout.splitlines():
#                 if "state" in line:
#                     print(f"    {line.strip()}")
#             print(f"  You may need to change INTERFACE variable in the code")
#         else:
#             print(f"  Interface '{INTERFACE}' found and ready")
#     except Exception as e:
#         print(f"  Could not check interface: {e}")
    
#     print("\n  URLs:")
#     print("    Network Traffic  ->  http://127.0.0.1:8090/network-traffic")
#     print("    Attacks          ->  http://127.0.0.1:8090/attacks")
#     print("    Analysis         ->  http://127.0.0.1:8090/analysis")
#     print("    Notifications    ->  http://127.0.0.1:8090/notifications")
#     print("    Legacy Dash      ->  http://127.0.0.1:8090/dash/")
#     print("    Zero-Day Stats   ->  http://127.0.0.1:8090/api/zero-day-stats")
#     print("    Zero-Day Config  ->  http://127.0.0.1:8090/api/zero-day-config")
#     print("    Brute-Force Live ->  http://127.0.0.1:8090/api/brute-force-stats")
#     print("\n  Debug/Admin:")
#     print("    Reset Baseline   ->  curl -X POST http://127.0.0.1:8090/api/reset-baseline")
#     print("    Reset Cooldown   ->  curl -X POST http://127.0.0.1:8090/api/reset-cooldown/<IP>")
#     print("    Debug Bucket     ->  http://127.0.0.1:8090/api/debug-bucket/<IP>")
#     print("="*65)
#     print("  IMPORTANT: Wait 180s of CLEAN traffic before testing.")
#     print("  If you saw zero-day during idle, reset the baseline:")
#     print("    curl -X POST http://127.0.0.1:8090/api/reset-baseline")
#     print("  Then wait 180s idle before running nmap/hping.")
#     print("="*65 + "\n")

#     if not os.path.exists("templates"):
#         os.makedirs("templates")
#     try:
#         flask_app.run(host="0.0.0.0", port=8090, debug=False, threaded=True)
#     except Exception as e:
#         print(f"Error starting server: {e}")


































