# SmartEye Hybrid IDS (Traffic Streaming + Attack Detection)

This project provides a **live network intrusion detection system (IDS)** with a web dashboard.
It captures packets from a network interface, detects common attack patterns (scans, DoS/DDoS, floods, brute force, credential stuffing), and exposes results through a **Flask + Dash** UI.
It also supports an **optional ML model** and includes a **zero-day / anomaly detector** based on baseline statistics.

> **Important:** Running the packet sniffer requires elevated privileges (typically `sudo`) because it uses raw packet capture (Scapy).

---

## Project components

### `main.py`

Core application entry point.

- Starts a **packet sniffer thread** using Scapy (`sniff()`), continuously populating in-memory structures:
  - `packet_list`: recent packet metadata for the UI
  - `attack_history`: detected attack events
  - `traffic_history`: historical packet records (bounded deque)
- Runs attack detection logic in `packet_callback(pkt)`:
  - **Port scans**: SYN scans, UDP scans, ICMP scans
  - **Special TCP scans**: XMAS scan (FIN+PSH+URG), NULL scan (flags == 0)
  - **Flood / DoS-style alerts**: SYN flood / DoS, UDP flood, RST flood, FIN flood, ACK flood
  - **HTTP flood**: high-rate PSH/ACK packets to common web ports
  - **Brute force**: repeated connection attempts across monitored service ports
  - **Credential stuffing**: many unique sources hitting web ports for the same destination/port
  - **DDoS**: many sources contributing traffic to the same destination
  - **Zero-day / anomaly**: after baseline learning, detect outliers per-source using statistical Z-scores
- Exposes Flask routes for pages and JSON APIs consumed by the HTML templates.

### `auth.py`

Authentication & authorization layer.

- Implements `AuthManager` with decorators:
  - `login_required` for user-protected routes
  - `admin_required` for admin-only pages
- Stores login sessions in the SQLite DB (via `database.py`).

### `database.py`

SQLite database wrapper.

- Creates and manages tables:
  - `users`
  - `sessions`
  - `login_attempts`
  - `user_activity`
- Provides methods used by `auth.py`:
  - create users, verify passwords
  - session creation and invalidation
  - lock accounts after repeated failed attempts

### `templates/`

UI pages rendered by Flask/Dash.

Routes in `main.py` map to templates like:

- `network_traffic.html`
- `analysis.html`
- `attacks.html`
- `notifications.html`
- `settings.html`
- `login.html`, `register.html`

### `model/`

Pretrained ML artifacts used when ML is enabled in `main.py`:

- `.h5` TensorFlow/Keras model
- `.pkl` label encoders / scalers

---

## How it works (deep runtime description)

At a high level, SmartEye runs three parallel concerns:

1. **Continuous packet ingestion** (Scapy sniffer)
2. **Stateful threat inference** (rule engine + anomaly detector)
3. **Operational visualization** (Flask endpoints polled by the dashboard UI)

### 1) Packet ingestion: converting raw packets into “features”

- `main.py` starts a background thread that executes `sniff(iface=INTERFACE, prn=packet_callback, store=False)`.
- For every received packet, `packet_callback(pkt)`:
  1. Extracts the minimum representation needed for detection/UI:
     - `src`, `dst` (IP addresses)
     - `protocol` (`TCP`, `UDP`, `ICMP`, otherwise `OTHER`)
     - `dport` (transport destination port for TCP/UDP)
     - `length` (packet size)
     - **TCP flags** string built from SYN/ACK/FIN/RST/PSH/URG
  2. Builds a metadata object `pkt_info` containing timestamps, addresses, protocol, port, flags, and a computed `status`.
  3. Appends this metadata into:
     - `packet_list` (bounded to `MAX_PACKETS`) for the “live table”
     - `traffic_history` (bounded to 5000) for longer internal computations

This separation is important: the IDS does not try to decode application payloads; it infers intent from header-level behavior.

### 2) Stateful rule engine: why detection is mostly “behavioral”

Detection is implemented as a set of heuristics that track how an IP behaves over time.

#### A. Rate and time windows

The IDS uses per-source sliding windows (mostly 1-second windows via `deque`s) and larger event windows (e.g., `PORT_SCAN_WINDOW`, `SCAN_WINDOW`).

- `rate_update(rate_dict, key)` maintains a rolling 1-second packet-per-second estimate.
- For scan detectors, the code keeps a “set of observed targets/ports” and resets it when the time window expires.

#### B. Whitelisting to reduce false positives

`packet_callback` immediately skips detection logic for whitelisted sources:

- Whitelisted IPs: `WHITELISTED_IPS`
- Link-local/loopback/multicast are always ignored
- Private ranges are only whitelisted when `WHITELIST_PRIVATE_RANGES` is enabled (the README notes it is tuned for testing)

This design prevents noisy traffic from known devices (router/gateway/localhost) from repeatedly triggering alerts.

#### C. Port scans (SYN/UDP/ICMP)

For scan-like behavior, the IDS looks for a _single origin_ contacting _many distinct ports or targets_ within a fixed time window.

- **SYN scan**: when SYN packets without ACK are seen, it calls `check_port_scan(src, dst, dport)`.
- **UDP scan**: `check_udp_scan(src, dst, dport)` uses UDP packets and counts unique UDP ports.
- **ICMP scan**: `check_icmp_scan(src, dst)` counts unique destinations reached by ICMP.

Each check logs an attack event via `log_attack(...)` once the unique-port/unique-target count crosses the threshold.

#### D. Specialized TCP scan types: XMAS + NULL

These are header-only patterns that commonly indicate scanning tools.

- **XMAS scan**: FIN + PSH + URG flags (`is_xmas`) to many ports within `SCAN_WINDOW`.
- **NULL scan**: packets where `flags == ""` (`is_null`) to many ports within `SCAN_WINDOW`.

Unlike the generic SYN/UDP/ICMP logic, these rely entirely on the exact combination/absence of TCP flags.

#### E. Flood / DoS family

Flood detectors are primarily PPS (packets-per-second) driven.

- **DoS / SYN flood**: high PPS from a single attacker source.
- **DoS / UDP flood**: high PPS from a single source, tracked by `udp_rate`.
- **RST flood**, **FIN flood**, **ACK flood**: header-flag specific floods using dedicated rate trackers.
- **HTTP flood**: a PSH+ACK pattern aimed at common web ports (`HTTP_PORTS`).

A packet’s `attack_status` is then set to `attack` or `suspicious` depending on whether it passes the “hard” threshold or only the softer warning band.

#### F. Brute force + credential stuffing

These detectors model multi-attempt behavior rather than raw PPS:

- **Brute force**: repeated TCP SYN attempts to one of the monitored service ports in `BRUTE_FORCE_PORTS` within `BRUTE_FORCE_WINDOW`.
- **Credential stuffing**: many distinct source IPs hitting web ports on the same destination/port within `CRED_STUFF_WINDOW`.

#### G. DDoS logic

DDoS is inferred when:

- a destination receives traffic from many distinct sources (`len(dst_sources[dst]) >= DDOS_SOURCE_THRESHOLD`)
- and the combined PPS is above `DDOS_TOTAL_PPS`.

This blends “many sources” + “high overall volume” into a single decision.

### 3) Zero-day / anomaly detection: learning a baseline, then flagging statistical outliers

Zero-day detection is implemented in three phases:

1. **Baseline learning period** (`BASELINE_LEARNING_SECONDS`, default 180s)
   - For each source IP, the IDS aggregates a bucket of:
     - number of packets
     - total bytes
     - number of unique destinations
     - number of unique destination ports
     - TCP SYN / UDP / ICMP counters
     - average packet size
     - destination port entropy (Shannon entropy over the unique port set)
   - It collects these features in `baseline_samples`.

2. **Baseline establishment**
   - After enough samples exist, it computes:
     - mean per feature
     - std per feature (with safeguards so std doesn’t become too small)
   - It then marks `baseline_ready = True`.

3. **Continuous anomaly scoring**
   - Every time the per-source bucket exceeds the flush interval, the system computes the same feature vector.
   - Each feature is converted to a Z-score:
     - `z = abs(value - mean) / std`
   - If at least `ANOMALY_FEATURE_COUNT` features exceed `ANOMALY_Z_THRESHOLD`, the source becomes an anomaly candidate.
   - `ZERO_DAY_COOLDOWN` prevents repeated alerts from the same source.

Anomaly alerts are logged as `ZERO_DAY` and set the status to `attack`/`suspicious` depending on the integration point.

### 4) Attack recording and UI state updates

When `log_attack(...)` is called:

- The IDS appends a structured event to `attack_history` (bounded by 1000)
- It also writes a human-readable line to `attack_logs.log`
- It applies an **(atype, src)** cooldown (`ATTACK_COOLDOWN_SEC`) to reduce duplicate spam

In parallel, every packet metadata record gets a computed `status` field and is stored in `packet_list` for the UI.

### 5) Dashboard polling: how the pages get live data

The HTML templates are backed by Flask JSON endpoints (e.g., `/api/real-time-traffic`, `/api/network-status`, `/api/attacks`, `/api/analysis`).

The dashboard repeatedly polls these endpoints to:

- show the latest packets
- summarize status distribution (normal/suspicious/attack)
- show recent attack history
- render aggregated statistics (protocol distribution, top conversations, size distribution)

---

## Attack detection summary

The system labels each packet with a `status`:

- `normal`
- `suspicious`
- `attack`

Detected alert types include (as implemented in `main.py`):

- `PORT_SCAN` (SYN scan)
- `UDP_SCAN`
- `ICMP_SCAN`
- `XMAS_SCAN` (FIN+PSH+URG)
- `NULL_SCAN` (flags == 0)
- `DoS` (UDP flood / SYN flood)
- `DDoS`
- `RST_FLOOD`
- `FIN_FLOOD`
- `ACK_FLOOD`
- `HTTP_FLOOD`
- `BRUTE_FORCE`
- `CREDENTIAL_STUFFING`
- `ZERO_DAY` (anomaly-based)

---

## Whitelisting behavior

`main.py` supports `WHITELISTED_IPS` and `WHITELIST_PRIVATE_RANGES`.

- Packets from whitelisted sources skip detection logic.
- The default configuration is tuned to avoid false positives during testing.

Adjust these values for your environment (router/gateway IPs, known scanners, etc.).

---

## Setup and running

### 1) Install dependencies

The project expects Python packages listed in:

- `requirements.txt` (basic)
- `requirements_enhanced.txt` (if you need additional capabilities)

### 2) Start the app

Run:

```bash
sudo python main.py
```

Then open the dashboard pages:

- `http://127.0.0.1:8090/network-traffic`
- `http://127.0.0.1:8090/analysis`
- `http://127.0.0.1:8090/attacks`
- `http://127.0.0.1:8090/notifications`
- `http://127.0.0.1:8090/settings`

A legacy Dash dashboard is also available under:

- `http://127.0.0.1:8090/dash/`

---

## Tests / attack simulation

The repository includes scripts for injecting/validating behavior:

- `test_attacks.py`
- `zero_day_attacks.py`

Example usage (from comments in the repo):

```bash
sudo python test_attacks.py --target 172.20.10.2 --attack 3 --iface wlan0
sudo python test_attacks.py --target 172.20.10.2 --attack all --iface wlan0
python test_attacks.py --attack list
```

---

## Files you may edit

- `main.py`
  - Detection thresholds under the CONFIG section.
  - Whitelist settings.
  - Interface (`INTERFACE`).
- `templates/*`
  - UI text/layout.
- `auth.py`, `database.py`
  - Authentication rules, password policies, lockout behavior.

---

## Notes / limitations

- Packet capture is best-effort; some environments may drop traffic or prevent capturing depending on interface permissions.
- Detection heuristics are tuned for demonstration/testing. In real deployments, thresholds should be calibrated per environment.
- The optional ML pathway is guarded by `ML_ENABLED`; baseline-based zero-day detection works independently.
