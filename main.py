import threading
import time
import numpy as np
import pickle
from collections import defaultdict, deque
from datetime import datetime

from scapy.all import sniff, IP, TCP, UDP, ICMP

import dash
from dash import html, dcc, dash_table
from dash.dependencies import Input, Output
import plotly.graph_objs as go

# =============================
# CONFIG
# =============================
INTERFACE = "wlan0"       # CHANGE if needed
MAX_PACKETS = 500

DOS_PPS_THRESHOLD = 500
DDOS_SOURCE_THRESHOLD = 5
DDOS_TOTAL_PPS = 1500

FLOW_MIN_PACKETS = 10

LOG_FILE = "attack_logs.log"

# =============================
# GLOBAL STATE
# =============================
packet_list = []
packet_lock = threading.Lock()

paused = False
last_attack = None

flow_window = deque(maxlen=50)

# Rate tracking
udp_rate = defaultdict(deque)
tcp_rate = defaultdict(deque)
icmp_rate = defaultdict(deque)

dst_sources = defaultdict(set)

# Scan tracking
syn_ports = defaultdict(set)
udp_ports = defaultdict(set)
icmp_targets = defaultdict(set)

# =============================
# OPTIONAL ML
# =============================
ML_ENABLED = False
model = None
scaler = None
label_encoder = None

try:
    from tensorflow import keras
    from sklearn.preprocessing import StandardScaler

    model = keras.models.load_model("model/best_fnn_good_classes.h5")
    with open("model/fixed_label_encoders_good_classes.pkl", "rb") as f:
        label_encoder = pickle.load(f)[" Label"]

    scaler = StandardScaler()
    scaler.fit(np.random.randn(100, model.input_shape[1]))

    ML_ENABLED = True
    print("✅ ML ENABLED")

except Exception as e:
    print("⚠️ ML disabled:", e)

# =============================
# HELPERS
# =============================
def log_attack(atype, msg):
    global paused, last_attack
    paused = True
    last_attack = f"{atype} | {msg}"

    print(f"🚨 ATTACK DETECTED [{atype}] {msg}")

    with open(LOG_FILE, "a") as f:
        f.write(f"[{datetime.now()}] {atype} | {msg}\n")


def rate_update(rate_dict, key):
    now = time.time()
    rate_dict[key].append(now)
    while rate_dict[key] and now - rate_dict[key][0] > 1:
        rate_dict[key].popleft()
    return len(rate_dict[key])

# =============================
# PACKET CALLBACK
# =============================
def packet_callback(pkt):
    global paused

    if paused or IP not in pkt:
        return

    src = pkt[IP].src
    dst = pkt[IP].dst
    proto = "OTHER"
    dport = 0
    flags = ""

    if TCP in pkt:
        proto = "TCP"
        dport = pkt[TCP].dport
        if pkt[TCP].flags.S: flags += "SYN "
        if pkt[TCP].flags.A: flags += "ACK "
        if pkt[TCP].flags.F: flags += "FIN "

    elif UDP in pkt:
        proto = "UDP"
        dport = pkt[UDP].dport

    elif ICMP in pkt:
        proto = "ICMP"

    pkt_info = {
        "time": time.time(),
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "src": src,
        "dst": dst,
        "protocol": proto,
        "dport": dport,
        "length": len(pkt),
        "attack": ""
    }

    with packet_lock:
        packet_list.append(pkt_info)
        if len(packet_list) > MAX_PACKETS:
            packet_list.pop(0)

    # =============================
    # PORT SCANS
    # =============================
    if proto == "TCP" and "SYN" in flags:
        syn_ports[src].add(dport)
        if len(syn_ports[src]) >= 20:
            log_attack("PORT_SCAN", f"SRC={src} PORTS={len(syn_ports[src])}")

    if proto == "UDP":
        udp_ports[src].add(dport)
        if len(udp_ports[src]) >= 15:
            log_attack("UDP_SCAN", f"SRC={src} PORTS={len(udp_ports[src])}")

    if proto == "ICMP":
        icmp_targets[src].add(dst)
        if len(icmp_targets[src]) >= 5:
            log_attack("ICMP_SCAN", f"SRC={src} TARGETS={len(icmp_targets[src])}")

    # =============================
    # DoS / DDoS
    # =============================
    if proto == "UDP":
        pps = rate_update(udp_rate, src)
        dst_sources[dst].add(src)

        if pps > DOS_PPS_THRESHOLD:
            log_attack("DoS", f"UDP_FLOOD SRC={src} PPS={pps}")

        total_pps = sum(len(udp_rate[s]) for s in dst_sources[dst])
        if len(dst_sources[dst]) >= DDOS_SOURCE_THRESHOLD and total_pps > DDOS_TOTAL_PPS:
            log_attack("DDoS", f"UDP_DDoS DST={dst} SOURCES={len(dst_sources[dst])}")

    if proto == "TCP" and "SYN" in flags:
        pps = rate_update(tcp_rate, src)
        dst_sources[dst].add(src)

        if pps > DOS_PPS_THRESHOLD:
            log_attack("DoS", f"SYN_FLOOD SRC={src} PPS={pps}")

        total_pps = sum(len(tcp_rate[s]) for s in dst_sources[dst])
        if len(dst_sources[dst]) >= DDOS_SOURCE_THRESHOLD and total_pps > DDOS_TOTAL_PPS:
            log_attack("DDoS", f"SYN_DDoS DST={dst} SOURCES={len(dst_sources[dst])}")

# =============================
# SNIFFER THREAD
# =============================
def start_sniffer():
    print("📡 Sniffing on", INTERFACE)
    sniff(iface=INTERFACE, prn=packet_callback, store=False)

threading.Thread(target=start_sniffer, daemon=True).start()

# =============================
# DASH APP
# =============================
app = dash.Dash(__name__)
app.title = "Hybrid IDS"

app.layout = html.Div([
    html.H1("🛡 Hybrid IDS Dashboard", style={"textAlign": "center"}),

    html.Div(id="alert-box", style={"textAlign": "center", "padding": "15px"}),

    html.Button("▶ Resume Capture", id="resume-btn"),

    html.Div(id="stats"),

    dash_table.DataTable(
        id="table",
        columns=[
            {"name": "Time", "id": "timestamp"},
            {"name": "Source", "id": "src"},
            {"name": "Destination", "id": "dst"},
            {"name": "Proto", "id": "protocol"},
            {"name": "Len", "id": "length"},
        ],
        page_size=10,
        style_cell={"fontFamily": "monospace", "fontSize": 12}
    ),

    dcc.Interval(id="tick", interval=2000)
])

# =============================
# CALLBACKS
# =============================
@app.callback(
    [Output("table", "data"),
     Output("alert-box", "children"),
     Output("stats", "children")],
    Input("tick", "n_intervals")
)
def update_ui(n):
    with packet_lock:
        data = packet_list[-10:]

    alert = "✅ NORMAL"
    if paused:
        alert = html.Div(
            [html.H2("🚨 ATTACK DETECTED"), html.P(last_attack)],
            style={"background": "#ffcccc", "padding": "10px"}
        )

    stats = f"Packets captured: {len(packet_list)}"

    return data, alert, stats


@app.callback(
    Output("alert-box", "style"),
    Input("resume-btn", "n_clicks")
)
def resume(n):
    global paused
    if n:
        paused = False
    return {}

# =============================
# MAIN
# =============================
if __name__ == "__main__":
    print("🌐 Dashboard → http://127.0.0.1:8050")
    print("⚠️ Run with sudo")
    app.run(host="0.0.0.0", port=8050, debug=False)
