# import threading
# import time
# import numpy as np
# import pickle
# from collections import defaultdict, deque
# from datetime import datetime

# from scapy.all import sniff, IP, TCP, UDP, ICMP

# import dash
# from dash import html, dcc, dash_table
# from dash.dependencies import Input, Output
# import plotly.graph_objs as go

# # =============================
# # CONFIG
# # =============================
# INTERFACE = "wlan0"       # CHANGE if needed
# MAX_PACKETS = 500

# DOS_PPS_THRESHOLD = 500
# DDOS_SOURCE_THRESHOLD = 5
# DDOS_TOTAL_PPS = 1500

# FLOW_MIN_PACKETS = 10

# LOG_FILE = "attack_logs.log"

# # =============================
# # GLOBAL STATE
# # =============================
# packet_list = []
# packet_lock = threading.Lock()

# paused = False
# last_attack = None

# flow_window = deque(maxlen=50)

# # Rate tracking
# udp_rate = defaultdict(deque)
# tcp_rate = defaultdict(deque)
# icmp_rate = defaultdict(deque)

# dst_sources = defaultdict(set)

# # Scan tracking
# syn_ports = defaultdict(set)
# udp_ports = defaultdict(set)
# icmp_targets = defaultdict(set)

# # =============================
# # OPTIONAL ML
# # =============================
# ML_ENABLED = False
# model = None
# scaler = None
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
#     print("✅ ML ENABLED")

# except Exception as e:
#     print("⚠️ ML disabled:", e)

# # =============================
# # HELPERS
# # =============================
# def log_attack(atype, msg):
#     global paused, last_attack
#     paused = True
#     last_attack = f"{atype} | {msg}"

#     print(f"🚨 ATTACK DETECTED [{atype}] {msg}")

#     with open(LOG_FILE, "a") as f:
#         f.write(f"[{datetime.now()}] {atype} | {msg}\n")


# def rate_update(rate_dict, key):
#     now = time.time()
#     rate_dict[key].append(now)
#     while rate_dict[key] and now - rate_dict[key][0] > 1:
#         rate_dict[key].popleft()
#     return len(rate_dict[key])

# # =============================
# # PACKET CALLBACK
# # =============================
# def packet_callback(pkt):
#     global paused

#     if paused or IP not in pkt:
#         return

#     src = pkt[IP].src
#     dst = pkt[IP].dst
#     proto = "OTHER"
#     dport = 0
#     flags = ""

#     if TCP in pkt:
#         proto = "TCP"
#         dport = pkt[TCP].dport
#         if pkt[TCP].flags.S: flags += "SYN "
#         if pkt[TCP].flags.A: flags += "ACK "
#         if pkt[TCP].flags.F: flags += "FIN "

#     elif UDP in pkt:
#         proto = "UDP"
#         dport = pkt[UDP].dport

#     elif ICMP in pkt:
#         proto = "ICMP"

#     pkt_info = {
#         "time": time.time(),
#         "timestamp": datetime.now().strftime("%H:%M:%S"),
#         "src": src,
#         "dst": dst,
#         "protocol": proto,
#         "dport": dport,
#         "length": len(pkt),
#         "attack": ""
#     }

#     with packet_lock:
#         packet_list.append(pkt_info)
#         if len(packet_list) > MAX_PACKETS:
#             packet_list.pop(0)

#     # =============================
#     # PORT SCANS
#     # =============================
#     if proto == "TCP" and "SYN" in flags:
#         syn_ports[src].add(dport)
#         if len(syn_ports[src]) >= 20:
#             log_attack("PORT_SCAN", f"SRC={src} PORTS={len(syn_ports[src])}")

#     if proto == "UDP":
#         udp_ports[src].add(dport)
#         if len(udp_ports[src]) >= 15:
#             log_attack("UDP_SCAN", f"SRC={src} PORTS={len(udp_ports[src])}")

#     if proto == "ICMP":
#         icmp_targets[src].add(dst)
#         if len(icmp_targets[src]) >= 5:
#             log_attack("ICMP_SCAN", f"SRC={src} TARGETS={len(icmp_targets[src])}")

#     # =============================
#     # DoS / DDoS
#     # =============================
#     if proto == "UDP":
#         pps = rate_update(udp_rate, src)
#         dst_sources[dst].add(src)

#         if pps > DOS_PPS_THRESHOLD:
#             log_attack("DoS", f"UDP_FLOOD SRC={src} PPS={pps}")

#         total_pps = sum(len(udp_rate[s]) for s in dst_sources[dst])
#         if len(dst_sources[dst]) >= DDOS_SOURCE_THRESHOLD and total_pps > DDOS_TOTAL_PPS:
#             log_attack("DDoS", f"UDP_DDoS DST={dst} SOURCES={len(dst_sources[dst])}")

#     if proto == "TCP" and "SYN" in flags:
#         pps = rate_update(tcp_rate, src)
#         dst_sources[dst].add(src)

#         if pps > DOS_PPS_THRESHOLD:
#             log_attack("DoS", f"SYN_FLOOD SRC={src} PPS={pps}")

#         total_pps = sum(len(tcp_rate[s]) for s in dst_sources[dst])
#         if len(dst_sources[dst]) >= DDOS_SOURCE_THRESHOLD and total_pps > DDOS_TOTAL_PPS:
#             log_attack("DDoS", f"SYN_DDoS DST={dst} SOURCES={len(dst_sources[dst])}")

# # =============================
# # SNIFFER THREAD
# # =============================
# def start_sniffer():
#     print("📡 Sniffing on", INTERFACE)
#     sniff(iface=INTERFACE, prn=packet_callback, store=False)

# threading.Thread(target=start_sniffer, daemon=True).start()

# # =============================
# # DASH APP
# # =============================
# app = dash.Dash(__name__)
# app.title = "Hybrid IDS"

# app.layout = html.Div([
#     html.H1("🛡 Hybrid IDS Dashboard", style={"textAlign": "center"}),

#     html.Div(id="alert-box", style={"textAlign": "center", "padding": "15px"}),

#     html.Button("▶ Resume Capture", id="resume-btn"),

#     html.Div(id="stats"),

#     dash_table.DataTable(
#         id="table",
#         columns=[
#             {"name": "Time", "id": "timestamp"},
#             {"name": "Source", "id": "src"},
#             {"name": "Destination", "id": "dst"},
#             {"name": "Proto", "id": "protocol"},
#             {"name": "Len", "id": "length"},
#         ],
#         page_size=10,
#         style_cell={"fontFamily": "monospace", "fontSize": 12}
#     ),

#     dcc.Interval(id="tick", interval=2000)
# ])

# # =============================
# # CALLBACKS
# # =============================
# @app.callback(
#     [Output("table", "data"),
#      Output("alert-box", "children"),
#      Output("stats", "children")],
#     Input("tick", "n_intervals")
# )
# def update_ui(n):
#     with packet_lock:
#         data = packet_list[-10:]

#     alert = "✅ NORMAL"
#     if paused:
#         alert = html.Div(
#             [html.H2("🚨 ATTACK DETECTED"), html.P(last_attack)],
#             style={"background": "#ffcccc", "padding": "10px"}
#         )

#     stats = f"Packets captured: {len(packet_list)}"

#     return data, alert, stats


# @app.callback(
#     Output("alert-box", "style"),
#     Input("resume-btn", "n_clicks")
# )
# def resume(n):
#     global paused
#     if n:
#         paused = False
#     return {}

# # =============================
# # MAIN
# # =============================
# if __name__ == "__main__":
#     print("🌐 Dashboard → http://127.0.0.1:8050")
#     print("⚠️ Run with sudo")
#     app.run(host="0.0.0.0", port=8050, debug=False)





import threading
import time
import numpy as np
import pickle
from collections import defaultdict, deque
from datetime import datetime, timedelta

from scapy.all import sniff, IP, TCP, UDP, ICMP

import dash
from dash import html, dcc, dash_table
from dash.dependencies import Input, Output
import plotly.graph_objs as go
from flask import Flask, render_template, jsonify, request  # Added Flask imports

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

# For traffic analysis
traffic_history = deque(maxlen=1000)
attack_history = []

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
    
    attack_entry = {
        "type": atype,
        "message": msg,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "time": datetime.now()
    }
    attack_history.append(attack_entry)
    
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
    attack_status = "normal"

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
        "full_timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "src": src,
        "dst": dst,
        "protocol": proto,
        "dport": dport,
        "length": len(pkt),
        "attack": "",
        "status": attack_status,
        "flags": flags.strip()
    }

    # Store in traffic history
    traffic_history.append({
        **pkt_info,
        "attack": ""
    })

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
            attack_status = "attack"

    if proto == "UDP":
        udp_ports[src].add(dport)
        if len(udp_ports[src]) >= 15:
            log_attack("UDP_SCAN", f"SRC={src} PORTS={len(udp_ports[src])}")
            attack_status = "attack"

    if proto == "ICMP":
        icmp_targets[src].add(dst)
        if len(icmp_targets[src]) >= 5:
            log_attack("ICMP_SCAN", f"SRC={src} TARGETS={len(icmp_targets[src])}")
            attack_status = "attack"

    # =============================
    # DoS / DDoS
    # =============================
    if proto == "UDP":
        pps = rate_update(udp_rate, src)
        dst_sources[dst].add(src)

        if pps > DOS_PPS_THRESHOLD:
            log_attack("DoS", f"UDP_FLOOD SRC={src} PPS={pps}")
            attack_status = "attack"
        elif pps > DOS_PPS_THRESHOLD * 0.7:
            attack_status = "suspicious"

        total_pps = sum(len(udp_rate[s]) for s in dst_sources[dst])
        if len(dst_sources[dst]) >= DDOS_SOURCE_THRESHOLD and total_pps > DDOS_TOTAL_PPS:
            log_attack("DDoS", f"UDP_DDoS DST={dst} SOURCES={len(dst_sources[dst])}")
            attack_status = "attack"

    if proto == "TCP" and "SYN" in flags:
        pps = rate_update(tcp_rate, src)
        dst_sources[dst].add(src)

        if pps > DOS_PPS_THRESHOLD:
            log_attack("DoS", f"SYN_FLOOD SRC={src} PPS={pps}")
            attack_status = "attack"
        elif pps > DOS_PPS_THRESHOLD * 0.7:
            attack_status = "suspicious"

        total_pps = sum(len(tcp_rate[s]) for s in dst_sources[dst])
        if len(dst_sources[dst]) >= DDOS_SOURCE_THRESHOLD and total_pps > DDOS_TOTAL_PPS:
            log_attack("DDoS", f"SYN_DDoS DST={dst} SOURCES={len(dst_sources[dst])}")
            attack_status = "attack"

    # Update packet status
    pkt_info["status"] = attack_status
    if traffic_history:
        traffic_history[-1]["status"] = attack_status

# =============================
# SNIFFER THREAD
# =============================
def start_sniffer():
    print("📡 Sniffing on", INTERFACE)
    sniff(iface=INTERFACE, prn=packet_callback, store=False)

threading.Thread(target=start_sniffer, daemon=True).start()

# =============================
# FLASK APP FOR TEMPLATES
# =============================
flask_app = Flask(__name__, template_folder='templates')

# =============================
# FLASK ROUTES
# =============================
@flask_app.route('/')
def index():
    return render_template('base.html')

@flask_app.route('/network-traffic')
def network_traffic():
    return render_template('network_traffic.html')

@flask_app.route('/analysis')
def analysis():
    return render_template('analysis.html')

@flask_app.route('/attacks')
def attacks():
    return render_template('attacks.html')

@flask_app.route('/notifications')
def notifications():
    return render_template('notifications.html')

@flask_app.route('/settings')
def settings():
    return render_template('settings.html')

# =============================
# API ENDPOINTS
# =============================
@flask_app.route('/api/status')
def api_status():
    status = "active"
    if paused:
        status = "danger"
    elif len(attack_history) > 0:
        # Check if last attack was recent (last 5 minutes)
        if attack_history and (datetime.now() - attack_history[-1]["time"]).seconds < 300:
            status = "warning"
    
    return jsonify({
        "status": status,
        "packets_captured": len(packet_list),
        "active_attacks": len([a for a in attack_history if (datetime.now() - a["time"]).seconds < 300]),
        "interface": INTERFACE,
        "ml_enabled": ML_ENABLED
    })

@flask_app.route('/api/traffic')
def api_traffic():
    with packet_lock:
        packets = packet_list.copy()
    
    # Calculate statistics
    stats = {
        "total": len(packets),
        "safe": len([p for p in packets if p.get("status") == "normal"]),
        "suspicious": len([p for p in packets if p.get("status") == "suspicious"]),
        "attack": len([p for p in packets if p.get("status") == "attack"]),
        "tcp": len([p for p in packets if p.get("protocol") == "TCP"]),
        "udp": len([p for p in packets if p.get("protocol") == "UDP"]),
        "icmp": len([p for p in packets if p.get("protocol") == "ICMP"])
    }
    
    # Prepare packet data for frontend
    packet_data = []
    for pkt in packets[-100:]:  # Last 100 packets
        packet_data.append({
            "timestamp": pkt.get("timestamp", "--:--:--"),
            "src": pkt.get("src", "N/A"),
            "dst": pkt.get("dst", "N/A"),
            "protocol": pkt.get("protocol", "N/A"),
            "dport": pkt.get("dport", "N/A"),
            "length": pkt.get("length", 0),
            "status": pkt.get("status", "normal")
        })
    
    return jsonify({
        "packets": packet_data[::-1],  # Reverse to show newest first
        "stats": stats,
        "last_updated": datetime.now().strftime("%H:%M:%S")
    })

@flask_app.route('/api/attacks')
def api_attacks():
    # Sort attacks by time (newest first)
    sorted_attacks = sorted(attack_history, key=lambda x: x["time"], reverse=True)
    
    attack_data = []
    for attack in sorted_attacks[:50]:  # Last 50 attacks
        attack_data.append({
            "type": attack["type"],
            "message": attack["message"],
            "timestamp": attack["timestamp"],
            "time_ago": get_time_ago(attack["time"])
        })
    
    return jsonify({
        "attacks": attack_data,
        "total": len(attack_history),
        "today": len([a for a in attack_history if a["time"].date() == datetime.now().date()])
    })

@flask_app.route('/api/analysis')
def api_analysis():
    with packet_lock:
        packets = packet_list.copy()
    
    # Calculate analysis data
    now = datetime.now()
    hour_ago = now - timedelta(hours=1)
    
    # Protocol distribution
    protocols = defaultdict(int)
    for pkt in packets:
        protocols[pkt.get("protocol", "OTHER")] += 1
    
    # Top sources
    sources = defaultdict(int)
    for pkt in packets:
        sources[pkt.get("src")] += 1
    top_sources = sorted(sources.items(), key=lambda x: x[1], reverse=True)[:10]
    
    # Top destinations
    destinations = defaultdict(int)
    for pkt in packets:
        destinations[pkt.get("dst")] += 1
    top_destinations = sorted(destinations.items(), key=lambda x: x[1], reverse=True)[:10]
    
    return jsonify({
        "protocols": dict(protocols),
        "top_sources": [{"ip": ip, "count": count} for ip, count in top_sources],
        "top_destinations": [{"ip": ip, "count": count} for ip, count in top_destinations],
        "packet_rate": len(packets) / 60 if len(packets) > 0 else 0,  # packets per minute
        "avg_packet_size": np.mean([p.get("length", 0) for p in packets]) if packets else 0
    })

@flask_app.route('/api/clear-traffic', methods=['POST'])
def api_clear_traffic():
    global packet_list, traffic_history
    with packet_lock:
        packet_list.clear()
        traffic_history.clear()
    return jsonify({"success": True, "message": "Traffic data cleared"})

@flask_app.route('/api/notifications')
def api_notifications():
    notifications_list = []
    
    # System notifications
    notifications_list.append({
        "id": 1,
        "type": "system",
        "title": "System Started",
        "message": f"IDS started on interface {INTERFACE}",
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "read": True
    })
    
    if ML_ENABLED:
        notifications_list.append({
            "id": 2,
            "type": "system",
            "title": "ML Enabled",
            "message": "Machine learning detection is active",
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "read": True
        })
    
    # Attack notifications (last 10)
    for i, attack in enumerate(attack_history[-10:]):
        notifications_list.append({
            "id": 1000 + i,
            "type": "attack",
            "title": f"Attack: {attack['type']}",
            "message": attack['message'],
            "timestamp": attack['timestamp'],
            "read": False
        })
    
    return jsonify({
        "notifications": notifications_list[::-1],  # Newest first
        "unread": len([n for n in notifications_list if not n.get("read", False)])
    })

def get_time_ago(dt):
    """Helper to format time ago"""
    now = datetime.now()
    diff = now - dt
    
    if diff.days > 0:
        return f"{diff.days} day{'s' if diff.days > 1 else ''} ago"
    elif diff.seconds > 3600:
        hours = diff.seconds // 3600
        return f"{hours} hour{'s' if hours > 1 else ''} ago"
    elif diff.seconds > 60:
        minutes = diff.seconds // 60
        return f"{minutes} minute{'s' if minutes > 1 else ''} ago"
    else:
        return "Just now"

# =============================
# DASH APP (Keep existing dashboard)
# =============================
app = dash.Dash(__name__, server=flask_app, url_base_pathname='/dash/')  # Mount Dash under /dash/
app.title = "Hybrid IDS - Real-time"

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
# DASH CALLBACKS (Keep existing)
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
    print("🌐 Main Dashboard → http://127.0.0.1:8050")
    print("🌐 New UI → http://127.0.0.1:8050/network-traffic")
    print("📊 Old Dashboard → http://127.0.0.1:8050/dash/")
    print("⚠️ Run with sudo")
    
    # Create templates directory if it doesn't exist
    import os
    if not os.path.exists('templates'):
        os.makedirs('templates')
        print("📁 Created templates directory")
    
    # Run the Flask app (which includes Dash)
    flask_app.run(host="0.0.0.0", port=8050, debug=False)
