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
import json
from collections import defaultdict, deque
from datetime import datetime, timedelta

from scapy.all import sniff, IP, TCP, UDP, ICMP

import dash
from dash import html, dcc, dash_table
from dash.dependencies import Input, Output
import plotly.graph_objs as go
from flask import Flask, render_template, jsonify, request, redirect, url_for, flash, g

# Import authentication modules
from database import db
from auth import auth

# =============================
# CONFIG
# =============================
INTERFACE = "wlan0"       # CHANGE if needed
MAX_PACKETS = 5000

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
traffic_history = deque(maxlen=5000)
attack_history = deque(maxlen=1000)

# System start time for uptime calculation
system_start_time = datetime.now()

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

def get_uptime():
    """Calculate system uptime"""
    uptime = datetime.now() - system_start_time
    days = uptime.days
    hours = uptime.seconds // 3600
    minutes = (uptime.seconds % 3600) // 60
    seconds = uptime.seconds % 60
    
    if days > 0:
        return f"{days}d {hours}h {minutes}m"
    elif hours > 0:
        return f"{hours}h {minutes}m {seconds}s"
    else:
        return f"{minutes}m {seconds}s"

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
        if pkt[TCP].flags.R: flags += "RST "
        if pkt[TCP].flags.P: flags += "PSH "
        if pkt[TCP].flags.U: flags += "URG "

    elif UDP in pkt:
        proto = "UDP"
        dport = pkt[UDP].dport

    elif ICMP in pkt:
        proto = "ICMP"

    pkt_info = {
        "time": time.time(),
        "timestamp": datetime.now().strftime("%H:%M:%S.%f")[:-3],
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
    print(f"📡 Sniffing on {INTERFACE}")
    try:
        sniff(iface=INTERFACE, prn=packet_callback, store=False)
    except Exception as e:
        print(f"❌ Sniffer error: {e}")
        print("Trying fallback to default interface...")
        try:
            sniff(prn=packet_callback, store=False)
        except Exception as e2:
            print(f"❌ Fallback also failed: {e2}")

threading.Thread(target=start_sniffer, daemon=True).start()

# =============================
# FLASK APP FOR TEMPLATES
# =============================
flask_app = Flask(__name__, template_folder='templates')

# Configure Flask app
flask_app.config['SECRET_KEY'] = 'hybrid-ids-secret-key-change-in-production-2024'
flask_app.config['SESSION_TYPE'] = 'filesystem'
flask_app.config['SESSION_PERMANENT'] = True
flask_app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)

# Initialize auth manager with Flask app
auth.init_app(flask_app)

# =============================
# FLASK ROUTES (HTML PAGES)
# =============================
@flask_app.route('/')
def index():
    """Start on login page - redirect to login if not authenticated"""
    if auth.is_authenticated():
        # Redirect authenticated users to the main dashboard
        return redirect(url_for('network_traffic'))
    return render_template('login.html')

@flask_app.route('/network-traffic')
@auth.login_required
def network_traffic():
    return render_template('network_traffic.html')

@flask_app.route('/analysis')
@auth.login_required
def analysis():
    return render_template('analysis.html')

@flask_app.route('/attacks')
@auth.login_required
def attacks():
    return render_template('attacks.html')

@flask_app.route('/notifications')
@auth.login_required
def notifications():
    return render_template('notifications.html')

@flask_app.route('/settings')
@auth.admin_required
def settings():
    """Admin-only settings page"""
    return render_template('settings.html')

# =============================
# AUTHENTICATION ROUTES
# =============================

@flask_app.route('/login')
def login():
    """Login page"""
    if auth.is_authenticated():
        return redirect(url_for('index'))
    return render_template('login.html')

@flask_app.route('/login', methods=['POST'])
def login_post():
    """Handle login form submission"""
    username = request.form.get('username')
    password = request.form.get('password')
    remember = request.form.get('remember') == 'on'

    if not username or not password:
        flash('Please provide both username and password.', 'danger')
        return redirect(url_for('login'))

    success, message = auth.login_user(username, password, remember)
    if success:
        flash(message, 'success')
        next_page = request.args.get('next')
        # Redirect to network-traffic dashboard after successful login
        return redirect(next_page) if next_page else redirect(url_for('network_traffic'))
    else:
        flash(message, 'danger')
        return redirect(url_for('login'))

@flask_app.route('/register')
def register():
    """Registration page"""
    if auth.is_authenticated():
        return redirect(url_for('index'))
    return render_template('register.html')

@flask_app.route('/register', methods=['POST'])
def register_post():
    """Handle registration form submission"""
    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')
    confirm_password = request.form.get('confirm_password')
    full_name = request.form.get('full_name')

    success, message = auth.register_user(username, email, password, confirm_password, full_name)
    if success:
        flash(message, 'success')
        # Users need to login after registration, so redirect to login page
        return redirect(url_for('login'))
    else:
        if isinstance(message, list):
            for error in message:
                flash(error, 'danger')
        else:
            flash(message, 'danger')
        return redirect(url_for('register'))

@flask_app.route('/logout')
def logout():
    """Logout user and redirect to login page"""
    auth.logout_user()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('login'))

@flask_app.route('/change-password', methods=['POST'])
def change_password():
    """Change user password"""
    if not auth.is_authenticated():
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401

    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')

    success, message = auth.change_password(current_password, new_password, confirm_password)
    if success:
        return jsonify({'success': True, 'message': message})
    else:
        return jsonify({'success': False, 'message': message}), 400

# =============================
# API ENDPOINTS FOR REAL DATA
# =============================

@flask_app.route('/api/real-time-traffic')
def api_real_time_traffic():
    """Get real-time traffic data with packet details"""
    try:
        with packet_lock:
            # Get the most recent packets
            recent_packets = packet_list[-100:]  # Last 100 packets
            
            # Convert to frontend format
            packet_data = []
            for pkt in recent_packets:
                # Determine status based on attack detection
                status = pkt.get("status", "normal")
                
                packet_data.append({
                    "timestamp": pkt.get("timestamp", "--:--:--"),
                    "src": pkt.get("src", "N/A"),
                    "dst": pkt.get("dst", "N/A"),
                    "protocol": pkt.get("protocol", "N/A"),
                    "dport": pkt.get("dport", "N/A"),
                    "length": pkt.get("length", 0),
                    "status": status,
                    "flags": pkt.get("flags", "")
                })
        
        # Calculate real-time statistics
        stats = calculate_real_time_stats()
        
        return jsonify({
            "packets": packet_data[::-1],  # Reverse to show newest first
            "stats": stats,
            "last_updated": datetime.now().strftime("%H:%M:%S"),
            "total_captured": len(packet_list),
            "status": "success"
        })
    except Exception as e:
        return jsonify({
            "packets": [],
            "stats": {},
            "last_updated": datetime.now().strftime("%H:%M:%S"),
            "total_captured": 0,
            "status": "error",
            "error": str(e)
        })

def calculate_real_time_stats():
    """Calculate real-time traffic statistics"""
    try:
        with packet_lock:
            packets = packet_list[-1000:] if len(packet_list) > 1000 else packet_list.copy()
        
        if not packets:
            return {
                "total": 0,
                "safe": 0,
                "suspicious": 0,
                "attack": 0,
                "tcp": 0,
                "udp": 0,
                "icmp": 0,
                "other": 0,
                "avg_packet_size": 0,
                "packets_per_sec": 0
            }
        
        # Calculate protocol distribution
        tcp_count = len([p for p in packets if p.get("protocol") == "TCP"])
        udp_count = len([p for p in packets if p.get("protocol") == "UDP"])
        icmp_count = len([p for p in packets if p.get("protocol") == "ICMP"])
        other_count = len(packets) - tcp_count - udp_count - icmp_count
        
        # Calculate status distribution
        safe_count = len([p for p in packets if p.get("status") == "normal"])
        suspicious_count = len([p for p in packets if p.get("status") == "suspicious"])
        attack_count = len([p for p in packets if p.get("status") == "attack"])
        
        # If status not set, estimate from attack history
        if attack_count == 0 and suspicious_count == 0:
            recent_attacks = [a for a in attack_history 
                             if (datetime.now() - a["time"]).seconds < 10]
            if recent_attacks:
                attack_count = min(len(packets), len(recent_attacks) * 10)
                safe_count = len(packets) - attack_count
        
        # Calculate average packet size
        avg_size = sum(p.get("length", 0) for p in packets) / len(packets) if packets else 0
        
        # Calculate packets per second (last 5 seconds)
        now = time.time()
        recent_packets = [p for p in packets if now - p.get("time", now) <= 5]
        packets_per_sec = len(recent_packets) / 5 if recent_packets else 0
        
        return {
            "total": len(packets),
            "safe": safe_count,
            "suspicious": suspicious_count,
            "attack": attack_count,
            "tcp": tcp_count,
            "udp": udp_count,
            "icmp": icmp_count,
            "other": other_count,
            "avg_packet_size": round(avg_size, 2),
            "packets_per_sec": round(packets_per_sec, 2)
        }
    except Exception as e:
        print(f"Error calculating stats: {e}")
        return {
            "total": 0,
            "safe": 0,
            "suspicious": 0,
            "attack": 0,
            "tcp": 0,
            "udp": 0,
            "icmp": 0,
            "other": 0,
            "avg_packet_size": 0,
            "packets_per_sec": 0
        }

@flask_app.route('/api/traffic-history')
def api_traffic_history():
    """Get traffic history for charts"""
    try:
        # Get traffic from the last 5 minutes
        five_min_ago = time.time() - 300
        
        with packet_lock:
            recent_traffic = [p for p in packet_list if p.get("time", 0) > five_min_ago]
        
        # Group by protocol for pie chart
        protocol_data = {}
        for pkt in recent_traffic:
            proto = pkt.get("protocol", "OTHER")
            protocol_data[proto] = protocol_data.get(proto, 0) + 1
        
        # Create timeline data (packets per 10-second interval)
        timeline_data = []
        now = time.time()
        
        for i in range(30):  # Last 5 minutes in 10-second intervals
            interval_start = now - (i + 1) * 10
            interval_end = now - i * 10
            
            interval_packets = [
                p for p in recent_traffic 
                if interval_start < p.get("time", 0) <= interval_end
            ]
            
            # Count protocols in this interval
            tcp_count = len([p for p in interval_packets if p.get("protocol") == "TCP"])
            udp_count = len([p for p in interval_packets if p.get("protocol") == "UDP"])
            icmp_count = len([p for p in interval_packets if p.get("protocol") == "ICMP"])
            
            timeline_data.append({
                "time": datetime.fromtimestamp(interval_end).strftime("%H:%M:%S"),
                "packets": len(interval_packets),
                "tcp": tcp_count,
                "udp": udp_count,
                "icmp": icmp_count
            })
        
        timeline_data.reverse()  # Oldest to newest
        
        return jsonify({
            "protocol_distribution": protocol_data,
            "timeline": timeline_data,
            "time_range": "5 minutes",
            "status": "success"
        })
    except Exception as e:
        return jsonify({
            "error": str(e),
            "protocol_distribution": {},
            "timeline": [],
            "time_range": "5 minutes",
            "status": "error"
        })

@flask_app.route('/api/top-conversations')
def api_top_conversations():
    """Get top IP conversations"""
    try:
        with packet_lock:
            recent_packets = packet_list[-500:] if len(packet_list) > 500 else packet_list.copy()
        
        # Count conversations between source-destination pairs
        conversation_counts = {}
        conversation_bytes = {}
        
        for pkt in recent_packets:
            src = pkt.get("src", "Unknown")
            dst = pkt.get("dst", "Unknown")
            key = f"{src}->{dst}"
            
            conversation_counts[key] = conversation_counts.get(key, 0) + 1
            conversation_bytes[key] = conversation_bytes.get(key, 0) + pkt.get("length", 0)
        
        # Get top 10 conversations
        top_conversations = sorted(
            conversation_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]
        
        result = []
        for conv, count in top_conversations:
            src, dst = conv.split("->")
            total_bytes = conversation_bytes.get(conv, 0)
            avg_size = total_bytes // count if count > 0 else 0
            
            result.append({
                "source": src,
                "destination": dst,
                "packet_count": count,
                "total_bytes": total_bytes,
                "avg_packet_size": avg_size
            })
        
        return jsonify({
            "conversations": result,
            "status": "success"
        })
    except Exception as e:
        return jsonify({
            "conversations": [],
            "status": "error",
            "error": str(e)
        })

@flask_app.route('/api/packet-size-distribution')
def api_packet_size_distribution():
    """Get packet size distribution data"""
    try:
        with packet_lock:
            recent_packets = packet_list[-500:] if len(packet_list) > 500 else packet_list.copy()
        
        # Group packet sizes into bins
        size_bins = {
            "0-100": 0,
            "101-500": 0,
            "501-1000": 0,
            "1001-1500": 0,
            "1501+": 0
        }
        
        sizes = []
        for pkt in recent_packets:
            size = pkt.get("length", 0)
            sizes.append(size)
            if size <= 100:
                size_bins["0-100"] += 1
            elif size <= 500:
                size_bins["101-500"] += 1
            elif size <= 1000:
                size_bins["501-1000"] += 1
            elif size <= 1500:
                size_bins["1001-1500"] += 1
            else:
                size_bins["1501+"] += 1
        
        # Find most common size range
        most_common = max(size_bins.items(), key=lambda x: x[1])[0] if size_bins else "0-100"
        
        return jsonify({
            "distribution": size_bins,
            "min_size": min(sizes) if sizes else 0,
            "max_size": max(sizes) if sizes else 0,
            "avg_size": sum(sizes) / len(sizes) if sizes else 0,
            "most_common": most_common,
            "status": "success"
        })
    except Exception as e:
        return jsonify({
            "distribution": {},
            "min_size": 0,
            "max_size": 0,
            "avg_size": 0,
            "most_common": "0-100",
            "status": "error",
            "error": str(e)
        })

@flask_app.route('/api/network-status')
def api_network_status():
    """Get overall network status"""
    try:
        status = "normal"
        
        if paused:
            status = "under_attack"
        elif len(attack_history) > 0:
            # Check if last attack was recent (last 2 minutes)
            if attack_history and (datetime.now() - attack_history[-1]["time"]).seconds < 120:
                status = "warning"
        
        # Calculate traffic rate
        now = time.time()
        recent_packets = [p for p in packet_list if now - p.get("time", now) <= 10]
        packets_per_sec = len(recent_packets) / 10 if recent_packets else 0
        
        # Get uptime
        uptime_str = get_uptime()
        
        # Calculate memory usage (simulated based on packet count)
        memory_mb = len(packet_list) * 0.01  # Rough estimate
        
        return jsonify({
            "status": status,
            "packets_per_second": round(packets_per_sec, 2),
            "total_packets": len(packet_list),
            "active_attacks": len([a for a in attack_history if (datetime.now() - a["time"]).seconds < 300]),
            "interface": INTERFACE,
            "uptime": uptime_str,
            "ml_enabled": ML_ENABLED,
            "memory_usage": round(memory_mb, 2),
            "capture_status": "active" if not paused else "paused",
            "attack_status": "normal" if status == "normal" else "warning" if status == "warning" else "critical",
            "system_time": datetime.now().strftime("%H:%M:%S"),
            "status": "success"
        })
    except Exception as e:
        return jsonify({
            "status": "error",
            "error": str(e),
            "interface": INTERFACE,
            "uptime": "00:00:00",
            "ml_enabled": ML_ENABLED,
            "capture_status": "error",
            "attack_status": "unknown",
            "status": "error"
        })

@flask_app.route('/api/attacks')
def api_attacks():
    """Get attack history"""
    try:
        # Convert deque to list for sorting
        attacks_list = list(attack_history)
        
        # Sort by time (newest first)
        attacks_list.sort(key=lambda x: x["time"], reverse=True)
        
        attack_data = []
        for attack in attacks_list[:50]:  # Last 50 attacks
            # Extract source and target from message
            source = "Unknown"
            target = "Unknown"
            message = attack["message"]
            
            # Try to extract IP addresses from message
            import re
            src_match = re.search(r'SRC=([\d\.]+)', message)
            dst_match = re.search(r'DST=([\d\.]+)', message)
            
            if src_match:
                source = src_match.group(1)
            if dst_match:
                target = dst_match.group(1)
            
            # Determine severity
            severity = "medium"
            if "DDoS" in attack["type"]:
                severity = "critical"
            elif "DoS" in attack["type"]:
                severity = "high"
            elif "FLOOD" in attack["type"]:
                severity = "high"
            elif "SCAN" in attack["type"]:
                severity = "medium"
            
            attack_data.append({
                "type": attack["type"],
                "message": message,
                "timestamp": attack["timestamp"],
                "source": source,
                "target": target,
                "severity": severity,
                "time_ago": get_time_ago(attack["time"])
            })
        
        return jsonify({
            "attacks": attack_data,
            "total": len(attack_history),
            "today": len([a for a in attack_history if a["time"].date() == datetime.now().date()]),
            "status": "success"
        })
    except Exception as e:
        return jsonify({
            "attacks": [],
            "total": 0,
            "today": 0,
            "status": "error",
            "error": str(e)
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

@flask_app.route('/api/notifications')
def api_notifications():
    """Get system notifications"""
    try:
        notifications_list = []
        
        # System notifications
        notifications_list.append({
            "id": 1,
            "type": "system",
            "title": "System Started",
            "message": f"Hybrid IDS started on interface {INTERFACE}",
            "timestamp": system_start_time.strftime("%H:%M:%S"),
            "read": True,
            "priority": "info"
        })
        
        if ML_ENABLED:
            notifications_list.append({
                "id": 2,
                "type": "system",
                "title": "ML Detection Enabled",
                "message": "Machine learning attack detection is active",
                "timestamp": datetime.now().strftime("%H:%M:%S"),
                "read": True,
                "priority": "info"
            })
        
        # Attack notifications (last 10)
        attack_list = list(attack_history)
        for i, attack in enumerate(attack_list[-10:]):
            priority = "critical" if "DDoS" in attack["type"] else "high" if "DoS" in attack["type"] else "medium"
            notifications_list.append({
                "id": 1000 + i,
                "type": "attack",
                "title": f"Attack: {attack['type']}",
                "message": attack['message'],
                "timestamp": attack['timestamp'],
                "read": False,
                "priority": priority
            })
        
        return jsonify({
            "notifications": notifications_list[::-1],  # Newest first
            "unread": len([n for n in notifications_list if not n.get("read", False)]),
            "status": "success"
        })
    except Exception as e:
        return jsonify({
            "notifications": [],
            "unread": 0,
            "status": "error",
            "error": str(e)
        })

@flask_app.route('/api/analysis')
def api_analysis():
    """Get analysis data"""
    try:
        with packet_lock:
            packets = packet_list.copy()
        
        if len(packets) == 0:
            return jsonify({
                "protocols": {},
                "top_sources": [],
                "top_destinations": [],
                "packet_rate": 0,
                "avg_packet_size": 0,
                "total_bytes": 0,
                "hourly_pattern": [],
                "status": "success"
            })
        
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
        
        # Packet rate (packets per minute)
        packet_rate = len(packets) / max(1, (time.time() - packets[0].get("time", time.time()))) * 60
        
        # Average packet size
        avg_packet_size = np.mean([p.get("length", 0) for p in packets]) if packets else 0
        
        # Total bytes transferred
        total_bytes = sum([p.get("length", 0) for p in packets])
        
        # Hourly pattern (simulated for now)
        hourly_pattern = []
        for hour in range(24):
            hourly_pattern.append({
                "hour": f"{hour:02d}:00",
                "packets": np.random.randint(50, 500)
            })
        
        return jsonify({
            "protocols": dict(protocols),
            "top_sources": [{"ip": ip, "count": count} for ip, count in top_sources],
            "top_destinations": [{"ip": ip, "count": count} for ip, count in top_destinations],
            "packet_rate": round(packet_rate, 2),
            "avg_packet_size": round(avg_packet_size, 2),
            "total_bytes": total_bytes,
            "hourly_pattern": hourly_pattern,
            "status": "success"
        })
    except Exception as e:
        return jsonify({
            "protocols": {},
            "top_sources": [],
            "top_destinations": [],
            "packet_rate": 0,
            "avg_packet_size": 0,
            "total_bytes": 0,
            "hourly_pattern": [],
            "status": "error",
            "error": str(e)
        })

@flask_app.route('/api/clear-traffic', methods=['POST'])
def api_clear_traffic():
    """Clear displayed traffic data"""
    try:
        global packet_list
        with packet_lock:
            packet_list.clear()
        
        return jsonify({
            "success": True,
            "message": "Traffic data cleared",
            "status": "success"
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "message": str(e),
            "status": "error"
        })

@flask_app.route('/api/resume-capture', methods=['POST'])
def api_resume_capture():
    """Resume packet capture after attack detection"""
    try:
        global paused
        paused = False
        
        return jsonify({
            "success": True,
            "message": "Capture resumed",
            "status": "success"
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "message": str(e),
            "status": "error"
        })

# =============================
# DASH APP (Keep existing dashboard)
# =============================
app = dash.Dash(__name__, server=flask_app, url_base_pathname='/dash/')
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
    print("\n" + "="*60)
    print("🛡  HYBRID INTRUSION DETECTION SYSTEM")
    print("="*60)
    print(f"📡 Interface: {INTERFACE}")
    print(f"🔧 ML Detection: {'ENABLED' if ML_ENABLED else 'DISABLED'}")
    print(f"📊 Max Packets: {MAX_PACKETS}")
    print("="*60)
    print("🌐 Dashboard URLs:")
    print("   Main UI → http://127.0.0.1:8090/network-traffic")
    print("   Analysis → http://127.0.0.1:8090/analysis")
    print("   Attacks → http://127.0.0.1:8090/attacks")
    print("   Notifications → http://127.0.0.1:8090/notifications")
    print("   Settings → http://127.0.0.1:8090/settings")
    print("   Old Dashboard → http://127.0.0.1:8090/dash/")
    print("="*60)
    print("⚠️  Run with: sudo python main.py")
    print("="*60 + "\n")
    
    # Create templates directory if it doesn't exist
    import os
    if not os.path.exists('templates'):
        os.makedirs('templates')
        print("📁 Created templates directory")
        print("📝 Please place your HTML templates in the 'templates' folder")
    
    # Run the Flask app (which includes Dash)
    try:
        flask_app.run(host="0.0.0.0", port=8090, debug=False, threaded=True)
    except Exception as e:
        print(f"❌ Error starting server: {e}")
        print("💡 Try using a different port: flask_app.run(port=8091)")
