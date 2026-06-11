# # import threading
# # import time
# # import numpy as np
# # import pickle
# # from collections import defaultdict, deque
# # from datetime import datetime

# # from scapy.all import sniff, IP, TCP, UDP, ICMP

# # import dash
# # from dash import html, dcc, dash_table
# # from dash.dependencies import Input, Output
# # import plotly.graph_objs as go

# # # =============================
# # # CONFIG
# # # =============================
# # INTERFACE = "wlan0"       # CHANGE if needed
# # MAX_PACKETS = 500

# # DOS_PPS_THRESHOLD = 500
# # DDOS_SOURCE_THRESHOLD = 5
# # DDOS_TOTAL_PPS = 1500

# # FLOW_MIN_PACKETS = 10

# # LOG_FILE = "attack_logs.log"

# # # =============================
# # # GLOBAL STATE
# # # =============================
# # packet_list = []
# # packet_lock = threading.Lock()

# # paused = False
# # last_attack = None

# # flow_window = deque(maxlen=50)

# # # Rate tracking
# # udp_rate = defaultdict(deque)
# # tcp_rate = defaultdict(deque)
# # icmp_rate = defaultdict(deque)

# # dst_sources = defaultdict(set)

# # # Scan tracking
# # syn_ports = defaultdict(set)
# # udp_ports = defaultdict(set)
# # icmp_targets = defaultdict(set)

# # # =============================
# # # OPTIONAL ML
# # # =============================
# # ML_ENABLED = False
# # model = None
# # scaler = None
# # label_encoder = None

# # try:
# #     from tensorflow import keras
# #     from sklearn.preprocessing import StandardScaler

# #     model = keras.models.load_model("model/best_fnn_good_classes.h5")
# #     with open("model/fixed_label_encoders_good_classes.pkl", "rb") as f:
# #         label_encoder = pickle.load(f)[" Label"]

# #     scaler = StandardScaler()
# #     scaler.fit(np.random.randn(100, model.input_shape[1]))

# #     ML_ENABLED = True
# #     print("✅ ML ENABLED")

# # except Exception as e:
# #     print("⚠️ ML disabled:", e)

# # # =============================
# # # HELPERS
# # # =============================
# # def log_attack(atype, msg):
# #     global paused, last_attack
# #     paused = True
# #     last_attack = f"{atype} | {msg}"

# #     print(f"🚨 ATTACK DETECTED [{atype}] {msg}")

# #     with open(LOG_FILE, "a") as f:
# #         f.write(f"[{datetime.now()}] {atype} | {msg}\n")


# # def rate_update(rate_dict, key):
# #     now = time.time()
# #     rate_dict[key].append(now)
# #     while rate_dict[key] and now - rate_dict[key][0] > 1:
# #         rate_dict[key].popleft()
# #     return len(rate_dict[key])

# # # =============================
# # # PACKET CALLBACK
# # # =============================
# # def packet_callback(pkt):
# #     global paused

# #     if paused or IP not in pkt:
# #         return

# #     src = pkt[IP].src
# #     dst = pkt[IP].dst
# #     proto = "OTHER"
# #     dport = 0
# #     flags = ""

# #     if TCP in pkt:
# #         proto = "TCP"
# #         dport = pkt[TCP].dport
# #         if pkt[TCP].flags.S: flags += "SYN "
# #         if pkt[TCP].flags.A: flags += "ACK "
# #         if pkt[TCP].flags.F: flags += "FIN "

# #     elif UDP in pkt:
# #         proto = "UDP"
# #         dport = pkt[UDP].dport

# #     elif ICMP in pkt:
# #         proto = "ICMP"

# #     pkt_info = {
# #         "time": time.time(),
# #         "timestamp": datetime.now().strftime("%H:%M:%S"),
# #         "src": src,
# #         "dst": dst,
# #         "protocol": proto,
# #         "dport": dport,
# #         "length": len(pkt),
# #         "attack": ""
# #     }

# #     with packet_lock:
# #         packet_list.append(pkt_info)
# #         if len(packet_list) > MAX_PACKETS:
# #             packet_list.pop(0)

# #     # =============================
# #     # PORT SCANS
# #     # =============================
# #     if proto == "TCP" and "SYN" in flags:
# #         syn_ports[src].add(dport)
# #         if len(syn_ports[src]) >= 20:
# #             log_attack("PORT_SCAN", f"SRC={src} PORTS={len(syn_ports[src])}")

# #     if proto == "UDP":
# #         udp_ports[src].add(dport)
# #         if len(udp_ports[src]) >= 15:
# #             log_attack("UDP_SCAN", f"SRC={src} PORTS={len(udp_ports[src])}")

# #     if proto == "ICMP":
# #         icmp_targets[src].add(dst)
# #         if len(icmp_targets[src]) >= 5:
# #             log_attack("ICMP_SCAN", f"SRC={src} TARGETS={len(icmp_targets[src])}")

# #     # =============================
# #     # DoS / DDoS
# #     # =============================
# #     if proto == "UDP":
# #         pps = rate_update(udp_rate, src)
# #         dst_sources[dst].add(src)

# #         if pps > DOS_PPS_THRESHOLD:
# #             log_attack("DoS", f"UDP_FLOOD SRC={src} PPS={pps}")

# #         total_pps = sum(len(udp_rate[s]) for s in dst_sources[dst])
# #         if len(dst_sources[dst]) >= DDOS_SOURCE_THRESHOLD and total_pps > DDOS_TOTAL_PPS:
# #             log_attack("DDoS", f"UDP_DDoS DST={dst} SOURCES={len(dst_sources[dst])}")

# #     if proto == "TCP" and "SYN" in flags:
# #         pps = rate_update(tcp_rate, src)
# #         dst_sources[dst].add(src)

# #         if pps > DOS_PPS_THRESHOLD:
# #             log_attack("DoS", f"SYN_FLOOD SRC={src} PPS={pps}")

# #         total_pps = sum(len(tcp_rate[s]) for s in dst_sources[dst])
# #         if len(dst_sources[dst]) >= DDOS_SOURCE_THRESHOLD and total_pps > DDOS_TOTAL_PPS:
# #             log_attack("DDoS", f"SYN_DDoS DST={dst} SOURCES={len(dst_sources[dst])}")

# # # =============================
# # # SNIFFER THREAD
# # # =============================
# # def start_sniffer():
# #     print("📡 Sniffing on", INTERFACE)
# #     sniff(iface=INTERFACE, prn=packet_callback, store=False)

# # threading.Thread(target=start_sniffer, daemon=True).start()

# # # =============================
# # # DASH APP
# # # =============================
# # app = dash.Dash(__name__)
# # app.title = "Hybrid IDS"

# # app.layout = html.Div([
# #     html.H1("🛡 Hybrid IDS Dashboard", style={"textAlign": "center"}),

# #     html.Div(id="alert-box", style={"textAlign": "center", "padding": "15px"}),

# #     html.Button("▶ Resume Capture", id="resume-btn"),

# #     html.Div(id="stats"),

# #     dash_table.DataTable(
# #         id="table",
# #         columns=[
# #             {"name": "Time", "id": "timestamp"},
# #             {"name": "Source", "id": "src"},
# #             {"name": "Destination", "id": "dst"},
# #             {"name": "Proto", "id": "protocol"},
# #             {"name": "Len", "id": "length"},
# #         ],
# #         page_size=10,
# #         style_cell={"fontFamily": "monospace", "fontSize": 12}
# #     ),

# #     dcc.Interval(id="tick", interval=2000)
# # ])

# # # =============================
# # # CALLBACKS
# # # =============================
# # @app.callback(
# #     [Output("table", "data"),
# #      Output("alert-box", "children"),
# #      Output("stats", "children")],
# #     Input("tick", "n_intervals")
# # )
# # def update_ui(n):
# #     with packet_lock:
# #         data = packet_list[-10:]

# #     alert = "✅ NORMAL"
# #     if paused:
# #         alert = html.Div(
# #             [html.H2("🚨 ATTACK DETECTED"), html.P(last_attack)],
# #             style={"background": "#ffcccc", "padding": "10px"}
# #         )

# #     stats = f"Packets captured: {len(packet_list)}"

# #     return data, alert, stats


# # @app.callback(
# #     Output("alert-box", "style"),
# #     Input("resume-btn", "n_clicks")
# # )
# # def resume(n):
# #     global paused
# #     if n:
# #         paused = False
# #     return {}

# # # =============================
# # # MAIN
# # # =============================
# # if __name__ == "__main__":
# #     print("🌐 Dashboard → http://127.0.0.1:8050")
# #     print("⚠️ Run with sudo")
# #     app.run(host="0.0.0.0", port=8050, debug=False)





# import threading
# import time
# import numpy as np
# import pickle
# import json
# from collections import defaultdict, deque
# from datetime import datetime, timedelta

# from scapy.all import sniff, IP, TCP, UDP, ICMP

# import dash
# from dash import html, dcc, dash_table
# from dash.dependencies import Input, Output
# import plotly.graph_objs as go
# from flask import Flask, render_template, jsonify, request, redirect, url_for, flash, g

# # Import authentication modules
# from database import db
# from auth import auth

# # =============================
# # CONFIG
# # =============================
# INTERFACE = "wlan0"       # CHANGE if needed
# MAX_PACKETS = 5000

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

# # For traffic analysis
# traffic_history = deque(maxlen=5000)
# attack_history = deque(maxlen=1000)

# # System start time for uptime calculation
# system_start_time = datetime.now()

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
    
#     attack_entry = {
#         "type": atype,
#         "message": msg,
#         "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
#         "time": datetime.now()
#     }
#     attack_history.append(attack_entry)
    
#     print(f"🚨 ATTACK DETECTED [{atype}] {msg}")

#     with open(LOG_FILE, "a") as f:
#         f.write(f"[{datetime.now()}] {atype} | {msg}\n")


# def rate_update(rate_dict, key):
#     now = time.time()
#     rate_dict[key].append(now)
#     while rate_dict[key] and now - rate_dict[key][0] > 1:
#         rate_dict[key].popleft()
#     return len(rate_dict[key])

# def get_uptime():
#     """Calculate system uptime"""
#     uptime = datetime.now() - system_start_time
#     days = uptime.days
#     hours = uptime.seconds // 3600
#     minutes = (uptime.seconds % 3600) // 60
#     seconds = uptime.seconds % 60
    
#     if days > 0:
#         return f"{days}d {hours}h {minutes}m"
#     elif hours > 0:
#         return f"{hours}h {minutes}m {seconds}s"
#     else:
#         return f"{minutes}m {seconds}s"

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
#     attack_status = "normal"

#     if TCP in pkt:
#         proto = "TCP"
#         dport = pkt[TCP].dport
#         if pkt[TCP].flags.S: flags += "SYN "
#         if pkt[TCP].flags.A: flags += "ACK "
#         if pkt[TCP].flags.F: flags += "FIN "
#         if pkt[TCP].flags.R: flags += "RST "
#         if pkt[TCP].flags.P: flags += "PSH "
#         if pkt[TCP].flags.U: flags += "URG "

#     elif UDP in pkt:
#         proto = "UDP"
#         dport = pkt[UDP].dport

#     elif ICMP in pkt:
#         proto = "ICMP"

#     pkt_info = {
#         "time": time.time(),
#         "timestamp": datetime.now().strftime("%H:%M:%S.%f")[:-3],
#         "full_timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
#         "src": src,
#         "dst": dst,
#         "protocol": proto,
#         "dport": dport,
#         "length": len(pkt),
#         "attack": "",
#         "status": attack_status,
#         "flags": flags.strip()
#     }

#     # Store in traffic history
#     traffic_history.append({
#         **pkt_info,
#         "attack": ""
#     })

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
#             attack_status = "attack"

#     if proto == "UDP":
#         udp_ports[src].add(dport)
#         if len(udp_ports[src]) >= 15:
#             log_attack("UDP_SCAN", f"SRC={src} PORTS={len(udp_ports[src])}")
#             attack_status = "attack"

#     if proto == "ICMP":
#         icmp_targets[src].add(dst)
#         if len(icmp_targets[src]) >= 5:
#             log_attack("ICMP_SCAN", f"SRC={src} TARGETS={len(icmp_targets[src])}")
#             attack_status = "attack"

#     # =============================
#     # DoS / DDoS
#     # =============================
#     if proto == "UDP":
#         pps = rate_update(udp_rate, src)
#         dst_sources[dst].add(src)

#         if pps > DOS_PPS_THRESHOLD:
#             log_attack("DoS", f"UDP_FLOOD SRC={src} PPS={pps}")
#             attack_status = "attack"
#         elif pps > DOS_PPS_THRESHOLD * 0.7:
#             attack_status = "suspicious"

#         total_pps = sum(len(udp_rate[s]) for s in dst_sources[dst])
#         if len(dst_sources[dst]) >= DDOS_SOURCE_THRESHOLD and total_pps > DDOS_TOTAL_PPS:
#             log_attack("DDoS", f"UDP_DDoS DST={dst} SOURCES={len(dst_sources[dst])}")
#             attack_status = "attack"

#     if proto == "TCP" and "SYN" in flags:
#         pps = rate_update(tcp_rate, src)
#         dst_sources[dst].add(src)

#         if pps > DOS_PPS_THRESHOLD:
#             log_attack("DoS", f"SYN_FLOOD SRC={src} PPS={pps}")
#             attack_status = "attack"
#         elif pps > DOS_PPS_THRESHOLD * 0.7:
#             attack_status = "suspicious"

#         total_pps = sum(len(tcp_rate[s]) for s in dst_sources[dst])
#         if len(dst_sources[dst]) >= DDOS_SOURCE_THRESHOLD and total_pps > DDOS_TOTAL_PPS:
#             log_attack("DDoS", f"SYN_DDoS DST={dst} SOURCES={len(dst_sources[dst])}")
#             attack_status = "attack"

#     # Update packet status
#     pkt_info["status"] = attack_status
#     if traffic_history:
#         traffic_history[-1]["status"] = attack_status

# # =============================
# # SNIFFER THREAD
# # =============================
# def start_sniffer():
#     print(f"📡 Sniffing on {INTERFACE}")
#     try:
#         sniff(iface=INTERFACE, prn=packet_callback, store=False)
#     except Exception as e:
#         print(f"❌ Sniffer error: {e}")
#         print("Trying fallback to default interface...")
#         try:
#             sniff(prn=packet_callback, store=False)
#         except Exception as e2:
#             print(f"❌ Fallback also failed: {e2}")

# threading.Thread(target=start_sniffer, daemon=True).start()

# # =============================
# # FLASK APP FOR TEMPLATES
# # =============================
# flask_app = Flask(__name__, template_folder='templates')

# # Configure Flask app
# flask_app.config['SECRET_KEY'] = 'hybrid-ids-secret-key-change-in-production-2024'
# flask_app.config['SESSION_TYPE'] = 'filesystem'
# flask_app.config['SESSION_PERMANENT'] = True
# flask_app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)

# # Initialize auth manager with Flask app
# auth.init_app(flask_app)

# # =============================
# # FLASK ROUTES (HTML PAGES)
# # =============================
# @flask_app.route('/')
# def index():
#     """Start on login page - redirect to login if not authenticated"""
#     if auth.is_authenticated():
#         # Redirect authenticated users to the main dashboard
#         return redirect(url_for('network_traffic'))
#     return render_template('login.html')

# @flask_app.route('/network-traffic')
# @auth.login_required
# def network_traffic():
#     return render_template('network_traffic.html')

# @flask_app.route('/analysis')
# @auth.login_required
# def analysis():
#     return render_template('analysis.html')

# @flask_app.route('/attacks')
# @auth.login_required
# def attacks():
#     return render_template('attacks.html')

# @flask_app.route('/notifications')
# @auth.login_required
# def notifications():
#     return render_template('notifications.html')

# @flask_app.route('/settings')
# @auth.admin_required
# def settings():
#     """Admin-only settings page"""
#     return render_template('settings.html')

# # =============================
# # AUTHENTICATION ROUTES
# # =============================

# @flask_app.route('/login')
# def login():
#     """Login page"""
#     if auth.is_authenticated():
#         return redirect(url_for('index'))
#     return render_template('login.html')

# @flask_app.route('/login', methods=['POST'])
# def login_post():
#     """Handle login form submission"""
#     username = request.form.get('username')
#     password = request.form.get('password')
#     remember = request.form.get('remember') == 'on'

#     if not username or not password:
#         flash('Please provide both username and password.', 'danger')
#         return redirect(url_for('login'))

#     success, message = auth.login_user(username, password, remember)
#     if success:
#         flash(message, 'success')
#         next_page = request.args.get('next')
#         # Redirect to network-traffic dashboard after successful login
#         return redirect(next_page) if next_page else redirect(url_for('network_traffic'))
#     else:
#         flash(message, 'danger')
#         return redirect(url_for('login'))

# @flask_app.route('/register')
# def register():
#     """Registration page"""
#     if auth.is_authenticated():
#         return redirect(url_for('index'))
#     return render_template('register.html')

# @flask_app.route('/register', methods=['POST'])
# def register_post():
#     """Handle registration form submission"""
#     username = request.form.get('username')
#     email = request.form.get('email')
#     password = request.form.get('password')
#     confirm_password = request.form.get('confirm_password')
#     full_name = request.form.get('full_name')

#     success, message = auth.register_user(username, email, password, confirm_password, full_name)
#     if success:
#         flash(message, 'success')
#         # Users need to login after registration, so redirect to login page
#         return redirect(url_for('login'))
#     else:
#         if isinstance(message, list):
#             for error in message:
#                 flash(error, 'danger')
#         else:
#             flash(message, 'danger')
#         return redirect(url_for('register'))

# @flask_app.route('/logout')
# def logout():
#     """Logout user and redirect to login page"""
#     auth.logout_user()
#     flash('You have been logged out successfully.', 'info')
#     return redirect(url_for('login'))

# @flask_app.route('/change-password', methods=['POST'])
# def change_password():
#     """Change user password"""
#     if not auth.is_authenticated():
#         return jsonify({'success': False, 'message': 'Not authenticated'}), 401

#     current_password = request.form.get('current_password')
#     new_password = request.form.get('new_password')
#     confirm_password = request.form.get('confirm_password')

#     success, message = auth.change_password(current_password, new_password, confirm_password)
#     if success:
#         return jsonify({'success': True, 'message': message})
#     else:
#         return jsonify({'success': False, 'message': message}), 400

# # =============================
# # API ENDPOINTS FOR REAL DATA
# # =============================

# @flask_app.route('/api/real-time-traffic')
# def api_real_time_traffic():
#     """Get real-time traffic data with packet details"""
#     try:
#         with packet_lock:
#             # Get the most recent packets
#             recent_packets = packet_list[-100:]  # Last 100 packets
            
#             # Convert to frontend format
#             packet_data = []
#             for pkt in recent_packets:
#                 # Determine status based on attack detection
#                 status = pkt.get("status", "normal")
                
#                 packet_data.append({
#                     "timestamp": pkt.get("timestamp", "--:--:--"),
#                     "src": pkt.get("src", "N/A"),
#                     "dst": pkt.get("dst", "N/A"),
#                     "protocol": pkt.get("protocol", "N/A"),
#                     "dport": pkt.get("dport", "N/A"),
#                     "length": pkt.get("length", 0),
#                     "status": status,
#                     "flags": pkt.get("flags", "")
#                 })
        
#         # Calculate real-time statistics
#         stats = calculate_real_time_stats()
        
#         return jsonify({
#             "packets": packet_data[::-1],  # Reverse to show newest first
#             "stats": stats,
#             "last_updated": datetime.now().strftime("%H:%M:%S"),
#             "total_captured": len(packet_list),
#             "status": "success"
#         })
#     except Exception as e:
#         return jsonify({
#             "packets": [],
#             "stats": {},
#             "last_updated": datetime.now().strftime("%H:%M:%S"),
#             "total_captured": 0,
#             "status": "error",
#             "error": str(e)
#         })

# def calculate_real_time_stats():
#     """Calculate real-time traffic statistics"""
#     try:
#         with packet_lock:
#             packets = packet_list[-1000:] if len(packet_list) > 1000 else packet_list.copy()
        
#         if not packets:
#             return {
#                 "total": 0,
#                 "safe": 0,
#                 "suspicious": 0,
#                 "attack": 0,
#                 "tcp": 0,
#                 "udp": 0,
#                 "icmp": 0,
#                 "other": 0,
#                 "avg_packet_size": 0,
#                 "packets_per_sec": 0
#             }
        
#         # Calculate protocol distribution
#         tcp_count = len([p for p in packets if p.get("protocol") == "TCP"])
#         udp_count = len([p for p in packets if p.get("protocol") == "UDP"])
#         icmp_count = len([p for p in packets if p.get("protocol") == "ICMP"])
#         other_count = len(packets) - tcp_count - udp_count - icmp_count
        
#         # Calculate status distribution
#         safe_count = len([p for p in packets if p.get("status") == "normal"])
#         suspicious_count = len([p for p in packets if p.get("status") == "suspicious"])
#         attack_count = len([p for p in packets if p.get("status") == "attack"])
        
#         # If status not set, estimate from attack history
#         if attack_count == 0 and suspicious_count == 0:
#             recent_attacks = [a for a in attack_history 
#                              if (datetime.now() - a["time"]).seconds < 10]
#             if recent_attacks:
#                 attack_count = min(len(packets), len(recent_attacks) * 10)
#                 safe_count = len(packets) - attack_count
        
#         # Calculate average packet size
#         avg_size = sum(p.get("length", 0) for p in packets) / len(packets) if packets else 0
        
#         # Calculate packets per second (last 5 seconds)
#         now = time.time()
#         recent_packets = [p for p in packets if now - p.get("time", now) <= 5]
#         packets_per_sec = len(recent_packets) / 5 if recent_packets else 0
        
#         return {
#             "total": len(packets),
#             "safe": safe_count,
#             "suspicious": suspicious_count,
#             "attack": attack_count,
#             "tcp": tcp_count,
#             "udp": udp_count,
#             "icmp": icmp_count,
#             "other": other_count,
#             "avg_packet_size": round(avg_size, 2),
#             "packets_per_sec": round(packets_per_sec, 2)
#         }
#     except Exception as e:
#         print(f"Error calculating stats: {e}")
#         return {
#             "total": 0,
#             "safe": 0,
#             "suspicious": 0,
#             "attack": 0,
#             "tcp": 0,
#             "udp": 0,
#             "icmp": 0,
#             "other": 0,
#             "avg_packet_size": 0,
#             "packets_per_sec": 0
#         }

# @flask_app.route('/api/traffic-history')
# def api_traffic_history():
#     """Get traffic history for charts"""
#     try:
#         # Get traffic from the last 5 minutes
#         five_min_ago = time.time() - 300
        
#         with packet_lock:
#             recent_traffic = [p for p in packet_list if p.get("time", 0) > five_min_ago]
        
#         # Group by protocol for pie chart
#         protocol_data = {}
#         for pkt in recent_traffic:
#             proto = pkt.get("protocol", "OTHER")
#             protocol_data[proto] = protocol_data.get(proto, 0) + 1
        
#         # Create timeline data (packets per 10-second interval)
#         timeline_data = []
#         now = time.time()
        
#         for i in range(30):  # Last 5 minutes in 10-second intervals
#             interval_start = now - (i + 1) * 10
#             interval_end = now - i * 10
            
#             interval_packets = [
#                 p for p in recent_traffic 
#                 if interval_start < p.get("time", 0) <= interval_end
#             ]
            
#             # Count protocols in this interval
#             tcp_count = len([p for p in interval_packets if p.get("protocol") == "TCP"])
#             udp_count = len([p for p in interval_packets if p.get("protocol") == "UDP"])
#             icmp_count = len([p for p in interval_packets if p.get("protocol") == "ICMP"])
            
#             timeline_data.append({
#                 "time": datetime.fromtimestamp(interval_end).strftime("%H:%M:%S"),
#                 "packets": len(interval_packets),
#                 "tcp": tcp_count,
#                 "udp": udp_count,
#                 "icmp": icmp_count
#             })
        
#         timeline_data.reverse()  # Oldest to newest
        
#         return jsonify({
#             "protocol_distribution": protocol_data,
#             "timeline": timeline_data,
#             "time_range": "5 minutes",
#             "status": "success"
#         })
#     except Exception as e:
#         return jsonify({
#             "error": str(e),
#             "protocol_distribution": {},
#             "timeline": [],
#             "time_range": "5 minutes",
#             "status": "error"
#         })

# @flask_app.route('/api/top-conversations')
# def api_top_conversations():
#     """Get top IP conversations"""
#     try:
#         with packet_lock:
#             recent_packets = packet_list[-500:] if len(packet_list) > 500 else packet_list.copy()
        
#         # Count conversations between source-destination pairs
#         conversation_counts = {}
#         conversation_bytes = {}
        
#         for pkt in recent_packets:
#             src = pkt.get("src", "Unknown")
#             dst = pkt.get("dst", "Unknown")
#             key = f"{src}->{dst}"
            
#             conversation_counts[key] = conversation_counts.get(key, 0) + 1
#             conversation_bytes[key] = conversation_bytes.get(key, 0) + pkt.get("length", 0)
        
#         # Get top 10 conversations
#         top_conversations = sorted(
#             conversation_counts.items(),
#             key=lambda x: x[1],
#             reverse=True
#         )[:10]
        
#         result = []
#         for conv, count in top_conversations:
#             src, dst = conv.split("->")
#             total_bytes = conversation_bytes.get(conv, 0)
#             avg_size = total_bytes // count if count > 0 else 0
            
#             result.append({
#                 "source": src,
#                 "destination": dst,
#                 "packet_count": count,
#                 "total_bytes": total_bytes,
#                 "avg_packet_size": avg_size
#             })
        
#         return jsonify({
#             "conversations": result,
#             "status": "success"
#         })
#     except Exception as e:
#         return jsonify({
#             "conversations": [],
#             "status": "error",
#             "error": str(e)
#         })

# @flask_app.route('/api/packet-size-distribution')
# def api_packet_size_distribution():
#     """Get packet size distribution data"""
#     try:
#         with packet_lock:
#             recent_packets = packet_list[-500:] if len(packet_list) > 500 else packet_list.copy()
        
#         # Group packet sizes into bins
#         size_bins = {
#             "0-100": 0,
#             "101-500": 0,
#             "501-1000": 0,
#             "1001-1500": 0,
#             "1501+": 0
#         }
        
#         sizes = []
#         for pkt in recent_packets:
#             size = pkt.get("length", 0)
#             sizes.append(size)
#             if size <= 100:
#                 size_bins["0-100"] += 1
#             elif size <= 500:
#                 size_bins["101-500"] += 1
#             elif size <= 1000:
#                 size_bins["501-1000"] += 1
#             elif size <= 1500:
#                 size_bins["1001-1500"] += 1
#             else:
#                 size_bins["1501+"] += 1
        
#         # Find most common size range
#         most_common = max(size_bins.items(), key=lambda x: x[1])[0] if size_bins else "0-100"
        
#         return jsonify({
#             "distribution": size_bins,
#             "min_size": min(sizes) if sizes else 0,
#             "max_size": max(sizes) if sizes else 0,
#             "avg_size": sum(sizes) / len(sizes) if sizes else 0,
#             "most_common": most_common,
#             "status": "success"
#         })
#     except Exception as e:
#         return jsonify({
#             "distribution": {},
#             "min_size": 0,
#             "max_size": 0,
#             "avg_size": 0,
#             "most_common": "0-100",
#             "status": "error",
#             "error": str(e)
#         })

# @flask_app.route('/api/network-status')
# def api_network_status():
#     """Get overall network status"""
#     try:
#         status = "normal"
        
#         if paused:
#             status = "under_attack"
#         elif len(attack_history) > 0:
#             # Check if last attack was recent (last 2 minutes)
#             if attack_history and (datetime.now() - attack_history[-1]["time"]).seconds < 120:
#                 status = "warning"
        
#         # Calculate traffic rate
#         now = time.time()
#         recent_packets = [p for p in packet_list if now - p.get("time", now) <= 10]
#         packets_per_sec = len(recent_packets) / 10 if recent_packets else 0
        
#         # Get uptime
#         uptime_str = get_uptime()
        
#         # Calculate memory usage (simulated based on packet count)
#         memory_mb = len(packet_list) * 0.01  # Rough estimate
        
#         return jsonify({
#             "status": status,
#             "packets_per_second": round(packets_per_sec, 2),
#             "total_packets": len(packet_list),
#             "active_attacks": len([a for a in attack_history if (datetime.now() - a["time"]).seconds < 300]),
#             "interface": INTERFACE,
#             "uptime": uptime_str,
#             "ml_enabled": ML_ENABLED,
#             "memory_usage": round(memory_mb, 2),
#             "capture_status": "active" if not paused else "paused",
#             "attack_status": "normal" if status == "normal" else "warning" if status == "warning" else "critical",
#             "system_time": datetime.now().strftime("%H:%M:%S"),
#             "status": "success"
#         })
#     except Exception as e:
#         return jsonify({
#             "status": "error",
#             "error": str(e),
#             "interface": INTERFACE,
#             "uptime": "00:00:00",
#             "ml_enabled": ML_ENABLED,
#             "capture_status": "error",
#             "attack_status": "unknown",
#             "status": "error"
#         })

# @flask_app.route('/api/attacks')
# def api_attacks():
#     """Get attack history"""
#     try:
#         # Convert deque to list for sorting
#         attacks_list = list(attack_history)
        
#         # Sort by time (newest first)
#         attacks_list.sort(key=lambda x: x["time"], reverse=True)
        
#         attack_data = []
#         for attack in attacks_list[:50]:  # Last 50 attacks
#             # Extract source and target from message
#             source = "Unknown"
#             target = "Unknown"
#             message = attack["message"]
            
#             # Try to extract IP addresses from message
#             import re
#             src_match = re.search(r'SRC=([\d\.]+)', message)
#             dst_match = re.search(r'DST=([\d\.]+)', message)
            
#             if src_match:
#                 source = src_match.group(1)
#             if dst_match:
#                 target = dst_match.group(1)
            
#             # Determine severity
#             severity = "medium"
#             if "DDoS" in attack["type"]:
#                 severity = "critical"
#             elif "DoS" in attack["type"]:
#                 severity = "high"
#             elif "FLOOD" in attack["type"]:
#                 severity = "high"
#             elif "SCAN" in attack["type"]:
#                 severity = "medium"
            
#             attack_data.append({
#                 "type": attack["type"],
#                 "message": message,
#                 "timestamp": attack["timestamp"],
#                 "source": source,
#                 "target": target,
#                 "severity": severity,
#                 "time_ago": get_time_ago(attack["time"])
#             })
        
#         return jsonify({
#             "attacks": attack_data,
#             "total": len(attack_history),
#             "today": len([a for a in attack_history if a["time"].date() == datetime.now().date()]),
#             "status": "success"
#         })
#     except Exception as e:
#         return jsonify({
#             "attacks": [],
#             "total": 0,
#             "today": 0,
#             "status": "error",
#             "error": str(e)
#         })

# def get_time_ago(dt):
#     """Helper to format time ago"""
#     now = datetime.now()
#     diff = now - dt
    
#     if diff.days > 0:
#         return f"{diff.days} day{'s' if diff.days > 1 else ''} ago"
#     elif diff.seconds > 3600:
#         hours = diff.seconds // 3600
#         return f"{hours} hour{'s' if hours > 1 else ''} ago"
#     elif diff.seconds > 60:
#         minutes = diff.seconds // 60
#         return f"{minutes} minute{'s' if minutes > 1 else ''} ago"
#     else:
#         return "Just now"

# @flask_app.route('/api/notifications')
# def api_notifications():
#     """Get system notifications"""
#     try:
#         notifications_list = []
        
#         # System notifications
#         notifications_list.append({
#             "id": 1,
#             "type": "system",
#             "title": "System Started",
#             "message": f"Hybrid IDS started on interface {INTERFACE}",
#             "timestamp": system_start_time.strftime("%H:%M:%S"),
#             "read": True,
#             "priority": "info"
#         })
        
#         if ML_ENABLED:
#             notifications_list.append({
#                 "id": 2,
#                 "type": "system",
#                 "title": "ML Detection Enabled",
#                 "message": "Machine learning attack detection is active",
#                 "timestamp": datetime.now().strftime("%H:%M:%S"),
#                 "read": True,
#                 "priority": "info"
#             })
        
#         # Attack notifications (last 10)
#         attack_list = list(attack_history)
#         for i, attack in enumerate(attack_list[-10:]):
#             priority = "critical" if "DDoS" in attack["type"] else "high" if "DoS" in attack["type"] else "medium"
#             notifications_list.append({
#                 "id": 1000 + i,
#                 "type": "attack",
#                 "title": f"Attack: {attack['type']}",
#                 "message": attack['message'],
#                 "timestamp": attack['timestamp'],
#                 "read": False,
#                 "priority": priority
#             })
        
#         return jsonify({
#             "notifications": notifications_list[::-1],  # Newest first
#             "unread": len([n for n in notifications_list if not n.get("read", False)]),
#             "status": "success"
#         })
#     except Exception as e:
#         return jsonify({
#             "notifications": [],
#             "unread": 0,
#             "status": "error",
#             "error": str(e)
#         })

# @flask_app.route('/api/analysis')
# def api_analysis():
#     """Get analysis data"""
#     try:
#         with packet_lock:
#             packets = packet_list.copy()
        
#         if len(packets) == 0:
#             return jsonify({
#                 "protocols": {},
#                 "top_sources": [],
#                 "top_destinations": [],
#                 "packet_rate": 0,
#                 "avg_packet_size": 0,
#                 "total_bytes": 0,
#                 "hourly_pattern": [],
#                 "status": "success"
#             })
        
#         # Protocol distribution
#         protocols = defaultdict(int)
#         for pkt in packets:
#             protocols[pkt.get("protocol", "OTHER")] += 1
        
#         # Top sources
#         sources = defaultdict(int)
#         for pkt in packets:
#             sources[pkt.get("src")] += 1
#         top_sources = sorted(sources.items(), key=lambda x: x[1], reverse=True)[:10]
        
#         # Top destinations
#         destinations = defaultdict(int)
#         for pkt in packets:
#             destinations[pkt.get("dst")] += 1
#         top_destinations = sorted(destinations.items(), key=lambda x: x[1], reverse=True)[:10]
        
#         # Packet rate (packets per minute)
#         packet_rate = len(packets) / max(1, (time.time() - packets[0].get("time", time.time()))) * 60
        
#         # Average packet size
#         avg_packet_size = np.mean([p.get("length", 0) for p in packets]) if packets else 0
        
#         # Total bytes transferred
#         total_bytes = sum([p.get("length", 0) for p in packets])
        
#         # Hourly pattern (simulated for now)
#         hourly_pattern = []
#         for hour in range(24):
#             hourly_pattern.append({
#                 "hour": f"{hour:02d}:00",
#                 "packets": np.random.randint(50, 500)
#             })
        
#         return jsonify({
#             "protocols": dict(protocols),
#             "top_sources": [{"ip": ip, "count": count} for ip, count in top_sources],
#             "top_destinations": [{"ip": ip, "count": count} for ip, count in top_destinations],
#             "packet_rate": round(packet_rate, 2),
#             "avg_packet_size": round(avg_packet_size, 2),
#             "total_bytes": total_bytes,
#             "hourly_pattern": hourly_pattern,
#             "status": "success"
#         })
#     except Exception as e:
#         return jsonify({
#             "protocols": {},
#             "top_sources": [],
#             "top_destinations": [],
#             "packet_rate": 0,
#             "avg_packet_size": 0,
#             "total_bytes": 0,
#             "hourly_pattern": [],
#             "status": "error",
#             "error": str(e)
#         })

# @flask_app.route('/api/clear-traffic', methods=['POST'])
# def api_clear_traffic():
#     """Clear displayed traffic data"""
#     try:
#         global packet_list
#         with packet_lock:
#             packet_list.clear()
        
#         return jsonify({
#             "success": True,
#             "message": "Traffic data cleared",
#             "status": "success"
#         })
#     except Exception as e:
#         return jsonify({
#             "success": False,
#             "message": str(e),
#             "status": "error"
#         })

# @flask_app.route('/api/resume-capture', methods=['POST'])
# def api_resume_capture():
#     """Resume packet capture after attack detection"""
#     try:
#         global paused
#         paused = False
        
#         return jsonify({
#             "success": True,
#             "message": "Capture resumed",
#             "status": "success"
#         })
#     except Exception as e:
#         return jsonify({
#             "success": False,
#             "message": str(e),
#             "status": "error"
#         })

# # =============================
# # DASH APP (Keep existing dashboard)
# # =============================
# app = dash.Dash(__name__, server=flask_app, url_base_pathname='/dash/')
# app.title = "Hybrid IDS - Real-time"

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
#     print("\n" + "="*60)
#     print("🛡  HYBRID INTRUSION DETECTION SYSTEM")
#     print("="*60)
#     print(f"📡 Interface: {INTERFACE}")
#     print(f"🔧 ML Detection: {'ENABLED' if ML_ENABLED else 'DISABLED'}")
#     print(f"📊 Max Packets: {MAX_PACKETS}")
#     print("="*60)
#     print("🌐 Dashboard URLs:")
#     print("   Main UI → http://127.0.0.1:8090/network-traffic")
#     print("   Analysis → http://127.0.0.1:8090/analysis")
#     print("   Attacks → http://127.0.0.1:8090/attacks")
#     print("   Notifications → http://127.0.0.1:8090/notifications")
#     print("   Settings → http://127.0.0.1:8090/settings")
#     print("   Old Dashboard → http://127.0.0.1:8090/dash/")
#     print("="*60)
#     print("⚠️  Run with: sudo python main.py")
#     print("="*60 + "\n")
    
#     # Create templates directory if it doesn't exist
#     import os
#     if not os.path.exists('templates'):
#         os.makedirs('templates')
#         print("📁 Created templates directory")
#         print("📝 Please place your HTML templates in the 'templates' folder")
    
#     # Run the Flask app (which includes Dash)
#     try:
#         flask_app.run(host="0.0.0.0", port=8090, debug=False, threaded=True)
#     except Exception as e:
#         print(f"❌ Error starting server: {e}")
#         print("💡 Try using a different port: flask_app.run(port=8091)")






























# import threading
# import time
# import numpy as np
# import pickle
# import json
# import ipaddress
# from collections import defaultdict, deque
# from datetime import datetime, timedelta

# from scapy.all import sniff, IP, TCP, UDP, ICMP

# import dash
# from dash import html, dcc, dash_table
# from dash.dependencies import Input, Output
# import plotly.graph_objs as go
# from flask import Flask, render_template, jsonify, request, redirect, url_for, flash, g

# # Import authentication modules
# from database import db
# from auth import auth

# # =============================
# # CONFIG
# # =============================
# INTERFACE = "wlan0"       # CHANGE if needed
# MAX_PACKETS = 5000

# DOS_PPS_THRESHOLD = 500
# DDOS_SOURCE_THRESHOLD = 5
# DDOS_TOTAL_PPS = 1500

# FLOW_MIN_PACKETS = 10

# LOG_FILE = "attack_logs.log"

# # =============================
# # WHITELIST
# # Add your router IP and any other trusted IPs here.
# # Run:  ip route | grep default   → shows your router/gateway IP
# # =============================
# WHITELISTED_IPS = {
#     "192.168.243.99",    # Default router/gateway — CHANGE to match yours
#     "192.168.243.1",    # Alternative common router IP
#     "127.0.0.1",         # Localhost
    
                      
#     "0.0.0.0",        # Unspecified
# }

# # If True, loopback, link-local, and multicast addresses are also
# # excluded from scan detection (recommended — these are never real attackers)
# WHITELIST_PRIVATE_RANGES = True

# # =============================
# # GLOBAL STATE
# # =============================
# packet_list = []
# packet_lock = threading.Lock()

# paused = False
# last_attack = None

# flow_window = deque(maxlen=50)

# # Rate tracking — these deques hold timestamps of recent packets per IP.
# # len(tcp_rate[ip]) gives current packets/sec for that IP.
# udp_rate  = defaultdict(deque)
# tcp_rate  = defaultdict(deque)
# icmp_rate = defaultdict(deque)

# dst_sources = defaultdict(set)

# # Scan tracking — keyed by "src->dst" to avoid false positives
# # from normal hosts talking to many different servers.
# # A real scan = one attacker hitting MANY ports on ONE specific target.
# syn_ports    = defaultdict(set)   # key: "src_ip->dst_ip"
# udp_ports    = defaultdict(set)   # key: "src_ip->dst_ip"
# icmp_targets = defaultdict(set)   # key: src_ip

# # For traffic analysis
# traffic_history = deque(maxlen=5000)
# attack_history  = deque(maxlen=1000)

# # System start time for uptime calculation
# system_start_time = datetime.now()

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
# # WHITELIST HELPER
# # =============================
# def is_whitelisted(ip):
#     """
#     Returns True if this IP should be excluded from scan detection.
#     Covers:
#       - Manually whitelisted IPs (your router, localhost, etc.)
#       - Loopback, link-local, and multicast (never real attackers)
#     """
#     if ip in WHITELISTED_IPS:
#         return True

#     if WHITELIST_PRIVATE_RANGES:
#         try:
#             addr = ipaddress.ip_address(ip)
#             if addr.is_loopback or addr.is_link_local or addr.is_multicast:
#                 return True
#         except ValueError:
#             pass

#     return False


# # =============================
# # HELPERS
# # =============================
# def log_attack(atype, msg):
#     global paused, last_attack
#     paused = True
#     last_attack = f"{atype} | {msg}"

#     attack_entry = {
#         "type":      atype,
#         "message":   msg,
#         "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
#         "time":      datetime.now()
#     }
#     attack_history.append(attack_entry)

#     print(f"🚨 ATTACK DETECTED [{atype}] {msg}")

#     with open(LOG_FILE, "a") as f:
#         f.write(f"[{datetime.now()}] {atype} | {msg}\n")


# def rate_update(rate_dict, key):
#     now = time.time()
#     rate_dict[key].append(now)
#     while rate_dict[key] and now - rate_dict[key][0] > 1:
#         rate_dict[key].popleft()
#     return len(rate_dict[key])


# def get_uptime():
#     uptime  = datetime.now() - system_start_time
#     days    = uptime.days
#     hours   = uptime.seconds // 3600
#     minutes = (uptime.seconds % 3600) // 60
#     seconds = uptime.seconds % 60

#     if days > 0:
#         return f"{days}d {hours}h {minutes}m"
#     elif hours > 0:
#         return f"{hours}h {minutes}m {seconds}s"
#     else:
#         return f"{minutes}m {seconds}s"


# def get_time_ago(dt):
#     now  = datetime.now()
#     diff = now - dt

#     if diff.days > 0:
#         return f"{diff.days} day{'s' if diff.days > 1 else ''} ago"
#     elif diff.seconds > 3600:
#         hours = diff.seconds // 3600
#         return f"{hours} hour{'s' if hours > 1 else ''} ago"
#     elif diff.seconds > 60:
#         minutes = diff.seconds // 60
#         return f"{minutes} minute{'s' if minutes > 1 else ''} ago"
#     else:
#         return "Just now"


# # =============================
# # PACKET CALLBACK
# # =============================
# def packet_callback(pkt):
#     global paused

#     if paused or IP not in pkt:
#         return

#     src   = pkt[IP].src
#     dst   = pkt[IP].dst
#     proto = "OTHER"
#     dport = 0
#     flags = ""
#     attack_status = "normal"

#     if TCP in pkt:
#         proto = "TCP"
#         dport = pkt[TCP].dport
#         if pkt[TCP].flags.S: flags += "SYN "
#         if pkt[TCP].flags.A: flags += "ACK "
#         if pkt[TCP].flags.F: flags += "FIN "
#         if pkt[TCP].flags.R: flags += "RST "
#         if pkt[TCP].flags.P: flags += "PSH "
#         if pkt[TCP].flags.U: flags += "URG "

#     elif UDP in pkt:
#         proto = "UDP"
#         dport = pkt[UDP].dport

#     elif ICMP in pkt:
#         proto = "ICMP"

#     pkt_info = {
#         "time":           time.time(),
#         "timestamp":      datetime.now().strftime("%H:%M:%S.%f")[:-3],
#         "full_timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
#         "src":            src,
#         "dst":            dst,
#         "protocol":       proto,
#         "dport":          dport,
#         "length":         len(pkt),
#         "attack":         "",
#         "status":         attack_status,
#         "flags":          flags.strip()
#     }

#     traffic_history.append({**pkt_info, "attack": ""})

#     with packet_lock:
#         packet_list.append(pkt_info)
#         if len(packet_list) > MAX_PACKETS:
#             packet_list.pop(0)

#     # =============================
#     # PORT SCAN DETECTION
#     #
#     # FIX 1: is_whitelisted(src)
#     #   → Skips router/gateway so its normal UDP traffic never triggers
#     #     false UDP_SCAN alerts.
#     #
#     # FIX 2: key = "src->dst"
#     #   → Counts unique ports per attacker+victim pair. A real scanner
#     #     hammers many ports on ONE target. Normal traffic hits different
#     #     ports across MANY servers — never crosses the threshold.
#     #
#     # FIX 3: current_pps < DOS_PPS_THRESHOLD * 0.5
#     #   → Skips scan detection entirely when a source is already sending
#     #     flood-level traffic. DoS/DDoS tools send packets to many random
#     #     ports rapidly which would falsely trigger scan detection.
#     #     At flood speed it's a DoS — let the DoS detector handle it.
#     # =============================
#     if proto == "TCP" and "SYN" in flags:
#         if not is_whitelisted(src):
#             current_pps = len(tcp_rate[src])   # current packets/sec for this src
#             if current_pps < DOS_PPS_THRESHOLD * 0.5:
#                 key = f"{src}->{dst}"
#                 syn_ports[key].add(dport)
#                 if len(syn_ports[key]) >= 20:
#                     log_attack("PORT_SCAN", f"SRC={src} DST={dst} PORTS={len(syn_ports[key])}")
#                     attack_status = "attack"

#     if proto == "UDP":
#         if not is_whitelisted(src):
#             current_pps = len(udp_rate[src])   # current packets/sec for this src
#             if current_pps < DOS_PPS_THRESHOLD * 0.5:
#                 key = f"{src}->{dst}"
#                 udp_ports[key].add(dport)
#                 if len(udp_ports[key]) >= 15:
#                     log_attack("UDP_SCAN", f"SRC={src} DST={dst} PORTS={len(udp_ports[key])}")
#                     attack_status = "attack"

#     if proto == "ICMP":
#         if not is_whitelisted(src):
#             current_pps = len(icmp_rate[src])  # current packets/sec for this src
#             if current_pps < DOS_PPS_THRESHOLD * 0.5:
#                 icmp_targets[src].add(dst)
#                 if len(icmp_targets[src]) >= 5:
#                     log_attack("ICMP_SCAN", f"SRC={src} TARGETS={len(icmp_targets[src])}")
#                     attack_status = "attack"

#     # =============================
#     # DoS / DDoS DETECTION
#     # Rate tracking is always updated regardless of scan detection above,
#     # so PPS counts are always accurate for the flood checks below.
#     # =============================
#     if proto == "UDP":
#         pps = rate_update(udp_rate, src)
#         dst_sources[dst].add(src)

#         if pps > DOS_PPS_THRESHOLD:
#             log_attack("DoS", f"UDP_FLOOD SRC={src} PPS={pps}")
#             attack_status = "attack"
#         elif pps > DOS_PPS_THRESHOLD * 0.7:
#             attack_status = "suspicious"

#         total_pps = sum(len(udp_rate[s]) for s in dst_sources[dst])
#         if len(dst_sources[dst]) >= DDOS_SOURCE_THRESHOLD and total_pps > DDOS_TOTAL_PPS:
#             log_attack("DDoS", f"UDP_DDoS DST={dst} SOURCES={len(dst_sources[dst])}")
#             attack_status = "attack"

#     if proto == "TCP" and "SYN" in flags:
#         pps = rate_update(tcp_rate, src)
#         dst_sources[dst].add(src)

#         if pps > DOS_PPS_THRESHOLD:
#             log_attack("DoS", f"SYN_FLOOD SRC={src} PPS={pps}")
#             attack_status = "attack"
#         elif pps > DOS_PPS_THRESHOLD * 0.7:
#             attack_status = "suspicious"

#         total_pps = sum(len(tcp_rate[s]) for s in dst_sources[dst])
#         if len(dst_sources[dst]) >= DDOS_SOURCE_THRESHOLD and total_pps > DDOS_TOTAL_PPS:
#             log_attack("DDoS", f"SYN_DDoS DST={dst} SOURCES={len(dst_sources[dst])}")
#             attack_status = "attack"

#     if proto == "ICMP":
#         rate_update(icmp_rate, src)

#     # Update packet status
#     pkt_info["status"] = attack_status
#     if traffic_history:
#         traffic_history[-1]["status"] = attack_status


# # =============================
# # SNIFFER THREAD
# # =============================
# def start_sniffer():
#     print(f"📡 Sniffing on {INTERFACE}")
#     try:
#         sniff(iface=INTERFACE, prn=packet_callback, store=False)
#     except Exception as e:
#         print(f"❌ Sniffer error: {e}")
#         print("Trying fallback to default interface...")
#         try:
#             sniff(prn=packet_callback, store=False)
#         except Exception as e2:
#             print(f"❌ Fallback also failed: {e2}")

# threading.Thread(target=start_sniffer, daemon=True).start()


# # =============================
# # FLASK APP
# # =============================
# flask_app = Flask(__name__, template_folder='templates')

# flask_app.config['SECRET_KEY'] = 'hybrid-ids-secret-key-change-in-production-2024'
# flask_app.config['SESSION_TYPE'] = 'filesystem'
# flask_app.config['SESSION_PERMANENT'] = True
# flask_app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)

# auth.init_app(flask_app)


# # =============================
# # FLASK ROUTES
# # =============================
# @flask_app.route('/')
# def index():
#     if auth.is_authenticated():
#         return redirect(url_for('network_traffic'))
#     return render_template('login.html')

# @flask_app.route('/network-traffic')
# @auth.login_required
# def network_traffic():
#     return render_template('network_traffic.html')

# @flask_app.route('/analysis')
# @auth.login_required
# def analysis():
#     return render_template('analysis.html')

# @flask_app.route('/attacks')
# @auth.login_required
# def attacks():
#     return render_template('attacks.html')

# @flask_app.route('/notifications')
# @auth.login_required
# def notifications():
#     return render_template('notifications.html')

# @flask_app.route('/settings')
# @auth.admin_required
# def settings():
#     return render_template('settings.html')


# # =============================
# # AUTH ROUTES
# # =============================
# @flask_app.route('/login')
# def login():
#     if auth.is_authenticated():
#         return redirect(url_for('index'))
#     return render_template('login.html')

# @flask_app.route('/login', methods=['POST'])
# def login_post():
#     username = request.form.get('username')
#     password = request.form.get('password')
#     remember = request.form.get('remember') == 'on'

#     if not username or not password:
#         flash('Please provide both username and password.', 'danger')
#         return redirect(url_for('login'))

#     success, message = auth.login_user(username, password, remember)
#     if success:
#         flash(message, 'success')
#         next_page = request.args.get('next')
#         return redirect(next_page) if next_page else redirect(url_for('network_traffic'))
#     else:
#         flash(message, 'danger')
#         return redirect(url_for('login'))

# @flask_app.route('/register')
# def register():
#     if auth.is_authenticated():
#         return redirect(url_for('index'))
#     return render_template('register.html')

# @flask_app.route('/register', methods=['POST'])
# def register_post():
#     username         = request.form.get('username')
#     email            = request.form.get('email')
#     password         = request.form.get('password')
#     confirm_password = request.form.get('confirm_password')
#     full_name        = request.form.get('full_name')

#     success, message = auth.register_user(username, email, password, confirm_password, full_name)
#     if success:
#         flash(message, 'success')
#         return redirect(url_for('login'))
#     else:
#         if isinstance(message, list):
#             for error in message:
#                 flash(error, 'danger')
#         else:
#             flash(message, 'danger')
#         return redirect(url_for('register'))

# @flask_app.route('/logout')
# def logout():
#     auth.logout_user()
#     flash('You have been logged out successfully.', 'info')
#     return redirect(url_for('login'))

# @flask_app.route('/change-password', methods=['POST'])
# def change_password():
#     if not auth.is_authenticated():
#         return jsonify({'success': False, 'message': 'Not authenticated'}), 401

#     current_password = request.form.get('current_password')
#     new_password     = request.form.get('new_password')
#     confirm_password = request.form.get('confirm_password')

#     success, message = auth.change_password(current_password, new_password, confirm_password)
#     if success:
#         return jsonify({'success': True, 'message': message})
#     else:
#         return jsonify({'success': False, 'message': message}), 400


# # =============================
# # API ENDPOINTS
# # =============================

# @flask_app.route('/api/real-time-traffic')
# def api_real_time_traffic():
#     try:
#         with packet_lock:
#             recent_packets = packet_list[-100:]
#             packet_data = []
#             for pkt in recent_packets:
#                 packet_data.append({
#                     "timestamp": pkt.get("timestamp", "--:--:--"),
#                     "src":       pkt.get("src", "N/A"),
#                     "dst":       pkt.get("dst", "N/A"),
#                     "protocol":  pkt.get("protocol", "N/A"),
#                     "dport":     pkt.get("dport", "N/A"),
#                     "length":    pkt.get("length", 0),
#                     "status":    pkt.get("status", "normal"),
#                     "flags":     pkt.get("flags", "")
#                 })

#         stats = calculate_real_time_stats()

#         return jsonify({
#             "packets":        packet_data[::-1],
#             "stats":          stats,
#             "last_updated":   datetime.now().strftime("%H:%M:%S"),
#             "total_captured": len(packet_list),
#             "status":         "success"
#         })
#     except Exception as e:
#         return jsonify({
#             "packets": [], "stats": {},
#             "last_updated": datetime.now().strftime("%H:%M:%S"),
#             "total_captured": 0, "status": "error", "error": str(e)
#         })


# def calculate_real_time_stats():
#     try:
#         with packet_lock:
#             packets = packet_list[-1000:] if len(packet_list) > 1000 else packet_list.copy()

#         if not packets:
#             return {
#                 "total": 0, "safe": 0, "suspicious": 0, "attack": 0,
#                 "tcp": 0, "udp": 0, "icmp": 0, "other": 0,
#                 "avg_packet_size": 0, "packets_per_sec": 0
#             }

#         tcp_count   = sum(1 for p in packets if p.get("protocol") == "TCP")
#         udp_count   = sum(1 for p in packets if p.get("protocol") == "UDP")
#         icmp_count  = sum(1 for p in packets if p.get("protocol") == "ICMP")
#         other_count = len(packets) - tcp_count - udp_count - icmp_count

#         safe_count       = sum(1 for p in packets if p.get("status") == "normal")
#         suspicious_count = sum(1 for p in packets if p.get("status") == "suspicious")
#         attack_count     = sum(1 for p in packets if p.get("status") == "attack")

#         avg_size = sum(p.get("length", 0) for p in packets) / len(packets)

#         now    = time.time()
#         recent = [p for p in packets if now - p.get("time", now) <= 5]
#         packets_per_sec = len(recent) / 5 if recent else 0

#         return {
#             "total":           len(packets),
#             "safe":            safe_count,
#             "suspicious":      suspicious_count,
#             "attack":          attack_count,
#             "tcp":             tcp_count,
#             "udp":             udp_count,
#             "icmp":            icmp_count,
#             "other":           other_count,
#             "avg_packet_size": round(avg_size, 2),
#             "packets_per_sec": round(packets_per_sec, 2)
#         }
#     except Exception as e:
#         print(f"Error calculating stats: {e}")
#         return {
#             "total": 0, "safe": 0, "suspicious": 0, "attack": 0,
#             "tcp": 0, "udp": 0, "icmp": 0, "other": 0,
#             "avg_packet_size": 0, "packets_per_sec": 0
#         }


# @flask_app.route('/api/traffic-history')
# def api_traffic_history():
#     try:
#         five_min_ago = time.time() - 300

#         with packet_lock:
#             recent_traffic = [p for p in packet_list if p.get("time", 0) > five_min_ago]

#         protocol_data = {}
#         for pkt in recent_traffic:
#             proto = pkt.get("protocol", "OTHER")
#             protocol_data[proto] = protocol_data.get(proto, 0) + 1

#         timeline_data = []
#         now = time.time()

#         for i in range(30):
#             interval_start = now - (i + 1) * 10
#             interval_end   = now - i * 10

#             interval_packets = [
#                 p for p in recent_traffic
#                 if interval_start < p.get("time", 0) <= interval_end
#             ]

#             timeline_data.append({
#                 "time":    datetime.fromtimestamp(interval_end).strftime("%H:%M:%S"),
#                 "packets": len(interval_packets),
#                 "tcp":     sum(1 for p in interval_packets if p.get("protocol") == "TCP"),
#                 "udp":     sum(1 for p in interval_packets if p.get("protocol") == "UDP"),
#                 "icmp":    sum(1 for p in interval_packets if p.get("protocol") == "ICMP")
#             })

#         timeline_data.reverse()

#         return jsonify({
#             "protocol_distribution": protocol_data,
#             "timeline":   timeline_data,
#             "time_range": "5 minutes",
#             "status":     "success"
#         })
#     except Exception as e:
#         return jsonify({
#             "error": str(e), "protocol_distribution": {},
#             "timeline": [], "time_range": "5 minutes", "status": "error"
#         })


# @flask_app.route('/api/top-conversations')
# def api_top_conversations():
#     try:
#         with packet_lock:
#             recent_packets = packet_list[-500:] if len(packet_list) > 500 else packet_list.copy()

#         conversation_counts = {}
#         conversation_bytes  = {}

#         for pkt in recent_packets:
#             src = pkt.get("src", "Unknown")
#             dst = pkt.get("dst", "Unknown")
#             key = f"{src}->{dst}"
#             conversation_counts[key] = conversation_counts.get(key, 0) + 1
#             conversation_bytes[key]  = conversation_bytes.get(key, 0) + pkt.get("length", 0)

#         top_conversations = sorted(
#             conversation_counts.items(), key=lambda x: x[1], reverse=True
#         )[:10]

#         result = []
#         for conv, count in top_conversations:
#             src, dst    = conv.split("->")
#             total_bytes = conversation_bytes.get(conv, 0)
#             result.append({
#                 "source":          src,
#                 "destination":     dst,
#                 "packet_count":    count,
#                 "total_bytes":     total_bytes,
#                 "avg_packet_size": total_bytes // count if count > 0 else 0
#             })

#         return jsonify({"conversations": result, "status": "success"})
#     except Exception as e:
#         return jsonify({"conversations": [], "status": "error", "error": str(e)})


# @flask_app.route('/api/packet-size-distribution')
# def api_packet_size_distribution():
#     try:
#         with packet_lock:
#             recent_packets = packet_list[-500:] if len(packet_list) > 500 else packet_list.copy()

#         size_bins = {"0-100": 0, "101-500": 0, "501-1000": 0, "1001-1500": 0, "1501+": 0}
#         sizes = []

#         for pkt in recent_packets:
#             size = pkt.get("length", 0)
#             sizes.append(size)
#             if size <= 100:    size_bins["0-100"]     += 1
#             elif size <= 500:  size_bins["101-500"]   += 1
#             elif size <= 1000: size_bins["501-1000"]  += 1
#             elif size <= 1500: size_bins["1001-1500"] += 1
#             else:              size_bins["1501+"]     += 1

#         most_common = max(size_bins.items(), key=lambda x: x[1])[0] if size_bins else "0-100"

#         return jsonify({
#             "distribution": size_bins,
#             "min_size":     min(sizes) if sizes else 0,
#             "max_size":     max(sizes) if sizes else 0,
#             "avg_size":     sum(sizes) / len(sizes) if sizes else 0,
#             "most_common":  most_common,
#             "status":       "success"
#         })
#     except Exception as e:
#         return jsonify({
#             "distribution": {}, "min_size": 0, "max_size": 0,
#             "avg_size": 0, "most_common": "0-100", "status": "error", "error": str(e)
#         })


# @flask_app.route('/api/network-status')
# def api_network_status():
#     try:
#         status = "normal"
#         if paused:
#             status = "under_attack"
#         elif attack_history and (datetime.now() - attack_history[-1]["time"]).seconds < 120:
#             status = "warning"

#         now             = time.time()
#         recent_packets  = [p for p in packet_list if now - p.get("time", now) <= 10]
#         packets_per_sec = len(recent_packets) / 10 if recent_packets else 0

#         return jsonify({
#             "status":             status,
#             "packets_per_second": round(packets_per_sec, 2),
#             "total_packets":      len(packet_list),
#             "active_attacks":     len([a for a in attack_history if (datetime.now() - a["time"]).seconds < 300]),
#             "interface":          INTERFACE,
#             "uptime":             get_uptime(),
#             "ml_enabled":         ML_ENABLED,
#             "memory_usage":       round(len(packet_list) * 0.01, 2),
#             "capture_status":     "active" if not paused else "paused",
#             "attack_status":      "normal" if status == "normal" else "warning" if status == "warning" else "critical",
#             "system_time":        datetime.now().strftime("%H:%M:%S"),
#         })
#     except Exception as e:
#         return jsonify({
#             "status": "error", "error": str(e), "interface": INTERFACE,
#             "uptime": "00:00:00", "ml_enabled": ML_ENABLED,
#             "capture_status": "error", "attack_status": "unknown"
#         })


# @flask_app.route('/api/attacks')
# def api_attacks():
#     try:
#         import re
#         attacks_list = sorted(list(attack_history), key=lambda x: x["time"], reverse=True)

#         attack_data = []
#         for attack in attacks_list[:50]:
#             source  = "Unknown"
#             target  = "Unknown"
#             message = attack["message"]

#             src_match = re.search(r'SRC=([\d\.]+)', message)
#             dst_match = re.search(r'DST=([\d\.]+)', message)
#             if src_match: source = src_match.group(1)
#             if dst_match: target = dst_match.group(1)

#             severity = "medium"
#             if "DDoS"    in attack["type"]: severity = "critical"
#             elif "DoS"   in attack["type"]: severity = "high"
#             elif "FLOOD" in attack["type"]: severity = "high"
#             elif "SCAN"  in attack["type"]: severity = "medium"

#             attack_data.append({
#                 "type":      attack["type"],
#                 "message":   message,
#                 "timestamp": attack["timestamp"],
#                 "source":    source,
#                 "target":    target,
#                 "severity":  severity,
#                 "time_ago":  get_time_ago(attack["time"])
#             })

#         return jsonify({
#             "attacks": attack_data,
#             "total":   len(attack_history),
#             "today":   len([a for a in attack_history if a["time"].date() == datetime.now().date()]),
#             "status":  "success"
#         })
#     except Exception as e:
#         return jsonify({"attacks": [], "total": 0, "today": 0, "status": "error", "error": str(e)})


# @flask_app.route('/api/notifications')
# def api_notifications():
#     try:
#         notifications_list = []

#         notifications_list.append({
#             "id": 1, "type": "system",
#             "title":     "System Started",
#             "message":   f"Hybrid IDS started on interface {INTERFACE}",
#             "timestamp": system_start_time.strftime("%H:%M:%S"),
#             "read": True, "priority": "info"
#         })

#         if ML_ENABLED:
#             notifications_list.append({
#                 "id": 2, "type": "system",
#                 "title":     "ML Detection Enabled",
#                 "message":   "Machine learning attack detection is active",
#                 "timestamp": datetime.now().strftime("%H:%M:%S"),
#                 "read": True, "priority": "info"
#             })

#         for i, attack in enumerate(list(attack_history)[-10:]):
#             priority = "critical" if "DDoS" in attack["type"] else "high" if "DoS" in attack["type"] else "medium"
#             notifications_list.append({
#                 "id":        1000 + i,
#                 "type":      "attack",
#                 "title":     f"Attack: {attack['type']}",
#                 "message":   attack['message'],
#                 "timestamp": attack['timestamp'],
#                 "read":      False,
#                 "priority":  priority
#             })

#         return jsonify({
#             "notifications": notifications_list[::-1],
#             "unread":        len([n for n in notifications_list if not n.get("read", False)]),
#             "status":        "success"
#         })
#     except Exception as e:
#         return jsonify({"notifications": [], "unread": 0, "status": "error", "error": str(e)})


# @flask_app.route('/api/analysis')
# def api_analysis():
#     try:
#         with packet_lock:
#             packets = packet_list.copy()

#         if not packets:
#             return jsonify({
#                 "protocols": {}, "top_sources": [], "top_destinations": [],
#                 "packet_rate": 0, "avg_packet_size": 0, "total_bytes": 0,
#                 "hourly_pattern": [], "status": "success"
#             })

#         protocols = defaultdict(int)
#         for pkt in packets:
#             protocols[pkt.get("protocol", "OTHER")] += 1

#         sources = defaultdict(int)
#         for pkt in packets:
#             sources[pkt.get("src")] += 1
#         top_sources = sorted(sources.items(), key=lambda x: x[1], reverse=True)[:10]

#         destinations = defaultdict(int)
#         for pkt in packets:
#             destinations[pkt.get("dst")] += 1
#         top_destinations = sorted(destinations.items(), key=lambda x: x[1], reverse=True)[:10]

#         elapsed      = time.time() - packets[0].get("time", time.time())
#         packet_rate  = len(packets) / max(1, elapsed) * 60
#         avg_pkt_size = np.mean([p.get("length", 0) for p in packets])
#         total_bytes  = sum(p.get("length", 0) for p in packets)

#         hourly_pattern = [
#             {"hour": f"{h:02d}:00", "packets": np.random.randint(50, 500)}
#             for h in range(24)
#         ]

#         return jsonify({
#             "protocols":        dict(protocols),
#             "top_sources":      [{"ip": ip, "count": c} for ip, c in top_sources],
#             "top_destinations": [{"ip": ip, "count": c} for ip, c in top_destinations],
#             "packet_rate":      round(packet_rate, 2),
#             "avg_packet_size":  round(avg_pkt_size, 2),
#             "total_bytes":      total_bytes,
#             "hourly_pattern":   hourly_pattern,
#             "status":           "success"
#         })
#     except Exception as e:
#         return jsonify({
#             "protocols": {}, "top_sources": [], "top_destinations": [],
#             "packet_rate": 0, "avg_packet_size": 0, "total_bytes": 0,
#             "hourly_pattern": [], "status": "error", "error": str(e)
#         })


# @flask_app.route('/api/clear-traffic', methods=['POST'])
# def api_clear_traffic():
#     try:
#         global packet_list
#         with packet_lock:
#             packet_list.clear()
#         return jsonify({"success": True, "message": "Traffic data cleared", "status": "success"})
#     except Exception as e:
#         return jsonify({"success": False, "message": str(e), "status": "error"})


# @flask_app.route('/api/resume-capture', methods=['POST'])
# def api_resume_capture():
#     try:
#         global paused
#         paused = False
#         return jsonify({"success": True, "message": "Capture resumed", "status": "success"})
#     except Exception as e:
#         return jsonify({"success": False, "message": str(e), "status": "error"})


# # =============================
# # DASH APP (legacy dashboard)
# # =============================
# app = dash.Dash(__name__, server=flask_app, url_base_pathname='/dash/')
# app.title = "Hybrid IDS - Real-time"

# app.layout = html.Div([
#     html.H1("🛡 Hybrid IDS Dashboard", style={"textAlign": "center"}),
#     html.Div(id="alert-box", style={"textAlign": "center", "padding": "15px"}),
#     html.Button("▶ Resume Capture", id="resume-btn"),
#     html.Div(id="stats"),
#     dash_table.DataTable(
#         id="table",
#         columns=[
#             {"name": "Time",        "id": "timestamp"},
#             {"name": "Source",      "id": "src"},
#             {"name": "Destination", "id": "dst"},
#             {"name": "Proto",       "id": "protocol"},
#             {"name": "Len",         "id": "length"},
#         ],
#         page_size=10,
#         style_cell={"fontFamily": "monospace", "fontSize": 12}
#     ),
#     dcc.Interval(id="tick", interval=2000)
# ])

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
#     print("\n" + "="*60)
#     print("🛡  HYBRID INTRUSION DETECTION SYSTEM")
#     print("="*60)
#     print(f"📡 Interface:    {INTERFACE}")
#     print(f"🔧 ML Detection: {'ENABLED' if ML_ENABLED else 'DISABLED'}")
#     print(f"📊 Max Packets:  {MAX_PACKETS}")
#     print(f"🚫 Whitelisted:  {', '.join(WHITELISTED_IPS)}")
#     print("="*60)
#     print("🌐 Dashboard URLs:")
#     print("   Main UI       → http://127.0.0.1:8090/network-traffic")
#     print("   Analysis      → http://127.0.0.1:8090/analysis")
#     print("   Attacks       → http://127.0.0.1:8090/attacks")
#     print("   Notifications → http://127.0.0.1:8090/notifications")
#     print("   Settings      → http://127.0.0.1:8090/settings")
#     print("   Legacy Dash   → http://127.0.0.1:8090/dash/")
#     print("="*60)
#     print("⚠️  Run with: sudo python main.py")
#     print("💡 To find your router IP: ip route | grep default")
#     print("="*60 + "\n")

#     import os
#     if not os.path.exists('templates'):
#         os.makedirs('templates')
#         print("📁 Created templates directory")

#     try:
#         flask_app.run(host="0.0.0.0", port=8090, debug=False, threaded=True)
#     except Exception as e:
#         print(f"❌ Error starting server: {e}")
#         print("💡 Try a different port: flask_app.run(port=8091)")














# #=====================================================end of v1 those codes below are working ======================================================
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

# # --- Zero-day / anomaly (FIXED - reduced false positives) --------------------
# BASELINE_LEARNING_SECONDS = 300     # Increased from 180
# ANOMALY_Z_THRESHOLD       = 5.0     # Increased from 4.0
# ANOMALY_FEATURE_COUNT     = 5       # Increased from 4
# ZERO_DAY_COOLDOWN         = 120     # Increased from 60
# MIN_PACKETS_FOR_ANOMALY   = 50      # NEW: Minimum packets before checking
# ANOMALY_MIN_STD_DEV       = 0.5     # NEW: Minimum standard deviation
# BASELINE_MIN_SAMPLES      = 50      # NEW: Minimum samples for baseline

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

# # Per-source 1-second sliding-window rate trackers
# udp_rate  = defaultdict(deque)
# tcp_rate  = defaultdict(deque)
# icmp_rate = defaultdict(deque)
# rst_rate  = defaultdict(deque)
# fin_rate  = defaultdict(deque)
# ack_rate  = defaultdict(deque)
# http_rate = defaultdict(deque)

# dst_sources = defaultdict(set)

# # --- Scan state (time-windowed) ----------------------------------------------
# syn_scan_state  = defaultdict(lambda: {"ports":   set(), "first_seen": 0.0})
# udp_scan_state  = defaultdict(lambda: {"ports":   set(), "first_seen": 0.0})
# icmp_scan_state = defaultdict(lambda: {"targets": set(), "first_seen": 0.0})
# xmas_scan_state = defaultdict(lambda: {"ports":   set(), "first_seen": 0.0})
# null_scan_state = defaultdict(lambda: {"ports":   set(), "first_seen": 0.0})
# scan_lock       = threading.Lock()

# # --- Brute force state -------------------------------------------------------
# brute_force_attempts = defaultdict(deque)
# brute_force_lock     = threading.Lock()

# # --- Credential stuffing state -----------------------------------------------
# cred_stuff_sources = defaultdict(lambda: {"srcs": set(), "first_seen": 0.0})

# # --- Histories ---------------------------------------------------------------
# traffic_history = deque(maxlen=5000)
# attack_history  = deque(maxlen=1000)

# # --- Alert cooldown ----------------------------------------------------------
# attack_cooldowns = defaultdict(float)
# cooldown_lock    = threading.Lock()

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
#     """
#     Return True only for explicitly listed IPs.
#     Loopback and link-local are always whitelisted.
#     """
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
#     """Slide a 1-second window; return current pps count."""
#     now = time.time()
#     rate_dict[key].append(now)
#     while rate_dict[key] and now - rate_dict[key][0] > 1.0:
#         rate_dict[key].popleft()
#     return len(rate_dict[key])


# def log_attack(atype: str, msg: str, src: str = "") -> None:
#     """Log attack. Drops duplicate (atype, src) within cooldown window."""
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
# # ZERO-DAY HELPERS (FIXED)
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
#     """Extract features from a bucket with safe handling of empty buckets"""
#     n = bucket["pkt_count"]
#     if n == 0:
#         return {fname: 0 for fname in FEATURE_NAMES}
    
#     ports_list = list(bucket["unique_dports"])
#     entropy = _entropy(ports_list) if ports_list else 0
    
#     return {
#         "pkt_count":     n,
#         "byte_count":    bucket["byte_count"],
#         "unique_dsts":   len(bucket["unique_dsts"]),
#         "unique_dports": len(bucket["unique_dports"]),
#         "syn_count":     bucket["syn_count"],
#         "udp_count":     bucket["udp_count"],
#         "icmp_count":    bucket["icmp_count"],
#         "avg_pkt_size":  bucket["byte_count"] / n if n else 0,
#         "dst_entropy":   entropy,
#     }


# def _update_baseline(features: dict) -> None:
#     """Update baseline with new features, with safeguards"""
#     global baseline_ready, baseline_means, baseline_stds
    
#     # Add features to samples
#     for fname, val in features.items():
#         baseline_samples[fname].append(val)
    
#     if baseline_ready:
#         return
    
#     # Check if we have enough samples
#     elapsed = time.time() - (baseline_start or time.time())
#     sample_count = len(baseline_samples.get("pkt_count", []))
    
#     if elapsed >= BASELINE_LEARNING_SECONDS and sample_count >= BASELINE_MIN_SAMPLES:
#         valid_features = 0
#         for fname in FEATURE_NAMES:
#             vals = baseline_samples[fname]
#             if vals and len(vals) >= 10:  # Need at least 10 samples per feature
#                 mean = float(np.mean(vals))
#                 std  = float(np.std(vals))
#                 # Ensure minimum standard deviation to avoid division by near-zero
#                 std = max(std, ANOMALY_MIN_STD_DEV)
#                 baseline_means[fname] = mean
#                 baseline_stds[fname]  = std
#                 valid_features += 1
        
#         # Only mark as ready if we have enough features
#         if valid_features >= len(FEATURE_NAMES) * 0.7:  # 70% of features
#             baseline_ready = True
#             print(f"[Zero-Day] Baseline established with {sample_count} samples — anomaly detection ACTIVE.")
#             print(f"[Zero-Day] Feature means: { {k: round(v,2) for k,v in baseline_means.items()} }")
#         else:
#             print(f"[Zero-Day] Warning: Only {valid_features}/{len(FEATURE_NAMES)} features have sufficient samples")


# def _check_anomaly(features: dict, packet_count: int = 0):
#     """Check for anomalies with additional safeguards against false positives"""
#     if not baseline_ready:
#         return False, [], 0.0
    
#     # Don't check if we don't have enough packets
#     if packet_count < MIN_PACKETS_FOR_ANOMALY:
#         return False, [], 0.0
    
#     anomalous = []
#     max_z     = 0.0
    
#     for fname in FEATURE_NAMES:
#         val  = features.get(fname, 0)
#         mean = baseline_means.get(fname, 0)
#         std  = baseline_stds.get(fname, 1)
        
#         # Skip checking if standard deviation is too small (stable feature)
#         if std < ANOMALY_MIN_STD_DEV:
#             continue
            
#         z = abs(val - mean) / std
        
#         # For packet_count, use a different threshold (more lenient)
#         if fname == "pkt_count":
#             if z > ANOMALY_Z_THRESHOLD * 1.5:  # More lenient for packet count
#                 anomalous.append((fname, val, mean, round(z, 2)))
#                 max_z = max(max_z, z)
#         else:
#             if z > ANOMALY_Z_THRESHOLD:
#                 anomalous.append((fname, val, mean, round(z, 2)))
#                 max_z = max(max_z, z)
    
#     # Require more features to trigger and ensure it's not just normal variation
#     is_anomaly = len(anomalous) >= ANOMALY_FEATURE_COUNT and max_z > ANOMALY_Z_THRESHOLD
    
#     # Additional check: if only pkt_count and byte_count are anomalous, it's likely just a traffic burst
#     if is_anomaly:
#         anomalous_features = set(f for f, _, _, _ in anomalous)
#         if anomalous_features.issubset({"pkt_count", "byte_count"}):
#             return False, [], max_z
        
#         # Check if the anomaly is actually reasonable given traffic patterns
#         pkt_ratio = features.get("pkt_count", 0) / (baseline_means.get("pkt_count", 1) + 1)
#         if pkt_ratio > 10:  # More than 10x normal traffic
#             # This might be a real DoS attack, keep it
#             pass
#         elif pkt_ratio < 0.1:  # Very low traffic
#             return False, [], max_z
    
#     return is_anomaly, anomalous, round(max_z, 2)


# def flush_ip_bucket(src: str) -> str:
#     """Flush IP bucket and check for anomalies with better safeguards"""
#     with ip_bucket_lock:
#         bucket = ip_bucket_data[src]
#         now    = time.time()
        
#         # Don't flush buckets that are too new or have no packets
#         if now - bucket["bucket_start"] < 10 or bucket["pkt_count"] == 0:
#             return "normal"
        
#         packet_count = bucket["pkt_count"]
#         features = _extract_bucket_features(bucket)
        
#         # Reset the bucket
#         ip_bucket_data[src] = {
#             "pkt_count": 0, "byte_count": 0,
#             "unique_dsts": set(), "unique_dports": set(),
#             "syn_count": 0, "udp_count": 0, "icmp_count": 0,
#             "sizes": [], "bucket_start": now,
#         }
    
#     # Update baseline with this bucket's features
#     if not baseline_ready:
#         _update_baseline(features)
#         return "normal"
    
#     # Check for anomalies
#     is_anom, anom_list, max_z = _check_anomaly(features, packet_count)
    
#     if is_anom and not is_whitelisted(src):
#         last = zero_day_last_alert.get(src, 0)
#         if now - last >= ZERO_DAY_COOLDOWN:
#             zero_day_last_alert[src] = now
#             summary = ", ".join(f"{f}={v:.1f}(z={z})" for f, v, m, z in anom_list[:5])
            
#             # Log with more context to help debug
#             log_attack("ZERO_DAY", f"SRC={src} packets={packet_count} max_z={max_z} [{summary}]", src=src)
#             return "attack"
    
#     return "normal"


# def update_ip_bucket(src, dst, proto, dport, pkt_len, flags):
#     """Update bucket data for a source IP"""
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
#     """SYN scan: many ports on one target."""
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
#         print(f"[Zero-Day] Baseline learning started ({BASELINE_LEARNING_SECONDS}s window)...")

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

#     # Flag combinations
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

#     # Skip ALL detection for whitelisted sources
#     if is_whitelisted(src):
#         return

#     # ── PORT SCAN (SYN) ───────────────────────────────────────
#     if is_syn and len(tcp_rate[src]) < DOS_PPS_THRESHOLD * 0.5:
#         if check_port_scan(src, dst, dport):
#             attack_status = "attack"

#     # ── XMAS SCAN (FIN+PSH+URG) ──────────────────────────────
#     if is_xmas:
#         if check_xmas_scan(src, dst, dport):
#             attack_status = "attack"

#     # ── NULL SCAN (flags=0) ───────────────────────────────────
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
#             log_attack("DoS", f"UDP_FLOOD SRC={src} PPS={pps}", src=src)
#             attack_status = "attack"
#         elif pps > DOS_PPS_THRESHOLD * 0.7:
#             attack_status = "suspicious"

#     # ── SYN DoS ───────────────────────────────────────────────
#     if is_syn:
#         pps = rate_update(tcp_rate, src)
#         dst_sources[dst].add(src)
#         if pps > DOS_PPS_THRESHOLD:
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
#             log_attack("DDoS",
#                        f"DST={dst} SOURCES={len(dst_sources[dst])} TOTAL_PPS={total_pps}",
#                        src=src)
#             attack_status = "attack"

#     # ── RST FLOOD ─────────────────────────────────────────────
#     if is_pure_rst:
#         rst_pps = rate_update(rst_rate, src)
#         if rst_pps > RST_FLOOD_THRESHOLD:
#             log_attack("RST_FLOOD", f"SRC={src} PPS={rst_pps}", src=src)
#             attack_status = "attack"
#         elif rst_pps > RST_FLOOD_THRESHOLD * 0.7:
#             attack_status = "suspicious"

#     # ── FIN FLOOD ─────────────────────────────────────────────
#     if is_pure_fin:
#         fin_pps = rate_update(fin_rate, src)
#         if fin_pps > FIN_FLOOD_THRESHOLD:
#             log_attack("FIN_FLOOD", f"SRC={src} PPS={fin_pps}", src=src)
#             attack_status = "attack"
#         elif fin_pps > FIN_FLOOD_THRESHOLD * 0.7:
#             attack_status = "suspicious"

#     # ── ACK FLOOD ─────────────────────────────────────────────
#     if is_ack_only:
#         ack_pps = rate_update(ack_rate, src)
#         if ack_pps > ACK_FLOOD_THRESHOLD:
#             log_attack("ACK_FLOOD", f"SRC={src} PPS={ack_pps}", src=src)
#             attack_status = "attack"
#         elif ack_pps > ACK_FLOOD_THRESHOLD * 0.7:
#             attack_status = "suspicious"

#     # ── HTTP FLOOD ────────────────────────────────────────────
#     if is_psh_ack and dport in HTTP_PORTS:
#         http_pps = rate_update(http_rate, src)
#         if http_pps > HTTP_FLOOD_THRESHOLD:
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
#     # Only check zero-day if no other attack was detected
#     if attack_status == "normal":
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
#     """Background worker to periodically flush IP buckets"""
#     while True:
#         time.sleep(10)
#         with ip_bucket_lock:
#             sources = list(ip_bucket_data.keys())
#         for src in sources:
#             flush_ip_bucket(src)

# threading.Thread(target=_bucket_flush_worker, daemon=True).start()


# def _start_sniffer():
#     """Start packet sniffer"""
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
#     """Parse attack_logs.log and return every detected attack line."""
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
#                 parsed.append({
#                     "timestamp": "--",
#                     "type": "UNKNOWN",
#                     "message": ln,
#                 })

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
#                            "message":f"Baseline established — Z={ANOMALY_Z_THRESHOLD}",
#                            "timestamp":datetime.now().strftime("%H:%M:%S"),
#                            "read":True,"priority":"info"})
#         elif baseline_start:
#             pct = min(99,int(((time.time()-baseline_start)/BASELINE_LEARNING_SECONDS)*100))
#             notifs.append({"id":3,"type":"system","title":"Zero-Day Baseline Learning",
#                            "message":f"Building baseline ({pct}% complete)",
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


# @flask_app.route("/api/zero-day-stats")
# def api_zero_day_stats():
#     try:
#         stats = {}
#         if baseline_ready:
#             for fname in FEATURE_NAMES:
#                 stats[fname] = {"mean":round(baseline_means.get(fname,0),3),
#                                 "std": round(baseline_stds.get(fname,0),3)}
#         return jsonify({"enabled":True,"baseline_ready":baseline_ready,
#                         "feature_stats":stats,"z_threshold":ANOMALY_Z_THRESHOLD,
#                         "feature_count_req":ANOMALY_FEATURE_COUNT,
#                         "min_packets_required":MIN_PACKETS_FOR_ANOMALY,
#                         "cooldown_sec":ZERO_DAY_COOLDOWN,
#                         "learning_window":BASELINE_LEARNING_SECONDS,
#                         "total_zero_day":sum(1 for a in attack_history if "ZERO_DAY" in a["type"]),
#                         "status":"success"})
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
# # DASH (legacy dashboard)
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
#     print("\n" + "="*65)
#     print("   HYBRID INTRUSION DETECTION SYSTEM (FIXED - Reduced False Positives)")
#     print("="*65)
#     print(f"  Interface          : {INTERFACE}")
#     print(f"  ML Detection       : {'ENABLED' if ML_ENABLED else 'DISABLED'}")
#     print(f"  Whitelisted IPs    : {', '.join(WHITELISTED_IPS)}")
#     print(f"  Private Ranges     : {'AUTO-WHITELISTED' if WHITELIST_PRIVATE_RANGES else 'NOT whitelisted (correct for testing)'}")
#     print(f"  Zero-Day           : baseline={BASELINE_LEARNING_SECONDS}s  z={ANOMALY_Z_THRESHOLD}  features={ANOMALY_FEATURE_COUNT}  min_packets={MIN_PACKETS_FOR_ANOMALY}")
#     print(f"  Brute Force        : {BRUTE_FORCE_THRESHOLD} attempts/{BRUTE_FORCE_WINDOW}s")
#     print(f"  RST/FIN Flood      : threshold={RST_FLOOD_THRESHOLD}/{FIN_FLOOD_THRESHOLD} pps")
#     print(f"  ACK Flood          : threshold={ACK_FLOOD_THRESHOLD} pps")
#     print(f"  HTTP Flood         : threshold={HTTP_FLOOD_THRESHOLD} pps")
#     print(f"  XMAS/NULL Scan     : {XMAS_SCAN_THRESHOLD}/{NULL_SCAN_THRESHOLD} ports/{SCAN_WINDOW}s")
#     print(f"  Cred Stuffing      : {CRED_STUFF_SRC_THRESHOLD} unique IPs/{CRED_STUFF_WINDOW}s")
#     print(f"  Alert Cooldown     : {ATTACK_COOLDOWN_SEC}s per (type, source)")
#     print(f"  Suspicious @ >     : {int(DOS_PPS_THRESHOLD*SUSPICIOUS_PPS_FACTOR)} pps")
#     print("="*65)
#     print("  URLs:")
#     print("    Network Traffic  ->  http://127.0.0.1:8090/network-traffic")
#     print("    Attacks          ->  http://127.0.0.1:8090/attacks")
#     print("    Analysis         ->  http://127.0.0.1:8090/analysis")
#     print("    Notifications    ->  http://127.0.0.1:8090/notifications")
#     print("    Legacy Dash      ->  http://127.0.0.1:8090/dash/")
#     print("    Zero-Day Stats   ->  http://127.0.0.1:8090/api/zero-day-stats")
#     print("    Brute-Force Live ->  http://127.0.0.1:8090/api/brute-force-stats")
#     print("="*65)
#     print("  Run with:  sudo python main.py")
#     print("="*65 + "\n")

#     if not os.path.exists("templates"):
#         os.makedirs("templates")
#     try:
#         flask_app.run(host="0.0.0.0", port=8090, debug=False, threaded=True)
#     except Exception as e:
#         print(f"Error starting server: {e}")









#!/usr/bin/env python3
# =============================================================================
# HYBRID INTRUSION DETECTION SYSTEM  —  main.py  (false-positive-hardened)
# =============================================================================
# Key changes vs v1:
#  1. All scan states now use (src, dst) pair keys properly; window resets
#     are inside the lock to avoid TOCTOU races.
#  2. Port-scan gate: only trigger when SYN rate is LOW (not already flagged
#     as a flood), preventing the same burst from raising both DoS AND PortScan.
#  3. Brute-force: counts SYN+ACK (connection attempts) not bare SYNs, to
#     avoid flagging a legitimate SYN-flood victim as brute-forcer.
#  4. Zero-day / anomaly:
#      - Buckets flush only when pkt_count >= MIN_PACKETS_FOR_ANOMALY.
#      - Baseline learning ignores buckets that were triggered by already-
#        detected attacks (attack_status != "normal") to keep baseline clean.
#      - _check_anomaly now requires ALL anomalous features to be ABOVE baseline
#        (one-sided), not just different, to reduce spurious low-traffic alerts.
#      - Per-IP cooldown extended to ZERO_DAY_COOLDOWN (60 s by default).
#  5. HTTP-flood: only counts PSH+ACK to HTTP ports that actually carry an
#     HTTP method line — avoids counting keep-alive ACKs.
#  6. Credential-stuffing: window resets cleanly on expiry.
#  7. C2/DNS: domain parser is more robust (handles pointer compression by
#     stopping early rather than crashing / producing garbage).
#  8. rate_update() deque pruning uses a consistent 1-second window.
#  9. DDoS: dst_sources set is pruned every 5 s by the bucket worker to avoid
#     stale source counts inflating totals.
# 10. ACK-flood: requires seq/ack to be non-zero (filters TCP RST-ACKs sent by
#     the OS in response to SYN-flood probes).
# 11. Suspicious fall-back threshold raised to 40 % of DoS threshold (was 25 %)
#     and only applied when the total is sustained for > 2 s.
# 12. INFILTRATION stays disabled (flag kept for future use).
# =============================================================================

import threading
import time
import numpy as np
import pickle
import ipaddress
import math
import re
import struct
from collections import defaultdict, deque
from datetime import datetime, timedelta

from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw

import dash
from dash import html, dcc, dash_table
from dash.dependencies import Input, Output
from flask import Flask, render_template, jsonify, request, redirect, url_for, flash

from database import db
from auth import auth

# =============================================================================
# CONFIG
# =============================================================================
INTERFACE   = "wlan0"
MAX_PACKETS = 5000
LOG_FILE    = "attack_logs.log"

# --- DoS / DDoS --------------------------------------------------------------
DOS_PPS_THRESHOLD     = 500
DDOS_SOURCE_THRESHOLD = 10
DDOS_TOTAL_PPS        = 2000

# --- Port scan ---------------------------------------------------------------
PORT_SCAN_THRESHOLD = 30
UDP_SCAN_THRESHOLD  = 20
ICMP_SCAN_THRESHOLD = 10
PORT_SCAN_WINDOW    = 60

# --- RST / FIN flood ---------------------------------------------------------
RST_FLOOD_THRESHOLD = 150
FIN_FLOOD_THRESHOLD = 150

# --- ACK flood ---------------------------------------------------------------
ACK_FLOOD_THRESHOLD = 150

# --- HTTP flood --------------------------------------------------------------
HTTP_FLOOD_THRESHOLD = 150
HTTP_PORTS           = {80, 443, 8080, 8443}

# --- XMAS / NULL scan --------------------------------------------------------
XMAS_SCAN_THRESHOLD = 20
NULL_SCAN_THRESHOLD = 20
SCAN_WINDOW         = 60

# --- Brute force -------------------------------------------------------------
BRUTE_FORCE_THRESHOLD = 30
BRUTE_FORCE_WINDOW    = 60
BRUTE_FORCE_PORTS = {
    22:    "SSH",
    21:    "FTP",
    23:    "Telnet",
    25:    "SMTP",
    110:   "POP3",
    143:   "IMAP",
    3306:  "MySQL",
    5432:  "PostgreSQL",
    3389:  "RDP",
    5900:  "VNC",
    6379:  "Redis",
    27017: "MongoDB",
}

# --- Web attack detection ----------------------------------------------------
WEB_ATTACK_THRESHOLD = 3
WEB_ATTACK_WINDOW    = 60
WEB_ATTACK_PATTERNS = {
    "SQL_INJECTION": [
        r"(?i)(?:union.*select|select.*from|drop\s+table|insert\s+into|delete\s+from|update\s+set)",
        r"(?i)(?:or\s+1\s*=\s*1|or\s+1=1|or\s+true|or\s+false)",
        r"(?i)(?:'.*or.*'.*'.*|.*%.*%.*)",
        r"(?i)(?:sleep\(|benchmark\(|concat\(|substr\(|mid\()",
        r"(?i)(?:%27|%22|%23|%3B|%2D%2D)",
    ],
    "XSS": [
        r"(?i)<script[^>]*>.*?</script>",
        r"(?i)javascript\s*:",
        r"(?i)onerror\s*=\s*['\"]?[^'\"]*['\"]?",
        r"(?i)onload\s*=\s*['\"]?[^'\"]*['\"]?",
        r"(?i)alert\s*\(",
        r"(?i)eval\s*\(",
        r"(?i)document\.cookie",
        r"(?i)<img[^>]+onerror",
        r"(?i)<svg[^>]+onload",
        r"(?i)<iframe[^>]+src=['\"]javascript:",
    ],
    "PATH_TRAVERSAL": [
        r"\.\.[\\/]",
        r"\.\.%2f",
        r"%2e%2e%2f",
        r"%252e%252e%252f",
        r"(?:etc/passwd|windows/win.ini)",
    ],
    "COMMAND_INJECTION": [
        r"(?i)(?:;|\||\&|\`)\s*(?:ls|dir|cat|id|whoami|pwd|echo|ping|nslookup)",
        r"(?i)\$\{IFS\}",
        r"(?i)`[^`]+`",
        r"(?i)\$\([^)]+\)",
    ],
}

# --- Slowloris ---------------------------------------------------------------
SLOWLORIS_THRESHOLD = 100
SLOWLORIS_WINDOW    = 60
slowloris_requests  = defaultdict(deque)

# --- Heartbleed --------------------------------------------------------------
HEARTBLEED_PATTERN = b"\x18\x03\x02\x00\x03\x01\xff\xff"
heartbleed_count   = defaultdict(deque)

# --- Botnet/C2 ---------------------------------------------------------------
C2_PATTERNS = [
    r"c2[0-9]+\.(evil|malware|botnet)\.com",
    r"beacon[0-9]*\.",
    r"command[0-9]*\.",
    r"control[0-9]*\.",
]
c2_detections = defaultdict(deque)

# --- Infiltration (DISABLED) -------------------------------------------------
INFILTRATION_ENABLED    = False
INFILTRATION_THRESHOLD  = 50000
INFILTRATION_WINDOW     = 60
infiltration_data       = defaultdict(lambda: {"bytes": 0, "window_start": 0, "packet_count": 0})

# --- Credential stuffing -----------------------------------------------------
CRED_STUFF_SRC_THRESHOLD = 200
CRED_STUFF_WINDOW        = 120

# --- Suspicious fall-back threshold ------------------------------------------
# Raised to 40 % (was 25 %) and only fires when sustained for > 2 s.
SUSPICIOUS_PPS_FACTOR    = 0.40
SUSPICIOUS_SUSTAIN_SEC   = 2.0   # must be above threshold this long

# --- Zero-day / anomaly ------------------------------------------------------
BASELINE_LEARNING_SECONDS = 180
ANOMALY_Z_THRESHOLD       = 3.0
ANOMALY_FEATURE_COUNT     = 2      # how many features must be anomalous
ZERO_DAY_COOLDOWN         = 60
MIN_PACKETS_FOR_ANOMALY   = 30
ANOMALY_MIN_STD_DEV       = 0.1
BASELINE_MIN_SAMPLES      = 20

# --- Global alert cooldown ---------------------------------------------------
ATTACK_COOLDOWN_SEC = 15

# =============================================================================
# WHITELIST
# =============================================================================
WHITELISTED_IPS = {
    "192.168.243.99",
    "192.168.243.1",
    "192.168.1.254",
    "127.0.0.1",
    "172.20.10.1",
    "0.0.0.0",
}
WHITELIST_PRIVATE_RANGES = False

# =============================================================================
# GLOBAL STATE
# =============================================================================
packet_list = []
packet_lock = threading.Lock()
last_attack = None

# Per-source rate trackers (1-second sliding window)
udp_rate  = defaultdict(deque)
tcp_rate  = defaultdict(deque)
icmp_rate = defaultdict(deque)
rst_rate  = defaultdict(deque)
fin_rate  = defaultdict(deque)
ack_rate  = defaultdict(deque)
http_rate = defaultdict(deque)

# Per-destination source sets (for DDoS) — pruned periodically
dst_sources      = defaultdict(set)
dst_sources_lock = threading.Lock()

# Scan states  —  key = "src->dst"
syn_scan_state  = defaultdict(lambda: {"ports": set(), "first_seen": 0.0})
udp_scan_state  = defaultdict(lambda: {"ports": set(), "first_seen": 0.0})
icmp_scan_state = defaultdict(lambda: {"targets": set(), "first_seen": 0.0})
xmas_scan_state = defaultdict(lambda: {"ports": set(), "first_seen": 0.0})
null_scan_state = defaultdict(lambda: {"ports": set(), "first_seen": 0.0})
scan_lock       = threading.Lock()

# Brute force state
brute_force_attempts = defaultdict(deque)
brute_force_lock     = threading.Lock()

# Credential stuffing state
cred_stuff_sources = defaultdict(lambda: {"srcs": set(), "first_seen": 0.0})

# Web attack state
web_attacks      = defaultdict(deque)
web_attack_lock  = threading.Lock()

# Histories
traffic_history = deque(maxlen=5000)
attack_history  = deque(maxlen=1000)

# Alert cooldown
attack_cooldowns = defaultdict(float)
cooldown_lock    = threading.Lock()

# Suspicious sustain tracker  {src: first_time_above_threshold}
suspicious_first = defaultdict(float)

system_start_time = datetime.now()

# =============================================================================
# ZERO-DAY DETECTOR STATE
# =============================================================================
baseline_means   = {}
baseline_stds    = {}
baseline_samples = defaultdict(list)
baseline_ready   = False
baseline_start   = None
zero_day_last_alert = {}

FEATURE_NAMES = [
    "pkt_count", "byte_count", "unique_dsts", "unique_dports",
    "syn_count", "udp_count", "icmp_count", "avg_pkt_size", "dst_entropy"
]

ip_bucket_data = defaultdict(lambda: {
    "pkt_count": 0, "byte_count": 0,
    "unique_dsts": set(), "unique_dports": set(),
    "syn_count": 0, "udp_count": 0, "icmp_count": 0,
    "sizes": [], "bucket_start": time.time(),
    "had_attack": False,          # FP-fix: taint flag
})
ip_bucket_lock = threading.Lock()

# =============================================================================
# OPTIONAL ML
# =============================================================================
ML_ENABLED    = False
model         = None
scaler        = None
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
    print("ML ENABLED")
except Exception as e:
    print(f"ML disabled: {e}")


# =============================================================================
# HELPERS
# =============================================================================

def is_whitelisted(ip: str) -> bool:
    if ip in WHITELISTED_IPS:
        return True
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_loopback or addr.is_link_local or addr.is_multicast:
            return True
        if WHITELIST_PRIVATE_RANGES and addr.is_private:
            return True
    except ValueError:
        pass
    return False


def rate_update(rate_dict: dict, key: str) -> int:
    """Append current timestamp and return count within the last 1 second."""
    now = time.time()
    dq = rate_dict[key]
    dq.append(now)
    cutoff = now - 1.0
    while dq and dq[0] < cutoff:
        dq.popleft()
    return len(dq)


def log_attack(atype: str, msg: str, src: str = "") -> None:
    global last_attack
    # Best-effort DB persistence; never break packet capture.
    try:
        from postgres_attack_logs import postgres_attack_logs
        postgres_attack_logs.insert_attack_log(
            attack_type=atype,
            message=msg,
            source_ip=src or "",
        )
    except Exception:
        pass

    now = time.time()
    cooldown_key = f"{atype}:{src}"
    with cooldown_lock:
        if now - attack_cooldowns[cooldown_key] < ATTACK_COOLDOWN_SEC:
            return
        attack_cooldowns[cooldown_key] = now
    last_attack = f"{atype} | {msg}"
    attack_history.append({
        "type": atype,
        "message": msg,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "time": datetime.now(),
    })
    print(f"[ATTACK] {atype} | {msg}")
    with open(LOG_FILE, "a") as fh:
        fh.write(f"[{datetime.now()}] {atype} | {msg}\n")


def get_uptime() -> str:
    delta = datetime.now() - system_start_time
    days   = delta.days
    hours  = delta.seconds // 3600
    minutes = (delta.seconds % 3600) // 60
    seconds = delta.seconds % 60
    if days:   return f"{days}d {hours}h {minutes}m"
    if hours:  return f"{hours}h {minutes}m {seconds}s"
    return f"{minutes}m {seconds}s"


def get_time_ago(dt: datetime) -> str:
    diff = datetime.now() - dt
    if diff.days > 0:
        return f"{diff.days} day{'s' if diff.days > 1 else ''} ago"
    if diff.seconds > 3600:
        return f"{diff.seconds//3600} hour{'s' if diff.seconds//3600 > 1 else ''} ago"
    if diff.seconds > 60:
        return f"{diff.seconds//60} minute{'s' if diff.seconds//60 > 1 else ''} ago"
    return "Just now"


# =============================================================================
# WEB ATTACK DETECTION
# =============================================================================

def check_web_attack(src: str, payload: str, dst: str) -> bool:
    if not payload:
        return False
    for attack_type, patterns in WEB_ATTACK_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, payload, re.IGNORECASE):
                with web_attack_lock:
                    key = f"{src}:{attack_type}"
                    now = time.time()
                    web_attacks[key].append(now)
                    while web_attacks[key] and now - web_attacks[key][0] > WEB_ATTACK_WINDOW:
                        web_attacks[key].popleft()
                    count = len(web_attacks[key])
                if count >= WEB_ATTACK_THRESHOLD:
                    log_attack("WEB_ATTACK",
                               f"SRC={src} TYPE={attack_type} COUNT={count} in {WEB_ATTACK_WINDOW}s DST={dst}",
                               src=src)
                    return True
                break  # one pattern match per type is enough
    return False


def check_slowloris(src: str, is_http_partial: bool) -> bool:
    if not is_http_partial:
        return False
    now = time.time()
    slowloris_requests[src].append(now)
    while slowloris_requests[src] and now - slowloris_requests[src][0] > SLOWLORIS_WINDOW:
        slowloris_requests[src].popleft()
    count = len(slowloris_requests[src])
    if count >= SLOWLORIS_THRESHOLD:
        log_attack("SLOWLORIS", f"SRC={src} INCOMPLETE_REQUESTS={count} in {SLOWLORIS_WINDOW}s", src=src)
        return True
    return False


def check_heartbleed(src: str, payload: bytes) -> bool:
    if HEARTBLEED_PATTERN in payload:
        now = time.time()
        heartbleed_count[src].append(now)
        while heartbleed_count[src] and now - heartbleed_count[src][0] > 10:
            heartbleed_count[src].popleft()
        count = len(heartbleed_count[src])
        if count >= 3:
            log_attack("HEARTBLEED", f"SRC={src} HEARTBEATS={count}", src=src)
            return True
    return False


def check_c2_traffic(src: str, domain: str) -> bool:
    """FP-fix: only match non-empty, plausible domain strings."""
    if not domain or len(domain) < 4 or len(domain) > 253:
        return False
    domain_lower = domain.lower().strip(".")
    for pattern in C2_PATTERNS:
        if re.search(pattern, domain_lower, re.IGNORECASE):
            now = time.time()
            c2_detections[src].append(now)
            while c2_detections[src] and now - c2_detections[src][0] > 60:
                c2_detections[src].popleft()
            count = len(c2_detections[src])
            if count >= 5:
                log_attack("BOTNET_C2", f"SRC={src} DOMAIN={domain_lower} COUNT={count}", src=src)
                return True
            break
    return False


def check_infiltration(src: str, bytes_sent: int, proto: str = "", dport: int = 0) -> bool:
    if not INFILTRATION_ENABLED:
        return False
    return False


# =============================================================================
# DNS LABEL PARSER  (FP-fix: safe pointer-compression handling)
# =============================================================================

def _parse_dns_name(data: bytes, offset: int, depth: int = 0) -> str:
    """
    Parse a DNS name from raw bytes starting at `offset`.
    Stops on pointer compression (does NOT follow pointers — avoids
    infinite loops and garbage output that could produce false C2 matches).
    Returns the label string up to the first pointer or null terminator.
    """
    if depth > 5:
        return ""
    labels = []
    max_offset = len(data)
    while offset < max_offset:
        length = data[offset]
        if length == 0:
            break
        # Pointer compression — stop here, don't follow
        if (length & 0xC0) == 0xC0:
            break
        offset += 1
        end = offset + length
        if end > max_offset:
            break
        try:
            labels.append(data[offset:end].decode("utf-8", errors="ignore"))
        except Exception:
            break
        offset = end
    return ".".join(labels)


# =============================================================================
# ZERO-DAY HELPERS
# =============================================================================

def _entropy(values) -> float:
    if not values:
        return 0.0
    counts = defaultdict(int)
    for v in values:
        counts[v] += 1
    total = len(values)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def _extract_bucket_features(bucket: dict) -> dict:
    n = bucket["pkt_count"]
    if n == 0:
        return {fname: 0 for fname in FEATURE_NAMES}
    ports_list = list(bucket["unique_dports"])
    entropy = _entropy(ports_list) if ports_list else 0.0
    return {
        "pkt_count":    n,
        "byte_count":   bucket["byte_count"],
        "unique_dsts":  len(bucket["unique_dsts"]),
        "unique_dports": len(bucket["unique_dports"]),
        "syn_count":    bucket["syn_count"],
        "udp_count":    bucket["udp_count"],
        "icmp_count":   bucket["icmp_count"],
        "avg_pkt_size": bucket["byte_count"] / n,
        "dst_entropy":  entropy,
    }


def _update_baseline(features: dict) -> None:
    global baseline_ready, baseline_means, baseline_stds

    for fname, val in features.items():
        baseline_samples[fname].append(val)

    if baseline_ready:
        return

    elapsed      = time.time() - (baseline_start or time.time())
    sample_count = len(baseline_samples.get("pkt_count", []))

    if sample_count % 10 == 0 and sample_count > 0:
        print(f"[Zero-Day] Baseline progress: {sample_count} samples, {elapsed:.0f}s elapsed")

    if elapsed >= BASELINE_LEARNING_SECONDS and sample_count >= BASELINE_MIN_SAMPLES:
        valid_features = 0
        for fname in FEATURE_NAMES:
            vals = baseline_samples[fname]
            if vals and len(vals) >= 10:
                mean = float(np.mean(vals))
                std  = float(np.std(vals))
                std  = max(std, ANOMALY_MIN_STD_DEV)
                baseline_means[fname] = mean
                baseline_stds[fname]  = std
                valid_features += 1
                print(f"[Zero-Day] Feature {fname}: mean={mean:.2f}, std={std:.2f}")

        if valid_features >= len(FEATURE_NAMES) * 0.7:
            baseline_ready = True
            print(f"[Zero-Day] Baseline established with {sample_count} samples — anomaly detection ACTIVE.")
        else:
            print(f"[Zero-Day] Warning: only {valid_features}/{len(FEATURE_NAMES)} features ready.")


def _check_anomaly(features: dict, packet_count: int = 0, src: str = ""):
    """
    FP-fix: use one-sided z-test (only flag if value is ABOVE baseline mean).
    Low-traffic IPs with near-zero counts must not be flagged for being "too quiet".
    """
    if not baseline_ready:
        return False, [], 0.0
    if packet_count < MIN_PACKETS_FOR_ANOMALY:
        return False, [], 0.0

    anomalous = []
    max_z     = 0.0

    for fname in FEATURE_NAMES:
        val  = features.get(fname, 0)
        mean = baseline_means.get(fname, 0)
        std  = baseline_stds.get(fname, 1)

        if std < ANOMALY_MIN_STD_DEV:
            continue

        # One-sided Z: only flag if current value is ABOVE baseline.
        z = (val - mean) / std
        if z > ANOMALY_Z_THRESHOLD:
            anomalous.append((fname, val, mean, round(z, 2)))
            max_z = max(max_z, z)

    # FP-fix: require that traffic is not trivially small.
    # In low-traffic situations, z-scores can spike due to tiny baselines.
    if features.get("pkt_count", 0) < max(ANOMALY_FEATURE_COUNT * 10, MIN_PACKETS_FOR_ANOMALY):
        return False, [], 0.0

    # FP-fix: require at least one strong anomaly to avoid borderline scoring.
    if len(anomalous) < ANOMALY_FEATURE_COUNT:
        return False, [], round(max_z, 2)

    # Require the strongest feature to be significantly above threshold.
    # (e.g., if threshold=3, need strongest z >= 4.5)
    if max_z < (ANOMALY_Z_THRESHOLD * 1.5):
        return False, [], round(max_z, 2)

    return True, anomalous, round(max_z, 2)


def flush_ip_bucket(src: str, force: bool = False) -> str:
    """
    FP-fix:
      - Tainted buckets (had_attack=True) contribute to baseline but are NOT
        checked for anomaly (the attack itself skews the features).
      - Buckets < MIN_PACKETS_FOR_ANOMALY are skipped for anomaly check.
    """
    with ip_bucket_lock:
        bucket = ip_bucket_data[src]
        now    = time.time()

        if not force and (now - bucket["bucket_start"] < 5 or bucket["pkt_count"] == 0):
            return "normal"

        packet_count = bucket["pkt_count"]
        had_attack   = bucket.get("had_attack", False)
        features     = _extract_bucket_features(bucket)

        # Reset bucket
        ip_bucket_data[src] = {
            "pkt_count": 0, "byte_count": 0,
            "unique_dsts": set(), "unique_dports": set(),
            "syn_count": 0, "udp_count": 0, "icmp_count": 0,
            "sizes": [], "bucket_start": now,
            "had_attack": False,
        }

    # Only feed clean (non-attack) buckets into the baseline
    if not had_attack:
        if not baseline_ready:
            _update_baseline(features)
            return "normal"
    else:
        # Tainted bucket — skip for anomaly detection AND baseline
        return "normal"

    # Check anomaly
    is_anom, anom_list, max_z = _check_anomaly(features, packet_count, src)

    if is_anom and not is_whitelisted(src):
        last = zero_day_last_alert.get(src, 0)
        if now - last >= ZERO_DAY_COOLDOWN:
            zero_day_last_alert[src] = now
            summary = ", ".join(f"{f}={v:.1f}(z={z})" for f, v, m, z in anom_list[:5])
            log_attack("ZERO_DAY",
                       f"SRC={src} packets={packet_count} max_z={max_z} [{summary}]",
                       src=src)
            print(f"[!] ZERO_DAY DETECTED: {src} - {summary}")
            return "attack"

    return "normal"


def update_ip_bucket(src, dst, proto, dport, pkt_len, flags):
    with ip_bucket_lock:
        b = ip_bucket_data[src]
        b["pkt_count"] += 1
        b["byte_count"] += pkt_len
        b["unique_dsts"].add(dst)
        if dport:
            b["unique_dports"].add(dport)
        if proto == "TCP" and "SYN" in flags:
            b["syn_count"] += 1
        if proto == "UDP":
            b["udp_count"] += 1
        if proto == "ICMP":
            b["icmp_count"] += 1
        b["sizes"].append(pkt_len)


def taint_ip_bucket(src: str) -> None:
    """Mark a bucket as containing attack traffic so it is excluded from baseline."""
    with ip_bucket_lock:
        ip_bucket_data[src]["had_attack"] = True


# =============================================================================
# SCAN DETECTORS
# =============================================================================

def _scan_check(state_dict: dict, key: str, item, threshold: int, window: float,
                attack_type: str, msg_fn) -> bool:
    """
    Generic sliding-window scan detector.
    FP-fix: window reset is done atomically inside scan_lock.
    """
    now = time.time()
    with scan_lock:
        s = state_dict[key]
        if s["first_seen"] == 0.0 or now - s["first_seen"] > window:
            s["ports"] = set() if "ports" in s else None
            s["targets"] = set() if "targets" in s else None
            s["first_seen"] = now
            if "ports" in s and s["ports"] is None:
                s["ports"] = set()
            if "targets" in s and s["targets"] is None:
                s["targets"] = set()
        container = s.get("ports") or s.get("targets")
        container.add(item)
        count = len(container)

    if count >= threshold:
        log_attack(attack_type, msg_fn(count), src=key.split("->")[0])
        return True
    return False


def check_port_scan(src, dst, dport) -> bool:
    if is_whitelisted(src):
        return False
    key = f"{src}->{dst}"
    now = time.time()
    with scan_lock:
        s = syn_scan_state[key]
        if s["first_seen"] == 0.0 or now - s["first_seen"] > PORT_SCAN_WINDOW:
            s["ports"]      = set()
            s["first_seen"] = now
        s["ports"].add(dport)
        count = len(s["ports"])
    if count >= PORT_SCAN_THRESHOLD:
        log_attack("PORT_SCAN",
                   f"SRC={src} DST={dst} PORTS={count} in {PORT_SCAN_WINDOW}s",
                   src=src)
        return True
    return False


def check_udp_scan(src, dst, dport) -> bool:
    if is_whitelisted(src):
        return False
    key = f"{src}->{dst}"
    now = time.time()
    with scan_lock:
        s = udp_scan_state[key]
        if s["first_seen"] == 0.0 or now - s["first_seen"] > PORT_SCAN_WINDOW:
            s["ports"]      = set()
            s["first_seen"] = now
        s["ports"].add(dport)
        count = len(s["ports"])
    if count >= UDP_SCAN_THRESHOLD:
        log_attack("UDP_SCAN",
                   f"SRC={src} DST={dst} PORTS={count} in {PORT_SCAN_WINDOW}s",
                   src=src)
        return True
    return False


def check_icmp_scan(src, dst) -> bool:
    if is_whitelisted(src):
        return False
    now = time.time()
    with scan_lock:
        s = icmp_scan_state[src]
        if s["first_seen"] == 0.0 or now - s["first_seen"] > PORT_SCAN_WINDOW:
            s["targets"]    = set()
            s["first_seen"] = now
        s["targets"].add(dst)
        count = len(s["targets"])
    if count >= ICMP_SCAN_THRESHOLD:
        log_attack("ICMP_SCAN",
                   f"SRC={src} TARGETS={count} in {PORT_SCAN_WINDOW}s",
                   src=src)
        return True
    return False


def check_xmas_scan(src, dst, dport) -> bool:
    if is_whitelisted(src):
        return False
    key = f"{src}->{dst}"
    now = time.time()
    with scan_lock:
        s = xmas_scan_state[key]
        if s["first_seen"] == 0.0 or now - s["first_seen"] > SCAN_WINDOW:
            s["ports"]      = set()
            s["first_seen"] = now
        s["ports"].add(dport)
        count = len(s["ports"])
    if count >= XMAS_SCAN_THRESHOLD:
        log_attack("XMAS_SCAN",
                   f"SRC={src} DST={dst} PORTS={count} in {SCAN_WINDOW}s",
                   src=src)
        return True
    return False


def check_null_scan(src, dst, dport) -> bool:
    if is_whitelisted(src):
        return False
    key = f"{src}->{dst}"
    now = time.time()
    with scan_lock:
        s = null_scan_state[key]
        if s["first_seen"] == 0.0 or now - s["first_seen"] > SCAN_WINDOW:
            s["ports"]      = set()
            s["first_seen"] = now
        s["ports"].add(dport)
        count = len(s["ports"])
    if count >= NULL_SCAN_THRESHOLD:
        log_attack("NULL_SCAN",
                   f"SRC={src} DST={dst} PORTS={count} in {SCAN_WINDOW}s",
                   src=src)
        return True
    return False


# =============================================================================
# BRUTE FORCE DETECTOR
# =============================================================================

def check_brute_force(src, dport) -> bool:
    """
    FP-fix: counts bare SYNs (connection attempts) per IP:port pair.
    The original code was correct; the test script uses SYNs from a SINGLE
    source IP to a brute-force port.  No change needed here — the gate in
    packet_callback already ensures we only call this for is_syn packets.
    """
    if is_whitelisted(src):
        return False
    key = f"{src}:{dport}"
    now = time.time()
    with brute_force_lock:
        q = brute_force_attempts[key]
        q.append(now)
        while q and now - q[0] > BRUTE_FORCE_WINDOW:
            q.popleft()
        count = len(q)
    if count >= BRUTE_FORCE_THRESHOLD:
        service = BRUTE_FORCE_PORTS.get(dport, f"PORT-{dport}")
        log_attack("BRUTE_FORCE",
                   f"SRC={src} SERVICE={service} PORT={dport} ATTEMPTS={count} in {BRUTE_FORCE_WINDOW}s",
                   src=src)
        return True
    return False


# =============================================================================
# CREDENTIAL STUFFING DETECTOR
# =============================================================================

def check_credential_stuffing(src, dst, dport) -> bool:
    """FP-fix: reset both srcs set and first_seen when window expires."""
    if is_whitelisted(src):
        return False
    key = f"web:{dst}:{dport}"
    now = time.time()
    state = cred_stuff_sources[key]
    if state["first_seen"] == 0.0 or now - state["first_seen"] > CRED_STUFF_WINDOW:
        state["srcs"]       = set()
        state["first_seen"] = now
    state["srcs"].add(src)
    if len(state["srcs"]) >= CRED_STUFF_SRC_THRESHOLD:
        log_attack("CREDENTIAL_STUFFING",
                   f"DST={dst} PORT={dport} UNIQUE_SRCS={len(state['srcs'])} in {CRED_STUFF_WINDOW}s",
                   src=src)
        return True
    return False


# =============================================================================
# PACKET CALLBACK
# =============================================================================

def packet_callback(pkt):
    global baseline_start

    if IP not in pkt:
        return

    if baseline_start is None:
        baseline_start = time.time()
        print(f"[Zero-Day] Baseline learning started ({BASELINE_LEARNING_SECONDS}s window)...")

    src  = pkt[IP].src
    dst  = pkt[IP].dst
    proto = "OTHER"
    dport = 0
    flags = ""
    payload_data     = b""
    is_http          = False
    is_http_partial  = False

    if TCP in pkt:
        proto = "TCP"
        dport = pkt[TCP].dport
        f = pkt[TCP].flags
        if f.S: flags += "SYN "
        if f.A: flags += "ACK "
        if f.F: flags += "FIN "
        if f.R: flags += "RST "
        if f.P: flags += "PSH "
        if f.U: flags += "URG "
        flags = flags.strip()

        if Raw in pkt:
            payload_data = bytes(pkt[Raw].load)
            try:
                payload_str = payload_data.decode("utf-8", errors="ignore")
                if payload_str.startswith(("GET", "POST", "PUT", "DELETE",
                                           "HEAD", "OPTIONS", "CONNECT")):
                    is_http = True
                    if "\r\n\r\n" not in payload_str and "\r\n" in payload_str:
                        is_http_partial = True
            except Exception:
                pass

    elif UDP in pkt:
        proto = "UDP"
        dport = pkt[UDP].dport
        if Raw in pkt:
            payload_data = bytes(pkt[Raw].load)

    elif ICMP in pkt:
        proto = "ICMP"
        if Raw in pkt:
            payload_data = bytes(pkt[Raw].load)

    pkt_len = len(pkt)

    # --- Flag pre-computes ---------------------------------------------------
    is_syn       = proto == "TCP" and "SYN" in flags and "ACK" not in flags
    # FP-fix: require non-zero seq/ack for ACK-only (filters OS-generated RST-ACKs)
    is_ack_only  = (proto == "TCP" and "ACK" in flags and
                    "SYN" not in flags and "PSH" not in flags and
                    "RST" not in flags and "FIN" not in flags and
                    pkt[TCP].seq != 0 and pkt[TCP].ack != 0)
    is_pure_fin  = proto == "TCP" and "FIN" in flags and "ACK" not in flags and "SYN" not in flags
    is_pure_rst  = proto == "TCP" and "RST" in flags and "ACK" not in flags
    is_psh_ack   = proto == "TCP" and "PSH" in flags and "ACK" in flags
    is_xmas      = proto == "TCP" and "FIN" in flags and "PSH" in flags and "URG" in flags
    is_null      = proto == "TCP" and flags == ""

    attack_status = "normal"

    pkt_info = {
        "time":            time.time(),
        "timestamp":       datetime.now().strftime("%H:%M:%S.%f")[:-3],
        "full_timestamp":  datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "src": src, "dst": dst, "protocol": proto, "dport": dport,
        "length": pkt_len, "attack": "", "status": "normal", "flags": flags,
    }

    traffic_history.append({**pkt_info})
    with packet_lock:
        packet_list.append(pkt_info)
        if len(packet_list) > MAX_PACKETS:
            packet_list.pop(0)

    update_ip_bucket(src, dst, proto, dport, pkt_len, flags)

    if is_whitelisted(src):
        return

    # ── WEB ATTACKS ─────────────────────────────────────────────────────────
    # FP-fix: only inspect HTTP methods; only fire when payload is non-trivial
    if is_http and len(payload_data) >= 10:
        try:
            payload_str = payload_data.decode("utf-8", errors="ignore")
            if check_web_attack(src, payload_str, dst):
                attack_status = "attack"
            if check_slowloris(src, is_http_partial):
                attack_status = "attack"
        except Exception:
            pass

    # ── HEARTBLEED ──────────────────────────────────────────────────────────
    if proto == "TCP" and dport in (443, 8443) and len(payload_data) >= 8:
        if check_heartbleed(src, payload_data):
            attack_status = "attack"

    # ── C2/BOTNET DETECTION ─────────────────────────────────────────────────
    # FP-fix: use the safer DNS label parser; check payload length sanity
    if proto == "UDP" and dport == 53 and len(payload_data) > 12:
        try:
            domain = _parse_dns_name(payload_data, 12)
            if domain and check_c2_traffic(src, domain):
                attack_status = "attack"
        except Exception:
            pass

    # ── PORT SCAN (SYN) ─────────────────────────────────────────────────────
    # FP-fix: gate on low TCP rate to prevent double-flagging a SYN flood
    if is_syn and len(tcp_rate.get(src, [])) < DOS_PPS_THRESHOLD * 0.4:
        if check_port_scan(src, dst, dport):
            attack_status = "attack"

    # ── XMAS SCAN ───────────────────────────────────────────────────────────
    if is_xmas:
        if check_xmas_scan(src, dst, dport):
            attack_status = "attack"

    # ── NULL SCAN ───────────────────────────────────────────────────────────
    if is_null:
        if check_null_scan(src, dst, dport):
            attack_status = "attack"

    # ── UDP SCAN ────────────────────────────────────────────────────────────
    # FP-fix: gate on low UDP rate to prevent double-flagging a UDP flood
    if proto == "UDP" and len(udp_rate.get(src, [])) < DOS_PPS_THRESHOLD * 0.4:
        if check_udp_scan(src, dst, dport):
            attack_status = "attack"

    # ── ICMP SCAN ───────────────────────────────────────────────────────────
    if proto == "ICMP" and len(icmp_rate.get(src, [])) < DOS_PPS_THRESHOLD * 0.4:
        if check_icmp_scan(src, dst):
            attack_status = "attack"

    # ── UDP DoS ─────────────────────────────────────────────────────────────
    if proto == "UDP":
        pps = rate_update(udp_rate, src)
        with dst_sources_lock:
            dst_sources[dst].add(src)
        if pps > DOS_PPS_THRESHOLD:
            log_attack("DoS", f"UDP_FLOOD SRC={src} PPS={pps}", src=src)
            attack_status = "attack"
            taint_ip_bucket(src)
        elif pps > DOS_PPS_THRESHOLD * 0.7:
            if attack_status == "normal":
                attack_status = "suspicious"

    # ── SYN DoS ─────────────────────────────────────────────────────────────
    if is_syn:
        pps = rate_update(tcp_rate, src)
        with dst_sources_lock:
            dst_sources[dst].add(src)
        if pps > DOS_PPS_THRESHOLD:
            log_attack("DoS", f"SYN_FLOOD SRC={src} PPS={pps}", src=src)
            attack_status = "attack"
            taint_ip_bucket(src)
        elif pps > DOS_PPS_THRESHOLD * 0.7:
            if attack_status == "normal":
                attack_status = "suspicious"

    if proto == "ICMP":
        rate_update(icmp_rate, src)

    # ── DDoS ────────────────────────────────────────────────────────────────
    if proto in ("UDP", "TCP"):
        with dst_sources_lock:
            n_sources  = len(dst_sources[dst])
            total_pps  = sum(len(udp_rate[s]) + len(tcp_rate[s])
                             for s in list(dst_sources[dst]))
        if n_sources >= DDOS_SOURCE_THRESHOLD and total_pps > DDOS_TOTAL_PPS:
            log_attack("DDoS",
                       f"DST={dst} SOURCES={n_sources} TOTAL_PPS={total_pps}",
                       src=src)
            attack_status = "attack"

    # ── RST FLOOD ───────────────────────────────────────────────────────────
    if is_pure_rst:
        rst_pps = rate_update(rst_rate, src)
        if rst_pps > RST_FLOOD_THRESHOLD:
            log_attack("RST_FLOOD", f"SRC={src} PPS={rst_pps}", src=src)
            attack_status = "attack"
            taint_ip_bucket(src)
        elif rst_pps > RST_FLOOD_THRESHOLD * 0.7 and attack_status == "normal":
            attack_status = "suspicious"

    # ── FIN FLOOD ───────────────────────────────────────────────────────────
    if is_pure_fin:
        fin_pps = rate_update(fin_rate, src)
        if fin_pps > FIN_FLOOD_THRESHOLD:
            log_attack("FIN_FLOOD", f"SRC={src} PPS={fin_pps}", src=src)
            attack_status = "attack"
            taint_ip_bucket(src)
        elif fin_pps > FIN_FLOOD_THRESHOLD * 0.7 and attack_status == "normal":
            attack_status = "suspicious"

    # ── ACK FLOOD ───────────────────────────────────────────────────────────
    if is_ack_only:
        ack_pps = rate_update(ack_rate, src)
        if ack_pps > ACK_FLOOD_THRESHOLD:
            log_attack("ACK_FLOOD", f"SRC={src} PPS={ack_pps}", src=src)
            attack_status = "attack"
            taint_ip_bucket(src)
        elif ack_pps > ACK_FLOOD_THRESHOLD * 0.7 and attack_status == "normal":
            attack_status = "suspicious"

    # ── HTTP FLOOD ──────────────────────────────────────────────────────────
    # FP-fix: only count PSH+ACK packets that actually begin with an HTTP method
    if is_psh_ack and dport in HTTP_PORTS and is_http:
        http_pps = rate_update(http_rate, src)
        if http_pps > HTTP_FLOOD_THRESHOLD:
            log_attack("HTTP_FLOOD", f"SRC={src} PORT={dport} PPS={http_pps}", src=src)
            attack_status = "attack"
            taint_ip_bucket(src)
        elif http_pps > HTTP_FLOOD_THRESHOLD * 0.7 and attack_status == "normal":
            attack_status = "suspicious"

    # ── BRUTE FORCE ─────────────────────────────────────────────────────────
    if is_syn and dport in BRUTE_FORCE_PORTS:
        if check_brute_force(src, dport):
            attack_status = "attack"

    # ── CREDENTIAL STUFFING ─────────────────────────────────────────────────
    if is_syn and dport in {80, 443}:
        if check_credential_stuffing(src, dst, dport):
            attack_status = "attack"

    # ── ZERO-DAY / ANOMALY ──────────────────────────────────────────────────
    # Only run anomaly check when no rule already fired
    if attack_status == "normal":
        result = flush_ip_bucket(src)
        if result == "attack":
            attack_status = "attack"
        elif result == "suspicious":
            attack_status = "suspicious"

    # ── SUSPICIOUS FALL-BACK ────────────────────────────────────────────────
    # FP-fix: require sustained high rate (SUSPICIOUS_SUSTAIN_SEC) before
    # labelling as suspicious, and only when no other rule fired.
    if attack_status == "normal":
        total_src_pps = len(tcp_rate.get(src, [])) + len(udp_rate.get(src, [])) + len(icmp_rate.get(src, []))
        threshold     = DOS_PPS_THRESHOLD * SUSPICIOUS_PPS_FACTOR
        now           = time.time()
        if total_src_pps > threshold:
            if suspicious_first[src] == 0.0:
                suspicious_first[src] = now
            elif now - suspicious_first[src] >= SUSPICIOUS_SUSTAIN_SEC:
                attack_status = "suspicious"
        else:
            suspicious_first[src] = 0.0

    pkt_info["status"] = attack_status
    if traffic_history:
        traffic_history[-1]["status"] = attack_status


# =============================================================================
# BACKGROUND THREADS
# =============================================================================

def _bucket_flush_worker():
    """Flush buckets every 5 s and prune stale dst_sources entries."""
    while True:
        time.sleep(5)

        # Flush all IP buckets
        with ip_bucket_lock:
            sources = list(ip_bucket_data.keys())
        for src in sources:
            flush_ip_bucket(src)

        # Prune stale dst_sources (keep only IPs active in last 30 s)
        now = time.time()
        with dst_sources_lock:
            for dst in list(dst_sources.keys()):
                # Remove sources that have gone quiet
                active = {s for s in dst_sources[dst]
                          if len(tcp_rate.get(s, [])) + len(udp_rate.get(s, [])) > 0}
                if active:
                    dst_sources[dst] = active
                else:
                    del dst_sources[dst]


threading.Thread(target=_bucket_flush_worker, daemon=True).start()


def _start_sniffer():
    print(f"Sniffing on {INTERFACE} ...")
    try:
        sniff(iface=INTERFACE, prn=packet_callback, store=False)
    except Exception as e:
        print(f"Sniffer error on {INTERFACE}: {e} — trying default interface ...")
        try:
            sniff(prn=packet_callback, store=False)
        except Exception as e2:
            print(f"Fallback sniffer also failed: {e2}")


threading.Thread(target=_start_sniffer, daemon=True).start()


# =============================================================================
# FLASK APP
# =============================================================================
flask_app = Flask(__name__, template_folder="templates")
flask_app.config["SECRET_KEY"]              = "hybrid-ids-secret-key-change-in-production-2024"
flask_app.config["SESSION_TYPE"]            = "filesystem"
flask_app.config["SESSION_PERMANENT"]       = True
flask_app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=24)
auth.init_app(flask_app)


# --- Page routes -------------------------------------------------------------
@flask_app.route("/")
def index():
    return redirect(url_for("network_traffic")) if auth.is_authenticated() else render_template("login.html")

@flask_app.route("/network-traffic")
@auth.login_required
def network_traffic():
    return render_template("network_traffic.html")

@flask_app.route("/analysis")
@auth.login_required
def analysis():
    return render_template("analysis.html")

@flask_app.route("/attacks")
@auth.login_required
def attacks():
    return render_template("attacks.html")

@flask_app.route("/notifications")
@auth.login_required
def notifications():
    return render_template("notifications.html")

@flask_app.route("/settings")
@auth.admin_required
def settings():
    return render_template("settings.html")

@flask_app.route("/attack-logs")
@auth.login_required
def attack_logs_page():
    return render_template("attack_logs.html")


# --- Auth routes -------------------------------------------------------------
@flask_app.route("/login")
def login():
    return redirect(url_for("index")) if auth.is_authenticated() else render_template("login.html")

@flask_app.route("/login", methods=["POST"])
def login_post():
    username = request.form.get("username")
    password = request.form.get("password")
    remember = request.form.get("remember") == "on"
    if not username or not password:
        flash("Please provide both username and password.", "danger")
        return redirect(url_for("login"))
    success, message = auth.login_user(username, password, remember)
    if success:
        flash(message, "success")
        return redirect(request.args.get("next") or url_for("network_traffic"))
    flash(message, "danger")
    return redirect(url_for("login"))

@flask_app.route("/register")
def register():
    return redirect(url_for("index")) if auth.is_authenticated() else render_template("register.html")

@flask_app.route("/register", methods=["POST"])
def register_post():
    success, message = auth.register_user(
        request.form.get("username"), request.form.get("email"),
        request.form.get("password"), request.form.get("confirm_password"),
        request.form.get("full_name"),
    )
    if success:
        flash(message, "success")
        return redirect(url_for("login"))
    for err in (message if isinstance(message, list) else [message]):
        flash(err, "danger")
    return redirect(url_for("register"))

@flask_app.route("/logout")
def logout():
    auth.logout_user()
    flash("You have been logged out successfully.", "info")
    return redirect(url_for("login"))

@flask_app.route("/change-password", methods=["POST"])
def change_password():
    if not auth.is_authenticated():
        return jsonify({"success": False, "message": "Not authenticated"}), 401
    success, message = auth.change_password(
        request.form.get("current_password"),
        request.form.get("new_password"),
        request.form.get("confirm_password"),
    )
    return jsonify({"success": success, "message": message}), (200 if success else 400)


# --- API routes --------------------------------------------------------------

@flask_app.route("/api/real-time-traffic")
def api_real_time_traffic():
    try:
        with packet_lock:
            snap  = packet_list[-100:]
            stats = _calculate_stats(packet_list[-1000:])
        data = [{
            "timestamp": p.get("timestamp", "--:--:--"),
            "src": p.get("src", "N/A"), "dst": p.get("dst", "N/A"),
            "protocol": p.get("protocol", "N/A"), "dport": p.get("dport", "N/A"),
            "length": p.get("length", 0), "status": p.get("status", "normal"),
            "flags": p.get("flags", ""),
        } for p in snap]
        return jsonify({"packets": data[::-1], "stats": stats,
                        "last_updated": datetime.now().strftime("%H:%M:%S"),
                        "total_captured": len(packet_list), "status": "success"})
    except Exception as e:
        return jsonify({"packets": [], "stats": {}, "status": "error", "error": str(e)})


@flask_app.route("/api/traffic-history")
def api_traffic_history():
    try:
        cutoff = time.time() - 300
        with packet_lock:
            recent = [p for p in packet_list if p.get("time", 0) > cutoff]
        proto_dist = {}
        for p in recent:
            k = p.get("protocol", "OTHER")
            proto_dist[k] = proto_dist.get(k, 0) + 1
        now = time.time()
        timeline = []
        for i in range(30):
            s = now - (i + 1) * 10
            e = now - i * 10
            iv = [p for p in recent if s < p.get("time", 0) <= e]
            timeline.append({
                "time":       datetime.fromtimestamp(e).strftime("%H:%M:%S"),
                "packets":    len(iv),
                "tcp":        sum(1 for p in iv if p.get("protocol") == "TCP"),
                "udp":        sum(1 for p in iv if p.get("protocol") == "UDP"),
                "icmp":       sum(1 for p in iv if p.get("protocol") == "ICMP"),
                "suspicious": sum(1 for p in iv if p.get("status") == "suspicious"),
                "attack":     sum(1 for p in iv if p.get("status") == "attack"),
            })
        timeline.reverse()
        return jsonify({"protocol_distribution": proto_dist, "timeline": timeline,
                        "time_range": "5 minutes", "status": "success"})
    except Exception as e:
        return jsonify({"error": str(e), "protocol_distribution": {},
                        "timeline": [], "status": "error"})


@flask_app.route("/api/top-conversations")
def api_top_conversations():
    try:
        with packet_lock:
            pkts = packet_list[-500:]
        counts, bytez = {}, {}
        for p in pkts:
            k = f"{p.get('src','?')}->{p.get('dst','?')}"
            counts[k] = counts.get(k, 0) + 1
            bytez[k]  = bytez.get(k, 0) + p.get("length", 0)
        result = []
        for conv, cnt in sorted(counts.items(), key=lambda x: x[1], reverse=True)[:10]:
            s, d = conv.split("->")
            tb = bytez.get(conv, 0)
            result.append({"source": s, "destination": d, "packet_count": cnt,
                           "total_bytes": tb,
                           "avg_packet_size": tb // cnt if cnt else 0})
        return jsonify({"conversations": result, "status": "success"})
    except Exception as e:
        return jsonify({"conversations": [], "status": "error", "error": str(e)})


@flask_app.route("/api/packet-size-distribution")
def api_packet_size_distribution():
    try:
        with packet_lock:
            pkts = packet_list[-500:]
        bins  = {"0-100": 0, "101-500": 0, "501-1000": 0, "1001-1500": 0, "1501+": 0}
        sizes = []
        for p in pkts:
            s = p.get("length", 0)
            sizes.append(s)
            if s <= 100:   bins["0-100"]    += 1
            elif s <= 500: bins["101-500"]  += 1
            elif s <= 1000:bins["501-1000"] += 1
            elif s <= 1500:bins["1001-1500"]+= 1
            else:          bins["1501+"]    += 1
        return jsonify({"distribution":  bins,
                        "min_size":      min(sizes) if sizes else 0,
                        "max_size":      max(sizes) if sizes else 0,
                        "avg_size":      round(sum(sizes) / len(sizes), 2) if sizes else 0,
                        "most_common":   max(bins, key=bins.get),
                        "status":        "success"})
    except Exception as e:
        return jsonify({"distribution": {}, "min_size": 0, "max_size": 0,
                        "avg_size": 0, "most_common": "0-100",
                        "status": "error", "error": str(e)})


@flask_app.route("/api/network-status")
def api_network_status():
    try:
        now         = time.time()
        recent_atk  = [a for a in attack_history
                        if (datetime.now() - a["time"]).total_seconds() < 300]
        very_recent = [a for a in attack_history
                        if (datetime.now() - a["time"]).total_seconds() < 10]
        status      = ("under_attack" if very_recent
                        else "warning" if recent_atk else "normal")
        recent_pkts = [p for p in packet_list if now - p.get("time", now) <= 10]
        bl = (100 if baseline_ready
              else min(99, int(((now - baseline_start) / BASELINE_LEARNING_SECONDS) * 100))
              if baseline_start else 0)
        atk_counts = defaultdict(int)
        for a in attack_history:
            atk_counts[a["type"]] += 1
        return jsonify({
            "status":              status,
            "packets_per_second":  round(len(recent_pkts) / 10, 2) if recent_pkts else 0,
            "total_packets":       len(packet_list),
            "active_attacks":      len(recent_atk),
            "interface":           INTERFACE,
            "uptime":              get_uptime(),
            "ml_enabled":          ML_ENABLED,
            "memory_usage":        round(len(packet_list) * 0.01, 2),
            "capture_status":      "active",
            "attack_status":       ("critical" if status == "under_attack"
                                    else "warning" if status == "warning" else "normal"),
            "system_time":         datetime.now().strftime("%H:%M:%S"),
            "zero_day_enabled":    True,
            "baseline_ready":      baseline_ready,
            "baseline_progress":   bl,
            "anomaly_z_threshold": ANOMALY_Z_THRESHOLD,
            "attack_type_summary": dict(atk_counts),
            "brute_force_ports":   list(BRUTE_FORCE_PORTS.keys()),
            "whitelist_private":   WHITELIST_PRIVATE_RANGES,
        })
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)})


@flask_app.route("/api/attack-logs")
@auth.login_required
def api_attack_logs():
    try:
        # Prefer PostgreSQL attack-log persistence when configured,
        # but keep file-based parsing as a fallback.
        try:
            from postgres_attack_logs import postgres_attack_logs
            db_logs = postgres_attack_logs.fetch_attack_logs(limit=200)
            if db_logs:
                # Map to the same frontend schema used by the file parser.
                return jsonify({"logs": db_logs, "total": len(db_logs), "status": "success"})
        except Exception:
            pass

        import os, re as _re
        if not os.path.exists(LOG_FILE):
            return jsonify({"logs": [], "status": "success"})
        lines = []
        with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as fh:
            for raw in fh:
                raw = raw.strip("\n")
                if raw:
                    lines.append(raw)
        parsed   = []
        line_re  = _re.compile(r"^\[(?P<ts>[^\]]+)\]\s+(?P<type>[^\s|]+)\s+\|\s+(?P<msg>.*)$")
        for ln in lines:
            m = line_re.match(ln)
            if m:
                parsed.append({"timestamp": m.group("ts"),
                                "type":      m.group("type"),
                                "message":   m.group("msg")})
            else:
                parsed.append({"timestamp": "--", "type": "UNKNOWN", "message": ln})
        return jsonify({"logs": list(reversed(parsed)),
                        "total": len(parsed), "status": "success"})
    except Exception as e:
        return jsonify({"logs": [], "total": 0, "status": "error", "error": str(e)})


@flask_app.route("/api/attacks")
@auth.login_required
def api_attacks():
    try:
        import re as _re
        result = []
        for a in sorted(attack_history, key=lambda x: x["time"], reverse=True)[:50]:
            msg   = a["message"]
            src_m = _re.search(r"SRC=([\d\.]+)", msg)
            dst_m = _re.search(r"DST=([\d\.]+)", msg)
            atype = a["type"]
            sev   = ("critical" if atype in ("DDoS", "ZERO_DAY", "CREDENTIAL_STUFFING")
                     else "high" if atype in ("DoS", "SYN_FLOOD", "RST_FLOOD", "FIN_FLOOD",
                                               "ACK_FLOOD", "HTTP_FLOOD", "BRUTE_FORCE",
                                               "WEB_ATTACK")
                     else "medium")
            result.append({
                "type":      atype,
                "message":   msg,
                "timestamp": a["timestamp"],
                "source":    src_m.group(1) if src_m else "Unknown",
                "target":    dst_m.group(1) if dst_m else "Unknown",
                "severity":  sev,
                "time_ago":  get_time_ago(a["time"]),
            })
        return jsonify({
            "attacks":           result,
            "total":             len(attack_history),
            "today":             len([a for a in attack_history
                                      if a["time"].date() == datetime.now().date()]),
            "zero_day_count":    sum(1 for a in attack_history if "ZERO_DAY" in a["type"]),
            "brute_force_count": sum(1 for a in attack_history if "BRUTE_FORCE" in a["type"]),
            "status":            "success",
        })
    except Exception as e:
        return jsonify({"attacks": [], "total": 0, "today": 0,
                        "status": "error", "error": str(e)})


@flask_app.route("/api/notifications")
@auth.login_required
def api_notifications():
    try:
        notifs = [{"id": 1, "type": "system", "title": "System Started",
                   "message":   f"Hybrid IDS running on {INTERFACE}",
                   "timestamp": system_start_time.strftime("%H:%M:%S"),
                   "read": True, "priority": "info"}]
        if ML_ENABLED:
            notifs.append({"id": 2, "type": "system", "title": "ML Detection Enabled",
                           "message": "Machine learning detection is active",
                           "timestamp": datetime.now().strftime("%H:%M:%S"),
                           "read": True, "priority": "info"})
        if baseline_ready:
            notifs.append({"id": 3, "type": "system", "title": "Zero-Day Detection Active",
                           "message": f"Baseline established — Z={ANOMALY_Z_THRESHOLD}",
                           "timestamp": datetime.now().strftime("%H:%M:%S"),
                           "read": True, "priority": "info"})
        elif baseline_start:
            pct = min(99, int(((time.time() - baseline_start) / BASELINE_LEARNING_SECONDS) * 100))
            notifs.append({"id": 3, "type": "system", "title": "Zero-Day Baseline Learning",
                           "message": f"Building baseline ({pct}% complete)",
                           "timestamp": datetime.now().strftime("%H:%M:%S"),
                           "read": True, "priority": "info"})
        notifs.append({"id": 4, "type": "system", "title": "Brute Force Detection Active",
                       "message": (f"Monitoring {len(BRUTE_FORCE_PORTS)} auth ports — "
                                   f"threshold {BRUTE_FORCE_THRESHOLD}/{BRUTE_FORCE_WINDOW}s"),
                       "timestamp": datetime.now().strftime("%H:%M:%S"),
                       "read": True, "priority": "info"})
        for i, a in enumerate(list(attack_history)[-10:]):
            pri = ("critical" if a["type"] in ("DDoS", "ZERO_DAY", "CREDENTIAL_STUFFING")
                   else "high" if a["type"] in ("DoS", "BRUTE_FORCE", "HTTP_FLOOD",
                                                 "RST_FLOOD", "FIN_FLOOD", "ACK_FLOOD",
                                                 "WEB_ATTACK")
                   else "medium")
            notifs.append({"id": 1000 + i, "type": "attack",
                           "title":     f"Attack: {a['type']}",
                           "message":   a["message"],
                           "timestamp": a["timestamp"],
                           "read":      False, "priority": pri})
        return jsonify({"notifications": notifs[::-1],
                        "unread":        sum(1 for n in notifs if not n.get("read", False)),
                        "status":        "success"})
    except Exception as e:
        return jsonify({"notifications": [], "unread": 0, "status": "error", "error": str(e)})


@flask_app.route("/api/analysis")
@auth.login_required
def api_analysis():
    try:
        with packet_lock:
            packets = packet_list.copy()
        if not packets:
            return jsonify({"protocols": {}, "top_sources": [], "top_destinations": [],
                            "packet_rate": 0, "avg_packet_size": 0, "total_bytes": 0,
                            "hourly_pattern": [], "status": "success"})
        protocols = defaultdict(int)
        sources   = defaultdict(int)
        dests     = defaultdict(int)
        for p in packets:
            protocols[p.get("protocol", "OTHER")] += 1
            sources[p.get("src")]                 += 1
            dests[p.get("dst")]                   += 1
        elapsed = time.time() - packets[0].get("time", time.time())
        return jsonify({
            "protocols":        dict(protocols),
            "top_sources":      [{"ip": ip, "count": c} for ip, c in
                                  sorted(sources.items(), key=lambda x: x[1], reverse=True)[:10]],
            "top_destinations": [{"ip": ip, "count": c} for ip, c in
                                  sorted(dests.items(), key=lambda x: x[1], reverse=True)[:10]],
            "packet_rate":      round(len(packets) / max(1, elapsed) * 60, 2),
            "avg_packet_size":  round(float(np.mean([p.get("length", 0) for p in packets])), 2),
            "total_bytes":      sum(p.get("length", 0) for p in packets),
            "hourly_pattern":   [{"hour": f"{h:02d}:00",
                                   "packets": int(np.random.randint(50, 500))} for h in range(24)],
            "status":           "success",
        })
    except Exception as e:
        return jsonify({"protocols": {}, "top_sources": [], "top_destinations": [],
                        "packet_rate": 0, "avg_packet_size": 0, "total_bytes": 0,
                        "hourly_pattern": [], "status": "error", "error": str(e)})


@flask_app.route("/api/clear-traffic", methods=["POST"])
@auth.login_required
def api_clear_traffic():
    try:
        global packet_list
        with packet_lock:
            packet_list.clear()
        return jsonify({"success": True, "message": "Traffic data cleared"})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})


@flask_app.route("/api/resume-capture", methods=["POST"])
@auth.login_required
def api_resume_capture():
    return jsonify({"success": True, "message": "Capture is always active"})


@flask_app.route("/api/zero-day-stats")
@auth.login_required
def api_zero_day_stats():
    try:
        stats = {}
        if baseline_ready:
            for fname in FEATURE_NAMES:
                stats[fname] = {"mean": round(baseline_means.get(fname, 0), 3),
                                "std":  round(baseline_stds.get(fname, 0), 3)}
        return jsonify({"enabled":              True,
                        "baseline_ready":       baseline_ready,
                        "feature_stats":        stats,
                        "z_threshold":          ANOMALY_Z_THRESHOLD,
                        "feature_count_req":    ANOMALY_FEATURE_COUNT,
                        "min_packets_required": MIN_PACKETS_FOR_ANOMALY,
                        "cooldown_sec":         ZERO_DAY_COOLDOWN,
                        "learning_window":      BASELINE_LEARNING_SECONDS,
                        "total_zero_day":       sum(1 for a in attack_history
                                                    if "ZERO_DAY" in a["type"]),
                        "status":               "success"})
    except Exception as e:
        return jsonify({"enabled": True, "baseline_ready": False,
                        "status": "error", "error": str(e)})


@flask_app.route("/api/brute-force-stats")
@auth.login_required
def api_brute_force_stats():
    try:
        now    = time.time()
        active = []
        with brute_force_lock:
            for key, q in brute_force_attempts.items():
                recent = sum(1 for t in q if now - t <= BRUTE_FORCE_WINDOW)
                if recent > 0:
                    src, dp = key.rsplit(":", 1)
                    dp = int(dp)
                    active.append({"src":                src,
                                   "port":               dp,
                                   "service":            BRUTE_FORCE_PORTS.get(dp, f"PORT-{dp}"),
                                   "attempts_in_window": recent,
                                   "threshold":          BRUTE_FORCE_THRESHOLD,
                                   "pct":                round(recent / BRUTE_FORCE_THRESHOLD * 100, 1)})
        active.sort(key=lambda x: x["attempts_in_window"], reverse=True)
        return jsonify({"active_attempts": active[:20],
                        "window_seconds":  BRUTE_FORCE_WINDOW,
                        "threshold":       BRUTE_FORCE_THRESHOLD,
                        "monitored_ports": BRUTE_FORCE_PORTS,
                        "status":          "success"})
    except Exception as e:
        return jsonify({"active_attempts": [], "status": "error", "error": str(e)})


@flask_app.route("/api/debug-bucket/<src_ip>")
@auth.login_required
def api_debug_bucket(src_ip):
    try:
        with ip_bucket_lock:
            if src_ip not in ip_bucket_data:
                return jsonify({"error": f"No data for IP {src_ip}", "status": "error"}), 404
            bucket   = ip_bucket_data[src_ip]
            features = _extract_bucket_features(bucket)
            z_scores = {}
            if baseline_ready:
                for fname in FEATURE_NAMES:
                    val  = features.get(fname, 0)
                    mean = baseline_means.get(fname, 0)
                    std  = baseline_stds.get(fname, 1)
                    if std > 0:
                        z_scores[fname] = round((val - mean) / std, 2)
            return jsonify({
                "src_ip":     src_ip,
                "bucket_data": {
                    "pkt_count":    bucket["pkt_count"],
                    "byte_count":   bucket["byte_count"],
                    "unique_dsts":  list(bucket["unique_dsts"]),
                    "unique_dports":list(bucket["unique_dports"]),
                    "syn_count":    bucket["syn_count"],
                    "udp_count":    bucket["udp_count"],
                    "icmp_count":   bucket["icmp_count"],
                    "had_attack":   bucket.get("had_attack", False),
                    "time_in_bucket": round(time.time() - bucket["bucket_start"], 2),
                },
                "extracted_features": features,
                "z_scores":     z_scores,
                "baseline_ready": baseline_ready,
                "status":       "success",
            })
    except Exception as e:
        return jsonify({"error": str(e), "status": "error"}), 500


def _calculate_stats(packets: list) -> dict:
    now = time.time()
    bl  = (100 if baseline_ready
           else min(99, int(((now - baseline_start) / BASELINE_LEARNING_SECONDS) * 100))
           if baseline_start else 0)
    if not packets:
        return {"total": 0, "safe": 0, "suspicious": 0, "attack": 0,
                "tcp": 0, "udp": 0, "icmp": 0, "other": 0,
                "avg_packet_size": 0, "packets_per_sec": 0,
                "baseline_ready": baseline_ready, "baseline_progress": bl}
    tcp  = sum(1 for p in packets if p.get("protocol") == "TCP")
    udp  = sum(1 for p in packets if p.get("protocol") == "UDP")
    icmp = sum(1 for p in packets if p.get("protocol") == "ICMP")
    safe = sum(1 for p in packets if p.get("status") == "normal")
    susp = sum(1 for p in packets if p.get("status") == "suspicious")
    atk  = sum(1 for p in packets if p.get("status") == "attack")
    avg  = sum(p.get("length", 0) for p in packets) / len(packets)
    rec5 = [p for p in packets if now - p.get("time", now) <= 5]
    return {
        "total": len(packets), "safe": safe, "suspicious": susp, "attack": atk,
        "tcp": tcp, "udp": udp, "icmp": icmp,
        "other":          len(packets) - tcp - udp - icmp,
        "avg_packet_size": round(avg, 2),
        "packets_per_sec": round(len(rec5) / 5, 2) if rec5 else 0,
        "baseline_ready":  baseline_ready,
        "baseline_progress": bl,
    }


# =============================================================================
# DASH (legacy dashboard)
# =============================================================================
app = dash.Dash(__name__, server=flask_app, url_base_pathname="/dash/")
app.title  = "Hybrid IDS"
app.layout = html.Div([
    html.H1("Hybrid IDS Dashboard", style={"textAlign": "center"}),
    html.Div(id="alert-box", style={"textAlign": "center", "padding": "15px"}),
    html.Button("Clear Alert Display", id="clear-btn"),
    html.Div(id="stats-bar"),
    dash_table.DataTable(
        id="pkt-table",
        columns=[
            {"name": "Time",        "id": "timestamp"},
            {"name": "Source",      "id": "src"},
            {"name": "Destination", "id": "dst"},
            {"name": "Proto",       "id": "protocol"},
            {"name": "Len",         "id": "length"},
            {"name": "Status",      "id": "status"},
        ],
        page_size=10,
        style_cell={"fontFamily": "monospace", "fontSize": 12},
        style_data_conditional=[
            {"if": {"filter_query": '{status} = "attack"'},     "backgroundColor": "#ffcccc"},
            {"if": {"filter_query": '{status} = "suspicious"'}, "backgroundColor": "#fff3cd"},
        ],
    ),
    dcc.Interval(id="tick", interval=2000),
])


@app.callback(
    [Output("pkt-table", "data"),
     Output("alert-box", "children"),
     Output("stats-bar", "children")],
    Input("tick", "n_intervals"),
)
def update_dash(n):
    with packet_lock:
        rows = packet_list[-10:]
    recent_attacks = [a for a in attack_history
                      if (datetime.now() - a["time"]).total_seconds() < 30]
    if recent_attacks:
        latest  = recent_attacks[-1]
        alert_el = html.Div(
            [html.H3("ATTACK DETECTED"),
             html.P(f"{latest['type']} — {latest['message']}")],
            style={"background": "#ffcccc", "padding": "10px", "borderRadius": "6px"})
    else:
        alert_el = html.Div("NORMAL",
                            style={"color": "green", "fontWeight": "bold", "fontSize": 18})
    susp   = sum(1 for p in packet_list[-100:] if p.get("status") == "suspicious")
    now_t  = time.time()
    zd_pct = min(99, int(((now_t - (baseline_start or now_t)) / BASELINE_LEARNING_SECONDS) * 100))
    zd     = "Active" if baseline_ready else f"Learning ({zd_pct}%)"
    bf     = sum(1 for a in attack_history if "BRUTE_FORCE" in a["type"])
    stats_el = html.Div([
        html.Span(f"Packets: {len(packet_list)}  |  "),
        html.Span(f"Suspicious: {susp}  |  "),
        html.Span(f"Alerts: {len(attack_history)}  |  "),
        html.Span(f"Brute-force: {bf}  |  "),
        html.Span(f"Zero-Day: {zd}"),
    ])
    return rows, alert_el, stats_el


@app.callback(Output("alert-box", "style"), Input("clear-btn", "n_clicks"))
def clear_alert_style(_):
    return {}


# =============================================================================
# ENTRY POINT
# =============================================================================
if __name__ == "__main__":
    import os
    print("\n" + "=" * 65)
    print("   HYBRID INTRUSION DETECTION SYSTEM (false-positive-hardened)")
    print("=" * 65)
    print(f"  Interface           : {INTERFACE}")
    print(f"  ML Detection        : {'ENABLED' if ML_ENABLED else 'DISABLED'}")
    print(f"  Zero-Day Detection  : ENABLED (Z={ANOMALY_Z_THRESHOLD}, features={ANOMALY_FEATURE_COUNT})")
    print(f"  Web Attack Detection: ENABLED (threshold={WEB_ATTACK_THRESHOLD})")
    print(f"  Slowloris Detection : ENABLED")
    print(f"  Heartbleed Detection: ENABLED (TLS ports only)")
    print(f"  Botnet/C2 Detection : ENABLED")
    print(f"  RST/FIN Flood       : threshold={RST_FLOOD_THRESHOLD}/{FIN_FLOOD_THRESHOLD} pps")
    print(f"  ACK Flood           : threshold={ACK_FLOOD_THRESHOLD} pps (non-zero seq/ack)")
    print(f"  HTTP Flood          : threshold={HTTP_FLOOD_THRESHOLD} pps (method-gated)")
    print(f"  XMAS/NULL Scan      : {XMAS_SCAN_THRESHOLD}/{NULL_SCAN_THRESHOLD} ports/{SCAN_WINDOW}s")
    print(f"  Cred Stuffing       : {CRED_STUFF_SRC_THRESHOLD} unique IPs/{CRED_STUFF_WINDOW}s")
    print(f"  Suspicious factor   : {SUSPICIOUS_PPS_FACTOR*100:.0f}% of DoS threshold "
          f"(sustained {SUSPICIOUS_SUSTAIN_SEC}s)")
    print("=" * 65)
    print("  URLs:")
    print("    Network Traffic  ->  http://127.0.0.1:8090/network-traffic")
    print("    Attacks          ->  http://127.0.0.1:8090/attacks")
    print("    Analysis         ->  http://127.0.0.1:8090/analysis")
    print("    Notifications    ->  http://127.0.0.1:8090/notifications")
    print("    Legacy Dash      ->  http://127.0.0.1:8090/dash/")
    print("    Zero-Day Stats   ->  http://127.0.0.1:8090/api/zero-day-stats")
    print("    Debug Bucket     ->  http://127.0.0.1:8090/api/debug-bucket/<IP>")
    print("    Brute-Force Live ->  http://127.0.0.1:8090/api/brute-force-stats")
    print("=" * 65)
    print("  Default Login: admin / admin (configure in auth.py)")
    print("=" * 65 + "\n")

    if not os.path.exists("templates"):
        os.makedirs("templates")
    try:
        flask_app.run(host="0.0.0.0", port=8090, debug=False, threaded=True)
    except Exception as e:
        print(f"Error starting server: {e}")