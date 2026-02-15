"""
Guardian SIEM v2.0 — Dashboard & API Server
Full-featured Flask application with:
  - Real-time WebSocket event feed
  - REST API for events, stats, MITRE, GeoIP, rules, alerts, threat intel
  - SIGMA + YARA integration, Active Response, Syslog, PDF Reports
  - User authentication with role-based access control
  - Professional SOC dashboard UI
"""

from flask import Flask, render_template, jsonify, request, send_from_directory
from flask_sock import Sock
import sqlite3
import os
import re
import json
import time
import yaml
import secrets
import ipaddress
import threading
from datetime import datetime

from event_bus import EventBus
from rules_engine import RulesEngine
from mitre_tagger import MitreTagger
from threat_intel import ThreatIntel
from geoip_lookup import GeoIPLookup
from alert_manager import AlertManager
from sigma_engine import SigmaEngine
from yara_scanner import YaraScanner
from active_response import ActiveResponse
from report_generator import ReportGenerator
from syslog_receiver import SyslogReceiver
from auth import setup_auth

# ---- App Setup ----
app = Flask(__name__)
sock = Sock(app)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "database", "guardian_events.db")
CONFIG_PATH = os.path.join(BASE_DIR, "config", "config.yaml")

# Load config
config = {}
try:
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f) or {}
except Exception:
    pass

# Security: use env var, config value, or generate random key (never hardcoded)
app.secret_key = (
    os.environ.get("GUARDIAN_SECRET_KEY")
    or config.get("dashboard", {}).get("secret_key", "")
    or secrets.token_hex(32)
)

# ---- Initialize Modules ----
event_bus = EventBus()
rules_engine = RulesEngine()
mitre_tagger = MitreTagger()
threat_intel = ThreatIntel()
geoip = GeoIPLookup()
alert_manager = AlertManager()
sigma_engine = SigmaEngine()
yara_scanner = YaraScanner()
active_response = ActiveResponse()
report_gen = ReportGenerator()
syslog_receiver = SyslogReceiver()

# Setup authentication (checks config for enabled/disabled)
user_db = setup_auth(app, config)

# WebSocket clients
ws_clients = set()
ws_lock = threading.Lock()


def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# ---- Event Processing Pipeline ----
def process_event(event):
    """Pipeline: event → rules engine → SIGMA → MITRE enrichment → GeoIP → active response → alert."""
    source = event.get("source", "")
    message = event.get("message", "")

    # Extract IP from message
    ip_match = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', message)
    src_ip = ip_match.group(1) if ip_match else ""

    # Native Rules Engine evaluation
    matches = rules_engine.evaluate(source, message)

    # SIGMA Rules evaluation
    sigma_matches = sigma_engine.evaluate({
        "source": source, "message": message,
        "severity": event.get("severity", ""),
    })
    for sm in sigma_matches:
        # Merge SIGMA matches into the same format
        matches.append({
            "rule_name": f"SIGMA: {sm['rule_name']}",
            "description": sm.get("description", ""),
            "severity": sm["severity"],
            "mitre_id": sm.get("mitre_id", ""),
            "mitre_tactic": sm.get("mitre_tactic", ""),
            "hit_count": 1,
            "threshold": 1,
            "window_seconds": 0,
            "matched_at": sm["matched_at"],
            "source": source,
            "message_excerpt": message[:200],
        })

    for match in matches:
        # MITRE enrichment
        mitre_info = mitre_tagger.enrich(match.get("mitre_id", ""))

        # GeoIP enrichment
        geo_data = {}
        if src_ip:
            geo_data = geoip.lookup(src_ip)

        # Enrich the event
        enrichment = {
            "rule_matched": match["rule_name"],
            "mitre_id": match.get("mitre_id", ""),
            "mitre_tactic": match.get("mitre_tactic", ""),
            "threat_score": mitre_info.get("severity_weight", 0) * 10,
            "geo_country": geo_data.get("country", ""),
            "geo_city": geo_data.get("city", ""),
            "geo_lat": geo_data.get("latitude", 0),
            "geo_lon": geo_data.get("longitude", 0),
            "src_ip": src_ip,
        }

        # Emit enriched alert event
        alert_event = event_bus.emit(
            f"Alert_{source}", match["severity"],
            f"[{match['rule_name']}] {message[:300]}",
            enrichment=enrichment
        )

        # Dispatch alert notification
        alert_manager.send_alert(match)

        # Active response evaluation
        active_response.respond({
            "severity": match["severity"],
            "src_ip": src_ip,
            "rule_name": match["rule_name"],
            "mitre_id": match.get("mitre_id", ""),
        })

        # Push to WebSocket clients
        broadcast_ws({"type": "new_event", "event": alert_event})


# Register the pipeline as an event subscriber
event_bus.subscribe(lambda event: threading.Thread(
    target=process_event, args=(event,), daemon=True
).start() if not event.get("source", "").startswith("Alert_") else None)


# ---- WebSocket ----
def broadcast_ws(data):
    """Send data to all connected WebSocket clients."""
    with ws_lock:
        dead = set()
        for ws in ws_clients:
            try:
                ws.send(json.dumps(data))
            except Exception:
                dead.add(ws)
        ws_clients -= dead


@sock.route('/ws')
def websocket(ws):
    # Security: validate authentication before accepting WebSocket
    if app.config.get("AUTH_ENABLED"):
        from flask import session as ws_session
        if not ws_session.get("authenticated"):
            ws.close()
            return
    with ws_lock:
        ws_clients.add(ws)
    try:
        while True:
            # Keep connection alive, receive pings
            ws.receive(timeout=30)
    except Exception:
        pass
    finally:
        with ws_lock:
            ws_clients.discard(ws)


# ---- Dashboard Route ----
@app.route('/')
def index():
    return render_template('dashboard.html')


# ---- REST API: Events ----
@app.route('/api/events')
def get_events():
    limit = request.args.get('limit', 50, type=int)
    severity = request.args.get('severity', None)
    source = request.args.get('source', None)
    since = request.args.get('since', None)
    mitre_id = request.args.get('mitre_id', None)

    events = event_bus.query(
        limit=min(limit, 500),
        severity=severity,
        source=source,
        since=since,
        mitre_id=mitre_id
    )
    return jsonify(events)


# ---- REST API: Stats ----
@app.route('/api/stats')
def get_stats():
    stats = event_bus.get_stats()
    return jsonify(stats)


# ---- REST API: MITRE ATT&CK Data ----
@app.route('/api/mitre')
def get_mitre():
    techniques = mitre_tagger.get_all_techniques()
    stats = event_bus.get_stats()
    return jsonify({
        "techniques": techniques,
        "tactics": mitre_tagger.get_tactic_summary(),
        "top_triggered": stats.get("top_mitre", {}),
    })


# ---- REST API: GeoIP Data ----
@app.route('/api/geo')
def get_geo():
    """Return GeoIP data for all unique IPs in recent events."""
    conn = get_db_connection()
    try:
        rows = conn.execute(
            """SELECT src_ip, geo_country, geo_city, geo_lat, geo_lon, 
                      COUNT(*) as count, MAX(threat_score) as threat_score
               FROM events 
               WHERE src_ip != '' AND geo_lat != 0
               GROUP BY src_ip
               ORDER BY count DESC LIMIT 100"""
        ).fetchall()
        return jsonify([{
            "ip": row["src_ip"],
            "country": row["geo_country"],
            "city": row["geo_city"],
            "latitude": row["geo_lat"],
            "longitude": row["geo_lon"],
            "count": row["count"],
            "threat_score": row["threat_score"],
        } for row in rows])
    finally:
        conn.close()


# ---- REST API: Detection Rules ----
@app.route('/api/rules')
def get_rules():
    return jsonify(rules_engine.get_rules_summary())


# ---- REST API: Alerts ----
@app.route('/api/alerts')
def get_alerts():
    return jsonify(alert_manager.get_recent_alerts())


# ---- REST API: Threat Intel Lookup ----
@app.route('/api/threat/<ip>')
def get_threat_intel(ip):
    # Security: validate IP address before external API calls
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return jsonify({"error": "Invalid IP address"}), 400
    result = threat_intel.lookup_ip(ip)
    return jsonify(result)


# ---- REST API: GeoIP Lookup ----
@app.route('/api/geoip/<ip>')
def get_geoip(ip):
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return jsonify({"error": "Invalid IP address"}), 400
    result = geoip.lookup(ip)
    return jsonify(result)


# ---- REST API: Health Check ----
@app.route('/api/health')
def health():
    return jsonify({
        "status": "operational",
        "version": "2.0.0",
        "timestamp": datetime.now().isoformat(),
        "modules": {
            "event_bus": "active",
            "rules_engine": f"{len(rules_engine.rules)} rules loaded",
            "sigma_engine": f"{len(sigma_engine.rules)} SIGMA rules",
            "mitre_tagger": f"{len(mitre_tagger.techniques)} techniques",
            "threat_intel": "configured" if threat_intel.abuseipdb_key or threat_intel.virustotal_key else "no API keys",
            "geoip": "maxmind" if geoip.reader else "ip-api.com fallback",
            "yara_scanner": yara_scanner.get_stats(),
            "active_response": active_response.get_stats(),
            "syslog_receiver": syslog_receiver.get_stats(),
            "alert_manager": "active",
            "auth": "enabled" if app.config.get("AUTH_ENABLED") else "disabled",
        },
        "ws_clients": len(ws_clients),
    })


# ---- REST API: SIGMA Rules ----
@app.route('/api/sigma/rules')
def get_sigma_rules():
    return jsonify(sigma_engine.get_rules_summary())


@app.route('/api/sigma/reload', methods=['POST'])
def reload_sigma():
    sigma_engine.reload_rules()
    return jsonify({"status": "reloaded", "count": len(sigma_engine.rules)})


# ---- REST API: YARA Scanner ----
@app.route('/api/yara/stats')
def get_yara_stats():
    return jsonify(yara_scanner.get_stats())


@app.route('/api/yara/results')
def get_yara_results():
    limit = request.args.get('limit', 50, type=int)
    return jsonify(yara_scanner.get_recent_results(limit))


@app.route('/api/yara/scan', methods=['POST'])
def trigger_yara_scan():
    data = request.get_json() or {}
    directory = data.get("directory", os.path.join(BASE_DIR, "service_logs"))
    extensions = data.get("extensions", None)

    # Security: prevent path traversal — restrict scanning to allowed directories
    allowed_bases = [
        os.path.realpath(os.path.join(BASE_DIR, "service_logs")),
        os.path.realpath(os.path.join(BASE_DIR, "logs")),
    ]
    requested = os.path.realpath(directory)
    if not any(requested.startswith(base) for base in allowed_bases):
        return jsonify({"error": "Directory not allowed. Scanning restricted to service_logs/ and logs/"}), 403

    results = yara_scanner.scan_directory(directory, recursive=True, extensions=extensions)
    return jsonify({"matches": len(results), "results": results})


@app.route('/api/yara/reload', methods=['POST'])
def reload_yara():
    yara_scanner.reload_rules()
    return jsonify({"status": "reloaded"})


# ---- REST API: Active Response ----
@app.route('/api/response/stats')
def get_response_stats():
    return jsonify(active_response.get_stats())


@app.route('/api/response/blocked')
def get_blocked_ips():
    return jsonify(active_response.get_blocked_ips())


@app.route('/api/response/log')
def get_response_log():
    limit = request.args.get('limit', 100, type=int)
    return jsonify(active_response.get_action_log(limit))


@app.route('/api/response/block', methods=['POST'])
def manual_block():
    data = request.get_json() or {}
    ip = data.get("ip", "")
    reason = data.get("reason", "Manual block via API")
    if not ip:
        return jsonify({"error": "ip required"}), 400
    # Security: validate IP before passing to firewall
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return jsonify({"error": "Invalid IP address"}), 400
    result = active_response.block_ip(ip, reason)
    return jsonify(result)


@app.route('/api/response/unblock', methods=['POST'])
def manual_unblock():
    data = request.get_json() or {}
    ip = data.get("ip", "")
    if not ip:
        return jsonify({"error": "ip required"}), 400
    result = active_response.unblock_ip(ip)
    return jsonify(result)


# ---- REST API: Reports ----
@app.route('/api/reports')
def list_reports():
    return jsonify(report_gen.get_available_reports())


@app.route('/api/reports/generate', methods=['POST'])
def generate_report():
    data = request.get_json() or {}
    report_type = data.get("type", "daily")
    hours = data.get("hours", 24)
    path = report_gen.generate_report(report_type=report_type, hours=hours)
    filename = os.path.basename(path)
    return jsonify({"status": "generated", "filename": filename, "path": path})


@app.route('/api/reports/download/<filename>')
def download_report(filename):
    return send_from_directory(report_gen.reports_dir, filename, as_attachment=True)


# ---- REST API: Syslog Receiver ----
@app.route('/api/syslog/stats')
def get_syslog_stats():
    return jsonify(syslog_receiver.get_stats())


# ---- Main ----
if __name__ == '__main__':
    host = config.get("dashboard", {}).get("host", "0.0.0.0")
    port = config.get("dashboard", {}).get("port", 5001)

    # Start syslog receiver if configured
    syslog_config = config.get("syslog", {})
    if syslog_config.get("udp_enabled") or syslog_config.get("tcp_enabled"):
        def syslog_callback(source, severity, raw_message, parsed):
            enrichment = {
                "src_ip": parsed.get("sender_ip", ""),
                "raw_log": raw_message[:500],
            }
            event_bus.emit(source, severity, parsed.get("message", raw_message), enrichment=enrichment)

        syslog_receiver.set_callback(syslog_callback)
        syslog_receiver.start()

    # Periodic cleanup of expired active response blocks
    def cleanup_loop():
        while True:
            time.sleep(300)
            active_response.cleanup_expired()

    threading.Thread(target=cleanup_loop, daemon=True).start()

    print(f"\n🛡️  Guardian SIEM v2.0 Dashboard")
    print(f"   http://localhost:{port}")
    print(f"   API: http://localhost:{port}/api/health")
    print(f"   Rules: {len(rules_engine.rules)} native + {len(sigma_engine.rules)} SIGMA")
    print(f"   MITRE: {len(mitre_tagger.techniques)} techniques mapped")
    print(f"   YARA: {'active' if yara_scanner._compiled_rules else 'no rules compiled'}")
    print(f"   Auth: {'enabled' if app.config.get('AUTH_ENABLED') else 'disabled'}")
    print(f"   Syslog: UDP:{syslog_config.get('udp_port', 1514)} TCP:{syslog_config.get('tcp_port', 1514)}\n")
    # Security: never enable debug in production (exposes Werkzeug interactive debugger)
    debug = config.get("dashboard", {}).get("debug", False)
    app.run(host=host, port=port, debug=debug)