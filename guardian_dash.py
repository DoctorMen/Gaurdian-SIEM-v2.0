"""
Guardian SIEM v2.0 — Dashboard & API Server
Full-featured Flask application with:
  - Real-time WebSocket event feed
  - REST API for events, stats, MITRE, GeoIP, rules, alerts, threat intel
  - Professional SOC dashboard UI
"""

from flask import Flask, render_template, jsonify, request
from flask_sock import Sock
import sqlite3
import os
import re
import json
import time
import yaml
import threading
from datetime import datetime

from event_bus import EventBus
from rules_engine import RulesEngine
from mitre_tagger import MitreTagger
from threat_intel import ThreatIntel
from geoip_lookup import GeoIPLookup
from alert_manager import AlertManager

# ---- App Setup ----
app = Flask(__name__)
sock = Sock(app)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "database", "guardian_events.db")
CONFIG_PATH = os.path.join(BASE_DIR, "config", "config.yaml")

# Load config
config = {}
try:
    with open(CONFIG_PATH, "r") as f:
        config = yaml.safe_load(f) or {}
except Exception:
    pass

app.secret_key = config.get("dashboard", {}).get("secret_key", "guardian-dev-key")

# ---- Initialize Modules ----
event_bus = EventBus()
rules_engine = RulesEngine()
mitre_tagger = MitreTagger()
threat_intel = ThreatIntel()
geoip = GeoIPLookup()
alert_manager = AlertManager()

# WebSocket clients
ws_clients = set()
ws_lock = threading.Lock()


def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# ---- Event Processing Pipeline ----
def process_event(event):
    """Pipeline: event → rules engine → MITRE enrichment → GeoIP → threat intel → alert."""
    source = event.get("source", "")
    message = event.get("message", "")

    # Extract IP from message
    ip_match = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', message)
    src_ip = ip_match.group(1) if ip_match else ""

    # Rules Engine evaluation
    matches = rules_engine.evaluate(source, message)

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
    result = threat_intel.lookup_ip(ip)
    return jsonify(result)


# ---- REST API: GeoIP Lookup ----
@app.route('/api/geoip/<ip>')
def get_geoip(ip):
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
            "mitre_tagger": f"{len(mitre_tagger.techniques)} techniques",
            "threat_intel": "configured" if threat_intel.abuseipdb_key or threat_intel.virustotal_key else "no API keys",
            "geoip": "maxmind" if geoip.reader else "ip-api.com fallback",
            "alert_manager": "active",
        },
        "ws_clients": len(ws_clients),
    })


# ---- Main ----
if __name__ == '__main__':
    host = config.get("dashboard", {}).get("host", "0.0.0.0")
    port = config.get("dashboard", {}).get("port", 5001)
    print(f"\n🛡️  Guardian SIEM v2.0 Dashboard")
    print(f"   http://localhost:{port}")
    print(f"   API: http://localhost:{port}/api/health")
    print(f"   Rules: {len(rules_engine.rules)} active")
    print(f"   MITRE: {len(mitre_tagger.techniques)} techniques mapped\n")
    app.run(host=host, port=port, debug=True)