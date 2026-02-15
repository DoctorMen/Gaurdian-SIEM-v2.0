"""
Guardian SIEM v2.0 — Event Bus
Central event pipeline that receives security events from all sources,
persists them to SQLite, and dispatches to registered subscribers
(rules engine, alert manager, dashboard via WebSocket).
"""

import sqlite3
from datetime import datetime
import os
import json
import threading


class EventBus:
    """Central event bus — the backbone of Guardian SIEM."""

    _instance = None
    _lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        """Singleton pattern to ensure one shared event bus."""
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self):
        if self._initialized:
            return
        base_dir = os.path.dirname(os.path.abspath(__file__))
        db_dir = os.path.join(base_dir, "database")
        if not os.path.exists(db_dir):
            os.makedirs(db_dir)
        self.db_path = os.path.join(db_dir, "guardian_events.db")
        self._subscribers = []  # Callback functions for real-time processing
        self._sub_lock = threading.Lock()  # Guards _subscribers list
        self._init_db()
        self._initialized = True

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        # Upgraded schema with enrichment fields
        conn.execute('''CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY,
            timestamp TEXT,
            source TEXT,
            severity TEXT,
            message TEXT,
            rule_matched TEXT DEFAULT '',
            mitre_id TEXT DEFAULT '',
            mitre_tactic TEXT DEFAULT '',
            threat_score INTEGER DEFAULT 0,
            geo_country TEXT DEFAULT '',
            geo_city TEXT DEFAULT '',
            geo_lat REAL DEFAULT 0,
            geo_lon REAL DEFAULT 0,
            src_ip TEXT DEFAULT '',
            raw_log TEXT DEFAULT ''
        )''')
        # Add indexes for dashboard performance
        conn.execute('CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp DESC)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_events_source ON events(source)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_events_mitre ON events(mitre_id)')
        conn.commit()
        conn.close()

    def subscribe(self, callback):
        """Register a callback to receive events in real-time."""
        with self._sub_lock:
            self._subscribers.append(callback)

    def emit(self, source, severity, message, enrichment=None):
        """
        Emit a security event.

        Args:
            source: Event source identifier
            severity: CRITICAL, HIGH, MEDIUM, LOW, INFO
            message: Human-readable event description
            enrichment: Optional dict with additional fields:
                        rule_matched, mitre_id, mitre_tactic,
                        threat_score, geo_country, geo_city, geo_lat, geo_lon,
                        src_ip, raw_log
        """
        timestamp = datetime.now().isoformat()
        enrichment = enrichment or {}

        event = {
            "timestamp": timestamp,
            "source": source,
            "severity": severity,
            "message": message,
            "rule_matched": enrichment.get("rule_matched", ""),
            "mitre_id": enrichment.get("mitre_id", ""),
            "mitre_tactic": enrichment.get("mitre_tactic", ""),
            "threat_score": enrichment.get("threat_score", 0),
            "geo_country": enrichment.get("geo_country", ""),
            "geo_city": enrichment.get("geo_city", ""),
            "geo_lat": enrichment.get("geo_lat", 0),
            "geo_lon": enrichment.get("geo_lon", 0),
            "src_ip": enrichment.get("src_ip", ""),
            "raw_log": enrichment.get("raw_log", ""),
        }

        # Persist to database
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.execute(
            """INSERT INTO events 
            (timestamp, source, severity, message, rule_matched, mitre_id, mitre_tactic,
             threat_score, geo_country, geo_city, geo_lat, geo_lon, src_ip, raw_log)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (timestamp, source, severity, message,
             event["rule_matched"], event["mitre_id"], event["mitre_tactic"],
             event["threat_score"], event["geo_country"], event["geo_city"],
             event["geo_lat"], event["geo_lon"], event["src_ip"], event["raw_log"])
        )
        conn.commit()
        conn.close()

        # Notify all subscribers (snapshot to avoid holding lock during callbacks)
        with self._sub_lock:
            subs = list(self._subscribers)
        for callback in subs:
            try:
                callback(event)
            except Exception as e:
                print(f"[EventBus] Subscriber error: {e}")

        print(f"[{severity}] {source}: {message[:120]}")
        return event

    def query(self, limit=50, severity=None, source=None, since=None, mitre_id=None):
        """
        Query events with optional filters.

        Args:
            limit: Max events to return
            severity: Filter by severity level
            source: Filter by source
            since: ISO timestamp — return events after this time
            mitre_id: Filter by MITRE technique ID

        Returns:
            List of event dicts
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        query = "SELECT * FROM events WHERE 1=1"
        params = []

        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if source:
            query += " AND source LIKE ?"
            params.append(f"%{source}%")
        if since:
            query += " AND timestamp > ?"
            params.append(since)
        if mitre_id:
            query += " AND mitre_id = ?"
            params.append(mitre_id)

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        rows = conn.execute(query, params).fetchall()
        conn.close()
        return [dict(row) for row in rows]

    def get_stats(self):
        """Return aggregate statistics for the dashboard."""
        conn = sqlite3.connect(self.db_path)
        stats = {}

        # Total events
        stats["total_events"] = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]

        # Events by severity
        rows = conn.execute("SELECT severity, COUNT(*) as cnt FROM events GROUP BY severity").fetchall()
        stats["by_severity"] = {row[0]: row[1] for row in rows}

        # Events by source
        rows = conn.execute("SELECT source, COUNT(*) as cnt FROM events GROUP BY source ORDER BY cnt DESC LIMIT 10").fetchall()
        stats["by_source"] = {row[0]: row[1] for row in rows}

        # Events in last hour
        stats["last_hour"] = conn.execute(
            "SELECT COUNT(*) FROM events WHERE timestamp > datetime('now', '-1 hour')"
        ).fetchone()[0]

        # Events in last 24h
        stats["last_24h"] = conn.execute(
            "SELECT COUNT(*) FROM events WHERE timestamp > datetime('now', '-24 hours')"
        ).fetchone()[0]

        # Top MITRE techniques
        rows = conn.execute(
            "SELECT mitre_id, COUNT(*) as cnt FROM events WHERE mitre_id != '' GROUP BY mitre_id ORDER BY cnt DESC LIMIT 10"
        ).fetchall()
        stats["top_mitre"] = {row[0]: row[1] for row in rows}

        # Unique source IPs
        stats["unique_ips"] = conn.execute(
            "SELECT COUNT(DISTINCT src_ip) FROM events WHERE src_ip != ''"
        ).fetchone()[0]

        conn.close()
        return stats


if __name__ == "__main__":
    bus = EventBus()
    bus.emit("System", "INFO", "Event Bus v2.0 Initialized Successfully.")
    bus.emit("Test", "HIGH", "Test high-severity event", {
        "mitre_id": "T1110", "mitre_tactic": "Credential Access", "src_ip": "10.0.0.1"
    })
    print(f"\nStats: {json.dumps(bus.get_stats(), indent=2)}")