"""
Guardian SIEM v2.0 — Threat Intelligence Module
Queries external threat intelligence APIs (AbuseIPDB, VirusTotal) to enrich
IP addresses and indicators with reputation data.
Includes local caching to respect API rate limits.
"""

import os
import json
import time
import hashlib
import sqlite3
import yaml
from datetime import datetime

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


class ThreatIntelCache:
    """Local SQLite cache for threat intelligence lookups."""

    def __init__(self, db_path):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        conn.execute('''CREATE TABLE IF NOT EXISTS threat_cache (
            indicator TEXT PRIMARY KEY,
            source TEXT,
            data TEXT,
            score INTEGER,
            cached_at REAL
        )''')
        conn.commit()
        conn.close()

    def get(self, indicator, source, ttl_hours=24):
        """Retrieve cached result if not expired."""
        conn = sqlite3.connect(self.db_path)
        row = conn.execute(
            "SELECT data, score, cached_at FROM threat_cache WHERE indicator=? AND source=?",
            (indicator, source)
        ).fetchone()
        conn.close()

        if row is None:
            return None

        data, score, cached_at = row
        if time.time() - cached_at > ttl_hours * 3600:
            return None  # Cache expired

        return {"data": json.loads(data), "score": score, "cached": True}

    def put(self, indicator, source, data, score):
        """Store a lookup result in cache."""
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            "INSERT OR REPLACE INTO threat_cache (indicator, source, data, score, cached_at) VALUES (?, ?, ?, ?, ?)",
            (indicator, source, json.dumps(data), score, time.time())
        )
        conn.commit()
        conn.close()


class ThreatIntel:
    """Queries external threat intelligence APIs with caching."""

    def __init__(self, config_path=None):
        base_dir = os.path.dirname(os.path.abspath(__file__))
        if config_path is None:
            config_path = os.path.join(base_dir, "config", "config.yaml")

        self.config = {}
        self._load_config(config_path)

        db_path = os.path.join(base_dir, "database", "threat_cache.db")
        self.cache = ThreatIntelCache(db_path)

        # API keys from config or environment variables (env vars take precedence)
        self.abuseipdb_key = os.environ.get(
            "ABUSEIPDB_API_KEY",
            self.config.get("threat_intel", {}).get("abuseipdb", {}).get("api_key", "")
        )
        self.virustotal_key = os.environ.get(
            "VIRUSTOTAL_API_KEY",
            self.config.get("threat_intel", {}).get("virustotal", {}).get("api_key", "")
        )

    def _load_config(self, config_path):
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                self.config = yaml.safe_load(f) or {}
        except (FileNotFoundError, yaml.YAMLError):
            self.config = {}

    def lookup_ip(self, ip_address):
        """
        Look up an IP address across all enabled threat intel sources.

        Returns:
            Dict with combined reputation data from all sources
        """
        results = {
            "ip": ip_address,
            "timestamp": datetime.now().isoformat(),
            "sources": {},
            "threat_score": 0,       # 0-100, higher = more malicious
            "is_malicious": False,
            "tags": [],
        }

        # AbuseIPDB lookup
        if self.abuseipdb_key:
            abuse_result = self._query_abuseipdb(ip_address)
            if abuse_result:
                results["sources"]["abuseipdb"] = abuse_result
                results["threat_score"] = max(results["threat_score"], abuse_result.get("score", 0))
                if abuse_result.get("score", 0) >= 50:
                    results["is_malicious"] = True
                    results["tags"].append("abuseipdb-flagged")

        # VirusTotal lookup
        if self.virustotal_key:
            vt_result = self._query_virustotal(ip_address)
            if vt_result:
                results["sources"]["virustotal"] = vt_result
                results["threat_score"] = max(results["threat_score"], vt_result.get("score", 0))
                if vt_result.get("score", 0) >= 50:
                    results["is_malicious"] = True
                    results["tags"].append("virustotal-flagged")

        # If no API keys configured, return a stub
        if not self.abuseipdb_key and not self.virustotal_key:
            results["sources"]["local"] = {
                "note": "No threat intel API keys configured. Set ABUSEIPDB_API_KEY or VIRUSTOTAL_API_KEY env vars.",
                "score": 0,
            }

        return results

    def _query_abuseipdb(self, ip_address):
        """Query AbuseIPDB API v2."""
        if not HAS_REQUESTS:
            return {"error": "requests library not installed", "score": 0}

        # Check cache first
        cached = self.cache.get(ip_address, "abuseipdb",
                                self.config.get("threat_intel", {}).get("abuseipdb", {}).get("cache_ttl_hours", 24))
        if cached:
            return cached["data"]

        try:
            headers = {"Key": self.abuseipdb_key, "Accept": "application/json"}
            params = {"ipAddress": ip_address, "maxAgeInDays": 90}
            resp = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers=headers, params=params, timeout=10
            )
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                result = {
                    "score": data.get("abuseConfidenceScore", 0),
                    "total_reports": data.get("totalReports", 0),
                    "country_code": data.get("countryCode", ""),
                    "isp": data.get("isp", ""),
                    "domain": data.get("domain", ""),
                    "is_tor": data.get("isTor", False),
                    "last_reported": data.get("lastReportedAt", ""),
                }
                self.cache.put(ip_address, "abuseipdb", result, result["score"])
                return result
            else:
                return {"error": f"HTTP {resp.status_code}", "score": 0}
        except Exception as e:
            return {"error": str(e), "score": 0}

    def _query_virustotal(self, ip_address):
        """Query VirusTotal API v3."""
        if not HAS_REQUESTS:
            return {"error": "requests library not installed", "score": 0}

        # Check cache first
        cached = self.cache.get(ip_address, "virustotal",
                                self.config.get("threat_intel", {}).get("virustotal", {}).get("cache_ttl_hours", 24))
        if cached:
            return cached["data"]

        try:
            headers = {"x-apikey": self.virustotal_key}
            resp = requests.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}",
                headers=headers, timeout=10
            )
            if resp.status_code == 200:
                attrs = resp.json().get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                total = sum(stats.values()) if stats else 1
                score = int((malicious / max(total, 1)) * 100)
                result = {
                    "score": score,
                    "malicious_detections": malicious,
                    "total_engines": total,
                    "country": attrs.get("country", ""),
                    "as_owner": attrs.get("as_owner", ""),
                    "network": attrs.get("network", ""),
                }
                self.cache.put(ip_address, "virustotal", result, score)
                return result
            else:
                return {"error": f"HTTP {resp.status_code}", "score": 0}
        except Exception as e:
            return {"error": str(e), "score": 0}


if __name__ == "__main__":
    ti = ThreatIntel()
    print("\n--- Threat Intel Lookup Test ---")
    test_ips = ["8.8.8.8", "1.1.1.1", "192.168.1.1"]
    for ip in test_ips:
        result = ti.lookup_ip(ip)
        print(f"  {ip}: score={result['threat_score']}, malicious={result['is_malicious']}, sources={list(result['sources'].keys())}")
