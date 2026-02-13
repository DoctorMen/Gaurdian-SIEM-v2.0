"""Tests for PDF/HTML Report Generator"""

import os
import sys
import tempfile
import shutil
import sqlite3
import pytest
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from report_generator import ReportGenerator


@pytest.fixture
def report_gen(tmp_path):
    """Create a ReportGenerator with a temp database."""
    db_path = str(tmp_path / "test_events.db")

    # Create test database with sample events
    conn = sqlite3.connect(db_path)
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

    # Insert test events
    events = [
        (datetime.now().isoformat(), "Network_IPS", "CRITICAL", "Port scan from 1.2.3.4", "Port Scan", "T1046", "Discovery", 80, "US", "New York", 40.7, -74.0, "1.2.3.4", ""),
        (datetime.now().isoformat(), "Windows_EventLog", "HIGH", "Failed login 4625", "Brute Force", "T1110", "Credential Access", 60, "CN", "Beijing", 39.9, 116.4, "5.6.7.8", ""),
        (datetime.now().isoformat(), "Network_IPS", "MEDIUM", "High traffic from 10.0.0.1", "", "", "", 20, "", "", 0, 0, "10.0.0.1", ""),
        (datetime.now().isoformat(), "Syslog", "LOW", "User login success", "", "", "", 0, "", "", 0, 0, "", ""),
        (datetime.now().isoformat(), "FileMonitor", "INFO", "File access logged", "", "", "", 0, "", "", 0, 0, "", ""),
    ]
    for ev in events:
        conn.execute(
            "INSERT INTO events (timestamp, source, severity, message, rule_matched, mitre_id, mitre_tactic, threat_score, geo_country, geo_city, geo_lat, geo_lon, src_ip, raw_log) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ev
        )
    conn.commit()
    conn.close()

    gen = ReportGenerator()
    gen.db_path = db_path
    gen.reports_dir = str(tmp_path / "reports")
    os.makedirs(gen.reports_dir, exist_ok=True)
    return gen


class TestReportGenerator:
    def test_gather_data(self, report_gen):
        data = report_gen._gather_data(hours=24)
        assert data["total_events"] == 5
        assert "CRITICAL" in data["severity_counts"]
        assert data["severity_counts"]["CRITICAL"] == 1

    def test_gather_data_top_sources(self, report_gen):
        data = report_gen._gather_data(hours=24)
        assert len(data["top_sources"]) > 0
        source_names = [s["source"] for s in data["top_sources"]]
        assert "Network_IPS" in source_names

    def test_gather_data_top_ips(self, report_gen):
        data = report_gen._gather_data(hours=24)
        assert len(data["top_ips"]) > 0

    def test_gather_data_mitre(self, report_gen):
        data = report_gen._gather_data(hours=24)
        assert len(data["mitre_techniques"]) > 0
        techniques = [m["technique"] for m in data["mitre_techniques"]]
        assert "T1046" in techniques or "T1110" in techniques

    def test_gather_data_critical_events(self, report_gen):
        data = report_gen._gather_data(hours=24)
        assert len(data["recent_critical"]) >= 1

    def test_generate_html_report(self, report_gen):
        """Test HTML report generation (always available, no reportlab needed)."""
        data = report_gen._gather_data(hours=24)
        html = report_gen._generate_html(data, "daily")
        assert "Guardian SIEM" in html
        assert "Daily Security Report" in html
        assert "Total Events" in html
        assert "5" in html  # should show total count

    def test_generate_report_creates_file(self, report_gen):
        path = report_gen.generate_report(report_type="daily", hours=24)
        assert os.path.isfile(path)
        assert os.path.getsize(path) > 0

    def test_get_available_reports(self, report_gen):
        report_gen.generate_report(report_type="daily", hours=24)
        reports = report_gen.get_available_reports()
        assert len(reports) >= 1
        assert "filename" in reports[0]
        assert "size_kb" in reports[0]

    def test_empty_database(self, tmp_path):
        config_file = str(tmp_path / "config.yaml")
        with open(config_file, "w") as f:
            f.write("reports:\n  output_directory: reports\n")
        gen = ReportGenerator(config_path=config_file)
        gen.db_path = str(tmp_path / "nonexistent.db")
        gen.reports_dir = str(tmp_path / "reports")
        os.makedirs(gen.reports_dir, exist_ok=True)
        data = gen._gather_data(hours=24)
        assert data["total_events"] == 0
