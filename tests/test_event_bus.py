"""
Guardian SIEM v2.0 — Unit Tests: Event Bus
Tests the core event pipeline, database operations, and query filtering.
"""

import os
import sys
import unittest
import tempfile
import sqlite3

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from event_bus import EventBus


class TestEventBus(unittest.TestCase):
    """Test suite for the Event Bus module."""

    def setUp(self):
        """Create a fresh EventBus with a temp database for each test."""
        # Reset singleton for testing
        EventBus._instance = None
        EventBus._lock = __import__("threading").Lock()

        self.bus = EventBus()
        # Override DB path to temp file
        self.temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.bus.db_path = self.temp_db.name
        self.bus._init_db()

    def tearDown(self):
        self.temp_db.close()
        os.unlink(self.temp_db.name)
        EventBus._instance = None

    def test_emit_basic_event(self):
        """Test that a basic event is persisted to the database."""
        event = self.bus.emit("TestSource", "INFO", "Test message")
        self.assertEqual(event["source"], "TestSource")
        self.assertEqual(event["severity"], "INFO")
        self.assertEqual(event["message"], "Test message")
        self.assertIn("timestamp", event)

    def test_emit_with_enrichment(self):
        """Test that enrichment data is stored correctly."""
        enrichment = {
            "mitre_id": "T1110",
            "mitre_tactic": "Credential Access",
            "src_ip": "192.168.1.100",
            "geo_country": "United States",
            "threat_score": 75,
        }
        event = self.bus.emit("Test", "HIGH", "Brute force", enrichment=enrichment)
        self.assertEqual(event["mitre_id"], "T1110")
        self.assertEqual(event["src_ip"], "192.168.1.100")
        self.assertEqual(event["threat_score"], 75)

    def test_query_returns_events(self):
        """Test that query returns persisted events."""
        self.bus.emit("Source1", "INFO", "Message 1")
        self.bus.emit("Source2", "HIGH", "Message 2")
        self.bus.emit("Source3", "CRITICAL", "Message 3")

        events = self.bus.query(limit=10)
        self.assertEqual(len(events), 3)

    def test_query_filter_by_severity(self):
        """Test severity filtering."""
        self.bus.emit("S1", "INFO", "Info event")
        self.bus.emit("S2", "HIGH", "High event")
        self.bus.emit("S3", "HIGH", "Another high event")

        events = self.bus.query(severity="HIGH")
        self.assertEqual(len(events), 2)
        for e in events:
            self.assertEqual(e["severity"], "HIGH")

    def test_query_filter_by_source(self):
        """Test source filtering."""
        self.bus.emit("Network_IPS", "INFO", "Network event")
        self.bus.emit("Windows_Security", "INFO", "Windows event")

        events = self.bus.query(source="Network")
        self.assertEqual(len(events), 1)
        self.assertIn("Network", events[0]["source"])

    def test_query_filter_by_mitre_id(self):
        """Test MITRE ID filtering."""
        self.bus.emit("S1", "HIGH", "Brute force", {"mitre_id": "T1110"})
        self.bus.emit("S2", "MEDIUM", "Port scan", {"mitre_id": "T1046"})

        events = self.bus.query(mitre_id="T1110")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["mitre_id"], "T1110")

    def test_query_limit(self):
        """Test that limit parameter is respected."""
        for i in range(20):
            self.bus.emit("Test", "INFO", f"Event {i}")

        events = self.bus.query(limit=5)
        self.assertEqual(len(events), 5)

    def test_get_stats(self):
        """Test statistics generation."""
        self.bus.emit("S1", "INFO", "Info 1")
        self.bus.emit("S2", "HIGH", "High 1")
        self.bus.emit("S3", "HIGH", "High 2")
        self.bus.emit("S4", "CRITICAL", "Critical 1", {"src_ip": "1.2.3.4"})

        stats = self.bus.get_stats()
        self.assertEqual(stats["total_events"], 4)
        self.assertEqual(stats["by_severity"].get("HIGH"), 2)
        self.assertEqual(stats["by_severity"].get("CRITICAL"), 1)
        self.assertGreaterEqual(stats["unique_ips"], 1)

    def test_subscriber_receives_events(self):
        """Test that registered subscribers receive events."""
        received = []
        self.bus.subscribe(lambda e: received.append(e))

        self.bus.emit("Test", "INFO", "Subscribed event")
        self.assertEqual(len(received), 1)
        self.assertEqual(received[0]["message"], "Subscribed event")

    def test_empty_enrichment_defaults(self):
        """Test that missing enrichment fields default gracefully."""
        event = self.bus.emit("Test", "INFO", "No enrichment")
        self.assertEqual(event["mitre_id"], "")
        self.assertEqual(event["threat_score"], 0)
        self.assertEqual(event["src_ip"], "")


if __name__ == "__main__":
    unittest.main()
