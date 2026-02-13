"""
Guardian SIEM v2.0 — Unit Tests: Alert Manager
Tests alert dispatching, deduplication, and rate limiting.
"""

import os
import sys
import unittest
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from alert_manager import AlertManager


class TestAlertManager(unittest.TestCase):
    """Test suite for the Alert Manager module."""

    def setUp(self):
        self.am = AlertManager()
        self.am._cooldown_seconds = 1  # Low cooldown for testing

    def _make_alert(self, rule_name="Test Rule", severity="HIGH"):
        return {
            "rule_name": rule_name,
            "severity": severity,
            "description": "Test alert",
            "mitre_id": "T1110",
            "source": "TestSource",
            "message_excerpt": "Test message",
            "matched_at": "2026-01-01T00:00:00",
        }

    def test_send_alert(self):
        """Test that alerts are logged to the in-memory buffer."""
        alert = self._make_alert()
        self.am.send_alert(alert)

        log = self.am.get_recent_alerts()
        self.assertEqual(len(log), 1)
        self.assertEqual(log[0]["rule_name"], "Test Rule")

    def test_deduplication(self):
        """Test that duplicate alerts within cooldown are suppressed."""
        alert = self._make_alert()
        self.am.send_alert(alert)
        self.am.send_alert(alert)  # Should be deduplicated

        log = self.am.get_recent_alerts()
        self.assertEqual(len(log), 1)

    def test_dedup_expires(self):
        """Test that duplicates are allowed after cooldown expires."""
        self.am._cooldown_seconds = 0.1  # 100ms cooldown
        alert = self._make_alert()
        self.am.send_alert(alert)
        time.sleep(0.2)
        self.am.send_alert(alert)

        log = self.am.get_recent_alerts()
        self.assertEqual(len(log), 2)

    def test_different_rules_not_deduplicated(self):
        """Test that different rules are not deduplicated against each other."""
        self.am.send_alert(self._make_alert("Rule A"))
        self.am.send_alert(self._make_alert("Rule B"))

        log = self.am.get_recent_alerts()
        self.assertEqual(len(log), 2)

    def test_get_alert_stats(self):
        """Test alert statistics generation."""
        self.am.send_alert(self._make_alert("Rule A", "CRITICAL"))
        self.am.send_alert(self._make_alert("Rule B", "HIGH"))
        self.am.send_alert(self._make_alert("Rule C", "HIGH"))

        stats = self.am.get_alert_stats()
        self.assertEqual(stats["total"], 3)
        self.assertEqual(stats["by_severity"]["CRITICAL"], 1)
        self.assertEqual(stats["by_severity"]["HIGH"], 2)

    def test_recent_alerts_limit(self):
        """Test that recent alerts respects limit."""
        self.am._cooldown_seconds = 0
        for i in range(10):
            self.am.send_alert(self._make_alert(f"Rule {i}"))

        log = self.am.get_recent_alerts(limit=5)
        self.assertEqual(len(log), 5)

    def test_alert_channels_logged(self):
        """Test that dispatched channels are recorded."""
        self.am.send_alert(self._make_alert())

        log = self.am.get_recent_alerts()
        self.assertIn("console", log[0]["channels"])


if __name__ == "__main__":
    unittest.main()
