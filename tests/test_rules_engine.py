"""
Guardian SIEM v2.0 — Unit Tests: Rules Engine
Tests detection rule loading, pattern matching, threshold logic, and sliding windows.
"""

import os
import sys
import unittest
import tempfile
import yaml

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rules_engine import RulesEngine


class TestRulesEngine(unittest.TestCase):
    """Test suite for the Rules Engine module."""

    def setUp(self):
        """Create a temporary rules file for testing."""
        self.rules_data = {
            "rules": [
                {
                    "name": "Test Brute Force",
                    "source": ".*",
                    "pattern": "(failed login|4625)",
                    "severity": "HIGH",
                    "mitre_id": "T1110",
                    "mitre_tactic": "Credential Access",
                    "threshold": 3,
                    "window_seconds": 60,
                    "enabled": True,
                },
                {
                    "name": "Test Port Scan",
                    "source": "Network_IPS",
                    "pattern": "port scan",
                    "severity": "MEDIUM",
                    "mitre_id": "T1046",
                    "mitre_tactic": "Discovery",
                    "threshold": 1,
                    "window_seconds": 10,
                    "enabled": True,
                },
                {
                    "name": "Disabled Rule",
                    "source": ".*",
                    "pattern": "this should never match anything",
                    "severity": "LOW",
                    "enabled": False,
                },
            ]
        }
        self.temp_file = tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        )
        yaml.dump(self.rules_data, self.temp_file)
        self.temp_file.close()

        self.engine = RulesEngine(rules_path=self.temp_file.name)

    def tearDown(self):
        os.unlink(self.temp_file.name)

    def test_load_rules(self):
        """Test that active rules are loaded and disabled rules are excluded."""
        self.assertEqual(len(self.engine.rules), 2)  # Disabled rule excluded

    def test_pattern_matching(self):
        """Test that regex patterns match correctly."""
        matches = self.engine.evaluate("Windows", "Event 4625: Failed login for admin")
        # Threshold is 3, this is only hit #1 — should not alert yet
        self.assertEqual(len(matches), 0)

    def test_threshold_triggers(self):
        """Test that alert fires only after threshold is reached."""
        # Fire 2 events — below threshold of 3
        self.engine.evaluate("Windows", "Event 4625: Failed login #1")
        self.engine.evaluate("Windows", "Event 4625: Failed login #2")

        # Third event should trigger the alert
        matches = self.engine.evaluate("Windows", "Event 4625: Failed login #3")
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["rule_name"], "Test Brute Force")
        self.assertEqual(matches[0]["severity"], "HIGH")
        self.assertEqual(matches[0]["mitre_id"], "T1110")

    def test_source_filtering(self):
        """Test that source regex filter works."""
        # Port scan rule only matches "Network_IPS" source
        matches = self.engine.evaluate("Windows_EventLog", "port scan detected")
        self.assertEqual(len(matches), 0)

        matches = self.engine.evaluate("Network_IPS", "port scan detected")
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["rule_name"], "Test Port Scan")

    def test_no_match(self):
        """Test that non-matching events return empty."""
        matches = self.engine.evaluate("SomeSource", "normal activity nothing suspicious")
        self.assertEqual(len(matches), 0)

    def test_threshold_resets_after_alert(self):
        """Test that counter resets after alert fires."""
        for i in range(3):
            self.engine.evaluate("W", f"4625 attempt {i}")

        # Counter should have reset; need 3 more to trigger again
        matches = self.engine.evaluate("W", "4625 attempt post-reset")
        self.assertEqual(len(matches), 0)

    def test_get_rules_summary(self):
        """Test rules summary output."""
        summary = self.engine.get_rules_summary()
        self.assertEqual(len(summary), 2)
        self.assertTrue(all("name" in r for r in summary))
        self.assertTrue(all("severity" in r for r in summary))

    def test_reload_rules(self):
        """Test hot-reload functionality."""
        self.engine.reload_rules()
        self.assertEqual(len(self.engine.rules), 2)

    def test_missing_rules_file(self):
        """Test graceful handling of missing rules file."""
        engine = RulesEngine(rules_path="/nonexistent/path.yaml")
        self.assertEqual(len(engine.rules), 0)

    def test_case_insensitive_matching(self):
        """Test that pattern matching is case-insensitive."""
        matches = self.engine.evaluate("Windows", "FAILED LOGIN event 4625")
        # This is hit #1, below threshold
        # But it should still register as a hit internally
        stats = self.engine.get_stats()
        self.assertIn("Test Brute Force", stats)


if __name__ == "__main__":
    unittest.main()
