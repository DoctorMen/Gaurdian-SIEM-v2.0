"""
Guardian SIEM v2.0 — Unit Tests: Threat Intelligence
Tests caching, API key handling, and lookup logic.
"""

import os
import sys
import unittest
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from threat_intel import ThreatIntel, ThreatIntelCache


class TestThreatIntelCache(unittest.TestCase):
    """Test the local threat intel cache."""

    def setUp(self):
        self.temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.cache = ThreatIntelCache(self.temp_db.name)

    def tearDown(self):
        self.temp_db.close()
        os.unlink(self.temp_db.name)

    def test_put_and_get(self):
        """Test storing and retrieving cached data."""
        test_data = {"score": 85, "country": "CN"}
        self.cache.put("1.2.3.4", "abuseipdb", test_data, 85)

        result = self.cache.get("1.2.3.4", "abuseipdb")
        self.assertIsNotNone(result)
        self.assertEqual(result["data"]["score"], 85)
        self.assertTrue(result["cached"])

    def test_cache_miss(self):
        """Test that missing entries return None."""
        result = self.cache.get("9.9.9.9", "abuseipdb")
        self.assertIsNone(result)

    def test_cache_expiry(self):
        """Test that expired entries are not returned."""
        test_data = {"score": 50}
        self.cache.put("1.2.3.4", "abuseipdb", test_data, 50)

        # Query with TTL of 0 hours (everything is expired)
        result = self.cache.get("1.2.3.4", "abuseipdb", ttl_hours=0)
        self.assertIsNone(result)

    def test_overwrite_existing(self):
        """Test that put overwrites existing entries."""
        self.cache.put("1.2.3.4", "abuseipdb", {"score": 10}, 10)
        self.cache.put("1.2.3.4", "abuseipdb", {"score": 90}, 90)

        result = self.cache.get("1.2.3.4", "abuseipdb")
        self.assertEqual(result["data"]["score"], 90)


class TestThreatIntel(unittest.TestCase):
    """Test the Threat Intelligence lookup module."""

    def setUp(self):
        self.ti = ThreatIntel()

    def test_lookup_without_api_keys(self):
        """Test that lookup works gracefully without API keys."""
        result = self.ti.lookup_ip("8.8.8.8")
        self.assertEqual(result["ip"], "8.8.8.8")
        self.assertIn("sources", result)
        self.assertFalse(result["is_malicious"])
        self.assertEqual(result["threat_score"], 0)

    def test_lookup_result_structure(self):
        """Test that lookup returns expected structure."""
        result = self.ti.lookup_ip("1.1.1.1")
        required_keys = ["ip", "timestamp", "sources", "threat_score", "is_malicious", "tags"]
        for key in required_keys:
            self.assertIn(key, result)

    def test_lookup_private_ip(self):
        """Test lookup of a private IP address."""
        result = self.ti.lookup_ip("192.168.1.1")
        self.assertEqual(result["ip"], "192.168.1.1")
        # Private IPs should still return a valid structure
        self.assertIn("sources", result)


if __name__ == "__main__":
    unittest.main()
