"""
Guardian SIEM v2.0 — Unit Tests: GeoIP Lookup
Tests GeoIP resolution, caching, and private IP detection.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from geoip_lookup import GeoIPLookup


class TestGeoIPLookup(unittest.TestCase):
    """Test suite for the GeoIP Lookup module."""

    def setUp(self):
        self.geo = GeoIPLookup()

    def test_private_ip_detection(self):
        """Test that private IPs are correctly identified."""
        private_ips = ["10.0.0.1", "172.16.0.1", "192.168.1.1", "127.0.0.1"]
        for ip in private_ips:
            self.assertTrue(
                GeoIPLookup._is_private(ip),
                f"{ip} should be detected as private"
            )

    def test_public_ip_not_private(self):
        """Test that public IPs are not marked as private."""
        public_ips = ["8.8.8.8", "1.1.1.1", "104.26.10.78"]
        for ip in public_ips:
            self.assertFalse(
                GeoIPLookup._is_private(ip),
                f"{ip} should NOT be detected as private"
            )

    def test_private_ip_lookup(self):
        """Test that private IPs return 'Private' country."""
        result = self.geo.lookup("192.168.1.1")
        self.assertEqual(result["country"], "Private")
        self.assertEqual(result["city"], "Local Network")

    def test_lookup_result_structure(self):
        """Test that lookup returns expected structure."""
        result = self.geo.lookup("192.168.1.1")
        required_keys = ["ip", "country", "country_code", "city", "latitude", "longitude"]
        for key in required_keys:
            self.assertIn(key, result, f"Missing key: {key}")

    def test_loopback_is_private(self):
        """Test that loopback address is treated as private."""
        result = self.geo.lookup("127.0.0.1")
        self.assertEqual(result["country"], "Private")

    def test_invalid_ip_handling(self):
        """Test graceful handling of invalid IP formats."""
        self.assertFalse(GeoIPLookup._is_private("not-an-ip"))
        self.assertFalse(GeoIPLookup._is_private("999.999.999.999"))


class TestGeoIPEdgeCases(unittest.TestCase):
    """Edge case tests for GeoIP private IP detection."""

    def test_172_range_boundaries(self):
        """Test 172.16-31.x.x range boundaries."""
        self.assertTrue(GeoIPLookup._is_private("172.16.0.1"))
        self.assertTrue(GeoIPLookup._is_private("172.31.255.255"))
        self.assertFalse(GeoIPLookup._is_private("172.15.0.1"))
        self.assertFalse(GeoIPLookup._is_private("172.32.0.1"))

    def test_10_range(self):
        """Test full 10.x.x.x range."""
        self.assertTrue(GeoIPLookup._is_private("10.0.0.0"))
        self.assertTrue(GeoIPLookup._is_private("10.255.255.255"))


if __name__ == "__main__":
    unittest.main()
