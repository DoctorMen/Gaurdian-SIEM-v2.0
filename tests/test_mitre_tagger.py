"""
Guardian SIEM v2.0 — Unit Tests: MITRE Tagger
Tests technique enrichment, tactic lookups, and data integrity.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mitre_tagger import MitreTagger


class TestMitreTagger(unittest.TestCase):
    """Test suite for the MITRE ATT&CK Tagger module."""

    def setUp(self):
        self.tagger = MitreTagger()

    def test_load_mappings(self):
        """Test that techniques and tactics are loaded from YAML."""
        self.assertGreater(len(self.tagger.techniques), 0)
        self.assertGreater(len(self.tagger.tactics), 0)

    def test_enrich_known_technique(self):
        """Test enrichment of a known technique ID."""
        result = self.tagger.enrich("T1110")
        self.assertEqual(result["mitre_id"], "T1110")
        self.assertEqual(result["technique_name"], "Brute Force")
        self.assertEqual(result["tactic"], "Credential Access")
        self.assertIn("reference_url", result)
        self.assertGreater(result["severity_weight"], 0)

    def test_enrich_subtechnique(self):
        """Test enrichment of a sub-technique (T1070.001)."""
        result = self.tagger.enrich("T1070.001")
        self.assertEqual(result["mitre_id"], "T1070.001")
        self.assertIn("Clear", result["technique_name"])
        self.assertIn("attack.mitre.org", result["reference_url"])

    def test_enrich_unknown_technique(self):
        """Test graceful handling of unknown technique IDs."""
        result = self.tagger.enrich("T9999")
        self.assertEqual(result["technique_name"], "Unknown")
        self.assertIn("reference_url", result)

    def test_enrich_empty_id(self):
        """Test handling of empty/None technique ID."""
        result = self.tagger.enrich("")
        self.assertEqual(result["technique_name"], "Unknown")

        result = self.tagger.enrich(None)
        self.assertEqual(result["technique_name"], "Unknown")

    def test_get_tactic_summary(self):
        """Test tactic summary generation."""
        summary = self.tagger.get_tactic_summary()
        self.assertGreater(len(summary), 0)
        for tactic_id, info in summary.items():
            self.assertIn("name", info)
            self.assertIn("description", info)

    def test_get_technique_by_tactic(self):
        """Test filtering techniques by tactic name."""
        results = self.tagger.get_technique_by_tactic("Credential Access")
        self.assertGreater(len(results), 0)
        for tid, info in results.items():
            self.assertEqual(info["tactic"], "Credential Access")

    def test_reference_url_format(self):
        """Test that reference URLs are properly formatted."""
        result = self.tagger.enrich("T1070.001")
        # Sub-technique URL should use / instead of .
        self.assertIn("T1070/001", result["reference_url"])


if __name__ == "__main__":
    unittest.main()
