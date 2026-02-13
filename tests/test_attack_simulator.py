"""
Tests for attack_simulator.py — Purple Team Attack Simulator
"""

import os
import sys
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from attack_simulator import AttackSimulator, AtomicTest


class TestAtomicTest:
    """Tests for the AtomicTest data class."""

    def test_create_atomic_test(self):
        test = AtomicTest(
            technique_id="T9999",
            technique_name="Test Technique",
            tactic="Testing",
            description="A test technique",
            events=[("src", "HIGH", "message", {})],
            expected_rules=["Rule1"],
            severity="HIGH",
        )
        assert test.technique_id == "T9999"
        assert test.technique_name == "Test Technique"
        assert test.tactic == "Testing"
        assert len(test.events) == 1
        assert test.expected_rules == ["Rule1"]
        assert test.severity == "HIGH"

    def test_default_expected_rules(self):
        test = AtomicTest("T0000", "Test", "Test", "Test", [])
        assert test.expected_rules == []
        assert test.severity == "HIGH"


class TestAttackSimulator:
    """Tests for the AttackSimulator class."""

    def setup_method(self):
        self.sim = AttackSimulator()

    def test_all_techniques_registered(self):
        """Verify all 11 expected techniques are registered."""
        expected = [
            "T1003", "T1110", "T1059.001", "T1046", "T1070.001",
            "T1543.003", "T1041", "T1059", "T1558.003", "T1021.001", "T1486",
        ]
        for tid in expected:
            assert tid in self.sim.tests, f"Technique {tid} not registered"
        assert len(self.sim.tests) == 11

    def test_all_campaigns_registered(self):
        """Verify all 3 campaigns are registered."""
        assert "apt29" in self.sim.campaigns
        assert "ransomware" in self.sim.campaigns
        assert "insider" in self.sim.campaigns
        assert len(self.sim.campaigns) == 3

    def test_technique_has_events(self):
        """Every technique must have at least one event."""
        for tid, test in self.sim.tests.items():
            assert len(test.events) > 0, f"{tid} has no events"

    def test_technique_events_have_required_fields(self):
        """Each event tuple must have (source, severity, message, enrichment)."""
        for tid, test in self.sim.tests.items():
            for i, event in enumerate(test.events):
                assert len(event) == 4, f"{tid} event {i} doesn't have 4 fields"
                source, severity, message, enrichment = event
                assert isinstance(source, str), f"{tid} event {i} source not str"
                assert severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"), \
                    f"{tid} event {i} invalid severity: {severity}"
                assert isinstance(message, str) and len(message) > 0, \
                    f"{tid} event {i} empty message"
                assert isinstance(enrichment, dict), f"{tid} event {i} enrichment not dict"

    def test_all_techniques_have_mitre_id(self):
        """Every technique's events must include mitre_id in enrichment."""
        for tid, test in self.sim.tests.items():
            for event in test.events:
                enrichment = event[3]
                assert "mitre_id" in enrichment, f"{tid} missing mitre_id"

    def test_run_test_valid_technique(self):
        """Running a valid technique should return results."""
        result = self.sim.run_test("T1070.001", delay=0)
        assert result is not None
        assert result["technique_id"] == "T1070.001"
        assert result["status"] == "COMPLETED"
        assert result["events_emitted"] == 2

    def test_run_test_unknown_technique(self):
        """Running an unknown technique should return None."""
        result = self.sim.run_test("T9999", delay=0)
        assert result is None

    def test_run_campaign_apt29(self):
        """APT29 campaign should execute all its techniques."""
        result = self.sim.run_campaign("apt29", delay=0)
        assert result is not None
        assert result["techniques_executed"] == 6
        assert result["total_events"] > 0

    def test_run_campaign_ransomware(self):
        """Ransomware campaign should include T1486."""
        campaign = self.sim.campaigns["ransomware"]
        assert "T1486" in campaign["techniques"]
        assert "T1110" in campaign["techniques"]

    def test_run_campaign_unknown(self):
        """Unknown campaign should return None."""
        result = self.sim.run_campaign("nonexistent", delay=0)
        assert result is None

    def test_run_all_tests(self):
        """Run all tests and verify results."""
        results = self.sim.run_all_tests(delay=0)
        assert len(results) == 11
        total_events = sum(r["events_emitted"] for r in results)
        assert total_events > 50  # Should be ~70+ events

    def test_credential_dumping_events(self):
        """T1003 should have Mimikatz-related events."""
        test = self.sim.tests["T1003"]
        messages = [e[2] for e in test.events]
        assert any("mimikatz" in m.lower() for m in messages)
        assert any("lsass" in m.lower() for m in messages)

    def test_brute_force_event_count(self):
        """T1110 should have 12 failed + 1 success = 13 events."""
        test = self.sim.tests["T1110"]
        assert len(test.events) == 13

    def test_kerberoasting_events(self):
        """T1558.003 should reference RC4 and Event ID 4769."""
        test = self.sim.tests["T1558.003"]
        messages = [e[2] for e in test.events]
        assert any("4769" in m for m in messages)
        assert any("RC4" in m for m in messages)

    def test_ransomware_events(self):
        """T1486 should include encryption and ransom note events."""
        test = self.sim.tests["T1486"]
        messages = [e[2] for e in test.events]
        assert any("encrypted" in m.lower() for m in messages)
        assert any("ransom" in m.lower() for m in messages)

    def test_list_tests(self, capsys):
        """list_tests() should print without errors."""
        self.sim.list_tests()
        captured = capsys.readouterr()
        assert "T1003" in captured.out
        assert "apt29" in captured.out

    def test_detection_coverage_no_db(self):
        """Coverage report should handle missing database gracefully."""
        report = self.sim.get_detection_coverage()
        # Should either return results or an error dict
        assert isinstance(report, dict)

    def test_campaign_techniques_exist(self):
        """All techniques referenced in campaigns must exist in tests."""
        for cid, campaign in self.sim.campaigns.items():
            for tid in campaign["techniques"]:
                assert tid in self.sim.tests, \
                    f"Campaign '{cid}' references unknown technique '{tid}'"
