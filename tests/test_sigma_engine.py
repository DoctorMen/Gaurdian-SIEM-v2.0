"""Tests for SIGMA Engine"""

import os
import sys
import yaml
import tempfile
import shutil
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from sigma_engine import SigmaEngine, SigmaRule


@pytest.fixture
def temp_rules_dir():
    d = tempfile.mkdtemp()
    yield d
    shutil.rmtree(d)


@pytest.fixture
def sample_rule_data():
    return {
        "title": "Test Failed Logon",
        "id": "test-001",
        "status": "stable",
        "level": "high",
        "description": "Detects failed logon",
        "author": "Test",
        "tags": ["attack.credential_access", "attack.t1110"],
        "logsource": {"product": "windows", "service": "security"},
        "detection": {
            "selection": {"EventID": [4625]},
            "condition": "selection",
        },
    }


class TestSigmaRule:
    def test_parse_basic_rule(self, sample_rule_data):
        rule = SigmaRule(sample_rule_data)
        assert rule.title == "Test Failed Logon"
        assert rule.severity == "HIGH"
        assert rule.mitre_id == "T1110"
        assert rule.mitre_tactic == "Credential Access"

    def test_level_mapping(self):
        for level, expected in [("critical", "CRITICAL"), ("high", "HIGH"),
                                ("medium", "MEDIUM"), ("low", "LOW"),
                                ("informational", "INFO")]:
            rule = SigmaRule({"title": "t", "level": level, "detection": {"condition": "selection"}})
            assert rule.severity == expected

    def test_sigma_wildcards(self):
        val = SigmaRule._sigma_to_regex("*.exe", [])
        assert val == "^.*\\.exe$"

    def test_contains_modifier(self):
        val = SigmaRule._sigma_to_regex("IEX(", ["contains"])
        assert "^" not in val
        assert "$" not in val

    def test_startswith_modifier(self):
        val = SigmaRule._sigma_to_regex("cmd", ["startswith"])
        assert val.startswith("^")

    def test_endswith_modifier(self):
        val = SigmaRule._sigma_to_regex(".exe", ["endswith"])
        assert val.endswith("$")


class TestSigmaEngine:
    def test_load_creates_sample_rules(self, temp_rules_dir):
        engine = SigmaEngine(rules_dir=temp_rules_dir)
        assert len(engine.rules) > 0

    def test_evaluate_keyword_match(self, temp_rules_dir):
        rule_data = {
            "title": "Test Keyword",
            "level": "medium",
            "logsource": {"product": "windows"},
            "detection": {
                "selection": ["failed login", "access denied"],
                "condition": "selection",
            },
        }
        filepath = os.path.join(temp_rules_dir, "test.yml")
        with open(filepath, "w") as f:
            yaml.dump(rule_data, f)

        engine = SigmaEngine(rules_dir=temp_rules_dir)
        matches = engine.evaluate({"source": "windows", "message": "User failed login attempt"})
        assert len(matches) >= 1
        assert matches[0]["rule_name"] == "Test Keyword"

    def test_evaluate_no_match(self, temp_rules_dir):
        rule_data = {
            "title": "No Match",
            "level": "low",
            "logsource": {"product": "linux"},
            "detection": {
                "selection": ["segfault"],
                "condition": "selection",
            },
        }
        filepath = os.path.join(temp_rules_dir, "nomatch.yml")
        with open(filepath, "w") as f:
            yaml.dump(rule_data, f)

        engine = SigmaEngine(rules_dir=temp_rules_dir)
        matches = engine.evaluate({"source": "windows", "message": "Normal event"})
        assert len(matches) == 0

    def test_evaluate_field_selection(self, temp_rules_dir):
        rule_data = {
            "title": "EventID Match",
            "level": "high",
            "logsource": {"product": "windows"},
            "detection": {
                "selection": {"EventID": [4625]},
                "condition": "selection",
            },
        }
        filepath = os.path.join(temp_rules_dir, "field.yml")
        with open(filepath, "w") as f:
            yaml.dump(rule_data, f)

        engine = SigmaEngine(rules_dir=temp_rules_dir)
        matches = engine.evaluate({"source": "windows", "message": "Event 4625 failed logon", "EventID": "4625"})
        assert len(matches) >= 1

    def test_condition_and_not(self, temp_rules_dir):
        rule_data = {
            "title": "Selection And Not Filter",
            "level": "medium",
            "logsource": {"product": "windows"},
            "detection": {
                "selection": ["login attempt"],
                "filter": ["service_account"],
                "condition": "selection and not filter",
            },
        }
        filepath = os.path.join(temp_rules_dir, "andnot.yml")
        with open(filepath, "w") as f:
            yaml.dump(rule_data, f)

        engine = SigmaEngine(rules_dir=temp_rules_dir)

        # Should match: has selection but no filter
        matches = engine.evaluate({"source": "windows", "message": "User login attempt from admin"})
        assert len(matches) >= 1

        # Should NOT match: has both selection and filter
        matches = engine.evaluate({"source": "windows", "message": "service_account login attempt"})
        assert len(matches) == 0

    def test_get_rules_summary(self, temp_rules_dir):
        engine = SigmaEngine(rules_dir=temp_rules_dir)
        summary = engine.get_rules_summary()
        assert isinstance(summary, list)
        if summary:
            assert "title" in summary[0]
            assert "severity" in summary[0]

    def test_reload_rules(self, temp_rules_dir):
        engine = SigmaEngine(rules_dir=temp_rules_dir)
        initial = len(engine.rules)
        engine.reload_rules()
        assert len(engine.rules) == initial
