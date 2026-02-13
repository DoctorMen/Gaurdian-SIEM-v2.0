"""Tests for Syslog Receiver (UDP/TCP)"""

import os
import sys
import tempfile
import pytest
import yaml

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from syslog_receiver import SyslogReceiver


@pytest.fixture
def receiver(tmp_path):
    """Create a SyslogReceiver with a temp config."""
    config = {
        "syslog": {
            "udp_enabled": True,
            "tcp_enabled": True,
            "udp_port": 0,
            "tcp_port": 0,
            "bind_address": "127.0.0.1"
        }
    }
    config_file = str(tmp_path / "config.yaml")
    with open(config_file, "w") as f:
        yaml.dump(config, f)
    r = SyslogReceiver(config_path=config_file)
    return r


class TestSyslogReceiver:
    def test_parse_rfc3164(self, receiver):
        msg = "<34>Oct 11 22:14:15 mymachine su: 'su root' failed for testuser"
        parsed = receiver.parse_syslog(msg)
        assert parsed["facility_code"] == 4  # auth
        assert parsed["severity_code"] == 2  # critical
        assert "su root" in parsed.get("message", msg)

    def test_parse_rfc5424(self, receiver):
        msg = '<165>1 2023-08-25T12:00:00Z myhost app 1234 ID47 [exampleSDID@32473 iut="3" eventSource="Application"] Test message'
        parsed = receiver.parse_syslog(msg)
        assert parsed is not None
        assert "severity_code" in parsed
        assert parsed["hostname"] == "myhost"
        assert parsed["app_name"] == "app"

    def test_parse_priority(self, receiver):
        """Test PRI field decoding."""
        msg = "<13>Oct  1 12:00:00 host test: Test message"
        parsed = receiver.parse_syslog(msg)
        # PRI 13 = facility 1 (user), severity 5 (notice)
        assert parsed["facility_code"] == 1
        assert parsed["severity_code"] == 5

    def test_stats_initial(self, receiver):
        stats = receiver.get_stats()
        assert stats["total_messages"] == 0
        assert stats["parse_errors"] == 0

    def test_callback_registration(self, receiver):
        results = []
        receiver.set_callback(lambda src, sev, raw, parsed: results.append(parsed))
        assert receiver._message_callback is not None

    def test_severity_mapping(self, receiver):
        """Verify severity code to Guardian severity mapping."""
        mapping = {
            0: "CRITICAL", 1: "CRITICAL", 2: "CRITICAL",
            3: "HIGH", 4: "MEDIUM", 5: "LOW", 6: "INFO", 7: "INFO"
        }
        for code, expected in mapping.items():
            result = receiver._severity_map.get(code)
            assert result == expected, f"Severity {code} should be {expected}, got {result}"

    def test_facility_mapping(self, receiver):
        """Verify facility code to name mapping."""
        assert receiver._facilities[0] == "kern"
        assert receiver._facilities[1] == "user"
        assert receiver._facilities[4] == "auth"

    def test_parse_no_priority(self, receiver):
        """Messages without PRI should still be handled."""
        msg = "Plain message without priority"
        parsed = receiver.parse_syslog(msg)
        assert parsed is not None
        assert "message" in parsed
        # Should increment parse_errors since no PRI found
        assert receiver._stats["parse_errors"] == 1

    def test_parse_rfc5424_structured_data(self, receiver):
        msg = '<165>1 2023-08-25T12:00:00Z myhost app 1234 ID47 [exampleSDID@32473 iut="3" eventSource="Application"] Test message'
        parsed = receiver.parse_syslog(msg)
        assert "exampleSDID@32473" in parsed["structured_data"]
        sd = parsed["structured_data"]["exampleSDID@32473"]
        assert sd["iut"] == "3"
        assert sd["eventSource"] == "Application"
