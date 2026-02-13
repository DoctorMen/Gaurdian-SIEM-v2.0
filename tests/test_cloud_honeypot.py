"""
Tests for cloud_honeypot.py — Cloud Honeypot Log Parser
"""

import os
import sys
import json
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from cloud_honeypot import CloudHoneypotParser, CloudLogEvent


class TestCloudLogEvent:
    """Tests for the CloudLogEvent data class."""

    def test_create_event(self):
        event = CloudLogEvent(
            timestamp="2025-01-01T12:00:00Z",
            source_ip="198.51.100.1",
            action="GetObject",
            resource="s3://bucket/file.txt",
            user_agent="Shodan/3.0",
            status="AccessDenied",
        )
        assert event.source_ip == "198.51.100.1"
        assert event.action == "GetObject"
        assert event.status == "AccessDenied"

    def test_to_dict(self):
        event = CloudLogEvent(
            timestamp="2025-01-01T12:00:00Z",
            source_ip="198.51.100.1",
            action="ListBuckets",
            resource="bucket-name",
        )
        d = event.to_dict()
        assert d["source_ip"] == "198.51.100.1"
        assert d["action"] == "ListBuckets"
        assert "timestamp" in d

    def test_extra_fields(self):
        event = CloudLogEvent(
            timestamp="2025-01-01T12:00:00Z",
            source_ip="198.51.100.1",
            action="Test",
            resource="test",
            extra={"custom_field": "custom_value"},
        )
        d = event.to_dict()
        assert d["custom_field"] == "custom_value"


class TestCloudHoneypotParser:
    """Tests for the CloudHoneypotParser class."""

    def setup_method(self):
        self.parser = CloudHoneypotParser()

    def test_directories_created(self):
        assert os.path.isdir(self.parser.logs_dir)
        assert os.path.isdir(self.parser.reports_dir)

    def test_generate_sample_logs(self):
        """Sample log generation should create 2 files."""
        paths = self.parser.generate_sample_logs()
        assert len(paths) == 2
        for path in paths:
            assert os.path.isfile(path)
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            assert isinstance(data, dict)

    def test_parse_cloudtrail_sample(self):
        """Should parse the generated CloudTrail sample."""
        paths = self.parser.generate_sample_logs()
        aws_path = [p for p in paths if "cloudtrail" in p][0]
        events = self.parser.parse_file(aws_path, log_format="aws")
        assert len(events) > 100
        assert all(isinstance(e, CloudLogEvent) for e in events)

    def test_parse_azure_sample(self):
        """Should parse the generated Azure sample."""
        paths = self.parser.generate_sample_logs()
        azure_path = [p for p in paths if "azure" in p][0]
        events = self.parser.parse_file(azure_path, log_format="azure")
        assert len(events) > 50
        assert all(isinstance(e, CloudLogEvent) for e in events)

    def test_auto_detect_aws_format(self):
        """Format detection should recognize CloudTrail."""
        data = {"Records": [{"eventName": "GetObject"}]}
        fmt = self.parser._detect_format(data)
        assert fmt == "aws"

    def test_auto_detect_azure_format(self):
        data = {"value": [{"operationName": "test"}]}
        fmt = self.parser._detect_format(data)
        assert fmt == "azure"

    def test_auto_detect_gcp_format(self):
        data = {"entries": [{"methodName": "test"}]}
        fmt = self.parser._detect_format(data)
        assert fmt == "gcp"

    def test_auto_detect_generic_format(self):
        data = {"something_else": []}
        fmt = self.parser._detect_format(data)
        assert fmt == "generic"

    def test_analyze_with_data(self):
        """Analysis should produce a structured report."""
        # Generate and parse sample data first
        self.parser.generate_sample_logs()
        self.parser.parse_directory(self.parser.logs_dir)
        report = self.parser.analyze()

        assert "error" not in report
        assert report["summary"]["total_events"] > 0
        assert report["summary"]["unique_source_ips"] > 0
        assert len(report["top_ips"]) > 0
        assert len(report["top_actions"]) > 0

    def test_analyze_empty(self):
        """Analysis with no events should return error."""
        parser = CloudHoneypotParser()
        parser.events = []
        report = parser.analyze()
        assert "error" in report

    def test_generate_html_report(self):
        """HTML report should be generated from analysis."""
        self.parser.generate_sample_logs()
        self.parser.parse_directory(self.parser.logs_dir)
        report_data = self.parser.analyze()
        path = self.parser.generate_report(report_data)

        assert path is not None
        assert os.path.isfile(path)
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        assert "<!DOCTYPE html>" in content
        assert "Guardian SIEM" in content
        assert "Honeypot" in content

    def test_recommendations_generated(self):
        """Recommendations should be generated based on data."""
        self.parser.generate_sample_logs()
        self.parser.parse_directory(self.parser.logs_dir)
        report = self.parser.analyze()
        assert len(report["recommendations"]) > 0
        for rec in report["recommendations"]:
            assert "priority" in rec
            assert "finding" in rec
            assert "recommendation" in rec

    def test_parse_generic_format(self):
        """Generic JSON format should be parseable."""
        test_data = [
            {"timestamp": "2025-01-01T00:00:00Z", "source_ip": "1.2.3.4",
             "action": "read", "resource": "test"},
            {"timestamp": "2025-01-01T00:01:00Z", "ip": "5.6.7.8",
             "event": "write", "target": "test2"},
        ]
        test_path = os.path.join(self.parser.logs_dir, "test_generic.json")
        with open(test_path, "w", encoding="utf-8") as f:
            json.dump(test_data, f)

        events = self.parser.parse_file(test_path, log_format="generic")
        assert len(events) == 2
        assert events[0].source_ip == "1.2.3.4"
        assert events[1].source_ip == "5.6.7.8"

        # Cleanup
        os.remove(test_path)

    def test_emit_to_siem(self):
        """Emitting events to SIEM should not raise errors."""
        self.parser.events = [
            CloudLogEvent(
                timestamp="2025-01-01T00:00:00Z",
                source_ip="198.51.100.1",
                action="ListBuckets",
                resource="honeypot-bucket",
                user_agent="Shodan/3.0",
                status="AccessDenied",
            ),
            CloudLogEvent(
                timestamp="2025-01-01T00:01:00Z",
                source_ip="203.0.113.5",
                action="GetObject",
                resource="honeypot-bucket",
                user_agent="python-requests/2.28",
                status="Success",
            ),
        ]
        count = self.parser.emit_to_siem()
        assert count == 2

    def test_scanner_detection(self):
        """Known scanners should be detected in analysis."""
        self.parser.events = [
            CloudLogEvent(
                timestamp="2025-01-01T00:00:00Z",
                source_ip="198.51.100.1",
                action="ListBuckets",
                resource="bucket",
                user_agent="Shodan/3.0",
                status="Success",
            ),
            CloudLogEvent(
                timestamp="2025-01-01T00:00:00Z",
                source_ip="198.51.100.2",
                action="ListBuckets",
                resource="bucket",
                user_agent="censys/2.0",
                status="Success",
            ),
        ]
        report = self.parser.analyze()
        assert report["summary"]["known_scanners_detected"] == 2
        scanner_names = [s["scanner"] for s in report["scanners_detected"]]
        assert "Shodan" in scanner_names
        assert "Censys" in scanner_names
