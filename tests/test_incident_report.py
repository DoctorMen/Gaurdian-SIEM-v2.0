"""
Tests for incident_report.py — Professional Incident Report Generator
"""

import os
import sys
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from incident_report import IncidentReport, IncidentReportGenerator, MITRE_DESCRIPTIONS


class TestIncidentReport:
    """Tests for the IncidentReport data class."""

    def test_create_default_report(self):
        report = IncidentReport()
        assert report.incident_id.startswith("INC-")
        assert report.severity == "HIGH"
        assert report.classification == "Security Incident"
        assert len(report.timeline) == 0
        assert len(report.techniques) == 0

    def test_create_custom_report(self):
        report = IncidentReport(
            incident_id="INC-TEST-001",
            title="Test Incident",
            severity="CRITICAL",
            classification="Ransomware",
        )
        assert report.incident_id == "INC-TEST-001"
        assert report.title == "Test Incident"
        assert report.severity == "CRITICAL"

    def test_ioc_sets_initialized(self):
        report = IncidentReport()
        assert isinstance(report.iocs["ip_addresses"], set)
        assert isinstance(report.iocs["domains"], set)
        assert isinstance(report.iocs["file_paths"], set)
        assert isinstance(report.iocs["processes"], set)
        assert isinstance(report.iocs["users"], set)


class TestMitreDescriptions:
    """Tests for MITRE ATT&CK enrichment data."""

    def test_all_expected_techniques_present(self):
        expected = [
            "T1003", "T1110", "T1059.001", "T1046", "T1070.001",
            "T1543.003", "T1041", "T1059", "T1558.003", "T1021.001", "T1486",
        ]
        for tid in expected:
            assert tid in MITRE_DESCRIPTIONS, f"Missing MITRE description for {tid}"

    def test_technique_has_required_fields(self):
        for tid, info in MITRE_DESCRIPTIONS.items():
            assert "name" in info, f"{tid} missing name"
            assert "description" in info, f"{tid} missing description"
            assert "data_sources" in info, f"{tid} missing data_sources"
            assert "platforms" in info, f"{tid} missing platforms"
            assert len(info["name"]) > 0
            assert len(info["description"]) > 10


class TestIncidentReportGenerator:
    """Tests for the IncidentReportGenerator class."""

    def setup_method(self):
        self.gen = IncidentReportGenerator()

    def test_reports_dir_created(self):
        assert os.path.isdir(self.gen.reports_dir)

    def test_generate_from_db_no_events(self):
        """Should generate a report even with no events in DB."""
        path = self.gen.generate_from_db(hours=1, title="Test - No Events")
        assert path is not None
        assert os.path.isfile(path)
        # Clean up
        os.remove(path)

    def test_generated_report_is_html(self):
        """Report should be valid HTML."""
        path = self.gen.generate_from_db(hours=1, title="HTML Test")
        assert path.endswith(".html")
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        assert "<!DOCTYPE html>" in content
        assert "Guardian SIEM" in content
        assert "Executive Summary" in content
        assert "Remediation Plan" in content
        os.remove(path)

    def test_report_contains_all_sections(self):
        """Report must have all 7 required sections."""
        path = self.gen.generate_from_db(hours=1, title="Sections Test")
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        sections = [
            "Executive Summary",
            "Attack Kill Chain",
            "Technical Analysis",
            "Indicators of Compromise",
            "Impact Assessment",
            "Remediation Plan",
            "Lessons Learned",
        ]
        for section in sections:
            assert section in content, f"Missing section: {section}"
        os.remove(path)

    def test_extract_iocs_from_message(self):
        """IOC extraction should parse IPs, file paths, users, domains."""
        incident = IncidentReport()
        msg = (
            "Image: C:\\Users\\admin\\mimikatz.exe targeting "
            "http://evil.com/payload.ps1 "
            "User: CORP\\compromised_admin"
        )
        self.gen._extract_iocs_from_message(msg, incident)
        assert "C:\\Users\\admin\\mimikatz.exe" in incident.iocs["file_paths"]
        assert "evil.com" in incident.iocs["domains"]
        assert "CORP\\compromised_admin" in incident.iocs["users"]

    def test_extract_processes(self):
        incident = IncidentReport()
        msg = "SourceImage: C:\\temp\\mimikatz.exe TargetImage: C:\\Windows\\System32\\lsass.exe"
        self.gen._extract_iocs_from_message(msg, incident)
        assert "mimikatz.exe" in incident.iocs["processes"]
        # lsass.exe/svchost.exe should be filtered
        # (depends on regex matching—the filter checks system process names)

    def test_auto_classify_severity_critical(self):
        incident = IncidentReport()
        incident.max_threat_score = 95
        assert self.gen._auto_classify_severity(incident) == "CRITICAL"

    def test_auto_classify_severity_high(self):
        incident = IncidentReport()
        incident.max_threat_score = 70
        assert self.gen._auto_classify_severity(incident) == "HIGH"

    def test_auto_classify_severity_low(self):
        incident = IncidentReport()
        incident.max_threat_score = 10
        assert self.gen._auto_classify_severity(incident) == "LOW"

    def test_render_remediation_ransomware(self):
        """Ransomware incident should have specific remediation steps."""
        incident = IncidentReport()
        incident.techniques["T1486"] = [{"mitre_tactic": "Impact"}]
        html = self.gen._render_remediation(incident)
        assert "DO NOT PAY THE RANSOM" in html
        assert "immutable backup" in html.lower()

    def test_render_remediation_credential_theft(self):
        incident = IncidentReport()
        incident.techniques["T1003"] = [{"mitre_tactic": "Credential Access"}]
        incident.techniques["T1558.003"] = [{"mitre_tactic": "Credential Access"}]
        html = self.gen._render_remediation(incident)
        assert "krbtgt" in html
        assert "Credential Guard" in html

    def test_render_executive_summary_ransomware(self):
        incident = IncidentReport()
        incident.techniques["T1486"] = [{}]
        incident.severity = "CRITICAL"
        html = self.gen._render_executive_summary(incident)
        assert "ransomware" in html.lower()

    def test_render_executive_summary_exfiltration(self):
        incident = IncidentReport()
        incident.techniques["T1041"] = [{}]
        incident.severity = "HIGH"
        html = self.gen._render_executive_summary(incident)
        assert "exfiltration" in html.lower()

    def test_render_lessons_learned(self):
        incident = IncidentReport()
        html = self.gen._render_lessons_learned(incident)
        assert "Lessons" in html or "Detection" in html or "recommendations" in html.lower()

    def test_render_impact_assessment_lateral(self):
        incident = IncidentReport()
        incident.techniques["T1021.001"] = [{"mitre_tactic": "Lateral Movement"}]
        html = self.gen._render_impact_assessment(incident)
        assert "Lateral Movement" in html
