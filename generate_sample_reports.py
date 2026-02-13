"""
Generate sample reports for the Guardian SIEM portfolio.
Run this script to create demo incident reports and honeypot reports.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from incident_report import IncidentReportGenerator
from cloud_honeypot import CloudHoneypotParser


def main():
    print("=" * 65)
    print("  Guardian SIEM — Sample Report Generator")
    print("  Generating portfolio-ready demonstration reports")
    print("=" * 65)

    gen = IncidentReportGenerator()

    # 1. APT29 Campaign Incident Report
    print("\n  [1/4] Generating APT29 campaign incident report...")
    path = gen.generate_from_simulator(
        campaign="apt29",
        title="INC-2025-017: APT29 (Cozy Bear) Intrusion — Full Kill Chain"
    )
    print(f"        -> {path}")

    # 2. Ransomware Campaign Incident Report
    print("\n  [2/4] Generating ransomware campaign incident report...")
    path = gen.generate_from_simulator(
        campaign="ransomware",
        title="INC-2025-042: Human-Operated Ransomware Deployment"
    )
    print(f"        -> {path}")

    # 3. Insider Threat Incident Report
    print("\n  [3/4] Generating insider threat incident report...")
    path = gen.generate_from_simulator(
        campaign="insider",
        title="INC-2025-008: Insider Threat — Data Exfiltration"
    )
    print(f"        -> {path}")

    # 4. Cloud Honeypot Report
    print("\n  [4/4] Generating cloud honeypot intelligence report...")
    hp = CloudHoneypotParser()
    hp.generate_sample_logs()
    hp.parse_directory(hp.logs_dir)
    report_data = hp.analyze()
    path = hp.generate_report(report_data)
    print(f"        -> {path}")

    print("\n" + "=" * 65)
    print("  All reports generated! Open HTML files in a browser.")
    print("  Reports directory: reports/incidents/ and reports/honeypot/")
    print("=" * 65)


if __name__ == "__main__":
    main()
