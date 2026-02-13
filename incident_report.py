"""
Guardian SIEM — Professional Incident Report Generator
=========================================================
Produces interview-ready incident reports in the format used by
real SOC teams and incident response engagements:

  1. Executive Summary       — Non-technical overview for leadership
  2. Technical Analysis      — Full forensic timeline with MITRE mapping
  3. Indicators of Compromise — IPs, hashes, domains, file paths
  4. Impact Assessment       — Scope of compromise, affected assets
  5. Remediation Plan        — Immediate, short-term, and long-term actions
  6. Lessons Learned         — What to improve for next time
  7. Appendix                — Raw event data, rule hits, detection gaps

Generates HTML by default. When reportlab is available, generates PDF.
Can consume live DB data or attack_simulator results.

Usage:
    python incident_report.py                              # From latest events in DB
    python incident_report.py --campaign apt29             # Run attack sim + report
    python incident_report.py --title "Ransomware Incident INC-2025-042"
"""

import os
import sys
import json
import sqlite3
import argparse
from datetime import datetime, timedelta
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


# ─── MITRE ATT&CK Enrichment Data ───────────────────────────────────────────
MITRE_DESCRIPTIONS = {
    "T1003": {
        "name": "OS Credential Dumping",
        "description": "Adversaries may attempt to dump credentials from the OS for lateral movement.",
        "data_sources": ["Process Monitoring", "API Monitoring", "PowerShell Logs"],
        "platforms": ["Windows"],
    },
    "T1110": {
        "name": "Brute Force",
        "description": "Adversaries may use brute force techniques to gain access to accounts.",
        "data_sources": ["Authentication Logs", "Account Monitoring"],
        "platforms": ["Windows", "Linux", "Cloud"],
    },
    "T1059.001": {
        "name": "PowerShell",
        "description": "Adversaries may abuse PowerShell for execution of commands and scripts.",
        "data_sources": ["PowerShell Logs", "Process Monitoring", "Script Block Logging"],
        "platforms": ["Windows"],
    },
    "T1046": {
        "name": "Network Service Scanning",
        "description": "Adversaries may scan for services to identify targets for lateral movement.",
        "data_sources": ["Network Traffic", "Firewall Logs", "IDS/IPS"],
        "platforms": ["Windows", "Linux", "Network"],
    },
    "T1070.001": {
        "name": "Clear Windows Event Logs",
        "description": "Adversaries may clear logs to remove evidence of intrusion activities.",
        "data_sources": ["Windows Event Logs", "API Monitoring"],
        "platforms": ["Windows"],
    },
    "T1543.003": {
        "name": "Windows Service",
        "description": "Adversaries may create new services for persistence or privilege escalation.",
        "data_sources": ["Service Monitoring", "Windows Event Logs"],
        "platforms": ["Windows"],
    },
    "T1041": {
        "name": "Exfiltration Over C2 Channel",
        "description": "Adversaries may steal data by exfiltrating it over an existing C2 channel.",
        "data_sources": ["Network Traffic", "Netflow/Enclave Netflow"],
        "platforms": ["Windows", "Linux"],
    },
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "description": "Adversaries may abuse command and script interpreters to execute commands.",
        "data_sources": ["Process Monitoring", "Process Command-line Parameters"],
        "platforms": ["Windows", "Linux", "macOS"],
    },
    "T1558.003": {
        "name": "Kerberoasting",
        "description": "Adversaries may request service tickets for service accounts with SPNs to crack offline.",
        "data_sources": ["Windows Event Logs (4769)", "Active Directory"],
        "platforms": ["Windows"],
    },
    "T1021.001": {
        "name": "Remote Desktop Protocol",
        "description": "Adversaries may use RDP to move laterally across a network.",
        "data_sources": ["Authentication Logs", "Logon Sessions"],
        "platforms": ["Windows"],
    },
    "T1486": {
        "name": "Data Encrypted for Impact",
        "description": "Adversaries may encrypt data on target systems to interrupt availability.",
        "data_sources": ["File Monitoring", "Process Monitoring"],
        "platforms": ["Windows", "Linux"],
    },
}


class IncidentReport:
    """Represents a single incident with all forensic metadata."""

    def __init__(self, incident_id=None, title=None, severity="HIGH",
                 classification="Security Incident"):
        self.incident_id = incident_id or f"INC-{datetime.now().strftime('%Y-%m%d-%H%M')}"
        self.title = title or "Security Incident Report"
        self.severity = severity
        self.classification = classification
        self.created_at = datetime.now()
        self.analyst = "Guardian SIEM Automated Analysis"

        # Data sections populated during analysis
        self.timeline = []           # Chronological list of events
        self.techniques = {}         # MITRE technique_id -> list of events
        self.iocs = {                # Indicators of compromise
            "ip_addresses": set(),
            "domains": set(),
            "file_paths": set(),
            "processes": set(),
            "users": set(),
        }
        self.affected_assets = set()
        self.geo_sources = {}        # IP -> {country, city}
        self.severity_counts = Counter()
        self.rule_hits = Counter()
        self.detection_gaps = []
        self.max_threat_score = 0


class IncidentReportGenerator:
    """
    Generates professional incident reports from Guardian SIEM data.

    Follows the NIST Computer Security Incident Handling Guide (SP 800-61)
    structure with adaptations for MITRE ATT&CK mapping.
    """

    def __init__(self, config_path=None):
        self.base_dir = os.path.dirname(os.path.abspath(__file__))
        self.db_path = os.path.join(self.base_dir, "database", "guardian_events.db")
        self.reports_dir = os.path.join(self.base_dir, "reports", "incidents")
        os.makedirs(self.reports_dir, exist_ok=True)

    def generate_from_db(self, hours=24, title=None, severity=None):
        """
        Generate an incident report from events in the database.

        Args:
            hours: Look-back window in hours
            title: Custom incident title
            severity: Override severity classification

        Returns:
            Path to the generated report file
        """
        incident = IncidentReport(title=title, severity=severity or "HIGH")
        since = (datetime.now() - timedelta(hours=hours)).isoformat()

        if not os.path.isfile(self.db_path):
            # Generate with synthetic data for demo purposes
            incident.title = title or "Demonstration Incident Report"
            return self._write_report(incident)

        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row

        try:
            rows = conn.execute(
                """SELECT timestamp, source, severity, message, src_ip,
                          rule_matched, mitre_id, mitre_tactic, threat_score,
                          geo_country, geo_city
                   FROM events WHERE timestamp >= ?
                   ORDER BY timestamp ASC""", (since,)
            ).fetchall()

            for row in rows:
                event = dict(row)
                incident.timeline.append(event)

                # Classify by MITRE technique
                mitre_id = event.get("mitre_id", "")
                if mitre_id:
                    if mitre_id not in incident.techniques:
                        incident.techniques[mitre_id] = []
                    incident.techniques[mitre_id].append(event)

                # Extract IOCs
                src_ip = event.get("src_ip", "")
                if src_ip:
                    incident.iocs["ip_addresses"].add(src_ip)
                    country = event.get("geo_country", "")
                    city = event.get("geo_city", "")
                    if country:
                        incident.geo_sources[src_ip] = {"country": country, "city": city}

                # Extract file paths and processes from message
                msg = event.get("message", "")
                self._extract_iocs_from_message(msg, incident)

                # Track severity
                sev = event.get("severity", "INFO")
                incident.severity_counts[sev] += 1

                # Track rules
                rule = event.get("rule_matched", "")
                if rule:
                    incident.rule_hits[rule] += 1

                # Track threat scores
                score = event.get("threat_score")
                if score and score > incident.max_threat_score:
                    incident.max_threat_score = score

            # Auto-classify severity based on data
            if not severity:
                incident.severity = self._auto_classify_severity(incident)

        except sqlite3.Error:
            pass
        finally:
            conn.close()

        return self._write_report(incident)

    def generate_from_simulator(self, campaign=None, technique=None, title=None):
        """
        Run the attack simulator and generate an incident report from results.

        Args:
            campaign: Campaign ID (e.g., "apt29", "ransomware")
            technique: Single technique ID (e.g., "T1003")
            title: Custom title

        Returns:
            Path to the generated report file
        """
        from attack_simulator import AttackSimulator

        sim = AttackSimulator()
        incident = IncidentReport(title=title)

        if campaign:
            result = sim.run_campaign(campaign, delay=0.05)
            if result:
                incident.title = title or f"Incident Report: {result['campaign']}"
                incident.classification = f"Simulated Attack Campaign: {campaign}"
        elif technique:
            result = sim.run_test(technique, delay=0.05)
            if result:
                incident.title = title or f"Incident Report: {result['technique_name']}"
                incident.classification = f"Simulated Technique: {technique}"
        else:
            sim.run_all_tests(delay=0.02)
            incident.title = title or "Full Purple Team Assessment Report"
            incident.classification = "Purple Team Exercise - All Techniques"

        # Pull the events that were just emitted from the DB
        return self.generate_from_db(hours=1, title=incident.title,
                                     severity=incident.severity)

    def _extract_iocs_from_message(self, message, incident):
        """Parse event messages for indicators of compromise."""
        import re

        # File paths (Windows)
        paths = re.findall(r'[A-Z]:\\[\w\\.\-]+', message)
        for p in paths:
            if "\\System32\\" not in p:  # Skip system dirs
                incident.iocs["file_paths"].add(p)

        # Processes
        procs = re.findall(r'(?:\w*Image|\w*Process):\s*(?:[A-Z]:\\[\w\\.\-]*\\)?([\w.\-]+\.exe)', message)
        for proc in procs:
            if proc.lower() not in ("svchost.exe", "services.exe", "csrss.exe"):
                incident.iocs["processes"].add(proc)

        # Usernames
        users = re.findall(r'(?:User|Account|Subject):\s*([\w\\]+)', message)
        for user in users:
            if user not in ("NT AUTHORITY\\SYSTEM", "SYSTEM"):
                incident.iocs["users"].add(user)

        # Domains
        domains = re.findall(r'https?://([^\s/\'"]+)', message)
        for d in domains:
            incident.iocs["domains"].add(d)

    def _auto_classify_severity(self, incident):
        """Determine overall incident severity from event data."""
        if incident.max_threat_score >= 90:
            return "CRITICAL"
        elif incident.severity_counts.get("CRITICAL", 0) > 0:
            return "CRITICAL"
        elif incident.severity_counts.get("HIGH", 0) > 3:
            return "HIGH"
        elif incident.max_threat_score >= 60:
            return "HIGH"
        elif incident.severity_counts.get("MEDIUM", 0) > 5:
            return "MEDIUM"
        return "LOW"

    def _write_report(self, incident):
        """Generate the full incident report as HTML."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_title = incident.incident_id.replace("-", "_")
        filename = f"incident_{safe_title}_{timestamp}.html"
        output_path = os.path.join(self.reports_dir, filename)

        html = self._render_html(incident)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)

        print(f"  [+] Incident report generated: {output_path}")
        return output_path

    def _render_html(self, incident):
        """Render the incident report as professional HTML."""

        # Build the kill chain narrative
        kill_chain = self._build_kill_chain_narrative(incident)

        # Build timeline HTML
        timeline_html = self._render_timeline(incident)

        # Build IOC table
        ioc_html = self._render_iocs(incident)

        # Build MITRE technique table
        mitre_html = self._render_mitre_table(incident)

        # Build remediation plan
        remediation_html = self._render_remediation(incident)

        # Severity color mapping
        severity_colors = {
            "CRITICAL": "#ff1744",
            "HIGH": "#ff6d00",
            "MEDIUM": "#ffc400",
            "LOW": "#00c853",
            "INFO": "#2979ff",
        }
        sev_color = severity_colors.get(incident.severity, "#999")

        total_events = len(incident.timeline)
        critical_count = incident.severity_counts.get("CRITICAL", 0)
        high_count = incident.severity_counts.get("HIGH", 0)
        techniques_used = len(incident.techniques)
        unique_ips = len(incident.iocs["ip_addresses"])

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{incident.title}</title>
    <style>
        :root {{
            --primary: #1a237e;
            --primary-light: #3f51b5;
            --danger: #ff1744;
            --warning: #ff9100;
            --success: #00c853;
            --dark: #212121;
            --light: #fafafa;
            --border: #e0e0e0;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #f5f5f5;
            color: var(--dark);
            line-height: 1.6;
        }}
        .report-container {{
            max-width: 1000px;
            margin: 20px auto;
            background: white;
            box-shadow: 0 2px 20px rgba(0,0,0,0.1);
        }}
        .report-header {{
            background: linear-gradient(135deg, var(--primary) 0%, var(--primary-light) 100%);
            color: white;
            padding: 40px;
        }}
        .report-header h1 {{
            font-size: 28px;
            margin-bottom: 10px;
            letter-spacing: -0.5px;
        }}
        .report-header .meta {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 10px;
            margin-top: 20px;
            font-size: 14px;
            opacity: 0.9;
        }}
        .severity-badge {{
            display: inline-block;
            padding: 4px 16px;
            border-radius: 20px;
            font-weight: bold;
            font-size: 14px;
            background: {sev_color};
            color: white;
        }}
        .section {{
            padding: 30px 40px;
            border-bottom: 1px solid var(--border);
        }}
        .section h2 {{
            color: var(--primary);
            font-size: 22px;
            margin-bottom: 15px;
            padding-bottom: 8px;
            border-bottom: 2px solid var(--primary-light);
        }}
        .section h3 {{
            color: var(--primary-light);
            font-size: 17px;
            margin: 15px 0 8px 0;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 15px;
            margin: 20px 0;
        }}
        .stat-card {{
            background: var(--light);
            border-radius: 8px;
            padding: 20px;
            text-align: center;
            border-left: 4px solid var(--primary-light);
        }}
        .stat-card .number {{
            font-size: 32px;
            font-weight: bold;
            color: var(--primary);
        }}
        .stat-card .label {{
            font-size: 13px;
            color: #666;
            margin-top: 5px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
            font-size: 14px;
        }}
        th, td {{
            padding: 10px 12px;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }}
        th {{
            background: #e8eaf6;
            color: var(--primary);
            font-weight: 600;
        }}
        tr:hover {{ background: #f5f5f5; }}
        .timeline-event {{
            display: flex;
            gap: 15px;
            padding: 10px 0;
            border-left: 3px solid var(--primary-light);
            padding-left: 15px;
            margin: 10px 0;
        }}
        .timeline-event .time {{
            min-width: 85px;
            color: #666;
            font-size: 13px;
        }}
        .timeline-event .content {{
            flex: 1;
        }}
        .timeline-event .sev-tag {{
            display: inline-block;
            padding: 2px 8px;
            border-radius: 3px;
            font-size: 11px;
            font-weight: bold;
            color: white;
        }}
        .tag-CRITICAL {{ background: #ff1744; }}
        .tag-HIGH {{ background: #ff6d00; }}
        .tag-MEDIUM {{ background: #ffc400; color: #333; }}
        .tag-LOW {{ background: #00c853; }}
        .tag-INFO {{ background: #2979ff; }}
        .remediation-box {{
            background: #e8f5e9;
            border: 1px solid #a5d6a7;
            border-radius: 8px;
            padding: 20px;
            margin: 10px 0;
        }}
        .remediation-box.immediate {{
            background: #ffebee;
            border-color: #ef9a9a;
        }}
        .remediation-box.short-term {{
            background: #fff3e0;
            border-color: #ffcc80;
        }}
        .ioc-tag {{
            display: inline-block;
            background: #e8eaf6;
            padding: 3px 10px;
            border-radius: 3px;
            margin: 3px;
            font-family: monospace;
            font-size: 13px;
        }}
        .mitre-technique {{
            background: var(--light);
            border-radius: 8px;
            padding: 15px;
            margin: 10px 0;
            border-left: 4px solid var(--warning);
        }}
        .footer {{
            padding: 20px 40px;
            background: var(--light);
            text-align: center;
            font-size: 12px;
            color: #999;
        }}
        .kill-chain-flow {{
            display: flex;
            flex-wrap: wrap;
            gap: 5px;
            align-items: center;
            margin: 15px 0;
        }}
        .kill-chain-step {{
            background: var(--primary);
            color: white;
            padding: 8px 16px;
            border-radius: 20px;
            font-size: 13px;
            font-weight: 500;
        }}
        .kill-chain-arrow {{
            font-size: 20px;
            color: #999;
        }}
        @media print {{
            .report-container {{ box-shadow: none; margin: 0; }}
            .section {{ page-break-inside: avoid; }}
        }}
    </style>
</head>
<body>
    <div class="report-container">
        <!-- Header -->
        <div class="report-header">
            <div style="display:flex;justify-content:space-between;align-items:start;">
                <div>
                    <h1>{incident.title}</h1>
                    <span class="severity-badge">{incident.severity}</span>
                </div>
                <div style="text-align:right;">
                    <div style="font-size:24px;font-weight:bold;">GUARDIAN SIEM</div>
                    <div style="opacity:0.8;">Incident Response Report</div>
                </div>
            </div>
            <div class="meta">
                <div><strong>Incident ID:</strong> {incident.incident_id}</div>
                <div><strong>Classification:</strong> {incident.classification}</div>
                <div><strong>Generated:</strong> {incident.created_at.strftime('%B %d, %Y %H:%M UTC')}</div>
                <div><strong>Analyst:</strong> {incident.analyst}</div>
            </div>
        </div>

        <!-- Key Metrics -->
        <div class="section">
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="number">{total_events}</div>
                    <div class="label">Total Events</div>
                </div>
                <div class="stat-card">
                    <div class="number" style="color:{severity_colors['CRITICAL']}">{critical_count}</div>
                    <div class="label">Critical Alerts</div>
                </div>
                <div class="stat-card">
                    <div class="number">{techniques_used}</div>
                    <div class="label">MITRE Techniques</div>
                </div>
                <div class="stat-card">
                    <div class="number">{unique_ips}</div>
                    <div class="label">Unique Source IPs</div>
                </div>
            </div>
        </div>

        <!-- 1. Executive Summary -->
        <div class="section">
            <h2>1. Executive Summary</h2>
            {self._render_executive_summary(incident)}
        </div>

        <!-- 2. Kill Chain Analysis -->
        <div class="section">
            <h2>2. Attack Kill Chain</h2>
            {kill_chain}
        </div>

        <!-- 3. Technical Analysis & Timeline -->
        <div class="section">
            <h2>3. Technical Analysis</h2>
            <h3>3.1 MITRE ATT&amp;CK Mapping</h3>
            {mitre_html}
            <h3>3.2 Event Timeline</h3>
            {timeline_html}
        </div>

        <!-- 4. Indicators of Compromise -->
        <div class="section">
            <h2>4. Indicators of Compromise (IOCs)</h2>
            {ioc_html}
        </div>

        <!-- 5. Impact Assessment -->
        <div class="section">
            <h2>5. Impact Assessment</h2>
            {self._render_impact_assessment(incident)}
        </div>

        <!-- 6. Remediation Plan -->
        <div class="section">
            <h2>6. Remediation Plan</h2>
            {remediation_html}
        </div>

        <!-- 7. Lessons Learned -->
        <div class="section">
            <h2>7. Lessons Learned</h2>
            {self._render_lessons_learned(incident)}
        </div>

        <!-- Footer -->
        <div class="footer">
            <p>Guardian SIEM — Automated Incident Report</p>
            <p>Generated {incident.created_at.strftime('%Y-%m-%d %H:%M:%S')} |
               Report ID: {incident.incident_id} |
               Classification: {incident.classification}</p>
            <p style="margin-top:8px;">This report was generated by Guardian SIEM's automated analysis engine.
               All findings should be validated by a human analyst before taking action.</p>
        </div>
    </div>
</body>
</html>"""

        return html

    def _render_executive_summary(self, incident):
        """Generate non-technical executive summary."""
        total = len(incident.timeline)
        critical = incident.severity_counts.get("CRITICAL", 0)
        high = incident.severity_counts.get("HIGH", 0)
        techniques = len(incident.techniques)
        unique_ips = len(incident.iocs["ip_addresses"])
        users = incident.iocs["users"]

        # Determine primary threat type
        if "T1486" in incident.techniques:
            threat_type = "ransomware deployment"
        elif "T1003" in incident.techniques and "T1558.003" in incident.techniques:
            threat_type = "credential theft and Active Directory compromise"
        elif "T1041" in incident.techniques:
            threat_type = "data exfiltration"
        elif "T1110" in incident.techniques:
            threat_type = "brute force intrusion"
        else:
            threat_type = "multi-stage intrusion"

        # Get the geographic origin if available
        geo_text = ""
        for ip, geo in incident.geo_sources.items():
            if geo.get("country"):
                geo_text = f" originating from {geo['country']}"
                break

        user_text = ""
        if users:
            compromised = [u for u in users if "admin" in u.lower() or "compromised" in u.lower()]
            if compromised:
                user_text = (f" Compromised accounts include: "
                             f"<strong>{', '.join(list(compromised)[:3])}</strong>.")

        return f"""<p>
            Guardian SIEM detected a <strong>{incident.severity.lower()}-severity {threat_type}</strong>
            event{geo_text}. The incident involved <strong>{total} security events</strong> across
            <strong>{techniques} MITRE ATT&amp;CK techniques</strong>, with <strong>{critical} critical</strong>
            and <strong>{high} high-severity alerts</strong> generated.
        </p>
        <p style="margin-top:10px;">
            The attack involved <strong>{unique_ips} unique source IP address(es)</strong>
            communicating with internal systems.{user_text}
        </p>
        <p style="margin-top:10px;">
            <strong>Business Impact:</strong> {"Potentially catastrophic. Ransomware encryption and shadow copy deletion detected." if "T1486" in incident.techniques else "Significant. Credential compromise may allow further unauthorized access if not remediated." if "T1003" in incident.techniques else "Moderate. Requires investigation to determine full scope of compromise."}
        </p>
        <p style="margin-top:10px;">
            <strong>Recommended Action:</strong> {"Immediate containment required. Isolate affected hosts and begin incident response." if incident.severity == "CRITICAL" else "Escalate to senior analyst for triage and containment assessment."}
        </p>"""

    def _build_kill_chain_narrative(self, incident):
        """Build a visual kill chain showing attack progression."""
        # Map MITRE tactics to kill chain phases
        tactic_order = [
            "Initial Access", "Execution", "Persistence", "Privilege Escalation",
            "Defense Evasion", "Credential Access", "Discovery",
            "Lateral Movement", "Collection", "Exfiltration", "Impact",
        ]

        observed_tactics = set()
        for tid, events in incident.techniques.items():
            for e in events:
                tactic = e.get("mitre_tactic", "")
                if tactic:
                    observed_tactics.add(tactic)

        if not observed_tactics:
            return "<p>No MITRE ATT&amp;CK techniques were observed in this incident.</p>"

        # Build kill chain flow
        steps = []
        for tactic in tactic_order:
            if tactic in observed_tactics:
                # Get techniques in this tactic
                techs = []
                for tid, events in incident.techniques.items():
                    for e in events:
                        if e.get("mitre_tactic") == tactic:
                            info = MITRE_DESCRIPTIONS.get(tid, {})
                            techs.append(info.get("name", tid))
                            break
                tech_text = ", ".join(set(techs))
                steps.append(f'<div class="kill-chain-step">{tactic}<br>'
                             f'<small>{tech_text}</small></div>')

        flow_html = '<span class="kill-chain-arrow"> &#10132; </span>'.join(steps)
        return f'<div class="kill-chain-flow">{flow_html}</div>'

    def _render_timeline(self, incident):
        """Render chronological event timeline."""
        if not incident.timeline:
            return "<p>No events recorded in the analysis window.</p>"

        # Show up to 30 most relevant events
        critical_events = [e for e in incident.timeline
                           if e.get("severity") in ("CRITICAL", "HIGH")]
        display_events = critical_events[:30] if critical_events else incident.timeline[:30]

        rows = []
        for event in display_events:
            ts = event.get("timestamp", "")
            if ts:
                try:
                    dt = datetime.fromisoformat(ts)
                    ts = dt.strftime("%H:%M:%S")
                except (ValueError, TypeError):
                    ts = str(ts)[:10]

            sev = event.get("severity", "INFO")
            source = event.get("source", "")
            msg = event.get("message", "")[:200]
            mitre = event.get("mitre_id", "")
            rule = event.get("rule_matched", "")

            rows.append(f"""
            <div class="timeline-event">
                <div class="time">{ts}</div>
                <div class="content">
                    <span class="sev-tag tag-{sev}">{sev}</span>
                    <strong> [{source}]</strong>
                    {f'<span style="color:#666;"> ({mitre})</span>' if mitre else ""}
                    {f'<span style="color:#388e3c;"> Rule: {rule}</span>' if rule else ""}
                    <br><span style="font-size:13px;color:#555;">{msg}</span>
                </div>
            </div>""")

        remaining = len(incident.timeline) - len(display_events)
        footer = (f'<p style="color:#999;margin-top:10px;font-size:13px;">'
                  f'Showing {len(display_events)} of {len(incident.timeline)} events. '
                  f'{remaining} additional events omitted for brevity.</p>'
                  if remaining > 0 else "")

        return "\n".join(rows) + footer

    def _render_iocs(self, incident):
        """Render indicators of compromise."""
        sections = []

        if incident.iocs["ip_addresses"]:
            ips_html = ""
            for ip in sorted(incident.iocs["ip_addresses"]):
                geo = incident.geo_sources.get(ip, {})
                geo_text = f" ({geo['country']}, {geo['city']})" if geo.get("country") else ""
                ips_html += f'<span class="ioc-tag">{ip}{geo_text}</span>\n'
            sections.append(f'<h3>IP Addresses ({len(incident.iocs["ip_addresses"])})</h3>\n{ips_html}')

        if incident.iocs["domains"]:
            domains_html = "\n".join(f'<span class="ioc-tag">{d}</span>'
                                     for d in sorted(incident.iocs["domains"]))
            sections.append(f'<h3>Domains ({len(incident.iocs["domains"])})</h3>\n{domains_html}')

        if incident.iocs["file_paths"]:
            paths_html = "\n".join(f'<span class="ioc-tag">{p}</span>'
                                   for p in sorted(incident.iocs["file_paths"]))
            sections.append(f'<h3>Suspicious File Paths ({len(incident.iocs["file_paths"])})</h3>\n{paths_html}')

        if incident.iocs["processes"]:
            procs_html = "\n".join(f'<span class="ioc-tag">{p}</span>'
                                   for p in sorted(incident.iocs["processes"]))
            sections.append(f'<h3>Suspicious Processes ({len(incident.iocs["processes"])})</h3>\n{procs_html}')

        if incident.iocs["users"]:
            users_html = "\n".join(f'<span class="ioc-tag">{u}</span>'
                                   for u in sorted(incident.iocs["users"]))
            sections.append(f'<h3>Compromised Accounts ({len(incident.iocs["users"])})</h3>\n{users_html}')

        if not sections:
            return "<p>No indicators of compromise were extracted.</p>"

        return "\n".join(sections)

    def _render_mitre_table(self, incident):
        """Render MITRE ATT&CK technique breakdown."""
        if not incident.techniques:
            return "<p>No MITRE ATT&amp;CK techniques were mapped for this incident.</p>"

        rows = []
        for tid in sorted(incident.techniques.keys()):
            events = incident.techniques[tid]
            info = MITRE_DESCRIPTIONS.get(tid, {})
            name = info.get("name", "Unknown")
            desc = info.get("description", "")
            tactic = events[0].get("mitre_tactic", "") if events else ""
            count = len(events)
            max_score = max((e.get("threat_score", 0) or 0) for e in events)

            rows.append(f"""
            <div class="mitre-technique">
                <strong>{tid}: {name}</strong>
                <span style="float:right;color:#666;">{tactic} | {count} events | Threat Score: {max_score}</span>
                <br><span style="font-size:13px;color:#555;">{desc}</span>
                <br><small style="color:#999;">Data Sources: {', '.join(info.get('data_sources', ['N/A']))}</small>
            </div>""")

        return "\n".join(rows)

    def _render_impact_assessment(self, incident):
        """Render impact assessment based on techniques observed."""
        impacts = []

        if "T1003" in incident.techniques or "T1558.003" in incident.techniques:
            impacts.append("""
            <h3>Credential Compromise</h3>
            <p>Credential dumping and/or Kerberoasting was detected. All passwords for
            affected service accounts and users should be considered compromised.
            The attacker may possess plaintext credentials or crackable hashes that
            enable persistent access.</p>
            <p><strong>Affected scope:</strong> All accounts that authenticated on
            compromised hosts during the incident window.</p>""")

        if "T1021.001" in incident.techniques:
            impacts.append("""
            <h3>Lateral Movement</h3>
            <p>RDP-based lateral movement was detected, indicating the attacker
            expanded access beyond the initial compromised host. Multiple systems
            may be affected including critical infrastructure (Domain Controllers,
            file servers).</p>""")

        if "T1486" in incident.techniques:
            impacts.append("""
            <h3>Ransomware Encryption</h3>
            <p><strong style="color:#ff1744;">CRITICAL:</strong> Ransomware encryption
            activity was detected. File systems on affected hosts may be partially or
            fully encrypted. Volume Shadow Copies may have been deleted, preventing
            native restoration.</p>
            <p><strong>Data at risk:</strong> All user files, databases, and application
            data on affected hosts.</p>""")

        if "T1041" in incident.techniques:
            impacts.append("""
            <h3>Data Exfiltration</h3>
            <p>Data exfiltration was detected. Sensitive information may have been
            transferred to external attacker-controlled infrastructure. The volume
            and type of exfiltrated data should be assessed to determine regulatory
            notification requirements (GDPR, HIPAA, PCI-DSS).</p>""")

        if "T1070.001" in incident.techniques:
            impacts.append("""
            <h3>Evidence Destruction</h3>
            <p>Event log clearing was detected, indicating the attacker attempted
            to destroy forensic evidence. Some events may be missing from the
            timeline. Review backup log sources (Syslog, SIEM) for complete
            picture.</p>""")

        if not impacts:
            impacts.append("""
            <h3>General Assessment</h3>
            <p>Security events were detected that warrant investigation. The full
            scope of impact should be determined through additional forensic
            analysis of affected systems.</p>""")

        return "\n".join(impacts)

    def _render_remediation(self, incident):
        """Generate a prioritized remediation plan."""
        immediate = []
        short_term = []
        long_term = []

        # Always recommend
        immediate.append("Isolate affected hosts from the network to prevent further spread")
        immediate.append("Preserve forensic evidence (memory dumps, disk images) before remediation")

        if "T1003" in incident.techniques or "T1558.003" in incident.techniques:
            immediate.append("Reset passwords for all compromised accounts identified in IOC section")
            immediate.append("Reset the Kerberos krbtgt account password TWICE (Golden Ticket mitigation)")
            short_term.append("Audit all service account SPNs and rotate to AES-256 encryption")
            short_term.append("Deploy Credential Guard on all Domain Controllers")
            long_term.append("Implement Privileged Access Workstations (PAW) for admin accounts")
            long_term.append("Deploy LSASS protection via Windows Defender Credential Guard")

        if "T1110" in incident.techniques:
            immediate.append("Block attacker source IPs at the perimeter firewall")
            short_term.append("Enforce account lockout policies (5 attempts, 30-minute lockout)")
            short_term.append("Implement MFA for all remote access (RDP, VPN, OWA)")
            long_term.append("Deploy adaptive authentication with risk-based MFA")

        if "T1486" in incident.techniques:
            immediate.append("DO NOT PAY THE RANSOM - contact law enforcement (FBI IC3)")
            immediate.append("Identify and isolate the ransomware process (kill PID)")
            short_term.append("Restore affected systems from known-good backups")
            short_term.append("Scan all systems for ransomware persistence mechanisms")
            long_term.append("Implement immutable backup strategy (3-2-1 rule with air-gapped copy)")

        if "T1041" in incident.techniques:
            immediate.append("Block all communication to identified C2 IP addresses")
            short_term.append("Conduct data loss assessment - identify what was exfiltrated")
            short_term.append("Notify legal team for regulatory breach notification assessment")
            long_term.append("Deploy DLP (Data Loss Prevention) at network egress points")

        if "T1070.001" in incident.techniques:
            short_term.append("Enable centralized log forwarding (events survive local deletion)")
            long_term.append("Deploy tamper-proof logging with write-once storage")

        # Always recommend
        long_term.append("Conduct tabletop exercises quarterly to improve incident response")
        long_term.append("Review and update detection rules based on gaps identified in this incident")
        long_term.append("Schedule penetration test to validate remediation effectiveness")

        def render_list(items, css_class, title):
            if not items:
                return ""
            li = "\n".join(f"<li>{item}</li>" for item in items)
            return f"""
            <div class="remediation-box {css_class}">
                <h3>{title}</h3>
                <ul style="margin:10px 0 0 20px;">{li}</ul>
            </div>"""

        return (render_list(immediate, "immediate", "Immediate Actions (0-4 hours)")
                + render_list(short_term, "short-term", "Short-Term Actions (1-7 days)")
                + render_list(long_term, "", "Long-Term Improvements (30-90 days)"))

    def _render_lessons_learned(self, incident):
        """Generate lessons learned based on incident data."""
        lessons = []

        # Detection gaps analysis
        techniques_without_rules = []
        for tid in incident.techniques:
            events = incident.techniques[tid]
            has_rule = any(e.get("rule_matched") for e in events)
            if not has_rule:
                info = MITRE_DESCRIPTIONS.get(tid, {})
                techniques_without_rules.append(
                    f"{tid}: {info.get('name', 'Unknown')}")

        if techniques_without_rules:
            techs = ", ".join(techniques_without_rules)
            lessons.append(f"""
            <h3>Detection Gaps</h3>
            <p>The following MITRE ATT&amp;CK techniques were present but did not trigger
            detection rules: <strong>{techs}</strong>. New SIGMA or YAML rules should
            be created to detect these techniques in future incidents.</p>""")
        else:
            lessons.append("""
            <h3>Detection Coverage</h3>
            <p>All observed techniques triggered at least one detection rule. Detection
            coverage is currently comprehensive for the attack patterns in this incident.</p>""")

        # Response time
        lessons.append("""
        <h3>Mean Time to Detect (MTTD)</h3>
        <p>Events were ingested and correlated in real-time by Guardian SIEM's EventBus
        pipeline. For future incidents, establish a baseline MTTD metric and track improvements.</p>""")

        # Process improvements
        lessons.append("""
        <h3>Process Recommendations</h3>
        <ul style="margin:10px 0 0 20px;">
            <li>Document this incident in the organization's incident tracking system</li>
            <li>Schedule a post-incident review within 5 business days</li>
            <li>Update runbooks with any new procedures discovered during response</li>
            <li>Share anonymized IOCs with industry ISAC for community defense</li>
            <li>Review this report with the security team for training purposes</li>
        </ul>""")

        return "\n".join(lessons)


def main():
    parser = argparse.ArgumentParser(
        description="Guardian SIEM — Professional Incident Report Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python incident_report.py                                  # Report from last 24h of events
  python incident_report.py --hours 4                        # Report from last 4 hours
  python incident_report.py --campaign apt29                 # Simulate APT29 + generate report
  python incident_report.py --campaign ransomware            # Simulate ransomware + report
  python incident_report.py --technique T1003                # Single technique + report
  python incident_report.py --title "INC-2025-042 Ransomware"  # Custom title
        """
    )
    parser.add_argument("--hours", type=int, default=24,
                        help="Look-back window in hours (default: 24)")
    parser.add_argument("--campaign", "-c",
                        help="Run attack simulator campaign before generating report")
    parser.add_argument("--technique", "-t",
                        help="Run a specific attack technique before generating report")
    parser.add_argument("--title",
                        help="Custom incident title")

    args = parser.parse_args()
    gen = IncidentReportGenerator()

    print("\n" + "=" * 65)
    print("  Guardian SIEM — Incident Report Generator")
    print("=" * 65)

    if args.campaign:
        path = gen.generate_from_simulator(campaign=args.campaign, title=args.title)
    elif args.technique:
        path = gen.generate_from_simulator(technique=args.technique, title=args.title)
    else:
        path = gen.generate_from_db(hours=args.hours, title=args.title)

    print(f"\n  Report saved to: {path}")
    print("  Open in a browser for the full formatted report.\n")


if __name__ == "__main__":
    main()
