"""
Guardian SIEM — Cloud Honeypot Log Parser
============================================
Parses cloud service logs to identify reconnaissance, unauthorized access,
and automated scanning activity against honeypot resources.

Supported Log Formats:
  - AWS CloudTrail (JSON)
  - Azure Activity Log (JSON)
  - GCP Cloud Audit Logs (JSON)
  - Generic cloud access logs

Use Case:
  "I left an S3 bucket open for 24 hours. Here are the 500 bots that
   found it and what they tried to do."  — Interview talking point

Usage:
    python cloud_honeypot.py --file logs/cloudtrail_sample.json --format aws
    python cloud_honeypot.py --file logs/azure_activity.json --format azure
    python cloud_honeypot.py --generate-sample                # Create sample logs
    python cloud_honeypot.py --analyze logs/                  # Analyze all logs in dir
"""

import os
import sys
import json
import random
import argparse
import hashlib
from datetime import datetime, timedelta
from html import escape as esc
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from event_bus import EventBus


# ─── Known Scanner / Bot Signatures ─────────────────────────────────────────
KNOWN_SCANNERS = {
    "Shodan": {"org": "Shodan.io", "description": "Internet-wide scanner"},
    "Censys": {"org": "Censys Inc", "description": "Search engine for devices"},
    "BinaryEdge": {"org": "BinaryEdge", "description": "Cyber threat intelligence"},
    "ZoomEye": {"org": "Knownsec", "description": "Chinese cyberspace search engine"},
    "GreyNoise": {"org": "GreyNoise Intelligence", "description": "Internet background noise"},
    "Masscan": {"org": "Unknown", "description": "Mass IP port scanner"},
    "Stretchoid": {"org": "Stretchoid.com", "description": "Web crawling service"},
    "CriminalIP": {"org": "AI SPERA", "description": "CTI search engine"},
}


class CloudLogEvent:
    """Represents a single cloud log entry."""

    def __init__(self, timestamp, source_ip, action, resource, user_agent="",
                 status="Success", region="", account_id="", extra=None):
        self.timestamp = timestamp
        self.source_ip = source_ip
        self.action = action
        self.resource = resource
        self.user_agent = user_agent
        self.status = status
        self.region = region
        self.account_id = account_id
        self.extra = extra or {}

    def to_dict(self):
        return {
            "timestamp": self.timestamp.isoformat() if isinstance(self.timestamp, datetime) else self.timestamp,
            "source_ip": self.source_ip,
            "action": self.action,
            "resource": self.resource,
            "user_agent": self.user_agent,
            "status": self.status,
            "region": self.region,
            "account_id": self.account_id,
            **self.extra,
        }


class CloudHoneypotParser:
    """
    Parses cloud service logs and generates intelligence reports on
    scanning activity, unauthorized access attempts, and bot behavior.
    """

    def __init__(self):
        self.bus = EventBus()
        self.events = []
        self.base_dir = os.path.dirname(os.path.abspath(__file__))
        self.logs_dir = os.path.join(self.base_dir, "logs", "honeypot")
        self.reports_dir = os.path.join(self.base_dir, "reports", "honeypot")
        os.makedirs(self.logs_dir, exist_ok=True)
        os.makedirs(self.reports_dir, exist_ok=True)

    # ─── Log Parsing ────────────────────────────────────────────────────

    def parse_file(self, filepath, log_format="auto"):
        """
        Parse a cloud log file and extract events.

        Args:
            filepath: Path to the log file
            log_format: 'aws', 'azure', 'gcp', or 'auto'

        Returns:
            List of CloudLogEvent objects
        """
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)

        if log_format == "auto":
            log_format = self._detect_format(data)

        if log_format == "aws":
            events = self._parse_cloudtrail(data)
        elif log_format == "azure":
            events = self._parse_azure_activity(data)
        elif log_format == "gcp":
            events = self._parse_gcp_audit(data)
        else:
            events = self._parse_generic(data)

        self.events.extend(events)
        print(f"  [+] Parsed {len(events)} events from {filepath} ({log_format})")
        return events

    def parse_directory(self, dirpath):
        """Parse all JSON files in a directory."""
        total = 0
        for filename in sorted(os.listdir(dirpath)):
            if filename.endswith(".json"):
                filepath = os.path.join(dirpath, filename)
                events = self.parse_file(filepath)
                total += len(events)
        print(f"  [+] Total events parsed from directory: {total}")
        return self.events

    def _detect_format(self, data):
        """Auto-detect log format from content."""
        if isinstance(data, dict):
            if "Records" in data:
                return "aws"
            if "value" in data and isinstance(data.get("value"), list):
                return "azure"
            if "entries" in data:
                return "gcp"
        return "generic"

    def _parse_cloudtrail(self, data):
        """Parse AWS CloudTrail JSON logs."""
        events = []
        records = data.get("Records", [])
        for record in records:
            event = CloudLogEvent(
                timestamp=record.get("eventTime", ""),
                source_ip=record.get("sourceIPAddress", ""),
                action=record.get("eventName", ""),
                resource=record.get("requestParameters", {}).get("bucketName", "")
                    or record.get("resources", [{}])[0].get("ARN", "") if record.get("resources") else "",
                user_agent=record.get("userAgent", ""),
                status="Success" if not record.get("errorCode") else record.get("errorCode", "Failed"),
                region=record.get("awsRegion", ""),
                account_id=record.get("recipientAccountId", ""),
                extra={
                    "event_source": record.get("eventSource", ""),
                    "event_type": record.get("eventType", ""),
                    "error_message": record.get("errorMessage", ""),
                },
            )
            events.append(event)
        return events

    def _parse_azure_activity(self, data):
        """Parse Azure Activity Log JSON."""
        events = []
        records = data.get("value", [])
        for record in records:
            caller_ip = ""
            http_req = record.get("httpRequest", {})
            if isinstance(http_req, dict):
                caller_ip = http_req.get("clientIpAddress", "")

            event = CloudLogEvent(
                timestamp=record.get("eventTimestamp", ""),
                source_ip=caller_ip,
                action=record.get("operationName", {}).get("value", "") if isinstance(record.get("operationName"), dict) else record.get("operationName", ""),
                resource=record.get("resourceId", ""),
                user_agent=http_req.get("clientRequestId", "") if isinstance(http_req, dict) else "",
                status=record.get("status", {}).get("value", "") if isinstance(record.get("status"), dict) else record.get("status", ""),
                region=record.get("resourceLocation", ""),
                account_id=record.get("subscriptionId", ""),
                extra={
                    "category": record.get("category", {}).get("value", "") if isinstance(record.get("category"), dict) else "",
                    "caller": record.get("caller", ""),
                    "level": record.get("level", ""),
                },
            )
            events.append(event)
        return events

    def _parse_gcp_audit(self, data):
        """Parse GCP Cloud Audit Logs."""
        events = []
        entries = data.get("entries", [])
        for entry in entries:
            req_meta = entry.get("requestMetadata", {})
            event = CloudLogEvent(
                timestamp=entry.get("timestamp", ""),
                source_ip=req_meta.get("callerIp", ""),
                action=entry.get("methodName", ""),
                resource=entry.get("resourceName", ""),
                user_agent=req_meta.get("callerSuppliedUserAgent", ""),
                status=entry.get("status", {}).get("message", "") if isinstance(entry.get("status"), dict) else "",
                region=entry.get("resource", {}).get("labels", {}).get("location", ""),
                account_id=entry.get("resource", {}).get("labels", {}).get("project_id", ""),
                extra={
                    "service_name": entry.get("serviceName", ""),
                    "principal_email": entry.get("authenticationInfo", {}).get("principalEmail", ""),
                },
            )
            events.append(event)
        return events

    def _parse_generic(self, data):
        """Parse generic JSON array of events."""
        events = []
        records = data if isinstance(data, list) else data.get("events", [])
        for record in records:
            event = CloudLogEvent(
                timestamp=record.get("timestamp", ""),
                source_ip=record.get("source_ip", record.get("ip", "")),
                action=record.get("action", record.get("event", "")),
                resource=record.get("resource", record.get("target", "")),
                user_agent=record.get("user_agent", ""),
                status=record.get("status", "Unknown"),
                region=record.get("region", ""),
            )
            events.append(event)
        return events

    # ─── Analysis ────────────────────────────────────────────────────────

    def analyze(self):
        """
        Analyze parsed events and generate intelligence report.

        Returns:
            Dict with analysis results
        """
        if not self.events:
            return {"error": "No events to analyze. Parse logs first."}

        report = {
            "summary": {},
            "top_ips": [],
            "top_actions": [],
            "scanners_detected": [],
            "unauthorized_access": [],
            "geographic_distribution": [],
            "timeline": [],
            "user_agents": [],
            "recommendations": [],
        }

        # ── Summary Stats ──
        ip_counter = Counter()
        action_counter = Counter()
        ua_counter = Counter()
        status_counter = Counter()
        scanner_ips = {}
        unauthorized = []
        hourly = defaultdict(int)

        for event in self.events:
            ip_counter[event.source_ip] += 1
            action_counter[event.action] += 1
            ua_counter[event.user_agent] += 1
            status_counter[event.status] += 1

            # Check for known scanner user agents
            for scanner_name, info in KNOWN_SCANNERS.items():
                if scanner_name.lower() in event.user_agent.lower():
                    scanner_ips[event.source_ip] = {
                        "scanner": scanner_name,
                        "org": info["org"],
                        "count": ip_counter[event.source_ip],
                    }

            # Track unauthorized attempts
            if event.status in ("AccessDenied", "Forbidden", "403", "Failed",
                                "UnauthorizedAccess"):
                unauthorized.append(event)

            # Hourly distribution
            try:
                if isinstance(event.timestamp, str):
                    dt = datetime.fromisoformat(event.timestamp.replace("Z", "+00:00"))
                else:
                    dt = event.timestamp
                hourly[dt.strftime("%Y-%m-%d %H:00")] += 1
            except (ValueError, AttributeError):
                pass

        # Populate report
        unique_ips = len(ip_counter)
        total_events = len(self.events)
        success_count = sum(1 for e in self.events if e.status in ("Success", "200", "OK"))
        fail_count = total_events - success_count

        report["summary"] = {
            "total_events": total_events,
            "unique_source_ips": unique_ips,
            "unique_actions": len(action_counter),
            "successful_requests": success_count,
            "failed_requests": fail_count,
            "known_scanners_detected": len(scanner_ips),
            "unauthorized_attempts": len(unauthorized),
            "analysis_timestamp": datetime.now().isoformat(),
        }

        report["top_ips"] = [
            {"ip": ip, "count": count}
            for ip, count in ip_counter.most_common(20)
        ]

        report["top_actions"] = [
            {"action": action, "count": count}
            for action, count in action_counter.most_common(15)
        ]

        report["scanners_detected"] = [
            {"ip": ip, **info} for ip, info in scanner_ips.items()
        ]

        report["unauthorized_access"] = [
            {
                "timestamp": e.timestamp.isoformat() if isinstance(e.timestamp, datetime) else e.timestamp,
                "source_ip": e.source_ip,
                "action": e.action,
                "resource": e.resource,
                "status": e.status,
            }
            for e in unauthorized[:50]
        ]

        report["user_agents"] = [
            {"user_agent": ua[:100], "count": count}
            for ua, count in ua_counter.most_common(15) if ua
        ]

        report["timeline"] = [
            {"hour": hour, "count": count}
            for hour, count in sorted(hourly.items())
        ]

        # Generate recommendations
        report["recommendations"] = self._generate_recommendations(report)

        return report

    def _generate_recommendations(self, report):
        """Generate security recommendations based on analysis."""
        recs = []
        summary = report["summary"]

        if summary["known_scanners_detected"] > 0:
            recs.append({
                "priority": "MEDIUM",
                "finding": f"{summary['known_scanners_detected']} known internet scanners detected",
                "recommendation": "This is expected for internet-facing resources. "
                                  "Ensure security groups/firewalls only expose intended services.",
            })

        if summary["unauthorized_attempts"] > 10:
            recs.append({
                "priority": "HIGH",
                "finding": f"{summary['unauthorized_attempts']} unauthorized access attempts",
                "recommendation": "Enable AWS GuardDuty / Azure Defender / GCP Security Command Center. "
                                  "Review IAM policies for least privilege. Enable MFA for all accounts.",
            })

        if summary["unique_source_ips"] > 100:
            recs.append({
                "priority": "MEDIUM",
                "finding": f"{summary['unique_source_ips']} unique IPs accessed resources",
                "recommendation": "Consider deploying a WAF or rate-limiting. "
                                  "Review if the resource should be publicly accessible.",
            })

        # Always recommend
        recs.append({
            "priority": "INFO",
            "finding": "Honeypot data collection complete",
            "recommendation": "Feed IOC IP addresses into threat intelligence blocklist. "
                              "Share anonymized results with community via STIX/TAXII.",
        })

        return recs

    # ─── Emit to SIEM ────────────────────────────────────────────────────

    def emit_to_siem(self, events=None):
        """Emit parsed events into the Guardian SIEM pipeline via EventBus."""
        events = events or self.events
        emitted = 0
        for event in events:
            severity = "MEDIUM"
            if event.status in ("AccessDenied", "Forbidden", "Failed"):
                severity = "HIGH"

            # Check for known scanners
            for scanner_name in KNOWN_SCANNERS:
                if scanner_name.lower() in event.user_agent.lower():
                    severity = "LOW"  # Known scanners are noisy but expected
                    break

            self.bus.emit(
                source="Cloud_Honeypot",
                severity=severity,
                message=f"Cloud {event.action}: {event.resource} from {event.source_ip} "
                        f"({event.status}) UA: {event.user_agent[:80]}",
                enrichment={
                    "src_ip": event.source_ip,
                    "mitre_id": "T1595" if "scan" in event.action.lower() else "T1530",
                    "mitre_tactic": "Reconnaissance",
                    "threat_score": 30 if severity == "LOW" else 60,
                },
            )
            emitted += 1

        print(f"  [+] Emitted {emitted} cloud honeypot events to SIEM")
        return emitted

    # ─── Report Generation ───────────────────────────────────────────────

    def generate_report(self, report_data=None, output_path=None):
        """Generate an HTML report from analysis results."""
        if report_data is None:
            report_data = self.analyze()

        if "error" in report_data:
            print(f"  [!] {report_data['error']}")
            return None

        if output_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = os.path.join(
                self.reports_dir, f"honeypot_report_{timestamp}.html")

        html = self._render_html_report(report_data)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)

        print(f"  [+] Honeypot report generated: {output_path}")
        return output_path

    def _render_html_report(self, data):
        """Render honeypot analysis as HTML."""
        summary = data["summary"]

        # Top IPs table rows
        ip_rows = "\n".join(
            f'<tr><td><code>{esc(str(ip["ip"]))}</code></td><td>{ip["count"]}</td></tr>'
            for ip in data["top_ips"][:15]
        )

        # Scanner rows
        scanner_rows = "\n".join(
            f'<tr><td><code>{esc(str(s["ip"]))}</code></td><td>{esc(str(s["scanner"]))}</td>'
            f'<td>{esc(str(s["org"]))}</td><td>{s["count"]}</td></tr>'
            for s in data["scanners_detected"]
        ) or "<tr><td colspan='4'>No known scanners detected</td></tr>"

        # Top actions
        action_rows = "\n".join(
            f'<tr><td>{esc(str(a["action"]))}</td><td>{a["count"]}</td></tr>'
            for a in data["top_actions"][:10]
        )

        # Unauthorized access
        unauth_rows = "\n".join(
            f'<tr><td>{esc(str(u["timestamp"][:19]))}</td><td><code>{esc(str(u["source_ip"]))}</code></td>'
            f'<td>{esc(str(u["action"]))}</td><td>{esc(str(u["resource"][:60]))}</td>'
            f'<td style="color:#ff1744;">{esc(str(u["status"]))}</td></tr>'
            for u in data["unauthorized_access"][:20]
        ) or "<tr><td colspan='5'>No unauthorized access attempts</td></tr>"

        # Recommendations
        rec_html = "\n".join(
            f'<div style="background:{"#ffebee" if r["priority"]=="HIGH" else "#fff3e0" if r["priority"]=="MEDIUM" else "#e8f5e9"};'
            f'padding:15px;border-radius:8px;margin:10px 0;">'
            f'<strong>[{esc(str(r["priority"]))}]</strong> {esc(str(r["finding"]))}<br>'
            f'<span style="color:#555;">{esc(str(r["recommendation"]))}</span></div>'
            for r in data["recommendations"]
        )

        # User agent table
        ua_rows = "\n".join(
            f'<tr><td style="font-family:monospace;font-size:12px;">{esc(str(ua["user_agent"]))}</td>'
            f'<td>{ua["count"]}</td></tr>'
            for ua in data["user_agents"][:10]
        )

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Cloud Honeypot Analysis Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', Tahoma, sans-serif;
            background: #f5f5f5;
            color: #212121;
            line-height: 1.6;
        }}
        .container {{
            max-width: 1000px;
            margin: 20px auto;
            background: white;
            box-shadow: 0 2px 20px rgba(0,0,0,0.1);
        }}
        .header {{
            background: linear-gradient(135deg, #1b5e20 0%, #4caf50 100%);
            color: white;
            padding: 40px;
        }}
        .header h1 {{ font-size: 28px; }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 15px;
            padding: 25px 40px;
        }}
        .stat {{
            background: #f5f5f5;
            border-radius: 8px;
            padding: 20px;
            text-align: center;
            border-top: 4px solid #4caf50;
        }}
        .stat .num {{
            font-size: 32px;
            font-weight: bold;
            color: #1b5e20;
        }}
        .stat .lbl {{ font-size: 13px; color: #666; }}
        .section {{
            padding: 25px 40px;
            border-bottom: 1px solid #e0e0e0;
        }}
        .section h2 {{
            color: #1b5e20;
            margin-bottom: 15px;
            padding-bottom: 8px;
            border-bottom: 2px solid #4caf50;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 10px 0;
            font-size: 14px;
        }}
        th, td {{
            padding: 8px 12px;
            text-align: left;
            border-bottom: 1px solid #e0e0e0;
        }}
        th {{
            background: #e8f5e9;
            color: #1b5e20;
        }}
        tr:hover {{ background: #f5f5f5; }}
        code {{ background: #f5f5f5; padding: 2px 6px; border-radius: 3px; }}
        .footer {{
            padding: 20px 40px;
            text-align: center;
            font-size: 12px;
            color: #999;
        }}
        @media print {{
            .container {{ box-shadow: none; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div style="display:flex;justify-content:space-between;align-items:center;">
                <div>
                    <h1>Cloud Honeypot Analysis Report</h1>
                    <p style="opacity:0.9;">Guardian SIEM — Threat Intelligence from Cloud Exposure</p>
                </div>
                <div style="text-align:right;">
                    <div style="font-size:20px;font-weight:bold;">GUARDIAN SIEM</div>
                    <div style="opacity:0.8;">Honeypot Intelligence</div>
                </div>
            </div>
        </div>

        <div class="stats">
            <div class="stat">
                <div class="num">{summary['total_events']}</div>
                <div class="lbl">Total Events</div>
            </div>
            <div class="stat">
                <div class="num">{summary['unique_source_ips']}</div>
                <div class="lbl">Unique Source IPs</div>
            </div>
            <div class="stat">
                <div class="num" style="color:#ff6d00;">{summary['unauthorized_attempts']}</div>
                <div class="lbl">Unauthorized Attempts</div>
            </div>
            <div class="stat">
                <div class="num">{summary['known_scanners_detected']}</div>
                <div class="lbl">Known Scanners</div>
            </div>
        </div>

        <div class="section">
            <h2>Top Source IPs</h2>
            <table>
                <tr><th>IP Address</th><th>Request Count</th></tr>
                {ip_rows}
            </table>
        </div>

        <div class="section">
            <h2>Known Scanners Detected</h2>
            <p style="color:#555;margin-bottom:10px;">These IPs are associated with
            known internet scanning services.</p>
            <table>
                <tr><th>IP Address</th><th>Scanner</th><th>Organization</th><th>Requests</th></tr>
                {scanner_rows}
            </table>
        </div>

        <div class="section">
            <h2>Top API Actions</h2>
            <table>
                <tr><th>Action</th><th>Count</th></tr>
                {action_rows}
            </table>
        </div>

        <div class="section">
            <h2>Unauthorized Access Attempts</h2>
            <table>
                <tr><th>Timestamp</th><th>Source IP</th><th>Action</th><th>Resource</th><th>Status</th></tr>
                {unauth_rows}
            </table>
        </div>

        <div class="section">
            <h2>User Agents</h2>
            <table>
                <tr><th>User Agent</th><th>Count</th></tr>
                {ua_rows}
            </table>
        </div>

        <div class="section">
            <h2>Recommendations</h2>
            {rec_html}
        </div>

        <div class="footer">
            <p>Guardian SIEM — Cloud Honeypot Intelligence Report</p>
            <p>Generated {summary['analysis_timestamp'][:19]}</p>
        </div>
    </div>
</body>
</html>"""

    # ─── Sample Data Generation ──────────────────────────────────────────

    def generate_sample_logs(self):
        """
        Generate realistic sample CloudTrail + Azure logs for demo purposes.
        Creates 500+ events simulating 24h of honeypot exposure.
        """
        print("  [+] Generating sample cloud honeypot logs...")

        # Generate AWS CloudTrail sample
        aws_path = os.path.join(self.logs_dir, "cloudtrail_honeypot_24h.json")
        aws_records = self._generate_cloudtrail_sample()
        with open(aws_path, "w", encoding="utf-8") as f:
            json.dump({"Records": aws_records}, f, indent=2)
        print(f"  [+] AWS CloudTrail sample: {aws_path} ({len(aws_records)} events)")

        # Generate Azure Activity Log sample
        azure_path = os.path.join(self.logs_dir, "azure_activity_honeypot_24h.json")
        azure_records = self._generate_azure_sample()
        with open(azure_path, "w", encoding="utf-8") as f:
            json.dump({"value": azure_records}, f, indent=2)
        print(f"  [+] Azure Activity sample: {azure_path} ({len(azure_records)} events)")

        return [aws_path, azure_path]

    def _generate_cloudtrail_sample(self):
        """Generate realistic AWS CloudTrail S3 honeypot logs."""
        records = []
        base_time = datetime.now() - timedelta(hours=24)

        # Simulated bot IPs (use documentation ranges)
        bot_ips = [
            f"198.51.100.{random.randint(1, 254)}" for _ in range(80)
        ] + [
            f"203.0.113.{random.randint(1, 254)}" for _ in range(60)
        ] + [
            f"192.0.2.{random.randint(1, 254)}" for _ in range(40)
        ]

        scanner_uas = [
            "Shodan/3.0", "censys/2.0", "BinaryEdge/1.0",
            "ZoomEye/1.0", "python-requests/2.28.0",
            "Go-http-client/1.1", "curl/7.88.1",
            "Mozilla/5.0 (compatible; bot)", "Masscan/1.3",
            "AWS Security Scanner", "Boto3/1.28.0",
        ]

        s3_actions = [
            ("ListBuckets", "s3.amazonaws.com", "AccessDenied"),
            ("GetBucketAcl", "s3.amazonaws.com", None),
            ("GetBucketPolicy", "s3.amazonaws.com", "AccessDenied"),
            ("ListObjects", "s3.amazonaws.com", None),
            ("GetObject", "s3.amazonaws.com", None),
            ("PutObject", "s3.amazonaws.com", "AccessDenied"),
            ("DeleteObject", "s3.amazonaws.com", "AccessDenied"),
            ("GetBucketLocation", "s3.amazonaws.com", None),
            ("HeadBucket", "s3.amazonaws.com", None),
            ("GetBucketVersioning", "s3.amazonaws.com", None),
        ]

        bucket_name = "honeypot-research-data-2025"

        for i in range(350):
            delta_minutes = random.randint(0, 1440)  # Spread over 24 hours
            timestamp = base_time + timedelta(minutes=delta_minutes)
            ip = random.choice(bot_ips)
            ua = random.choice(scanner_uas)
            action, source, error = random.choice(s3_actions)

            record = {
                "eventVersion": "1.08",
                "eventTime": timestamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "eventSource": source,
                "eventName": action,
                "awsRegion": random.choice(["us-east-1", "eu-west-1", "ap-southeast-1"]),
                "sourceIPAddress": ip,
                "userAgent": ua,
                "eventType": "AwsApiCall",
                "recipientAccountId": "123456789012",
                "requestParameters": {"bucketName": bucket_name},
                "resources": [{"ARN": f"arn:aws:s3:::{bucket_name}"}],
            }

            if error:
                record["errorCode"] = error
                record["errorMessage"] = f"Access Denied: {action} on {bucket_name}"

            records.append(record)

        # Sort by time
        records.sort(key=lambda r: r["eventTime"])
        return records

    def _generate_azure_sample(self):
        """Generate realistic Azure Activity Log honeypot data."""
        records = []
        base_time = datetime.now() - timedelta(hours=24)

        bot_ips = [
            f"198.51.100.{random.randint(1, 254)}" for _ in range(50)
        ] + [
            f"203.0.113.{random.randint(1, 254)}" for _ in range(30)
        ]

        operations = [
            ("Microsoft.Storage/storageAccounts/listKeys/action", "Succeeded"),
            ("Microsoft.Storage/storageAccounts/listKeys/action", "Failed"),
            ("Microsoft.Storage/storageAccounts/blobServices/containers/read", "Succeeded"),
            ("Microsoft.Storage/storageAccounts/blobServices/containers/read", "Failed"),
            ("Microsoft.Storage/storageAccounts/read", "Succeeded"),
            ("Microsoft.Compute/virtualMachines/read", "Succeeded"),
            ("Microsoft.Compute/virtualMachines/start/action", "Failed"),
            ("Microsoft.Network/networkSecurityGroups/read", "Succeeded"),
            ("Microsoft.Authorization/roleAssignments/read", "Succeeded"),
            ("Microsoft.KeyVault/vaults/secrets/read", "Failed"),
        ]

        for i in range(200):
            delta_minutes = random.randint(0, 1440)
            timestamp = base_time + timedelta(minutes=delta_minutes)
            ip = random.choice(bot_ips)
            operation, status = random.choice(operations)

            record = {
                "eventTimestamp": timestamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "operationName": {"value": operation},
                "status": {"value": status},
                "resourceId": f"/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/honeypot-rg/providers/{operation.split('/')[0]}/{operation.split('/')[1]}/honeypot-storage",
                "resourceLocation": random.choice(["eastus", "westeurope", "southeastasia"]),
                "subscriptionId": "00000000-0000-0000-0000-000000000000",
                "httpRequest": {"clientIpAddress": ip, "clientRequestId": f"req-{hashlib.md5(str(i).encode()).hexdigest()[:8]}"},
                "caller": f"scanner-{hashlib.md5(ip.encode()).hexdigest()[:6]}@external.com",
                "category": {"value": "Administrative"},
                "level": "Warning" if status == "Failed" else "Informational",
            }
            records.append(record)

        records.sort(key=lambda r: r["eventTimestamp"])
        return records


def main():
    parser = argparse.ArgumentParser(
        description="Guardian SIEM — Cloud Honeypot Log Parser & Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cloud_honeypot.py --generate-sample           Generate 500+ sample events
  python cloud_honeypot.py --file logs/honeypot/cloudtrail_honeypot_24h.json --format aws
  python cloud_honeypot.py --analyze logs/honeypot/     Analyze all logs in directory
  python cloud_honeypot.py --generate-sample --analyze  Generate + analyze + report
        """
    )
    parser.add_argument("--file", "-f", help="Path to a cloud log file (JSON)")
    parser.add_argument("--format", choices=["aws", "azure", "gcp", "auto"],
                        default="auto", help="Log format (default: auto-detect)")
    parser.add_argument("--analyze", "-a", nargs="?", const="auto",
                        help="Analyze logs (optionally specify directory)")
    parser.add_argument("--generate-sample", action="store_true",
                        help="Generate sample CloudTrail + Azure honeypot logs")
    parser.add_argument("--emit", action="store_true",
                        help="Emit parsed events into the SIEM via EventBus")
    parser.add_argument("--report", action="store_true",
                        help="Generate HTML analysis report")

    args = parser.parse_args()
    honeypot = CloudHoneypotParser()

    print("\n" + "=" * 65)
    print("  Guardian SIEM — Cloud Honeypot Log Parser")
    print("=" * 65)

    if args.generate_sample:
        paths = honeypot.generate_sample_logs()
        if args.analyze:
            honeypot.parse_directory(honeypot.logs_dir)
        elif not args.file:
            # Parse the samples we just generated
            for p in paths:
                honeypot.parse_file(p)

    if args.file:
        honeypot.parse_file(args.file, log_format=args.format)

    if args.analyze and args.analyze != "auto":
        honeypot.parse_directory(args.analyze)
    elif args.analyze == "auto" and not args.generate_sample:
        honeypot.parse_directory(honeypot.logs_dir)

    if args.emit:
        honeypot.emit_to_siem()

    if args.report or args.generate_sample or args.analyze:
        report_data = honeypot.analyze()
        if "error" not in report_data:
            path = honeypot.generate_report(report_data)
            print(f"\n  Open {path} in a browser for the full report.\n")
        else:
            print(f"\n  [!] {report_data['error']}\n")

    if not any([args.file, args.analyze, args.generate_sample, args.emit, args.report]):
        parser.print_help()


if __name__ == "__main__":
    main()
