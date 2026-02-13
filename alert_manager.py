"""
Guardian SIEM v2.0 — Alert Manager
Handles alert notifications via Email (SMTP) and Slack webhooks.
Supports alert deduplication and rate limiting to prevent notification spam.
"""

import os
import json
import time
import smtplib
import yaml
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from collections import defaultdict

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


class AlertManager:
    """Manages alert notifications across multiple channels."""

    def __init__(self, config_path=None):
        base_dir = os.path.dirname(os.path.abspath(__file__))
        if config_path is None:
            config_path = os.path.join(base_dir, "config", "config.yaml")

        self.config = {}
        self._load_config(config_path)
        self._alert_history = defaultdict(float)  # dedup: rule_name -> last_alert_time
        self._cooldown_seconds = 300  # 5 min cooldown between duplicate alerts
        self._alert_log = []  # In-memory log for dashboard

    def _load_config(self, config_path):
        try:
            with open(config_path, "r") as f:
                self.config = yaml.safe_load(f) or {}
        except (FileNotFoundError, yaml.YAMLError) as e:
            print(f"[AlertManager] Config load error: {e}")
            self.config = {}

    def send_alert(self, alert_data):
        """
        Process and dispatch an alert through all enabled channels.

        Args:
            alert_data: Dict with keys: rule_name, severity, description,
                       mitre_id, source, message_excerpt, matched_at
        """
        rule_name = alert_data.get("rule_name", "Unknown")
        severity = alert_data.get("severity", "MEDIUM")

        # Deduplication check
        now = time.time()
        last_alert = self._alert_history.get(rule_name, 0)
        if now - last_alert < self._cooldown_seconds:
            return  # Skip duplicate

        self._alert_history[rule_name] = now

        # Log to in-memory buffer (for dashboard API)
        log_entry = {
            **alert_data,
            "dispatched_at": datetime.now().isoformat(),
            "channels": [],
        }

        alerting_config = self.config.get("alerting", {})

        # Console output (always enabled)
        self._console_alert(alert_data)
        log_entry["channels"].append("console")

        if not alerting_config.get("enabled", False):
            self._alert_log.append(log_entry)
            return

        # Email notification
        email_config = alerting_config.get("email", {})
        if email_config.get("enabled", False) and severity in ("CRITICAL", "HIGH"):
            success = self._send_email(alert_data, email_config)
            if success:
                log_entry["channels"].append("email")

        # Slack notification
        slack_config = alerting_config.get("slack", {})
        if slack_config.get("enabled", False):
            success = self._send_slack(alert_data, slack_config)
            if success:
                log_entry["channels"].append("slack")

        self._alert_log.append(log_entry)

    def _console_alert(self, alert_data):
        """Print alert to console with severity coloring."""
        severity = alert_data.get("severity", "MEDIUM")
        rule = alert_data.get("rule_name", "Unknown")
        mitre = alert_data.get("mitre_id", "")
        msg = alert_data.get("message_excerpt", "")[:100]

        severity_icons = {
            "CRITICAL": "🔴", "HIGH": "🟠",
            "MEDIUM": "🟡", "LOW": "🟢", "INFO": "🔵"
        }
        icon = severity_icons.get(severity, "⚪")
        print(f"\n{icon} ALERT [{severity}] {rule}")
        if mitre:
            print(f"   MITRE ATT&CK: {mitre}")
        print(f"   {msg}")

    def _send_email(self, alert_data, email_config):
        """Send alert via SMTP email."""
        try:
            smtp_server = email_config.get("smtp_server", "smtp.gmail.com")
            smtp_port = email_config.get("smtp_port", 587)
            sender = email_config.get("sender", "")
            password = os.environ.get("GUARDIAN_SMTP_PASSWORD", email_config.get("password", ""))
            recipients = email_config.get("recipients", [])

            if not sender or not password or not recipients:
                return False

            severity = alert_data.get("severity", "MEDIUM")
            rule_name = alert_data.get("rule_name", "Unknown")

            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"[Guardian SIEM] {severity} Alert: {rule_name}"
            msg["From"] = sender
            msg["To"] = ", ".join(recipients)

            html_body = f"""
            <html><body style="font-family: Arial, sans-serif;">
            <div style="background: {'#dc3545' if severity == 'CRITICAL' else '#fd7e14'}; 
                        color: white; padding: 15px; border-radius: 5px;">
                <h2>⚠️ Guardian SIEM Alert</h2>
            </div>
            <table style="margin: 15px 0; border-collapse: collapse;">
                <tr><td style="padding: 8px; font-weight: bold;">Rule:</td>
                    <td style="padding: 8px;">{rule_name}</td></tr>
                <tr><td style="padding: 8px; font-weight: bold;">Severity:</td>
                    <td style="padding: 8px;">{severity}</td></tr>
                <tr><td style="padding: 8px; font-weight: bold;">MITRE ATT&CK:</td>
                    <td style="padding: 8px;">{alert_data.get('mitre_id', 'N/A')}</td></tr>
                <tr><td style="padding: 8px; font-weight: bold;">Source:</td>
                    <td style="padding: 8px;">{alert_data.get('source', 'N/A')}</td></tr>
                <tr><td style="padding: 8px; font-weight: bold;">Time:</td>
                    <td style="padding: 8px;">{alert_data.get('matched_at', 'N/A')}</td></tr>
                <tr><td style="padding: 8px; font-weight: bold;">Details:</td>
                    <td style="padding: 8px;">{alert_data.get('message_excerpt', 'N/A')}</td></tr>
            </table>
            <p style="color: #666; font-size: 12px;">Guardian SIEM v2.0 — Automated Alert</p>
            </body></html>
            """
            msg.attach(MIMEText(html_body, "html"))

            with smtplib.SMTP(smtp_server, smtp_port) as server:
                server.starttls()
                server.login(sender, password)
                server.sendmail(sender, recipients, msg.as_string())

            print(f"[AlertManager] Email sent to {', '.join(recipients)}")
            return True
        except Exception as e:
            print(f"[AlertManager] Email failed: {e}")
            return False

    def _send_slack(self, alert_data, slack_config):
        """Send alert to Slack via webhook."""
        if not HAS_REQUESTS:
            return False

        webhook_url = os.environ.get(
            "GUARDIAN_SLACK_WEBHOOK",
            slack_config.get("webhook_url", "")
        )
        if not webhook_url:
            return False

        try:
            severity = alert_data.get("severity", "MEDIUM")
            color_map = {
                "CRITICAL": "#dc3545", "HIGH": "#fd7e14",
                "MEDIUM": "#ffc107", "LOW": "#28a745", "INFO": "#17a2b8"
            }
            payload = {
                "attachments": [{
                    "color": color_map.get(severity, "#6c757d"),
                    "title": f"Guardian SIEM Alert — {severity}",
                    "fields": [
                        {"title": "Rule", "value": alert_data.get("rule_name", ""), "short": True},
                        {"title": "MITRE ATT&CK", "value": alert_data.get("mitre_id", "N/A"), "short": True},
                        {"title": "Source", "value": alert_data.get("source", ""), "short": True},
                        {"title": "Time", "value": alert_data.get("matched_at", ""), "short": True},
                        {"title": "Details", "value": alert_data.get("message_excerpt", "")[:300], "short": False},
                    ],
                    "footer": "Guardian SIEM v2.0",
                }]
            }
            resp = requests.post(webhook_url, json=payload, timeout=10)
            if resp.status_code == 200:
                print("[AlertManager] Slack notification sent")
                return True
        except Exception as e:
            print(f"[AlertManager] Slack failed: {e}")
        return False

    def get_recent_alerts(self, limit=50):
        """Return recent alerts for dashboard API."""
        return self._alert_log[-limit:][::-1]

    def get_alert_stats(self):
        """Return alert statistics for dashboard."""
        stats = {"total": len(self._alert_log), "by_severity": defaultdict(int)}
        for alert in self._alert_log:
            stats["by_severity"][alert.get("severity", "UNKNOWN")] += 1
        stats["by_severity"] = dict(stats["by_severity"])
        return stats


if __name__ == "__main__":
    am = AlertManager()
    test_alert = {
        "rule_name": "Brute Force Detection",
        "severity": "HIGH",
        "description": "Multiple failed login attempts",
        "mitre_id": "T1110",
        "source": "Windows_EventLog",
        "message_excerpt": "Event 4625: Failed logon for ADMIN from 192.168.1.50 (5 attempts in 60s)",
        "matched_at": datetime.now().isoformat(),
    }
    am.send_alert(test_alert)
    print(f"\nAlert log: {am.get_alert_stats()}")
