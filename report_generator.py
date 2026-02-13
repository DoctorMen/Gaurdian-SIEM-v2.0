"""
Guardian SIEM v2.0 — PDF Report Generator
Generates professional incident and summary reports in PDF format.
  - Executive summary with key metrics
  - Event timeline visualization
  - Severity breakdown charts (ASCII-based for portability)
  - MITRE ATT&CK coverage summary
  - Top threat sources with GeoIP
  - Active detection rules overview
  - Exports to PDF using reportlab (or HTML fallback)
"""

import os
import io
import yaml
import sqlite3
from datetime import datetime, timedelta
from collections import Counter, defaultdict

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        PageBreak, Image, HRFlowable
    )
    from reportlab.graphics.shapes import Drawing, Rect, String
    from reportlab.graphics.charts.barcharts import VerticalBarChart
    from reportlab.graphics.charts.piecharts import Pie
    HAS_REPORTLAB = True
except ImportError:
    HAS_REPORTLAB = False


class ReportGenerator:
    """Generates PDF security reports from Guardian SIEM data."""

    def __init__(self, config_path=None):
        base_dir = os.path.dirname(os.path.abspath(__file__))
        if config_path is None:
            config_path = os.path.join(base_dir, "config", "config.yaml")

        self.config = {}
        self._load_config(config_path)
        self.base_dir = base_dir
        self.db_path = os.path.join(base_dir, "database", "guardian_events.db")
        self.reports_dir = os.path.join(base_dir, "reports")
        os.makedirs(self.reports_dir, exist_ok=True)

        self.severity_colors = {
            "CRITICAL": colors.HexColor("#ff1744"),
            "HIGH": colors.HexColor("#ff9100"),
            "MEDIUM": colors.HexColor("#ffea00"),
            "LOW": colors.HexColor("#00e676"),
            "INFO": colors.HexColor("#448aff"),
        } if HAS_REPORTLAB else {}

    def _load_config(self, config_path):
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                self.config = yaml.safe_load(f) or {}
        except (FileNotFoundError, yaml.YAMLError):
            self.config = {}

    def generate_report(self, report_type="daily", hours=24, output_path=None):
        """
        Generate a PDF report.

        Args:
            report_type: 'daily', 'weekly', 'incident', or 'executive'
            hours: Time window for the report (in hours)
            output_path: Custom output path (default: reports/ directory)

        Returns:
            Path to the generated PDF file, or HTML string if reportlab unavailable
        """
        # Gather data
        data = self._gather_data(hours)

        if output_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"guardian_{report_type}_report_{timestamp}.pdf"
            output_path = os.path.join(self.reports_dir, filename)

        if HAS_REPORTLAB:
            self._generate_pdf(data, report_type, output_path)
            return output_path
        else:
            # Fallback: generate HTML report
            html_path = output_path.replace(".pdf", ".html")
            html = self._generate_html(data, report_type)
            with open(html_path, "w", encoding="utf-8") as f:
                f.write(html)
            return html_path

    def _gather_data(self, hours):
        """Query the event database for report data."""
        since = (datetime.now() - timedelta(hours=hours)).isoformat()
        data = {
            "generated_at": datetime.now().isoformat(),
            "period_hours": hours,
            "period_start": since,
            "period_end": datetime.now().isoformat(),
            "total_events": 0,
            "severity_counts": {},
            "top_sources": [],
            "top_ips": [],
            "top_rules": [],
            "mitre_techniques": [],
            "geo_countries": [],
            "recent_critical": [],
            "hourly_distribution": {},
        }

        if not os.path.isfile(self.db_path):
            return data

        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row

        try:
            # Total events
            row = conn.execute(
                "SELECT COUNT(*) as cnt FROM events WHERE timestamp >= ?", (since,)
            ).fetchone()
            data["total_events"] = row["cnt"] if row else 0

            # Severity breakdown
            rows = conn.execute(
                """SELECT severity, COUNT(*) as cnt FROM events
                   WHERE timestamp >= ? GROUP BY severity ORDER BY cnt DESC""", (since,)
            ).fetchall()
            data["severity_counts"] = {r["severity"]: r["cnt"] for r in rows}

            # Top sources
            rows = conn.execute(
                """SELECT source, COUNT(*) as cnt FROM events
                   WHERE timestamp >= ? GROUP BY source ORDER BY cnt DESC LIMIT 10""", (since,)
            ).fetchall()
            data["top_sources"] = [{"source": r["source"], "count": r["cnt"]} for r in rows]

            # Top IPs
            rows = conn.execute(
                """SELECT src_ip, COUNT(*) as cnt, MAX(threat_score) as max_threat,
                          geo_country, geo_city
                   FROM events WHERE timestamp >= ? AND src_ip != ''
                   GROUP BY src_ip ORDER BY cnt DESC LIMIT 15""", (since,)
            ).fetchall()
            data["top_ips"] = [{
                "ip": r["src_ip"], "count": r["cnt"],
                "threat_score": r["max_threat"],
                "country": r["geo_country"], "city": r["geo_city"],
            } for r in rows]

            # Top triggered rules
            rows = conn.execute(
                """SELECT rule_matched, COUNT(*) as cnt, MAX(severity) as max_sev
                   FROM events WHERE timestamp >= ? AND rule_matched != ''
                   GROUP BY rule_matched ORDER BY cnt DESC LIMIT 10""", (since,)
            ).fetchall()
            data["top_rules"] = [{
                "rule": r["rule_matched"], "count": r["cnt"], "severity": r["max_sev"]
            } for r in rows]

            # MITRE techniques triggered
            rows = conn.execute(
                """SELECT mitre_id, mitre_tactic, COUNT(*) as cnt
                   FROM events WHERE timestamp >= ? AND mitre_id != ''
                   GROUP BY mitre_id ORDER BY cnt DESC LIMIT 10""", (since,)
            ).fetchall()
            data["mitre_techniques"] = [{
                "technique": r["mitre_id"], "tactic": r["mitre_tactic"], "count": r["cnt"]
            } for r in rows]

            # Geographic distribution
            rows = conn.execute(
                """SELECT geo_country, COUNT(*) as cnt FROM events
                   WHERE timestamp >= ? AND geo_country != ''
                   GROUP BY geo_country ORDER BY cnt DESC LIMIT 10""", (since,)
            ).fetchall()
            data["geo_countries"] = [{"country": r["geo_country"], "count": r["cnt"]} for r in rows]

            # Recent critical events
            rows = conn.execute(
                """SELECT timestamp, source, severity, message, src_ip, rule_matched, mitre_id
                   FROM events WHERE timestamp >= ? AND severity IN ('CRITICAL', 'HIGH')
                   ORDER BY timestamp DESC LIMIT 20""", (since,)
            ).fetchall()
            data["recent_critical"] = [dict(r) for r in rows]

        except sqlite3.Error:
            pass
        finally:
            conn.close()

        return data

    def _generate_pdf(self, data, report_type, output_path):
        """Generate a professional PDF report using reportlab."""
        doc = SimpleDocTemplate(
            output_path, pagesize=letter,
            topMargin=0.75 * inch, bottomMargin=0.75 * inch,
            leftMargin=0.75 * inch, rightMargin=0.75 * inch,
        )

        styles = getSampleStyleSheet()

        # Custom styles
        title_style = ParagraphStyle(
            "ReportTitle", parent=styles["Title"],
            fontSize=24, spaceAfter=6,
            textColor=colors.HexColor("#00e5ff"),
        )
        heading_style = ParagraphStyle(
            "SectionHeading", parent=styles["Heading2"],
            fontSize=14, spaceBefore=16, spaceAfter=8,
            textColor=colors.HexColor("#00e5ff"),
            borderPadding=(0, 0, 4, 0),
        )
        body_style = ParagraphStyle(
            "ReportBody", parent=styles["Normal"],
            fontSize=10, leading=14,
            textColor=colors.HexColor("#333333"),
        )
        small_style = ParagraphStyle(
            "SmallText", parent=styles["Normal"],
            fontSize=8, textColor=colors.HexColor("#666666"),
        )

        story = []

        # ---- Title Page ----
        story.append(Spacer(1, 1.5 * inch))
        story.append(Paragraph("🛡️ Guardian SIEM", title_style))
        report_titles = {
            "daily": "Daily Security Report",
            "weekly": "Weekly Security Summary",
            "incident": "Incident Report",
            "executive": "Executive Security Briefing",
        }
        story.append(Paragraph(report_titles.get(report_type, "Security Report"), styles["Heading2"]))
        story.append(Spacer(1, 12))
        story.append(Paragraph(
            f"Report Period: {data['period_hours']} hours<br/>"
            f"Generated: {data['generated_at'][:19].replace('T', ' ')}<br/>"
            f"Total Events: {data['total_events']}",
            body_style
        ))
        story.append(Spacer(1, 0.5 * inch))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#00e5ff")))
        story.append(PageBreak())

        # ---- Executive Summary ----
        story.append(Paragraph("Executive Summary", heading_style))

        crit = data["severity_counts"].get("CRITICAL", 0)
        high = data["severity_counts"].get("HIGH", 0)
        medium = data["severity_counts"].get("MEDIUM", 0)
        low = data["severity_counts"].get("LOW", 0)
        info = data["severity_counts"].get("INFO", 0)

        summary_text = (
            f"During the past {data['period_hours']} hours, Guardian SIEM processed "
            f"<b>{data['total_events']}</b> security events. Of these, "
            f"<font color='red'><b>{crit}</b> were CRITICAL</font>, "
            f"<font color='#ff9100'><b>{high}</b> HIGH</font>, "
            f"<font color='#cc9900'><b>{medium}</b> MEDIUM</font>, "
            f"<b>{low}</b> LOW, and <b>{info}</b> informational."
        )
        story.append(Paragraph(summary_text, body_style))
        story.append(Spacer(1, 12))

        # ---- Severity Table ----
        story.append(Paragraph("Severity Distribution", heading_style))
        sev_data = [["Severity", "Count", "Percentage"]]
        total = max(data["total_events"], 1)
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            cnt = data["severity_counts"].get(sev, 0)
            pct = f"{cnt / total * 100:.1f}%"
            sev_data.append([sev, str(cnt), pct])

        sev_table = Table(sev_data, colWidths=[2 * inch, 1.5 * inch, 1.5 * inch])
        sev_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e0e0e0")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8f9fa")]),
            ("ALIGN", (1, 0), (-1, -1), "CENTER"),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(sev_table)
        story.append(Spacer(1, 12))

        # ---- Top Sources ----
        if data["top_sources"]:
            story.append(Paragraph("Top Event Sources", heading_style))
            src_data = [["Source", "Event Count"]]
            for s in data["top_sources"]:
                src_data.append([s["source"], str(s["count"])])

            src_table = Table(src_data, colWidths=[4 * inch, 2 * inch])
            src_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e0e0e0")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8f9fa")]),
                ("ALIGN", (1, 0), (1, -1), "CENTER"),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]))
            story.append(src_table)
            story.append(Spacer(1, 12))

        # ---- Top Threat IPs ----
        if data["top_ips"]:
            story.append(Paragraph("Top Threat Source IPs", heading_style))
            ip_data = [["IP Address", "Events", "Threat Score", "Country", "City"]]
            for ip in data["top_ips"][:10]:
                ip_data.append([
                    ip["ip"], str(ip["count"]),
                    str(ip.get("threat_score", 0)),
                    ip.get("country", ""), ip.get("city", ""),
                ])

            ip_table = Table(ip_data, colWidths=[1.5 * inch, 0.8 * inch, 1 * inch, 1.5 * inch, 1.2 * inch])
            ip_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e0e0e0")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8f9fa")]),
                ("ALIGN", (1, 0), (3, -1), "CENTER"),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]))
            story.append(ip_table)
            story.append(Spacer(1, 12))

        # ---- MITRE ATT&CK Coverage ----
        if data["mitre_techniques"]:
            story.append(Paragraph("MITRE ATT&CK Techniques Observed", heading_style))
            mitre_data = [["Technique ID", "Tactic", "Occurrences"]]
            for m in data["mitre_techniques"]:
                mitre_data.append([m["technique"], m.get("tactic", ""), str(m["count"])])

            mitre_table = Table(mitre_data, colWidths=[1.5 * inch, 3 * inch, 1.5 * inch])
            mitre_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e0e0e0")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8f9fa")]),
                ("ALIGN", (2, 0), (2, -1), "CENTER"),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]))
            story.append(mitre_table)
            story.append(Spacer(1, 12))

        # ---- Top Detection Rules ----
        if data["top_rules"]:
            story.append(Paragraph("Most Triggered Detection Rules", heading_style))
            rule_data = [["Rule Name", "Triggers", "Max Severity"]]
            for r in data["top_rules"]:
                rule_data.append([r["rule"], str(r["count"]), r.get("severity", "")])

            rule_table = Table(rule_data, colWidths=[3.5 * inch, 1.25 * inch, 1.25 * inch])
            rule_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e0e0e0")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8f9fa")]),
                ("ALIGN", (1, 0), (-1, -1), "CENTER"),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]))
            story.append(rule_table)
            story.append(Spacer(1, 12))

        # ---- Recent Critical Events ----
        if data["recent_critical"]:
            story.append(PageBreak())
            story.append(Paragraph("Recent Critical/High Events", heading_style))
            for evt in data["recent_critical"][:15]:
                ts = evt.get("timestamp", "")[:19].replace("T", " ")
                sev = evt.get("severity", "")
                msg = evt.get("message", "")[:120]
                src = evt.get("source", "")
                mitre = evt.get("mitre_id", "")

                evt_text = (
                    f"<font color='#999'>{ts}</font>  "
                    f"<b>[{sev}]</b> {src}<br/>"
                    f"  {msg}"
                )
                if mitre:
                    evt_text += f"  <font color='#00e5ff'>({mitre})</font>"
                story.append(Paragraph(evt_text, body_style))
                story.append(Spacer(1, 4))

        # ---- Footer ----
        story.append(Spacer(1, 0.5 * inch))
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.gray))
        story.append(Paragraph(
            f"Generated by Guardian SIEM v2.0 — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            small_style
        ))

        doc.build(story)
        print(f"[ReportGenerator] PDF saved: {output_path}")

    def _generate_html(self, data, report_type):
        """Generate an HTML report (fallback when reportlab is unavailable)."""
        report_titles = {
            "daily": "Daily Security Report",
            "weekly": "Weekly Security Summary",
            "incident": "Incident Report",
            "executive": "Executive Security Briefing",
        }
        title = report_titles.get(report_type, "Security Report")

        crit = data["severity_counts"].get("CRITICAL", 0)
        high = data["severity_counts"].get("HIGH", 0)
        medium = data["severity_counts"].get("MEDIUM", 0)
        low = data["severity_counts"].get("LOW", 0)
        info = data["severity_counts"].get("INFO", 0)

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Guardian SIEM — {title}</title>
<style>
  body {{ font-family: 'Segoe UI', sans-serif; background: #f5f5f5; color: #333; max-width: 900px; margin: 0 auto; padding: 20px; }}
  h1 {{ color: #00838f; border-bottom: 2px solid #00e5ff; padding-bottom: 8px; }}
  h2 {{ color: #00838f; margin-top: 24px; }}
  table {{ border-collapse: collapse; width: 100%; margin: 12px 0; }}
  th {{ background: #1e293b; color: white; padding: 8px 12px; text-align: left; font-size: 0.9em; }}
  td {{ padding: 6px 12px; border-bottom: 1px solid #e0e0e0; font-size: 0.9em; }}
  tr:nth-child(even) {{ background: #f8f9fa; }}
  .stat {{ display: inline-block; background: white; border: 1px solid #e0e0e0; border-radius: 8px; padding: 16px 24px; margin: 4px; text-align: center; }}
  .stat .value {{ font-size: 2em; font-weight: bold; color: #00838f; }}
  .stat .label {{ font-size: 0.8em; color: #666; }}
  .critical {{ color: #ff1744; font-weight: bold; }}
  .high {{ color: #ff9100; font-weight: bold; }}
  .footer {{ margin-top: 40px; font-size: 0.8em; color: #999; border-top: 1px solid #e0e0e0; padding-top: 8px; }}
</style>
</head>
<body>
<h1>🛡️ Guardian SIEM — {title}</h1>
<p>Report Period: {data['period_hours']} hours | Generated: {data['generated_at'][:19].replace('T', ' ')}</p>

<div>
  <div class="stat"><div class="value">{data['total_events']}</div><div class="label">Total Events</div></div>
  <div class="stat"><div class="value critical">{crit}</div><div class="label">Critical</div></div>
  <div class="stat"><div class="value high">{high}</div><div class="label">High</div></div>
  <div class="stat"><div class="value">{medium}</div><div class="label">Medium</div></div>
  <div class="stat"><div class="value">{low + info}</div><div class="label">Low/Info</div></div>
</div>
"""

        # Top Sources table
        if data["top_sources"]:
            html += "<h2>Top Event Sources</h2><table><tr><th>Source</th><th>Count</th></tr>"
            for s in data["top_sources"]:
                html += f"<tr><td>{s['source']}</td><td>{s['count']}</td></tr>"
            html += "</table>"

        # Top IPs table
        if data["top_ips"]:
            html += "<h2>Top Threat IPs</h2><table><tr><th>IP</th><th>Events</th><th>Threat Score</th><th>Country</th></tr>"
            for ip in data["top_ips"][:10]:
                html += f"<tr><td>{ip['ip']}</td><td>{ip['count']}</td><td>{ip.get('threat_score',0)}</td><td>{ip.get('country','')}</td></tr>"
            html += "</table>"

        # MITRE table
        if data["mitre_techniques"]:
            html += "<h2>MITRE ATT&CK Techniques</h2><table><tr><th>Technique</th><th>Tactic</th><th>Count</th></tr>"
            for m in data["mitre_techniques"]:
                html += f"<tr><td>{m['technique']}</td><td>{m.get('tactic','')}</td><td>{m['count']}</td></tr>"
            html += "</table>"

        # Recent critical events
        if data["recent_critical"]:
            html += "<h2>Recent Critical/High Events</h2><table><tr><th>Time</th><th>Severity</th><th>Source</th><th>Message</th></tr>"
            for evt in data["recent_critical"][:15]:
                ts = evt.get("timestamp", "")[:19].replace("T", " ")
                sev_class = evt.get("severity", "").lower()
                html += f"<tr><td>{ts}</td><td class='{sev_class}'>{evt.get('severity','')}</td><td>{evt.get('source','')}</td><td>{evt.get('message','')[:100]}</td></tr>"
            html += "</table>"

        html += f"""
<div class="footer">Generated by Guardian SIEM v2.0 — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
</body></html>"""
        return html

    def get_available_reports(self):
        """List previously generated reports."""
        reports = []
        for fname in os.listdir(self.reports_dir):
            if fname.endswith((".pdf", ".html")):
                fpath = os.path.join(self.reports_dir, fname)
                reports.append({
                    "filename": fname,
                    "size_kb": round(os.path.getsize(fpath) / 1024, 1),
                    "created": datetime.fromtimestamp(os.path.getctime(fpath)).isoformat(),
                })
        reports.sort(key=lambda x: x["created"], reverse=True)
        return reports
