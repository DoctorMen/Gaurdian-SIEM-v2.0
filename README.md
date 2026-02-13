# 🛡️ Guardian SIEM v2.0

**A full-featured Security Information and Event Management (SIEM) system built in Python.**

Guardian captures live network traffic, ingests logs from multiple sources, evaluates events against configurable detection rules, enriches alerts with MITRE ATT&CK mappings and GeoIP data, queries external threat intelligence APIs, and presents everything through a professional real-time SOC dashboard.

[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.x-green.svg)](https://flask.palletsprojects.com)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)](Dockerfile)

---

## Features

| Feature | Description |
|---------|-------------|
| **Real-Time Dashboard** | Dark-themed SOC dashboard with live event feed via WebSocket, severity charts, and filter controls |
| **Rules Engine** | YAML-configurable detection rules with regex matching, threshold counting, and sliding windows |
| **MITRE ATT&CK** | Every alert mapped to ATT&CK technique IDs and tactics with an interactive heatmap |
| **Threat Intelligence** | Automated IP reputation checks via AbuseIPDB and VirusTotal APIs with local caching |
| **GeoIP Mapping** | Attack origin map powered by Leaflet.js with MaxMind GeoLite2 / ip-api.com fallback |
| **Passive IPS** | Scapy-based network monitor detecting rate anomalies, port scans, and DNS anomalies |
| **Log Ingestion** | Windows Event Log, Sysmon, and file-based log parsing (Apache, Nginx, custom) |
| **Alert Notifications** | Email (SMTP) and Slack webhook alerting with deduplication and rate limiting |
| **Identity Verifier** | Windows Authenticode signature validation against trusted publisher lists |
| **Docker Deployment** | Full `docker-compose` stack — dashboard, IPS, and log ingestor in separate containers |
| **Unit Tests** | Comprehensive test suite covering all core modules |

---

## Architecture

```
┌──────────────────┐    ┌──────────────┐    ┌─────────────────┐
│   Passive IPS    │───▶│              │    │  Rules Engine   │
│ (Scapy capture)  │    │              │───▶│ (YAML rules)    │
└──────────────────┘    │              │    └────────┬────────┘
                        │  Event Bus   │             │
┌──────────────────┐    │  (Singleton) │    ┌────────▼────────┐
│  Log Ingestor    │───▶│              │    │ MITRE Tagger    │
│ (WinEvt/Sysmon/  │    │              │    │ (ATT&CK mapping)│
│  File tailing)   │    │              │    └────────┬────────┘
└──────────────────┘    │              │             │
                        │      │       │    ┌────────▼────────┐
┌──────────────────┐    │      │       │    │ Threat Intel    │
│ Identity Verifier│    │      ▼       │    │ (AbuseIPDB / VT)│
│ (Authenticode)   │    │  SQLite DB   │    └────────┬────────┘
└──────────────────┘    │              │             │
                        └──────┬───────┘    ┌────────▼────────┐
                               │            │  GeoIP Lookup   │
                        ┌──────▼───────┐    │ (MaxMind/ip-api)│
                        │   Flask +    │    └────────┬────────┘
                        │  WebSocket   │             │
                        │  Dashboard   │◀────────────┘
                        │  (REST API)  │
                        └──────┬───────┘    ┌─────────────────┐
                               │            │ Alert Manager   │
                               └───────────▶│ (Email / Slack) │
                                            └─────────────────┘
```

---

## Quick Start

### Prerequisites

- **Python 3.10+**
- **Windows** (for Identity Verifier and Windows Event Log ingestion; other modules work cross-platform)
- **Admin/elevated terminal** (required for raw packet capture)

### Installation

```bash
# Clone the repository
git clone https://github.com/DoctorMen/Gaurdian-SIEM-v2.0.git
cd Gaurdian-SIEM-v2.0

# Create and activate virtual environment
python -m venv .venv
.venv\Scripts\activate        # Windows
# source .venv/bin/activate   # Linux/macOS

# Install dependencies
pip install -r requirements.txt
```

### Run

```bash
# 1. Start the Dashboard (initializes DB automatically)
python guardian_dash.py

# 2. (Optional) Start the Passive IPS in another terminal (requires admin)
python passive_ips.py

# 3. (Optional) Start the Log Ingestor in another terminal
python log_ingestor.py
```

Open **http://localhost:5001** for the dashboard.

### Docker

```bash
# Build and launch all services
docker-compose up --build -d

# View logs
docker-compose logs -f
```

---

## Dashboard

The SOC dashboard provides:

- **Live Event Feed** — real-time events via WebSocket with severity filtering
- **Stats Cards** — total events, last 24h, critical alerts, unique IPs
- **Severity Distribution** — horizontal bar chart of event severities
- **Attack Origin Map** — Leaflet.js world map with GeoIP-plotted threat sources
- **MITRE ATT&CK Heatmap** — visual coverage of triggered techniques
- **Active Detection Rules** — table of all loaded YAML rules
- **Top Sources** — ranked list of event sources

---

## API Reference

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | SOC Dashboard UI |
| `/api/events` | GET | Events (query params: `limit`, `severity`, `source`, `since`, `mitre_id`) |
| `/api/stats` | GET | Aggregate statistics (totals, severity breakdown, top sources) |
| `/api/mitre` | GET | MITRE ATT&CK technique data and trigger counts |
| `/api/geo` | GET | GeoIP data for all tracked source IPs |
| `/api/rules` | GET | Active detection rules from YAML config |
| `/api/alerts` | GET | Recent alert notifications |
| `/api/threat/<ip>` | GET | Threat intelligence lookup for a specific IP |
| `/api/geoip/<ip>` | GET | GeoIP resolution for a specific IP |
| `/api/health` | GET | System health check and module status |
| `/ws` | WebSocket | Real-time event stream |

---

## Detection Rules

Rules are defined in `config/alert_rules.yaml`:

```yaml
rules:
  - name: "Brute Force Detection"
    description: "Multiple failed login attempts from the same source"
    source: ".*"
    pattern: "(failed login|authentication failure|4625)"
    severity: "HIGH"
    mitre_id: "T1110"
    mitre_tactic: "Credential Access"
    threshold: 5
    window_seconds: 60
    enabled: true
```

**Included rules:** Brute Force, Port Scan, Traffic Anomaly, Privilege Escalation, Log Tampering, Service Installation, Reverse Shell, Data Exfiltration, Unauthorized Access, Malware Signature.

Rules support regex patterns, source filtering, threshold counts with sliding windows, and hot-reload without restart.

---

## Threat Intelligence

Configure API keys via environment variables or `config/config.yaml`:

```bash
# Environment variables (recommended)
export ABUSEIPDB_API_KEY="your-key-here"
export VIRUSTOTAL_API_KEY="your-key-here"

# Or in config/config.yaml
threat_intel:
  abuseipdb:
    enabled: true
    api_key: "your-key-here"
```

Results are cached locally in SQLite to respect rate limits.

---

## Project Structure

```
Guardian_SIEM/
├── config/
│   ├── config.yaml              # Master configuration
│   ├── alert_rules.yaml         # Detection rules (YAML)
│   └── mitre_mappings.yaml      # MITRE ATT&CK technique/tactic mappings
├── database/                    # SQLite databases (auto-created)
├── service_logs/                # Drop log files here for ingestion
├── static/
│   ├── css/dashboard.css        # SOC dashboard dark theme
│   └── js/dashboard.js          # Real-time event feed & charts
├── templates/
│   └── dashboard.html           # Dashboard HTML template
├── tests/
│   ├── test_event_bus.py        # Event Bus unit tests
│   ├── test_rules_engine.py     # Rules Engine unit tests
│   ├── test_mitre_tagger.py     # MITRE Tagger unit tests
│   ├── test_threat_intel.py     # Threat Intel unit tests
│   ├── test_geoip.py            # GeoIP unit tests
│   └── test_alert_manager.py    # Alert Manager unit tests
├── event_bus.py                 # Central event pipeline (singleton)
├── guardian_dash.py             # Flask dashboard + WebSocket + REST API
├── passive_ips.py               # Scapy network monitor (IPS)
├── log_ingestor.py              # Multi-source log ingestion
├── rules_engine.py              # YAML-based detection rules engine
├── mitre_tagger.py              # MITRE ATT&CK enrichment
├── threat_intel.py              # AbuseIPDB + VirusTotal integration
├── geoip_lookup.py              # GeoIP resolution (MaxMind + ip-api.com)
├── alert_manager.py             # Email + Slack alerting
├── identity_verifier.py         # Windows Authenticode checker
├── Dockerfile                   # Container image definition
├── docker-compose.yml           # Multi-service orchestration
├── requirements.txt             # Python dependencies
└── README.md
```

---

## Running Tests

```bash
# Run all tests
python -m pytest tests/ -v

# Run specific test module
python -m pytest tests/test_rules_engine.py -v

# Run with coverage (install pytest-cov first)
python -m pytest tests/ --cov=. --cov-report=term-missing
```

---

## Configuration

All configuration lives in `config/config.yaml`. Key settings:

| Setting | Default | Description |
|---------|---------|-------------|
| `dashboard.port` | 5001 | Dashboard server port |
| `ips.threshold` | 100 | Packets per window to trigger alert |
| `ips.window_seconds` | 5 | Sliding window size |
| `alerting.email.enabled` | false | Enable email notifications |
| `alerting.slack.enabled` | false | Enable Slack notifications |
| `threat_intel.abuseipdb.enabled` | false | Enable AbuseIPDB lookups |
| `threat_intel.virustotal.enabled` | false | Enable VirusTotal lookups |
| `log_ingestion.poll_interval_seconds` | 5 | Log polling frequency |

---

## Roadmap

- [ ] Elasticsearch backend option for large-scale deployments
- [ ] SIGMA rule format support
- [ ] YARA file scanning integration
- [ ] Active response (auto-block IPs via firewall rules)
- [ ] User authentication for dashboard
- [ ] PDF report generation
- [ ] Syslog receiver (UDP/TCP)

---

## License

MIT
