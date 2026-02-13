# Guardian SIEM v2.0

A lightweight Security Information and Event Management (SIEM) system built in Python. Guardian monitors network traffic, detects anomalies, verifies software identity, and serves a live event dashboard — all from a local machine.

## Architecture

```
┌──────────────┐     ┌───────────┐     ┌──────────────┐
│  Passive IPS │────▶│ Event Bus │────▶│   SQLite DB  │
│ (Scapy sniff)│     │           │     │              │
└──────────────┘     └───────────┘     └──────┬───────┘
                                              │
┌──────────────┐                     ┌────────▼───────┐
│  Identity    │                     │  Flask Dashboard│
│  Verifier    │                     │  (REST API)     │
└──────────────┘                     └────────────────┘
```

| Component | File | Description |
|-----------|------|-------------|
| **Event Bus** | `event_bus.py` | Central event pipeline — receives events from all sources and persists them to SQLite |
| **Passive IPS** | `passive_ips.py` | Sniffs live network traffic with Scapy, detects high-rate sources using a sliding window |
| **Identity Verifier** | `identity_verifier.py` | Validates Windows Authenticode signatures against a trusted publisher list |
| **Dashboard** | `guardian_dash.py` | Flask web server exposing a REST API to view the latest security events |

## Requirements

- Python 3.10+
- Windows (Identity Verifier uses PowerShell's `Get-AuthenticodeSignature`)
- Admin/elevated terminal (required for raw packet capture with Scapy)

## Setup

```bash
# Clone the repo
git clone https://github.com/<your-username>/Guardian_SIEM.git
cd Guardian_SIEM

# Create a virtual environment
python -m venv .venv
.venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Usage

### 1. Initialize the Event Bus (creates the database)
```bash
python event_bus.py
```

### 2. Start the Passive IPS (requires admin)
```bash
python passive_ips.py
```

### 3. Start the Dashboard
```bash
python guardian_dash.py
```
Then open [http://localhost:5001](http://localhost:5001) to view the dashboard, or hit [http://localhost:5001/api/events](http://localhost:5001/api/events) for raw JSON.

## API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Dashboard home page |
| `/api/events` | GET | Returns the 50 most recent events as JSON |

## Project Structure

```
Guardian_SIEM/
├── database/              # SQLite database (auto-created)
├── service_logs/          # Reserved for future file-based logging
├── event_bus.py           # Central event pipeline
├── guardian_dash.py       # Flask dashboard & API
├── identity_verifier.py   # Authenticode signature checker
├── passive_ips.py         # Network traffic monitor (IPS)
├── requirements.txt       # Python dependencies
└── README.md
```

## License

MIT
