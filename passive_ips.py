"""
Guardian SIEM v2.0 — Passive Intrusion Prevention System
Monitors live network traffic using Scapy, detects anomalies via
sliding-window rate analysis, and feeds events through the full
enrichment pipeline (Rules Engine → MITRE → GeoIP → Alerts).
"""

from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR
from event_bus import EventBus
from rules_engine import RulesEngine
from mitre_tagger import MitreTagger
from geoip_lookup import GeoIPLookup
from alert_manager import AlertManager
from collections import defaultdict
import time
import os
import yaml
import re


class GuardianIPS:
    """Passive network intrusion detection with full SIEM integration."""

    def __init__(self, config_path=None):
        base_dir = os.path.dirname(os.path.abspath(__file__))
        if config_path is None:
            config_path = os.path.join(base_dir, "config", "config.yaml")

        self.config = {}
        self._load_config(config_path)

        # Initialize all modules
        self.bus = EventBus()
        self.rules_engine = RulesEngine()
        self.mitre_tagger = MitreTagger()
        self.geoip = GeoIPLookup()
        self.alert_manager = AlertManager()

        # Traffic analysis state
        self.stats = defaultdict(list)
        self.port_scan_tracker = defaultdict(set)  # ip -> set of ports
        self.dns_tracker = defaultdict(list)  # ip -> list of DNS queries

        # Config
        ips_config = self.config.get("ips", {})
        self.THRESHOLD = ips_config.get("threshold", 100)
        self.WINDOW = ips_config.get("window_seconds", 5)

        # Counters for reporting
        self.total_packets = 0
        self.alerts_fired = 0

    def _load_config(self, config_path):
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                self.config = yaml.safe_load(f) or {}
        except (FileNotFoundError, yaml.YAMLError):
            self.config = {}

    def packet_callback(self, pkt):
        """Process each captured packet through the detection pipeline."""
        self.total_packets += 1

        if not pkt.haslayer(IP):
            return

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        now = time.time()

        # ---- Rate-based anomaly detection ----
        self.stats[src_ip] = [t for t in self.stats[src_ip] if now - t < self.WINDOW]
        self.stats[src_ip].append(now)

        if len(self.stats[src_ip]) > self.THRESHOLD:
            geo = self.geoip.lookup(src_ip)
            enrichment = {
                "src_ip": src_ip,
                "geo_country": geo.get("country", ""),
                "geo_city": geo.get("city", ""),
                "geo_lat": geo.get("latitude", 0),
                "geo_lon": geo.get("longitude", 0),
            }
            self.bus.emit(
                "Network_IPS", "WARNING",
                f"High traffic detected from {src_ip} ({len(self.stats[src_ip])} pkts/{self.WINDOW}s) "
                f"[{geo.get('city', '?')}, {geo.get('country', '?')}]",
                enrichment=enrichment
            )
            self.stats[src_ip] = []  # Reset after alert
            self.alerts_fired += 1

        # ---- Port scan detection ----
        if pkt.haslayer(TCP):
            dst_port = pkt[TCP].dport
            flags = pkt[TCP].flags

            # SYN without ACK = potential scan
            if flags == 0x02:  # SYN flag
                self.port_scan_tracker[src_ip].add(dst_port)

                # If we see connections to > 20 unique ports in window
                if len(self.port_scan_tracker[src_ip]) > 20:
                    ports_sample = sorted(list(self.port_scan_tracker[src_ip]))[:10]
                    geo = self.geoip.lookup(src_ip)
                    enrichment = {
                        "src_ip": src_ip,
                        "mitre_id": "T1046",
                        "mitre_tactic": "Discovery",
                        "geo_country": geo.get("country", ""),
                        "geo_city": geo.get("city", ""),
                        "geo_lat": geo.get("latitude", 0),
                        "geo_lon": geo.get("longitude", 0),
                    }
                    self.bus.emit(
                        "Network_IPS", "MEDIUM",
                        f"Port scan detected from {src_ip}: "
                        f"{len(self.port_scan_tracker[src_ip])} unique ports "
                        f"(sample: {ports_sample})",
                        enrichment=enrichment
                    )
                    self.port_scan_tracker[src_ip] = set()
                    self.alerts_fired += 1

        # ---- DNS monitoring ----
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            query = pkt[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
            self.dns_tracker[src_ip].append(query)

            # Detect suspicious DNS patterns (DGA-like, excessive queries)
            if len(self.dns_tracker[src_ip]) > 50:
                # Check for possible DGA (domain generation algorithm)
                recent = self.dns_tracker[src_ip][-50:]
                avg_len = sum(len(q) for q in recent) / len(recent)
                unique_ratio = len(set(recent)) / len(recent)

                if avg_len > 20 and unique_ratio > 0.9:
                    self.bus.emit(
                        "Network_IPS", "HIGH",
                        f"Suspicious DNS activity from {src_ip}: "
                        f"{len(set(recent))} unique queries, avg length {avg_len:.0f} "
                        f"(possible DGA/C2 beaconing)",
                        enrichment={"src_ip": src_ip, "mitre_id": "T1568", "mitre_tactic": "Command and Control"}
                    )
                    self.alerts_fired += 1

                self.dns_tracker[src_ip] = self.dns_tracker[src_ip][-10:]

    def get_status(self):
        """Return current IPS status for dashboard."""
        return {
            "total_packets": self.total_packets,
            "alerts_fired": self.alerts_fired,
            "tracked_ips": len(self.stats),
            "threshold": self.THRESHOLD,
            "window": self.WINDOW,
        }


if __name__ == "__main__":
    print("=" * 55)
    print(" 🛡️  Guardian IPS v2.0 — Passive Network Monitor")
    print("=" * 55)
    ips = GuardianIPS()
    print(f"  Threshold: {ips.THRESHOLD} packets / {ips.WINDOW}s window")
    print(f"  Rules loaded: {len(ips.rules_engine.rules)}")
    print(f"  Detections: Rate anomaly, Port scan, DNS anomaly")
    print(f"\n  Listening for packets... (Ctrl+C to stop)\n")

    try:
        sniff(prn=ips.packet_callback, store=0)
    except KeyboardInterrupt:
        status = ips.get_status()
        print(f"\n\n  Session Summary:")
        print(f"    Packets processed: {status['total_packets']}")
        print(f"    Alerts fired: {status['alerts_fired']}")
        print(f"    Unique IPs tracked: {status['tracked_ips']}")