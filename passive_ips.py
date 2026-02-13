from scapy.all import sniff, IP
from event_bus import EventBus
from collections import defaultdict
import time

class GuardianIPS:
    def __init__(self):
        self.bus = EventBus()
        self.stats = defaultdict(list)
        self.THRESHOLD = 1000  # High threshold for dev tools

    def packet_callback(self, pkt):
        if pkt.haslayer(IP):
            src_ip = pkt[IP].src
            now = time.time()

            # Sliding window logic to prevent instant blocks
            self.stats[src_ip] = [t for t in self.stats[src_ip] if now - t < 5]
            self.stats[src_ip].append(now)

            if len(self.stats[src_ip]) > self.THRESHOLD:
                self.bus.emit("Network_IPS", "WARNING", f"High traffic detected from {src_ip}")

if __name__ == "__main__":
    print("[*] Guardian IPS Started (Passive Mode)...")
    ips = GuardianIPS()
    sniff(prn=ips.packet_callback, store=0)