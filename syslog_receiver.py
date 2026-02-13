"""
Guardian SIEM v2.0 — Syslog Receiver
Multi-protocol syslog server that receives logs from network devices,
firewalls, Linux servers, and other syslog-capable sources.
  - UDP receiver (RFC 3164 / RFC 5424)
  - TCP receiver with persistent connections
  - RFC 5424 structured data parsing
  - Automatic severity mapping
  - All messages fed into the SIEM event bus
"""

import os
import re
import socket
import select
import threading
import time
import yaml
from datetime import datetime


class SyslogReceiver:
    """Multi-protocol syslog server (UDP + TCP)."""

    def __init__(self, config_path=None):
        base_dir = os.path.dirname(os.path.abspath(__file__))
        if config_path is None:
            config_path = os.path.join(base_dir, "config", "config.yaml")

        self.config = {}
        self._load_config(config_path)

        syslog_config = self.config.get("syslog", {})
        self.udp_enabled = syslog_config.get("udp_enabled", True)
        self.tcp_enabled = syslog_config.get("tcp_enabled", True)
        self.bind_address = syslog_config.get("bind_address", "0.0.0.0")
        self.udp_port = syslog_config.get("udp_port", 1514)
        self.tcp_port = syslog_config.get("tcp_port", 1514)
        self.max_message_size = syslog_config.get("max_message_size", 8192)

        self._running = False
        self._threads = []
        self._udp_socket = None
        self._tcp_socket = None
        self._tcp_clients = []
        self._tcp_lock = threading.Lock()

        # Stats
        self._stats = {
            "udp_messages": 0,
            "tcp_messages": 0,
            "parse_errors": 0,
            "total_messages": 0,
            "start_time": None,
        }

        # Callback for processed messages
        self._message_callback = None

        # Syslog facility names
        self._facilities = {
            0: "kern", 1: "user", 2: "mail", 3: "daemon",
            4: "auth", 5: "syslog", 6: "lpr", 7: "news",
            8: "uucp", 9: "cron", 10: "authpriv", 11: "ftp",
            12: "ntp", 13: "security", 14: "console", 15: "solaris-cron",
            16: "local0", 17: "local1", 18: "local2", 19: "local3",
            20: "local4", 21: "local5", 22: "local6", 23: "local7",
        }

        # Syslog severity → Guardian severity mapping
        self._severity_map = {
            0: "CRITICAL",  # Emergency
            1: "CRITICAL",  # Alert
            2: "CRITICAL",  # Critical
            3: "HIGH",      # Error
            4: "MEDIUM",    # Warning
            5: "LOW",       # Notice
            6: "INFO",      # Informational
            7: "INFO",      # Debug
        }

    def _load_config(self, config_path):
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                self.config = yaml.safe_load(f) or {}
        except (FileNotFoundError, yaml.YAMLError):
            self.config = {}

    def set_callback(self, callback):
        """
        Set callback for processed syslog messages.
        Callback receives: (source, severity, message, parsed_data)
        """
        self._message_callback = callback

    def start(self):
        """Start all enabled syslog receivers."""
        if self._running:
            return

        self._running = True
        self._stats["start_time"] = datetime.now().isoformat()

        if self.udp_enabled:
            t = threading.Thread(target=self._run_udp, daemon=True, name="syslog-udp")
            t.start()
            self._threads.append(t)
            print(f"[SyslogReceiver] UDP listening on {self.bind_address}:{self.udp_port}")

        if self.tcp_enabled:
            t = threading.Thread(target=self._run_tcp, daemon=True, name="syslog-tcp")
            t.start()
            self._threads.append(t)
            print(f"[SyslogReceiver] TCP listening on {self.bind_address}:{self.tcp_port}")

    def stop(self):
        """Stop all syslog receivers."""
        self._running = False

        if self._udp_socket:
            try:
                self._udp_socket.close()
            except Exception:
                pass

        if self._tcp_socket:
            try:
                self._tcp_socket.close()
            except Exception:
                pass

        with self._tcp_lock:
            for client in self._tcp_clients:
                try:
                    client.close()
                except Exception:
                    pass
            self._tcp_clients.clear()

        for t in self._threads:
            t.join(timeout=3)
        self._threads.clear()
        print("[SyslogReceiver] Stopped")

    def _run_udp(self):
        """UDP syslog receiver loop."""
        try:
            self._udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._udp_socket.bind((self.bind_address, self.udp_port))
            self._udp_socket.settimeout(1.0)

            while self._running:
                try:
                    data, addr = self._udp_socket.recvfrom(self.max_message_size)
                    if data:
                        message = data.decode("utf-8", errors="replace").strip()
                        self._process_message(message, addr[0], "udp")
                        self._stats["udp_messages"] += 1
                        self._stats["total_messages"] += 1
                except socket.timeout:
                    continue
                except OSError:
                    if self._running:
                        time.sleep(0.1)

        except OSError as e:
            print(f"[SyslogReceiver] UDP error: {e}")
        finally:
            if self._udp_socket:
                try:
                    self._udp_socket.close()
                except Exception:
                    pass

    def _run_tcp(self):
        """TCP syslog receiver loop."""
        try:
            self._tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._tcp_socket.bind((self.bind_address, self.tcp_port))
            self._tcp_socket.listen(10)
            self._tcp_socket.settimeout(1.0)

            while self._running:
                try:
                    client_sock, addr = self._tcp_socket.accept()
                    client_sock.settimeout(30)
                    with self._tcp_lock:
                        self._tcp_clients.append(client_sock)

                    t = threading.Thread(
                        target=self._handle_tcp_client,
                        args=(client_sock, addr),
                        daemon=True,
                        name=f"syslog-tcp-{addr[0]}:{addr[1]}"
                    )
                    t.start()

                except socket.timeout:
                    continue
                except OSError:
                    if self._running:
                        time.sleep(0.1)

        except OSError as e:
            print(f"[SyslogReceiver] TCP error: {e}")
        finally:
            if self._tcp_socket:
                try:
                    self._tcp_socket.close()
                except Exception:
                    pass

    def _handle_tcp_client(self, client_sock, addr):
        """Handle a single TCP syslog client connection."""
        buffer = ""
        try:
            while self._running:
                try:
                    data = client_sock.recv(self.max_message_size)
                    if not data:
                        break

                    buffer += data.decode("utf-8", errors="replace")

                    # Split on newlines (syslog TCP uses newline framing)
                    while "\n" in buffer:
                        line, buffer = buffer.split("\n", 1)
                        line = line.strip()
                        if line:
                            self._process_message(line, addr[0], "tcp")
                            self._stats["tcp_messages"] += 1
                            self._stats["total_messages"] += 1

                except socket.timeout:
                    continue
                except (ConnectionResetError, BrokenPipeError):
                    break

        except Exception:
            pass
        finally:
            with self._tcp_lock:
                if client_sock in self._tcp_clients:
                    self._tcp_clients.remove(client_sock)
            try:
                client_sock.close()
            except Exception:
                pass

    def _process_message(self, raw_message, sender_ip, protocol):
        """Parse a syslog message and dispatch to callback."""
        parsed = self.parse_syslog(raw_message)
        parsed["sender_ip"] = sender_ip
        parsed["protocol"] = protocol
        parsed["received_at"] = datetime.now().isoformat()

        # Map to Guardian severity
        guardian_severity = self._severity_map.get(parsed.get("severity_code", 6), "INFO")

        # Build source identifier
        hostname = parsed.get("hostname", sender_ip)
        facility = parsed.get("facility_name", "syslog")
        source = f"Syslog_{hostname}_{facility}"

        if self._message_callback:
            try:
                self._message_callback(source, guardian_severity, raw_message, parsed)
            except Exception as e:
                print(f"[SyslogReceiver] Callback error: {e}")

    def parse_syslog(self, message):
        """
        Parse a syslog message (supports RFC 3164 and RFC 5424).

        Returns:
            Dict with parsed fields: priority, facility, severity, hostname,
            timestamp, app_name, proc_id, msg_id, message, structured_data
        """
        result = {
            "raw": message,
            "priority": 13,  # default: user.notice
            "facility_code": 1,
            "facility_name": "user",
            "severity_code": 5,
            "severity_name": "notice",
            "hostname": "",
            "timestamp": "",
            "app_name": "",
            "proc_id": "",
            "msg_id": "",
            "structured_data": {},
            "message": message,
        }

        # Extract PRI (priority) field: <PRI>
        pri_match = re.match(r"<(\d{1,3})>(.*)", message)
        if not pri_match:
            self._stats["parse_errors"] += 1
            return result

        priority = int(pri_match.group(1))
        remainder = pri_match.group(2)

        result["priority"] = priority
        result["facility_code"] = priority >> 3
        result["severity_code"] = priority & 0x07
        result["facility_name"] = self._facilities.get(result["facility_code"], f"facility{result['facility_code']}")
        sev_names = {0: "emerg", 1: "alert", 2: "crit", 3: "err", 4: "warning", 5: "notice", 6: "info", 7: "debug"}
        result["severity_name"] = sev_names.get(result["severity_code"], "unknown")

        # Try RFC 5424 format: VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID
        rfc5424_match = re.match(
            r"(\d+)\s+"                               # VERSION
            r"(\d{4}-\d{2}-\d{2}T[\d:.]+(?:Z|[+-]\d{2}:\d{2})?|-)\s+"  # TIMESTAMP
            r"(\S+)\s+"                                 # HOSTNAME
            r"(\S+)\s+"                                 # APP-NAME
            r"(\S+)\s+"                                 # PROCID
            r"(\S+)\s*"                                 # MSGID
            r"(.*)",                                    # remaining (SD + MSG)
            remainder
        )

        if rfc5424_match:
            result["timestamp"] = rfc5424_match.group(2)
            result["hostname"] = rfc5424_match.group(3) if rfc5424_match.group(3) != "-" else ""
            result["app_name"] = rfc5424_match.group(4) if rfc5424_match.group(4) != "-" else ""
            result["proc_id"] = rfc5424_match.group(5) if rfc5424_match.group(5) != "-" else ""
            result["msg_id"] = rfc5424_match.group(6) if rfc5424_match.group(6) != "-" else ""

            remaining = rfc5424_match.group(7)

            # Parse structured data [ID key="value" ...]
            sd_pattern = re.compile(r'\[([^\]]+)\]')
            sd_matches = sd_pattern.findall(remaining)
            for sd in sd_matches:
                parts = sd.split(" ", 1)
                sd_id = parts[0]
                sd_params = {}
                if len(parts) > 1:
                    param_pattern = re.compile(r'(\w+)="([^"]*)"')
                    for key, val in param_pattern.findall(parts[1]):
                        sd_params[key] = val
                result["structured_data"][sd_id] = sd_params

            # Extract message after structured data
            msg_after_sd = sd_pattern.sub("", remaining).strip()
            if msg_after_sd:
                result["message"] = msg_after_sd
        else:
            # Try RFC 3164 format
            rfc3164_match = re.match(
                r"([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"  # TIMESTAMP
                r"(\S+)\s+"                                              # HOSTNAME
                r"(.*)",                                                  # MSG
                remainder
            )

            if rfc3164_match:
                result["timestamp"] = rfc3164_match.group(1)
                result["hostname"] = rfc3164_match.group(2)
                msg = rfc3164_match.group(3)

                # Extract app name from TAG: "app[PID]: message" or "app: message"
                tag_match = re.match(r"(\S+?)(?:\[(\d+)\])?:\s*(.*)", msg)
                if tag_match:
                    result["app_name"] = tag_match.group(1)
                    result["proc_id"] = tag_match.group(2) or ""
                    result["message"] = tag_match.group(3)
                else:
                    result["message"] = msg
            else:
                # Cannot parse header — treat entire remainder as message
                result["message"] = remainder

        return result

    def get_stats(self):
        """Return receiver statistics."""
        return {
            **self._stats,
            "running": self._running,
            "udp_enabled": self.udp_enabled,
            "tcp_enabled": self.tcp_enabled,
            "udp_port": self.udp_port,
            "tcp_port": self.tcp_port,
            "tcp_clients": len(self._tcp_clients),
        }


def run_standalone(event_bus_class=None):
    """Run syslog receiver standalone with event bus integration."""
    if event_bus_class is None:
        from event_bus import EventBus
        event_bus_class = EventBus

    bus = event_bus_class()
    receiver = SyslogReceiver()

    def on_message(source, severity, raw_message, parsed):
        enrichment = {
            "src_ip": parsed.get("sender_ip", ""),
            "raw_log": raw_message[:500],
        }
        bus.emit(source, severity, parsed.get("message", raw_message), enrichment=enrichment)

    receiver.set_callback(on_message)

    print("=" * 55)
    print(" 🛡️  Guardian SIEM — Syslog Receiver")
    print("=" * 55)
    receiver.start()

    try:
        while True:
            time.sleep(10)
            stats = receiver.get_stats()
            print(f"  Messages: {stats['total_messages']} "
                  f"(UDP: {stats['udp_messages']}, TCP: {stats['tcp_messages']}) "
                  f"Errors: {stats['parse_errors']}")
    except KeyboardInterrupt:
        receiver.stop()
        stats = receiver.get_stats()
        print(f"\n  Final: {stats['total_messages']} messages received")


if __name__ == "__main__":
    run_standalone()
