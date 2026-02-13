"""
Guardian SIEM v2.0 — Log Ingestor
Ingests logs from multiple sources:
  - Windows Event Logs (Security, System, Application)
  - Sysmon operational logs
  - Generic file-based logs (Apache, Nginx, custom)
Normalizes all events and feeds them into the Event Bus.
"""

import os
import re
import time
import glob
import yaml
import platform
from datetime import datetime, timedelta
from event_bus import EventBus

# Windows-only imports (graceful fallback)
try:
    import win32evtlog
    import win32evtlogutil
    HAS_WIN32 = True
except ImportError:
    HAS_WIN32 = False


class LogIngestor:
    """Multi-source log ingestion engine."""

    def __init__(self, config_path=None):
        base_dir = os.path.dirname(os.path.abspath(__file__))
        if config_path is None:
            config_path = os.path.join(base_dir, "config", "config.yaml")

        self.config = {}
        self._load_config(config_path)
        self.bus = EventBus()
        self._file_positions = {}  # Track file read positions for tailing
        self._last_event_times = {}  # Track last event time per source

    def _load_config(self, config_path):
        try:
            with open(config_path, "r") as f:
                self.config = yaml.safe_load(f) or {}
        except (FileNotFoundError, yaml.YAMLError) as e:
            print(f"[LogIngestor] Config error: {e}")
            self.config = {}

    # ---------------------------------------------------------------
    # Windows Event Log Ingestion
    # ---------------------------------------------------------------

    def ingest_windows_events(self):
        """Read recent Windows Event Log entries."""
        if not HAS_WIN32:
            print("[LogIngestor] pywin32 not installed — skipping Windows Event Log ingestion")
            return []

        if platform.system() != "Windows":
            return []

        ingestion_config = self.config.get("log_ingestion", {}).get("sources", {})
        win_config = ingestion_config.get("windows_event_log", {})

        if not win_config.get("enabled", False):
            return []

        log_names = win_config.get("log_names", ["Security", "System"])
        target_event_ids = set(win_config.get("event_ids", []))
        events_collected = []

        for log_name in log_names:
            try:
                events = self._read_windows_log(log_name, target_event_ids)
                events_collected.extend(events)
            except Exception as e:
                print(f"[LogIngestor] Error reading {log_name} log: {e}")

        return events_collected

    def _read_windows_log(self, log_name, target_event_ids, max_events=100):
        """Read events from a specific Windows Event Log."""
        events = []
        server = None  # Local machine

        try:
            handle = win32evtlog.OpenEventLog(server, log_name)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

            # Track position to avoid re-reading
            last_time_key = f"win_{log_name}"
            last_time = self._last_event_times.get(last_time_key, datetime.now() - timedelta(minutes=5))

            count = 0
            while count < max_events:
                records = win32evtlog.ReadEventLog(handle, flags, 0)
                if not records:
                    break
                for record in records:
                    event_time = record.TimeGenerated
                    if event_time <= last_time:
                        count = max_events  # Stop reading
                        break

                    event_id = record.EventID & 0xFFFF  # Mask to get actual ID

                    # Filter by target event IDs if specified
                    if target_event_ids and event_id not in target_event_ids:
                        continue

                    # Severity mapping from Windows event types
                    severity_map = {
                        1: "CRITICAL",  # Error
                        2: "HIGH",      # Warning
                        4: "INFO",      # Information
                        8: "INFO",      # Audit Success
                        16: "HIGH",     # Audit Failure
                    }
                    severity = severity_map.get(record.EventType, "INFO")

                    # Build message
                    try:
                        msg = win32evtlogutil.SafeFormatMessage(record, log_name)
                    except Exception:
                        msg = f"Event {event_id}"

                    message = f"Event {event_id}: {msg[:500]}"
                    source = f"Windows_{log_name}"

                    # Emit to event bus
                    self.bus.emit(source, severity, message)
                    events.append({
                        "timestamp": event_time.isoformat(),
                        "source": source,
                        "severity": severity,
                        "event_id": event_id,
                        "message": message,
                    })
                    count += 1

            # Update last read time
            if events:
                self._last_event_times[last_time_key] = datetime.now()

            win32evtlog.CloseEventLog(handle)
        except Exception as e:
            print(f"[LogIngestor] Windows log '{log_name}' error: {e}")

        if events:
            print(f"[LogIngestor] Collected {len(events)} events from Windows/{log_name}")
        return events

    # ---------------------------------------------------------------
    # File-Based Log Ingestion (Apache, Nginx, Custom)
    # ---------------------------------------------------------------

    def ingest_file_logs(self):
        """Tail and parse file-based logs."""
        ingestion_config = self.config.get("log_ingestion", {})
        sources_config = ingestion_config.get("sources", {}).get("file_logs", {})

        if not sources_config.get("enabled", False):
            return []

        watch_paths = ingestion_config.get("watch_paths", ["service_logs/"])
        patterns = sources_config.get("patterns", ["*.log"])
        events_collected = []
        base_dir = os.path.dirname(os.path.abspath(__file__))

        for watch_dir in watch_paths:
            full_dir = os.path.join(base_dir, watch_dir)
            if not os.path.exists(full_dir):
                continue

            for pattern in patterns:
                for filepath in glob.glob(os.path.join(full_dir, pattern)):
                    try:
                        new_lines = self._tail_file(filepath)
                        for line in new_lines:
                            parsed = self._parse_log_line(line, filepath)
                            if parsed:
                                self.bus.emit(parsed["source"], parsed["severity"], parsed["message"])
                                events_collected.append(parsed)
                    except Exception as e:
                        print(f"[LogIngestor] Error reading {filepath}: {e}")

        if events_collected:
            print(f"[LogIngestor] Collected {len(events_collected)} events from file logs")
        return events_collected

    def _tail_file(self, filepath):
        """Read new lines from a file since last check (file tailing)."""
        last_pos = self._file_positions.get(filepath, 0)
        new_lines = []

        try:
            file_size = os.path.getsize(filepath)

            # File was truncated/rotated — start from beginning
            if file_size < last_pos:
                last_pos = 0

            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                f.seek(last_pos)
                for line in f:
                    stripped = line.strip()
                    if stripped:
                        new_lines.append(stripped)
                self._file_positions[filepath] = f.tell()
        except Exception as e:
            print(f"[LogIngestor] Tail error {filepath}: {e}")

        return new_lines

    def _parse_log_line(self, line, filepath):
        """
        Parse a log line and extract severity/source/message.
        Supports common log formats: Apache, Nginx, syslog, generic.
        """
        filename = os.path.basename(filepath)
        source = f"FileLog_{filename}"

        # Severity detection via keywords
        severity = "INFO"
        severity_patterns = {
            "CRITICAL": r"(critical|fatal|emergency|panic)",
            "HIGH": r"(error|fail|denied|unauthorized|alert)",
            "MEDIUM": r"(warn|warning|suspect|unusual)",
            "LOW": r"(notice|info)",
        }
        for sev, pattern in severity_patterns.items():
            if re.search(pattern, line, re.IGNORECASE):
                severity = sev
                break

        # Extract IP addresses for enrichment
        ip_match = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', line)
        ip_info = f" [IP: {ip_match.group(1)}]" if ip_match else ""

        return {
            "timestamp": datetime.now().isoformat(),
            "source": source,
            "severity": severity,
            "message": f"{line[:500]}{ip_info}",
        }

    # ---------------------------------------------------------------
    # Continuous Ingestion Loop
    # ---------------------------------------------------------------

    def run(self, interval=None):
        """
        Run continuous log ingestion loop.

        Args:
            interval: Poll interval in seconds (from config or default 5)
        """
        if interval is None:
            interval = self.config.get("log_ingestion", {}).get("poll_interval_seconds", 5)

        print(f"[LogIngestor] Starting continuous ingestion (interval: {interval}s)")
        print(f"[LogIngestor] Windows Event Logs: {'enabled' if HAS_WIN32 else 'disabled (pywin32 not available)'}")
        print(f"[LogIngestor] File-based logs: scanning service_logs/")

        try:
            while True:
                self.ingest_windows_events()
                self.ingest_file_logs()
                time.sleep(interval)
        except KeyboardInterrupt:
            print("\n[LogIngestor] Stopped")


if __name__ == "__main__":
    ingestor = LogIngestor()
    print("\n--- One-shot ingestion test ---")
    win_events = ingestor.ingest_windows_events()
    print(f"Windows events collected: {len(win_events)}")
    file_events = ingestor.ingest_file_logs()
    print(f"File log events collected: {len(file_events)}")
    print("\nStarting continuous ingestion (Ctrl+C to stop)...")
    ingestor.run()
