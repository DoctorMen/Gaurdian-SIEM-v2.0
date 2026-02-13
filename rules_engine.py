"""
Guardian SIEM v2.0 — Rules Engine
Evaluates incoming events against configurable YAML-based detection rules.
Supports regex pattern matching, threshold counting, and sliding windows.
"""

import re
import os
import time
import yaml
from collections import defaultdict
from datetime import datetime


class RulesEngine:
    """Evaluates security events against a set of detection rules."""

    def __init__(self, rules_path=None):
        if rules_path is None:
            base_dir = os.path.dirname(os.path.abspath(__file__))
            rules_path = os.path.join(base_dir, "config", "alert_rules.yaml")
        self.rules_path = rules_path
        self.rules = []
        self._hit_tracker = defaultdict(list)  # rule_name -> list of timestamps
        self.load_rules()

    def load_rules(self):
        """Load and parse detection rules from YAML file."""
        try:
            with open(self.rules_path, "r") as f:
                data = yaml.safe_load(f)
            self.rules = [r for r in data.get("rules", []) if r.get("enabled", True)]
            print(f"[RulesEngine] Loaded {len(self.rules)} active rules")
        except FileNotFoundError:
            print(f"[RulesEngine] WARNING: Rules file not found: {self.rules_path}")
            self.rules = []
        except yaml.YAMLError as e:
            print(f"[RulesEngine] ERROR: Failed to parse rules YAML: {e}")
            self.rules = []

    def reload_rules(self):
        """Hot-reload rules without restarting the engine."""
        self.load_rules()
        self._hit_tracker.clear()

    def evaluate(self, source, message):
        """
        Evaluate an event against all active rules.

        Args:
            source: Event source (e.g., 'Network_IPS', 'Windows_EventLog')
            message: Event message text to match against

        Returns:
            List of matched rules with metadata, empty if no matches
        """
        matches = []
        now = time.time()

        for rule in self.rules:
            # Check if source matches (supports regex)
            source_pattern = rule.get("source", ".*")
            if not re.search(source_pattern, source, re.IGNORECASE):
                continue

            # Check if message matches the detection pattern
            pattern = rule.get("pattern", "")
            if not re.search(pattern, message, re.IGNORECASE):
                continue

            # Threshold / sliding window logic
            rule_name = rule["name"]
            threshold = rule.get("threshold", 1)
            window = rule.get("window_seconds", 60)

            # Record this hit
            self._hit_tracker[rule_name].append(now)

            # Prune old hits outside the window
            self._hit_tracker[rule_name] = [
                t for t in self._hit_tracker[rule_name] if now - t <= window
            ]

            hit_count = len(self._hit_tracker[rule_name])

            if hit_count >= threshold:
                matches.append({
                    "rule_name": rule["name"],
                    "description": rule.get("description", ""),
                    "severity": rule.get("severity", "MEDIUM"),
                    "mitre_id": rule.get("mitre_id", ""),
                    "mitre_tactic": rule.get("mitre_tactic", ""),
                    "hit_count": hit_count,
                    "threshold": threshold,
                    "window_seconds": window,
                    "matched_at": datetime.now().isoformat(),
                    "source": source,
                    "message_excerpt": message[:200],
                })
                # Reset counter after alert fires to prevent spam
                self._hit_tracker[rule_name] = []

        return matches

    def get_stats(self):
        """Return current rule hit counters for dashboard display."""
        return {
            rule_name: len(timestamps)
            for rule_name, timestamps in self._hit_tracker.items()
        }

    def get_rules_summary(self):
        """Return a summary of all loaded rules."""
        return [
            {
                "name": r["name"],
                "severity": r.get("severity", "MEDIUM"),
                "mitre_id": r.get("mitre_id", ""),
                "enabled": r.get("enabled", True),
                "description": r.get("description", ""),
            }
            for r in self.rules
        ]


if __name__ == "__main__":
    engine = RulesEngine()
    print(f"\n--- Loaded Rules ---")
    for r in engine.get_rules_summary():
        print(f"  [{r['severity']}] {r['name']} ({r['mitre_id']})")

    # Test evaluation
    print("\n--- Test Evaluations ---")
    test_events = [
        ("Windows_EventLog", "Event 4625: Failed login for user admin from 192.168.1.100"),
        ("Network_IPS", "High traffic detected from 10.0.0.5"),
        ("System", "Event 1102: The audit log was cleared"),
        ("Network_IPS", "Port scan detected from 172.16.0.50"),
        ("FileMonitor", "mimikatz.exe detected in C:\\temp"),
    ]
    for source, msg in test_events:
        results = engine.evaluate(source, msg)
        if results:
            for m in results:
                print(f"  ALERT [{m['severity']}] {m['rule_name']} — {m['mitre_id']}")
        else:
            print(f"  No match: {msg[:60]}")
