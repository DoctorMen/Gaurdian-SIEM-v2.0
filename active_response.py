"""
Guardian SIEM v2.0 — Active Response Module
Automated threat response actions triggered by high-severity alerts:
  - Windows Firewall IP blocking (netsh / PowerShell)
  - IP quarantine list management
  - Cooldown and whitelist protections
  - Dry-run mode for safe testing
  - Audit trail of all response actions

WARNING: This module modifies firewall rules. Use with caution.
Dry-run mode is enabled by default — no changes are made until
active_response.enabled = true AND active_response.dry_run = false
in config.yaml.
"""

import os
import subprocess
import time
import json
import yaml
import threading
import ipaddress
from datetime import datetime, timedelta
from collections import defaultdict


class ActiveResponse:
    """Automated threat response — blocks malicious IPs via host firewall."""

    def __init__(self, config_path=None):
        base_dir = os.path.dirname(os.path.abspath(__file__))
        if config_path is None:
            config_path = os.path.join(base_dir, "config", "config.yaml")

        self.config = {}
        self._load_config(config_path)

        ar_config = self.config.get("active_response", {})
        self.enabled = ar_config.get("enabled", False)
        self.dry_run = ar_config.get("dry_run", True)
        self.auto_block = ar_config.get("auto_block", False)
        self.block_duration_minutes = ar_config.get("block_duration_minutes", 60)
        self.severity_threshold = ar_config.get("severity_threshold", "HIGH")
        self.max_blocks_per_hour = ar_config.get("max_blocks_per_hour", 20)

        # Whitelisted IPs/subnets that should NEVER be blocked
        self.whitelist = set(ar_config.get("whitelist", [
            "127.0.0.1",
            "::1",
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
        ]))

        # State tracking
        self._blocked_ips = {}  # ip -> {"blocked_at", "expires_at", "reason", "rule_name"}
        self._action_log = []  # Audit trail
        self._block_count_window = []  # Rate limiting: timestamps of recent blocks
        self._lock = threading.Lock()

        # Rule name prefix for firewall entries
        self._fw_prefix = "Guardian_SIEM_Block_"

        self._severity_order = {
            "CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0
        }

        if self.enabled:
            mode = "DRY RUN" if self.dry_run else "LIVE"
            print(f"[ActiveResponse] Module active ({mode})")
            print(f"  Threshold: {self.severity_threshold}+  |  Auto-block: {self.auto_block}")
            print(f"  Block duration: {self.block_duration_minutes}m  |  Max/hr: {self.max_blocks_per_hour}")
        else:
            print("[ActiveResponse] Module disabled (enable in config.yaml)")

    def _load_config(self, config_path):
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                self.config = yaml.safe_load(f) or {}
        except (FileNotFoundError, yaml.YAMLError):
            self.config = {}

    def respond(self, alert_data):
        """
        Evaluate an alert and take response action if warranted.

        Args:
            alert_data: Dict with keys: severity, src_ip, rule_name, mitre_id, etc.

        Returns:
            Dict with action taken and details, or None if no action.
        """
        if not self.enabled:
            return None

        severity = alert_data.get("severity", "MEDIUM")
        src_ip = alert_data.get("src_ip", "")
        rule_name = alert_data.get("rule_name", "Unknown")

        # Check severity threshold
        if self._severity_order.get(severity, 0) < self._severity_order.get(self.severity_threshold, 3):
            return None

        # Must have an IP to block
        if not src_ip:
            return None

        # Check whitelist
        if self._is_whitelisted(src_ip):
            self._log_action("skipped_whitelist", src_ip, rule_name,
                           f"IP {src_ip} is whitelisted")
            return {"action": "skipped", "reason": "whitelisted", "ip": src_ip}

        # Check if already blocked
        with self._lock:
            if src_ip in self._blocked_ips:
                return {"action": "already_blocked", "ip": src_ip}

        # Check rate limit
        if not self._check_rate_limit():
            self._log_action("skipped_rate_limit", src_ip, rule_name,
                           "Block rate limit exceeded")
            return {"action": "skipped", "reason": "rate_limit_exceeded", "ip": src_ip}

        # Execute block
        if self.auto_block:
            return self.block_ip(src_ip, rule_name, severity)
        else:
            self._log_action("recommended", src_ip, rule_name,
                           f"Block recommended for {src_ip} (auto_block disabled)")
            return {"action": "recommended", "ip": src_ip, "rule_name": rule_name}

    def block_ip(self, ip, reason="Manual block", severity="HIGH"):
        """
        Block an IP address via Windows Firewall.

        Args:
            ip: IP address to block
            reason: Reason for blocking
            severity: Alert severity that triggered the block

        Returns:
            Dict with action result
        """
        # Safety checks
        if self._is_whitelisted(ip):
            return {"action": "rejected", "reason": "whitelisted", "ip": ip}

        with self._lock:
            if ip in self._blocked_ips:
                return {"action": "already_blocked", "ip": ip}

        now = datetime.now()
        expires = now + timedelta(minutes=self.block_duration_minutes)
        rule_name = f"{self._fw_prefix}{ip.replace('.', '_')}"

        if self.dry_run:
            self._log_action("blocked_dryrun", ip, reason,
                           f"[DRY RUN] Would block {ip} for {self.block_duration_minutes}m")
            with self._lock:
                self._blocked_ips[ip] = {
                    "blocked_at": now.isoformat(),
                    "expires_at": expires.isoformat(),
                    "reason": reason,
                    "severity": severity,
                    "dry_run": True,
                }
            return {"action": "blocked_dryrun", "ip": ip, "expires": expires.isoformat()}

        # LIVE MODE — actually create firewall rule
        success = self._create_firewall_rule(ip, rule_name)

        if success:
            with self._lock:
                self._blocked_ips[ip] = {
                    "blocked_at": now.isoformat(),
                    "expires_at": expires.isoformat(),
                    "reason": reason,
                    "severity": severity,
                    "firewall_rule": rule_name,
                    "dry_run": False,
                }
                self._block_count_window.append(time.time())

            self._log_action("blocked", ip, reason,
                           f"Blocked {ip} via firewall rule '{rule_name}', expires {expires.isoformat()}")
            return {"action": "blocked", "ip": ip, "rule_name": rule_name, "expires": expires.isoformat()}
        else:
            self._log_action("block_failed", ip, reason, f"Failed to create firewall rule for {ip}")
            return {"action": "failed", "ip": ip, "error": "Firewall rule creation failed"}

    def unblock_ip(self, ip):
        """
        Remove a firewall block for an IP address.

        Returns:
            Dict with action result
        """
        with self._lock:
            block_info = self._blocked_ips.pop(ip, None)

        if not block_info:
            return {"action": "not_found", "ip": ip}

        if block_info.get("dry_run", True):
            self._log_action("unblocked_dryrun", ip, "", "[DRY RUN] Removed block")
            return {"action": "unblocked_dryrun", "ip": ip}

        rule_name = block_info.get("firewall_rule", f"{self._fw_prefix}{ip.replace('.', '_')}")
        success = self._remove_firewall_rule(rule_name)

        if success:
            self._log_action("unblocked", ip, "", f"Removed firewall rule '{rule_name}'")
            return {"action": "unblocked", "ip": ip}
        else:
            self._log_action("unblock_failed", ip, "", f"Failed to remove rule '{rule_name}'")
            return {"action": "failed", "ip": ip}

    def cleanup_expired(self):
        """Remove expired firewall blocks. Should be called periodically."""
        now = datetime.now()
        expired = []

        with self._lock:
            for ip, info in self._blocked_ips.items():
                exp_str = info.get("expires_at", "")
                if exp_str:
                    try:
                        exp_time = datetime.fromisoformat(exp_str)
                        if now > exp_time:
                            expired.append(ip)
                    except ValueError:
                        pass

        results = []
        for ip in expired:
            result = self.unblock_ip(ip)
            results.append(result)

        return results

    def get_blocked_ips(self):
        """Return list of currently blocked IPs."""
        with self._lock:
            return dict(self._blocked_ips)

    def get_action_log(self, limit=100):
        """Return recent action log entries."""
        return self._action_log[-limit:]

    def get_stats(self):
        """Return module statistics."""
        with self._lock:
            return {
                "enabled": self.enabled,
                "dry_run": self.dry_run,
                "auto_block": self.auto_block,
                "blocked_count": len(self._blocked_ips),
                "total_actions": len(self._action_log),
                "severity_threshold": self.severity_threshold,
                "block_duration_minutes": self.block_duration_minutes,
                "whitelist_count": len(self.whitelist),
            }

    def _is_whitelisted(self, ip):
        """Check if an IP is in the whitelist (supports CIDR notation)."""
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            return True  # Invalid IPs are "whitelisted" (can't block them)

        for entry in self.whitelist:
            try:
                if "/" in entry:
                    network = ipaddress.ip_network(entry, strict=False)
                    if ip_obj in network:
                        return True
                else:
                    if ip_obj == ipaddress.ip_address(entry):
                        return True
            except ValueError:
                continue

        return False

    def _check_rate_limit(self):
        """Ensure we haven't exceeded max blocks per hour."""
        now = time.time()
        one_hour_ago = now - 3600
        self._block_count_window = [t for t in self._block_count_window if t > one_hour_ago]
        return len(self._block_count_window) < self.max_blocks_per_hour

    def _create_firewall_rule(self, ip, rule_name):
        """Create a Windows Firewall inbound block rule."""
        try:
            # Use netsh to create an inbound block rule
            cmd = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}",
                "dir=in",
                "action=block",
                f"remoteip={ip}",
                "enable=yes",
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            return result.returncode == 0
        except (subprocess.SubprocessError, OSError) as e:
            print(f"[ActiveResponse] Firewall error: {e}")
            return False

    def _remove_firewall_rule(self, rule_name):
        """Remove a Windows Firewall rule by name."""
        try:
            cmd = [
                "netsh", "advfirewall", "firewall", "delete", "rule",
                f"name={rule_name}",
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            return result.returncode == 0
        except (subprocess.SubprocessError, OSError) as e:
            print(f"[ActiveResponse] Firewall error: {e}")
            return False

    def _log_action(self, action_type, ip, rule_name, details):
        """Record an action in the audit trail."""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "action": action_type,
            "ip": ip,
            "rule_name": rule_name,
            "details": details,
        }
        self._action_log.append(entry)

        # Keep log bounded
        if len(self._action_log) > 10000:
            self._action_log = self._action_log[-5000:]
