"""
Guardian SIEM v2.0 — YARA File Scanner
Scans files and directories against YARA rules for malware/IOC detection.
Supports:
  - Loading compiled and source YARA rules
  - Recursive directory scanning
  - File-type filtering
  - Match enrichment with MITRE ATT&CK tags
  - Results fed into the SIEM event bus
"""

import os
import hashlib
import time
import yaml
import threading
from datetime import datetime
from collections import defaultdict

try:
    import yara
    HAS_YARA = True
except ImportError:
    HAS_YARA = False


class YaraScanner:
    """YARA-based file and memory scanning engine."""

    def __init__(self, rules_dir=None, config_path=None):
        base_dir = os.path.dirname(os.path.abspath(__file__))

        if rules_dir is None:
            rules_dir = os.path.join(base_dir, "config", "yara_rules")
        if config_path is None:
            config_path = os.path.join(base_dir, "config", "config.yaml")

        self.rules_dir = rules_dir
        self.config = {}
        self._load_config(config_path)
        self._compiled_rules = None
        self._scan_results = []
        self._scan_lock = threading.Lock()
        self._stats_lock = threading.Lock()
        self._stats = {
            "files_scanned": 0,
            "matches_found": 0,
            "last_scan": None,
            "scan_errors": 0,
        }

        # Ensure rules directory exists with samples
        if not os.path.isdir(self.rules_dir):
            os.makedirs(self.rules_dir, exist_ok=True)
            self._create_sample_rules()
        else:
            # If directory exists but has no rule files, create samples
            has_rules = any(
                f.endswith((".yar", ".yara"))
                for f in os.listdir(self.rules_dir)
            )
            if not has_rules:
                self._create_sample_rules()

        self._compile_rules()

    def _load_config(self, config_path):
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                self.config = yaml.safe_load(f) or {}
        except (FileNotFoundError, yaml.YAMLError):
            self.config = {}

    def _compile_rules(self):
        """Compile all YARA rules from the rules directory."""
        if not HAS_YARA:
            print("[YaraScanner] WARNING: yara-python not installed. Install with: pip install yara-python")
            return

        rule_files = {}
        for root, dirs, files in os.walk(self.rules_dir):
            for fname in files:
                if fname.endswith((".yar", ".yara")):
                    fpath = os.path.join(root, fname)
                    namespace = os.path.splitext(fname)[0]
                    rule_files[namespace] = fpath

        if not rule_files:
            print("[YaraScanner] No YARA rule files found.")
            self._compiled_rules = None
            return

        try:
            self._compiled_rules = yara.compile(filepaths=rule_files)
            print(f"[YaraScanner] Compiled {len(rule_files)} YARA rule files")
        except yara.Error as e:
            print(f"[YaraScanner] Compilation error: {e}")
            self._compiled_rules = None

    def reload_rules(self):
        """Hot-reload YARA rules."""
        self._compile_rules()

    def scan_file(self, filepath):
        """
        Scan a single file against all loaded YARA rules.

        Args:
            filepath: Path to the file to scan

        Returns:
            List of match results, or empty list
        """
        if not HAS_YARA or self._compiled_rules is None:
            return []

        if not os.path.isfile(filepath):
            return []

        results = []
        try:
            matches = self._compiled_rules.match(filepath, timeout=30)
            with self._stats_lock:
                self._stats["files_scanned"] += 1

            for match in matches:
                # Extract metadata from YARA rule
                meta = match.meta if hasattr(match, "meta") else {}

                result = {
                    "rule_name": match.rule,
                    "namespace": match.namespace,
                    "filepath": filepath,
                    "filename": os.path.basename(filepath),
                    "file_size": os.path.getsize(filepath),
                    "file_hash": self._hash_file(filepath),
                    "tags": list(match.tags) if hasattr(match, "tags") else [],
                    "meta": meta,
                    "strings_matched": len(match.strings) if hasattr(match, "strings") else 0,
                    "severity": meta.get("severity", "HIGH"),
                    "mitre_id": meta.get("mitre_id", ""),
                    "mitre_tactic": meta.get("mitre_tactic", ""),
                    "description": meta.get("description", f"YARA match: {match.rule}"),
                    "scanned_at": datetime.now().isoformat(),
                }
                results.append(result)
                with self._stats_lock:
                    self._stats["matches_found"] += 1

        except yara.TimeoutError:
            with self._stats_lock:
                self._stats["scan_errors"] += 1
        except yara.Error as e:
            with self._stats_lock:
                self._stats["scan_errors"] += 1
        except Exception as e:
            with self._stats_lock:
                self._stats["scan_errors"] += 1

        return results

    def scan_data(self, data, identifier="memory"):
        """
        Scan raw bytes/data against YARA rules (memory scanning).

        Args:
            data: Bytes to scan
            identifier: Label for the data source

        Returns:
            List of match results
        """
        if not HAS_YARA or self._compiled_rules is None:
            return []

        results = []
        try:
            matches = self._compiled_rules.match(data=data, timeout=30)
            for match in matches:
                meta = match.meta if hasattr(match, "meta") else {}
                result = {
                    "rule_name": match.rule,
                    "namespace": match.namespace,
                    "filepath": identifier,
                    "filename": identifier,
                    "file_size": len(data),
                    "file_hash": hashlib.sha256(data).hexdigest(),
                    "tags": list(match.tags) if hasattr(match, "tags") else [],
                    "meta": meta,
                    "strings_matched": len(match.strings) if hasattr(match, "strings") else 0,
                    "severity": meta.get("severity", "HIGH"),
                    "mitre_id": meta.get("mitre_id", ""),
                    "description": meta.get("description", f"YARA match: {match.rule}"),
                    "scanned_at": datetime.now().isoformat(),
                }
                results.append(result)
        except Exception:
            pass

        return results

    def scan_directory(self, directory, recursive=True, extensions=None):
        """
        Scan all files in a directory.

        Args:
            directory: Path to directory
            recursive: Whether to scan subdirectories
            extensions: Optional list of file extensions to scan (e.g. ['.exe', '.dll'])

        Returns:
            List of all match results
        """
        if not os.path.isdir(directory):
            return []

        all_results = []

        if recursive:
            walker = os.walk(directory)
        else:
            try:
                entries = os.listdir(directory)
                walker = [(directory, [], [e for e in entries if os.path.isfile(os.path.join(directory, e))])]
            except OSError:
                return []

        for root, dirs, files in walker:
            for fname in files:
                # Filter by extension
                if extensions:
                    ext = os.path.splitext(fname)[1].lower()
                    if ext not in extensions:
                        continue

                filepath = os.path.join(root, fname)

                # Skip very large files (configurable)
                yara_config = self.config.get("yara", {})
                max_size_mb = yara_config.get("max_file_size_mb", 50)
                try:
                    if os.path.getsize(filepath) > max_size_mb * 1024 * 1024:
                        continue
                except OSError:
                    continue

                results = self.scan_file(filepath)
                all_results.extend(results)

        with self._stats_lock:
            self._stats["last_scan"] = datetime.now().isoformat()

        with self._scan_lock:
            self._scan_results.extend(all_results)

        return all_results

    def get_recent_results(self, limit=50):
        """Return recent scan results for dashboard."""
        with self._scan_lock:
            return self._scan_results[-limit:]

    def get_stats(self):
        """Return scanning statistics."""
        with self._stats_lock:
            stats_copy = dict(self._stats)
        return {
            **stats_copy,
            "yara_available": HAS_YARA,
            "rules_compiled": self._compiled_rules is not None,
            "rules_directory": self.rules_dir,
        }

    @staticmethod
    def _hash_file(filepath, algo="sha256"):
        """Compute hash of a file."""
        h = hashlib.new(algo)
        try:
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    h.update(chunk)
            return h.hexdigest()
        except (IOError, OSError):
            return ""

    def _create_sample_rules(self):
        """Create sample YARA rules for common threat detection."""

        rules_content = r"""
/*
    Guardian SIEM — Sample YARA Rules
    Detects common malicious patterns in files.
*/

rule Suspicious_PowerShell_Script
{
    meta:
        description = "Detects PowerShell scripts with suspicious download/execution patterns"
        severity = "HIGH"
        mitre_id = "T1059.001"
        mitre_tactic = "Execution"
        author = "Guardian SIEM"

    strings:
        $ps1 = "Invoke-Expression" ascii nocase
        $ps2 = "IEX(" ascii nocase
        $ps3 = "DownloadString" ascii nocase
        $ps4 = "Net.WebClient" ascii nocase
        $ps5 = "-EncodedCommand" ascii nocase
        $ps6 = "FromBase64String" ascii nocase
        $ps7 = "Invoke-Mimikatz" ascii nocase

    condition:
        2 of ($ps*)
}

rule Webshell_Generic
{
    meta:
        description = "Detects generic webshell patterns"
        severity = "CRITICAL"
        mitre_id = "T1505.003"
        mitre_tactic = "Persistence"
        author = "Guardian SIEM"

    strings:
        $php1 = "eval($_" ascii nocase
        $php2 = "system($_" ascii nocase
        $php3 = "passthru(" ascii nocase
        $php4 = "shell_exec(" ascii nocase
        $asp1 = "eval(Request" ascii nocase
        $asp2 = "Execute(Request" ascii nocase
        $jsp1 = "Runtime.getRuntime().exec" ascii

    condition:
        any of them
}

rule Mimikatz_Strings
{
    meta:
        description = "Detects Mimikatz password dumping tool strings"
        severity = "CRITICAL"
        mitre_id = "T1003"
        mitre_tactic = "Credential Access"
        author = "Guardian SIEM"

    strings:
        $a1 = "sekurlsa::" ascii
        $a2 = "kerberos::" ascii
        $a3 = "lsadump::" ascii
        $a4 = "gentilkiwi" ascii
        $a5 = "mimikatz" ascii nocase

    condition:
        2 of ($a*)
}

rule Ransomware_Note_Patterns
{
    meta:
        description = "Detects common ransomware note text patterns"
        severity = "CRITICAL"
        mitre_id = "T1486"
        mitre_tactic = "Impact"
        author = "Guardian SIEM"

    strings:
        $r1 = "your files have been encrypted" ascii nocase
        $r2 = "bitcoin wallet" ascii nocase
        $r3 = "pay the ransom" ascii nocase
        $r4 = "decrypt your files" ascii nocase
        $r5 = ".onion" ascii

    condition:
        2 of ($r*)
}

rule Suspicious_PE_Packer
{
    meta:
        description = "Detects PE files that may be packed or obfuscated"
        severity = "MEDIUM"
        mitre_id = "T1027.002"
        mitre_tactic = "Defense Evasion"
        author = "Guardian SIEM"

    strings:
        $mz = { 4D 5A }
        $upx = "UPX!" ascii
        $aspack = "aPLib" ascii
        $themida = ".themida" ascii

    condition:
        $mz at 0 and any of ($upx, $aspack, $themida)
}
"""
        filepath = os.path.join(self.rules_dir, "guardian_default.yar")
        with open(filepath, "w") as f:
            f.write(rules_content.strip())
        print(f"[YaraScanner] Created sample rules at {filepath}")
