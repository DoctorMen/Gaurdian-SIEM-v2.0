"""
Guardian SIEM v2.0 — SIGMA Rule Engine
Loads and evaluates SIGMA-format detection rules alongside native YAML rules.
Supports a practical subset of the SIGMA specification:
  - logsource filtering (product, category, service)
  - detection with selection/filter/condition (keywords, field mappings)
  - AND/OR/NOT logic via condition expressions
  - severity/level mapping to Guardian severity scale

Reference: https://sigmahq.io/docs/specification.html
"""

import os
import re
import yaml
import glob
from datetime import datetime
from collections import defaultdict


class SigmaRule:
    """Parsed representation of a single SIGMA rule."""

    def __init__(self, data, filepath=""):
        self.raw = data
        self.filepath = filepath
        self.title = data.get("title", "Untitled")
        self.id = data.get("id", "")
        self.status = data.get("status", "experimental")
        self.description = data.get("description", "")
        self.author = data.get("author", "")
        self.date = data.get("date", "")
        self.references = data.get("references", [])
        self.tags = data.get("tags", [])
        self.enabled = True

        # Log source filtering
        logsource = data.get("logsource", {})
        self.product = logsource.get("product", "")
        self.category = logsource.get("category", "")
        self.service = logsource.get("service", "")

        # Detection logic
        self.detection = data.get("detection", {})
        self.condition = self.detection.get("condition", "selection")

        # Severity mapping: SIGMA level → Guardian severity
        level = data.get("level", "medium").lower()
        self.severity = {
            "critical": "CRITICAL",
            "high": "HIGH",
            "medium": "MEDIUM",
            "low": "LOW",
            "informational": "INFO",
        }.get(level, "MEDIUM")

        # MITRE ATT&CK from tags
        self.mitre_id = ""
        self.mitre_tactic = ""
        for tag in self.tags:
            if tag.startswith("attack.t"):
                self.mitre_id = tag.replace("attack.", "").upper()
            elif tag.startswith("attack.") and not tag[7:].startswith("t"):
                self.mitre_tactic = tag.replace("attack.", "").replace("_", " ").title()

        # Compile detection selections
        self._compiled_selections = {}
        self._compile_detection()

    def _compile_detection(self):
        """Pre-compile detection selections into matcher functions."""
        for key, value in self.detection.items():
            if key == "condition":
                continue

            if isinstance(value, dict):
                # Field-based selection: {field: value} or {field: [values]}
                self._compiled_selections[key] = ("fields", self._compile_field_selection(value))
            elif isinstance(value, list):
                # Keyword list: any string in the list matches
                self._compiled_selections[key] = ("keywords", self._compile_keyword_selection(value))
            elif isinstance(value, str):
                # Single keyword
                self._compiled_selections[key] = ("keywords", self._compile_keyword_selection([value]))

    def _compile_field_selection(self, field_map):
        """Compile field-based selection into regex matchers."""
        compiled = {}
        for field, values in field_map.items():
            if not isinstance(values, list):
                values = [values]

            # Handle SIGMA modifiers in field name
            field_name = field
            modifiers = []
            if "|" in field:
                parts = field.split("|")
                field_name = parts[0]
                modifiers = parts[1:]

            patterns = []
            for v in values:
                if v is None:
                    continue
                v_str = str(v)
                # Convert SIGMA wildcards to regex
                regex_str = self._sigma_to_regex(v_str, modifiers)
                try:
                    patterns.append(re.compile(regex_str, re.IGNORECASE))
                except re.error:
                    patterns.append(re.compile(re.escape(v_str), re.IGNORECASE))

            compiled[field_name] = (modifiers, patterns)
        return compiled

    def _compile_keyword_selection(self, keywords):
        """Compile keyword list into regex patterns.
        
        Keywords in SIGMA are substring matches against the full log message,
        so we compile them without anchors (contains behavior).
        """
        patterns = []
        for kw in keywords:
            if kw is None:
                continue
            kw_str = str(kw)
            # Keywords use contains-style matching (no ^ or $ anchors)
            regex_str = self._sigma_to_regex(kw_str, ["contains"])
            try:
                patterns.append(re.compile(regex_str, re.IGNORECASE))
            except re.error:
                patterns.append(re.compile(re.escape(kw_str), re.IGNORECASE))
        return patterns

    @staticmethod
    def _sigma_to_regex(value, modifiers):
        """Convert SIGMA wildcard pattern to regex."""
        if "re" in modifiers:
            return value

        # Escape regex special chars except * and ?
        escaped = ""
        for ch in value:
            if ch == "*":
                escaped += ".*"
            elif ch == "?":
                escaped += "."
            elif ch in r"\.+^${}()|[]":
                escaped += "\\" + ch
            else:
                escaped += ch

        if "contains" in modifiers:
            return escaped
        elif "startswith" in modifiers:
            return f"^{escaped}"
        elif "endswith" in modifiers:
            return f"{escaped}$"
        elif "base64" in modifiers:
            return escaped  # Simplified — full base64 decode not implemented
        else:
            return f"^{escaped}$"


class SigmaEngine:
    """Loads and evaluates SIGMA-format detection rules."""

    def __init__(self, rules_dir=None):
        if rules_dir is None:
            base_dir = os.path.dirname(os.path.abspath(__file__))
            rules_dir = os.path.join(base_dir, "config", "sigma_rules")

        self.rules_dir = rules_dir
        self.rules = []
        self._hit_tracker = defaultdict(list)
        self.load_rules()

    def load_rules(self):
        """Load all SIGMA YAML rules from the rules directory."""
        self.rules = []
        if not os.path.isdir(self.rules_dir):
            os.makedirs(self.rules_dir, exist_ok=True)
            self._create_sample_rules()
        else:
            # If directory exists but has no .yml files, create samples
            yml_files = glob.glob(os.path.join(self.rules_dir, "**", "*.yml"), recursive=True)
            if not yml_files:
                self._create_sample_rules()

        for filepath in glob.glob(os.path.join(self.rules_dir, "**", "*.yml"), recursive=True):
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    # Handle multi-document YAML files
                    for doc in yaml.safe_load_all(f):
                        if doc and isinstance(doc, dict) and "detection" in doc:
                            rule = SigmaRule(doc, filepath)
                            if rule.enabled:
                                self.rules.append(rule)
            except Exception as e:
                print(f"[SigmaEngine] Error loading {filepath}: {e}")

        print(f"[SigmaEngine] Loaded {len(self.rules)} SIGMA rules from {self.rules_dir}")

    def reload_rules(self):
        """Hot-reload SIGMA rules."""
        self.load_rules()
        self._hit_tracker.clear()

    def evaluate(self, event_data):
        """
        Evaluate an event against all loaded SIGMA rules.

        Args:
            event_data: Dict with keys like 'source', 'message', 'severity',
                       plus any extracted fields (e.g., 'EventID', 'Image', 'CommandLine')

        Returns:
            List of matched SigmaRule results with metadata
        """
        matches = []

        for rule in self.rules:
            # Check logsource filter
            if not self._check_logsource(rule, event_data):
                continue

            # Evaluate detection logic
            if self._evaluate_condition(rule, event_data):
                matches.append({
                    "rule_name": rule.title,
                    "sigma_id": rule.id,
                    "description": rule.description,
                    "severity": rule.severity,
                    "mitre_id": rule.mitre_id,
                    "mitre_tactic": rule.mitre_tactic,
                    "tags": rule.tags,
                    "author": rule.author,
                    "references": rule.references,
                    "matched_at": datetime.now().isoformat(),
                    "source": event_data.get("source", ""),
                    "message_excerpt": str(event_data.get("message", ""))[:200],
                })

        return matches

    def _check_logsource(self, rule, event_data):
        """Check if event matches the rule's logsource filter."""
        source = event_data.get("source", "").lower()
        product = event_data.get("product", "").lower()
        category = event_data.get("category", "").lower()

        if rule.product and rule.product.lower() not in (source, product):
            # Be lenient — if product is 'windows', match sources containing 'windows'
            if rule.product.lower() not in source and rule.product.lower() not in product:
                return False

        if rule.category and rule.category.lower() not in (source, category):
            if rule.category.lower() not in source and rule.category.lower() not in category:
                return False

        return True

    def _evaluate_condition(self, rule, event_data):
        """Evaluate the detection condition expression."""
        condition = rule.condition.strip()

        # Parse common condition patterns
        # "selection" — single selection must match
        # "selection and not filter" — selection matches, filter does not
        # "selection or keywords" — either matches
        # "all of selection*" — all selections matching pattern must match
        # "1 of selection*" — at least one selection matching pattern must match

        # Handle "all of <pattern>"
        all_match = re.match(r"all\s+of\s+(\S+)", condition)
        if all_match:
            pattern = all_match.group(1).replace("*", ".*")
            matching_keys = [k for k in rule._compiled_selections if re.match(pattern, k)]
            return all(self._check_selection(rule, k, event_data) for k in matching_keys) if matching_keys else False

        # Handle "1 of <pattern>" or "<N> of <pattern>"
        n_of_match = re.match(r"(\d+)\s+of\s+(\S+)", condition)
        if n_of_match:
            n = int(n_of_match.group(1))
            pattern = n_of_match.group(2).replace("*", ".*")
            matching_keys = [k for k in rule._compiled_selections if re.match(pattern, k)]
            count = sum(1 for k in matching_keys if self._check_selection(rule, k, event_data))
            return count >= n

        # Handle compound conditions with and/or/not
        # Tokenize: split on word boundaries for and/or/not
        tokens = re.findall(r'\b(?:and|or|not)\b|[a-zA-Z_][a-zA-Z0-9_]*', condition, flags=re.IGNORECASE)
        if len(tokens) == 1:
            # Simple: "selection"
            return self._check_selection(rule, condition.strip(), event_data)

        # Build simple evaluator for "A and not B", "A or B", etc.
        result = None
        pending_not = False
        pending_op = "and"  # default

        for token in tokens:
            token = token.strip()
            if token.lower() == "and":
                pending_op = "and"
                continue
            elif token.lower() == "or":
                pending_op = "or"
                continue
            elif token.lower() == "not":
                pending_not = True
                continue

            # It's a selection name
            val = self._check_selection(rule, token, event_data)
            if pending_not:
                val = not val
                pending_not = False

            if result is None:
                result = val
            elif pending_op == "and":
                result = result and val
            elif pending_op == "or":
                result = result or val

        return result if result is not None else False

    def _check_selection(self, rule, selection_name, event_data):
        """Check if an event matches a specific detection selection."""
        selection = rule._compiled_selections.get(selection_name)
        if selection is None:
            return False

        sel_type, compiled = selection
        message = str(event_data.get("message", ""))

        if sel_type == "keywords":
            # Any keyword pattern matches against the full message
            return any(p.search(message) for p in compiled)

        elif sel_type == "fields":
            # All field conditions must match (AND logic within a selection)
            for field_name, (modifiers, patterns) in compiled.items():
                # Look for the field in event_data, fall back to searching message
                field_value = str(event_data.get(field_name, ""))
                if not field_value and field_name.lower() != "message":
                    field_value = message

                # Check if any pattern matches the field value
                if "all" in modifiers:
                    if not all(p.search(field_value) for p in patterns):
                        return False
                else:
                    if not any(p.search(field_value) for p in patterns):
                        return False
            return True

        return False

    def get_rules_summary(self):
        """Return summary of all loaded SIGMA rules."""
        return [{
            "title": r.title,
            "id": r.id,
            "status": r.status,
            "severity": r.severity,
            "description": r.description,
            "author": r.author,
            "tags": r.tags,
            "mitre_id": r.mitre_id,
            "logsource": {
                "product": r.product,
                "category": r.category,
                "service": r.service,
            },
        } for r in self.rules]

    def _create_sample_rules(self):
        """Create sample SIGMA rules to get started."""
        sample_rules = [
            {
                "title": "Multiple Failed Logon Attempts",
                "id": "0e95725d-7320-415d-80f7-004da920fc11",
                "status": "stable",
                "level": "high",
                "description": "Detects multiple failed logon attempts indicating brute force.",
                "author": "Guardian SIEM",
                "date": "2025/01/01",
                "tags": ["attack.credential_access", "attack.t1110"],
                "logsource": {
                    "product": "windows",
                    "service": "security",
                },
                "detection": {
                    "selection": {
                        "EventID": [4625],
                    },
                    "condition": "selection",
                },
                "falsepositives": ["Misconfigured service accounts"],
            },
            {
                "title": "Suspicious PowerShell Execution",
                "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                "status": "experimental",
                "level": "high",
                "description": "Detects suspicious PowerShell commands often used in attacks.",
                "author": "Guardian SIEM",
                "date": "2025/01/01",
                "tags": ["attack.execution", "attack.t1059.001"],
                "logsource": {
                    "product": "windows",
                    "category": "process_creation",
                },
                "detection": {
                    "selection": {
                        "CommandLine|contains": [
                            "-EncodedCommand",
                            "-enc ",
                            "Invoke-Expression",
                            "IEX(",
                            "downloadstring",
                            "Net.WebClient",
                            "bypass",
                        ],
                    },
                    "condition": "selection",
                },
                "falsepositives": ["Legitimate admin scripts"],
            },
            {
                "title": "Clearing Windows Event Logs",
                "id": "b2c3d4e5-f6a7-8901-bcde-f12345678901",
                "status": "stable",
                "level": "critical",
                "description": "Detects clearing of Windows event logs — indicator of anti-forensics.",
                "author": "Guardian SIEM",
                "date": "2025/01/01",
                "tags": ["attack.defense_evasion", "attack.t1070.001"],
                "logsource": {
                    "product": "windows",
                    "service": "security",
                },
                "detection": {
                    "selection": {
                        "EventID": [1102],
                    },
                    "condition": "selection",
                },
                "falsepositives": ["Legitimate log rotation"],
            },
            {
                "title": "Reverse Shell Command Patterns",
                "id": "c3d4e5f6-a7b8-9012-cdef-123456789012",
                "status": "experimental",
                "level": "critical",
                "description": "Detects command patterns commonly used to establish reverse shells.",
                "author": "Guardian SIEM",
                "date": "2025/01/01",
                "tags": ["attack.execution", "attack.t1059"],
                "logsource": {
                    "product": "windows",
                    "category": "process_creation",
                },
                "detection": {
                    "selection": [
                        "*ncat*-e*",
                        "*nc.exe*-e*",
                        "*bash -i*",
                        "*python*socket*connect*",
                        "*powershell*TCPClient*",
                        "*/dev/tcp/*",
                    ],
                    "condition": "selection",
                },
                "falsepositives": ["Penetration testing"],
            },
            {
                "title": "Suspicious Service Installation",
                "id": "d4e5f6a7-b8c9-0123-defa-234567890123",
                "status": "stable",
                "level": "medium",
                "description": "Detects installation of a new service which may indicate persistence.",
                "author": "Guardian SIEM",
                "date": "2025/01/01",
                "tags": ["attack.persistence", "attack.t1543.003"],
                "logsource": {
                    "product": "windows",
                    "service": "system",
                },
                "detection": {
                    "selection": {
                        "EventID": [7045],
                    },
                    "condition": "selection",
                },
                "falsepositives": ["Legitimate software installation"],
            },
        ]

        for i, rule in enumerate(sample_rules):
            filename = f"sigma_{i+1:03d}_{rule['title'].lower().replace(' ', '_')[:40]}.yml"
            filepath = os.path.join(self.rules_dir, filename)
            with open(filepath, "w", encoding="utf-8") as f:
                yaml.dump(rule, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
