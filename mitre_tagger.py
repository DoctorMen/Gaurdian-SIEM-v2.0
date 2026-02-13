"""
Guardian SIEM v2.0 — MITRE ATT&CK Tagger
Maps security events and alerts to MITRE ATT&CK framework techniques and tactics.
Provides enrichment data for dashboard visualization and reporting.
"""

import os
import yaml


class MitreTagger:
    """Maps events to MITRE ATT&CK techniques and tactics."""

    def __init__(self, mappings_path=None):
        if mappings_path is None:
            base_dir = os.path.dirname(os.path.abspath(__file__))
            mappings_path = os.path.join(base_dir, "config", "mitre_mappings.yaml")
        self.mappings_path = mappings_path
        self.techniques = {}
        self.tactics = {}
        self.load_mappings()

    def load_mappings(self):
        """Load MITRE ATT&CK mappings from YAML."""
        try:
            with open(self.mappings_path, "r") as f:
                data = yaml.safe_load(f)
            self.tactics = data.get("tactics", {})
            self.techniques = data.get("techniques", {})
            print(f"[MitreTagger] Loaded {len(self.techniques)} techniques, {len(self.tactics)} tactics")
        except FileNotFoundError:
            print(f"[MitreTagger] WARNING: Mappings file not found: {self.mappings_path}")
        except yaml.YAMLError as e:
            print(f"[MitreTagger] ERROR: Failed to parse YAML: {e}")

    def enrich(self, mitre_id):
        """
        Enrich an alert with full MITRE ATT&CK context.

        Args:
            mitre_id: Technique ID (e.g., 'T1110')

        Returns:
            Dict with technique details, or minimal dict if not found
        """
        if not mitre_id:
            return {"mitre_id": "", "technique_name": "Unknown", "tactic": "Unknown"}

        technique = self.techniques.get(mitre_id, {})
        if not technique:
            return {
                "mitre_id": mitre_id,
                "technique_name": "Unknown",
                "tactic": "Unknown",
                "reference_url": f"https://attack.mitre.org/techniques/{mitre_id.replace('.', '/')}/",
            }

        tactic_id = technique.get("tactic_id", "")
        tactic_info = self.tactics.get(tactic_id, {})

        return {
            "mitre_id": mitre_id,
            "technique_name": technique.get("name", "Unknown"),
            "tactic": technique.get("tactic", "Unknown"),
            "tactic_id": tactic_id,
            "tactic_description": tactic_info.get("description", ""),
            "technique_description": technique.get("description", ""),
            "severity_weight": technique.get("severity_weight", 5),
            "reference_url": f"https://attack.mitre.org/techniques/{mitre_id.replace('.', '/')}/",
        }

    def get_tactic_summary(self):
        """Return all tactics for dashboard heatmap."""
        return {
            tid: {
                "name": info.get("name", ""),
                "description": info.get("description", ""),
            }
            for tid, info in self.tactics.items()
        }

    def get_technique_by_tactic(self, tactic_name):
        """Get all techniques for a given tactic."""
        return {
            tid: info
            for tid, info in self.techniques.items()
            if info.get("tactic", "").lower() == tactic_name.lower()
        }

    def get_all_techniques(self):
        """Return all loaded techniques."""
        return self.techniques


if __name__ == "__main__":
    tagger = MitreTagger()
    print("\n--- Technique Enrichment Test ---")
    for tid in ["T1110", "T1046", "T1070.001", "T1059", "T9999"]:
        info = tagger.enrich(tid)
        print(f"  {tid}: {info['technique_name']} [{info['tactic']}] (weight: {info.get('severity_weight', '?')})")
