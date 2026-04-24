import yaml
from pathlib import Path

class MITREEnricher:
    def __init__(self, path="config/prod/mitre_mapping.yaml"):
        with open(path) as f: self.mapping = yaml.safe_load(f)
    def enrich(self, alert: dict) -> dict:
        t = alert.get("threat_type", "").upper()
        m = self.mapping.get(t, {})
        return {**alert, "mitre": m, "stix_type": "indicator", "labels": [f"attack-pattern/{m.get('technique_id','?')}"]}
