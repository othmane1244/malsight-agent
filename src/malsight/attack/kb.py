"""Base de connaissance MITRE ATT&CK : validation des IDs et recherche de techniques.

Télécharger la base une fois :  malsight download-attack
(source : https://github.com/mitre-attack/attack-stix-data)
"""
from __future__ import annotations

import re
import urllib.request
from functools import lru_cache
from pathlib import Path

ATTACK_URL = ("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
              "master/enterprise-attack/enterprise-attack.json")
DEFAULT_PATH = Path("data/enterprise-attack.json")
TID = re.compile(r"^T\d{4}(?:\.\d{3})?$")


def download(dest: Path = DEFAULT_PATH) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    urllib.request.urlretrieve(ATTACK_URL, dest)
    return dest


class AttackKB:
    def __init__(self, techniques: dict[str, dict]):
        # id -> {"name", "tactics", "description"}
        self.techniques = techniques

    @classmethod
    @lru_cache(maxsize=1)
    def load(cls, path: Path = DEFAULT_PATH) -> "AttackKB":
        from mitreattack.stix20 import MitreAttackData
        data = MitreAttackData(str(path))
        techniques = {}
        for t in data.get_techniques(remove_revoked_deprecated=True):
            tid = next((r["external_id"] for r in t["external_references"]
                        if r.get("source_name") == "mitre-attack"), None)
            if tid:
                techniques[tid] = {
                    "name": t["name"],
                    "tactics": [p["phase_name"] for p in t.get("kill_chain_phases", [])],
                    "description": t.get("description", ""),
                }
        return cls(techniques)

    def is_valid(self, tid: str) -> bool:
        return bool(TID.match(tid)) and tid in self.techniques

    def name(self, tid: str) -> str:
        return self.techniques.get(tid, {}).get("name", "")

    def tactic(self, tid: str) -> str:
        return ", ".join(self.techniques.get(tid, {}).get("tactics", []))

    def search(self, query: str, k: int = 5) -> list[tuple[str, str]]:
        """Recherche lexicale simple. À remplacer par un index vectoriel (Chroma) en phase 4."""
        words = {w for w in re.findall(r"\w{4,}", query.lower())}
        scored = []
        for tid, t in self.techniques.items():
            text = (t["name"] + " " + t["description"]).lower()
            score = sum(text.count(w) for w in words)
            if score:
                scored.append((score, tid, t["name"]))
        return [(tid, name) for _, tid, name in sorted(scored, reverse=True)[:k]]
