"""Base MITRE D3FEND : contre-mesures défensives d'une technique ATT&CK (décision D6).

Fonctionne HORS LIGNE : l'analyse ne lit que le cache local data/d3fend/. Le réseau n'est
utilisé que par `malsight download-d3fend`, qui pré-remplit le cache.

API officielle (alpha, https://d3fend.mitre.org/api-docs) :
    GET https://d3fend.mitre.org/api/offensive-technique/attack/<ID ATT&CK>.json
La réponse contient `off_to_def.results.bindings` (format SPARQL JSON) : une ligne par lien
technique offensive -> artefact -> technique défensive, avec notamment `def_tech_id`
(ex. « D3-LFP »), `def_tech_label`, `def_tactic_label`, `def_artifact_label` et `def_tech`
(IRI, dont le fragment donne la page d3fend.mitre.org/technique/d3f:<fragment>/).
"""
from __future__ import annotations

import json
import re
import urllib.request
from collections.abc import Callable, Iterable
from datetime import datetime, timezone
from pathlib import Path

from malsight.schemas import Countermeasure

API_TECHNIQUE = "https://d3fend.mitre.org/api/offensive-technique/attack/{tid}.json"
API_VERSION = "https://d3fend.mitre.org/api/version.json"
DEFAULT_CACHE = Path("data/d3fend")
TID = re.compile(r"^T\d{4}(?:\.\d{3})?$")
D3ID = re.compile(r"\bD3-[A-Z0-9]+\b")
# Ordre de présentation des tactiques D3FEND (prévention et détection d'abord)
ORDRE_TACTIQUES = ["Harden", "Detect", "Isolate", "Deceive", "Evict", "Restore", "Model"]

Fetcher = Callable[[str], dict]


def _fetch_json(url: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "malsight-agent (pedagogique)"})
    with urllib.request.urlopen(req, timeout=60) as r:          # noqa: S310 (URL fixe, https)
        return json.loads(r.read().decode("utf-8"))


def _val(binding: dict, key: str) -> str:
    return (binding.get(key) or {}).get("value", "") or ""


def parse_api(doc: dict, tid: str) -> list[Countermeasure]:
    """Réponse de l'API D3FEND -> contre-mesures uniques, triées par tactique puis identifiant."""
    vues: dict[str, Countermeasure] = {}
    for b in ((doc.get("off_to_def") or {}).get("results") or {}).get("bindings", []):
        d3id = _val(b, "def_tech_id")
        if not D3ID.fullmatch(d3id) or d3id in vues:
            continue
        fragment = _val(b, "def_tech").rsplit("#", 1)[-1]
        vues[d3id] = Countermeasure(
            id=d3id, name=_val(b, "def_tech_label"), technique=tid,
            tactic=_val(b, "def_tactic_label"), artifact=_val(b, "def_artifact_label"),
            url=f"https://d3fend.mitre.org/technique/d3f:{fragment}/" if fragment else "")

    def rang(c: Countermeasure):
        t = ORDRE_TACTIQUES.index(c.tactic) if c.tactic in ORDRE_TACTIQUES else len(ORDRE_TACTIQUES)
        return (t, c.id)
    return sorted(vues.values(), key=rang)


def parent(tid: str) -> str | None:
    return tid.split(".")[0] if "." in tid else None


class DefendKB:
    """Lecture seule du cache local : un fichier <ID ATT&CK>.json par technique."""

    def __init__(self, cache: Path = DEFAULT_CACHE):
        self.cache = Path(cache)

    def _lire(self, tid: str) -> list[Countermeasure] | None:
        f = self.cache / f"{tid}.json"
        if not f.exists():
            return None
        doc = json.loads(f.read_text(encoding="utf-8"))
        return [Countermeasure(**c) for c in doc.get("countermeasures", [])]

    def countermeasures(self, tid: str) -> list[Countermeasure]:
        """Contre-mesures d'une technique ; à défaut, celles de la technique parente (même ID couvert)."""
        if not TID.match(tid):
            return []
        cms = self._lire(tid)
        if not cms and (p := parent(tid)):
            cms = [c.model_copy(update={"technique": tid}) for c in (self._lire(p) or [])]
        return cms or []

    def known_ids(self) -> set[str]:
        """Tous les identifiants D3FEND présents dans le cache."""
        ids: set[str] = set()
        for f in self.cache.glob("T*.json"):
            ids |= {c["id"] for c in json.loads(f.read_text(encoding="utf-8")).get("countermeasures", [])}
        return ids

    def covers(self, d3id: str, tid: str) -> bool:
        return any(c.id == d3id for c in self.countermeasures(tid))


def techniques_des_verites(dossier: Path) -> list[str]:
    """Techniques ATT&CK citées dans lab/verite-terrain/*.json (avec leurs parentes)."""
    ids: set[str] = set()
    for f in sorted(Path(dossier).glob("T*.json")):
        for t in json.loads(f.read_text(encoding="utf-8")).get("attack", []):
            ids.add(t["id"])
            if p := parent(t["id"]):
                ids.add(p)
    return sorted(ids)


def download(techniques: Iterable[str], cache: Path = DEFAULT_CACHE, fetch: Fetcher = _fetch_json) -> dict:
    """Pré-remplit le cache (seule fonction qui utilise le réseau). Retourne un bilan par technique."""
    cache = Path(cache)
    cache.mkdir(parents=True, exist_ok=True)
    try:
        version = fetch(API_VERSION).get("version", "")
    except Exception:                                           # noqa: BLE001 (version facultative)
        version = ""
    bilan = {}
    for tid in techniques:
        if not TID.match(tid):
            raise ValueError(f"ID ATT&CK invalide : {tid}")
        cms = parse_api(fetch(API_TECHNIQUE.format(tid=tid)), tid)
        (cache / f"{tid}.json").write_text(json.dumps({
            "technique": tid, "d3fend_version": version,
            "telecharge_le": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "source": API_TECHNIQUE.format(tid=tid),
            "countermeasures": [c.model_dump() for c in cms],
        }, ensure_ascii=False, indent=1), encoding="utf-8")
        bilan[tid] = len(cms)
    return bilan
