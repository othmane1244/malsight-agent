"""Agent sur une série d'échantillons du labo, comparé à leur vérité terrain (#16).

Pour chaque échantillon Tnn : dossier de cas depuis la collecte du labo (cases/Tnn), analyse par
l'agent (modèle LLM_MODEL), comparaison à lab/verite-terrain/Tnn.json. Écrit dans le dossier de
sortie : <Tnn>/report.json, <Tnn>/rapport.md, bilan.json, bilan.csv, bilan.md.
Aucun journal brut ni dossier de cas n'est copié. Ne lance jamais d'échantillon : lecture seule.

Usage : malsight serie docs/resultats/dev_gemma4 --echantillon T01 --echantillon T02 ...
"""
from __future__ import annotations

import csv
import json
import os
import time
import traceback
from collections.abc import Callable
from pathlib import Path

from malsight.evaluation.comparer import correspond
from malsight.schemas import Case, Report

COLONNES = [
    ("echantillon", "Échantillon"), ("attack_attendues", "ATT&CK attendues"),
    ("attack_trouvees", "ATT&CK trouvées"), ("attack_vraies", "Vraies"), ("attack_en_trop", "En trop"),
    ("attack_ratees", "Ratées"), ("iocs", "IOC trouvés / attendus"),
    ("comportements", "Comportements observés / inférés"), ("rejets", "Rejets"),
    ("temps_s", "Temps (s)"), ("json_valide", "JSON valide"),
]


def evaluer(report: Report, verite: dict) -> dict:
    """Indicateurs d'un rapport par rapport à sa vérité terrain."""
    attendues = {t["id"] for t in verite["attack"]}
    trouvees = [t.id for t in report.attack]
    iocs_ok = sum(any(i.type == a["type"] and correspond(a["type"], a["value"], i.value) for i in report.iocs)
                  for a in verite["iocs"])
    return {
        "attack_attendues": sorted(attendues), "attack_trouvees": trouvees,
        "attack_vraies": sorted(set(trouvees) & attendues), "attack_en_trop": sorted(set(trouvees) - attendues),
        "attack_ratees": sorted(attendues - set(trouvees)),
        "iocs_trouves": iocs_ok, "iocs_attendus": len(verite["iocs"]),
        "comportements_observes": sum(b.kind == "observed" for b in report.behaviors),
        "comportements_inferes": sum(b.kind == "inferred" for b in report.behaviors),
        "rejets": list(report.rejected_claims),
    }


def lancer_serie(echantillons: list[str], sortie: Path, analyser: Callable[[Case], Report],
                 cases: Path = Path("cases"), verites: Path = Path("lab/verite-terrain"),
                 dossier_echantillons: Path = Path("lab/echantillons-test"),
                 construire: Callable[..., Case] | None = None, journal: Callable[[str], None] = print) -> dict:
    """Analyse chaque échantillon en séquence ; une erreur de l'agent est notée sans arrêter la série."""
    from malsight.normalize import build_case
    from malsight.report.render import to_markdown
    construire = construire or build_case
    sortie.mkdir(parents=True, exist_ok=True)
    bilan: dict[str, dict] = {}
    for tid in echantillons:
        vt = json.loads((verites / f"{tid}.json").read_text(encoding="utf-8"))
        case = construire(dossier_echantillons / vt["echantillon"], labo=cases / tid)
        d = sortie / tid
        d.mkdir(exist_ok=True)
        ligne: dict = {"echantillon": tid, "modele": os.getenv("LLM_MODEL", "")}
        t0 = time.time()
        try:
            r = analyser(case)
            ligne["json_valide"] = True
        except Exception as e:                                  # noqa: BLE001 (série robuste)
            ligne.update(json_valide=False, erreur=f"{type(e).__name__}: {e}"[:500])
            (d / "erreur.txt").write_text(traceback.format_exc(), encoding="utf-8")
            r = None
        ligne["temps_s"] = round(time.time() - t0, 1)
        if r is not None:
            (d / "report.json").write_text(r.model_dump_json(indent=2), encoding="utf-8")
            (d / "rapport.md").write_text(to_markdown(r), encoding="utf-8")
            ligne.update(evaluer(r, vt))
        else:
            ligne["attack_attendues"] = sorted(t["id"] for t in vt["attack"])
        bilan[tid] = ligne
        ecrire_tableaux(bilan, sortie)                          # écrit au fil de l'eau
        journal(f"{tid} : {ligne['temps_s']} s, JSON {'ok' if ligne['json_valide'] else 'INVALIDE'}, "
                f"ATT&CK {ligne.get('attack_trouvees')} / {ligne['attack_attendues']}")
    return bilan


def _cellules(l: dict) -> dict[str, str]:
    def ids(v):
        return ", ".join(v) if v else "—"
    ok = l.get("json_valide")
    return {
        "echantillon": l["echantillon"], "attack_attendues": ids(l.get("attack_attendues")),
        "attack_trouvees": ids(l.get("attack_trouvees")) if ok else "—",
        "attack_vraies": str(len(l.get("attack_vraies", []))) if ok else "—",
        "attack_en_trop": ids(l.get("attack_en_trop")) if ok else "—",
        "attack_ratees": ids(l.get("attack_ratees")) if ok else ids(l.get("attack_attendues")),
        "iocs": f"{l['iocs_trouves']}/{l['iocs_attendus']}" if ok else "—",
        "comportements": f"{l['comportements_observes']} / {l['comportements_inferes']}" if ok else "—",
        "rejets": str(len(l.get("rejets", []))) if ok else "—",
        "temps_s": str(l.get("temps_s", "")), "json_valide": "oui" if ok else "non",
    }


def ecrire_tableaux(bilan: dict, sortie: Path) -> None:
    """bilan.json (complet), bilan.csv et bilan.md (une ligne par échantillon + total)."""
    sortie.mkdir(parents=True, exist_ok=True)
    (sortie / "bilan.json").write_text(json.dumps(bilan, ensure_ascii=False, indent=1), encoding="utf-8")
    lignes = [_cellules(l) for l in bilan.values()]
    with (sortie / "bilan.csv").open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=[c for c, _ in COLONNES])
        w.writeheader()
        w.writerows(lignes)
    valides = [l for l in bilan.values() if l.get("json_valide")]
    attendues = sum(len(l.get("attack_attendues", [])) for l in bilan.values())
    vraies = sum(len(l.get("attack_vraies", [])) for l in valides)
    en_trop = sum(len(l.get("attack_en_trop", [])) for l in valides)
    md = ["| " + " | ".join(t for _, t in COLONNES) + " |", "|" + " --- |" * len(COLONNES)]
    md += ["| " + " | ".join(c[k] for k, _ in COLONNES) + " |" for c in lignes]
    total = {
        "echantillon": "**Total**", "attack_attendues": str(attendues), "attack_trouvees": "",
        "attack_vraies": f"**{vraies}/{attendues}**", "attack_en_trop": str(en_trop), "attack_ratees": str(attendues - vraies),
        "iocs": f"{sum(l.get('iocs_trouves', 0) for l in valides)}/{sum(l.get('iocs_attendus', 0) for l in valides)}",
        "comportements": f"{sum(l.get('comportements_observes', 0) for l in valides)} / "
                         f"{sum(l.get('comportements_inferes', 0) for l in valides)}",
        "rejets": str(sum(len(l.get('rejets', [])) for l in valides)),
        "temps_s": str(round(sum(l.get("temps_s", 0) for l in bilan.values()), 1)),
        "json_valide": f"{len(valides)}/{len(bilan)}",
    }
    md.append("| " + " | ".join(total[k] for k, _ in COLONNES) + " |")
    (sortie / "bilan.md").write_text("\n".join(md) + "\n", encoding="utf-8")
