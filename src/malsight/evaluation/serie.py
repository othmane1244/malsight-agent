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

# mode -> (LLM utilisé, règles D7 appliquées)
MODES = {"llm": (True, False), "regles": (False, True), "hybride": (True, True)}

COLONNES = [
    ("echantillon", "Échantillon"), ("attack_attendues", "ATT&CK attendues"),
    ("attack_trouvees", "ATT&CK trouvées"), ("attack_vraies", "Vraies (strict)"),
    ("attack_vraies_tol", "Vraies (tolérant)"), ("attack_en_trop", "FP strict"),
    ("attack_en_trop_tol", "FP tolérant"), ("attack_ratees", "Ratées (strict)"), ("iocs", "IOC trouvés / attendus"),
    ("comportements", "Comportements observés / inférés"), ("rejets", "Rejets"),
    ("temps_s", "Temps (s)"), ("json_valide", "JSON valide"),
]


def _parent(tid: str) -> str:
    return tid.split(".")[0]


def noter_attack(trouvees: list[str], attendues: set[str]) -> dict:
    """Notation ATT&CK (D9).

    - strict : seule la (sous-)technique exacte compte ; toute technique trouvée non attendue
      exactement est un faux positif ;
    - tolérant : la technique PARENTE d'une technique attendue compte aussi (T1053 pour T1053.005) ;
      toute autre technique trouvée est un faux positif.
    """
    trouvees_set = set(trouvees)
    vraies_tol = sorted(a for a in attendues if a in trouvees_set or _parent(a) in trouvees_set)
    parents_attendus = {_parent(a) for a in attendues if "." in a}
    return {
        "attack_vraies": sorted(trouvees_set & attendues),
        "attack_en_trop": sorted(trouvees_set - attendues),
        "attack_ratees": sorted(attendues - trouvees_set),
        "attack_vraies_tol": vraies_tol,
        "attack_en_trop_tol": sorted(t for t in trouvees_set if t not in attendues and t not in parents_attendus),
        "attack_ratees_tol": sorted(attendues - set(vraies_tol)),
    }


def evaluer(report: Report, verite: dict) -> dict:
    """Indicateurs d'un rapport par rapport à sa vérité terrain."""
    attendues = {t["id"] for t in verite["attack"]}
    trouvees = [t.id for t in report.attack]
    iocs_ok = sum(any(i.type == a["type"] and correspond(a["type"], a["value"], i.value) for i in report.iocs)
                  for a in verite["iocs"])
    return {
        "attack_attendues": sorted(attendues), "attack_trouvees": trouvees,
        **noter_attack(trouvees, attendues),
        "iocs_trouves": iocs_ok, "iocs_attendus": len(verite["iocs"]),
        "comportements_observes": sum(b.kind == "observed" for b in report.behaviors),
        "comportements_inferes": sum(b.kind == "inferred" for b in report.behaviors),
        "rejets": list(report.rejected_claims),
    }


def lancer_serie(echantillons: list[str], sortie: Path, analyser: Callable[[Case], Report],
                 cases: Path = Path("cases"), verites: Path = Path("lab/verite-terrain"),
                 dossier_echantillons: Path = Path("lab/echantillons-test"),
                 construire: Callable[..., Case] | None = None, journal: Callable[[str], None] = print,
                 mode: str = "llm") -> dict:
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
        uses_llm = MODES.get(mode, (True, False))[0]
        ligne: dict = {"echantillon": tid, "mode": mode, "modele": os.getenv("LLM_MODEL", "") if uses_llm else ""}
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
        "attack_vraies_tol": str(len(l.get("attack_vraies_tol", []))) if ok else "—",
        "attack_en_trop": ids(l.get("attack_en_trop")) if ok else "—",
        "attack_en_trop_tol": ids(l.get("attack_en_trop_tol")) if ok else "—",
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
    s = scores(bilan)
    attendues = s["attendues"]
    md = ["| " + " | ".join(t for _, t in COLONNES) + " |", "|" + " --- |" * len(COLONNES)]
    md += ["| " + " | ".join(c[k] for k, _ in COLONNES) + " |" for c in lignes]
    valides = [l for l in bilan.values() if l.get("json_valide")]
    total = {
        "echantillon": "**Total**", "attack_attendues": str(attendues), "attack_trouvees": "",
        "attack_vraies": f"**{s['strict']['vraies']}/{attendues}**",
        "attack_vraies_tol": f"**{s['tolerant']['vraies']}/{attendues}**",
        "attack_en_trop": str(s["strict"]["fp"]), "attack_en_trop_tol": str(s["tolerant"]["fp"]),
        "attack_ratees": str(attendues - s["strict"]["vraies"]),
        "iocs": f"{sum(l.get('iocs_trouves', 0) for l in valides)}/{sum(l.get('iocs_attendus', 0) for l in valides)}",
        "comportements": f"{sum(l.get('comportements_observes', 0) for l in valides)} / "
                         f"{sum(l.get('comportements_inferes', 0) for l in valides)}",
        "rejets": str(sum(len(l.get('rejets', [])) for l in valides)),
        "temps_s": str(round(sum(l.get("temps_s", 0) for l in bilan.values()), 1)),
        "json_valide": f"{len(valides)}/{len(bilan)}",
    }
    md.append("| " + " | ".join(total[k] for k, _ in COLONNES) + " |")
    md += ["", "Notation ATT&CK (D9) : **strict** = (sous-)technique exacte ; **tolérant** = la technique "
           "parente d'une technique attendue compte aussi. Toute technique en trop est un faux positif (FP).", "",
           "| Score | Vraies | FP | Précision | Rappel |", "| --- | --- | --- | --- | --- |"]
    for nom, cle in (("strict", "strict"), ("tolérant", "tolerant")):
        x = s[cle]
        md.append(f"| {nom} | {x['vraies']}/{attendues} | {x['fp']} | {_pct(x['precision'])} | {_pct(x['rappel'])} |")
    (sortie / "bilan.md").write_text("\n".join(md) + "\n", encoding="utf-8")


def _pct(x: float | None) -> str:
    return "—" if x is None else f"{x:.0%}"


def scores(bilan: dict) -> dict:
    """Totaux strict / tolérant (D9) : vraies, faux positifs, précision, rappel. Un rapport non
    valide compte comme zéro technique trouvée."""
    valides = [l for l in bilan.values() if l.get("json_valide")]
    attendues = sum(len(l.get("attack_attendues", [])) for l in bilan.values())
    out = {"attendues": attendues}
    for cle, vraies_k, fp_k in (("strict", "attack_vraies", "attack_en_trop"),
                                ("tolerant", "attack_vraies_tol", "attack_en_trop_tol")):
        vraies = sum(len(l.get(vraies_k, [])) for l in valides)
        fp = sum(len(l.get(fp_k, [])) for l in valides)
        out[cle] = {"vraies": vraies, "fp": fp,
                    "precision": vraies / (vraies + fp) if vraies + fp else None,
                    "rappel": vraies / attendues if attendues else None}
    return out


def tableau_modes(series: dict[str, Path]) -> list[str]:
    """Tableau comparatif de plusieurs séries (une ligne par mode) : scores strict et tolérant (D9),
    précision, rappel, faux positifs, IOC, témoin négatif, JSON valides, temps moyen par échantillon."""
    tete = ["Mode", "Strict : vraies", "Strict : FP", "Strict : précision", "Strict : rappel",
            "Tolérant : vraies", "Tolérant : FP", "Tolérant : précision", "Tolérant : rappel",
            "IOC", "Témoin négatif sans FP", "JSON valides", "Temps moyen (s)"]
    lignes = ["| " + " | ".join(tete) + " |", "|" + " --- |" * len(tete)]
    for mode, dossier in series.items():
        bilan = json.loads((Path(dossier) / "bilan.json").read_text(encoding="utf-8"))
        s = scores(bilan)
        valides = [l for l in bilan.values() if l.get("json_valide")]
        negatifs = [l for l in bilan.values() if not l.get("attack_attendues")]
        temoin = all(l.get("json_valide") and not l.get("attack_en_trop") for l in negatifs) if negatifs else None
        temps = [l["temps_s"] for l in bilan.values() if "temps_s" in l]
        cellules = [
            f"`{mode}`",
            f"{s['strict']['vraies']}/{s['attendues']}", str(s["strict"]["fp"]),
            _pct(s["strict"]["precision"]), _pct(s["strict"]["rappel"]),
            f"{s['tolerant']['vraies']}/{s['attendues']}", str(s["tolerant"]["fp"]),
            _pct(s["tolerant"]["precision"]), _pct(s["tolerant"]["rappel"]),
            f"{sum(l.get('iocs_trouves', 0) for l in valides)}/{sum(l.get('iocs_attendus', 0) for l in valides)}",
            "—" if temoin is None else ("oui" if temoin else "**non**"),
            f"{len(valides)}/{len(bilan)}",
            f"{sum(temps) / len(temps):.1f}" if temps else "—",
        ]
        lignes.append("| " + " | ".join(cellules) + " |")
    return lignes


def renoter(sortie: Path, verites: Path = Path("lab/verite-terrain"),
            reverifier: Callable[[str, Report], Report] | None = None) -> dict:
    """Recalcule la notation d'une série existante à partir de ses report.json (sans relancer
    l'agent) et réécrit bilan.json / .csv / .md. Les champs non liés à la notation sont conservés.

    `reverifier(tid, rapport)` : applique le vérificateur actuel au rapport enregistré (le rapport
    réécrit remplace l'ancien ; l'ancien reste dans l'historique git). Le vérificateur ne fait que
    retirer : les techniques ATT&CK obtenues sont celles qu'une nouvelle exécution donnerait pour le
    même brouillon du LLM ; seules les recommandations déjà rédigées ne sont pas réécrites."""
    from malsight.report.render import to_markdown
    bilan = json.loads((sortie / "bilan.json").read_text(encoding="utf-8"))
    for tid, ligne in bilan.items():
        ligne.setdefault("echantillon", tid)
        f = sortie / tid / "report.json"
        if ligne.get("json_valide") and f.exists():
            vt = json.loads((verites / f"{tid}.json").read_text(encoding="utf-8"))
            r = Report.model_validate_json(f.read_text(encoding="utf-8"))
            if reverifier is not None:
                r = reverifier(tid, r)
                f.write_text(r.model_dump_json(indent=2), encoding="utf-8")
                (sortie / tid / "rapport.md").write_text(to_markdown(r), encoding="utf-8")
                ligne["reverifie"] = True
            ligne.update(evaluer(r, vt))
    ecrire_tableaux(bilan, sortie)
    return bilan
