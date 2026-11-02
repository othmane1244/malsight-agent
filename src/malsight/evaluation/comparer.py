"""Compare un dossier de résultats du labo à sa vérité terrain (lab/verite-terrain/Tnn.json).

Lecture seule : ne lit que sysmon.csv, procmon.csv et manifeste.json produits par
lab/scripts/collect.ps1. Pour Sysmon, le parseur du projet est appliqué ligne par ligne
(même normalisation, mêmes exclusions) afin de citer l'EID et le processus de chaque preuve.
Pour Procmon, recherche ciblée des opérations d'écriture réussies sur les IOC attendus
(en attendant le parseur Procmon complet, issue #8).
"""
from __future__ import annotations

import csv
import json
from dataclasses import dataclass, field
from pathlib import Path, PureWindowsPath

from malsight.extractors.dynamic import parse_sysmon_rows
from malsight.extractors.lab import trouver_dossier  # noqa: F401  (réexporté pour la CLI et les tests)
from malsight.schemas import Case

# Champ du parseur Sysmon (DynamicData) correspondant à chaque type d'IOC de la vérité terrain
_CHAMP_SYSMON = {"registry_key": "registry_keys_set", "file_path": "files_written",
                 "domain": "domains", "ip": "ips"}
# Opérations Procmon qui prouvent une écriture
_ECRITURES_PROCMON = {"RegCreateKey", "RegSetValue", "WriteFile", "SetRenameInformationFile",
                      "SetEndOfFileInformationFile"}
_PROCESSUS_IGNORES = {"System"}   # écritures différées du cache disque (PID 4)


@dataclass
class ResultatIoc:
    type: str
    valeur: str
    sysmon: list[str] = field(default_factory=list)
    procmon: list[str] = field(default_factory=list)

    @property
    def trouve(self) -> bool:
        return bool(self.sysmon or self.procmon)


def correspond(type_ioc: str, attendu: str, observe: str) -> bool:
    """Égalité sans casse ; une clé de registre couvre aussi ses valeurs et sous-clés."""
    a, o = attendu.lower().rstrip("\\"), observe.lower().rstrip("\\")
    if type_ioc == "registry_key":
        return o == a or o.startswith(a + "\\")
    return o == a


def verite_pour(dossier: Path, verites: Path) -> Path:
    """Retrouve Tnn.json à partir du nom d'échantillon du manifeste."""
    manifeste = json.loads((dossier / "manifeste.json").read_text(encoding="utf-8-sig"))
    tid = manifeste["echantillon"].split("_", 1)[0]
    return verites / f"{tid}.json"


def _preuves_sysmon(csv_sysmon: Path, iocs: list[dict]) -> dict[int, list[str]]:
    preuves: dict[int, list[str]] = {i: [] for i in range(len(iocs))}
    with csv_sysmon.open(encoding="utf-8-sig", newline="") as f:
        for ligne in csv.DictReader(f):
            extrait = parse_sysmon_rows([ligne])
            for i, ioc in enumerate(iocs):
                champ = _CHAMP_SYSMON.get(ioc["type"])
                if champ and any(correspond(ioc["type"], ioc["value"], v) for v in getattr(extrait, champ)):
                    image = PureWindowsPath(ligne.get("Image") or "?").name
                    preuves[i].append(f"EID {ligne['EventID']} ({image})")
    return preuves


def _preuves_procmon(csv_procmon: Path, iocs: list[dict]) -> dict[int, list[str]]:
    compte: dict[int, dict[str, int]] = {i: {} for i in range(len(iocs))}
    cibles = [(i, ioc) for i, ioc in enumerate(iocs) if ioc["type"] in ("registry_key", "file_path")]
    with csv_procmon.open(encoding="utf-8-sig", newline="") as f:
        for ligne in csv.DictReader(f):
            op, proc = ligne.get("Operation", ""), ligne.get("Process Name", "")
            ecriture = op in _ECRITURES_PROCMON or (op == "CreateFile" and "Write" in ligne.get("Detail", ""))
            if not ecriture or ligne.get("Result") != "SUCCESS" or proc in _PROCESSUS_IGNORES:
                continue
            for i, ioc in cibles:
                if correspond(ioc["type"], ioc["value"], ligne.get("Path", "")):
                    cle = f"{op} ({proc})"
                    compte[i][cle] = compte[i].get(cle, 0) + 1
    return {i: [f"{k} ×{n}" if n > 1 else k for k, n in c.items()] for i, c in compte.items()}


def comparer(dossier: Path, verite: Path) -> tuple[dict, list[ResultatIoc]]:
    """Retourne la vérité terrain et, pour chaque IOC attendu, ses preuves Sysmon/Procmon."""
    vt = json.loads(verite.read_text(encoding="utf-8"))
    iocs = vt["iocs"]
    sysmon = _preuves_sysmon(dossier / "sysmon.csv", iocs)
    csv_procmon = dossier / "procmon.csv"
    procmon = _preuves_procmon(csv_procmon, iocs) if csv_procmon.exists() else {}
    return vt, [ResultatIoc(ioc["type"], ioc["value"], sysmon[i], procmon.get(i, []))
                for i, ioc in enumerate(iocs)]


def ioc_dans_cas(case: Case, ioc: dict) -> list[str]:
    """Observations du dossier de cas qui correspondent à un IOC attendu (vide si absent)."""
    kind = {"registry_key": "registry", "file_path": "file", "domain": "domain", "ip": "ip"}.get(ioc["type"])
    return [f"{o.value} [{'+'.join(o.sources)}, {o.attribution}]" for o in case.dynamic.observations
            if o.kind == kind and correspond(ioc["type"], ioc["value"], o.value)]


def tableau(vt: dict, resultats: list[ResultatIoc]) -> str:
    """Tableau Markdown : IOC attendu / trouvé / source."""
    def cellule(preuves: list[str]) -> str:
        if not preuves:
            return "—"
        return ", ".join(preuves[:3]) + (f" (+{len(preuves) - 3})" if len(preuves) > 3 else "")

    lignes = [f"### {vt['id']} : {vt['echantillon']}", "",
              "| IOC attendu | Type | Trouvé | Sysmon | Procmon |",
              "| --- | --- | --- | --- | --- |"]
    for r in resultats:
        lignes.append(f"| `{r.valeur}` | {r.type} | {'✅' if r.trouve else '❌'} | {cellule(r.sysmon)} | {cellule(r.procmon)} |")
    n = sum(r.trouve for r in resultats)
    lignes += ["", f"**{n}/{len(resultats)} IOC retrouvés.**"]
    techniques = ", ".join(t["id"] for t in vt.get("attack", [])) or "aucune (témoin négatif)"
    lignes.append(f"Techniques ATT&CK attendues : {techniques} (non évaluées ici : à comparer au rapport de l'agent).")
    return "\n".join(lignes)
