"""Dossier de collecte du labo (sysmon.csv + procmon.csv) -> DynamicData fusionné. Lecture seule.

Attribution (issue #8) — on ne filtre PAS par PID seul :
1. **Arbre de l'échantillon** : PID racine (auto.json, sinon processus dont la ligne de commande
   cite l'échantillon, sinon processus qui a créé C:\\travail\\<échantillon>) et tous ses
   descendants (Procmon « Process Create », Sysmon EID 1).
2. **Services intermédiaires** : écritures (registre, fichiers) de svchost.exe, services.exe et
   wmiprvse.exe pendant que l'arbre est actif (+ marge). La persistance de T02 (tâche planifiée)
   et T03 (service) est écrite par ces services, pas par l'échantillon.
3. **Sysmon hors arbre** : gardé seulement s'il est corroboré par une écriture Procmon gardée
   (évite d'aligner l'horloge UTC de Sysmon sur l'heure locale de Procmon).
Les opérations vues par les deux sources sont dédupliquées ; chaque élément note ses sources.
"""
from __future__ import annotations

import csv
import json
import re
from pathlib import Path, PureWindowsPath

from malsight.extractors.dynamic import LAB_TOOL_IMAGES, normalize_registry_key, parse_sysmon_rows
from malsight.extractors.procmon import EvenementProcmon, load_procmon_csv
from malsight.schemas import DynamicData, Observation

SERVICES_INTERMEDIAIRES = {"svchost.exe", "services.exe", "wmiprvse.exe"}
MARGE_S = 2.0

# Traces du labo lui-même et bruit propre à PowerShell : jamais attribués à l'échantillon
_BRUIT = re.compile(
    r"C:\\labo-outils\\|C:\\entree\\|C:\\resultats\\|malsight-collecte|malsight-analyse-auto"
    r"|__PSScriptPolicyTest_|\\PowerShell\\(?:ModuleAnalysisCache|StartupProfileData)|\\PSReadLine\\"
    r"|^\\Device\\|^\\REGISTRY\\A\\", re.I)

# Bruit système connu : écritures automatiques de Windows observées sur TOUS les échantillons,
# y compris le témoin négatif T11 (mesure : docs/journal.md). Désactivable (filtrer_bruit=False).
BRUIT_SYSTEME = re.compile(
    r"^[A-Z]:\\\$"                                              # métafichiers NTFS ($LogFile, $Mft...)
    r"|\\winevt\\Logs\\|\\catroot2\\|\\appcompat\\Programs\\"   # journaux d'événements, catalogues, Amcache
    r"|\\(?:VolatileNotifications|Notifications\\Data)\\"       # état WNF
    r"|\\Services\\bam\\State\\"                                # Background Activity Moderator
    r"|\\System\\GameConfigStore\\|\\AppModel\\SystemAppData\\|\\HostActivityManager\\"
    r"|\\Control\\DeviceContainers\\|\\CurrentVersion\\AppReadiness\\"   # suivi des lancements d'applis
    r"|\\Wbem\\Tracing\\|\\Wbem\\CIMOM\\"                       # traçage interne de WMI (pas la persistance WMI)
    r"|\\Local Settings\\MuiCache\\"
    r"|\\Internet Settings\\ZoneMap\\(?:ProxyBypass|IntranetName|UNCAsIntranet|AutoDetect)$"
    r"|\\Windows Error Reporting\\TermReason\\"
    r"|\\PowerShell\\PSReadLine$|\\Microsoft\\Windows\\PowerShell$", re.I)


def trouver_dossier(chemin: Path) -> Path:
    """Accepte un dossier de collecte, ou un dossier qui en contient exactement un."""
    if (chemin / "sysmon.csv").exists():
        return chemin
    candidats = [d for d in chemin.iterdir() if d.is_dir() and (d / "sysmon.csv").exists()]
    if len(candidats) != 1:
        raise FileNotFoundError(f"{chemin} : {len(candidats)} dossier(s) de collecte trouvé(s), 1 attendu")
    return candidats[0]


def _cle(kind: str, value: str) -> str:
    v = " ".join(value.split()).lower().rstrip("\\")
    return f"{kind}:{v}"


class _Fusion:
    """Accumule les observations dédupliquées, dans l'ordre (arbre de l'échantillon d'abord)."""

    def __init__(self, exclus: set[str] = frozenset(), filtrer_bruit: bool = True):
        self.obs: dict[str, Observation] = {}
        self.exclus = {v.lower() for v in exclus}
        self.filtrer_bruit = filtrer_bruit

    def ajouter(self, kind, value, source, operation, processus, attribution):
        if not value or value == "-" or _BRUIT.search(value) or value.lower() in self.exclus:
            return
        if self.filtrer_bruit and BRUIT_SYSTEME.search(value):
            return
        k = _cle(kind, value)
        o = self.obs.get(k)
        if o is None:
            o = self.obs[k] = Observation(kind=kind, value=value, attribution=attribution)
        elif attribution == "sample_tree":
            o.attribution = "sample_tree"       # l'arbre de l'échantillon prime
        for liste, v in ((o.sources, source), (o.operations, operation), (o.processes, processus)):
            if v and v not in liste:
                liste.append(v)

    def resultat(self, source: str) -> DynamicData:
        obs = sorted(self.obs.values(), key=lambda o: o.attribution != "sample_tree")  # tri stable
        par = {k: [o.value for o in obs if o.kind == k] for k in ("process", "file", "registry", "domain", "ip")}
        return DynamicData(source=source, observations=obs, processes_created=par["process"],
                           files_written=par["file"], registry_keys_set=par["registry"],
                           domains=par["domain"], ips=par["ip"])


def _racines(dossier: Path, echantillon: str, sysmon: list[dict], procmon: list[EvenementProcmon]) -> set[int]:
    auto = dossier / "auto.json"
    if auto.exists():
        pid = json.loads(auto.read_text(encoding="utf-8-sig")).get("pid_echantillon")
        if pid:
            return {int(pid)}
    nom = echantillon.lower()
    pids = {int(r["ProcessId"]) for r in sysmon
            if r.get("EventID") == "1" and nom and nom in (r.get("CommandLine") or "").lower()}
    pids |= {e.pid for e in procmon if e.operation == "Process Start" and nom and nom in e.ligne_commande.lower()}
    if pids:
        return pids
    # Mode manuel : l'échantillon tourne dans la console qui l'a copié dans C:\travail
    copie = f"c:\\travail\\{nom}"
    pids = {int(r["ProcessId"]) for r in sysmon
            if r.get("EventID") == "11" and (r.get("TargetFilename") or "").lower() == copie}
    pids |= {e.pid for e in procmon if e.nature == "file" and e.chemin.lower() == copie}
    return pids


def _descendants(racines: set[int], sysmon: list[dict], procmon: list[EvenementProcmon]) -> set[int]:
    enfants: dict[int, set[int]] = {}
    for r in sysmon:
        if r.get("EventID") == "1" and not LAB_TOOL_IMAGES.match(r.get("Image") or "") \
                and not _BRUIT.search(r.get("CommandLine") or ""):
            enfants.setdefault(int(r.get("ParentProcessId") or 0), set()).add(int(r["ProcessId"]))
    for e in procmon:
        if e.operation == "Process Create" and e.pid_enfant and not _BRUIT.search(e.ligne_commande):
            enfants.setdefault(e.pid, set()).add(e.pid_enfant)
    arbre, a_voir = set(racines), list(racines)
    while a_voir:
        for c in enfants.get(a_voir.pop(), ()):
            if c not in arbre:
                arbre.add(c)
                a_voir.append(c)
    return arbre


def fusionner(sysmon: list[dict], procmon: list[EvenementProcmon], racines: set[int],
              echantillon: str = "", filtrer_bruit: bool = True) -> DynamicData:
    """Fusionne Sysmon et Procmon autour de l'arbre de processus de l'échantillon."""
    arbre = _descendants(racines, sysmon, procmon)
    # La copie de l'échantillon dans C:\travail est faite par le labo, pas par l'échantillon
    f = _Fusion(exclus={f"C:\\travail\\{echantillon}"} if echantillon else set(), filtrer_bruit=filtrer_bruit)

    # Fenêtre d'activité de l'arbre (horloge Procmon)
    temps = [e.t for e in procmon if e.pid in arbre]
    fenetre = (min(temps), max(temps) + MARGE_S) if temps else None

    def libelle(nom, pid):
        return f"{nom} ({pid})"

    # 1. Procmon
    for e in procmon:
        dans_arbre = e.pid in arbre
        service = (not dans_arbre and fenetre and e.processus.lower() in SERVICES_INTERMEDIAIRES
                   and fenetre[0] <= e.t <= fenetre[1] and e.nature in ("file", "registry"))
        if not (dans_arbre or service):
            continue
        attribution = "sample_tree" if dans_arbre else "service_window"
        proc = libelle(e.processus, e.pid)
        if e.nature == "registry":
            f.ajouter("registry", normalize_registry_key(e.chemin), "procmon", e.operation, proc, attribution)
        elif e.nature == "file":
            f.ajouter("file", e.chemin, "procmon", e.operation, proc, attribution)
        elif e.operation == "Process Create" and e.ligne_commande:
            f.ajouter("process", e.ligne_commande, "procmon", e.operation, proc, attribution)
        elif e.nature == "network" and "->" in e.chemin:
            hote = e.chemin.split("->")[-1].strip().rsplit(":", 1)[0]
            f.ajouter("ip" if re.fullmatch(r"[\d.]+", hote) else "domain", hote.lower(), "procmon",
                      e.operation, proc, attribution)
    corrobores = set(f.obs)

    # 2. Sysmon (parseur existant, ligne par ligne)
    for r in sysmon:
        try:
            pid = int(r.get("ProcessId") or 0)
        except ValueError:
            continue
        extrait = parse_sysmon_rows([r])
        if r.get("EventID") == "1":
            pid = int(r.get("ParentProcessId") or 0)     # un processus créé est attribué à son parent
        dans_arbre = pid in arbre
        proc = libelle(PureWindowsPath(r.get("Image") or "?").name, r.get("ProcessId"))
        op = f"EID {r.get('EventID')}"
        for kind, valeurs in (("process", extrait.processes_created), ("file", extrait.files_written),
                              ("registry", extrait.registry_keys_set), ("domain", extrait.domains),
                              ("ip", extrait.ips)):
            for v in valeurs:
                if dans_arbre:
                    f.ajouter(kind, v, "sysmon", op, proc, "sample_tree")
                elif _cle(kind, v) in corrobores:
                    f.ajouter(kind, v, "sysmon", op, proc, f.obs[_cle(kind, v)].attribution)
    return f.resultat("sysmon+procmon" if procmon else "sysmon")


def load_lab_collection(chemin: Path, filtrer_bruit: bool = True) -> DynamicData:
    """Lit un dossier de collecte du labo (ou un dossier qui en contient un, ex. cases/T02)."""
    dossier = trouver_dossier(chemin)
    with (dossier / "sysmon.csv").open(encoding="utf-8-sig", newline="") as fh:
        sysmon = list(csv.DictReader(fh))
    procmon = load_procmon_csv(dossier / "procmon.csv") if (dossier / "procmon.csv").exists() else []
    echantillon = ""
    if (dossier / "manifeste.json").exists():
        echantillon = json.loads((dossier / "manifeste.json").read_text(encoding="utf-8-sig")).get("echantillon", "")
    return fusionner(sysmon, procmon, _racines(dossier, echantillon, sysmon, procmon),
                     echantillon=echantillon, filtrer_bruit=filtrer_bruit)
