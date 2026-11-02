"""Règles déterministes artefact -> technique ATT&CK (décision D7).

Chaque règle est GÉNÉRIQUE et SOURCÉE (page ATT&CK de la technique ou règle Sigma publique) :
les artefacts (clés, dossiers, exécutables, options) sont repris des sources, pas d'un échantillon.
Elles ne couvrent que des techniques du jeu de développement (T01 à T12) ; aucune règle n'a été
écrite pour les techniques propres au jeu de validation (T13 à T16, D4).

Une règle s'applique aux observations dynamiques déjà attribuées à l'échantillon (arbre de
processus ou service intermédiaire, voir extractors/lab.py) : jamais au bruit filtré.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from malsight.schemas import AttackTechnique, DynamicData

SIGMA = "https://github.com/SigmaHQ/sigma/blob/master/"
ATTACK = "https://attack.mitre.org/techniques/"


@dataclass(frozen=True)
class Regle:
    id: str
    technique: str
    kind: str                      # "registry", "file", "process"
    motif: re.Pattern
    description: str
    sources: tuple[str, ...]


def _r(motif: str) -> re.Pattern:
    return re.compile(motif, re.I)


# Exécutables : nom d'image en début de ligne de commande (avec ou sans guillemets / chemin)
def _exe(*noms: str) -> str:
    return r'^\s*"?(?:[^"]*\\)?(?:' + "|".join(re.escape(n) for n in noms) + r')"?(?=\s|$)'


REGLES: tuple[Regle, ...] = (
    Regle("R-T1547.001-registre", "T1547.001", "registry",
          _r(r"\\Software\\(?:WOW6432Node\\)?Microsoft\\Windows\\CurrentVersion\\"
             r"(?:Run|RunOnce|RunOnceEx|RunServices|RunServicesOnce)\\"),
          "Valeur écrite sous une clé Run / RunOnce (HKCU ou HKLM)",
          (ATTACK + "T1547/001/",
           SIGMA + "rules/windows/registry/registry_set/registry_set_asep_reg_keys_modification_currentversion.yml")),
    Regle("R-T1547.001-demarrage", "T1547.001", "file",
          _r(r"\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\"),
          "Fichier écrit dans un dossier de démarrage (Startup)",
          (ATTACK + "T1547/001/",)),
    Regle("R-T1053.005-fichier", "T1053.005", "file",
          _r(r"^[A-Z]:\\Windows\\(?:System32|SysWOW64)\\Tasks\\"),
          "Fichier de tâche planifiée créé dans Windows\\System32\\Tasks",
          (ATTACK + "T1053/005/", SIGMA + "rules/windows/file/file_event/file_event_win_susp_task_write.yml")),
    Regle("R-T1053.005-registre", "T1053.005", "registry",
          _r(r"\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\(?:Tree|Tasks)\\"),
          "Entrée créée dans le cache des tâches planifiées (TaskCache)",
          (ATTACK + "T1053/005/", SIGMA + "rules/windows/registry/registry_set/registry_set_taskcache_entry.yml")),
    Regle("R-T1053.005-schtasks", "T1053.005", "process",
          _r(_exe("schtasks.exe", "schtasks") + r".*\s/create\b"),
          "Création de tâche par schtasks.exe /create",
          (SIGMA + "rules/windows/process_creation/proc_creation_win_schtasks_creation.yml",)),
    Regle("R-T1543.003-registre", "T1543.003", "registry",
          _r(r"^HKLM\\System\\CurrentControlSet\\Services\\[^\\]+\\ImagePath$"),
          "Valeur ImagePath d'un service écrite (création ou modification de service)",
          (ATTACK + "T1543/003/",
           SIGMA + "rules/windows/registry/registry_set/registry_set_asep_reg_keys_modification_currentcontrolset.yml")),
    Regle("R-T1543.003-sc", "T1543.003", "process",
          _r(_exe("sc.exe", "sc") + r".*\bcreate\b"),
          "Création de service par sc.exe create",
          (SIGMA + "rules/windows/process_creation/proc_creation_win_sc_create_service.yml",)),
    Regle("R-T1037.001-registre", "T1037.001", "registry",
          _r(r"^HKCU\\Environment\\UserInitMprLogonScript$"),
          "Script de logon déclaré dans HKCU\\Environment\\UserInitMprLogonScript",
          (ATTACK + "T1037/001/",
           SIGMA + "rules/windows/registry/registry_set/registry_set_persistence_logon_scripts_userinitmprlogonscript.yml")),
    Regle("R-T1082-processus", "T1082", "process",
          _r(_exe("systeminfo.exe", "systeminfo", "hostname.exe", "hostname")),
          "Découverte du système : systeminfo.exe ou hostname.exe",
          (ATTACK + "T1082/",
           SIGMA + "rules/windows/process_creation/proc_creation_win_systeminfo_execution.yml",
           SIGMA + "rules/windows/process_creation/proc_creation_win_hostname_execution.yml")),
    Regle("R-T1016-processus", "T1016", "process",
          _r(_exe("ipconfig.exe", "ipconfig", "route.exe", "route", "arp.exe", "arp", "nbtstat.exe", "nbtstat")
             + r"|" + _exe("netsh.exe", "netsh") + r".*\binterface\s+(?:show|ip\s+show)"),
          "Découverte de la configuration réseau : ipconfig, route, arp, nbtstat, netsh interface show",
          (ATTACK + "T1016/",
           SIGMA + "rules/windows/process_creation/proc_creation_win_susp_network_command.yml")),
    Regle("R-T1059.001-encodee", "T1059.001", "process",
          _r(_exe("powershell.exe", "powershell", "pwsh.exe", "pwsh")
             + r".*\s-(?:e|ec|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|"
               r"encodedcomma|encodedcomman|encodedcommand)\s"),
          "PowerShell lancé avec une commande encodée (-EncodedCommand et ses abréviations)",
          (ATTACK + "T1059/001/",
           SIGMA + "rules/windows/process_creation/proc_creation_win_powershell_encode.yml")),
    Regle("R-T1560-archive", "T1560", "file",
          _r(r"\.(?:zip|7z|rar|cab|tar|gz|tgz)$"),
          "Archive créée par l'échantillon (collecte puis archivage de données)",
          (ATTACK + "T1560/",)),
)


CREATIONS = {"RegCreateKey", "CreateFile", "EID 11", "EID 12"}   # opérations qui créent un artefact


def _cree_pendant_l_analyse(o, crees: set[str]) -> bool:
    """L'artefact, ou l'une de ses clés / dossiers parents, a été créé pendant l'analyse."""
    v = o.value.lower()
    return v in crees or any(v.startswith(c + "\\") for c in crees)


def appliquer(dyn: DynamicData, regles: tuple[Regle, ...] = REGLES) -> list[AttackTechnique]:
    """Techniques ATT&CK déduites des observations, avec la règle et l'artefact en preuve.

    Écriture d'un service intermédiaire (`service_window`) : la règle ne s'applique que si
    l'artefact ou un parent a été CRÉÉ pendant l'analyse. Un service qui met à jour l'état d'un
    objet existant (ex. dernière exécution d'une tâche système) n'est pas une action de
    l'échantillon ; enregistrer une tâche ou un service crée, lui, de nouvelles clés.
    """
    crees = {o.value.lower().rstrip("\\") for o in dyn.observations if CREATIONS & set(o.operations)}
    trouvees: dict[str, AttackTechnique] = {}
    for o in dyn.observations:
        for r in regles:
            if r.kind != o.kind or not r.motif.search(o.value):
                continue
            if o.attribution == "service_window" and o.kind != "process" and not _cree_pendant_l_analyse(o, crees):
                continue
            if r.technique in trouvees:
                continue
            processus = f" ({', '.join(o.processes[:1])})" if o.processes else ""
            trouvees[r.technique] = AttackTechnique(
                id=r.technique, source="rule", confidence="high",
                evidence=f"règle {r.id} : {o.value}{processus}")
    return list(trouvees.values())
