"""Parseur du procmon.csv produit par le labo (lab/scripts/collect.ps1). Lecture seule.

Le CSV de Procmon suit les réglages régionaux de Windows :
- « Time of Day » : heure sans date, virgule ou point décimal, parfois AM/PM
  (« 12:05:22,0453416 », « 12:05:22.0453416 », « 1:05:22.0453416 PM ») ;
- nombres du champ Detail avec séparateur de milliers variable (« 8 080 », « 8,080 », « 8.080 »,
  espaces insécables).
Seules les opérations utiles sont gardées : écritures réussies (registre, fichiers),
création/démarrage/fin de processus et connexions réseau.
"""
from __future__ import annotations

import csv
import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path

_HEURE = re.compile(r"^\s*(\d{1,2}):(\d{2}):(\d{2})(?:[.,](\d+))?\s*([AaPp][Mm])?\s*$")
# Entier avec séparateur de milliers optionnel (espace, espace insécable, virgule, point)
_ENTIER = r"(\d{1,3}(?:[   ,.]\d{3})+|\d+)"
_PID = re.compile(r"(?<![\w ])PID:\s*" + _ENTIER + r"(?=,\s|$)")
_PID_PARENT = re.compile(r"Parent PID:\s*" + _ENTIER + r"(?=,\s|$)")
_LIGNE_CMD = re.compile(r"Command line:\s*(.*?)(?:, Current directory:|, Environment:|$)")
_RENOMME = re.compile(r"FileName:\s*(.+?)(?:, |$)")

# Outils du labo (Procmon ne donne que le nom du processus, pas son chemin)
OUTILS_LABO = {"procmon.exe", "procmon64.exe", "procmon64a.exe", "sysmon.exe", "sysmon64.exe", "sysmon64a.exe"}
PROCESSUS_IGNORES = {"system", "idle"}          # écritures différées du cache disque (PID 4)

ECRITURES_REGISTRE = {"RegSetValue", "RegCreateKey"}
ECRITURES_FICHIER = {"WriteFile", "SetRenameInformationFile", "SetEndOfFileInformationFile", "CreateFile"}
PROCESSUS = {"Process Create", "Process Start", "Process Exit"}
RESEAU = {"TCP Connect", "TCP Send", "UDP Send"}


def heure_en_secondes(texte: str) -> float | None:
    """« 12:05:22,0453416 » / « 1:05:22.0453416 PM » -> secondes depuis minuit."""
    m = _HEURE.match(texte or "")
    if not m:
        return None
    h, mi, s, frac, ampm = m.groups()
    h = int(h)
    if ampm:
        h = h % 12 + (12 if ampm.lower() == "pm" else 0)
    return h * 3600 + int(mi) * 60 + int(s) + (float("0." + frac) if frac else 0.0)


def entier_local(texte: str) -> int:
    """« 8 080 », « 8,080 », « 8.080 », « 8080 » -> 8080 (entiers seulement)."""
    return int(re.sub(r"\D", "", texte))


@dataclass
class EvenementProcmon:
    t: float                 # secondes depuis minuit (horloge locale de la sandbox)
    processus: str           # nom de l'image, ex. « svchost.exe »
    pid: int
    operation: str
    chemin: str
    detail: str
    pid_enfant: int | None = None      # Process Create
    pid_parent: int | None = None      # Process Start
    ligne_commande: str = ""

    @property
    def nature(self) -> str:
        """« registry », « file », « process », « network »."""
        if self.operation in ECRITURES_REGISTRE:
            return "registry"
        if self.operation in ECRITURES_FICHIER:
            return "file"
        if self.operation in PROCESSUS:
            return "process"
        return "network"


def _est_ecriture_fichier(op: str, detail: str) -> bool:
    if op != "CreateFile":
        return True
    # CreateFile n'est une écriture que si le fichier a été créé ou écrasé
    return bool(re.search(r"OpenResult:\s*(Created|Overwritten|Superseded)", detail))


def parse_procmon_rows(rows: Iterable[dict[str, str]]) -> Iterator[EvenementProcmon]:
    """Ne garde que les opérations utiles et réussies ; exclut outils du labo et cache disque."""
    precedent, jour = None, 0.0
    for r in rows:
        op = r.get("Operation", "")
        if op not in ECRITURES_REGISTRE | ECRITURES_FICHIER | PROCESSUS | RESEAU:
            continue
        if r.get("Result") != "SUCCESS":
            continue
        processus = r.get("Process Name", "")
        if processus.lower() in OUTILS_LABO | PROCESSUS_IGNORES:
            continue
        detail = r.get("Detail", "") or ""
        if op == "RegCreateKey" and "REG_CREATED_NEW_KEY" not in detail:
            continue                                    # simple ouverture d'une clé existante
        if op in ECRITURES_FICHIER and not _est_ecriture_fichier(op, detail):
            continue
        t = heure_en_secondes(r.get("Time of Day", ""))
        if t is None:
            continue
        if precedent is not None and t + jour < precedent - 43200:
            jour += 86400                               # passage de minuit pendant la capture
        t += jour
        precedent = t
        ev = EvenementProcmon(t=t, processus=processus, pid=entier_local(r.get("PID", "0") or "0"),
                              operation=op, chemin=r.get("Path", "") or "", detail=detail)
        if op == "Process Create" and (m := _PID.search(detail)):
            ev.pid_enfant = entier_local(m.group(1))
        if op == "Process Start" and (m := _PID_PARENT.search(detail)):
            ev.pid_parent = entier_local(m.group(1))
        if op in ("Process Create", "Process Start") and (m := _LIGNE_CMD.search(detail)):
            ev.ligne_commande = m.group(1).strip()
        if op == "SetRenameInformationFile" and (m := _RENOMME.search(detail)):
            ev.chemin = m.group(1).strip()              # destination du renommage
        yield ev


def load_procmon_csv(path: Path) -> list[EvenementProcmon]:
    with path.open(encoding="utf-8-sig", newline="") as f:
        return list(parse_procmon_rows(csv.DictReader(f)))
