"""Parseurs de rapports d'analyse dynamique déjà produits (aucune exécution ici)."""
from __future__ import annotations

import csv
import json
import re
from collections.abc import Iterable
from pathlib import Path

from malsight.schemas import ApiCall, DynamicData


def _as_list(x) -> list:
    return x if isinstance(x, list) else []


def parse_cape(doc: dict, max_calls: int = 20000) -> DynamicData:
    """Extrait les éléments utiles d'un rapport JSON CAPEv2."""
    behavior = doc.get("behavior", {}) or {}
    summary = behavior.get("summary", {}) or {}
    network = doc.get("network", {}) or {}

    calls: list[ApiCall] = []
    for proc in _as_list(behavior.get("processes")):
        pname = proc.get("process_name")
        for call in _as_list(proc.get("calls")):
            if len(calls) >= max_calls:
                break
            args = {a.get("name", ""): str(a.get("value", ""))
                    for a in _as_list(call.get("arguments")) if isinstance(a, dict)}
            calls.append(ApiCall(api=call.get("api", ""), process=pname, args=args))

    hosts = [h.get("ip") if isinstance(h, dict) else h for h in _as_list(network.get("hosts"))]
    return DynamicData(
        source="cape",
        api_calls=calls,
        files_written=_as_list(summary.get("write_files")),
        registry_keys_set=_as_list(summary.get("write_keys")),
        processes_created=_as_list(summary.get("executed_commands")),
        mutexes=_as_list(summary.get("mutexes")),
        domains=[d.get("domain") for d in _as_list(network.get("domains")) if d.get("domain")],
        ips=[h for h in hosts if h],
        urls=[h.get("uri") for h in _as_list(network.get("http")) if h.get("uri")],
    )


def load_cape(path: Path) -> DynamicData:
    return parse_cape(json.loads(path.read_text(encoding="utf-8", errors="replace")))


# ---------- Sysmon (labo Windows Sandbox, décision D1) ----------

# Outils du labo : leurs événements ne concernent pas l'échantillon.
LAB_TOOL_IMAGES = re.compile(
    r"^(?:C:\\labo-outils\\|C:\\Windows\\Sysmon(?:64)?a?\.exe$)", re.I)

_HKU_USER_CLASSES = re.compile(r"^HKU\\S-1-5-21-[\d-]+_Classes(?=\\|$)", re.I)
_HKU_USER = re.compile(r"^HKU\\S-1-5-21-[\d-]+(?=\\|$)", re.I)
_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")


def normalize_registry_key(key: str) -> str:
    r"""Ramène une clé Sysmon d'utilisateur à la forme de la vérité terrain.

    ``HKU\<SID utilisateur>\X`` devient ``HKCU\X`` et ``HKU\<SID>_Classes\X``
    devient ``HKCU\Software\Classes\X``. Les comptes système (``HKU\S-1-5-18``,
    ``HKU\.DEFAULT``) et les autres ruches restent inchangés.
    """
    key = _HKU_USER_CLASSES.sub(r"HKCU\\Software\\Classes", key)
    return _HKU_USER.sub("HKCU", key)


def _unique(values: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(v for v in values if v and v != "-"))


def parse_sysmon_rows(rows: Iterable[dict[str, str]], exclude_lab_tools: bool = True) -> DynamicData:
    """Extrait les éléments utiles d'événements Sysmon (une ligne par événement).

    Les colonnes sont celles produites par ``lab/scripts/collect.ps1`` (``EventID`` +
    champs EventData). La colonne ``Task`` n'est pas utilisée : elle est mal renseignée.
    - EID 1 : processus créés (ligne de commande) ;
    - EID 11 : fichiers créés ;
    - EID 12 (CreateKey) et 13 (SetValue) : clés de registre, normalisées en ``HKCU`` ;
    - EID 22 : domaines demandés (noms avec un point) et IPv4 des réponses ;
    - EID 3 : destinations réseau (IP, nom d'hôte).
    """
    procs, files, keys, domains, ips = [], [], [], [], []
    for r in rows:
        image = r.get("Image") or ""
        if exclude_lab_tools and LAB_TOOL_IMAGES.match(image):
            continue
        eid = (r.get("EventID") or "").strip()
        if eid == "1":
            procs.append(r.get("CommandLine") or image)
        elif eid == "11":
            files.append(r.get("TargetFilename", ""))
        elif eid == "13" or (eid == "12" and r.get("EventType") == "CreateKey"):
            keys.append(normalize_registry_key(r.get("TargetObject", "")))
        elif eid == "22":
            name = (r.get("QueryName") or "").strip().rstrip(".")
            if "." in name:
                domains.append(name.lower())
            ips += _IPV4.findall(r.get("QueryResults") or "")
        elif eid == "3":
            ips.append(r.get("DestinationIp", ""))
            host = (r.get("DestinationHostname") or "").strip()
            if "." in host:
                domains.append(host.lower())
    return DynamicData(
        source="sysmon",
        processes_created=_unique(procs),
        files_written=_unique(files),
        registry_keys_set=_unique(keys),
        domains=_unique(domains),
        ips=_unique(ips),
    )


def load_sysmon_csv(path: Path, exclude_lab_tools: bool = True) -> DynamicData:
    """Lit le ``sysmon.csv`` d'une collecte du labo (UTF-8, avec ou sans BOM)."""
    with path.open(encoding="utf-8-sig", newline="") as f:
        return parse_sysmon_rows(csv.DictReader(f), exclude_lab_tools)
