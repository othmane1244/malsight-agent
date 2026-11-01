"""Parseurs de rapports d'analyse dynamique déjà produits (aucune exécution ici)."""
from __future__ import annotations

import json
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
