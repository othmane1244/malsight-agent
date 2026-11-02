"""Outils exposés à l'agent. TOUS en lecture seule sur le dossier de cas.

Règle : ne jamais ajouter ici d'outil qui exécute, écrit ou contacte le réseau.
"""
from __future__ import annotations

from collections import Counter

from malsight.schemas import Case
from malsight.sensitive_apis import categorize


class CaseTools:
    def __init__(self, case: Case):
        self.case = case

    def get_overview(self) -> dict:
        c = self.case
        return {
            "sample": c.sample.model_dump(),
            "n_imports": sum(len(v) for v in c.imports.values()),
            "n_strings": len(c.strings),
            "n_capa_rules": len(c.capa),
            "dynamic_source": c.dynamic.source,
            "n_api_calls": len(c.dynamic.api_calls),
        }

    def get_sensitive_apis(self) -> list[dict]:
        found = {}
        for funcs in self.case.imports.values():
            for f in funcs:
                if (cat := categorize(f)):
                    found[f] = {"name": f, "category": cat, "source": "static_import"}
        for call in self.case.dynamic.api_calls:
            if (cat := categorize(call.api)) and call.api not in found:
                found[call.api] = {"name": call.api, "category": cat, "source": "dynamic_call"}
        return list(found.values())

    def get_capa_matches(self) -> list[dict]:
        return [m.model_dump() for m in self.case.capa]

    def get_iocs(self) -> dict[str, list[str]]:
        d = self.case.dynamic
        iocs = {k: list(v) for k, v in self.case.raw_iocs.items()}
        for key, vals in [("domain", d.domains), ("ip", d.ips), ("url", d.urls),
                          ("file_path", d.files_written), ("registry_key", d.registry_keys_set),
                          ("mutex", d.mutexes)]:
            iocs[key] = sorted(set(iocs.get(key, [])) | set(vals))
        return {k: v for k, v in iocs.items() if v}

    def get_dynamic_summary(self, top: int = 30, max_observations: int = 60) -> dict:
        d = self.case.dynamic
        if d.observations:
            # Labo (Sysmon + Procmon) : observations avec leur provenance, arbre de l'échantillon d'abord
            obs = sorted(d.observations, key=lambda o: o.attribution != "sample_tree")[:max_observations]
            return {
                "observations": [{"kind": o.kind, "value": o.value, "attribution": o.attribution,
                                  "sources": o.sources, "process": (o.processes or [""])[0]} for o in obs],
                "n_observations": len(d.observations),
                "top_api_calls": Counter(c.api for c in d.api_calls).most_common(top),
            }
        return {
            "top_api_calls": Counter(c.api for c in d.api_calls).most_common(top),
            "files_written": d.files_written[:50],
            "registry_keys_set": d.registry_keys_set[:50],
            "processes_created": d.processes_created[:20],
            "network": {"domains": d.domains, "ips": d.ips, "urls": d.urls[:20]},
        }

    def search_strings(self, pattern: str, limit: int = 20) -> list[str]:
        p = pattern.lower()
        return [s for s in self.case.strings if p in s.lower()][:limit]
