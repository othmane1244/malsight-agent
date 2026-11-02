"""Construit le dossier de cas JSON unique à partir des sorties des outils."""
from __future__ import annotations

import re
from pathlib import Path

from malsight.extractors import dynamic, static
from malsight.schemas import Case, DynamicData

_RE = {
    "ip": re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
    "url": re.compile(r"\bhttps?://[^\s\"'<>]{4,}", re.I),
    "domain": re.compile(r"\b(?:[a-z0-9-]{1,63}\.)+(?:com|net|org|io|ru|cn|info|biz|xyz|local|lab)\b", re.I),
    "registry_key": re.compile(r"\b(?:HKLM|HKCU|HKEY_[A-Z_]+)\\[^\s\"']+", re.I),
    "file_path": re.compile(r"\b[A-Z]:\\[^\s\"'<>|]+", re.I),
}


def iocs_from_strings(strings: list[str]) -> dict[str, list[str]]:
    out: dict[str, set[str]] = {k: set() for k in _RE}
    for s in strings:
        for kind, rx in _RE.items():
            out[kind].update(rx.findall(s))
    return {k: sorted(v) for k, v in out.items() if v}


def build_case(sample: Path, cape_report: Path | None = None,
               yara_rules: Path | None = None, labo: Path | None = None) -> Case:
    """Dossier de cas : analyse statique de l'échantillon + données dynamiques déjà produites
    (rapport CAPE, ou dossier de collecte du labo sysmon.csv + procmon.csv)."""
    if cape_report and labo:
        raise ValueError("Donner un rapport CAPE ou un dossier du labo, pas les deux.")
    strings = static.extract_strings(sample)
    capa = static.run_capa(sample)
    dyn = DynamicData()
    if labo:
        from malsight.extractors.lab import load_lab_collection
        dyn = load_lab_collection(labo)
    if cape_report:
        dyn = dynamic.load_cape(cape_report)
        capa += static.run_capa(cape_report)   # dynamic capa sur le rapport CAPE
    return Case(
        sample=static.sample_info(sample),
        imports=static.pe_imports(sample),
        strings=strings,
        yara_matches=static.yara_scan(sample, yara_rules),
        capa=capa,
        dynamic=dyn,
        raw_iocs=iocs_from_strings(strings),
    )


def save_case(case: Case, cases_dir: Path = Path("cases")) -> Path:
    folder = cases_dir / case.sample.sha256
    folder.mkdir(parents=True, exist_ok=True)
    out = folder / "case.json"
    out.write_text(case.model_dump_json(indent=2), encoding="utf-8")
    return out
