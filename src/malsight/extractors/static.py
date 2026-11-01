"""Analyse statique : hachages, imports, chaînes, YARA, capa.

Aucune de ces fonctions n'exécute l'échantillon : elles lisent le fichier.
"""
from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path

from malsight.schemas import CapaMatch, SampleInfo

_ASCII = re.compile(rb"[\x20-\x7e]{5,}")
_UTF16 = re.compile(rb"(?:[\x20-\x7e]\x00){5,}")


def sample_info(path: Path) -> SampleInfo:
    data = path.read_bytes()
    ftype = "PE" if data[:2] == b"MZ" else ("ELF" if data[:4] == b"\x7fELF" else "unknown")
    return SampleInfo(
        filename=path.name,
        sha256=hashlib.sha256(data).hexdigest(),
        md5=hashlib.md5(data).hexdigest(),
        size=len(data),
        file_type=ftype,
    )


def pe_imports(path: Path) -> dict[str, list[str]]:
    """Table d'import d'un PE (vide si ce n'est pas un PE ou si pefile échoue)."""
    try:
        import pefile
    except ImportError:
        return {}
    try:
        pe = pefile.PE(str(path), fast_load=True)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
        )
    except pefile.PEFormatError:
        return {}
    imports: dict[str, list[str]] = {}
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        dll = entry.dll.decode(errors="replace").lower()
        imports[dll] = [i.name.decode(errors="replace") for i in entry.imports if i.name]
    return imports


def extract_strings(path: Path, limit: int = 5000) -> list[str]:
    """Chaînes ASCII et UTF-16. Utilise FLOSS s'il est installé (chaînes désobfusquées)."""
    if shutil.which("floss"):
        try:
            out = subprocess.run(
                ["floss", "-j", "-q", str(path)], capture_output=True, text=True, timeout=300
            )
            doc = json.loads(out.stdout)
            s = doc.get("strings", {})
            found = [x["string"] for kind in s.values() for x in kind if isinstance(x, dict)]
            if found:
                return found[:limit]
        except (subprocess.SubprocessError, json.JSONDecodeError, KeyError):
            pass
    data = path.read_bytes()
    found = [m.decode() for m in _ASCII.findall(data)]
    found += [m.decode("utf-16le") for m in _UTF16.findall(data)]
    return list(dict.fromkeys(found))[:limit]


def yara_scan(path: Path, rules_dir: Path | None) -> list[str]:
    if not rules_dir or not rules_dir.exists():
        return []
    import yara
    files = {p.stem: str(p) for p in rules_dir.rglob("*.yar")}
    if not files:
        return []
    rules = yara.compile(filepaths=files)
    return [m.rule for m in rules.match(str(path))]


def parse_capa_json(doc: dict) -> list[CapaMatch]:
    """Convertit la sortie `capa -j` (statique ou dynamique) en CapaMatch."""
    matches = []
    for name, rule in doc.get("rules", {}).items():
        meta = rule.get("meta", {})
        attack = []
        for a in meta.get("attack", []):
            tid = a.get("id") or (a.get("parts") or [""])[-1]
            if tid:
                attack.append(tid.split(" ")[-1].strip("[]"))
        mbc = [m.get("id", "") for m in meta.get("mbc", []) if m.get("id")]
        matches.append(CapaMatch(rule=name, namespace=meta.get("namespace"),
                                 attack_ids=attack, mbc=mbc))
    return matches


def run_capa(target: Path) -> list[CapaMatch]:
    """Lance capa sur un binaire OU sur un rapport CAPE (.json) : capa détecte le format."""
    if not shutil.which("capa"):
        return []
    out = subprocess.run(["capa", "-j", str(target)], capture_output=True, text=True, timeout=900)
    if out.returncode != 0:
        return []
    return parse_capa_json(json.loads(out.stdout))
