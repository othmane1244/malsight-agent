"""Modèles de données : le dossier de cas (entrée de l'agent) et le rapport (sortie)."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


# ---------- Dossier de cas : faits extraits par les outils ----------

class SampleInfo(BaseModel):
    filename: str
    sha256: str
    md5: str
    size: int
    file_type: str = "unknown"


class CapaMatch(BaseModel):
    rule: str
    namespace: str | None = None
    attack_ids: list[str] = Field(default_factory=list)   # ex. ["T1547.001"]
    mbc: list[str] = Field(default_factory=list)


class ApiCall(BaseModel):
    api: str
    process: str | None = None
    args: dict[str, str] = Field(default_factory=dict)


class Observation(BaseModel):
    """Un élément dynamique observé, avec sa provenance (labo : fusion Sysmon + Procmon)."""
    kind: Literal["process", "file", "registry", "domain", "ip"]
    value: str
    sources: list[str] = Field(default_factory=list)       # "sysmon", "procmon"
    operations: list[str] = Field(default_factory=list)    # ex. "EID 13", "RegSetValue"
    processes: list[str] = Field(default_factory=list)     # ex. "svchost.exe (1448)"
    attribution: Literal["sample_tree", "service_window"] = "sample_tree"


class DynamicData(BaseModel):
    source: str = "none"                                  # "cape", "sysmon", "sysmon+procmon", ...
    observations: list[Observation] = Field(default_factory=list)   # détail et provenance
    api_calls: list[ApiCall] = Field(default_factory=list)
    files_written: list[str] = Field(default_factory=list)
    registry_keys_set: list[str] = Field(default_factory=list)
    processes_created: list[str] = Field(default_factory=list)
    mutexes: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    ips: list[str] = Field(default_factory=list)
    urls: list[str] = Field(default_factory=list)


class Case(BaseModel):
    """Tout ce que l'agent a le droit de lire. Rien d'autre."""
    sample: SampleInfo
    imports: dict[str, list[str]] = Field(default_factory=dict)   # dll -> fonctions
    strings: list[str] = Field(default_factory=list)
    yara_matches: list[str] = Field(default_factory=list)
    capa: list[CapaMatch] = Field(default_factory=list)
    dynamic: DynamicData = Field(default_factory=DynamicData)
    raw_iocs: dict[str, list[str]] = Field(default_factory=dict)  # type -> valeurs


# ---------- Rapport : synthèse produite par l'agent ----------

Confidence = Literal["high", "medium", "low"]


class Behavior(BaseModel):
    summary: str
    evidence: str            # référence vers un fait du dossier de cas
    kind: Literal["observed", "inferred"] = "observed"


class IOC(BaseModel):
    type: Literal["sha256", "md5", "domain", "ip", "url", "file_path", "registry_key", "mutex"]
    value: str
    source: str


class SensitiveApi(BaseModel):
    name: str
    category: str
    source: Literal["static_import", "dynamic_call"]


class AttackTechnique(BaseModel):
    id: str
    name: str = ""
    tactic: str = ""
    source: Literal["capa", "llm"]
    confidence: Confidence
    evidence: str


class Report(BaseModel):
    sample: SampleInfo
    executive_summary: str = ""
    behaviors: list[Behavior] = Field(default_factory=list)
    iocs: list[IOC] = Field(default_factory=list)
    sensitive_apis: list[SensitiveApi] = Field(default_factory=list)
    attack: list[AttackTechnique] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    uncertainties: list[str] = Field(default_factory=list)
    rejected_claims: list[str] = Field(default_factory=list)   # rempli par le vérificateur
