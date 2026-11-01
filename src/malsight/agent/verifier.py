"""Vérificateur : rejette toute affirmation du rapport sans appui dans le dossier de cas."""
from __future__ import annotations

from malsight.agent.tools import CaseTools
from malsight.schemas import Case, Report


def _strings(obj):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield str(k)
            yield from _strings(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            yield from _strings(v)
    elif obj is not None:
        yield str(obj)


def _case_text(case: Case) -> str:
    """Tout le texte brut du dossier de cas (sans échappement JSON), pour retrouver les preuves."""
    return "\n".join(_strings(case.model_dump())).lower()


def verify(report: Report, case: Case, kb=None) -> Report:
    tools = CaseTools(case)
    corpus = _case_text(case)
    rejected: list[str] = []

    # IOC : la valeur doit exister dans le dossier de cas
    hashes = {case.sample.sha256, case.sample.md5}
    kept_iocs = []
    for ioc in report.iocs:
        if ioc.value in hashes or ioc.value.lower() in corpus:
            kept_iocs.append(ioc)
        else:
            rejected.append(f"IOC sans preuve : {ioc.type}={ioc.value}")
    report.iocs = kept_iocs

    # API sensibles : doivent être importées ou appelées
    known = {a["name"] for a in tools.get_sensitive_apis()}
    kept_apis = [a for a in report.sensitive_apis if a.name in known]
    rejected += [f"API non observée : {a.name}" for a in report.sensitive_apis if a.name not in known]
    report.sensitive_apis = kept_apis

    # ATT&CK : ID valide dans la base officielle + preuve non vide
    kept_attack, seen = [], set()
    for t in report.attack:
        if t.id in seen:
            continue
        if kb is not None and not kb.is_valid(t.id):
            rejected.append(f"ID ATT&CK inexistant : {t.id}")
            continue
        if not t.evidence.strip():
            rejected.append(f"Technique sans preuve : {t.id}")
            continue
        if kb is not None:
            t.name = t.name or kb.name(t.id)
            t.tactic = t.tactic or kb.tactic(t.id)
        seen.add(t.id)
        kept_attack.append(t)
    report.attack = kept_attack

    # Comportements "observed" : la preuve doit apparaître dans les données
    for b in report.behaviors:
        if b.kind == "observed" and b.evidence.lower() not in corpus:
            b.kind = "inferred"
            report.uncertainties.append(f"Preuve non retrouvée telle quelle : « {b.evidence} »")

    report.rejected_claims += rejected
    return report
