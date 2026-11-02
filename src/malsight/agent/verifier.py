"""Vérificateur : rejette toute affirmation du rapport sans appui dans le dossier de cas."""
from __future__ import annotations

import re

from malsight.agent.tools import CaseTools
from malsight.schemas import Case, Report
from malsight.sensitive_apis import categorize


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


# Valeurs vérifiables citées dans une preuve (le LLM les entoure souvent de JSON, guillemets...)
_FIN = r"[^\s\"'`<>|,;\[\]()«»]+"
_RE_PREUVE = [
    re.compile(r"\b(?:HKLM|HKCU|HKU|HKCR|HKEY_[A-Z_]+)\\" + _FIN, re.I),      # clé de registre
    re.compile(r"\b[A-Z]:\\" + _FIN, re.I),                                     # chemin Windows
    re.compile(r"\b(?:[a-z0-9-]{1,63}\.)+(?:com|net|org|io|ru|cn|info|biz|xyz|local|lab)\b", re.I),  # domaine
]
_RE_MOT = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]{3,}\b")


def valeurs_citees(evidence: str) -> list[str]:
    """Extrait d'une preuve les valeurs à vérifier : chemins, clés, domaines, noms d'API sensibles.

    Normalise l'échappement JSON (« \\\\ » -> « \\ ») et retire la ponctuation finale.
    """
    texte = evidence.replace("\\\\", "\\")
    valeurs: list[str] = []
    for rx in _RE_PREUVE:
        for v in rx.findall(texte):
            v = v.rstrip(".:!?\"'`»")
            if v and not any(v.lower() in w.lower() for w in valeurs):   # un domaine inclus dans un chemin
                valeurs.append(v)
    for mot in _RE_MOT.findall(texte):
        # Nom d'API : seulement les API connues, avec une majuscule (exclut « send », « connect »...)
        if categorize(mot) and any(c.isupper() for c in mot) and mot not in valeurs:
            valeurs.append(mot)
    return valeurs


def preuve_retrouvee(evidence: str, corpus: str) -> tuple[bool, list[str]]:
    """(retrouvée, valeurs manquantes). Toutes les valeurs citées doivent être dans le dossier de cas ;
    sans valeur reconnaissable, on revient à la recherche du texte mot pour mot."""
    valeurs = valeurs_citees(evidence)
    if not valeurs:
        ok = bool(evidence.strip()) and evidence.lower() in corpus
        return ok, [] if ok else [evidence]
    manquantes = [v for v in valeurs if v.lower() not in corpus]
    return not manquantes, manquantes


def _verify_countermeasures(report: Report, defend) -> list[str]:
    """D3FEND : tout ID absent du cache est rejeté, comme toute contre-mesure d'une technique non retenue."""
    rejected: list[str] = []
    connus = defend.known_ids() if defend is not None else set()
    retenues = {t.id for t in report.attack}
    kept = []
    for c in report.countermeasures:
        if c.id not in connus:
            rejected.append(f"ID D3FEND absent du cache : {c.id}")
        elif c.technique not in retenues:
            rejected.append(f"Contre-mesure {c.id} pour une technique non retenue : {c.technique}")
        elif not defend.covers(c.id, c.technique):
            rejected.append(f"D3FEND ne relie pas {c.id} à {c.technique}")
        else:
            kept.append(c)
    report.countermeasures = kept
    # Recommandations : un ID D3FEND absent du cache est RETIRÉ du texte (la recommandation reste)
    from malsight.defend.kb import D3ID
    kept_recs = []
    for rec in report.recommendations:
        inconnus = sorted({i for i in D3ID.findall(rec) if i not in connus})
        for i in inconnus:
            rejected.append(f"ID D3FEND absent du cache retiré d'une recommandation : {i}")
            rec = re.sub(r"\s*\(\s*" + re.escape(i) + r"\s*\)", "", rec)      # « (D3-XXX) »
            rec = re.sub(r"\b" + re.escape(i) + r"\b", "", rec)              # « D3-XXX » nu
        rec = re.sub(r"\(\s*[,;]?\s*\)", "", rec)                            # parenthèses vidées
        rec = re.sub(r"\s{2,}", " ", rec).replace(" .", ".").replace(" ,", ",").strip()
        if rec:
            kept_recs.append(rec)
    report.recommendations = kept_recs
    return rejected


def verify(report: Report, case: Case, kb=None, defend=None) -> Report:
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
            # Toujours le nom et la tactique officiels : jamais ceux écrits par le LLM
            nom_officiel = kb.name(t.id)
            if t.name and nom_officiel and t.name.strip().lower() != nom_officiel.lower() \
                    and nom_officiel.lower() not in t.name.lower():
                report.uncertainties.append(
                    f"Nom ATT&CK corrigé pour {t.id} : « {t.name} » -> « {nom_officiel} » (base officielle)")
            t.name = nom_officiel or t.name
            t.tactic = kb.tactic(t.id) or t.tactic
        seen.add(t.id)
        kept_attack.append(t)
    report.attack = kept_attack

    # Contre-mesures D3FEND et IDs D3FEND cités dans les recommandations
    rejected += _verify_countermeasures(report, defend)

    # Comportements "observed" : chaque valeur citée dans la preuve doit exister dans le dossier de cas
    for b in report.behaviors:
        if b.kind != "observed":
            continue
        ok, manquantes = preuve_retrouvee(b.evidence, corpus)
        if not ok:
            b.kind = "inferred"
            note = f"Preuve non retrouvée dans le dossier de cas ({', '.join(manquantes)}) : « {b.summary} »"
            if note not in report.uncertainties:
                report.uncertainties.append(note)

    report.rejected_claims += rejected
    return report
