"""Orchestration : faits déterministes -> LLM (option) -> vérificateur.

Version de départ volontairement simple et linéaire. En phase 4, elle pourra devenir
un graphe LangGraph (planificateur / outils / RAG / vérificateur) avec état sur disque.
"""
from __future__ import annotations

import json
import os

from pydantic import BaseModel, Field

from malsight.agent import prompts, verifier
from malsight.agent.tools import CaseTools
from malsight.schemas import (IOC, AttackTechnique, Behavior, Case, Countermeasure,
                              Report, SensitiveApi)


class LLMDraft(BaseModel):
    """Étape 1 : ce que le LLM a le droit de remplir. Le reste vient des outils."""
    executive_summary: str = ""
    behaviors: list[Behavior] = Field(default_factory=list)
    attack: list[AttackTechnique] = Field(default_factory=list)
    uncertainties: list[str] = Field(default_factory=list)


class LLMRecommendations(BaseModel):
    """Étape 2 : recommandations rédigées à partir des techniques retenues et des contre-mesures D3FEND."""
    recommendations: list[str] = Field(default_factory=list)


def deterministic_report(case: Case, tools: CaseTools, regles: bool = False) -> Report:
    """Partie du rapport qui ne dépend d'aucun LLM : IOC, API, capa et (option) règles D7."""
    report = Report(sample=case.sample)
    report.iocs = [IOC(type="sha256", value=case.sample.sha256, source="fichier"),
                   IOC(type="md5", value=case.sample.md5, source="fichier")]
    for kind, values in tools.get_iocs().items():
        report.iocs += [IOC(type=kind, value=v, source="extraction") for v in values]
    report.sensitive_apis = [SensitiveApi(**a) for a in tools.get_sensitive_apis()]
    for m in case.capa:
        for tid in m.attack_ids:
            report.attack.append(AttackTechnique(id=tid, source="capa", confidence="high",
                                                 evidence=f"règle capa : {m.rule}"))
    if regles:
        from malsight.attack.regles import appliquer
        report.attack += appliquer(case.dynamic)
    return report


def _fiche(kb, tid: str, n: int = 300) -> dict:
    """Nom et début de la description officielle d'une technique (contexte du LLM)."""
    if kb is None or not getattr(kb, "techniques", None) or tid not in kb.techniques:
        return {"id": tid}
    t = kb.techniques[tid]
    return {"id": tid, "name": t["name"], "description": " ".join(t.get("description", "").split())[:n]}


def _llm():
    provider = os.getenv("LLM_PROVIDER", "ollama")
    model = os.getenv("LLM_MODEL", "gemma4:e4b")
    if provider == "ollama":
        from langchain_ollama import ChatOllama
        # Valeurs explicites : le contexte par défaut d'Ollama (4096 tokens) est partagé entre le
        # prompt et la réponse, et la génération n'a pas de limite (risque de boucle en sortie JSON).
        return ChatOllama(model=model, temperature=0.1,
                          base_url=os.getenv("OLLAMA_HOST", "http://localhost:11434"),
                          num_ctx=int(os.getenv("LLM_NUM_CTX", "8192")),
                          num_predict=int(os.getenv("LLM_NUM_PREDICT", "2048")),
                          client_kwargs={"timeout": float(os.getenv("LLM_TIMEOUT_S", "600"))})
    if provider == "anthropic":
        from langchain_anthropic import ChatAnthropic
        return ChatAnthropic(model=model, temperature=0.1)
    raise ValueError(f"LLM_PROVIDER inconnu : {provider}")


def countermeasures_for(report: Report, defend, par_technique: int = 12) -> list[Countermeasure]:
    """Contre-mesures D3FEND des techniques retenues, lues dans le cache local (jamais par le LLM)."""
    if defend is None:
        return []
    out, vus = [], set()
    for t in report.attack:
        for c in defend.countermeasures(t.id)[:par_technique]:
            if (c.id, c.technique) not in vus:
                vus.add((c.id, c.technique))
                out.append(c)
    return out


def llm_recommendations(report: Report, llm=None) -> list[str]:
    """Étape 2 : le LLM rédige les recommandations avec les contre-mesures D3FEND en contexte."""
    techniques = [{"id": t.id, "name": t.name, "evidence": t.evidence} for t in report.attack]
    contre_mesures = {}
    for c in report.countermeasures:
        contre_mesures.setdefault(c.technique, []).append(
            {"id": c.id, "name": c.name, "tactic": c.tactic, "artifact": c.artifact})
    user = prompts.RECOMMANDATIONS_TEMPLATE.format(
        techniques=json.dumps(techniques, ensure_ascii=False, indent=1) if techniques else "aucune",
        countermeasures=json.dumps(contre_mesures, ensure_ascii=False, indent=1) if contre_mesures else "aucune",
        iocs=json.dumps([{"type": i.type, "value": i.value} for i in report.iocs][:40], ensure_ascii=False))
    llm = (llm or _llm()).with_structured_output(LLMRecommendations)
    return llm.invoke([("system", prompts.SYSTEM_PROMPT), ("user", user)]).recommendations


def llm_draft(case: Case, tools: CaseTools, report: Report, kb=None, llm=None) -> LLMDraft:
    facts = {
        "overview": tools.get_overview(),
        "sensitive_apis": tools.get_sensitive_apis(),
        "capa_rules": [m.rule for m in case.capa],
        "dynamic": tools.get_dynamic_summary(),
        "iocs": tools.get_iocs(),
    }
    identifiees = [_fiche(kb, t.id) | {"source": t.source, "evidence": t.evidence} for t in report.attack]
    candidates = []
    if kb is not None:
        query = " ".join([m.rule for m in case.capa] + [a["category"] for a in facts["sensitive_apis"]])
        deja = {t.id for t in report.attack}
        candidates = [_fiche(kb, tid) for tid, _ in kb.search(query, k=8) if tid not in deja]
    user = prompts.USER_TEMPLATE.format(
        facts=json.dumps(facts, ensure_ascii=False, indent=1, default=str)[:60000],
        capa_attack=json.dumps(identifiees, ensure_ascii=False, indent=1) if identifiees else "aucune",
        candidates=json.dumps(candidates, ensure_ascii=False, indent=1) if candidates else "aucune")
    llm = (llm or _llm()).with_structured_output(LLMDraft)
    return llm.invoke([("system", prompts.SYSTEM_PROMPT), ("user", user)])


def analyze(case: Case, use_llm: bool = True, kb=None, defend=None, llm=None, regles: bool = False) -> Report:
    """1. faits déterministes (et règles D7 si `regles`) ; 2. brouillon LLM (résumé, comportements,
    ATT&CK) ; 3. vérification ; 4. contre-mesures D3FEND des techniques retenues (cache local) ;
    5. recommandations LLM avec ces contre-mesures en contexte ; 6. vérification finale.
    Modes d'évaluation : llm (use_llm, sans règles), regles (règles seules), hybride (les deux)."""
    tools = CaseTools(case)
    report = deterministic_report(case, tools, regles=regles)
    if use_llm:
        draft = llm_draft(case, tools, report, kb, llm=llm)
        report.executive_summary = draft.executive_summary
        report.behaviors = draft.behaviors
        # D10 : les techniques du LLM sont des suggestions à valider, jamais la liste officielle
        report.suggestions = [t.model_copy(update={"source": "llm",
                                                   "confidence": "low" if t.confidence == "low" else "medium"})
                              for t in draft.attack]
        report.uncertainties = draft.uncertainties
    else:
        report.executive_summary = "Rapport généré sans LLM : faits extraits uniquement."
    report = verifier.verify(report, case, kb)              # techniques retenues avant D3FEND
    report.countermeasures = countermeasures_for(report, defend)
    if use_llm:
        report.recommendations = llm_recommendations(report, llm=llm)
    return verifier.verify(report, case, kb, defend)
