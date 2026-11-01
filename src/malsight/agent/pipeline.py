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
from malsight.schemas import (IOC, AttackTechnique, Behavior, Case, Report,
                              SensitiveApi)


class LLMDraft(BaseModel):
    """Ce que le LLM a le droit de remplir. Le reste vient des outils."""
    executive_summary: str = ""
    behaviors: list[Behavior] = Field(default_factory=list)
    attack: list[AttackTechnique] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    uncertainties: list[str] = Field(default_factory=list)


def deterministic_report(case: Case, tools: CaseTools) -> Report:
    """Partie du rapport qui ne dépend d'aucun LLM."""
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
    return report


def _llm():
    provider = os.getenv("LLM_PROVIDER", "ollama")
    model = os.getenv("LLM_MODEL", "qwen2.5:14b")
    if provider == "ollama":
        from langchain_ollama import ChatOllama
        return ChatOllama(model=model, temperature=0.1,
                          base_url=os.getenv("OLLAMA_HOST", "http://localhost:11434"))
    if provider == "anthropic":
        from langchain_anthropic import ChatAnthropic
        return ChatAnthropic(model=model, temperature=0.1)
    raise ValueError(f"LLM_PROVIDER inconnu : {provider}")


def llm_draft(case: Case, tools: CaseTools, report: Report, kb=None) -> LLMDraft:
    facts = {
        "overview": tools.get_overview(),
        "sensitive_apis": tools.get_sensitive_apis(),
        "capa_rules": [m.rule for m in case.capa],
        "dynamic": tools.get_dynamic_summary(),
        "iocs": tools.get_iocs(),
    }
    capa_ids = sorted({t.id for t in report.attack})
    candidates = []
    if kb is not None:
        query = " ".join([m.rule for m in case.capa] + [a["category"] for a in facts["sensitive_apis"]])
        candidates = kb.search(query, k=8)
    user = prompts.USER_TEMPLATE.format(
        facts=json.dumps(facts, ensure_ascii=False, indent=1, default=str)[:60000],
        capa_attack=capa_ids or "aucune", candidates=candidates or "aucune")
    llm = _llm().with_structured_output(LLMDraft)
    return llm.invoke([("system", prompts.SYSTEM_PROMPT), ("user", user)])


def analyze(case: Case, use_llm: bool = True, kb=None) -> Report:
    tools = CaseTools(case)
    report = deterministic_report(case, tools)
    if use_llm:
        draft = llm_draft(case, tools, report, kb)
        report.executive_summary = draft.executive_summary
        report.behaviors = draft.behaviors
        report.attack += [t.model_copy(update={"source": "llm",
                                               "confidence": "low" if t.confidence == "low" else "medium"})
                          for t in draft.attack]
        report.recommendations = draft.recommendations
        report.uncertainties = draft.uncertainties
    else:
        report.executive_summary = "Rapport généré sans LLM : faits extraits uniquement."
    return verifier.verify(report, case, kb)
