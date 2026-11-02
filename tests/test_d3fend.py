"""MITRE D3FEND (D6) : parseur de l'API, cache hors ligne, vérificateur, pipeline et rapport.

Aucun appel réseau : l'API est simulée par une fixture tirée d'une vraie réponse (T1547.001),
et urllib est neutralisé pour tout le module.
"""
import json
import urllib.request
from pathlib import Path

import pytest

from malsight.agent import verifier
from malsight.agent.pipeline import LLMDraft, LLMRecommendations, analyze
from malsight.defend.kb import API_TECHNIQUE, API_VERSION, DefendKB, download, parse_api, techniques_des_verites
from malsight.report.render import to_markdown
from malsight.schemas import AttackTechnique, Countermeasure, Report

FIX = Path(__file__).parent / "fixtures"
API_T1547_001 = json.loads((FIX / "d3fend_api_T1547.001.json").read_text(encoding="utf-8"))
VERITES = Path(__file__).resolve().parents[1] / "lab" / "verite-terrain"


@pytest.fixture(autouse=True)
def pas_de_reseau(monkeypatch):
    def interdit(*a, **k):
        raise AssertionError("appel réseau interdit dans les tests")
    monkeypatch.setattr(urllib.request, "urlopen", interdit)


def faux_fetch(url):
    if url == API_VERSION:
        return {"version": "1.6.0"}
    if url == API_TECHNIQUE.format(tid="T1547.001"):
        return API_T1547_001
    return {"off_to_def": {"results": {"bindings": []}}}     # technique sans contre-mesure


@pytest.fixture
def defend(tmp_path):
    download(["T1547.001", "T1547", "T1082"], tmp_path, fetch=faux_fetch)
    return DefendKB(tmp_path)


def test_parse_api_dedoublonne_trie_et_construit_les_liens():
    cms = parse_api(API_T1547_001, "T1547.001")
    assert [c.id for c in cms] == ["D3-FIM", "D3-SICA", "D3-LFP", "D3-RC"]    # Detect, Isolate, Restore
    lfp = next(c for c in cms if c.id == "D3-LFP")
    assert lfp.name == "Local File Permissions" and lfp.tactic == "Isolate" and lfp.artifact == "File"
    assert lfp.url == "https://d3fend.mitre.org/technique/d3f:LocalFilePermissions/"
    assert all(c.technique == "T1547.001" and c.source == "d3fend" for c in cms)


def test_download_ecrit_le_cache(tmp_path):
    bilan = download(["T1547.001", "T1082"], tmp_path, fetch=faux_fetch)
    assert bilan == {"T1547.001": 4, "T1082": 0}
    doc = json.loads((tmp_path / "T1547.001.json").read_text(encoding="utf-8"))
    assert doc["d3fend_version"] == "1.6.0" and len(doc["countermeasures"]) == 4
    with pytest.raises(ValueError):
        download(["../etc"], tmp_path, fetch=faux_fetch)


def test_lecture_hors_ligne_et_parent(defend, tmp_path):
    assert {c.id for c in defend.countermeasures("T1547.001")} == {"D3-FIM", "D3-SICA", "D3-LFP", "D3-RC"}
    assert defend.countermeasures("T1082") == []                       # présent mais vide
    assert defend.countermeasures("T9999") == []                       # absent du cache
    assert defend.known_ids() == {"D3-FIM", "D3-SICA", "D3-LFP", "D3-RC"}
    # Sous-technique absente : on retombe sur la parente, en gardant l'ID demandé
    (tmp_path / "T1547.json").write_text((tmp_path / "T1547.001.json").read_text(encoding="utf-8"), encoding="utf-8")
    assert {c.technique for c in defend.countermeasures("T1547.009")} == {"T1547.009"}
    assert defend.covers("D3-LFP", "T1547.009")


def test_techniques_des_verites_avec_parentes():
    tids = techniques_des_verites(VERITES)
    assert {"T1547.001", "T1547", "T1053.005", "T1053", "T1105", "T1082"} <= set(tids)


def _rapport(case, attack_ids, cms, recs=()):
    r = Report(sample=case.sample)
    r.attack = [AttackTechnique(id=t, source="llm", confidence="medium", evidence="preuve") for t in attack_ids]
    r.countermeasures = cms
    r.recommendations = list(recs)
    return r


def test_verificateur_rejette_les_ids_d3fend_hors_cache(case, defend):
    bons = defend.countermeasures("T1547.001")
    invente = Countermeasure(id="D3-XYZ", name="Inventée", technique="T1547.001")
    hors_technique = bons[0].model_copy(update={"technique": "T1082"})
    r = _rapport(case, ["T1547.001", "T1082"], bons + [invente, hors_technique],
                 ["Restreindre les permissions (D3-LFP).", "Activer D3-XYZ partout."])
    r = verifier.verify(r, case, kb=None, defend=defend)
    assert {c.id for c in r.countermeasures} == {c.id for c in bons}
    # L'ID inventé est retiré, la recommandation reste (correction du 3 novembre)
    assert r.recommendations == ["Restreindre les permissions (D3-LFP).", "Activer partout."]
    assert any("D3-XYZ" in m and "absent du cache" in m for m in r.rejected_claims)
    assert any("ne relie pas" in m for m in r.rejected_claims)


def test_verificateur_sans_cache_rejette_toute_contre_mesure(case, defend):
    r = _rapport(case, ["T1547.001"], defend.countermeasures("T1547.001"))
    r = verifier.verify(r, case, kb=None, defend=None)
    assert r.countermeasures == []


class FauxLLM:
    """Remplace le LLM : renvoie un brouillon puis des recommandations, et garde les prompts reçus."""

    def __init__(self):
        self.prompts = []

    def with_structured_output(self, schema):
        self.schema = schema
        return self

    def invoke(self, messages):
        self.prompts.append(messages[-1][1])
        if self.schema is LLMDraft:
            return LLMDraft(executive_summary="Persistance par clé Run.",
                            attack=[AttackTechnique(id="T1547.001", source="llm", confidence="medium",
                                                    evidence="RegSetValue sur la clé Run")])
        return LLMRecommendations(recommendations=[
            "Surveiller les écritures dans les clés Run (D3-SICA).",
            "Appliquer D3-INVENTE sur les postes."])


def test_pipeline_donne_les_contre_mesures_au_llm(case, kb, defend):
    llm = FauxLLM()
    r = analyze(case, use_llm=True, kb=kb, defend=defend, llm=llm)
    assert len(llm.prompts) == 2
    assert "D3-SICA" in llm.prompts[1] and "Local File Permissions" in llm.prompts[1]   # contexte D3FEND
    assert "<donnees_echantillon>" in llm.prompts[1]                                    # IOC délimités
    assert {c.technique for c in r.countermeasures} == {"T1547.001"}
    assert r.recommendations == ["Surveiller les écritures dans les clés Run (D3-SICA).",
                                 "Appliquer sur les postes."]
    assert any("D3-INVENTE" in m for m in r.rejected_claims)


def test_pipeline_sans_llm_ajoute_les_contre_mesures_des_techniques_capa(case, kb, defend):
    r = analyze(case, use_llm=False, kb=kb, defend=defend)          # capa : T1547.001 (conftest)
    assert {c.id for c in r.countermeasures} == {"D3-FIM", "D3-SICA", "D3-LFP", "D3-RC"}


def test_rapport_markdown_section_d3fend(case, kb, defend):
    md = to_markdown(analyze(case, use_llm=False, kb=kb, defend=defend))
    assert "## Contre-mesures D3FEND" in md
    assert "[D3-LFP Local File Permissions](https://d3fend.mitre.org/technique/d3f:LocalFilePermissions/)" in md
