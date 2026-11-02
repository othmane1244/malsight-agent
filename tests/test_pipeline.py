from malsight.agent.pipeline import analyze
from malsight.agent.tools import CaseTools
from malsight.agent.verifier import verify
from malsight.report.render import to_markdown
from malsight.schemas import IOC, AttackTechnique, Behavior, Report


def test_tools_are_read_only(case):
    names = {n for n in dir(CaseTools) if not n.startswith("_")}
    assert names == {"get_overview", "get_sensitive_apis", "get_capa_matches",
                     "get_iocs", "get_dynamic_summary", "search_strings"}


def test_sensitive_apis(case):
    apis = {a["name"]: a for a in CaseTools(case).get_sensitive_apis()}
    assert apis["RegSetValueExW"]["category"] == "persistance"
    assert apis["InternetOpenUrlW"]["source"] == "dynamic_call"
    assert "Sleep" not in apis


def test_report_without_llm(case, kb):
    r = analyze(case, use_llm=False, kb=kb)
    assert any(t.id == "T1547.001" and t.source == "capa" for t in r.attack)
    assert any(i.value == "update.demo.lab" for i in r.iocs)
    md = to_markdown(r)
    assert "T1547.001" in md and "update.demo.lab" in md


def test_verifier_rejects_hallucinations(case, kb):
    r = Report(sample=case.sample)
    r.iocs = [IOC(type="domain", value="evil.example.com", source="llm"),
              IOC(type="domain", value="update.demo.lab", source="llm")]
    r.attack = [AttackTechnique(id="T9999", source="llm", confidence="low", evidence="x"),
                AttackTechnique(id="T1059.003", source="llm", confidence="medium",
                                evidence="cmd.exe /c whoami")]
    r.behaviors = [Behavior(summary="Chiffre des fichiers", evidence="CryptEncrypt")]
    r = verify(r, case, kb)
    assert [i.value for i in r.iocs] == ["update.demo.lab"]
    assert [t.id for t in r.attack] == ["T1059.003"]
    assert r.attack[0].name == "Windows Command Shell"
    assert r.behaviors[0].kind == "inferred"
    assert len(r.rejected_claims) == 2


def test_verifier_keeps_backslash_iocs(case, kb):
    r = analyze(case, use_llm=False, kb=kb)
    kinds = {i.type for i in r.iocs}
    assert {"registry_key", "file_path", "mutex"} <= kinds
    assert not r.rejected_claims


def test_llm_ollama_contexte_et_limite_explicites(monkeypatch):
    """Contexte, limite de génération et délai explicites (pas les valeurs par défaut d'Ollama)."""
    import langchain_ollama

    from malsight.agent import pipeline
    recus = {}

    class FauxChatOllama:
        def __init__(self, **kw):
            recus.update(kw)

    monkeypatch.setattr(langchain_ollama, "ChatOllama", FauxChatOllama)
    monkeypatch.setenv("LLM_PROVIDER", "ollama")
    monkeypatch.delenv("LLM_NUM_CTX", raising=False)
    pipeline._llm()
    assert recus["num_ctx"] == 8192 and recus["num_predict"] == 2048
    assert recus["client_kwargs"]["timeout"] == 600.0
    monkeypatch.setenv("LLM_NUM_CTX", "16384")
    pipeline._llm()
    assert recus["num_ctx"] == 16384
