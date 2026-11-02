"""D10 « les outils classent, le LLM explique » : liste officielle (outils) et suggestions (LLM)."""
from malsight.agent.verifier import verify
from malsight.evaluation.serie import evaluer, scores
from malsight.report.render import to_markdown
from malsight.schemas import AttackTechnique, Case, DynamicData, Observation, Report, SampleInfo

SAMPLE = SampleInfo(filename="x", sha256="a" * 64, md5="b" * 32, size=1)
RUN = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\X"
AUTRE = r"HKCU\Software\Vendor\Config"


def cas(*cles):
    return Case(sample=SAMPLE, dynamic=DynamicData(registry_keys_set=list(cles), observations=[
        Observation(kind="registry", value=c, processes=["powershell.exe (1)"], attribution="sample_tree") for c in cles]))


def tech(tid, source="llm", preuve=RUN):
    return AttackTechnique(id=tid, source=source, confidence="high" if source != "llm" else "medium", evidence=preuve)


def test_technique_llm_deplacee_vers_les_suggestions(kb):
    r = verify(Report(sample=SAMPLE, attack=[tech("T1547.001", "rule", "règle R-T1547.001-registre"),
                                             tech("T1059.003", preuve=RUN)]), cas(RUN), kb)
    assert [t.id for t in r.attack] == ["T1547.001"] and all(t.source != "llm" for t in r.attack)
    assert [t.id for t in r.suggestions] == ["T1059.003"]


def test_suggestion_couverte_par_une_regle_non_declenchee_rejetee(kb):
    # T1547.001 est couverte par R-T1547.001 ; ici la clé n'est pas une clé Run : la règle ne se déclenche pas
    r = verify(Report(sample=SAMPLE, suggestions=[tech("T1547.001", preuve=AUTRE)]), cas(AUTRE), kb)
    assert r.suggestions == []
    assert any("règle D7 qui ne s'est pas déclenchée" in m for m in r.rejected_claims)
    # Même suggestion quand la règle se déclenche sur le cas : gardée
    r = verify(Report(sample=SAMPLE, suggestions=[tech("T1547.001", preuve=RUN)]), cas(RUN), kb)
    assert [t.id for t in r.suggestions] == ["T1547.001"]


def test_suggestion_en_double_de_la_liste_officielle_retiree(kb):
    r = verify(Report(sample=SAMPLE, attack=[tech("T1547.001", "rule", "règle R-T1547.001-registre")],
                      suggestions=[tech("T1547.001")]), cas(RUN), kb)
    assert [t.id for t in r.attack] == ["T1547.001"] and r.suggestions == []


def test_notation_officielle_et_colonne_suggestions():
    vt = {"attack": [{"id": "T1547.001"}, {"id": "T1082"}], "iocs": []}
    r = Report(sample=SAMPLE, attack=[tech("T1547.001", "rule")], suggestions=[tech("T1082"), tech("T1059.003")])
    e = evaluer(r, vt)
    assert e["attack_vraies"] == ["T1547.001"] and e["attack_ratees"] == ["T1082"]   # D9 : liste officielle
    assert e["suggestions"] == ["T1082", "T1059.003"] and e["suggestions_vraies"] == ["T1082"]
    s = scores({"T12": {"json_valide": True, **e}})
    assert s["suggestions"] == {"total": 2, "vraies": 1, "vraies_tol": 1, "precision": 0.5}


def test_rapport_section_suggestions():
    md = to_markdown(Report(sample=SAMPLE, suggestions=[tech("T1059.003")]))
    assert "## Suggestions à valider par l'analyste" in md and "T1059.003" in md
    assert "Aucune." in to_markdown(Report(sample=SAMPLE)).split("## Suggestions à valider par l'analyste")[1][:40]
