"""Règles artefact -> technique (D7), contexte de l'agent et vérificateur (corrections du 3 novembre).

Les cas positifs reprennent des artefacts tirés des SOURCES des règles (ATT&CK, Sigma), pas des
échantillons du labo.
"""
import pytest

from malsight.agent.pipeline import _fiche, analyze, llm_draft
from malsight.agent.tools import CaseTools
from malsight.agent.verifier import verify
from malsight.attack.regles import REGLES, appliquer
from malsight.evaluation.serie import MODES
from malsight.schemas import AttackTechnique, Case, DynamicData, Observation, Report, SampleInfo

SAMPLE = SampleInfo(filename="x", sha256="a" * 64, md5="b" * 32, size=1)


def _dyn(*obs):
    return DynamicData(source="sysmon+procmon", observations=[
        Observation(kind=k, value=v, processes=["powershell.exe (100)"], attribution=a) for k, v, a in obs])


@pytest.mark.parametrize("kind, valeur, technique", [
    ("registry", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Updater", "T1547.001"),
    ("registry", r"HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce\x", "T1547.001"),
    ("file", r"C:\Users\u\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\a.lnk", "T1547.001"),
    ("file", r"C:\Windows\System32\Tasks\Maintenance", "T1053.005"),
    ("registry", r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Maintenance", "T1053.005"),
    ("process", r'"C:\Windows\system32\schtasks.exe" /create /tn x /tr calc.exe', "T1053.005"),
    ("registry", r"HKLM\System\CurrentControlSet\Services\Updater\ImagePath", "T1543.003"),
    ("process", "sc.exe create Updater binPath= C:\\x.exe", "T1543.003"),
    ("registry", r"HKCU\Environment\UserInitMprLogonScript", "T1037.001"),
    ("process", '"C:\\Windows\\system32\\systeminfo.exe"', "T1082"),
    ("process", "hostname", "T1082"),
    ("process", "ipconfig /all", "T1016"),
    ("process", '"C:\\Windows\\system32\\ARP.EXE" -a', "T1016"),
    ("process", "netsh interface show interface", "T1016"),
    ("process", "powershell.exe -NoProfile -enc SQBFAFgA", "T1059.001"),
    ("process", '"C:\\...\\powershell.exe" -EncodedCommand SQBFAFgA', "T1059.001"),
    ("file", r"C:\Users\u\AppData\Local\Temp\export.7z", "T1560"),
])
def test_regle_positive(kind, valeur, technique):
    assert [t.id for t in appliquer(_dyn((kind, valeur, "sample_tree")))] == [technique]


@pytest.mark.parametrize("kind, valeur", [
    ("registry", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU\a"),   # pas une clé Run
    ("registry", r"HKCU\Software\Vendor\Run\x"),
    ("file", r"C:\Windows\System32\drivers\etc\hosts"),
    ("registry", r"HKLM\System\CurrentControlSet\Services\Updater\Start"),             # pas ImagePath
    ("process", "powershell.exe -NoProfile -ExecutionPolicy Bypass -File a.ps1"),       # -ExecutionPolicy ≠ -e
    ("process", "notepad.exe C:\\routes.txt"),
    ("process", "schtasks.exe /query"),
    ("file", r"C:\travail\rapport.txt"),
])
def test_regle_negative(kind, valeur):
    assert appliquer(_dyn((kind, valeur, "sample_tree"))) == []


def test_chaque_regle_est_sourcee():
    for r in REGLES:
        assert r.sources and all(s.startswith("https://") for s in r.sources), r.id
        assert any("attack.mitre.org" in s or "SigmaHQ/sigma" in s for s in r.sources), r.id


def test_aucune_regle_pour_le_jeu_de_validation():
    # D4 / D7 : T1033 (T15) et T1546.013 (T16) n'apparaissent que dans le jeu de validation
    assert not {"T1033", "T1546.013"} & {r.technique for r in REGLES}


def test_regle_preuve_et_source():
    t = appliquer(_dyn(("registry", r"HKCU\Environment\UserInitMprLogonScript", "sample_tree")))[0]
    assert t.source == "rule" and t.confidence == "high"
    assert "R-T1037.001-registre" in t.evidence and "UserInitMprLogonScript" in t.evidence


# ---------- Vérificateur : nom et tactique officiels ----------

def test_nom_et_tactique_toujours_officiels(kb):
    r = Report(sample=SAMPLE, attack=[AttackTechnique(
        id="T1547.001", name="PowerShell: Encoded Command Execution", tactic="execution",
        source="llm", confidence="medium", evidence="x")])
    r = verify(r, Case(sample=SAMPLE), kb)
    assert r.attack[0].name == "Registry Run Keys / Startup Folder" and r.attack[0].tactic == "persistence"
    assert any("Nom ATT&CK corrigé" in u for u in r.uncertainties)


# ---------- Contexte du LLM : descriptions, provenance, règles ----------

class FauxKB:
    techniques = {"T1547.001": {"name": "Registry Run Keys / Startup Folder", "tactics": ["persistence"],
                                "description": "Adversaries may achieve persistence by adding a program to a startup folder."},
                  "T1112": {"name": "Modify Registry", "tactics": ["defense-evasion"],
                            "description": "Adversaries may interact with the Windows Registry."}}

    def is_valid(self, tid): return tid in self.techniques
    def name(self, tid): return self.techniques[tid]["name"]
    def tactic(self, tid): return ", ".join(self.techniques[tid]["tactics"])
    def search(self, q, k=5): return [("T1112", "Modify Registry"), ("T1547.001", "x")]


class LLMEspion:
    def __init__(self):
        self.prompts = []

    def with_structured_output(self, schema):
        self.schema = schema
        return self

    def invoke(self, messages):
        self.prompts.append(messages[-1][1])
        return self.schema()


def test_fiche_technique():
    f = _fiche(FauxKB(), "T1547.001")
    assert f["name"] == "Registry Run Keys / Startup Folder" and f["description"].startswith("Adversaries")
    assert _fiche(None, "T1547.001") == {"id": "T1547.001"}


def test_contexte_descriptions_provenance_et_regles():
    case = Case(sample=SAMPLE, dynamic=_dyn(
        ("registry", r"HKLM\SOFTWARE\Bruit\Fond", "service_window"),
        ("registry", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\X", "sample_tree")))
    llm = LLMEspion()
    from malsight.agent.pipeline import deterministic_report
    report = deterministic_report(case, CaseTools(case), regles=True)
    llm_draft(case, CaseTools(case), report, FauxKB(), llm=llm)
    p = llm.prompts[0]
    assert '"attribution": "sample_tree"' in p and '"attribution": "service_window"' in p
    assert p.index("Run\\\\X") < p.index("Bruit\\\\Fond")                     # arbre de l'échantillon d'abord
    assert "Adversaries may interact with the Windows Registry" in p          # description du candidat
    assert '"source": "rule"' in p and "R-T1547.001-registre" in p           # technique déjà identifiée


def test_modes_d_analyse():
    assert MODES == {"llm": (True, False), "regles": (False, True), "hybride": (True, True)}
    case = Case(sample=SAMPLE, dynamic=_dyn(
        ("registry", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\X", "sample_tree")))
    assert [t.id for t in analyze(case, use_llm=False, kb=FauxKB(), regles=True).attack] == ["T1547.001"]
    assert analyze(case, use_llm=False, kb=FauxKB(), regles=False).attack == []
