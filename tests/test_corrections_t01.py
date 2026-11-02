"""Corrections issues du premier essai de l'agent sur T01 (gemma4:e4b) : preuves, IOC, prompt."""
import pytest

from malsight.agent import prompts
from malsight.agent.verifier import preuve_retrouvee, valeurs_citees, verify
from malsight.normalize import iocs_from_strings, nettoyer_ioc
from malsight.schemas import Behavior, Case, DynamicData, Report, SampleInfo


# ---------- 1. Vérificateur : valeurs citées dans la preuve ----------

@pytest.mark.parametrize("preuve, attendu", [
    ('files_written: ["C:\\travail\\malsight_test.txt"]', [r"C:\travail\malsight_test.txt"]),
    ('registry_keys_set: ["HKCU\\\\Software\\\\Run\\\\MalsightTest"]', [r"HKCU\Software\Run\MalsightTest"]),  # échappement JSON
    ('domains: ["test.malsight.lab"]', ["test.malsight.lab"]),
    ("Appel à RegSetValueExW puis send()", ["RegSetValueExW"]),        # « send » : mot courant, ignoré
    ("Écrit C:\\travail\\a.txt, puis contacte c2.malsight.lab.", [r"C:\travail\a.txt", "c2.malsight.lab"]),
    ("Le script crée une persistance", []),
])
def test_valeurs_citees(preuve, attendu):
    assert valeurs_citees(preuve) == attendu


@pytest.fixture
def cas_t01():
    return Case(sample=SampleInfo(filename="T01.ps1", sha256="a" * 64, md5="b" * 32, size=1),
                dynamic=DynamicData(
                    registry_keys_set=[r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\MalsightTest"],
                    files_written=[r"C:\travail\malsight_test.txt"], domains=["test.malsight.lab"]))


def test_comportement_reste_observe_si_toutes_les_valeurs_sont_retrouvees(cas_t01):
    r = Report(sample=cas_t01.sample, behaviors=[
        Behavior(summary="Persistance", evidence='registry_keys_set: ["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\MalsightTest"]'),
        Behavior(summary="Écriture", evidence='files_written: ["C:\\travail\\malsight_test.txt"]'),
        Behavior(summary="DNS", evidence="tentative de résolution de test.malsight.lab"),
    ])
    r = verify(r, cas_t01)
    assert [b.kind for b in r.behaviors] == ["observed"] * 3
    assert r.uncertainties == []


def test_comportement_infere_si_une_valeur_manque(cas_t01):
    r = Report(sample=cas_t01.sample, behaviors=[
        Behavior(summary="Écrit puis contacte", evidence="C:\\travail\\malsight_test.txt puis evil.malsight.lab")])
    r = verify(r, cas_t01)
    assert r.behaviors[0].kind == "inferred"
    assert "evil.malsight.lab" in r.uncertainties[0] and "malsight_test.txt" not in r.uncertainties[0]


def test_preuve_sans_valeur_reconnaissable_cherchee_mot_pour_mot():
    assert preuve_retrouvee("persistance au démarrage", "... persistance au démarrage ...") == (True, [])
    assert preuve_retrouvee("texte absent", "corpus") == (False, ["texte absent"])


# ---------- 2. Extraction d'IOC : valeurs abrégées et ponctuation finale ----------

def test_iocs_exclut_les_valeurs_abregees_et_retire_la_ponctuation():
    iocs = iocs_from_strings([
        r"1. écrit la valeur dans HKCU\...\CurrentVersion\Run, pointant vers notepad.exe ;",   # en-tête de T01
        r"Set-ItemProperty HKCU\Software\Demo\Run, puis C:\travail\a.txt.",
        "voir update.malsight.lab.",
    ])
    assert iocs["registry_key"] == [r"HKCU\Software\Demo\Run"]
    assert iocs["file_path"] == [r"C:\travail\a.txt"]
    assert iocs["domain"] == ["update.malsight.lab"]


@pytest.mark.parametrize("brut, net", [("C:\\a\\b.txt).", "C:\\a\\b.txt"), ("HKCU\\…\\Run", None), ("x...y", None)])
def test_nettoyer_ioc(brut, net):
    assert nettoyer_ioc(brut) == net


# ---------- 3. Prompt : tentative et réussite ----------

def test_prompt_distingue_tentative_et_reussite():
    p = " ".join(prompts.SYSTEM_PROMPT.split())          # sans retours à la ligne
    assert "tentative de résolution DNS" in p
    assert "N'affirme jamais une communication réseau" in p
    assert "sans preuve d'une réponse" in p
