"""Comparaison résultats du labo / vérité terrain (malsight.evaluation.comparer)."""
import json
import shutil
from pathlib import Path

import pytest
from typer.testing import CliRunner

from malsight.cli import app
from malsight.evaluation.comparer import comparer, correspond, tableau, trouver_dossier, verite_pour

FIX = Path(__file__).parent / "fixtures"
VERITES = Path(__file__).resolve().parents[1] / "lab" / "verite-terrain"


@pytest.fixture
def collecte_t01(tmp_path):
    """Dossier de collecte T01 au format de collect.ps1 (fixtures réelles de l'essai 2)."""
    d = tmp_path / "T01" / "T01_persistance_run.ps1_20261102-120700"
    d.mkdir(parents=True)
    shutil.copy(FIX / "sysmon_T01.csv", d / "sysmon.csv")
    shutil.copy(FIX / "procmon_T01.csv", d / "procmon.csv")
    (d / "manifeste.json").write_text(json.dumps({"echantillon": "T01_persistance_run.ps1"}), encoding="utf-8")
    return d


@pytest.mark.parametrize("type_ioc, attendu, observe, ok", [
    ("registry_key", r"HKLM\Soft\Tree\MalsightTest", r"HKLM\Soft\Tree\MalsightTest\Id", True),   # valeur de la clé
    ("registry_key", r"HKLM\Soft\Tree\MalsightTest", r"HKLM\Soft\Tree\MalsightTest2", False),    # autre clé
    ("file_path", r"C:\travail\a.txt", r"c:\TRAVAIL\A.TXT", True),                              # casse ignorée
    ("file_path", r"C:\travail\a.txt", r"C:\travail\a.txt.bak", False),
    ("domain", "test.malsight.lab", "TEST.malsight.lab", True),
])
def test_correspond(type_ioc, attendu, observe, ok):
    assert correspond(type_ioc, attendu, observe) is ok


def test_dossier_et_verite_retrouves(collecte_t01):
    assert trouver_dossier(collecte_t01.parent) == collecte_t01
    assert verite_pour(collecte_t01, VERITES) == VERITES / "T01.json"


def test_t01_trois_ioc_avec_leurs_sources(collecte_t01):
    vt, res = comparer(collecte_t01, VERITES / "T01.json")
    par_type = {r.type: r for r in res}
    assert all(r.trouve for r in res)
    assert par_type["registry_key"].sysmon == ["EID 13 (powershell.exe)"]
    assert par_type["registry_key"].procmon == ["RegSetValue (powershell.exe)"]
    assert par_type["domain"].sysmon == ["EID 22 (powershell.exe)"] and par_type["domain"].procmon == []
    fichier = par_type["file_path"].procmon
    assert "WriteFile (powershell.exe)" in fichier
    assert not any("System" in p for p in fichier)          # écho du cache disque exclu
    assert "3/3 IOC retrouvés" in tableau(vt, res)


def test_ioc_absent_signale(collecte_t01, tmp_path):
    vt = json.loads((VERITES / "T01.json").read_text(encoding="utf-8"))
    vt["iocs"].append({"type": "domain", "value": "absent.malsight.lab", "preuve_attendue": "aucune"})
    fausse = tmp_path / "T01.json"
    fausse.write_text(json.dumps(vt), encoding="utf-8")
    _, res = comparer(collecte_t01, fausse)
    assert [r.trouve for r in res] == [True, True, True, False]


def test_commande_comparer(collecte_t01):
    r = CliRunner().invoke(app, ["comparer", str(collecte_t01.parent), "--verites", str(VERITES)])
    assert r.exit_code == 0, r.output
    assert "| IOC attendu | Type | Trouvé | Sysmon | Procmon |" in r.output
