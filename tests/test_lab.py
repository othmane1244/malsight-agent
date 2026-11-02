"""Fusion Sysmon + Procmon d'un dossier de collecte du labo (issue #8)."""
import csv
import json
import shutil
from pathlib import Path

import pytest

from malsight.evaluation.comparer import ioc_dans_cas
from malsight.extractors.lab import fusionner, load_lab_collection
from malsight.extractors.procmon import parse_procmon_rows
from malsight.normalize import build_case

RACINE = Path(__file__).resolve().parents[1]
FIX = Path(__file__).parent / "fixtures"
VERITES = RACINE / "lab" / "verite-terrain"
T01 = RACINE / "lab" / "echantillons-test" / "T01_persistance_run.ps1"


@pytest.fixture
def collecte_t01(tmp_path):
    """Collecte T01 en mode manuel (pas d'auto.json) : fixtures réelles de l'essai 2."""
    d = tmp_path / "T01_persistance_run.ps1_20261102-120700"
    d.mkdir()
    shutil.copy(FIX / "sysmon_T01.csv", d / "sysmon.csv")
    shutil.copy(FIX / "procmon_T01.csv", d / "procmon.csv")
    (d / "manifeste.json").write_text(json.dumps({"echantillon": "T01_persistance_run.ps1"}), encoding="utf-8")
    return d


def _par_valeur(dyn):
    return {o.value: o for o in dyn.observations}


def test_t01_fusion_sources_et_deduplication(collecte_t01):
    dyn = load_lab_collection(collecte_t01)
    obs = _par_valeur(dyn)
    run = obs[r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\MalsightTest"]
    assert sorted(run.sources) == ["procmon", "sysmon"] and run.attribution == "sample_tree"
    assert set(run.operations) == {"RegSetValue", "EID 13"}
    fichier = obs[r"C:\travail\malsight_test.txt"]
    assert sorted(fichier.sources) == ["procmon", "sysmon"]
    assert all("System" not in p for p in fichier.processes)              # écho du cache exclu
    assert obs["test.malsight.lab"].sources == ["sysmon"]                 # DNS : Sysmon seul
    assert r"C:\travail\T01_persistance_run.ps1" not in obs               # copie faite par le labo
    assert dyn.registry_keys_set.count(r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\MalsightTest") == 1
    assert dyn.source == "sysmon+procmon"


def test_t01_build_case_contient_les_ioc(collecte_t01):
    case = build_case(T01, labo=collecte_t01.parent)
    for ioc in json.loads((VERITES / "T01.json").read_text(encoding="utf-8"))["iocs"]:
        assert ioc_dans_cas(case, ioc), ioc["value"]


def test_build_case_refuse_cape_et_labo(collecte_t01):
    with pytest.raises(ValueError):
        build_case(T01, cape_report=FIX / "cape_mini.json", labo=collecte_t01)


# ---------- Scénario T02 synthétique : persistance écrite par un service ----------

def _p(heure, proc, pid, op, chemin="", detail=""):
    return {"Time of Day": heure, "Process Name": proc, "PID": str(pid), "Operation": op,
            "Path": chemin, "Result": "SUCCESS", "Detail": detail}


TACHE = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\MalsightTest"
FICHIER_TACHE = r"C:\Windows\System32\Tasks\MalsightTest"
PROCMON_T02 = [
    _p("12:57:05,0", "svchost.exe", 1448, "RegSetValue", r"HKLM\SOFTWARE\Avant\Fenetre"),       # avant : ignoré
    _p("12:57:11,6", "powershell.exe", 3752, "Process Create", r"C:\...\powershell.exe",
       'PID: 8 080, Command line: powershell.exe -File "C:\\travail\\T02_tache_planifiee.ps1"'),
    _p("12:57:11,6", "powershell.exe", 8080, "Process Start", "",
       'Parent PID: 3 752, Command line: powershell.exe -File "C:\\travail\\T02_tache_planifiee.ps1"'),
    _p("12:57:15,0", "RuntimeBroker.exe", 5000, "RegSetValue", r"HKCU\Software\Bruit\Valeur"),  # hors arbre, pas un service
    _p("12:57:22,1", "svchost.exe", 1448, "RegCreateKey", TACHE, "Disposition: REG_CREATED_NEW_KEY"),
    _p("12:57:22,1", "svchost.exe", 1448, "RegSetValue", TACHE + r"\SD"),
    _p("12:57:22,1", "svchost.exe", 1448, "CreateFile", FICHIER_TACHE, "Disposition: OverwriteIf, OpenResult: Created"),
    _p("12:57:22,2", "powershell.exe", 8080, "Process Exit", "", "Exit Status: 0"),
    _p("12:57:40,0", "svchost.exe", 1448, "RegSetValue", r"HKLM\SOFTWARE\Apres\Fenetre"),      # après : ignoré
]
SYSMON_T02 = [
    {"EventID": "11", "ProcessId": "1448", "Image": r"C:\Windows\system32\svchost.exe", "TargetFilename": FICHIER_TACHE},
    {"EventID": "13", "ProcessId": "999", "Image": r"C:\Windows\system32\WMIADAP.EXE", "EventType": "SetValue",
     "TargetObject": r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Perflib\Updating"},     # non corroboré
]


def test_attribution_service_sans_filtrer_par_pid():
    dyn = fusionner(SYSMON_T02, list(parse_procmon_rows(PROCMON_T02)), racines={8080})
    obs = _par_valeur(dyn)
    assert obs[TACHE].attribution == "service_window" and obs[TACHE].processes == ["svchost.exe (1448)"]
    assert TACHE + r"\SD" in obs
    tache = obs[FICHIER_TACHE]
    assert sorted(tache.sources) == ["procmon", "sysmon"]       # Sysmon corroboré par Procmon
    assert set(tache.operations) == {"CreateFile", "EID 11"}
    for bruit in (r"HKLM\SOFTWARE\Avant\Fenetre", r"HKLM\SOFTWARE\Apres\Fenetre", r"HKCU\Software\Bruit\Valeur",
                  r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Perflib\Updating"):
        assert bruit not in obs, bruit


def test_racine_lue_dans_auto_json(tmp_path):
    d = tmp_path / "T02_tache_planifiee.ps1_20261102-125853"
    d.mkdir()
    for nom, lignes in (("procmon.csv", PROCMON_T02), ("sysmon.csv", SYSMON_T02)):
        champs = sorted({k for ligne in lignes for k in ligne})
        with (d / nom).open("w", encoding="utf-8", newline="") as f:
            w = csv.DictWriter(f, fieldnames=champs)
            w.writeheader()
            w.writerows(lignes)
    (d / "manifeste.json").write_text(json.dumps({"echantillon": "T02_tache_planifiee.ps1"}), encoding="utf-8")
    (d / "auto.json").write_text(json.dumps({"pid_echantillon": 8080}), encoding="utf-8")
    obs = _par_valeur(load_lab_collection(d))
    assert TACHE in obs and FICHIER_TACHE in obs


def test_filtre_du_bruit_systeme_desactivable():
    wnf = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Notifications\Data\418A073AA3BC1C75"
    ntfs = r"C:\$LogFile"
    lignes = PROCMON_T02 + [_p("12:57:12,0", "powershell.exe", 8080, "RegSetValue", wnf),
                            _p("12:57:12,0", "svchost.exe", 1448, "WriteFile", ntfs)]
    evs = list(parse_procmon_rows(lignes))
    avec = _par_valeur(fusionner([], evs, racines={8080}))
    sans = _par_valeur(fusionner([], evs, racines={8080}, filtrer_bruit=False))
    assert wnf in sans and ntfs in sans
    assert wnf not in avec and ntfs not in avec
    assert TACHE in avec                                        # le signal reste
