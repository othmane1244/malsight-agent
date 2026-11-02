"""Parseur Procmon (issue #8) : format dépendant de la langue et filtrage des opérations."""
from pathlib import Path

import pytest

from malsight.extractors.procmon import entier_local, heure_en_secondes, load_procmon_csv, parse_procmon_rows

FIX = Path(__file__).parent / "fixtures"


@pytest.mark.parametrize("texte, attendu", [
    ("12:05:22,0453416", 12 * 3600 + 5 * 60 + 22.0453416),     # Windows en français
    ("12:05:22.0453416", 12 * 3600 + 5 * 60 + 22.0453416),     # point décimal
    ("1:05:22.5 PM", 13 * 3600 + 5 * 60 + 22.5),              # anglais, 12 h
    ("12:00:01.0 AM", 1.0),                                    # minuit en notation 12 h
    ("12:00:01.0 PM", 12 * 3600 + 1.0),
    ("pas une heure", None),
])
def test_heure_en_secondes(texte, attendu):
    assert heure_en_secondes(texte) == pytest.approx(attendu) if attendu is not None else heure_en_secondes(texte) is None


@pytest.mark.parametrize("texte", ["8080", "8 080", "8\u00a0080", "8\u202f080", "8,080", "8.080"])
def test_entier_local(texte):
    assert entier_local(texte) == 8080


def _ligne(op, chemin="", detail="", proc="powershell.exe", pid="100", resultat="SUCCESS", heure="10:00:00,0"):
    return {"Time of Day": heure, "Process Name": proc, "PID": pid, "Operation": op,
            "Path": chemin, "Result": resultat, "Detail": detail}


def test_filtrage_des_operations():
    lignes = [
        _ligne("RegSetValue", r"HKCU\Software\X\V", "Type: REG_SZ"),                        # gardé
        _ligne("RegSetValue", r"HKCU\Software\X\V", resultat="ACCESS DENIED"),              # échec
        _ligne("RegQueryValue", r"HKCU\Software\X\V"),                                      # lecture
        _ligne("RegCreateKey", r"HKCU\Software\X", "Disposition: REG_OPENED_EXISTING_KEY"), # simple ouverture
        _ligne("RegCreateKey", r"HKCU\Software\Y", "Disposition: REG_CREATED_NEW_KEY"),     # gardé
        _ligne("CreateFile", r"C:\travail\a.txt", "Disposition: OpenIf, OpenResult: Opened"),   # ouverture
        _ligne("CreateFile", r"C:\travail\b.txt", "Disposition: OpenIf, OpenResult: Created"),  # gardé
        _ligne("WriteFile", r"C:\travail\b.txt", "Offset: 0, Length: 4 096", proc="System", pid="4"),  # cache
        _ligne("RegSetValue", r"HKCU\Software\Sysinternals\X", proc="Procmon64.exe"),       # outil du labo
    ]
    evs = list(parse_procmon_rows(lignes))
    assert [(e.operation, e.chemin) for e in evs] == [
        ("RegSetValue", r"HKCU\Software\X\V"), ("RegCreateKey", r"HKCU\Software\Y"), ("CreateFile", r"C:\travail\b.txt")]


@pytest.mark.parametrize("pid_texte", ["8 080", "8,080", "8080"])
def test_processus_pid_avec_separateur_de_milliers(pid_texte):
    cmd = '"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" -File "C:\\travail\\T02.ps1"'
    evs = list(parse_procmon_rows([
        _ligne("Process Create", r"C:\Windows\System32\powershell.exe", f"PID: {pid_texte}, Command line: {cmd}", pid="3 752"),
        _ligne("Process Start", "", f"Parent PID: 3 752, Command line: {cmd}, Current directory: C:\\", pid=pid_texte),
    ]))
    assert evs[0].pid == 3752 and evs[0].pid_enfant == 8080 and evs[0].ligne_commande == cmd
    assert evs[1].pid == 8080 and evs[1].pid_parent == 3752 and evs[1].ligne_commande == cmd


def test_passage_de_minuit():
    evs = list(parse_procmon_rows([_ligne("RegSetValue", r"HKCU\A", heure="23:59:59,5"),
                                   _ligne("RegSetValue", r"HKCU\B", heure="00:00:00,5")]))
    assert evs[1].t - evs[0].t == pytest.approx(1.0)


def test_fixture_t01():
    evs = load_procmon_csv(FIX / "procmon_T01.csv")
    ops = {(e.operation, e.chemin) for e in evs}
    assert ("RegSetValue", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\MalsightTest") in ops
    assert ("WriteFile", r"C:\travail\malsight_test.txt") in ops
    assert all(e.processus != "System" for e in evs)                 # écho du cache exclu
    assert all(e.processus != "Procmon64.exe" for e in evs)          # outil du labo exclu
