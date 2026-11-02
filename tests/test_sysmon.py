"""Parseur Sysmon (issue #8) : normalisation du registre et IOC de T01."""
import json
from pathlib import Path

import pytest

from malsight.extractors.dynamic import load_sysmon_csv, normalize_registry_key, parse_sysmon_rows

FIX = Path(__file__).parent / "fixtures"
VERITE_T01 = Path(__file__).resolve().parents[1] / "lab" / "verite-terrain" / "T01.json"
SID = "S-1-5-21-1111111111-2222222222-3333333333-504"


@pytest.mark.parametrize("brut, attendu", [
    (rf"HKU\{SID}\Software\Microsoft\Windows\CurrentVersion\Run\MalsightTest",
     r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\MalsightTest"),
    (rf"HKU\{SID}_Classes\ProcMon.Logfile.1\shell\open\command\(Default)",
     r"HKCU\Software\Classes\ProcMon.Logfile.1\shell\open\command\(Default)"),
    (rf"HKU\{SID}", "HKCU"),
    (r"HKU\S-1-5-18\Software\X", r"HKU\S-1-5-18\Software\X"),          # compte SYSTEM : inchangé
    (r"HKU\.DEFAULT\Software\X", r"HKU\.DEFAULT\Software\X"),
    (r"HKLM\System\CurrentControlSet\Services\AppID\Start", r"HKLM\System\CurrentControlSet\Services\AppID\Start"),
])
def test_normalize_registry_key(brut, attendu):
    assert normalize_registry_key(brut) == attendu


def test_sysmon_t01_retrouve_la_verite_terrain():
    dyn = load_sysmon_csv(FIX / "sysmon_T01.csv")
    attendus = json.loads(VERITE_T01.read_text(encoding="utf-8"))["iocs"]
    champs = {"registry_key": dyn.registry_keys_set, "file_path": dyn.files_written, "domain": dyn.domains}
    assert dyn.source == "sysmon"
    for ioc in attendus:
        assert ioc["value"] in champs[ioc["type"]], f"IOC manquant : {ioc['type']}={ioc['value']}"


def test_sysmon_exclut_les_outils_du_labo():
    dyn = load_sysmon_csv(FIX / "sysmon_T01.csv")
    tout = " ".join(dyn.processes_created + dyn.registry_keys_set + dyn.files_written)
    assert "Procmon" not in tout and "Sysmon64" not in tout and "ProcMon.Logfile" not in tout
    complet = load_sysmon_csv(FIX / "sysmon_T01.csv", exclude_lab_tools=False)
    assert any("Procmon64.exe" in p for p in complet.processes_created)


def test_sysmon_domaines_et_ips():
    dyn = parse_sysmon_rows([
        {"EventID": "22", "Image": "x.exe", "QueryName": "wpad", "QueryResults": "-"},
        {"EventID": "22", "Image": "x.exe", "QueryName": "Update.Demo.LAB.", "QueryResults": "::ffff:10.0.0.5;"},
        {"EventID": "3", "Image": "x.exe", "DestinationIp": "10.0.0.6", "DestinationHostname": "c2.demo.lab"},
        {"EventID": "12", "Image": "x.exe", "EventType": "DeleteKey", "TargetObject": r"HKLM\Software\Supprime"},
    ])
    assert dyn.domains == ["update.demo.lab", "c2.demo.lab"]   # « wpad » (sans point) ignoré
    assert dyn.ips == ["10.0.0.5", "10.0.0.6"]
    assert dyn.registry_keys_set == []                       # suppression : pas une écriture
