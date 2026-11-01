"""Fusion des règles Sysmon maison (lab/scripts/Merge-SysmonConfig.ps1)."""
import shutil
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

RACINE = Path(__file__).resolve().parents[1]
SCRIPT = RACINE / "lab" / "scripts" / "Merge-SysmonConfig.ps1"
REGLES = RACINE / "lab" / "sysmon-malsight.xml"
BASE = Path(__file__).parent / "fixtures" / "sysmon_base_mini.xml"
POWERSHELL = shutil.which("powershell") or shutil.which("pwsh")


def test_regles_maison_valides():
    racine = ET.parse(REGLES).getroot()
    conds = racine.findall("./EventFiltering/RuleGroup/FileCreate[@onmatch='include']/TargetFilename")
    assert any(c.text == "C:\\travail\\" and c.get("condition") == "begin with" for c in conds)


def _fusion(base: Path, sortie: Path) -> ET.Element:
    subprocess.run([POWERSHELL, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(SCRIPT),
                    "-Base", str(base), "-Ajout", str(REGLES), "-Sortie", str(sortie)],
                   check=True, capture_output=True)
    return ET.parse(sortie).getroot()


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell absent")
def test_fusion_dans_groupe_existant(tmp_path):
    racine = _fusion(BASE, tmp_path / "fusion.xml")
    inclus = racine.findall("./EventFiltering/RuleGroup/FileCreate[@onmatch='include']")
    assert len(inclus) == 1  # un seul groupe par couple événement/onmatch
    cibles = [c.text for c in inclus[0]]
    assert "\\Startup\\" in cibles and "C:\\travail\\" in cibles
    assert len(racine.findall("./EventFiltering/RuleGroup/FileCreate[@onmatch='exclude']")) == 1
    assert racine.findtext("HashAlgorithms") == "md5,sha256"


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell absent")
def test_fusion_cree_un_groupe_si_absent(tmp_path):
    base = tmp_path / "base.xml"
    base.write_text('<Sysmon schemaversion="4.50"><EventFiltering/></Sysmon>', encoding="utf-8")
    racine = _fusion(base, tmp_path / "fusion.xml")
    inclus = racine.findall("./EventFiltering/RuleGroup/FileCreate[@onmatch='include']")
    assert len(inclus) == 1 and inclus[0][0].text == "C:\\travail\\"
