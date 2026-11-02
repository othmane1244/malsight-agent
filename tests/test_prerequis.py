"""Vérification des prérequis du labo côté hôte (lab/scripts/verifier-prerequis.ps1)."""
import shutil
import subprocess
from pathlib import Path

import pytest

RACINE = Path(__file__).resolve().parents[1]
SCRIPT = RACINE / "lab" / "scripts" / "verifier-prerequis.ps1"
POWERSHELL = shutil.which("powershell") or shutil.which("pwsh")
pytestmark = [pytest.mark.slow, pytest.mark.skipif(POWERSHELL is None, reason="PowerShell absent")]


@pytest.fixture
def labo(tmp_path):
    """Arborescence C:\\labo complète, avec des outils factices (fichiers vides)."""
    outils = tmp_path / "entree" / "outils"
    scripts = tmp_path / "entree" / "scripts"
    samples = tmp_path / "entree" / "samples"
    for d in (outils, scripts, samples, tmp_path / "resultats"):
        d.mkdir(parents=True)
    (outils / "Sysmon64.exe").write_bytes(b"")
    (outils / "Procmon64.exe").write_bytes(b"")
    shutil.copy(Path(__file__).parent / "fixtures" / "sysmon_base_mini.xml", outils / "sysmonconfig-export.xml")
    for f in ("setup-sandbox.ps1", "collect.ps1", "Merge-SysmonConfig.ps1", "analyse-auto.ps1"):
        shutil.copy(RACINE / "lab" / "scripts" / f, scripts / f)
    shutil.copy(RACINE / "lab" / "sysmon-malsight.xml", scripts / "sysmon-malsight.xml")
    shutil.copy(RACINE / "lab" / "echantillons-test" / "T01_persistance_run.ps1", samples)
    return tmp_path


def _verifier(labo: Path) -> subprocess.CompletedProcess:
    return subprocess.run([POWERSHELL, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(SCRIPT),
                           "-Labo", str(labo)], capture_output=True, text=True, encoding="utf-8",
                          errors="replace")


def test_prerequis_complets(labo):
    r = _verifier(labo)
    assert r.returncode == 0, r.stdout


def test_config_sysmon_manquante(labo):
    (labo / "entree" / "outils" / "sysmonconfig-export.xml").unlink()
    r = _verifier(labo)
    assert r.returncode == 1
    assert "sysmonconfig-export.xml" in r.stdout


def test_script_pas_a_jour(labo):
    (labo / "entree" / "scripts" / "collect.ps1").write_text("# ancienne version\n", encoding="utf-8")
    r = _verifier(labo)
    assert r.returncode == 1
    assert "collect.ps1" in r.stdout
