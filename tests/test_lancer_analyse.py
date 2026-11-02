"""Mode automatique (D3) : lab/scripts/lancer-analyse.ps1, en mode -SansLancer uniquement.

Ces tests ne lancent jamais de sandbox ni d'échantillon : ils vérifient le filtrage des
échantillons autorisés et le contenu du .wsb généré.
"""
import shutil
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

RACINE = Path(__file__).resolve().parents[1]
SCRIPT = RACINE / "lab" / "scripts" / "lancer-analyse.ps1"
POWERSHELL = shutil.which("powershell") or shutil.which("pwsh")
pytestmark = [pytest.mark.slow, pytest.mark.skipif(POWERSHELL is None, reason="PowerShell absent")]


def _lancer(echantillon: str, wsb: Path, *extra: str) -> subprocess.CompletedProcess:
    return subprocess.run([POWERSHELL, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(SCRIPT),
                           "-Echantillon", echantillon, "-SansLancer", "-SortieWsb", str(wsb), *extra],
                          capture_output=True, text=True, encoding="utf-8", errors="replace")


def test_wsb_genere_pour_un_echantillon_autorise(tmp_path):
    wsb = tmp_path / "t02.wsb"
    r = _lancer("T02", wsb, "-Attente", "60")
    assert r.returncode == 0, r.stdout + r.stderr
    conf = ET.parse(wsb).getroot()
    assert conf.findtext("Networking") == "Disable"
    assert conf.findtext("VGpu") == "Disable"
    assert conf.findtext("ClipboardRedirection") == "Disable"
    cmd = conf.findtext("LogonCommand/Command")
    assert "analyse-auto.ps1 -Echantillon T02_tache_planifiee.ps1 -Attente 60" in cmd
    lecture_seule = {m.findtext("SandboxFolder"): m.findtext("ReadOnly") for m in conf.iter("MappedFolder")}
    assert lecture_seule == {"C:\\entree": "true", "C:\\resultats": "false"}


@pytest.mark.parametrize("echantillon", ["T99", "T1", "..\\T01", "T01_persistance_run.ps1", "X01"])
def test_echantillon_refuse(tmp_path, echantillon):
    wsb = tmp_path / "refus.wsb"
    r = _lancer(echantillon, wsb)
    assert r.returncode != 0
    assert not wsb.exists()
