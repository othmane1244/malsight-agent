"""Cohérence des fichiers de vérité terrain du labo (lab/verite-terrain/*.json)."""
import json
import re
from pathlib import Path
from typing import get_args

import pytest

from malsight.schemas import IOC

VERITE = Path(__file__).resolve().parents[1] / "lab" / "verite-terrain"
FICHIERS = sorted(VERITE.glob("*.json"))
TYPES_IOC = set(get_args(IOC.model_fields["type"].annotation))


def test_verite_terrain_presente():
    assert FICHIERS, "aucun fichier de vérité terrain"


@pytest.mark.parametrize("chemin", FICHIERS, ids=lambda p: p.stem)
def test_verite_terrain_valide(chemin):
    data = json.loads(chemin.read_text(encoding="utf-8"))
    assert data["id"] == chemin.stem
    assert data["echantillon"].startswith(data["id"] + "_")
    script = VERITE.parent / "echantillons-test" / data["echantillon"]
    assert script.exists()
    assert "[switch]$Nettoyer" in script.read_text(encoding="utf-8-sig"), "option -Nettoyer attendue"
    assert data["iocs"], "au moins un IOC attendu"
    for ioc in data["iocs"]:
        assert ioc["type"] in TYPES_IOC
        assert ioc["value"] and ioc["preuve_attendue"]
    assert isinstance(data["attack"], list)          # vide pour un témoin négatif
    for tech in data["attack"]:
        assert re.fullmatch(r"T\d{4}(\.\d{3})?", tech["id"])
        assert tech["nom"] and tech["preuve_attendue"]


def test_chaque_echantillon_a_sa_verite_terrain():
    scripts = sorted((VERITE.parent / "echantillons-test").glob("T*.ps1"))
    ids = {p.name.split("_", 1)[0] for p in scripts}
    assert ids == {p.stem for p in FICHIERS}


def test_temoin_negatif_sans_technique():
    t11 = json.loads((VERITE / "T11.json").read_text(encoding="utf-8"))
    assert t11["attack"] == []
