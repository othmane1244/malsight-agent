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
    assert (VERITE.parent / "echantillons-test" / data["echantillon"]).exists()
    assert data["iocs"], "au moins un IOC attendu"
    for ioc in data["iocs"]:
        assert ioc["type"] in TYPES_IOC
        assert ioc["value"] and ioc["preuve_attendue"]
    for tech in data["attack"]:
        assert re.fullmatch(r"T\d{4}(\.\d{3})?", tech["id"])
