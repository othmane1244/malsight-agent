"""Série d'évaluation (malsight.evaluation.serie) : indicateurs et tableaux, sans LLM."""
import csv
import json
from pathlib import Path

from malsight.evaluation.serie import ecrire_tableaux, evaluer, lancer_serie
from malsight.schemas import IOC, AttackTechnique, Behavior, Case, Report, SampleInfo

VT = {"id": "T12", "echantillon": "T12_x.ps1",
      "iocs": [{"type": "domain", "value": "c2.malsight.lab"}, {"type": "file_path", "value": r"C:\travail\a.txt"}],
      "attack": [{"id": "T1082"}, {"id": "T1547.001"}]}
SAMPLE = SampleInfo(filename="x", sha256="a" * 64, md5="b" * 32, size=1)


def _rapport():
    return Report(sample=SAMPLE,
                  iocs=[IOC(type="domain", value="c2.malsight.lab", source="extraction")],
                  attack=[AttackTechnique(id="T1547.001", source="llm", confidence="medium", evidence="e"),
                          AttackTechnique(id="T1059.001", source="llm", confidence="low", evidence="e")],
                  behaviors=[Behavior(summary="s", evidence="e"), Behavior(summary="s", evidence="e", kind="inferred")],
                  rejected_claims=["IOC sans preuve : x"])


def test_evaluer():
    e = evaluer(_rapport(), VT)
    assert e["attack_vraies"] == ["T1547.001"] and e["attack_en_trop"] == ["T1059.001"]
    assert e["attack_ratees"] == ["T1082"]
    assert (e["iocs_trouves"], e["iocs_attendus"]) == (1, 2)
    assert (e["comportements_observes"], e["comportements_inferes"]) == (1, 1)
    assert len(e["rejets"]) == 1


def test_lancer_serie_robuste_et_tableaux(tmp_path):
    verites = tmp_path / "verites"
    verites.mkdir()
    for tid in ("T11", "T12"):
        (verites / f"{tid}.json").write_text(json.dumps(VT | {"id": tid}), encoding="utf-8")

    def construire(chemin, labo):
        return Case(sample=SAMPLE)

    def analyser(case, appels=[]):
        appels.append(1)
        if len(appels) == 1:
            raise ValueError("JSON du LLM invalide")             # premier échantillon : échec
        return _rapport()

    bilan = lancer_serie(["T11", "T12"], tmp_path / "out", analyser, verites=verites,
                         construire=construire, journal=lambda m: None)
    assert bilan["T11"]["json_valide"] is False and "invalide" in bilan["T11"]["erreur"]
    assert bilan["T12"]["json_valide"] is True
    out = tmp_path / "out"
    assert (out / "T12" / "report.json").exists() and (out / "T12" / "rapport.md").exists()
    assert (out / "T11" / "erreur.txt").exists() and not (out / "T11" / "report.json").exists()
    lignes = list(csv.DictReader((out / "bilan.csv").open(encoding="utf-8")))
    assert [l["json_valide"] for l in lignes] == ["non", "oui"]
    md = (out / "bilan.md").read_text(encoding="utf-8")
    assert "| **Total** |" in md and "**1/4**" in md and "| 1/2 |" in md


def test_ecrire_tableaux_seul(tmp_path):
    ecrire_tableaux({"T12": {"echantillon": "T12", "json_valide": True, "temps_s": 3.0, **evaluer(_rapport(), VT)}},
                    tmp_path)
    assert json.loads((tmp_path / "bilan.json").read_text(encoding="utf-8"))["T12"]["attack_ratees"] == ["T1082"]
