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


# ---------- Notation ATT&CK (D9) : strict / tolérant ----------

import pytest  # noqa: E402

from malsight.evaluation.serie import noter_attack, renoter, scores  # noqa: E402


@pytest.mark.parametrize("trouvees, attendues, vraies, fp, vraies_tol, fp_tol", [
    (["T1053.005"], {"T1053.005"}, ["T1053.005"], [], ["T1053.005"], []),           # exacte
    (["T1053"], {"T1053.005"}, [], ["T1053"], ["T1053.005"], []),                   # parente : tolérant seul
    (["T1053", "T1027"], {"T1053.005"}, [], ["T1027", "T1053"], ["T1053.005"], ["T1027"]),
    (["T1560.001"], {"T1560"}, [], ["T1560.001"], [], ["T1560.001"]),               # sous-technique : FP (règle littérale)
    (["T1082"], {"T1016"}, [], ["T1082"], [], ["T1082"]),                           # voisine : FP partout
    ([], set(), [], [], [], []),                                                    # témoin négatif
    (["T1059.001"], set(), [], ["T1059.001"], [], ["T1059.001"]),                   # FP sur le témoin
])
def test_noter_attack(trouvees, attendues, vraies, fp, vraies_tol, fp_tol):
    n = noter_attack(trouvees, attendues)
    assert (n["attack_vraies"], n["attack_en_trop"]) == (vraies, fp)
    assert (n["attack_vraies_tol"], n["attack_en_trop_tol"]) == (vraies_tol, fp_tol)


def test_scores_et_tableau(tmp_path):
    bilan = {
        "T02": {"echantillon": "T02", "json_valide": True, "temps_s": 1, "attack_attendues": ["T1053.005"],
                **noter_attack(["T1053", "T1027"], {"T1053.005"})},
        "T03": {"echantillon": "T03", "json_valide": False, "temps_s": 1, "attack_attendues": ["T1543.003"]},
    }
    s = scores(bilan)
    assert s["attendues"] == 2
    assert (s["strict"]["vraies"], s["strict"]["fp"]) == (0, 2)
    assert (s["tolerant"]["vraies"], s["tolerant"]["fp"]) == (1, 1)
    assert s["tolerant"]["precision"] == 0.5 and s["tolerant"]["rappel"] == 0.5
    for l in bilan.values():
        l.update(iocs_trouves=0, iocs_attendus=0, comportements_observes=0, comportements_inferes=0, rejets=[])
    ecrire_tableaux(bilan, tmp_path)
    md = (tmp_path / "bilan.md").read_text(encoding="utf-8")
    assert "| strict | 0/2 | 2 | 0% | 0% |" in md and "| tolérant | 1/2 | 1 | 50% | 50% |" in md


def test_tableau_modes(tmp_path):
    from malsight.evaluation.serie import tableau_modes
    for mode, trouvees, temps in (("regles", ["T1053.005"], 0.0), ("llm", ["T1053", "T1027"], 120.0)):
        bilan = {
            "T02": {"echantillon": "T02", "json_valide": True, "temps_s": temps, "attack_attendues": ["T1053.005"],
                    "iocs_trouves": 2, "iocs_attendus": 2, **noter_attack(trouvees, {"T1053.005"})},
            "T11": {"echantillon": "T11", "json_valide": True, "temps_s": temps, "attack_attendues": [],
                    "iocs_trouves": 1, "iocs_attendus": 1, **noter_attack([], set())},
        }
        (tmp_path / mode).mkdir()
        (tmp_path / mode / "bilan.json").write_text(json.dumps(bilan), encoding="utf-8")
    lignes = tableau_modes({"regles": tmp_path / "regles", "llm": tmp_path / "llm"})
    assert lignes[2].startswith("| `regles` | 1/1 | 0 | 100% | 100% | 1/1 | 0 |")
    assert lignes[3].startswith("| `llm` | 0/1 | 2 | 0% | 0% | 1/1 | 1 | 50% | 100% |")
    assert "| 3/3 | oui | 2/2 | 120.0 |" in lignes[3]


def test_renoter_a_partir_des_rapports(tmp_path):
    verites = tmp_path / "verites"
    verites.mkdir()
    (verites / "T12.json").write_text(json.dumps(VT), encoding="utf-8")
    (tmp_path / "T12").mkdir()
    (tmp_path / "T12" / "report.json").write_text(_rapport().model_dump_json(), encoding="utf-8")
    (tmp_path / "bilan.json").write_text(json.dumps({"T12": {"json_valide": True, "temps_s": 9.9,
                                                             "attack_vraies": []}}), encoding="utf-8")
    b = renoter(tmp_path, verites)
    assert b["T12"]["attack_vraies"] == ["T1547.001"] and b["T12"]["attack_vraies_tol"] == ["T1547.001"]
    assert b["T12"]["temps_s"] == 9.9                                   # champs non liés conservés
    assert "Vraies (tolérant)" in (tmp_path / "bilan.md").read_text(encoding="utf-8")
    # Revérification : le rapport enregistré est remplacé par celui du vérificateur actuel
    def sans_t1059(tid, r):
        r.attack = [t for t in r.attack if t.id != "T1059.001"]
        return r
    b = renoter(tmp_path, verites, reverifier=sans_t1059)
    assert b["T12"]["reverifie"] is True and b["T12"]["attack_trouvees"] == ["T1547.001"]
    assert "T1059.001" not in (tmp_path / "T12" / "report.json").read_text(encoding="utf-8")
