"""Interface en ligne de commande : malsight extract | analyze | comparer | download-attack | download-d3fend."""
from __future__ import annotations

from pathlib import Path

import typer

from malsight.schemas import Case

app = typer.Typer(help="MalSight Agent : analyse défensive assistée par IA (pédagogique).")


@app.command()
def extract(sample: Path, cape_report: Path = typer.Option(None, help="Rapport JSON CAPEv2"),
            yara_rules: Path = typer.Option(None, help="Dossier de règles .yar"),
            labo: Path = typer.Option(None, help="Dossier de collecte du labo (sysmon.csv + procmon.csv), ex. cases/T02"),
            cases_dir: Path = Path("cases")):
    """Analyse statique + lecture des données dynamiques (CAPE ou labo) -> dossier de cas JSON."""
    from malsight.normalize import build_case, save_case
    out = save_case(build_case(sample, cape_report, yara_rules, labo), cases_dir)
    typer.echo(f"Dossier de cas : {out}")


@app.command()
def analyze(case_file: Path, out: Path = typer.Option(None, help="Rapport Markdown de sortie"),
            no_llm: bool = typer.Option(False, help="Sans LLM : faits extraits et règles D7 uniquement"),
            attack_db: Path = Path("data/enterprise-attack.json"),
            d3fend_cache: Path = typer.Option(Path("data/d3fend"), help="Cache local D3FEND (hors ligne)")):
    """Dossier de cas -> rapport vérifié (Markdown + IOC STIX)."""
    from malsight.agent.pipeline import analyze as run
    from malsight.defend.kb import DefendKB
    from malsight.report.render import to_markdown, to_stix
    kb = None
    if attack_db.exists():
        from malsight.attack.kb import AttackKB
        kb = AttackKB.load(attack_db)
    else:
        typer.echo("Base ATT&CK absente : lancez `malsight download-attack` (IDs non vérifiés).")
    defend = DefendKB(d3fend_cache)
    if not any(d3fend_cache.glob("T*.json")):
        typer.echo("Cache D3FEND vide : lancez `malsight download-d3fend` (aucune contre-mesure).")
    case = Case.model_validate_json(case_file.read_text(encoding="utf-8"))
    # D10 : la liste officielle vient des règles D7 (et de capa) ; le LLM ajoute résumé, suggestions et
    # recommandations. --no-llm : règles seules (mode « regles »), sans appel au modèle.
    report = run(case, use_llm=not no_llm, kb=kb, defend=defend, regles=True)
    out = out or case_file.with_name("rapport.md")
    out.write_text(to_markdown(report), encoding="utf-8")
    case_file.with_name("report.json").write_text(report.model_dump_json(indent=2), encoding="utf-8")
    try:
        case_file.with_name("iocs.stix.json").write_text(to_stix(report), encoding="utf-8")
    except ImportError:
        pass
    typer.echo(f"Rapport : {out}")


@app.command()
def comparer(resultats: Path = typer.Argument(..., help="Dossier de collecte (ou dossier qui en contient un, ex. cases/T02)"),
             verite: Path = typer.Option(None, help="Vérité terrain (défaut : lab/verite-terrain/<Tnn>.json d'après le manifeste)"),
             verites: Path = typer.Option(Path("lab/verite-terrain"), help="Dossier des vérités terrain")):
    """Compare un dossier de résultats du labo à sa vérité terrain (IOC attendu / trouvé / source)."""
    from malsight.evaluation.comparer import comparer as run, tableau, trouver_dossier, verite_pour
    dossier = trouver_dossier(resultats)
    vt, res = run(dossier, verite or verite_pour(dossier, verites))
    typer.echo(tableau(vt, res))
    if not all(r.trouve for r in res):
        raise typer.Exit(1)


@app.command()
def serie(sortie: Path = typer.Argument(..., help="Dossier de résultats, ex. docs/resultats/dev_gemma4"),
          echantillon: list[str] = typer.Option(None, help="Tnn (répétable) ; défaut : T01 à T12 (jeu de développement)"),
          cases: Path = typer.Option(Path("cases"), help="Collectes du labo (cases/Tnn)"),
          mode: str = typer.Option("llm", help="llm (LLM seul) | regles (règles D7 seules, sans LLM) | hybride"),
          attack_db: Path = Path("data/enterprise-attack.json"),
          d3fend_cache: Path = Path("data/d3fend")):
    """Agent (LLM_MODEL) sur une série d'échantillons du labo, comparé aux vérités terrain."""
    from malsight.agent.pipeline import analyze as run
    from malsight.attack.kb import AttackKB
    from malsight.defend.kb import DefendKB
    from malsight.evaluation.serie import MODES, lancer_serie
    if mode not in MODES:
        raise typer.BadParameter(f"mode inconnu : {mode} (attendu : {', '.join(MODES)})")
    use_llm, regles = MODES[mode]
    kb = AttackKB.load(attack_db) if attack_db.exists() else None
    defend = DefendKB(d3fend_cache)
    ids = echantillon or [f"T{i:02d}" for i in range(1, 13)]
    lancer_serie(ids, sortie, lambda c: run(c, use_llm=use_llm, kb=kb, defend=defend, regles=regles),
                 cases=cases, journal=typer.echo, mode=mode)
    typer.echo(f"Résultats : {sortie} (bilan.md, bilan.csv, bilan.json)")


@app.command()
def injection(base_connues: str = typer.Option("T11", help="Base des variantes 1 à 4 (défaut : témoin négatif T11)"),
              base_inedites: str = typer.Option("T01", help="Base des variantes inédites 5a / 5b (domaine, clé Run)"),
              sortie: Path = typer.Option(None, help="Dossier de résultats (défaut : docs/resultats/injection_<modèle>)"),
              mode: str = typer.Option("hybride", help="llm | hybride"),
              depuis_rapports: bool = typer.Option(False, help="Recalculer critères et tableau à partir des rapports "
                                                              "déjà enregistrés, sans relancer l'agent"),
              cases: Path = Path("cases"), attack_db: Path = Path("data/enterprise-attack.json"),
              d3fend_cache: Path = Path("data/d3fend")):
    """Test anti-injection (#12) : variantes 1 à 4 (connues) et 5a / 5b (inédites) ; critères et
    classement (le LLM a résisté / le LLM a obéi mais le vérificateur a bloqué / échec)."""
    import json
    import os

    from malsight.agent.pipeline import analyze as run
    from malsight.attack.kb import AttackKB
    from malsight.defend.kb import DefendKB
    from malsight.evaluation.injection import (ECHEC, VARIANTES, VARIANTES_INEDITES, ecrire_resultats,
                                               evaluer_injection, recharger)
    from malsight.evaluation.serie import MODES
    from malsight.normalize import build_case
    use_llm, regles = MODES[mode]
    kb = AttackKB.load(attack_db) if attack_db.exists() else None
    defend = DefendKB(d3fend_cache)

    def charger(tid):
        vt = json.loads(Path(f"lab/verite-terrain/{tid}.json").read_text(encoding="utf-8"))
        return build_case(Path("lab/echantillons-test") / vt["echantillon"], labo=cases / tid)

    def analyser(c):
        return run(c, use_llm=use_llm, kb=kb, defend=defend, regles=regles)

    modele = os.getenv("LLM_MODEL", "gemma4:e4b") if use_llm else "sans LLM"
    sortie = sortie or Path("docs/resultats") / f"injection_{modele.replace(':', '_')}"
    if depuis_rapports:
        from malsight.agent.verifier import verify
        ref_c, res_c, ref_i, res_i = recharger(
            sortie, base_connues, base_inedites, cas_connues=charger(base_connues), cas_inedites=charger(base_inedites),
            verifier=lambda r, c: verify(r, c, kb, defend))
    else:
        ref_c, res_c = evaluer_injection(charger(base_connues), analyser, variantes=VARIANTES)
        ref_i, res_i = evaluer_injection(charger(base_inedites), analyser, variantes={}, inedites=VARIANTES_INEDITES)
    lignes = ecrire_resultats(sortie, f"# Test anti-injection : mode {mode}, modèle {modele}",
                              base_connues, ref_c, res_c, base_inedites, ref_i, res_i)
    typer.echo("\n".join(lignes))
    if any(res["classement"] == ECHEC for res in [*res_c.values(), *res_i.values()]):
        raise typer.Exit(1)


@app.command()
def bilan(sortie: list[Path] = typer.Argument(..., help="Dossier(s) de série, ex. docs/resultats/dev_regles"),
          reverifier: bool = typer.Option(False, help="Appliquer le vérificateur actuel aux rapports enregistrés"),
          cases: Path = Path("cases"), attack_db: Path = Path("data/enterprise-attack.json"),
          d3fend_cache: Path = Path("data/d3fend")):
    """Recalcule la notation (D9 : strict / tolérant) de séries existantes, sans relancer l'agent."""
    from malsight.evaluation.serie import renoter, scores
    fonction = None
    if reverifier:
        from malsight.agent.verifier import verify
        from malsight.attack.kb import AttackKB
        from malsight.defend.kb import DefendKB
        from malsight.normalize import build_case
        kb = AttackKB.load(attack_db) if attack_db.exists() else None
        defend = DefendKB(d3fend_cache)

        def fonction(tid, rapport):
            import json as _json
            vt = _json.loads(Path(f"lab/verite-terrain/{tid}.json").read_text(encoding="utf-8"))
            case = build_case(Path("lab/echantillons-test") / vt["echantillon"], labo=cases / tid)
            return verify(rapport, case, kb, defend)
    for s in sortie:
        sc = scores(renoter(s, reverifier=fonction))
        typer.echo(f"{s} : strict {sc['strict']['vraies']}/{sc['attendues']} (FP {sc['strict']['fp']}), "
                   f"tolérant {sc['tolerant']['vraies']}/{sc['attendues']} (FP {sc['tolerant']['fp']})")


@app.command()
def modes(serie: list[str] = typer.Argument(..., help="mode=dossier, ex. regles=docs/resultats/dev_regles"),
          sortie: Path = typer.Option(None, help="Fichier Markdown où écrire le tableau")):
    """Tableau comparatif des modes (strict / tolérant, précision, rappel, FP, IOC, temps moyen)."""
    from malsight.evaluation.serie import tableau_modes
    lignes = tableau_modes({m: Path(d) for m, d in (s.split("=", 1) for s in serie)})
    if sortie:
        sortie.write_text("\n".join(lignes) + "\n", encoding="utf-8")
    typer.echo("\n".join(lignes))


@app.command("download-attack")
def download_attack(dest: Path = Path("data/enterprise-attack.json")):
    """Télécharge la base MITRE ATT&CK Enterprise (STIX)."""
    from malsight.attack.kb import download
    typer.echo(f"Base ATT&CK : {download(dest)}")


@app.command("download-d3fend")
def download_d3fend(verites: Path = typer.Option(Path("lab/verite-terrain"), help="Vérités terrain (techniques à couvrir)"),
                    technique: list[str] = typer.Option(None, help="Technique ATT&CK supplémentaire (répétable)"),
                    cache: Path = typer.Option(Path("data/d3fend"), help="Cache local D3FEND")):
    """Pré-remplit le cache D3FEND (réseau) ; l'analyse l'utilise ensuite hors ligne."""
    from malsight.defend.kb import download, techniques_des_verites
    tids = sorted(set(techniques_des_verites(verites)) | set(technique or []))
    for tid, n in download(tids, cache).items():
        typer.echo(f"{tid} : {n} contre-mesure(s)")
    typer.echo(f"Cache D3FEND : {cache} ({len(tids)} techniques)")


if __name__ == "__main__":
    app()
