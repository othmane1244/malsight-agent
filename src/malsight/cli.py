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
            no_llm: bool = typer.Option(False, help="Sans LLM : faits extraits uniquement"),
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
    report = run(case, use_llm=not no_llm, kb=kb, defend=defend)
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
