# MalSight Agent

> Agent IA **défensif** pour l'analyse assistée de malware, dans un cadre pédagogique.

MalSight Agent lit les résultats d'analyses **statique** et **dynamique** d'échantillons **bénins**, produits dans un laboratoire isolé. Il en tire une synthèse structurée :

- comportements observés (fichiers, registre, processus, réseau)
- indicateurs de compromission (IOC)
- API Windows sensibles, regroupées par finalité
- techniques MITRE ATT&CK, chacune avec sa preuve
- recommandations de détection et de remédiation

L'agent **n'exécute jamais rien**. Il ne consulte que des données déjà extraites, avec des outils en lecture seule.

## Architecture

```
Échantillon bénin ──► [1] Laboratoire isolé (statique : pefile, FLOSS, YARA, capa
                                              dynamique : CAPEv2 ou Sysmon/Procmon)
                  ──► [2] Normalisation  → dossier de cas JSON (cases/<sha256>/case.json)
                  ──► [3] Agent IA (lecture seule) : planificateur → outils → RAG ATT&CK → vérificateur
                  ──► [4] Rapport validé (JSON → Markdown/PDF, IOC en STIX 2.1)
                  ──► [5] Validation humaine
```

Les détails sont dans [`docs/architecture.md`](docs/architecture.md).

## Structure du dépôt

```
malsight-agent/
├── docs/                  # architecture, planning, éthique, état de l'art
├── lab/                   # guide d'installation du laboratoire isolé
├── samples/               # (ignoré par git) échantillons, JAMAIS commités
├── cases/                 # (ignoré par git) dossiers de cas générés
├── src/malsight/
│   ├── schemas.py         # modèles Pydantic : dossier de cas + rapport
│   ├── extractors/        # analyse statique et parseurs de rapports dynamiques
│   ├── normalize.py       # construit le dossier de cas JSON
│   ├── attack/            # base ATT&CK (validation des IDs, RAG)
│   ├── agent/             # outils en lecture seule, prompts, vérificateur
│   ├── report/            # génération du rapport (Jinja2)
│   └── cli.py             # point d'entrée en ligne de commande
└── tests/
```

## Démarrage rapide

Prérequis : Python 3.11.

```bash
python3.11 -m venv .venv && source .venv/bin/activate   # Windows : py -3.11 -m venv .venv ; .venv\Scripts\activate
pip install -r requirements.txt
pip install -e .

# 1. Extraire et normaliser (statique, + rapport CAPE optionnel)
malsight extract samples/test.exe --cape-report rapports/cape.json

# 2. Lancer l'agent sur le dossier de cas et produire le rapport
malsight analyze cases/<sha256>/case.json --out cases/<sha256>/rapport.md
```

Les outils `capa` et `floss` s'installent séparément, sous forme de binaires autonomes, et doivent être accessibles dans le `PATH` :

- capa : [releases](https://github.com/mandiant/capa/releases)
- FLOSS : [releases](https://github.com/mandiant/flare-floss/releases) (`floss.exe` sous Windows). Le paquet pip `flare-floss` n'est pas utilisé : sa dépendance `binary2strings` n'a pas de wheel Windows et demande un compilateur C++.

Sans ces binaires, le pipeline fonctionne quand même : pas de règles capa, et une extraction de chaînes ASCII/UTF-16 simple à la place de FLOSS.

## Usage éthique

- Uniquement des échantillons **bénins ou pédagogiques** (binaires de test, Atomic Red Team, EICAR, échantillons fournis par l'encadrant).
- Analyse dynamique **uniquement** dans un environnement isolé et jetable, sans accès Internet réel : Windows Sandbox sans réseau pour l'instant ([D1](docs/decisions.md)), VM + INetSim seulement si décidé au jalon J2.
- Aucun échantillon n'est versionné dans ce dépôt.
- Le projet produit des règles de **détection**, jamais de code offensif.

Voir [`docs/ethique.md`](docs/ethique.md).

## Équipe

| Rôle | Membre |
| --- | --- |
| Laboratoire + extraction | _à compléter_ |
| Agent + RAG ATT&CK | _à compléter_ |
| Rapport + évaluation | _à compléter_ |

## Licence

MIT, voir [LICENSE](LICENSE).
