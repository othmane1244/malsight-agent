# CLAUDE.md : règles du projet MalSight Agent

La conception de référence est dans [`docs/conception.md`](docs/conception.md). En cas de doute sur un choix d'architecture, s'y reporter.

## Cadre : pédagogique et défensif uniquement

- Aucun code offensif : pas d'exploit, de charge utile, de technique d'évasion ni d'outil d'attaque. Le projet ne produit que des règles de **détection** (YARA, Sigma) et des recommandations de durcissement et de remédiation.
- Aucune exécution d'échantillon, ni par le code du projet ni pendant le développement. L'analyse dynamique se fait en dehors du projet, dans le laboratoire isolé ; le projet ne fait que **lire** les rapports produits.

## Agent

- Les outils de `src/malsight/agent/tools.py` restent en **lecture seule** sur le dossier de cas. Ne jamais y ajouter d'outil qui exécute, écrit ou contacte le réseau. `tests/test_pipeline.py::test_tools_are_read_only` fige la liste des outils : ne pas l'élargir pour contourner cette règle.
- Chaque fait du rapport (IOC, API, technique ATT&CK, comportement) doit citer sa preuve issue du dossier de cas.
- Le vérificateur (`src/malsight/agent/verifier.py`) ne doit **jamais** être contourné : tout rapport passe par `verify()` avant d'être rendu ou exporté.

## Dépôt

- Jamais d'échantillon, de binaire (`.exe`, `.dll`, `.bin`...), de PCAP ou de zip dans git. `samples/` et `cases/` sont ignorés ; ne pas modifier `.gitignore` pour les inclure.
- **Seule exception** : les scripts **texte bénins écrits par l'équipe**, rangés dans `lab/echantillons-test/`, chacun avec sa vérité terrain dans `lab/verite-terrain/` (même identifiant, ex. `T01`). Tout le reste (binaires, échantillons externes, zip, même bénins) reste interdit.

## Environnement et tests

- Python 3.11, venv dans `.venv` (Windows : `py -3.11 -m venv .venv`).
- `capa` et `floss` sont des binaires autonomes (pas des paquets pip), à placer dans le `PATH`.
- Lancer `pytest` avant chaque commit ; ne pas committer si un test échoue.
- Ajouter un test pour chaque nouvelle fonction.

## Langue

- Documentation, commentaires de documentation et messages de commit en **français**.
