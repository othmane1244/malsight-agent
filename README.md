# MalSight Agent

> Agent IA **défensif** pour l'analyse assistée de malware, dans un cadre pédagogique.
> Version de soutenance : `v1.0-soutenance` (gel du code, décision D11).

MalSight Agent lit les journaux d'analyse dynamique d'échantillons **bénins**, collectés dans un
laboratoire isolé (Windows Sandbox sans réseau, Sysmon + Procmon). Il en tire un rapport
structuré et **vérifié** :

- comportements observés, avec leur preuve et leur provenance (Sysmon, Procmon) ;
- indicateurs de compromission (IOC), extraits par les outils ;
- techniques MITRE ATT&CK : **liste officielle classée par des règles sourcées**, plus des
  **suggestions du LLM à valider par l'analyste** (décision D10) ;
- contre-mesures MITRE **D3FEND** et recommandations de détection et de remédiation.

L'agent **n'exécute jamais rien** : il ne lit que des données déjà extraites, avec des outils en
lecture seule. Tout rapport passe par un **vérificateur** qui rejette ce qui n'est pas prouvé.

## Principe : « les outils classent, le LLM explique » (D10)

```
Échantillon bénin ─► [1] Labo Windows Sandbox (sans réseau) : Sysmon + Procmon, collecte automatique
                  ─► [2] Fusion Sysmon + Procmon, attribution à l'arbre de l'échantillon, filtre du bruit
                  ─► [3] Dossier de cas JSON (cases/<sha256>/case.json)
                  ─► [4] Règles ATT&CK sourcées (D7)  ──► liste officielle
                      LLM local (Ollama, gemma4:e4b)   ──► résumé, comportements, suggestions, recommandations
                  ─► [5] Vérificateur : preuves, IDs ATT&CK / D3FEND officiels, garde anti-injection (D8)
                  ─► [6] Rapport Markdown + IOC STIX 2.1 ─► validation humaine
```

## Résultats (modèle gemma4:e4b, contexte 8192, notation D9)

**Jeu de développement T01 à T12** (12 techniques attendues ; règles réglées sur ce jeu) :

| Mode | Liste officielle : vraies / FP | Précision | Rappel | Suggestions LLM : vraies / total | IOC | Témoin négatif sans FP | Temps moyen |
| --- | --- | --- | --- | --- | --- | --- | --- |
| règles seules | 10/12 · 0 | 100 % | 83 % | — | 17/17 | oui | < 1 s |
| LLM seul | 0/12 · 0 | — | 0 % | 4 / 5 | 17/17 | oui | 157 s |
| **hybride** | **10/12 · 0** | **100 %** | **83 %** | 0 / 1 | 17/17 | oui | 125 s |

**Jeu de validation T13 à T16** (écrit avant les règles, jamais utilisé pour les régler, D4) :

| Mode | Liste officielle : vraies / FP | Précision | Rappel | Suggestions LLM : vraies / total | IOC | Temps moyen |
| --- | --- | --- | --- | --- | --- | --- |
| règles seules | 2/4 · 0 | 100 % | 50 % | — | 5/5 | < 1 s |
| LLM seul | 0/4 · 0 | — | 0 % | 1 / 2 | 5/5 | 127 s |
| **hybride** | **2/4 · 0** | **100 %** | **50 %** | 0 / 1 | 5/5 | 135 s |

- Les règles **généralisent aux variantes** (RunOnce, tâche créée via COM) sans faux positif,
  mais les techniques **absentes du jeu de développement** (T1033, T1546.013) ne sont trouvées ni
  par les règles ni par le LLM : rappel **83 % → 50 %** en validation.
- **Test anti-injection** (consignes cachées dans les données de l'échantillon, dont 2 consignes
  inédites) : aucune obéissance non bloquée (`docs/resultats/injection_gemma4_e4b/`).
- Détails : [`docs/resultats/`](docs/resultats/) · journal : [`docs/journal.md`](docs/journal.md) ·
  décisions D1 à D11 : [`docs/decisions.md`](docs/decisions.md).

## Commandes principales

Prérequis : Python 3.11, [Ollama](https://ollama.com) avec `gemma4:e4b`, Windows 11 Pro avec
Windows Sandbox pour le labo.

```powershell
py -3.11 -m venv .venv ; .venv\Scripts\activate
pip install -r requirements.txt ; pip install -e .

# Une fois (réseau) : bases MITRE ATT&CK et D3FEND en local ; ensuite tout marche hors ligne
malsight download-attack
malsight download-d3fend

# Labo (hôte) : collecte automatique d'un échantillon de test, puis comparaison à sa vérité terrain
.\lab\scripts\lancer-analyse.ps1 -Echantillon T12      # Windows Sandbox sans réseau (D3)
malsight comparer C:\labo\resultats

# Dossier de cas puis rapport vérifié (Markdown + IOC STIX)
malsight extract lab\echantillons-test\T12_scenario_combine.ps1 --labo cases\T12
malsight analyze cases\<sha256>\case.json

# Évaluation : série d'échantillons, notation, comparaison des modes, test anti-injection
malsight serie docs\resultats\x --mode hybride          # llm | regles | hybride
malsight bilan docs\resultats\x --reverifier
malsight modes regles=docs\resultats\dev_regles hybride=docs\resultats\dev_gemma4_hybride
malsight injection --depuis-rapports
```

Procédure complète du labo : [`lab/README.md`](lab/README.md). Démo de 3 minutes :
[`docs/demo.md`](docs/demo.md).

## Limites

- **Couverture** : la liste officielle ne contient que ce que les règles D7 couvrent
  (8 techniques) ; T1112, T1105, T1033, T1546.013 ne sont pas trouvées. Le LLM ne comble pas ces
  trous de façon fiable : ses techniques restent des suggestions.
- **Petit jeu, échantillons simples** : 16 scripts PowerShell bénins écrits par l'auteur ; pas
  d'exécutables, donc capa et FLOSS (outils pour PE) n'ont pas été utilisés.
- **Pas de réseau simulé** : seules les tentatives (DNS) sont visibles ; pas d'INetSim ni de PCAP.
- **Filtre de bruit** tiré des observations du jeu de développement ; à confirmer sur d'autres
  versions de Windows.
- **Garde anti-injection par motifs** : heuristique contournable (les consignes inédites ne sont
  pas détectées) ; la protection repose sur l'architecture (D8).
- **Pertinence des contre-mesures D3FEND** et des suggestions : vérifiées sur leur existence, pas
  sur leur pertinence ; d'où la validation humaine obligatoire.
- **Non fait (perspectives)** : export PDF, propositions de règles YARA / Sigma, recherche
  vectorielle (Chroma), interface Streamlit, comparaison avec qwen3:8b ou un LLM cloud.

## Usage éthique

- Uniquement des échantillons **bénins** écrits par l'auteur (`lab/echantillons-test/`, avec leur
  vérité terrain) ; aucun échantillon externe ni binaire dans le dépôt.
- Analyse dynamique **uniquement** dans une Windows Sandbox jetable sans réseau ([D1](docs/decisions.md)).
- Aucun comportement d'évasion ([D2](docs/decisions.md)) ; le projet ne produit que de la
  **détection** et des recommandations défensives.

Voir [`docs/ethique.md`](docs/ethique.md).

## Structure du dépôt

```
malsight-agent/
├── docs/          # conception, décisions D1-D11, journal, planning, résultats, démo
├── lab/           # Windows Sandbox, scripts de collecte, échantillons de test, vérités terrain
├── cases/         # (ignoré par git) collectes et dossiers de cas
├── src/malsight/
│   ├── extractors/   # statique, Sysmon, Procmon, fusion du labo
│   ├── attack/       # base ATT&CK, règles sourcées D7
│   ├── defend/       # contre-mesures D3FEND (cache local)
│   ├── agent/        # outils en lecture seule, prompts, vérificateur, garde anti-injection
│   ├── evaluation/   # comparaison, séries, notation, test anti-injection
│   ├── report/       # rapport Markdown, export STIX
│   └── cli.py
└── tests/         # 175 tests rapides + 11 tests PowerShell (pytest -m slow)
```

## Auteur

Projet réalisé **seul** (othmane1244) en 14 jours ; planning et périmètre :
[D5](docs/decisions.md), [`docs/planning.md`](docs/planning.md).

## Licence

MIT, voir [LICENSE](LICENSE).
