# Architecture

Les faits viennent des outils ; l'agent les corrèle et rédige.

| Étage | Rôle | Outils | Sortie |
| --- | --- | --- | --- |
| 1. Laboratoire isolé | Analyse statique et dynamique de l'échantillon | pefile, FLOSS, YARA, capa, CAPEv2 ou Sysmon/Procmon, INetSim | Sorties brutes (JSON, logs) |
| 2. Normalisation | Fusionner les sorties dans un format unique | Python, Pydantic | `cases/<sha256>/case.json` |
| 3. Agent IA | Corréler, mapper sur ATT&CK, rédiger | LangGraph, Ollama, mitreattack-python, Chroma | Rapport JSON brut |
| 4. Vérificateur + rapport | Rejeter tout fait sans preuve, valider les IDs ATT&CK, mettre en forme | Pydantic, Jinja2, stix2 | `rapport.md`, `iocs.stix.json` |
| 5. Validation humaine | Relire, corriger, publier | — | Rapport final |

## Règles de conception

1. Chaque IOC, API ou technique cite sa **preuve** (`evidence`) issue du dossier de cas.
2. Les techniques ATT&CK viennent de capa (confiance haute) ou du LLM (confiance moyenne/basse), et leurs IDs sont **toujours** vérifiés contre la base officielle.
3. Les outils exposés à l'agent sont en **lecture seule** : aucun outil d'exécution.
4. Le contenu de l'échantillon (chaînes, noms) est une **donnée non fiable** : il est délimité dans les prompts (anti-injection).
5. Le rapport sépare **faits observés**, **inférences** et **incertitudes**.
