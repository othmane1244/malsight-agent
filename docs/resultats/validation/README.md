# Jeu de validation T13 à T16 : résultats (D4)

**Modèle : gemma4:e4b** (Ollama, contexte 8192) · notation D9 sur la liste officielle (outils) ·
suggestions du LLM à part (D10). Jeu **écrit avant les règles D7** (commit 43ef7d7), jamais
utilisé pour régler filtres, règles, parseurs ou prompts. Collecte du 3 novembre en mode
automatique (D3), aucune correction de fait de la vérité terrain (tableau D4 vide).

Généré par `malsight modes regles=validation/regles llm=validation/llm hybride=validation/hybride`.
Détails par échantillon : `regles/`, `llm/`, `hybride/` (`bilan.md`, `report.json`, `rapport.md`).

| Mode | Strict : vraies | Strict : FP | Strict : précision | Strict : rappel | Tolérant : vraies | Tolérant : FP | Tolérant : précision | Tolérant : rappel | Suggestions LLM : vraies / total | IOC | JSON valides | Temps moyen (s) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `regles` | 2/4 | 0 | 100% | 50% | 2/4 | 0 | 100% | 50% | 0 / 0 | 5/5 | 4/4 | 0.0 |
| `llm` | 0/4 | 0 | — | 0% | 0/4 | 0 | — | 0% | 1 / 2 (tolérant : 2 / 2) | 5/5 | 4/4 | 127.2 |
| `hybride` | **2/4** | **0** | **100%** | 50% | 2/4 | 0 | 100% | 50% | 0 / 1 | 5/5 | 4/4 | 134.6 |

Pas de témoin négatif dans ce jeu (colonne omise).

## Par échantillon

| Échantillon | Attendue | Rôle | `regles` | `llm` (suggestions) | `hybride` (officielle / suggestions) |
| --- | --- | --- | --- | --- | --- |
| T13 RunOnce | T1547.001 | technique du jeu de dev., réalisée autrement | ✅ | T1547.001 ✅ | ✅ / — |
| T14 tâche via COM | T1053.005 | technique du jeu de dev., réalisée autrement | ✅ | T1053 (parente : tolérant ✅) | ✅ / — |
| T15 `whoami /all` | T1033 | technique **absente** du jeu de dev. | ✗ (pas de règle) | — | ✗ / T1087.002 ✗ |
| T16 profil PowerShell | T1546.013 | technique **absente** du jeu de dev. | ✗ (pas de règle) | — | ✗ / — |

## Lecture

- **Les règles généralisent aux variantes** : RunOnce (T13) et la tâche créée via l'API COM
  (T14) sont reconnues sans faux positif, alors qu'elles n'existaient pas dans le jeu de
  développement (les règles reposent sur des artefacts tirés des sources ATT&CK / Sigma).
- **Les techniques absentes du jeu de développement ne sont pas trouvées** : aucune règle ne
  couvre T1033 ni T1546.013 (choix D4 / D7), et le LLM ne les propose pas non plus. En hybride, il
  suggère T1087.002 (*Domain Account*) pour `whoami /all` : même famille (découverte), mauvaise
  technique, signalée « à valider ».
- **Précision officielle maintenue à 100 %** (0 faux positif), comme sur le développement ;
  **rappel 50 %** contre 83 % sur le développement : c'est l'estimation honnête de la
  généralisation à des techniques nouvelles.
- Le vérificateur a rejeté 2 techniques sans preuve vérifiable (T1059.001 sur T15, T1021.001 sur
  T16) et retiré 8 ID D3FEND inventés des recommandations du mode `llm`.
- IOC 5/5, JSON 4/4 dans les trois modes.
