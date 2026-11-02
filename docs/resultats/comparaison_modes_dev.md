# Comparaison des 3 modes : jeu de développement T01 à T12 (tableau final, D10)

**Modèle : gemma4:e4b** (Ollama, contexte 8192) · notation D9 sur la **liste officielle**
(outils : règles D7, capa) · suggestions du LLM comptées à part (D10) · 12 techniques attendues
(T11 = témoin négatif, aucune). Généré par
`malsight modes regles=dev_regles llm=dev_gemma4_llm hybride=dev_gemma4_hybride`.

| Mode | Strict : vraies | Strict : FP | Strict : précision | Strict : rappel | Tolérant : vraies | Tolérant : FP | Tolérant : précision | Tolérant : rappel | Suggestions LLM : vraies / total | IOC | Témoin négatif sans FP | JSON valides | Temps moyen (s) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `regles` | 10/12 | 0 | 100% | 83% | 10/12 | 0 | 100% | 83% | 0 / 0 | 17/17 | oui | 12/12 | 0.0 |
| `llm` | 0/12 | 0 | — | 0% | 0/12 | 0 | — | 0% | 4 / 5 | 17/17 | oui | 12/12 | 156.6 |
| `hybride` | **10/12** | **0** | **100%** | 83% | **10/12** | **0** | **100%** | 83% | 0 / 1 | 17/17 | oui | 12/12 | 124.8 |

Suggestions gardées : `llm` : T01 T1547.001 ✓, T03 T1543.003 ✓, T09 T1074 ✗, T12 T1082 ✓ et
T1547.001 ✓ ; `hybride` : T10 T1566.001 ✗ (aucune règle ne couvre T1566.001).

## Comment ces séries ont été obtenues

- `regles` : sans LLM, déterministe.
- `llm` : série du 3 novembre (contexte 8192), revérifiée avec le vérificateur actuel (D8 + D10)
  à partir des rapports enregistrés (`malsight bilan --reverifier`). Le vérificateur ne fait que
  retirer ou déplacer : mêmes brouillons du LLM.
- `hybride` : relancée le 3 novembre avec le vérificateur D8, puis revérifiée avec D10.
- En mode `llm`, la liste officielle est vide par construction (aucun outil n'y classe) ; le
  filtre des suggestions utilise quand même le déclenchement des règles (D10).

## Évolution

| Étape | `llm` strict (vraies / FP) | `hybride` strict (vraies / FP) |
| --- | --- | --- |
| Contexte 8192, règles D7 | 4/12 · 8 | 10/12 · 2 |
| + preuve vérifiable des techniques LLM (D8) | 4/12 · 4 | 10/12 · 3 (relance, LLM non déterministe) |
| + D10 (liste officielle = outils ; LLM en suggestions) | 0/12 · 0 (suggestions 4/5) | **10/12 · 0** (suggestions 0/1) |

## Lecture

- **Les outils classent** : 10/12 sans aucun faux positif. T1112 (T05) et T1105 (T10) n'ont
  volontairement pas de règle (D7) et restent ratées.
- **Le LLM explique** : résumé, comportements regroupés, recommandations D3FEND, et suggestions
  à valider. Seules, ses suggestions sont justes 4 fois sur 5 ; en hybride, la seule restante
  (T1566.001 sur un domaine) est fausse et clairement signalée comme suggestion.
- Témoin négatif T11 : aucun faux positif. IOC : 17/17. JSON : 12/12.
