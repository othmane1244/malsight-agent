| Échantillon | ATT&CK attendues | ATT&CK trouvées | Vraies (strict) | Vraies (tolérant) | FP strict | FP tolérant | Ratées (strict) | IOC trouvés / attendus | Suggestions LLM (vraies / total) | Comportements observés / inférés | Rejets | Temps (s) | JSON valide |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| T01 | T1547.001 | T1547.001 | 1 | 1 | — | — | — | 3/3 | 0 / 0 | 0 / 0 | 0 | 0.0 | oui |
| T02 | T1053.005 | T1053.005 | 1 | 1 | — | — | — | 2/2 | 0 / 0 | 0 / 0 | 0 | 0.0 | oui |
| T03 | T1543.003 | T1543.003 | 1 | 1 | — | — | — | 1/1 | 0 / 0 | 0 / 0 | 0 | 0.0 | oui |
| T04 | T1037.001 | T1037.001 | 1 | 1 | — | — | — | 1/1 | 0 / 0 | 0 / 0 | 0 | 0.0 | oui |
| T05 | T1112 | — | 0 | 0 | — | — | T1112 | 1/1 | 0 / 0 | 0 / 0 | 0 | 0.0 | oui |
| T06 | T1059.001 | T1059.001 | 1 | 1 | — | — | — | 1/1 | 0 / 0 | 0 / 0 | 0 | 0.0 | oui |
| T07 | T1082 | T1082 | 1 | 1 | — | — | — | 1/1 | 0 / 0 | 0 / 0 | 0 | 0.0 | oui |
| T08 | T1016 | T1016 | 1 | 1 | — | — | — | 1/1 | 0 / 0 | 0 / 0 | 0 | 0.0 | oui |
| T09 | T1560 | T1560 | 1 | 1 | — | — | — | 1/1 | 0 / 0 | 0 / 0 | 0 | 0.0 | oui |
| T10 | T1105 | — | 0 | 0 | — | — | T1105 | 1/1 | 0 / 0 | 0 / 0 | 0 | 0.0 | oui |
| T11 | — | — | 0 | 0 | — | — | — | 1/1 | 0 / 0 | 0 / 0 | 0 | 0.0 | oui |
| T12 | T1082, T1547.001 | T1082, T1547.001 | 2 | 2 | — | — | — | 3/3 | 0 / 0 | 0 / 0 | 0 | 0.0 | oui |
| **Total** | 12 |  | **10/12** | **10/12** | 0 | 0 | 2 | 17/17 | 0 / 0 | 0 / 0 | 0 | 0.0 | 12/12 |

Notation ATT&CK (D9) : **strict** = (sous-)technique exacte ; **tolérant** = la technique parente d'une technique attendue compte aussi. Toute technique en trop est un faux positif (FP).

| Score | Vraies | FP | Précision | Rappel |
| --- | --- | --- | --- | --- |
| strict | 10/12 | 0 | 100% | 83% |
| tolérant | 10/12 | 0 | 100% | 83% |
