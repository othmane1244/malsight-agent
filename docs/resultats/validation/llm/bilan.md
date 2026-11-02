| Échantillon | ATT&CK attendues | ATT&CK trouvées | Vraies (strict) | Vraies (tolérant) | FP strict | FP tolérant | Ratées (strict) | IOC trouvés / attendus | Suggestions LLM (vraies / total) | Comportements observés / inférés | Rejets | Temps (s) | JSON valide |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| T13 | T1547.001 | — | 0 | 0 | — | — | T1547.001 | 1/1 | 1 / 1 (T1547.001) | 0 / 1 | 4 | 105.8 | oui |
| T14 | T1053.005 | — | 0 | 0 | — | — | T1053.005 | 2/2 | 0 / 1 (T1053) | 3 / 0 | 4 | 143.3 | oui |
| T15 | T1033 | — | 0 | 0 | — | — | T1033 | 1/1 | 0 / 0 | 3 / 0 | 1 | 132.0 | oui |
| T16 | T1546.013 | — | 0 | 0 | — | — | T1546.013 | 1/1 | 0 / 0 | 1 / 0 | 1 | 127.7 | oui |
| **Total** | 4 |  | **0/4** | **0/4** | 0 | 0 | 4 | 5/5 | 1 / 2 | 7 / 1 | 10 | 508.8 | 4/4 |

Notation ATT&CK (D9) : **strict** = (sous-)technique exacte ; **tolérant** = la technique parente d'une technique attendue compte aussi. Toute technique en trop est un faux positif (FP).

| Score | Vraies | FP | Précision | Rappel |
| --- | --- | --- | --- | --- |
| strict | 0/4 | 0 | — | 0% |
| tolérant | 0/4 | 0 | — | 0% |
