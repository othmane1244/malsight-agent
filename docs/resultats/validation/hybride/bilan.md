| Échantillon | ATT&CK attendues | ATT&CK trouvées | Vraies (strict) | Vraies (tolérant) | FP strict | FP tolérant | Ratées (strict) | IOC trouvés / attendus | Suggestions LLM (vraies / total) | Comportements observés / inférés | Rejets | Temps (s) | JSON valide |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| T13 | T1547.001 | T1547.001 | 1 | 1 | — | — | — | 1/1 | 0 / 0 | 1 / 0 | 0 | 115.4 | oui |
| T14 | T1053.005 | T1053.005 | 1 | 1 | — | — | — | 2/2 | 0 / 0 | 2 / 0 | 0 | 171.5 | oui |
| T15 | T1033 | — | 0 | 0 | — | — | T1033 | 1/1 | 0 / 1 (T1087.002) | 3 / 0 | 0 | 126.8 | oui |
| T16 | T1546.013 | — | 0 | 0 | — | — | T1546.013 | 1/1 | 0 / 0 | 1 / 0 | 1 | 124.7 | oui |
| **Total** | 4 |  | **2/4** | **2/4** | 0 | 0 | 2 | 5/5 | 0 / 1 | 7 / 0 | 1 | 538.4 | 4/4 |

Notation ATT&CK (D9) : **strict** = (sous-)technique exacte ; **tolérant** = la technique parente d'une technique attendue compte aussi. Toute technique en trop est un faux positif (FP).

| Score | Vraies | FP | Précision | Rappel |
| --- | --- | --- | --- | --- |
| strict | 2/4 | 0 | 100% | 50% |
| tolérant | 2/4 | 0 | 100% | 50% |
