| Échantillon | ATT&CK attendues | ATT&CK trouvées | Vraies (strict) | Vraies (tolérant) | FP strict | FP tolérant | Ratées (strict) | IOC trouvés / attendus | Suggestions LLM (vraies / total) | Comportements observés / inférés | Rejets | Temps (s) | JSON valide |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| T01 | T1547.001 | — | 0 | 0 | — | — | T1547.001 | 3/3 | 1 / 1 (T1547.001) | 3 / 0 | 12 | 175.9 | oui |
| T02 | T1053.005 | — | 0 | 0 | — | — | T1053.005 | 2/2 | 0 / 0 | 3 / 0 | 13 | 191.0 | oui |
| T03 | T1543.003 | — | 0 | 0 | — | — | T1543.003 | 1/1 | 1 / 1 (T1543.003) | 0 / 1 | 3 | 148.2 | oui |
| T04 | T1037.001 | — | 0 | 0 | — | — | T1037.001 | 1/1 | 0 / 0 | 1 / 1 | 13 | 163.8 | oui |
| T05 | T1112 | — | 0 | 0 | — | — | T1112 | 1/1 | 0 / 0 | 3 / 0 | 13 | 190.9 | oui |
| T06 | T1059.001 | — | 0 | 0 | — | — | T1059.001 | 1/1 | 0 / 0 | 2 / 0 | 1 | 152.8 | oui |
| T07 | T1082 | — | 0 | 0 | — | — | T1082 | 1/1 | 0 / 0 | 3 / 0 | 1 | 144.8 | oui |
| T08 | T1016 | — | 0 | 0 | — | — | T1016 | 1/1 | 0 / 0 | 3 / 0 | 8 | 178.0 | oui |
| T09 | T1560 | — | 0 | 0 | — | — | T1560 | 1/1 | 0 / 1 (T1074) | 1 / 0 | 0 | 157.9 | oui |
| T10 | T1105 | — | 0 | 0 | — | — | T1105 | 1/1 | 0 / 0 | 0 / 15 | 13 | 164.8 | oui |
| T11 | — | — | 0 | 0 | — | — | — | 1/1 | 0 / 0 | 1 / 0 | 0 | 90.5 | oui |
| T12 | T1082, T1547.001 | — | 0 | 0 | — | — | T1082, T1547.001 | 3/3 | 2 / 2 (T1082, T1547.001) | 4 / 0 | 19 | 120.3 | oui |
| **Total** | 12 |  | **0/12** | **0/12** | 0 | 0 | 12 | 17/17 | 4 / 5 | 24 / 17 | 96 | 1878.9 | 12/12 |

Notation ATT&CK (D9) : **strict** = (sous-)technique exacte ; **tolérant** = la technique parente d'une technique attendue compte aussi. Toute technique en trop est un faux positif (FP).

| Score | Vraies | FP | Précision | Rappel |
| --- | --- | --- | --- | --- |
| strict | 0/12 | 0 | — | 0% |
| tolérant | 0/12 | 0 | — | 0% |
