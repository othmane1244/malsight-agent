| Échantillon | ATT&CK attendues | ATT&CK trouvées | Vraies (strict) | Vraies (tolérant) | FP strict | FP tolérant | Ratées (strict) | IOC trouvés / attendus | Comportements observés / inférés | Rejets | Temps (s) | JSON valide |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| T01 | T1547.001 | T1547.001 | 1 | 1 | — | — | — | 3/3 | 3 / 0 | 0 | 115.5 | oui |
| T02 | T1053.005 | T1053.005 | 1 | 1 | — | — | — | 2/2 | 2 / 0 | 0 | 142.5 | oui |
| T03 | T1543.003 | T1543.003 | 1 | 1 | — | — | — | 1/1 | 1 / 0 | 0 | 120.4 | oui |
| T04 | T1037.001 | T1037.001 | 1 | 1 | — | — | — | 1/1 | 1 / 0 | 0 | 130.1 | oui |
| T05 | T1112 | T1547.001 | 0 | 0 | T1547.001 | T1547.001 | T1112 | 1/1 | 3 / 0 | 0 | 128.0 | oui |
| T06 | T1059.001 | T1059.001 | 1 | 1 | — | — | — | 1/1 | 2 / 0 | 0 | 127.7 | oui |
| T07 | T1082 | T1082 | 1 | 1 | — | — | — | 1/1 | 2 / 0 | 0 | 118.4 | oui |
| T08 | T1016 | T1016, T1547.001 | 1 | 1 | T1547.001 | T1547.001 | — | 1/1 | 3 / 0 | 0 | 141.6 | oui |
| T09 | T1560 | T1560 | 1 | 1 | — | — | — | 1/1 | 3 / 0 | 0 | 112.8 | oui |
| T10 | T1105 | T1566.001 | 0 | 0 | T1566.001 | T1566.001 | T1105 | 1/1 | 0 / 2 | 5 | 125.5 | oui |
| T11 | — | — | 0 | 0 | — | — | — | 1/1 | 1 / 0 | 0 | 98.3 | oui |
| T12 | T1082, T1547.001 | T1082, T1547.001 | 2 | 2 | — | — | — | 3/3 | 4 / 0 | 0 | 137.2 | oui |
| **Total** | 12 |  | **10/12** | **10/12** | 3 | 3 | 2 | 17/17 | 25 / 2 | 5 | 1498.0 | 12/12 |

Notation ATT&CK (D9) : **strict** = (sous-)technique exacte ; **tolérant** = la technique parente d'une technique attendue compte aussi. Toute technique en trop est un faux positif (FP).

| Score | Vraies | FP | Précision | Rappel |
| --- | --- | --- | --- | --- |
| strict | 10/12 | 3 | 77% | 83% |
| tolérant | 10/12 | 3 | 77% | 83% |
