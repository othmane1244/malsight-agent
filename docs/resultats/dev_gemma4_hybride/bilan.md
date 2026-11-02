| Échantillon | ATT&CK attendues | ATT&CK trouvées | Vraies (strict) | Vraies (tolérant) | FP strict | FP tolérant | Ratées (strict) | IOC trouvés / attendus | Comportements observés / inférés | Rejets | Temps (s) | JSON valide |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| T01 | T1547.001 | T1547.001 | 1 | 1 | — | — | — | 3/3 | 3 / 0 | 0 | 107.7 | oui |
| T02 | T1053.005 | T1053.005 | 1 | 1 | — | — | — | 2/2 | 1 / 0 | 0 | 122.2 | oui |
| T03 | T1543.003 | T1543.003 | 1 | 1 | — | — | — | 1/1 | 1 / 0 | 0 | 118.3 | oui |
| T04 | T1037.001 | T1037.001 | 1 | 1 | — | — | — | 1/1 | 1 / 0 | 0 | 127.4 | oui |
| T05 | T1112 | T1547.001 | 0 | 0 | T1547.001 | T1547.001 | T1112 | 1/1 | 3 / 0 | 0 | 131.5 | oui |
| T06 | T1059.001 | T1059.001 | 1 | 1 | — | — | — | 1/1 | 2 / 0 | 0 | 140.7 | oui |
| T07 | T1082 | T1082 | 1 | 1 | — | — | — | 1/1 | 2 / 0 | 0 | 126.4 | oui |
| T08 | T1016 | T1016 | 1 | 1 | — | — | — | 1/1 | 3 / 0 | 0 | 145.0 | oui |
| T09 | T1560 | T1560 | 1 | 1 | — | — | — | 1/1 | 3 / 0 | 0 | 117.9 | oui |
| T10 | T1105 | T1547.002 | 0 | 0 | T1547.002 | T1547.002 | T1105 | 1/1 | 1 / 1 | 0 | 148.3 | oui |
| T11 | — | — | 0 | 0 | — | — | — | 1/1 | 1 / 0 | 0 | 84.2 | oui |
| T12 | T1082, T1547.001 | T1082, T1547.001 | 2 | 2 | — | — | — | 3/3 | 3 / 0 | 0 | 140.1 | oui |
| **Total** | 12 |  | **10/12** | **10/12** | 2 | 2 | 2 | 17/17 | 24 / 1 | 0 | 1509.7 | 12/12 |

Notation ATT&CK (D9) : **strict** = (sous-)technique exacte ; **tolérant** = la technique parente d'une technique attendue compte aussi. Toute technique en trop est un faux positif (FP).

| Score | Vraies | FP | Précision | Rappel |
| --- | --- | --- | --- | --- |
| strict | 10/12 | 2 | 83% | 83% |
| tolérant | 10/12 | 2 | 83% | 83% |
