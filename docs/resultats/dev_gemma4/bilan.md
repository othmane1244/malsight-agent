| Échantillon | ATT&CK attendues | ATT&CK trouvées | Vraies (strict) | Vraies (tolérant) | FP strict | FP tolérant | Ratées (strict) | IOC trouvés / attendus | Comportements observés / inférés | Rejets | Temps (s) | JSON valide |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| T01 | T1547.001 | T1547.001 | 1 | 1 | — | — | — | 3/3 | 3 / 0 | 0 | 113.5 | oui |
| T02 | T1053.005 | T1053, T1027 | 0 | 1 | T1027, T1053 | T1027 | T1053.005 | 2/2 | 14 / 0 | 0 | 160.4 | oui |
| T03 | T1543.003 | — | 0 | 0 | — | — | T1543.003 | 1/1 | 1 / 0 | 4 | 110.4 | oui |
| T04 | T1037.001 | T1547.001 | 0 | 0 | T1547.001 | T1547.001 | T1037.001 | 1/1 | 2 / 0 | 0 | 107.8 | oui |
| T05 | T1112 | T1071.001 | 0 | 0 | T1071.001 | T1071.001 | T1112 | 1/1 | 2 / 0 | 5 | 131.3 | oui |
| T06 | T1059.001 | T1027.002 | 0 | 0 | T1027.002 | T1027.002 | T1059.001 | 1/1 | 2 / 0 | 0 | 130.0 | oui |
| T07 | T1082 | T1082 | 1 | 1 | — | — | — | 1/1 | 2 / 0 | 0 | 119.4 | oui |
| T08 | T1016 | T1082 | 0 | 0 | T1082 | T1082 | T1016 | 1/1 | 8 / 0 | 0 | 133.7 | oui |
| T09 | T1560 | T1005 | 0 | 0 | T1005 | T1005 | T1560 | 1/1 | 3 / 0 | 0 | 111.3 | oui |
| T10 | T1105 | T1071.001 | 0 | 0 | T1071.001 | T1071.001 | T1105 | 1/1 | 3 / 0 | 6 | 133.5 | oui |
| T11 | — | — | 0 | 0 | — | — | — | 1/1 | 1 / 0 | 0 | 85.1 | oui |
| T12 | T1082, T1547.001 | T1059.001 | 0 | 0 | T1059.001 | T1059.001 | T1082, T1547.001 | 3/3 | 4 / 0 | 0 | 130.7 | oui |
| **Total** | 12 |  | **2/12** | **3/12** | 9 | 8 | 10 | 17/17 | 45 / 0 | 15 | 1467.1 | 12/12 |

Notation ATT&CK (D9) : **strict** = (sous-)technique exacte ; **tolérant** = la technique parente d'une technique attendue compte aussi. Toute technique en trop est un faux positif (FP).

| Score | Vraies | FP | Précision | Rappel |
| --- | --- | --- | --- | --- |
| strict | 2/12 | 9 | 18% | 17% |
| tolérant | 3/12 | 8 | 27% | 25% |
