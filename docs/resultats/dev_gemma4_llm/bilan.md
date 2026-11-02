| Échantillon | ATT&CK attendues | ATT&CK trouvées | Vraies (strict) | Vraies (tolérant) | FP strict | FP tolérant | Ratées (strict) | IOC trouvés / attendus | Comportements observés / inférés | Rejets | Temps (s) | JSON valide |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| T01 | T1547.001 | T1547.001 | 1 | 1 | — | — | — | 3/3 | 3 / 0 | 0 | 175.9 | oui |
| T02 | T1053.005 | T1053 | 0 | 1 | T1053 | — | T1053.005 | 2/2 | 3 / 0 | 0 | 191.0 | oui |
| T03 | T1543.003 | T1543.003 | 1 | 1 | — | — | — | 1/1 | 0 / 1 | 0 | 148.2 | oui |
| T04 | T1037.001 | T1547.001 | 0 | 0 | T1547.001 | T1547.001 | T1037.001 | 1/1 | 1 / 1 | 0 | 163.8 | oui |
| T05 | T1112 | T1547.001 | 0 | 0 | T1547.001 | T1547.001 | T1112 | 1/1 | 3 / 0 | 0 | 190.9 | oui |
| T06 | T1059.001 | T1027 | 0 | 0 | T1027 | T1027 | T1059.001 | 1/1 | 2 / 0 | 0 | 152.8 | oui |
| T07 | T1082 | T1047 | 0 | 0 | T1047 | T1047 | T1082 | 1/1 | 3 / 0 | 0 | 144.8 | oui |
| T08 | T1016 | T1082 | 0 | 0 | T1082 | T1082 | T1016 | 1/1 | 3 / 0 | 0 | 178.0 | oui |
| T09 | T1560 | T1074 | 0 | 0 | T1074 | T1074 | T1560 | 1/1 | 1 / 0 | 0 | 157.9 | oui |
| T10 | T1105 | T1547.001 | 0 | 0 | T1547.001 | T1547.001 | T1105 | 1/1 | 0 / 15 | 0 | 164.8 | oui |
| T11 | — | — | 0 | 0 | — | — | — | 1/1 | 1 / 0 | 0 | 90.5 | oui |
| T12 | T1082, T1547.001 | T1082, T1547.001 | 2 | 2 | — | — | — | 3/3 | 4 / 0 | 0 | 120.3 | oui |
| **Total** | 12 |  | **4/12** | **5/12** | 8 | 7 | 8 | 17/17 | 24 / 17 | 0 | 1878.9 | 12/12 |

Notation ATT&CK (D9) : **strict** = (sous-)technique exacte ; **tolérant** = la technique parente d'une technique attendue compte aussi. Toute technique en trop est un faux positif (FP).

| Score | Vraies | FP | Précision | Rappel |
| --- | --- | --- | --- | --- |
| strict | 4/12 | 8 | 33% | 33% |
| tolérant | 5/12 | 7 | 42% | 42% |
