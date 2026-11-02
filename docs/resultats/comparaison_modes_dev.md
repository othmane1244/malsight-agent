# Comparaison des 3 modes : jeu de développement T01 à T12

**Modèle : gemma4:e4b** (Ollama, contexte 8192) · notation D9 · 12 techniques attendues
(T11 = témoin négatif, aucune). Détails par échantillon : `dev_regles/`, `dev_gemma4_llm/`,
`dev_gemma4_hybride/` (`bilan.md`, `report.json`, `rapport.md`).

| Mode | Strict (vraies / FP) | Tolérant (vraies / FP) | Précision strict | Rappel strict | T11 sans FP | IOC | JSON valides | Temps total |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `regles` (règles D7 seules, sans LLM) | **10/12 · 0** | **10/12 · 0** | **100 %** | 83 % | oui | 17/17 | 12/12 | < 1 s |
| `llm` (LLM seul) | 4/12 · 8 | 5/12 · 7 | 33 % | 33 % | oui | 17/17 | 12/12 | 1 879 s |
| `hybride` (règles + LLM) | **10/12** · 2 | **10/12** · 2 | 83 % | 83 % | oui | 17/17 | 12/12 | 1 510 s |
| *historique : LLM seul, contexte 4096, avant D7* | *2/12 · 9* | *3/12 · 8* | *18 %* | *17 %* | *oui* | *17/17* | *12/12* | *1 467 s* |

## Lecture

- **Les règles portent la justesse ATT&CK** : 10/12 sans aucun faux positif. Les 2 techniques
  ratées (T1112 de T05, T1105 de T10) n'ont volontairement pas de règle (D7).
- **Le LLM seul reste faible sur le mapping** (4/12 strict) malgré un contexte suffisant :
  techniques voisines (T1082 au lieu de T1016, T1074 au lieu de T1560, T1547.001 au lieu de
  T1037.001) ou sans lien (T1047, T1027). Mais il réussit T12 (T1082 et T1547.001 dans le même
  récit) et ne propose rien sur le témoin négatif T11.
- **Le mode hybride n'ajoute aucune vraie technique aux règles** : le LLM ne trouve ni T1112 ni
  T1105, et ajoute **2 faux positifs** dont la preuve ne soutient pas la technique :
  - T05 : T1547.001 (*Registry Run Keys*) avec pour preuve `HKCU\Software\MalsightTest`, qui
    n'est pas une clé Run ;
  - T10 : T1547.002 (*Authentication Package*) avec pour preuve le domaine `update.malsight.lab`.
- **L'apport du LLM est ailleurs** : résumé, comportements regroupés et décrits (24 observés,
  1 inféré en hybride contre 24 / 17 en LLM seul), recommandations avec contre-mesures D3FEND.
- Le contexte 8192 a amélioré le LLM seul (2/12 -> 4/12 strict) mais l'essentiel du gain vient
  des règles.

## Pistes (non appliquées, à décider)

1. **Cohérence technique / preuve** : en mode hybride, une technique proposée par le LLM et
   couverte par une règle D7 n'est retenue que si la règle s'est déclenchée (supprimerait le FP de
   T05). Les techniques sans règle (T1547.002 de T10) resteraient au LLM.
2. **Confiance du LLM** : n'afficher les techniques `source = llm` que comme « à valider » quand
   aucune règle ni capa ne les confirme (elles ne compteraient plus dans le score principal).
3. Mesurer d'abord ces pistes sur le jeu de développement uniquement (D4).
