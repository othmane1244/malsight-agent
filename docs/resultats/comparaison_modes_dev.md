# Comparaison des 3 modes : jeu de développement T01 à T12 (tableau final)

**Modèle : gemma4:e4b** (Ollama, contexte 8192) · notation D9 · vérificateur avec preuve
vérifiable des techniques LLM (D8) · 12 techniques attendues (T11 = témoin négatif, aucune).
Généré par `malsight modes regles=dev_regles llm=dev_gemma4_llm hybride=dev_gemma4_hybride`.
Détails par échantillon : `dev_regles/`, `dev_gemma4_llm/`, `dev_gemma4_hybride/`.

| Mode | Strict : vraies | Strict : FP | Strict : précision | Strict : rappel | Tolérant : vraies | Tolérant : FP | Tolérant : précision | Tolérant : rappel | IOC | Témoin négatif sans FP | JSON valides | Temps moyen (s) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `regles` | 10/12 | 0 | 100% | 83% | 10/12 | 0 | 100% | 83% | 17/17 | oui | 12/12 | 0.0 |
| `llm` | 4/12 | 4 | 50% | 33% | 4/12 | 4 | 50% | 33% | 17/17 | oui | 12/12 | 156.6 |
| `hybride` | 10/12 | 3 | 77% | 83% | 10/12 | 3 | 77% | 83% | 17/17 | oui | 12/12 | 124.8 |

## Comment ces séries ont été obtenues

- `regles` : sans LLM, déterministe.
- `llm` : série du 3 novembre (contexte 8192), **revérifiée** avec le vérificateur actuel à partir
  des rapports enregistrés (`malsight bilan --reverifier`) : le vérificateur ne fait que retirer,
  les techniques sont celles qu'une nouvelle exécution donnerait pour le même brouillon du LLM.
  Avant revérification : 4/12 strict avec 8 FP (5/12 et 7 FP en tolérant).
- `hybride` : **relancée** entièrement avec le vérificateur actuel. Le LLM n'est pas déterministe :
  d'une exécution à l'autre, les techniques qu'il propose varient (le FP de T08 est nouveau).

## Lecture

- **Les règles portent la justesse ATT&CK** : 10/12, aucun faux positif. T1112 (T05) et T1105
  (T10) n'ont volontairement pas de règle (D7).
- **La preuve vérifiable (D8) a divisé par deux les faux positifs du LLM seul** (8 -> 4), sans
  perdre de vraie technique : les techniques à preuve « N/A » ou sans valeur sont rejetées.
- **Le mode hybride n'apporte aucune vraie technique au-delà des règles** et garde **3 faux
  positifs** dont la preuve cite une valeur réelle mais **sans rapport avec la technique** :
  T05 T1547.001 (clé `HKCU\Software\MalsightTest`, pas une clé Run), T08 T1547.001 (un fichier
  texte), T10 T1566.001 *Spearphishing Attachment* (un domaine). Le vérificateur contrôle que la
  preuve existe, pas qu'elle soutient la technique.
- **Témoin négatif T11** : aucun faux positif dans les 3 modes. **IOC** : 17/17 partout (les IOC
  viennent des outils). **JSON** : 12/12 partout.
- **Apport du LLM** : résumé, comportements regroupés, recommandations avec contre-mesures D3FEND.

## Piste (non appliquée, à décider)

Cohérence technique / règle : une technique proposée par le LLM et **couverte par une règle D7**
n'est retenue que si la règle s'est déclenchée sur ce cas. Supprimerait les FP de T05 et T08
(T1547.001) ; T1566.001 (T10), sans règle, resterait au LLM. À mesurer d'abord sur le jeu de
développement (D4).
