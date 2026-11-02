# Journal de bord

Un point par semaine, du plus récent au plus ancien : **fait**, **bloquant**, **priorité**.
Les décisions structurantes vont dans [`decisions.md`](decisions.md) ; le détail des tâches
est dans les [issues](https://github.com/othmane1244/malsight-agent/issues) et les
[milestones](https://github.com/othmane1244/malsight-agent/milestones).

---

## 2026-11-03 (après-midi) : contexte Ollama et statut des séries de référence

- **Incident** : la série `llm` (gemma4:e4b) est restée bloquée près d'une heure sur T02. Cause :
  contexte Ollama par défaut de **4096 tokens**, partagé entre le prompt (T02 : environ 3 000
  tokens) et la réponse, et génération sans limite en sortie JSON. Correctif (commit d2e976c) :
  `LLM_NUM_CTX` 8192, `LLM_NUM_PREDICT` 2048 et `LLM_TIMEOUT_S` 600 explicites.
- **Statut des séries** :
  - `docs/resultats/dev_gemma4/` (contexte **4096**, avant les règles D7) devient une **mesure
    historique** : T02 et T10, les plus gros prompts, ont pu être tronqués. Elle reste utile
    seulement pour la comparaison avec `qwen3:8b` sur l'ancien code (base `43ef7d7`).
  - La nouvelle série `llm` (contexte **8192**) la **remplace** comme référence du mode LLM seul.
  - Le **tableau final des 3 modes** (`llm`, `regles`, `hybride`) n'utilise **que des séries en
    contexte 8192** (le mode `regles` n'utilise pas de LLM).
- **qwen3:8b** (téléchargement en cours) : sa **comparaison finale** avec gemma4:e4b se fera en
  **mode hybride, contexte 8192**. Sa série sur la base `43ef7d7` (contexte par défaut) ne sert
  qu'à comparer avec l'ancienne série gemma `dev_gemma4`.

---

## 2026-11-03 : agent sur le jeu de développement T01 à T12 (gemma4:e4b)

> **Mesure historique** (contexte Ollama 4096, avant les règles D7) : remplacée comme référence
> du mode LLM seul par la série `dev_gemma4_llm` (contexte 8192). Voir l'entrée suivante.

Résultats complets : `docs/resultats/dev_gemma4/` (`report.json` et `rapport.md` par échantillon,
`bilan.csv`, `bilan.md`). Relançable avec `malsight serie <sortie>` (autre modèle : `LLM_MODEL`).

| Échantillon | ATT&CK attendues | ATT&CK trouvées | Vraies | En trop | Ratées | IOC | Comportements obs. / inf. | Rejets | Temps (s) | JSON |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| T01 | T1547.001 | T1547.001 | 1 | — | — | 3/3 | 3 / 0 | 0 | 113.5 | oui |
| T02 | T1053.005 | T1053, T1027 | 0 | T1027, T1053 | T1053.005 | 2/2 | 14 / 0 | 0 | 160.4 | oui |
| T03 | T1543.003 | — | 0 | — | T1543.003 | 1/1 | 1 / 0 | 4 | 110.4 | oui |
| T04 | T1037.001 | T1547.001 | 0 | T1547.001 | T1037.001 | 1/1 | 2 / 0 | 0 | 107.8 | oui |
| T05 | T1112 | T1071.001 | 0 | T1071.001 | T1112 | 1/1 | 2 / 0 | 5 | 131.3 | oui |
| T06 | T1059.001 | T1027.002 | 0 | T1027.002 | T1059.001 | 1/1 | 2 / 0 | 0 | 130.0 | oui |
| T07 | T1082 | T1082 | 1 | — | — | 1/1 | 2 / 0 | 0 | 119.4 | oui |
| T08 | T1016 | T1082 | 0 | T1082 | T1016 | 1/1 | 8 / 0 | 0 | 133.7 | oui |
| T09 | T1560 | T1005 | 0 | T1005 | T1560 | 1/1 | 3 / 0 | 0 | 111.3 | oui |
| T10 | T1105 | T1071.001 | 0 | T1071.001 | T1105 | 1/1 | 3 / 0 | 6 | 133.5 | oui |
| T11 | — | — | 0 | — | — | 1/1 | 1 / 0 | 0 | 85.1 | oui |
| T12 | T1082, T1547.001 | T1059.001 | 0 | T1059.001 | T1082, T1547.001 | 3/3 | 4 / 0 | 0 | 130.7 | oui |
| **Total** | 12 | | **2/12** | 9 | 10 | 17/17 | 45 / 0 | 15 | 1467 | 12/12 |

### Points demandés
- **T11 (témoin négatif)** : **aucune technique proposée**, un seul comportement (le fichier
  journal) : pas de faux positif. ✅
- **T12 (scénario combiné)** : le **récit** est juste (persistance par clé Run, `systeminfo`,
  tentative DNS vers `c2.malsight.lab`, tous « observés »), mais le **mapping ATT&CK échoue** :
  ni T1082 ni T1547.001, seulement T1059.001 avec la clé Run comme preuve. ❌
- **T05** (Procmon seul) : l'agent **utilise bien** `HKCU\Software\MalsightTest` (comportement
  observé), mais le relie à T1071.001 *Web Protocols* au lieu de T1112. ⚠️
- **T10** (Sysmon seul) : l'agent **utilise bien** la requête DNS, décrite comme « tentative »
  (correction du 2 novembre efficace), mais choisit T1071.001 au lieu de T1105. ⚠️

### Erreurs classées par type
| Type | Cas | Nombre |
| --- | --- | --- |
| **A. Technique ratée, voisine choisie** (bonne famille, mauvais ID) | T02 (T1053 au lieu de .005), T04 (T1547.001 au lieu de T1037.001), T08 (T1082 au lieu de T1016), T09 (T1005 au lieu de T1560) | 4 |
| **B. Technique inventée, sans lien avec la preuve** | T02 T1027 (clés TaskCache), T05 T1071.001 (clé de registre), T10 T1071.001 (aucun échange HTTP), T12 T1059.001 (clé Run comme preuve) | 4 |
| **C. ID et nom incohérents** | T06 : « T1027.002 PowerShell: Encoded Command Execution » ; T1027.002 est en réalité *Software Packing*. Le vérificateur garde le nom du LLM (`verifier.py`, `t.name = t.name or kb.name(t.id)`) | 1 |
| **D. Récit juste, technique absente** | T03 (service décrit, aucune technique), T12 (persistance + découverte décrites) | 2 |
| **E. IOC manquant** | aucun : les IOC viennent des outils, pas du LLM | 0 |
| **F. Preuve exacte mais non pertinente** (bruit décrit comme comportement) | T04 (clé TaskCache d'un service), T05 (base de notifications), T08 (clés `RFC1156Agent`), T10 (traçage RAS) ; T02 : 14 comportements, un par clé | 5 cas |
| **G. IDs D3FEND inventés** dans les recommandations (rejetés) | T03, T05, T10 (`D3-REG`, `D3-FILE`, `D3-NET`...) : toujours quand aucune contre-mesure n'était fournie (aucune technique retenue, ou technique hors cache comme T1071.001) | 15 rejets |

### Corrections proposées (non appliquées, à décider)
1. **Règles déterministes artefact → technique** (source `rule`, confiance haute), comme capa ou
   Sigma : clé `...\CurrentVersion\Run\` → T1547.001 ; `System32\Tasks\` ou `TaskCache\Tree\` →
   T1053.005 ; `Services\<nom>\ImagePath` → T1543.003 ; `UserInitMprLogonScript` → T1037.001 ;
   `systeminfo`/`hostname` → T1082 ; `ipconfig`/`route`/`arp` → T1016 ; `-EncodedCommand` →
   T1059.001 ; création d'un `.zip` à partir de fichiers écrits → T1560. Règles de
   référence publiques, mais à **garder génériques** (D4 : le jeu de validation mesurera le
   sur-ajustement). Traite A, B (en partie) et D.
2. **Vérificateur ATT&CK** : remplacer toujours le nom et la tactique par ceux de la base
   officielle (C) ; exiger que la preuve d'une technique cite des valeurs du dossier de cas
   (même contrôle que les comportements).
3. **Contexte du brouillon** : donner au LLM, pour les techniques candidates, le nom et un extrait
   de la description officielle, plutôt que les seuls IDs.
4. **Provenance dans le contexte** : passer à l'agent l'attribution (`sample_tree` /
   `service_window`) et les éléments de l'arbre de l'échantillon en premier ; consigne de grouper
   les comportements (un par action, pas un par clé). Traite F.
5. **D3FEND sans contre-mesure fournie** : retirer l'ID inventé de la recommandation au lieu de la
   rejeter entière (le texte reste, l'ID part, rejet noté), et renforcer la consigne. Traite G.
6. **Modèle** : comparer avec `qwen3:8b` (téléchargement en cours) avant de figer.

---

## 2026-11-02 (nuit) : D3FEND et premier essai de l'agent (#11, #12)

### Fait
- Contre-mesures MITRE D3FEND (D6) : cache local, vérification des IDs, section du rapport.
- Premier essai de l'agent de bout en bout sur T01 avec `gemma4:e4b` (modèle de
  développement, D5) : T1547.001 trouvée (1/1), JSON valide, 143 s. Trois défauts corrigés
  (preuves vérifiées valeur par valeur, IOC abrégés exclus, tentative / réussite dans le prompt).

### Limite connue : pertinence des contre-mesures D3FEND
- Le vérificateur garantit qu'un ID D3FEND **existe** dans le cache et que D3FEND le **relie** à
  une technique retenue ; il ne juge pas si son **usage** dans une recommandation est pertinent.
  Exemple (essai gemma4:e4b) : D3-CF *Content Filtering*, qui porte sur des fichiers dans
  D3FEND, est cité pour « bloquer l'accès aux domaines suspects ».
- Choix assumé (pas de correction automatique) : c'est l'un des arguments de la **validation
  humaine** obligatoire (`docs/ethique.md`, point 5 ; rapport « à valider avant diffusion »).
  À présenter comme limite dans le mémoire.

---

## 2026-11-02 (nuit) : parseur Procmon et fusion Sysmon + Procmon (#8)

### Fait
- **Parseur Procmon** (`extractors/procmon.py`) : heure sans date (virgule ou point, AM/PM,
  passage de minuit), entiers avec séparateur de milliers (`8 080`, `8,080`, `8.080`) ; garde
  les écritures réussies (`RegSetValue`, `RegCreateKey` d'une clé nouvelle, `CreateFile` créé ou
  écrasé, `WriteFile`, renommages), les processus et le réseau ; exclut outils du labo et `System`.
- **Fusion** (`extractors/lab.py`) : arbre de processus de l'échantillon (racine `auto.json`,
  descendants via Procmon et Sysmon EID 1) + écritures de `svchost`, `services`, `wmiprvse`
  pendant que l'arbre est actif ; Sysmon hors arbre gardé seulement s'il est corroboré par
  Procmon. Chaque élément devient une `Observation` (sources, opérations, processus, attribution
  `sample_tree` / `service_window`), dédupliquée entre les deux sources.
- **`malsight extract ECHANTILLON --labo cases/T02`** construit le dossier de cas à partir d'une
  collecte du labo (en plus de `--cape-report`).

### Vérification sur les 12 dossiers `cases/` et mesure du bruit
Chaque IOC attendu est présent dans le dossier de cas généré (**17/17**). Bruit = observations
extraites, sans et avec le filtre de bruit système connu (`BRUIT_SYSTEME` : métafichiers NTFS,
journaux d'événements, WNF, BAM, Amcache, `GameConfigStore`, traçage WMI…) :

| Cas | IOC | Sans filtre | Avec filtre | dont arbre de l'échantillon | dont fenêtre de services |
| --- | --- | --- | --- | --- | --- |
| T01 (auto, `cases/T01/`) | 3/3 | 64 | **3** | 3 | 0 |
| *T01 manuel (essai 2, `cases/essai2/`, gardé pour mémoire)* | *3/3* | *710* | *99* | *3* | *96* |
| T02 | 2/2 | 68 | 15 | 0 | 15 (tâche planifiée : TaskCache + fichier) |
| T03 | 1/1 | 22 | 7 | 0 | 7 (clés du service MalsightTest) |
| T04 | 1/1 | 22 | 2 | 1 | 1 |
| T05 | 1/1 | 25 | 8 | 2 | 6 (service de notifications) |
| T06 | 1/1 | 58 | 2 | 2 | 0 |
| T07 | 1/1 | 79 | 3 | 3 | 0 |
| T08 | 1/1 | 51 | 8 | 8 | 0 |
| T09 | 1/1 | 54 | 5 | 5 | 0 |
| T10 | 1/1 | 49 | 17 | 17 | 0 (16 clés de traçage RAS) |
| **T11 (témoin négatif)** | 1/1 | **57** | **1** | 1 | 0 |
| T12 | 3/3 | 95 | 4 | 4 | 0 |

- **Témoin négatif T11 : 57 éléments extraits avant filtre, 1 après, pour 1 attendu** : plus
  aucun faux positif dynamique. Sur les 12 échantillons (T01 automatique) : 644 → 75 observations.
- **T01 relancé en mode automatique** : 64 → **3** observations, exactement ses 3 IOC (contre
  99 pour la collecte manuelle de l'essai 2, dont la racine était la console qui avait aussi fait
  la préparation et la collecte). L'essai 2 est gardé dans `cases/essai2/`, le nouveau T01 est
  dans `cases/T01/`.
- **Limite** : la liste `BRUIT_SYSTEME` est tirée de ces 12 analyses. Décision D4 : T01 à T12
  deviennent le jeu de **développement** ; un jeu de **validation** T13 à T16, écrit sans
  regarder les filtres, mesurera les résultats finaux (#23). Le bruit restant (notifications pour
  T05, traçage RAS pour T10) est laissé visible volontairement.

---

## 2026-11-02 (soir) : série T03 à T12, jeu de test complet (#6 fermée)

### Fait
- T03 seul, puis série autorisée T04 à T12 en mode automatique (D3), `malsight comparer` après
  chaque échantillon. **12/12 échantillons validés, 17/17 IOC retrouvés.** Résultats archivés
  hors git dans `cases/T02/` à `cases/T12/` (T01 : `cases/essai2/`).

  | Échantillon | Technique ATT&CK | IOC trouvés / attendus | Sources |
  | --- | --- | --- | --- |
  | T01 `persistance_run` | T1547.001 | 3/3 | clé Run : Sysmon + Procmon · fichier : Sysmon + Procmon · DNS : Sysmon seul |
  | T02 `tache_planifiee` | T1053.005 | 2/2 | fichier de tâche : Sysmon + Procmon (`svchost.exe`) · clé TaskCache : Procmon seul |
  | T03 `service` | T1543.003 | 1/1 | ImagePath : Sysmon + Procmon (`services.exe`) |
  | T04 `script_logon` | T1037.001 | 1/1 | `UserInitMprLogonScript` : Sysmon + Procmon |
  | T05 `registre` | T1112 | 1/1 | `HKCU\Software\MalsightTest\Config` : **Procmon seul** (attendu) |
  | T06 `powershell_encode` | T1059.001 | 1/1 | fichier : Sysmon + Procmon · `-EncodedCommand` : Sysmon EID 1 |
  | T07 `decouverte_systeme` | T1082 | 1/1 | fichier : Sysmon + Procmon · `systeminfo`, `hostname` : Sysmon EID 1 |
  | T08 `decouverte_reseau` | T1016 | 1/1 | fichier : Sysmon + Procmon · `ipconfig`, `route`, `arp` : Sysmon EID 1 |
  | T09 `archivage` | T1560 | 1/1 | `collecte.zip` : Sysmon + Procmon |
  | T10 `telechargement` | T1105 | 1/1 | `update.malsight.lab` : **Sysmon EID 22 seul** (réseau coupé) |
  | T11 `temoin_negatif` | *aucune* | 1/1 | `journal_t11.txt` : Sysmon + Procmon |
  | T12 `scenario_combine` | T1082 + T1547.001 | 3/3 | clé Run : Sysmon + Procmon · fichier : Sysmon + Procmon · DNS : Sysmon seul · `systeminfo` : EID 1 |

### Incident : course entre deux sandboxes (série T04 → T05)
- À la fin de T04, le lanceur a rendu la main dès les résultats complets, alors que la
  sandbox ne s'éteint que 10 s après la collecte. T05, lancé 3 s plus tard, a trouvé la
  sandbox de T04 encore ouverte et le lanceur a refusé d'en ouvrir une seconde.
- **Le garde-fou D3 a fonctionné** : arrêt au premier échec, aucun échantillon exécuté,
  incident signalé avant de continuer. T05 n'avait pas été lancé.
- Correctif (commit 8c3e546) : après un succès, `lancer-analyse.ps1` attend la fermeture de
  la sandbox (180 s au plus). La série T05 à T12 relancée ensuite n'a eu aucun échec.

### Constats
- **Sources** : 2 IOC ne sont visibles que dans Procmon (T02 TaskCache, T05), 3 que dans Sysmon
  (les domaines de T01, T10, T12) : aucune source seule ne suffit, la fusion (#8) est nécessaire.
- **Attribution** : la persistance de T02 et T03 est écrite par un service système
  (`svchost.exe`, `services.exe`), pas par le processus de l'échantillon.
- **Témoin négatif T11** : le parseur Sysmon en extrait déjà 14 processus, 25 clés de registre
  et 3 fichiers, dont un seul attendu (`journal_t11.txt`) ; le reste est du bruit système
  (WMIADAP, `Perflib`, `taskhostw`, `__PSScriptPolicyTest_*.ps1`). C'est la base pour mesurer
  faux positifs et hallucinations de l'agent (#16).

### Priorité
1. Parseur Procmon et fusion avec Sysmon, sans filtrer par PID seul (#8).
2. Filtrage du bruit système, mesuré sur T11.

---

## 2026-11-02 (soir) : T02, premier échantillon en mode automatique

### Fait
- **Mode automatique validé (D3)** : `lancer-analyse.ps1 -Echantillon T02` a tout enchaîné sans
  intervention (prérequis, sandbox, exécution PID 8080 code 0, attente 90 s, collecte,
  `auto.json`, extinction). PML finalisé, SHA-256 identique au dépôt. Archivé dans `cases/T02/`.
- **T02 : 2/2 IOC retrouvés** (`malsight comparer cases/T02`) :

  | IOC attendu | Sysmon | Procmon |
  | --- | --- | --- |
  | `C:\Windows\System32\Tasks\MalsightTest` | EID 11 (svchost.exe) | CreateFile, WriteFile (svchost.exe) |
  | `HKLM\…\Schedule\TaskCache\Tree\MalsightTest` | — (hors config, attendu) | RegCreateKey, RegSetValue ×3 (svchost.exe) |
- **Commande `malsight comparer`** : tableau IOC attendu / trouvé / source à partir d'un dossier
  de collecte ; T01 (essai 2) 3/3, T02 2/2.
- Règle d'évasion précisée (D2, T05 gardé), tests PowerShell marqués `slow` (CI verte, 44 tests).

### Constats
- **Attribution** : la persistance de T02 est écrite par `svchost.exe` (service Planificateur de
  tâches), pas par le processus de l'échantillon. Filtrer les journaux par PID seul ferait
  perdre cette preuve : à prendre en compte pour la fusion Sysmon + Procmon (#8).
- Le parseur Sysmon garde encore beaucoup de bruit système (WMIADAP, `Perflib`, `taskhostw`,
  `__PSScriptPolicyTest_*.ps1`) : le témoin négatif T11 servira à le mesurer.

### Priorité
1. T03 à T12 en mode automatique, un par un, avec `malsight comparer` après chacun (#6).
2. Parseur Procmon et fusion avec Sysmon (#8).

---

## 2026-11-02 (fin de journée) : essai 2 de T01 réussi

### Fait
- Essai 2 avec les corrections du commit f5d278d : #4 **fermée** (6/6 critères).

  | Vérification | Essai 1 | Essai 2 |
  | --- | --- | --- |
  | Préparation de la sandbox | lancée à la main | automatique, aucun journal d'erreur (*) |
  | Sysmon : 3 IOC de T01 (EID 13, 11, 22) | ✅ (116 événements) | ✅ (105 événements) |
  | Signature de `procmon.PML` | octets nuls (non finalisé) | `PML_` (164 Mo) |
  | `procmon.csv` | absent | 70 Mo (`RegSetValue`, `CreateFile`/`WriteFile`) |
  | SHA-256 du manifeste = dépôt | ✅ | ✅ |

  (*) Indice dans Sysmon : la ligne de commande parente est exactement celle de la LogonCommand
  (`-NoProfile`, absent de la commande manuelle du README). À confirmer par l'équipe.
- **Parseur Sysmon (#8)** : `load_sysmon_csv` + normalisation `HKU\<SID>\` → `HKCU\`, testé sur
  une fixture anonymisée tirée de l'essai 2 (`tests/fixtures/sysmon_T01.csv`) ; les 3 IOC de
  `lab/verite-terrain/T01.json` sont retrouvés.
- Résultats archivés hors git dans `cases/essai1/` et `cases/essai2/`.

### Constats utiles pour le bilan J2 (D1)
- **Le DNS est capté par Sysmon même sans réseau** : la requête `test.malsight.lab` apparaît
  en EID 22 (résolution en échec), alors qu'elle est absente de Procmon. Sans INetSim, on voit
  donc **quels domaines** un échantillon cherche à joindre, mais pas ce qu'il ferait ensuite
  (connexion, échange HTTP). C'est l'argument à peser au bilan J2 pour l'option VM + INetSim (#5).
- Procmon écrit déjà les clés en `HKCU\`, Sysmon en `HKU\<SID>\` : seul Sysmon est à normaliser.
- Le CSV Procmon suit la langue de Windows (virgule décimale, espace dans les milliers, heure
  sans date) et pèse ~70 Mo pour 4 minutes : filtrage par processus nécessaire (détails dans #8).
- La colonne `Task` du CSV Sysmon est fausse (« Sysmon config state changed » partout) : le
  parseur s'appuie sur `EventID`.
- T01 tourne dans la même console PowerShell que `setup-sandbox.ps1` (même PID) : on ne peut pas
  isoler l'échantillon par son seul PID.

### Bloquant
- Aucun.

### Priorité
1. Échantillons T02 à T10 (#6), après validation de la liste.
2. Parseur Procmon et fusion avec Sysmon (#8).

---

## 2026-11-02 (après-midi) : premier essai réel de T01

### Constats
- **Sysmon fonctionne** : 116 événements, les 3 IOC de T01 sont présents.
  - EID 13 : `HKU\S-1-5-21-…-504\Software\Microsoft\Windows\CurrentVersion\Run\MalsightTest`
    → `notepad.exe`. La clé est en `HKU\<SID>\`, pas en `HKCU\` : normalisation prévue dans #8.
  - EID 11 : `C:\travail\malsight_test.txt` (règle maison `sysmon-malsight.xml` validée).
  - EID 22 : `test.malsight.lab`.
- **LogonCommand** : `setup-sandbox.ps1` ne s'est pas lancé (ou a échoué sans message visible)
  et a dû être lancé à la main. Cause : `sysmonconfig-export.xml` manquait dans `C:\labo\entree\outils`.
- **ExecutionPolicy et `C:\travail`** : il a fallu les régler et le créer à la main.
- **Procmon** : `procmon.PML is not a Process Monitor backing file (signature missing)`. Le PML
  (220 Mo) commence par des octets nuls : en-tête jamais finalisé. Causes probables : écriture
  directe dans `C:\resultats` (dossier partagé avec l'hôte) et conversion lancée avant la fin
  de l'arrêt de Procmon.

### Corrections
- `lab/scripts/verifier-prerequis.ps1` : vérification côté hôte avant `analyse.wsb` (outils,
  config Sysmon valide, scripts à jour par rapport au dépôt, résultats vidés), testée.
- `analyse.wsb` : la LogonCommand passe par `cmd /c start` pour ouvrir une vraie fenêtre ;
  `setup-sandbox.ps1` affiche les erreurs en rouge et copie son journal dans `C:\resultats`.
- `setup-sandbox.ps1` : ExecutionPolicy Bypass pour la session, création de `C:\travail`.
- Procmon : capture en local (`C:\labo-outils\procmon.PML`), `Wait-Process` après `/Terminate`,
  conversion CSV en local, copie vers `C:\resultats` seulement à la fin ; contrôle de la
  signature `PML_`.

### Priorité
1. Refaire l'essai T01 avec les scripts corrigés et cocher le dernier critère de #4.
2. Utiliser les journaux de T01 comme fixture du parseur Sysmon (#8).

---

## 2026-11-02

### Fait
- **Dépôt** : structure initiale (pipeline, agent, vérificateur, rapport), `CLAUDE.md` avec les
  règles du projet, 13 tests verts. Exception documentée : seuls les scripts texte bénins de
  l'équipe sont versionnés (`lab/echantillons-test/` + `lab/verite-terrain/`).
- **Labo (décision D1)** : Windows Sandbox seul, bilan au jalon J2. `lab/analyse.wsb` (réseau,
  vGPU et presse-papiers coupés), `setup-sandbox.ps1` (Sysmon SwiftOnSecurity + règle maison
  `C:\travail\`, Procmon), `collect.ps1` (EVTX, CSV, manifeste), procédure dans `lab/README.md`.
  Éthique, conception et architecture alignées sur D1.
- **T01** : premier échantillon de test (persistance clé Run, fichier témoin, requête DNS) avec
  sa vérité terrain (`T1547.001`).
- **Suivi** : 4 milestones (J1 à J4), 13 labels, 22 issues créées sur GitHub ; avancement
  coché dans #4, #6, #8, #12 et #22.

### Bloquant
- Aucun. Le labo n'a pas encore tourné pour de vrai : les scripts sont seulement vérifiés
  (syntaxe, fusion Sysmon testée).

### Priorité
1. Premier essai réel de T01 dans la sandbox (#4).
2. Compléter le jeu d'échantillons bénins avec vérité terrain (#6).
3. Cadrage J1 : note d'état de l'art (#1), cahier des charges (#2), schéma JSON (#3).
