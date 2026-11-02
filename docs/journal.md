# Journal de bord

Un point par semaine, du plus récent au plus ancien : **fait**, **bloquant**, **priorité**.
Les décisions structurantes vont dans [`decisions.md`](decisions.md) ; le détail des tâches
est dans les [issues](https://github.com/othmane1244/malsight-agent/issues) et les
[milestones](https://github.com/othmane1244/malsight-agent/milestones).

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
