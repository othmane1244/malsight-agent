# Journal de bord

Un point par semaine, du plus récent au plus ancien : **fait**, **bloquant**, **priorité**.
Les décisions structurantes vont dans [`decisions.md`](decisions.md) ; le détail des tâches
est dans les [issues](https://github.com/othmane1244/malsight-agent/issues) et les
[milestones](https://github.com/othmane1244/malsight-agent/milestones).

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
