# Échantillons de test

Scripts PowerShell **texte et bénins, écrits par l'équipe MalSight** : c'est la seule exception
à la règle « aucun échantillon dans git » (voir `CLAUDE.md`). Chacun a sa vérité terrain dans
[`../verite-terrain/`](../verite-terrain/) (même identifiant) et une option `-Nettoyer`.

À exécuter **uniquement dans la Windows Sandbox du labo** (réseau coupé), voir
[`../README.md`](../README.md). Aucun ne télécharge, n'installe ni ne démarre de programme :
les cibles sont `notepad.exe` ou des fichiers texte dans `C:\travail\`.

| ID | Script | Technique ATT&CK | Comportement | Visible dans |
| --- | --- | --- | --- | --- |
| T01 | `T01_persistance_run.ps1` | T1547.001 | valeur Run → notepad, fichier témoin, DNS `test.malsight.lab` | Sysmon + Procmon |
| T02 | `T02_tache_planifiee.ps1` | T1053.005 | tâche planifiée → notepad (2099) | Sysmon (fichier de tâche) + Procmon (TaskCache) |
| T03 | `T03_service.ps1` | T1543.003 | service manuel → notepad, jamais démarré | Sysmon + Procmon |
| T04 | `T04_script_logon.ps1` | T1037.001 | `UserInitMprLogonScript` → notepad | Sysmon + Procmon |
| T05 | `T05_registre.ps1` | T1112 | clé `HKCU\Software\MalsightTest` | **Procmon seul** |
| T06 | `T06_powershell_encode.ps1` | T1059.001 | `powershell -EncodedCommand` qui écrit un fichier | Sysmon + Procmon |
| T07 | `T07_decouverte_systeme.ps1` | T1082 | `systeminfo`, `hostname` | Sysmon + Procmon |
| T08 | `T08_decouverte_reseau.ps1` | T1016 | `ipconfig /all`, `route print`, `arp -a` | Sysmon + Procmon |
| T09 | `T09_archivage.ps1` | T1560 | 3 fichiers factices → `collecte.zip` | Sysmon + Procmon |
| T10 | `T10_telechargement.ps1` | T1105 | téléchargement depuis `update.malsight.lab` (échec attendu) | **Sysmon EID 22 seul** |
| T11 | `T11_temoin_negatif.ps1` | *aucune* | **témoin négatif** : date + journal texte | Sysmon + Procmon |
| T12 | `T12_scenario_combine.ps1` | T1082 + T1547.001 | **scénario combiné** : systeminfo, Run, DNS `c2.malsight.lab` | Sysmon + Procmon |

**Origine** : tous écrits par l'équipe pour ce projet (aucune source externe). Les techniques
d'évasion d'ATT&CK sont exclues, sauf T1112 (simple écriture d'une clé applicative factice).
