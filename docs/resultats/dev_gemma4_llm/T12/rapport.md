# Rapport d'analyse : T12_scenario_combine.ps1

| Champ | Valeur |
| --- | --- |
| SHA-256 | `561a7e11d3359407846f22cabacbe578fe4b49555660b122e90cd9c2d1d39586` |
| MD5 | `acbdc6e0398ec6b1e8d774cd8e32b8bf` |
| Type | unknown |
| Taille | 1904 octets |

> Rapport généré par MalSight Agent. **À valider par un analyste avant diffusion.**

## Résumé

L'échantillon, exécuté via PowerShell, a effectué plusieurs actions de reconnaissance et de persistance. Il a exécuté `systeminfo.exe` et a créé un fichier local (`C:\travail\malsight_t12_info.txt`). De plus, il a tenté d'établir une communication avec le domaine `c2.malsight.lab` et a établi une persistance en écrivant une clé de registre dans `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\MalsightTest12`.

## Comportements

| Comportement | Preuve | Statut |
| --- | --- | --- |
| Exécution d'outils système pour la collecte d'informations | `Exécution de "C:\Windows\system32\systeminfo.exe" par powershell.exe (7444)` | observé |
| Création de fichiers locaux | `Création du fichier "C:\travail\malsight_t12_info.txt" par powershell.exe (7444)` | observé |
| Établissement d'une persistance au démarrage | `Écriture de la clé de registre "HKCU\Software\Microsoft\Windows\CurrentVersion\Run\MalsightTest12" par powershell.exe (7444)` | observé |
| Tentative de communication réseau avec un domaine externe | `Observation du domaine "c2.malsight.lab" par powershell.exe (7444)` | observé |

## Indicateurs de compromission (IOC)

| Type | Valeur | Source |
| --- | --- | --- |
| sha256 | `561a7e11d3359407846f22cabacbe578fe4b49555660b122e90cd9c2d1d39586` | fichier |
| md5 | `acbdc6e0398ec6b1e8d774cd8e32b8bf` | fichier |
| domain | `c2.malsight.lab` | extraction |
| file_path | `C:\travail\malsight_t12_info.txt` | extraction |
| registry_key | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\MalsightTest12` | extraction |

## API sensibles

| API | Catégorie | Source |
| --- | --- | --- |

## Techniques MITRE ATT&CK

| ID | Technique | Tactique | Source | Confiance | Preuve |
| --- | --- | --- | --- | --- | --- |

## Suggestions à valider par l'analyste

Techniques proposées par le modèle de langage, **non retenues dans la liste officielle** (D10 :
les outils classent, le LLM explique). Chacune cite une preuve retrouvée dans le dossier de cas,
mais sa pertinence reste à valider.

| ID | Technique | Tactique | Confiance | Preuve |
| --- | --- | --- | --- | --- |
| [T1082](https://attack.mitre.org/techniques/T1082/) | System Information Discovery | discovery | medium | Observation du domaine "c2.malsight.lab" |
| [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | Registry Run Keys / Startup Folder | persistence, privilege-escalation | medium | Écriture de la clé de registre "HKCU\Software\Microsoft\Windows\CurrentVersion\Run\MalsightTest12" |

## Contre-mesures D3FEND

- Aucune (aucune technique ATT&CK retenue, ou cache D3FEND absent : `malsight download-d3fend`).

## Recommandations

- Surveiller les tentatives d'accès ou de modification des clés de registre de démarrage utilisateur, telles que "HKCU\Software\Microsoft\Windows\CurrentVersion\Run", pour détecter des écritures suspectes (D3-SCA).
- Mettre en place une surveillance des appels système pour détecter toute tentative d'exécution de processus ou de modification de configuration système non autorisée (D3-PSA).
- Implémenter une politique de contrôle des applications (Application Whitelisting) pour restreindre l'exécution des exécutables non approuvés (D3-EAL).
- Surveiller les requêtes DNS ou les connexions réseau vers des domaines connus ou suspects, comme "c2.malsight.lab", même si l'activité réseau n'est pas prouvée dans les données (D3-DE).
- Surveiller la création de fichiers dans des chemins spécifiques ou l'écriture de données dans des fichiers de configuration pour détecter des exfiltrations potentielles (D3-FIM).

## Incertitudes

- Aucune signalée.

## Affirmations rejetées par le vérificateur

- Contre-mesure D3-PSA pour une technique non retenue : T1082
- Contre-mesure D3-SCA pour une technique non retenue : T1082
- Contre-mesure D3-EAL pour une technique non retenue : T1082
- Contre-mesure D3-EDL pour une technique non retenue : T1082
- Contre-mesure D3-HBPI pour une technique non retenue : T1082
- Contre-mesure D3-SCF pour une technique non retenue : T1082
- Contre-mesure D3-DE pour une technique non retenue : T1082
- Contre-mesure D3-FE pour une technique non retenue : T1547.001
- Contre-mesure D3-DA pour une technique non retenue : T1547.001
- Contre-mesure D3-EFA pour une technique non retenue : T1547.001
- Contre-mesure D3-FA pour une technique non retenue : T1547.001
- Contre-mesure D3-FIM pour une technique non retenue : T1547.001
- Contre-mesure D3-SICA pour une technique non retenue : T1547.001
- Contre-mesure D3-CF pour une technique non retenue : T1547.001
- Contre-mesure D3-CM pour une technique non retenue : T1547.001
- Contre-mesure D3-CQ pour une technique non retenue : T1547.001
- Contre-mesure D3-EAL pour une technique non retenue : T1547.001
- Contre-mesure D3-EDL pour une technique non retenue : T1547.001
- Contre-mesure D3-LFP pour une technique non retenue : T1547.001
