# Rapport d'analyse : T04_script_logon.ps1

| Champ | Valeur |
| --- | --- |
| SHA-256 | `75f147e378deae3f4ad4f4bf64b5367f4e8bc203a47b2dfcb114510d54c9a37b` |
| MD5 | `79df13f3d86a8156fb0bc208fd4c1536` |
| Type | unknown |
| Taille | 998 octets |

> Rapport généré par MalSight Agent. **À valider par un analyste avant diffusion.**

## Résumé

L'échantillon, un script PowerShell nommé `T04_script_logon.ps1`, a été analysé. L'activité observée se concentre sur la modification de clés de registre associées aux scripts de connexion utilisateur et au cache des tâches planifiées. Spécifiquement, il est observé que l'échantillon tente d'écrire dans la clé de registre `HKCU\Environment\UserInitMprLogonScript` via `powershell.exe`, ce qui est corrélé à la technique T1037.001 (Logon Script (Windows)). Une autre modification de registre est observée sur une clé de cache de tâches planifiées (`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{A0A2225E-7E5D-4CAE-B899-09B3E96B259D}\DynamicInfo`) attribuée à `svchost.exe`, mais cette activité est considérée comme une activité de fond de Windows ou un processus système et n'est pas directement attribuée à l'action de l'échantillon.

## Comportements

| Comportement | Preuve | Statut |
| --- | --- | --- |
| Modification de la variable d'environnement de script de connexion utilisateur. | `HKCU\Environment\UserInitMprLogonScript` | observé |

## Indicateurs de compromission (IOC)

| Type | Valeur | Source |
| --- | --- | --- |
| sha256 | `75f147e378deae3f4ad4f4bf64b5367f4e8bc203a47b2dfcb114510d54c9a37b` | fichier |
| md5 | `79df13f3d86a8156fb0bc208fd4c1536` | fichier |
| registry_key | `HKCU\Environment\UserInitMprLogonScript` | extraction |
| registry_key | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{A0A2225E-7E5D-4CAE-B899-09B3E96B259D}\DynamicInfo` | extraction |

## API sensibles

| API | Catégorie | Source |
| --- | --- | --- |

## Techniques MITRE ATT&CK

| ID | Technique | Tactique | Source | Confiance | Preuve |
| --- | --- | --- | --- | --- | --- |
| [T1037.001](https://attack.mitre.org/techniques/T1037/001/) | Logon Script (Windows) | persistence, privilege-escalation | rule | high | règle R-T1037.001-registre : HKCU\Environment\UserInitMprLogonScript (powershell.exe (8064)) |

## Suggestions à valider par l'analyste

- Aucune.

## Contre-mesures D3FEND

Contre-mesures défensives [MITRE D3FEND](https://d3fend.mitre.org) associées aux techniques
ATT&CK retenues (source : d3fend, cache local ; IDs vérifiés).

| Technique ATT&CK | Contre-mesure D3FEND | Tactique | Artefact |
| --- | --- | --- | --- |
| [T1037.001](https://attack.mitre.org/techniques/T1037/001/) | [D3-FE File Encryption](https://d3fend.mitre.org/technique/d3f:FileEncryption/) | Harden | File |
| [T1037.001](https://attack.mitre.org/techniques/T1037/001/) | [D3-DA Dynamic Analysis](https://d3fend.mitre.org/technique/d3f:DynamicAnalysis/) | Detect | Executable File |
| [T1037.001](https://attack.mitre.org/techniques/T1037/001/) | [D3-EFA Emulated File Analysis](https://d3fend.mitre.org/technique/d3f:EmulatedFileAnalysis/) | Detect | Executable File |
| [T1037.001](https://attack.mitre.org/techniques/T1037/001/) | [D3-FA File Analysis](https://d3fend.mitre.org/technique/d3f:FileAnalysis/) | Detect | File |
| [T1037.001](https://attack.mitre.org/techniques/T1037/001/) | [D3-FIM File Integrity Monitoring](https://d3fend.mitre.org/technique/d3f:FileIntegrityMonitoring/) | Detect | File |
| [T1037.001](https://attack.mitre.org/techniques/T1037/001/) | [D3-CF Content Filtering](https://d3fend.mitre.org/technique/d3f:ContentFiltering/) | Isolate | File |
| [T1037.001](https://attack.mitre.org/techniques/T1037/001/) | [D3-CM Content Modification](https://d3fend.mitre.org/technique/d3f:ContentModification/) | Isolate | File |
| [T1037.001](https://attack.mitre.org/techniques/T1037/001/) | [D3-CQ Content Quarantine](https://d3fend.mitre.org/technique/d3f:ContentQuarantine/) | Isolate | File |
| [T1037.001](https://attack.mitre.org/techniques/T1037/001/) | [D3-EAL Executable Allowlisting](https://d3fend.mitre.org/technique/d3f:ExecutableAllowlisting/) | Isolate | Executable File |
| [T1037.001](https://attack.mitre.org/techniques/T1037/001/) | [D3-EDL Executable Denylisting](https://d3fend.mitre.org/technique/d3f:ExecutableDenylisting/) | Isolate | Executable File |
| [T1037.001](https://attack.mitre.org/techniques/T1037/001/) | [D3-LFP Local File Permissions](https://d3fend.mitre.org/technique/d3f:LocalFilePermissions/) | Isolate | File |
| [T1037.001](https://attack.mitre.org/techniques/T1037/001/) | [D3-RFAM Remote File Access Mediation](https://d3fend.mitre.org/technique/d3f:RemoteFileAccessMediation/) | Isolate | File |

## Recommandations

- Surveiller les modifications des clés de registre de démarrage utilisateur, telles que HKCU\Environment\UserInitMprLogonScript, pour détecter l'exécution de scripts non autorisés (D3-FIM).
- Mettre en place des politiques de sécurité pour restreindre l'exécution de scripts via des chemins de registre spécifiques comme HKCU\Environment\UserInitMprLogonScript (D3-EAL).
- Utiliser des outils de détection des comportements pour identifier l'écriture de scripts dans des emplacements de démarrage système ou utilisateur (D3-DA).
- Surveiller les tentatives d'accès ou de modification des clés de registre liées aux tâches planifiées, telles que HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{A0A2225E-7E5D-4CAE-B899-09B3E96B259D}\DynamicInfo (D3-FIM).

## Incertitudes

- L'écriture dans la clé de registre HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{A0A2225E-7E5D-4CAE-B899-09B3E96B259D}\DynamicInfo est attribuée à svchost.exe et pourrait représenter une activité système normale plutôt qu'une action directe de l'échantillon.
