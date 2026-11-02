# Rapport d'analyse : T04_script_logon.ps1

| Champ | Valeur |
| --- | --- |
| SHA-256 | `75f147e378deae3f4ad4f4bf64b5367f4e8bc203a47b2dfcb114510d54c9a37b` |
| MD5 | `79df13f3d86a8156fb0bc208fd4c1536` |
| Type | unknown |
| Taille | 998 octets |

> Rapport généré par MalSight Agent. **À valider par un analyste avant diffusion.**

## Résumé

L'échantillon est un script PowerShell nommé "T04_script_logon.ps1". L'analyse dynamique montre que ce script a modifié des clés de registre spécifiques, notamment dans les chemins liés aux scripts de connexion utilisateur et au cache des tâches planifiées. Aucune activité réseau, création de processus ou écriture de fichiers n'a été observée dans les données fournies.

## Comportements

| Comportement | Preuve | Statut |
| --- | --- | --- |
| Modification des clés de registre pour potentiellement exécuter un script au logon de l'utilisateur. | `HKCU\Environment\UserInitMprLogonScript` | observé |
| Modification des clés de registre liées au cache des tâches planifiées. | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{A0A2225E-7E5D-4CAE-B899-09B3E96B259D}\DynamicInfo` | observé |

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
| [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | Registry Run Keys / Startup Folder | persistence, privilege-escalation | llm | medium | HKCU\Environment\UserInitMprLogonScript |

## Contre-mesures D3FEND

Contre-mesures défensives [MITRE D3FEND](https://d3fend.mitre.org) associées aux techniques
ATT&CK retenues (source : d3fend, cache local ; IDs vérifiés).

| Technique ATT&CK | Contre-mesure D3FEND | Tactique | Artefact |
| --- | --- | --- | --- |
| [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | [D3-FE File Encryption](https://d3fend.mitre.org/technique/d3f:FileEncryption/) | Harden | File |
| [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | [D3-DA Dynamic Analysis](https://d3fend.mitre.org/technique/d3f:DynamicAnalysis/) | Detect | Executable File |
| [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | [D3-EFA Emulated File Analysis](https://d3fend.mitre.org/technique/d3f:EmulatedFileAnalysis/) | Detect | Executable File |
| [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | [D3-FA File Analysis](https://d3fend.mitre.org/technique/d3f:FileAnalysis/) | Detect | File |
| [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | [D3-FIM File Integrity Monitoring](https://d3fend.mitre.org/technique/d3f:FileIntegrityMonitoring/) | Detect | File |
| [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | [D3-SICA System Init Config Analysis](https://d3fend.mitre.org/technique/d3f:SystemInitConfigAnalysis/) | Detect | System Init Configuration |
| [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | [D3-CF Content Filtering](https://d3fend.mitre.org/technique/d3f:ContentFiltering/) | Isolate | File |
| [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | [D3-CM Content Modification](https://d3fend.mitre.org/technique/d3f:ContentModification/) | Isolate | File |
| [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | [D3-CQ Content Quarantine](https://d3fend.mitre.org/technique/d3f:ContentQuarantine/) | Isolate | File |
| [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | [D3-EAL Executable Allowlisting](https://d3fend.mitre.org/technique/d3f:ExecutableAllowlisting/) | Isolate | Executable File |
| [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | [D3-EDL Executable Denylisting](https://d3fend.mitre.org/technique/d3f:ExecutableDenylisting/) | Isolate | Executable File |
| [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | [D3-LFP Local File Permissions](https://d3fend.mitre.org/technique/d3f:LocalFilePermissions/) | Isolate | File |

## Recommandations

- Surveiller les modifications des clés de registre de démarrage utilisateur, telles que HKCU\Environment\UserInitMprLogonScript, pour détecter l'ajout de scripts non autorisés (D3-FIM).
- Implémenter des politiques de sécurité pour restreindre l'écriture dans les clés de registre de démarrage utilisateur et système (D3-LFP).
- Utiliser des solutions de détection des comportements pour surveiller l'exécution de scripts ou de programmes à partir de chemins de démarrage utilisateur (D3-DA).
- Surveiller les tentatives de création ou de modification de clés de registre liées aux tâches planifiées (ex: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{A0A2225E-7E5D-4CAE-B899-09B3E96B259D}\DynamicInfo) (D3-FIM).
- Mettre en place des mécanismes de contrôle des applications pour n'autoriser l'exécution que des exécutables connus et approuvés (D3-EAL).

## Incertitudes

- Aucune activité réseau, création de processus ou écriture de fichiers n'a été observée, ce qui limite la compréhension complète du comportement de l'échantillon.
