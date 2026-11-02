# Rapport d'analyse : T05_registre.ps1

| Champ | Valeur |
| --- | --- |
| SHA-256 | `5bd166c11137cafde8f578e7a72d88f0632df4a1bf3a368bef4e1e96e5dd4b7e` |
| MD5 | `abd04bcc990942fbf87ef91ba187bc1e` |
| Type | unknown |
| Taille | 1058 octets |

> Rapport généré par MalSight Agent. **À valider par un analyste avant diffusion.**

## Résumé

L'échantillon, exécuté via PowerShell, a interagi avec le système de registre pour créer des clés sous `HKCU\Software\MalsightTest` et `HKCU\Software\MalsightTest\Config` (observation `sample_tree`). De plus, des modifications de registre ont été observées sur des chemins liés aux notifications système de Windows (`service_window`). Aucune activité réseau, appel API sensible, ou règle CAPA n'a été détectée. L'activité observée est principalement limitée à la modification de clés de registre utilisateur.

## Comportements

| Comportement | Preuve | Statut |
| --- | --- | --- |
| Modification de clés de registre utilisateur pour un test spécifique. | `HKCU\Software\MalsightTest` | observé |
| Modification de clés de registre utilisateur pour un test spécifique. | `HKCU\Software\MalsightTest\Config` | observé |
| Interaction avec des clés de registre système liées aux notifications Windows. | `HKCU\Software\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.Power` | observé |

## Indicateurs de compromission (IOC)

| Type | Valeur | Source |
| --- | --- | --- |
| sha256 | `5bd166c11137cafde8f578e7a72d88f0632df4a1bf3a368bef4e1e96e5dd4b7e` | fichier |
| md5 | `abd04bcc990942fbf87ef91ba187bc1e` | fichier |
| registry_key | `HKCU\Software\MalsightTest` | extraction |
| registry_key | `HKCU\Software\MalsightTest\Config` | extraction |
| registry_key | `HKCU\Software\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.Power` | extraction |
| registry_key | `HKCU\Software\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.Power\Setting` | extraction |
| registry_key | `HKCU\Software\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.Power\appType` | extraction |
| registry_key | `HKCU\Software\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.Power\wnsId` | extraction |
| registry_key | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{A0A2225E-7E5D-4CAE-B899-09B3E96B259D}\DynamicInfo` | extraction |
| file_path | `C:\Users\WDAGUtilityAccount\AppData\Local\Microsoft\Windows\Notifications\wpndatabase.db-wal` | extraction |

## API sensibles

| API | Catégorie | Source |
| --- | --- | --- |

## Techniques MITRE ATT&CK

| ID | Technique | Tactique | Source | Confiance | Preuve |
| --- | --- | --- | --- | --- | --- |
| [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | Registry Run Keys / Startup Folder | persistence, privilege-escalation | llm | medium | HKCU\Software\MalsightTest |

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

- Surveiller la création ou la modification des clés de registre de démarrage utilisateur, telles que HKCU\Software\MalsightTest, pour détecter des tentatives de persistance (D3-FIM).
- Surveiller les modifications des clés de registre système sensibles, en particulier celles liées aux notifications ou aux tâches planifiées, pour détecter des changements non autorisés (D3-FIM).
- Mettre en place des politiques de contrôle des applications pour restreindre l'exécution de fichiers provenant de chemins temporaires ou non standard (D3-EAL).
- Configurer des règles de détection (Sysmon/EDR) pour alerter sur l'écriture de clés de registre spécifiques utilisées pour la persistance, comme HKCU\Software\MalsightTest (D3-FIM).
- Analyser les processus qui accèdent ou modifient les bases de données de notifications utilisateur (ex: C:\Users\WDAGUtilityAccount\AppData\Local\Microsoft\Windows\Notifications\wpndatabase.db-wal) pour identifier des comportements anormaux (D3-DA).

## Incertitudes

- Les modifications de registre observées sur les chemins de notifications système (`service_window`) ne sont pas directement attribuables à l'exécution de l'échantillon, mais sont des activités de fond de Windows détectées pendant l'analyse.
