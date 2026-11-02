# Rapport d'analyse : T05_registre.ps1

| Champ | Valeur |
| --- | --- |
| SHA-256 | `5bd166c11137cafde8f578e7a72d88f0632df4a1bf3a368bef4e1e96e5dd4b7e` |
| MD5 | `abd04bcc990942fbf87ef91ba187bc1e` |
| Type | unknown |
| Taille | 1058 octets |

> Rapport généré par MalSight Agent. **À valider par un analyste avant diffusion.**

## Résumé

L'échantillon, exécuté via PowerShell, a interagi avec le système de registre pour créer des clés sous `HKCU\Software\MalsightTest` et `HKCU\Software\MalsightTest\Config` (attribution : sample_tree). De plus, des modifications de registre ont été observées sur des chemins liés aux notifications système de Windows (`service_window`). Aucune activité réseau, appel API sensible, ou règle CAPA n'a été détectée. L'activité observée est principalement limitée à la modification de clés de registre utilisateur.

## Comportements

| Comportement | Preuve | Statut |
| --- | --- | --- |
| Modification de clés de registre utilisateur pour un test spécifique. | `HKCU\Software\MalsightTest` | observé |
| Modification de clés de registre utilisateur pour un test spécifique. | `HKCU\Software\MalsightTest\Config` | observé |
| Interaction avec les clés de registre des notifications système de Windows. | `HKCU\Software\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.Power` | observé |

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

- Surveiller la création ou la modification des clés de registre de démarrage utilisateur, telles que HKCU\Software\MalsightTest, pour détecter des tentatives de persistance non autorisées (D3-FIM).
- Surveiller les modifications des clés de registre système sensibles, en particulier celles liées aux notifications ou aux tâches planifiées, pour détecter des changements de configuration (D3-SICA).
- Mettre en place des politiques de contrôle des applications pour restreindre l'exécution de fichiers provenant de chemins temporaires ou d'AppData, afin de limiter l'impact potentiel (D3-EAL).
- Utiliser des solutions de détection basées sur les signatures de hachage (SHA256: 5bd166c11137cafde8f578e7a72d88f0632df4a1bf3a368bef4e1e96e5dd4b7e, MD5: abd04bcc990942fbf87ef91ba187bc1e) pour bloquer l'exécution d'artefacts connus (D3-DA).
- Implémenter des règles de surveillance des modifications de clés de registre spécifiques (ex: HKCU\Software\MalsightTest) pour détecter les mécanismes de persistance (D3-FIM).
- Durcir les droits d'accès aux clés de registre critiques (ex: HKCU\Software\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\...) pour empêcher leur modification par des processus non système (D3-LFP).

## Incertitudes

- L'activité de modification des clés de registre liées aux notifications système (ex: `HKCU\Software\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.Power`) est attribuée à `service_window` et pourrait représenter une activité normale de fond de Windows, bien que l'échantillon ait été exécuté en même temps que ces observations.
