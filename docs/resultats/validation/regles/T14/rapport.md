# Rapport d'analyse : T14_tache_com.ps1

| Champ | Valeur |
| --- | --- |
| SHA-256 | `e6da01058c5ac5a5fcbdb6a33ef6c4ba04aa2f95654ff16b591d4bb7f31ca044` |
| MD5 | `350ff8888502b035739809902f90610b` |
| Type | unknown |
| Taille | 1721 octets |

> Rapport généré par MalSight Agent. **À valider par un analyste avant diffusion.**

## Résumé

Rapport généré sans LLM : faits extraits uniquement.

## Comportements

| Comportement | Preuve | Statut |
| --- | --- | --- |

## Indicateurs de compromission (IOC)

| Type | Valeur | Source |
| --- | --- | --- |
| sha256 | `e6da01058c5ac5a5fcbdb6a33ef6c4ba04aa2f95654ff16b591d4bb7f31ca044` | fichier |
| md5 | `350ff8888502b035739809902f90610b` | fichier |
| file_path | `C:\Windows\System32\Tasks\MalsightTest14` | extraction |
| registry_key | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SRUM\Telemetry\BatteryIdTable` | extraction |
| registry_key | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SRUM\Telemetry\CompositeBatteryData` | extraction |
| registry_key | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SRUM\Telemetry\LastLongTermEventTime` | extraction |
| registry_key | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SRUM\Telemetry\MaxBatteryIndex` | extraction |
| registry_key | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SRUM\Telemetry\SerializedStateData` | extraction |
| registry_key | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Plain\{B2F663AA-D5A2-4529-B716-3585F6D73624}` | extraction |
| registry_key | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{B2F663AA-D5A2-4529-B716-3585F6D73624}` | extraction |
| registry_key | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{B2F663AA-D5A2-4529-B716-3585F6D73624}\Actions` | extraction |
| registry_key | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{B2F663AA-D5A2-4529-B716-3585F6D73624}\Description` | extraction |
| registry_key | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{B2F663AA-D5A2-4529-B716-3585F6D73624}\DynamicInfo` | extraction |
| registry_key | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{B2F663AA-D5A2-4529-B716-3585F6D73624}\Hash` | extraction |
| registry_key | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{B2F663AA-D5A2-4529-B716-3585F6D73624}\Path` | extraction |
| registry_key | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{B2F663AA-D5A2-4529-B716-3585F6D73624}\Schema` | extraction |
| registry_key | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{B2F663AA-D5A2-4529-B716-3585F6D73624}\Triggers` | extraction |
| registry_key | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{B2F663AA-D5A2-4529-B716-3585F6D73624}\URI` | extraction |
| registry_key | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\MalsightTest14` | extraction |
| registry_key | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\MalsightTest14\Id` | extraction |
| registry_key | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\MalsightTest14\Index` | extraction |
| registry_key | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\MalsightTest14\SD` | extraction |
| registry_key | `HKLM\SYSTEM\SOFTWARE\Microsoft\TIP\AggregateResults\data` | extraction |

## API sensibles

| API | Catégorie | Source |
| --- | --- | --- |

## Techniques MITRE ATT&CK

| ID | Technique | Tactique | Source | Confiance | Preuve |
| --- | --- | --- | --- | --- | --- |
| [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | Scheduled Task | execution, persistence, privilege-escalation | rule | high | règle R-T1053.005-registre : HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\MalsightTest14 (svchost.exe (1448)) |

## Suggestions à valider par l'analyste

- Aucune.

## Contre-mesures D3FEND

Contre-mesures défensives [MITRE D3FEND](https://d3fend.mitre.org) associées aux techniques
ATT&CK retenues (source : d3fend, cache local ; IDs vérifiés).

| Technique ATT&CK | Contre-mesure D3FEND | Tactique | Artefact |
| --- | --- | --- | --- |
| [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | [D3-PLA Process Lineage Analysis](https://d3fend.mitre.org/technique/d3f:ProcessLineageAnalysis/) | Detect | Process |
| [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | [D3-PSA Process Spawn Analysis](https://d3fend.mitre.org/technique/d3f:ProcessSpawnAnalysis/) | Detect | Process |
| [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | [D3-PSMD Process Self-Modification Detection](https://d3fend.mitre.org/technique/d3f:ProcessSelf-ModificationDetection/) | Detect | Process |
| [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | [D3-SCA System Call Analysis](https://d3fend.mitre.org/technique/d3f:SystemCallAnalysis/) | Detect | System Call |
| [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | [D3-SDM System Daemon Monitoring](https://d3fend.mitre.org/technique/d3f:SystemDaemonMonitoring/) | Detect | Operating System Process |
| [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | [D3-SJA Scheduled Job Analysis](https://d3fend.mitre.org/technique/d3f:ScheduledJobAnalysis/) | Detect | Job Schedule |
| [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | [D3-ABPI Application-based Process Isolation](https://d3fend.mitre.org/technique/d3f:Application-basedProcessIsolation/) | Isolate | Process |
| [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | [D3-EAL Executable Allowlisting](https://d3fend.mitre.org/technique/d3f:ExecutableAllowlisting/) | Isolate | Create Process |
| [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | [D3-EDL Executable Denylisting](https://d3fend.mitre.org/technique/d3f:ExecutableDenylisting/) | Isolate | Create Process |
| [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | [D3-HBPI Hardware-based Process Isolation](https://d3fend.mitre.org/technique/d3f:Hardware-basedProcessIsolation/) | Isolate | Process |
| [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | [D3-KBPI Kernel-based Process Isolation](https://d3fend.mitre.org/technique/d3f:Kernel-basedProcessIsolation/) | Isolate | Process |
| [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | [D3-SCF System Call Filtering](https://d3fend.mitre.org/technique/d3f:SystemCallFiltering/) | Isolate | System Call |

## Recommandations


## Incertitudes

- Aucune signalée.
