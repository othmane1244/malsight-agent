# Rapport d'analyse : T14_tache_com.ps1

| Champ | Valeur |
| --- | --- |
| SHA-256 | `e6da01058c5ac5a5fcbdb6a33ef6c4ba04aa2f95654ff16b591d4bb7f31ca044` |
| MD5 | `350ff8888502b035739809902f90610b` |
| Type | unknown |
| Taille | 1721 octets |

> Rapport généré par MalSight Agent. **À valider par un analyste avant diffusion.**

## Résumé

L'échantillon analysé, nommé T14_tache_com.ps1, n'a pas d'appels API sensibles ni de règles CAPA spécifiques. L'analyse dynamique montre que des modifications de registre et des écritures de fichiers ont eu lieu, toutes attribuées à des processus système (`svchost.exe`). Ces actions consistent principalement à créer et manipuler des entrées de registre et des fichiers associés au Planificateur de tâches de Windows, notamment sous la clé `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\MalsightTest14` et un identifiant de tâche spécifique. De plus, des écritures de registre sont observées dans des zones de télémétrie système (SRUM et TIP), ce qui suggère une activité de fond ou de test de système plutôt qu'une exécution malveillante directe de l'échantillon.

## Comportements

| Comportement | Preuve | Statut |
| --- | --- | --- |
| Création et manipulation d'éléments du Planificateur de tâches (Scheduled Task) | `Création de clés de registre : HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\MalsightTest14, HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\MalsightTest14\SD, HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\MalsightTest14\Id, HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\MalsightTest14\Index, HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{B2F663AA-D5A2-4529-B716-3585F6D73624}, HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{B2F663AA-D5A2-4529-B716-3585F6D73624}\Path, HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{B2F663AA-D5A2-4529-B716-3585F6D73624}\Hash, HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Plain\{B2F663AA-D5A2-4529-B716-3585F6D73624}, HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{B2F663AA-D5A2-4529-B716-3585F6D73624}\Schema, HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{B2F663AA-D5A2-4529-B716-3585F6D73624}\Description, HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{B2F663AA-D5A2-4529-B716-3585F6D73624}\URI, HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{B2F663AA-D5A2-4529-B716-3585F6D73624}\Triggers, HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{B2F663AA-D5A2-4529-B716-3585F6D73624}\Actions, HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{B2F663AA-D5A2-4529-B716-3585F6D73624}\DynamicInfo, et écriture de fichier : C:\Windows\System32\Tasks\MalsightTest14` | observé |
| Écriture de données de télémétrie système (SRUM et TIP) | `HKLM\SYSTEM\SOFTWARE\Microsoft\TIP\AggregateResults\data (de svchost.exe (2060)), HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SRUM\Telemetry\LastLongTermEventTime (de svchost.exe (2060)), HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SRUM\Telemetry\CompositeBatteryData (de svchost.exe (2060)), HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SRUM\Telemetry\BatteryIdTable (de svchost.exe (2060)), HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SRUM\Telemetry\MaxBatteryIndex (de svchost.exe (2060)), HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SRUM\Telemetry\SerializedStateData (de svchost.exe (2060))` | observé |

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

- Surveiller la création ou la modification de tâches planifiées, en particulier celles qui pointent vers des chemins inhabituels ou des exécutables non standard. (D3-SJA)
- Surveiller les modifications des clés de registre liées au système de planification des tâches, telles que HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\MalsightTest14, pour détecter toute activité suspecte. (D3-SJA)
- Mettre en place des politiques de contrôle des applications pour limiter l'exécution de processus à partir de répertoires non standard comme C:\Windows\System32\Tasks, sauf si cela est explicitement requis par la fonction métier. (D3-EAL)
- Analyser la lignée des processus pour détecter si des processus légitimes (comme svchost.exe) sont utilisés pour déclencher des tâches ou exécuter des commandes de manière anormale. (D3-PLA)
- Surveiller les appels système liés à la manipulation du registre dans les zones de planification des tâches pour détecter des écritures non autorisées. (D3-SCA)

## Incertitudes

- L'attribution de toutes les actions (création de tâches, écritures de télémétrie) à 'service_window' (svchost.exe) rend difficile de déterminer si l'échantillon a initié ces actions ou si elles sont des activités de fond du système qui ont été capturées pendant l'exécution.
- Aucune activité réseau n'est observée, ce qui empêche de déterminer si l'échantillon communique avec des infrastructures externes.
