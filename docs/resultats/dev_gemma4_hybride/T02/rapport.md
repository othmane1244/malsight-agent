# Rapport d'analyse : T02_tache_planifiee.ps1

| Champ | Valeur |
| --- | --- |
| SHA-256 | `cc7ed63f0672353ffeaf5dbc1b7a6e5ffe70858c5c433feeda6b401cdfaba47b` |
| MD5 | `179a3d0948ee1f3502db8a063b4eeed8` |
| Type | unknown |
| Taille | 1119 octets |

> Rapport généré par MalSight Agent. **À valider par un analyste avant diffusion.**

## Résumé

L'échantillon n'a pas d'activité API ou de règles CAPA détectables. L'analyse dynamique montre que des modifications et des écritures de clés de registre liées au Planificateur de tâches de Windows ont eu lieu, spécifiquement dans les chemins `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\...`. Ces écritures, ainsi que la création d'un fichier de tâche (`C:\Windows\System32\Tasks\MalsightTest`), sont attribuées à `svchost.exe (1448)` et sont cohérentes avec l'utilisation du Planificateur de tâches. L'activité observée est principalement une interaction avec les mécanismes de planification système.

## Comportements

| Comportement | Preuve | Statut |
| --- | --- | --- |
| Écriture de clés de registre liées au Planificateur de tâches | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{A0A2225E-7E5D-4CAE-B899-09B3E96B259D}\DynamicInfo (service_window), HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\MalsightTest (service_window), HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\MalsightTest\SD (service_window), HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\MalsightTest\Id (service_window), HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\MalsightTest\Index (service_window), HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{7497102D-8538-4CE3-BADF-E83613BEE80F} (service_window), HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{7497102D-8538-4CE3-BADF-E83613BEE80F}\Path (service_window), HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{7497102D-8538-4CE3-BADF-E83613BEE80F}\Hash (service_window), HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{7497102D-8538-4CE3-BADF-E83613BEE80F}\Schema (service_window), HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{7497102D-8538-4CE3-BADF-E83613BEE80F}\URI (service_window), HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{7497102D-8538-4CE3-BADF-E83613BEE80F}\Triggers (service_window), HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{7497102D-8538-4CE3-BADF-E83613BEE80F}\Actions (service_window), HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{7497102D-8538-4CE3-BADF-E83613BEE80F}\DynamicInfo (service_window)` | observé |
| Création d'un fichier de tâche planifiée | `C:\Windows\System32\Tasks\MalsightTest (service_window)` | observé |

## Indicateurs de compromission (IOC)

| Type | Valeur | Source |
| --- | --- | --- |
| sha256 | `cc7ed63f0672353ffeaf5dbc1b7a6e5ffe70858c5c433feeda6b401cdfaba47b` | fichier |
| md5 | `179a3d0948ee1f3502db8a063b4eeed8` | fichier |
| file_path | `C:\Windows\System32\Tasks\MalsightTest` | extraction |
| registry_key | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Plain\{7497102D-8538-4CE3-BADF-E83613BEE80F}` | extraction |
| registry_key | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{7497102D-8538-4CE3-BADF-E83613BEE80F}` | extraction |
| registry_key | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{7497102D-8538-4CE3-BADF-E83613BEE80F}\Actions` | extraction |
| registry_key | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{7497102D-8538-4CE3-BADF-E83613BEE80F}\DynamicInfo` | extraction |
| registry_key | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{7497102D-8538-4CE3-BADF-E83613BEE80F}\Hash` | extraction |
| registry_key | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{7497102D-8538-4CE3-BADF-E83613BEE80F}\Path` | extraction |
| registry_key | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{7497102D-8538-4CE3-BADF-E83613BEE80F}\Schema` | extraction |
| registry_key | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{7497102D-8538-4CE3-BADF-E83613BEE80F}\Triggers` | extraction |
| registry_key | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{7497102D-8538-4CE3-BADF-E83613BEE80F}\URI` | extraction |
| registry_key | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{A0A2225E-7E5D-4CAE-B899-09B3E96B259D}\DynamicInfo` | extraction |
| registry_key | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\MalsightTest` | extraction |
| registry_key | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\MalsightTest\Id` | extraction |
| registry_key | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\MalsightTest\Index` | extraction |
| registry_key | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\MalsightTest\SD` | extraction |

## API sensibles

| API | Catégorie | Source |
| --- | --- | --- |

## Techniques MITRE ATT&CK

| ID | Technique | Tactique | Source | Confiance | Preuve |
| --- | --- | --- | --- | --- | --- |
| [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | Scheduled Task | execution, persistence, privilege-escalation | rule | high | règle R-T1053.005-registre : HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\MalsightTest (svchost.exe (1448)) |

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

- Surveiller les modifications des clés de registre liées au planificateur de tâches, en particulier sous `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\*` (D3-SJA).
- Détecter la création de tâches planifiées suspectes en analysant les chemins et les arguments utilisés, comme ceux observés dans `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\MalsightTest` (D3-SJA).
- Mettre en place des règles de détection basées sur les hachages (SHA256: cc7ed63f0672353ffeaf5dbc1b7a6e5ffe70858c5c433feeda6b401cdfaba47b, MD5: 179a3d0948ee1f3502db8a063b4eeed8) et les chemins de fichiers (C:\Windows\System32\Tasks\MalsightTest) (D3-EAL).
- Analyser la lignée des processus pour détecter si des processus système légitimes (comme svchost.exe) sont utilisés pour exécuter des tâches planifiées suspectes (D3-PLA).
- Durcir les droits d'écriture sur les clés de registre du planificateur de tâches pour limiter qui peut créer ou modifier des tâches (D3-SJA).
- Utiliser l'analyse des appels système pour détecter les interactions inhabituelles avec les API de gestion des tâches planifiées (D3-SCA).

## Incertitudes

- L'attribution des écritures de registre au Planificateur de tâches est attribuée à 'service_window' (svchost.exe (1448)), ce qui rend difficile de déterminer si l'échantillon a initié ces actions ou si elles sont le résultat d'une activité système de fond.
