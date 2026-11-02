# Rapport d'analyse : T02_tache_planifiee.ps1

| Champ | Valeur |
| --- | --- |
| SHA-256 | `cc7ed63f0672353ffeaf5dbc1b7a6e5ffe70858c5c433feeda6b401cdfaba47b` |
| MD5 | `179a3d0948ee1f3502db8a063b4eeed8` |
| Type | unknown |
| Taille | 1119 octets |

> Rapport généré par MalSight Agent. **À valider par un analyste avant diffusion.**

## Résumé

L'échantillon est un script PowerShell (`T02_tache_planifiee.ps1`) qui a interagi avec le système de planification des tâches de Windows. Il a écrit un fichier dans le répertoire des tâches système et a créé plusieurs clés de registre associées à la planification de tâches, suggérant la création ou la modification d'une tâche planifiée. Aucune activité réseau ou processus n'a été observé.

## Comportements

| Comportement | Preuve | Statut |
| --- | --- | --- |
| Création de fichier système | `C:\Windows\System32\Tasks\MalsightTest` | observé |
| Modification du registre pour la planification des tâches | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{A0A2225E-7E5D-4CAE-B899-09B3E96B259D}\DynamicInfo` | observé |
| Modification du registre pour la planification des tâches | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\MalsightTest` | observé |
| Modification du registre pour la planification des tâches | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\MalsightTest\SD` | observé |
| Modification du registre pour la planification des tâches | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\MalsightTest\Id` | observé |
| Modification du registre pour la planification des tâches | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\MalsightTest\Index` | observé |
| Modification du registre pour la planification des tâches | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{7497102D-8538-4CE3-BADF-E83613BEE80F}\Path` | observé |
| Modification du registre pour la planification des tâches | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{7497102D-8538-4CE3-BADF-E83613BEE80F}\Hash` | observé |
| Modification du registre pour la planification des tâches | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Plain\{7497102D-8538-4CE3-BADF-E83613BEE80F}` | observé |
| Modification du registre pour la planification des tâches | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{7497102D-8538-4CE3-BADF-E83613BEE80F}\Schema` | observé |
| Modification du registre pour la planification des tâches | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{7497102D-8538-4CE3-BADF-E83613BEE80F}\URI` | observé |
| Modification du registre pour la planification des tâches | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{7497102D-8538-4CE3-BADF-E83613BEE80F}\Triggers` | observé |
| Modification du registre pour la planification des tâches | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{7497102D-8538-4CE3-BADF-E83613BEE80F}\Actions` | observé |
| Modification du registre pour la planification des tâches | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{7497102D-8538-4CE3-BADF-E83613BEE80F}\DynamicInfo` | observé |

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
| [T1053](https://attack.mitre.org/techniques/T1053/) | Scheduled Task/Job | execution, persistence, privilege-escalation | llm | medium | Création de fichier dans C:\Windows\System32\Tasks\MalsightTest |
| [T1027](https://attack.mitre.org/techniques/T1027/) | Obfuscated Files or Information | stealth | llm | medium | Modification de clés de registre liées à la planification des tâches (HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\*) |

## Contre-mesures D3FEND

Contre-mesures défensives [MITRE D3FEND](https://d3fend.mitre.org) associées aux techniques
ATT&CK retenues (source : d3fend, cache local ; IDs vérifiés).

| Technique ATT&CK | Contre-mesure D3FEND | Tactique | Artefact |
| --- | --- | --- | --- |
| [T1053](https://attack.mitre.org/techniques/T1053/) | [D3-FE File Encryption](https://d3fend.mitre.org/technique/d3f:FileEncryption/) | Harden | File |
| [T1053](https://attack.mitre.org/techniques/T1053/) | [D3-FA File Analysis](https://d3fend.mitre.org/technique/d3f:FileAnalysis/) | Detect | File |
| [T1053](https://attack.mitre.org/techniques/T1053/) | [D3-FIM File Integrity Monitoring](https://d3fend.mitre.org/technique/d3f:FileIntegrityMonitoring/) | Detect | File |
| [T1053](https://attack.mitre.org/techniques/T1053/) | [D3-PLA Process Lineage Analysis](https://d3fend.mitre.org/technique/d3f:ProcessLineageAnalysis/) | Detect | Process |
| [T1053](https://attack.mitre.org/techniques/T1053/) | [D3-PSA Process Spawn Analysis](https://d3fend.mitre.org/technique/d3f:ProcessSpawnAnalysis/) | Detect | Process |
| [T1053](https://attack.mitre.org/techniques/T1053/) | [D3-PSMD Process Self-Modification Detection](https://d3fend.mitre.org/technique/d3f:ProcessSelf-ModificationDetection/) | Detect | Process |
| [T1053](https://attack.mitre.org/techniques/T1053/) | [D3-SCA System Call Analysis](https://d3fend.mitre.org/technique/d3f:SystemCallAnalysis/) | Detect | System Call |
| [T1053](https://attack.mitre.org/techniques/T1053/) | [D3-SDM System Daemon Monitoring](https://d3fend.mitre.org/technique/d3f:SystemDaemonMonitoring/) | Detect | Operating System Process |
| [T1053](https://attack.mitre.org/techniques/T1053/) | [D3-SJA Scheduled Job Analysis](https://d3fend.mitre.org/technique/d3f:ScheduledJobAnalysis/) | Detect | Job Schedule |
| [T1053](https://attack.mitre.org/techniques/T1053/) | [D3-ABPI Application-based Process Isolation](https://d3fend.mitre.org/technique/d3f:Application-basedProcessIsolation/) | Isolate | Process |
| [T1053](https://attack.mitre.org/techniques/T1053/) | [D3-CF Content Filtering](https://d3fend.mitre.org/technique/d3f:ContentFiltering/) | Isolate | File |
| [T1053](https://attack.mitre.org/techniques/T1053/) | [D3-CM Content Modification](https://d3fend.mitre.org/technique/d3f:ContentModification/) | Isolate | File |

## Recommandations

- Surveiller la création de fichiers dans des chemins inhabituels pour les tâches planifiées, comme "C:\Windows\System32\Tasks\MalsightTest", en utilisant Sysmon pour détecter les événements de création de fichiers (D3-FIM).
- Détecter les modifications des clés de registre associées à la planification des tâches, en particulier dans "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\*", car ces modifications peuvent indiquer une obfuscation ou une persistance (D3-FIM).
- Mettre en place des règles de détection pour surveiller les appels d'API ou les séquences d'API liées à la création ou la modification de tâches planifiées (ex: utilisation de COM/WMI pour la gestion des tâches), afin de détecter les comportements de persistance (D3-SCA).
- Durcir les droits d'écriture sur les répertoires de tâches planifiées (ex: "C:\Windows\System32\Tasks") pour limiter qui peut créer ou modifier des tâches (D3-FE).
- Analyser les processus parents et enfants lors de l'exécution de tâches planifiées pour détecter des chaînes d'exécution anormales (D3-PLA).
- Surveiller les tentatives d'accès ou de modification des clés de registre spécifiques aux tâches planifiées (ex: "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\*") pour détecter les activités suspectes (D3-FIM).

## Incertitudes

- Aucune signalée.
