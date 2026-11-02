# Rapport d'analyse : T14_tache_com.ps1

| Champ | Valeur |
| --- | --- |
| SHA-256 | `e6da01058c5ac5a5fcbdb6a33ef6c4ba04aa2f95654ff16b591d4bb7f31ca044` |
| MD5 | `350ff8888502b035739809902f90610b` |
| Type | unknown |
| Taille | 1721 octets |

> Rapport généré par MalSight Agent. **À valider par un analyste avant diffusion.**

## Résumé

L'échantillon analysé, nommé "T14_tache_com.ps1", n'a pas d'appels API sensibles ni de règles CAPA associées. L'analyse dynamique montre que des modifications de registre et des écritures de fichiers ont eu lieu, toutes attribuées à des processus système (`svchost.exe`). Ces actions consistent à créer et à modifier des éléments liés au planificateur de tâches de Windows (Task Scheduler), notamment en écrivant des clés de registre et un fichier dans `C:\Windows\System32\Tasks\MalsightTest14`. De plus, des écritures de registre sont observées dans des zones de télémétrie système (SRUM et TIP), ce qui suggère une interaction avec les mécanismes de reporting ou de gestion des données système.

## Comportements

| Comportement | Preuve | Statut |
| --- | --- | --- |
| Création et modification d'éléments du Planificateur de tâches (Task Scheduler) | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\MalsightTest14` | observé |
| Création d'un fichier de tâche dans le répertoire système | `C:\Windows\System32\Tasks\MalsightTest14` | observé |
| Écriture de données de télémétrie système (SRUM et TIP) | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SRUM\Telemetry\LastLongTermEventTime` | observé |

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

## Suggestions à valider par l'analyste

Techniques proposées par le modèle de langage, **non retenues dans la liste officielle** (D10 :
les outils classent, le LLM explique). Chacune cite une preuve retrouvée dans le dossier de cas,
mais sa pertinence reste à valider.

| ID | Technique | Tactique | Confiance | Preuve |
| --- | --- | --- | --- | --- |
| [T1053](https://attack.mitre.org/techniques/T1053/) | Scheduled Task/Job | execution, persistence, privilege-escalation | medium | HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\MalsightTest14 |

## Contre-mesures D3FEND

- Aucune (aucune technique ATT&CK retenue, ou cache D3FEND absent : `malsight download-d3fend`).

## Recommandations

- Surveiller la création ou la modification de fichiers dans le chemin `C:\Windows\System32\Tasks\MalsightTest14` pour détecter des artefacts potentiels.
- Surveiller les modifications des clés de registre liées au planificateur de tâches, en particulier sous `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{B2F663AA-D5A2-4529-B716-3585F6D73624}` et ses sous-clés, pour détecter des ajouts ou des modifications non autorisés.
- Surveiller les accès et modifications des clés de registre de télémétrie de batterie sous `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SRUM\Telemetry\*` pour identifier des tentatives de manipulation de données système.
- Mettre en place des règles de détection (YARA/Sigma) basées sur les hachages SHA256 (`e6da01058c5ac5a5fcbdb6a33ef6c4ba04aa2f95654ff16b591d4bb7f31ca044`) et MD5 (`350ff8888502b035739809902f90610b`) pour détecter la présence de l'échantillon.
- Surveiller les appels d'API ou les activités liées à la création de tâches planifiées pour détecter des comportements anormaux (D3-LFP).

## Incertitudes

- Toutes les modifications de registre et les écritures de fichiers sont attribuées à `svchost.exe` (1448) ou `svchost.exe` (2060) via `service_window`, ce qui rend difficile de déterminer si l'échantillon est la cause directe de ces actions ou si elles sont des activités de fond de Windows coïncidant avec l'exécution.

## Affirmations rejetées par le vérificateur

- ID D3FEND absent du cache retiré d'une recommandation : D3-FSD
- ID D3FEND absent du cache retiré d'une recommandation : D3-RMD
- ID D3FEND absent du cache retiré d'une recommandation : D3-RMD
- ID D3FEND absent du cache retiré d'une recommandation : D3-FSD
