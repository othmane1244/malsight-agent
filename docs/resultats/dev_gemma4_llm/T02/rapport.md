# Rapport d'analyse : T02_tache_planifiee.ps1

| Champ | Valeur |
| --- | --- |
| SHA-256 | `cc7ed63f0672353ffeaf5dbc1b7a6e5ffe70858c5c433feeda6b401cdfaba47b` |
| MD5 | `179a3d0948ee1f3502db8a063b4eeed8` |
| Type | unknown |
| Taille | 1119 octets |

> Rapport généré par MalSight Agent. **À valider par un analyste avant diffusion.**

## Résumé

L'échantillon, nommé "T02_tache_planifiee.ps1", n'a pas d'appels API ou de règles CAPA détectées. L'analyse dynamique montre que des modifications et des écritures de registre liées à la gestion des tâches planifiées de Windows ont eu lieu. Ces activités sont attribuées à `svchost.exe (1448)` et concernent la création ou la modification de tâches planifiées, notamment des clés nommées `MalsightTest` et des GUID spécifiques, ainsi que la création d'un fichier de tâche dans `C:\Windows\System32\Tasks\MalsightTest`. Il est important de noter que toutes les observations de registre et de fichiers sont attribuées à `service_window` (via `svchost.exe`), et non directement à l'exécution de l'échantillon lui-même.

## Comportements

| Comportement | Preuve | Statut |
| --- | --- | --- |
| Modification du registre pour la gestion des tâches planifiées. | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{A0A2225E-7E5D-4CAE-B899-09B3E96B259D}\DynamicInfo, HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\MalsightTest, HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\MalsightTest\SD, HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\MalsightTest\Id, HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\MalsightTest\Index, HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{7497102D-8538-4CE3-BADF-E83613BEE80F}\Path, HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{7497102D-8538-4CE3-BADF-E83613BEE80F}\Hash, HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{7497102D-8538-4CE3-BADF-E83613BEE80F}\Schema, HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{7497102D-8538-4CE3-BADF-E83613BEE80F}\Triggers, HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{7497102D-8538-4CE3-BADF-E83613BEE80F}\Actions, HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{7497102D-8538-4CE3-BADF-E83613BEE80F}\DynamicInfo` | observé |
| Création ou modification d'un fichier de tâche planifiée. | `C:\Windows\System32\Tasks\MalsightTest (file)` | observé |
| Modification du registre pour des éléments de tâches planifiées spécifiques. | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\MalsightTest (registry), HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{7497102D-8538-4CE3-BADF-E83613BEE80F}\DynamicInfo (registry)` | observé |

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

## Contre-mesures D3FEND

- Aucune (aucune technique ATT&CK retenue, ou cache D3FEND absent : `malsight download-d3fend`).

## Recommandations

- Surveiller les modifications des clés de registre liées au planificateur de tâches, en particulier sous `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\` pour détecter l'ajout ou la modification de tâches (D3-SJA).
- Surveiller les appels d'API ou les événements système liés à la création ou à la modification de tâches planifiées, en ciblant les chemins de registre comme `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\` (D3-SJA).
- Mettre en place une surveillance de l'intégrité des fichiers et des clés de registre critiques du système, notamment les chemins de tâches planifiées, pour détecter toute altération (D3-FIM).
- Analyser la lignée des processus pour détecter si des processus non attendus interagissent avec les outils de gestion des tâches ou écrivent dans les répertoires de tâches (D3-PLA).
- Pour les systèmes critiques, envisager de restreindre les droits d'écriture sur les clés de registre du planificateur de tâches pour limiter la capacité d'un processus compromis à persister via des tâches (Durcissement).
- Analyser les événements de création de tâches planifiées pour vérifier l'origine et la destination des exécutions, en se basant sur les chemins de registre observés comme `C:\Windows\System32\Tasks\MalsightTest` (D3-SJA).

## Incertitudes

- Toutes les modifications de registre et la création de fichiers sont attribuées à `service_window` via `svchost.exe (1448)`, ce qui rend difficile de déterminer si l'échantillon a initié ces actions ou si elles sont des activités système de fond.
- L'échantillon lui-même n'a pas d'appels API ou de règles CAPA enregistrées dans les données fournies.

## Affirmations rejetées par le vérificateur

- Technique sans preuve vérifiable, rejetée : T1053 (aucune valeur reconnaissable)
- Contre-mesure D3-FE pour une technique non retenue : T1053
- Contre-mesure D3-FA pour une technique non retenue : T1053
- Contre-mesure D3-FIM pour une technique non retenue : T1053
- Contre-mesure D3-PLA pour une technique non retenue : T1053
- Contre-mesure D3-PSA pour une technique non retenue : T1053
- Contre-mesure D3-PSMD pour une technique non retenue : T1053
- Contre-mesure D3-SCA pour une technique non retenue : T1053
- Contre-mesure D3-SDM pour une technique non retenue : T1053
- Contre-mesure D3-SJA pour une technique non retenue : T1053
- Contre-mesure D3-ABPI pour une technique non retenue : T1053
- Contre-mesure D3-CF pour une technique non retenue : T1053
- Contre-mesure D3-CM pour une technique non retenue : T1053
