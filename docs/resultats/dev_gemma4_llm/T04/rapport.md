# Rapport d'analyse : T04_script_logon.ps1

| Champ | Valeur |
| --- | --- |
| SHA-256 | `75f147e378deae3f4ad4f4bf64b5367f4e8bc203a47b2dfcb114510d54c9a37b` |
| MD5 | `79df13f3d86a8156fb0bc208fd4c1536` |
| Type | unknown |
| Taille | 998 octets |

> Rapport généré par MalSight Agent. **À valider par un analyste avant diffusion.**

## Résumé

L'échantillon, un script PowerShell nommé `T04_script_logon.ps1`, a été exécuté et a interagi avec le système de registre. Il a écrit une valeur dans la clé `HKCU\Environment\UserInitMprLogonScript` et une autre clé dans le cache des tâches planifiées (`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{A0A2225E-7E5D-4CAE-B899-09B3E96B259D}\DynamicInfo`). Ces actions suggèrent une tentative de persistance ou de modification des scripts de connexion utilisateur et des tâches planifiées.

## Comportements

| Comportement | Preuve | Statut |
| --- | --- | --- |
| Modification des scripts de connexion utilisateur (UserInit/MprLogon) | `HKCU\Environment\UserInitMprLogonScript` | inféré |
| Écriture dans le cache des tâches planifiées | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{A0A2225E-7E5D-4CAE-B899-09B3E96B259D}\DynamicInfo` | observé |

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

## Suggestions à valider par l'analyste

- Aucune.

## Contre-mesures D3FEND

- Aucune (aucune technique ATT&CK retenue, ou cache D3FEND absent : `malsight download-d3fend`).

## Recommandations

- Surveiller les modifications des clés de registre de démarrage utilisateur, telles que HKCU\Environment\UserInitMprLogonScript, pour détecter l'ajout de scripts ou de chemins exécutables non autorisés (D3-FIM).
- Mettre en place des politiques de durcissement pour restreindre l'écriture dans les clés de registre de démarrage utilisateur (HKCU\Environment\UserInitMprLogonScript) afin de prévenir l'exécution de code au démarrage (D3-LFP).
- Utiliser des solutions de détection des comportements pour identifier les tentatives de modification des clés de registre système critiques, comme celles liées aux tâches planifiées (HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{A0A2225E-7E5D-4CAE-B899-09B3E96B259D}\DynamicInfo) (D3-FIM).
- Considérer l'implémentation de listes blanches (Allowlisting) pour les exécutables et les scripts afin de n'autoriser que les programmes connus et nécessaires au fonctionnement normal du système (D3-EAL).
- Surveiller les événements de création ou de modification de tâches planifiées pour détecter toute activité suspecte (D3-FIM).

## Incertitudes

- L'attribution de la modification de la clé `HKCU\Environment\UserInitMprLogonScript` est attribuée au processus `powershell.exe (8064)` via `sample_tree`, ce qui indique que l'échantillon est responsable de cette action. Cependant, le contexte exact de cette modification (valeur écrite, données) n'est pas fourni, rendant l'impact précis incertain.
- L'écriture dans `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{A0A2225E-7E5D-4CAE-B899-09B3E96B259D}\DynamicInfo` est attribuée à `service_window` via `procmon`, ce qui pourrait indiquer une activité de fond de Windows ou une interaction indirecte avec un service, même si l'échantillon est le déclencheur général.

## Affirmations rejetées par le vérificateur

- Suggestion couverte par une règle D7 qui ne s'est pas déclenchée, rejetée : T1547.001
- Contre-mesure D3-FE pour une technique non retenue : T1547.001
- Contre-mesure D3-DA pour une technique non retenue : T1547.001
- Contre-mesure D3-EFA pour une technique non retenue : T1547.001
- Contre-mesure D3-FA pour une technique non retenue : T1547.001
- Contre-mesure D3-FIM pour une technique non retenue : T1547.001
- Contre-mesure D3-SICA pour une technique non retenue : T1547.001
- Contre-mesure D3-CF pour une technique non retenue : T1547.001
- Contre-mesure D3-CM pour une technique non retenue : T1547.001
- Contre-mesure D3-CQ pour une technique non retenue : T1547.001
- Contre-mesure D3-EAL pour une technique non retenue : T1547.001
- Contre-mesure D3-EDL pour une technique non retenue : T1547.001
- Contre-mesure D3-LFP pour une technique non retenue : T1547.001
