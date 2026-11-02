# Rapport d'analyse : T05_registre.ps1

| Champ | Valeur |
| --- | --- |
| SHA-256 | `5bd166c11137cafde8f578e7a72d88f0632df4a1bf3a368bef4e1e96e5dd4b7e` |
| MD5 | `abd04bcc990942fbf87ef91ba187bc1e` |
| Type | unknown |
| Taille | 1058 octets |

> Rapport généré par MalSight Agent. **À valider par un analyste avant diffusion.**

## Résumé

L'échantillon est un script PowerShell (`T05_registre.ps1`) qui a interagi avec le système en modifiant plusieurs clés de registre et en écrivant un fichier local. Aucune activité réseau ou processus créé n'a été observé. Les modifications de registre ciblent des emplacements liés aux notifications Windows et au planificateur de tâches, ainsi que la création d'une base de données de notifications.

## Comportements

| Comportement | Preuve | Statut |
| --- | --- | --- |
| Modification du registre pour créer des clés de configuration et des entrées de notifications. | `HKCU\Software\MalsightTest, HKCU\Software\MalsightTest\Config, HKCU\Software\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.Power, HKCU\Software\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.Power\Setting, HKCU\Software\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.Power\appType, HKCU\Software\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.Power\wnsId, HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{A0A2225E-7E5D-4CAE-B899-09B3E96B259D}\DynamicInfo` | observé |
| Écriture d'un fichier de base de données de notifications. | `C:\Users\WDAGUtilityAccount\AppData\Local\Microsoft\Windows\Notifications\wpndatabase.db-wal` | observé |

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
| [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | Web Protocols | command-and-control | llm | medium | HKCU\Software\MalsightTest |

## Contre-mesures D3FEND

- Aucune (aucune technique ATT&CK retenue, ou cache D3FEND absent : `malsight download-d3fend`).

## Recommandations


## Incertitudes

- Aucune activité réseau n'a été observée, ce qui empêche de déterminer si des communications externes ont eu lieu.

## Affirmations rejetées par le vérificateur

- Recommandation citant un ID D3FEND absent du cache (D3-REG) : Surveiller la création ou la modification des clés de registre suivantes : HKCU\Software\MalsightTest, HKCU\Software\MalsightTest\Config, HKCU\Software\MalsightTest\DynamicInfo (ou toute clé sous HKCU\Software\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.Power) pour détecter des activités suspectes (D3-REG).
- Recommandation citant un ID D3FEND absent du cache (D3-FILE) : Surveiller les modifications des fichiers de base de données de notifications Windows, tels que C:\Users\WDAGUtilityAccount\AppData\Local\Microsoft\Windows\Notifications\wpndatabase.db-wal, car ces fichiers sont des cibles potentielles pour la persistance ou l'exfiltration d'informations (D3-FILE).
- Recommandation citant un ID D3FEND absent du cache (D3-HASH) : Mettre en place des règles de détection (YARA/Sigma) pour identifier les hachages SHA256 (5bd166c11137cafde8f578e7a72d88f0632df4a1bf3a368bef4e1e96e5dd4b7e) et MD5 (abd04bcc990942fbf87ef91ba187bc1e) associés à l'échantillon (D3-HASH).
- Recommandation citant un ID D3FEND absent du cache (D3-API) : Surveiller les appels d'API ou les opérations de registre ciblant des chemins spécifiques comme HKCU\Software\MalsightTest pour détecter des tentatives de persistance ou de configuration malveillante (D3-API).
- Recommandation citant un ID D3FEND absent du cache (D3-REG) : Durcir les politiques de registre pour limiter les modifications dans les sous-clés de notifications Windows (ex: HKCU\Software\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.Power) pour empêcher la modification des paramètres système (D3-REG).
