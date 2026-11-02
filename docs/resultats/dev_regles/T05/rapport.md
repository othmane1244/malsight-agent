# Rapport d'analyse : T05_registre.ps1

| Champ | Valeur |
| --- | --- |
| SHA-256 | `5bd166c11137cafde8f578e7a72d88f0632df4a1bf3a368bef4e1e96e5dd4b7e` |
| MD5 | `abd04bcc990942fbf87ef91ba187bc1e` |
| Type | unknown |
| Taille | 1058 octets |

> Rapport généré par MalSight Agent. **À valider par un analyste avant diffusion.**

## Résumé

Rapport généré sans LLM : faits extraits uniquement.

## Comportements

| Comportement | Preuve | Statut |
| --- | --- | --- |

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

## Suggestions à valider par l'analyste

- Aucune.

## Contre-mesures D3FEND

- Aucune (aucune technique ATT&CK retenue, ou cache D3FEND absent : `malsight download-d3fend`).

## Recommandations


## Incertitudes

- Aucune signalée.
