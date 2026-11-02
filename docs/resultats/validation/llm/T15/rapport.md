# Rapport d'analyse : T15_utilisateur.ps1

| Champ | Valeur |
| --- | --- |
| SHA-256 | `636eb716c425c1123f6e9d235da11c089859cc35f8f9ba06d2b6bb446dc33f08` |
| MD5 | `26ffba7cdd7026ef60f05e5b85d7d2cd` |
| Type | unknown |
| Taille | 1157 octets |

> Rapport généré par MalSight Agent. **À valider par un analyste avant diffusion.**

## Résumé

L'échantillon exécute des commandes système et écrit des données sur le système de fichiers et le registre. Il exécute `whoami.exe /all` via `powershell.exe` et crée un fichier nommé `C:\travail\malsight_t15.txt`. L'activité de registre observée provient principalement de processus système (`svchost.exe`) et concerne des clés de télémétrie (SRUM) et des résultats agrégés (TIP), sans lien direct prouvé avec l'activité de l'échantillon.

## Comportements

| Comportement | Preuve | Statut |
| --- | --- | --- |
| Exécution d'une commande système pour récupérer des informations d'identification de l'utilisateur. | `powershell.exe (4020) exécute "C:\Windows\system32\whoami.exe" /all` | observé |
| Création d'un fichier dans le répertoire de travail. | `C:\travail\malsight_t15.txt créé par powershell.exe (4020)` | observé |
| Lecture/Écriture de clés de registre liées à la télémétrie système (SRUM) et aux résultats agrégés (TIP). | `HKLM\SYSTEM\SOFTWARE\Microsoft\TIP\AggregateResults\data (par svchost.exe (2060)) ; HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SRUM\Telemetry\LastLongTermEventTime (par svchost.exe (2060)) ; HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SRUM\Telemetry\CompositeBatteryData (par svchost.exe (2060)) ; HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SRUM\Telemetry\BatteryIdTable (par svchost.exe (2060)) ; HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SRUM\Telemetry\MaxBatteryIndex (par svchost.exe (2060)) ; HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SRUM\Telemetry\SerializedStateData (par svchost.exe (2060))` | observé |

## Indicateurs de compromission (IOC)

| Type | Valeur | Source |
| --- | --- | --- |
| sha256 | `636eb716c425c1123f6e9d235da11c089859cc35f8f9ba06d2b6bb446dc33f08` | fichier |
| md5 | `26ffba7cdd7026ef60f05e5b85d7d2cd` | fichier |
| file_path | `C:\travail\malsight_t15.txt` | extraction |
| registry_key | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SRUM\Telemetry\BatteryIdTable` | extraction |
| registry_key | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SRUM\Telemetry\CompositeBatteryData` | extraction |
| registry_key | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SRUM\Telemetry\LastLongTermEventTime` | extraction |
| registry_key | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SRUM\Telemetry\MaxBatteryIndex` | extraction |
| registry_key | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SRUM\Telemetry\SerializedStateData` | extraction |
| registry_key | `HKLM\SYSTEM\SOFTWARE\Microsoft\TIP\AggregateResults\data` | extraction |

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

- Surveiller les modifications des clés de registre liées à la télémétrie de la batterie (ex: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SRUM\Telemetry\*).
- Surveiller la création ou la modification de fichiers dans le répertoire C:\travail\.
- Surveiller les hachages SHA256 (636eb716c425c1123f6e9d235da11c089859cc35f8f9ba06d2b6bb446dc33f08) et MD5 (26ffba7cdd7026ef60f05e5b85d7d2cd) pour toute exécution.
- Surveiller les accès aux clés de registre spécifiques : HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SRUM\Telemetry\BatteryIdTable, HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SRUM\Telemetry\CompositeBatteryData, HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SRUM\Telemetry\LastLongTermEventTime, HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SRUM\Telemetry\MaxBatteryIndex, HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SRUM\Telemetry\SerializedStateData, et HKLM\SYSTEM\SOFTWARE\Microsoft\TIP\AggregateResults\data.

## Incertitudes

- L'activité de modification des clés de registre de télémétrie (SRUM/TIP) est attribuée à 'svchost.exe (2060)' et n'est pas directement liée à l'activité de l'échantillon, mais est observée pendant son exécution.
- Aucune activité réseau (connexion établie, résolution DNS) n'est observée, ce qui limite l'analyse des communications externes.

## Affirmations rejetées par le vérificateur

- Technique sans preuve vérifiable, rejetée : T1059.001 (aucune valeur reconnaissable)
