# Rapport d'analyse : T16_profil_powershell.ps1

| Champ | Valeur |
| --- | --- |
| SHA-256 | `afc924e9da8688254d77e10b14b1f8529f2a6848acd7a52c91121e4a1fa63fad` |
| MD5 | `5c4fb521e07eb82472f5e2a5245c90fd` |
| Type | unknown |
| Taille | 1393 octets |

> Rapport généré par MalSight Agent. **À valider par un analyste avant diffusion.**

## Résumé

L'échantillon est un script PowerShell (`T16_profil_powershell.ps1`) qui a interagi avec le système de fichiers pour créer ou modifier des fichiers de profil PowerShell dans le répertoire de l'utilisateur. Il n'y a aucune preuve d'activité réseau ou d'utilisation de clés de registre critiques pour des opérations malveillantes. Les modifications de registre observées proviennent de processus système (`svchost.exe`) et concernent des zones de télémétrie système (SRUM), ce qui suggère une activité de fond de Windows plutôt qu'une action directe de l'échantillon.

## Comportements

| Comportement | Preuve | Statut |
| --- | --- | --- |
| Écriture de fichiers de profil PowerShell | `C:\Users\WDAGUtilityAccount\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1` | observé |

## Indicateurs de compromission (IOC)

| Type | Valeur | Source |
| --- | --- | --- |
| sha256 | `afc924e9da8688254d77e10b14b1f8529f2a6848acd7a52c91121e4a1fa63fad` | fichier |
| md5 | `5c4fb521e07eb82472f5e2a5245c90fd` | fichier |
| file_path | `C:\Users\WDAGUtilityAccount\Documents\WindowsPowerShell` | extraction |
| file_path | `C:\Users\WDAGUtilityAccount\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1` | extraction |
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

- Surveiller les écritures de clés de registre spécifiques liées à la télémétrie de la batterie (ex: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SRUM\Telemetry\*). (Aucun identifiant D3FEND spécifique fourni)
- Surveiller la création ou la modification de fichiers dans le répertoire utilisateur Documents, en particulier les fichiers de profil PowerShell (ex: C:\Users\WDAGUtilityAccount\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1).
- Surveiller l'exécution de scripts PowerShell depuis des chemins non standards ou des répertoires utilisateurs (ex: C:\Users\WDAGUtilityAccount\Documents\WindowsPowerShell).
- Mettre en place des politiques de durcissement pour limiter les droits d'écriture dans les clés de registre système critiques de télémétrie (SRUM).
- Analyser les hachages (sha256: afc924e9da8688254d77e10b14b1f8529f2a6848acd7a52c91121e4a1fa63fad, md5: 5c4fb521e07eb82472f5e2a5245c90fd) pour toute activité suspecte, même si aucune technique n'est attribuée.

## Incertitudes

- Les modifications de registre observées (ex: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SRUM\Telemetry\*) sont attribuées à `svchost.exe` et concernent des zones de télémétrie système. Il est incertain si l'échantillon a initié ces écritures ou si elles sont une activité de fond de Windows coïncidant avec l'exécution.

## Affirmations rejetées par le vérificateur

- Technique sans preuve vérifiable, rejetée : T1021.001 (aucune valeur reconnaissable)
