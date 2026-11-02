# Rapport d'analyse : T15_utilisateur.ps1

| Champ | Valeur |
| --- | --- |
| SHA-256 | `636eb716c425c1123f6e9d235da11c089859cc35f8f9ba06d2b6bb446dc33f08` |
| MD5 | `26ffba7cdd7026ef60f05e5b85d7d2cd` |
| Type | unknown |
| Taille | 1157 octets |

> Rapport généré par MalSight Agent. **À valider par un analyste avant diffusion.**

## Résumé

L'échantillon exécute des commandes système et écrit des données sur le système de fichiers et le registre. Il exécute `whoami.exe /all` via `powershell.exe` et crée un fichier nommé `C:\travail\malsight_t15.txt`. De plus, il y a des écritures de registre observées sur des clés liées à la télémétrie de Windows (SRUM) et des résultats agrégés (TIP), attribuées à `svchost.exe`.

## Comportements

| Comportement | Preuve | Statut |
| --- | --- | --- |
| Exécution d'une commande système pour récupérer des informations d'identification de l'utilisateur. | `process: "C:\Windows\system32\whoami.exe" /all` | observé |
| Création d'un fichier dans le répertoire 'C:\travail'. | `file: C:\travail\malsight_t15.txt` | observé |
| Écriture de données dans des clés de registre liées à la télémétrie de Windows (SRUM) et des résultats agrégés. | `registry: HKLM\SYSTEM\SOFTWARE\Microsoft\TIP\AggregateResults\data` | observé |

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

Techniques proposées par le modèle de langage, **non retenues dans la liste officielle** (D10 :
les outils classent, le LLM explique). Chacune cite une preuve retrouvée dans le dossier de cas,
mais sa pertinence reste à valider.

| ID | Technique | Tactique | Confiance | Preuve |
| --- | --- | --- | --- | --- |
| [T1087.002](https://attack.mitre.org/techniques/T1087/002/) | Domain Account | discovery | medium | process: "C:\Windows\system32\whoami.exe" /all |

## Contre-mesures D3FEND

- Aucune (aucune technique ATT&CK retenue, ou cache D3FEND absent : `malsight download-d3fend`).

## Recommandations

- Surveiller les modifications des clés de registre liées à la télémétrie de la batterie (ex: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SRUM\Telemetry\*), car ces clés sont listées dans les IOCs et pourraient être ciblées pour masquer des activités ou des données.
- Surveiller la création ou la modification de fichiers dans le répertoire C:\travail\, en particulier les fichiers avec des extensions spécifiques, pour détecter des écritures inhabituelles.
- Surveiller les hachages SHA256 (636eb716c425c1123f6e9d235da11c089859cc35f8f9ba06d2b6bb446dc33f08) et MD5 (26ffba7cdd7026ef60f05e5b85d7d2cd) pour toute activité de fichier suspecte.
- Mettre en place des règles de surveillance des accès aux clés de registre système critiques (HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SRUM\Telemetry\* et HKLM\SYSTEM\SOFTWARE\Microsoft\TIP\AggregateResults\data) pour détecter toute modification non sollicitée.

## Incertitudes

- Les écritures de registre sur les clés de télémétrie (SRUM) et TIP sont attribuées à 'svchost.exe' et ne sont pas directement liées à l'activité de l'échantillon, mais sont observées pendant son exécution.
