# Rapport d'analyse : T09_archivage.ps1

| Champ | Valeur |
| --- | --- |
| SHA-256 | `14a0a901790ea75816c93424419e51c61fad1628514a82f916d590baa33d0abd` |
| MD5 | `6024d633dd165c894da09e563f5f7da5` |
| Type | unknown |
| Taille | 1270 octets |

> Rapport généré par MalSight Agent. **À valider par un analyste avant diffusion.**

## Résumé

L'échantillon exécute des opérations de collecte et d'archivage de données. Il crée un répertoire nommé `C:\travail\collecte` et y place plusieurs fichiers de type document (`document1.txt`, `document2.txt`, `document3.txt`). Finalement, il archive ces éléments dans un fichier compressé nommé `C:\travail\collecte.zip` au sein de ce même répertoire. L'activité observée est limitée aux opérations de système de fichiers.

## Comportements

| Comportement | Preuve | Statut |
| --- | --- | --- |
| Création et remplissage d'un répertoire de collecte de données. | `Création du répertoire `C:\travail\collecte` (via `procmon`, `sysmon` avec `powershell.exe (7900)`).` | observé |
| Collecte de plusieurs fichiers de données dans le répertoire créé. | `Présence des fichiers `C:\travail\collecte\document1.txt`, `C:\travail\collecte\document2.txt`, et `C:\travail\collecte\document3.txt` (via `procmon`, `sysmon` avec `powershell.exe (7900)`).` | observé |
| Archivage des données collectées dans un fichier compressé. | `Création du fichier `C:\travail\collecte.zip` dans le répertoire `C:\travail\collecte` (via `procmon`, `sysmon` avec `powershell.exe (7900)`).` | observé |

## Indicateurs de compromission (IOC)

| Type | Valeur | Source |
| --- | --- | --- |
| sha256 | `14a0a901790ea75816c93424419e51c61fad1628514a82f916d590baa33d0abd` | fichier |
| md5 | `6024d633dd165c894da09e563f5f7da5` | fichier |
| file_path | `C:\travail\collecte` | extraction |
| file_path | `C:\travail\collecte.zip` | extraction |
| file_path | `C:\travail\collecte\` | extraction |
| file_path | `C:\travail\collecte\document1.txt` | extraction |
| file_path | `C:\travail\collecte\document2.txt` | extraction |
| file_path | `C:\travail\collecte\document3.txt` | extraction |

## API sensibles

| API | Catégorie | Source |
| --- | --- | --- |

## Techniques MITRE ATT&CK

| ID | Technique | Tactique | Source | Confiance | Preuve |
| --- | --- | --- | --- | --- | --- |
| [T1560](https://attack.mitre.org/techniques/T1560/) | Archive Collected Data | collection | rule | high | règle R-T1560-archive : C:\travail\collecte.zip (powershell.exe (7900)) |

## Suggestions à valider par l'analyste

- Aucune.

## Contre-mesures D3FEND

Contre-mesures défensives [MITRE D3FEND](https://d3fend.mitre.org) associées aux techniques
ATT&CK retenues (source : d3fend, cache local ; IDs vérifiés).

| Technique ATT&CK | Contre-mesure D3FEND | Tactique | Artefact |
| --- | --- | --- | --- |
| [T1560](https://attack.mitre.org/techniques/T1560/) | [D3-FE File Encryption](https://d3fend.mitre.org/technique/d3f:FileEncryption/) | Harden | File |
| [T1560](https://attack.mitre.org/techniques/T1560/) | [D3-FA File Analysis](https://d3fend.mitre.org/technique/d3f:FileAnalysis/) | Detect | File |
| [T1560](https://attack.mitre.org/techniques/T1560/) | [D3-FIM File Integrity Monitoring](https://d3fend.mitre.org/technique/d3f:FileIntegrityMonitoring/) | Detect | File |
| [T1560](https://attack.mitre.org/techniques/T1560/) | [D3-CF Content Filtering](https://d3fend.mitre.org/technique/d3f:ContentFiltering/) | Isolate | File |
| [T1560](https://attack.mitre.org/techniques/T1560/) | [D3-CM Content Modification](https://d3fend.mitre.org/technique/d3f:ContentModification/) | Isolate | File |
| [T1560](https://attack.mitre.org/techniques/T1560/) | [D3-CQ Content Quarantine](https://d3fend.mitre.org/technique/d3f:ContentQuarantine/) | Isolate | File |
| [T1560](https://attack.mitre.org/techniques/T1560/) | [D3-LFP Local File Permissions](https://d3fend.mitre.org/technique/d3f:LocalFilePermissions/) | Isolate | File |
| [T1560](https://attack.mitre.org/techniques/T1560/) | [D3-RFAM Remote File Access Mediation](https://d3fend.mitre.org/technique/d3f:RemoteFileAccessMediation/) | Isolate | File |
| [T1560](https://attack.mitre.org/techniques/T1560/) | [D3-DF Decoy File](https://d3fend.mitre.org/technique/d3f:DecoyFile/) | Deceive | File |
| [T1560](https://attack.mitre.org/techniques/T1560/) | [D3-FEV File Eviction](https://d3fend.mitre.org/technique/d3f:FileEviction/) | Evict | File |
| [T1560](https://attack.mitre.org/techniques/T1560/) | [D3-RF Restore File](https://d3fend.mitre.org/technique/d3f:RestoreFile/) | Restore | File |

## Recommandations

- Surveiller la création et la compression de fichiers dans des répertoires spécifiques comme `C:\travail\collecte` (Détection Sysmon : Event ID 11/12 pour la création de fichiers et l'activité ZIP/compression).
- Mettre en place une surveillance des processus exécutant des commandes de compression (ex: `powershell.exe` avec des arguments liés à `zip` ou `archive`) pour détecter l'empaquetage de données (D3-FA).
- Appliquer des politiques de contrôle des répertoires pour limiter l'écriture et la création de fichiers compressés dans des chemins non autorisés (D3-LFP).
- Surveiller les tentatives de collecte de données en regroupant les activités de lecture de multiples fichiers (`document1.txt`, `document2.txt`, `document3.txt`) dans un même répertoire avant leur archivage (D3-FIM).
- Envisager des mécanismes de détection basés sur le comportement de regroupement de données (Data Staging) plutôt que sur des IOC spécifiques, car l'archivage est une activité de préparation à l'exfiltration (D3-FA).

## Incertitudes

- Aucune signalée.
