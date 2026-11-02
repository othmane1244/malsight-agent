# Rapport d'analyse : T09_archivage.ps1

| Champ | Valeur |
| --- | --- |
| SHA-256 | `14a0a901790ea75816c93424419e51c61fad1628514a82f916d590baa33d0abd` |
| MD5 | `6024d633dd165c894da09e563f5f7da5` |
| Type | unknown |
| Taille | 1270 octets |

> Rapport généré par MalSight Agent. **À valider par un analyste avant diffusion.**

## Résumé

L'échantillon est un script PowerShell (T09_archivage.ps1) qui exécute des opérations de système de fichiers. Il écrit plusieurs fichiers dans le répertoire `C:\travail\collecte` et crée ensuite une archive ZIP de ces fichiers dans le même répertoire. Aucune activité réseau, de registre, ou de processus n'a été observée. L'activité se limite à la collecte et l'archivage de données locales.

## Comportements

| Comportement | Preuve | Statut |
| --- | --- | --- |
| Création et écriture de fichiers dans un répertoire de collecte. | `C:\travail\collecte` | observé |
| Écriture de fichiers spécifiques dans le répertoire de collecte. | `C:\travail\collecte\document1.txt, C:\travail\collecte\document2.txt, C:\travail\collecte\document3.txt` | observé |
| Création d'un fichier compressé (archive ZIP) contenant les fichiers collectés. | `C:\travail\collecte.zip` | observé |

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
| [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System | collection | llm | medium | L'échantillon écrit et archive des fichiers locaux dans C:\travail\collecte, ce qui est une forme de collecte de données. |

## Contre-mesures D3FEND

- Aucune (aucune technique ATT&CK retenue, ou cache D3FEND absent : `malsight download-d3fend`).

## Recommandations

- Surveiller la création et la modification de fichiers dans le répertoire `C:\travail\collecte` (IOC : `file_path`, `C:\travail\collecte`). Une surveillance des opérations de type 'write' ou 'archive' dans ce chemin est recommandée pour détecter la collecte de données locales (T1005).
- Mettre en place des règles de détection (ex: Sysmon) pour alerter sur la création de fichiers compressés (ex: `.zip`) dans des répertoires de travail non standard, comme `C:\travail\collecte.zip` (IOC : `file_path`).
- Durcir les politiques de contrôle des dossiers pour restreindre l'écriture de données dans des répertoires utilisateurs spécifiques (`C:\travail\collecte`) aux processus autorisés, limitant ainsi la capacité de collecte de données (T1005).
- Analyser les processus qui accèdent ou écrivent des fichiers multiples (ex: `document1.txt`, `document2.txt`, `document3.txt`) dans un même répertoire de manière séquentielle, car cela peut indiquer une activité de rassemblement de données (T1005).

## Incertitudes

- Aucune signalée.
