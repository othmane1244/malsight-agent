# Rapport d'analyse : T09_archivage.ps1

| Champ | Valeur |
| --- | --- |
| SHA-256 | `14a0a901790ea75816c93424419e51c61fad1628514a82f916d590baa33d0abd` |
| MD5 | `6024d633dd165c894da09e563f5f7da5` |
| Type | unknown |
| Taille | 1270 octets |

> Rapport généré par MalSight Agent. **À valider par un analyste avant diffusion.**

## Résumé

L'échantillon, exécuté via `powershell.exe`, a été observé en train de créer et de manipuler des fichiers dans le répertoire `C:\travail\collecte`. Il a créé plusieurs fichiers texte (`document1.txt`, `document2.txt`, `document3.txt`) et a finalement compressé ce contenu dans un fichier ZIP nommé `C:\travail\collecte.zip`. L'activité observée est limitée à des opérations de système de fichiers (création/écriture de fichiers) et ne révèle aucune activité réseau, de modification de registre ou de planification de tâches.

## Comportements

| Comportement | Preuve | Statut |
| --- | --- | --- |
| Création et archivage de fichiers dans un répertoire spécifique | `Création des fichiers suivants : `C:\travail\collecte\document1.txt`, `C:\travail\collecte\document2.txt`, `C:\travail\collecte\document3.txt` et du répertoire `C:\travail\collecte`. L'archivage final est visible par la création de `C:\travail\collecte.zip`.` | observé |

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
| [T1074](https://attack.mitre.org/techniques/T1074/) | Data Staged | collection | llm | medium | Aucune preuve directe de la technique T1074 (Data Staging) n'est fournie, mais la création et la compression de multiples fichiers dans un répertoire unique (`C:\travail\collecte`) suggèrent une préparation de données. |

## Contre-mesures D3FEND

- Aucune (aucune technique ATT&CK retenue, ou cache D3FEND absent : `malsight download-d3fend`).

## Recommandations

- Surveiller la création et la compression de multiples fichiers dans un répertoire unique (ex: `C:\travail\collecte`) en utilisant Sysmon pour détecter les opérations de fichiers multiples suivies d'une compression (ex: `zip`, `rar`).
- Mettre en place des règles de détection (YARA/Sigma) ciblant la création de fichiers compressés contenant des données collectées, en particulier dans des répertoires temporaires ou de travail.
- Durcir les politiques de contrôle des répertoires pour limiter l'écriture de données collectées dans des chemins spécifiques comme `C:\travail\collecte` aux utilisateurs ou processus autorisés.
- Surveiller les appels API liés à la manipulation de fichiers (ex: `CreateFile`, `WriteFile`, `ZipArchive`) lorsqu'ils sont exécutés en séquence sur plusieurs fichiers, car cela indique potentiellement une étape de préparation de données (Data Staging).

## Incertitudes

- Le contenu des fichiers créés (`document1.txt`, etc.) n'est pas visible, il est donc incertain si ces fichiers contiennent des données sensibles ou s'ils sont vides.
- Nom ATT&CK corrigé pour T1074 : « Data Staging » -> « Data Staged » (base officielle)
