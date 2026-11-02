# Rapport d'analyse : T07_decouverte_systeme.ps1

| Champ | Valeur |
| --- | --- |
| SHA-256 | `91379f80153cf471af84f022d11c9a6b683a02ed584a80d0bf3734b6bab1e5f7` |
| MD5 | `83410fbb1e5852e13f895ac481f70758` |
| Type | unknown |
| Taille | 990 octets |

> Rapport généré par MalSight Agent. **À valider par un analyste avant diffusion.**

## Résumé

L'échantillon, nommé "T07_decouverte_systeme.ps1", est un script PowerShell qui exécute des outils système standard pour collecter des informations sur l'environnement hôte. Il écrit également un fichier texte contenant potentiellement ces informations dans le répertoire "C:\travail\".

## Comportements

| Comportement | Preuve | Statut |
| --- | --- | --- |
| Exécution de commandes système pour la découverte d'informations sur le système. | `processes_created: ["C:\Windows\system32\HOSTNAME.EXE", "C:\Windows\system32\systeminfo.exe"]` | observé |
| Écriture d'un fichier contenant des données dans le répertoire "C:\travail\". | `files_written: ["C:\travail\malsight_t07.txt"]` | observé |

## Indicateurs de compromission (IOC)

| Type | Valeur | Source |
| --- | --- | --- |
| sha256 | `91379f80153cf471af84f022d11c9a6b683a02ed584a80d0bf3734b6bab1e5f7` | fichier |
| md5 | `83410fbb1e5852e13f895ac481f70758` | fichier |
| file_path | `C:\travail\malsight_t07.txt` | extraction |

## API sensibles

| API | Catégorie | Source |
| --- | --- | --- |

## Techniques MITRE ATT&CK

| ID | Technique | Tactique | Source | Confiance | Preuve |
| --- | --- | --- | --- | --- | --- |
| [T1082](https://attack.mitre.org/techniques/T1082/) | System Information Discovery | discovery | llm | medium | processes_created: ["C:\Windows\system32\HOSTNAME.EXE", "C:\Windows\system32\systeminfo.exe"] |

## Contre-mesures D3FEND

Contre-mesures défensives [MITRE D3FEND](https://d3fend.mitre.org) associées aux techniques
ATT&CK retenues (source : d3fend, cache local ; IDs vérifiés).

| Technique ATT&CK | Contre-mesure D3FEND | Tactique | Artefact |
| --- | --- | --- | --- |
| [T1082](https://attack.mitre.org/techniques/T1082/) | [D3-PSA Process Spawn Analysis](https://d3fend.mitre.org/technique/d3f:ProcessSpawnAnalysis/) | Detect | Create Process |
| [T1082](https://attack.mitre.org/techniques/T1082/) | [D3-SCA System Call Analysis](https://d3fend.mitre.org/technique/d3f:SystemCallAnalysis/) | Detect | System Call |
| [T1082](https://attack.mitre.org/techniques/T1082/) | [D3-EAL Executable Allowlisting](https://d3fend.mitre.org/technique/d3f:ExecutableAllowlisting/) | Isolate | Create Process |
| [T1082](https://attack.mitre.org/techniques/T1082/) | [D3-EDL Executable Denylisting](https://d3fend.mitre.org/technique/d3f:ExecutableDenylisting/) | Isolate | Create Process |
| [T1082](https://attack.mitre.org/techniques/T1082/) | [D3-HBPI Hardware-based Process Isolation](https://d3fend.mitre.org/technique/d3f:Hardware-basedProcessIsolation/) | Isolate | Create Process |
| [T1082](https://attack.mitre.org/techniques/T1082/) | [D3-SCF System Call Filtering](https://d3fend.mitre.org/technique/d3f:SystemCallFiltering/) | Isolate | System Call |
| [T1082](https://attack.mitre.org/techniques/T1082/) | [D3-DE Decoy Environment](https://d3fend.mitre.org/technique/d3f:DecoyEnvironment/) | Deceive | Decoy Artifact |

## Recommandations

- Surveiller la création de processus exécutant des outils système comme 'systeminfo.exe' ou des noms génériques comme 'HOSTNAME.EXE' (T1082) en analysant les arguments de ligne de commande (D3-PSA).
- Mettre en place des règles de détection (Sysmon/Sigma) pour surveiller l'exécution de fichiers spécifiques connus (IOC : sha256 91379f80153cf471af84f022d11c9a6b683a02ed584a80d0bf3734b6bab1e5f7, md5 83410fbb1e5852e13f895ac481f70758) et de chemins de fichiers spécifiques (IOC : C:\travail\malsight_t07.txt).
- Appliquer des politiques de contrôle des applications (Application Whitelisting) pour restreindre l'exécution des binaires système aux chemins attendus, afin de détecter les déviations ou les exécutions inhabituelles (D3-EAL).
- Surveiller les tentatives d'accès ou de modification des fichiers de type 'txt' dans des répertoires non standard comme 'C:\travail\' (IOC : C:\travail\malsight_t07.txt) pour détecter des activités de persistance ou de fuite d'informations.
- Analyser les appels système (System Call Analysis) pour détecter des séquences d'appels inhabituelles associées à la collecte d'informations système (D3-SCA).

## Incertitudes

- Aucune signalée.
