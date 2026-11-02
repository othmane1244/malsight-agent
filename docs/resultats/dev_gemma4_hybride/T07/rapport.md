# Rapport d'analyse : T07_decouverte_systeme.ps1

| Champ | Valeur |
| --- | --- |
| SHA-256 | `91379f80153cf471af84f022d11c9a6b683a02ed584a80d0bf3734b6bab1e5f7` |
| MD5 | `83410fbb1e5852e13f895ac481f70758` |
| Type | unknown |
| Taille | 990 octets |

> Rapport généré par MalSight Agent. **À valider par un analyste avant diffusion.**

## Résumé

L'échantillon, un script PowerShell nommé "T07_decouverte_systeme.ps1", exécute des commandes système pour collecter des informations sur l'environnement cible. Il exécute des outils système standards comme `HOSTNAME.EXE` et `systeminfo.exe` via `powershell.exe`, et crée un fichier texte local nommé `C:\travail\malsight_t07.txt` pour y stocker potentiellement les résultats de cette collecte d'informations.

## Comportements

| Comportement | Preuve | Statut |
| --- | --- | --- |
| Collecte d'informations système de base | `L'exécution de "C:\Windows\system32\HOSTNAME.EXE" et "C:\Windows\system32\systeminfo.exe" via powershell.exe (3320) est observée.` | observé |
| Création d'un fichier de sortie local | `Le fichier "C:\travail\malsight_t07.txt" est créé par powershell.exe (3320).` | observé |

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
| [T1082](https://attack.mitre.org/techniques/T1082/) | System Information Discovery | discovery | rule | high | règle R-T1082-processus : "C:\Windows\system32\HOSTNAME.EXE" (powershell.exe (3320)) |

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

- Surveiller l'exécution de processus système comme `powershell.exe` lorsqu'il est appelé avec des arguments spécifiques ou lorsqu'il est lancé depuis des chemins inhabituels, en particulier pour la découverte d'informations système (T1082). (D3-PSA)
- Mettre en place des politiques de contrôle des processus pour limiter les exécutions de binaires système (comme `HOSTNAME.EXE`) à des contextes et des parents attendus, afin de détecter les anomalies de lancement. (D3-EAL)
- Surveiller les appels système liés à la récupération d'informations système (ex: appels aux fonctions de récupération de nom d'hôte ou d'informations système) pour détecter des comportements de reconnaissance. (D3-SCA)
- Analyser les fichiers suspects basés sur les hachages fournis (sha256: 91379f80153cf471af84f022d11c9a6b683a02ed584a80d0bf3734b6bab1e5f7, md5: 83410fbb1e5852e13f895ac481f70758) et le chemin de fichier (C:\travail\malsight_t07.txt) pour bloquer leur exécution ou leur modification. (D3-EDL)
- Implémenter des mécanismes de détection des chemins de fichiers et des noms de processus spécifiques mentionnés dans les IOCs pour une réponse rapide. (D3-EDL)

## Incertitudes

- Aucune signalée.
