# Rapport d'analyse : T07_decouverte_systeme.ps1

| Champ | Valeur |
| --- | --- |
| SHA-256 | `91379f80153cf471af84f022d11c9a6b683a02ed584a80d0bf3734b6bab1e5f7` |
| MD5 | `83410fbb1e5852e13f895ac481f70758` |
| Type | unknown |
| Taille | 990 octets |

> Rapport généré par MalSight Agent. **À valider par un analyste avant diffusion.**

## Résumé

L'échantillon, un script PowerShell nommé "T07_decouverte_systeme.ps1", exécute des commandes système pour collecter des informations sur l'environnement cible. Les activités observées incluent l'exécution de `HOSTNAME.EXE` et `systeminfo.exe` via `powershell.exe`, ainsi que la création d'un fichier texte dans le répertoire `C:\travail\malsight_t07.txt`. Ces actions sont typiques des phases de reconnaissance et de collecte d'informations (Discovery).

## Comportements

| Comportement | Preuve | Statut |
| --- | --- | --- |
| Collecte d'informations système de base | `Exécution de "C:\Windows\system32\HOSTNAME.EXE" par powershell.exe (3320) ; Exécution de "C:\Windows\system32\systeminfo.exe" par powershell.exe (3320)` | observé |
| Écriture de données dans un fichier local | `Création du fichier "C:\travail\malsight_t07.txt" par powershell.exe (3320)` | observé |

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

- Surveiller l'exécution de processus spécifiques comme `powershell.exe` lorsqu'ils sont appelés avec des arguments contenant des noms de fichiers système comme `C:\Windows\system32\HOSTNAME.EXE` (Détection de processus anormaux) (D3-PSA).
- Mettre en place des politiques de contrôle des processus pour limiter l'exécution de scripts ou d'outils système (comme PowerShell) à des chemins et des arguments prédéfinis (D3-EAL).
- Surveiller les appels système pour détecter des tentatives d'exécution de commandes d'information système inhabituelles ou non sollicitées (D3-SCA).
- Analyser les fichiers avec les hachages SHA256 `91379f80153cf471af84f022d11c9a6b683a02ed584a80d0bf3734b6bab1e5f7` et MD5 `83410fbb1e5852e13f895ac481f70758` et bloquer leur exécution ou leur mouvement (Remédiation/Blocage des IOCs).
- Surveiller la création ou la modification du fichier `C:\travail\malsight_t07.txt` pour détecter toute activité suspecte liée à ce chemin (Surveillance de fichiers spécifiques).

## Incertitudes

- Aucune signalée.
