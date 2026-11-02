# Rapport d'analyse : T08_decouverte_reseau.ps1

| Champ | Valeur |
| --- | --- |
| SHA-256 | `a8957953c905b4f7c069d1f759816f77a93a0334ca0c8436fd91993676a3cf90` |
| MD5 | `2006d0747f6ab9022f05118743b17516` |
| Type | unknown |
| Taille | 1030 octets |

> Rapport généré par MalSight Agent. **À valider par un analyste avant diffusion.**

## Résumé

L'échantillon exécute des commandes système standard pour la découverte de réseau et modifie des clés de registre spécifiques. Il exécute successivement `ipconfig.exe /all`, `ROUTE.EXE print`, et `ARP.EXE -a` via `powershell.exe`. De plus, il écrit un fichier local et manipule plusieurs clés de registre sous `HKLM\SOFTWARE\Microsoft\RFC1156Agent`. Ces actions indiquent une phase de reconnaissance et de persistance potentielle.

## Comportements

| Comportement | Preuve | Statut |
| --- | --- | --- |
| Exécution d'outils système pour la découverte d'informations réseau. | `L'échantillon exécute "C:\Windows\system32\ipconfig.exe" /all, "C:\Windows\system32\ROUTE.EXE" print, et "C:\Windows\system32\ARP.EXE" -a, tous lancés depuis "powershell.exe (7472)".` | observé |
| Écriture de données sur le système de fichiers. | `Création du fichier "C:\travail\malsight_t08.txt" par "powershell.exe (7472)".` | observé |
| Modification de clés de registre liées à un agent système. | `L'échantillon interagit avec les clés de registre suivantes : HKLM\SOFTWARE\Microsoft\RFC1156Agent, HKLM\SOFTWARE\Microsoft\RFC1156Agent\CurrentVersion, HKLM\SOFTWARE\Microsoft\RFC1156Agent\CurrentVersion\Parameters, et HKLM\SOFTWARE\Microsoft\RFC1156Agent\CurrentVersion\Parameters\TrapPollTimeMilliSecs, en utilisant "ARP.EXE (8168)".` | observé |

## Indicateurs de compromission (IOC)

| Type | Valeur | Source |
| --- | --- | --- |
| sha256 | `a8957953c905b4f7c069d1f759816f77a93a0334ca0c8436fd91993676a3cf90` | fichier |
| md5 | `2006d0747f6ab9022f05118743b17516` | fichier |
| file_path | `C:\travail\malsight_t08.txt` | extraction |
| registry_key | `HKLM\SOFTWARE\Microsoft\RFC1156Agent` | extraction |
| registry_key | `HKLM\SOFTWARE\Microsoft\RFC1156Agent\CurrentVersion` | extraction |
| registry_key | `HKLM\SOFTWARE\Microsoft\RFC1156Agent\CurrentVersion\Parameters` | extraction |
| registry_key | `HKLM\SOFTWARE\Microsoft\RFC1156Agent\CurrentVersion\Parameters\TrapPollTimeMilliSecs` | extraction |

## API sensibles

| API | Catégorie | Source |
| --- | --- | --- |

## Techniques MITRE ATT&CK

| ID | Technique | Tactique | Source | Confiance | Preuve |
| --- | --- | --- | --- | --- | --- |
| [T1016](https://attack.mitre.org/techniques/T1016/) | System Network Configuration Discovery | discovery | rule | high | règle R-T1016-processus : "C:\Windows\system32\ipconfig.exe" /all (powershell.exe (7472)) |

## Contre-mesures D3FEND

Contre-mesures défensives [MITRE D3FEND](https://d3fend.mitre.org) associées aux techniques
ATT&CK retenues (source : d3fend, cache local ; IDs vérifiés).

| Technique ATT&CK | Contre-mesure D3FEND | Tactique | Artefact |
| --- | --- | --- | --- |
| [T1016](https://attack.mitre.org/techniques/T1016/) | [D3-FE File Encryption](https://d3fend.mitre.org/technique/d3f:FileEncryption/) | Harden | File |
| [T1016](https://attack.mitre.org/techniques/T1016/) | [D3-DA Dynamic Analysis](https://d3fend.mitre.org/technique/d3f:DynamicAnalysis/) | Detect | Executable File |
| [T1016](https://attack.mitre.org/techniques/T1016/) | [D3-EFA Emulated File Analysis](https://d3fend.mitre.org/technique/d3f:EmulatedFileAnalysis/) | Detect | Executable File |
| [T1016](https://attack.mitre.org/techniques/T1016/) | [D3-FA File Analysis](https://d3fend.mitre.org/technique/d3f:FileAnalysis/) | Detect | File |
| [T1016](https://attack.mitre.org/techniques/T1016/) | [D3-FIM File Integrity Monitoring](https://d3fend.mitre.org/technique/d3f:FileIntegrityMonitoring/) | Detect | File |
| [T1016](https://attack.mitre.org/techniques/T1016/) | [D3-PSA Process Spawn Analysis](https://d3fend.mitre.org/technique/d3f:ProcessSpawnAnalysis/) | Detect | Create Process |
| [T1016](https://attack.mitre.org/techniques/T1016/) | [D3-SCA System Call Analysis](https://d3fend.mitre.org/technique/d3f:SystemCallAnalysis/) | Detect | System Call |
| [T1016](https://attack.mitre.org/techniques/T1016/) | [D3-CF Content Filtering](https://d3fend.mitre.org/technique/d3f:ContentFiltering/) | Isolate | File |
| [T1016](https://attack.mitre.org/techniques/T1016/) | [D3-CM Content Modification](https://d3fend.mitre.org/technique/d3f:ContentModification/) | Isolate | File |
| [T1016](https://attack.mitre.org/techniques/T1016/) | [D3-CQ Content Quarantine](https://d3fend.mitre.org/technique/d3f:ContentQuarantine/) | Isolate | File |
| [T1016](https://attack.mitre.org/techniques/T1016/) | [D3-EAL Executable Allowlisting](https://d3fend.mitre.org/technique/d3f:ExecutableAllowlisting/) | Isolate | Create Process |
| [T1016](https://attack.mitre.org/techniques/T1016/) | [D3-EDL Executable Denylisting](https://d3fend.mitre.org/technique/d3f:ExecutableDenylisting/) | Isolate | Executable File |

## Recommandations

- Surveiller l'exécution de `ipconfig.exe` lorsqu'il est appelé par des processus inattendus comme `powershell.exe` (Détection de processus anormaux).
- Mettre en place une surveillance des modifications des clés de registre spécifiques associées à l'agent RFC1156, notamment `HKLM\SOFTWARE\Microsoft\RFC1156Agent` et ses sous-clés, pour détecter toute tentative de persistance ou de modification de configuration (D3-FIM).
- Surveiller les appels aux outils système comme `ipconfig.exe` pour détecter des séquences d'actions inhabituelles de découverte de réseau (D3-PSA).
- Considérer l'application de politiques de contrôle des applications pour limiter l'exécution des outils système de diagnostic réseau (`ipconfig.exe`) aux utilisateurs ou processus autorisés (D3-EAL).
- Analyser les fichiers suspects (SHA256: a8957953c905b4f7c069d1f759816f77a93a0334ca0c8436fd91993676a3cf90, MD5: 2006d0747f6ab9022f05118743b17516) en utilisant des solutions de sandbox ou d'analyse dynamique pour identifier leur comportement réel (D3-DA, D3-FA).

## Incertitudes

- Aucune signalée.
