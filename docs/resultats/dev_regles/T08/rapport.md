# Rapport d'analyse : T08_decouverte_reseau.ps1

| Champ | Valeur |
| --- | --- |
| SHA-256 | `a8957953c905b4f7c069d1f759816f77a93a0334ca0c8436fd91993676a3cf90` |
| MD5 | `2006d0747f6ab9022f05118743b17516` |
| Type | unknown |
| Taille | 1030 octets |

> Rapport généré par MalSight Agent. **À valider par un analyste avant diffusion.**

## Résumé

Rapport généré sans LLM : faits extraits uniquement.

## Comportements

| Comportement | Preuve | Statut |
| --- | --- | --- |

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

## Suggestions à valider par l'analyste

- Aucune.

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


## Incertitudes

- Aucune signalée.
