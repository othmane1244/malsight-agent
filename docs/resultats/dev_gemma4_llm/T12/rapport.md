# Rapport d'analyse : T12_scenario_combine.ps1

| Champ | Valeur |
| --- | --- |
| SHA-256 | `561a7e11d3359407846f22cabacbe578fe4b49555660b122e90cd9c2d1d39586` |
| MD5 | `acbdc6e0398ec6b1e8d774cd8e32b8bf` |
| Type | unknown |
| Taille | 1904 octets |

> Rapport généré par MalSight Agent. **À valider par un analyste avant diffusion.**

## Résumé

L'échantillon, exécuté via PowerShell, a effectué plusieurs actions de reconnaissance et de persistance. Il a exécuté `systeminfo.exe` et a créé un fichier local (`C:\travail\malsight_t12_info.txt`). De plus, il a tenté d'établir une communication avec le domaine `c2.malsight.lab` et a établi une persistance en écrivant une clé de registre dans `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\MalsightTest12`.

## Comportements

| Comportement | Preuve | Statut |
| --- | --- | --- |
| Exécution d'outils système pour la collecte d'informations | `Exécution de "C:\Windows\system32\systeminfo.exe" par powershell.exe (7444)` | observé |
| Création de fichiers locaux | `Création du fichier "C:\travail\malsight_t12_info.txt" par powershell.exe (7444)` | observé |
| Établissement d'une persistance au démarrage | `Écriture de la clé de registre "HKCU\Software\Microsoft\Windows\CurrentVersion\Run\MalsightTest12" par powershell.exe (7444)` | observé |
| Tentative de communication réseau avec un domaine externe | `Observation du domaine "c2.malsight.lab" par powershell.exe (7444)` | observé |

## Indicateurs de compromission (IOC)

| Type | Valeur | Source |
| --- | --- | --- |
| sha256 | `561a7e11d3359407846f22cabacbe578fe4b49555660b122e90cd9c2d1d39586` | fichier |
| md5 | `acbdc6e0398ec6b1e8d774cd8e32b8bf` | fichier |
| domain | `c2.malsight.lab` | extraction |
| file_path | `C:\travail\malsight_t12_info.txt` | extraction |
| registry_key | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\MalsightTest12` | extraction |

## API sensibles

| API | Catégorie | Source |
| --- | --- | --- |

## Techniques MITRE ATT&CK

| ID | Technique | Tactique | Source | Confiance | Preuve |
| --- | --- | --- | --- | --- | --- |
| [T1082](https://attack.mitre.org/techniques/T1082/) | System Information Discovery | discovery | llm | medium | Observation du domaine "c2.malsight.lab" |
| [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | Registry Run Keys / Startup Folder | persistence, privilege-escalation | llm | medium | Écriture de la clé de registre "HKCU\Software\Microsoft\Windows\CurrentVersion\Run\MalsightTest12" |

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
| [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | [D3-FE File Encryption](https://d3fend.mitre.org/technique/d3f:FileEncryption/) | Harden | File |
| [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | [D3-DA Dynamic Analysis](https://d3fend.mitre.org/technique/d3f:DynamicAnalysis/) | Detect | Executable File |
| [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | [D3-EFA Emulated File Analysis](https://d3fend.mitre.org/technique/d3f:EmulatedFileAnalysis/) | Detect | Executable File |
| [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | [D3-FA File Analysis](https://d3fend.mitre.org/technique/d3f:FileAnalysis/) | Detect | File |
| [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | [D3-FIM File Integrity Monitoring](https://d3fend.mitre.org/technique/d3f:FileIntegrityMonitoring/) | Detect | File |
| [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | [D3-SICA System Init Config Analysis](https://d3fend.mitre.org/technique/d3f:SystemInitConfigAnalysis/) | Detect | System Init Configuration |
| [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | [D3-CF Content Filtering](https://d3fend.mitre.org/technique/d3f:ContentFiltering/) | Isolate | File |
| [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | [D3-CM Content Modification](https://d3fend.mitre.org/technique/d3f:ContentModification/) | Isolate | File |
| [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | [D3-CQ Content Quarantine](https://d3fend.mitre.org/technique/d3f:ContentQuarantine/) | Isolate | File |
| [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | [D3-EAL Executable Allowlisting](https://d3fend.mitre.org/technique/d3f:ExecutableAllowlisting/) | Isolate | Executable File |
| [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | [D3-EDL Executable Denylisting](https://d3fend.mitre.org/technique/d3f:ExecutableDenylisting/) | Isolate | Executable File |
| [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | [D3-LFP Local File Permissions](https://d3fend.mitre.org/technique/d3f:LocalFilePermissions/) | Isolate | File |

## Recommandations

- Surveiller les tentatives d'accès ou de modification des clés de registre de démarrage utilisateur, telles que "HKCU\Software\Microsoft\Windows\CurrentVersion\Run", pour détecter des écritures suspectes (D3-SCA).
- Mettre en place une surveillance des appels système pour détecter toute tentative d'exécution de processus ou de modification de configuration système non autorisée (D3-PSA).
- Implémenter une politique de contrôle des applications (Application Whitelisting) pour restreindre l'exécution des exécutables non approuvés (D3-EAL).
- Surveiller les requêtes DNS ou les connexions réseau vers des domaines connus ou suspects, comme "c2.malsight.lab", même si l'activité réseau n'est pas prouvée dans les données (D3-DE).
- Surveiller la création de fichiers dans des chemins spécifiques ou l'écriture de données dans des fichiers de configuration pour détecter des exfiltrations potentielles (D3-FIM).

## Incertitudes

- Aucune signalée.
