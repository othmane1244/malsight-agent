# Rapport d'analyse : T12_scenario_combine.ps1

| Champ | Valeur |
| --- | --- |
| SHA-256 | `561a7e11d3359407846f22cabacbe578fe4b49555660b122e90cd9c2d1d39586` |
| MD5 | `acbdc6e0398ec6b1e8d774cd8e32b8bf` |
| Type | unknown |
| Taille | 1904 octets |

> Rapport généré par MalSight Agent. **À valider par un analyste avant diffusion.**

## Résumé

L'échantillon exécute des actions de découverte d'informations système et établit une persistance sur la machine analysée. Il exécute `systeminfo.exe` pour collecter des informations système et ajoute une clé de registre de démarrage (`HKCU\Software\Microsoft\Windows\CurrentVersion\Run\MalsightTest12`) pour assurer la persistance. De plus, il tente de communiquer avec un domaine externe (`c2.malsight.lab`).

## Comportements

| Comportement | Preuve | Statut |
| --- | --- | --- |
| Collecte d'informations système | `Exécution de "C:\Windows\system32\systeminfo.exe" par powershell.exe (7444) (procmon, sysmon)` | observé |
| Établissement de la persistance via le registre de démarrage | `Écriture de la clé de registre HKCU\Software\Microsoft\Windows\CurrentVersion\Run\MalsightTest12 par powershell.exe (7444) (procmon, sysmon)` | observé |
| Tentative de communication réseau avec un domaine C2 | `Observation du domaine c2.malsight.lab par powershell.exe (7444) (sysmon)` | observé |

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
| [T1082](https://attack.mitre.org/techniques/T1082/) | System Information Discovery | discovery | rule | high | règle R-T1082-processus : "C:\Windows\system32\systeminfo.exe" (powershell.exe (7444)) |
| [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | Registry Run Keys / Startup Folder | persistence, privilege-escalation | rule | high | règle R-T1547.001-registre : HKCU\Software\Microsoft\Windows\CurrentVersion\Run\MalsightTest12 (powershell.exe (7444)) |

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

- Surveiller l'exécution de `systeminfo.exe` (T1082) en analysant les arguments passés ou le contexte de son lancement, car il est utilisé pour la collecte d'informations système. (D3-PSA)
- Mettre en place une surveillance des modifications des clés de registre de démarrage (Run Keys) telles que `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\*` pour détecter l'ajout de chemins suspects. (D3-FIM)
- Implémenter des politiques de contrôle des applications (Application Whitelisting) pour restreindre l'exécution de binaires système comme `systeminfo.exe` aux contextes attendus, afin de détecter les usages abusifs. (D3-EAL)
- Surveiller les tentatives de création de clés de registre dans les chemins de démarrage utilisateur (HKCU\Software\Microsoft\Windows\CurrentVersion\Run) pour détecter les persistance malveillante. (D3-FIM)
- Bloquer ou surveiller les connexions réseau sortantes vers des domaines connus de Command and Control (C2) tels que `c2.malsight.lab` au niveau du pare-feu ou de la résolution DNS. (Aucun D3FEND spécifique)
- Analyser les processus qui accèdent ou écrivent dans des fichiers spécifiques comme `C:\travail\malsight_t12_info.txt` pour comprendre le flux de données collectées. (D3-PSA)

## Incertitudes

- Aucune signalée.
