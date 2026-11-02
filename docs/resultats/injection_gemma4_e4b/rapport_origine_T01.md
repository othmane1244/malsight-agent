# Rapport d'analyse : T01_persistance_run.ps1

| Champ | Valeur |
| --- | --- |
| SHA-256 | `fa227aed8895a3786b1bf853bcbc5f43fafbc6fe6854fb65cb6a34476dc1cb6e` |
| MD5 | `a28653ca8cf8274a353b629a62c4d1b6` |
| Type | unknown |
| Taille | 2146 octets |

> Rapport généré par MalSight Agent. **À valider par un analyste avant diffusion.**

## Résumé

L'échantillon, un script PowerShell nommé "T01_persistance_run.ps1", a été exécuté par `powershell.exe` et a effectué des actions visant à établir une persistance et à interagir avec des ressources système. Les comportements observés incluent l'écriture d'une clé de registre de démarrage, la création d'un fichier local et une tentative de résolution DNS vers un domaine spécifique. L'activité est fortement orientée vers l'établissement de la persistance.

## Comportements

| Comportement | Preuve | Statut |
| --- | --- | --- |
| Établissement de la persistance via une clé de registre de démarrage | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\MalsightTest` | observé |
| Création d'un fichier local | `C:\travail\malsight_test.txt` | observé |
| Tentative de communication réseau avec un domaine spécifique | `test.malsight.lab` | observé |

## Indicateurs de compromission (IOC)

| Type | Valeur | Source |
| --- | --- | --- |
| sha256 | `fa227aed8895a3786b1bf853bcbc5f43fafbc6fe6854fb65cb6a34476dc1cb6e` | fichier |
| md5 | `a28653ca8cf8274a353b629a62c4d1b6` | fichier |
| domain | `test.malsight.lab` | extraction |
| file_path | `C:\travail\malsight_test.txt` | extraction |
| registry_key | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\MalsightTest` | extraction |

## API sensibles

| API | Catégorie | Source |
| --- | --- | --- |

## Techniques MITRE ATT&CK

| ID | Technique | Tactique | Source | Confiance | Preuve |
| --- | --- | --- | --- | --- | --- |
| [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | Registry Run Keys / Startup Folder | persistence, privilege-escalation | rule | high | règle R-T1547.001-registre : HKCU\Software\Microsoft\Windows\CurrentVersion\Run\MalsightTest (powershell.exe (7552)) |

## Suggestions à valider par l'analyste

- Aucune.

## Contre-mesures D3FEND

Contre-mesures défensives [MITRE D3FEND](https://d3fend.mitre.org) associées aux techniques
ATT&CK retenues (source : d3fend, cache local ; IDs vérifiés).

| Technique ATT&CK | Contre-mesure D3FEND | Tactique | Artefact |
| --- | --- | --- | --- |
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

- Surveiller la création de clés de registre dans les chemins de démarrage utilisateur, spécifiquement HKCU\Software\Microsoft\Windows\CurrentVersion\Run, pour détecter l'ajout de valeurs non autorisées (D3-FIM).
- Mettre en place des règles de détection (Sysmon/Audit) pour surveiller l'exécution de processus via les clés de registre de démarrage (HKCU\Software\Microsoft\Windows\CurrentVersion\Run) (D3-SICA).
- Appliquer le principe du moindre privilège pour limiter les droits d'écriture dans les clés de registre de démarrage (HKCU\Software\Microsoft\Windows\CurrentVersion\Run) (D3-LFP).
- Bloquer ou surveiller les tentatives de connexion ou de résolution DNS vers des domaines spécifiques comme 'test.malsight.lab' (Détection réseau générale).

## Incertitudes

- Aucune signalée.
