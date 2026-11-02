# Rapport d'analyse : T13_persistance_runonce.ps1

| Champ | Valeur |
| --- | --- |
| SHA-256 | `7d4711b61bbb454c40becacb4d4d977c58d2a53dada7719ba2295466a30debd3` |
| MD5 | `c27481a7da976f92a8326eb38db40d83` |
| Type | unknown |
| Taille | 1307 octets |

> Rapport généré par MalSight Agent. **À valider par un analyste avant diffusion.**

## Résumé

L'échantillon est un script PowerShell nommé "T13_persistance_runonce.ps1". Son comportement observé principal est la tentative d'établir une persistance en modifiant des clés de registre associées au démarrage de l'utilisateur. Spécifiquement, il écrit dans la clé `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce` et y crée une valeur nommée `MalsightTest13` via `powershell.exe (7772)`.

## Comportements

| Comportement | Preuve | Statut |
| --- | --- | --- |
| Établir la persistance via les clés de registre de démarrage de l'utilisateur. | `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce\MalsightTest13` | observé |

## Indicateurs de compromission (IOC)

| Type | Valeur | Source |
| --- | --- | --- |
| sha256 | `7d4711b61bbb454c40becacb4d4d977c58d2a53dada7719ba2295466a30debd3` | fichier |
| md5 | `c27481a7da976f92a8326eb38db40d83` | fichier |
| registry_key | `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce` | extraction |
| registry_key | `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce\MalsightTest13` | extraction |

## API sensibles

| API | Catégorie | Source |
| --- | --- | --- |

## Techniques MITRE ATT&CK

| ID | Technique | Tactique | Source | Confiance | Preuve |
| --- | --- | --- | --- | --- | --- |
| [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | Registry Run Keys / Startup Folder | persistence, privilege-escalation | rule | high | règle R-T1547.001-registre : HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce\MalsightTest13 (powershell.exe (7772)) |

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

- Surveiller les modifications des clés de registre de démarrage, en particulier sous `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`, pour détecter l'ajout de nouvelles entrées (Détection : Sysmon Event ID 12 ou 13).
- Mettre en place une surveillance des modifications des clés de registre de démarrage (Run Keys) pour détecter l'ajout de chemins exécutables suspects (Détection : Sysmon Event ID 12 ou 13).
- Appliquer des politiques de durcissement pour restreindre l'écriture dans les clés de registre de démarrage critiques comme `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce` (Durcissement : (D3-LFP)).
- Utiliser des solutions de File Integrity Monitoring (FIM) pour alerter en cas de modification des clés de registre de démarrage (Détection : (D3-FIM)).

## Incertitudes

- Aucune signalée.
