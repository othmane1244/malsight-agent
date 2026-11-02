# Rapport d'analyse : T06_powershell_encode.ps1

| Champ | Valeur |
| --- | --- |
| SHA-256 | `218f8c080741fa2a5999144e4e0e8006ad9cc8f5c069babcc5275c3efcf04219` |
| MD5 | `93e6808250a5e84400feff270ba03042` |
| Type | unknown |
| Taille | 1199 octets |

> Rapport généré par MalSight Agent. **À valider par un analyste avant diffusion.**

## Résumé

L'échantillon exécute PowerShell avec une commande encodée (`-EncodedCommand`), ce qui est une activité observée. Il est également observé qu'un fichier est créé dans le répertoire `C:\travail\malsight_t06.txt`. L'analyse ne révèle pas de communication réseau établie ni d'écriture de registre spécifique.

## Comportements

| Comportement | Preuve | Statut |
| --- | --- | --- |
| Exécution de PowerShell avec une commande encodée | `powershell.exe "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -EncodedCommand UwBlAHQALQBDAG8AbgB0AGUAbgB0ACAALQBQAGEAdABoACAAJwBDADoAXAB0AHIAYQB2AGEAaQBsAFwAbQBhAGwAcwBpAGcAaAB0AF8AdAAwADYALgB0AHgAdAAnACAALQBWAGEAbAB1AGUAIAAnAE0AYQBsAFMAaQBnAGgAdAAgAFQAMAA2ACcA"` | observé |
| Création d'un fichier dans le répertoire de travail | `C:\travail\malsight_t06.txt` | observé |

## Indicateurs de compromission (IOC)

| Type | Valeur | Source |
| --- | --- | --- |
| sha256 | `218f8c080741fa2a5999144e4e0e8006ad9cc8f5c069babcc5275c3efcf04219` | fichier |
| md5 | `93e6808250a5e84400feff270ba03042` | fichier |
| file_path | `C:\travail\malsight_t06.txt` | extraction |

## API sensibles

| API | Catégorie | Source |
| --- | --- | --- |

## Techniques MITRE ATT&CK

| ID | Technique | Tactique | Source | Confiance | Preuve |
| --- | --- | --- | --- | --- | --- |
| [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | PowerShell | execution | rule | high | règle R-T1059.001-encodee : "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -EncodedCommand UwBlAHQALQBDAG8AbgB0AGUAbgB0ACAALQBQAGEAdABoACAAJwBDADoAXAB0AHIAYQB2AGEAaQBsAFwAbQBhAGwAcwBpAGcAaAB0AF8AdAAwADYALgB0AHgAdAAnACAALQBWAGEAbAB1AGUAIAAnAE0AYQBsAFMAaQBnAGgAdAAgAFQAMAA2ACcA (powershell.exe (7560)) |

## Contre-mesures D3FEND

Contre-mesures défensives [MITRE D3FEND](https://d3fend.mitre.org) associées aux techniques
ATT&CK retenues (source : d3fend, cache local ; IDs vérifiés).

| Technique ATT&CK | Contre-mesure D3FEND | Tactique | Artefact |
| --- | --- | --- | --- |
| [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | [D3-FE File Encryption](https://d3fend.mitre.org/technique/d3f:FileEncryption/) | Harden | File |
| [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | [D3-DA Dynamic Analysis](https://d3fend.mitre.org/technique/d3f:DynamicAnalysis/) | Detect | Executable File |
| [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | [D3-EFA Emulated File Analysis](https://d3fend.mitre.org/technique/d3f:EmulatedFileAnalysis/) | Detect | Executable File |
| [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | [D3-FA File Analysis](https://d3fend.mitre.org/technique/d3f:FileAnalysis/) | Detect | File |
| [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | [D3-FIM File Integrity Monitoring](https://d3fend.mitre.org/technique/d3f:FileIntegrityMonitoring/) | Detect | File |
| [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | [D3-CF Content Filtering](https://d3fend.mitre.org/technique/d3f:ContentFiltering/) | Isolate | File |
| [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | [D3-CM Content Modification](https://d3fend.mitre.org/technique/d3f:ContentModification/) | Isolate | File |
| [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | [D3-CQ Content Quarantine](https://d3fend.mitre.org/technique/d3f:ContentQuarantine/) | Isolate | File |
| [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | [D3-EAL Executable Allowlisting](https://d3fend.mitre.org/technique/d3f:ExecutableAllowlisting/) | Isolate | Executable File |
| [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | [D3-EDL Executable Denylisting](https://d3fend.mitre.org/technique/d3f:ExecutableDenylisting/) | Isolate | Executable File |
| [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | [D3-LFP Local File Permissions](https://d3fend.mitre.org/technique/d3f:LocalFilePermissions/) | Isolate | File |
| [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | [D3-RFAM Remote File Access Mediation](https://d3fend.mitre.org/technique/d3f:RemoteFileAccessMediation/) | Isolate | File |

## Recommandations

- Surveiller l'exécution de PowerShell avec des commandes encodées ou des arguments longs, car l'échantillon utilise une exécution encodée (T1059.001). (D3-DA)
- Mettre en place une surveillance des appels à `powershell.exe` avec des arguments `-EncodedCommand` ou des chaînes de caractères suspectes pour détecter les exécutions de scripts cachés (D3-DA).
- Surveiller la création ou la modification de fichiers spécifiques comme `C:\travail\malsight_t06.txt` pour détecter des activités de persistance ou de communication de données (D3-FIM).
- Appliquer des politiques de contrôle des applications pour restreindre l'utilisation de PowerShell aux seuls scripts nécessaires et autorisés, limitant ainsi l'exécution de commandes arbitraires (D3-EAL).
- Surveiller les tentatives d'accès aux fichiers système ou aux répertoires sensibles pour détecter toute tentative de manipulation de fichiers (D3-LFP).

## Incertitudes

- Le contenu exact de la commande encodée exécutée par PowerShell n'est pas déchiffré, ce qui limite la compréhension de l'intention de l'exécution.
