# Rapport d'analyse : T10_telechargement.ps1

| Champ | Valeur |
| --- | --- |
| SHA-256 | `f8a938c6909044c78ef5a18ef7436bb9eedc48c2370c256d0823a8b5c21d7681` |
| MD5 | `ddeb822a26e2e57bca8f7dbbff7e8468` |
| Type | unknown |
| Taille | 1322 octets |

> Rapport généré par MalSight Agent. **À valider par un analyste avant diffusion.**

## Résumé

L'échantillon, exécuté via `powershell.exe`, a interagi avec le système de fichiers et le registre pour configurer des paramètres de traçage PowerShell. Il a également tenté de communiquer avec un domaine externe. Aucune activité de création de persistance ou d'exécution de code suspect n'a été observée. Les actions se concentrent sur la modification des clés de registre liées au traçage de PowerShell et une tentative de connexion réseau.

## Comportements

| Comportement | Preuve | Statut |
| --- | --- | --- |
| Configuration des paramètres de traçage PowerShell | `HKLM\Software\Microsoft\Tracing\powershell_RASAPI32\EnableFileTracing` | inféré |
| Configuration des paramètres de traçage PowerShell | `HKLM\SOFTWARE\Microsoft\Tracing\powershell_RASAPI32\EnableAutoFileTracing` | inféré |
| Configuration des paramètres de traçage PowerShell | `HKLM\SOFTWARE\Microsoft\Tracing\powershell_RASAPI32\EnableConsoleTracing` | inféré |
| Configuration des paramètres de traçage PowerShell | `HKLM\SOFTWARE\Microsoft\Tracing\powershell_RASAPI32\FileTracingMask` | inféré |
| Configuration des paramètres de traçage PowerShell | `HKLM\SOFTWARE\Microsoft\Tracing\powershell_RASAPI32\ConsoleTracingMask` | inféré |
| Configuration des paramètres de traçage PowerShell | `HKLM\SOFTWARE\Microsoft\Tracing\powershell_RASAPI32\MaxFileSize` | inféré |
| Configuration des paramètres de traçage PowerShell | `HKLM\SOFTWARE\Microsoft\Tracing\powershell_RASAPI32\FileDirectory` | inféré |
| Configuration des paramètres de traçage PowerShell | `HKLM\SOFTWARE\Microsoft\Tracing\powershell_RASMANCS\EnableFileTracing` | inféré |
| Configuration des paramètres de traçage PowerShell | `HKLM\SOFTWARE\Microsoft\Tracing\powershell_RASMANCS\EnableAutoFileTracing` | inféré |
| Configuration des paramètres de traçage PowerShell | `HKLM\SOFTWARE\Microsoft\Tracing\powershell_RASMANCS\EnableConsoleTracing` | inféré |
| Configuration des paramètres de traçage PowerShell | `HKLM\SOFTWARE\Microsoft\Tracing\powershell_RASMANCS\FileTracingMask` | inféré |
| Configuration des paramètres de traçage PowerShell | `HKLM\SOFTWARE\Microsoft\Tracing\powershell_RASMANCS\ConsoleTracingMask` | inféré |
| Configuration des paramètres de traçage PowerShell | `HKLM\SOFTWARE\Microsoft\Tracing\powershell_RASMANCS\MaxFileSize` | inféré |
| Configuration des paramètres de traçage PowerShell | `HKLM\SOFTWARE\Microsoft\Tracing\powershell_RASMANCS\FileDirectory` | inféré |
| Tentative de communication réseau avec un domaine externe | `update.malsight.lab` | inféré |

## Indicateurs de compromission (IOC)

| Type | Valeur | Source |
| --- | --- | --- |
| sha256 | `f8a938c6909044c78ef5a18ef7436bb9eedc48c2370c256d0823a8b5c21d7681` | fichier |
| md5 | `ddeb822a26e2e57bca8f7dbbff7e8468` | fichier |
| url | `http://update.malsight.lab/outil.txt` | extraction |
| domain | `update.malsight.lab` | extraction |
| file_path | `C:\travail\outil.txt` | extraction |
| registry_key | `HKLM\SOFTWARE\Microsoft\Tracing\powershell_RASAPI32\ConsoleTracingMask` | extraction |
| registry_key | `HKLM\SOFTWARE\Microsoft\Tracing\powershell_RASAPI32\EnableAutoFileTracing` | extraction |
| registry_key | `HKLM\SOFTWARE\Microsoft\Tracing\powershell_RASAPI32\EnableConsoleTracing` | extraction |
| registry_key | `HKLM\SOFTWARE\Microsoft\Tracing\powershell_RASAPI32\EnableFileTracing` | extraction |
| registry_key | `HKLM\SOFTWARE\Microsoft\Tracing\powershell_RASAPI32\FileDirectory` | extraction |
| registry_key | `HKLM\SOFTWARE\Microsoft\Tracing\powershell_RASAPI32\FileTracingMask` | extraction |
| registry_key | `HKLM\SOFTWARE\Microsoft\Tracing\powershell_RASAPI32\MaxFileSize` | extraction |
| registry_key | `HKLM\SOFTWARE\Microsoft\Tracing\powershell_RASMANCS\ConsoleTracingMask` | extraction |
| registry_key | `HKLM\SOFTWARE\Microsoft\Tracing\powershell_RASMANCS\EnableAutoFileTracing` | extraction |
| registry_key | `HKLM\SOFTWARE\Microsoft\Tracing\powershell_RASMANCS\EnableConsoleTracing` | extraction |
| registry_key | `HKLM\SOFTWARE\Microsoft\Tracing\powershell_RASMANCS\EnableFileTracing` | extraction |
| registry_key | `HKLM\SOFTWARE\Microsoft\Tracing\powershell_RASMANCS\FileDirectory` | extraction |
| registry_key | `HKLM\SOFTWARE\Microsoft\Tracing\powershell_RASMANCS\FileTracingMask` | extraction |
| registry_key | `HKLM\SOFTWARE\Microsoft\Tracing\powershell_RASMANCS\MaxFileSize` | extraction |
| registry_key | `HKLM\Software\Microsoft\Tracing\powershell_RASAPI32` | extraction |
| registry_key | `HKLM\Software\Microsoft\Tracing\powershell_RASMANCS` | extraction |

## API sensibles

| API | Catégorie | Source |
| --- | --- | --- |

## Techniques MITRE ATT&CK

| ID | Technique | Tactique | Source | Confiance | Preuve |
| --- | --- | --- | --- | --- | --- |
| [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | Registry Run Keys / Startup Folder | persistence, privilege-escalation | llm | medium | update.malsight.lab |

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

- Surveiller les modifications des clés de registre de démarrage ou des clés de registre système (ex: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run) pour détecter l'ajout de chemins ou de valeurs non autorisés (D3-FIM).
- Mettre en place des règles de détection (Sysmon/Sigma) pour surveiller les tentatives d'écriture de fichiers dans des répertoires sensibles ou des chemins de démarrage (D3-FIM).
- Durcir les politiques de registre pour limiter les modifications des clés de traçage PowerShell (ex: HKLM\SOFTWARE\Microsoft\Tracing\*) pour empêcher la modification des paramètres de traçage (D3-SICA).
- Analyser les processus qui accèdent ou modifient les clés de registre liées au traçage de PowerShell (ex: HKLM\SOFTWARE\Microsoft\Tracing\*) pour identifier des comportements anormaux (D3-DA).
- Bloquer ou restreindre l'accès réseau aux domaines ou adresses IP non reconnus ou non nécessaires, en particulier pour les domaines observés comme 'update.malsight.lab' (D3-CF).
- Appliquer le principe du moindre privilège pour limiter les droits d'écriture des utilisateurs et des processus sur les clés de registre système critiques (D3-LFP).

## Incertitudes

- L'activité réseau observée est une tentative de résolution DNS pour 'update.malsight.lab' et ne confirme pas une communication établie ou des données échangées.
