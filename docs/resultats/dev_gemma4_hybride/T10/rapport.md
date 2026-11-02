# Rapport d'analyse : T10_telechargement.ps1

| Champ | Valeur |
| --- | --- |
| SHA-256 | `f8a938c6909044c78ef5a18ef7436bb9eedc48c2370c256d0823a8b5c21d7681` |
| MD5 | `ddeb822a26e2e57bca8f7dbbff7e8468` |
| Type | unknown |
| Taille | 1322 octets |

> Rapport généré par MalSight Agent. **À valider par un analyste avant diffusion.**

## Résumé

L'échantillon, exécuté via `powershell.exe`, a principalement interagi avec le registre Windows pour configurer des paramètres de traçage PowerShell (RASAPI32 et RASMANCS). Il a également tenté de communiquer avec le domaine `update.malsight.lab`. Aucune activité de création de fichier, de modification de clé de registre critique ou de communication réseau réussie n'a été observée. L'activité suggère une tentative de configuration ou de reconnaissance des mécanismes de traçage de PowerShell.

## Comportements

| Comportement | Preuve | Statut |
| --- | --- | --- |
| Configuration des paramètres de traçage PowerShell | `HKLM\Software\Microsoft\Tracing\powershell_RASAPI32` | inféré |
| Tentative de communication réseau avec un domaine externe | `update.malsight.lab` | observé |

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
| [T1547.002](https://attack.mitre.org/techniques/T1547/002/) | Authentication Package | persistence, privilege-escalation | llm | medium | update.malsight.lab |

## Contre-mesures D3FEND

Contre-mesures défensives [MITRE D3FEND](https://d3fend.mitre.org) associées aux techniques
ATT&CK retenues (source : d3fend, cache local ; IDs vérifiés).

| Technique ATT&CK | Contre-mesure D3FEND | Tactique | Artefact |
| --- | --- | --- | --- |
| [T1547.002](https://attack.mitre.org/techniques/T1547/002/) | [D3-FE File Encryption](https://d3fend.mitre.org/technique/d3f:FileEncryption/) | Harden | File |
| [T1547.002](https://attack.mitre.org/techniques/T1547/002/) | [D3-SU Software Update](https://d3fend.mitre.org/technique/d3f:SoftwareUpdate/) | Harden | Software |
| [T1547.002](https://attack.mitre.org/techniques/T1547/002/) | [D3-DA Dynamic Analysis](https://d3fend.mitre.org/technique/d3f:DynamicAnalysis/) | Detect | Executable File |
| [T1547.002](https://attack.mitre.org/techniques/T1547/002/) | [D3-EFA Emulated File Analysis](https://d3fend.mitre.org/technique/d3f:EmulatedFileAnalysis/) | Detect | Executable File |
| [T1547.002](https://attack.mitre.org/techniques/T1547/002/) | [D3-FA File Analysis](https://d3fend.mitre.org/technique/d3f:FileAnalysis/) | Detect | File |
| [T1547.002](https://attack.mitre.org/techniques/T1547/002/) | [D3-FIM File Integrity Monitoring](https://d3fend.mitre.org/technique/d3f:FileIntegrityMonitoring/) | Detect | File |
| [T1547.002](https://attack.mitre.org/techniques/T1547/002/) | [D3-SICA System Init Config Analysis](https://d3fend.mitre.org/technique/d3f:SystemInitConfigAnalysis/) | Detect | System Init Configuration |
| [T1547.002](https://attack.mitre.org/techniques/T1547/002/) | [D3-CF Content Filtering](https://d3fend.mitre.org/technique/d3f:ContentFiltering/) | Isolate | File |
| [T1547.002](https://attack.mitre.org/techniques/T1547/002/) | [D3-CM Content Modification](https://d3fend.mitre.org/technique/d3f:ContentModification/) | Isolate | File |
| [T1547.002](https://attack.mitre.org/techniques/T1547/002/) | [D3-CQ Content Quarantine](https://d3fend.mitre.org/technique/d3f:ContentQuarantine/) | Isolate | File |
| [T1547.002](https://attack.mitre.org/techniques/T1547/002/) | [D3-EAL Executable Allowlisting](https://d3fend.mitre.org/technique/d3f:ExecutableAllowlisting/) | Isolate | Executable File |
| [T1547.002](https://attack.mitre.org/techniques/T1547/002/) | [D3-EDL Executable Denylisting](https://d3fend.mitre.org/technique/d3f:ExecutableDenylisting/) | Isolate | Executable File |

## Recommandations

- Surveiller les modifications des clés de registre liées au traçage de PowerShell, telles que 'HKLM\SOFTWARE\Microsoft\Tracing\powershell_RASAPI32\ConsoleTracingMask' ou 'HKLM\SOFTWARE\Microsoft\Tracing\powershell_RASMANCS\EnableConsoleTracing', pour détecter toute tentative d'activation ou de modification non autorisée (D3-FIM).
- Mettre en place des règles de détection (Sysmon/Sigma) pour alerter sur l'accès ou la modification des clés de registre spécifiques au traçage de PowerShell (ex: 'HKLM\SOFTWARE\Microsoft\Tracing\powershell_RASAPI32*') (D3-FIM).
- Bloquer ou surveiller les connexions sortantes vers le domaine 'update.malsight.lab' (D3-CQ).
- Surveiller les tentatives de création de fichiers dans des chemins spécifiques comme 'C:\travail\outil.txt' ou les tentatives de téléchargement de fichiers depuis des URL suspectes (D3-DA).
- Appliquer le principe du moindre privilège pour limiter les droits d'écriture et de modification des clés de registre système critiques (D3-FE).
- Considérer l'utilisation de politiques de durcissement pour restreindre l'exécution de scripts ou d'outils en utilisant des mécanismes de *Content Filtering* (D3-CF) ou *Executable Allowlisting* (D3-EAL).

## Incertitudes

- L'activité réseau observée est une tentative de résolution DNS pour le domaine `update.malsight.lab`, mais il n'y a pas de preuve de connexion établie ou de données échangées.
