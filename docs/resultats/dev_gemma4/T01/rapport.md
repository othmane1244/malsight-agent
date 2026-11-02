# Rapport d'analyse : T01_persistance_run.ps1

| Champ | Valeur |
| --- | --- |
| SHA-256 | `fa227aed8895a3786b1bf853bcbc5f43fafbc6fe6854fb65cb6a34476dc1cb6e` |
| MD5 | `a28653ca8cf8274a353b629a62c4d1b6` |
| Type | unknown |
| Taille | 2146 octets |

> Rapport généré par MalSight Agent. **À valider par un analyste avant diffusion.**

## Résumé

L'échantillon est un script PowerShell (filename: T01_persistance_run.ps1) qui exécute des actions de persistance et de modification de fichiers. Il écrit un fichier dans le répertoire C:\travail\malsight_test.txt et établit une entrée de registre pour assurer sa persistance au démarrage de l'utilisateur. Il tente également une activité réseau vers le domaine test.malsight.lab.

## Comportements

| Comportement | Preuve | Statut |
| --- | --- | --- |
| Écriture de fichiers | `files_written: ["C:\travail\malsight_test.txt"]` | observé |
| Modification du registre pour la persistance | `registry_keys_set: ["HKCU\Software\Microsoft\Windows\CurrentVersion\Run\MalsightTest"]` | observé |
| Tentative de communication réseau | `domains: ["test.malsight.lab"]` | observé |

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
| [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | Registry Run Keys / Startup Folder | persistence, privilege-escalation | llm | medium | registry_keys_set: ["HKCU\Software\Microsoft\Windows\CurrentVersion\Run\MalsightTest"] |

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

- Surveiller la création ou la modification des clés de registre de démarrage utilisateur, en particulier dans `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, pour détecter l'ajout de chemins non autorisés (D3-FIM).
- Mettre en place des politiques de contrôle des applications pour restreindre l'exécution de fichiers provenant de chemins non standard ou de dossiers utilisateurs (D3-EAL).
- Surveiller les tentatives d'écriture de clés de registre dans les chemins de démarrage utilisateur (ex: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`) via des outils de surveillance de registre (D3-FIM).
- Analyser les fichiers exécutables suspects en utilisant des environnements de sandbox ou d'analyse dynamique (D3-DA) avant de permettre leur exécution.
- Appliquer des restrictions de permissions de fichiers et de registre pour limiter les modifications aux clés de démarrage critiques (D3-LFP).
- Utiliser des solutions de filtrage de contenu pour bloquer l'exécution de fichiers basés sur des signatures connues (D3-CF).

## Incertitudes

- Aucune signalée.
