# Rapport d'analyse : T12_scenario_combine.ps1

| Champ | Valeur |
| --- | --- |
| SHA-256 | `561a7e11d3359407846f22cabacbe578fe4b49555660b122e90cd9c2d1d39586` |
| MD5 | `acbdc6e0398ec6b1e8d774cd8e32b8bf` |
| Type | unknown |
| Taille | 1904 octets |

> Rapport généré par MalSight Agent. **À valider par un analyste avant diffusion.**

## Résumé

L'échantillon est un script PowerShell (déduit du nom de fichier `T12_scenario_combine.ps1`) qui exécute des actions de persistance et de collecte d'informations système. Il écrit un fichier dans le répertoire `C:\travail\` et crée une entrée de registre pour assurer la persistance au démarrage. Il tente également d'exécuter `systeminfo.exe` et de communiquer avec le domaine `c2.malsight.lab`.

## Comportements

| Comportement | Preuve | Statut |
| --- | --- | --- |
| Création de fichiers et exfiltration potentielle d'informations. | `files_written: ["C:\travail\malsight_t12_info.txt"]` | observé |
| Mise en place d'un mécanisme de persistance au niveau du registre. | `registry_keys_set: ["HKCU\Software\Microsoft\Windows\CurrentVersion\Run\MalsightTest12"]` | observé |
| Exécution d'un outil système pour collecter des informations sur le système. | `processes_created: ["\"C:\Windows\system32\systeminfo.exe""]` | observé |
| Tentative de communication réseau avec un domaine spécifique. | `domains: ["c2.malsight.lab"]` | observé |

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
| [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | PowerShell | execution | llm | medium | HKCU\Software\Microsoft\Windows\CurrentVersion\Run\MalsightTest12 |

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

- Surveiller la création de clés de registre dans les chemins de démarrage utilisateur, comme HKCU\Software\Microsoft\Windows\CurrentVersion\Run, pour détecter l'ajout de tâches persistantes (D3-FIM).
- Mettre en place des politiques de sécurité pour restreindre l'exécution de scripts PowerShell depuis des chemins non approuvés ou des clés de registre de démarrage (D3-EAL).
- Surveiller les modifications des clés de registre de démarrage (HKCU\Software\Microsoft\Windows\CurrentVersion\Run) pour détecter toute modification non autorisée (D3-FIM).
- Utiliser des solutions de détection des comportements pour identifier l'exécution de scripts PowerShell (D3-DA).
- Bloquer l'exécution de fichiers basés sur des hachages connus (sha256: 561a7e11d3359407846f22cabacbe578fe4b49555660b122e90cd9c2d1d39586, md5: acbdc6e0398ec6b1e8d774cd8e32b8bf) (D3-CF).
- Surveiller les tentatives de connexion ou de résolution DNS vers des domaines connus comme c2.malsight.lab (D3-RFAM).

## Incertitudes

- Le type de fichier est indiqué comme "unknown" dans l'en-tête, ce qui rend l'analyse de son exécution initiale incertaine.
- L'activité réseau avec le domaine "c2.malsight.lab" est observée, mais il n'y a pas de preuve de connexion établie ou de données échangées, ce qui rend la nature de cette communication incertaine (tentative ou succès).
