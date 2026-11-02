# Rapport d'analyse : T08_decouverte_reseau.ps1

| Champ | Valeur |
| --- | --- |
| SHA-256 | `a8957953c905b4f7c069d1f759816f77a93a0334ca0c8436fd91993676a3cf90` |
| MD5 | `2006d0747f6ab9022f05118743b17516` |
| Type | unknown |
| Taille | 1030 octets |

> Rapport généré par MalSight Agent. **À valider par un analyste avant diffusion.**

## Résumé

L'échantillon exécute une série de commandes système pour la découverte d'informations réseau et écrit ensuite des données dans un fichier local. Les actions observées incluent l'exécution de `ipconfig.exe`, `route.exe`, et `arp.exe` via `powershell.exe`, ce qui indique une phase de reconnaissance réseau. De plus, l'échantillon interagit avec le registre pour créer ou modifier des clés sous `HKLM\SOFTWARE\Microsoft\RFC1156Agent` et écrit un fichier nommé `C:\travail\malsight_t08.txt`.

## Comportements

| Comportement | Preuve | Statut |
| --- | --- | --- |
| Exécution d'outils système pour la découverte de configuration réseau. | `L'échantillon exécute "C:\Windows\system32\ipconfig.exe" /all, "C:\Windows\system32\ROUTE.EXE" print, et "C:\Windows\system32\ARP.EXE" -a, le tout depuis powershell.exe (7472).` | observé |
| Modification du registre pour des clés liées à 'RFC1156Agent'. | `L'échantillon accède et écrit dans les clés de registre suivantes : HKLM\SOFTWARE\Microsoft\RFC1156Agent, HKLM\SOFTWARE\Microsoft\RFC1156Agent\CurrentVersion, HKLM\SOFTWARE\Microsoft\RFC1156Agent\CurrentVersion\Parameters, et HKLM\SOFTWARE\Microsoft\RFC1156Agent\CurrentVersion\Parameters\TrapPollTimeMilliSecs (via ARP.EXE (8168)).` | observé |
| Écriture de données dans un fichier local. | `L'échantillon écrit le contenu dans le fichier C:\travail\malsight_t08.txt (via powershell.exe (7472)).` | observé |

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
| [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | Registry Run Keys / Startup Folder | persistence, privilege-escalation | llm | medium | L'écriture de données dans un fichier local : C:\travail\malsight_t08.txt. |

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

- Surveiller l'exécution de commandes système comme `ipconfig.exe` (T1016) en analysant les arguments passés, car cela indique une découverte de configuration réseau. (D3-PSA)
- Surveiller toute écriture de données dans des fichiers dans le répertoire `C:\travail\` ou tout autre répertoire utilisateur non standard, en particulier si cela est associé à la création de fichiers de configuration ou de marqueurs. (D3-FIM)
- Mettre en place des règles de détection pour les modifications des clés de registre spécifiques associées à des agents ou des services, telles que `HKLM\SOFTWARE\Microsoft\RFC1156Agent` (T1547.001). (D3-FIM)
- Appliquer le principe du moindre privilège pour limiter les droits d'écriture dans les clés de registre système critiques (HKLM), en particulier celles utilisées pour les clés de démarrage ou les configurations d'agents. (D3-LFP)
- Utiliser des solutions de détection comportementale pour identifier les séquences d'actions de reconnaissance (ex: exécution d'outils système suivies d'écritures de fichiers de configuration). (D3-DA)
- Surveiller les processus qui exécutent des outils de ligne de commande système (`ipconfig.exe`) en les liant à des processus parents inhabituels (ex: `powershell.exe`) pour détecter des chaînes d'attaque de type 'Living off the Land'. (D3-PSA)

## Incertitudes

- Aucune signalée.
