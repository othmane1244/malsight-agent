# Rapport d'analyse : T08_decouverte_reseau.ps1

| Champ | Valeur |
| --- | --- |
| SHA-256 | `a8957953c905b4f7c069d1f759816f77a93a0334ca0c8436fd91993676a3cf90` |
| MD5 | `2006d0747f6ab9022f05118743b17516` |
| Type | unknown |
| Taille | 1030 octets |

> Rapport généré par MalSight Agent. **À valider par un analyste avant diffusion.**

## Résumé

L'échantillon, nommé "T08_decouverte_reseau.ps1", exécute plusieurs commandes système courantes pour la découverte de réseau et modifie des clés de registre spécifiques. Il écrit également un fichier local. Aucune activité réseau externe n'a été observée. Les actions observées sont principalement liées à la reconnaissance du système.

## Comportements

| Comportement | Preuve | Statut |
| --- | --- | --- |
| Modification du registre pour créer des clés associées à un agent. | `HKLM\SOFTWARE\Microsoft\RFC1156Agent` | observé |
| Création de clés de registre spécifiques sous HKLM\SOFTWARE\Microsoft\RFC1156Agent. | `HKLM\SOFTWARE\Microsoft\RFC1156Agent\CurrentVersion` | observé |
| Création de clés de registre spécifiques sous HKLM\SOFTWARE\Microsoft\RFC1156Agent\CurrentVersion. | `HKLM\SOFTWARE\Microsoft\RFC1156Agent\CurrentVersion\Parameters` | observé |
| Modification de la valeur de registre "TrapPollTimeMilliSecs" sous HKLM\SOFTWARE\Microsoft\RFC1156Agent\CurrentVersion\Parameters. | `HKLM\SOFTWARE\Microsoft\RFC1156Agent\CurrentVersion\Parameters\TrapPollTimeMilliSecs` | observé |
| Exécution de commandes système pour la découverte de réseau. | `procmon: "C:\Windows\system32\ipconfig.exe" /all` | observé |
| Exécution de commandes système pour la découverte de réseau. | `procmon: "C:\Windows\system32\ROUTE.EXE" print` | observé |
| Exécution de commandes système pour la découverte de réseau. | `procmon: "C:\Windows\system32\ARP.EXE" -a` | observé |
| Écriture d'un fichier local. | `C:\travail\malsight_t08.txt` | observé |

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
| [T1082](https://attack.mitre.org/techniques/T1082/) | System Information Discovery | discovery | llm | medium | Exécution de "C:\Windows\system32\ipconfig.exe" /all, "C:\Windows\system32\ROUTE.EXE" print, "C:\Windows\system32\ARP.EXE" -a |

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

## Recommandations

- Surveiller l'exécution de commandes système courantes comme `ipconfig.exe`, `route.exe` et `arp.exe` (T1082) en analysant les arguments passés, car ces outils sont souvent utilisés pour la reconnaissance réseau.
- Mettre en place des règles de détection (ex: Sysmon) pour surveiller la création de processus utilisant des outils système standards avec des arguments spécifiques (ex: `ipconfig.exe /all`, `route.exe print`, `arp.exe -a`). (D3-PSA)
- Durcir les politiques de registre pour surveiller toute modification des clés associées à l'agent RFC1156, notamment `HKLM\SOFTWARE\Microsoft\RFC1156Agent` et ses sous-clés, pour détecter des tentatives de persistance ou de modification de configuration. (D3-SCA)
- Implémenter des mécanismes de contrôle d'application (Application Whitelisting) pour restreindre l'exécution des outils système uniquement aux chemins et contextes attendus, limitant ainsi l'utilisation abusive de `ipconfig.exe`, `route.exe`, et `arp.exe`. (D3-EAL)
- Surveiller les tentatives de création de fichiers dans des répertoires inhabituels ou non liés aux opérations normales, comme `C:\travail\malsight_t08.txt`, en tant qu'indicateur potentiel de dépôt de données ou de résultats de reconnaissance.

## Incertitudes

- Aucune signalée.
