# Rapport d'analyse : T07_decouverte_systeme.ps1

| Champ | Valeur |
| --- | --- |
| SHA-256 | `91379f80153cf471af84f022d11c9a6b683a02ed584a80d0bf3734b6bab1e5f7` |
| MD5 | `83410fbb1e5852e13f895ac481f70758` |
| Type | unknown |
| Taille | 990 octets |

> Rapport généré par MalSight Agent. **À valider par un analyste avant diffusion.**

## Résumé

L'échantillon, un script PowerShell nommé "T07_decouverte_systeme.ps1", exécute des commandes système pour collecter des informations sur l'environnement. Il exécute spécifiquement `systeminfo.exe` et tente d'exécuter un exécutable nommé `HOSTNAME.EXE` situé dans `C:\Windows\system32\`. Enfin, il crée un fichier texte dans le répertoire `C:\travail\` nommé `malsight_t07.txt`.

## Comportements

| Comportement | Preuve | Statut |
| --- | --- | --- |
| Exécution de commandes système pour la collecte d'informations (Reconnaissance) | `Exécution de "C:\Windows\system32\systeminfo.exe" par powershell.exe (3320) (sources: procmon, sysmon)` | observé |
| Tentative d'exécution d'un exécutable système non standard (Reconnaissance/Exécution) | `Exécution de "C:\Windows\system32\HOSTNAME.EXE" par powershell.exe (3320) (sources: procmon, sysmon)` | observé |
| Création d'un fichier local pour stocker des données (Persistance/Exfiltration) | `Création du fichier "C:\travail\malsight_t07.txt" par powershell.exe (3320) (sources: procmon, sysmon)` | observé |

## Indicateurs de compromission (IOC)

| Type | Valeur | Source |
| --- | --- | --- |
| sha256 | `91379f80153cf471af84f022d11c9a6b683a02ed584a80d0bf3734b6bab1e5f7` | fichier |
| md5 | `83410fbb1e5852e13f895ac481f70758` | fichier |
| file_path | `C:\travail\malsight_t07.txt` | extraction |

## API sensibles

| API | Catégorie | Source |
| --- | --- | --- |

## Techniques MITRE ATT&CK

| ID | Technique | Tactique | Source | Confiance | Preuve |
| --- | --- | --- | --- | --- | --- |

## Suggestions à valider par l'analyste

- Aucune.

## Contre-mesures D3FEND

- Aucune (aucune technique ATT&CK retenue, ou cache D3FEND absent : `malsight download-d3fend`).

## Recommandations

- Surveiller l'exécution de `systeminfo.exe` ou de commandes WMI suspectes (T1047) en analysant les arguments passés, car cela peut indiquer une collecte d'informations système.
- Mettre en place des règles de détection (ex: Sysmon) pour alerter sur l'utilisation de WMI (T1047) lorsqu'elle est associée à des processus non standard ou à des chemins inhabituels.
- Surveiller la création ou la modification de fichiers spécifiques comme `C:\travail\malsight_t07.txt` pour détecter des écritures de données potentiellement malveillantes.
- Analyser les processus qui accèdent ou écrivent des données dans des répertoires de travail non standard (`C:\travail\`) pour identifier des comportements d'exfiltration ou de staging de données.

## Incertitudes

- Le fichier "C:\Windows\system32\HOSTNAME.EXE" est exécuté, mais sa fonction réelle n'est pas détaillée par les données fournies.

## Affirmations rejetées par le vérificateur

- Technique sans preuve vérifiable, rejetée : T1047 (aucune valeur reconnaissable)
