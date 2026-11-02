# Rapport d'analyse : T06_powershell_encode.ps1

| Champ | Valeur |
| --- | --- |
| SHA-256 | `218f8c080741fa2a5999144e4e0e8006ad9cc8f5c069babcc5275c3efcf04219` |
| MD5 | `93e6808250a5e84400feff270ba03042` |
| Type | unknown |
| Taille | 1199 octets |

> Rapport généré par MalSight Agent. **À valider par un analyste avant diffusion.**

## Résumé

L'échantillon est un script PowerShell (`T06_powershell_encode.ps1`) qui exécute une commande encodée via `powershell.exe`. Il écrit ensuite un fichier nommé `malsight_t06.txt` dans le répertoire `C:\travail\`. Aucune activité réseau n'a été observée. L'exécution de la commande encodée est la principale activité observée.

## Comportements

| Comportement | Preuve | Statut |
| --- | --- | --- |
| Exécution de PowerShell avec une commande encodée. | `processes_created: "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -EncodedCommand UwBlAHQALQBDAG8AbgB0AGUAbgB0ACAALQBQAGEAdABoACAAJwBDADoAXAB0AHIAYQB2AGEAaQBsAFwAbQBhAGwAcwBpAGcAaAB0AF8AdAAwADYALgB0AHgAdAAnACAALQBWAGEAbAB1AGUAIAAnAE0AYQBsAFMAaQBnAGgAdAAgAFQAMAA2ACcA"` | observé |
| Écriture d'un fichier sur le système de fichiers. | `files_written: ["C:\travail\malsight_t06.txt"]` | observé |

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
| [T1027.002](https://attack.mitre.org/techniques/T1027/002/) | PowerShell: Encoded Command Execution | stealth | llm | medium | processes_created: "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -EncodedCommand UwBlAHQALQBDAG8AbgB0AGUAbgB0ACAALQBQAGEAdABoACAAJwBDADoAXAB0AHIAYQB2AGEAaQBsAFwAbQBhAGwAcwBpAGcAaAB0AF8AdAAwADYALgB0AHgAdAAnACAALQBWAGEAbAB1AGUAIAAnAE0AYQBsAFMAaQBnAGgAdAAgAFQAMAA2ACcA" |

## Contre-mesures D3FEND

- Aucune (aucune technique ATT&CK retenue, ou cache D3FEND absent : `malsight download-d3fend`).

## Recommandations

- Surveiller l'exécution de PowerShell avec des arguments `-EncodedCommand` en analysant les chaînes de caractères décodées pour détecter des commandes suspectes (Détection : Sysmon Event ID 1, Arguments de ligne de commande).
- Mettre en place des politiques de durcissement pour restreindre l'exécution de PowerShell en mode script sans arguments encodés, ou forcer l'utilisation de politiques de sécurité strictes (Durcissement : Appliquer des stratégies de groupe pour limiter l'exécution de scripts).
- Surveiller la création de fichiers avec des extensions inhabituelles ou des noms spécifiques comme `malsight_t06.txt` (Détection : Sysmon Event ID 11/12 pour la création de fichiers).
- Analyser les processus parents et enfants pour détecter des chaînes d'exécution de PowerShell provenant de processus inattendus (Détection : Sysmon Event ID 1, analyse de la chaîne de processus parent).
- Mettre en œuvre des mécanismes de détection basés sur les hachages SHA256 (`218f8c080741fa2a5999144e4e0e8006ad9cc8f5c069babcc5275c3efcf04219`) et MD5 (`93e6808250a5e84400feff270ba03042`) pour bloquer l'exécution de fichiers connus (Détection : Hashing/Antivirus).
- Surveiller les accès aux chemins de fichiers spécifiques comme `C:\travail\malsight_t06.txt` pour détecter toute activité de lecture, écriture ou modification (Détection : Sysmon Event ID 11/12).

## Incertitudes

- Aucune signalée.
