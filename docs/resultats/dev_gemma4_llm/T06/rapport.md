# Rapport d'analyse : T06_powershell_encode.ps1

| Champ | Valeur |
| --- | --- |
| SHA-256 | `218f8c080741fa2a5999144e4e0e8006ad9cc8f5c069babcc5275c3efcf04219` |
| MD5 | `93e6808250a5e84400feff270ba03042` |
| Type | unknown |
| Taille | 1199 octets |

> Rapport généré par MalSight Agent. **À valider par un analyste avant diffusion.**

## Résumé

L'échantillon exécute PowerShell avec une commande encodée (`-EncodedCommand`) et crée ensuite un fichier local. Aucune activité réseau n'a été observée. L'exécution de PowerShell avec des commandes encodées est un comportement notable.

## Comportements

| Comportement | Preuve | Statut |
| --- | --- | --- |
| Exécution de PowerShell avec une commande encodée | `powershell.exe "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -EncodedCommand UwBlAHQALQBDAG8AbgB0AGUAbgB0ACAALQBQAGEAdABoACAAJwBDADoAXAB0AHIAYQB2AGEAaQBsAFwAbQBhAGwAcwBpAGcAaAB0AF8AdAAwADYALgB0AHgAdAAnACAALQBWAGEAbAB1AGUAIAAnAE0AYQBsAFMAaQBnAGgAdAAgAFQAMAA2ACcA` | observé |
| Création d'un fichier local | `C:\travail\malsight_t06.txt` | observé |

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
| [T1027](https://attack.mitre.org/techniques/T1027/) | Obfuscated Files or Information | stealth | llm | medium | L'utilisation de l'argument `-EncodedCommand` avec PowerShell pour exécuter une chaîne de caractères encodée est une technique courante pour masquer l'intention réelle de la commande. |

## Contre-mesures D3FEND

- Aucune (aucune technique ATT&CK retenue, ou cache D3FEND absent : `malsight download-d3fend`).

## Recommandations

- Surveiller l'utilisation de PowerShell avec l'argument `-EncodedCommand` via Sysmon (Event ID 1) pour détecter l'exécution de commandes encodées. (D3-PS) (D3-LFP)
- Mettre en place des règles de détection YARA ou Sigma ciblant les chaînes de caractères ou les signatures associées aux IOCs SHA256 (218f8c080741fa2a5999144e4e0e8006ad9cc8f5c069babcc5275c3efcf04219) et MD5 (93e6808250a5e84400feff270ba03042).
- Appliquer le durcissement de la politique d'exécution de PowerShell (PowerShell Constrained Language Mode) pour limiter les capacités d'encodage et d'exécution de scripts complexes. (D3-PS)
- Surveiller les accès aux fichiers spécifiques comme `C:\travail\malsight_t06.txt` pour détecter toute lecture ou modification non autorisée.

## Incertitudes

- Aucune signalée.
