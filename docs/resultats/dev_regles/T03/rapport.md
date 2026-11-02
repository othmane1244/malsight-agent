# Rapport d'analyse : T03_service.ps1

| Champ | Valeur |
| --- | --- |
| SHA-256 | `bd8fd8f188f1c0310a195806b74e512c7fb0eacca6daeadbf2dafa54c2ffa01f` |
| MD5 | `bbe26e04013dda9baceada038738c305` |
| Type | unknown |
| Taille | 942 octets |

> Rapport généré par MalSight Agent. **À valider par un analyste avant diffusion.**

## Résumé

Rapport généré sans LLM : faits extraits uniquement.

## Comportements

| Comportement | Preuve | Statut |
| --- | --- | --- |

## Indicateurs de compromission (IOC)

| Type | Valeur | Source |
| --- | --- | --- |
| sha256 | `bd8fd8f188f1c0310a195806b74e512c7fb0eacca6daeadbf2dafa54c2ffa01f` | fichier |
| md5 | `bbe26e04013dda9baceada038738c305` | fichier |
| registry_key | `HKLM\System\CurrentControlSet\Services\MalsightTest` | extraction |
| registry_key | `HKLM\System\CurrentControlSet\Services\MalsightTest\DisplayName` | extraction |
| registry_key | `HKLM\System\CurrentControlSet\Services\MalsightTest\ErrorControl` | extraction |
| registry_key | `HKLM\System\CurrentControlSet\Services\MalsightTest\ImagePath` | extraction |
| registry_key | `HKLM\System\CurrentControlSet\Services\MalsightTest\ObjectName` | extraction |
| registry_key | `HKLM\System\CurrentControlSet\Services\MalsightTest\Start` | extraction |
| registry_key | `HKLM\System\CurrentControlSet\Services\MalsightTest\Type` | extraction |

## API sensibles

| API | Catégorie | Source |
| --- | --- | --- |

## Techniques MITRE ATT&CK

| ID | Technique | Tactique | Source | Confiance | Preuve |
| --- | --- | --- | --- | --- | --- |
| [T1543.003](https://attack.mitre.org/techniques/T1543/003/) | Windows Service | persistence, privilege-escalation | rule | high | règle R-T1543.003-registre : HKLM\System\CurrentControlSet\Services\MalsightTest\ImagePath (services.exe (852)) |

## Suggestions à valider par l'analyste

- Aucune.

## Contre-mesures D3FEND

Contre-mesures défensives [MITRE D3FEND](https://d3fend.mitre.org) associées aux techniques
ATT&CK retenues (source : d3fend, cache local ; IDs vérifiés).

| Technique ATT&CK | Contre-mesure D3FEND | Tactique | Artefact |
| --- | --- | --- | --- |
| [T1543.003](https://attack.mitre.org/techniques/T1543/003/) | [D3-SCP System Configuration Permissions](https://d3fend.mitre.org/technique/d3f:SystemConfigurationPermissions/) | Harden | System Configuration Database |
| [T1543.003](https://attack.mitre.org/techniques/T1543/003/) | [D3-RD Restore Database](https://d3fend.mitre.org/technique/d3f:RestoreDatabase/) | Restore | Database |
| [T1543.003](https://attack.mitre.org/techniques/T1543/003/) | [D3-DI Data Inventory](https://d3fend.mitre.org/technique/d3f:DataInventory/) | Model | Database |

## Recommandations


## Incertitudes

- Aucune signalée.
