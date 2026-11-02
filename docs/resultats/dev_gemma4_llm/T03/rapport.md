# Rapport d'analyse : T03_service.ps1

| Champ | Valeur |
| --- | --- |
| SHA-256 | `bd8fd8f188f1c0310a195806b74e512c7fb0eacca6daeadbf2dafa54c2ffa01f` |
| MD5 | `bbe26e04013dda9baceada038738c305` |
| Type | unknown |
| Taille | 942 octets |

> Rapport généré par MalSight Agent. **À valider par un analyste avant diffusion.**

## Résumé

L'échantillon analysé, nommé T03_service.ps1, n'a pas d'appels d'API sensibles ni de règles CAPA détectées. L'activité observée se limite à la modification du registre système par le processus `services.exe` (852), qui crée et configure un nouveau service nommé `MalsightTest`. Ce comportement est une tentative de persistance système.

## Comportements

| Comportement | Preuve | Statut |
| --- | --- | --- |
| Création et configuration d'un service système persistant | `HKLM\System\CurrentControlSet\Services\MalsightTest` | inféré |

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
| [T1543.003](https://attack.mitre.org/techniques/T1543/003/) | Windows Service | persistence, privilege-escalation | llm | medium | Création de la clé de registre HKLM\System\CurrentControlSet\Services\MalsightTest et définition de ses sous-clés (Type, Start, ImagePath, etc.) par services.exe. |

## Contre-mesures D3FEND

Contre-mesures défensives [MITRE D3FEND](https://d3fend.mitre.org) associées aux techniques
ATT&CK retenues (source : d3fend, cache local ; IDs vérifiés).

| Technique ATT&CK | Contre-mesure D3FEND | Tactique | Artefact |
| --- | --- | --- | --- |
| [T1543.003](https://attack.mitre.org/techniques/T1543/003/) | [D3-SCP System Configuration Permissions](https://d3fend.mitre.org/technique/d3f:SystemConfigurationPermissions/) | Harden | System Configuration Database |
| [T1543.003](https://attack.mitre.org/techniques/T1543/003/) | [D3-RD Restore Database](https://d3fend.mitre.org/technique/d3f:RestoreDatabase/) | Restore | Database |
| [T1543.003](https://attack.mitre.org/techniques/T1543/003/) | [D3-DI Data Inventory](https://d3fend.mitre.org/technique/d3f:DataInventory/) | Model | Database |

## Recommandations

- Surveiller la création de clés de registre sous HKLM\System\CurrentControlSet\Services, en particulier celles qui définissent un `ImagePath` pointant vers des exécutables non standards ou des chemins inhabituels. (D3-SCP)
- Surveiller les appels API ou les événements de création de services Windows (ex: `CreateService`) qui modifient des clés de registre critiques comme HKLM\System\CurrentControlSet\Services. (D3-SCP)
- Mettre en place des règles de détection (ex: Sysmon Event ID 12/13) pour alerter sur la création de services avec des noms suspects ou des chemins d'exécution non autorisés. (D3-SCP)
- Durcir les permissions de modification des clés de registre critiques du système (HKLM\System\CurrentControlSet\Services) pour limiter qui peut y écrire. (D3-SCP)
- Analyser les changements de configuration système (Registry/File System) pour détecter des modifications non sollicitées des services système. (D3-DI)

## Incertitudes

- L'attribution de l'écriture des clés de registre au processus `services.exe` (852) est notée comme 'service_window', ce qui suggère que l'activité pourrait être une activité de fond de Windows plutôt qu'une action directe de l'échantillon. Cependant, l'ensemble des modifications est cohérent avec une tentative de persistance.
- Aucune preuve d'exécution directe de l'échantillon est visible dans les appels d'API ou les processus enfants, rendant difficile de déterminer si l'échantillon a initié cette modification ou si elle est le résultat d'un contexte système.
