# Rapport d'analyse : T03_service.ps1

| Champ | Valeur |
| --- | --- |
| SHA-256 | `bd8fd8f188f1c0310a195806b74e512c7fb0eacca6daeadbf2dafa54c2ffa01f` |
| MD5 | `bbe26e04013dda9baceada038738c305` |
| Type | unknown |
| Taille | 942 octets |

> Rapport généré par MalSight Agent. **À valider par un analyste avant diffusion.**

## Résumé

L'échantillon analysé n'a pas d'activité d'exécution directe visible dans les données fournies. Cependant, des modifications de registre ont été observées via `services.exe` (processus système) qui consistent à créer et configurer un service Windows nommé `MalsightTest`. Cette action est une technique de persistance visant à faire exécuter un payload en arrière-plan au démarrage du système.

## Comportements

| Comportement | Preuve | Statut |
| --- | --- | --- |
| Création et configuration d'un service Windows pour la persistance. | `HKLM\System\CurrentControlSet\Services\MalsightTest (Création de la clé de service), HKLM\System\CurrentControlSet\Services\MalsightTest\Type, HKLM\System\CurrentControlSet\Services\MalsightTest\Start, HKLM\System\CurrentControlSet\Services\MalsightTest\ErrorControl, HKLM\System\CurrentControlSet\Services\MalsightTest\ImagePath, HKLM\System\CurrentControlSet\Services\MalsightTest\DisplayName, HKLM\System\CurrentControlSet\Services\MalsightTest\ObjectName` | observé |

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

## Contre-mesures D3FEND

Contre-mesures défensives [MITRE D3FEND](https://d3fend.mitre.org) associées aux techniques
ATT&CK retenues (source : d3fend, cache local ; IDs vérifiés).

| Technique ATT&CK | Contre-mesure D3FEND | Tactique | Artefact |
| --- | --- | --- | --- |
| [T1543.003](https://attack.mitre.org/techniques/T1543/003/) | [D3-SCP System Configuration Permissions](https://d3fend.mitre.org/technique/d3f:SystemConfigurationPermissions/) | Harden | System Configuration Database |
| [T1543.003](https://attack.mitre.org/techniques/T1543/003/) | [D3-RD Restore Database](https://d3fend.mitre.org/technique/d3f:RestoreDatabase/) | Restore | Database |
| [T1543.003](https://attack.mitre.org/techniques/T1543/003/) | [D3-DI Data Inventory](https://d3fend.mitre.org/technique/d3f:DataInventory/) | Model | Database |

## Recommandations

- Surveiller la création ou la modification de services système dans les chemins critiques comme HKLM\System\CurrentControlSet\Services, en particulier les clés nommées 'MalsightTest'. (D3-SCP)
- Détecter toute tentative de modification des clés de registre associées à la définition d'un service (ex: HKLM\System\CurrentControlSet\Services\MalsightTest\ImagePath, HKLM\System\CurrentControlSet\Services\MalsightTest\Start), car ces modifications sont typiques de l'établissement de persistance via des services. (D3-SCP)
- Surveiller l'exécution de processus depuis des chemins inhabituels ou non standard pour les services système, comme l'utilisation de 'services.exe' avec des arguments ou des chemins non attendus. (D3-SCP)
- Utiliser des règles de détection basées sur les hachages SHA256 (bd8fd8f188f1c0310a195806b74e512c7fb0eacca6daeadbf2dafa54c2ffa01f) et MD5 (bbe26e04013dda9baceada038738c305) pour bloquer l'exécution de fichiers connus. (D3-DI)
- Mettre en place des politiques de durcissement pour restreindre les droits d'écriture sur les clés de registre système critiques (HKLM\System\CurrentControlSet\Services), limitant ainsi la capacité d'un processus non autorisé à créer ou modifier des services. (D3-SCP)
- Surveiller les événements de création de tâches planifiées ou de services qui pointent vers des exécutables suspects ou qui modifient des clés de registre système de manière non standard. (D3-SCP)

## Incertitudes

- L'activité observée (création de service) est attribuée à `services.exe` (processus système) et non directement à l'exécutable de l'échantillon, ce qui rend difficile de déterminer si l'échantillon a initié cette action ou si elle est une activité de fond du système.
