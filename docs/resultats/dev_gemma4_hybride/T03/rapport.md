# Rapport d'analyse : T03_service.ps1

| Champ | Valeur |
| --- | --- |
| SHA-256 | `bd8fd8f188f1c0310a195806b74e512c7fb0eacca6daeadbf2dafa54c2ffa01f` |
| MD5 | `bbe26e04013dda9baceada038738c305` |
| Type | unknown |
| Taille | 942 octets |

> Rapport généré par MalSight Agent. **À valider par un analyste avant diffusion.**

## Résumé

L'échantillon analysé n'a pas d'activité d'exécution directe visible dans les données fournies. Cependant, des modifications de registre ont été observées via `services.exe` (processus système), indiquant une tentative de persistance en créant ou en modifiant un service Windows nommé `MalsightTest`. Cette activité est fortement corrélée à la technique de persistance T1543.003 (Windows Service).

## Comportements

| Comportement | Preuve | Statut |
| --- | --- | --- |
| Création/Modification d'un service Windows pour la persistance | `HKLM\System\CurrentControlSet\Services\MalsightTest` | observé |

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
- Surveiller les modifications des clés de registre de services (ex: HKLM\System\CurrentControlSet\Services\MalsightTest\ImagePath, HKLM\System\CurrentControlSet\Services\MalsightTest\Start) pour détecter des changements non autorisés. (D3-SCP)
- Mettre en place des politiques de durcissement pour restreindre la création de services système non signés ou non documentés dans le registre. (D3-SCP)
- Analyser les artefacts avec les hachages SHA256 (bd8fd8f188f1c0310a195806b74e512c7fb0eacca6daeadbf2dafa54c2ffa01f) et MD5 (bbe26e04013dda9baceada038738c305) pour identifier leur nature et leur comportement connu. (D3-DI)
- Surveiller les tentatives d'écriture ou de modification des clés de registre listées (HKLM\System\CurrentControlSet\Services\MalsightTest\*) pour détecter toute activité suspecte. (D3-SCP)
- Utiliser des règles de détection basées sur les chemins de registre spécifiques (ex: HKLM\System\CurrentControlSet\Services\MalsightTest\*) pour alerter sur la présence de services potentiellement malveillants. (D3-SCP)

## Incertitudes

- L'attribution de l'activité de modification de registre au processus `services.exe (852)` est notée comme 'service_window', ce qui signifie que l'action pourrait être une activité normale du système plutôt qu'une action directe de l'échantillon lui-même. L'échantillon n'a pas été vu exécuter ces commandes de registre directement.
- Aucune activité réseau (connexion établie, résolution DNS) n'a été observée, ce qui limite la compréhension des objectifs de communication de l'échantillon.
