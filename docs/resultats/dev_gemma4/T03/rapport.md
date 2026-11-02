# Rapport d'analyse : T03_service.ps1

| Champ | Valeur |
| --- | --- |
| SHA-256 | `bd8fd8f188f1c0310a195806b74e512c7fb0eacca6daeadbf2dafa54c2ffa01f` |
| MD5 | `bbe26e04013dda9baceada038738c305` |
| Type | unknown |
| Taille | 942 octets |

> Rapport généré par MalSight Agent. **À valider par un analyste avant diffusion.**

## Résumé

L'échantillon est un script PowerShell (`T03_service.ps1`) qui interagit avec le système d'exploitation en modifiant des clés de registre pour créer ou configurer un service système nommé `MalsightTest`. Aucune activité réseau, création de processus ou modification de fichiers n'a été observée dans les données fournies. L'activité principale est la persistance via le registre.

## Comportements

| Comportement | Preuve | Statut |
| --- | --- | --- |
| Modification du registre pour la persistance de service. | `HKLM\System\CurrentControlSet\Services\MalsightTest` | observé |

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

## Contre-mesures D3FEND

- Aucune (aucune technique ATT&CK retenue, ou cache D3FEND absent : `malsight download-d3fend`).

## Recommandations


## Incertitudes

- Aucune activité réseau, processus ou fichier n'a été observée, ce qui limite la compréhension complète du comportement de l'échantillon.

## Affirmations rejetées par le vérificateur

- Recommandation citant un ID D3FEND absent du cache (D3-REG) : Surveiller la création ou la modification des clés de registre suivantes : HKLM\System\CurrentControlSet\Services\MalsightTest, HKLM\System\CurrentControlSet\Services\MalsightTest\DisplayName, HKLM\System\CurrentControlSet\Services\MalsightTest\ErrorControl, HKLM\System\CurrentControlSet\Services\MalsightTest\ImagePath, HKLM\System\CurrentControlSet\Services\MalsightTest\ObjectName, HKLM\System\CurrentControlSet\Services\MalsightTest\Start, et HKLM\System\CurrentControlSet\Services\MalsightTest\Type. (D3-REG)
- Recommandation citant un ID D3FEND absent du cache (D3-FILE) : Surveiller l'écriture de fichiers avec les hachages SHA256 : bd8fd8f188f1c0310a195806b74e512c7fb0eacca6daeadbf2dafa54c2ffa01f et MD5 : bbe26e04013dda9baceada038738c305. (D3-FILE)
- Recommandation citant un ID D3FEND absent du cache (D3-PRIV) : Appliquer le principe du moindre privilège pour limiter les droits d'écriture dans les clés de registre système critiques, en particulier dans HKLM\System\CurrentControlSet\Services. (D3-PRIV)
- Recommandation citant un ID D3FEND absent du cache (D3-SVC) : Surveiller les tentatives de modification des services système (création/modification de clés sous HKLM\System\CurrentControlSet\Services) pour détecter des changements non autorisés. (D3-SVC)
