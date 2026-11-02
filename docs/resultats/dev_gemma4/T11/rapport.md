# Rapport d'analyse : T11_temoin_negatif.ps1

| Champ | Valeur |
| --- | --- |
| SHA-256 | `412fabad6e7a7f182f34e56502ddd3c4adaef3f8d69333338b2502e600094258` |
| MD5 | `9d45396a8fdc603d82da39de93d48f97` |
| Type | unknown |
| Taille | 1116 octets |

> Rapport généré par MalSight Agent. **À valider par un analyste avant diffusion.**

## Résumé

L'échantillon est un script PowerShell nommé "T11_temoin_negatif.ps1". L'analyse dynamique montre qu'il écrit un fichier nommé "journal_t11.txt" dans le répertoire "C:\travail\". Aucune activité réseau, aucune modification de registre, ni création de processus n'ont été observées. L'analyse statique indique zéro importation de bibliothèques, zéro règle CAPA et zéro appel d'API sensible.

## Comportements

| Comportement | Preuve | Statut |
| --- | --- | --- |
| Écriture de fichier | `files_written: ["C:\travail\journal_t11.txt"]` | observé |

## Indicateurs de compromission (IOC)

| Type | Valeur | Source |
| --- | --- | --- |
| sha256 | `412fabad6e7a7f182f34e56502ddd3c4adaef3f8d69333338b2502e600094258` | fichier |
| md5 | `9d45396a8fdc603d82da39de93d48f97` | fichier |
| file_path | `C:\travail\journal_t11.txt` | extraction |

## API sensibles

| API | Catégorie | Source |
| --- | --- | --- |

## Techniques MITRE ATT&CK

| ID | Technique | Tactique | Source | Confiance | Preuve |
| --- | --- | --- | --- | --- | --- |

## Contre-mesures D3FEND

- Aucune (aucune technique ATT&CK retenue, ou cache D3FEND absent : `malsight download-d3fend`).

## Recommandations

- Surveiller la création ou la modification de fichiers dans le répertoire `C:\travail\` pour détecter l'écriture de fichiers spécifiques comme `journal_t11.txt`.
- Surveiller l'utilisation de hachages connus (SHA256: `412fabad6e7a7f182f34e56502ddd3c4adaef3f8d69333338b2502e600094258`, MD5: `9d45396a8fdc603d82da39de93d48f97`) dans les journaux d'événements ou les systèmes de détection pour identifier des artefacts potentiels.
- Mettre en place des politiques de contrôle des répertoires pour restreindre l'écriture de fichiers dans des dossiers utilisateurs non essentiels, comme `C:\travail\`.

## Incertitudes

- Aucune activité réseau, de registre ou de processus n'a été observée, ce qui limite la compréhension du comportement complet de l'échantillon.
