# Rapport d'analyse : T11_temoin_negatif.ps1

| Champ | Valeur |
| --- | --- |
| SHA-256 | `412fabad6e7a7f182f34e56502ddd3c4adaef3f8d69333338b2502e600094258` |
| MD5 | `9d45396a8fdc603d82da39de93d48f97` |
| Type | unknown |
| Taille | 1116 octets |

> Rapport généré par MalSight Agent. **À valider par un analyste avant diffusion.**

## Résumé

L'échantillon est un script PowerShell (`T11_temoin_negatif.ps1`) qui a été exécuté. L'activité observée se limite à la création ou la modification d'un fichier dans le répertoire `C:\travail\journal_t11.txt` par le processus `powershell.exe`. Aucune autre activité significative (communication réseau, modification de registre, exécution de processus enfants) n'a été détectée dans les données fournies.

## Comportements

| Comportement | Preuve | Statut |
| --- | --- | --- |
| Écriture de fichier | `C:\travail\journal_t11.txt` | observé |

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

- Surveiller la création de fichiers dans des répertoires spécifiques comme `C:\travail\` pour détecter l'écriture de fichiers non sollicitée (Exemple : journal_t11.txt).
- Surveiller les hachages SHA256 et MD5 connus (412fabad6e7a7f182f34e56502ddd3c4adaef3f8d69333338b2502e600094258, 9d45396a8fdc603d82da39de93d48f97) pour toute exécution ou présence sur le système.
- Mettre en place des politiques de contrôle des applications pour restreindre l'exécution de fichiers provenant de répertoires utilisateurs non standard ou temporaires.

## Incertitudes

- Aucune activité réseau ou de modification de registre n'a été observée, ce qui limite la portée de l'analyse.
