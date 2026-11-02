# Rapport d'analyse : T11_temoin_negatif.ps1

| Champ | Valeur |
| --- | --- |
| SHA-256 | `412fabad6e7a7f182f34e56502ddd3c4adaef3f8d69333338b2502e600094258` |
| MD5 | `9d45396a8fdc603d82da39de93d48f97` |
| Type | unknown |
| Taille | 1116 octets |

> Rapport généré par MalSight Agent. **À valider par un analyste avant diffusion.**

## Résumé

L'échantillon est un script PowerShell (`T11_temoin_negatif.ps1`) qui a été exécuté. L'activité observée se limite à la création ou la modification d'un fichier local. Aucune activité réseau, modification de registre, ou exécution de processus enfant n'a été détectée. Le script écrit un fichier nommé `journal_t11.txt` dans le répertoire `C:\travail\`.

## Comportements

| Comportement | Preuve | Statut |
| --- | --- | --- |
| Écriture d'un fichier local | `C:\travail\journal_t11.txt` | observé |

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

- Surveiller la création de fichiers dans des répertoires spécifiques comme `C:\travail\` pour détecter des écritures de données non sollicitées. (Aucun identifiant D3FEND spécifique)
- Surveiller les hachages SHA256 et MD5 connus (ex: `412fabad6e7a7f182f34e56502ddd3c4adaef3f8d69333338b2502e600094258`, `9d45396a8fdc603d82da39de93d48f97`) pour bloquer l'exécution de fichiers malveillants connus.
- Mettre en place des politiques de contrôle des répertoires pour restreindre l'écriture de fichiers dans des chemins non essentiels comme `C:\travail\`.

## Incertitudes

- Aucune signalée.
