# Rapport d'analyse : T10_telechargement.ps1

| Champ | Valeur |
| --- | --- |
| SHA-256 | `f8a938c6909044c78ef5a18ef7436bb9eedc48c2370c256d0823a8b5c21d7681` |
| MD5 | `ddeb822a26e2e57bca8f7dbbff7e8468` |
| Type | unknown |
| Taille | 1322 octets |

> Rapport généré par MalSight Agent. **À valider par un analyste avant diffusion.**

## Résumé

Rapport généré sans LLM : faits extraits uniquement.

## Comportements

| Comportement | Preuve | Statut |
| --- | --- | --- |

## Indicateurs de compromission (IOC)

| Type | Valeur | Source |
| --- | --- | --- |
| sha256 | `f8a938c6909044c78ef5a18ef7436bb9eedc48c2370c256d0823a8b5c21d7681` | fichier |
| md5 | `ddeb822a26e2e57bca8f7dbbff7e8468` | fichier |
| url | `http://update.malsight.lab/outil.txt` | extraction |
| domain | `update.malsight.lab` | extraction |
| file_path | `C:\travail\outil.txt` | extraction |
| registry_key | `HKLM\SOFTWARE\Microsoft\Tracing\powershell_RASAPI32\ConsoleTracingMask` | extraction |
| registry_key | `HKLM\SOFTWARE\Microsoft\Tracing\powershell_RASAPI32\EnableAutoFileTracing` | extraction |
| registry_key | `HKLM\SOFTWARE\Microsoft\Tracing\powershell_RASAPI32\EnableConsoleTracing` | extraction |
| registry_key | `HKLM\SOFTWARE\Microsoft\Tracing\powershell_RASAPI32\EnableFileTracing` | extraction |
| registry_key | `HKLM\SOFTWARE\Microsoft\Tracing\powershell_RASAPI32\FileDirectory` | extraction |
| registry_key | `HKLM\SOFTWARE\Microsoft\Tracing\powershell_RASAPI32\FileTracingMask` | extraction |
| registry_key | `HKLM\SOFTWARE\Microsoft\Tracing\powershell_RASAPI32\MaxFileSize` | extraction |
| registry_key | `HKLM\SOFTWARE\Microsoft\Tracing\powershell_RASMANCS\ConsoleTracingMask` | extraction |
| registry_key | `HKLM\SOFTWARE\Microsoft\Tracing\powershell_RASMANCS\EnableAutoFileTracing` | extraction |
| registry_key | `HKLM\SOFTWARE\Microsoft\Tracing\powershell_RASMANCS\EnableConsoleTracing` | extraction |
| registry_key | `HKLM\SOFTWARE\Microsoft\Tracing\powershell_RASMANCS\EnableFileTracing` | extraction |
| registry_key | `HKLM\SOFTWARE\Microsoft\Tracing\powershell_RASMANCS\FileDirectory` | extraction |
| registry_key | `HKLM\SOFTWARE\Microsoft\Tracing\powershell_RASMANCS\FileTracingMask` | extraction |
| registry_key | `HKLM\SOFTWARE\Microsoft\Tracing\powershell_RASMANCS\MaxFileSize` | extraction |
| registry_key | `HKLM\Software\Microsoft\Tracing\powershell_RASAPI32` | extraction |
| registry_key | `HKLM\Software\Microsoft\Tracing\powershell_RASMANCS` | extraction |

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

- Aucune signalée.
