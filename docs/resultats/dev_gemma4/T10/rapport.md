# Rapport d'analyse : T10_telechargement.ps1

| Champ | Valeur |
| --- | --- |
| SHA-256 | `f8a938c6909044c78ef5a18ef7436bb9eedc48c2370c256d0823a8b5c21d7681` |
| MD5 | `ddeb822a26e2e57bca8f7dbbff7e8468` |
| Type | unknown |
| Taille | 1322 octets |

> Rapport généré par MalSight Agent. **À valider par un analyste avant diffusion.**

## Résumé

L'échantillon est un script PowerShell nommé "T10_telechargement.ps1". Son activité observée principale consiste à modifier des clés de registre liées au traçage de PowerShell, spécifiquement sous les chemins `HKLM\Software\Microsoft\Tracing\powershell_RASAPI32` et `HKLM\SOFTWARE\Microsoft\Tracing\powershell_RASMANCS`. Il tente également de communiquer avec le domaine `update.malsight.lab` via une URL `http://update.malsight.lab/outil.txt`. Aucune exécution de processus ou activité réseau réussie n'est confirmée, mais les modifications de registre et les tentatives de connexion sont notables.

## Comportements

| Comportement | Preuve | Statut |
| --- | --- | --- |
| Modification des paramètres de traçage de PowerShell. | `HKLM\Software\Microsoft\Tracing\powershell_RASAPI32` | observé |
| Modification des paramètres de traçage de PowerShell (second ensemble de clés). | `HKLM\SOFTWARE\Microsoft\Tracing\powershell_RASMANCS` | observé |
| Tentative de communication réseau avec un domaine spécifique. | `update.malsight.lab` | observé |

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
| [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | Web Protocols | command-and-control | llm | medium | update.malsight.lab |

## Contre-mesures D3FEND

- Aucune (aucune technique ATT&CK retenue, ou cache D3FEND absent : `malsight download-d3fend`).

## Recommandations


## Incertitudes

- L'activité réseau observée est limitée à un domaine (`update.malsight.lab`) et ne confirme pas une connexion établie ou un transfert de données, ce qui est considéré comme une tentative.
- Aucune API spécifique n'est listée dans `top_api_calls` ou `sensitive_apis`, rendant difficile la caractérisation des appels système précis.

## Affirmations rejetées par le vérificateur

- Recommandation citant un ID D3FEND absent du cache (D3-REG) : Surveiller les modifications des clés de registre liées au traçage de PowerShell, telles que HKLM\SOFTWARE\Microsoft\Tracing\powershell_RASAPI32\* ou HKLM\SOFTWARE\Microsoft\Tracing\powershell_RASMANCS\* (D3-REG).
- Recommandation citant un ID D3FEND absent du cache (D3-FILE) : Mettre en place des règles de détection pour les accès ou modifications des fichiers dans le chemin C:\travail\ (D3-FILE).
- Recommandation citant un ID D3FEND absent du cache (D3-NET) : Surveiller les connexions sortantes vers le domaine update.malsight.lab (D3-NET).
- Recommandation citant un ID D3FEND absent du cache (D3-DNS) : Bloquer ou surveiller les requêtes DNS pour le domaine update.malsight.lab (D3-DNS).
- Recommandation citant un ID D3FEND absent du cache (D3-REG) : Appliquer le principe du moindre privilège pour limiter les droits d'écriture et de modification des clés de registre de traçage de PowerShell (D3-REG).
- Recommandation citant un ID D3FEND absent du cache (D3-SCRIPT) : Surveiller l'exécution de scripts utilisant des protocoles web (T1071.001) en contexte de travail suspect (D3-SCRIPT).
