# Rapport d'analyse : T10_telechargement.ps1

| Champ | Valeur |
| --- | --- |
| SHA-256 | `f8a938c6909044c78ef5a18ef7436bb9eedc48c2370c256d0823a8b5c21d7681` |
| MD5 | `ddeb822a26e2e57bca8f7dbbff7e8468` |
| Type | unknown |
| Taille | 1322 octets |

> Rapport généré par MalSight Agent. **À valider par un analyste avant diffusion.**

## Résumé

L'échantillon, exécuté via `powershell.exe`, a principalement interagi avec le registre Windows pour configurer des paramètres de traçage PowerShell (RASAPI32 et RASMANCS). Il a également tenté de communiquer avec le domaine `update.malsight.lab`. Aucune activité de création de fichier, de modification de clé de registre critique, ou de communication réseau réussie n'a été observée. L'activité suggère une tentative de configuration ou de reconnaissance des mécanismes de traçage de PowerShell.

## Comportements

| Comportement | Preuve | Statut |
| --- | --- | --- |
| Configuration des paramètres de traçage PowerShell | `HKLM\Software\Microsoft\Tracing\powershell_RASAPI32` | inféré |
| Tentative de résolution DNS et de connexion à un domaine externe | `update.malsight.lab` | inféré |

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

## Suggestions à valider par l'analyste

Techniques proposées par le modèle de langage, **non retenues dans la liste officielle** (D10 :
les outils classent, le LLM explique). Chacune cite une preuve retrouvée dans le dossier de cas,
mais sa pertinence reste à valider.

| ID | Technique | Tactique | Confiance | Preuve |
| --- | --- | --- | --- | --- |
| [T1566.001](https://attack.mitre.org/techniques/T1566/001/) | Spearphishing Attachment | initial-access | medium | update.malsight.lab |

## Contre-mesures D3FEND

- Aucune (aucune technique ATT&CK retenue, ou cache D3FEND absent : `malsight download-d3fend`).

## Recommandations

- Surveiller les modifications des clés de registre liées au traçage de PowerShell, telles que HKLM\SOFTWARE\Microsoft\Tracing\powershell_RASAPI32\* ou HKLM\SOFTWARE\Microsoft\Tracing\powershell_RASMANCS\*.
- Mettre en place des règles de détection pour les accès aux domaines suspects comme 'update.malsight.lab'.
- Surveiller la création de fichiers dans des chemins inhabituels ou liés à des téléchargements suspects, comme 'C:\travail\outil.txt'.
- Appliquer le principe du moindre privilège pour limiter les droits d'écriture et de modification des clés de registre système liées au traçage.
- Surveiller l'exécution de fichiers provenant de sources externes ou de chemins non standard.

## Incertitudes

- L'activité réseau observée est limitée à une seule entrée de domaine (`update.malsight.lab`) et ne confirme pas une connexion établie ou un transfert de données, ce qui est considéré comme une tentative.
- L'ensemble des modifications de registre concernent des clés de traçage PowerShell, ce qui pourrait être une activité légitime de configuration ou une tentative de persistance/reconnaissance des mécanismes de sécurité.

## Affirmations rejetées par le vérificateur

- ID D3FEND absent du cache retiré d'une recommandation : D3-REG
- ID D3FEND absent du cache retiré d'une recommandation : D3-NET
- ID D3FEND absent du cache retiré d'une recommandation : D3-FILE
- ID D3FEND absent du cache retiré d'une recommandation : D3-PRIV
- ID D3FEND absent du cache retiré d'une recommandation : D3-EXEC
