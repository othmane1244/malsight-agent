# Rapport d'analyse : T10_telechargement.ps1

| Champ | Valeur |
| --- | --- |
| SHA-256 | `f8a938c6909044c78ef5a18ef7436bb9eedc48c2370c256d0823a8b5c21d7681` |
| MD5 | `ddeb822a26e2e57bca8f7dbbff7e8468` |
| Type | unknown |
| Taille | 1322 octets |

> Rapport généré par MalSight Agent. **À valider par un analyste avant diffusion.**

## Résumé

L'échantillon, exécuté via `powershell.exe`, a interagi avec le système de fichiers et le registre pour configurer des paramètres de traçage PowerShell. Il a également tenté de communiquer avec un domaine externe. Aucune activité de création de persistance ou d'exécution de code suspect n'a été observée. Les actions se concentrent sur la modification des clés de registre liées au traçage de PowerShell et une tentative de connexion réseau.

## Comportements

| Comportement | Preuve | Statut |
| --- | --- | --- |
| Configuration des paramètres de traçage PowerShell | `HKLM\Software\Microsoft\Tracing\powershell_RASAPI32\EnableFileTracing` | inféré |
| Configuration des paramètres de traçage PowerShell | `HKLM\SOFTWARE\Microsoft\Tracing\powershell_RASAPI32\EnableAutoFileTracing` | inféré |
| Configuration des paramètres de traçage PowerShell | `HKLM\SOFTWARE\Microsoft\Tracing\powershell_RASAPI32\EnableConsoleTracing` | inféré |
| Configuration des paramètres de traçage PowerShell | `HKLM\SOFTWARE\Microsoft\Tracing\powershell_RASAPI32\FileTracingMask` | inféré |
| Configuration des paramètres de traçage PowerShell | `HKLM\SOFTWARE\Microsoft\Tracing\powershell_RASAPI32\ConsoleTracingMask` | inféré |
| Configuration des paramètres de traçage PowerShell | `HKLM\SOFTWARE\Microsoft\Tracing\powershell_RASAPI32\MaxFileSize` | inféré |
| Configuration des paramètres de traçage PowerShell | `HKLM\SOFTWARE\Microsoft\Tracing\powershell_RASAPI32\FileDirectory` | inféré |
| Configuration des paramètres de traçage PowerShell | `HKLM\SOFTWARE\Microsoft\Tracing\powershell_RASMANCS\EnableFileTracing` | inféré |
| Configuration des paramètres de traçage PowerShell | `HKLM\SOFTWARE\Microsoft\Tracing\powershell_RASMANCS\EnableAutoFileTracing` | inféré |
| Configuration des paramètres de traçage PowerShell | `HKLM\SOFTWARE\Microsoft\Tracing\powershell_RASMANCS\EnableConsoleTracing` | inféré |
| Configuration des paramètres de traçage PowerShell | `HKLM\SOFTWARE\Microsoft\Tracing\powershell_RASMANCS\FileTracingMask` | inféré |
| Configuration des paramètres de traçage PowerShell | `HKLM\SOFTWARE\Microsoft\Tracing\powershell_RASMANCS\ConsoleTracingMask` | inféré |
| Configuration des paramètres de traçage PowerShell | `HKLM\SOFTWARE\Microsoft\Tracing\powershell_RASMANCS\MaxFileSize` | inféré |
| Configuration des paramètres de traçage PowerShell | `HKLM\SOFTWARE\Microsoft\Tracing\powershell_RASMANCS\FileDirectory` | inféré |
| Tentative de communication réseau avec un domaine externe | `update.malsight.lab` | inféré |

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

- Aucune.

## Contre-mesures D3FEND

- Aucune (aucune technique ATT&CK retenue, ou cache D3FEND absent : `malsight download-d3fend`).

## Recommandations

- Surveiller les modifications des clés de registre de démarrage ou des clés de registre système (ex: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run) pour détecter l'ajout de chemins ou de valeurs non autorisés (D3-FIM).
- Mettre en place des règles de détection (Sysmon/Sigma) pour surveiller les tentatives d'écriture de fichiers dans des répertoires sensibles ou des chemins de démarrage (D3-FIM).
- Durcir les politiques de registre pour limiter les modifications des clés de traçage PowerShell (ex: HKLM\SOFTWARE\Microsoft\Tracing\*) pour empêcher la modification des paramètres de traçage (D3-SICA).
- Analyser les processus qui accèdent ou modifient les clés de registre liées au traçage de PowerShell (ex: HKLM\SOFTWARE\Microsoft\Tracing\*) pour identifier des comportements anormaux (D3-DA).
- Bloquer ou restreindre l'accès réseau aux domaines ou adresses IP non reconnus ou non nécessaires, en particulier pour les domaines observés comme 'update.malsight.lab' (D3-CF).
- Appliquer le principe du moindre privilège pour limiter les droits d'écriture des utilisateurs et des processus sur les clés de registre système critiques (D3-LFP).

## Incertitudes

- L'activité réseau observée est une tentative de résolution DNS pour 'update.malsight.lab' et ne confirme pas une communication établie ou des données échangées.

## Affirmations rejetées par le vérificateur

- Suggestion couverte par une règle D7 qui ne s'est pas déclenchée, rejetée : T1547.001
- Contre-mesure D3-FE pour une technique non retenue : T1547.001
- Contre-mesure D3-DA pour une technique non retenue : T1547.001
- Contre-mesure D3-EFA pour une technique non retenue : T1547.001
- Contre-mesure D3-FA pour une technique non retenue : T1547.001
- Contre-mesure D3-FIM pour une technique non retenue : T1547.001
- Contre-mesure D3-SICA pour une technique non retenue : T1547.001
- Contre-mesure D3-CF pour une technique non retenue : T1547.001
- Contre-mesure D3-CM pour une technique non retenue : T1547.001
- Contre-mesure D3-CQ pour une technique non retenue : T1547.001
- Contre-mesure D3-EAL pour une technique non retenue : T1547.001
- Contre-mesure D3-EDL pour une technique non retenue : T1547.001
- Contre-mesure D3-LFP pour une technique non retenue : T1547.001
