# Rapport d'analyse : T01_persistance_run.ps1

| Champ | Valeur |
| --- | --- |
| SHA-256 | `fa227aed8895a3786b1bf853bcbc5f43fafbc6fe6854fb65cb6a34476dc1cb6e` |
| MD5 | `a28653ca8cf8274a353b629a62c4d1b6` |
| Type | unknown |
| Taille | 2146 octets |

> Rapport généré par MalSight Agent. **À valider par un analyste avant diffusion.**

## Résumé

L'échantillon, un script PowerShell nommé "T01_persistance_run.ps1", a été observé en exécution. Il a effectué des actions de persistance en modifiant une clé de registre et a créé un fichier local. De plus, il a tenté d'interagir avec un domaine spécifique. Toutes les activités observées proviennent du processus `powershell.exe (7552)` et sont considérées comme des tentatives ou des actions directes de l'échantillon.

## Comportements

| Comportement | Preuve | Statut |
| --- | --- | --- |
| Établir une persistance au démarrage via le registre de l'utilisateur. | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\MalsightTest` | observé |
| Créer un fichier local dans le répertoire de travail. | `C:\travail\malsight_test.txt` | observé |
| Interagir avec un domaine spécifique. | `test.malsight.lab` | observé |

## Indicateurs de compromission (IOC)

| Type | Valeur | Source |
| --- | --- | --- |
| sha256 | `fa227aed8895a3786b1bf853bcbc5f43fafbc6fe6854fb65cb6a34476dc1cb6e` | fichier |
| md5 | `a28653ca8cf8274a353b629a62c4d1b6` | fichier |
| domain | `test.malsight.lab` | extraction |
| file_path | `C:\travail\malsight_test.txt` | extraction |
| registry_key | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\MalsightTest` | extraction |

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
| [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | Registry Run Keys / Startup Folder | persistence, privilege-escalation | medium | HKCU\Software\Microsoft\Windows\CurrentVersion\Run\MalsightTest |

## Contre-mesures D3FEND

- Aucune (aucune technique ATT&CK retenue, ou cache D3FEND absent : `malsight download-d3fend`).

## Recommandations

- Surveiller la création ou la modification des clés de registre de démarrage utilisateur, en particulier dans `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, pour détecter l'ajout de chemins non autorisés (D3-FIM).
- Mettre en place des politiques de contrôle des applications pour restreindre l'exécution de fichiers provenant de chemins non standard ou de dossiers utilisateurs (D3-EAL).
- Surveiller les tentatives d'exécution de fichiers en utilisant des mécanismes de contrôle des applications ou des politiques de sécurité pour bloquer les exécutions suspectes (D3-EDL).
- Surveiller les modifications des fichiers de configuration système et des clés de registre critiques pour détecter toute persistance non autorisée (D3-FIM).
- Analyser les fichiers suspects en utilisant des outils d'analyse de contenu pour identifier les signatures malveillantes avant leur exécution (D3-DA).

## Incertitudes

- Aucune signalée.

## Affirmations rejetées par le vérificateur

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
