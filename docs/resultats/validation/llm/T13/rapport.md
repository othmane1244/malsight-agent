# Rapport d'analyse : T13_persistance_runonce.ps1

| Champ | Valeur |
| --- | --- |
| SHA-256 | `7d4711b61bbb454c40becacb4d4d977c58d2a53dada7719ba2295466a30debd3` |
| MD5 | `c27481a7da976f92a8326eb38db40d83` |
| Type | unknown |
| Taille | 1307 octets |

> Rapport généré par MalSight Agent. **À valider par un analyste avant diffusion.**

## Résumé

L'échantillon est un script PowerShell nommé "T13_persistance_runonce.ps1". Son comportement observé se limite à la modification du registre pour établir une persistance au démarrage de l'utilisateur actuel. Il écrit une clé de registre sous `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce` avec la valeur `MalsightTest13` via `powershell.exe`. Aucune activité réseau, appel API sensible ou autre comportement malveillant n'a été observé.

## Comportements

| Comportement | Preuve | Statut |
| --- | --- | --- |
| Établir une persistance au démarrage de l'utilisateur via la clé RunOnce du registre. | `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce\MalsightTest13` | inféré |

## Indicateurs de compromission (IOC)

| Type | Valeur | Source |
| --- | --- | --- |
| sha256 | `7d4711b61bbb454c40becacb4d4d977c58d2a53dada7719ba2295466a30debd3` | fichier |
| md5 | `c27481a7da976f92a8326eb38db40d83` | fichier |
| registry_key | `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce` | extraction |
| registry_key | `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce\MalsightTest13` | extraction |

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
| [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | Registry Run Keys / Startup Folder | persistence, privilege-escalation | medium | HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce |

## Contre-mesures D3FEND

- Aucune (aucune technique ATT&CK retenue, ou cache D3FEND absent : `malsight download-d3fend`).

## Recommandations

- Surveiller la création ou la modification des clés de registre dans les chemins de démarrage utilisateur, tels que `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`, pour détecter des exécutions potentiellement indésirables.
- Mettre en place des règles de détection (YARA/Sigma) basées sur les hachages SHA256 (`7d4711b61bbb454c40becacb4d4d977c58d2a53dada7719ba2295466a30debd3`) et MD5 (`c27481a7da976f92a8326eb38db40d83`) pour identifier l'échantillon lors de l'exécution.
- Durcir les politiques de sécurité pour limiter l'écriture dans les clés de registre de démarrage utilisateur (`HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`) aux processus de confiance connus.
- Surveiller les appels API liés à la modification du registre pour détecter toute tentative d'écriture dans les chemins de démarrage système ou utilisateur.

## Incertitudes

- Le script est exécuté par `powershell.exe (7772)` qui est l'attribution de l'action, mais la nature exacte de l'exécution (manuelle, planifiée, etc.) n'est pas précisée.

## Affirmations rejetées par le vérificateur

- ID D3FEND absent du cache retiré d'une recommandation : D3-RSC
- ID D3FEND absent du cache retiré d'une recommandation : D3-HSH
- ID D3FEND absent du cache retiré d'une recommandation : D3-REG
- ID D3FEND absent du cache retiré d'une recommandation : D3-API
