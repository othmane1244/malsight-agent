# Rapport d'analyse : T08_decouverte_reseau.ps1

| Champ | Valeur |
| --- | --- |
| SHA-256 | `a8957953c905b4f7c069d1f759816f77a93a0334ca0c8436fd91993676a3cf90` |
| MD5 | `2006d0747f6ab9022f05118743b17516` |
| Type | unknown |
| Taille | 1030 octets |

> Rapport généré par MalSight Agent. **À valider par un analyste avant diffusion.**

## Résumé

L'échantillon, un script PowerShell nommé "T08_decouverte_reseau.ps1", exécute plusieurs commandes système standard pour la découverte de réseau. Il exécute `ipconfig.exe`, `route print`, et `arp.exe` pour collecter des informations sur la configuration réseau et la table ARP. De plus, il interagit avec le registre pour créer ou modifier des clés sous `HKLM\SOFTWARE\Microsoft\RFC1156Agent` et écrit un fichier texte nommé `C:\travail\malsight_t08.txt`. Ces actions suggèrent une phase de reconnaissance réseau.

## Comportements

| Comportement | Preuve | Statut |
| --- | --- | --- |
| Exécution de commandes système pour la découverte d'informations réseau. | `Exécution de "C:\Windows\system32\ipconfig.exe" /all par powershell.exe (7472) ; Exécution de "C:\Windows\system32\ROUTE.EXE" print par powershell.exe (7472) ; Exécution de "C:\Windows\system32\ARP.EXE" -a par powershell.exe (7472).` | observé |
| Modification du registre pour créer des clés associées à un agent RFC1156. | `Création/Modification des clés de registre : HKLM\SOFTWARE\Microsoft\RFC1156Agent, HKLM\SOFTWARE\Microsoft\RFC1156Agent\CurrentVersion, HKLM\SOFTWARE\Microsoft\RFC1156Agent\CurrentVersion\Parameters, et HKLM\SOFTWARE\Microsoft\RFC1156Agent\CurrentVersion\Parameters\TrapPollTimeMilliSecs par ARP.EXE (8168).` | observé |
| Écriture d'un fichier de données dans le répertoire de travail. | `Création du fichier "C:\travail\malsight_t08.txt" par powershell.exe (7472).` | observé |

## Indicateurs de compromission (IOC)

| Type | Valeur | Source |
| --- | --- | --- |
| sha256 | `a8957953c905b4f7c069d1f759816f77a93a0334ca0c8436fd91993676a3cf90` | fichier |
| md5 | `2006d0747f6ab9022f05118743b17516` | fichier |
| file_path | `C:\travail\malsight_t08.txt` | extraction |
| registry_key | `HKLM\SOFTWARE\Microsoft\RFC1156Agent` | extraction |
| registry_key | `HKLM\SOFTWARE\Microsoft\RFC1156Agent\CurrentVersion` | extraction |
| registry_key | `HKLM\SOFTWARE\Microsoft\RFC1156Agent\CurrentVersion\Parameters` | extraction |
| registry_key | `HKLM\SOFTWARE\Microsoft\RFC1156Agent\CurrentVersion\Parameters\TrapPollTimeMilliSecs` | extraction |

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

- Surveiller l'exécution de commandes système de découverte d'informations comme `ipconfig.exe` et `route print` (T1082) en analysant les appels système (D3-SCA) pour détecter des séquences inhabituelles ou des processus non autorisés.
- Mettre en place une surveillance des modifications des clés de registre spécifiques telles que `HKLM\SOFTWARE\Microsoft\RFC1156Agent` et ses sous-clés (IOC) pour détecter toute tentative de persistance ou de configuration non désirée.
- Implémenter des politiques de contrôle des applications (Application Whitelisting) pour restreindre l'exécution de binaires non approuvés, ce qui aiderait à contrer l'utilisation de commandes système (D3-EAL).
- Surveiller les tentatives d'accès ou de modification des clés de registre critiques (IOC) en utilisant des mécanismes de surveillance de registre pour détecter les changements non sollicités.
- Pour les processus exécutant des commandes système de découverte (T1082), envisager l'utilisation de mécanismes de détection basés sur le comportement des appels système (D3-SCA) plutôt que sur la simple signature de la commande.

## Incertitudes

- Le rôle exact de l'écriture du fichier "C:\travail\malsight_t08.txt" n'est pas clair sans connaître le contenu ou la destination finale des données collectées.

## Affirmations rejetées par le vérificateur

- Technique sans preuve vérifiable, rejetée : T1082 (aucune valeur reconnaissable)
- Contre-mesure D3-PSA pour une technique non retenue : T1082
- Contre-mesure D3-SCA pour une technique non retenue : T1082
- Contre-mesure D3-EAL pour une technique non retenue : T1082
- Contre-mesure D3-EDL pour une technique non retenue : T1082
- Contre-mesure D3-HBPI pour une technique non retenue : T1082
- Contre-mesure D3-SCF pour une technique non retenue : T1082
- Contre-mesure D3-DE pour une technique non retenue : T1082
