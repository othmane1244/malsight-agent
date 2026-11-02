# Laboratoire isolé

> Décision actuelle (voir [`docs/decisions.md`](../docs/decisions.md), D1) : le labo démarre avec
> **Windows Sandbox seul**. L'ajout de VirtualBox + INetSim sera décidé au jalon J2.

## Contenu

| Fichier | Rôle |
| --- | --- |
| `analyse.wsb` | Configuration Windows Sandbox : réseau, vGPU et presse-papiers coupés, dossiers mappés |
| `scripts/verifier-prerequis.ps1` | À lancer **sur l'hôte** avant `analyse.wsb` : outils, config Sysmon, scripts à jour, résultats vidés |
| `scripts/setup-sandbox.ps1` | Lancé au démarrage de la sandbox : ExecutionPolicy, `C:\travail`, Sysmon, Procmon (capture locale), consignes ; erreur visible en rouge |
| `sysmon-malsight.xml` | Règles Sysmon maison (événement 11 dans `C:\travail\`), fusionnées dans la config SwiftOnSecurity |
| `scripts/Merge-SysmonConfig.ps1` | Fusion des règles maison dans la config Sysmon de base (appelé par `setup-sandbox.ps1`) |
| `scripts/collect.ps1` | Lancé après l'exécution : arrête Procmon et attend sa fin, convertit le PML en local, exporte Sysmon (EVTX + CSV), copie le tout dans les résultats |
| `scripts/lancer-analyse.ps1` | **Mode automatique** (D3), sur l'hôte : un échantillon de test de bout en bout |
| `scripts/analyse-auto.ps1` | Mode automatique, dans la sandbox : setup, exécution, attente, collecte, extinction |

Aucun outil, échantillon ni journal n'est versionné : tout vit dans `C:\labo`, hors du dépôt.

## Prérequis (une seule fois)

1. Windows 11 Pro avec la fonctionnalité **Windows Sandbox** activée.
2. Créer l'arborescence hors du dépôt :

   ```text
   C:\labo\entree\outils      Sysmon, Procmon, sysmonconfig-export.xml
   C:\labo\entree\scripts     copie de lab/scripts/*.ps1 et lab/sysmon-malsight.xml
   C:\labo\entree\samples     échantillons BÉNINS uniquement (docs/ethique.md)
   C:\labo\resultats          journaux exportés (seul dossier en écriture)
   ```

3. Télécharger depuis les sites officiels et extraire dans `C:\labo\entree\outils` :
   - [Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon) (`Sysmon64.exe`)
   - [Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon) (`Procmon64.exe`)
   - [`sysmonconfig-export.xml`](https://github.com/SwiftOnSecurity/sysmon-config) (SwiftOnSecurity)
4. Copier les scripts du dépôt (à refaire après chaque modification des scripts) :

   ```powershell
   New-Item -ItemType Directory -Force C:\labo\entree\scripts
   Copy-Item .\lab\scripts\*.ps1, .\lab\sysmon-malsight.xml C:\labo\entree\scripts\ -Force
   ```

5. Échantillons de test de l'équipe, T01 à T12 (liste dans
   [`echantillons-test/README.md`](echantillons-test/README.md), vérité terrain dans
   `lab/verite-terrain/`) : les copier tous avec
   `Copy-Item .\lab\echantillons-test\T*.ps1 C:\labo\entree\samples\ -Force`,
   puis dans la sandbox lancer **un seul échantillon par session**, par exemple
   `& C:\travail\T01_persistance_run.ps1` (la fenêtre de `setup-sandbox.ps1` a déjà
   ExecutionPolicy Bypass).

## Mode automatique (échantillons de test, décision D3)

Pour un échantillon de `lab/echantillons-test/` ayant une vérité terrain, depuis la racine
du dépôt, sur l'hôte :

```powershell
.\lab\scripts\lancer-analyse.ps1 -Echantillon T02            # attente de 90 s par défaut
.\lab\scripts\lancer-analyse.ps1 -Echantillon T02 -SansLancer # vérifie et génère le .wsb seulement
```

Le script refuse tout identifiant qui ne correspond pas à exactement un script `Tnn_*.ps1`
avec sa vérité terrain. Il copie scripts et échantillon dans `C:\labo\entree`, vérifie les
prérequis, ouvre une sandbox (mêmes restrictions que `analyse.wsb`) qui prépare Sysmon/Procmon,
exécute l'échantillon dans un processus séparé, attend 90 s, collecte, écrit `auto.json`
(PID et code de sortie de l'échantillon) puis s'éteint. Sur l'hôte, le script attend le
dossier de résultats (15 min au plus) et affiche son chemin. En cas d'erreur, la sandbox
reste ouverte et le journal est dans `C:\labo\resultats\auto-erreur_<date>.log`.

Un échantillon à la fois ; vider `C:\labo\resultats` entre deux analyses (étape 7 ci-dessous).

## Procédure d'analyse manuelle (par échantillon)

0. Sur l'hôte, depuis la racine du dépôt, vérifier les prérequis (code de sortie 0 attendu) :

   ```powershell
   .\lab\scripts\verifier-prerequis.ps1
   ```

   Il signale les outils manquants, un `sysmonconfig-export.xml` absent ou invalide, des scripts
   copiés qui ne sont plus à jour, et un dossier de résultats non vidé.
1. Double-cliquer sur `lab\analyse.wsb`. La sandbox démarre et `setup-sandbox.ps1` s'exécute
   dans une fenêtre PowerShell « MalSight » : ExecutionPolicy Bypass pour la session, création
   de `C:\travail`, installation de Sysmon, capture Procmon **en local**
   (`C:\labo-outils\procmon.PML`).
2. Attendre le message vert **« Sandbox prête »**. En cas de message rouge **« ÉCHEC »**, ne rien
   exécuter : le journal est dans `C:\labo-outils\setup.log` et copié sur l'hôte dans
   `C:\labo\resultats\setup-erreur_<date>.log`. Si aucune fenêtre n'apparaît, lancer à la main :
   `powershell -ExecutionPolicy Bypass -NoExit -File C:\entree\scripts\setup-sandbox.ps1`.
3. Dans la même fenêtre, copier l'échantillon en local puis l'exécuter :

   ```powershell
   Copy-Item C:\entree\samples\<fichier> C:\travail\
   & C:\travail\<fichier>
   ```

   Attendre ensuite 2 à 3 minutes.
4. Dans la même fenêtre, lancer la collecte. Elle arrête Procmon, attend la fin du processus,
   convertit le PML en CSV en local, puis copie tout vers `C:\resultats` :

   ```powershell
   C:\entree\scripts\collect.ps1 -Echantillon <fichier>
   ```

5. Sur l'hôte, vérifier `C:\labo\resultats\<fichier>_<date>\` :

   | Fichier | Contenu |
   | --- | --- |
   | `procmon.PML` / `procmon.csv` | Capture Procmon brute et convertie |
   | `sysmon.evtx` / `sysmon.csv` | Journal Sysmon (une colonne par champ EventData) |
   | `sysmon-config.xml` | Config Sysmon utilisée (SwiftOnSecurity + règles maison) |
   | `manifeste.json` | Nom, SHA-256, horodatage de la capture, liste des fichiers |

6. Fermer la sandbox : tout son contenu est détruit, la suivante repart d'un état propre
   (équivalent d'une restauration de snapshot).
7. Sur l'hôte, copier les résultats vers le dépôt (`cases/`, ignoré par git) ou une archive,
   sans binaire, puis **vider** `C:\labo\resultats`.

## Check-list d'isolement

- [x] Réseau désactivé (`<Networking>Disable</Networking>`)
- [x] vGPU, presse-papiers, micro, caméra et imprimantes désactivés
- [x] `C:\entree` (outils, scripts, échantillons) en **lecture seule**
- [x] Un seul dossier partagé en écriture, `C:\labo\resultats`, réservé aux journaux ; on n'y
      exécute jamais rien côté hôte, et il est vidé après chaque collecte (copie des résultats
      vers le dépôt ou une archive, sans binaire)
- [x] Sandbox jetable : état propre à chaque démarrage
- [ ] Échantillon vérifié comme bénin avant de le copier dans `C:\labo\entree\samples`

## Limites connues

- **Pas de réseau simulé** : les tentatives réseau apparaissent dans Sysmon (requêtes DNS,
  connexions) mais échouent ; pas de réponse type INetSim, ni de PCAP.
- **Microsoft Defender** est actif dans la sandbox : un fichier comme EICAR sera mis en
  quarantaine, ce qui est en soi une observation à consigner.
- Une seule sandbox à la fois, sans persistance ni snapshots intermédiaires.

## Cible ultérieure (si décidée au jalon J2)

| VM | Rôle | Réseau |
| --- | --- | --- |
| REMnux (Linux) | Analyse statique, INetSim (faux services DNS/HTTP) | Host-only |
| FLARE-VM (Windows 10/11) | Exécution des échantillons bénins, Sysmon, Procmon, Wireshark | Host-only, passerelle/DNS = REMnux |
| (option) Ubuntu 24.04 + CAPEv2 | Sandbox automatisée | Réseau isolé |
