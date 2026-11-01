# Laboratoire isolé

> Décision actuelle (voir [`docs/decisions.md`](../docs/decisions.md), D1) : le labo démarre avec
> **Windows Sandbox seul**. L'ajout de VirtualBox + INetSim sera décidé au jalon J2.

## Contenu

| Fichier | Rôle |
| --- | --- |
| `analyse.wsb` | Configuration Windows Sandbox : réseau, vGPU et presse-papiers coupés, dossiers mappés |
| `scripts/setup-sandbox.ps1` | Lancé au démarrage de la sandbox : installe Sysmon, démarre Procmon, affiche les consignes |
| `scripts/collect.ps1` | Lancé après l'exécution : arrête Procmon, exporte Sysmon (EVTX + CSV), range les résultats |

Aucun outil, échantillon ni journal n'est versionné : tout vit dans `C:\labo`, hors du dépôt.

## Prérequis (une seule fois)

1. Windows 11 Pro avec la fonctionnalité **Windows Sandbox** activée.
2. Créer l'arborescence hors du dépôt :

   ```text
   C:\labo\entree\outils      Sysmon, Procmon, sysmonconfig-export.xml
   C:\labo\entree\scripts     copie de lab/scripts/*.ps1
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
   Copy-Item .\lab\scripts\*.ps1 C:\labo\entree\scripts\ -Force
   ```

## Procédure d'analyse (par échantillon)

1. Double-cliquer sur `lab\analyse.wsb`. La sandbox démarre et `setup-sandbox.ps1` s'exécute
   dans une fenêtre PowerShell : Sysmon s'installe, Procmon capture vers
   `C:\resultats\procmon_<date>.PML`.
2. Attendre le message **« Sandbox prête »**.
3. Dans la sandbox, copier l'échantillon en local puis l'exécuter :

   ```powershell
   New-Item -ItemType Directory -Force C:\travail
   Copy-Item C:\entree\samples\<fichier> C:\travail\
   ```

   Lancer `C:\travail\<fichier>`, puis attendre 2 à 3 minutes.
4. Dans la fenêtre PowerShell, lancer la collecte :

   ```powershell
   C:\entree\scripts\collect.ps1 -Echantillon <fichier>
   ```

5. Sur l'hôte, vérifier `C:\labo\resultats\<fichier>_<date>\` :

   | Fichier | Contenu |
   | --- | --- |
   | `procmon.PML` / `procmon.csv` | Capture Procmon brute et convertie |
   | `sysmon.evtx` / `sysmon.csv` | Journal Sysmon (une colonne par champ EventData) |
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
