# Journal des décisions

Chaque décision d'architecture ou d'organisation est consignée ici : contexte, décision,
justification, conséquences et date de réexamen. Une décision remplacée n'est pas effacée :
elle passe au statut « remplacée » avec un lien vers la nouvelle.

---

## D1 : Windows Sandbox seul pour le labo

- **Date** : 2026-11-01
- **Statut** : acceptée, à réexaminer au jalon **J2** (dossier JSON, fin S7 ; voir [`planning.md`](planning.md))

### Contexte

La conception ([`conception.md`](conception.md)) prévoit un labo VirtualBox/KVM avec
REMnux, FLARE-VM et INetSim. Mettre en place ces VM (images lourdes, réseau host-only,
INetSim, snapshots) prend du temps, alors que la phase 2 (S2-S4) doit surtout produire
rapidement des journaux réels pour construire le pipeline d'extraction (phase 3).
Le poste de l'équipe est sous Windows 11 Pro, avec Windows Sandbox activé.

### Décision

Le labo démarre avec **Windows Sandbox seul** (`lab/analyse.wsb`) : réseau coupé,
Sysmon (config SwiftOnSecurity) + Procmon, collecte par scripts (`lab/scripts/`).
Au jalon J2, un bilan décide s'il faut ajouter **VirtualBox + INetSim**.

### Justification

- **Mise en place immédiate** : fonctionnalité intégrée à Windows, aucune image à télécharger,
  configuration en un fichier `.wsb` versionné.
- **Isolement par conception** : sandbox jetable (état propre à chaque démarrage, équivalent
  d'un snapshot restauré), réseau désactivé, presse-papiers et vGPU coupés.
- **Suffisant pour les échantillons bénins** de la phase 2 (binaires de test de l'équipe,
  Atomic Red Team, EICAR) : l'essentiel des comportements visés (processus, fichiers,
  registre) est observable par Sysmon et Procmon sans réseau.
- **Débloque la phase 3** plus tôt : les formats Sysmon (EVTX/CSV) et Procmon sont les mêmes
  que dans une FLARE-VM, le pipeline de normalisation restera valable.

### Conséquences et risques acceptés

- **Pas de réseau simulé** : pas d'INetSim ni de PCAP ; seules les tentatives réseau
  (DNS, connexions) vues par Sysmon sont disponibles.
- **Dossier partagé en écriture** (`C:\labo\resultats`) : écart à l'ancienne règle « aucun
  partage de dossier en écriture ». La règle a été **mise à jour en conséquence** dans
  [`ethique.md`](ethique.md), [`conception.md`](conception.md) (tableau des risques) et
  [`lab/README.md`](../lab/README.md) (check-list d'isolement) : un seul dossier partagé en
  écriture, `C:\labo\resultats`, réservé aux journaux ; on n'y exécute jamais rien côté hôte,
  et il est vidé après chaque collecte (copie des résultats vers le dépôt ou une archive,
  sans binaire).
- Pas de snapshot intermédiaire ni de sandbox parallèle ; Defender actif dans la sandbox.
- Pas de CAPEv2 : capa dynamique (qui lit les rapports CAPE) n'est pas disponible pour l'instant.

### Critères du bilan J2

Ajouter VirtualBox + INetSim si au moins un de ces points est vrai :

1. Des échantillons du jeu de test ont un comportement réseau à observer (DNS, HTTP, C2 simulé).
2. Le pipeline ou l'évaluation a besoin de PCAP ou de rapports CAPE (capa dynamique).
3. Le dossier en écriture ou les limites de Windows Sandbox posent un problème concret.

Sinon, Windows Sandbox est conservé jusqu'à la fin du projet.
