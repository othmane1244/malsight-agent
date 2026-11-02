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

---

## D2 : garder T05 (T1112 Modify Registry) malgré son classement « Defense Evasion »

- **Date** : 2026-11-02
- **Statut** : acceptée

### Contexte

`CLAUDE.md` interdisait toute « technique d'évasion ». L'échantillon de test T05 écrit la clé
factice `HKCU\Software\MalsightTest\Config` ; ATT&CK range cette action sous T1112 *Modify
Registry*, technique classée dans la tactique *Defense Evasion*.

### Décision

On garde T05. La règle est précisée dans `CLAUDE.md` : sont interdits les **comportements**
d'évasion (masquage, suppression de traces, désactivation des défenses, obfuscation destinée à
tromper), pas les techniques ATT&CK en tant qu'étiquettes. Une technique classée Defense Evasion
est acceptable si le script n'a aucun effet d'évasion réel.

### Justification

- **Aucun effet d'évasion** : T05 n'écrit qu'une clé applicative inventée ; il ne cache rien,
  ne supprime aucune trace et ne touche à aucune défense. Il est réversible (`-Nettoyer`).
- **Valeur pour l'évaluation** : c'est le seul échantillon dont le comportement est visible
  **uniquement dans Procmon** (clé hors config Sysmon). Il teste la fusion Sysmon + Procmon (#8)
  et le risque qu'un agent n'utilise qu'une source.
- **Réalisme** : beaucoup de malwares stockent leur configuration dans le registre ; un agent
  doit savoir le reconnaître sans le confondre avec une persistance.
- L'alternative T1012 *Query Registry* (lecture seule) ne produirait aucune écriture à détecter.

### Conséquences

- Chaque nouvel échantillon classé Defense Evasion doit justifier dans son en-tête et dans
  `lab/echantillons-test/README.md` qu'il n'a aucun effet d'évasion réel.
- T06 (`-EncodedCommand`) suit la même règle : la commande en clair est affichée avant
  l'exécution, l'encodage ne sert pas à tromper.
