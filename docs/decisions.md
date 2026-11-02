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

---

## D3 : mode automatique d'analyse (`lancer-analyse.ps1`)

- **Date** : 2026-11-02
- **Statut** : acceptée

### Contexte

Avec 12 échantillons de test (T01 à T12), la procédure manuelle (ouvrir la sandbox, copier,
exécuter, attendre, collecter, fermer) devient longue et source d'erreurs. Le mode automatique
était prévu dès la mise en place du labo (D1).

### Décision

`lab/scripts/lancer-analyse.ps1 -Echantillon T02`, lancé sur l'hôte :
1. n'accepte qu'un identifiant `Tnn` correspondant à **exactement un** script de
   `lab/echantillons-test/` **et** à une vérité terrain dans `lab/verite-terrain/` ;
2. génère un `.wsb` temporaire à partir de `lab/analyse.wsb` (mêmes restrictions ; refus si le
   réseau n'y est plus désactivé), dont la LogonCommand lance `analyse-auto.ps1` ;
3. copie scripts et échantillon dans `C:\labo\entree`, vérifie les prérequis ;
4. dans la sandbox, `analyse-auto.ps1` installe Sysmon/Procmon, exécute l'échantillon dans un
   processus séparé, attend 90 s, lance `collect.ps1`, écrit `auto.json` (PID, code de sortie)
   puis éteint la sandbox. En cas d'erreur, la sandbox reste ouverte et un journal
   `auto-erreur_<date>.log` est copié dans les résultats.

Le mode manuel (`lab/analyse.wsb`) reste disponible.

### Justification

- **Reproductibilité** : même délai, même procédure pour chaque échantillon ; comparaison
  possible entre essais et entre échantillons pour l'évaluation (#16, #17).
- **Meilleure attribution** : l'échantillon tourne dans son propre processus, dont le PID est
  noté dans `auto.json` ; en manuel, T01 partageait la console de `setup-sandbox.ps1` (même PID).
- **Sécurité inchangée** : mêmes restrictions que le mode manuel (réseau coupé, entrée en
  lecture seule, sandbox jetable) ; la liste blanche empêche de lancer autre chose que les
  scripts bénins de l'équipe, même par erreur.

### Conséquences et garde-fous

- Exception à la règle « aucune exécution d'échantillon » de `CLAUDE.md`, limitée à ce script
  et à la Windows Sandbox. Le pipeline Python (`src/`) n'exécute toujours rien.
- **Claude ne lance ce script qu'avec l'accord explicite de l'utilisateur, pour des
  échantillons nommés** : un seul (« OK pour T04 ») ou une liste (« OK pour T04, T05, T06 »).
  L'accord ne vaut que pour les échantillons cités, jamais pour une plage implicite
  (« la suite », « tous ») ni pour un échantillon ajouté ou modifié après l'accord.
- **Liste d'échantillons** : lancement un par un, dans l'ordre, `malsight comparer` après
  chacun, et **arrêt au premier échec** (analyse en erreur, délai dépassé ou IOC manquant) :
  Claude le signale et ne lance pas les suivants. *(Précision ajoutée le 2026-11-02, après
  la validation de T02 et T03 en mode automatique.)*
- Les tests (`tests/test_lancer_analyse.py`) n'utilisent que `-SansLancer` : ils ne lancent
  jamais de sandbox.

---

## D4 : jeu de développement (T01 à T12) et jeu de validation (T13 à T16)

- **Date** : 2026-11-02
- **Statut** : acceptée

### Contexte

Le filtre de bruit système de la fusion Sysmon + Procmon (`BRUIT_SYSTEME`, #8) a été réglé en
regardant les journaux de T01 à T12 : le bruit du témoin négatif T11 est passé de 57 à 1
observation. Mesurer ensuite les performances finales sur ces mêmes échantillons les
surestimerait (sur-ajustement) : le filtre a « vu » leurs journaux.

### Décision

- **Jeu de développement : T01 à T12.** On peut régler dessus les filtres, les parseurs, les
  prompts et les seuils, autant que nécessaire.
- **Jeu de validation : T13 à T16**, créé plus tard, **écrit sans regarder les filtres** ni leurs
  résultats, et **jamais utilisé pour les régler**. Il sert uniquement à mesurer les résultats
  finaux (#16, et comparaisons #17, #18).

### Règles pour le jeu de validation

1. Les scripts T13 à T16 et leurs vérités terrain sont écrits **avant** toute analyse de leurs
   journaux, à partir des techniques ATT&CK choisies, sans consulter `BRUIT_SYSTEME`.
2. Ils suivent les mêmes règles que T01 à T12 : scripts texte bénins de l'équipe,
   `-Nettoyer`, vérité terrain, aucun comportement d'évasion (D2).
3. Une fois leurs journaux collectés, **aucune modification** des filtres, parseurs ou prompts
   ne doit être motivée par ce qu'on y voit. Si un défaut est découvert, il est corrigé sur le
   jeu de développement, puis le jeu de validation est **remplacé** (T17+…) avant la mesure
   finale, et l'épisode est consigné ici.
4. Les résultats sont rapportés séparément : développement (optimiste) et validation
   (estimation honnête).

### Justification

- Séparation classique apprentissage / test : sans elle, un taux de faux positifs de 0 sur T11
  ne prouve rien, puisque le filtre a été écrit en regardant T11.
- Coût faible : 4 scripts de plus, collectés en mode automatique (D3).

---

## D5 : replanification sur 14 jours, travail seul, gel du code le 9 novembre

- **Date** : 2026-11-02
- **Statut** : acceptée

### Contexte

Le projet est mené **seul** (et non en équipe de 3) et la soutenance est fixée au
**lundi 16 novembre 2026**, soit 14 jours. Le planning de 14 semaines (`docs/planning.md`,
version initiale) n'est plus tenable.

### Décision

- **Gel du code le lundi 9 novembre** : ensuite, seuls les résultats finaux, le mémoire, les
  slides, la démo et la répétition. Planning détaillé dans `docs/planning.md`.
- **Hors périmètre, présentés comme perspectives** dans le mémoire et la soutenance :
  - **Chroma / recherche vectorielle** (#10 simplifiée) : on garde la validation des IDs
    ATT&CK contre la base officielle et la recherche lexicale existante ;
  - **Interface Streamlit** (#15) ;
  - **Option VM + INetSim** (#5) : bilan J2 fait par anticipation, **Windows Sandbox suffit**
    (D1) : les 12 échantillons du jeu de développement sont observés sans réseau simulé, et les
    tentatives réseau restent visibles par Sysmon (EID 22) ;
  - **Comparaison local / cloud** (#18).
- **Maintenu** : le jeu de validation T13 à T16 (#23, D4), à faire le 8 novembre.
- **Jalons** : J1 clos (labo + jeu de test faits ; cadrage, état de l'art et schéma rédigés dans
  le mémoire, #1 à #3 rattachées à J4), J2 = 4 novembre, J3 = 6 novembre, J4 = 16 novembre.
- **Suivi** : sans équipe, la relecture croisée (#22) est remplacée par une relecture différée
  (relire le lendemain) et par les garde-fous automatiques (tests, vérificateur, CI).
- **Modèles LLM (ajout du 2026-11-02)** : **`gemma4:e4b`** (Ollama, déjà installé) est le modèle
  de **développement** ; c'est la valeur par défaut de `LLM_MODEL`. **`qwen3:8b`** est en
  téléchargement (lent) ; dès qu'il est prêt, comparaison sur T01 (techniques trouvées /
  attendues, rejets, temps, JSON valide) pour choisir le modèle des mesures finales du 9 novembre.

### Justification

- Priorité au cœur démontrable : agent de bout en bout, vérificateur, évaluation mesurée sur
  un jeu de validation honnête (D4). Les éléments retirés n'apportent rien à cette démonstration.
- La recherche lexicale + validation des IDs suffit pour un jeu de 16 échantillons aux
  techniques connues ; la recherche vectorielle n'est utile qu'à plus grande échelle.
- Le gel du code une semaine avant laisse le temps de rédiger sans que les résultats bougent.

---

## D6 : contre-mesures MITRE D3FEND pour les recommandations

- **Date** : 2026-11-02
- **Statut** : acceptée

### Contexte

Les recommandations étaient rédigées librement par le LLM, sans référentiel : impossible de
vérifier qu'elles correspondent aux techniques observées, et risque d'inventer des mesures.
MITRE D3FEND relie chaque technique ATT&CK à des techniques défensives identifiées
(`D3-LFP`, `D3-FIM`...), classées par tactique (Harden, Detect, Isolate, Deceive, Evict,
Restore).

### Décision

- `src/malsight/defend/kb.py` récupère les contre-mesures d'une technique via l'API officielle
  (`https://d3fend.mitre.org/api/offensive-technique/attack/<ID>.json`, champs
  `off_to_def.results.bindings` : `def_tech_id`, `def_tech_label`, `def_tactic_label`,
  `def_artifact_label`, `def_tech`). À défaut pour une sous-technique, la technique parente.
- **Hors ligne** : l'analyse ne lit que le cache `data/d3fend/` (ignoré par git), pré-rempli par
  `malsight download-d3fend` pour toutes les techniques de `lab/verite-terrain/` (et leurs
  parentes). Seule cette commande utilise le réseau.
- Le rapport gagne une liste `countermeasures` (id D3FEND, nom, technique ATT&CK couverte,
  tactique, artefact, lien, source `d3fend`), **remplie depuis le cache, jamais par le LLM**.
- Le pipeline passe en deux appels : brouillon (résumé, comportements, ATT&CK), vérification,
  contre-mesures des techniques retenues, puis recommandations rédigées **avec ces contre-mesures
  en contexte** (ID cités entre parenthèses).
- Le vérificateur rejette toute contre-mesure dont l'ID est absent du cache, qui couvre une
  technique non retenue ou que D3FEND ne relie pas à cette technique, et toute recommandation
  citant un ID D3FEND absent du cache.
- Section « Contre-mesures D3FEND » dans le rapport, avec liens vers d3fend.mitre.org.

### Justification

- Recommandations ancrées dans un référentiel officiel et vérifiables, comme les IDs ATT&CK.
- Cohérent avec la charte (`docs/ethique.md`) : uniquement défensif, et mode local privilégié
  (aucun appel réseau pendant l'analyse).
- Coût faible : 15 techniques en cache (API D3FEND 1.6.0), 3 à 27 contre-mesures chacune.

### Limites

- L'API D3FEND est annoncée « alpha » : son format peut changer. Le cache garde la version et la
  date de téléchargement ; les tests utilisent une réponse réelle figée (fixture).
- Une contre-mesure D3FEND est générique : la pertinence de chaque recommandation reste à
  valider par l'analyste (rapport « à valider avant diffusion »).
