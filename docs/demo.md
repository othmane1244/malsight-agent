# Démo de 3 minutes : T12, scénario combiné

**Échantillon** : `lab/echantillons-test/T12_scenario_combine.ps1` (bénin, écrit par l'auteur) :
`systeminfo` (découverte, T1082), valeur Run `MalsightTest12` vers notepad (persistance,
T1547.001), tentative DNS vers `c2.malsight.lab` (réseau coupé). Vérité terrain :
`lab/verite-terrain/T12.json` (3 IOC, 2 techniques).

**Message à faire passer** : *les outils classent, le LLM explique, le vérificateur exige des
preuves* (D10, D8). Tout est hors ligne, en local, et rien n'est exécuté par l'agent.

## Préparation (avant la soutenance, pas pendant les 3 minutes)

1. Collecte déjà faite et archivée : `cases\T12\` (mode automatique, D3). **Ne pas relancer la
   sandbox en direct** (environ 3 minutes, plus le démarrage de Windows Sandbox).
2. Ollama démarré, modèle **chargé à l'avance** (le premier chargement prend du temps) :
   `ollama run gemma4:e4b "ok"` puis vérifier `ollama ps` (gemma4:e4b, contexte 8192).
3. Bases locales présentes : `data\enterprise-attack.json`, `data\d3fend\` (aucun réseau requis).
4. Deux terminaux PowerShell dans le dépôt, `.venv\Scripts\activate`, police agrandie ;
   un éditeur Markdown ouvert sur `docs\resultats\dev_gemma4_hybride\T12\rapport.md` (plan B).
5. Repérer le dossier de cas : `malsight extract ... --labo cases\T12` affiche
   `cases\561a7e11...\case.json`.

## Déroulé (temps mesurés le 3 novembre : extraction 1 s, `--no-llm` 15 s, hybride avec LLM 120-140 s)

| Temps | À l'écran | Commande | Ce qu'on dit |
| --- | --- | --- | --- |
| **0:00** | Terminal 2 | `malsight analyze cases\561a7e11...\case.json` | « Je lance l'agent tout de suite : le LLM local met environ deux minutes. » |
| 0:05-0:35 | `lab\echantillons-test\T12_scenario_combine.ps1` | (afficher le script) | Échantillon bénin écrit pour l'occasion ; exécuté **seulement** dans une Windows Sandbox sans réseau, collecte Sysmon + Procmon automatique. |
| 0:35-1:05 | Terminal 1 | `malsight comparer cases\T12` | Tableau IOC attendu / trouvé / source : clé Run (Sysmon + Procmon), fichier, **DNS vu par Sysmon seul** ; 3/3. |
| 1:05-1:30 | Terminal 1 | `malsight extract lab\echantillons-test\T12_scenario_combine.ps1 --labo cases\T12` | Fusion Sysmon + Procmon, attribution à l'arbre de processus de l'échantillon, filtre du bruit : 4 observations utiles au lieu de 95. |
| 1:30-2:00 | `docs\resultats\comparaison_modes_dev.md` | (afficher) | Résultat clé : règles seules 10/12 sans faux positif ; LLM seul 4 suggestions justes sur 5 mais aucun classement fiable ; d'où D10. Validation honnête : rappel 50 % sur des techniques nouvelles. |
| **2:00-2:50** | Rapport de T12 (terminal 2 terminé) | ouvrir `cases\561a7e11...\rapport.md` | **Techniques officielles** T1082 et T1547.001 avec leur règle et leur preuve ; **suggestions à valider** ; contre-mesures **D3FEND** avec liens ; recommandations ; incertitudes (tentative DNS = tentative, pas de communication). |
| 2:50-3:00 | — | — | « Le rapport est à valider par un analyste : l'agent assiste, il ne décide pas. » |

## Plan B : Ollama lent ou indisponible

- **À 2:00, l'analyse n'est pas finie** : ouvrir le rapport déjà généré avec le même modèle,
  `docs\resultats\dev_gemma4_hybride\T12\rapport.md` (« même commande, exécutée ce matin ; le
  modèle tourne en local sur CPU/GPU »). Laisser tourner l'analyse en direct et y revenir si elle
  se termine.
- **Ollama ne répond pas du tout** : `malsight analyze cases\561a7e11...\case.json --no-llm`
  (15 s, sans modèle) : la **liste officielle** (T1082, T1547.001), les IOC et les contre-mesures
  D3FEND sont là, car ils viennent des outils (D10) ; seuls le résumé, les suggestions et les
  recommandations rédigées manquent. C'est en soi une démonstration de l'architecture.
- **Question sur l'injection de prompt** : `docs\resultats\injection_gemma4_e4b\criteres.md`
  (aucune obéissance non bloquée, consignes inédites non détectées par la garde mais contenues
  par l'architecture).

## À ne pas faire en direct

- Relancer la sandbox ou une série complète (`malsight serie` : environ 25 minutes).
- Modifier quoi que ce soit dans le code (gel D11).
