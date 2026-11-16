# Agent IA pour l'analyse assistée de malware — Étude, architecture et planning

Nov 1, 2026 · Othmane Aliouali

## 1. Contexte, objectifs et périmètre

L'agent ne lance jamais d'exécution : il **lit** des rapports d'analyse déjà produits (statique et dynamique) et rédige une synthèse défensive structurée. C'est le choix qui garde le projet dans le cadre pédagogique et éthique imposé.

**Livrable attendu de l'agent, pour chaque échantillon :**

- Résumé des comportements observés (fichiers, registre, processus, réseau)
- Liste d'IOC : hachages, domaines, IP, URL, chemins, clés de registre, mutex
- API Windows sensibles appelées, regroupées par finalité (injection, persistance, réseau, chiffrement)
- Techniques MITRE ATT&CK associées, chacune avec sa preuve
- Recommandations de détection et de remédiation (règles YARA/Sigma proposées, durcissement)

**Règles du périmètre :**

- Échantillons **bénins ou pédagogiques** uniquement (binaires de test, simulateurs comme les tests Atomic Red Team, échantillons fournis par l'encadrant)
- Laboratoire **isolé** et jetable, sans accès Internet réel : Windows Sandbox avec réseau désactivé pour commencer ([D1](decisions.md)) ; VM avec réseau simulé (INetSim / FakeNet-NG) et snapshots seulement si décidé au jalon J2
- L'agent n'a que des outils en **lecture seule** : il ne peut ni exécuter, ni modifier, ni générer de code offensif
- Un humain valide toujours le rapport final (l'agent *assiste*, il ne décide pas)

## 2. État de l'art : ce qui existe déjà

La tendance 2025-2026 est claire : on branche un LLM sur des outils d'analyse existants via le protocole **MCP** (Model Context Protocol), et on structure le travail en étapes avec un état sauvegardé sur disque. Le LLM ne remplace pas les outils : il orchestre et rédige.

### Projets GitHub les plus pertinents

| Projet | Ce qu'il fait | Intérêt pour nous |
| --- | --- | --- |
| [mandiant/capa](https://github.com/mandiant/capa) | Détecte les capacités d'un binaire (PE, ELF, .NET) **ou d'un rapport de sandbox** (CAPE, DRAKVUF, VMRay) et les mappe sur ATT&CK et MBC | Pièce centrale : donne des techniques ATT&CK fiables, avec règles vérifiables |
| [kevoreilly/CAPEv2](https://github.com/kevoreilly/CAPEv2) | Sandbox open source (successeur de Cuckoo) : traçage d'API, captures réseau, YARA, Suricata, signatures comportementales | Source de l'analyse dynamique ; produit un rapport JSON |
| [mrphrazer/agentic-malware-analysis](https://github.com/mrphrazer/agentic-malware-analysis) | Environnement Docker : agent (Claude Code / Codex) + Ghidra ou Binary Ninja via MCP, 8 phases, dossier de cas sur disque | Meilleur modèle d'architecture à imiter (orchestrateur, phases, état persistant) |
| [JameZUK/Arkana](https://github.com/JameZUK/Arkana) | Serveur MCP de 250+ outils (YARA, capa, FLOSS, angr, émulation), mapping ATT&CK et export d'IOC automatiques | Bonne référence de « boîte à outils » ; trop large pour un projet étudiant, à étudier plutôt qu'à reprendre |
| [LaurieWired/GhidraMCP](https://github.com/LaurieWired/GhidraMCP) | Expose Ghidra (décompilation, fonctions, xrefs) à un LLM via MCP | Option pour l'analyse statique profonde (extension, pas cœur) |
| [raphabot/awesome-cybersecurity-agentic-ai](https://github.com/raphabot/awesome-cybersecurity-agentic-ai) | Liste curée de projets d'IA agentique en cybersécurité | Point d'entrée pour la veille |

### Articles et retours d'expérience

- [Building a Pipeline for Agentic Malware Analysis](https://synthesis.to/2026/03/18/agentic_malware_analysis.html) (mars 2026) : un agent non structuré reste superficiel et sature son contexte ; **la structure et l'état persistant comptent plus que le choix du modèle**. Le rapport doit séparer faits observés et inférences. Erreurs constatées (clé AES manquée, AES-128 au lieu de 256) : la validation humaine reste nécessaire.
- [Cisco Talos – Using LLMs as a reverse engineering sidekick](https://blog.talosintelligence.com/using-llm-as-a-reverse-engineering-sidekick/) (juillet 2025) : comparaison modèle local (Devstral 24B via Ollama) et cloud (Claude) ; le local est plus lent et perd ses instructions sur un long contexte. Ne pas dire au modèle que le fichier est malveillant : cela biaise l'analyse.
- [CyberSOCEval (Meta & CrowdStrike, arXiv 2509.20166)](https://www.alphaxiv.org/abs/2509.20166) : benchmark de LLM sur des **rapports de sandbox** et sur le mapping ATT&CK. Précision de seulement 23 à 34 % en analyse de malware : les LLM seuls ne suffisent pas, d'où l'intérêt d'outils déterministes (capa) en amont.
- [Mandiant – Dynamic capa](https://cloud.google.com/blog/topics/threat-intelligence/dynamic-capa-executable-behavior-cape-sandbox) (capa v7, 2024) : capa lit directement le JSON de CAPE et résume des milliers d'appels d'API en capacités ; utile sur les échantillons packés.
- [Your AI RE agent reads function names, not just code](https://dev.to/keel_alican_akyol/your-ai-reverse-engineering-agent-reads-function-names-not-just-code-c0o) : risques d'**injection de prompt** via les chaînes et noms de fonctions d'un binaire, et outils MCP en écriture non contrôlés. Parade : mode **lecture seule côté serveur**, sélection des fonctions par API sensibles plutôt que par nom.

**Conclusion de l'état de l'art :** outils déterministes pour extraire les faits, LLM pour corréler et rédiger, pipeline par étapes avec état sur disque, validation humaine.

## 3. Approche recommandée

Nous recommandons un **pipeline hybride** : des outils déterministes extraient les faits, puis un agent LLM à outils en lecture seule les corrèle, les mappe sur ATT&CK et rédige le rapport. C'est l'approche que l'état de l'art valide, et elle est réalisable en un semestre.

| Option | Principe | Avantages | Limites | Verdict |
| --- | --- | --- | --- | --- |
| A. LLM seul | On colle le rapport brut de sandbox dans un prompt | Très simple | Contexte saturé, hallucinations, 23-34 % de précision (CyberSOCEval) | Trop fragile |
| **B. Pipeline hybride + agent** | Extraction déterministe (capa, YARA, CAPE) → données normalisées → agent LLM avec outils de consultation → rapport validé | Faits traçables, ATT&CK fiable, défensif par construction | Demande une bonne normalisation | **Recommandée** |
| C. Agent autonome + désassembleur | Agent qui pilote Ghidra/Binary Ninja via MCP | Analyse très profonde | Complexe, coûteux, non déterministe, risques d'injection | En extension seulement |

**Les 6 principes de conception :**

1. **Les faits viennent des outils, pas du LLM.** Chaque IOC, API et technique du rapport doit pointer vers une preuve (règle capa, appel d'API, ligne de log).
2. **ATT&CK par double source.** capa fournit les techniques « sûres » ; le LLM en propose d'autres, mais uniquement à partir d'IDs vérifiés dans la base officielle ATT&CK (RAG), avec un niveau de confiance.
3. **Sortie structurée.** L'agent remplit un schéma JSON (Pydantic) validé automatiquement, puis le rapport Markdown/PDF est généré à partir de ce JSON.
4. **Outils en lecture seule, isolés.** Aucun outil d'exécution exposé à l'agent ; le contenu des échantillons (chaînes, noms) est traité comme donnée non fiable (anti-injection de prompt).
5. **État persistant.** Un dossier de cas par échantillon (artefacts + JSON d'état), comme dans agentic-malware-analysis.
6. **Humain dans la boucle.** Le rapport distingue faits observés / inférences / incertitudes, et un analyste le valide.

## 4. Architecture du système

Le système compte cinq étages : laboratoire, normalisation, agent, rapport, validation humaine. Seul l'étage 1 touche l'échantillon ; l'agent ne voit que des données déjà extraites.

&#91;embedded content: architecture · 5 étages, de l'échantillon au rapport validé\]

Le Vérificateur est le garde-fou central : il rejette tout IOC ou technique sans preuve dans le dossier de cas.

**Exemple de schéma de sortie (simplifié) :**

```json
{
  "sample": {"sha256": "...", "type": "PE32"},
  "behaviors": [{"summary": "Crée une clé Run", "evidence": "RegSetValueExW HKCU\\...\\Run"}],
  "iocs": [{"type": "domain", "value": "test.lab.local", "source": "dns_capture"}],
  "sensitive_apis": [{"name": "CreateRemoteThread", "category": "injection"}],
  "attack": [{"id": "T1547.001", "name": "Registry Run Keys", "source": "capa", "confidence": "high"}],
  "recommendations": ["Surveiller les écritures dans les clés Run (Sysmon EID 13)"]
}
```

## 5. Stack d'outils par couche

Tout est open source et gratuit, sauf l'API LLM cloud, optionnelle si vous utilisez un modèle local via Ollama.

| Couche | Outils recommandés | Rôle |
| --- | --- | --- |
| Laboratoire isolé | Actuellement ([D1](decisions.md)) : Windows Sandbox + Sysmon/Procmon. Si décidé au jalon J2 : VirtualBox ou KVM, [REMnux](https://remnux.org) (Linux), [FLARE-VM](https://github.com/mandiant/flare-vm) (Windows), INetSim / FakeNet-NG | Environnement jetable sans Internet ; réseau simulé et snapshots avec l'option VM |
| Échantillons bénins | Binaires de test maison, tests [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team), fichier EICAR, échantillons fournis par l'encadrant | Produire des comportements observables sans danger |
| Analyse statique | [pefile](https://github.com/erocarrera/pefile), [FLOSS](https://github.com/mandiant/flare-floss), YARA, Detect It Easy, [capa](https://github.com/mandiant/capa) | Hachages, imports/API, chaînes, packers, capacités + ATT&CK |
| Analyse dynamique | [CAPEv2](https://github.com/kevoreilly/CAPEv2) (ou Procmon + Sysmon + Wireshark en version légère) | Appels d'API, fichiers, registre, réseau, rapport JSON |
| Normalisation | Python, Pydantic, parseurs maison | Convertir les sorties hétérogènes en un « dossier de cas » JSON unique |
| Connaissance ATT&CK | [mitreattack-python](https://github.com/mitre-attack/mitreattack-python) + base vectorielle (Chroma ou FAISS) | Vérifier les IDs de techniques, RAG sur les descriptions et mitigations |
| Agent LLM | LangGraph (ou orchestration Python simple) ; modèle local via Ollama (Qwen, Llama, Mistral) ou API cloud | Corréler, mapper, rédiger ; outils en lecture seule |
| Outils de l'agent (option MCP) | Serveur MCP maison en lecture seule ; [GhidraMCP](https://github.com/LaurieWired/GhidraMCP) en extension | Exposer les données du cas à l'agent proprement |
| Rapport et défense | Jinja2 → Markdown/PDF, export STIX 2.1 des IOC, génération de règles YARA/Sigma à valider | Livrable lisible + IOC réutilisables |
| Interface (option) | Streamlit | Déposer un rapport, lancer l'analyse, afficher la synthèse |

Conseil : commencez avec **capa + pefile + FLOSS + Procmon/Sysmon** si CAPE est trop lourd à installer ; CAPE peut arriver en phase 2.

## 6. Planning du projet

Le projet tient en 14 semaines et 7 phases, avec un jalon tous les 3-4 semaines pour montrer un résultat à l'encadrant. Les dates sont à caler sur votre calendrier réel.

&#91;embedded content: planning · 7 phases, 4 jalons, 14 semaines\]

Les phases Agent et Rapport se chevauchent volontairement : le format de rapport guide la conception de l'agent.

| Phase | Semaines | Tâches clés | Livrable |
| --- | --- | --- | --- |
| 1. Cadrage + état de l'art | S1-S2 | Lire les sources, choisir la stack, définir le schéma JSON de sortie, répartir les rôles | Cahier des charges + note d'état de l'art |
| 2. Labo isolé + échantillons | S2-S4 | Mettre en place le labo Windows Sandbox (réseau coupé, Sysmon/Procmon, [D1](decisions.md)) ; REMnux + FLARE-VM + INetSim seulement si décidé au jalon J2 ; constituer 10-20 échantillons bénins avec vérité terrain | Labo documenté + jeu d'échantillons étiquetés |
| 3. Extraction + normalisation | S4-S7 | Scripts pefile/FLOSS/YARA/capa, collecte dynamique (CAPE ou Sysmon/Procmon), parseurs vers le dossier de cas | Pipeline qui produit un JSON par échantillon |
| 4. Agent LLM + RAG ATT&CK | S7-S10 | Outils de lecture, index ATT&CK (mitreattack-python + Chroma), prompts, vérificateur de preuves | Prototype d'agent fonctionnel |
| 5. Rapport + recommandations | S9-S11 | Gabarit Jinja2, export STIX des IOC, propositions YARA/Sigma, interface Streamlit (option) | Rapport automatique Markdown/PDF |
| 6. Évaluation + tests | S11-S13 | Métriques (section 7), comparaison agent / LLM seul / capa seul, local vs cloud | Tableau de résultats + analyse |
| 7. Rédaction + soutenance | S13-S14 | Mémoire, démo enregistrée, slides | Mémoire + démonstration |

**Répartition suggérée pour une équipe de 3 :** un responsable labo + extraction, un responsable agent + RAG, un responsable rapport + évaluation ; tous participent au cadrage et à la rédaction.

## 7. Évaluation, risques et bonnes pratiques

On évalue l'agent contre une **vérité terrain** : pour chaque échantillon bénin, l'équipe sait ce qu'il fait, donc on peut mesurer ce que l'agent trouve ou invente.

**Métriques proposées :**

| Mesure | Comment la calculer |
| --- | --- |
| Précision / rappel des IOC | IOC extraits vs IOC attendus (liste établie à la main) |
| Précision / rappel ATT&CK | Techniques proposées vs techniques attendues (les tests Atomic Red Team sont déjà étiquetés par technique) |
| Taux d'hallucination | Part des affirmations du rapport sans preuve dans les données du cas |
| Qualité perçue | Grille notée par 2-3 relecteurs (clarté, utilité des recommandations) |
| Coût et temps | Tokens, durée par échantillon ; comparaison modèle local vs cloud |
| Comparaison | Agent vs LLM seul (option A) vs capa seul : montre la valeur ajoutée |

**Risques et parades :**

| Risque | Parade |
| --- | --- |
| Hallucination d'IOC ou de techniques | Chaque élément doit citer sa preuve ; validation des IDs ATT&CK contre la base officielle ; rejet automatique sinon |
| Injection de prompt via chaînes du binaire | Données de l'échantillon délimitées comme non fiables, outils en lecture seule côté serveur, pas d'outil d'action |
| Contexte saturé par de gros rapports | Résumé et filtrage avant le LLM, outils de consultation ciblée, état sur disque |
| Fuite de données vers un LLM cloud | Modèle local (Ollama) ou échantillons sans donnée sensible |
| Évasion de l'isolement du labo | Windows Sandbox jetable sans réseau ([D1](decisions.md)), ou VM sans réseau réel avec snapshots si décidé au jalon J2, échantillons bénins uniquement, un seul dossier partagé en écriture, `C:\labo\resultats`, réservé aux journaux ; on n'y exécute jamais rien côté hôte, et il est vidé après chaque collecte (copie des résultats vers le dépôt ou une archive, sans binaire) |
| Résultats non reproductibles | Température basse, versions figées des modèles et règles, journal des appels d'outils |
| Glissement vers l'offensif | L'agent n'a ni outil d'exécution ni génération de code ; seules les règles de **détection** sont produites |

## 8. Sources

**Articles et publications**

- [Building a Pipeline for Agentic Malware Analysis – synthesis.to (mars 2026)](https://synthesis.to/2026/03/18/agentic_malware_analysis.html)
- [Using LLMs as a reverse engineering sidekick – Cisco Talos (juillet 2025)](https://blog.talosintelligence.com/using-llm-as-a-reverse-engineering-sidekick/)
- [CyberSOCEval: Benchmarking LLMs for Malware Analysis and Threat Intelligence – Meta & CrowdStrike, arXiv 2509.20166](https://www.alphaxiv.org/abs/2509.20166)
- [Dynamic capa: executable behavior from CAPE sandbox – Mandiant / Google Cloud (2024)](https://cloud.google.com/blog/topics/threat-intelligence/dynamic-capa-executable-behavior-cape-sandbox)
- [Your AI reverse-engineering agent reads function names, not just code – DEV Community](https://dev.to/keel_alican_akyol/your-ai-reverse-engineering-agent-reads-function-names-not-just-code-c0o)
- [Exploring LLMs for Semantic Analysis and Categorization of Android Malware – arXiv 2501.04848](https://arxiv.org/abs/2501.04848)
- [SynthCTI: LLM-Driven Synthetic CTI to enhance MITRE Technique Mapping – arXiv 2507.16852](https://arxiv.org/html/2507.16852v1)
- [Uncovering Vulnerabilities of LLM-Assisted Cyber Threat Intelligence – arXiv 2509.23573](https://arxiv.org/html/2509.23573v1)

**Dépôts GitHub**

- [mandiant/capa](https://github.com/mandiant/capa) et [capa-rules](https://github.com/mandiant/capa-rules/)
- [mandiant/flare-floss](https://github.com/mandiant/flare-floss)
- [kevoreilly/CAPEv2](https://github.com/kevoreilly/CAPEv2)
- [mrphrazer/agentic-malware-analysis](https://github.com/mrphrazer/agentic-malware-analysis)
- [JameZUK/Arkana](https://github.com/JameZUK/Arkana)
- [LaurieWired/GhidraMCP](https://github.com/LaurieWired/GhidraMCP)
- [mitre-attack/mitreattack-python](https://github.com/mitre-attack/mitreattack-python)
- [raphabot/awesome-cybersecurity-agentic-ai](https://github.com/raphabot/awesome-cybersecurity-agentic-ai)
- [erocarrera/pefile](https://github.com/erocarrera/pefile), [mandiant/flare-vm](https://github.com/mandiant/flare-vm), [redcanaryco/atomic-red-team](https://github.com/redcanaryco/atomic-red-team)

**Référentiels** : [MITRE ATT&CK](https://attack.mitre.org), [REMnux](https://remnux.org), [Local AI agents with LangGraph and Ollama – DigitalOcean](https://digitalocean.com/community/tutorials/local-ai-agents-with-langgraph-and-ollama)
