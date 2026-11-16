# Politique de sécurité

## Périmètre

MalSight Agent est un **projet académique** et pédagogique, sans déploiement en production ni
support garanti. Il est publié tel quel, sous licence MIT.

| Version | Suivie |
| --- | --- |
| `main` (dernier commit) | oui, au mieux |
| `v1.0-soutenance` | non (version figée) |

Sont dans le périmètre :

- le code Python de `src/malsight/` (extraction, agent, vérificateur, rapport, CLI) ;
- les scripts du laboratoire dans `lab/scripts/` ;
- les garde-fous du projet : outils de l'agent en **lecture seule**, **vérificateur** des
  preuves, **garde anti-injection** (voir [`docs/decisions.md`](docs/decisions.md), D8).

Sont hors périmètre :

- les dépendances tierces (Ollama, LangChain, Sysmon, Procmon, Windows Sandbox…) : signaler la
  faille à leurs mainteneurs ;
- les contournements de la garde anti-injection par motifs **déjà documentés** comme limite
  connue dans le [README](README.md#limites).

## Signaler une faille

Merci de **ne pas ouvrir d'issue publique** pour une faille de sécurité.

Utilisez le signalement privé de GitHub : onglet **Security** du dépôt, puis
**Report a vulnerability**. Indiquez :

- la version (commit) concernée ;
- les étapes pour reproduire, avec un dossier de cas minimal si possible (jamais d'échantillon
  malveillant réel ni de binaire) ;
- l'impact attendu (ex. un rapport non prouvé qui passe le vérificateur, un outil de l'agent qui
  écrit ou exécute).

Projet personnel : la réponse se fait au mieux, sans délai garanti.

## Rappel éthique

Le projet est **défensif** : il n'exécute aucun échantillon (sauf l'exception D3, dans une
Windows Sandbox sans réseau) et ne produit que de la détection. Voir
[`docs/ethique.md`](docs/ethique.md).
