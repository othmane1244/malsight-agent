# Charte d'usage éthique

1. **Échantillons bénins uniquement** : binaires de test écrits par l'équipe, tests Atomic Red Team, fichier EICAR, échantillons fournis par l'encadrant.
2. **Isolement** : toute exécution a lieu dans un environnement isolé et jetable, sans accès Internet réel. Actuellement (décision [D1](decisions.md)) : **Windows Sandbox avec réseau désactivé**, détruite à la fermeture après chaque analyse. Une VM (réseau hôte seul + INetSim, restaurée par snapshot après chaque analyse) ne sera ajoutée que si le bilan du jalon J2 le décide. Un seul dossier partagé en écriture, `C:\labo\resultats`, réservé aux journaux ; on n'y exécute jamais rien côté hôte, et il est vidé après chaque collecte (copie des résultats vers le dépôt ou une archive, sans binaire).
3. **Pas d'échantillon dans git** : le dossier `samples/` et les extensions binaires sont ignorés.
4. **Agent défensif** : l'agent n'a aucun outil d'exécution ni de génération de code offensif. Il ne produit que des synthèses et des règles de détection.
5. **Validation humaine** : aucun rapport n'est publié sans relecture par un membre de l'équipe.
6. **Données** : avec un LLM cloud, aucune donnée sensible n'est transmise ; le mode local (Ollama) est privilégié.
