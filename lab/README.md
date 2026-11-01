# Laboratoire isolé

## Machines
| VM | Rôle | Réseau |
| --- | --- | --- |
| REMnux (Linux) | Analyse statique, INetSim (faux services DNS/HTTP) | Host-only |
| FLARE-VM (Windows 10/11) | Exécution des échantillons bénins, Sysmon, Procmon, Wireshark | Host-only, passerelle/DNS = REMnux |
| (option) Ubuntu 24.04 + CAPEv2 | Sandbox automatisée | Réseau isolé |

## Check-list d'isolement
- [ ] Carte réseau en **host-only** (pas de NAT ni de pont)
- [ ] Dossiers partagés désactivés ou en lecture seule
- [ ] Presse-papiers et glisser-déposer désactivés
- [ ] Snapshot « propre » pris avant chaque analyse et restauré après
- [ ] INetSim actif sur REMnux, DNS de la VM Windows pointé dessus

## Collecte dynamique minimale (sans CAPE)
1. Restaurer le snapshot propre, lancer Sysmon (config SwiftOnSecurity), Procmon, Wireshark.
2. Exécuter l'échantillon bénin pendant 2-3 minutes.
3. Exporter : journal Sysmon (EVTX → JSON), Procmon (CSV), PCAP.
4. Copier les exports vers l'hôte, restaurer le snapshot.
