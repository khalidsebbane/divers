# Scania France : audit des lenteurs ERP IRIUM (Informix / RHEL)

Boîte à outils pour **identifier la source des lenteurs** sur l'infrastructure IRIUM, en supervisant tous les serveurs en même temps pendant une matinée :

| Fichier | Rôle |
|---|---|
| `audit-irium.sh` | Collecte en **lecture seule** sur chaque serveur : système, CPU, mémoire, disques, réseau, Informix, processus IRIUM/ipscrond. Bash, sans dépendance |
| `rapport_audit.py` | Analyse les collectes de **tous les serveurs** et produit un **rapport HTML unique** avec un diagnostic automatique. Python 3.6+, sans dépendance |

![Exemple de diagnostic (données simulées)](docs/exemple-diagnostic.png)

## Environnement Scania (relevé le 21/10/2026)

| Serveur | Rôle | Commande de supervision |
|---|---|---|
| `x0296se` | Base principale Informix `ol_x0296se` (`INFORMIXDIR=/opt/irium/informix`) | `./audit-irium.sh supervision --debut 07:30 --duree 5h --intervalle 30` |
| `x0297se` | Secondaire **RSS** (`ol_x0297se`, asynchrone) | idem |
| x0290se, x0294se, x0295se | Programmes Genero (fglrun), ≈ 1 200 sessions | idem `--bdd-hote x0296se --bdd-port sqlexec` |
| serveurs d'applications IRIUM | Applications | idem `--bdd-hote x0296se --bdd-port sqlexec` |
| serveur ipscrond | Tâches d'arrière-plan | idem `--bdd-hote x0296se --bdd-port sqlexec` |

L'environnement Informix est lu dans le profil du compte `informix` : `ONCONFIG=onconfig.ol_x0296se`, `INFORMIXSQLHOSTS=…/sqlhosts.ol_x0296se`. Le journal du moteur `$INFORMIXDIR/tmp/online.log` est au format daté (`MSG_DATE 1`), ce que le script et le rapport gèrent.

x0296se : VM RHEL 7.6, 12 vCPU, 40 Go de RAM, IDS 14.10.FC7WE. Sous RHEL 7, Python 3.6+ peut manquer. Le rapport est alors généré sur un autre poste à partir de l'archive.

- **Plan d'actions consolidé**, croisant le rapport du ticket 345564 et l'ONCONFIG : [docs/recommandations-x0296se.md](docs/recommandations-x0296se.md).
- **Lecture préliminaire de l'ONCONFIG** : [docs/analyse-configuration-x0296se.md](docs/analyse-configuration-x0296se.md).

Les priorités :
- dbspace `datadbs` plein à 99,4 % ;
- parcours complets de sav_evt et sav_lor ;
- parcours inverses sur i_agrtrf1 et i_agrrem7 ;
- fraîcheur des statistiques ;
- `DIRECT_IO 0x5` sans effet (O_DIRECT absent).

## Ce qui est collecté

| Domaine | Contenu |
|---|---|
| **Système & OS** | version RHEL, noyau, uptime, charge, virtualisation (temps « steal »), profil tuned, NTP, paramètres noyau (swappiness, THP, shm, sem), limites du compte informix, erreurs dmesg/journal (I/O, OOM, tâches bloquées), **historique sar des jours précédents** |
| **CPU & mémoire** | utilisateur / système / iowait / steal en continu, charge par CPU, file d'exécution, mémoire disponible, swap in/out, **top 10 des processus** en CPU et en mémoire toutes les 5 min, processus bloqués en état D |
| **Stockage & I/O** | `df -Th`, `df -i`, lsblk, LVM, multipath, planificateur I/O, options de montage ; pour **chaque disque en continu** : occupation %, temps de réponse (await) en lecture et écriture, IOPS, débit ; `iostat -dxk` si sysstat est présent |
| **Réseau** | erreurs d'interface, vitesse et duplex, connexions par port, **retransmissions TCP** ; depuis les serveurs d'applications et ipscrond : **latence (ping et connexion TCP) vers la base** |
| **Informix** | voir le tableau ci-dessous |
| **IRIUM / ipscrond** | nombre de processus IRIUM, **traitements ipscrond en cours** (commande, durée, CPU) pour les relier aux pics de la base |
| **Pression mémoire du noyau** | compactages et allocations bloquantes, recyclage du cache de pages (Mo/s), fragmentation (`/proc/buddyinfo`), `vm.min_free_kbytes`, THP |

| Commande Informix | Fréquence | Usage |
|---|---|---|
| `onstat -` | chaque relevé | mode du moteur, détection d'un moteur **bloqué** (`Blocked:CKPT/LONGTX…`) |
| `onstat -p` | chaque relevé | cache lecture/écriture, attentes de verrous, interblocages, attentes de checkpoint, balayages séquentiels, bufwaits, débordements (calculés par intervalle, pas en cumul) |
| `onstat -u` | chaque relevé | sessions actives et **sessions en attente par cause** : verrou, buffer, checkpoint, log, mutex |
| `onstat -k` | chaque relevé | nombre de verrous, débordements de la table des verrous |
| `onstat -g rea` | chaque relevé | threads prêts en attente de VP CPU (**saturation CPU du moteur**) |
| `onstat -F` | chaque relevé | écritures au premier plan (manque de buffers propres) |
| `onstat -g glo` | 5 min | occupation réelle des VP CPU |
| `onstat -g ckp`, `-l`, `-g iof`, `-g dri`, `-x`, `-g wai` | 5 min | durée et blocage des checkpoints, logs non sauvegardés, **temps d'I/O par chunk**, réplication HDR (état, backlog), transactions, attentes |
| `onstat -g ses`, `-g sql`, `-g ath`, `-g repl`, `-g rss`, `-g ppf` + requêtes **sysmaster** | 15 min | sessions, SQL en cours, threads ; **sessions et tables les plus coûteuses** (lectures, balayages séquentiels, attentes de verrous) |
| `onstat -g ppf` + `sysptprof` + `syssesprof` (export unload) | 15 min et en fin d'audit | **compteurs par table et par index** : lectures physiques et logiques, lectures ISAM, scans séquentiels, **parcours inverses**, verrous, hit ratio ; **compteurs par session** (utilisateur, poste, PID). Le rapport calcule le cumul depuis le démarrage et le delta sur la fenêtre |
| Inventaire SQL (une fois) | | **remplissage des dbspaces**, taille et nombre d'extents des plus grosses tables, **date des dernières statistiques** (`systables.ustlowts`, `sysdistrib`) de chaque base, rattachement index → table |
| Ouverture des chunks (une fois) | | drapeaux d'ouverture des chunks par les processus `oninit` : **DIRECT_IO réellement actif ou non** (`O_DIRECT`) |
| Une fois, au démarrage | | `onstat -g seg`, `-g osi`, `-d`, `-D`, `-R`, `-g buf`, `-g ntt`, `-g mgm`, `-g lmx`, `-s`, `-g cluster`, `-c` ; **ONCONFIG complet** ; sqlhosts ; chunks → périphériques ; journal du moteur (MSGPATH) |

**Impact sur la production : négligeable.** Les `onstat` lisent la mémoire partagée sans verrou. Les requêtes SQL ne lisent que sysmaster et le catalogue (`SET ISOLATION TO DIRTY READ`, délai limité). Aucune commande lourde n'est lancée (ni `oncheck`, ni `UPDATE STATISTICS`, ni trace SQL), et rien n'est modifié. `--sans-sql` désactive toutes les requêtes. Chaque commande a un délai maximal.

## Déroulé recommandé

### La veille : préparation (15 min)

1. **Copier** le dossier `scania-fr/` sur les 4 serveurs, par exemple dans `/root/scania-fr`, puis `chmod +x audit-irium.sh`.
2. **Vérifier que l'heure est synchronisée** sur tous les serveurs (`chronyc tracking`). La comparaison entre serveurs repose sur l'heure.
3. **Repérer le nom exact des processus IRIUM** : `ps -ef | grep -iE 'ips|irium|fgl' | grep -v grep`. Si les noms diffèrent des motifs par défaut (`ipscrond|fglrun|fglgo|irium|ips…`), les passer avec `--motifs`.
4. **Relever le port du listener Informix** dans `$INFORMIXDIR/etc/sqlhosts` (ex. 9088).
5. **Lancer un instantané** sur chaque serveur pour valider. Il prend environ 2 minutes :
   ```bash
   ./audit-irium.sh instantane
   ```

### Le jour J : supervision de la matinée

Lancer **sur les 4 serveurs**, avec la même heure de début et le même intervalle :

| Serveur | Commande (en root) |
|---|---|
| Base principale Informix | `./audit-irium.sh supervision --debut 07:30 --duree 5h --intervalle 30` |
| Réplica Informix | `./audit-irium.sh supervision --debut 07:30 --duree 5h --intervalle 30` |
| Serveur(s) d'applications IRIUM | `./audit-irium.sh supervision --debut 07:30 --duree 5h --intervalle 30 --bdd-hote <serveur-bdd> --bdd-port 9088` |
| Serveur ipscrond | `./audit-irium.sh supervision --debut 07:30 --duree 5h --intervalle 30 --bdd-hote <serveur-bdd> --bdd-port 9088` |

- La supervision tourne en arrière-plan et **continue après la déconnexion SSH**. Elle peut être lancée la veille, grâce à `--debut 07:30`.
- **Suivi** : `./audit-irium.sh statut`. **Arrêt anticipé** : `./audit-irium.sh arreter`. L'archive est alors finalisée.
- **Volume** : environ 5 à 20 Mo par serveur pour une matinée.

**Signaler chaque lenteur ressentie, en direct** (support, key users au téléphone) sur n'importe quel serveur supervisé :
```bash
./audit-irium.sh marquer "Lenteur saisie commande - agence Lyon"
```
C'est le point clé de la méthode. Le rapport montre, pour chaque signalement, **ce qui sortait de l'ordinaire à ce moment-là** sur tous les serveurs.

### Après : rapport

**À la fin de chaque audit, le rapport du serveur est généré automatiquement** dans le dossier de l'audit (et dans l'archive) : `rapport_<serveur>.html`, avec le plan d'actions et les classements au format CSV dans `rapport_<serveur>_inventaire/`. Il faut pour cela que `rapport_audit.py` soit à côté de `audit-irium.sh`. `--sans-rapport` désactive cette étape.

Pour le **rapport consolidé des 4 serveurs**, récupérer les archives `/var/tmp/scania-fr/<serveur>_<date>.tar.gz` des 4 serveurs, puis, sur n'importe quelle machine avec Python 3.6+ :
```bash
python3 rapport_audit.py srv-bdd_*.tar.gz srv-rep_*.tar.gz srv-app_*.tar.gz srv-cron_*.tar.gz -o rapport_scania.html
```
Sur RHEL 8 sans python3 : `/usr/libexec/platform-python rapport_audit.py …`

## Lire le rapport

1. **Diagnostic** : la liste des constats classés par gravité, avec les preuves chiffrées et la recommandation. Le bandeau du haut résume les causes les plus probables.
2. **Signalements de lenteur** : pour chaque marque, les indicateurs qui s'écartent de leur moyenne à ± 5 minutes.
3. **Corrélations** : coïncidence minute par minute entre les traitements ipscrond et les verrous, la charge ou le CPU de la base.
4. **Par serveur** :
   - des graphiques alignés sur la même période, où les signalements apparaissent en pointillés rouges ;
   - les processus les plus consommateurs, les traitements ipscrond et les disques ;
   - pour Informix : les paramètres ONCONFIG commentés, les chunks, les VP, la réplication, le journal du moteur et les sorties brutes ;
   - **les objets les plus coûteux**, sur le modèle du rapport du ticket 345564 : classement 1 (lectures physiques), 2 (lectures logiques, avec le profil d'accès déduit), 3 (scans séquentiels, avec pages par scan), 4 (parcours inverses d'index), verrous par objet, sessions les plus consommatrices ; remplissage des dbspaces ; ouverture des chunks.
5. **Recommandations**, en fin de rapport : le plan d'actions priorisé. Il regroupe :
   - **Immédiat** : risque d'incident, par exemple un dbspace plein ;
   - **P1** : effet majeur sur la charge ;
   - **P2** et **P3**.

   Chaque action précise sa nature : système, base de données, applicatif ou configuration. La revue de l'**ONCONFIG est croisée avec les mesures**, par exemple :
   - `USELASTCOMMITTED NONE` passe en P1 si une contention sur les verrous a été mesurée ;
   - `DIRECT_IO` est signalé s'il est configuré alors que les chunks ne sont pas ouverts en `O_DIRECT` ;
   - `DS_NONPDQ_QUERY_MEM` est relevé si des tris débordent sur disque ;
   - `OPTCOMPIND 2` est relevé en présence de scans coûteux.

   Le tableau « Mesure de l'efficacité » donne les indicateurs de référence à comparer après chaque correction. Le même plan est exporté en CSV, avec des colonnes de suivi, pour Excel.

Repères utilisés par le diagnostic :

| Indicateur | Normal | Signe d'un problème |
|---|---|---|
| CPU (p95) | < 70 % | > 85 % : saturation ; steal > 5 % : hôte de virtualisation surchargé |
| iowait (p95) | < 5 % | > 15 % : le stockage limite |
| Disque : temps de réponse | < 5 ms (SSD/baie) | > 20 ms, avec occupation > 80 % : goulot d'I/O |
| Swap in/out | 0 | > 0 de façon continue : mémoire insuffisante |
| Cache de lecture Informix | > 98 % (OLTP) | < 95 % : BUFFERPOOL trop petit ou balayages séquentiels |
| Sessions en attente de verrou | 0 à 1 | ≥ 3 de façon répétée : contention (batch pendant la journée ?) |
| Checkpoints | < 2 s, non bloquants | > 10 s ou bloquants : écriture trop lente ou log physique trop petit (déclencheur « Plog ») |
| Écritures au premier plan | 0 | > 0 : CLEANERS / LRU à revoir |
| Threads prêts (`onstat -g rea`) | < nombre de VP CPU | au-delà de façon continue : manque de VP CPU ou de cœurs |
| Latence application → base | < 0,5 ms (même LAN) | > 2 ms : réseau. IRIUM fait de nombreux allers-retours, donc chaque milliseconde compte |
| Réplication HDR synchrone | | Toute lenteur de la réplica ralentit les validations de la base principale |
| Dbspace de données | > 10 % libre | < 5 % : P1 ; < 1 % : **Immédiat** (échec d'allocation d'extents) |
| Lectures physiques par objet | réparties | 2 objets ≥ 30 % des pages lues sur disque : parcours complets répétés |
| Parcours inverses d'index | rares | > 100/s concentrés sur 1 ou 2 index : requêtes « dernière ligne » en boucle |
| Scans séquentiels | petites tables | ≥ 4 000 pages par scan avec ≥ 10^8 pages lues au total : index manquant ; ≥ 0,5 scan/s sur une table moyenne : index sur le critère |
| Index : lectures logiques / lecture ISAM | ≈ 3 | ≥ 2 000 lectures ISAM/s : traitement ligne à ligne (boucle FOREACH) |
| Statistiques de l'optimiseur | < 30 jours | absentes ou anciennes sur une table en tête des classements |
| Pression mémoire du noyau | 0 | compactages > 1/s, allocations bloquantes > 10/s, ou aucun bloc libre > 16 Ko |

## Causes fréquentes sur ce type d'architecture

- **Traitements ipscrond lancés en journée** : verrous et cache vidé par des balayages séquentiels. C'est visible dans « Corrélations » et dans la courbe « traitements ipscrond ».
- **HDR en mode synchrone** (`HDR_TXN_SCOPE`, `DRINTERVAL`) avec une réplica dont le disque ou le réseau est plus lent : chaque validation de la base principale l'attend.
- **Checkpoints bloquants** : stockage des chunks lent, log physique trop petit, CLEANERS insuffisants.
- **Index manquants** ou statistiques obsolètes : tables en tête des balayages séquentiels (sysmaster).
- **VM sous-dimensionnée ou hôte surchargé** : temps steal, vCPU partagés.
- **THP activées, swappiness élevé, mémoire partagée non résidente** sur le serveur de base.

## Compléments pour le DBA pendant un incident

Lorsqu'une session précise est lente, en direct :

```bash
onstat -g ses <sid>        # détail de la session : mémoire, threads, SQL
onstat -g sql <sid>        # requête en cours
onstat -u | grep <sid>     # attente en cours (L = verrou, B = buffer, C = checkpoint…)
onstat -k | grep <adresse> # verrou attendu et détenteur
onstat -g stk <tid>        # pile du thread (support IBM/HCL)
```

## Tests

```bash
python3 -m pytest tests
```

L'ensemble a aussi été validé de bout en bout. Le test s'est fait sur un simulateur reproduisant les sorties `onstat` d'Informix 12.10, avec un incident déclenché par un traitement ipscrond. Le diagnostic a bien relevé la contention de verrous, les checkpoints bloquants, les écritures au premier plan et la file d'attente CPU, et les a reliés aux signalements. **À valider** : le format exact des sorties `onstat` sur votre version d'Informix (`onstat -` dans le rapport). Les sorties brutes sont toujours jointes, ce qui permet une relecture manuelle.
