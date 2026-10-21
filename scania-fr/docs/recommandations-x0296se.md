# Recommandations : x0296se / ol_x0296se (magix_prod), Scania France

Sources :

- rapport « Analyse des performances Informix x0296se » (ticket 345564, DSI – Infrastructure Système, 14/10/2026) et son classeur d'inventaire ;
- `onconfig.ol_x0296se`, `sqlhosts.ol_x0296se` et environnement du compte `informix` (21/10/2026) ;
- règles du rapport automatique `rapport_audit.py`.

Les recommandations ci-dessous croisent les **mesures** du ticket et la **configuration**. Le rapport généré en fin d'audit les recalcule à partir des mesures du jour : priorités, preuves chiffrées et classements.

## Contexte confirmé par le ticket

| Élément | Valeur | Conséquence pour l'analyse |
|---|---|---|
| Serveur | VM VMware, **RHEL 7.6**, **12 vCPU**, **40 Go** de RAM | Python 3.6+ souvent absent sous RHEL 7 : le rapport est alors produit sur un autre poste à partir de l'archive |
| Instance | IDS 14.10.FC7WE, secondaire **RSS** x0297se | RSS est **asynchrone** : `HDR_TXN_SCOPE NEAR_SYNC` et `DRINTERVAL 0` sont **sans effet**. Ce point corrige la note de configuration précédente : la réplication ne ralentit pas les COMMIT |
| Charge | ≈ 1 200 sessions Genero (fglrun) depuis x0290se, x0294se, x0295se ; load 7,5 à 12 ; CPU utilisateur 25 à 40 % | Le coût vient des lectures : 71 milliards de lectures logiques en 3 j 4 h, soit 260 000/s en moyenne et plus d'un million/s en pointe |
| Mémoire | BUFFERPOOL 16 Go + SHMVIRTSIZE 11,7 Go, verrouillés (`RESIDENT -1`) : ≈ 28 Go sur 40 | Il reste ≈ 12 Go pour l'OS et le cache de pages. Sans I/O directe, c'est ce cache qui absorbe les 200 à 500 Mo/s de lectures et se fragmente |

## Plan d'actions consolidé

| Prio. | Réf. | Constat (mesure + configuration) | Action | Nature |
|---|---|---|---|---|
| **Immédiat** | R1 | **datadbs à 99,4 %** (0,6 % libre) | Ajouter un chunk (`onspaces -a datadbs …`) ou un *storage pool* avec extension automatique. Contrôler ensuite l'espace chaque semaine (le rapport le signale dès 10 %) | Base |
| **P1** | R2 | Lectures physiques : **sav_evt** et **sav_lor** font 44 % des pages lues. Parcours d'environ 22 Go et 16 Go ; session **277616** (crxzcj, x0295se) | Trace SQL ciblée (`sysadmin:task('set sql user tracing on', <sid>)`), puis `SET EXPLAIN` et index sur les critères. À défaut, traitement hors pointe ou sur le RSS x0297se, en lecture | Base et applicatif |
| **P1** | R3 | **Parcours inverses** : i_agrtrf1 et i_agrrem7, 99 %, ≈ 4 700/s | Identifier les requêtes `ORDER BY … DESC`, `MAX` et `FIRST 1`. Index décroissant, réécriture, ou valeur conservée en mémoire par le programme | Base et applicatif |
| **P1** | R4 | **Statistiques** de l'optimiseur non vérifiées | Le rapport compare désormais `systables.ustlowts` et `sysdistrib.constructed` aux tables en tête des classements. Relancer `UPDATE STATISTICS` (MEDIUM, puis HIGH sur les colonnes de tête des index) hors pointe, puis planifier l'Auto Update Statistics | Base |
| **P1** | R5 | **`DIRECT_IO 0x5`** dans l'ONCONFIG, mais **O_DIRECT absent** des chunks ; pression mémoire du noyau (compaction, NFS) | Positionner `DIRECT_IO 1` et redémarrer l'instance en fenêtre de maintenance. Le rapport suivant vérifie le drapeau `O_DIRECT` de chaque chunk (« Ouverture des chunks ») | Configuration |
| **P2** | R6 | **zsc_whi** (≈ 199 000 pages par scan, 19 612 scans), **trs_cpp**, **zag_ent** (516 000 pages par scan) ; 0,2 à 1,1 milliard de demandes de verrou | `SET EXPLAIN` et index sur les critères. En COMMITTED READ, Informix teste le verrou de **chaque ligne lue**, ce qui explique probablement ce volume sur des scans complets. Lectures de consultation en `DIRTY READ` ou `COMMITTED READ LAST COMMITTED`, à valider avec l'éditeur | Base et applicatif |
| **P2** | R7 | `USELASTCOMMITTED "NONE"` | À activer (`"COMMITTED READ"`) **si le rapport mesure des attentes de verrou**. Il passe alors automatiquement en P1. Cela supprime les attentes des lecteurs sur les batchs, mais pas les demandes de verrou | Configuration |
| **P2** | R8 | Accès unitaires en boucle : i_mmat, i_stec1, i_zlfa1, i_seor1, i_ska5, i_savevt2, i_zent1, chacun de 4 000 à 7 600 lectures/s | Traitements ensemblistes (jointures) au lieu de FOREACH + SELECT par ligne ; cache des données de référence | Applicatif |
| **P2** | R9 | 11 VP CPU + 6 VP NET pour **12 vCPU** ; load jusqu'à 12 | Comparer l'occupation des VP (`onstat -g glo`) et les threads prêts (`onstat -g rea`) dans le rapport. Si les VP CPU sont saturés : réduire les VP NET (4 suffisent souvent pour 1 200 sessions) plutôt qu'ajouter des VP CPU. Demander une réservation CPU sur l'hôte VMware si le *steal* est > 5 % | Configuration et système |
| **P2** | R10 | `OPTCOMPIND 2` et scans coûteux mesurés | Tester `SET OPTCOMPIND 0` en session sur les requêtes des R2 et R6 avant tout changement global | Configuration |
| **P3** | R11 | Scans fréquents de sav_sal et agr_loc ; relectures de gen_apr et zsc_dsm ; tmp_resources | Index sur le critère de recherche ; paramètres conservés en mémoire par le programme | Base et applicatif |
| **P3** | R12 | Hit ratio bas sur dpc_lig (78 %) et i_atve2 (81 %) | Revoir l'ordre des colonnes de l'index et les requêtes d'accès | Base |
| **P3** | R13 | `DS_NONPDQ_QUERY_MEM 512` | Passer à 2 048–4 096 Ko si le rapport montre des tris sur disque (`dsksorts`) | Configuration |
| **P3** | R14 | `LOGBUFF 64`, `PHYSBUFF 128`, `LOGSIZE 10000` (10 Mo) | LOGBUFF 256, PHYSBUFF 512 et logs de 50 à 100 Mo si plus de 20 bascules par heure. Ces paramètres ne sont pas la cause des lenteurs | Configuration |
| **P3** | R15 | `lru_min_dirty 1` / `lru_max_dirty 2` | À conserver tant que les checkpoints restent courts. À revoir après le passage à DIRECT_IO, d'après les temps d'écriture des chunks (`onstat -g iof`) | Configuration |
| Infra | R16 | THP désactivées et `vm.min_free_kbytes` à 256 Mo le 13/10 ; ajout de RAM à l'étude | Rendre ces réglages permanents (`tuned` ou `/etc/sysctl.d`, grub). L'ajout de RAM n'est utile qu'en complément de R5 : il ne réduit pas le volume lu | Système |
| Risque | R17 | `LTAPEDEV /dev/null` : les logs logiques ne sont pas sauvegardés | Sans effet sur les performances. En revanche, aucune restauration à un instant donné n'est possible, et le RSS réplique aussi les erreurs logiques. À valider avec Scania | Base |

**À ne pas changer :** `HDR_TXN_SCOPE`, `DRINTERVAL` et `DRTIMEOUT`, sans effet avec RSS. `LOG_INDEX_BUILDS 1`, requis par RSS. `DEF_TABLE_LOCKMODE row`, `LOCKS 2000000`, `RESIDENT -1`, `TEMPTAB_NOLOG 1`.

## Ce que l'audit mesure désormais automatiquement

| Élément du rapport 345564 | Collecte (`audit-irium.sh`) | Restitution (`rapport_audit.py`) |
|---|---|---|
| Classement 1 : lectures physiques | `sysmaster:sysptprof` toutes les 15 min et en fin d'audit | Cumul, part, delta sur la fenêtre, hit ratio, règle « 2 objets ≥ 30 % » |
| Classement 2 : lectures logiques | `onstat -g ppf` | Lectures logiques / ISAM et profil d'accès déduit : accès unitaires, scans répétés, verrouillage massif |
| Classement 3 : scans séquentiels | `onstat -g ppf` + taille réelle des tables (`sysptnhdr`) | Pages par scan, fréquence, verrous, extents |
| Classement 4 : parcours inverses | `onstat -g ppf` (rvscn) + rattachement index → table (`sysindexes`) | Part des accès inverses, fréquence par seconde |
| Sessions (syssesprof) | `syssesprof` + `syssessions` (utilisateur, poste, PID) | Session dominante, avec les commandes de trace à lancer |
| Dbspace presque plein (A0) | `sysdbspaces` / `syschunks` | Immédiat < 1 %, P1 < 5 %, P2 < 10 % |
| Fraîcheur des statistiques (A1) | `systables.ustlowts`, `sysdistrib.constructed` de chaque base | Tables en tête des classements sans statistiques, ou statistiques de plus de 30 jours |
| I/O directe non effective | Drapeaux d'ouverture des chunks par `oninit` (`/proc/<pid>/fdinfo`) | DIRECT_IO configuré mais O_DIRECT absent |
| Pression mémoire (section 3) | `/proc/vmstat` (compact_stall, allocstall, pgsteal), `/proc/buddyinfo`, `vm.min_free_kbytes` | Compactages et allocations bloquantes par seconde, recyclage en Mo/s, plus grand bloc libre |
| Mesure de l'efficacité | identique avant et après correction | Tableau d'indicateurs de référence et export CSV du plan d'actions et des classements (colonnes de suivi) |

## Mise en œuvre

```bash
# x0296se, matinée complète ; le rapport est produit à la fin (si Python 3.6+ est présent)
./audit-irium.sh supervision --debut 07:30 --duree 5h --intervalle 30
# x0290se / x0294se / x0295se (Genero) : latence vers la base
./audit-irium.sh supervision --debut 07:30 --duree 5h --intervalle 30 --bdd-hote x0296se --bdd-port sqlexec
# rapport consolidé (sur n'importe quel poste Python 3.6+)
python3 rapport_audit.py x0296se_*.tar.gz x0295se_*.tar.gz -o rapport_scania.html
```

Après chaque correction (R1 à R6 en priorité), relancer le même audit sur la même plage horaire. Comparer ensuite le tableau « Mesure de l'efficacité » et les classements, ou les fichiers CSV dans Excel.
