# Analyse préliminaire de la configuration Informix : x0296se (Scania France)

Sources : `onconfig.ol_x0296se`, `sqlhosts.ol_x0296se` et environnement du compte `informix`, transmis le 21/10/2026.
Il s'agit d'une **lecture à froid** de la configuration. Le plan d'actions consolidé avec le rapport du ticket 345564 figure dans [recommandations-x0296se.md](recommandations-x0296se.md).
Elle doit être confirmée par la supervision de la matinée : RAM et cœurs réels, mesures de charge.

## Environnement

| Élément | Valeur |
|---|---|
| Serveur / instance | `x0296se` / `ol_x0296se` (SERVERNUM 51), alias `ol_x0296se_loc` (mémoire partagée), `ol_x0296se_net` |
| Secondaire | `ol_x0297se` sur `x0297se`, de type **RSS** (confirmé par le ticket 345564) ; `x0298se` est commenté |
| Serveur | VM VMware, RHEL 7.6, 12 vCPU, 40 Go de RAM, IDS 14.10.FC7WE (ticket 345564) |
| INFORMIXDIR | `/opt/irium/informix` (livré avec IRIUM) |
| ONCONFIG / SQLHOSTS | `onconfig.ol_x0296se` / `$INFORMIXDIR/etc/sqlhosts.ol_x0296se` |
| Journal du moteur | `$INFORMIXDIR/tmp/online.log` (MSG_DATE 1 : lignes datées) |
| Listener | `onsoctcp` sur le service `sqlexec` (habituellement 9088/tcp, à vérifier dans `/etc/services`) |
| Données | `/opt/irium/data/ol_x0296se/` ; 4 dbspaces temporaires (`tempdbs1` à `tempdbs4`) |
| Environnement client | DBDATE `DMY4/`, DBMONEY ` .`, DBDELIMITER `|` |

## Points forts de la configuration

- **DEF_TABLE_LOCKMODE row** et **LOCKS 2 000 000** : verrouillage par ligne, table des verrous largement dimensionnée.
- **RESIDENT -1** : la mémoire partagée ne peut pas partir en swap.
- **DBSPACETEMP** réparti sur 4 dbspaces et **TEMPTAB_NOLOG 1** : les tables temporaires ne sont pas journalisées.
- **Log physique de 4 Go** (`PHYSFILE 4096000`) : les checkpoints déclenchés par le log physique devraient être rares.
- **AUTO_TUNE 1**, **STMT_CACHE 2**, BATCHEDREAD actifs, **DIRECTIVES 1**.

## Points à examiner, par ordre d'impact probable sur les lenteurs

| # | Paramètre | Constat | Impact possible | Action proposée |
|---|---|---|---|---|
| 1 | `USELASTCOMMITTED "NONE"` | En COMMITTED READ, les lectures **attendent** les transactions en cours qui modifient les mêmes lignes | Écrans IRIUM bloqués pendant les traitements ipscrond ou les saisies concurrentes : c'est la cause classique de lenteurs « aléatoires » | Mesurer pendant la supervision les sessions en attente de verrou (`onstat -u`, flag L). Si elles sont confirmées, tester `USELASTCOMMITTED "COMMITTED READ"` en recette, **après accord de l'éditeur IRIUM** |
| 2 | `HDR_TXN_SCOPE NEAR_SYNC`, `DRINTERVAL 0` | **Corrigé** : le secondaire x0297se est un **RSS**, toujours asynchrone. Ces paramètres HDR sont sans effet | Aucun sur les validations | Ne pas modifier. Surveiller seulement le retard du RSS (`onstat -g rss`) |
| 3 | `VPCLASS cpu,num=11` + `NETTYPE soctcp,6,300,NET` | 11 VP CPU **et** 6 VP réseau dédiés | Si le serveur a 12 à 16 cœurs, les VP se disputent les CPU. Le rapport le signale si `nproc` < 17 | Comparer avec `nproc` et l'occupation des VP (`onstat -g glo`). Si c'est serré : passer les écouteurs en classe CPU ou réduire les VP NET |
| 4 | `BUFFERPOOL 8 000 000 × 2 Ko` (≈ 15,3 Go) + `SHMVIRTSIZE` ≈ 11,7 Go, `RESIDENT -1` | ≈ 27 Go de mémoire verrouillée dès le démarrage | Au-delà de 75 % de la RAM : swap de l'OS et des autres processus | Vérifier `free -g`. Le rapport compare automatiquement avec la RAM |
| 5 | `lru_min_dirty=1`, `lru_max_dirty=2` | Nettoyage permanent des pages modifiées | Charge d'écriture continue sur les disques. Utile pour des checkpoints courts, pénalisant si le stockage est saturé en écriture | Croiser avec le temps de réponse en écriture des disques et la durée des checkpoints |
| 6 | `LOGSIZE 10000` (≈ 10 Mo) × 300 | Logs logiques petits | Bascules fréquentes sous forte activité, et autant d'envois vers la réplica HDR | Le rapport calcule le nombre de logs remplis par heure. Au-delà de 20/h, passer à 50-100 Mo |
| 7 | `LOGBUFF 64`, `PHYSBUFF 128` | Buffers de log petits | Vidages plus fréquents ; avec HDR synchrone, chaque vidage est envoyé à la réplica | 256 à 1024 Ko sont courants sur un OLTP chargé |
| 8 | `DS_NONPDQ_QUERY_MEM 512` (PDQ désactivé) | 512 Ko par requête pour les tris et hachages | Tris volumineux dans les dbspaces temporaires | Comparer `total_sorts` et `dsksorts` (sysmaster, dans le rapport) |
| 9 | `OPTCOMPIND 2` | Optimiseur autorisé à préférer hachage et balayage complet | Plans moins favorables aux index en OLTP | À traiter requête par requête (SET EXPLAIN) avant tout changement global |
| 10 | `RTO_SERVER_RESTART 0`, `CKPTINTVL 300` | Checkpoint toutes les 5 minutes au plus | Normal. À vérifier : durée et blocage des checkpoints | Le rapport trace chaque checkpoint |
| 11 | `DIRECT_IO 0x5` | Valeur hors des valeurs usuelles (0 / 1). Le ticket 345564 confirme que **O_DIRECT est absent** sur les chunks | Lectures de 200 à 500 Mo/s via le cache de pages du noyau : recyclage, fragmentation, compaction (alerte NFS) | **`DIRECT_IO 1` + redémarrage** (P1). Le rapport vérifie le drapeau O_DIRECT de chaque chunk |
| 12 | `LTAPEDEV /dev/null` | Les logs logiques ne sont pas sauvegardés | Aucun impact sur les performances, mais **pas de restauration à un instant donné**. La réplica HDR ne protège pas d'une erreur logique | À faire valider par Scania (politique de sauvegarde) |

## Ce que la supervision permettra de trancher

| Hypothèse | Indicateur du rapport |
|---|---|
| Lecteurs bloqués par les écritures (point 1) | Sessions en attente de **verrou**, attentes de verrous par minute, tables en tête de sysptprof ; corrélation avec ipscrond |
| Attentes de log (flag G) | Sessions en attente d'écriture du log logique sur x0296se : disque des logs ou LOGBUFF (la réplication RSS n'intervient pas) |
| Manque de CPU moteur (point 3) | Threads prêts (`onstat -g rea`), occupation des VP CPU, CPU du serveur |
| Mémoire (point 4) | Mémoire disponible, swap in/out |
| Stockage (points 5 à 7) | Temps de réponse disque par périphérique, temps par chunk (`onstat -g iof`), durée et blocage des checkpoints, écritures au premier plan |

## Commandes de la supervision pour cet environnement

```bash
# x0296se (base principale) et x0297se (réplica) : l'environnement Informix est relu dans le profil du compte informix
./audit-irium.sh supervision --debut 07:30 --duree 5h --intervalle 30

# serveurs d'applications IRIUM et serveur ipscrond : ajouter la latence vers la base
./audit-irium.sh supervision --debut 07:30 --duree 5h --intervalle 30 --bdd-hote x0296se --bdd-port sqlexec
```

Si la détection échoue, forcer les valeurs :
`--informixdir /opt/irium/informix --informixserver ol_x0296se --onconfig onconfig.ol_x0296se`.
