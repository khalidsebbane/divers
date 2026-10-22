#!/bin/bash
# =============================================================================================
# Audit de performance ERP IRIUM / Informix / RHEL - Scania France
#
# Collecte en LECTURE SEULE l'état des serveurs, de la base Informix et des programmes IRIUM, pour identifier
# la source des lenteurs. Le rôle de chaque serveur est détecté automatiquement (base principale, secondaire,
# applications IRIUM / Genero, tâches ipscrond).
#
# MODE CAMPAGNE (recommandé) : script et rapport déposés sur un partage commun (NFS) monté sur tous les serveurs.
#   ./audit-irium.sh campagne demarrer [nom] --serveurs "x0296se x0297se x0295se" [--debut 07:30] [--duree 5h]
#        [--intervalle 30] [--bdd-hote x0296se --bdd-port sqlexec]
#        lance la collecte sur chaque serveur (SSH root ; sinon affiche la commande « rejoindre » à lancer)
#   ./audit-irium.sh campagne rejoindre [nom]       à lancer sur un serveur si le SSH root n'est pas possible
#   ./audit-irium.sh campagne etat [nom]            avancement de chaque serveur
#   ./audit-irium.sh marquer "lenteur saisie commande agence Lyon"   signalement utilisateur (depuis n'importe quel serveur)
#   ./audit-irium.sh campagne rapport [nom]         rapport CENTRAL à tout moment (données partielles ou finales)
#   ./audit-irium.sh campagne arreter [nom]         arrêt anticipé de tous les serveurs
#   Résultat : <partage>/campagnes/<nom>/rapport_<nom>.html : un seul rapport pour tous les serveurs, régénéré
#   automatiquement pendant la campagne et à la fin ; données de chaque serveur dans <partage>/campagnes/<nom>/<serveur>/.
#
# MODE AUTONOME (un serveur) :
#   ./audit-irium.sh instantane                                   photo complète (2 à 3 minutes)
#   ./audit-irium.sh supervision --duree 4h [--intervalle 30] [--debut 07:30] [--bdd-hote ...] [--bdd-port ...]
#   ./audit-irium.sh statut | arreter
#
# Options communes : [--partage DIR] (défaut : dossier du script)  [--sortie /var/tmp/scania-fr] (travail local)
#   [--base magix_prod]  [--motifs 'ipscrond|fglrun|...']  [--services 'digital_dealer|autre_service']  [--table-programmes agr_lds]  [--sans-sql]  [--sans-rapport]
#   [--informixdir DIR --informixserver NOM --onconfig FICHIER]
#   [--trace-sql]  trace SQL du moteur (sysadmin task) pendant l'audit sur la base principale, coupée à la fin :
#                  top des requêtes par lectures, durée, verrous, tris disque (seule option non « lecture seule »)
# Impact : quelques commandes « onstat » (lecture de la mémoire partagée), lectures de /proc et requêtes sysmaster /
# catalogue en lecture seule. Aucune commande lourde (oncheck, update statistics...) n'est lancée, rien n'est modifié.
# =============================================================================================
set -uo pipefail
export LC_ALL=C LANG=C

SORTIE=/var/tmp/scania-fr
DUREE=4h
INTERVALLE=30
DEBUT=""
BDD_HOTE=""
BDD_PORT=""
ROLE=auto
AVEC_SQL=1
TRACE_SQL=0   # --trace-sql : trace SQL du moteur pendant l'audit (seule option qui modifie l'état du moteur, désactivée à la fin)
TRACE_ACTIVEE=0 DERNIER_VERROUS=0 FILTRE_BASES="dbsname NOT IN ('sysmaster','sysadmin','sysutils','sysuser')"
RAPPORT=1
SCRIPT="$(readlink -f "$0")"
PARTAGE="$(dirname "$SCRIPT")"
CAMPAGNE="" SERVEURS="" PROG_TABLE=agr_lds PROG_BASE="" PROG_DATE="" PROG_DEPUIS=""
MOTIFS='ipscrond|fglrun|fglgo|fglrunner|irium|ips[a-z_]*'
BASE=magix_prod   # base(s) IRIUM analysée(s) (séparées par des virgules) ; détection automatique si absente
SERVICES='digital_dealer'   # services / processus applicatifs à superviser (expression régulière, alternatives séparées par |)
INFORMIXDIR_OPT="" INFORMIXSERVER_OPT="" ONCONFIG_OPT=""
HOTE="${AUDIT_HOTE:-$(hostname -s 2>/dev/null || hostname)}"   # AUDIT_HOTE : tests uniquement
EN_COURS_LIEN="$SORTIE/en-cours"

# ---------------------------------------------------------------------------------------------
journal() { echo "$(date '+%F %T') $*" | tee -a "${DOSSIER:-/tmp}/journal.txt" >&2; }
horodatage() { echo "### $(date +%s) $(date '+%F %T')"; }
# exécute une commande avec délai maximal et l'ajoute horodatée à un fichier brut
brut() { local f="$1"; shift; { horodatage; timeout 60 "$@" 2>&1; echo; } >> "$f"; }
existe() { command -v "$1" >/dev/null 2>&1; }

duree_s() {
  case "$1" in
    *h) echo $(( ${1%h} * 3600 ));; *m) echo $(( ${1%m} * 60 ));; *s) echo "${1%s}";; *) echo $(( $1 * 60 ));;
  esac
}

# ---------------------------------------------------------------------------------------------
# Environnement Informix
# ---------------------------------------------------------------------------------------------
charger_informix() {
  if [ -n "$INFORMIXDIR_OPT" ]; then export INFORMIXDIR="$INFORMIXDIR_OPT"; fi
  if [ -z "${INFORMIXDIR:-}" ] && id informix >/dev/null 2>&1; then
    local e; e="$( (su - informix -s /bin/bash -c env; su - informix -c env) 2>/dev/null | grep -E '^(INFORMIX[A-Z_]*|ONCONFIG|DBDATE|DB_LOCALE|CLIENT_LOCALE|SERVER_LOCALE|LD_LIBRARY_PATH)=' | sort -u)"
    while IFS= read -r l; do [ -n "$l" ] && export "${l?}"; done <<< "$e"
  fi
  if [ -z "${INFORMIXDIR:-}" ]; then
    for d in /opt/irium/informix /opt/informix /informix /usr/informix /opt/IBM/informix /home/informix; do
      [ -x "$d/bin/onstat" ] && { export INFORMIXDIR="$d"; break; }
    done
  fi
  [ -n "$INFORMIXSERVER_OPT" ] && export INFORMIXSERVER="$INFORMIXSERVER_OPT"
  [ -n "$ONCONFIG_OPT" ] && export ONCONFIG="$ONCONFIG_OPT"
  [ -n "${INFORMIXDIR:-}" ] && export PATH="$INFORMIXDIR/bin:$PATH"
  existe onstat && timeout 20 onstat - >/dev/null 2>&1
  local rc=$?
  # onstat - : code 5 = en ligne ; 255 = pas de moteur
  if existe onstat && [ "$rc" -ne 255 ] && [ "$rc" -ne 124 ]; then IFX=1; else IFX=0; fi
}

detecter_role() {
  ROLES=()
  if [ "$IFX" -eq 1 ]; then
    local entete; entete="$(timeout 20 onstat - 2>/dev/null | grep -i 'informix' | head -1)"
    case "$entete" in
      *"(Prim)"*) ROLES+=("bdd-principale") ;;
      *"(Sec)"*|*"Read-Only"*) ROLES+=("bdd-replica-hdr") ;;
      *"(RSS)"*) ROLES+=("bdd-replica-rss") ;;
      *"(SDS)"*) ROLES+=("bdd-replica-sds") ;;
      *)   # en-tête sans indicateur : serveur autonome ou primaire, à confirmer par onstat -g rss / -g dri
        if timeout 20 onstat -g rss 2>/dev/null | grep -qi 'Local server type: *Primary' || timeout 20 onstat -g dri 2>/dev/null | grep -qiE '^\s*(primary|standard)\b' \
           || ! timeout 20 onstat -g dri 2>/dev/null | grep -qiE 'secondary'; then ROLES+=("bdd-principale"); else ROLES+=("bdd"); fi ;;
    esac
  fi
  pgrep -f ipscrond >/dev/null 2>&1 && ROLES+=("batch-ipscrond")
  [ "$(pgrep -fc "$MOTIFS" 2>/dev/null | head -1 || echo 0)" -gt 1 ] && ! printf '%s\n' "${ROLES[@]:-}" | grep -q batch && ROLES+=("applications-irium")
  [ ${#ROLES[@]} -eq 0 ] && ROLES+=("inconnu")
  [ "$ROLE" != auto ] && ROLES=("$ROLE")
  ROLE_TXT="$(IFS=,; echo "${ROLES[*]}")"
}

# ---------------------------------------------------------------------------------------------
# Collecte statique (une fois)
# ---------------------------------------------------------------------------------------------
statique_systeme() {
  local d="$DOSSIER/statique"; mkdir -p "$d"
  {
    echo "== Serveur"; hostname -f 2>/dev/null; cat /etc/redhat-release 2>/dev/null; uname -a
    echo; echo "== Uptime / charge"; uptime
    echo; echo "== Virtualisation"; systemd-detect-virt 2>/dev/null || echo "?"
    echo; echo "== Profil tuned"; tuned-adm active 2>/dev/null || echo "tuned absent"
    echo; echo "== Heure / NTP"; date; (chronyc tracking 2>/dev/null || ntpq -p 2>/dev/null || timedatectl 2>/dev/null) | head -20
  } > "$d/systeme.txt" 2>&1
  { lscpu; echo; existe numactl && numactl --hardware; } > "$d/cpu.txt" 2>&1
  { free -m; echo; cat /proc/meminfo; } > "$d/memoire.txt" 2>&1
  {
    for k in vm.swappiness vm.dirty_ratio vm.dirty_background_ratio vm.overcommit_memory kernel.shmmax kernel.shmall kernel.shmmni \
             kernel.sem fs.file-max net.core.somaxconn net.ipv4.tcp_keepalive_time net.core.rmem_max net.core.wmem_max kernel.numa_balancing \
             vm.min_free_kbytes vm.zone_reclaim_mode vm.vfs_cache_pressure vm.dirty_expire_centisecs; do
      echo "$k = $(sysctl -n "$k" 2>/dev/null)"
    done
    echo "transparent_hugepage = $(cat /sys/kernel/mm/transparent_hugepage/enabled 2>/dev/null)"
    echo "transparent_hugepage_defrag = $(cat /sys/kernel/mm/transparent_hugepage/defrag 2>/dev/null)"
    echo "hugepages = $(grep -E 'HugePages_(Total|Free)' /proc/meminfo | tr '\n' ' ')"
    echo; echo "== buddyinfo (blocs libres par ordre : 4K 8K 16K ... 4M)"; cat /proc/buddyinfo 2>/dev/null
  } > "$d/noyau.txt" 2>&1
  { df -Th; echo; df -i; echo; lsblk -o NAME,KNAME,TYPE,SIZE,ROTA,SCHED,MOUNTPOINT 2>/dev/null || lsblk; echo
    for q in /sys/block/*/queue; do b=${q%/queue}; echo "${b##*/} scheduler=$(cat $q/scheduler 2>/dev/null) rotational=$(cat $q/rotational 2>/dev/null) nr_requests=$(cat $q/nr_requests 2>/dev/null) read_ahead_kb=$(cat $q/read_ahead_kb 2>/dev/null)"; done
    echo; echo "== Options de montage"; grep -vE '^(proc|sysfs|cgroup|devpts|tmpfs|securityfs|debugfs|mqueue|hugetlbfs|pstore|bpf|tracefs|configfs|fusectl|selinuxfs|autofs|binfmt_misc|rpc_pipefs|nfsd)' /proc/mounts
    echo; existe multipath && multipath -ll 2>/dev/null; existe pvs && { pvs; vgs; lvs; } 2>/dev/null
  } > "$d/disques.txt" 2>&1
  { ip -s link 2>/dev/null; echo; ip addr 2>/dev/null; echo
    for i in $(ls /sys/class/net | grep -v lo); do echo "$i: $(existe ethtool && ethtool "$i" 2>/dev/null | grep -E 'Speed|Duplex|Link detected' | tr -s ' \n' ' ')"; done
    echo; ss -s 2>/dev/null; echo; ss -tn state established 2>/dev/null | awk 'NR>1{split($3,a,":"); p[a[length(a)]]++} END{for(k in p) print "port local " k ": " p[k] " connexions"}' | sort -t: -k2 -nr | head -20
  } > "$d/reseau.txt" 2>&1
  services_systemd debut
  { echo "== Erreurs noyau (dmesg)"; dmesg -T 2>/dev/null | grep -iE 'error|fail|i/o|oom|killed process|hung task|blocked for more|scsi|nfs.*not responding|soft lockup' | tail -100
    echo; echo "== Journal système (erreurs, 2 derniers jours)"; journalctl -p err --since "-2d" --no-pager 2>/dev/null | tail -150
    echo; echo "== /var/log/messages (2 derniers jours)"; grep -iE 'error|oom|i/o|hung|blocked' /var/log/messages 2>/dev/null | tail -100
  } > "$d/erreurs.txt" 2>&1
  { echo "== Limites du compte informix"; su - informix -s /bin/bash -c 'ulimit -a' 2>/dev/null
    echo; echo "== limits.conf"; grep -vE '^\s*(#|$)' /etc/security/limits.conf /etc/security/limits.d/* 2>/dev/null
  } > "$d/limites.txt" 2>&1
  # Historique sar des jours précédents (si sysstat est installé) : permet de comparer avec une journée normale
  if existe sar; then
    for f in $(ls -t /var/log/sa/sa[0-9]* 2>/dev/null | head -8); do
      { echo "== $f"; sar -u -f "$f" 2>/dev/null | tail -30; sar -r -f "$f" 2>/dev/null | tail -8; sar -q -f "$f" 2>/dev/null | tail -8; sar -d -p -f "$f" 2>/dev/null | grep -i average; } >> "$d/sar_historique.txt" 2>&1
    done
  fi
  { ps -eo pid,ppid,user,etimes,pcpu,pmem,rss,vsz,nlwp,stat,comm,args --sort=-pcpu 2>/dev/null; } > "$d/processus.txt"
  crontab -l > "$d/crontab_root.txt" 2>&1; ls -la /etc/cron.d >> "$d/crontab_root.txt" 2>&1
}

statique_informix() {
  [ "$IFX" -eq 1 ] || return 0
  local d="$DOSSIER/statique/informix"; mkdir -p "$d"
  { env | grep -E '^(INFORMIX|ONCONFIG|DB)' ; } > "$d/environnement.txt"
  for o in "-" "-g seg" "-g osi" "-g glo" "-g dis" "-d" "-D" "-g iof" "-l" "-F" "-R" "-g buf" "-p" "-g ckp" \
           "-g dri" "-g rss" "-g sds" "-g cluster" "-g repl" "-g nif" "-g ntt" "-g ntd" "-g mgm" "-g lmx" "-s" "-x" "-k" "-u" \
           "-g ses" "-g sql" "-g ath" "-g wai" "-g rea" "-g act" "-g ppf" "-g cfg" "-g his" "-c"; do
    f="$d/onstat$(echo "$o" | tr ' -' '_')".txt
    timeout 90 onstat $o > "$f" 2>&1
  done
  # Fichier ONCONFIG complet (sans commentaires)
  local cf="${INFORMIXDIR}/etc/${ONCONFIG:-onconfig}"
  [ -f "$cf" ] && grep -vE '^\s*(#|$)' "$cf" > "$d/onconfig.txt"
  # sqlhosts
  cat "${INFORMIXSQLHOSTS:-$INFORMIXDIR/etc/sqlhosts}" > "$d/sqlhosts.txt" 2>/dev/null
  # Chunks -> périphériques (pour relier les I/O disque aux dbspaces)
  timeout 60 onstat -d 2>/dev/null | awk '$NF ~ /^\// {print $NF}' | sort -u | while read -r p; do
    echo "$p -> $(df -P "$p" 2>/dev/null | awk 'NR==2{print $1" monté sur "$6}') $( [ -b "$(readlink -f "$p")" ] && echo '(périphérique brut)' || echo '(fichier)')"
  done > "$d/chunks_peripheriques.txt"
  # Journal du moteur (MSGPATH) : dernières 20 000 lignes
  local msg; msg="$(chemin_msgpath)"
  [ -f "$msg" ] && tail -n 20000 "$msg" > "$d/online_log.txt"
  ouverture_chunks
  inventaire_sql
  programmes_init
  trace_sql_demarrer
}

# ---------------------------------------------------------------------------------------------
# Informix expert : chaînes de blocage, mémoire des sessions, trace SQL (option)
# ---------------------------------------------------------------------------------------------
releve_unl() {   # releve_unl <fichier raw> <base> <requête> : ajoute le résultat horodaté
  local t="$DOSSIER/informix/inventaire/tmp_rel.unl"
  if unl "$2" "$t" "$3"; then { horodatage; cat "$t" 2>/dev/null; echo; } >> "$1"; fi
  rm -f "$t"
}

chaines_verrous() {
  releve_unl "$DOSSIER/informix/verrous_attente.raw" sysmaster \
    "SELECT FIRST 200 TRIM(l.dbsname), TRIM(l.tabname), TRIM(l.type), l.owner, TRIM(so.username), TRIM(so.hostname), so.pid, l.waiter, TRIM(sw.username), TRIM(sw.hostname) FROM syslocks l, OUTER syssessions so, OUTER syssessions sw WHERE l.waiter > 0 AND so.sid = l.owner AND sw.sid = l.waiter"
}

memoire_sessions() {
  releve_unl "$DOSSIER/informix/memoire_sessions.raw" sysmaster \
    "SELECT FIRST 20 m.sid, TRIM(s.username), TRIM(s.hostname), s.pid, m.memtotal, m.memused FROM sysscblst m, syssessions s WHERE m.sid = s.sid ORDER BY m.memtotal DESC"
}

trace_sql_demarrer() {
  [ "$TRACE_SQL" -eq 1 ] && [ "$IFX" -eq 1 ] && [ "$AVEC_SQL" -eq 1 ] && [[ "$ROLE_TXT" == *bdd-principale* ]] || return 0
  local cf="${INFORMIXDIR}/etc/${ONCONFIG:-onconfig}"
  if grep -qE '^\s*SQLTRACE\s+.*level=(low|med|high)' "$cf" 2>/dev/null; then
    journal "Trace SQL déjà active (SQLTRACE dans l'ONCONFIG) : relevé seul, sans modification"
  elif timeout 60 dbaccess sysadmin - >> "$DOSSIER/informix/inventaire/erreurs_sql.txt" 2>&1 <<'EOSQL'
EXECUTE FUNCTION task('set sql tracing on', 3000, '4k', 'low', 'global');
EOSQL
  then TRACE_ACTIVEE=1; journal "Trace SQL activée pour la durée de l'audit (3000 requêtes en mémoire, niveau low)"
  else journal "Activation de la trace SQL impossible (voir informix/inventaire/erreurs_sql.txt)"; TRACE_SQL=0; return 0; fi
  unl sysmaster "$DOSSIER/informix/trace_sql_colonnes.unl" "SELECT TRIM(c.colname) FROM syscolumns c, systables t WHERE c.tabid = t.tabid AND t.tabname = 'syssqltrace' ORDER BY c.colno"
}

trace_sql_releve() {   # le tampon est circulaire : relevé toutes les 5 minutes, dédoublonné par le rapport
  [ "$TRACE_SQL" -eq 1 ] || return 0
  releve_unl "$DOSSIER/informix/trace_sql.raw" sysmaster "SELECT * FROM syssqltrace"
}

trace_sql_arreter() {
  [ "$TRACE_ACTIVEE" -eq 1 ] || return 0
  trace_sql_releve
  timeout 60 dbaccess sysadmin - >> "$DOSSIER/informix/inventaire/erreurs_sql.txt" 2>&1 <<'EOSQL'
EXECUTE FUNCTION task('set sql tracing off');
EOSQL
  TRACE_ACTIVEE=0; journal "Trace SQL désactivée"
}

# Journal des programmes IRIUM (table agr_lds : un enregistrement par programme lancé) sur la base principale
programmes_init() {
  [ "$IFX" -eq 1 ] && [ "$AVEC_SQL" -eq 1 ] && existe dbaccess || return 0
  [[ "$ROLE_TXT" == *bdd-principale* || "$ROLE_TXT" == bdd ]] || return 0
  [[ "$PROG_TABLE" =~ ^[A-Za-z0-9_]+$ ]] || return 0
  local v="$DOSSIER/informix/inventaire" b t="$DOSSIER/informix/inventaire/tmp_prog.unl"
  for b in $(bases_retenues); do
    [[ "$b" =~ ^[A-Za-z0-9_]+$ ]] || continue
    unl "$b" "$t" "SELECT TRIM(c.colname), c.coltype FROM syscolumns c, systables t WHERE c.tabid = t.tabid AND t.tabname = '$PROG_TABLE' ORDER BY c.colno" || continue
    [ -s "$t" ] && { PROG_BASE="$b"; break; }
  done
  [ -n "$PROG_BASE" ] || { rm -f "$t"; journal "Table des programmes $PROG_TABLE introuvable : journal applicatif non collecté"; return 0; }
  PROG_DATE="$(cut -d'|' -f1 "$t" | grep -iE '_open$' | head -1)"
  [ -n "$PROG_DATE" ] || PROG_DATE="$(cut -d'|' -f1 "$t" | grep -iE 'debut|date' | head -1)"
  { echo "base=$PROG_BASE"; echo "table=$PROG_TABLE"; echo "colonne_date=$PROG_DATE"; echo "colonnes=$(cut -d'|' -f1 "$t" | paste -sd, -)"; } > "$DOSSIER/informix/programmes_table.txt"
  rm -f "$t"
  [ -n "$PROG_DATE" ] || { PROG_BASE=""; journal "Pas de colonne de date dans $PROG_TABLE : journal applicatif non collecté"; return 0; }
  PROG_DEPUIS="$(date -d '-1 hour' '+%F %T')"   # programmes déjà en cours au démarrage
  echo "depuis=$PROG_DEPUIS" >> "$DOSSIER/informix/programmes_table.txt"
  journal "Journal des programmes IRIUM : $PROG_BASE:$PROG_TABLE (colonne $PROG_DATE)"
}

programmes_releve() {   # nouveaux programmes depuis le relevé précédent
  [ -n "$PROG_BASE" ] || return 0
  local t="$DOSSIER/informix/inventaire/tmp_prog.unl" maint; maint="$(date '+%F %T')"
  if unl "$PROG_BASE" "$t" "SELECT * FROM $PROG_TABLE WHERE $PROG_DATE >= '$PROG_DEPUIS' AND $PROG_DATE < '$maint'"; then
    { horodatage; cat "$t" 2>/dev/null; echo; } >> "$DOSSIER/informix/programmes.raw"; PROG_DEPUIS="$maint"
  fi
  rm -f "$t"
}

programmes_final() {    # relecture complète en fin d'audit : dates de fin des programmes terminés entre-temps
  [ -n "$PROG_BASE" ] || return 0
  local d0; d0="$(awk -F= '$1=="depuis"{print $2}' "$DOSSIER/informix/programmes_table.txt")"
  unl "$PROG_BASE" "$DOSSIER/informix/programmes_final.unl" "SELECT * FROM $PROG_TABLE WHERE $PROG_DATE >= '$d0'" || rm -f "$DOSSIER/informix/programmes_final.unl"
}

# DIRECT_IO réellement actif ? Drapeaux d'ouverture des chunks par les processus oninit (O_DIRECT = 040000)
ouverture_chunks() {
  local f="$DOSSIER/statique/informix/chunks_ouverture.txt" chunks pid fd cible fl
  chunks="$(timeout 60 onstat -d 2>/dev/null | awk '$NF ~ /^\// {print $NF}' | sort -u | while read -r p; do readlink -f "$p"; done)"
  [ -n "$chunks" ] || return 0
  echo "# chunk|pid|flags(octal)|o_direct|type" > "$f"
  for pid in $(pgrep -x oninit 2>/dev/null); do
    for fd in /proc/"$pid"/fd/*; do
      cible="$(readlink "$fd" 2>/dev/null)" || continue
      grep -qxF "$cible" <<< "$chunks" || continue
      grep -qF "$cible|" "$f" && continue
      fl="$(awk '/^flags/{print $2}' "/proc/$pid/fdinfo/${fd##*/}" 2>/dev/null)"
      echo "$cible|$pid|$fl|$(( (8#${fl:-0} & 8#40000) ? 1 : 0 ))|$([ -b "$cible" ] && echo brut || echo fichier)" >> "$f"
    done
  done
}

# Exécute une requête SQL en lecture seule et écrit le résultat au format unload (séparateur |)
unl() {   # unl <base> <fichier> <requête>
  [ "$IFX" -eq 1 ] && [ "$AVEC_SQL" -eq 1 ] && existe dbaccess || return 1
  mkdir -p "$DOSSIER/informix/inventaire"
  timeout 300 dbaccess "$1" - >> "$DOSSIER/informix/inventaire/erreurs_sql.txt" 2>&1 <<EOSQL
SET ISOLATION TO DIRTY READ;
SET LOCK MODE TO WAIT 5;
UNLOAD TO '$2' DELIMITER '|' $3;
EOSQL
}

# Bases analysées : celles de --base présentes sur l'instance, sinon toutes les bases utilisateur (10 au plus)
bases_retenues() {
  local v="$DOSSIER/informix/inventaire" toutes b r=""
  toutes="$(cut -d'|' -f1 "$v/bases.unl" 2>/dev/null)"
  for b in ${BASE//,/ }; do grep -qxF "$b" <<< "$toutes" && r="$r $b"; done
  [ -n "$r" ] && echo $r || echo "$toutes" | head -10
}

# Inventaire (une fois) : remplissage des dbspaces, taille/extents des tables, fraîcheur des statistiques
inventaire_sql() {
  [ "$IFX" -eq 1 ] && [ "$AVEC_SQL" -eq 1 ] && existe dbaccess || return 0
  local v="$DOSSIER/informix/inventaire" b; mkdir -p "$v"
  local sysb="'sysmaster','sysadmin','sysutils','sysuser','sysha','syscdr','sys_trace'"
  unl sysmaster "$v/bases.unl" "SELECT TRIM(name), is_logging, is_buff_log, is_ansi FROM sysdatabases WHERE name NOT IN ($sysb)"
  FILTRE_BASES="dbsname IN ($(for b in $(bases_retenues); do printf "'%s'," "$b"; done | sed 's/,$//'))"
  [ "$FILTRE_BASES" = "dbsname IN ()" ] && FILTRE_BASES="dbsname NOT IN ($sysb)"
  journal "Base(s) analysée(s) : $(bases_retenues | tr '\n' ' ')"
  unl sysmaster "$v/dbspaces.unl" "SELECT TRIM(d.name), d.is_temp, d.is_blobspace, SUM(c.chksize), SUM(c.nfree), COUNT(*) FROM sysdbspaces d, syschunks c WHERE d.dbsnum = c.dbsnum GROUP BY 1, 2, 3"
  unl sysmaster "$v/partitions.unl" "SELECT partnum, TRIM(dbsname), TRIM(tabname) FROM systabnames WHERE $FILTRE_BASES"
  unl sysmaster "$v/tailles.unl" "SELECT FIRST 300 TRIM(n.dbsname), TRIM(n.tabname), h.nptotal, h.npused, h.nrows, h.nextns FROM systabnames n, sysptnhdr h WHERE n.partnum = h.partnum AND n.$FILTRE_BASES ORDER BY h.nptotal DESC"
  for b in $(bases_retenues); do
    [[ "$b" =~ ^[A-Za-z0-9_]+$ ]] || continue
    unl "$b" "$v/stats_$b.unl" "SELECT TRIM(tabname), nrows, npused, ustlowts, locklevel, rowsize FROM systables WHERE tabid > 99 AND tabtype = 'T'"
    unl "$b" "$v/distrib_$b.unl" "SELECT TRIM(t.tabname), MAX(d.constructed), COUNT(*) FROM sysdistrib d, systables t WHERE d.tabid = t.tabid AND t.tabid > 99 GROUP BY 1"
    unl "$b" "$v/index_$b.unl" "SELECT TRIM(i.idxname), TRIM(t.tabname), i.idxtype, i.clustered, i.levels, i.leaves, i.nunique, i.part1, i.part2, i.part3, i.part4, i.part5, i.part6, i.part7, i.part8 FROM sysindexes i, systables t WHERE i.tabid = t.tabid AND t.tabid > 99" \
      || unl "$b" "$v/index_$b.unl" "SELECT TRIM(i.idxname), TRIM(t.tabname) FROM sysindexes i, systables t WHERE i.tabid = t.tabid AND t.tabid > 99"
  done
}

# MSGPATH peut contenir $INFORMIXDIR (ex. Scania : $INFORMIXDIR/tmp/online.log)
chemin_msgpath() {
  local cf="${INFORMIXDIR}/etc/${ONCONFIG:-onconfig}" m
  m="$(grep -E '^\s*MSGPATH' "$cf" 2>/dev/null | awk '{print $2}' | tail -1)"
  [ -z "$m" ] && m="$(timeout 30 onstat -c 2>/dev/null | awk '$1=="MSGPATH"{print $2}' | tail -1)"
  m="${m//\$INFORMIXDIR/$INFORMIXDIR}"; m="${m//\$\{INFORMIXDIR\}/$INFORMIXDIR}"
  echo "$m"
}

# ---------------------------------------------------------------------------------------------
# Requêtes sysmaster (lecture seule, délai limité)
# ---------------------------------------------------------------------------------------------
sql_sysmaster() {
  [ "$IFX" -eq 1 ] && [ "$AVEC_SQL" -eq 1 ] && existe dbaccess || return 0
  local f="$DOSSIER/informix/sql_sysmaster.raw"
  { horodatage
    timeout 120 dbaccess sysmaster - 2>&1 <<'EOSQL'
-- Sessions les plus consommatrices (lectures logiques, I/O, verrous, attentes)
SELECT FIRST 15 s.sid, TRIM(s.username) utilisateur, TRIM(s.hostname) machine, p.isreads lectures, p.iswrites ecritures,
       p.bufreads lect_buffers, p.pagreads lect_disque, p.lockreqs demandes_verrous, p.lockwts attentes_verrous,
       p.seqscans balayages_seq, p.total_sorts tris, p.dsksorts tris_disque
FROM syssessions s, syssesprof p WHERE s.sid = p.sid ORDER BY p.bufreads DESC;

-- Tables les plus lues par balayage séquentiel (index manquants probables)
SELECT FIRST 20 TRIM(dbsname) base, TRIM(tabname) table_, seqscans balayages_seq, isreads lectures, bufreads lect_buffers,
       pagreads lect_disque, lockwts attentes_verrous, deadlks interblocages
FROM sysptprof WHERE seqscans > 0 AND dbsname NOT IN ('sysmaster','sysadmin','sysutils','sysuser')
ORDER BY seqscans DESC;

-- Tables avec le plus d'attentes de verrous
SELECT FIRST 15 TRIM(dbsname) base, TRIM(tabname) table_, lockreqs demandes, lockwts attentes, deadlks interblocages, lktouts expirations
FROM sysptprof WHERE lockwts > 0 ORDER BY lockwts DESC;

-- Sessions par machine cliente et utilisateur
SELECT TRIM(hostname) machine, TRIM(username) utilisateur, COUNT(*) sessions FROM syssessions
GROUP BY 1, 2 ORDER BY 3 DESC;
EOSQL
    echo; } >> "$f"
}

# ---------------------------------------------------------------------------------------------
# Échantillonnage
# ---------------------------------------------------------------------------------------------
echantillon_systeme() {
  local s="$DOSSIER/series"
  for f in stat meminfo vmstat diskstats loadavg; do { horodatage; cat /proc/$f; } >> "$s/$f.raw"; done
  { horodatage; cat /proc/net/dev; } >> "$s/netdev.raw"
  { horodatage; cat /proc/net/snmp; } >> "$s/snmp.raw"
  # processus IRIUM / ipscrond (comptage et commandes en cours)
  { horodatage; ps -eo pid,ppid,user,etimes,pcpu,pmem,rss,args 2>/dev/null | grep -E "$MOTIFS" | grep -vE 'grep|audit-irium'; } >> "$s/irium.raw"
}

echantillon_processus() {
  { horodatage; echo "# CPU"; ps -eo pid,user,pcpu,pmem,rss,etimes,comm,args --sort=-pcpu | head -11
    echo "# MEMOIRE"; ps -eo pid,user,pcpu,pmem,rss,etimes,comm,args --sort=-rss | head -11
    echo "# ETAT_D"; ps -eo pid,user,stat,wchan:32,comm | awk '$3 ~ /D/' | head -30; } >> "$DOSSIER/series/top.raw"
  existe iostat && brut "$DOSSIER/series/iostat.raw" iostat -dxk 5 2
}

echantillon_latence() {
  [ -n "$BDD_HOTE" ] || return 0
  if [ -n "$BDD_PORT" ] && ! [[ "$BDD_PORT" =~ ^[0-9]+$ ]]; then   # nom de service (ex. sqlexec) -> numéro
    BDD_PORT="$(getent services "$BDD_PORT" 2>/dev/null | awk '{split($2,a,"/"); print a[1]; exit}')"
  fi
  local f="$DOSSIER/series/latence.raw"
  { horodatage
    ping -c 5 -i 0.2 -W 2 "$BDD_HOTE" 2>&1 | tail -2
    if [ -n "$BDD_PORT" ]; then
      local t0 t1; t0=$(date +%s%N)
      if timeout 5 bash -c "exec 3<>/dev/tcp/$BDD_HOTE/$BDD_PORT" 2>/dev/null; then t1=$(date +%s%N); echo "tcp_connect_ms $(( (t1 - t0) / 1000000 ))"
      else echo "tcp_connect_ms ECHEC"; fi
    fi; } >> "$f"
}

echantillon_informix() {
  [ "$IFX" -eq 1 ] || return 0
  local i="$DOSSIER/informix"
  brut "$i/onstat_p.raw" onstat -p
  local u; u="$(timeout 60 onstat -u 2>&1)"
  { horodatage; echo "$u"; echo; } >> "$i/onstat_u.raw"
  # au moins 2 sessions en attente de verrou : qui bloque qui (au plus toutes les 2 minutes)
  if [ "$(awk 'length($2) == 7 && substr($2, 1, 1) == "L"' <<< "$u" | wc -l)" -ge 2 ] && [ $(( $(date +%s) - DERNIER_VERROUS )) -ge 120 ]; then
    DERNIER_VERROUS=$(date +%s); chaines_verrous
  fi
  { horodatage; timeout 60 onstat -k 2>&1 | tail -3; echo; } >> "$i/onstat_k.raw"
  brut "$i/onstat_rea.raw" onstat -g rea
  brut "$i/onstat_F.raw" onstat -F
  { horodatage; timeout 30 onstat - 2>&1; echo; } >> "$i/onstat_entete.raw"
}

echantillon_informix_lent() {   # toutes les 5 minutes
  { horodatage; cat /proc/buddyinfo 2>/dev/null; } >> "$DOSSIER/series/buddyinfo.raw"
  [ "$IFX" -eq 1 ] || return 0
  local i="$DOSSIER/informix"
  brut "$i/onstat_glo.raw" onstat -g glo
  brut "$i/onstat_ckp.raw" onstat -g ckp
  brut "$i/onstat_l.raw" onstat -l
  brut "$i/onstat_iof.raw" onstat -g iof
  brut "$i/onstat_dri.raw" onstat -g dri
  brut "$i/onstat_x.raw" onstat -x
  brut "$i/onstat_wai.raw" onstat -g wai
  brut "$i/onstat_spi.raw" onstat -g spi
  brut "$i/onstat_ioq.raw" onstat -g ioq
  brut "$i/onstat_buf.raw" onstat -g buf
  programmes_releve
  trace_sql_releve
}

echantillon_informix_lourd() {  # toutes les 15 minutes
  [ "$IFX" -eq 1 ] || return 0
  local i="$DOSSIER/informix"
  brut "$i/onstat_ses.raw" onstat -g ses
  brut "$i/onstat_sql.raw" onstat -g sql
  brut "$i/onstat_ath.raw" onstat -g ath
  brut "$i/onstat_repl.raw" onstat -g repl
  brut "$i/onstat_rss.raw" onstat -g rss
  brut "$i/onstat_d.raw" onstat -d
  memoire_sessions
  sql_sysmaster
  profils_objets
}

# Compteurs par partition (table/index) et par session : comparés entre le premier et le dernier relevé
profils_objets() {
  [ "$IFX" -eq 1 ] || return 0
  local i="$DOSSIER/informix" t="$DOSSIER/informix/inventaire/tmp.unl"
  brut "$i/onstat_ppf.raw" onstat -g ppf
  if unl sysmaster "$t" "SELECT TRIM(dbsname), TRIM(tabname), isreads, bufreads, pagreads, seqscans, lockreqs, lockwts, iswrites, bufwrites, pagwrites FROM sysptprof WHERE $FILTRE_BASES AND (bufreads > 0 OR pagreads > 0)"; then
    { horodatage; cat "$t" 2>/dev/null; echo; } >> "$i/profil_tables.raw"
  fi
  if unl sysmaster "$t" "SELECT FIRST 300 p.sid, TRIM(s.username), TRIM(s.hostname), s.pid, p.pagreads, p.bufreads, p.isreads, p.seqscans, p.lockreqs, p.lockwts, p.total_sorts, p.dsksorts FROM syssesprof p, syssessions s WHERE p.sid = s.sid ORDER BY p.pagreads DESC"; then
    { horodatage; cat "$t" 2>/dev/null; echo; } >> "$i/profil_sessions.raw"
  fi
  rm -f "$t"
}

# ---------------------------------------------------------------------------------------------
preparer() {
  [ "$(id -u)" -eq 0 ] || { echo "À lancer en root." >&2; exit 1; }
  charger_informix
  detecter_role
  DOSSIER="$SORTIE/${HOTE}_$(date +%Y%m%d_%H%M)"
  mkdir -p "$DOSSIER/series" "$DOSSIER/informix" "$DOSSIER/statique"
  {
    echo "serveur=$HOTE"; echo "roles=$ROLE_TXT"; echo "informix=$IFX"
    echo "INFORMIXDIR=${INFORMIXDIR:-}"; echo "INFORMIXSERVER=${INFORMIXSERVER:-}"; echo "ONCONFIG=${ONCONFIG:-}"
    echo "intervalle_s=$INTERVALLE"; echo "bdd_hote=$BDD_HOTE"; echo "bdd_port=$BDD_PORT"; echo "motifs=$MOTIFS"
    echo "services=$SERVICES"; echo "base=$BASE"; echo "clk_tck=$(getconf CLK_TCK 2>/dev/null || echo 100)"; echo "page_ko=$(( $(getconf PAGESIZE 2>/dev/null || echo 4096) / 1024 ))"
    echo "nb_cpu=$(nproc)"; echo "debut=$(date '+%F %T')"; echo "version_script=2.0"; echo "campagne=$CAMPAGNE"
  } > "$DOSSIER/info.txt"
  ln -sfn "$DOSSIER" "$EN_COURS_LIEN"
  journal "Audit $HOTE - rôle(s) : $ROLE_TXT - Informix : $([ "$IFX" -eq 1 ] && echo "oui ($INFORMIXSERVER)" || echo non)"
}

terminer() {
  trace_sql_arreter
  echo "fin=$(date '+%F %T')" >> "$DOSSIER/info.txt"
  services_systemd fin
  [ "$IFX" -eq 1 ] && { timeout 60 onstat -g ckp > "$DOSSIER/informix/fin_onstat_ckp.txt" 2>&1
    local msg; msg="$(chemin_msgpath)"; [ -f "$msg" ] && tail -n 20000 "$msg" > "$DOSSIER/informix/fin_online_log.txt"; }
  rm -f "$EN_COURS_LIEN" "$SORTIE/supervision.pid"
  if [ -n "$CAMPAGNE" ]; then
    synchroniser termine
    rapport_central final
  else
    generer_rapport
  fi
  tar -C "$SORTIE" -czf "$DOSSIER.tar.gz" "$(basename "$DOSSIER")" 2>/dev/null
  journal "Terminé. Données : $DOSSIER - Archive : $DOSSIER.tar.gz"
}

# Services systemd (actifs, en échec) et ports en écoute : au début et à la fin de l'audit
services_systemd() {   # services_systemd debut|fin
  local d="$DOSSIER/statique"
  existe systemctl && {
    timeout 30 systemctl list-units --type=service --all --no-pager --no-legend --plain > "$d/services_systemd_$1.txt" 2>&1
    timeout 30 systemctl --failed --no-pager --no-legend --plain > "$d/services_echec_$1.txt" 2>&1; }
  timeout 30 ss -ltnp > "$d/ports_ecoute_$1.txt" 2>&1
}

# Processus des services supervisés : CPU (ticks), mémoire, threads, démarrage (/proc/<pid>/stat), à chaque relevé
echantillon_services() {
  [ -n "$SERVICES" ] || return 0
  local pid st r cmd
  { horodatage
    for pid in $(pgrep -f -- "$SERVICES" 2>/dev/null); do
      [ "$pid" = "$$" ] && continue
      st="$(cat "/proc/$pid/stat" 2>/dev/null)" || continue
      cmd="$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null)"
      case "$cmd" in *audit-irium*|*pgrep*) continue;; esac
      r="${st##*) }"
      set -- $r   # 1 état, 2 ppid, 12 utime, 13 stime, 18 threads, 20 démarrage, 22 rss (pages)
      [ $# -ge 22 ] || continue
      echo "$pid|${2:-}|${1:-}|${12:-0}|${13:-0}|${18:-0}|${20:-0}|${22:-0}|${cmd% }"
    done; } >> "$DOSSIER/series/services.raw"
}

# Rapport HTML (diagnostic + recommandations) généré automatiquement à la fin de l'audit
trouver_python() {   # Python 3.6+ de préférence, sinon le Python 2.7 de RHEL 7
  local py
  local scl
  for py in /usr/libexec/platform-python python3 python3.6; do
    existe "$py" && "$py" -c 'import sys; sys.exit(sys.version_info < (3, 6))' 2>/dev/null && { echo "$py"; return 0; }
  done
  for scl in /opt/rh/rh-python3*/enable; do   # RHEL 7 : Python 3 des Software Collections (ex. rh-python36)
    [ -f "$scl" ] || continue
    scl="$(basename "$(dirname "$scl")")"
    scl enable "$scl" -- python3 -c 'import sys; sys.exit(sys.version_info < (3, 6))' 2>/dev/null && { echo "scl enable $scl -- python3"; return 0; }
  done
  for py in python python2 python2.7; do
    existe "$py" && "$py" -c 'import sys; sys.exit(sys.version_info[:2] != (2, 7))' 2>/dev/null && { echo "$py"; return 0; }
  done
  return 1
}

generer_rapport() {
  [ "$RAPPORT" -eq 1 ] || return 0
  local py r; r="$(dirname "$SCRIPT")/rapport_audit.py"
  [ -f "$r" ] || { journal "rapport_audit.py absent à côté du script : rapport non généré"; return 0; }
  py="$(trouver_python)" || { journal "Python 2.7 ou 3.6+ absent : générer le rapport sur un autre poste (rapport_audit.py <archive>)"; return 0; }
  if timeout 600 $py "$r" "$DOSSIER" -o "$DOSSIER/rapport_${HOTE}.html" >> "$DOSSIER/journal.txt" 2>&1; then
    journal "Rapport : $DOSSIER/rapport_${HOTE}.html (recommandations en fin de rapport)"
  else
    journal "Échec de génération du rapport (voir journal.txt) : relancer rapport_audit.py sur l'archive"
  fi
}

# ---------------------------------------------------------------------------------------------
# Campagne : collecte simultanée de tous les serveurs vers un partage commun, rapport central unique
# ---------------------------------------------------------------------------------------------
camp_dir() { echo "$PARTAGE/campagnes/$CAMPAGNE"; }

derniere_campagne() { ls -1t "$PARTAGE/campagnes" 2>/dev/null | head -1; }

lire_conf_campagne() {   # charge campagne.conf (clé=valeur, sans exécution)
  local f k v; f="$(camp_dir)/campagne.conf"
  [ -f "$f" ] || { echo "Campagne « $CAMPAGNE » introuvable dans $PARTAGE/campagnes." >&2; exit 1; }
  while IFS='=' read -r k v; do
    case "$k" in
      duree) DUREE="$v";; intervalle) INTERVALLE="$v";; debut) DEBUT="$v";; bdd_hote) BDD_HOTE="$v";; bdd_port) BDD_PORT="$v";;
      motifs) MOTIFS="$v";; services) SERVICES="$v";; base) BASE="$v";; sans_sql) [ "$v" = 1 ] && AVEC_SQL=0;; trace_sql) [ "$v" = 1 ] && TRACE_SQL=1;; table_programmes) PROG_TABLE="$v";; serveurs) SERVEURS="$v";;
    esac
  done < "$f"
}

# Copie du dossier local vers le partage (le travail reste local : un partage lent ou figé ne bloque pas la collecte)
synchroniser() {
  [ -n "$CAMPAGNE" ] || return 0
  local dest; dest="$(camp_dir)/$HOTE"
  timeout 120 mkdir -p "$dest" 2>/dev/null
  if existe rsync; then timeout 300 rsync -a "$DOSSIER/" "$dest/" 2>/dev/null; else timeout 300 cp -ru "$DOSSIER/." "$dest/" 2>/dev/null; fi
  { echo "etat=${1:-en_cours}"; echo "maj=$(date +%s)"; echo "roles=$ROLE_TXT"; echo "intervalle=$INTERVALLE"
    echo "echantillons=$(grep -c '^###' "$DOSSIER/series/stat.raw" 2>/dev/null || echo 0)"; echo "dossier_local=$DOSSIER"; } \
    > "$(camp_dir)/.$HOTE.etat.tmp" 2>/dev/null && mv -f "$(camp_dir)/.$HOTE.etat.tmp" "$(camp_dir)/$HOTE.etat" 2>/dev/null \
    || journal "Partage $(camp_dir) inaccessible : données conservées localement ($DOSSIER)"
}

arret_campagne_demande() { [ -n "$CAMPAGNE" ] && timeout 10 test -e "$(camp_dir)/ARRET"; }

# Rapport central de la campagne (tous les serveurs) ; verrou pour ne pas le générer deux fois en même temps
rapport_central() {   # rapport_central [final|periodique]
  [ "$RAPPORT" -eq 1 ] || return 0
  local c; c="$(camp_dir)"
  local py r="$PARTAGE/rapport_audit.py" sortie="$c/rapport_${CAMPAGNE}.html" verrou="$c/.rapport.verrou" n=0
  [ -f "$r" ] || r="$(dirname "$SCRIPT")/rapport_audit.py"
  [ -f "$r" ] || return 0
  py="$(trouver_python)" || { [ "${1:-}" = final ] && journal "Python 2.7 ou 3.6+ absent ici : le rapport central sera produit par un autre serveur (ou « campagne rapport »)"; return 0; }
  if [ "${1:-}" = periodique ] && [ -f "$sortie" ] && [ $(( $(date +%s) - $(stat -c %Y "$sortie") )) -lt 1500 ]; then return 0; fi
  if [ "${1:-}" = final ]; then   # attendre la fin des autres serveurs (15 min au plus) pour un rapport complet
    local t_lim=$(( $(date +%s) + 900 ))
    while [ "$(date +%s)" -lt "$t_lim" ] && grep -l '^etat=en_cours' "$c"/*.etat 2>/dev/null | while read -r f; do
        [ $(( $(date +%s) - $(awk -F= '$1=="maj"{print $2}' "$f") )) -lt 900 ] && echo x; done | grep -q x; do
      sleep 20
    done
  fi
  find "$verrou" -maxdepth 0 -mmin +15 -exec rmdir {} \; 2>/dev/null   # verrou abandonné
  until mkdir "$verrou" 2>/dev/null; do
    [ "${1:-}" = periodique ] && return 0
    n=$((n + 1)); [ "$n" -gt 60 ] && return 0; sleep 5
  done
  if timeout 900 nice -n 19 $py "$r" "$c" -o "$sortie" > "$c/.rapport_${HOTE}.log" 2>&1; then
    journal "Rapport central mis à jour : $sortie"
  else
    journal "Échec du rapport central (voir $c/.rapport_${HOTE}.log)"
  fi
  rmdir "$verrou" 2>/dev/null
}

est_local() { [ "$1" = "$HOTE" ] || [ "$1" = "$(hostname -f 2>/dev/null)" ] || [ "$1" = localhost ]; }

cmd_campagne() {
  local sous="${1:-}"; shift || true
  [ -n "${1:-}" ] && [[ "$1" != --* ]] && [ "$sous" != marquer ] && { CAMPAGNE="$1"; shift; }
  analyser_options "$@"
  [ "$sous" = marquer ] && { [ -n "$CAMPAGNE" ] || CAMPAGNE="$(derniere_campagne)"; cmd_marquer "${RESTE[@]:-}"; return; }
  case "$sous" in
    demarrer) [ -n "$CAMPAGNE" ] || CAMPAGNE="$(date +%Y%m%d)" ;;
    *) [ -n "$CAMPAGNE" ] || CAMPAGNE="$(derniere_campagne)"; [ -n "$CAMPAGNE" ] || { echo "Aucune campagne dans $PARTAGE/campagnes." >&2; exit 1; } ;;
  esac
  [[ "$CAMPAGNE" =~ ^[A-Za-z0-9._-]+$ ]] || { echo "Nom de campagne invalide : $CAMPAGNE" >&2; exit 1; }
  local c; c="$(camp_dir)"
  case "$sous" in
    demarrer)
      [ "$(id -u)" -eq 0 ] || { echo "À lancer en root." >&2; exit 1; }
      mkdir -p "$c" 2>/dev/null && touch "$c/.test_ecriture" 2>/dev/null && rm -f "$c/.test_ecriture" \
        || { echo "Écriture impossible dans $c (partage en lecture seule ou « root_squash » ?)." >&2; exit 1; }
      [ -f "$c/campagne.conf" ] && grep -lq '^etat=en_cours' "$c"/*.etat 2>/dev/null && { echo "La campagne $CAMPAGNE est déjà en cours." >&2; exit 1; }
      rm -f "$c/ARRET"
      { echo "nom=$CAMPAGNE"; echo "creee_le=$(date '+%F %T')"; echo "par=${SUDO_USER:-${USER:-root}}@$HOTE"; echo "debut=$DEBUT"; echo "duree=$DUREE"
        echo "intervalle=$INTERVALLE"; echo "bdd_hote=$BDD_HOTE"; echo "bdd_port=$BDD_PORT"; echo "motifs=$MOTIFS"; echo "services=$SERVICES"; echo "base=$BASE"; echo "sans_sql=$((1 - AVEC_SQL))"; echo "trace_sql=$TRACE_SQL"
        echo "table_programmes=$PROG_TABLE"; echo "serveurs=${SERVEURS:-$HOTE}"; } > "$c/campagne.conf"
      echo "Campagne $CAMPAGNE : $c"
      local srv
      for srv in ${SERVEURS:-$HOTE}; do
        if est_local "$srv"; then
          local ifx=(); [ -n "$INFORMIXDIR_OPT" ] && ifx+=(--informixdir "$INFORMIXDIR_OPT")
          [ -n "$INFORMIXSERVER_OPT" ] && ifx+=(--informixserver "$INFORMIXSERVER_OPT"); [ -n "$ONCONFIG_OPT" ] && ifx+=(--onconfig "$ONCONFIG_OPT")
          bash "$SCRIPT" campagne rejoindre "$CAMPAGNE" --partage "$PARTAGE" --sortie "$SORTIE" "${ifx[@]}" | sed "s/^/  [$srv] /"
        elif ssh -n -o BatchMode=yes -o ConnectTimeout=5 "root@$srv" "bash '$SCRIPT' campagne rejoindre '$CAMPAGNE' --partage '$PARTAGE'" 2>&1 | sed "s/^/  [$srv] /"; then
          :
        else
          echo "  [$srv] SSH impossible : lancer sur ce serveur (en root) : bash $SCRIPT campagne rejoindre $CAMPAGNE"
        fi
      done
      echo; echo "Suivi : $SCRIPT campagne etat   ·   signalement : $SCRIPT marquer \"texte\"   ·   rapport à tout moment : $SCRIPT campagne rapport"
      ;;
    rejoindre)
      lire_conf_campagne
      [ -n "$BDD_HOTE" ] && est_local "$BDD_HOTE" && BDD_HOTE=""   # pas de mesure de latence de la base vers elle-même
      cmd_supervision
      ;;
    etat)
      lire_conf_campagne
      echo "Campagne $CAMPAGNE ($c) : début ${DEBUT:-immédiat}, durée $DUREE, intervalle $INTERVALLE s"
      [ -e "$c/ARRET" ] && echo "Arrêt demandé."
      printf '%-14s %-34s %-10s %-20s %s\n' Serveur 'Rôle(s)' État 'Dernier relevé' Échantillons
      local f now; now=$(date +%s)
      for srv in $( { printf '%s\n' $SERVEURS; ls "$c" 2>/dev/null | sed -n 's/\.etat$//p'; } | awk '!v[$0]++'); do
        f="$c/$srv.etat"
        if [ -f "$f" ]; then
          local etat maj roles ech
          etat="$(awk -F= '$1=="etat"{print $2}' "$f")"; maj="$(awk -F= '$1=="maj"{print $2}' "$f")"
          roles="$(awk -F= '$1=="roles"{print $2}' "$f")"; ech="$(awk -F= '$1=="echantillons"{print $2}' "$f")"
          [ "$etat" = en_cours ] && [ $(( now - maj )) -gt 900 ] && etat="silencieux"
          printf '%-14s %-34s %-10s %-20s %s\n' "$srv" "$roles" "$etat" "$(date -d "@$maj" '+%d/%m %H:%M:%S')" "$ech"
        else
          printf '%-14s %-34s %-10s\n' "$srv" "-" "$([ -n "$DEBUT" ] && echo programmé || echo absent)"
        fi
      done
      [ -f "$c/marqueurs.txt" ] && echo "Signalements : $(wc -l < "$c/marqueurs.txt")"
      [ -f "$c/rapport_$CAMPAGNE.html" ] && echo "Rapport central : $c/rapport_$CAMPAGNE.html (mis à jour le $(date -r "$c/rapport_$CAMPAGNE.html" '+%d/%m %H:%M'))"
      ;;
    rapport)
      local py; py="$(trouver_python)" || { echo "Python 2.7 ou 3.6+ requis sur ce serveur pour générer le rapport." >&2; exit 1; }
      $py "$PARTAGE/rapport_audit.py" "$c" -o "$c/rapport_${CAMPAGNE}.html"
      ;;
    arreter)
      touch "$c/ARRET" && echo "Arrêt demandé : chaque serveur termine son relevé en cours, synchronise ses données puis le rapport central est produit."
      ;;
    *) sed -n '3,31p' "$SCRIPT"; exit 1 ;;
  esac
}

cmd_instantane() {
  preparer
  journal "Collecte de la configuration système..."; statique_systeme
  journal "Collecte Informix..."; statique_informix
  journal "Échantillons (3 x $INTERVALLE s)..."
  for n in 1 2 3; do
    echantillon_systeme; echantillon_services; echantillon_informix; echantillon_latence
    [ $n -eq 1 ] && { echantillon_processus; echantillon_informix_lent; echantillon_informix_lourd; }
    [ $n -lt 3 ] && sleep "$INTERVALLE"
  done
  echantillon_informix_lent
  profils_objets
  programmes_final
  terminer
}

boucle_supervision() {
  local fin=$(( $(date +%s) + $(duree_s "$DUREE") )) n=0
  local p5=$(( 300 / INTERVALLE )) p15=$(( 900 / INTERVALLE )) p2=$(( 120 / INTERVALLE )) p30=$(( 1800 / INTERVALLE ))
  [ "$p5" -ge 1 ] || p5=1; [ "$p15" -ge 1 ] || p15=1; [ "$p2" -ge 1 ] || p2=1; [ "$p30" -ge 1 ] || p30=1
  journal "Supervision jusqu'à $(date -d "@$fin" '+%H:%M') (un échantillon toutes les $INTERVALLE s)"
  trap 'journal "Arrêt demandé"; terminer; exit 0' TERM INT
  while [ "$(date +%s)" -lt "$fin" ]; do
    arret_campagne_demande && { journal "Arrêt de la campagne demandé"; break; }
    local t0; t0=$(date +%s)
    echantillon_systeme
    echantillon_services
    echantillon_informix
    (( n % p2 == 0 )) && echantillon_latence
    (( n % p5 == 0 )) && { echantillon_processus; echantillon_informix_lent; }
    (( n % p15 == 0 )) && echantillon_informix_lourd
    (( n % p5 == 0 )) && synchroniser
    # rapport central intermédiaire toutes les 30 min, généré par un serveur sans base Informix (pas de charge sur la base)
    (( n > 0 && n % p30 == 0 )) && [ -n "$CAMPAGNE" ] && [ "$IFX" -eq 0 ] && ( rapport_central periodique ) &
    n=$((n + 1))
    local reste=$(( INTERVALLE - ($(date +%s) - t0) ))
    if [ "$reste" -gt 0 ]; then sleep "$reste" & wait $!; fi   # « wait » : l'arrêt est pris en compte immédiatement
  done
  echantillon_informix_lent
  profils_objets
  programmes_final
  terminer
}

executer_supervision() {   # processus détaché (lancé par cmd_supervision)
  echo $$ > "$SORTIE/supervision.pid"
  if [ -n "$DEBUT" ]; then
    local cible; cible=$(date -d "$DEBUT" +%s); [ "$cible" -lt "$(date +%s)" ] && cible=$(date -d "tomorrow $DEBUT" +%s)
    trap 'rm -f "$SORTIE/supervision.pid"; exit 0' TERM INT
    sleep $(( cible - $(date +%s) )) & wait $!
    trap - TERM INT
  fi
  preparer
  synchroniser
  statique_systeme
  statique_informix
  synchroniser
  boucle_supervision
}

cmd_supervision() {
  [ "$(id -u)" -eq 0 ] || { echo "À lancer en root." >&2; exit 1; }
  [ "$INTERVALLE" -ge 10 ] || INTERVALLE=10
  mkdir -p "$SORTIE"
  if [ -f "$SORTIE/supervision.pid" ] && kill -0 "$(cat "$SORTIE/supervision.pid")" 2>/dev/null; then
    echo "Une supervision est déjà en cours (pid $(cat "$SORTIE/supervision.pid"))." >&2; exit 1
  fi
  if [ -n "$CAMPAGNE" ]; then
    touch "$(camp_dir)/.test_$HOTE" 2>/dev/null && rm -f "$(camp_dir)/.test_$HOTE" \
      || { echo "Écriture impossible dans $(camp_dir) depuis $HOTE (partage monté ? « no_root_squash » ?)." >&2; exit 1; }
  fi
  [ -n "$DEBUT" ] && echo "Démarrage programmé à $DEBUT."
  local a=(--duree "$DUREE" --intervalle "$INTERVALLE" --sortie "$SORTIE" --partage "$PARTAGE" --motifs "$MOTIFS" --services "$SERVICES" --base "$BASE" --role "$ROLE"
           --table-programmes "$PROG_TABLE")
  [ -n "$DEBUT" ] && a+=(--debut "$DEBUT"); [ -n "$BDD_HOTE" ] && a+=(--bdd-hote "$BDD_HOTE"); [ -n "$BDD_PORT" ] && a+=(--bdd-port "$BDD_PORT")
  [ -n "$CAMPAGNE" ] && a+=(--campagne "$CAMPAGNE"); [ "$AVEC_SQL" -eq 0 ] && a+=(--sans-sql); [ "$TRACE_SQL" -eq 1 ] && a+=(--trace-sql); [ "$RAPPORT" -eq 0 ] && a+=(--sans-rapport)
  [ -n "$INFORMIXDIR_OPT" ] && a+=(--informixdir "$INFORMIXDIR_OPT"); [ -n "$INFORMIXSERVER_OPT" ] && a+=(--informixserver "$INFORMIXSERVER_OPT")
  [ -n "$ONCONFIG_OPT" ] && a+=(--onconfig "$ONCONFIG_OPT")
  # nouvelle session (setsid) : la supervision continue après la fermeture de la connexion SSH
  setsid nohup bash "$SCRIPT" _executer "${a[@]}" </dev/null >/dev/null 2>&1 &
  sleep 2
  echo "Supervision lancée en arrière-plan sur $HOTE (pid $(cat "$SORTIE/supervision.pid" 2>/dev/null)), durée $DUREE, intervalle $INTERVALLE s${CAMPAGNE:+, campagne $CAMPAGNE}."
  [ -z "$CAMPAGNE" ] && echo "Suivi : $0 statut   ·   signaler une lenteur : $0 marquer \"description\"   ·   arrêt anticipé : $0 arreter"
  return 0
}

cmd_marquer() {
  local texte="${*:-lenteur signalée}" ligne
  ligne="$(date +%s)|$(date '+%F %T')|${SUDO_USER:-${USER:-$(id -un)}}@$HOTE|${texte//|//}"
  # campagne : signalement central (partage), quel que soit le serveur où la commande est tapée
  [ -z "$CAMPAGNE" ] && [ -f "$EN_COURS_LIEN/info.txt" ] && CAMPAGNE="$(awk -F= '$1=="campagne"{print $2}' "$EN_COURS_LIEN/info.txt")"
  [ -z "$CAMPAGNE" ] && [ ! -d "$EN_COURS_LIEN" ] && CAMPAGNE="$(derniere_campagne)"
  if [ -n "$CAMPAGNE" ] && [ -d "$(camp_dir)" ]; then
    echo "$ligne" >> "$(camp_dir)/marqueurs.txt" || exit 1
  else
    [ -d "$EN_COURS_LIEN" ] || { echo "Aucune supervision ni campagne en cours." >&2; exit 1; }
    echo "$ligne" >> "$EN_COURS_LIEN/marqueurs.txt"
  fi
  echo "Signalement enregistré à $(date '+%H:%M:%S') : $texte"
}

cmd_statut() {
  if [ -f "$SORTIE/supervision.pid" ] && kill -0 "$(cat "$SORTIE/supervision.pid")" 2>/dev/null; then
    echo "Supervision en cours (pid $(cat "$SORTIE/supervision.pid"))"
    [ -d "$EN_COURS_LIEN" ] && { echo "Dossier : $(readlink -f "$EN_COURS_LIEN")"; tail -n 5 "$EN_COURS_LIEN/journal.txt" 2>/dev/null
      echo "Échantillons : $(grep -c '^###' "$EN_COURS_LIEN/series/stat.raw" 2>/dev/null || echo 0)"; du -sh "$EN_COURS_LIEN/" 2>/dev/null; }
  else
    echo "Aucune supervision en cours."
  fi
  ls -1t "$SORTIE"/*.tar.gz 2>/dev/null | head -5 | sed 's/^/Archive : /'
}

cmd_arreter() {
  [ -f "$SORTIE/supervision.pid" ] || { echo "Aucune supervision en cours."; exit 0; }
  local pid; pid="$(cat "$SORTIE/supervision.pid")"
  kill -TERM "$pid" 2>/dev/null && echo "Arrêt demandé (pid $pid) : l'archive est finalisée dans quelques secondes."
}

# ---------------------------------------------------------------------------------------------
ACTION="${1:-}"; shift || true
RESTE=()
analyser_options() {
while [ $# -gt 0 ]; do
  case "$1" in
    --partage) PARTAGE="$(readlink -f "$2")"; shift 2;; --campagne) CAMPAGNE="$2"; shift 2;; --serveurs) SERVEURS="${2//,/ }"; shift 2;;
    --table-programmes) PROG_TABLE="$2"; shift 2;;
    --duree) DUREE="$2"; shift 2;; --intervalle) INTERVALLE="$2"; shift 2;; --debut) DEBUT="$2"; shift 2;;
    --sortie) SORTIE="$2"; EN_COURS_LIEN="$SORTIE/en-cours"; shift 2;;
    --bdd-hote) BDD_HOTE="$2"; shift 2;; --bdd-port) BDD_PORT="$2"; shift 2;; --motifs) MOTIFS="$2"; shift 2;; --services) SERVICES="$2"; shift 2;; --base) BASE="$2"; shift 2;;
    --role) ROLE="$2"; shift 2;; --sans-sql) AVEC_SQL=0; shift;; --trace-sql) TRACE_SQL=1; shift;; --sans-rapport) RAPPORT=0; shift;;
    --informixdir) INFORMIXDIR_OPT="$2"; shift 2;; --informixserver) INFORMIXSERVER_OPT="$2"; shift 2;; --onconfig) ONCONFIG_OPT="$2"; shift 2;;
    --*) echo "Option inconnue : $1" >&2; exit 1;;
    *) RESTE+=("$1"); shift;;
  esac
done
}
if [ "$ACTION" = campagne ]; then cmd_campagne "$@"; exit $?; fi
analyser_options "$@"
case "$ACTION" in
  instantane) cmd_instantane ;;
  supervision) cmd_supervision ;;
  marquer) cmd_marquer "${RESTE[@]:-}" ;;
  statut) cmd_statut ;;
  arreter) cmd_arreter ;;
  _executer) executer_supervision ;;  # interne
  *) sed -n '3,31p' "$0"; exit 1 ;;
esac
