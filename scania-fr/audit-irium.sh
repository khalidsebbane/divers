#!/bin/bash
# =============================================================================================
# Audit de performance ERP IRIUM / Informix / RHEL - Scania France
#
# Collecte en LECTURE SEULE toutes les métriques utiles pour identifier la source des lenteurs.
# À lancer en root sur chaque serveur : base principale, réplica (HDR/RSS), serveurs d'applications
# IRIUM, serveur des tâches d'arrière-plan (ipscrond). Le rôle du serveur est détecté automatiquement.
#
#   ./audit-irium.sh instantane                                   photo complète (2 à 3 minutes)
#   ./audit-irium.sh supervision --duree 4h [--intervalle 30]      supervision d'une matinée (en arrière-plan)
#        [--debut 07:30]            attendre cette heure avant de commencer
#        [--bdd-hote srv-bdd]       (serveurs apps / batch) mesurer la latence vers la base
#        [--bdd-port 9088]          port du listener Informix (sqlhosts)
#        [--motifs 'ipscrond|fglrun|...']  processus IRIUM à suivre
#        [--sortie /var/tmp/scania-fr]     dossier de sortie
#        [--sans-sql]               ne pas interroger sysmaster par SQL
#   ./audit-irium.sh marquer "lenteur saisie commande agence Lyon"   noter un signalement utilisateur
#   ./audit-irium.sh statut | arreter
#
# Résultat : <sortie>/<serveur>_<date>/ + archive .tar.gz, à analyser avec rapport_audit.py
# Impact : quelques commandes « onstat » (lecture de la mémoire partagée) et lectures de /proc par minute.
# Aucune commande lourde (oncheck, update statistics...) n'est lancée, rien n'est modifié.
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
MOTIFS='ipscrond|fglrun|fglgo|fglrunner|irium|ips[a-z_]*'
INFORMIXDIR_OPT="" INFORMIXSERVER_OPT="" ONCONFIG_OPT=""
HOTE=$(hostname -s 2>/dev/null || hostname)
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
    for d in /opt/informix /informix /usr/informix /opt/IBM/informix /home/informix; do
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
      *) ROLES+=("bdd") ;;
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
             kernel.sem fs.file-max net.core.somaxconn net.ipv4.tcp_keepalive_time net.core.rmem_max net.core.wmem_max kernel.numa_balancing; do
      echo "$k = $(sysctl -n "$k" 2>/dev/null)"
    done
    echo "transparent_hugepage = $(cat /sys/kernel/mm/transparent_hugepage/enabled 2>/dev/null)"
    echo "transparent_hugepage_defrag = $(cat /sys/kernel/mm/transparent_hugepage/defrag 2>/dev/null)"
    echo "hugepages = $(grep -E 'HugePages_(Total|Free)' /proc/meminfo | tr '\n' ' ')"
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
  local msg; msg="$(timeout 30 onstat -c 2>/dev/null | awk '$1=="MSGPATH"{print $2}')"
  [ -z "$msg" ] && msg="$(grep -E '^\s*MSGPATH' "$cf" 2>/dev/null | awk '{print $2}')"
  [ -f "$msg" ] && tail -n 20000 "$msg" > "$d/online_log.txt"
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
  brut "$i/onstat_u.raw" onstat -u
  { horodatage; timeout 60 onstat -k 2>&1 | tail -3; echo; } >> "$i/onstat_k.raw"
  brut "$i/onstat_rea.raw" onstat -g rea
  brut "$i/onstat_F.raw" onstat -F
  { horodatage; timeout 30 onstat - 2>&1; echo; } >> "$i/onstat_entete.raw"
}

echantillon_informix_lent() {   # toutes les 5 minutes
  [ "$IFX" -eq 1 ] || return 0
  local i="$DOSSIER/informix"
  brut "$i/onstat_glo.raw" onstat -g glo
  brut "$i/onstat_ckp.raw" onstat -g ckp
  brut "$i/onstat_l.raw" onstat -l
  brut "$i/onstat_iof.raw" onstat -g iof
  brut "$i/onstat_dri.raw" onstat -g dri
  brut "$i/onstat_x.raw" onstat -x
  brut "$i/onstat_wai.raw" onstat -g wai
}

echantillon_informix_lourd() {  # toutes les 15 minutes
  [ "$IFX" -eq 1 ] || return 0
  local i="$DOSSIER/informix"
  brut "$i/onstat_ses.raw" onstat -g ses
  brut "$i/onstat_sql.raw" onstat -g sql
  brut "$i/onstat_ath.raw" onstat -g ath
  brut "$i/onstat_repl.raw" onstat -g repl
  brut "$i/onstat_rss.raw" onstat -g rss
  brut "$i/onstat_ppf.raw" onstat -g ppf
  sql_sysmaster
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
    echo "nb_cpu=$(nproc)"; echo "debut=$(date '+%F %T')"; echo "version_script=1.0"
  } > "$DOSSIER/info.txt"
  ln -sfn "$DOSSIER" "$EN_COURS_LIEN"
  journal "Audit $HOTE - rôle(s) : $ROLE_TXT - Informix : $([ "$IFX" -eq 1 ] && echo "oui ($INFORMIXSERVER)" || echo non)"
}

terminer() {
  echo "fin=$(date '+%F %T')" >> "$DOSSIER/info.txt"
  [ "$IFX" -eq 1 ] && { timeout 60 onstat -g ckp > "$DOSSIER/informix/fin_onstat_ckp.txt" 2>&1
    local msg; msg="$(timeout 30 onstat -c 2>/dev/null | awk '$1=="MSGPATH"{print $2}')"; [ -f "$msg" ] && tail -n 20000 "$msg" > "$DOSSIER/informix/fin_online_log.txt"; }
  rm -f "$EN_COURS_LIEN" "$SORTIE/supervision.pid"
  tar -C "$SORTIE" -czf "$DOSSIER.tar.gz" "$(basename "$DOSSIER")" 2>/dev/null
  journal "Terminé. Données : $DOSSIER - Archive : $DOSSIER.tar.gz"
}

cmd_instantane() {
  preparer
  journal "Collecte de la configuration système..."; statique_systeme
  journal "Collecte Informix..."; statique_informix
  journal "Échantillons (3 x $INTERVALLE s)..."
  for n in 1 2 3; do
    echantillon_systeme; echantillon_informix; echantillon_latence
    [ $n -eq 1 ] && { echantillon_processus; echantillon_informix_lent; echantillon_informix_lourd; }
    [ $n -lt 3 ] && sleep "$INTERVALLE"
  done
  echantillon_informix_lent
  terminer
}

boucle_supervision() {
  local fin=$(( $(date +%s) + $(duree_s "$DUREE") )) n=0
  local p5=$(( 300 / INTERVALLE )) p15=$(( 900 / INTERVALLE )) p2=$(( 120 / INTERVALLE ))
  [ "$p5" -ge 1 ] || p5=1; [ "$p15" -ge 1 ] || p15=1; [ "$p2" -ge 1 ] || p2=1
  journal "Supervision jusqu'à $(date -d "@$fin" '+%H:%M') (un échantillon toutes les $INTERVALLE s)"
  trap 'journal "Arrêt demandé"; terminer; exit 0' TERM INT
  while [ "$(date +%s)" -lt "$fin" ]; do
    local t0; t0=$(date +%s)
    echantillon_systeme
    echantillon_informix
    (( n % p2 == 0 )) && echantillon_latence
    (( n % p5 == 0 )) && { echantillon_processus; echantillon_informix_lent; }
    (( n % p15 == 0 )) && echantillon_informix_lourd
    n=$((n + 1))
    local reste=$(( INTERVALLE - ($(date +%s) - t0) ))
    if [ "$reste" -gt 0 ]; then sleep "$reste" & wait $!; fi   # « wait » : l'arrêt est pris en compte immédiatement
  done
  echantillon_informix_lent
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
  statique_systeme
  statique_informix
  boucle_supervision
}

cmd_supervision() {
  [ "$(id -u)" -eq 0 ] || { echo "À lancer en root." >&2; exit 1; }
  [ "$INTERVALLE" -ge 10 ] || INTERVALLE=10
  mkdir -p "$SORTIE"
  if [ -f "$SORTIE/supervision.pid" ] && kill -0 "$(cat "$SORTIE/supervision.pid")" 2>/dev/null; then
    echo "Une supervision est déjà en cours (pid $(cat "$SORTIE/supervision.pid"))." >&2; exit 1
  fi
  [ -n "$DEBUT" ] && echo "Démarrage programmé à $DEBUT."
  # nouvelle session (setsid) : la supervision continue après la fermeture de la connexion SSH
  setsid nohup bash "$(readlink -f "$0")" _executer "${ARGS_ORIG[@]}" </dev/null >/dev/null 2>&1 &
  sleep 2
  echo "Supervision lancée en arrière-plan (pid $(cat "$SORTIE/supervision.pid" 2>/dev/null)), durée $DUREE, intervalle $INTERVALLE s."
  echo "Suivi : $0 statut   ·   signaler une lenteur : $0 marquer \"description\"   ·   arrêt anticipé : $0 arreter"
}

cmd_marquer() {
  local texte="${*:-lenteur signalée}"
  [ -d "$EN_COURS_LIEN" ] || { echo "Aucune supervision en cours sur ce serveur." >&2; exit 1; }
  echo "$(date +%s)|$(date '+%F %T')|${SUDO_USER:-${USER:-$(id -un)}}|$texte" >> "$EN_COURS_LIEN/marqueurs.txt"
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
ARGS_ORIG=("$@")
while [ $# -gt 0 ]; do
  case "$1" in
    --duree) DUREE="$2"; shift 2;; --intervalle) INTERVALLE="$2"; shift 2;; --debut) DEBUT="$2"; shift 2;;
    --sortie) SORTIE="$2"; EN_COURS_LIEN="$SORTIE/en-cours"; shift 2;;
    --bdd-hote) BDD_HOTE="$2"; shift 2;; --bdd-port) BDD_PORT="$2"; shift 2;; --motifs) MOTIFS="$2"; shift 2;;
    --role) ROLE="$2"; shift 2;; --sans-sql) AVEC_SQL=0; shift;;
    --informixdir) INFORMIXDIR_OPT="$2"; shift 2;; --informixserver) INFORMIXSERVER_OPT="$2"; shift 2;; --onconfig) ONCONFIG_OPT="$2"; shift 2;;
    *) [ "$ACTION" = marquer ] && break; echo "Option inconnue : $1" >&2; exit 1;;
  esac
done
case "$ACTION" in
  instantane) cmd_instantane ;;
  supervision) cmd_supervision ;;
  marquer) cmd_marquer "$@" ;;
  statut) cmd_statut ;;
  arreter) cmd_arreter ;;
  _executer) executer_supervision ;;  # interne
  *) sed -n '3,22p' "$0"; exit 1 ;;
esac
