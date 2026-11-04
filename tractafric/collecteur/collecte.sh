#!/bin/bash
# Lancé par cron sur chaque serveur : instantané du serveur, puis génération du portail sur le serveur GENERATEUR.
#   collecte.sh [--conf fichier] [--nom APP1 --role app] [--sans-portail]
set -u
ICI="$(cd "$(dirname "$0")" && pwd)"
CONF="$(dirname "$ICI")/tractafric.conf"
ARGS=() GENERER=1
while [ $# -gt 0 ]; do
  case "$1" in
    --conf) CONF="$2"; shift 2 ;;
    --nom|--role) ARGS+=("$1" "$2"); shift 2 ;;
    --sans-portail) GENERER=0; shift ;;
    *) echo "option inconnue : $1" >&2; exit 2 ;;
  esac
done
[ -r "$CONF" ] || { echo "configuration introuvable : $CONF" >&2; exit 1; }
# shellcheck disable=SC1090
. "$CONF"
PARTAGE="${PARTAGE:-$(dirname "$ICI")/donnees-portail}"
case "$PARTAGE" in /var/*|/tmp/*|/var|/tmp) echo "PARTAGE ne doit pas être sous /var ni /tmp : $PARTAGE" >&2; exit 1 ;; esac
mkdir -p "$PARTAGE/journal" || exit 1
JOURNAL="$PARTAGE/journal/collecte_$(hostname -s).log"
[ -n "${PROFIL_INFORMIX:-}" ] && [ -r "$PROFIL_INFORMIX" ] && . "$PROFIL_INFORMIX" >/dev/null 2>&1
export LC_ALL=C PYTHONIOENCODING=utf-8 PATH="${INFORMIXDIR:+$INFORMIXDIR/bin:}$PATH:/usr/sbin:/sbin"

trouver_python() {
  local p
  for p in /usr/libexec/platform-python python3 python3.6 python2.7 python; do
    command -v "$p" >/dev/null 2>&1 && { command -v "$p"; return 0; }
  done
  for p in /opt/rh/rh-python3*/root/usr/bin/python3; do [ -x "$p" ] && { echo "$p"; return 0; }; done
  return 1
}
PY="$(trouver_python)" || { echo "aucun Python trouvé" >> "$JOURNAL"; exit 1; }

# Pas deux collectes en même temps sur un même serveur ; journal limité à 5 Mo
exec 9> "$PARTAGE/journal/.verrou_$(hostname -s)"
command -v flock >/dev/null 2>&1 && ! flock -n 9 && { echo "$(date '+%F %T') collecte précédente encore en cours" >> "$JOURNAL"; exit 0; }
[ -f "$JOURNAL" ] && [ "$(stat -c %s "$JOURNAL" 2>/dev/null || echo 0)" -gt 5242880 ] && mv -f "$JOURNAL" "$JOURNAL.1"

nice -n 10 "$PY" "$ICI/collecte_infra.py" --conf "$CONF" --partage "$PARTAGE" "${ARGS[@]}" >> "$JOURNAL" 2>&1

# Le serveur GENERATEUR construit le portail à partir des instantanés de tous les serveurs
MOI="$("$PY" -c "import sys; sys.path.insert(0, '$ICI'); import collecte_infra as c; print(c.identifier(c.lire_conf('$CONF'))[0])" 2>/dev/null)"
for a in "${ARGS[@]}"; do [ "${prec:-}" = "--nom" ] && MOI="$a"; prec="$a"; done
if [ "$GENERER" -eq 1 ] && [ -n "${GENERATEUR:-}" ] && [ "$MOI" = "$GENERATEUR" ]; then
  sleep 60   # laisse finir les collectes des autres serveurs lancées à la même minute
  "$PY" "$(dirname "$ICI")/portail/generer_portail.py" --conf "$CONF" --partage "$PARTAGE" >> "$JOURNAL" 2>&1
fi
