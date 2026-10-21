#!/bin/bash
# =============================================================================================
# SIEM Informix - mode local (test, sans portail) : collecte automatique archivée + rapports HTML.
#
#   ./siem-local.sh installer [--base NOM_BASE] [--jours 45]   installation (en root, depuis ce dossier)
#        options : --informixdir /opt/informix --informixserver ol_prod --onconfig onconfig.ol_prod (si non détectés)
#   ./siem-local.sh collecter                                   une passe de collecte (lancée par cron)
#   ./siem-local.sh rapport [options de rapport_local.py]       rapport HTML (ex. --ip 10.x.x.x, --utilisateur x)
#   ./siem-local.sh poste <IP> [--depuis AAAA-MM-JJ]            enquête détaillée sur un poste (rapport_poste.py)
#   ./siem-local.sh statut                                      état de la collecte
#   ./siem-local.sh desinstaller [--tout]                       retire la tâche cron (--tout : supprime aussi les données)
#
# Emplacements : programme et configuration dans /msdos/ks/siem, archive dans /msdos/ks/siem/donnees,
# rapports dans /msdos/ks/rapports et dernier rapport global dans /msdos/ks/rapport-siem.html
# =============================================================================================
set -euo pipefail
RACINE="${SIEM_RACINE:-/msdos/ks}"
DOSSIER="$RACINE/siem"
ICI="$(cd "$(dirname "$0")" && pwd)"

python_systeme() {
  for p in /usr/libexec/platform-python /usr/bin/python3 /usr/bin/python3.6 python3; do
    command -v "$p" >/dev/null 2>&1 && "$p" -c 'import sys; sys.exit(sys.version_info < (3, 6))' 2>/dev/null && { command -v "$p"; return; }
  done
  echo "Aucun Python 3.6+ (ni /usr/libexec/platform-python, ni python3)." >&2; exit 1
}

cmd_installer() {
  local base="" jours=45 ifxdir="" ifxsrv="" onconf=""
  while [ $# -gt 0 ]; do case "$1" in
    --base) base="$2"; shift 2;; --jours) jours="$2"; shift 2;;
    --informixdir) ifxdir="$2"; shift 2;; --informixserver) ifxsrv="$2"; shift 2;; --onconfig) onconf="$2"; shift 2;;
    *) echo "option inconnue : $1" >&2; exit 1;; esac; done
  [ "$(id -u)" -eq 0 ] || { echo "À lancer en root (lecture de /var/log/secure, btmp, audit.log)." >&2; exit 1; }
  for f in collecteur.py rapport_local.py rapport_poste.py siem-local.sh; do
    [ -f "$ICI/$f" ] || { echo "$f introuvable à côté du script." >&2; exit 1; }
  done
  local py; py="$(python_systeme)"
  echo "1/6 Python système : $py"

  install -d -m 0750 "$DOSSIER" "$DOSSIER/donnees" "$DOSSIER/var" "$RACINE/rapports"
  if [ "$ICI" != "$DOSSIER" ]; then
    install -m 0750 "$ICI/collecteur.py" "$ICI/rapport_local.py" "$ICI/rapport_poste.py" "$ICI/siem-local.sh" "$DOSSIER/"
    [ -d "$ICI/auditd" ] && cp -r "$ICI/auditd" "$DOSSIER/"
  fi
  echo "2/6 Programmes installés dans $DOSSIER"

  # Environnement Informix relevé sur le compte informix (profil bash, puis shell du compte)
  local sources="wtmp,btmp,secure,auditd"
  if id informix >/dev/null 2>&1; then
    local envifx; envifx="$( (su - informix -s /bin/bash -c env; su - informix -c env) 2>/dev/null || true)"
    [ -n "$ifxdir" ] || ifxdir="$(echo "$envifx" | sed -n 's/^INFORMIXDIR=//p' | head -1)"
    [ -n "$ifxsrv" ] || ifxsrv="$(echo "$envifx" | sed -n 's/^INFORMIXSERVER=//p' | head -1)"
    [ -n "$onconf" ] || onconf="$(echo "$envifx" | sed -n 's/^ONCONFIG=//p' | head -1)"
  fi
  if [ -z "$ifxdir" ]; then
    for d in /opt/informix /informix /usr/informix /home/informix; do [ -x "$d/bin/dbaccess" ] && { ifxdir="$d"; break; }; done
  fi
  [ -n "$ifxsrv" ] && sources="$sources,sessions"
  [ -n "$base" ] && sources="$sources,applicatif"
  echo "3/6 Informix : INFORMIXDIR=${ifxdir:-?} INFORMIXSERVER=${ifxsrv:-?} ONCONFIG=${onconf:-?} base agr_lds=${base:-non renseignée}"

  if [ ! -f "$DOSSIER/collecteur.ini" ]; then
    cat > "$DOSSIER/collecteur.ini" <<EOF
# Configuration générée par siem-local.sh (mode local, sans portail)
[collecteur]
dossier = $DOSSIER/var
sources = $sources
historique_jours = $jours

[portail]
url =

[systeme]
wtmp = /var/log/wtmp*
btmp = /var/log/btmp*
secure = /var/log/secure*
auditd = /var/log/audit/audit.log*

[informix]
informixdir = ${ifxdir:-/opt/informix}
informixserver = $ifxsrv
onconfig = $onconf
dbdate = Y4MD-
encodage = latin-1
timeout = 120
resoudre_ip = oui
# Audit Informix : décommenter une fois onaudit activé (docs/informix-audit.md)
# commande_onshowaudit = onshowaudit -n $ifxsrv
audit_champ_date = 1
audit_champ_machine = 2
audit_champ_pid = 3
audit_champ_utilisateur = 5
audit_champ_erreur = 6
audit_champ_code = 7
audit_champ_objet = 8

[applicatif]
base = $base
table = agr_lds
filtre = (alds_complement IS NULL OR alds_complement NOT MATCHES 'Xp_cron*')
compte_base = regix
colonne_date = alds_open
EOF
    chmod 0600 "$DOSSIER/collecteur.ini"
    echo "4/6 Configuration créée : $DOSSIER/collecteur.ini"
  else
    echo "4/6 Configuration existante conservée : $DOSSIER/collecteur.ini"
  fi

  cat > /etc/cron.d/siem-local <<EOF
# SIEM Informix - mode local : collecte toutes les 5 minutes, rapport global chaque matin à 6h30
SHELL=/bin/bash
*/5 * * * * root $DOSSIER/siem-local.sh collecter >> $DOSSIER/var/collecte.log 2>&1
30 6 * * * root $DOSSIER/siem-local.sh rapport >> $DOSSIER/var/rapport.log 2>&1
EOF
  chmod 0644 /etc/cron.d/siem-local
  echo "5/6 Tâche planifiée : /etc/cron.d/siem-local"

  echo "6/6 Première collecte (reprise de $jours jours d'historique) et premier rapport..."
  "$DOSSIER/siem-local.sh" collecter
  "$DOSSIER/siem-local.sh" rapport || true
  echo
  echo "Installation terminée. Rapport : $RACINE/rapport-siem.html"
}

cmd_collecter() {
  local py; py="$(python_systeme)"
  install -d "$DOSSIER/var" "$DOSSIER/donnees"
  # une seule collecte à la fois
  exec 9>"$DOSSIER/var/collecte.verrou"
  flock -n 9 || { echo "$(date '+%F %T') collecte déjà en cours"; return 0; }
  "$py" "$DOSSIER/collecteur.py" -c "$DOSSIER/collecteur.ini" --sortie "$DOSSIER/donnees/evenements-$(date +%Y-%m).jsonl"
}

cmd_rapport() {
  local py; py="$(python_systeme)"
  local partages="regix,informix,root"
  "$py" "$DOSSIER/rapport_local.py" --archive "$DOSSIER/donnees" --postes "$DOSSIER/postes.csv" --partages "$partages" \
    --sortie "$RACINE/rapports" --dernier "$RACINE/rapport-siem.html" "$@"
}

cmd_poste() {
  [ $# -ge 1 ] || { echo "usage : siem-local.sh poste <IP> [--depuis AAAA-MM-JJ] [--nom NOM-DU-PC]" >&2; exit 1; }
  local ip="$1"; shift
  local py; py="$(python_systeme)"
  "$py" "$DOSSIER/rapport_poste.py" --ip "$ip" -c "$DOSSIER/collecteur.ini" -o "$RACINE/rapports" "$@"
}

cmd_statut() {
  echo "Dossier      : $DOSSIER"
  echo "Tâche cron   : $( [ -f /etc/cron.d/siem-local ] && echo active || echo absente )"
  echo "Archive      :"; ls -lh "$DOSSIER"/donnees/evenements-*.jsonl* 2>/dev/null | awk '{print "  " $9 "  " $5}' || echo "  vide"
  echo "Points de reprise :"; sed -n '/points/,/}/p' "$DOSSIER/var/etat.json" 2>/dev/null | grep '"' || echo "  aucun"
  echo "Dernières collectes :"; tail -n 8 "$DOSSIER/var/collecte.log" 2>/dev/null || echo "  aucune"
  echo "Dernier rapport : $(ls -l --time-style='+%d/%m/%Y %H:%M' "$RACINE/rapport-siem.html" 2>/dev/null | awk '{print $6, $7}')"
}

cmd_desinstaller() {
  rm -f /etc/cron.d/siem-local
  echo "Tâche planifiée retirée."
  if [ "${1:-}" = "--tout" ]; then
    rm -rf "$DOSSIER" "$RACINE/rapports" "$RACINE/rapport-siem.html"
    echo "Programmes, archive et rapports supprimés."
  else
    echo "Archive conservée dans $DOSSIER/donnees (à importer dans le portail : python -m app.outils importer <fichier>)."
  fi
}

action="${1:-}"; shift || true
case "$action" in
  installer) cmd_installer "$@" ;;
  collecter) cmd_collecter ;;
  rapport) cmd_rapport "$@" ;;
  poste) cmd_poste "$@" ;;
  statut) cmd_statut ;;
  desinstaller) cmd_desinstaller "$@" ;;
  *) sed -n '3,15p' "$0"; exit 1 ;;
esac
