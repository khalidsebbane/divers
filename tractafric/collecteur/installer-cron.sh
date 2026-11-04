#!/bin/bash
# Installe (ou retire) la collecte périodique dans la crontab du compte courant (root, ou informix sans root).
#   ./installer-cron.sh              installe, à la fréquence FREQUENCE_MIN du fichier de configuration
#   ./installer-cron.sh --retirer    retire la ligne
#   ./installer-cron.sh --tester     lance une collecte immédiate et affiche le résultat
set -eu
ICI="$(cd "$(dirname "$0")" && pwd)"
CONF="$(dirname "$ICI")/tractafric.conf"
MARQUE="# portail-infra-irium"
[ -r "$CONF" ] || { echo "copier d'abord tractafric.conf.exemple en tractafric.conf et l'adapter" >&2; exit 1; }
. "$CONF"
FREQ="${FREQUENCE_MIN:-15}"
mkdir -p "${PARTAGE:?PARTAGE absent de la configuration}/journal" 2>/dev/null && [ -w "$PARTAGE" ] || \
  { echo "le dossier $PARTAGE n'est pas inscriptible par $(id -un) : choisir un PARTAGE à lui (ex. \$HOME/portail-infra-central)" >&2; exit 1; }
actuelle="$(crontab -l 2>/dev/null | grep -vF "$MARQUE" || true)"
case "${1:-}" in
  --retirer) printf '%s\n' "$actuelle" | crontab -; echo "collecte retirée de la crontab de $(id -un)"; exit 0 ;;
  --tester)  "$ICI/collecte.sh"; tail -5 "${PARTAGE}/journal/collecte_$(hostname -s).log"; exit 0 ;;
esac
chmod 755 "$ICI/collecte.sh"
printf '%s\n%s\n' "$actuelle" "*/$FREQ * * * * $ICI/collecte.sh >/dev/null 2>&1 $MARQUE" | sed '/^$/d' | crontab -
echo "collecte installée dans la crontab de $(id -un) : toutes les $FREQ minutes ($(crontab -l | grep -F "$MARQUE"))"
