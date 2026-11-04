#!/bin/bash
# À lancer UNE fois, en root, sur le serveur CENTRAL (ex. REPL) : met en place la collecte centralisée par SSH.
#   ./deployer-ssh.sh                      tous les serveurs de SERVEURS (sauf le central)
#   ./deployer-ssh.sh APP1 APP2            seulement ceux-là (ajout d'un serveur, mise à jour du collecteur)
#   ./deployer-ssh.sh --desinstaller [APP1 ...]
# Le compte d'administration utilisé pour le déploiement se choisit avec ADMIN=compte (défaut root) ;
# s'il n'est pas root, il doit avoir sudo sur les serveurs (le mot de passe est demandé).
set -eu
ICI="$(cd "$(dirname "$0")" && pwd)"; RACINE="$(dirname "$ICI")"; CONF="$RACINE/tractafric.conf"
[ "$(id -u)" -eq 0 ] || { echo "à lancer en root sur le serveur central" >&2; exit 1; }
[ -r "$CONF" ] || { echo "copier d'abord tractafric.conf.exemple en tractafric.conf et l'adapter" >&2; exit 1; }
. "$CONF"
RETIRER=0; [ "${1:-}" = "--desinstaller" ] && { RETIRER=1; shift; }
CIBLES=" $* "
ADMIN="${ADMIN:-root}"; COMPTE="${COMPTE_SSH:-root}"; CLE="${CLE_SSH:-/root/.ssh/portail_infra}"; PORT="${PORT_SSH:-22}"
[ "${MODE:-}" = central ] || { echo "MODE=central attendu dans $CONF" >&2; exit 1; }
[ -n "${CENTRAL:-}" ] || { echo "CENTRAL (nom du serveur central, ex. REPL) attendu dans $CONF" >&2; exit 1; }
IP_CENTRAL=""
for s in $SERVEURS; do IFS=: read -r n h r ip <<< "$s"; [ "$n" = "$CENTRAL" ] && IP_CENTRAL="$ip"; done
[ -n "$IP_CENTRAL" ] || { echo "IP du serveur $CENTRAL absente de SERVEURS (format NOM:hote:role:IP)" >&2; exit 1; }

if [ ! -f "$CLE" ]; then
  install -d -m 700 "$(dirname "$CLE")"
  ssh-keygen -q -t ed25519 -N '' -C "portail-infra@$(hostname -s)" -f "$CLE"
  echo "Clé du portail créée : $CLE"
fi
PUB="$(cat "$CLE.pub")"
SUDO=""; [ "$ADMIN" != root ] && SUDO="sudo"
KH=/root/.ssh/known_hosts; touch "$KH"; chmod 600 "$KH"
BILAN=()

for s in $SERVEURS; do
  IFS=: read -r NOM HOTE ROLE IP <<< "$s"
  [ "$NOM" = "$CENTRAL" ] && continue
  [ "$CIBLES" = "  " ] || [[ "$CIBLES" == *" $NOM "* ]] || continue
  CIBLE="${IP:-$HOTE}"
  echo; echo "=== $NOM ($ROLE) : $CIBLE"
  if ! ssh-keygen -F "$CIBLE" -f "$KH" >/dev/null 2>&1 && ! ssh-keygen -F "[$CIBLE]:$PORT" -f "$KH" >/dev/null 2>&1; then
    ssh-keyscan -p "$PORT" -t ed25519,ecdsa,rsa "$CIBLE" 2>/dev/null > "$KH.nouveau" || true
    [ -s "$KH.nouveau" ] || { echo "  injoignable sur le port $PORT"; BILAN+=("$NOM : injoignable"); rm -f "$KH.nouveau"; continue; }
    echo "  Empreinte(s) de $CIBLE (à comparer avec « ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub » sur le serveur) :"
    ssh-keygen -lf "$KH.nouveau" | sed 's/^/    /'
    cat "$KH.nouveau" >> "$KH"; rm -f "$KH.nouveau"
  fi
  DEPOT="portail-infra-depot"
  if [ "$RETIRER" -eq 1 ]; then
    scp -q -P "$PORT" "$ICI/installer-distant.sh" "$ADMIN@$CIBLE:" && \
      ssh -t -p "$PORT" "$ADMIN@$CIBLE" "$SUDO bash ~/installer-distant.sh --desinstaller --compte $COMPTE; rm -f ~/installer-distant.sh" \
      && BILAN+=("$NOM : retiré") || BILAN+=("$NOM : ÉCHEC du retrait")
    continue
  fi
  # Dépôt temporaire dans le dossier personnel du compte d'administration (ni /tmp ni /var), puis installation en root
  if ssh -p "$PORT" "$ADMIN@$CIBLE" "umask 077; rm -rf ~/$DEPOT && mkdir ~/$DEPOT" && \
     scp -q -P "$PORT" "$ICI/collecte_infra.py" "$ICI/installer-distant.sh" "$CONF" "$ADMIN@$CIBLE:$DEPOT/" && \
     ssh -t -p "$PORT" "$ADMIN@$CIBLE" "$SUDO bash ~/$DEPOT/installer-distant.sh --nom $NOM --role $ROLE --depuis $IP_CENTRAL --compte $COMPTE --cle '$PUB'"; then
    # Test avec la clé du portail : la commande forcée doit renvoyer l'instantané de CE serveur
    if ssh -i "$CLE" -o BatchMode=yes -o ConnectTimeout=10 -p "$PORT" "$COMPTE@$CIBLE" collecte 2>/dev/null | tail -1 | grep -q "\"nom\": \"$NOM\""; then
      BILAN+=("$NOM : OK")
    else
      BILAN+=("$NOM : installé, mais le test avec la clé du portail échoue (voir PermitRootLogin, AllowUsers, from=)")
    fi
  else
    BILAN+=("$NOM : ÉCHEC de l'installation")
  fi
done

echo; echo "=== Bilan"; printf '  %s\n' "${BILAN[@]:-aucun serveur traité}"
if [ "$RETIRER" -eq 0 ]; then
  echo; echo "Étapes suivantes sur $CENTRAL :"
  echo "  $ICI/installer-cron.sh --tester    # collecte de tous les serveurs + génération du portail"
  echo "  $ICI/installer-cron.sh             # collecte toutes les ${FREQUENCE_MIN:-15} minutes"
fi
