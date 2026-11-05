#!/bin/bash
# À lancer UNE fois sur le serveur CENTRAL (ex. REPL), sous le compte qui portera le cron de collecte (ex. informix,
# ou root s'il est disponible) : met en place la collecte centralisée par SSH.
#   ./deployer-ssh.sh                      tous les serveurs de SERVEURS (sauf le central)
#   ./deployer-ssh.sh APP1 APP2            seulement ceux-là (ajout d'un serveur, mise à jour du collecteur)
#   ./deployer-ssh.sh --desinstaller [APP1 ...]
# ELEVATION=aucune (sans root) : connexion directe sous le compte de collecte de chaque serveur (COMPTE_SSH,
#   COMPTE_SSH_<NOM>), installation dans son dossier personnel. Mot de passe de ce compte demandé une fois par serveur.
# ELEVATION=su ou sudo : connexion sous ADMIN puis passage en root, installation dans /opt/portail-infra.
# Ensuite plus aucun mot de passe : la collecte utilise la clé du portail.
set -eu
ICI="$(cd "$(dirname "$0")" && pwd)"; RACINE="$(dirname "$ICI")"; CONF="$RACINE/tractafric.conf"
[ -r "$CONF" ] || { echo "copier d'abord tractafric.conf.exemple en tractafric.conf et l'adapter" >&2; exit 1; }
. "$CONF"
RETIRER=0; [ "${1:-}" = "--desinstaller" ] && { RETIRER=1; shift; }
CIBLES=" $* "
ADMIN_DEFAUT="${ADMIN:-}"; ELEVATION_DEFAUT="${ELEVATION:-aucune}"; CLE="${CLE_SSH:-$HOME/.ssh/portail_infra}"; PORT="${PORT_SSH:-22}"
mkdir -p "$HOME/.ssh"; chmod 700 "$HOME/.ssh"
[ "${MODE:-}" = central ] || { echo "MODE=central attendu dans $CONF" >&2; exit 1; }
[ -n "${CENTRAL:-}" ] || { echo "CENTRAL (nom du serveur central, ex. REPL) attendu dans $CONF" >&2; exit 1; }
IP_CENTRAL=""
for s in $SERVEURS; do IFS=: read -r n h r ip <<< "$s"; [ "$n" = "$CENTRAL" ] && IP_CENTRAL="$ip"; done
[ -n "$IP_CENTRAL" ] || { echo "IP du serveur $CENTRAL absente de SERVEURS (format NOM:hote:role:IP)" >&2; exit 1; }
# Adresse(s) sous lesquelles le central se présente aux autres serveurs (plusieurs cartes réseau : liste séparée par des virgules)
IP_CENTRAL="${SOURCES_CENTRAL:-$IP_CENTRAL}"

if [ ! -f "$CLE" ]; then
  install -d -m 700 "$(dirname "$CLE")"
  ssh-keygen -q -t ed25519 -N '' -C "portail-infra@$(hostname -s)" -f "$CLE"
  echo "Clé du portail créée : $CLE"
fi
PUB="$(cat "$CLE.pub")"
SSHOPTS=(-p "$PORT" -o ControlMaster=auto -o "ControlPath=$HOME/.ssh/cm-portail-%r@%h:%p" -o ControlPersist=120)
SCPOPTS=(-q -P "$PORT" -o "ControlPath=$HOME/.ssh/cm-portail-%r@%h:%p")
executer() {   # executer <cible> <commande> : sous le compte de connexion (aucune) ou en root (su, sudo)
  if [ "$ADMIN" = root ] || [ "$ELEVATION" = aucune ]; then ssh -t "${SSHOPTS[@]}" "$ADMIN@$1" "$2"
  elif [ "$ELEVATION" = sudo ]; then ssh -t "${SSHOPTS[@]}" "$ADMIN@$1" "sudo bash -c \"$2\""
  else echo "  Mot de passe root de $1 :"; ssh -t "${SSHOPTS[@]}" "$ADMIN@$1" "su - root -c \"$2\""
  fi
}
KH="$HOME/.ssh/known_hosts"; touch "$KH"; chmod 600 "$KH"
BILAN=()

for s in $SERVEURS; do
  IFS=: read -r NOM HOTE ROLE IP <<< "$s"
  [ "$NOM" = "$CENTRAL" ] && continue
  [ "$CIBLES" = "  " ] || [[ "$CIBLES" == *" $NOM "* ]] || continue
  CIBLE="${IP:-$HOTE}"
  # Valeurs propres au serveur : COMPTE_SSH_APP1=irium, ADMIN_APP1=..., ELEVATION_APP1=... l'emportent
  v="COMPTE_SSH_$NOM"; COMPTE="${!v:-${COMPTE_SSH:-root}}"
  v="ELEVATION_$NOM"; ELEVATION="${!v:-${ELEVATION_DEFAUT}}"
  v="ADMIN_$NOM"; ADMIN="${!v:-${ADMIN_DEFAUT:-$COMPTE}}"
  [ "$ELEVATION" = aucune ] && ADMIN="$COMPTE"   # sans root, on ne peut installer que dans le compte de collecte lui-même
  OPT_SUDO=""; [ "${SUDO_COLLECTE:-oui}" = non ] && OPT_SUDO="--sans-sudo"
  ssh -O exit "${SSHOPTS[@]}" "$ADMIN@$CIBLE" 2>/dev/null || true
  echo; echo "=== $NOM ($ROLE) : $CIBLE, compte $COMPTE"
  if ! ssh-keygen -F "$CIBLE" -f "$KH" >/dev/null 2>&1 && ! ssh-keygen -F "[$CIBLE]:$PORT" -f "$KH" >/dev/null 2>&1; then
    ssh-keyscan -p "$PORT" -t ed25519,ecdsa,rsa "$CIBLE" 2>/dev/null > "$KH.nouveau" || true
    [ -s "$KH.nouveau" ] || { echo "  injoignable sur le port $PORT"; BILAN+=("$NOM : injoignable"); rm -f "$KH.nouveau"; continue; }
    echo "  Empreinte(s) de $CIBLE (à comparer avec « ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub » sur le serveur) :"
    ssh-keygen -lf "$KH.nouveau" | sed 's/^/    /'
    cat "$KH.nouveau" >> "$KH"; rm -f "$KH.nouveau"
  fi
  DEPOT="portail-infra-depot"
  if [ "$RETIRER" -eq 1 ]; then
    MAISON="$(ssh "${SSHOPTS[@]}" "$ADMIN@$CIBLE" 'echo $HOME')" && \
      scp "${SCPOPTS[@]}" "$ICI/installer-distant.sh" "$ADMIN@$CIBLE:" && \
      executer "$CIBLE" "bash $MAISON/installer-distant.sh --desinstaller --compte $COMPTE; rm -f $MAISON/installer-distant.sh" \
      && BILAN+=("$NOM : retiré") || BILAN+=("$NOM : ÉCHEC du retrait")
    continue
  fi
  # Dépôt temporaire dans le dossier personnel du compte de connexion (ni /tmp ni /var), puis installation
  if MAISON="$(ssh "${SSHOPTS[@]}" "$ADMIN@$CIBLE" "umask 077; rm -rf ~/$DEPOT && mkdir ~/$DEPOT && echo \$HOME")" && \
     scp "${SCPOPTS[@]}" "$ICI/collecte_infra.py" "$ICI/installer-distant.sh" "$CONF" "$ADMIN@$CIBLE:$DEPOT/" && \
     executer "$CIBLE" "bash $MAISON/$DEPOT/installer-distant.sh --nom $NOM --role $ROLE --depuis $IP_CENTRAL --compte $COMPTE $OPT_SUDO --cle '$PUB'"; then
    # Test avec la clé du portail : la commande forcée doit renvoyer l'instantané de CE serveur
    if ssh -i "$CLE" -o BatchMode=yes -o ConnectTimeout=10 -p "$PORT" "$COMPTE@$CIBLE" collecte 2>/dev/null | tail -1 | grep -q "\"nom\": \"$NOM\""; then
      BILAN+=("$NOM : OK")
    else
      BILAN+=("$NOM : installé, mais le test avec la clé du portail échoue (voir AllowUsers/AllowGroups de sshd, from=, droits de ~/.ssh)")
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
