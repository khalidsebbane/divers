#!/bin/bash
# Exécuté sur chaque serveur interrogé (déposé et lancé par deployer-ssh.sh depuis le serveur central).
# Installe le collecteur et autorise la clé du serveur central à lancer UNIQUEMENT le collecteur.
#
#   Sans root (cas habituel) : lancé sous le compte de collecte (informix sur BDD/REPL, irium ailleurs).
#     Collecteur dans ~/portail-infra, clé dans ~/.ssh/authorized_keys du compte. Aucun privilège.
#   En root : collecteur dans /opt/portail-infra ; avec --compte autre que root, règle sudo limitée au collecteur
#     (sauf --sans-sudo) pour lire les crontabs de tous les comptes et /var/log/cron.
#
#   installer-distant.sh --nom APP1 --role app --cle "ssh-ed25519 AAAA... portail-infra@hote" --depuis 10.0.1.12 [--compte X] [--sans-sudo]
#   installer-distant.sh --desinstaller [--compte X]
set -eu
NOM="" ROLE="" CLE="" DEPUIS="" COMPTE="" RETIRER=0 SANS_SUDO=0 DEPOT="$(cd "$(dirname "$0")" && pwd)"
while [ $# -gt 0 ]; do
  case "$1" in
    --nom) NOM="$2"; shift 2 ;; --role) ROLE="$2"; shift 2 ;; --cle) CLE="$2"; shift 2 ;;
    --depuis) DEPUIS="$2"; shift 2 ;; --compte) COMPTE="$2"; shift 2 ;;
    --desinstaller) RETIRER=1; shift ;; --sans-sudo) SANS_SUDO=1; shift ;;
    *) echo "option inconnue : $1" >&2; exit 2 ;;
  esac
done
MOI="$(id -un)"
if [ "$(id -u)" -eq 0 ]; then
  COMPTE="${COMPTE:-root}"; DOSSIER=/opt/portail-infra
else
  [ -z "$COMPTE" ] || [ "$COMPTE" = "$MOI" ] || { echo "sans root, le compte de collecte doit être le compte courant ($MOI), pas $COMPTE" >&2; exit 1; }
  COMPTE="$MOI"; SANS_SUDO=1; DOSSIER="$HOME/portail-infra"
fi
MAISON="$(getent passwd "$COMPTE" | cut -d: -f6)"
[ -n "$MAISON" ] || { echo "compte $COMPTE introuvable" >&2; exit 1; }
AK="$MAISON/.ssh/authorized_keys"

retirer_cle() { [ -f "$AK" ] && sed -i '/ portail-infra@/d' "$AK" || true; }

if [ "$RETIRER" -eq 1 ]; then
  retirer_cle
  [ "$(id -u)" -eq 0 ] && rm -f /etc/sudoers.d/portail-infra
  rm -rf "$DOSSIER"
  echo "$(hostname -s) : collecteur et clé du portail retirés ($COMPTE)"; exit 0
fi
[[ "$NOM" =~ ^[A-Za-z0-9_-]+$ && "$ROLE" =~ ^(bdd|repl|app|api)$ ]] || { echo "--nom et --role obligatoires" >&2; exit 2; }
[[ "$CLE" =~ ^ssh-(ed25519|rsa)\ [A-Za-z0-9+/=]+\ portail-infra@ ]] || { echo "clé publique invalide" >&2; exit 2; }
[[ "$DEPUIS" =~ ^[0-9a-fA-F.:,/*]+$ ]] || { echo "--depuis : adresse IP du serveur central obligatoire" >&2; exit 2; }

PY=""
for p in /usr/libexec/platform-python /usr/bin/python3 /usr/bin/python2.7 /usr/bin/python; do [ -x "$p" ] && { PY="$p"; break; }; done
[ -n "$PY" ] || { echo "aucun Python trouvé" >&2; exit 1; }

if [ "$(id -u)" -eq 0 ]; then
  PROPRIO=root; [ "$SANS_SUDO" -eq 1 ] && PROPRIO="$COMPTE"
  # 711 : le compte informix traverse les dossiers pour écrire ses fichiers unload dans travail/informix
  install -d -o root -g root -m 711 "$DOSSIER" "$DOSSIER/collecteur"
  install -d -o "$PROPRIO" -m 711 "$DOSSIER/collecteur/travail"
  install -o "$PROPRIO" -m 600 "$DEPOT/collecte_infra.py" "$DOSSIER/collecteur/collecte_infra.py"
  install -o "$PROPRIO" -m 600 "$DEPOT/tractafric.conf" "$DOSSIER/tractafric.conf"
else
  install -d -m 700 "$DOSSIER" "$DOSSIER/collecteur" "$DOSSIER/collecteur/travail"
  install -m 600 "$DEPOT/collecte_infra.py" "$DOSSIER/collecteur/collecte_infra.py"
  install -m 600 "$DEPOT/tractafric.conf" "$DOSSIER/tractafric.conf"
fi
CMD="$PY $DOSSIER/collecteur/collecte_infra.py --stdout --nom $NOM --role $ROLE"
FORCEE="$CMD"
if [ "$(id -u)" -eq 0 ]; then
  rm -f /etc/sudoers.d/portail-infra
  if [ "$COMPTE" != root ] && [ "$SANS_SUDO" -eq 0 ]; then
    printf '%s ALL=(root) NOPASSWD: %s\n' "$COMPTE" "$CMD" > /etc/sudoers.d/portail-infra.tmp
    chmod 440 /etc/sudoers.d/portail-infra.tmp
    visudo -cf /etc/sudoers.d/portail-infra.tmp >/dev/null && mv -f /etc/sudoers.d/portail-infra.tmp /etc/sudoers.d/portail-infra
    FORCEE="sudo -n $CMD"
  fi
  install -d -o "$COMPTE" -m 700 "$MAISON/.ssh"
  touch "$AK"; chown "$COMPTE" "$AK"
else
  mkdir -p "$MAISON/.ssh"; chmod 700 "$MAISON/.ssh"; touch "$AK"
fi
chmod 600 "$AK"
retirer_cle
printf 'from="%s",command="%s",no-pty,no-port-forwarding,no-agent-forwarding,no-X11-forwarding,no-user-rc %s\n' "$DEPUIS" "$FORCEE" "$CLE" >> "$AK"
command -v restorecon >/dev/null 2>&1 && restorecon -R "$MAISON/.ssh" 2>/dev/null || true
[ "$(basename "$DEPOT")" = portail-infra-depot ] && rm -rf "$DEPOT"

# Contrôle : une collecte doit produire un instantané
if [ "$(id -u)" -ne 0 ] || [ "${PROPRIO:-root}" = root ]; then TAILLE="$($CMD 2>/dev/null | wc -c)"
else TAILLE="$(runuser -u "$COMPTE" -- $CMD 2>/dev/null | wc -c)"; fi
echo "$(hostname -s) ($NOM, $ROLE) : collecteur installé dans $DOSSIER pour le compte $COMPTE, Python $PY, instantané de test : $TAILLE octets"
[ "$TAILLE" -gt 100 ] || echo "ATTENTION : instantané de test vide. Lancer à la main : $CMD | tail -c 300"
