#!/bin/bash
# Exécuté en root sur chaque serveur interrogé (déposé et lancé par deployer-ssh.sh depuis le serveur central).
# Installe le collecteur dans /opt/portail-infra et autorise la clé du serveur central à lancer UNIQUEMENT le collecteur.
#   installer-distant.sh --nom APP1 --role app --cle "ssh-ed25519 AAAA... portail-infra" --depuis 10.0.1.12 [--compte root]
#   installer-distant.sh --desinstaller [--compte root]
set -eu
NOM="" ROLE="" CLE="" DEPUIS="" COMPTE=root RETIRER=0 DEPOT="$(cd "$(dirname "$0")" && pwd)"
while [ $# -gt 0 ]; do
  case "$1" in
    --nom) NOM="$2"; shift 2 ;; --role) ROLE="$2"; shift 2 ;; --cle) CLE="$2"; shift 2 ;;
    --depuis) DEPUIS="$2"; shift 2 ;; --compte) COMPTE="$2"; shift 2 ;; --desinstaller) RETIRER=1; shift ;;
    *) echo "option inconnue : $1" >&2; exit 2 ;;
  esac
done
[ "$(id -u)" -eq 0 ] || { echo "à lancer en root" >&2; exit 1; }
DOSSIER=/opt/portail-infra
MAISON="$(getent passwd "$COMPTE" | cut -d: -f6)"
[ -n "$MAISON" ] || { echo "compte $COMPTE introuvable" >&2; exit 1; }
AK="$MAISON/.ssh/authorized_keys"

retirer_cle() { [ -f "$AK" ] && sed -i '/ portail-infra@/d' "$AK" || true; }

if [ "$RETIRER" -eq 1 ]; then
  retirer_cle; rm -f /etc/sudoers.d/portail-infra; rm -rf "$DOSSIER"
  echo "$(hostname -s) : collecteur et clé du portail retirés"; exit 0
fi
[[ "$NOM" =~ ^[A-Za-z0-9_-]+$ && "$ROLE" =~ ^(bdd|repl|app|api)$ ]] || { echo "--nom et --role obligatoires" >&2; exit 2; }
[[ "$CLE" =~ ^ssh-(ed25519|rsa)\ [A-Za-z0-9+/=]+\ portail-infra@ ]] || { echo "clé publique invalide" >&2; exit 2; }
[[ "$DEPUIS" =~ ^[0-9a-fA-F.:,/*]+$ ]] || { echo "--depuis : adresse IP du serveur central obligatoire" >&2; exit 2; }

PY=""
for p in /usr/libexec/platform-python /usr/bin/python3 /usr/bin/python2.7 /usr/bin/python; do [ -x "$p" ] && { PY="$p"; break; }; done
[ -n "$PY" ] || { echo "aucun Python trouvé" >&2; exit 1; }

install -d -o root -g root -m 700 "$DOSSIER" "$DOSSIER/collecteur" "$DOSSIER/collecteur/travail"
install -o root -g root -m 600 "$DEPOT/collecte_infra.py" "$DOSSIER/collecteur/collecte_infra.py"
install -o root -g root -m 600 "$DEPOT/tractafric.conf" "$DOSSIER/tractafric.conf"
CMD="$PY $DOSSIER/collecteur/collecte_infra.py --stdout --nom $NOM --role $ROLE"
FORCEE="$CMD"
if [ "$COMPTE" != root ]; then
  printf '%s ALL=(root) NOPASSWD: %s\n' "$COMPTE" "$CMD" > /etc/sudoers.d/portail-infra.tmp
  chmod 440 /etc/sudoers.d/portail-infra.tmp
  visudo -cf /etc/sudoers.d/portail-infra.tmp >/dev/null && mv -f /etc/sudoers.d/portail-infra.tmp /etc/sudoers.d/portail-infra
  FORCEE="sudo -n $CMD"
fi
install -d -o "$COMPTE" -m 700 "$MAISON/.ssh"
touch "$AK"; chown "$COMPTE" "$AK"; chmod 600 "$AK"
retirer_cle
printf 'from="%s",command="%s",no-pty,no-port-forwarding,no-agent-forwarding,no-X11-forwarding,no-user-rc %s\n' "$DEPUIS" "$FORCEE" "$CLE" >> "$AK"
command -v restorecon >/dev/null 2>&1 && restorecon -R "$MAISON/.ssh" 2>/dev/null || true
[ "$(basename "$DEPOT")" = portail-infra-depot ] && rm -rf "$DEPOT"

# Contrôle : une collecte locale doit produire un instantané
TAILLE="$($CMD 2>/dev/null | wc -c)"
echo "$(hostname -s) ($NOM, $ROLE) : collecteur installé, Python $PY, instantané de test : $TAILLE octets"
if [ "$COMPTE" = root ] && command -v sshd >/dev/null 2>&1; then
  PRL="$(sshd -T 2>/dev/null | awk '$1=="permitrootlogin"{print $2}')"
  case "$PRL" in
    no) echo "ATTENTION : PermitRootLogin no. Mettre « PermitRootLogin forced-commands-only » dans /etc/ssh/sshd_config"
        echo "            (root n'est alors autorisé QUE par clé à commande forcée), puis systemctl reload sshd" ;;
  esac
fi
