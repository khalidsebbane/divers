#!/bin/bash
# =============================================================================================
# Préparation d'un serveur Informix pour la collecte pilotée par le portail SIEM (à lancer en root).
#
#   ./preparer-serveur-bdd.sh --cle "ssh-ed25519 AAAA... portail-siem-informix" --ip-portail 10.20.0.15 [--auditd]
#
# Ce que fait le script (et rien d'autre) :
#   1. installe collecteur.py dans /opt/siem-informix (propriété root, lecture seule pour les autres) ;
#   2. crée le compte technique « siemcollect » (sans mot de passe) ;
#   3. autorise la clé du portail UNIQUEMENT depuis l'IP du portail et UNIQUEMENT pour lancer le collecteur
#      (commande forcée : pas de shell, pas de transfert de port, pas de terminal) ;
#   4. autorise, via sudo, cette seule commande en root (lecture de /var/log/secure, btmp, audit.log) ;
#   5. avec --auditd : installe les règles auditd du SIEM (chemin Informix et uid adaptés automatiquement).
#
# Rien ne tourne en permanence, aucun port n'est ouvert : c'est le portail qui se connecte.
# Désinstallation : ./preparer-serveur-bdd.sh --desinstaller
# =============================================================================================
set -euo pipefail

COMPTE=siemcollect
DOSSIER=/opt/siem-informix
CLE=""
IP_PORTAIL=""
PYTHON=""
AUDITD=0
DESINSTALLER=0
SOURCE_DIR="$(cd "$(dirname "$0")" && pwd)"

usage() { sed -n '3,18p' "$0"; exit 1; }
while [ $# -gt 0 ]; do
  case "$1" in
    --cle) CLE="$2"; shift 2 ;;
    --ip-portail) IP_PORTAIL="$2"; shift 2 ;;
    --python) PYTHON="$2"; shift 2 ;;
    --compte) COMPTE="$2"; shift 2 ;;
    --dossier) DOSSIER="$2"; shift 2 ;;
    --auditd) AUDITD=1; shift ;;
    --desinstaller) DESINSTALLER=1; shift ;;
    *) usage ;;
  esac
done

[ "$(id -u)" -eq 0 ] || { echo "À lancer en root." >&2; exit 1; }

if [ "$DESINSTALLER" -eq 1 ]; then
  rm -f /etc/sudoers.d/siem-collecteur /etc/audit/rules.d/siem-informix.rules
  id "$COMPTE" >/dev/null 2>&1 && userdel -r "$COMPTE" 2>/dev/null || true
  rm -rf "$DOSSIER"
  command -v augenrules >/dev/null && augenrules --load >/dev/null 2>&1 || true
  echo "Collecte SIEM désinstallée."
  exit 0
fi

[ -n "$CLE" ] && [ -n "$IP_PORTAIL" ] || usage
case "$CLE" in ssh-ed25519\ *|ssh-rsa\ *|ecdsa-sha2-*) ;; *) echo "Clé publique invalide." >&2; exit 1 ;; esac
[ -f "$SOURCE_DIR/collecteur.py" ] || { echo "collecteur.py introuvable à côté du script." >&2; exit 1; }

# --- Python : celui du système, aucune installation
if [ -z "$PYTHON" ]; then
  for p in /usr/libexec/platform-python /usr/bin/python3 /usr/bin/python3.6; do
    [ -x "$p" ] && "$p" -c 'import sys; sys.exit(sys.version_info < (3, 6))' 2>/dev/null && { PYTHON="$p"; break; }
  done
fi
[ -n "$PYTHON" ] || { echo "Aucun Python 3.6+ trouvé (ni /usr/libexec/platform-python, ni python3)." >&2; exit 1; }
COMMANDE="sudo $PYTHON $DOSSIER/collecteur.py --distant"
echo "Python utilisé : $PYTHON"

# --- 1. Collecteur (root, non modifiable par le compte de collecte)
install -d -o root -g root -m 0755 "$DOSSIER"
install -o root -g root -m 0755 "$SOURCE_DIR/collecteur.py" "$DOSSIER/collecteur.py"

# --- 2. Compte technique sans mot de passe
if ! id "$COMPTE" >/dev/null 2>&1; then
  useradd --system --create-home --shell /bin/sh --comment "Collecte SIEM (commande forcée)" "$COMPTE"
fi
passwd -l "$COMPTE" >/dev/null 2>&1 || true

# --- 3. Clé du portail : depuis l'IP du portail, commande forcée uniquement
MAISON="$(getent passwd "$COMPTE" | cut -d: -f6)"
install -d -o "$COMPTE" -g "$COMPTE" -m 0700 "$MAISON/.ssh"
printf 'from="%s",command="%s",no-pty,no-port-forwarding,no-agent-forwarding,no-X11-forwarding,no-user-rc %s\n' \
  "$IP_PORTAIL" "$COMMANDE" "$CLE" > "$MAISON/.ssh/authorized_keys"
chown "$COMPTE:$COMPTE" "$MAISON/.ssh/authorized_keys"
chmod 0600 "$MAISON/.ssh/authorized_keys"
command -v restorecon >/dev/null && restorecon -R "$MAISON/.ssh" || true

# --- 4. sudo : cette seule commande, en root, sans mot de passe
TMP=$(mktemp)
cat > "$TMP" <<EOF
# Collecte SIEM : le compte $COMPTE ne peut lancer que le collecteur, en mode piloté.
Defaults:$COMPTE !requiretty
$COMPTE ALL=(root) NOPASSWD: $PYTHON $DOSSIER/collecteur.py --distant
EOF
visudo -cf "$TMP" >/dev/null
install -o root -g root -m 0440 "$TMP" /etc/sudoers.d/siem-collecteur
rm -f "$TMP"

# --- 5. Règles auditd (optionnel)
if [ "$AUDITD" -eq 1 ]; then
  IFXDIR="${INFORMIXDIR:-$(getent passwd informix | cut -d: -f6)}"
  UID_IFX="$(id -u informix 2>/dev/null || echo 1001)"
  [ -f "$SOURCE_DIR/auditd/siem-informix.rules" ] || { echo "auditd/siem-informix.rules introuvable." >&2; exit 1; }
  sed -e "s#/opt/informix#${IFXDIR:-/opt/informix}#g" -e "s#euid=1001#euid=${UID_IFX}#g" \
    "$SOURCE_DIR/auditd/siem-informix.rules" > /etc/audit/rules.d/siem-informix.rules
  augenrules --load >/dev/null && echo "Règles auditd chargées : $(auditctl -l | grep -c siem) règle(s) SIEM actives."
fi

# --- Vérifications
if grep -Eqi '^\s*AllowUsers' /etc/ssh/sshd_config 2>/dev/null && ! grep -Eqi "^\s*AllowUsers.*\b$COMPTE\b" /etc/ssh/sshd_config; then
  echo "ATTENTION : sshd_config contient AllowUsers : ajouter $COMPTE (depuis $IP_PORTAIL) puis recharger sshd." >&2
fi
echo "{\"config\":{\"collecteur\":{\"sources\":\"\"}}}" | sudo -u "$COMPTE" $COMMANDE >/dev/null && \
  echo "Test local réussi : le compte $COMPTE peut lancer le collecteur."
echo
echo "Serveur prêt. Dans le portail : Administration > Collecte > Ajouter un serveur, puis « Tester »."
echo "  Compte : $COMPTE   Python : $PYTHON   Collecteur : $DOSSIER/collecteur.py"
