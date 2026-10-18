#!/bin/bash
# =============================================================================================
# Installation native du portail SIEM sur le serveur isolé (RHEL 8/9 ou compatible), à lancer en root
# depuis le dossier décompressé du paquet (construire-paquet-hors-ligne.sh) ou du dépôt.
#
#   ./deploiement/installer-portail.sh [--python /usr/bin/python3.11] [--port 443]
#
# Crée : compte « siem », /opt/siem-portail (application), /var/lib/siem-portail (données),
#        /etc/siem-portail (configuration, certificats), service systemd « siem-portail », règle pare-feu.
# =============================================================================================
set -euo pipefail
PY=""; PORT=443
while [ $# -gt 0 ]; do case "$1" in --python) PY="$2"; shift 2;; --port) PORT="$2"; shift 2;; *) echo "option inconnue $1"; exit 1;; esac; done
[ "$(id -u)" -eq 0 ] || { echo "À lancer en root." >&2; exit 1; }
RACINE="$(cd "$(dirname "$0")/.." && pwd)"
[ -d "$RACINE/app" ] || RACINE="$RACINE/portail"
[ -d "$RACINE/app" ] || { echo "Dossier de l'application introuvable." >&2; exit 1; }
PAQUET="$(cd "$(dirname "$0")/.." && pwd)"

if [ -z "$PY" ]; then
  for p in python3.12 python3.11 python3; do
    command -v "$p" >/dev/null && "$p" -c 'import sys; sys.exit(sys.version_info < (3, 10))' && { PY="$(command -v $p)"; break; }
  done
fi
[ -n "$PY" ] || { echo "Python 3.10+ requis : dnf install python3.11 (dépôt AppStream ou ISO RHEL monté)." >&2; exit 1; }
command -v ssh >/dev/null || echo "ATTENTION : client SSH absent (dnf install openssh-clients) : collecte pilotée impossible." >&2
command -v openssl >/dev/null || { echo "openssl requis." >&2; exit 1; }

id siem >/dev/null 2>&1 || useradd --system --home-dir /var/lib/siem-portail --shell /sbin/nologin siem
install -d -o root -g root -m 0755 /opt/siem-portail
install -d -o siem -g siem -m 0750 /var/lib/siem-portail
install -d -o root -g siem -m 0750 /etc/siem-portail /etc/siem-portail/certs /etc/siem-portail/marque
cp -r "$RACINE/app" "$RACINE/requirements.txt" /opt/siem-portail/
install -m 0755 "$RACINE/demarrer.sh" /opt/siem-portail/demarrer.sh

echo "Environnement Python ($PY)..."
"$PY" -m venv /opt/siem-portail/venv
if [ -d "$PAQUET/wheels" ]; then
  /opt/siem-portail/venv/bin/pip install --quiet --no-index --find-links "$PAQUET/wheels" -r /opt/siem-portail/requirements.txt
else
  /opt/siem-portail/venv/bin/pip install --quiet -r /opt/siem-portail/requirements.txt
fi

if [ ! -f /etc/siem-portail/portail.env ]; then
  ENV_SRC="$RACINE/.env.exemple"
  [ -f "$PAQUET/deploiement/tractafric/portail.env.exemple" ] && ENV_SRC="$PAQUET/deploiement/tractafric/portail.env.exemple"
  sed -e 's|^SIEM_BASE=.*|SIEM_BASE=/var/lib/siem-portail/siem.db|' -e 's|^SIEM_MARQUE_LOGO=.*|SIEM_MARQUE_LOGO=/etc/siem-portail/marque/logo.png|' \
      -e 's|^SIEM_AD_CA=.*|SIEM_AD_CA=/etc/siem-portail/certs/ca-interne.pem|' "$ENV_SRC" > /etc/siem-portail/portail.env
  echo "SIEM_PORT=$PORT" >> /etc/siem-portail/portail.env
  chown root:siem /etc/siem-portail/portail.env && chmod 0640 /etc/siem-portail/portail.env
fi
[ -f "$PAQUET/deploiement/tractafric/logo.png" ] && [ ! -f /etc/siem-portail/marque/logo.png ] && \
  install -o root -g siem -m 0644 "$PAQUET/deploiement/tractafric/logo.png" /etc/siem-portail/marque/logo.png
if [ ! -f /etc/siem-portail/certs/cert.pem ]; then
  openssl req -x509 -newkey rsa:3072 -nodes -days 825 -subj "/CN=$(hostname -f)" -addext "subjectAltName=DNS:$(hostname -f)" \
    -keyout /etc/siem-portail/certs/cle.pem -out /etc/siem-portail/certs/cert.pem 2>/dev/null
  chown root:siem /etc/siem-portail/certs/*.pem && chmod 0640 /etc/siem-portail/certs/cle.pem
  echo "Certificat autosigné créé : le remplacer par un certificat de l'autorité interne (cert.pem / cle.pem)."
fi

install -m 0644 "$PAQUET/deploiement/siem-portail.service" /etc/systemd/system/siem-portail.service
command -v restorecon >/dev/null && restorecon -R /opt/siem-portail /var/lib/siem-portail /etc/siem-portail || true
if command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then
  firewall-cmd --permanent --add-port="$PORT/tcp" >/dev/null && firewall-cmd --reload >/dev/null
fi
systemctl daemon-reload
systemctl enable --now siem-portail
sleep 3
systemctl --no-pager --lines=0 status siem-portail || true
echo
journalctl -u siem-portail --no-pager | grep -o "admin.local.*" | tail -1 || true
echo "Portail installé : https://$(hostname -f)$( [ "$PORT" = 443 ] || echo ":$PORT" )"
echo "Étapes suivantes : éditer /etc/siem-portail/portail.env (Active Directory), puis : systemctl restart siem-portail"
