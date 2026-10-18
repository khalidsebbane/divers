#!/bin/sh
# Lance le portail en HTTPS. Sans certificat fourni, un certificat autosigné est créé au premier démarrage
# (à remplacer par un certificat de l'autorité interne : cert.pem + cle.pem dans le dossier des certificats).
set -e
CERTS="${SIEM_CERTS:-/certs}"
DONNEES="$(dirname "${SIEM_BASE:-/donnees/siem.db}")"
if [ ! -f "$CERTS/cert.pem" ] || [ ! -f "$CERTS/cle.pem" ]; then
  CERTS="$DONNEES/certs"
  if [ ! -f "$CERTS/cert.pem" ]; then
    mkdir -p "$CERTS"
    openssl req -x509 -newkey rsa:3072 -nodes -days 825 -subj "/CN=$(hostname)" \
      -addext "subjectAltName=DNS:$(hostname)" -keyout "$CERTS/cle.pem" -out "$CERTS/cert.pem" 2>/dev/null
    chmod 600 "$CERTS/cle.pem"
    echo "Certificat autosigné créé dans $CERTS (à remplacer par un certificat de l'autorité interne)." >&2
  fi
fi
exec uvicorn app.main:app --host 0.0.0.0 --port "${SIEM_PORT:-8443}" --ssl-certfile "$CERTS/cert.pem" --ssl-keyfile "$CERTS/cle.pem" \
  --proxy-headers --no-server-header
