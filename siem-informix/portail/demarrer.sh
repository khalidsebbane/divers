#!/bin/sh
# Lance le portail ; HTTPS si un certificat est présent dans /certs (cert.pem + cle.pem)
set -e
if [ -f /certs/cert.pem ] && [ -f /certs/cle.pem ]; then
  exec uvicorn app.main:app --host 0.0.0.0 --port 8443 --ssl-certfile /certs/cert.pem --ssl-keyfile /certs/cle.pem --proxy-headers
fi
echo "ATTENTION : pas de certificat dans /certs, portail en HTTP (à réserver aux tests)" >&2
exec uvicorn app.main:app --host 0.0.0.0 --port 8443 --proxy-headers
