#!/bin/bash
# Lanceur : trouve un interpréteur Python 3 sur le serveur (RHEL 7/8/9) et lance le rapport.
# Usage : sudo ./rapport_connexions.sh --mois 2026-09 --echecs --secure
DIR="$(cd "$(dirname "$0")" && pwd)"
for PY in python3 /usr/libexec/platform-python /usr/libexec/platform-python3.6 python3.12 python3.11 python3.9 python3.8 python3.6; do
    if command -v "$PY" >/dev/null 2>&1 && "$PY" -c 'import sys; sys.exit(sys.version_info < (3, 3))' 2>/dev/null; then
        exec "$PY" "$DIR/rapport_connexions.py" "$@"
    fi
done
echo "ERREUR : aucun Python 3 trouvé (ni python3, ni /usr/libexec/platform-python)." >&2
echo "Chercher un interpréteur : ls /usr/bin/python* /usr/libexec/platform-python* 2>/dev/null" >&2
exit 1
