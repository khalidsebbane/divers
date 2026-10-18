#!/bin/bash
# À lancer sur un poste AVEC accès Internet : prépare un paquet installable sur le serveur isolé (sans Internet).
#   ./construire-paquet-hors-ligne.sh [version_python_du_serveur]   (défaut : 3.11, fourni par RHEL 8.8+ / 9)
# Produit : siem-portail-hors-ligne.tar.gz (application + dépendances Python précompilées).
set -euo pipefail
PYV="${1:-3.11}"
RACINE="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"
mkdir -p "$TMP/siem-portail/wheels"
pip download --quiet -r "$RACINE/portail/requirements.txt" -d "$TMP/siem-portail/wheels" \
  --only-binary=:all: --platform manylinux2014_x86_64 --platform manylinux_2_17_x86_64 --platform manylinux_2_28_x86_64 \
  --python-version "$PYV" --implementation cp
cp -r "$RACINE/portail/app" "$RACINE/portail/requirements.txt" "$RACINE/portail/demarrer.sh" "$RACINE/portail/.env.exemple" "$TMP/siem-portail/"
cp -r "$RACINE/deploiement" "$TMP/siem-portail/deploiement"
cp -r "$RACINE/collecteur" "$TMP/siem-portail/collecteur"
find "$TMP" -name __pycache__ -prune -exec rm -rf {} +
tar -C "$TMP" -czf "siem-portail-hors-ligne.tar.gz" siem-portail
rm -rf "$TMP"
echo "Paquet prêt : $(pwd)/siem-portail-hors-ligne.tar.gz (Python $PYV)"
