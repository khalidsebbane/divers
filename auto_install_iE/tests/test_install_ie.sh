#!/usr/bin/env bash
# Tests de install_ie.sh, sans privilège ni modification du système :
#   1. fonctions de validation et utilitaires (script « sourcé ») ;
#   2. exécution complète en mode --simulation, avec des commandes système factices.
# Utilisation : bash tests/test_install_ie.sh
set -uo pipefail

ICI="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="$ICI/../install_ie.sh"
ECHECS=0 TOTAL=0

verifier() {   # verifier "libellé" commande...
    local libelle=$1; shift
    TOTAL=$((TOTAL + 1))
    if "$@"; then printf '  ok    %s\n' "$libelle"; else printf '  ÉCHEC %s\n' "$libelle"; ECHECS=$((ECHECS + 1)); fi
}
non() { ! "$@"; }
egal() { [[ "$1" == "$2" ]] || { printf '        attendu « %s », obtenu « %s »\n' "$2" "$1"; return 1; }; }

echo "== Analyse statique"
verifier "bash -n" bash -n "$SCRIPT"
if command -v shellcheck >/dev/null; then verifier "shellcheck" shellcheck -S style "$SCRIPT"; fi
verifier "fins de ligne Unix (pas de CRLF)" non grep -q $'\r' "$SCRIPT"

echo "== Fonctions"
# shellcheck disable=SC1090
source "$SCRIPT"
set +e +u; trap - ERR

verifier "IP valide"                    valider_ip 192.168.111.50
verifier "IP octet > 255 refusée"       non valider_ip 192.168.1.256
verifier "IP incomplète refusée"        non valider_ip 10.0.0
verifier "IP avec zéros"                valider_ip 010.000.001.009
verifier "taille 200G"                  valider_taille 200G
verifier "taille 1T"                    valider_taille 1T
verifier "taille 0G refusée"            non valider_taille 0G
verifier "taille 200 refusée (brute)"   non valider_taille 200
verifier "normalise 200 -> 200G"        egal "$(normaliser_taille 200)" 200G
verifier "normalise 50g -> 50G"         egal "$(normaliser_taille 50g)" 50G
verifier "1T = 1024 Go"                 egal "$(taille_en_go 1T)" 1024
verifier "VG iriumvg"                   valider_vg iriumvg
verifier "VG commençant par chiffre"    non valider_vg 1vg
verifier "Genero 3"                     valider_genero 3
verifier "Genero 4 refusé"              non valider_genero 4
verifier "nom ancien serveur vide ok"   valider_nom_srv ""
verifier "nom ancien serveur tiret"     non valider_nom_srv "srv-01"
verifier "partition sdb"                egal "$(nom_partition /dev/sdb 1)" /dev/sdb1
verifier "partition nvme"               egal "$(nom_partition /dev/nvme0n1 2)" /dev/nvme0n1p2
# shellcheck disable=SC2329
verifier "nom d'instance Informix"      egal "$(hostname() { echo 'SRV-IE-01'; }; nom_instance_informix)" ol_srvie01

mdp=$(generer_mot_de_passe 16)
verifier "mot de passe : 16 caractères" egal "${#mdp}" 16
verifier "mot de passe : majuscule"     grep -q '[A-Z]' <<<"$mdp"
verifier "mot de passe : chiffre"       grep -q '[0-9]' <<<"$mdp"

f=$(mktemp)
printf 'ROOTPATH /x/rootdbs\n#LOCKS 1\nLOCKS 20000\nNETTYPE a\nNETTYPE b\n' >"$f"
onconfig_set "$f" ROOTPATH /opt/irium/data/ol_t/rootdbs
onconfig_set "$f" LOCKS 2000000
onconfig_set "$f" MSG_DATE 1
verifier "onconfig : remplacement"      grep -qx 'ROOTPATH /opt/irium/data/ol_t/rootdbs' "$f"
verifier "onconfig : commentaire gardé" grep -qx '#LOCKS 1' "$f"
verifier "onconfig : valeur LOCKS"      grep -qx 'LOCKS 2000000' "$f"
verifier "onconfig : ajout si absent"   grep -qx 'MSG_DATE 1' "$f"
rm -f "$f"

echo "== Simulation complète (commandes système factices)"
bac=$(mktemp -d)
mkdir -p "$bac/bin" "$bac/src" "$bac/irium/manager/bin"
for c in lsblk parted partprobe udevadm wipefs pvcreate vgcreate lvcreate mkfs.xfs blkid findmnt wget tar unzip \
         rpm dnf alternatives systemctl ssh-keygen chpasswd useradd usermod pvs vgs lvs mount umount mountpoint \
         smbpasswd pdbedit smbclient su crontab subscription-manager restorecon; do
    printf '#!/bin/sh\nexit 1\n' >"$bac/bin/$c"
done
cat >"$bac/bin/lsblk" <<'EOS'
#!/bin/sh
case "$*" in *-dno\ TYPE*) echo disk ;; *MOUNTPOINTS*|*NAME,TYPE*) ;; *) echo "NAME SIZE TYPE" ;; esac
EOS
printf '#!/bin/sh\nexit 0\n' >"$bac/bin/flock"
# shellcheck disable=SC2016
printf '#!/bin/sh\ncase "$1" in -qp) echo jre1.8 ;; *) exit 1 ;; esac\n' >"$bac/bin/rpm"
chmod +x "$bac"/bin/*
disque=$(find /dev -maxdepth 1 \( -name 'sd?' -o -name 'vd?' -o -name 'nvme?n1' \) -type b 2>/dev/null | sort | tail -1)
cat >"$bac/test.conf" <<EOF
DISK="${disque:-/dev/sdb}"
OLDSRV_IP="192.168.111.50"
OLDSRV_NAME="ancien"
INFORMIX_EDITION="workgroup"
SOURCES_DIR="$bac/src"
IRIUM_DIR="$bac/irium"
INFORMIX_DIR="$bac/irium/informix"
CREDENTIALS_FILE="$bac/identifiants.txt"
VARLOG_ACTION="non"
LANCER_DUMP="non"
INSTALLER_V3300="non"
EOF
chmod 600 "$bac/test.conf"
touch "$bac/src/genero-3.20.13-64.tgz" "$bac/src/jre-8u201-linux-x64.rpm" "$bac/src/informix" "$bac/src/param_ids" \
      "$bac/irium/manager/bin/archivage_ids.std"

if [[ $EUID -eq 0 && -n "$disque" ]]; then
    sortie=$(PATH="$bac/bin:$PATH" bash "$SCRIPT" --simulation --oui --config "$bac/test.conf" 2>&1)
    rc=$?
    verifier "simulation : code retour 0"            egal "$rc" 0
    verifier "simulation : toutes les étapes"        grep -q "Étape « migration » terminée" <<<"$sortie"
    verifier "simulation : rien d'exécuté (pvcreate)" grep -q '\[SIMU\].*pvcreate' <<<"$sortie"
    verifier "simulation : aucune erreur signalée"   non grep -q '\[ERR' <<<"$sortie"
    verifier "simulation : pas de secret affiché"    non grep -qi 'password=' <<<"$sortie"
    verifier "simulation : aucun état enregistré"    non compgen -G "$ICI/../.etat/*.ok"
    [[ $rc -eq 0 ]] || tail -25 <<<"$sortie"

    # Parcours interactif : réponses saisies dans un vrai terminal (commande « script »)
    if command -v script >/dev/null; then
        sed -i -e 's/^INFORMIX_EDITION=.*/INFORMIX_EDITION=""/' -e 's/^LANCER_DUMP=.*/LANCER_DUMP="demander"/' \
               -e 's/^INSTALLER_V3300=.*/INSTALLER_V3300="demander"/' "$bac/test.conf"
        # o : paramètres | 2 : Workgroup | o : dump | n : v3300 | o : lancement
        sortie=$(printf 'o\n2\no\nn\no\n' | PATH="$bac/bin:$PATH" NO_COLOR=1 \
                 script -qec "bash '$SCRIPT' --simulation --config '$bac/test.conf'" /dev/null 2>&1 | tr -d '\r')
        apres=$(sed '1,/Mode automatique/d' <<<"$sortie")
        verifier "interactif : questions puis mode automatique" grep -q 'Mode automatique' <<<"$sortie"
        verifier "interactif : édition choisie au début"        grep -q 'Édition retenue : WORKGROUP' <<<"$sortie"
        verifier "interactif : aucune question ensuite"         non grep -q 'o/n/s=arrêt\|Choix :' <<<"$apres"
        verifier "interactif : réponses appliquées (dump oui)"  grep -q '\[SIMU\].*backup.cde' <<<"$apres"
        verifier "interactif : réponses appliquées (v3300 non)" grep -q 'Installation v3300 ignorée' <<<"$apres"
        verifier "interactif : toutes les étapes"               grep -q "Étape « migration » terminée" <<<"$apres"
    fi
else
    echo "  (simulation ignorée : nécessite root et un périphérique bloc)"
fi
rm -rf "$bac"

echo
echo "$((TOTAL - ECHECS))/$TOTAL tests réussis."
(( ECHECS == 0 ))
