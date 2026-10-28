#!/usr/bin/env bash
# =============================================================================================
#  install_ie.sh : préparation automatique d'un serveur iE / IRIUM (RHEL 9)
#
#  Disques LVM, dossiers, comptes, SSH, Samba, Genero + licences, Java, Informix 14.10 FC13
#  (installation, configuration, initialisation), dump, version i80 v3300 et préparation de
#  la migration depuis l'ancien serveur.
#
#  Auteur original : Hicham SLIMANI (v1 04/06/2026, v5 18/09/2026)
#  Refonte         : v6.0, exécution par étapes, configuration externe, journalisation
#
#  Utilisation : sudo ./install_ie.sh [options]      (./install_ie.sh --aide pour le détail)
#
#  Codes de sortie : 0 succès | 1 erreur | 2 usage | 3 prérequis manquant | 130 interruption
# =============================================================================================
set -Eeuo pipefail
shopt -s inherit_errexit 2>/dev/null || true
umask 027

readonly SCRIPT_VERSION="6.0.0"
SCRIPT_NAME="$(basename "${BASH_SOURCE[0]}")"
SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
readonly SCRIPT_NAME SCRIPT_DIR
HORODATAGE="$(date +%Y%m%d_%H%M%S)"
readonly HORODATAGE

# --- Options (modifiables par la ligne de commande) -------------------------------------------
CONFIG_FILE="$SCRIPT_DIR/install_ie.conf"
NON_INTERACTIF=0
SIMULATION=0
FORCER=0
VERBEUX=0
ETAPES_DEMANDEES=""
ETAPE_DEPART=""

# --- Répertoires de travail (tout reste dans le dossier du script) -----------------------------
LOG_DIR="$SCRIPT_DIR/logs"
ETAT_DIR="$SCRIPT_DIR/.etat"
SORTIE_DIR="$SCRIPT_DIR/sortie"
LOG_FILE="$LOG_DIR/install_ie_${HORODATAGE}.log"
LOCK_FILE="/run/install_ie.lock"

# --- Variables internes ------------------------------------------------------------------------
DEBUT_EXECUTION=$SECONDS
ETAPE_COURANTE="initialisation"
TMP_DIR=""
PV=""
CREDENTIALS_TMP=""
JAVA_A_RESTAURER=0
declare -a ETAPES_A_LANCER=()
declare -a ETAPES_FAITES=() ETAPES_IGNOREES=()

# =============================================================================================
#  Valeurs par défaut (surchargées par install_ie.conf puis, en mode interactif, par la saisie)
# =============================================================================================
DISK="/dev/sdb"
PV_MODE="partition"              # partition : crée une partition GPT | disque : disque entier
PARTITION_NAME=""                # partition attendue (vide = détection automatique)
EFFACER_SIGNATURES="non"         # mode disque : autorise wipefs -a en mode --oui
VG_NAME="iriumvg"
SIZE_DATALV="100G"               # minimum 80G
SIZE_MSDOSLV="50G"
SIZE_BACKUPLV="30G"
DATALV_MIN_GO=80

VARLOG_ACTION="demander"         # oui | non | demander : LV dédié à /var/log s'il n'est pas monté
VARLOG_VG="vg_00"
VARLOG_SIZE="4G"

VERSION_GENERO="3"
OLDSRV_IP=""
OLDSRV_NAME=""
IP_SERVEUR=""                    # vide = première adresse de « hostname -I »

IRIUM_DIR="/opt/irium"
SOURCES_DIR="/home/irium"        # archives Genero, JRE, Informix, modèles informix / param_ids
INFORMIX_DIR="/opt/irium/informix"
INFORMIX_EXTRACT_DIR="/msdos/informix"
INFORMIX_EDITION=""              # 1|express  2|workgroup  3|enterprise (vide = question)
INFORMIX_CPU_VPS=8
INFORMIX_TIMEOUT=900             # secondes d'attente maximale de l'initialisation

JAVA8_RPM="jre-8u201-linux-x64.rpm"
JAVA8_PATH="/usr/java/jre1.8.0_201-amd64/bin/java"
PAQUET_IMAGICK="php-pecl-imagick-3.7.0-1.el9.x86_64"
DEPOT_CRB="codeready-builder-for-rhel-9-x86_64-rpms"

ECW_USER=""
ECW_PASSWORD=""
DL_VERIFY_TLS="non"              # le serveur ECW présente un certificat non reconnu
URL_SCRIPTO="https://ecw.irium-france.com/ECMIrium/IRIUM Releases/iPro/His/scripto.sh"
URL_INFORMIX="https://ecw.irium-france.com/ECMIrium/IRIUM Releases/iPro/His/Informix_fc13_Irium_Installer.tgz"
URL_V3300="https://ecw.irium-france.com/ECMIrium/IRIUM_Releases/i80/Release/i80_v3300.sh"

GENERO_LICENCE_NUMERO=""
GENERO_LICENCE_CLE=""
GENERO_CLIENT=""
LICENCE_HOTE="4js.com"

LANCER_DUMP="demander"           # oui | non | demander
INSTALLER_V3300="demander"       # oui | non | demander
V3300_BINAIRE="/users/i80_v3300.sh"
V3300_DIR="/users/i80"
PROMPT_COULEUR="RED"
CREDENTIALS_FILE="/root/ie_identifiants.txt"

# =============================================================================================
#  Affichage et journalisation
# =============================================================================================
if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
    GREEN=$'\e[1;32m'; RED=$'\e[1;31m'; YELLOW=$'\e[1;33m'; BLUE=$'\e[1;34m'
    ORANGE=$'\e[38;5;208m'; BOLD=$'\e[1m'; NC=$'\e[0m'
else
    GREEN=""; RED=""; YELLOW=""; BLUE=""; ORANGE=""; BOLD=""; NC=""
fi

_ts()     { date '+%F %T'; }
log()     { printf '%s %s[INFO]%s  %s\n'  "$(_ts)" "$GREEN"  "$NC" "$*"; }
ok()      { printf '%s %s[ OK ]%s  %s\n'  "$(_ts)" "$GREEN"  "$NC" "$*"; }
warn()    { printf '%s %s[WARN]%s  %s\n'  "$(_ts)" "$ORANGE" "$NC" "$*" >&2; }
erreur()  { printf '%s %s[ERR ]%s  %s\n'  "$(_ts)" "$RED"    "$NC" "$*" >&2; }
die()     { erreur "$1"; exit "${2:-1}"; }
section() {
    printf '\n%s%s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n' "$BLUE" "$BOLD" "$NC"
    printf '%s%s  %s%s\n' "$BLUE" "$BOLD" "$*" "$NC"
    printf '%s%s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n' "$BLUE" "$BOLD" "$NC"
}
debug()   { (( VERBEUX )) && printf '%s [DBG ]  %s\n' "$(_ts)" "$*"; return 0; }

banniere() {
    printf '%s%s' "$GREEN" "$BOLD"
    cat <<EOF
╔══════════════════════════════════════════════════════════════╗
║              Préparation automatique de iE                   ║
╠══════════════════════════════════════════════════════════════╣
║ Version : ${SCRIPT_VERSION}   (auteur original : Hicham SLIMANI)        ║
║ Configuration et synchronisation des environnements IRIUM    ║
╚══════════════════════════════════════════════════════════════╝
EOF
    printf '%s' "$NC"
}

# =============================================================================================
#  Gestion des erreurs, nettoyage, verrou
# =============================================================================================
DERNIERE_ERREUR=""
on_err() {
    local rc=$1 ligne=$2 cmd=$3
    [[ "$DERNIERE_ERREUR" == "$ligne" ]] && return 0      # déjà signalée (sous-shell)
    DERNIERE_ERREUR=$ligne
    erreur "Échec (code $rc) à la ligne $ligne, étape « $ETAPE_COURANTE » : $cmd"
    erreur "Journal complet : $LOG_FILE"
}

nettoyage() {
    local rc=$?
    set +e
    if (( JAVA_A_RESTAURER )) && [[ -x "$JAVA8_PATH" ]]; then
        alternatives --set java "$JAVA8_PATH" >/dev/null 2>&1 && log "Java 8 rétabli par défaut."
    fi
    [[ -n "$TMP_DIR" && -d "$TMP_DIR" ]] && rm -rf "$TMP_DIR"
    local duree=$(( SECONDS - DEBUT_EXECUTION ))
    echo
    if (( rc == 0 )); then
        ok "Terminé en $((duree / 60)) min $((duree % 60)) s."
    else
        erreur "Arrêt (code $rc) après $((duree / 60)) min $((duree % 60)) s, étape « $ETAPE_COURANTE »."
        erreur "Après correction, relancer : la reprise saute les étapes déjà terminées."
    fi
    (( ${#ETAPES_FAITES[@]} ))   && log "Étapes réalisées : ${ETAPES_FAITES[*]}"
    (( ${#ETAPES_IGNOREES[@]} )) && log "Étapes déjà faites (ignorées) : ${ETAPES_IGNOREES[*]}"
    [[ -f "$LOG_FILE" ]] && log "Journal : $LOG_FILE"
    exit "$rc"
}

interruption() { echo; erreur "Interruption demandée par l'utilisateur."; exit 130; }

prendre_verrou() {
    exec 9>"$LOCK_FILE"
    flock -n 9 || die "Une autre exécution de $SCRIPT_NAME est en cours (verrou $LOCK_FILE)." 1
}

# =============================================================================================
#  Outils génériques
# =============================================================================================

# Exécute une commande, ou l'affiche seulement en mode simulation.
run() {
    if (( SIMULATION )); then
        printf '%s %s[SIMU]%s  %s\n' "$(_ts)" "$YELLOW" "$NC" "$(printf '%q ' "$@")"
        return 0
    fi
    debug "exec: $(printf '%q ' "$@")"
    "$@"
}

# Exécute une commande en tant qu'un autre compte, avec son environnement de connexion.
run_as() {
    local compte=$1; shift
    run su - "$compte" -c "$*"
}

# Question oui/non. o|y = oui, n = non, s|q = arrêt du script. En mode --oui : réponse « oui ».
confirmer() {
    local question=$1 rep
    if (( NON_INTERACTIF )); then
        log "$question -> oui (mode non interactif)"
        return 0
    fi
    while true; do
        read -r -p "$question [o/n/s=arrêt] : " rep </dev/tty
        case "${rep,,}" in
            o|oui|y|yes) return 0 ;;
            n|non|no)    return 1 ;;
            s|q|stop)    log "Arrêt demandé par l'utilisateur."; exit 0 ;;
            *)           warn "Réponse invalide : o, n ou s." ;;
        esac
    done
}

# Décision pilotée par la configuration : oui | non | demander.
decider() {
    local valeur=$1 question=$2
    case "${valeur,,}" in
        oui|o|yes|y) return 0 ;;
        non|n|no)    return 1 ;;
        *)           confirmer "$question" ;;
    esac
}

# Saisie masquée d'un secret manquant (jamais écrit dans le journal).
demander_secret() {
    local var=$1 libelle=$2 valeur
    [[ -n "${!var:-}" ]] && return 0
    if (( SIMULATION )); then printf -v "$var" '%s' "<$var>"; return 0; fi
    (( NON_INTERACTIF )) && die "$var est vide dans $CONFIG_FILE (requis en mode --oui)." 3
    read -r -s -p "$libelle : " valeur </dev/tty; echo >/dev/tty
    [[ -n "$valeur" ]] || die "$var ne peut pas être vide." 3
    printf -v "$var" '%s' "$valeur"
}

saisir() {
    local var=$1 libelle=$2 rep
    read -r -p "$libelle [${!var}] : " rep </dev/tty
    [[ -n "$rep" ]] && printf -v "$var" '%s' "$rep"
    return 0
}

tmp_dir() {
    [[ -n "$TMP_DIR" ]] || TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/install_ie.XXXXXX")"
    printf '%s' "$TMP_DIR"
}

# Copie de sauvegarde unique par exécution : fichier.avant_ie_<horodatage>.
sauvegarder() {
    local f=$1
    [[ -e "$f" && ! -e "$f.avant_ie_$HORODATAGE" ]] || return 0
    run cp -a "$f" "$f.avant_ie_$HORODATAGE"
    log "Sauvegarde : $f.avant_ie_$HORODATAGE"
}

# Écrit stdin dans un fichier (via un fichier temporaire), avec mode et propriétaire.
ecrire_fichier() {
    local dest=$1 mode=${2:-0644} proprio=${3:-root:root} tmp
    if (( SIMULATION )); then
        cat >/dev/null
        printf '%s %s[SIMU]%s  écriture de %s (%s %s)\n' "$(_ts)" "$YELLOW" "$NC" "$dest" "$mode" "$proprio"
        return 0
    fi
    tmp="$(tmp_dir)/$(basename "$dest").$$"
    cat >"$tmp"
    if [[ "$proprio" == "auto" ]]; then          # conserve propriétaire et droits existants
        if [[ -e "$dest" ]]; then proprio=$(stat -c '%U:%G' "$dest"); mode=$(stat -c '%a' "$dest"); else proprio=root:root; fi
    fi
    [[ -e "$dest" ]] && cmp -s "$tmp" "$dest" && { debug "$dest inchangé"; return 0; }
    sauvegarder "$dest"
    install -m "$mode" -o "${proprio%%:*}" -g "${proprio##*:}" "$tmp" "$dest"
}

# Ajoute une ligne à un fichier si elle n'y figure pas déjà (idempotent).
ajouter_ligne() {
    local fichier=$1 ligne=$2
    [[ -f "$fichier" ]] && grep -qxF -- "$ligne" "$fichier" && return 0
    sauvegarder "$fichier"
    if (( SIMULATION )); then
        printf '%s %s[SIMU]%s  ajout dans %s : %s\n' "$(_ts)" "$YELLOW" "$NC" "$fichier" "$ligne"
    else
        printf '%s\n' "$ligne" >>"$fichier"
    fi
}

compte_existe() { id "$1" >/dev/null 2>&1; }
groupe_existe() { getent group "$1" >/dev/null 2>&1; }

# Mot de passe aléatoire : au moins une majuscule, une minuscule, un chiffre, un spécial.
generer_mot_de_passe() {
    local longueur=${1:-16} base
    _alea() {   # $2 caractères tirés de l'ensemble $1 (sans SIGPIPE : head se termine avant tr)
        local res=""
        while (( ${#res} < $2 )); do res+=$(head -c 512 /dev/urandom | LC_ALL=C tr -dc "$1"); done
        printf '%s' "${res:0:$2}"
    }
    base="$(_alea 'A-Z' 1)$(_alea 'a-z' 1)$(_alea '0-9' 1)$(_alea '!@#%^*()_+=' 1)"
    base+="$(_alea 'A-Za-z0-9!@#%^*()_+=' $(( longueur - 4 )))"
    fold -w1 <<<"$base" | shuf | tr -d '\n'
}

# Téléchargement authentifié : identifiants dans un wgetrc temporaire (absents de « ps »),
# fichier .part renommé seulement en cas de succès (pas de fichier vide laissé en place).
telecharger() {
    local url=$1 dest=$2 rc_file opts=()
    demander_secret ECW_USER "Utilisateur du portail ECW IRIUM"
    demander_secret ECW_PASSWORD "Mot de passe du portail ECW IRIUM"
    rc_file="$(tmp_dir)/wgetrc"
    ( umask 077; printf 'user=%s\npassword=%s\n' "$ECW_USER" "$ECW_PASSWORD" >"$rc_file" )
    [[ "${DL_VERIFY_TLS,,}" == "oui" ]] || opts+=(--no-check-certificate)
    log "Téléchargement : $(basename "$dest")"
    if (( SIMULATION )); then run wget "${opts[@]}" "$url" -O "$dest"; return 0; fi
    if WGETRC="$rc_file" wget --progress=dot:giga --tries=3 --timeout=60 "${opts[@]}" "$url" -O "$dest.part"; then
        mv -f "$dest.part" "$dest"
        ok "Téléchargé : $dest ($(du -h "$dest" | cut -f1))"
    else
        rm -f "$dest.part"
        return 1
    fi
}

port_accessible() { timeout 10 bash -c "exec 3<>/dev/tcp/$1/$2" 2>/dev/null; }

# =============================================================================================
#  Validations
# =============================================================================================
valider_ip() {
    local ip=$1 o
    [[ "$ip" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
    for o in "${BASH_REMATCH[@]:1}"; do (( 10#$o <= 255 )) || return 1; done
}
valider_taille()  { [[ "$1" =~ ^[1-9][0-9]*[GT]$ ]]; }
valider_vg()      { [[ "$1" =~ ^[A-Za-z][A-Za-z0-9_+.]*$ ]]; }
valider_genero()  { [[ "$1" =~ ^[23]$ ]]; }
valider_nom_srv() { [[ -z "$1" || "$1" =~ ^[a-z0-9_]+$ ]]; }

# 100, 100g, 100G -> 100G ; 1t -> 1T
normaliser_taille() {
    local t=${1^^}
    [[ "$t" =~ ^[0-9]+$ ]] && t="${t}G"
    printf '%s' "$t"
}
taille_en_go() {
    local t=$1
    case "$t" in *T) echo $(( ${t%T} * 1024 )) ;; *G) echo "${t%G}" ;; *) echo 0 ;; esac
}

# Nom de la partition n°N d'un disque : /dev/sdb -> /dev/sdb1, /dev/nvme0n1 -> /dev/nvme0n1p1
nom_partition() {
    local disque=$1 num=$2
    if [[ "$disque" =~ [0-9]$ ]]; then printf '%sp%s' "$disque" "$num"; else printf '%s%s' "$disque" "$num"; fi
}

# Nom de l'instance Informix : ol_<nom court en minuscules, sans tiret>
nom_instance_informix() {
    local h
    h="$(hostname -s)"
    h="${h,,}"
    printf 'ol_%s' "${h//-/}"
}

ip_serveur() {
    if [[ -n "$IP_SERVEUR" ]]; then printf '%s' "$IP_SERVEUR"; else hostname -I | awk '{print $1}'; fi
}

valider_parametres() {
    local e=0
    SIZE_DATALV=$(normaliser_taille "$SIZE_DATALV")
    SIZE_MSDOSLV=$(normaliser_taille "$SIZE_MSDOSLV")
    SIZE_BACKUPLV=$(normaliser_taille "$SIZE_BACKUPLV")
    VARLOG_SIZE=$(normaliser_taille "$VARLOG_SIZE")
    OLDSRV_NAME=${OLDSRV_NAME,,}

    [[ "$PV_MODE" == "partition" || "$PV_MODE" == "disque" ]] || { erreur "PV_MODE doit valoir partition ou disque."; e=1; }
    valider_vg "$VG_NAME"            || { erreur "Nom de Volume Group invalide : $VG_NAME"; e=1; }
    local v
    for v in SIZE_DATALV SIZE_MSDOSLV SIZE_BACKUPLV VARLOG_SIZE; do
        valider_taille "${!v}" || { erreur "$v : « ${!v} » invalide (attendu : 200G, 1T…)."; e=1; }
    done
    if valider_taille "$SIZE_DATALV" && (( $(taille_en_go "$SIZE_DATALV") < DATALV_MIN_GO )); then
        erreur "datalv doit faire au moins ${DATALV_MIN_GO}G (valeur : $SIZE_DATALV)."; e=1
    fi
    valider_genero "$VERSION_GENERO" || { erreur "VERSION_GENERO doit valoir 2 ou 3."; e=1; }
    [[ -z "$OLDSRV_IP" ]] || valider_ip "$OLDSRV_IP" || { erreur "Adresse IP de l'ancien serveur invalide : $OLDSRV_IP"; e=1; }
    [[ -z "$IP_SERVEUR" ]] || valider_ip "$IP_SERVEUR" || { erreur "IP_SERVEUR invalide : $IP_SERVEUR"; e=1; }
    valider_nom_srv "$OLDSRV_NAME"   || { erreur "Nom de l'ancien serveur invalide : $OLDSRV_NAME (minuscules, chiffres, _)."; e=1; }
    if [[ -n "$INFORMIX_EDITION" ]]; then
        case "${INFORMIX_EDITION,,}" in
            1|express|2|workgroup|3|enterprise) ;;
            *) erreur "INFORMIX_EDITION invalide : $INFORMIX_EDITION"; e=1 ;;
        esac
    fi
    if [[ "$PV_MODE" == "partition" && -n "$PARTITION_NAME" && "$PARTITION_NAME" != "$DISK"* ]]; then
        erreur "La partition $PARTITION_NAME n'appartient pas au disque $DISK."; e=1
    fi
    return "$e"
}

afficher_parametres() {
    section "Paramètres"
    printf '  %-34s %s\n' \
        "Disque"                          "$DISK" \
        "Volume physique"                 "$( [[ $PV_MODE == disque ]] && echo "disque entier" || echo "partition ${PARTITION_NAME:-(auto)}")" \
        "Volume Group"                    "$VG_NAME" \
        "datalv  (/data)"                 "$SIZE_DATALV" \
        "msdoslv (/msdos)"                "$SIZE_MSDOSLV" \
        "backuplv (/backup)"              "$SIZE_BACKUPLV" \
        "/var/log dédié"                  "$VARLOG_ACTION ($VARLOG_SIZE dans $VARLOG_VG)" \
        "Version Genero"                  "$VERSION_GENERO" \
        "Ancien serveur (IP / nom)"       "${OLDSRV_IP:-non renseignée} / ${OLDSRV_NAME:-non renseigné}" \
        "Instance Informix"               "$(nom_instance_informix)" \
        "Édition Informix"                "${INFORMIX_EDITION:-question}" \
        "Dump / v3300"                    "$LANCER_DUMP / $INSTALLER_V3300"
    echo
}

saisir_parametres() {
    section "Modification des paramètres (Entrée = valeur entre crochets)"
    while true; do
        saisir DISK "Disque à utiliser (ex : /dev/sdb)"
        saisir VG_NAME "Nom du Volume Group (ex : iriumvg, vg_00)"
        saisir PV_MODE "Volume physique : partition (recommandé) ou disque entier [partition/disque]"
        if [[ "$PV_MODE" == "partition" ]]; then
            saisir PARTITION_NAME "Partition attendue (vide = détection automatique, ex : ${DISK}1)"
        fi
        saisir SIZE_DATALV "Taille datalv (ex : 200G, minimum ${DATALV_MIN_GO}G)"
        saisir SIZE_BACKUPLV "Taille backuplv"
        saisir SIZE_MSDOSLV "Taille msdoslv"
        saisir OLDSRV_IP "IP de l'ancien serveur (ex : 192.168.1.250)"
        saisir OLDSRV_NAME "Nom de l'ancien serveur (alias ol_<nom>_net, vide = aucun)"
        saisir VERSION_GENERO "Version Genero (2 ou 3)"
        if valider_parametres; then
            afficher_parametres
            confirmer "Utiliser ces paramètres ?" && return 0
        else
            warn "Une ou plusieurs valeurs sont invalides : nouvelle saisie."
        fi
    done
}

# =============================================================================================
#  Étapes
# =============================================================================================
ETAPES=(controles disques dossiers varlog ssh comptes systeme scripto genero archivage
        services informix_install informix_config informix_init dump v3300 migration)
declare -A DESC_ETAPE=(
    [controles]="Contrôles préalables (root, OS, commandes, comptes, sources)"
    [disques]="Partition, PV, VG, LV datalv/msdoslv/backuplv, XFS, fstab, montage"
    [dossiers]="Dossiers /users, /backup, /msdos, liens et droits"
    [varlog]="Volume logique dédié à /var/log (s'il n'est pas déjà monté)"
    [ssh]="Clés SSH root et alias « oldsrv »"
    [comptes]="Comptes msdos/supie/cslie, mots de passe, Samba, home de manager"
    [systeme]="/etc/hosts, expect, couleur du prompt"
    [scripto]="Téléchargement de scripto"
    [genero]="Genero, Java 8, licences fgl et flm"
    [archivage]="archivage_ids (dump commenté), /var/log/backup_ids.log"
    [services]="GAS, compte strs"
    [informix_install]="Installation Informix 14.10 FC13 et Client SDK"
    [informix_config]="onconfig, sqlhosts, chunks, profil informix, sch_init"
    [informix_init]="Initialisation de l'instance (oninit -iy) et réglages sysadmin"
    [dump]="Sauvegarde ontape (backup.cde)"
    [v3300]="Installation de la version i80 v3300"
    [migration]="Commandes à lancer sur l'ancien et le nouveau serveur"
)

# --------------------------------------------------------------------------------------------
etape_controles() {
    [[ $EUID -eq 0 ]] || die "Ce script doit être exécuté en root." 3
    ok "Exécution en root."

    if [[ -r /etc/os-release ]]; then
        local nom_os version_os
        # shellcheck disable=SC1091
        nom_os=$(. /etc/os-release && echo "${PRETTY_NAME:-inconnu}")
        # shellcheck disable=SC1091
        version_os=$(. /etc/os-release && echo "${VERSION_ID:-?}")
        log "Système : $nom_os"
        [[ "${version_os%%.*}" == "9" ]] || warn "Script conçu pour RHEL 9 (détecté : $version_os)."
    fi

    local cmd manquantes=()
    for cmd in lsblk parted partprobe udevadm wipefs pvcreate vgcreate lvcreate mkfs.xfs blkid findmnt \
               wget tar unzip rpm dnf alternatives systemctl ssh-keygen chpasswd useradd usermod flock; do
        command -v "$cmd" >/dev/null 2>&1 || manquantes+=("$cmd")
    done
    (( ${#manquantes[@]} == 0 )) || die "Commandes manquantes : ${manquantes[*]}" 3
    ok "Commandes système présentes."

    local c absents=()
    for c in regix informix compta manager genero; do compte_existe "$c" || absents+=("$c"); done
    groupe_existe informix || absents+=("groupe:informix")
    (( ${#absents[@]} == 0 )) || warn "Comptes/groupes attendus absents de l'image : ${absents[*]}"

    [[ -d "$SOURCES_DIR" ]] || warn "Dossier des sources absent : $SOURCES_DIR"
    [[ -d "$IRIUM_DIR/manager" ]] || warn "$IRIUM_DIR/manager absent : l'image IRIUM est-elle complète ?"

    if [[ -n "$OLDSRV_IP" ]] && ! port_accessible "$OLDSRV_IP" 22; then
        warn "Ancien serveur $OLDSRV_IP injoignable sur le port 22 (à vérifier avant la migration)."
    fi
    log "Instance Informix prévue : $(nom_instance_informix), IP du serveur : $(ip_serveur)"
}

# --------------------------------------------------------------------------------------------
etape_disques() {
    log "État actuel des disques :"
    lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINTS
    echo

    local pv
    if vgs "$VG_NAME" >/dev/null 2>&1; then
        warn "Le Volume Group $VG_NAME existe déjà : partitionnement et création du PV ignorés."
    else
        [[ -b "$DISK" ]] || die "$DISK n'existe pas ou n'est pas un périphérique bloc."
        [[ "$(lsblk -dno TYPE "$DISK")" == "disk" ]] || die "$DISK n'est pas un disque entier."
        if lsblk -nro MOUNTPOINTS "$DISK" | grep -q .; then
            die "$DISK (ou une de ses partitions) est monté : disque système ou déjà utilisé ?"
        fi

        if [[ "$PV_MODE" == "disque" ]]; then preparer_disque_entier; else creer_partition; fi
        pv=$PV

        if pvs "$pv" >/dev/null 2>&1; then
            warn "$pv est déjà un volume physique."
        else
            run pvcreate "$pv"
            ok "Volume physique créé : $pv"
        fi
        confirmer "Créer le Volume Group $VG_NAME sur $pv ?" || die "Création du Volume Group annulée."
        run vgcreate "$VG_NAME" "$pv"
        ok "Volume Group $VG_NAME créé."
    fi

    verifier_espace_vg
    creer_volume datalv   "$SIZE_DATALV"   /data
    creer_volume msdoslv  "$SIZE_MSDOSLV"  /msdos
    creer_volume backuplv "$SIZE_BACKUPLV" /backup
    df -hT /data /msdos /backup 2>/dev/null || true
}

preparer_disque_entier() {
    if lsblk -nro TYPE "$DISK" | grep -qx part; then
        die "Mode disque entier : $DISK possède déjà des partitions."
    fi
    local sig
    sig=$(wipefs -n "$DISK") || die "Impossible de lire les signatures de $DISK."
    if [[ -n "$sig" ]]; then
        warn "Signatures présentes sur $DISK :"
        printf '%s\n' "$sig"
        if (( NON_INTERACTIF )) && [[ "${EFFACER_SIGNATURES,,}" != "oui" ]]; then
            die "Effacement refusé : mettre EFFACER_SIGNATURES=oui pour l'autoriser en mode --oui."
        fi
        confirmer "EFFACER définitivement les signatures de $DISK ?" || die "Vérification manuelle nécessaire avant pvcreate."
        run wipefs -a "$DISK"
        (( SIMULATION )) || [[ -z "$(wipefs -n "$DISK")" ]] || die "Signatures toujours présentes sur $DISK."
        ok "Signatures effacées sur $DISK."
    fi
    PV=$DISK
}

# Crée une partition LVM dans le dernier espace libre du disque (résultat dans PV).
creer_partition() {
    local avant apres nouvelle debut
    if [[ -n "$PARTITION_NAME" && -b "$PARTITION_NAME" ]]; then
        die "La partition $PARTITION_NAME existe déjà : choisir une autre partition ou PARTITION_NAME vide."
    fi
    avant=$(lsblk -lnpo NAME,TYPE "$DISK" | awk '$2=="part"{print $1}')

    if ! parted -s "$DISK" print >/dev/null 2>&1; then
        log "Aucune table de partitions sur $DISK : création GPT."
        run parted -s "$DISK" mklabel gpt
    fi
    if [[ -z "$avant" ]]; then
        debut="1MiB"
    else
        debut=$(parted -m -s "$DISK" unit MiB print free | awk -F: '
            { gsub(/;/, "", $NF) }
            $NF == "free" { s = $2; sub(/MiB/, "", s); sz = $4; sub(/MiB/, "", sz); if (sz + 0 >= 1024) start = s }
            END { if (start != "") printf "%dMiB", (start == int(start) ? start : int(start) + 1) }')
        [[ -n "$debut" ]] || die "Aucun espace libre (≥ 1 Gio) sur $DISK."
    fi
    log "Création d'une partition LVM sur $DISK de $debut à la fin du disque."
    run parted -s -a optimal "$DISK" mkpart primary "$debut" 100%
    run partprobe "$DISK" || warn "partprobe : relecture de la table différée."
    run udevadm settle

    if (( SIMULATION )); then PV=${PARTITION_NAME:-$(nom_partition "$DISK" 1)}; return 0; fi

    apres=$(lsblk -lnpo NAME,TYPE "$DISK" | awk '$2=="part"{print $1}')
    nouvelle=$(comm -13 <(sort <<<"$avant") <(sort <<<"$apres") | head -1)
    [[ -n "$nouvelle" && -b "$nouvelle" ]] || die "La nouvelle partition n'a pas été détectée sur $DISK."
    if [[ -n "$PARTITION_NAME" && "$nouvelle" != "$PARTITION_NAME" ]]; then
        die "parted a créé $nouvelle alors que $PARTITION_NAME était attendue : vérifier puis relancer."
    fi
    local num=${nouvelle##*[!0-9]}
    run parted -s "$DISK" set "$num" lvm on
    ok "Partition créée : $nouvelle"
    lsblk "$DISK"
    PV=$nouvelle
}

verifier_espace_vg() {
    (( SIMULATION )) && ! vgs "$VG_NAME" >/dev/null 2>&1 && return 0
    local besoin=0 libre lv taille
    for lv in "datalv:$SIZE_DATALV" "msdoslv:$SIZE_MSDOSLV" "backuplv:$SIZE_BACKUPLV"; do
        taille=${lv#*:}
        lvs "$VG_NAME/${lv%%:*}" >/dev/null 2>&1 || besoin=$(( besoin + $(taille_en_go "$taille") ))
    done
    libre=$(vgs --noheadings --units g --nosuffix -o vg_free "$VG_NAME" | awk '{printf "%d", $1}')
    log "Espace libre dans $VG_NAME : ${libre}G, nécessaire : ${besoin}G"
    (( libre >= besoin )) || die "Espace insuffisant dans $VG_NAME (${libre}G libres pour ${besoin}G demandés)."
}

# Ligne fstab idempotente, puis montage.
monter() {
    local dev=$1 point=$2 options=${3:-defaults}
    run mkdir -p "$point"
    if awk -v p="$point" '$1 !~ /^#/ && $2 == p {f=1} END {exit !f}' /etc/fstab; then
        log "$point déjà déclaré dans /etc/fstab."
    else
        ajouter_ligne /etc/fstab "$dev  $point  xfs  $options  0 0"
        ok "Ajout dans /etc/fstab : $dev -> $point"
    fi
    run systemctl daemon-reload
    if mountpoint -q "$point"; then
        log "$point déjà monté."
    else
        run mount "$point"
        ok "$point monté."
    fi
}

creer_volume() {
    local lv=$1 taille=$2 point=$3 dev
    dev="/dev/mapper/${VG_NAME//-/--}-$lv"
    if lvs "$VG_NAME/$lv" >/dev/null 2>&1; then
        warn "Volume logique $VG_NAME/$lv déjà présent."
    else
        run lvcreate -y -L "$taille" -n "$lv" "$VG_NAME"
        ok "Volume logique $lv ($taille) créé."
    fi
    if (( ! SIMULATION )) && [[ -n "$(blkid -o value -s TYPE "$dev" 2>/dev/null)" ]]; then
        log "$dev contient déjà un système de fichiers ($(blkid -o value -s TYPE "$dev"))."
    else
        run mkfs.xfs -q "$dev"
        ok "XFS créé sur $dev."
    fi
    monter "$dev" "$point"
}

# --------------------------------------------------------------------------------------------
etape_dossiers() {
    run install -d -m 0775 -o regix -g informix /users /backup
    run install -d -m 0775 /data
    run install -d -m 0777 -o regix -g informix "$V3300_DIR" "$V3300_DIR/log" /backup/import
    run install -d -m 0777 -o nobody -g nobody /msdos
    run mkdir -p "$IRIUM_DIR"

    local lien="$IRIUM_DIR/backup"
    if [[ -L "$lien" && "$(readlink "$lien")" == "/backup" ]]; then
        log "$lien pointe déjà vers /backup."
    else
        if [[ -e "$lien" || -L "$lien" ]]; then
            warn "$lien existe : déplacé vers $lien.avant_ie_$HORODATAGE"
            run mv "$lien" "$lien.avant_ie_$HORODATAGE"
        fi
        run ln -s /backup "$lien"
        ok "Lien $lien -> /backup créé."
    fi
    run chown -h regix:informix "$lien"
    ls -ld /data /backup /users /msdos "$lien" 2>/dev/null || true
}

# --------------------------------------------------------------------------------------------
etape_varlog() {
    if mountpoint -q /var/log; then
        ok "/var/log est déjà un point de montage dédié."
        df -h /var/log
        return 0
    fi
    warn "/var/log n'est PAS un volume dédié."
    decider "$VARLOG_ACTION" "Créer un volume logique $VARLOG_SIZE dans $VARLOG_VG pour /var/log ?" || {
        warn "Volume /var/log non créé (choix de l'utilisateur)."; return 0; }
    vgs "$VARLOG_VG" >/dev/null 2>&1 || die "Le Volume Group $VARLOG_VG (VARLOG_VG) n'existe pas."

    local lv=lv_var_log dev="/dev/mapper/${VARLOG_VG//-/--}-lv_var_log" tmp
    lvs "$VARLOG_VG/$lv" >/dev/null 2>&1 || run lvcreate -y -L "$VARLOG_SIZE" -n "$lv" "$VARLOG_VG"
    [[ -n "$(blkid -o value -s TYPE "$dev" 2>/dev/null)" ]] || run mkfs.xfs -q "$dev"

    tmp="$(tmp_dir)/varlog"
    run mkdir -p "$tmp"
    run mount "$dev" "$tmp"
    log "Copie du contenu de /var/log (droits, ACL, contextes SELinux conservés)..."
    run cp -a --preserve=all /var/log/. "$tmp/"
    run umount "$tmp"

    ajouter_ligne /etc/fstab "$dev  /var/log  xfs  defaults  0 0"
    run systemctl daemon-reload
    run mount /var/log
    command -v restorecon >/dev/null && run restorecon -R /var/log

    # Libère l'ancien contenu, désormais masqué, via un montage « bind » de la racine.
    local racine="$tmp/racine"
    run mkdir -p "$racine"
    run mount --bind / "$racine"
    run find "$racine/var/log" -mindepth 1 -delete
    run umount "$racine"

    run systemctl restart systemd-journald
    systemctl is-active -q rsyslog 2>/dev/null && run systemctl restart rsyslog
    mountpoint -q /var/log || (( SIMULATION )) || die "/var/log n'est pas monté après l'opération."
    ok "/var/log monté sur $dev."
    df -h /var/log
}

# --------------------------------------------------------------------------------------------
etape_ssh() {
    run install -d -m 0700 /root/.ssh
    local type
    for type in ed25519 rsa; do
        if [[ -f "/root/.ssh/id_$type" ]]; then
            log "Clé /root/.ssh/id_$type déjà présente : conservée."
        elif [[ $type == rsa ]]; then
            run ssh-keygen -q -t rsa -b 4096 -N "" -C "root@$(hostname -s)" -f /root/.ssh/id_rsa
        else
            run ssh-keygen -q -t ed25519 -N "" -C "root@$(hostname -s)" -f /root/.ssh/id_ed25519
        fi
    done

    if [[ -z "$OLDSRV_IP" ]]; then
        warn "OLDSRV_IP vide : alias « oldsrv » non configuré."
    elif [[ -f /root/.ssh/config ]] && grep -qE '^Host[[:space:]]+oldsrv$' /root/.ssh/config; then
        log "Alias « oldsrv » déjà présent dans /root/.ssh/config."
    else
        sauvegarder /root/.ssh/config
        if (( SIMULATION )); then
            log "[SIMU] ajout de l'alias oldsrv ($OLDSRV_IP) dans /root/.ssh/config"
        else
            printf '\nHost oldsrv\n    HostName %s\n    User root\n    IdentityFile ~/.ssh/id_rsa\n' "$OLDSRV_IP" >>/root/.ssh/config
        fi
        ok "Alias « oldsrv » -> $OLDSRV_IP ajouté."
    fi
    run touch /root/.ssh/config /root/.ssh/authorized_keys
    run chmod 600 /root/.ssh/config /root/.ssh/authorized_keys
    command -v restorecon >/dev/null && run restorecon -R /root/.ssh
    return 0
}

# --------------------------------------------------------------------------------------------
definir_mot_de_passe() {
    local compte=$1 mdp=$2
    if ! compte_existe "$compte"; then warn "Compte $compte absent : mot de passe non défini."; return 0; fi
    if (( SIMULATION )); then log "[SIMU] mot de passe de $compte"; else printf '%s:%s\n' "$compte" "$mdp" | chpasswd; fi
    printf '%-10s %s\n' "$compte" "$mdp" >>"$CREDENTIALS_TMP"
    ok "Mot de passe défini pour $compte."
}

etape_comptes() {
    CREDENTIALS_TMP="$(tmp_dir)/identifiants"
    ( umask 077; printf '# Identifiants %s, générés le %s (à saisir dans LockSelf puis supprimer)\n' \
        "$(hostname -s)" "$(date '+%F %T')" >"$CREDENTIALS_TMP" )

    compte_existe msdos || run useradd -g informix -s /sbin/nologin -M msdos
    run usermod -aG informix msdos
    local c
    for c in supie cslie; do                # supie : support iE, cslie : consultant iE
        compte_existe "$c" || run useradd -m "$c"
        run usermod -aG wheel "$c"
    done

    local mdp_msdos
    mdp_msdos=$(generer_mot_de_passe)
    definir_mot_de_passe msdos "$mdp_msdos"
    for c in supie cslie regix compta informix; do
        definir_mot_de_passe "$c" "$(generer_mot_de_passe)"
    done

    if command -v smbpasswd >/dev/null 2>&1; then
        if (( SIMULATION )); then
            log "[SIMU] smbpasswd -s -a msdos"
        else
            printf '%s\n%s\n' "$mdp_msdos" "$mdp_msdos" | smbpasswd -s -a msdos >/dev/null
        fi
        run smbpasswd -e msdos
        run systemctl enable --now smb nmb
        run systemctl restart smb nmb
        if (( ! SIMULATION )); then
            pdbedit -L | grep -q '^msdos:' && ok "Compte Samba msdos actif."
            if PASSWD="$mdp_msdos" smbclient -L //localhost -U msdos >/dev/null 2>&1; then
                ok "Connexion Samba msdos testée."
            else
                warn "Test smbclient msdos en échec (à vérifier)."
            fi
        fi
    else
        warn "Samba absent (smbpasswd introuvable) : partage msdos non configuré."
    fi

    if compte_existe manager; then
        run usermod -d "$IRIUM_DIR/manager" manager
        ok "Home de manager : $(getent passwd manager | cut -d: -f6)"
    else
        warn "Compte manager absent."
    fi

    if (( ! SIMULATION )); then
        sauvegarder "$CREDENTIALS_FILE"
        install -m 600 -o root -g root "$CREDENTIALS_TMP" "$CREDENTIALS_FILE"
    fi
    ok "Identifiants enregistrés dans $CREDENTIALS_FILE (droits 600, jamais écrits dans le journal)."
}

# --------------------------------------------------------------------------------------------
etape_systeme() {
    local ip nom
    ip=$(ip_serveur); nom=$(hostname)
    if awk -v n="$nom" '$1 !~ /^#/ { for (i = 2; i <= NF; i++) if ($i == n) f = 1 } END { exit !f }' /etc/hosts; then
        log "$nom déjà présent dans /etc/hosts."
    else
        ajouter_ligne /etc/hosts "$ip $nom $(hostname -s)"
        ok "/etc/hosts : $ip $nom"
    fi

    if command -v expect >/dev/null 2>&1; then
        log "expect déjà installé."
    else
        run dnf install -y expect || warn "Impossible d'installer expect."
    fi

    local profil=/etc/profile.d/custom.sh
    if [[ -f "$profil" ]]; then
        sauvegarder "$profil"
        run sed -i "s/^pc=.*/pc=\$${PROMPT_COULEUR}/" "$profil"
        ok "Couleur du prompt : $PROMPT_COULEUR ($(grep -m1 '^pc=' "$profil" || true))"
    else
        warn "$profil absent : couleur du prompt inchangée."
    fi
}

# --------------------------------------------------------------------------------------------
etape_scripto() {
    local bin="$IRIUM_DIR/manager/bin"
    [[ -d "$bin" ]] || die "$bin introuvable."
    telecharger "$URL_SCRIPTO" "$bin/scripto"
    run chmod 755 "$bin/scripto"
    rm -f "$bin"/scripto.sh 2>/dev/null || true
    ajouter_ligne /root/.bashrc "alias scripto='sh $bin/scripto'"
    ok "scripto installé : $bin/scripto (alias « scripto »)."
}

# --------------------------------------------------------------------------------------------
ecrire_licence_fgl() {
    ecrire_fichier "$IRIUM_DIR/fglgws/bin/newlicence" 0700 root:root <<EOFLIC
#!/bin/sh
# Renouvellement de la licence Genero fgl (généré par $SCRIPT_NAME le $(date +%F))
FGLDIR=$IRIUM_DIR/fglgws
export FGLDIR
PATH=\$PATH:\$FGLDIR/bin
export PATH

fglWrt -d <<EOF2 >/dev/null 2>&1
y
EOF2

fglWrt -l <<EOF3 >/dev/null 2>&1

$GENERO_LICENCE_NUMERO P
$GENERO_LICENCE_CLE 2
n
EOF3

fglWrt -m auto <<EOF4 >/dev/null 2>&1
$GENERO_CLIENT
n
EOF4
EOFLIC
}

ecrire_licence_flm() {
    ecrire_fichier "$IRIUM_DIR/flm/bin/newlicence" 0700 root:root <<EOFLIC
#!/bin/bash
# Renouvellement de la licence Genero License Server (généré par $SCRIPT_NAME le $(date +%F))
FLMDIR="$IRIUM_DIR/flm"
export FLMDIR
PATH="\$FLMDIR/bin:\$PATH"
export PATH

flmprg -d $GENERO_LICENCE_NUMERO <<EOF2 >/dev/null 2>&1
yes
EOF2
flmprg -l <<EOF3 >/dev/null 2>&1

$GENERO_LICENCE_NUMERO P
$GENERO_LICENCE_CLE 2
no


stop
EOF3
flmprg -m $GENERO_LICENCE_NUMERO auto <<EOF4 >/dev/null 2>&1
yes
$GENERO_CLIENT
no
EOF4
EOFLIC
}

etape_genero() {
    local archive
    case "$VERSION_GENERO" in
        2) archive="genero-2.50_26-64.tgz" ;;
        3) archive="genero-3.20.13-64.tgz" ;;
    esac
    [[ -f "$SOURCES_DIR/$archive" ]] || die "Archive Genero introuvable : $SOURCES_DIR/$archive"
    log "Extraction de $archive dans $IRIUM_DIR..."
    run tar -xf "$SOURCES_DIR/$archive" -C "$IRIUM_DIR"
    local d
    for d in fglgws gas gre; do
        [[ -d "$IRIUM_DIR/$d" ]] && run chown -R genero:genero "$IRIUM_DIR/$d"
    done
    ok "Genero $VERSION_GENERO installé."

    # Java 8 (JRE Oracle fourni par IRIUM)
    local rpm="$SOURCES_DIR/$JAVA8_RPM" pkg
    [[ -f "$rpm" ]] || die "RPM Java 8 introuvable : $rpm"
    pkg=$(rpm -qp --qf '%{NAME}' "$rpm" 2>/dev/null) || die "RPM illisible ou corrompu : $rpm"
    if rpm -q "$pkg" >/dev/null 2>&1; then
        log "Paquet $pkg déjà installé."
    else
        run rpm -ivh "$rpm"
    fi
    (( SIMULATION )) || [[ -x "$JAVA8_PATH" ]] || die "Java 8 introuvable : $JAVA8_PATH"
    run alternatives --set java "$JAVA8_PATH"
    (( SIMULATION )) || java -version 2>&1 | head -1 || true

    # Licences
    demander_secret GENERO_LICENCE_NUMERO "Numéro de licence Genero (ex : TAB#XXXXXXXX)"
    demander_secret GENERO_LICENCE_CLE "Clé de licence Genero"
    demander_secret GENERO_CLIENT "Identifiant client 4js"
    ecrire_licence_fgl
    ecrire_licence_flm

    if port_accessible "$LICENCE_HOTE" 443; then
        ok "$LICENCE_HOTE:443 accessible : activation des licences."
        run sh "$IRIUM_DIR/fglgws/bin/newlicence" || warn "Licence fgl : code retour non nul."
        run sh "$IRIUM_DIR/flm/bin/newlicence"    || warn "Licence flm : code retour non nul."
    else
        warn "$LICENCE_HOTE:443 inaccessible : licences à activer plus tard avec les scripts newlicence."
    fi

    local ligne_cron="0 21 * * 0 $IRIUM_DIR/fglgws/bin/newlicence # a enlever après migration"
    if crontab -l 2>/dev/null | grep -Fq "$IRIUM_DIR/fglgws/bin/newlicence"; then
        log "Tâche cron de la licence fgl déjà présente."
    elif (( SIMULATION )); then
        log "[SIMU] ajout cron : $ligne_cron"
    else
        { crontab -l 2>/dev/null || true; echo "$ligne_cron"; } | crontab -
        ok "Tâche cron de la licence fgl ajoutée (dimanche 21 h)."
    fi

    run_as regix "fglWrt -a see" || warn "fglWrt -a see en échec."
    run env PATH="$IRIUM_DIR/flm/bin:$PATH" FLMDIR="$IRIUM_DIR/flm" flmprg -a see || warn "flmprg -a see en échec."
}

# --------------------------------------------------------------------------------------------
etape_archivage() {
    local bin="$IRIUM_DIR/manager/bin"
    [[ -f "$bin/archivage_ids.std" ]] || die "$bin/archivage_ids.std introuvable."
    sauvegarder "$bin/archivage_ids"
    run cp "$bin/archivage_ids.std" "$bin/archivage_ids"
    run sed -i \
        -e '/^su - informix -c "\/opt\/irium\/manager\/bin\/ids_exportdb\.sh/s/^/#/' \
        -e 's|^\s*/opt/irium/manager/bin/archivage cron|#&|' \
        "$bin/archivage_ids"
    ok "Dump et archivage cron commentés dans $bin/archivage_ids :"
    grep -nE 'ids_exportdb|archivage cron' "$bin/archivage_ids" 2>/dev/null || true

    run touch /var/log/backup_ids.log
    run chmod 666 /var/log/backup_ids.log
    ok "/var/log/backup_ids.log prêt."
}

# --------------------------------------------------------------------------------------------
etape_services() {
    local f
    for f in "$IRIUM_DIR"/gas/appdata/session/fastcgidispatch/{session.owner,cmdline_options}; do
        if [[ -e "$f" ]]; then run chmod 777 "$f"; else warn "$f absent."; fi
    done
    if systemctl cat gas >/dev/null 2>&1; then
        run systemctl restart gas
        ok "Service gas redémarré."
    else
        warn "Service gas absent."
    fi
    if compte_existe strs; then
        log "Compte strs déjà présent."
    else
        run useradd -g informix -d "$IRIUM_DIR/strs/" -M strs
        ok "Compte strs créé."
    fi
}

# --------------------------------------------------------------------------------------------
choisir_edition() {
    local e=${INFORMIX_EDITION,,}
    while [[ ! "$e" =~ ^(1|2|3|express|workgroup|enterprise)$ ]]; do
        (( NON_INTERACTIF )) && die "INFORMIX_EDITION doit être renseigné en mode --oui." 3
        printf '  Édition Informix à installer :\n    1 - Express\n    2 - Workgroup\n    3 - Enterprise\n' >/dev/tty
        read -r -p "  Choix : " e </dev/tty
    done
    case "$e" in
        1|express)    EDITION_NOM=EXPRESS;    EDITION_ZIP="INF-ExpEd_License_Installv14.10.zip";    EDITION_INNER="ibm.editionInstaller.e.*.ALL.zip" ;;
        2|workgroup)  EDITION_NOM=WORKGROUP;  EDITION_ZIP="INF_WrkgrpEd_License_Install.zip";       EDITION_INNER="ibm.editionInstaller.we.*.ALL.zip" ;;
        3|enterprise) EDITION_NOM=ENTERPRISE; EDITION_ZIP="INF_EtprsEd_License_Install14.10.zip";   EDITION_INNER="ibm.editionInstaller.ee.*.ALL.zip" ;;
    esac
    log "Édition retenue : $EDITION_NOM"
}

etape_informix_install() {
    if [[ -x "$INFORMIX_DIR/bin/oninit" ]] && (( ! FORCER )); then
        warn "Informix déjà installé dans $INFORMIX_DIR (utiliser --forcer pour réinstaller)."
        return 0
    fi
    choisir_edition

    log "Dépendances système..."
    run dnf install -y "$PAQUET_IMAGICK" || warn "$PAQUET_IMAGICK non installé."
    if command -v subscription-manager >/dev/null 2>&1; then
        run subscription-manager repos --enable "$DEPOT_CRB" || warn "Dépôt $DEPOT_CRB non activé."
    fi
    run dnf install -y ncurses-compat-libs libaio libstdc++ java-11-openjdk

    # Archive de l'installeur : copie locale sinon téléchargement
    local archive_nom=Informix_fc13_Irium_Installer.tgz archive
    archive="$SOURCES_DIR/$archive_nom"
    if [[ -s "$archive" ]]; then
        ok "Installeur Informix présent : $archive"
    else
        log "Installeur absent de $SOURCES_DIR : téléchargement depuis le portail ECW."
        run mkdir -p "$SOURCES_DIR"
        telecharger "$URL_INFORMIX" "$archive" || die "Téléchargement de l'installeur Informix impossible."
    fi
    run mkdir -p "$INFORMIX_EXTRACT_DIR"
    run tar -xf "$archive" -C "$INFORMIX_EXTRACT_DIR"
    ok "Installeur décompressé dans $INFORMIX_EXTRACT_DIR"

    local fc13="$INFORMIX_EXTRACT_DIR/Informix_fc13_Irium_Installer/fc13" f
    for f in INF_SE-DevEdv14.10.FC13_LINx86.tar ibm.csdk.4.50.13.Linux.64.x86_64.tar \
             "$EDITION_ZIP" irium_ids.properties irium_csdk.properties; do
        (( SIMULATION )) || [[ -f "$fc13/$f" ]] || die "Fichier manquant : $fc13/$f"
    done
    ok "Fichiers sources Informix vérifiés."

    # L'installeur IBM exige Java 11 ; Java 8 est rétabli à la fin (ou en cas d'erreur).
    local java11=(/usr/lib/jvm/java-11-openjdk*/bin/java)
    if [[ -x "${java11[0]}" ]]; then
        JAVA_A_RESTAURER=1
        run alternatives --set java "$(readlink -f "${java11[0]}")"
        log "Java 11 activé temporairement pour l'installeur."
    else
        warn "Java 11 introuvable pour alternatives."
    fi

    local work
    work="$(tmp_dir)/ids_install"
    mkdir -p "$work"                       # dossier temporaire, créé même en simulation
    (
        cd "$work"
        log "Extraction du serveur IDS FC13..."
        run tar -xf "$fc13/INF_SE-DevEdv14.10.FC13_LINx86.tar"
        run tar -xf ibm.server.14.10.13.Linux.64.x86_64.tar
        log "Extraction du Client SDK FC13..."
        run tar -xf "$fc13/ibm.csdk.4.50.13.Linux.64.x86_64.tar"
        local csdk
        csdk=$(find . -maxdepth 2 -name 'ibm.csdk.*.Linux.*.tar' | head -1)
        if [[ -n "$csdk" ]]; then run tar -xf "$csdk"; fi
        log "Extraction de la licence $EDITION_NOM..."
        run unzip -oq "$fc13/$EDITION_ZIP"
        # shellcheck disable=SC2086
        run unzip -oq $EDITION_INNER
        (( SIMULATION )) || compgen -G '*_edition.jar' >/dev/null || die "Aucun fichier *_edition.jar trouvé."

        log "Installation Informix IDS $EDITION_NOM (silencieuse, plusieurs minutes)..."
        run ./ids_install -f "$fc13/irium_ids.properties" -i silent || warn "ids_install : code retour $?"
        log "Installation du Client SDK..."
        run ./installclientsdk -f "$fc13/irium_csdk.properties" -i silent || warn "installclientsdk : code retour $?"
    )
    run rm -rf "$work"

    (( SIMULATION )) || [[ -x "$INFORMIX_DIR/bin/oninit" ]] || die "Installation Informix incomplète : $INFORMIX_DIR/bin/oninit absent."
    "$INFORMIX_DIR/bin/onstat" -V 2>/dev/null || true

    if [[ -x "$JAVA8_PATH" ]]; then
        run alternatives --set java "$JAVA8_PATH"
        JAVA_A_RESTAURER=0
        log "Java 8 rétabli par défaut."
    fi
    ok "Installation Informix terminée."
}

# --------------------------------------------------------------------------------------------
onconfig_set() {
    local fichier=$1 cle=$2 valeur=$3
    if grep -qE "^${cle}([[:space:]]|$)" "$fichier"; then
        sed -i -E "s|^${cle}([[:space:]].*)?$|${cle} ${valeur}|" "$fichier"
    else
        printf '%s %s\n' "$cle" "$valeur" >>"$fichier"
    fi
}

configurer_onconfig() {
    local srv=$1 fichier="$INFORMIX_DIR/etc/onconfig.$1" aliases
    aliases="${srv}_loc, ${srv}_net"
    [[ -n "$OLDSRV_NAME" ]] && aliases+=", ol_${OLDSRV_NAME}_net"

    if (( SIMULATION )); then log "[SIMU] configuration de $fichier (alias : $aliases)"; return 0; fi
    sauvegarder "$fichier"
    install -m 0660 -o informix -g informix "$INFORMIX_DIR/etc/onconfig.std" "$fichier"

    local -a params=(
        "LTAPESIZE|104857600"            "ROOTPATH|$IRIUM_DIR/data/$srv/rootdbs"
        "SBSPACENAME|sbspadbs"           "MULTIPROCESSOR|1"
        "CLEANERS|10"                    "LOCKS|2000000"
        "SHMBASE|0x44000000L"            "SHMVIRTSIZE|2048000"
        "SHMADD|204800"                  "EXTSHMADD|204800"
        "SHMTOTAL|0"                     "DD_HASHSIZE|631"
        "STMT_CACHE|10240"               "DUMPSHMEM|0"
        "LTAPEDEV|/dev/null"             "BACKUP_FILTER|/bin/gzip"
        "RESTORE_FILTER|/bin/gzip -c -d" "MAX_PDQPRIORITY|0"
        "DBSERVERNAME|$srv"              "DBSERVERALIASES|$aliases"
        "USEOSTIME|1"                    "TAPEBLK|1024"
        "LTAPEBLK|1024"                  "SERVERNUM|17"
        "DIRECT_IO|0x4"                  "TEMPTAB_NOLOG|1"
        "MSG_DATE|1"
    )
    local p
    for p in "${params[@]}"; do onconfig_set "$fichier" "${p%%|*}" "${p#*|}"; done

    sed -i -E "s|^VPCLASS[[:space:]]+cpu.*|VPCLASS cpu,num=${INFORMIX_CPU_VPS}|" "$fichier"
    sed -i -E "s|^BUFFERPOOL[[:space:]]+size=2k.*|BUFFERPOOL size=2k,buffers=2000000,lrus=128,lru_min_dirty=50,lru_max_dirty=60|" "$fichier"
    # Une seule paire NETTYPE (le modèle peut en contenir plusieurs)
    awk '/^NETTYPE[[:space:]]/ { if (!n++) { print "NETTYPE ipcshm,6,150,CPU"; print "NETTYPE soctcp,6,150,NET" } next } { print }' \
        "$fichier" >"$fichier.tmp" && cat "$fichier.tmp" >"$fichier" && rm -f "$fichier.tmp"

    ok "onconfig.$srv configuré :"
    grep -E '^(DBSERVERNAME|DBSERVERALIASES|ROOTPATH|VPCLASS cpu|NETTYPE|BUFFERPOOL size=2k)' "$fichier"
}

etape_informix_config() {
    local srv data
    srv=$(nom_instance_informix)
    data="/data/$srv"
    (( SIMULATION )) || [[ -x "$INFORMIX_DIR/bin/oninit" ]] || die "Informix n'est pas installé dans $INFORMIX_DIR."
    log "Instance : $srv"

    # Dossier des chunks : jamais d'effacement d'une instance existante sans confirmation
    if [[ -s "$data/rootdbs" ]]; then
        warn "Des chunks non vides existent dans $data : une instance semble déjà initialisée."
        confirmer "Écraser la configuration ($data sera conservé, chunks non tronqués) ?" || die "Configuration Informix annulée."
    fi
    run install -d -m 0755 -o informix -g informix "$IRIUM_DIR/data" "$data"
    if [[ -L "$IRIUM_DIR/data/$srv" || ! -e "$IRIUM_DIR/data/$srv" ]]; then
        run ln -sfn "$data" "$IRIUM_DIR/data/$srv"
    else
        die "$IRIUM_DIR/data/$srv existe et n'est pas un lien : à vérifier manuellement."
    fi

    local chunk
    for chunk in rootdbs sbspadbs llogdbs1 plogdbs1 datadbs{1..11} testdbs{1..7} tempdbs{1..4} tempdbs{a..d}; do
        [[ -e "$data/$chunk" ]] || run install -m 0660 -o informix -g informix /dev/null "$data/$chunk"
    done
    ok "Chunks présents dans $data."

    run touch "/backup/$srv.ids"
    run chown -R regix:informix /backup
    run chmod 660 "/backup/$srv.ids"

    [[ -e "/var/log/$srv.log" ]] || run install -m 0640 -o informix -g informix /dev/null "/var/log/$srv.log"
    run ln -sfn "/var/log/$srv.log" "$INFORMIX_DIR/$srv.log"

    local modele
    for modele in "informix:/etc/sysconfig/informix" "param_ids:$IRIUM_DIR/manager/lib/param_ids"; do
        local src="$SOURCES_DIR/${modele%%:*}" dst="${modele#*:}"
        [[ -f "$src" ]] || die "Modèle introuvable : $src"
        sed "s/ol_servername/$srv/g" "$src" | ecrire_fichier "$dst" 0644 auto
        ok "$dst généré."
    done

    ecrire_fichier "$INFORMIX_DIR/.bash_profile" 0644 informix:informix <<EOF
# .bash_profile (généré par $SCRIPT_NAME)
[ -f ~/.bashrc ] && . ~/.bashrc

INFORMIXDIR=$INFORMIX_DIR
INFORMIXSERVER=$srv
ONCONFIG=onconfig.\${INFORMIXSERVER}
INFORMIXSQLHOSTS=\${INFORMIXDIR}/etc/sqlhosts.\${INFORMIXSERVER}
LD_LIBRARY_PATH=\${INFORMIXDIR}/lib:\${INFORMIXDIR}/lib/esql
PATH=\${INFORMIXDIR}/bin:\${INFORMIXDIR}/extend/krakatoa/jre/bin:\${PATH}
export INFORMIXDIR INFORMIXSERVER ONCONFIG INFORMIXSQLHOSTS PATH LD_LIBRARY_PATH
cd \$INFORMIXDIR

TERMCAP=/etc/termcap.regie
DBDATE=DMY4/
DBDELIMITER=\|
DBMONEY=" ."
export TERMCAP DBDATE DBDELIMITER DBMONEY
EOF

    configurer_onconfig "$srv"

    local hote; hote=$(hostname)
    {
        cat "$INFORMIX_DIR/etc/sqlhosts.std" 2>/dev/null || true
        printf '%-24s %-10s %-24s %s\n' "${srv}_loc" onipcshm "$hote" sqlexec "$srv" onipcshm "$hote" sqlexec \
            "${srv}_net" onsoctcp "$hote" sqlexec
        [[ -z "$OLDSRV_NAME" ]] || printf '%-24s %-10s %-24s %s\n' "ol_${OLDSRV_NAME}_net" onsoctcp "$hote" sqlexec
    } | ecrire_fichier "$INFORMIX_DIR/etc/sqlhosts.$srv" 0644 informix:informix
    ok "sqlhosts.$srv généré."

    local d="$IRIUM_DIR/data/$srv"
    ecrire_fichier "$INFORMIX_DIR/etc/sysadmin/sch_init_$srv.sql" 0644 informix:informix <<EOF
DATABASE sysadmin;

EXECUTE FUNCTION task("create dbspace", "physdbs", "$d/plogdbs1", 1024000, 0);
EXECUTE FUNCTION task("create dbspace", "logdbs", "$d/llogdbs1", 10240000, 0);
EXECUTE FUNCTION task("create dbspace", "datadbs", "$d/datadbs1", 10240000, 0);
EXECUTE FUNCTION task("add chunk", "datadbs", "$d/datadbs2", 10240000, 0);
EXECUTE FUNCTION task("create dbspace", "testdbs", "$d/testdbs1", 10240000, 0);
EXECUTE FUNCTION task("add chunk", "testdbs", "$d/testdbs2", 10240000, 0);
EXECUTE FUNCTION task("create tempdbspace", "tempdbs1", "$d/tempdbs1", 5120000, 0);
EXECUTE FUNCTION task("create tempdbspace", "tempdbs2", "$d/tempdbs2", 5120000, 0);
EXECUTE FUNCTION task("create tempdbspace", "tempdbs3", "$d/tempdbs3", 5120000, 0);
EXECUTE FUNCTION task("create tempdbspace", "tempdbs4", "$d/tempdbs4", 5120000, 0);
EXECUTE FUNCTION task("create sbspace", "sbspadbs", "$d/sbspadbs", 5120000, 0);

CLOSE DATABASE;
DATABASE sysadmin;

EXECUTE FUNCTION task("alter plog", "physdbs", "768000");
EXECUTE FUNCTION task("add log", "logdbs", "51200", "203");
$(for _ in 1 2 3 4 5 6; do echo 'EXECUTE FUNCTION task("onmode", "l");'; done)
EXECUTE FUNCTION task("onmode", "c");
$(for n in 1 2 3 4 5 6; do echo "EXECUTE FUNCTION task(\"drop log\", \"$n\");"; done)

CLOSE DATABASE;
DATABASE sysadmin;

EXECUTE FUNCTION task("set onconfig permanent", "DBSPACETEMP", "tempdbs1,tempdbs2,tempdbs3,tempdbs4");
EXECUTE FUNCTION task("set onconfig permanent", "DEF_TABLE_LOCKMODE", "row");
EXECUTE FUNCTION task("set onconfig permanent", "RESIDENT", "-1");
EXECUTE FUNCTION task("set onconfig permanent", "TAPEDEV", "$IRIUM_DIR/backup/$srv.ids");
EXECUTE FUNCTION task("set onconfig permanent", "STACKSIZE", "128");

UPDATE ph_task SET tk_enable = 'f' WHERE tk_name = "mon_compression_estimates";
CLOSE DATABASE;
EOF
    ok "Script d'initialisation sch_init_$srv.sql généré."
}

# --------------------------------------------------------------------------------------------
informix_etat() { su - informix -c 'onstat -' 2>/dev/null || true; }

attendre() {
    local delai=$1; shift
    local debut=$SECONDS
    until "$@"; do
        (( SECONDS - debut < delai )) || return 1
        printf '.'
        sleep 10
    done
    echo
}

informix_online()   { [[ "$(informix_etat)" == *On-Line* ]]; }
dbspaces_crees() {
    local sortie n
    sortie=$(su - informix -c 'onstat -d' 2>/dev/null) || return 1
    for n in physdbs logdbs datadbs testdbs tempdbs1 tempdbs2 tempdbs3 tempdbs4 sbspadbs; do
        grep -qw "$n" <<<"$sortie" || return 1
    done
}

etape_informix_init() {
    local srv; srv=$(nom_instance_informix)
    if (( ! SIMULATION )) && informix_online; then
        warn "L'instance $srv est déjà en ligne : initialisation ignorée (elle effacerait les données)."
    else
        warn "oninit -i initialise l'instance $srv : tout contenu des chunks sera PERDU."
        confirmer "Lancer l'initialisation d'Informix ?" || { warn "Initialisation reportée."; return 0; }
        run_as informix "oninit -iyv"
        if (( ! SIMULATION )); then
            log "Attente du passage en ligne (max ${INFORMIX_TIMEOUT}s)"
            attendre "$INFORMIX_TIMEOUT" informix_online || die "L'instance n'est pas passée On-Line (voir $INFORMIX_DIR/$srv.log)."
            ok "Instance $srv en ligne."
            log "Attente de la création des dbspaces par sch_init (max ${INFORMIX_TIMEOUT}s)"
            attendre "$INFORMIX_TIMEOUT" dbspaces_crees || warn "Tous les dbspaces ne sont pas encore créés."
            su - informix -c 'onstat -d' || true
            confirmer "Les dbspaces sont-ils corrects (onstat -d ci-dessus) ? Poursuivre ?" || die "Arrêt pour vérification d'onstat -d."
        fi
    fi

    log "Droits et tâches planifiées dans les bases système..."
    if (( SIMULATION )); then log "[SIMU] dbaccess sysadmin / sysmaster"; return 0; fi
    su - informix -c 'dbaccess sysadmin -' <<'SQL'
GRANT CONNECT TO PUBLIC;

-- auto_crsd : compression, compactage et défragmentation chaque jour à 02:00
UPDATE ph_task
   SET tk_enable = 't', tk_start_time = '02:00:00', tk_frequency = '1 00:00:00',
       tk_monday = 't', tk_tuesday = 't', tk_wednesday = 't', tk_thursday = 't',
       tk_friday = 't', tk_saturday = 't', tk_sunday = 't'
 WHERE tk_name = 'auto_crsd' AND tk_enable = 'f';

UPDATE ph_threshold SET value = 'T' WHERE task_name = 'auto_crsd' AND name = 'AUTOREPACK_ENABLED';
UPDATE ph_threshold SET value = 10  WHERE task_name = 'auto_crsd' AND name = 'AUTOREPACK_SPACE';
UPDATE ph_threshold SET value = 'T' WHERE task_name = 'auto_crsd' AND name = 'AUTOSHRINK_ENABLED';
UPDATE ph_threshold SET value = 10  WHERE task_name = 'auto_crsd' AND name = 'AUTOSHRINK_UNUSED';
UPDATE ph_threshold SET value = 'T' WHERE task_name = 'auto_crsd' AND name = 'AUTODEFRAG_ENABLED';
UPDATE ph_threshold SET value = 10  WHERE task_name = 'auto_crsd' AND name = 'AUTODEFRAG_EXTENTS';
SQL
    su - informix -c 'dbaccess sysmaster -' <<'SQL'
GRANT SELECT ON syssltdat TO PUBLIC;
GRANT SELECT ON syssqlcurall TO PUBLIC;
SQL
    ok "Paramétrage Informix terminé."
}

# --------------------------------------------------------------------------------------------
etape_dump() {
    decider "$LANCER_DUMP" "Lancer le dump Informix (backup.cde) ?" || { warn "Dump Informix ignoré."; return 0; }
    run_as informix "$IRIUM_DIR/manager/bin/backup.cde"
    if [[ -f /backup/status_ontape.log ]]; then
        ok "État du dump : $(tr -d '\n' </backup/status_ontape.log)"
    else
        warn "/backup/status_ontape.log absent : vérifier le dump."
    fi
}

# --------------------------------------------------------------------------------------------
etape_v3300() {
    decider "$INSTALLER_V3300" "Installer la v3300 dans $V3300_DIR ?" || { warn "Installation v3300 ignorée."; return 0; }
    if [[ -s "$V3300_BINAIRE" ]]; then
        ok "$V3300_BINAIRE présent localement."
    else
        telecharger "$URL_V3300" "$V3300_BINAIRE" || die "Téléchargement de $V3300_BINAIRE impossible."
    fi
    run chmod 774 "$V3300_BINAIRE"
    run chown regix:informix "$V3300_BINAIRE"
    run_as regix "cd $(dirname "$V3300_BINAIRE") && INSTALLDIR=$V3300_DIR bash ./$(basename "$V3300_BINAIRE") -a -t $V3300_DIR -q -f remove"
    if compgen -G '/tmp/i80.*.tgz' >/dev/null; then
        run rm -f /tmp/i80.*.tgz
        log "Archives temporaires i80 supprimées de /tmp."
    fi
    ok "v3300 installée dans $V3300_DIR."
}

# --------------------------------------------------------------------------------------------
etape_migration() {
    local ip cle ancien="$SORTIE_DIR/a_lancer_sur_ancien_serveur.sh" nouveau="$SORTIE_DIR/a_lancer_sur_nouveau_serveur.sh"
    ip=$(ip_serveur)
    if [[ -r /root/.ssh/id_rsa.pub ]]; then
        cle=$(</root/.ssh/id_rsa.pub)
    elif (( SIMULATION )); then
        cle="CLE_PUBLIQUE_ROOT"
    else
        die "/root/.ssh/id_rsa.pub absente : lancer d'abord l'étape ssh (--etapes ssh)."
    fi
    run install -d -m 0700 "$SORTIE_DIR"

    ecrire_fichier "$ancien" 0700 root:root <<EOF
#!/bin/bash
# À lancer en root sur l'ANCIEN serveur : autorise le nouveau serveur ($ip) à se connecter en root par clé.
set -euo pipefail
install -d -m 700 /root/.ssh
touch /root/.ssh/authorized_keys /root/.ssh/config
chmod 600 /root/.ssh/authorized_keys /root/.ssh/config
grep -qxF '$cle' /root/.ssh/authorized_keys || echo '$cle' >> /root/.ssh/authorized_keys
grep -qE '^Host[[:space:]]+newsrv\$' /root/.ssh/config || printf '\nHost newsrv\n    HostName %s\n    User root\n    IdentityFile ~/.ssh/id_rsa\n' '$ip' >> /root/.ssh/config
cp -a /etc/ssh/sshd_config /etc/ssh/sshd_config.avant_ie_\$(date +%Y%m%d_%H%M%S)
sed -i 's/^[[:space:]]*#\\?[[:space:]]*PermitRootLogin[[:space:]].*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
sshd -t && systemctl reload sshd
sshd -T | grep -E 'pubkeyauthentication|authorizedkeysfile|permitrootlogin'
echo "Clé publique de l'ancien serveur (à ajouter sur le nouveau si nécessaire) :"
cat /root/.ssh/id_rsa.pub 2>/dev/null || true
EOF

    ecrire_fichier "$nouveau" 0700 root:root <<EOF
#!/bin/bash
# À lancer en root sur le NOUVEAU serveur, une fois l'accès SSH vers « oldsrv » validé.
set -euo pipefail
ssh -o BatchMode=yes oldsrv true
rsync -avH oldsrv:$IRIUM_DIR/fglgws/bin/newlicence $IRIUM_DIR/fglgws/bin/newlicence
sh $IRIUM_DIR/fglgws/bin/newlicence
rsync -aH oldsrv:/users/ /users/ > $LOG_DIR/rsync_users.log 2>&1 &
rsync -aH oldsrv:/msdos/ /msdos/ > $LOG_DIR/rsync_msdos.log 2>&1 &
wait
echo "Synchronisation terminée (journaux : $LOG_DIR/rsync_*.log)."
EOF

    section "Préparation de la migration"
    log "1. Copier et lancer sur l'ancien serveur ($OLDSRV_IP) : $ancien"
    log "2. Puis lancer sur ce serveur                         : $nouveau"
    log "scripto : $IRIUM_DIR/manager/bin/scripto (alias « scripto » pour root)"
}

# =============================================================================================
#  Orchestration
# =============================================================================================
etape_faite()    { [[ -f "$ETAT_DIR/$1.ok" ]]; }
marquer_faite()  { (( SIMULATION )) || date '+%F %T' >"$ETAT_DIR/$1.ok"; }

etape_connue() {
    local e
    for e in "${ETAPES[@]}"; do [[ "$e" == "$1" ]] && return 0; done
    return 1
}

lister_etapes() {
    local e i=1 etat
    printf '%-4s %-18s %-8s %s\n' "N°" "ÉTAPE" "ÉTAT" "DESCRIPTION"
    for e in "${ETAPES[@]}"; do
        if etape_faite "$e"; then etat="faite"; else etat="-"; fi
        printf '%-4s %-18s %-8s %s\n' "$i" "$e" "$etat" "${DESC_ETAPE[$e]}"
        i=$((i + 1))
    done
}

# Calcule la liste des étapes à exécuter (ETAPES_A_LANCER) selon --etapes / --depuis.
selection_etapes() {
    local -a choix=() ; local e actif=0
    if [[ -n "$ETAPES_DEMANDEES" ]]; then
        IFS=',' read -r -a choix <<<"$ETAPES_DEMANDEES"
        for e in "${choix[@]}"; do etape_connue "$e" || die "Étape inconnue : $e (voir --liste)." 2; done
    elif [[ -n "$ETAPE_DEPART" ]]; then
        etape_connue "$ETAPE_DEPART" || die "Étape inconnue : $ETAPE_DEPART (voir --liste)." 2
        for e in "${ETAPES[@]}"; do
            [[ "$e" == "$ETAPE_DEPART" ]] && actif=1
            (( actif )) && choix+=("$e")
        done
    else
        choix=("${ETAPES[@]}")
    fi
    ETAPES_A_LANCER=("${choix[@]}")
}

executer_etape() {
    local e=$1
    if [[ "$e" != "controles" ]] && etape_faite "$e" && (( ! FORCER )) && [[ -z "$ETAPES_DEMANDEES" ]]; then
        log "Étape « $e » déjà réalisée le $(cat "$ETAT_DIR/$e.ok") : ignorée (--forcer pour la rejouer)."
        ETAPES_IGNOREES+=("$e")
        return 0
    fi
    ETAPE_COURANTE=$e
    section "Étape « $e » : ${DESC_ETAPE[$e]}"
    "etape_$e"
    marquer_faite "$e"
    ETAPES_FAITES+=("$e")
    ok "Étape « $e » terminée."
}

usage() {
    cat <<EOF
$SCRIPT_NAME v$SCRIPT_VERSION : préparation automatique d'un serveur iE / IRIUM (RHEL 9)

Utilisation : sudo ./$SCRIPT_NAME [options]

Options :
  -c, --config FICHIER   Fichier de configuration (défaut : install_ie.conf à côté du script)
  -y, --oui              Mode non interactif : toutes les confirmations sont acceptées
                         (l'effacement d'un disque exige en plus EFFACER_SIGNATURES=oui)
  -n, --simulation       Affiche les actions sans rien modifier (dry-run)
  -e, --etapes LISTE     N'exécute que ces étapes, séparées par des virgules (ex : ssh,comptes)
  -d, --depuis ETAPE     Reprend à partir de cette étape
  -f, --forcer           Rejoue les étapes déjà marquées comme faites
  -l, --liste            Liste les étapes et leur état, puis quitte
  -v, --verbeux          Trace détaillée (set -x) dans le journal
  -h, --aide             Affiche cette aide
      --version          Affiche la version

Exemples :
  sudo ./$SCRIPT_NAME                          # installation complète, interactive
  sudo ./$SCRIPT_NAME --simulation             # voir ce qui serait fait
  sudo ./$SCRIPT_NAME --depuis informix_config # reprise après correction
  sudo ./$SCRIPT_NAME --etapes dump,v3300 -y   # étapes ciblées, sans question

Journaux : $LOG_DIR      État des étapes : $ETAT_DIR
EOF
}

lire_options() {
    while (( $# )); do
        case "$1" in
            -c|--config)     [[ $# -ge 2 ]] || die "$1 attend un fichier." 2; CONFIG_FILE=$2; shift ;;
            -y|--oui|--yes)  NON_INTERACTIF=1 ;;
            -n|--simulation|--dry-run) SIMULATION=1 ;;
            -e|--etapes)     [[ $# -ge 2 ]] || die "$1 attend une liste." 2; ETAPES_DEMANDEES=$2; shift ;;
            -d|--depuis)     [[ $# -ge 2 ]] || die "$1 attend une étape." 2; ETAPE_DEPART=$2; shift ;;
            -f|--forcer)     FORCER=1 ;;
            -l|--liste)      lister_etapes; exit 0 ;;
            -v|--verbeux)    VERBEUX=1 ;;
            -h|--aide|--help) usage; exit 0 ;;
            --version)       echo "$SCRIPT_VERSION"; exit 0 ;;
            *)               erreur "Option inconnue : $1"; usage >&2; exit 2 ;;
        esac
        shift
    done
    [[ -z "$ETAPES_DEMANDEES" || -z "$ETAPE_DEPART" ]] || die "--etapes et --depuis sont incompatibles." 2
}

charger_configuration() {
    if [[ -f "$CONFIG_FILE" ]]; then
        local droits
        droits=$(stat -c '%a' "$CONFIG_FILE")
        [[ "$droits" =~ ^[0-7]00$ ]] || warn "$CONFIG_FILE est lisible par d'autres comptes (droits $droits) : chmod 600 conseillé."
        # shellcheck disable=SC1090
        . "$CONFIG_FILE"
        log "Configuration chargée : $CONFIG_FILE"
    else
        (( NON_INTERACTIF )) && die "Configuration introuvable : $CONFIG_FILE (cp install_ie.conf.exemple install_ie.conf)." 3
        warn "Pas de fichier $CONFIG_FILE : valeurs par défaut, à valider ou modifier ci-dessous."
    fi
}

main() {
    lire_options "$@"
    [[ $EUID -eq 0 ]] || die "Ce script doit être exécuté en root (sudo ./$SCRIPT_NAME)." 3

    install -d -m 0700 "$LOG_DIR" "$ETAT_DIR"
    ( umask 077; : >"$LOG_FILE" )
    exec > >(tee -a "$LOG_FILE") 2>&1

    trap 'on_err $? $LINENO "$BASH_COMMAND"' ERR
    trap nettoyage EXIT
    trap interruption INT TERM
    prendre_verrou

    banniere
    log "Lancement : $0 $*  (pid $$, journal $LOG_FILE)"
    (( SIMULATION )) && warn "MODE SIMULATION : aucune modification ne sera faite."
    (( VERBEUX )) && set -x

    charger_configuration
    valider_parametres || die "Paramètres invalides dans $CONFIG_FILE." 2
    afficher_parametres

    if (( ! NON_INTERACTIF )); then
        local rep
        while true; do
            read -r -p "Utiliser ces paramètres ? (o : continuer / n : les modifier / s : arrêt) " rep </dev/tty
            case "${rep,,}" in
                o|oui|y|yes) break ;;
                n|non|no)    saisir_parametres; break ;;
                s|q|stop)    log "Arrêt demandé."; exit 0 ;;
                *)           warn "Réponse invalide." ;;
            esac
        done
    fi

    selection_etapes
    local e
    for e in "${ETAPES_A_LANCER[@]}"; do
        executer_etape "$e"
    done
    ETAPE_COURANTE="fin"

    section "Récapitulatif"
    if [[ -f "$CREDENTIALS_FILE" ]]; then
        log "Identifiants des comptes : $CREDENTIALS_FILE (600)"
        if (( ! NON_INTERACTIF )) && [[ -w /dev/tty ]] && confirmer "Afficher les identifiants à l'écran (non journalisés) pour LockSelf ?"; then
            cat "$CREDENTIALS_FILE" >/dev/tty
        fi
    fi
    warn "À faire : saisir les identifiants dans LockSelf puis supprimer $CREDENTIALS_FILE (shred -u)."
    warn "Le fichier $CONFIG_FILE contient des secrets : le supprimer ou le protéger après l'installation."
}

# Le script peut être « sourcé » par les tests sans rien exécuter.
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
