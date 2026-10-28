# auto_install_iE : préparation automatique d'un serveur iE / IRIUM

Script d'installation d'un nouveau serveur **iE / IRIUM sous RHEL 9**. Il prépare :
- le stockage (disques LVM) ;
- les comptes ;
- Genero et ses licences ;
- Informix 14.10 FC13 ;
- la version i80 v3300 ;
- la migration depuis l'ancien serveur.

Il s'agit de la refonte (v6) du script `Installation_serveur_iE_auto_HIS_v5` d'Hicham SLIMANI. Les opérations métier sont les mêmes, mais le script est maintenant découpé en étapes, configurable, rejouable et journalisé.

| Fichier | Rôle |
|---|---|
| `install_ie.sh` | **Script tout-en-un**, le seul fichier à déposer sur le serveur (Bash, à lancer en root) |
| `install_ie.conf.exemple` | Modèle de configuration, facultatif (les paramètres peuvent aussi être modifiés en tête du script) |
| `tests/test_install_ie.sh` | Tests : analyse statique, fonctions de validation, simulation complète, parcours interactif |

## Utilisation

**1. Déposer le script sur le serveur.** Utilisez WinSCP, ou `scp` depuis votre poste :

```bash
scp install_ie.sh admin@nouveau-serveur:/root/
```

Si le fichier a été ouvert ou modifié sous Windows, retirez les fins de ligne Windows :

```bash
sed -i 's/\r$//' /root/install_ie.sh
```

**2. Renseigner les paramètres.** Trois possibilités, au choix :
- modifier le bloc `PARAMÈTRES` en tête de `install_ie.sh` (disque, VG, tailles, IP de l'ancien serveur…) ;
- ou créer un `install_ie.conf` à côté du script, à partir de `install_ie.conf.exemple` ;
- ou ne rien préparer : les valeurs sont affichées au lancement, et `n` permet de les saisir.

**3. Vérifier, puis lancer :**

```bash
sudo ./install_ie.sh --simulation
```

```bash
sudo ./install_ie.sh
```

`--simulation` affiche toutes les actions **sans rien modifier**.

Au lancement réel, **toutes les questions sont posées au début** :
- validation des paramètres ;
- édition Informix ;
- dump et v3300 ;
- volume dédié à `/var/log` ;
- effacement éventuel du disque ;
- secrets ECW et licence Genero, en saisie masquée.

Le script affiche ensuite le déroulement prévu et demande **une seule confirmation**. À partir de là, l'installation se déroule **sans aucune intervention** jusqu'à la fin. Seul l'affichage des identifiants, tout à la fin, est proposé.

Pour un lancement sans aucune question, mettez toutes les valeurs, secrets compris, dans `install_ie.conf`, puis :

```bash
sudo ./install_ie.sh --oui
```

## Prérequis

- RHEL 9 issu de l'**image IRIUM**, qui fournit déjà :
  - les comptes `regix`, `informix`, `compta`, `manager` et `genero` ;
  - le dossier `/opt/irium/manager` ;
  - Samba et le service `gas`.
- Dans `/home/irium` (`SOURCES_DIR`) :
  - `genero-3.20.13-64.tgz` (ou `genero-2.50_26-64.tgz`) ;
  - `jre-8u201-linux-x64.rpm` ;
  - les modèles `informix` et `param_ids` ;
  - éventuellement `Informix_fc13_Irium_Installer.tgz`. S'il est absent, il est téléchargé depuis le portail ECW.
- Un disque vide dédié aux données (par défaut `/dev/sdb`).
- Un accès au portail ECW IRIUM et à `4js.com:443` pour les licences. Sans accès, les licences s'activeront plus tard avec les scripts `newlicence` générés.

## Options

| Option | Effet |
|---|---|
| `-c, --config FICHIER` | Autre fichier de configuration |
| `-y, --oui` | Mode non interactif : toutes les confirmations sont acceptées |
| `-n, --simulation` | Affiche les commandes sans les exécuter (dry-run) |
| `-e, --etapes a,b` | N'exécute que ces étapes |
| `-d, --depuis ETAPE` | Reprend à partir de cette étape |
| `-f, --forcer` | Rejoue les étapes déjà faites |
| `-l, --liste` | Liste les étapes et leur état |
| `-v, --verbeux` | Trace détaillée (`set -x`) dans le journal |
| `-h, --aide` / `--version` | Aide / version |

En mode `--oui`, l'effacement d'un disque qui porte des signatures exige en plus `EFFACER_SIGNATURES="oui"` dans la configuration.

## Étapes

| Étape | Contenu |
|---|---|
| `controles` | root, version de l'OS, commandes, comptes de l'image, sources, accès SSH à l'ancien serveur |
| `disques` | partition GPT ou disque entier, PV, VG, LV `datalv`/`msdoslv`/`backuplv` ; contrôle de l'espace libre du VG, XFS, `/etc/fstab` (sauvegardé), montage |
| `dossiers` | `/users`, `/users/i80`, `/backup/import`, `/msdos`, lien `/opt/irium/backup` vers `/backup`, droits |
| `varlog` | LV dédié à `/var/log` s'il n'est pas déjà monté (copie avec droits et SELinux, ancien contenu libéré) |
| `ssh` | clés ed25519 et RSA de root (conservées si elles existent), alias `oldsrv` |
| `comptes` | `msdos`, `supie`, `cslie` ; mots de passe aléatoires ; Samba ; home de `manager` |
| `systeme` | `/etc/hosts`, `expect`, couleur du prompt |
| `scripto` | téléchargement de `scripto` et alias |
| `genero` | Genero 2 ou 3, Java 8, scripts de licence fgl et flm, tâche cron |
| `archivage` | `archivage_ids` (dump commenté), `/var/log/backup_ids.log` |
| `services` | droits des sessions GAS, redémarrage de `gas`, compte `strs` |
| `informix_install` | dépendances, Java 11 temporaire, IDS 14.10 FC13 et Client SDK (installation silencieuse) |
| `informix_config` | chunks, `onconfig`, `sqlhosts`, `.bash_profile`, `sch_init_<instance>.sql`, `/etc/sysconfig/informix`, `param_ids` |
| `informix_init` | `oninit -iy`, attente de l'état On-Line et des dbspaces, droits et tâches `auto_crsd` |
| `dump` | sauvegarde ontape (`backup.cde`) |
| `v3300` | installation i80 v3300 dans `/users/i80` |
| `migration` | génère `sortie/a_lancer_sur_ancien_serveur.sh` et `sortie/a_lancer_sur_nouveau_serveur.sh` |

Chaque étape réussie est enregistrée dans `.etat/`. Après une erreur, il suffit de **relancer** le script : les étapes déjà faites sont sautées. Pour rejouer une étape précise :

```bash
sudo ./install_ie.sh --etapes informix_config
```

L'instance Informix s'appelle `ol_<nom court du serveur>`, en minuscules et sans tiret (par exemple `SRV-IE01` donne `ol_srvie01`).

## Sécurité

- **Aucun secret dans le script ni dans le dépôt.** Les mots de passe ECW et les licences Genero sont dans `install_ie.conf`, ignoré par git. Le script avertit si ce fichier n'est pas en droits 600.
- **Le mot de passe ECW n'apparaît plus dans `ps`.** Il passe par un `wgetrc` temporaire, supprimé en fin d'exécution.
- **Les mots de passe des comptes ne sont jamais écrits dans le journal.** Ils sont générés aléatoirement (16 caractères, 4 classes) et enregistrés dans `/root/ie_identifiants.txt` (droits 600). En fin d'exécution, le script propose de les afficher à l'écran, hors journal, pour les reporter dans LockSelf. **Supprimer ensuite ce fichier** :

  ```bash
  shred -u /root/ie_identifiants.txt
  ```

- **Garde-fous sur les opérations destructrices :**
  - un disque monté est refusé, et en mode disque entier un disque déjà partitionné aussi ;
  - les signatures ne sont effacées qu'avec confirmation ;
  - `oninit -i` n'est jamais lancé sur une instance en ligne ;
  - les chunks existants ne sont jamais tronqués ;
  - un dossier existant n'est jamais supprimé : il est renommé en `*.avant_ie_<date>`.
- **Un fichier système n'est modifié qu'après sauvegarde** (`fichier.avant_ie_<date>`) : `fstab`, `hosts`, `.ssh/config`, `onconfig`, `archivage_ids`…
- **Une seule exécution à la fois** (verrou `/run/install_ie.lock`).
- **Les droits 777** de `/msdos`, `/users/i80` et des sessions GAS sont repris de la v5 parce que les applications IRIUM en ont besoin. À restreindre si l'éditeur le permet.

## Journaux

| Emplacement | Contenu |
|---|---|
| `logs/install_ie_<date>.log` | Journal complet de chaque exécution (droits 600) |
| `.etat/<etape>.ok` | Date de réussite de chaque étape |
| `sortie/` | Scripts de migration générés |

## Corrections par rapport à la v5

| Problème v5 | Correction |
|---|---|
| Fins de ligne Windows (CRLF) | LF, imposé par `.gitattributes` |
| Mot de passe ECW et clés de licence en clair dans le script | Fichier de configuration local, hors git, ou saisie masquée |
| Mots de passe affichés dans le journal (`cat /root/.msdospwd`, `cat pwd`) | Fichier 600 dédié, affichage hors journal |
| Fichier `pwd` écrit dans le dossier courant mais relu dans `/root/pwd` | Un seul fichier, `CREDENTIALS_FILE` |
| `n)²` dans le `case` de `/var/log` (commande `²` introuvable) | Supprimé |
| `find /var/log \| cpio -pdvm /mnt` recopiait `/mnt/var/log/...` | `cp -a /var/log/.` : contenu au bon endroit |
| VG `vg_00` codé en dur pour `/var/log` | `VARLOG_VG` |
| Fonction `inprogres` inexistante (typo) | Corrigé |
| `wget -O` laissait un fichier vide en cas d'échec, pris pour « présent » au lancement suivant | Téléchargement dans un `.part`, renommé seulement en cas de succès |
| `DBSERVERALIASES` : fichier `:"$INFORMIXDIR/..."` (deux-points en trop), alias `ol_<ancien>_net` jamais écrit | Corrigé |
| `INFORMIXSERVER` issu de `$HOSTNAME` (un FQDN donnait un nom avec des points) | Nom court (`hostname -s`) |
| `fstab`, `/etc/hosts`, `.bashrc`, `.ssh/config` complétés à chaque lancement (doublons), `.ssh/config` écrasé | Ajouts idempotents, avec sauvegarde |
| `rm -rf /opt/irium/data /data/ol_*` sans confirmation | Pas de suppression ; confirmation si une instance existe |
| `ssh-keygen` demandait d'écraser les clés existantes | Clés conservées |
| `/etc/passwd` modifié avec `sed` | `usermod -d` |
| `set -e` activé à mi-script, double `exec tee` | `set -Eeuo pipefail` dès le début, gestion d'erreur avec ligne et commande fautive |
| Test Java 8 toujours vrai (`[ -n "$JAVA8" ]`) | Vérification `-x` ; Java 8 rétabli même si l'installation Informix échoue |
| `sleep 30` puis vérification manuelle d'`onstat -d` | Attente active de l'état On-Line et des dbspaces (délai `INFORMIX_TIMEOUT`) |
| Partition à deviner (`/dev/sdb1`) ; NVMe et virtio non pris en charge | Partition détectée automatiquement, tous types de disques |
| Pas de contrôle de l'espace du VG avant `lvcreate` | Contrôle avant création, minimum 80G pour `datalv` |
| NETTYPE dupliqué si le modèle contenait plusieurs lignes | Une seule paire NETTYPE |

## Tests

```bash
bash tests/test_install_ie.sh
```

Le test vérifie :
- la syntaxe, `shellcheck` et l'absence de CRLF ;
- les fonctions de validation, de génération de mots de passe et de modification de l'onconfig ;
- en root, une **exécution complète en `--simulation`** avec des commandes système factices : toutes les étapes, aucune erreur, aucun secret affiché ;
- le **parcours interactif** dans un vrai terminal : réponses données au début, plus aucune question ensuite.

Il ne modifie pas le système.
