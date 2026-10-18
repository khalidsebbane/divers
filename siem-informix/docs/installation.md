# Installation

## 0. Prérequis

| Élément | Détail |
|---|---|
| Serveur SIEM | VM dédiée et isolée : RHEL 8.8+ / 9 (ou Docker), 2 vCPU, 4 Go de RAM, 50 Go de disque pour environ un an d'événements |
| Flux réseau | postes → SIEM `443/tcp` · SIEM → serveur Informix `22/tcp` · SIEM → contrôleurs AD `636/tcp` · SIEM → SMTP `587/tcp` (facultatif) |
| Active Directory | un compte de service en lecture seule (`svc-siem`), deux groupes : `GG_SIEM_Administrateurs` et `GG_SIEM_Lecteurs`, le certificat de l'autorité interne (PEM) |
| Serveur Informix | accès root pour lancer le script de préparation. Le Python système suffit (`/usr/libexec/platform-python` sur RHEL 8) |
| Certificat du portail | certificat de l'autorité interne pour `siem.<domaine>` (sinon un certificat autosigné est généré) |

## 1. Serveur SIEM isolé

### Option A : installation native RHEL (sans Docker, sans Internet)

Sur un **poste connecté à Internet** (même architecture, Python 3.11 installé ou non) :

```bash
git clone -b claude/blissful-fermi-qhv29b https://github.com/khalidsebbane/divers.git
cd divers/siem-informix
./deploiement/construire-paquet-hors-ligne.sh 3.11      # -> siem-portail-hors-ligne.tar.gz
```

Copier le paquet sur le serveur SIEM, puis en root :

```bash
dnf install -y python3.11 openssh-clients openssl        # depuis le dépôt local / l'ISO RHEL monté
tar xzf siem-portail-hors-ligne.tar.gz && cd siem-portail
./deploiement/installer-portail.sh                       # port 443 par défaut
```

Le script crée :
- le compte `siem` ;
- l'application dans `/opt/siem-portail` et les données dans `/var/lib/siem-portail` ;
- la configuration dans `/etc/siem-portail/portail.env`, préremplie aux couleurs de Tractafric avec le logo ;
- le service durci `siem-portail` et la règle de pare-feu.

Le mot de passe initial du compte de secours `admin.local` s'affiche à la fin. Il est aussi dans `journalctl -u siem-portail`.

### Option B : Docker

```bash
cd siem-informix/portail
cp ../deploiement/tractafric/portail.env.exemple .env && chmod 600 .env
mkdir -p donnees certs marque && cp ../deploiement/tractafric/logo.png marque/
docker compose up -d --build
docker compose logs portail | grep admin.local          # mot de passe initial du compte de secours
```
Sans Internet : `docker save siem-informix-portail:2.0 | gzip > portail.tar.gz` sur un poste connecté, puis `docker load` sur le serveur SIEM.

### Certificat HTTPS

Déposer `cert.pem` (avec la chaîne) et `cle.pem` dans `/etc/siem-portail/certs/` (Docker : `certs/`), puis `systemctl restart siem-portail`.

## 2. Active Directory

Dans `/etc/siem-portail/portail.env` :

```ini
SIEM_AD_SERVEURS=ldaps://dc1.tractafric.local:636,ldaps://dc2.tractafric.local:636
SIEM_AD_BASE_DN=DC=tractafric,DC=local
SIEM_AD_DOMAINE=TRACTAFRIC
SIEM_AD_COMPTE_SERVICE=CN=svc-siem,OU=Comptes de service,DC=tractafric,DC=local
SIEM_AD_MDP_SERVICE=********
SIEM_AD_GROUPE_ADMIN=CN=GG_SIEM_Administrateurs,OU=Groupes,DC=tractafric,DC=local
SIEM_AD_GROUPE_LECTEUR=CN=GG_SIEM_Lecteurs,OU=Groupes,DC=tractafric,DC=local
SIEM_AD_CA=/etc/siem-portail/certs/ca-interne.pem
```

Puis `systemctl restart siem-portail`.

- **Identifiant accepté** : `prenom.nom`, `TRACTAFRIC\prenom.nom` ou `prenom.nom@tractafric.local`.
- **Rôle** : il vient du groupe (les groupes imbriqués sont acceptés). Un compte désactivé ou hors des deux groupes est refusé.
- **Plusieurs contrôleurs** : si le premier ne répond pas, le portail passe au suivant.
- **AD indisponible** : les comptes locaux (`admin.local`) continuent de fonctionner. Garder leur mot de passe dans le coffre.
- **Sans LDAPS** : `ldap://` est accepté. La connexion est alors chiffrée par StartTLS avant tout envoi de mot de passe.

## 3. Serveur Informix (une seule fois)

Dans le portail : **Administration → Collecte**. Copier la **clé SSH du portail**, puis, sur le serveur Informix en root :

```bash
# copier le dossier collecteur/ (collecteur.py, preparer-serveur-bdd.sh, auditd/) par WinSCP ou scp
cd collecteur
./preparer-serveur-bdd.sh --cle "ssh-ed25519 AAAA... portail-siem-informix" --ip-portail <IP du serveur SIEM> --auditd
```

Le script :
- installe `/opt/siem-informix/collecteur.py` (root, non modifiable) ;
- crée le compte `siemcollect`, sans mot de passe ;
- autorise la clé du portail **depuis la seule IP du portail** et **pour la seule commande du collecteur** ;
- ajoute la règle `sudo` correspondante, vérifiée avec `visudo` ;
- avec `--auditd`, installe les règles auditd en adaptant le chemin Informix et l'uid du compte `informix`.

Il se termine par un test local.

- **`AllowUsers` dans `sshd_config`** : le script le signale. Ajouter `siemcollect`.
- **Désinstallation** : `./preparer-serveur-bdd.sh --desinstaller`.

**Droits base** (volet sessions et table `agr_lds`), à demander au DBA :
```sql
GRANT CONNECT TO root;     -- dans la base qui contient agr_lds
```

## 4. Déclarer le serveur dans le portail

**Administration → Collecte → Ajouter un serveur**

| Champ | Exemple |
|---|---|
| Nom / adresse | `srv-fr2-107` / `10.x.x.x` |
| Fréquence | 1 minute |
| Sources | wtmp, btmp, secure, auditd, sessions, programmes (agr_lds) ; onaudit une fois l'audit Informix activé ([informix-audit.md](informix-audit.md)) |
| Informix | `INFORMIXDIR`, `INFORMIXSERVER`, `ONCONFIG` (relevés avec `su - informix -c env`) |
| Table applicative | base, table `agr_lds`, colonne date `alds_open`, filtre `Xp_cron*` déjà renseigné |

Ensuite :
1. **Tester** vérifie la connexion SSH et le collecteur.
2. **Collecter** lance une collecte immédiate. Saisir `2026-09-01` pour reprendre tout septembre.
3. La collecte devient ensuite **automatique**.

Le tableau de bord affiche l'état de chaque serveur (à jour, en retard, en erreur).

## 5. Mise en service

1. **Postes** : affecter les IP des postes des administrateurs, pour attribuer les actions faites avec regix. Import en masse :
   `/opt/siem-portail/venv/bin/python -m app.outils postes postes.csv`.
2. **Notifications** : renseigner `SIEM_SMTP_*` pour recevoir les alertes hautes et critiques par e-mail.
3. **Sauvegarde** : sauvegarder chaque jour `/var/lib/siem-portail` (base, clé SSH, comptes locaux) et `/etc/siem-portail`.
4. **Mesures sur les comptes** (voir ci-dessous).

## Mesures sur les comptes

Le portail rend l'usage de regix visible. Pour que chaque action soit **attribuable avec certitude** :

1. **Changer le mot de passe de regix** et le garder dans un coffre, avec une sortie tracée.
2. **Créer des comptes Linux nominatifs** et interdire la connexion directe en regix et en informix : `DenyUsers regix informix` dans `sshd_config`.
3. **Passer au compte informix par `sudo -u informix`.** auditd garde l'utilisateur d'origine.
4. **Créer des utilisateurs base nominatifs avec un rôle DBA.** regix reste réservé à l'application.
5. **Réserver regix aux urgences** : chaque connexion directe déclenche une alerte.

## Exploitation

| Action | Commande |
|---|---|
| État du service | `systemctl status siem-portail` · `journalctl -u siem-portail -f` |
| Créer / réinitialiser un compte local | Administration → Comptes locaux (au moins un administrateur local doit toujours exister) |
| Mise à jour | relancer `installer-portail.sh` avec le nouveau paquet (la configuration et les données sont conservées) |
| Purge | automatique, selon `SIEM_CONSERVATION_JOURS` |
