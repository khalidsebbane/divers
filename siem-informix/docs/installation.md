# Installation

## 1. Portail (VM ou serveur séparé du serveur Informix)

Le portail doit être sur **une autre machine** que le serveur de base : les traces y sont conservées
même si quelqu'un les efface sur le serveur Informix.

### Avec Docker

```bash
cd portail
cp .env.exemple .env                     # renseigner SIEM_JETON_COLLECTEUR (openssl rand -hex 32)
mkdir -p donnees certs                   # copier cert.pem et cle.pem dans certs/ (certificat interne)
docker compose up -d --build
docker compose logs portail | grep "mot de passe"   # mot de passe initial du compte admin
docker compose exec portail python -m app.outils compte admin   # le changer
docker compose exec portail python -m app.outils compte dupont --role lecteur
```

### Sans Docker (Python 3.10+)

```bash
python3 -m venv /opt/siem-portail/venv && /opt/siem-portail/venv/bin/pip install -r requirements.txt
set -a; . ./.env; set +a
/opt/siem-portail/venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8443 \
    --ssl-certfile /etc/pki/siem/cert.pem --ssl-keyfile /etc/pki/siem/cle.pem
```

Comptes du portail :
- **admin** : il peut affecter les postes et changer le statut des alertes ;
- **lecteur** : consultation seule.

Sauvegarder le dossier `donnees/` (base d'événements et comptes).

### Affectation des postes

Écran *Postes*, ou import en masse : `python -m app.outils postes postes.csv` (format `ip;personne;libelle`).
Indispensable tant que le compte regix est partagé : c'est ce qui permet l'attribution « probable ».

## 2. Collecteur (serveur Informix, RHEL 7/8/9)

```bash
mkdir -p /opt/siem-informix/collecteur && cd /opt/siem-informix/collecteur
# copier collecteur.py, collecteur.ini.exemple, auditd/, systemd/
cp collecteur.ini.exemple collecteur.ini && chmod 600 collecteur.ini
vi collecteur.ini        # url et jeton du portail, environnement Informix, base de agr_lds
```

### Règles auditd

```bash
id -u informix                                   # reporter l'uid dans le fichier de règles
vi auditd/siem-informix.rules                    # adapter /opt/informix et l'uid
cp auditd/siem-informix.rules /etc/audit/rules.d/
augenrules --load && auditctl -l | grep siem     # vérifier que les règles sont actives
```

### Premier test, puis planification

```bash
/usr/libexec/platform-python collecteur.py -c collecteur.ini --test     # affiche sans envoyer
/usr/libexec/platform-python collecteur.py -c collecteur.ini            # première passe (reprend 45 jours)
cp systemd/siem-collecteur.* /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now siem-collecteur.timer
journalctl -u siem-collecteur -f
```

Sans systemd : `* * * * * /usr/libexec/platform-python /opt/siem-informix/collecteur/collecteur.py -c /opt/siem-informix/collecteur/collecteur.ini`

**Le serveur ne peut pas joindre le portail ?** Les événements restent dans `var/attente/`. On peut aussi écrire un fichier
(`--sortie evenements.jsonl`), le transférer, puis l'importer sur le portail avec `python -m app.outils importer evenements.jsonl`.

### Reprendre l'historique (ex. septembre)

```bash
/usr/libexec/platform-python collecteur.py -c collecteur.ini --depuis 2026-09-01
```
Les doublons sont ignorés par le portail : on peut relancer sans risque.

## Mesures sur les comptes

Le portail rend l'usage de regix visible. Pour que chaque action soit **attribuable avec certitude** :

1. **Changer le mot de passe de regix** et le garder dans un coffre (Vaultwarden, Passbolt, KeePass partagé), avec une sortie tracée.
2. **Créer un compte Linux nominatif par administrateur**, et interdire la connexion SSH directe en regix et en informix :
   `DenyUsers regix informix` dans `/etc/ssh/sshd_config`.
3. **Donner l'accès au compte informix par sudo** : `kbenali ALL=(informix) ALL` dans `/etc/sudoers.d/informix`.
   auditd conserve l'utilisateur d'origine (`auid`), donc chaque commande Informix est rattachée à une personne.
4. **Côté base, des utilisateurs nominatifs avec un rôle DBA** à la place de regix pour l'administration
   (`CREATE USER` / `GRANT` selon la version d'Informix, ou comptes OS mappés). regix reste réservé à l'application.
5. **Réserver regix aux urgences** : chaque connexion directe déclenche une alerte haute dans le portail.
