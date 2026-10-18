# Dossier sécurité (pour le RSSI)

## Périmètre et flux

| Flux | Sens | Port | Protection |
|---|---|---|---|
| Consultation du portail | postes → SIEM | 443 | TLS (certificat de l'autorité interne), authentification AD ou locale |
| Collecte | SIEM → serveur Informix | 22 | SSH, clé ed25519 dédiée, commande forcée, `from=` limité à l'IP du SIEM |
| Authentification | SIEM → contrôleurs AD | 636 | LDAPS, certificat vérifié ; compte de service en lecture seule |
| Notifications | SIEM → SMTP | 587 | STARTTLS (facultatif) |
| Assistant IA | SIEM → api.anthropic.com | 443 | **désactivé par défaut** ; à n'activer qu'après validation (données personnelles) |

Aucun flux entrant vers le serveur Informix n'est créé en dehors de SSH depuis le seul serveur SIEM.

## Serveur Informix : ce qui est modifié

| Élément | Détail | Réversible |
|---|---|---|
| `/opt/siem-informix/collecteur.py` | root:root 0755, lecture seule pour les autres comptes | `--desinstaller` |
| Compte `siemcollect` | compte système, mot de passe verrouillé | oui |
| `~siemcollect/.ssh/authorized_keys` | `from="<IP SIEM>",command="sudo <python> /opt/siem-informix/collecteur.py --distant",no-pty,no-port-forwarding,no-agent-forwarding,no-X11-forwarding,no-user-rc` | oui |
| `/etc/sudoers.d/siem-collecteur` | `siemcollect ALL=(root) NOPASSWD: <python> /opt/siem-informix/collecteur.py --distant` (vérifié par `visudo`) | oui |
| `/etc/audit/rules.d/siem-informix.rules` (option) | surveillance des commandes Informix, de la configuration, des comptes et de sudoers | oui |

**Ce que la clé du portail permet** : lancer le collecteur, et rien d'autre. Toute commande envoyée est ignorée et remplacée
par le collecteur ; il n'y a ni terminal, ni redirection de port, ni agent. Cela a été vérifié en test : la commande
`id; cat /etc/shadow` envoyée avec la clé a renvoyé la sortie du collecteur. Le collecteur ne fait que **lire** les journaux et
interroger la base en `SELECT` ; il n'écrit rien sur le serveur en mode piloté.

**Si le serveur SIEM était compromis**, l'attaquant pourrait lire, via le collecteur, ce que celui-ci lit déjà : journaux de connexion, audit, sessions et table `agr_lds`. Il ne pourrait ni exécuter de commande arbitraire ni modifier la base. Le script du collecteur appartient à root et `siemcollect` ne peut pas le modifier.

## Portail

- **Authentification**
  - **AD** : recherche du compte par le compte de service, puis vérification du mot de passe par une liaison LDAP au nom de l'utilisateur. Un mot de passe vide est refusé, ce qui empêche les liaisons anonymes.
  - **Rôles** : le rôle est donné par le groupe AD, groupes imbriqués compris.
  - **Comptes désactivés** : ils sont refusés.
  - **Comptes locaux** : réservés au secours, avec empreintes PBKDF2-SHA256 (310 000 itérations). Le dernier administrateur local ne peut pas être supprimé.
- **Sessions** : jeton aléatoire de 256 bits ; seule son empreinte SHA-256 est stockée. Le cookie est `HttpOnly`, `Secure` et `SameSite=Strict`. Durée maximale 8 h, inactivité maximale 30 min, déconnexion explicite.
- **Force brute** : verrouillage de 15 min après 5 échecs, par compte et par IP. Chaque échec est journalisé.
- **Web** :
  - CSP `default-src 'self'` et `frame-ancestors 'none'`, `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy: same-origin` ;
  - pas de cache sur l'API ;
  - en-tête anti-CSRF obligatoire sur toute écriture ;
  - aucune ressource externe (polices, scripts, CDN).
- **Droits** : lecteur = consultation ; administrateur = collecte, postes, alertes, comptes locaux, journal, paramètres.
- **Service** (installation native) : compte non privilégié `siem`, `ProtectSystem=strict`, `NoNewPrivileges`, `PrivateTmp`, écriture limitée à `/var/lib/siem-portail`.
- **Conteneur** (Docker) : système de fichiers en lecture seule, `cap_drop: ALL`, `no-new-privileges`.

## Traçabilité du portail

La table `journal_portail` est consultable dans **Administration → Journal d'audit**. Elle enregistre :
- les connexions réussies, échouées et bloquées, ainsi que les déconnexions ;
- la consultation des fiches utilisateur ;
- les exports CSV, avec les filtres utilisés ;
- les questions posées à l'assistant ;
- l'ajout, la modification et la suppression de sources, les collectes manuelles, la gestion des comptes locaux et l'affectation des postes.

## Données et RGPD

- **Contenu** : identifiants, adresses IP, postes, horaires, commandes et opérations. Ce sont des données personnelles des collaborateurs. Le traitement doit être déclaré au registre et les collaborateurs informés (charte informatique).
- **Durée de conservation** : réglable par `SIEM_CONSERVATION_JOURS`, 400 jours par défaut, avec purge automatique.
- **Assistant IA** : désactivé par défaut. Les **questions proposées** sont calculées localement, sans envoi de données. Le mode IA (questions libres) envoie à l'API Anthropic les extraits d'événements nécessaires à la réponse ; il ne doit être activé qu'après validation, ou jamais sur un serveur isolé.

## Points de vigilance

1. **Mot de passe de `regix`** : tant qu'il est partagé, l'attribution reste « probable ». Les mesures sur les comptes sont dans [installation.md](installation.md#mesures-sur-les-comptes).
2. **Clé SSH du portail** : `/var/lib/siem-portail/ssh/id_ed25519`, lisible par le seul compte `siem`. Il faut l'inclure dans les sauvegardes chiffrées.
3. **Fichier `/etc/siem-portail/portail.env`** : il contient le mot de passe du compte de service AD. Droits `0640 root:siem`.
4. **Certificat** : remplacer le certificat autosigné généré à l'installation par un certificat de l'autorité interne.
