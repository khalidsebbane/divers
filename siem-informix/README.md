# SIEM Informix : traçabilité système, base et applicatif

Portail qui **centralise et affiche les événements d'un serveur de base de données Informix** (Red Hat),
pour répondre à la question : **qui a fait quoi, quand et depuis où**, y compris quand un compte
administrateur partagé (ex. `regix`) est utilisé par plusieurs collaborateurs.

![Tableau de bord](docs/captures/tableau-de-bord.png)

## Ce que fait le portail

| Écran | Contenu |
|---|---|
| **Tableau de bord** | Indicateurs (événements, connexions, comptes partagés, opérations sensibles, alertes), activité par jour et par volet, dernières utilisations des comptes partagés, personnes et IP les plus actives |
| **Utilisateurs** | Liste des personnes et comptes vus, avec volumes par volet, IP, jours actifs |
| **Fiche utilisateur** | Chronologie complète mélangeant système, base et applicatif ; onglets Système / Base / Applicatif ; **sessions** (heure de connexion, de déconnexion, durée, IP, poste) ; adresses IP ; habitudes (carte jour × heure, programmes lancés) ; alertes ; export CSV |
| **Recherche** | Filtres texte, personne, compte, IP, volet, échecs ; export CSV pour Excel |
| **Alertes** | Règles automatiques, gravité, suivi (ouverte, en cours, close avec justification) |
| **Postes** | Affectation IP → personne, pour attribuer les actions d'un compte partagé |
| **Assistant** | Chatbot avec **questions proposées** (contextuelles à l'utilisateur affiché) et questions libres (IA, optionnelle) |

![Fiche utilisateur et assistant](docs/captures/fiche-utilisateur-assistant.png)

### Les trois volets

| Volet | Sources | Exemples d'événements |
|---|---|---|
| **Système** | `wtmp`, `btmp`, `/var/log/secure`, `auditd` | connexions SSH/console, échecs, `sudo`, `su`, commandes Informix (`onmode`, `ontape`, `dbaccess`...), modification de `onconfig`, `sudoers`, comptes |
| **Base** | audit Informix (`onaudit` / `onshowaudit`), `sysmaster:syssessions` | sessions base (machine cliente, heure), CREATE/DROP/ALTER, GRANT/REVOKE, suppressions de lignes sur tables sensibles |
| **Applicatif** | table des programmes lancés (`agr_lds`, fournie par le DBA) | programme lancé, utilisateur applicatif, poste, heure (traitements `Xp_cron*` exclus) |

### Qui a vraiment agi ? (attribution)

Chaque événement est rattaché à une **personne**, avec un niveau d'attribution affiché partout :

- **certaine** : la source donne l'identité. Cas d'un compte nominatif SSH, de l'utilisateur applicatif dans `agr_lds`, ou de l'utilisateur d'origine d'un `sudo`/`su` (champ `auid` d'auditd, conservé même après changement de compte) ;
- **probable** : un compte partagé utilisé depuis un poste affecté à une personne (écran *Postes*) ;
- **non identifiée** : un compte partagé utilisé depuis un poste inconnu. Une alerte est levée.

> Le portail rend l'usage de `regix` **visible**, mais seule la fin du partage rend chaque action **attribuable
> avec certitude**. Pour cela : comptes nominatifs, connexion avec un compte personnel puis `sudo -u informix`,
> et le mot de passe de regix changé et gardé dans un coffre. Voir [docs/installation.md](docs/installation.md#mesures-sur-les-comptes).

### Règles d'alerte

| Règle | Gravité |
|---|---|
| Compte partagé utilisé en direct (SSH), depuis un poste non affecté, ou hors heures ouvrées | moyenne → haute |
| Opération sensible en base : DROP, ALTER, GRANT, REVOKE… | moyenne → **critique** si suppression la nuit |
| Modification de `onconfig`/`sqlhosts`, `sudoers`, `/etc/passwd`, `/etc/shadow` | haute |
| Échecs de connexion répétés depuis une même IP (5 en 10 min) | haute |
| Nouvelle adresse IP pour une personne déjà connue | moyenne |
| Connexion hors heures ouvrées | faible |

## L'assistant (chatbot)

- **Questions proposées** : par exemple « Qui a utilisé le compte regix ces 7 derniers jours ? », « Qu'a fait kbenali hier ? », « Quelles sont les dernières sessions de… (heures de connexion et durée) ? », « Que s'est-il passé autour de l'alerte n°12 ? ».
  - Elles s'adaptent à l'utilisateur affiché et aux alertes graves en cours, et de nouvelles questions sont proposées après chaque réponse.
  - Chacune correspond à une requête précise : la réponse est **exacte, immédiate, sans IA, et aucune donnée ne sort du serveur**.
- **Questions libres** (optionnel) : elles sont traitées par Claude (API Anthropic, modèle `claude-opus-5-5`).
  - Claude interroge la base uniquement via des outils en **lecture seule** : recherche d'événements, profil d'une personne, alertes, et requêtes SQL `SELECT` contrôlées. Le journal du portail lui reste inaccessible.
  - La réponse se termine par 3 questions de suivi.
  - Sans clé API, une question libre est rapprochée de la question proposée la plus proche.
  - ⚠️ En mode IA, **les extraits d'événements utiles à la réponse sont envoyés à l'API Anthropic**. À valider avec le client (données personnelles, RGPD) avant d'activer `SIEM_ASSISTANT_IA`.

Les questions posées à l'assistant et les consultations de fiches et d'exports sont elles-mêmes tracées (table `journal_portail`).

## Architecture

```
Serveur Informix (RHEL)                                     VM / conteneur portail
┌──────────────────────────────────┐                     ┌───────────────────────────────┐
│ wtmp, btmp, secure, audit.log ─┐ │                     │ API FastAPI  ─ ingestion       │
│ onshowaudit (audit Informix) ──┼─┤  collecteur.py      │              ─ alertes         │
│ sysmaster:syssessions ─────────┤ ├─ HTTPS + jeton ───► │ SQLite (événements, alertes)  │──► navigateur
│ table agr_lds (programmes) ────┘ │  toutes les minutes │ Interface web + assistant     │     (HTTPS, comptes)
│ Python 3.6 interne, rien à       │  (mise en attente   │ Claude (optionnel)            │
│ installer                        │   si portail absent)│                               │
└──────────────────────────────────┘                     └───────────────────────────────┘
```

- **Collecteur** ([collecteur/](collecteur/)) :
  - un seul fichier Python, bibliothèque standard uniquement. Il tourne avec `/usr/libexec/platform-python` de RHEL 8, **sans rien installer** (l'abonnement Red Hat du serveur a expiré) ;
  - il reprend là où il s'était arrêté, met les événements en attente si le portail est injoignable, et le portail ignore les doublons.
- **Portail** ([portail/](portail/)) :
  - FastAPI + SQLite, interface web sans dépendance externe (fonctionne sans Internet), thème clair et sombre, utilisable sur mobile ;
  - les journaux sont copiés **hors du serveur** dès leur collecte : un administrateur qui utilise regix ne peut pas effacer ses traces côté portail.

## Démarrage rapide (démonstration)

```bash
cd portail
pip install -r requirements.txt
export SIEM_BASE=./donnees/siem.db SIEM_JETON_COLLECTEUR=$(openssl rand -hex 32)
python -m app.outils demo                 # données fictives sur 45 jours
python -m app.outils compte admin         # choisir le mot de passe
uvicorn app.main:app --port 8443          # puis http://localhost:8443
```

Installation réelle (serveur Informix + portail) : **[docs/installation.md](docs/installation.md)**.
Activation de l'audit Informix : **[docs/informix-audit.md](docs/informix-audit.md)**.

## Tests

```bash
pip install pytest httpx fastapi anthropic
python -m pytest tests
```

Les tests couvrent :
- la lecture de chaque source (wtmp, secure, auditd, onshowaudit, détection des colonnes de `agr_lds`) ;
- l'ingestion, l'attribution et les alertes ;
- l'API et les droits ;
- les questions proposées et le verrouillage SQL en lecture seule ;
- la boucle d'outils de l'assistant IA, avec un faux client Claude.

## Points à valider sur le serveur réel

1. **Colonnes de `agr_lds`** : elles sont détectées automatiquement (`syscolumns`). Les forcer dans `collecteur.ini` si besoin, puis vérifier avec `--test`.
2. **Format exact de `onshowaudit`** : il dépend de la version d'Informix. Les positions des champs sont réglables dans `collecteur.ini` ; à valider sur un extrait réel ([docs/informix-audit.md](docs/informix-audit.md)).
3. **Chemins `INFORMIXDIR` et uid du compte informix** dans les règles auditd.
4. **Volume** : l'audit de toutes les lectures pèse sur les performances. Il faut cibler les tables sensibles.
