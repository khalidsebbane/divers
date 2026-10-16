"""
Assistant du portail.

Deux modes :
  - Questions proposées : chaque suggestion correspond à une requête précise sur la base d'événements.
    Réponse exacte, immédiate, sans IA et sans envoi de données à l'extérieur.
  - Questions libres : envoyées à Claude (API Anthropic), qui interroge la base via des outils en lecture seule.
    Actif seulement si une clé API est configurée et SIEM_ASSISTANT_IA != non.
"""
import datetime as dt
import json
import logging
import re
import sqlite3

from . import db
from .config import config

log = logging.getLogger('siem.assistant')


# --------------------------------------------------------------------------------------------
# Périodes
# --------------------------------------------------------------------------------------------
def _periode(code):
    a = dt.date.today()
    if code == 'jour':
        return a, a
    if code == 'hier':
        h = a - dt.timedelta(days=1)
        return h, h
    if code == 'semaine':
        return a - dt.timedelta(days=6), a
    if code == 'mois':
        return a.replace(day=1), a
    return a - dt.timedelta(days=29), a


def _p(code):
    d, f = _periode(code)
    return d.isoformat(), f.isoformat()


def _fr(ts):
    if not ts:
        return ''
    try:
        return dt.datetime.fromisoformat(ts).strftime('%d/%m/%Y %H:%M')
    except ValueError:
        return ts


def _duree(s):
    if s is None:
        return 'en cours'
    h, m = divmod(int(s) // 60, 60)
    return '%dh%02d' % (h, m)


# --------------------------------------------------------------------------------------------
# Catalogue des questions proposées
# --------------------------------------------------------------------------------------------
def _partage():
    return config.comptes_partages[0] if config.comptes_partages else 'regix'


CATALOGUE_GLOBAL = [
    ('partage_semaine', 'Qui a utilisé le compte {partage} ces 7 derniers jours ?'),
    ('connectes', 'Qui est connecté en ce moment ?'),
    ('sensibles_semaine', 'Quelles opérations sensibles (DROP, ALTER, GRANT...) ont eu lieu cette semaine ?'),
    ('hors_heures_mois', 'Qui s\'est connecté en dehors des heures ouvrées ce mois-ci ?'),
    ('nouvelles_ip', 'Quelles nouvelles adresses IP sont apparues cette semaine ?'),
    ('echecs_semaine', 'Quels échecs de connexion cette semaine, et depuis quelles adresses ?'),
    ('actifs_mois', 'Quels sont les utilisateurs les plus actifs ce mois-ci ?'),
    ('alertes_ouvertes', 'Quelles alertes restent à traiter ?'),
]
CATALOGUE_PERSONNE = [
    ('p_hier', 'Qu\'a fait {p} hier ?'),
    ('p_ip_mois', 'Depuis quelles adresses IP {p} se connecte ce mois-ci ?'),
    ('p_programmes', 'Quels programmes {p} a lancés cette semaine ?'),
    ('p_sessions', 'Quelles sont les dernières sessions de {p} (heures de connexion et durée) ?'),
    ('p_hors_heures', 'Quelles connexions de {p} en dehors des heures ouvrées ce mois-ci ?'),
    ('p_sensibles', 'Quelles opérations sensibles en base pour {p} ce mois-ci ?'),
    ('p_partage', 'Quand {p} a utilisé le compte {partage} ce mois-ci ?'),
]


def suggestions(personne=None, limite=None):
    res = []
    if personne:
        res += [{'id': i, 'texte': t.format(p=personne, partage=_partage()), 'personne': personne} for i, t in CATALOGUE_PERSONNE]
    res += [{'id': i, 'texte': t.format(partage=_partage())} for i, t in CATALOGUE_GLOBAL]
    # Suggestions dynamiques : alertes graves encore ouvertes
    try:
        for a in db.alertes(statut='ouverte', limite=50):
            if a['gravite'] in ('haute', 'critique'):
                res.insert(1 if personne else 0, {'id': 'alerte', 'alerte': a['id'],
                                                  'texte': 'Que s\'est-il passé autour de l\'alerte n°%d (%s) ?' % (a['id'], a['titre'][:60])})
                break
    except sqlite3.Error:
        pass
    return res[:limite] if limite else res


def _tableau(colonnes, rows, cles):
    return {'colonnes': colonnes, 'lignes': [[r.get(k, '') if not callable(k) else k(r) for k in cles] for r in rows]}


def repondre_suggestion(sid, personne=None, alerte=None):
    partages = config.comptes_partages or ['regix']
    pl = ','.join('?' * len(partages))
    hh = (config.heure_debut, config.heure_fin)
    with db.connexion() as cx:
        if sid == 'partage_semaine':
            d, f = _p('semaine')
            rows = db.lignes(cx, "SELECT personne, attribution, ip, poste, COUNT(*) n, MIN(ts) premiere, MAX(ts) derniere"
                                 " FROM evenements WHERE LOWER(compte) IN (%s) AND categorie IN ('connexion','changement_compte','sudo')"
                                 " AND jour BETWEEN ? AND ? GROUP BY personne, ip ORDER BY n DESC" % pl, partages + [d, f])
            nb = len({r['personne'] for r in rows})
            texte = ('**%d personne(s)** ont utilisé le compte %s ces 7 derniers jours.' % (nb, '/'.join(partages)) if rows
                     else 'Aucune utilisation des comptes %s ces 7 derniers jours.' % '/'.join(partages))
            if any(r['attribution'] != 'certaine' for r in rows):
                texte += ' Les lignes « probable » sont attribuées d\'après le poste (affectation des IP), les lignes « non identifiée » ne peuvent pas être rattachées à une personne.'
            return texte, _tableau(['Personne', 'Attribution', 'IP', 'Poste', 'Utilisations', 'Première', 'Dernière'], rows,
                                   ['personne', lambda r: {'certaine': 'certaine', 'probable': 'probable'}.get(r['attribution'], 'non identifiée'),
                                    'ip', 'poste', 'n', lambda r: _fr(r['premiere']), lambda r: _fr(r['derniere'])])

        if sid == 'connectes':
            depuis = (dt.datetime.now() - dt.timedelta(hours=24)).strftime('%Y-%m-%dT%H:%M:%S')
            rows = db.lignes(cx, "SELECT o.personne, o.compte, o.ip, o.poste, o.source, o.ts FROM evenements o"
                                 " WHERE o.categorie='connexion' AND o.ts >= ? AND o.session != ''"
                                 " AND NOT EXISTS (SELECT 1 FROM evenements f WHERE f.categorie='deconnexion' AND f.session=o.session)"
                                 " ORDER BY o.ts DESC", (depuis,))
            return ('**%d session(s)** ouvertes depuis moins de 24 h et pas encore fermées.' % len(rows) if rows
                    else 'Aucune session ouverte détectée sur les dernières 24 h.'), \
                _tableau(['Personne', 'Compte', 'Volet', 'IP', 'Poste', 'Connecté depuis'], rows,
                         ['personne', 'compte', 'source', 'ip', 'poste', lambda r: _fr(r['ts'])])

        if sid in ('sensibles_semaine', 'p_sensibles'):
            d, f = _p('semaine' if sid == 'sensibles_semaine' else 'mois')
            extra, par = (' AND personne = ?', [personne]) if sid == 'p_sensibles' else ('', [])
            rows = db.lignes(cx, "SELECT ts, personne, compte, ip, action, objet, resultat FROM evenements"
                                 " WHERE source='base' AND categorie IN ('ddl','droits') AND jour BETWEEN ? AND ?%s"
                                 " ORDER BY ts DESC LIMIT 300" % extra, [d, f] + par)
            qui = ' pour %s' % personne if personne and sid == 'p_sensibles' else ''
            return ('**%d opération(s) sensible(s)**%s (création, modification, suppression d\'objets ou changement de droits).' % (len(rows), qui)
                    if rows else 'Aucune opération sensible en base%s sur la période.' % qui), \
                _tableau(['Date', 'Personne', 'Compte', 'IP', 'Opération', 'Objet', 'Résultat'], rows,
                         [lambda r: _fr(r['ts']), 'personne', 'compte', 'ip', 'action', 'objet', 'resultat'])

        if sid in ('hors_heures_mois', 'p_hors_heures'):
            d, f = _p('mois')
            extra, par = (' AND personne = ?', [personne]) if sid == 'p_hors_heures' else ('', [])
            rows = db.lignes(cx, "SELECT ts, personne, compte, source, ip, poste, action FROM evenements"
                                 " WHERE categorie='connexion' AND jour BETWEEN ? AND ?"
                                 " AND (heure < ? OR heure >= ? OR strftime('%%w', ts) IN ('0','6'))%s ORDER BY ts DESC LIMIT 300" % extra,
                             [d, f, hh[0], hh[1]] + par)
            return ('**%d connexion(s)** en dehors des heures ouvrées (%dh-%dh en semaine) ce mois-ci, par %d personne(s).'
                    % (len(rows), hh[0], hh[1], len({r['personne'] for r in rows})) if rows
                    else 'Aucune connexion hors heures ouvrées ce mois-ci.'), \
                _tableau(['Date', 'Personne', 'Compte', 'Volet', 'IP', 'Poste'], rows,
                         [lambda r: _fr(r['ts']), 'personne', 'compte', 'source', 'ip', 'poste'])

        if sid == 'nouvelles_ip':
            d, f = _p('semaine')
            rows = db.lignes(cx, "SELECT ip, GROUP_CONCAT(DISTINCT personne) personnes, GROUP_CONCAT(DISTINCT NULLIF(poste,'')) postes,"
                                 " MIN(ts) premiere, COUNT(*) n FROM evenements WHERE ip != '' AND ip != 'local'"
                                 " GROUP BY ip HAVING MIN(jour) BETWEEN ? AND ? ORDER BY premiere DESC", (d, f))
            return ('**%d adresse(s) IP** vues pour la première fois cette semaine.' % len(rows) if rows
                    else 'Aucune nouvelle adresse IP cette semaine.'), \
                _tableau(['IP', 'Personnes', 'Postes', 'Première apparition', 'Événements'], rows,
                         ['ip', 'personnes', 'postes', lambda r: _fr(r['premiere']), 'n'])

        if sid == 'echecs_semaine':
            d, f = _p('semaine')
            rows = db.lignes(cx, "SELECT ip, GROUP_CONCAT(DISTINCT compte) comptes, COUNT(*) n, MIN(ts) premiere, MAX(ts) derniere"
                                 " FROM evenements WHERE resultat='echec' AND jour BETWEEN ? AND ? GROUP BY ip ORDER BY n DESC", (d, f))
            return ('**%d échec(s)** cette semaine, depuis %d origine(s).' % (sum(r['n'] for r in rows), len(rows)) if rows
                    else 'Aucun échec cette semaine.'), \
                _tableau(['IP', 'Comptes essayés', 'Échecs', 'Premier', 'Dernier'], rows,
                         ['ip', 'comptes', 'n', lambda r: _fr(r['premiere']), lambda r: _fr(r['derniere'])])

        if sid == 'actifs_mois':
            d, f = _p('mois')
            rows = db.lignes(cx, "SELECT personne, COUNT(*) n, COUNT(DISTINCT jour) jours, SUM(source='systeme') sys,"
                                 " SUM(source='base') bdd, SUM(source='applicatif') app, MAX(ts) derniere FROM evenements"
                                 " WHERE jour BETWEEN ? AND ? GROUP BY personne ORDER BY n DESC LIMIT 15", (d, f))
            return 'Les utilisateurs les plus actifs depuis le 1er du mois :', \
                _tableau(['Personne', 'Événements', 'Jours actifs', 'Système', 'Base', 'Applicatif', 'Dernière activité'], rows,
                         ['personne', 'n', 'jours', 'sys', 'bdd', 'app', lambda r: _fr(r['derniere'])])

        if sid == 'alertes_ouvertes':
            rows = db.lignes(cx, "SELECT * FROM alertes WHERE statut != 'close' ORDER BY CASE gravite WHEN 'critique' THEN 0"
                                 " WHEN 'haute' THEN 1 WHEN 'moyenne' THEN 2 ELSE 3 END, ts DESC LIMIT 100")
            return ('**%d alerte(s)** à traiter, les plus graves en premier.' % len(rows) if rows else 'Aucune alerte ouverte.'), \
                _tableau(['N°', 'Date', 'Gravité', 'Alerte', 'Personne', 'IP'], rows,
                         ['id', lambda r: _fr(r['ts']), 'gravite', 'titre', 'personne', 'ip'])

        if sid == 'alerte' and alerte:
            a = cx.execute('SELECT * FROM alertes WHERE id = ?', (int(alerte),)).fetchone()
            if not a:
                return 'Alerte introuvable.', None
            t = dt.datetime.fromisoformat(a['ts'])
            rows = db.lignes(cx, 'SELECT ts, source, action, compte, ip, objet, resultat FROM evenements WHERE personne = ?'
                                 ' AND ts BETWEEN ? AND ? ORDER BY ts',
                             (a['personne'], (t - dt.timedelta(minutes=30)).isoformat(), (t + dt.timedelta(minutes=30)).isoformat()))
            return ('**Alerte n°%d - %s** (gravité %s)\n\n%s\n\nActivité de %s dans la demi-heure avant et après :'
                    % (a['id'], a['titre'], a['gravite'], a['message'] or '', a['personne'])), \
                _tableau(['Heure', 'Volet', 'Action', 'Compte', 'IP', 'Objet', 'Résultat'], rows,
                         [lambda r: _fr(r['ts']), 'source', 'action', 'compte', 'ip', 'objet', 'resultat'])

        # Questions sur une personne
        if not personne:
            return 'Choisissez d\'abord un utilisateur.', None
        if sid == 'p_hier':
            d, f = _p('hier')
            rows = db.lignes(cx, 'SELECT ts, source, action, compte, ip, objet, resultat FROM evenements'
                                 ' WHERE personne = ? AND jour = ? ORDER BY ts', (personne, d))
            if not rows:
                return 'Aucune activité de %s hier (%s).' % (personne, dt.date.fromisoformat(d).strftime('%d/%m/%Y')), None
            par = {}
            for r in rows:
                par[r['source']] = par.get(r['source'], 0) + 1
            return ('Hier, **%s** a eu %d événement(s) entre %s et %s : %s.'
                    % (personne, len(rows), rows[0]['ts'][11:16], rows[-1]['ts'][11:16],
                       ', '.join('%d %s' % (n, s) for s, n in sorted(par.items())))), \
                _tableau(['Heure', 'Volet', 'Action', 'Compte', 'IP', 'Objet', 'Résultat'], rows,
                         [lambda r: r['ts'][11:19], 'source', 'action', 'compte', 'ip', 'objet', 'resultat'])
        if sid == 'p_ip_mois':
            d, f = _p('mois')
            rows = db.lignes(cx, "SELECT ip, GROUP_CONCAT(DISTINCT NULLIF(poste,'')) postes, COUNT(*) n, COUNT(DISTINCT jour) jours,"
                                 " MIN(ts) premiere, MAX(ts) derniere FROM evenements WHERE personne = ? AND ip != ''"
                                 " AND jour BETWEEN ? AND ? GROUP BY ip ORDER BY n DESC", (personne, d, f))
            return ('%s a utilisé **%d adresse(s) IP** ce mois-ci.' % (personne, len(rows)) if rows
                    else 'Aucune adresse IP pour %s ce mois-ci.' % personne), \
                _tableau(['IP', 'Postes', 'Événements', 'Jours', 'Première', 'Dernière'], rows,
                         ['ip', 'postes', 'n', 'jours', lambda r: _fr(r['premiere']), lambda r: _fr(r['derniere'])])
        if sid == 'p_programmes':
            d, f = _p('semaine')
            rows = db.lignes(cx, "SELECT objet, COUNT(*) n, MIN(ts) premiere, MAX(ts) derniere FROM evenements"
                                 " WHERE personne = ? AND source='applicatif' AND jour BETWEEN ? AND ? GROUP BY objet ORDER BY n DESC",
                             (personne, d, f))
            return ('%s a lancé **%d programme(s) différent(s)** cette semaine (%d lancements).' % (personne, len(rows), sum(r['n'] for r in rows))
                    if rows else 'Aucun programme lancé par %s cette semaine.' % personne), \
                _tableau(['Programme', 'Lancements', 'Premier', 'Dernier'], rows,
                         ['objet', 'n', lambda r: _fr(r['premiere']), lambda r: _fr(r['derniere'])])
        if sid == 'p_sessions':
            d, f = _p('30j')
            rows = db.sessions(personne, d, f, limite=50)
            return ('Les %d dernières sessions de %s (30 derniers jours) :' % (len(rows), personne) if rows
                    else 'Aucune session pour %s sur les 30 derniers jours.' % personne), \
                _tableau(['Connexion', 'Déconnexion', 'Durée', 'Volet', 'Compte', 'IP', 'Poste', 'Opérations'], rows,
                         [lambda r: _fr(r['ts']), lambda r: _fr(r['fin']) or '-', lambda r: _duree(r['duree_s']),
                          'source', 'compte', 'ip', 'poste', 'operations'])
        if sid == 'p_partage':
            d, f = _p('mois')
            rows = db.lignes(cx, "SELECT ts, compte, attribution, ip, poste, action, source FROM evenements WHERE personne = ?"
                                 " AND LOWER(compte) IN (%s) AND categorie IN ('connexion','changement_compte','sudo')"
                                 " AND jour BETWEEN ? AND ? ORDER BY ts DESC" % pl, [personne] + partages + [d, f])
            return ('%s a utilisé un compte partagé **%d fois** ce mois-ci.' % (personne, len(rows)) if rows
                    else '%s n\'a pas utilisé de compte partagé ce mois-ci (d\'après les données disponibles).' % personne), \
                _tableau(['Date', 'Compte', 'Attribution', 'IP', 'Poste', 'Action'], rows,
                         [lambda r: _fr(r['ts']), 'compte', 'attribution', 'ip', 'poste', 'action'])
    return 'Question non reconnue.', None


def suivantes(sid, personne):
    """Questions proposées après une réponse : on enchaîne sur le même sujet."""
    toutes = suggestions(personne)
    autres = [s for s in toutes if s['id'] != sid]
    return autres[:4]


# --------------------------------------------------------------------------------------------
# Mode IA : Claude interroge la base via des outils en lecture seule
# --------------------------------------------------------------------------------------------
SYSTEME = """Tu es l'assistant d'un portail SIEM qui centralise les événements d'un serveur de base de données Informix (Red Hat).
Tu aides des administrateurs et des responsables sécurité à comprendre qui a fait quoi, quand et depuis où.

Les données ont trois volets (champ source) :
- systeme : connexions SSH/console, échecs, sudo, su, commandes et fichiers sensibles surveillés par auditd ;
- base : sessions Informix, opérations auditées (création/suppression d'objets, droits, modifications de données) ;
- applicatif : programmes lancés dans l'application (table de l'application), avec l'utilisateur applicatif.

Notions importantes :
- compte = compte technique utilisé (par exemple un compte partagé comme regix) ; personne = personne à qui l'action est attribuée.
- attribution = certaine (la source donne l'identité), probable (déduite du poste via l'affectation des IP) ou compte (personne non identifiée : action faite avec un compte partagé depuis un poste non affecté).
- Les heures sont l'heure locale du serveur. Heures ouvrées : {heures}, du lundi au vendredi.
- Comptes partagés surveillés : {partages}.

Méthode :
- Appuie chaque affirmation sur les résultats des outils. Ne devine jamais une identité, une heure ou une adresse IP.
- Quand une action vient d'un compte partagé, dis clairement si l'attribution est certaine, probable ou impossible.
- Si les données ne permettent pas de répondre, dis-le et indique quelle source manque (par exemple l'audit Informix non activé).
- Réponds en français, de façon concise : une phrase de synthèse, puis les faits (tableau Markdown si plusieurs lignes, dates au format JJ/MM/AAAA HH:MM).

Termine toujours ta réponse par une ligne unique de la forme :
SUGGESTIONS: question 1 | question 2 | question 3
avec trois questions de suivi utiles, courtes, que l'utilisateur pourrait poser ensuite."""

SCHEMA_SQL = """Tables SQLite disponibles (lecture seule) :
evenements(id, ts 'AAAA-MM-JJTHH:MM:SS', jour 'AAAA-MM-JJ', heure 0-23, source systeme|base|applicatif,
  categorie connexion|deconnexion|echec_connexion|authentification|sudo|changement_compte|commande|fichier|serveur|acces|ddl|droits|dml|lecture|admin|programme|audit,
  action, serveur, compte, utilisateur, personne, attribution certaine|probable|compte, ip, poste, session, objet, resultat succes|echec, details JSON)
alertes(id, ts, regle, gravite faible|moyenne|haute|critique, titre, message, personne, compte, ip, evenement_id, statut ouverte|en_cours|close)
postes(ip, personne, libelle)"""

OUTILS = [
    {
        'name': 'rechercher_evenements',
        'description': 'Recherche des événements avec des filtres. Retourne au plus « limite » événements, les plus récents d\'abord, et le nombre total.',
        'input_schema': {
            'type': 'object',
            'properties': {
                'personne': {'type': 'string', 'description': 'Personne exacte (voir lister_personnes).'},
                'compte': {'type': 'string', 'description': 'Compte technique, ex. regix.'},
                'ip': {'type': 'string'},
                'source': {'type': 'string', 'enum': ['systeme', 'base', 'applicatif']},
                'categorie': {'type': 'string', 'description': 'Une ou plusieurs catégories séparées par des virgules.'},
                'resultat': {'type': 'string', 'enum': ['succes', 'echec']},
                'texte': {'type': 'string', 'description': 'Texte cherché dans action, objet, personne, compte, ip, poste, détails.'},
                'debut': {'type': 'string', 'description': 'Date de début AAAA-MM-JJ incluse.'},
                'fin': {'type': 'string', 'description': 'Date de fin AAAA-MM-JJ incluse.'},
                'limite': {'type': 'integer', 'description': 'Nombre maximum d\'événements (1 à 200).'},
            },
            'required': [],
            'additionalProperties': False,
        },
    },
    {
        'name': 'profil_personne',
        'description': 'Synthèse de l\'activité d\'une personne sur une période : volumes par volet, adresses IP, comptes utilisés, sessions (connexion, déconnexion, durée), programmes, alertes.',
        'input_schema': {
            'type': 'object',
            'properties': {'personne': {'type': 'string'}, 'debut': {'type': 'string'}, 'fin': {'type': 'string'}},
            'required': ['personne', 'debut', 'fin'],
            'additionalProperties': False,
        },
    },
    {
        'name': 'lister_personnes',
        'description': 'Liste des personnes et comptes vus sur une période, avec leurs volumes, IP et dates de première/dernière activité. Utile pour retrouver le nom exact d\'une personne.',
        'input_schema': {
            'type': 'object',
            'properties': {'debut': {'type': 'string'}, 'fin': {'type': 'string'}, 'texte': {'type': 'string'}},
            'required': ['debut', 'fin'],
            'additionalProperties': False,
        },
    },
    {
        'name': 'lister_alertes',
        'description': 'Alertes générées par les règles (compte partagé, hors heures, opérations sensibles, échecs répétés, nouvelle IP...).',
        'input_schema': {
            'type': 'object',
            'properties': {'statut': {'type': 'string', 'enum': ['ouverte', 'en_cours', 'close']},
                           'gravite': {'type': 'string', 'enum': ['faible', 'moyenne', 'haute', 'critique']},
                           'debut': {'type': 'string'}, 'fin': {'type': 'string'}},
            'required': [],
            'additionalProperties': False,
        },
    },
    {
        'name': 'requete_sql',
        'description': 'Exécute une requête SQL SELECT (SQLite, lecture seule, 500 lignes maximum) pour les statistiques que les autres outils ne couvrent pas. ' + SCHEMA_SQL,
        'input_schema': {
            'type': 'object',
            'properties': {'sql': {'type': 'string', 'description': 'Une seule requête SELECT.'}},
            'required': ['sql'],
            'additionalProperties': False,
        },
    },
]


def _autoriser(action, arg1, arg2, _base, _trigger):
    # Lecture seule : SELECT, lecture de colonnes et fonctions uniquement ; journal du portail interdit
    if action == sqlite3.SQLITE_READ:
        return sqlite3.SQLITE_DENY if arg1 == 'journal_portail' else sqlite3.SQLITE_OK
    if action in (sqlite3.SQLITE_SELECT, sqlite3.SQLITE_FUNCTION):
        return sqlite3.SQLITE_OK
    return sqlite3.SQLITE_DENY


def sql_lecture(sql):
    sql = sql.strip().rstrip(';')
    if ';' in sql or not re.match(r'(?is)^\s*(select|with)\b', sql):
        raise ValueError('Seule une requête SELECT unique est autorisée.')
    cx = db.connexion(lecture_seule=True)
    try:
        cx.set_authorizer(_autoriser)
        cur = cx.execute(sql)
        cols = [c[0] for c in cur.description]
        rows = cur.fetchmany(500)
        return {'colonnes': cols, 'lignes': [list(r) for r in rows], 'tronque': len(rows) == 500}
    finally:
        cx.close()


def executer_outil(nom, entree):
    if nom == 'rechercher_evenements':
        f = {k: entree.get(k) for k in ('personne', 'compte', 'ip', 'source', 'categorie', 'resultat', 'texte', 'debut', 'fin')}
        total, rows = db.rechercher(limite=max(1, min(int(entree.get('limite') or 50), 200)), **f)
        for r in rows:
            r.pop('session', None)
        return {'total': total, 'evenements': rows}
    if nom == 'profil_personne':
        p = db.profil(entree['personne'], entree['debut'], entree['fin'])
        p['sessions'] = p['sessions'][:60]
        return p
    if nom == 'lister_personnes':
        return {'personnes': db.personnes(entree['debut'], entree['fin'], entree.get('texte'))[:200]}
    if nom == 'lister_alertes':
        return {'alertes': db.alertes(entree.get('statut'), entree.get('gravite'), entree.get('debut'), entree.get('fin'), limite=100)}
    if nom == 'requete_sql':
        return sql_lecture(entree['sql'])
    raise ValueError('Outil inconnu : %s' % nom)


def _extraire_suggestions(texte):
    m = re.search(r'^\s*SUGGESTIONS\s*:\s*(.+)$', texte, re.M)
    if not m:
        return texte.strip(), []
    sug = [s.strip(' -*') for s in m.group(1).split('|') if s.strip()]
    return (texte[:m.start()] + texte[m.end():]).strip(), sug[:3]


def repondre_ia(question, historique=None, personne=None, client=None):
    """Réponse à une question libre. historique : [{'role': 'user'|'assistant', 'texte': ...}] (texte seul)."""
    import anthropic
    client = client or anthropic.Anthropic()
    contexte = 'Date et heure actuelles du serveur : %s.' % dt.datetime.now().strftime('%A %d/%m/%Y %H:%M')
    if personne:
        contexte += ' L\'utilisateur consulte la fiche de la personne « %s ».' % personne
    messages = []
    for h in (historique or [])[-10:]:
        if h.get('role') in ('user', 'assistant') and h.get('texte'):
            messages.append({'role': h['role'], 'content': h['texte'][:6000]})
    if messages and messages[0]['role'] != 'user':
        messages = messages[1:]
    messages.append({'role': 'user', 'content': '%s\n\n%s' % (contexte, question)})
    systeme = [{'type': 'text', 'cache_control': {'type': 'ephemeral'},
                'text': SYSTEME.format(heures='%dh-%dh' % (config.heure_debut, config.heure_fin),
                                       partages=', '.join(config.comptes_partages) or 'aucun')}]
    outils = OUTILS
    tableaux = []
    for _tour in range(10):
        try:
            rep = client.beta.messages.create(
                model=config.modele, max_tokens=16000, system=systeme, tools=outils, messages=messages,
                thinking={'type': 'adaptive'}, output_config={'effort': 'medium'},
                betas=['server-side-fallback-2026-07-01'], extra_body={'fallbacks': 'default'})
        except anthropic.AuthenticationError:
            return {'texte': 'Assistant IA : clé API invalide. Les questions proposées restent disponibles.', 'suggestions': [], 'mode': 'erreur'}
        except anthropic.RateLimitError:
            return {'texte': 'Assistant IA momentanément saturé, réessayez dans une minute.', 'suggestions': [], 'mode': 'erreur'}
        except anthropic.APIStatusError as e:
            log.warning('API Anthropic %s : %s', e.status_code, e.message)
            return {'texte': 'Assistant IA indisponible (erreur %s).' % e.status_code, 'suggestions': [], 'mode': 'erreur'}
        except anthropic.APIConnectionError:
            return {'texte': 'Assistant IA injoignable (réseau). Les questions proposées restent disponibles.', 'suggestions': [], 'mode': 'erreur'}

        if rep.stop_reason == 'refusal':
            return {'texte': 'L\'assistant n\'a pas pu traiter cette demande. Reformulez-la ou utilisez une question proposée.',
                    'suggestions': [], 'mode': 'ia'}
        appels = [b for b in rep.content if b.type == 'tool_use']
        if rep.stop_reason != 'tool_use' or not appels:
            if rep.stop_reason == 'pause_turn':
                messages.append({'role': 'assistant', 'content': rep.content})
                continue
            texte = '\n'.join(b.text for b in rep.content if b.type == 'text')
            texte, sug = _extraire_suggestions(texte)
            return {'texte': texte or '(réponse vide)', 'suggestions': sug, 'mode': 'ia', 'tableaux': tableaux[-3:]}
        messages.append({'role': 'assistant', 'content': rep.content})
        resultats = []
        for b in appels:
            try:
                res = executer_outil(b.name, b.input or {})
                if b.name == 'requete_sql' and res.get('lignes'):
                    tableaux.append({'colonnes': res['colonnes'], 'lignes': res['lignes'][:100]})
                contenu, erreur = json.dumps(res, ensure_ascii=False, default=str)[:40000], False
            except Exception as e:  # erreur renvoyée à Claude pour qu'il corrige sa demande
                contenu, erreur = 'Erreur : %s' % e, True
            resultats.append({'type': 'tool_result', 'tool_use_id': b.id, 'content': contenu, 'is_error': erreur})
        messages.append({'role': 'user', 'content': resultats})
    return {'texte': 'La question demande trop d\'étapes. Précisez la période ou la personne.', 'suggestions': [], 'mode': 'ia'}


def mot_cle_vers_suggestion(question, personne=None):
    """Sans IA : rapproche une question libre d'une question proposée."""
    q = question.lower()
    regles = [
        (r'regix|partag', 'p_partage' if personne else 'partage_semaine'),
        (r'connect.*(maintenant|en ce moment|actuel)', 'connectes'),
        (r'drop|alter|grant|revoke|sensible|supprim', 'p_sensibles' if personne else 'sensibles_semaine'),
        (r'nuit|week|hors|soir', 'p_hors_heures' if personne else 'hors_heures_mois'),
        (r'nouvelle.*ip|nouvelles.*ip', 'nouvelles_ip'),
        (r'\bip\b|adresse', 'p_ip_mois' if personne else 'nouvelles_ip'),
        (r'échec|echec|mot de passe|bloqu', 'echecs_semaine'),
        (r'programme|lanc', 'p_programmes' if personne else 'actifs_mois'),
        (r'session|durée|duree|heure de connexion', 'p_sessions' if personne else 'connectes'),
        (r'hier|fait', 'p_hier' if personne else 'actifs_mois'),
        (r'alerte', 'alertes_ouvertes'),
        (r'actif|plus', 'actifs_mois'),
    ]
    for motif, sid in regles:
        if re.search(motif, q):
            return sid
    return None
