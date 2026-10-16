"""Stockage des événements (SQLite), ingestion, attribution aux personnes et requêtes du portail."""
import datetime as dt
import json
import os
import sqlite3
import threading

from .config import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS evenements (
    id INTEGER PRIMARY KEY,
    ts TEXT NOT NULL,              -- AAAA-MM-JJTHH:MM:SS (heure locale du serveur)
    jour TEXT NOT NULL,            -- AAAA-MM-JJ
    heure INTEGER NOT NULL,        -- 0..23
    source TEXT NOT NULL,          -- systeme | base | applicatif
    categorie TEXT NOT NULL,       -- connexion, deconnexion, echec_connexion, sudo, commande, ddl, droits, dml, programme...
    action TEXT NOT NULL,
    serveur TEXT,
    compte TEXT,                   -- compte technique utilisé (ex. regix)
    utilisateur TEXT,              -- utilisateur déclaré par la source
    personne TEXT,                 -- personne à qui l'action est attribuée
    attribution TEXT,              -- certaine | probable (via le poste) | compte (non résolu)
    ip TEXT, poste TEXT, session TEXT, objet TEXT,
    resultat TEXT,                 -- succes | echec
    details TEXT, brut TEXT,
    empreinte TEXT UNIQUE,
    recu TEXT
);
CREATE INDEX IF NOT EXISTS ix_ev_ts ON evenements(ts);
CREATE INDEX IF NOT EXISTS ix_ev_personne ON evenements(personne, ts);
CREATE INDEX IF NOT EXISTS ix_ev_compte ON evenements(compte, ts);
CREATE INDEX IF NOT EXISTS ix_ev_ip ON evenements(ip, ts);
CREATE INDEX IF NOT EXISTS ix_ev_source ON evenements(source, categorie, ts);
CREATE INDEX IF NOT EXISTS ix_ev_session ON evenements(session);

CREATE TABLE IF NOT EXISTS alertes (
    id INTEGER PRIMARY KEY,
    ts TEXT NOT NULL, regle TEXT NOT NULL, gravite TEXT NOT NULL,  -- faible | moyenne | haute | critique
    titre TEXT NOT NULL, message TEXT, personne TEXT, compte TEXT, ip TEXT,
    evenement_id INTEGER, statut TEXT NOT NULL DEFAULT 'ouverte',  -- ouverte | en_cours | close
    commentaire TEXT, maj TEXT,
    UNIQUE(regle, evenement_id)
);
CREATE INDEX IF NOT EXISTS ix_al_ts ON alertes(ts);

-- Affectation des postes : permet d'attribuer à une personne les actions d'un compte partagé
CREATE TABLE IF NOT EXISTS postes (ip TEXT PRIMARY KEY, personne TEXT NOT NULL, libelle TEXT);

-- Traçabilité du portail lui-même (qui a consulté quoi, questions posées à l'assistant)
CREATE TABLE IF NOT EXISTS journal_portail (id INTEGER PRIMARY KEY, ts TEXT, login TEXT, action TEXT, details TEXT);
"""

_verrou = threading.Lock()


def connexion(lecture_seule=False):
    os.makedirs(os.path.dirname(os.path.abspath(config.base)), exist_ok=True)
    if lecture_seule:
        cx = sqlite3.connect('file:%s?mode=ro' % os.path.abspath(config.base), uri=True, check_same_thread=False)
    else:
        cx = sqlite3.connect(config.base, check_same_thread=False, timeout=30)
        cx.execute('PRAGMA journal_mode=WAL')
    cx.row_factory = sqlite3.Row
    return cx


def initialiser():
    with connexion() as cx:
        cx.executescript(SCHEMA)


def lignes(cx, sql, params=()):
    return [dict(r) for r in cx.execute(sql, params).fetchall()]


# --------------------------------------------------------------------------------------------
# Ingestion
# --------------------------------------------------------------------------------------------
CHAMPS = ('ts', 'source', 'categorie', 'action', 'serveur', 'compte', 'utilisateur', 'ip', 'poste',
          'session', 'objet', 'resultat')


def attribuer(cx, ev, postes):
    """Détermine la personne réelle derrière un événement."""
    util = (ev.get('utilisateur') or '').strip()
    compte = (ev.get('compte') or '').strip()
    if util and util.lower() not in config.comptes_partages:
        return util, 'certaine'
    ip = (ev.get('ip') or '').strip()
    if ip and ip in postes:
        return postes[ip], 'probable'
    return (util or compte or 'inconnu'), 'compte'


def ingerer(evenements):
    """Insère un lot d'événements (doublons ignorés) et évalue les règles d'alerte. Retourne (insérés, alertes)."""
    from . import alertes as regles
    inseres, nb_alertes = 0, 0
    recu = dt.datetime.now().strftime('%Y-%m-%dT%H:%M:%S')
    with _verrou, connexion() as cx:
        postes = {r['ip']: r['personne'] for r in cx.execute('SELECT ip, personne FROM postes')}
        for ev in evenements:
            try:
                ts = dt.datetime.strptime(ev['ts'][:19], '%Y-%m-%dT%H:%M:%S')
            except (KeyError, ValueError, TypeError):
                continue
            if not ev.get('source') or not ev.get('categorie'):
                continue
            personne, attribution = attribuer(cx, ev, postes)
            valeurs = {k: str(ev.get(k) or '')[:2000] for k in CHAMPS}
            valeurs['resultat'] = valeurs['resultat'] or 'succes'
            cur = cx.execute(
                'INSERT OR IGNORE INTO evenements (ts, jour, heure, source, categorie, action, serveur, compte, utilisateur,'
                ' personne, attribution, ip, poste, session, objet, resultat, details, brut, empreinte, recu)'
                ' VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                (ts.strftime('%Y-%m-%dT%H:%M:%S'), ts.strftime('%Y-%m-%d'), ts.hour, valeurs['source'], valeurs['categorie'],
                 valeurs['action'], valeurs['serveur'], valeurs['compte'], valeurs['utilisateur'], personne, attribution,
                 valeurs['ip'], valeurs['poste'], valeurs['session'], valeurs['objet'], valeurs['resultat'],
                 json.dumps(ev.get('details') or {}, ensure_ascii=False)[:8000], str(ev.get('brut') or '')[:2000],
                 ev.get('empreinte') or None, recu))
            if cur.rowcount:
                inseres += 1
                e = dict(valeurs, id=cur.lastrowid, ts=ts, personne=personne, attribution=attribution,
                         details=ev.get('details') or {})
                nb_alertes += regles.evaluer(cx, e)
    return inseres, nb_alertes


def reattribuer():
    """Recalcule la personne des événements de comptes partagés après modification des postes."""
    with _verrou, connexion() as cx:
        postes = {r['ip']: r['personne'] for r in cx.execute('SELECT ip, personne FROM postes')}
        n = 0
        for r in cx.execute("SELECT id, compte, utilisateur, ip FROM evenements WHERE attribution != 'certaine'").fetchall():
            p, a = attribuer(cx, dict(r), postes)
            cx.execute('UPDATE evenements SET personne=?, attribution=? WHERE id=?', (p, a, r['id']))
            n += 1
        return n


def purger():
    limite = (dt.datetime.now() - dt.timedelta(days=config.conservation_jours)).strftime('%Y-%m-%d')
    with _verrou, connexion() as cx:
        cx.execute('DELETE FROM evenements WHERE jour < ?', (limite,))


def journaliser(login, action, details=''):
    with connexion() as cx:
        cx.execute('INSERT INTO journal_portail (ts, login, action, details) VALUES (?,?,?,?)',
                   (dt.datetime.now().strftime('%Y-%m-%dT%H:%M:%S'), login, action, str(details)[:2000]))


# --------------------------------------------------------------------------------------------
# Filtres communs
# --------------------------------------------------------------------------------------------
def filtres(debut=None, fin=None, personne=None, compte=None, ip=None, source=None, categorie=None,
            resultat=None, texte=None, poste=None):
    """Construit la clause WHERE. debut/fin : AAAA-MM-JJ (fin incluse)."""
    w, p = [], []
    if debut:
        w.append('ts >= ?'); p.append(debut[:10] + 'T00:00:00')
    if fin:
        w.append('ts <= ?'); p.append(fin[:10] + 'T23:59:59')
    for col, val in (('personne', personne), ('compte', compte), ('ip', ip), ('source', source),
                     ('categorie', categorie), ('resultat', resultat), ('poste', poste)):
        if val:
            vals = [v for v in str(val).split(',') if v]
            w.append('%s IN (%s)' % (col, ','.join('?' * len(vals)))); p.extend(vals)
    if texte:
        w.append('(action LIKE ? OR objet LIKE ? OR personne LIKE ? OR compte LIKE ? OR ip LIKE ? OR poste LIKE ? OR details LIKE ?)')
        p.extend(['%' + texte + '%'] * 7)
    return (' WHERE ' + ' AND '.join(w)) if w else '', p


COLONNES_EV = ('id, ts, source, categorie, action, serveur, compte, utilisateur, personne, attribution, ip, poste, '
               'session, objet, resultat, details')


def _decoder(rows):
    for r in rows:
        if isinstance(r.get('details'), str):
            try:
                r['details'] = json.loads(r['details'])
            except ValueError:
                pass
    return rows


def rechercher(limite=200, decalage=0, ordre='DESC', **f):
    where, p = filtres(**f)
    with connexion() as cx:
        total = cx.execute('SELECT COUNT(*) FROM evenements' + where, p).fetchone()[0]
        rows = lignes(cx, 'SELECT %s FROM evenements%s ORDER BY ts %s, id %s LIMIT ? OFFSET ?'
                      % (COLONNES_EV, where, ordre, ordre), p + [int(limite), int(decalage)])
    return total, _decoder(rows)


# --------------------------------------------------------------------------------------------
# Tableau de bord, personnes, sessions
# --------------------------------------------------------------------------------------------
def tableau_de_bord(debut, fin):
    where, p = filtres(debut=debut, fin=fin)
    partages = config.comptes_partages or ['__aucun__']
    pl = ','.join('?' * len(partages))
    with connexion() as cx:
        k = cx.execute(
            "SELECT COUNT(*) total, COUNT(DISTINCT personne) personnes, COUNT(DISTINCT NULLIF(ip,'')) ips,"
            " SUM(resultat='echec') echecs, SUM(categorie IN ('connexion')) connexions,"
            " SUM(LOWER(compte) IN (%s) AND categorie IN ('connexion','changement_compte','sudo')) partage,"
            " SUM(categorie IN ('ddl','droits')) sensibles FROM evenements%s" % (pl, where), partages + p).fetchone()
        alertes_ouvertes = cx.execute("SELECT COUNT(*) FROM alertes WHERE statut != 'close' AND ts >= ? AND ts <= ?",
                                      (debut + 'T00:00:00', fin + 'T23:59:59')).fetchone()[0]
        par_jour = lignes(cx, 'SELECT jour, source, COUNT(*) n FROM evenements%s GROUP BY jour, source ORDER BY jour' % where, p)
        top_personnes = lignes(cx, "SELECT personne, MAX(attribution='certaine') certaine, COUNT(*) n, COUNT(DISTINCT jour) jours,"
                                   " MAX(ts) derniere FROM evenements%s GROUP BY personne ORDER BY n DESC LIMIT 10" % where, p)
        top_ip = lignes(cx, "SELECT ip, GROUP_CONCAT(DISTINCT personne) personnes, COUNT(*) n, MAX(ts) derniere"
                            " FROM evenements%s%s ip != '' GROUP BY ip ORDER BY n DESC LIMIT 10"
                            % (where, ' AND' if where else ' WHERE'), p)
        partage = lignes(cx, "SELECT ts, compte, personne, attribution, ip, poste, action, source FROM evenements%s%s"
                             " LOWER(compte) IN (%s) AND categorie IN ('connexion','changement_compte','sudo')"
                             " ORDER BY ts DESC LIMIT 8" % (where, ' AND' if where else ' WHERE', pl), p + partages)
        dernieres_alertes = lignes(cx, 'SELECT * FROM alertes ORDER BY ts DESC LIMIT 8')
    return {'indicateurs': dict(k, alertes_ouvertes=alertes_ouvertes), 'par_jour': par_jour,
            'top_personnes': top_personnes, 'top_ip': top_ip, 'compte_partage': partage,
            'alertes': dernieres_alertes, 'comptes_partages': config.comptes_partages}


def personnes(debut, fin, texte=None):
    where, p = filtres(debut=debut, fin=fin)
    if texte:
        where += (' AND' if where else ' WHERE') + ' (personne LIKE ? OR compte LIKE ?)'
        p += ['%' + texte + '%'] * 2
    with connexion() as cx:
        return lignes(cx, "SELECT personne, MAX(attribution='certaine') certaine, COUNT(*) evenements,"
                          " SUM(source='systeme') systeme, SUM(source='base') base, SUM(source='applicatif') applicatif,"
                          " SUM(resultat='echec') echecs, COUNT(DISTINCT jour) jours,"
                          " GROUP_CONCAT(DISTINCT NULLIF(ip,'')) ips, GROUP_CONCAT(DISTINCT compte) comptes,"
                          " MIN(ts) premiere, MAX(ts) derniere FROM evenements%s GROUP BY personne ORDER BY personne" % where, p)


def profil(personne, debut, fin):
    where, p = filtres(debut=debut, fin=fin, personne=personne)
    with connexion() as cx:
        k = cx.execute("SELECT COUNT(*) total, SUM(source='systeme') systeme, SUM(source='base') base,"
                       " SUM(source='applicatif') applicatif, SUM(resultat='echec') echecs,"
                       " COUNT(DISTINCT jour) jours, MIN(ts) premiere, MAX(ts) derniere,"
                       " SUM(attribution='probable') probables FROM evenements" + where, p).fetchone()
        ips = lignes(cx, "SELECT ip, GROUP_CONCAT(DISTINCT NULLIF(poste,'')) postes, COUNT(*) n, MIN(ts) premiere, MAX(ts) derniere"
                         " FROM evenements%s AND ip != '' GROUP BY ip ORDER BY n DESC" % where, p)
        comptes = lignes(cx, "SELECT compte, COUNT(*) n FROM evenements%s AND compte != '' GROUP BY compte ORDER BY n DESC" % where, p)
        heures = lignes(cx, "SELECT CAST(strftime('%%w', ts) AS INTEGER) jour_semaine, heure, COUNT(*) n"
                            " FROM evenements%s GROUP BY 1, 2" % where, p)
        programmes = lignes(cx, "SELECT objet programme, COUNT(*) n, MAX(ts) dernier FROM evenements%s AND source='applicatif'"
                                " GROUP BY objet ORDER BY n DESC LIMIT 15" % where, p)
        alertes_p = lignes(cx, 'SELECT * FROM alertes WHERE personne = ? AND ts >= ? AND ts <= ? ORDER BY ts DESC LIMIT 20',
                           (personne, debut + 'T00:00:00', fin + 'T23:59:59'))
    return {'personne': personne, 'indicateurs': dict(k), 'ips': ips, 'comptes': comptes, 'heures': heures,
            'programmes': programmes, 'alertes': alertes_p, 'sessions': sessions(personne, debut, fin)}


def sessions(personne, debut, fin, limite=300):
    """Associe ouvertures et fermetures de session (système et base) par identifiant de session."""
    where, p = filtres(debut=debut, fin=fin, personne=personne)
    with connexion() as cx:
        ouv = lignes(cx, "SELECT ts, source, compte, ip, poste, session, action FROM evenements%s AND categorie='connexion'"
                         " ORDER BY ts DESC LIMIT ?" % where, p + [limite])
        ids = [o['session'] for o in ouv if o['session']]
        fins = {}
        for i in range(0, len(ids), 500):
            lot = ids[i:i + 500]
            for r in cx.execute("SELECT session, MIN(ts) ts, details FROM evenements WHERE categorie='deconnexion'"
                                " AND session IN (%s) GROUP BY session" % ','.join('?' * len(lot)), lot):
                fins[r['session']] = r['ts']
        nb = {}
        for i in range(0, len(ids), 500):
            lot = ids[i:i + 500]
            for r in cx.execute("SELECT session, COUNT(*) n FROM evenements WHERE session IN (%s)"
                                " AND categorie NOT IN ('connexion','deconnexion') GROUP BY session" % ','.join('?' * len(lot)), lot):
                nb[r['session']] = r['n']
    for o in ouv:
        o['fin'] = fins.get(o['session'])
        o['duree_s'] = int((dt.datetime.fromisoformat(o['fin']) - dt.datetime.fromisoformat(o['ts'])).total_seconds()) if o['fin'] else None
        o['operations'] = nb.get(o['session'], 0)
    return ouv


def alertes(statut=None, gravite=None, debut=None, fin=None, limite=500):
    w, p = [], []
    if statut:
        w.append('statut = ?'); p.append(statut)
    if gravite:
        w.append('gravite = ?'); p.append(gravite)
    if debut:
        w.append('ts >= ?'); p.append(debut + 'T00:00:00')
    if fin:
        w.append('ts <= ?'); p.append(fin + 'T23:59:59')
    with connexion() as cx:
        return lignes(cx, 'SELECT * FROM alertes%s ORDER BY ts DESC LIMIT ?' % ((' WHERE ' + ' AND '.join(w)) if w else ''),
                      p + [limite])


def maj_alerte(id_alerte, statut, commentaire, login):
    with connexion() as cx:
        cx.execute('UPDATE alertes SET statut=?, commentaire=?, maj=? WHERE id=?',
                   (statut, '%s (%s)' % (commentaire or '', login), dt.datetime.now().strftime('%Y-%m-%dT%H:%M:%S'), id_alerte))


def lister_postes():
    with connexion() as cx:
        return lignes(cx, 'SELECT * FROM postes ORDER BY ip')


def definir_poste(ip, personne, libelle=''):
    with connexion() as cx:
        if personne:
            cx.execute('INSERT OR REPLACE INTO postes (ip, personne, libelle) VALUES (?,?,?)', (ip, personne, libelle))
        else:
            cx.execute('DELETE FROM postes WHERE ip = ?', (ip,))
    return reattribuer()
