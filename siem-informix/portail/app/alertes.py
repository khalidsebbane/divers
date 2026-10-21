"""Règles d'alerte, évaluées à l'ingestion de chaque nouvel événement."""
import datetime as dt

from .config import config

GRAVITES = ('faible', 'moyenne', 'haute', 'critique')


def _creer(cx, e, regle, gravite, titre, message):
    cur = cx.execute(
        'INSERT OR IGNORE INTO alertes (ts, regle, gravite, titre, message, personne, compte, ip, evenement_id)'
        ' VALUES (?,?,?,?,?,?,?,?,?)',
        (e['ts'].strftime('%Y-%m-%dT%H:%M:%S'), regle, gravite, titre, message, e['personne'], e['compte'], e['ip'], e['id']))
    return cur.rowcount


def _qui(e):
    if e['attribution'] == 'probable':
        return '%s (probable, d\'après le poste %s)' % (e['personne'], e['ip'])
    if e['attribution'] == 'compte':
        return 'personne non identifiée'
    return e['personne']


def evaluer(cx, e):
    n = 0
    compte = (e['compte'] or '').lower()
    hors = config.hors_heures(e['ts'])
    quand = e['ts'].strftime('%d/%m/%Y %H:%M')

    # 1. Utilisation humaine d'un compte partagé (regix...) :
    #    - côté système : connexion directe au compte (SSH) sans identité certaine. Un sudo/su depuis un compte
    #      nominatif est tracé (personne certaine) et n'est signalé que hors heures ouvrées ;
    #    - côté base : l'application se connecte normalement avec ce compte, on ne signale que
    #      les sessions hors heures ouvrées.
    partage = compte in config.comptes_partages and e['categorie'] in ('connexion', 'changement_compte', 'sudo')
    if partage and ((e['source'] == 'systeme' and e['attribution'] != 'certaine') or hors):
        gravite = 'haute' if (hors or e['attribution'] == 'compte') else 'moyenne'
        motif = ' hors heures ouvrées' if hors else (' depuis un poste non affecté' if e['attribution'] == 'compte' else '')
        n += _creer(cx, e, 'compte_partage', gravite, 'Utilisation du compte partagé %s%s' % (e['compte'], motif),
                    '%s le %s depuis %s : %s' % (_qui(e), quand, e['ip'] or 'origine inconnue', e['action']))

    # 2. Connexion hors heures ouvrées
    elif config.alerte_hors_heures and hors and e['categorie'] == 'connexion' and e['source'] in ('systeme', 'base'):
        n += _creer(cx, e, 'hors_heures', 'faible', 'Connexion hors heures ouvrées',
                    '%s le %s depuis %s (%s)' % (_qui(e), quand, e['ip'] or 'origine inconnue', e['action']))

    # 3. Opérations sensibles en base
    if e['source'] == 'base' and e['categorie'] in ('ddl', 'droits'):
        suppression = e['action'].startswith('Suppression') or 'REVOKE' in e['action']
        gravite = 'critique' if (suppression and hors) else 'haute' if (suppression or e['categorie'] == 'droits') else 'moyenne'
        n += _creer(cx, e, 'operation_sensible', gravite, '%s : %s' % (e['action'], e['objet'] or ''),
                    '%s le %s (compte %s)' % (_qui(e), quand, e['compte']))

    # 4. Modification de la configuration, des comptes ou de sudo sur le serveur
    cle = (e.get('details') or {}).get('cle', '') if isinstance(e.get('details'), dict) else ''
    if cle in ('siem_identite', 'siem_sudoers', 'siem_conf_informix'):
        n += _creer(cx, e, 'modification_systeme', 'haute', e['action'],
                    '%s le %s : %s' % (_qui(e), quand, e['objet']))

    # 5. Échecs de connexion répétés depuis une même IP
    if e['resultat'] == 'echec' and e['categorie'] == 'echec_connexion' and e['ip']:
        depuis = (e['ts'] - dt.timedelta(minutes=10)).strftime('%Y-%m-%dT%H:%M:%S')
        nb = cx.execute("SELECT COUNT(*) FROM evenements WHERE ip=? AND categorie='echec_connexion' AND ts>=? AND ts<=?",
                        (e['ip'], depuis, e['ts'].strftime('%Y-%m-%dT%H:%M:%S'))).fetchone()[0]
        deja = cx.execute("SELECT COUNT(*) FROM alertes WHERE regle='echecs_repetes' AND ip=? AND ts>=?",
                          (e['ip'], (e['ts'] - dt.timedelta(hours=1)).strftime('%Y-%m-%dT%H:%M:%S'))).fetchone()[0]
        if nb >= config.seuil_echecs and not deja:
            n += _creer(cx, e, 'echecs_repetes', 'haute', 'Échecs de connexion répétés depuis %s' % e['ip'],
                        '%d échecs en 10 minutes (dernier compte essayé : %s)' % (nb, e['compte']))

    # 6. Nouvelle adresse IP pour une personne déjà connue
    if e['categorie'] == 'connexion' and e['ip'] and e['ip'] != 'local' and e['attribution'] == 'certaine':
        avant = e['ts'].strftime('%Y-%m-%dT%H:%M:%S')
        historique = cx.execute('SELECT COUNT(*) FROM evenements WHERE personne=? AND ts<?', (e['personne'], avant)).fetchone()[0]
        deja_vue = cx.execute('SELECT 1 FROM evenements WHERE personne=? AND ip=? AND ts<? LIMIT 1',
                              (e['personne'], e['ip'], avant)).fetchone()
        if historique >= 20 and not deja_vue:
            n += _creer(cx, e, 'nouvelle_ip', 'moyenne', 'Nouvelle adresse IP pour %s' % e['personne'],
                        'Première connexion depuis %s%s le %s' % (e['ip'], ' (%s)' % e['poste'] if e['poste'] else '', quand))
    return n
