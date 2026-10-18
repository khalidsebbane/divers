"""Tests du portail : ingestion, attribution, alertes, API, assistant (avec un faux client Claude)."""
import datetime as dt
import os
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'portail'))


@pytest.fixture()
def portail(tmp_path, monkeypatch):
    monkeypatch.setenv('SIEM_BASE', str(tmp_path / 'siem.db'))
    monkeypatch.setenv('SIEM_JETON_COLLECTEUR', 'jeton')
    monkeypatch.setenv('SIEM_ASSISTANT_IA', 'non')
    monkeypatch.setenv('SIEM_COOKIE_SECURISE', 'non')
    from app import config as cfg
    cfg.config.__init__()
    from app import auth, db, main
    auth._echecs.clear()
    db.initialiser()
    main.ajouter_compte('admin', 'motdepasse-admin', 'admin')
    main.ajouter_compte('lecteur', 'motdepasse-lecteur', 'lecteur')
    from fastapi.testclient import TestClient
    with TestClient(main.app, headers={'X-SIEM': '1'}) as client:
        yield client, db


def connecter(client, login='admin', mdp='motdepasse-admin'):
    client.cookies.clear()
    r = client.post('/api/connexion', json={'login': login, 'mot_de_passe': mdp})
    assert r.status_code == 200, r.text
    return client


def ev(ts, **k):
    base = {'ts': ts, 'source': 'systeme', 'categorie': 'connexion', 'action': 'Ouverture de session SSH', 'compte': 'regix',
            'utilisateur': '', 'ip': '10.1.1.1', 'session': 's1', 'resultat': 'succes'}
    base.update(k)
    base['empreinte'] = '|'.join(str(v) for v in base.values())
    return base


def test_ingestion_attribution_alertes(portail):
    client, db = portail
    assert client.post('/api/ingestion', json={'evenements': []}, headers={'X-Jeton': 'mauvais'}).status_code == 401
    db.definir_poste('10.1.1.1', 'jdupont', 'PC-021')
    lot = [ev('2026-09-02T23:10:00'),
           ev('2026-09-02T23:15:00', source='base', categorie='ddl', action='Suppression de table', objet='prod:t', ip='10.9.9.9')]
    r = client.post('/api/ingestion', json={'evenements': lot}, headers={'X-Jeton': 'jeton'}).json()
    assert r['inseres'] == 2
    # doublons ignorés
    assert client.post('/api/ingestion', json={'evenements': lot}, headers={'X-Jeton': 'jeton'}).json()['inseres'] == 0
    _, rows = db.rechercher(debut='2026-09-01', fin='2026-09-30', ordre='ASC')
    assert (rows[0]['personne'], rows[0]['attribution']) == ('jdupont', 'probable')
    assert (rows[1]['personne'], rows[1]['attribution']) == ('regix', 'compte')
    regles = {(a['regle'], a['gravite']) for a in db.alertes()}
    assert ('compte_partage', 'haute') in regles  # compte partagé hors heures
    assert ('operation_sensible', 'critique') in regles  # suppression la nuit


def test_echecs_repetes_et_nouvelle_ip(portail):
    client, db = portail
    lot = [ev('2026-09-03T03:00:%02d' % i, categorie='echec_connexion', resultat='echec', ip='10.6.6.6', session='') for i in range(6)]
    hist = [ev('2026-09-%02dT09:00:00' % (1 + i // 5), compte='kbenali', utilisateur='kbenali', ip='10.12.8.40',
               session='h%d' % i, action='a%d' % i) for i in range(25)]
    hist.append(ev('2026-09-10T10:00:00', compte='kbenali', utilisateur='kbenali', ip='192.168.50.14', session='n'))
    db.ingerer(lot + hist)
    regles = [a['regle'] for a in db.alertes()]
    assert regles.count('echecs_repetes') == 1
    assert 'nouvelle_ip' in regles


def test_api_authentification_et_roles(portail):
    client, db = portail
    assert client.get('/api/moi').status_code == 401
    assert client.get('/', follow_redirects=False).headers['location'] == '/connexion'
    assert client.post('/api/connexion', json={'login': 'admin', 'mot_de_passe': 'faux'}).status_code == 401
    assert client.post('/api/connexion', json={'login': 'admin', 'mot_de_passe': ''}).status_code == 401
    connecter(client, 'lecteur', 'motdepasse-lecteur')
    moi = client.get('/api/moi').json()
    assert (moi['role'], moi['source']) == ('lecteur', 'local')
    assert client.post('/api/postes', json={'ip': '1.1.1.1', 'personne': 'x'}).status_code == 403
    assert client.get('/api/admin/sources').status_code == 403
    connecter(client)
    assert client.post('/api/postes', json={'ip': '1.1.1.1', 'personne': 'x'}).status_code == 200
    assert client.get('/').status_code == 200
    # protection CSRF : une écriture sans l'en-tête X-SIEM est refusée
    assert client.post('/api/postes', json={'ip': '1.1.1.2', 'personne': 'y'}, headers={'X-SIEM': ''}).status_code == 403
    # déconnexion : la session ne vaut plus rien
    client.post('/api/deconnexion')
    assert client.get('/api/moi').status_code == 401
    journal = [j['action'] for j in db.journal()]
    assert 'echec_connexion' in journal and 'connexion' in journal and 'deconnexion' in journal


def test_verrouillage_apres_echecs(portail):
    client, _db = portail
    for _ in range(5):
        client.post('/api/connexion', json={'login': 'admin', 'mot_de_passe': 'faux'})
    r = client.post('/api/connexion', json={'login': 'admin', 'mot_de_passe': 'motdepasse-admin'})
    assert r.status_code == 401 and 'Trop de tentatives' in r.json()['detail']


def test_marque_et_logo(portail, tmp_path, monkeypatch):
    client, _db = portail
    from app.config import config
    logo = os.path.join(os.path.dirname(__file__), '..', 'deploiement', 'tractafric', 'logo.png')
    monkeypatch.setattr(config, 'marque_nom', 'Tractafric Equipment')
    monkeypatch.setattr(config, 'marque_couleur', '#FFC50C')
    monkeypatch.setattr(config, 'marque_logo', logo)
    m = client.get('/api/marque').json()
    assert m['nom'] == 'Tractafric Equipment' and m['logo'] == '/marque/logo'
    assert client.get('/marque/logo').headers['content-type'] == 'image/png'
    assert '--sur-marque:#111111' in client.get('/marque.css').text   # texte noir sur jaune
    assert client.get('/connexion').status_code == 200
    assert "frame-ancestors 'none'" in client.get('/connexion').headers['content-security-policy']


def _ad_simule(monkeypatch):
    from ldap3 import MOCK_SYNC, OFFLINE_AD_2012_R2, Connection, Server
    from ldap3.core.exceptions import LDAPBindError
    from app import auth
    from app.config import config
    serveur = Server('ad-simule', get_info=OFFLINE_AD_2012_R2)
    base = Connection(serveur, user='cn=svc-siem,dc=tf,dc=local', password='mdp-svc', client_strategy=MOCK_SYNC)
    admins, lecteurs = 'CN=GG_SIEM_Admins,OU=Groupes,DC=tf,DC=local', 'CN=GG_SIEM_Lecteurs,OU=Groupes,DC=tf,DC=local'
    base.strategy.add_entry('cn=svc-siem,dc=tf,dc=local', {'userPassword': 'mdp-svc', 'objectClass': 'user', 'sAMAccountName': 'svc-siem'})
    base.strategy.add_entry('cn=Karim Benali,ou=dsi,dc=tf,dc=local', {'userPassword': 'Secret-AD-1', 'objectClass': 'user',
        'sAMAccountName': 'kbenali', 'displayName': 'Karim Benali', 'memberOf': [admins], 'userAccountControl': 512})
    base.strategy.add_entry('cn=Jean Dupont,ou=compta,dc=tf,dc=local', {'userPassword': 'Secret-AD-2', 'objectClass': 'user',
        'sAMAccountName': 'jdupont', 'displayName': 'Jean Dupont', 'memberOf': [lecteurs], 'userAccountControl': 512})
    base.strategy.add_entry('cn=Ex Salarie,ou=compta,dc=tf,dc=local', {'userPassword': 'Secret-AD-3', 'objectClass': 'user',
        'sAMAccountName': 'exsal', 'memberOf': [admins], 'userAccountControl': 514})
    base.strategy.add_entry('cn=Stagiaire,ou=compta,dc=tf,dc=local', {'userPassword': 'Secret-AD-4', 'objectClass': 'user',
        'sAMAccountName': 'stagiaire', 'memberOf': [], 'userAccountControl': 512})

    def fabrique(utilisateur, mdp):
        cx = Connection(serveur, user=utilisateur, password=mdp, client_strategy=MOCK_SYNC)
        if not cx.bind():
            raise LDAPBindError('invalidCredentials')
        return cx
    monkeypatch.setattr(auth, 'fabrique_connexion', fabrique)
    for k, v in {'ad_serveurs': ['ldaps://dc1.tf.local'], 'ad_base_dn': 'dc=tf,dc=local', 'ad_compte_service': 'cn=svc-siem,dc=tf,dc=local',
                 'ad_mdp_service': 'mdp-svc', 'ad_groupe_admin': admins, 'ad_groupe_lecteur': lecteurs}.items():
        monkeypatch.setattr(config, k, v)


def test_connexion_active_directory(portail, monkeypatch):
    client, _db = portail
    _ad_simule(monkeypatch)
    connecter(client, 'TF\\kbenali', 'Secret-AD-1')
    moi = client.get('/api/moi').json()
    assert (moi['login'], moi['role'], moi['source'], moi['nom']) == ('kbenali', 'admin', 'ad', 'Karim Benali')
    connecter(client, 'jdupont@tf.local', 'Secret-AD-2')
    assert client.get('/api/moi').json()['role'] == 'lecteur'
    client.cookies.clear()
    assert client.post('/api/connexion', json={'login': 'jdupont', 'mot_de_passe': 'faux'}).status_code == 401
    assert client.post('/api/connexion', json={'login': 'exsal', 'mot_de_passe': 'Secret-AD-3'}).status_code == 401   # compte désactivé
    r = client.post('/api/connexion', json={'login': 'stagiaire', 'mot_de_passe': 'Secret-AD-4'})
    assert r.status_code == 401 and 'groupe AD' in r.json()['detail']
    # le compte local de secours fonctionne même si l'AD est configuré
    connecter(client, 'admin', 'motdepasse-admin')
    assert client.get('/api/moi').json()['source'] == 'local'


def test_ad_indisponible_message_clair(portail, monkeypatch):
    client, _db = portail
    _ad_simule(monkeypatch)
    from ldap3.core.exceptions import LDAPSocketOpenError
    from app import auth

    def panne(*_a):
        raise LDAPSocketOpenError('injoignable')
    monkeypatch.setattr(auth, 'fabrique_connexion', panne)
    r = client.post('/api/connexion', json={'login': 'kbenali', 'mot_de_passe': 'Secret-AD-1'})
    assert r.status_code == 401 and 'compte local de secours' in r.json()['detail']


def test_collecte_pilotee_locale(portail, tmp_path):
    """Le portail lance le collecteur (mode local, équivalent du SSH à commande forcée) et ingère le résultat."""
    import socket as so
    import struct
    import time
    client, db = portail
    connecter(client)
    wtmp = tmp_path / 'wtmp'
    fmt = '<hi32s4s32s256shhiii16s20s'
    d = int(time.mktime(dt.datetime(2026, 9, 1, 8, 0).timetuple()))
    wtmp.write_bytes(struct.pack(fmt, 7, 1, b'pts/0', b'ts/0', b'kbenali', b'10.12.8.40', 0, 0, 0, d, 0,
                                 so.inet_aton('10.12.8.40') + b'\0' * 12, b'\0' * 20))
    collecteur = os.path.join(os.path.dirname(__file__), '..', 'collecteur', 'collecteur.py')
    r = client.post('/api/admin/sources', json={'nom': 'srv-test', 'hote': 'localhost', 'mode': 'local', 'python': sys.executable,
                                                'chemin_collecteur': collecteur,
                                                'config': {'collecteur': {'sources': 'wtmp', 'historique_jours': '3650'},
                                                           'systeme': {'wtmp': str(wtmp)}}})
    sid = r.json()['id']
    assert client.post('/api/admin/sources/%d/tester' % sid).json()['ok']
    from app import collecte
    res = collecte.executer(sid)
    assert res['statut'] == 'ok' and res['nouveaux'] == 1
    assert collecte.executer(sid)['nouveaux'] == 0          # reprise au dernier point : pas de doublon
    src = collecte.source(sid)
    assert src['etat']['points']['wtmp'] == '2026-09-01T08:00:00' and src['evenements_total'] == 1
    sante = client.get('/api/collecte/sante').json()
    assert sante[0]['etat'] == 'ok'
    _, evts = db.rechercher(personne='kbenali')
    assert evts[0]['ip'] == '10.12.8.40'
    # authorized_keys proposé : commande forcée, sans shell ni redirection
    ak = client.get('/api/admin/sources').json()[0]['authorized_keys']
    assert 'command="sudo' in ak and '--distant' in ak and 'no-pty' in ak and 'no-port-forwarding' in ak


def test_comptes_locaux_dernier_admin(portail):
    client, _db = portail
    connecter(client)
    assert client.post('/api/admin/comptes', json={'login': 'secours', 'mot_de_passe': 'court', 'role': 'admin'}).status_code == 400
    assert client.post('/api/admin/comptes', json={'login': 'secours', 'mot_de_passe': 'un-mot-de-passe-long', 'role': 'lecteur'}).status_code == 200
    assert client.delete('/api/admin/comptes/admin').status_code == 400    # dernier administrateur local
    assert client.delete('/api/admin/comptes/secours').status_code == 200


def test_demo_tableau_fiche_export(portail):
    client, db = portail
    from app.demo import generer
    db.ingerer(generer(40))
    connecter(client)
    d = client.get('/api/tableau-de-bord').json()
    assert d['indicateurs']['total'] > 1000 and d['par_jour']
    f = client.get('/api/personnes/kbenali').json()
    assert f['indicateurs']['total'] > 0 and f['sessions'] and f['ips']
    assert any(s['fin'] for s in f['sessions'])
    csv = client.get('/api/evenements.csv?personne=kbenali')
    assert csv.status_code == 200 and csv.text.startswith('﻿Date;Heure;Volet')
    assert client.get('/api/evenements?texte=onconfig').json()['total'] >= 1


def test_assistant_suggestions_sans_ia(portail):
    client, db = portail
    from app.demo import generer
    db.ingerer(generer(40))
    connecter(client)
    sugg = client.get('/api/assistant/suggestions?personne=kbenali').json()['suggestions']
    assert len(sugg) >= 12
    for s in sugg:
        r = client.post('/api/assistant', json={'suggestion': s['id'], 'alerte': s.get('alerte'), 'personne': s.get('personne')})
        assert r.status_code == 200, s
        assert r.json()['texte'] and r.json()['mode'] == 'direct'
    # question libre sans IA : rapprochée d'une question proposée
    r = client.post('/api/assistant', json={'question': 'qui a utilisé regix ?'}).json()
    assert 'regix' in r['texte'] and r['tableaux']


def test_sql_lecture_seule(portail):
    _client, db = portail
    from app import assistant
    assert assistant.sql_lecture('SELECT COUNT(*) FROM evenements')['lignes'] == [[0]]
    for sql in ('DELETE FROM evenements', 'SELECT 1; DROP TABLE evenements', 'SELECT * FROM journal_portail',
                'WITH x AS (SELECT 1) INSERT INTO postes VALUES (1,2,3)'):
        with pytest.raises(Exception):
            assistant.sql_lecture(sql)


class FauxClaude:
    """Simule client.beta.messages.create : un appel d'outil, puis une réponse finale."""

    def __init__(self):
        self.appels = []
        self.beta = SimpleNamespace(messages=SimpleNamespace(create=self.create))

    def create(self, **k):
        self.appels.append(k)
        if len(self.appels) == 1:
            return SimpleNamespace(stop_reason='tool_use', content=[
                SimpleNamespace(type='tool_use', id='t1', name='requete_sql',
                                input={'sql': "SELECT personne, COUNT(*) n FROM evenements GROUP BY personne"})])
        return SimpleNamespace(stop_reason='end_turn', content=[
            SimpleNamespace(type='text', text='Synthèse : **2 personnes**.\nSUGGESTIONS: Et hier ? | Quelles IP ? | Quels programmes ?')])


def test_assistant_ia_boucle_outils(portail):
    _client, db = portail
    db.ingerer([ev('2026-09-02T10:00:00', compte='a', utilisateur='a'), ev('2026-09-02T11:00:00', compte='b', utilisateur='b')])
    from app import assistant
    faux = FauxClaude()
    r = assistant.repondre_ia('Qui est actif ?', historique=[{'role': 'user', 'texte': 'bonjour'}, {'role': 'assistant', 'texte': 'oui'}],
                              client=faux)
    assert r['texte'] == 'Synthèse : **2 personnes**.'
    assert r['suggestions'] == ['Et hier ?', 'Quelles IP ?', 'Quels programmes ?']
    assert r['tableaux'][0]['lignes']
    second = faux.appels[1]
    assert second['model'] == 'claude-opus-5-5' and second['thinking'] == {'type': 'adaptive'}
    assert second['messages'][-1]['content'][0]['type'] == 'tool_result'
    assert second['messages'][0] == {'role': 'user', 'content': 'bonjour'}
