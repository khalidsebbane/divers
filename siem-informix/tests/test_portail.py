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
    from app import config as cfg
    cfg.config.__init__()
    from app import db, main
    db.initialiser()
    main.ajouter_compte('admin', 'motdepasse-admin', 'admin')
    main.ajouter_compte('lecteur', 'motdepasse-lecteur', 'lecteur')
    from fastapi.testclient import TestClient
    with TestClient(main.app) as client:
        yield client, db


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
    assert client.get('/api/moi', auth=('admin', 'faux')).status_code == 401
    assert client.get('/api/moi', auth=('lecteur', 'motdepasse-lecteur')).json()['role'] == 'lecteur'
    assert client.post('/api/postes', json={'ip': '1.1.1.1', 'personne': 'x'}, auth=('lecteur', 'motdepasse-lecteur')).status_code == 403
    assert client.post('/api/postes', json={'ip': '1.1.1.1', 'personne': 'x'}, auth=('admin', 'motdepasse-admin')).status_code == 200
    assert client.get('/', auth=('admin', 'motdepasse-admin')).status_code == 200


def test_demo_tableau_fiche_export(portail):
    client, db = portail
    from app.demo import generer
    db.ingerer(generer(40))
    a = ('admin', 'motdepasse-admin')
    d = client.get('/api/tableau-de-bord', auth=a).json()
    assert d['indicateurs']['total'] > 1000 and d['par_jour']
    f = client.get('/api/personnes/kbenali', auth=a).json()
    assert f['indicateurs']['total'] > 0 and f['sessions'] and f['ips']
    assert any(s['fin'] for s in f['sessions'])
    csv = client.get('/api/evenements.csv?personne=kbenali', auth=a)
    assert csv.status_code == 200 and csv.text.startswith('﻿Date;Heure;Volet')
    assert client.get('/api/evenements?texte=onconfig', auth=a).json()['total'] >= 1


def test_assistant_suggestions_sans_ia(portail):
    client, db = portail
    from app.demo import generer
    db.ingerer(generer(40))
    a = ('admin', 'motdepasse-admin')
    sugg = client.get('/api/assistant/suggestions?personne=kbenali', auth=a).json()['suggestions']
    assert len(sugg) >= 12
    for s in sugg:
        r = client.post('/api/assistant', json={'suggestion': s['id'], 'alerte': s.get('alerte'), 'personne': s.get('personne')}, auth=a)
        assert r.status_code == 200, s
        assert r.json()['texte'] and r.json()['mode'] == 'direct'
    # question libre sans IA : rapprochée d'une question proposée
    r = client.post('/api/assistant', json={'question': 'qui a utilisé regix ?'}, auth=a).json()
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
