# -*- coding: utf-8 -*-
import datetime as dt
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

ICI = os.path.dirname(os.path.abspath(__file__))
RACINE = os.path.dirname(ICI)
sys.path.insert(0, os.path.join(RACINE, 'collecteur'))
sys.path.insert(0, os.path.join(RACINE, 'portail'))
import collecte_infra as c  # noqa: E402
import demo  # noqa: E402
import generer_portail as g  # noqa: E402

ONSTAT_ENTETE = 'IBM Informix Dynamic Server Version 14.10.FC7WE -- On-Line (Prim) -- Up 12 days 03:22:11 -- 23456789 Kbytes\n'
ONSTAT_P = ONSTAT_ENTETE + """
Profile
dskreads   pagreads   bufreads   %cached dskwrits   pagwrits   bufwrits   %cached
120000     150000     98000000   99.88   40000      60000      900000     95.56

isamtot    open       start      read       write      rewrite    delete     commit     rollbk
1000       10         20         30         40         50         60         70         0

ovlock     ovuserthread ovbuff     usercpu  syscpu   numckpts   flushes
0          0            0          100.0    20.0     500        1000

bufwaits   lokwaits   lockreqs   deadlks    dltouts    ckpwaits   compress   seqscans
2200       12         900000     1          0          34         5          4100
"""
ONSTAT_CKP = ONSTAT_ENTETE + """
                                                                    Critical Sections                          Physical Log    Logical Log
           Clock                                  Total Flush Block #      Ckpt  Wait  Long  # Dirty   Dskflu  Llog       Total Avg     Total   Avg
Interval   Time      Trigger    LSN               Time  Time  Time  Waits  Time  Time  Time  Buffers   /Sec    Pages      Pages /Sec    Pages   /Sec
41200      10:22:31  CKPTINTVL  1234:0x3456018    0.5   0.4   0.0   0      0.0   0.0   0.0   1234      2468    400        2000  6       3000    10
41201      10:27:31  *User      1234:0x3b56018    15.8  14.9  9.2   37     0.1   0.2   0.2   98765     6600    9000       5000  16      9000    30
"""
ONSTAT_L = ONSTAT_ENTETE + """
Logical Logging
address          number   flags    uniqid   begin                size     used    %used
44d5bf98         1        U-B----  1001     3:53                 5000     5000   100.00
44d5c000         2        U---C-L  1002     3:5053               5000     1200    24.00
44d5c068         3        F------  0        3:10053              5000        0     0.00
"""


def test_profil_et_cache():
    p = c.parse_profil(ONSTAT_P)
    assert p['bufreads'] == 98000000 and p['ckpwaits'] == 34 and p['seqscans'] == 4100
    assert c.ratio_cache(p) == round(100 * (1 - 150000 / 98000000.0), 2)  # pages lues sur disque / lectures logiques


def test_entete_checkpoints_logs():
    e = c.parse_onstat_entete(ONSTAT_ENTETE)
    assert e['version'] == '14.10.FC7WE' and e['mode'] == 'On-Line (Prim)' and e['memoire_ko'] == 23456789
    ck = c.parse_checkpoints(ONSTAT_CKP)
    assert [x['total_s'] for x in ck] == [0.5, 15.8] and ck[1]['declencheur'] == '*User' and ck[1]['attentes'] == 37
    assert c.parse_logs(ONSTAT_L) == {'nombre': 3, 'utilises': 2, 'non_sauvegardes': 1}


def test_systeme_meminfo_df():
    m = c.parse_meminfo('MemTotal: 1000 kB\nMemAvailable: 250 kB\nSwapTotal: 100 kB\nSwapFree: 75 kB\n')
    assert m['pct'] == 75.0 and m['swap_pct'] == 25.0
    d = c.parse_df('Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/sda1 1000 870 130 87% /data\n')
    assert d == [{'fs': '/dev/sda1', 'montage': '/data', 'taille_ko': 1000, 'utilise_ko': 870, 'pct': 87.0}]


def test_crontab_et_journal_cron():
    sysf = 'SHELL=/bin/bash\n# commentaire\n*/15 * * * * root /x/collecte.sh >/dev/null 2>&1\n@reboot root /x/demarrer.sh\n'
    t = c.parse_crontab(sysf, '/etc/crontab')
    assert [(x['utilisateur'], x['planification'], x['commande']) for x in t] == [
        ('root', '*/15 * * * *', '/x/collecte.sh >/dev/null 2>&1'), ('root', '@reboot', '/x/demarrer.sh')]
    u = c.parse_crontab('MAILTO=""\n0 22 * * 1-5 fglrun /irium/bin/Xp_cron_maj_stock.42r\n', 'crontab irium', 'irium')
    assert u[0]['utilisateur'] == 'irium' and u[0]['commande'].startswith('fglrun')
    maint = dt.datetime(2026, 11, 4, 10, 0, 0)
    log = ('Nov  4 09:45:01 srv CROND[123]: (root) CMD (/x/collecte.sh >/dev/null 2>&1)\n'
           'Nov  4 09:30:01 srv CROND[122]: (root) CMD (/x/collecte.sh >/dev/null 2>&1)\n'
           'Nov  1 09:30:01 srv CROND[100]: (root) CMD (/x/collecte.sh >/dev/null 2>&1)\n')
    e = c.parse_log_cron(log, maintenant=maint)['root|/x/collecte.sh >/dev/null 2>&1']
    assert e == {'nombre': 2, 'derniere': '2026-11-04 09:45:01'}


def test_connexions_colonnes_et_classement_cron():
    cols = ['alds_id', 'alds_user', 'alds_prog', 'alds_host', 'alds_open', 'alds_close', 'alds_complement']
    r = c.deviner_colonnes(cols, {})
    assert r == {'date': 'alds_open', 'fin': 'alds_close', 'utilisateur': 'alds_user', 'programme': 'alds_prog',
                 'poste': 'alds_host', 'complement': 'alds_complement'}
    e = c.expression_cron(r, {'MOTIFS_CRON': 'Xp_cron*', 'COMPTES_CRON': "batch o'neil"})
    assert e == "CASE WHEN alds_complement MATCHES 'Xp_cron*' OR alds_user IN ('batch', 'oneil') THEN 'cron' ELSE 'interactif' END"
    assert c.expression_cron({'date': 'd'}, {}) == "'interactif'"


def test_unload():
    assert c.parse_unload('a|b\\|c|d|\nligne\\\nsuite|x|\n') == [['a', 'b|c', 'd'], ['ligne\nsuite', 'x']]


def test_description_cron_et_categories():
    cas = {'*/15 * * * *': 'toutes les 15 min', '30 1 * * *': 'tous les jours à 01:30',
           '0 6 * * 1-5': 'du lundi au vendredi à 06:00', '*/10 7-19 * * 1-5': 'toutes les 10 min de 7h à 20h, du lundi au vendredi',
           '0 3 * * 0': 'chaque dimanche à 03:00', '0 4 1 * *': 'le 1er de chaque mois à 04:00', '@reboot': 'au démarrage du serveur',
           '5 8,12 * * *': 'tous les jours à 08:05, 12:05', '1 2 3 4 5': '1 2 3 4 5'}
    for p, attendu in cas.items():
        assert g.decrire_cron(p) == attendu, p
    assert g.categorie_tache('fglrun /irium/bin/Xp_cron_purge.42r') == 'IRIUM'
    assert g.categorie_tache('dbaccess magix_prod update_statistics.sql') == 'Informix'
    assert g.categorie_tache('/home/informix/sauve.sh # onbar -b -l') == 'Sauvegarde'
    assert g.categorie_tache('/opt/x/collecte.sh') == 'Portail'


def test_alertes():
    s = g.seuils({})
    maint = dt.datetime(2026, 11, 4, 10, 0, 0)
    srv = {'nom': 'BDD', 'role': 'bdd', 'hote': 'srv-bdd01'}
    assert [a['gravite'] for a in g.analyser_serveur(srv, None, s, maint)] == ['critique']
    snap = {'role': 'bdd', 'horodatage': '2026-11-04 09:55:00', 'erreurs': [],
            'systeme': {'cpu_pct': 30, 'memoire': {'pct': 50, 'swap_pct': 0}, 'disques': [{'montage': '/ifx', 'pct': 96}],
                        'services': {'crond': 'active', 'sshd': 'failed'}, 'os': 'Red Hat Enterprise Linux release 9.4'},
            'informix': {'etat': 'actif', 'entete': {'mode': 'On-Line (Prim)'},
                         'dbspaces': [{'nom': 'datadbs', 'taille_mo': 1000, 'libre_mo': 5}, {'nom': 'plogdbs', 'taille_mo': 100, 'libre_mo': 1},
                                      {'nom': 'tempdbs', 'temp': True, 'taille_mo': 100, 'libre_mo': 1}],
                         'checkpoints': [{'total_s': 15.8}], 'logs': {'nombre': 10, 'non_sauvegardes': 9},
                         'replication': {'serveurs': [{'nom': 'rss1', 'etat': 'Disconnected'}]}}}
    g.marquer_dbspaces(snap, {})
    al = g.analyser_serveur(srv, snap, s, maint)
    msgs = dict((a['message'], a['gravite']) for a in al)
    assert msgs['Système de fichiers /ifx rempli'] == 'critique'
    assert msgs['Service sshd : failed'] == 'haute'
    assert msgs['Dbspace datadbs presque plein (0.5 % libre)'] == 'critique'
    assert not any('plogdbs' in m or 'tempdbs' in m for m in msgs)       # journaux et temporaires : pas d'alerte d'espace
    assert msgs['Checkpoints longs (max 15.8 s)'] == 'haute'
    assert msgs['Secondaire rss1 : Disconnected'] == 'critique'
    assert g.statut(al, snap) == 'critique' and g.score(al) < 50
    vieux = dict(snap, horodatage='2026-11-04 08:00:00')
    assert g.statut(g.analyser_serveur(srv, vieux, s, maint), vieux) == 'injoignable'


def test_demo_et_portail_complet():
    d = tempfile.mkdtemp()
    try:
        conf = demo.conf_demo()
        demo.generer(os.path.join(d, 'partage'), conf)
        donnees = g.assembler(conf, os.path.join(d, 'partage'), demo=True)
        assert donnees['resume']['total'] == 6 and donnees['resume']['en_ligne'] == 6
        assert donnees['connexions']['kpi']['cron'] > 0 and donnees['connexions']['kpi']['interactif'] > 0
        assert set(l['de'] for l in donnees['schema']['liens']) >= {'APP1', 'APP2', 'APP3', 'API'}
        html = g.rendre(donnees, conf)
        assert not re.search(r'__[A-Z_]+__', html)
        assert html.count('<script') == 2 and 'http://' not in html.replace('http://www.w3.org/2000/svg', '')
        brut = html.split('id="donnees">')[1].split('</script>')[0]
        assert json.loads(brut)['meta']['demo'] is True
    finally:
        shutil.rmtree(d)


def test_echappement_script():
    conf = demo.conf_demo()
    donnees = {'meta': {'titre': 'x', 'client': 'y</script><b>', 'genere': '', 'demo': False}, 'test': '</script><script>alert(1)'}
    html = g.rendre(donnees, conf)
    assert '</script><script>alert(1)' not in html and 'y&lt;/script&gt;' in html


def test_collecteur_ecrit_dans_le_partage():
    d = tempfile.mkdtemp()
    try:
        conf = os.path.join(d, 't.conf')
        io.open(conf, 'w', encoding='utf-8').write('PARTAGE=%s\nSERVEURS="APP9:hote-inexistant:app"\nSERVICES=\n' % d)
        assert c.main(['--conf', conf, '--nom', 'APP9', '--role', 'app']) == 0
        snap = json.load(io.open(os.path.join(d, 'donnees', 'APP9', 'dernier.json'), encoding='utf-8'))
        assert snap['nom'] == 'APP9' and snap['systeme']['memoire']['total_ko'] > 0
        assert len(io.open(os.path.join(d, 'donnees', 'APP9', 'historique.jsonl'), encoding='utf-8').read().splitlines()) == 1
    finally:
        shutil.rmtree(d)


def test_scripts_shell_et_python27():
    for f in ('collecte.sh', 'installer-cron.sh'):
        subprocess.check_call(['bash', '-n', os.path.join(RACINE, 'collecteur', f)])
    for py in ('python2.7', 'python2'):
        if shutil.which(py):
            for f in ('collecteur/collecte_infra.py', 'portail/generer_portail.py', 'portail/demo.py'):
                subprocess.check_call([py, '-m', 'py_compile', os.path.join(RACINE, f)])
            return
    import pytest
    pytest.skip('Python 2.7 absent : compilation 2.7 non vérifiée')


# ------------------------------------------------------------------ mode central (SSH)
import collecte_centrale as cc  # noqa: E402

CONF_CENTRAL = {'MODE': 'central', 'CENTRAL': 'REPL', 'SERVEURS': 'BDD:srv-bdd01:bdd:10.0.1.11 REPL:srv-bdd02:repl:10.0.1.12 '
                'APP1:srv-app01:app:10.0.1.21', 'CLE_SSH': '/root/.ssh/portail_infra', 'SERVICES': '', 'INFORMIXSERVER': 'ol_prim',
                'INFORMIXSERVER_REPL': 'ol_rss'}


def test_serveurs_ip_et_surcharges():
    s = c.serveurs_conf(CONF_CENTRAL)
    assert s[0] == {'nom': 'BDD', 'hote': 'srv-bdd01', 'role': 'bdd', 'ip': '10.0.1.11'}
    assert c.serveurs_conf({'SERVEURS': 'X:h:app'})[0]['ip'] == ''
    assert c.conf_serveur(CONF_CENTRAL, 'REPL')['INFORMIXSERVER'] == 'ol_rss'
    assert c.conf_serveur(CONF_CENTRAL, 'BDD')['INFORMIXSERVER'] == 'ol_prim'


def test_commande_ssh_et_reponse():
    srv = c.serveurs_conf(CONF_CENTRAL)[2]
    cmd = cc.commande_ssh(srv, CONF_CENTRAL)
    assert cmd[0] == 'ssh' and 'BatchMode=yes' in cmd and 'StrictHostKeyChecking=yes' in cmd and cmd[-2:] == ['root@10.0.1.21', 'collecte']
    assert cc.lire_instantane('Bienvenue\n{"nom": "APP1", "erreurs": []}\n', srv)['nom'] == 'APP1'
    for mauvais in ('{"nom": "APP2"}', 'Permission denied (publickey).'):
        try:
            cc.lire_instantane(mauvais, srv)
            assert False
        except ValueError:
            pass


def test_collecte_centrale_avec_ssh_simule():
    d = tempfile.mkdtemp()
    appels = []

    def faux_ssh(cmd, delai, entree=None):
        appels.append(cmd[-2])
        if cmd[-2] == 'root@10.0.1.11':
            return 255, 'ssh: connect to host 10.0.1.11 port 22: Connection timed out'
        return 0, json.dumps({'nom': 'APP1', 'role': 'app', 'horodatage': '2026-11-04 10:00:00', 'erreurs': [],
                              'systeme': {'cpu_pct': 12, 'memoire': {'pct': 40}, 'disques': []}})
    try:
        res = dict(cc.collecter_tout(CONF_CENTRAL, d, faux_ssh, ips={'10.0.1.12'}))
        assert sorted(appels) == ['root@10.0.1.11', 'root@10.0.1.21']          # REPL collecté localement, pas en SSH
        assert res['REPL'].startswith('ok') and res['APP1'] == 'ok' and res['BDD'].startswith('ÉCHEC')
        assert os.path.exists(os.path.join(d, 'donnees', 'APP1', 'dernier.json'))
        assert not os.path.exists(os.path.join(d, 'donnees', 'BDD'))
        donnees = g.assembler(CONF_CENTRAL, d, maintenant=dt.datetime(2026, 11, 4, 10, 5))
        etats = dict((s['nom'], s['statut']) for s in donnees['serveurs'])
        assert etats['BDD'] == 'injoignable' and etats['APP1'] == 'ok'
    finally:
        shutil.rmtree(d)


def test_sortie_standard_ascii():
    d = tempfile.mkdtemp()
    try:
        conf = os.path.join(d, 't.conf')
        io.open(conf, 'w', encoding='utf-8').write('SERVICES=\n')
        out = subprocess.check_output([sys.executable, os.path.join(RACINE, 'collecteur', 'collecte_infra.py'), '--conf', conf,
                                       '--nom', 'APP1', '--role', 'app', '--stdout'], env=dict(os.environ, LANG='C', LC_ALL='C'))
        assert max(out) < 128 and json.loads(out.decode('ascii'))['nom'] == 'APP1'
    finally:
        shutil.rmtree(d)
        shutil.rmtree(os.path.join(RACINE, 'collecteur', 'travail'), ignore_errors=True)


def test_commandes_informix_sous_compte_informix(monkeypatch):
    import pwd
    appels = []
    monkeypatch.setattr(c, 'lancer', lambda cmd, delai=60, entree=None: (appels.append(cmd), (0, ''))[1])
    monkeypatch.setattr(c, 'existe', lambda x: True)
    monkeypatch.setattr(os, 'geteuid', lambda: 0)
    compte = pwd.getpwuid(65534).pw_name if any(p.pw_uid == 65534 for p in pwd.getpwall()) else pwd.getpwuid(os.getuid()).pw_name
    c.ifx({'COMPTE_INFORMIX': compte}, ['onstat', '-'])
    assert appels[-1] == ['runuser', '-u', compte, '--', 'onstat', '-']
    c.ifx({'COMPTE_INFORMIX': 'compte_absent_xyz'}, ['onstat', '-'])
    assert appels[-1] == ['onstat', '-']                                   # compte absent : commande directe
    monkeypatch.setattr(os, 'geteuid', lambda: 1000)
    c.ifx({'COMPTE_INFORMIX': compte}, ['onstat', '-'])
    assert appels[-1] == ['onstat', '-']                                   # déjà sous un compte non root


def test_compte_ssh_propre_a_un_serveur():
    conf = dict(CONF_CENTRAL, COMPTE_SSH='informix', COMPTE_SSH_APP1='irium')
    s = dict((x['nom'], x) for x in c.serveurs_conf(conf))
    assert cc.commande_ssh(s['APP1'], conf)[-2] == 'irium@10.0.1.21'
    assert cc.commande_ssh(s['BDD'], conf)[-2] == 'informix@10.0.1.11'
