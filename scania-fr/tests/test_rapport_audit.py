"""Tests de l'analyse : lecture des relevés /proc et onstat, diagnostic et signalements."""
import os
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import rapport_audit as r  # noqa: E402

T0 = 1792656000   # horodatage de référence


def bloc(t, txt):
    return '### %d x\n%s\n' % (T0 + t, txt)


PROFIL = """Profile
dskreads   pagreads   bufreads   %%cached dskwrits   pagwrits   bufwrits   %%cached
%d 2000 %d 99.0 %d 3000 %d 90.0

bufwaits   lokwaits   lockreqs   deadlks    dltouts    ckpwaits   compress   seqscans
%d %d 5000 %d 0 %d 0 %d
"""

U = """Userthreads
address          flags   sessid   user     tty      wait             tout locks nreads   nwrites
%s
 %d active, 1024 total, 145 maximum concurrent
"""


def fabriquer(d, incident=True):
    os.makedirs(os.path.join(d, 'series'))
    os.makedirs(os.path.join(d, 'informix'))
    os.makedirs(os.path.join(d, 'statique', 'informix'))
    with open(os.path.join(d, 'info.txt'), 'w') as f:
        f.write('serveur=srv-bdd\nroles=bdd-principale\ninformix=1\nnb_cpu=4\n')
    stat, mem, prof, us, irium = [], [], [], [], []
    cpu = [0] * 8
    br = dr = bw = dw = lw = sq = dl = cw = 0
    for i in range(30):
        pic = incident and 10 <= i < 20
        cpu = [cpu[0] + (90 if pic else 30), 0, cpu[2] + 5, cpu[3] + (2 if pic else 60), cpu[4] + (3 if pic else 5), 0, 0, 0]
        stat.append(bloc(i * 60, 'cpu  %s\nctxt %d\nprocs_running 3\nprocs_blocked 0' % (' '.join(map(str, cpu)), i * 1000)))
        mem.append(bloc(i * 60, 'MemTotal: 16000000 kB\nMemAvailable: 8000000 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB'))
        br += 100000; dr += 8000 if pic else 500; bw += 2000; dw += 200
        lw += 500 if pic else 2; sq += 10; dl += 1 if pic else 0; cw += 3 if pic else 0
        prof.append(bloc(i * 60, PROFIL % (dr, br, dw, bw, 10, lw, dl, cw, sq)))
        lignes = '\n'.join('4a1b%04x         %s %d     regix    -        0                0    1     1     1' % (k, 'L--PR--' if pic and k < 6 else '---PR--', k)
                           for k in range(20))
        us.append(bloc(i * 60, U % (lignes, 20)))
        irium.append(bloc(i * 60, ('1 1 root 100 0.0 0.1 1000 ipscrond\n' + ('2 1 root 50 40.0 1.0 9000 ipscrond facturation\n' if pic else ''))))
    for nom, contenu in [('series/stat.raw', stat), ('series/meminfo.raw', mem), ('series/irium.raw', irium),
                         ('informix/onstat_p.raw', prof), ('informix/onstat_u.raw', us)]:
        with open(os.path.join(d, nom), 'w') as f:
            f.write(''.join(contenu))
    with open(os.path.join(d, 'statique', 'informix', 'onconfig.txt'), 'w') as f:
        f.write('BUFFERPOOL size=2k,buffers=50000,lrus=8\nDEF_TABLE_LOCKMODE page\nHDR_TXN_SCOPE NEAR_SYNC\n')
    with open(os.path.join(d, 'marqueurs.txt'), 'w') as f:
        f.write('%d|x|support|Lenteur facturation\n' % (T0 + 15 * 60))


def test_metriques_et_diagnostic(tmp_path):
    d = str(tmp_path / 'srv-bdd_20261022_0730')
    fabriquer(d)
    s = r.charger(d)
    assert len(s['cpu']) == 29 and abs(s['cpu'][12]['user'] - 90) < 1
    pic = [e for e in s['profil'] if e['ts'] == s['cpu'][12]['ts']][0]
    assert pic['lockwts_min'] == 500 and pic['cache_lect'] == 92.0
    assert max(e['att_L'] for e in s['sessions']) == 6
    constats = r.diagnostic(s)
    titres = [c[2] for c in constats]
    assert 'Contention sur les verrous' in titres and 'Saturation processeur sur srv-bdd' in titres
    assert 'Cache de lecture insuffisant' not in titres            # moyenne > 95 %
    assert 'Checkpoints pénalisants' in titres                      # ckpwaits > 0
    # signalement : les verrous ressortent dans la fenêtre de ± 5 min
    obs = r.autour([s], s['marqueurs'][0][0])
    assert any(l == 'attentes verrous/min' for _n, l, _v, _m in obs)
    # corrélation entre traitements ipscrond et attentes de verrous
    cor = r.correlations([s])
    assert cor and cor[0][2] > 0.9


def test_sans_incident_et_html(tmp_path):
    d = str(tmp_path / 'srv-bdd_20261022_0730')
    fabriquer(d, incident=False)
    titres = [c[2] for c in r.diagnostic(r.charger(d))]
    assert 'Contention sur les verrous' not in titres and not any(t.startswith('Saturation') for t in titres)
    sortie = str(tmp_path / 'rapport.html')
    subprocess.run([sys.executable, os.path.join(os.path.dirname(__file__), '..', 'rapport_audit.py'), d, '-o', sortie],
                   check=True, stdout=subprocess.DEVNULL)
    page = open(sortie, encoding='utf-8').read()
    assert 'Signalements de lenteur' in page and 'Lenteur facturation' in page and 'DEF_TABLE_LOCKMODE' in page


def test_audit_syntaxe_bash():
    script = os.path.join(os.path.dirname(__file__), '..', 'audit-irium.sh')
    assert subprocess.run(['bash', '-n', script]).returncode == 0


def test_journal_moteur_msg_date_et_config_scania(tmp_path):
    import datetime as dt
    d = tmp_path / 'srv'
    (d / 'statique' / 'informix').mkdir(parents=True)
    (d / 'statique' / 'informix' / 'online_log.txt').write_text(
        '10/22/26 08:15:02  Checkpoint Completed:  duration was 12 seconds.\n'
        '10/22/26 08:16:10  Lock table overflow - user id 1001 session id 4012\n')
    ev, ckp = r.journal_moteur(str(d), dt.datetime(2026, 10, 22, 7, 30), dt.datetime(2026, 10, 22, 12, 30))
    assert ckp[0]['total'] == 12 and ckp[0]['ts'] == dt.datetime(2026, 10, 22, 8, 15, 2)
    assert ev and ev[0][1] == 'haute'
    cf = {'BUFFERPOOL': ['size=2k,buffers=8000000,lrus=128,lru_min_dirty=1,lru_max_dirty=2'], 'SHMVIRTSIZE': '12288000', 'RESIDENT': '-1',
          'VPCLASS': ['cpu,num=11'], 'NETTYPE': ['ipcshm,1,100,CPU', 'soctcp,6,300,NET'], 'USELASTCOMMITTED': '"NONE"',
          'HDR_TXN_SCOPE': 'NEAR_SYNC', 'DRINTERVAL': '0', 'LTAPEDEV': '/dev/null'}
    titres = {t: g for g, t, _p, _r in r.revue_configuration(cf, 32 * 1024, 12)}
    assert titres['Mémoire partagée Informix proche de la RAM totale'] == 'moyenne'      # 27 Go sur 32 Go
    assert titres['VP CPU + VP réseau supérieurs au nombre de cœurs'] == 'moyenne'
    assert 'Lecture de la dernière version validée désactivée' in titres and 'Réplication HDR synchrone' in titres
    assert 'Plus de VP CPU que de cœurs' in [t for _g, t, _p, _r in r.revue_configuration(cf, 32 * 1024, 8)]


PPF = """Partition profiles
partnum    lkrqs lkwts dlks  touts isrd  iswrt isrwt isdel bfrd  bfwrt seqsc rvscn rhitratio
0x200010 1000 0 0 0 900000 0 0 0 %d 0 %d 0 94
0x200020 10 0 0 0 %d 0 0 0 %d 0 0 %d 100
0x200030 %d 0 0 0 1600000 0 0 0 %d 0 %d 0 100
"""


def fabriquer_objets(d):
    """Ajoute à un audit les profils par objet, l'inventaire et l'ouverture des chunks (cas du ticket 345564)."""
    inv = os.path.join(d, 'informix', 'inventaire')
    os.makedirs(inv)
    ppf, tab, ses, ent = [], [], [], []
    for k, t in enumerate((0, 1740)):
        ppf.append(bloc(t, PPF % (9000000 + k * 4000000, 41 + k * 3, 800000000 + k * 900000, 2400000000 + k * 2700000, 790000000 + k * 880000,
                                  220000000 + k * 220000, 3895000000 + k * 3900000, 19600 + k * 20)))
        tab.append(bloc(t, 'magix_prod|sav_evt|900000|%d|%d|%d|1000|0|0|0|0|\nmagix_prod|sav_lor|700000|7000000|%d|30|800|0|0|0|0|\n' % (
            9000000 + k * 4000000, 465000000 + k * 600000, 41 + k * 3, 243000000 + k * 100000)))
        ses.append(bloc(t, '277616|crxzcj|x0295se|9553|%d|900000000|300000000|169|1000|0|120|40|\n301122|scaop|x0290se|12001|%d|80000000|30000000|12|10|0|50|0|\n' % (
            154000000 + k * 900000, 2000000 + k * 30000)))
        ent.append(bloc(t, 'IBM Informix Dynamic Server Version 14.10.FC7WE -- On-Line (Prim) -- Up 3 days 04:06:56 -- 25000000 Kbytes'))
    for nom, contenu in [('onstat_ppf.raw', ppf), ('profil_tables.raw', tab), ('profil_sessions.raw', ses), ('onstat_entete.raw', ent)]:
        with open(os.path.join(d, 'informix', nom), 'w') as f:
            f.write(''.join(contenu))
    fichiers = {
        'partitions.unl': '%d|magix_prod|sav_evt|\n%d|magix_prod|i_agrtrf1|\n%d|magix_prod|zsc_whi|\n' % (0x200010, 0x200020, 0x200030),
        'dbspaces.unl': 'rootdbs|0|0|500000|120000|1|\ndatadbs|0|0|5000000|30000|4|\ntempdbs1|1|0|1000000|990000|1|\n',
        'tailles.unl': 'magix_prod|sav_evt|11500000|11000000|52000000|12|\nmagix_prod|zsc_whi|200000|198617|900000|3|\n',
        'stats_magix_prod.unl': 'sav_evt|52000000|11000000|2026-01-15 02:00:00.00000|\nzsc_whi|900000|198617||\nsav_lor|1|1|2026-10-20 02:00:00.00000|\n',
        'distrib_magix_prod.unl': 'sav_evt|15/01/2026|4|\n',
        'index_magix_prod.unl': 'i_agrtrf1|agr_trf|\n',
    }
    for nom, contenu in fichiers.items():
        with open(os.path.join(inv, nom), 'w') as f:
            f.write(contenu)
    with open(os.path.join(d, 'statique', 'informix', 'chunks_ouverture.txt'), 'w') as f:
        f.write('# chunk|pid|flags(octal)|o_direct|type\n/opt/irium/data/datadbs1|738|02100002|0|fichier\n')
    with open(os.path.join(d, 'statique', 'informix', 'onconfig.txt'), 'a') as f:
        f.write('DIRECT_IO 0x5\nUSELASTCOMMITTED "NONE"\nOPTCOMPIND 2\n')
    with open(os.path.join(d, 'statique', 'informix', 'onstat__g_rss.txt'), 'w') as f:
        f.write('Local server type: Primary\nNumber of RSS servers: 1\n')


def test_objets_inventaire_et_recommandations(tmp_path):
    d = str(tmp_path / 'srv')
    fabriquer(d)
    fabriquer_objets(d)
    s = r.charger(d)
    assert s['obj']['uptime_s'] == 3 * 86400 + 4 * 3600 + 6 * 60 + 56
    cl = r.classements(s['obj'])
    assert cl['physiques']['liste'][0][0]['nom'] == 'sav_evt'
    assert cl['inverses']['liste'][0][0]['nom'] == 'i_agrtrf1' and cl['inverses']['liste'][0][0]['table'] == 'agr_trf'
    assert abs(cl['inverses']['liste'][0][3] - 880000 / 1740.0) < 1          # fréquence sur la fenêtre
    titres = {c[2]: c for c in r.diagnostic(s)}
    assert titres['Dbspace datadbs presque plein'][0] == 'critique'
    assert 'Dbspace tempdbs1 presque plein' not in titres
    assert 'Parcours inverses d\'index concentrés (i_agrtrf1)' in titres
    assert 'zsc_whi' in titres['Scans séquentiels coûteux sur de grandes tables'][3]
    st = titres['Statistiques de l\'optimiseur absentes ou anciennes sur des tables sollicitées'][3]
    assert 'sav_evt : 15/01/2026' in st and 'zsc_whi : jamais' in st
    assert 'session 277616' in titres['Une session concentre les lectures physiques (session 277616)'][3]
    # configuration croisée avec les mesures
    assert titres['DIRECT_IO configuré mais inactif sur les chunks'][0] in ('moyenne', 'haute')
    assert titres['Lecture de la dernière version validée désactivée'][0] == 'haute'   # contention mesurée
    assert titres['Optimiseur orienté coût global'][0] == 'moyenne'
    assert 'Paramètres HDR sans effet : secondaire RSS' in titres and 'Réplication HDR synchrone' not in titres
    plan = r.plan_recommandations([('srv',) + c for c in r.diagnostic(s)])
    assert plan[0]['prio'] == 'Immédiat' and plan[0]['ref'] == 'R01'
    sortie = str(tmp_path / 'rapport.html')
    r.generer([s], sortie)
    h = open(sortie, encoding='utf-8').read()
    assert 'id="reco"' in h and 'Classement 4' in h and h.rfind('id="reco"') > h.rfind('id="srv-0"')
    csvp = str(tmp_path / 'rapport_inventaire' / '00_plan_recommandations.csv')
    assert 'Dbspace datadbs presque plein' in open(csvp, encoding='utf-8-sig').read()


def test_pression_memoire_noyau(tmp_path):
    d = str(tmp_path / 'srv')
    fabriquer(d, incident=False)
    vm = ''.join(bloc(i * 60, 'pswpin 0\npswpout 0\npgmajfault 0\ncompact_stall %d\nallocstall_normal %d\npgsteal_kswapd %d' % (i * 1200, i * 3000, i * 5000000))
                 for i in range(30))
    with open(os.path.join(d, 'series', 'vmstat.raw'), 'w') as f:
        f.write(vm)
    with open(os.path.join(d, 'series', 'buddyinfo.raw'), 'w') as f:
        f.write(bloc(0, 'Node 0, zone   Normal   5000  300    0    0    0    0    0    0    0    0    0'))
    s = r.charger(d)
    assert s['buddy'][0]['bloc_ko'] == 8
    c = {x[2]: x for x in r.diagnostic(s)}['Pression mémoire du noyau (récupération et compactage)']
    assert c[0] == 'haute' and '8 Ko' in c[3]


def ecrire_programmes(d, pic_debut=10 * 60, pic_fin=20 * 60):
    """Journal agr_lds : saisies réparties toute la matinée, facturation lancée pendant le pic de verrous."""
    with open(os.path.join(d, 'informix', 'programmes_table.txt'), 'w') as f:
        f.write('base=magix_prod\ntable=agr_lds\ncolonne_date=alds_open\ncolonnes=alds_id,alds_user,alds_open,alds_close,alds_prog,alds_complement,alds_tty\n')
    import datetime as dt
    lignes = []
    for i in range(0, 30 * 60, 30):
        t = dt.datetime.fromtimestamp(T0 + i)
        lignes.append('%d|u%d|%s|%s|irium|Xp_saisie|pts/%d|' % (i, i % 7, t.strftime('%Y-%m-%d %H:%M:%S'), (t + dt.timedelta(seconds=20)).strftime('%Y-%m-%d %H:%M:%S'), i % 5))
    t = dt.datetime.fromtimestamp(T0 + pic_debut)
    lignes.append('9999|ipscron|%s|%s|irium|Xp_facturation|cron|' % (t.strftime('%Y-%m-%d %H:%M:%S'), dt.datetime.fromtimestamp(T0 + pic_fin).strftime('%Y-%m-%d %H:%M:%S')))
    with open(os.path.join(d, 'informix', 'programmes_final.unl'), 'w') as f:
        f.write('\n'.join(lignes) + '\n')


def test_programmes_irium_et_pics(tmp_path):
    d = str(tmp_path / 'srv')
    fabriquer(d)
    ecrire_programmes(d)
    s = r.charger(d)
    assert s['prog']['roles']['debut'] == 'alds_open' and s['prog']['roles']['fin'] == 'alds_close'
    assert s['prog']['roles']['programme'] == 'alds_prog'
    noms = {x['programme'] for x in s['aprog']['pics']}
    assert 'irium (Xp_facturation)' in noms and 'irium (Xp_saisie)' not in noms
    titres = {c[2]: c for c in r.diagnostic(s)}
    assert 'Xp_facturation' in titres['Programmes sur-représentés pendant les pics de la base'][3]
    import datetime as dt
    assert ('irium (Xp_facturation)', 1) in r.programmes_autour([s], dt.datetime.fromtimestamp(T0 + 15 * 60))


def test_campagne_rapport_central(tmp_path):
    camp = tmp_path / 'campagnes' / 'matin'
    bdd, app = str(camp / 'x0296se'), str(camp / 'x0295se')
    fabriquer(bdd)
    ecrire_programmes(bdd)
    fabriquer(app, incident=False)
    with open(os.path.join(app, 'info.txt'), 'w') as f:
        f.write('serveur=x0295se\nroles=applications-irium\ninformix=0\nnb_cpu=8\n')
    with open(os.path.join(bdd, 'info.txt'), 'w') as f:
        f.write('serveur=x0296se\nroles=bdd-principale\ninformix=1\nnb_cpu=4\n')
    (camp / 'campagne.conf').write_text('nom=matin\nduree=5h\nintervalle=30\nserveurs=x0296se x0295se x0297se\n')
    (camp / 'x0296se.etat').write_text('etat=termine\nmaj=%d\nroles=bdd-principale\nechantillons=30\n' % T0)
    (camp / 'marqueurs.txt').write_text('%d|x|support@x0295se|Lenteur centrale\n' % (T0 + 16 * 60))
    c = r.charger_campagne(str(camp))
    assert len(c['dossiers']) == 2 and c['marqueurs'][0][2] == 'Lenteur centrale'
    serveurs = [r.charger(x) for x in c['dossiers']]
    sortie = str(camp / 'rapport_matin.html')
    r.generer(serveurs, sortie, c)
    h = open(sortie, encoding='utf-8').read()
    assert 'Campagne matin' in h and 'Lenteur centrale' in h and 'pas encore de données' in h      # x0297se attendu mais absent
    assert h.index('Serveur x0296se') < h.index('Serveur x0295se')                                  # base en premier
    assert 'Xp_facturation' in h and 'http-equiv="refresh"' not in h                               # campagne terminée : pas de rechargement


def test_compatibilite_python27(tmp_path):
    """RHEL 7 n'a souvent que Python 2.7 : le rapport doit s'y exécuter (test sauté si aucun python2 n'est disponible)."""
    import shutil
    import pytest
    py2 = os.environ.get('PYTHON27') or shutil.which('python2.7') or shutil.which('python2')
    if not py2:
        pytest.skip('python 2.7 absent')
    d = str(tmp_path / 'srv')
    fabriquer(d)
    fabriquer_objets(d)
    ecrire_programmes(d)
    sortie = str(tmp_path / 'r.html')
    env = dict(os.environ, LC_ALL='C', LANG='C')
    p = subprocess.run([py2, os.path.join(os.path.dirname(__file__), '..', 'rapport_audit.py'), d, '-o', sortie],
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env)
    assert p.returncode == 0, p.stdout.decode('utf-8', 'replace')
    h = open(sortie, encoding='utf-8').read()
    assert 'Dbspace datadbs presque plein' in h and 'Xp_facturation' in h and 'id="reco"' in h
    assert open(str(tmp_path / 'r_inventaire' / '00_plan_recommandations.csv'), 'rb').read(3) == b'\xef\xbb\xbf'


def test_services_supervises(tmp_path):
    d = str(tmp_path / 'srv')
    fabriquer(d)
    with open(os.path.join(d, 'info.txt'), 'a') as f:
        f.write('services=digital_dealer|absent_svc\nclk_tck=100\npage_ko=4\n')
    lignes = []
    for i in range(30):
        if 12 <= i < 15:                                  # arrêt du service entre 12 et 15 min
            procs = ''
        else:
            pid, debut = (7528, 1000) if i < 12 else (8100, 90000)   # redémarré à 15 min (nouveau pid)
            ticks = i * 6000 * (2 if 10 <= i < 12 else 1)            # 100 % d'un cœur, puis 200 %
            procs = ('7512|1|S|0|0|1|900|300|/bin/bash /opt/irium/digital_dealer/digital_dealer_start.sh\n'
                     '%d|7517|R|%d|0|4|%d|%d|python3 digital_dealer.py -l ERROR\n' % (pid, ticks, debut, 50000 + i * 1000))
        lignes.append(bloc(i * 60, procs))
    with open(os.path.join(d, 'series', 'services.raw'), 'w') as f:
        f.write(''.join(lignes))
    with open(os.path.join(d, 'statique', 'services_echec_fin.txt'), 'w') as f:
        f.write('kdump.service loaded failed failed Crash recovery kernel arming\n')
    s = r.charger(d)
    dd = s['services']['digital_dealer']
    assert [(a, z) for a, z in dd['absences']] == [(r.dt.datetime.fromtimestamp(T0 + 12 * 60), r.dt.datetime.fromtimestamp(T0 + 15 * 60))]
    assert len(dd['demarrages']) == 1
    assert abs(stats_moy(dd['serie'][2:10]) - 100) < 1
    t = {c[2]: c for c in r.diagnostic(s)}
    assert 'Service digital_dealer arrêté pendant l\'audit' in t
    assert 'Processus digital_dealer (re)démarrés pendant l\'audit' in t
    assert 'Service absent_svc absent pendant tout l\'audit' in t
    assert 'kdump.service' in t['Services systemd en échec'][3] and t['Services systemd en échec'][0] == 'moyenne'
    sortie = str(tmp_path / 'r.html')
    r.generer([s], sortie)
    assert 'Services supervisés' in open(sortie, encoding='utf-8').read()


def stats_moy(serie):
    v = [e['cpu'] for e in serie if e.get('cpu') is not None]
    return sum(v) / len(v)


IOF = """AIO global files:
gfd pathname               bytes read      page reads  bytes write     page writes io/s
3   /data/ifx/datadbs1  %d 60 %d 385 12.3
        op type    count      avg. time
        seeks      0          N/A
        reads      %d         %s
        writes     %d         %s
"""


def test_expert_informix(tmp_path):
    d = str(tmp_path / 'srv')
    fabriquer(d)
    fabriquer_objets(d)
    inf = lambda n: os.path.join(d, 'informix', n)
    # chunk : 60 s entre deux relevés, 60 Mo lus, 1000 écritures de plus à 40 ms
    with open(inf('onstat_iof.raw'), 'w') as f:
        f.write(bloc(0, IOF % (0, 0, 100, '0.0050', 1000, '0.0100')) + bloc(60, IOF % (60 * 1048576, 0, 200, '0.0050', 2000, '0.0250')))
    with open(inf('onstat_spi.raw'), 'w') as f:
        f.write(bloc(0, '     100   1000   10.0 lockhash[1]\n     50   500   10.0 lockhash[2]\n') +
                bloc(60, '     5100   51000   10.0 lockhash[1]\n     2050   20500   10.0 lockhash[2]\n'))
    L = 'Logical Logging\nBuffer bufused  bufsize  numrecs    numpages   numwrits   recs/pages pages/io\n  L-2  0        32       %d  %d    %d    52.6       1.1\n'
    with open(inf('onstat_l.raw'), 'w') as f:
        f.write(bloc(0, L % (1000, 1000, 1000)) + bloc(60, L % (9000, 2000, 1900)))
    with open(inf('verrous_attente.raw'), 'w') as f:
        f.write(bloc(0, 'magix_prod|zag_ent|X|301500|ipscron|x0294se|14552|400001|u03|x0290se|\nmagix_prod|zag_ent|X|301500|ipscron|x0294se|14552|400002|u07|x0290se|\n'))
    with open(inf('trace_sql_colonnes.unl'), 'w') as f:
        f.write('sql_id|\nsql_sid|\nsql_runtime|\nsql_pgreads|\nsql_bfreads|\nsql_lockwaits|\nsql_isollevel|\nsql_statement|\n')
    lignes = ''.join("%d|277616|2.0|90000|100000|0|5|SELECT * FROM sav_evt WHERE sev_cod = 'A%d'|\n" % (i, i) for i in range(10)) + \
        ''.join('%d|301122|0.001|1|300|0|2|SELECT FIRST 1 * FROM agr_trf WHERE atr_cle = %d ORDER BY atr_dat DESC|\n' % (100 + i, i) for i in range(5))
    with open(inf('trace_sql.raw'), 'w') as f:
        f.write(bloc(0, lignes) + bloc(300, lignes))          # relevé en double : dédoublonné par sql_id
    with open(os.path.join(d, 'informix', 'inventaire', 'index_magix_prod.unl'), 'w') as f:
        f.write('i_a1|agr_trf|D|N|3|900|800|1|2|0|0|0|0|0|0|\ni_a2|agr_trf|D|N|2|700|500|1|0|0|0|0|0|0|0|\ni_u|agr_trf|U|N|6|100|100|1|0|0|0|0|0|0|0|\n')
    with open(os.path.join(d, 'informix', 'inventaire', 'stats_magix_prod.unl'), 'a') as f:
        f.write('zag_ent|2000000|516144|2026-10-01 02:00:00.00000|P|500|\n')
    s = r.charger(d)
    x = s['exp']
    v = x['chunks']['/data/ifx/datadbs1'][0]
    assert abs(v['lect_mo_s'] - 1.0) < 0.01 and abs(v['ecr_ms'] - 40.0) < 0.01 and abs(v['iops'] - 1100 / 60.0) < 0.01
    assert x['mutex'][0]['nom'] == 'lockhash' and abs(x['mutex'][0]['attentes_min'] - 7000) < 1
    assert abs(x['log']['l_pages_par_io'] - 1000 / 900.0) < 1e-6
    sq = x['sql']
    assert sq['nb'] == 15 and len(sq['groupes']) == 2
    g = max(sq['groupes'], key=lambda g: g['pgreads'])
    assert g['texte'] == 'SELECT * FROM sav_evt WHERE sev_cod = ?' and g['exec'] == 10 and g['isolation'] == {'5'}
    t = {c[2]: c for c in r.diagnostic(s)}
    assert 'Session 301500 bloque d\'autres sessions (ipscron@x0294se)' in t
    assert 'Une requête représente 100 % des lectures disque tracées' in t
    assert 'i_a2 couvert par' in t['Index probablement redondants'][3]
    assert 'i_u couvert' not in t['Index probablement redondants'][3]          # un index unique n'est jamais redondant
    assert 'Index profonds (5 niveaux ou plus)' in t
    assert 'zag_ent' in t['Tables en verrouillage par page'][3] or 'zag_ent' in t.get('Tables très sollicitées en verrouillage par page', ('',) * 4)[3]
    assert 'Contention sur les mutex internes' in t and 'Buffer de log logique vidé à chaque validation' not in t   # pas de validations dans le profil de test
    sortie = str(tmp_path / 'r.html')
    r.generer([s], sortie)
    h = open(sortie, encoding='utf-8').read()
    assert 'Analyse experte Informix' in h and 'Vitesse des chunks' in h and 'Chaînes de blocage' in h and 'Requêtes SQL tracées' in h


def test_dashboard_kpi(tmp_path):
    import dashboard_kpi as dk
    d = str(tmp_path / 'srv')
    fabriquer(d)
    fabriquer_objets(d)
    with open(os.path.join(d, 'statique', 'cycle_de_vie.txt'), 'w') as f:
        f.write('== Système\nRed Hat Enterprise Linux Server release 7.6 (Maipo)\nnoyau=3.10.0-957.el7.x86_64\n\n== Derniers paquets installés\n'
                'tzdata-2018g-1.el7.noarch                     Thu 15 Nov 2018 10:11:40 AM CET\n\n== Abonnement\nOverall Status: Unknown\n\n'
                '== Dépôts actifs (cache local)\nThere are no enabled repos.\n\n== Briques\npython=Python 2.7.5\n')
    s = r.charger(d)
    cv = dk.cycle_de_vie(s)
    assert cv['majeure'] == 7 and cv['mineure'] == 6 and cv['depots'] == 'aucun' and cv['derniere_maj'].year == 2018
    import datetime as dt
    assert dk.statut_os(cv, dt.date(2026, 10, 29))[0] == 'critique'
    assert dk.statut_os({'majeure': 9, 'mineure': 4}, dt.date(2026, 10, 29))[0] == 'bon'
    k = dk.kpis_serveur(s)
    assert k['dbspace']['statut'] == 'critique' and k['verrous']['statut'] in ('degrade', 'critique')
    arg = [a[0] for a in dk.argumentaire([s], {s['nom']: k}, {s['nom']: cv}, dt.date(2026, 10, 29))]
    assert 'Sécurité et conformité' in arg and 'Maintien en condition' in arg and 'Outillage' in arg
    sortie = str(tmp_path / 'dash.html')
    score, etat = dk.generer([s], sortie)
    h = open(sortie, encoding='utf-8').read()
    assert 0 <= score < 80 and 'Pourquoi passer à RHEL 9' in h and 'respecter ces prérequis' in h and 'Feuille de route' in h
    score2, _ = dk.generer([s], str(tmp_path / 'dash2.html'), avant=[s])
    assert 'Avant / après' in open(str(tmp_path / 'dash2.html'), encoding='utf-8').read()
