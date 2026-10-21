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
