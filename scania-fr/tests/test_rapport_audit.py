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
