# -*- coding: utf-8 -*-
"""Données fictives pour la démonstration du portail (aucune donnée client)."""
from __future__ import division, print_function, unicode_literals

import datetime as dt
import io
import json
import math
import os
import random
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'collecteur'))
from collecte_infra import ajouter_historique, ecrire_json, resume  # noqa: E402

SERVEURS = 'BDD:srv-bdd01:bdd REPL:srv-bdd02:repl APP1:srv-app01:app APP2:srv-app02:app APP3:srv-app03:app API:srv-api01:api'
PRENOMS = ['amine', 'fatou', 'youssef', 'awa', 'karim', 'mariam', 'omar', 'aicha', 'samuel', 'nadia', 'ibrahim',
           'salma', 'cheikh', 'leila', 'paul', 'hind', 'moussa', 'sara', 'yassine', 'kadi', 'eric', 'imane', 'ali',
           'grace', 'hamza', 'ines', 'serge', 'zineb', 'adama', 'rachid']
NOMS = ['bennani', 'diop', 'kone', 'traore', 'alaoui', 'ndiaye', 'mbarga', 'tazi', 'kouassi', 'cisse', 'idrissi',
        'fofana', 'essomba', 'berrada', 'sow', 'amrani', 'toure', 'nkoulou', 'chraibi', 'keita']
SITES = ['CASA', 'ABJ', 'DKR', 'DLA', 'LBV']
PROGRAMMES = [('ven_commandes', 18), ('pie_stock', 16), ('atl_ordres_rep', 14), ('pie_comptoir', 12),
              ('cpt_ecritures', 8), ('ach_receptions', 7), ('ven_factures', 7), ('crm_clients', 6),
              ('atl_pointage', 5), ('mag_inventaire', 3), ('tar_tarifs', 2), ('fin_reglements', 4), ('rep_tableaux', 3)]
CRONS = [('Xp_cron_relance_cde', 4), ('Xp_cron_maj_stock', 4), ('Xp_cron_edi_constructeur', 2),
         ('Xp_cron_purge', 1), ('Xp_cron_export_bi', 1)]


def conf_demo():
    return {'SERVEURS': SERVEURS, 'GENERATEUR': 'API', 'FREQUENCE_MIN': '15', 'CLIENT': 'Tractafric Equipment',
            'TITRE': "Portail d'infrastructure IRIUM iE", 'BASE': 'magix_prod', 'TABLE_CONNEXIONS': 'agr_lds'}


def pondere(r, liste):
    tot = sum(p for _, p in liste)
    x = r.uniform(0, tot)
    for v, p in liste:
        x -= p
        if x <= 0:
            return v
    return liste[-1][0]


def activite(h, jour_semaine):
    """Profil d'activité d'une journée ouvrée (0..1)."""
    if jour_semaine >= 5:
        base = 0.12 if jour_semaine == 5 and 8 <= h <= 13 else 0.03
        return base
    if h < 7 or h > 19:
        return 0.04
    return max(0.05, math.exp(-((h - 10.5) ** 2) / 6) * 0.95 + math.exp(-((h - 15.5) ** 2) / 5) * 0.8)


HOTES = dict((x.split(':')[0], x.split(':')[1]) for x in SERVEURS.split())


def systeme(nom, role, r, cpu, mem, os_, disques, motifs, services, ncpu, ram_go):
    tot = ram_go * 1024 * 1024
    return {
        'hote': HOTES[nom] + '.tractafric.local', 'os': os_, 'noyau': '3.10.0-1160.119.1.el7.x86_64'
        if 'release 7' in os_ else '4.18.0-513.24.1.el8_9.x86_64' if 'release 8' in os_ else '5.14.0-427.13.1.el9_4.x86_64',
        'ncpu': ncpu, 'uptime_s': r.randint(20, 160) * 86400, 'charge': [round(cpu / 100 * ncpu * f, 2) for f in (1, 0.9, 0.8)],
        'cpu_pct': cpu, 'iowait_pct': round(r.uniform(0.2, 4), 1),
        'memoire': {'total_ko': tot, 'dispo_ko': int(tot * (1 - mem / 100)), 'pct': mem, 'swap_total_ko': 8388608,
                    'swap_pct': round(r.uniform(0, 6), 1), 'thp': 'always' if role == 'bdd' else 'never'},
        'disques': [{'fs': '/dev/mapper/vg-%s' % m.strip('/').replace('/', '_') or 'root', 'montage': m,
                     'taille_ko': int(t * 1048576), 'utilise_ko': int(t * 1048576 * p / 100), 'pct': p} for m, t, p in disques],
        'top_processus': [{'pid': str(r.randint(1000, 60000)), 'utilisateur': u, 'cpu': c, 'mem': round(r.uniform(0.1, 6), 1),
                           'rss_ko': r.randint(20000, 900000), 'duree': '%d-%02d:%02d:%02d' % (r.randint(0, 9), r.randint(0, 23),
                                                                                             r.randint(0, 59), r.randint(0, 59)),
                           'commande': n} for u, c, n in motifs[1]],
        'processus': motifs[0], 'services': services, 'sessions_ssh': r.randint(0, 4),
        'tcp_etablies': r.randint(40, 900), 'ports_ecoute': [22, 443, 9088, 9089] if role in ('bdd', 'repl') else [22, 443, 6400],
    }


def taches(role, maint):
    t = [{'source': '/etc/crontab', 'utilisateur': 'root', 'planification': '*/15 * * * *',
          'commande': '/msdos/ks/tractafric/collecteur/collecte.sh >/dev/null 2>&1 # portail-infra-irium'},
         {'source': '/etc/cron.d/0hourly', 'utilisateur': 'root', 'planification': '01 * * * *',
          'commande': 'run-parts /etc/cron.hourly'},
         {'source': '/etc/cron.d/sysstat', 'utilisateur': 'root', 'planification': '*/10 * * * *',
          'commande': '/usr/lib64/sa/sa1 1 1'}]
    if role == 'bdd':
        t += [{'source': 'crontab informix', 'utilisateur': 'informix', 'planification': '30 1 * * *',
               'commande': '/home/informix/scripts/sauvegarde_n0.sh  # onbar -b -L 0'},
              {'source': 'crontab informix', 'utilisateur': 'informix', 'planification': '*/5 * * * *',
               'commande': '/home/informix/scripts/sauve_logs.sh  # onbar -b -l'},
              {'source': 'crontab informix', 'utilisateur': 'informix', 'planification': '0 3 * * 0',
               'commande': 'dbaccess magix_prod /home/informix/scripts/update_statistics.sql'},
              {'source': 'crontab informix', 'utilisateur': 'informix', 'planification': '0 6 * * 1-5',
               'commande': '/home/informix/scripts/controle_onstat.sh'}]
    if role == 'app':
        t += [{'source': 'crontab irium', 'utilisateur': 'irium', 'planification': '*/10 7-19 * * 1-5',
               'commande': 'fglrun /irium/bin/Xp_cron_relance_cde.42r'},
              {'source': 'crontab irium', 'utilisateur': 'irium', 'planification': '0 22 * * *',
               'commande': 'fglrun /irium/bin/Xp_cron_maj_stock.42r'},
              {'source': 'crontab irium', 'utilisateur': 'irium', 'planification': '15 5 * * 1',
               'commande': 'fglrun /irium/bin/Xp_cron_purge.42r'}]
    if role == 'api':
        t += [{'source': 'crontab irium', 'utilisateur': 'irium', 'planification': '0 */2 * * *',
               'commande': 'fglrun /irium/bin/Xp_cron_edi_constructeur.42r'},
              {'source': 'crontab root', 'utilisateur': 'root', 'planification': '0 4 1 * *',
               'commande': '/usr/local/bin/renouveler_certificats.sh'}]
    freq = {'*/15 * * * *': 96, '01 * * * *': 24, '*/10 * * * *': 144, '30 1 * * *': 1, '*/5 * * * *': 288,
            '0 6 * * 1-5': 1, '*/10 7-19 * * 1-5': 78, '0 22 * * *': 1, '0 */2 * * *': 12}
    for x in t:
        x['executions_24h'] = freq.get(x['planification'], 0)
        n = x['executions_24h']
        x['derniere_execution'] = (maint - dt.timedelta(minutes=(1440 // n) // 2 if n > 1 else 300)).strftime('%Y-%m-%d %H:%M:%S') if n else None
    return {'taches': t, 'journal_lisible': True}


def connexions(r, maint):
    users = sorted(set('%s.%s' % (r.choice(PRENOMS), r.choice(NOMS)) for _ in range(160)))[:128]
    poids = [(u, r.paretovariate(1.4)) for u in users]
    postes = dict((u, '%s-PC%03d' % (r.choice(SITES), r.randint(1, 240))) for u in users)
    det, par_h = [], {}
    for j in range(7, -1, -1):
        jour = (maint - dt.timedelta(days=j)).replace(minute=0, second=0, microsecond=0)
        for h in range(24):
            t0 = jour.replace(hour=h)
            if t0 > maint:
                break
            n = int(activite(h, t0.weekday()) * 230 * r.uniform(0.85, 1.15))
            nc = len(CRONS) + (r.randint(4, 9) if 7 <= h <= 19 and t0.weekday() < 5 else r.randint(0, 2))
            cle = t0.strftime('%Y-%m-%d %H')
            par_h[(cle, 'interactif')] = n
            par_h[(cle, 'cron')] = nc
            if maint - t0 > dt.timedelta(hours=24):
                continue
            for _ in range(n):
                d = t0 + dt.timedelta(seconds=r.randint(0, 3599))
                if d > maint:
                    continue
                u = pondere(r, poids)
                duree = int(r.expovariate(1 / 900.0)) + 20
                f = d + dt.timedelta(seconds=duree)
                det.append({'debut': d.strftime('%Y-%m-%d %H:%M:%S'), 'fin': f.strftime('%Y-%m-%d %H:%M:%S') if f < maint else '',
                            'utilisateur': u, 'programme': pondere(r, PROGRAMMES), 'poste': postes[u],
                            'ip': '10.%d.%d.%d' % (SITES.index(postes[u][:postes[u].index('-')]) * 10 + 10, r.randint(1, 20),
                                                    r.randint(2, 250)), 'type': 'interactif'})
            for _ in range(nc):
                d = t0 + dt.timedelta(seconds=r.randint(0, 3599))
                if d > maint:
                    continue
                f = d + dt.timedelta(seconds=r.randint(5, 600))
                det.append({'debut': d.strftime('%Y-%m-%d %H:%M:%S'), 'fin': f.strftime('%Y-%m-%d %H:%M:%S') if f < maint else '',
                            'utilisateur': 'irium', 'programme': pondere(r, CRONS), 'poste': r.choice(['srv-app01', 'srv-app02', 'srv-api01']),
                            'ip': '10.0.1.%d' % r.choice([21, 22, 30]), 'type': 'cron'})
    det.sort(key=lambda x: x['debut'], reverse=True)
    dern = {}
    for d in det:
        k = (d['utilisateur'], d['type'])
        e = dern.setdefault(k, {'utilisateur': d['utilisateur'], 'type': d['type'], 'derniere': d['debut'], 'nombre': 0})
        e['nombre'] += 1
    for u in ['%s.%s' % (r.choice(PRENOMS), r.choice(NOMS)) for _ in range(30)]:
        if (u, 'interactif') not in dern:
            dern[(u, 'interactif')] = {'utilisateur': u, 'type': 'interactif', 'nombre': r.randint(1, 400),
                                       'derniere': (maint - dt.timedelta(days=r.randint(2, 85), minutes=r.randint(0, 900))).strftime('%Y-%m-%d %H:%M:%S')}
    for e in dern.values():
        e['nombre'] = e['nombre'] * r.randint(18, 40) if e['type'] == 'interactif' and e['derniere'] > (maint - dt.timedelta(days=1)).strftime('%Y-%m-%d') else e['nombre']
    return {'table': 'magix_prod:agr_lds', 'fenetre_heures': 24, 'tronque': False,
            'colonnes': {'date': 'alds_open', 'fin': 'alds_close', 'utilisateur': 'alds_user', 'programme': 'alds_prog',
                         'poste': 'alds_host', 'complement': 'alds_complement'},
            'detail': det, 'par_heure': [{'heure': k[0], 'type': k[1], 'nombre': v} for k, v in sorted(par_h.items())],
            'derniere_connexion': sorted(dern.values(), key=lambda x: x['derniere'], reverse=True)}


def informix(r, role, maint):
    prim = role == 'bdd'
    ckp = []
    for i in range(20):
        t = maint - dt.timedelta(minutes=5 * (20 - i))
        tot = round(r.uniform(0.4, 2.5) if r.random() > 0.15 else r.uniform(4, 7.4), 1)
        ckp.append({'heure': t.strftime('%H:%M:%S'), 'declencheur': 'CKPTINTVL' if r.random() > 0.1 else 'Plog',
                    'total_s': tot if prim else round(tot / 3, 1), 'blocage_s': round(tot * 0.6, 1) if tot > 3 and prim else 0.0,
                    'attentes': r.randint(3, 40) if tot > 3 and prim else 0})
    dbs = [('rootdbs', 2048, 61), ('plogdbs', 8192, 3), ('llogdbs', 12288, 4), ('datadbs', 184320, 6.2),
           ('indexdbs', 61440, 18.5), ('tempdbs1', 10240, 92), ('tempdbs2', 10240, 94), ('sbspace1', 4096, 71)]
    return {
        'etat': 'actif',
        'entete': {'version': '14.10.FC10W1', 'mode': 'On-Line (Prim)' if prim else 'Read-Only (RSS)',
                   'depuis': '%d days %02d:%02d:%02d' % (r.randint(10, 60), r.randint(0, 23), r.randint(0, 59), r.randint(0, 59)),
                   'memoire_ko': 26214400 if prim else 18874368},
        'profil': {'bufreads': 9.8e9, 'pagreads': 1.2e8, 'dskreads': 1.1e8, 'lockwts': 1250, 'deadlks': 0,
                   'ckpwaits': 340 if prim else 0, 'seqscans': 4.1e6, 'bufwaits': 2.2e6},
        'cache_pct': 98.78 if prim else 97.9,
        'checkpoints': ckp,
        'logs': {'nombre': 120, 'utilises': 120, 'non_sauvegardes': 3},
        'replication': {'champs': {}, 'retard_pages': 0 if prim else r.randint(10, 140),
                        'serveurs': [{'nom': 'ol_tractafric_rss', 'etat': 'Active'}] if prim else []},
        'sessions': 1176 if prim else 38,
        'sessions_par_hote': [{'hote': 'srv-app01', 'nombre': 412}, {'hote': 'srv-app02', 'nombre': 388},
                              {'hote': 'srv-app03', 'nombre': 301}, {'hote': 'srv-api01', 'nombre': 63},
                              {'hote': 'srv-bdd01', 'nombre': 12}] if prim else [{'hote': 'srv-bdd02', 'nombre': 38}],
        'sessions_par_compte': [{'compte': 'irium', 'nombre': 1048}, {'compte': 'api_ws', 'nombre': 63},
                                {'compte': 'informix', 'nombre': 21}, {'compte': 'bi_lecture', 'nombre': 44}] if prim else
        [{'compte': 'bi_lecture', 'nombre': 32}, {'compte': 'informix', 'nombre': 6}],
        'dbspaces': [{'nom': n, 'temp': n.startswith('temp'), 'sb': n.startswith('sb'), 'taille_mo': t,
                      'libre_mo': int(t * p / 100)} for n, t, p in dbs],
    }


def generer(partage, conf, graine=42, maint=None):
    r = random.Random(graine)
    maint = (maint or dt.datetime.now()).replace(microsecond=0)
    defs = {
        'BDD': ('bdd', 58, 81, 'Red Hat Enterprise Linux Server release 7.9 (Maipo)', 16, 64,
                [('/', 50, 41), ('/opt/IBM/informix', 40, 52), ('/ifxdata', 480, 79), ('/backup', 1024, 71), ('/msdos/ks', 200, 34)],
                ['crond', 'sshd'], [('oninit', 'informix'), ('onbar', 'informix')]),
        'REPL': ('repl', 21, 68, 'Red Hat Enterprise Linux Server release 7.9 (Maipo)', 16, 64,
                 [('/', 50, 38), ('/opt/IBM/informix', 40, 51), ('/ifxdata', 480, 78), ('/msdos/ks', 200, 34)],
                 ['crond', 'sshd'], [('oninit', 'informix')]),
        'APP1': ('app', 64, 74, 'Red Hat Enterprise Linux release 8.10 (Ootpa)', 12, 48,
                 [('/', 50, 47), ('/irium', 120, 61), ('/msdos/ks', 200, 34)], ['crond', 'sshd', 'httpd'], [('fglrun', 'irium')]),
        'APP2': ('app', 59, 77, 'Red Hat Enterprise Linux release 8.10 (Ootpa)', 12, 48,
                 [('/', 50, 44), ('/irium', 120, 88), ('/msdos/ks', 200, 34)], ['crond', 'sshd', 'httpd'], [('fglrun', 'irium')]),
        'APP3': ('app', 47, 92, 'Red Hat Enterprise Linux release 8.10 (Ootpa)', 8, 32,
                 [('/', 50, 52), ('/irium', 120, 58), ('/msdos/ks', 200, 34)], ['crond', 'sshd', 'httpd'], [('fglrun', 'irium')]),
        'API': ('api', 23, 54, 'Red Hat Enterprise Linux release 9.4 (Plow)', 8, 16,
                [('/', 50, 36), ('/irium', 60, 42), ('/msdos/ks', 200, 34)], ['crond', 'sshd', 'httpd'],
                [('httpd', 'apache'), ('fglrun', 'irium')]),
    }
    fgl = {'APP1': 412, 'APP2': 388, 'APP3': 301, 'API': 63}
    for nom, (role, cpu, mem, os_, ncpu, ram, disques, svcs, procs) in defs.items():
        dossier = os.path.join(partage, 'donnees', nom)
        if not os.path.isdir(dossier):
            os.makedirs(dossier)
        hist = os.path.join(dossier, 'historique.jsonl')
        if os.path.exists(hist):
            os.unlink(hist)
        motifs = {}
        for p, u in procs:
            n = fgl.get(nom, 1) if p == 'fglrun' else (r.randint(18, 24) if p == 'oninit' else r.randint(8, 30))
            motifs[p] = {'nombre': n, 'rss_ko': n * r.randint(9000, 14000), 'utilisateurs': min(n, r.randint(1, 3))}
        top = [(procs[0][1], round(cpu * r.uniform(0.2, 0.5), 1), procs[0][0]), ('root', round(r.uniform(0.5, 3), 1), 'sshd'),
               (procs[0][1], round(r.uniform(1, 6), 1), procs[0][0]), ('root', round(r.uniform(0.1, 1), 1), 'crond')]
        sy = systeme(nom, role, r, cpu, mem, os_, disques, (motifs, top), dict((s, 'active') for s in svcs), ncpu, ram)
        snap = {'collecteur': '1.0', 'nom': nom, 'role': role, 'horodatage': maint.strftime('%Y-%m-%d %H:%M:%S'),
                'epoch': 0, 'erreurs': [], 'systeme': sy, 'cron': taches(role, maint)}
        if role in ('bdd', 'repl'):
            snap['informix'] = informix(r, role, maint)
        if role == 'bdd':
            snap['connexions'] = connexions(r, maint)
        if role == 'api':
            snap['api'] = [{'url': 'https://srv-api01.tractafric.local/api/sante', 'code': 200, 'ms': 184, 'erreur': '', 'ok': True},
                           {'url': 'https://srv-api01.tractafric.local/ws/commandes', 'code': 200, 'ms': 412, 'erreur': '', 'ok': True}]
        # historique : 7 jours, une mesure toutes les 15 minutes, au rythme de l'activité
        lignes = []
        for k in range(7 * 96, 0, -1):
            t = maint - dt.timedelta(minutes=15 * k)
            act = activite(t.hour + t.minute / 60.0, t.weekday())
            c = round(min(99, max(2, cpu * (0.25 + act) * r.uniform(0.85, 1.15))), 1)
            m = round(min(99, max(10, mem * (0.85 + 0.15 * act) + r.uniform(-2, 2))), 1)
            ligne = resume({'horodatage': t.strftime('%Y-%m-%d %H:%M:%S'),
                            'systeme': dict(sy, cpu_pct=c, memoire=dict(sy['memoire'], pct=m), charge=[c / 100 * ncpu]),
                            'informix': dict(snap['informix'], sessions=int(snap['informix']['sessions'] * (0.2 + 0.8 * act)))
                            if snap.get('informix') else None,
                            'api': [dict(a, ms=int(a['ms'] * (0.7 + act) * r.uniform(0.8, 1.3))) for a in snap['api']]
                            if snap.get('api') else None})
            lignes.append(json.dumps(ligne, sort_keys=True))
        with io.open(hist, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lignes) + '\n')
        ajouter_historique(hist, resume(snap), 8)
        ecrire_json(os.path.join(dossier, 'dernier.json'), snap)
    return partage
