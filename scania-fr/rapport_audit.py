#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Analyse des audits de performance IRIUM / Informix / RHEL (Scania France) et rapport HTML.

  python3 rapport_audit.py <dossier ou archive .tar.gz> [<autre serveur> ...] [-o rapport.html]

Un rapport unique regroupe tous les serveurs audités (base principale, réplica, applications, ipscrond) :
  - diagnostic automatique classé par gravité, avec les preuves chiffrées et les recommandations ;
  - analyse des signalements utilisateurs (« marquer ») : ce qui se passait à ce moment-là ;
  - corrélations entre serveurs (traitements ipscrond <-> charge et verrous de la base) ;
  - graphiques sur la période : CPU, charge, mémoire, disques, réseau, Informix (cache, verrous,
    sessions en attente, checkpoints, file d'attente CPU), processus IRIUM ;
  - classements des objets les plus coûteux (lectures physiques et logiques, scans séquentiels, parcours
    inverses d'index, verrous), sessions, remplissage des dbspaces, fraîcheur des statistiques ;
  - paramètres clés ONCONFIG commentés et croisés avec les mesures ;
  - en fin de rapport, le plan de recommandations priorisé (également exporté en CSV pour Excel).
Python 2.7 ou 3.6+, aucune dépendance : fonctionne avec le python 2.7 de RHEL 7 et /usr/libexec/platform-python (RHEL 8).
"""
from __future__ import division, print_function, unicode_literals

import argparse
import csv
import datetime as dt
import glob
import io
import math
import os
import re
import shutil
import sys
import tarfile
import tempfile

PY2 = sys.version_info[0] < 3
TAILLE_MAX_FICHIER = 200 * 1024 * 1024   # un relevé brut plus gros est anormal (ex. onstat -g spi non agrégé des anciennes versions)
if PY2:   # RHEL 7 : python 2.7 seul
    str = unicode  # noqa: F821

COULEURS = ['#2a78d6', '#eb6834', '#1baf7a', '#eda100', '#e87ba4', '#6250d6', '#008300', '#e34948']
GRAV = {'critique': ('#d03b3b', '⬣', 0), 'haute': ('#ec835a', '◆', 1), 'moyenne': ('#fab219', '▲', 2), 'info': ('#7a7a76', 'ℹ', 3)}
ATTENTES = {'B': 'buffer', 'C': 'checkpoint', 'G': 'écriture log', 'L': 'verrou', 'S': 'mutex', 'T': 'transaction',
            'Y': 'condition', 'X': 'rollback'}


# --------------------------------------------------------------------------------------------
# Lecture des fichiers bruts
# --------------------------------------------------------------------------------------------
def blocs(chemin):
    """Découpe un fichier « ### epoch date » en [(datetime, texte)]."""
    res = []
    if not os.path.exists(chemin):
        return res
    if os.path.getsize(chemin) > TAILLE_MAX_FICHIER:
        print('Ignoré (fichier de %d Mo) : %s' % (os.path.getsize(chemin) // 1048576, chemin), file=sys.stderr)
        return res
    with io.open(chemin, encoding='utf-8', errors='replace') as f:
        ts, buf = None, []
        for ligne in f:
            if ligne.startswith('### '):
                if ts is not None:
                    res.append((ts, ''.join(buf)))
                try:
                    ts = dt.datetime.fromtimestamp(int(ligne.split()[1]))
                except (IndexError, ValueError):
                    ts = None
                buf = []
            else:
                buf.append(ligne)
        if ts is not None:
            res.append((ts, ''.join(buf)))
    return res


def lire(chemin, defaut=''):
    try:
        with io.open(chemin, encoding='utf-8', errors='replace') as f:
            return f.read()
    except (IOError, OSError):
        return defaut


def num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def stats(valeurs):
    v = sorted(x for x in valeurs if x is not None)
    if not v:
        return {'n': 0, 'moy': None, 'max': None, 'p95': None, 'min': None}
    return {'n': len(v), 'moy': sum(v) / len(v), 'max': v[-1], 'min': v[0], 'p95': v[min(len(v) - 1, int(math.ceil(0.95 * len(v))) - 1)]}


# --------------------------------------------------------------------------------------------
# Système : /proc
# --------------------------------------------------------------------------------------------
def serie_cpu(d):
    res, prec = [], None
    for ts, t in blocs(os.path.join(d, 'series', 'stat.raw')):
        m = re.search(r'^cpu\s+(.+)$', t, re.M)
        if not m:
            continue
        v = [int(x) for x in m.group(1).split()]
        v += [0] * (8 - len(v))
        ctxt = re.search(r'^ctxt (\d+)', t, re.M)
        pr = re.search(r'^procs_running (\d+)', t, re.M)
        pb = re.search(r'^procs_blocked (\d+)', t, re.M)
        cur = (ts, v, int(ctxt.group(1)) if ctxt else 0)
        if prec:
            dv = [a - b for a, b in zip(v, prec[1])]
            tot = sum(dv[:8]) or 1
            el = (ts - prec[0]).total_seconds() or 1
            res.append({'ts': ts, 'user': 100.0 * (dv[0] + dv[1]) / tot, 'sys': 100.0 * (dv[2] + dv[5] + dv[6]) / tot,
                        'iowait': 100.0 * dv[4] / tot, 'steal': 100.0 * dv[7] / tot, 'idle': 100.0 * dv[3] / tot,
                        'ctxt_s': (cur[2] - prec[2]) / el, 'running': int(pr.group(1)) if pr else None,
                        'blocked': int(pb.group(1)) if pb else None})
        prec = cur
    return res


def serie_charge(d):
    res = []
    for ts, t in blocs(os.path.join(d, 'series', 'loadavg.raw')):
        p = t.split()
        if len(p) >= 3:
            res.append({'ts': ts, 'load1': num(p[0]), 'load5': num(p[1])})
    return res


def serie_memoire(d):
    res, prec = [], None
    vm = {ts: t for ts, t in blocs(os.path.join(d, 'series', 'vmstat.raw'))}
    for ts, t in blocs(os.path.join(d, 'series', 'meminfo.raw')):
        m = {k: int(v) for k, v in re.findall(r'^(\w+):\s+(\d+)', t, re.M)}
        tot = m.get('MemTotal') or 1
        dispo = m.get('MemAvailable', m.get('MemFree', 0) + m.get('Cached', 0))
        e = {'ts': ts, 'dispo_pct': 100.0 * dispo / tot, 'swap_utilise_mo': (m.get('SwapTotal', 0) - m.get('SwapFree', 0)) / 1024.0,
             'cache_mo': m.get('Cached', 0) / 1024.0, 'total_mo': tot / 1024.0}
        v = vm.get(ts)
        if v:
            pv = {k: int(x) for k, x in re.findall(r'^(\w+) (\d+)', v, re.M)}
            if prec:
                el = (ts - prec[0]).total_seconds() or 1
                e['swap_in_s'] = (pv.get('pswpin', 0) - prec[1].get('pswpin', 0)) / el
                e['swap_out_s'] = (pv.get('pswpout', 0) - prec[1].get('pswpout', 0)) / el
                e['majflt_s'] = (pv.get('pgmajfault', 0) - prec[1].get('pgmajfault', 0)) / el
                sp = lambda pref: sum(x for k, x in pv.items() if k.startswith(pref)) - sum(x for k, x in prec[1].items() if k.startswith(pref))
                e['compact_stall_s'] = sp('compact_stall') / el
                e['allocstall_s'] = sp('allocstall') / el
                e['pgscan_direct_s'] = sp('pgscan_direct') / el
                e['recup_mo_s'] = sp('pgsteal_') * 4 / 1024.0 / el
            prec = (ts, pv)
        res.append(e)
    return res


def serie_disques(d):
    """%util, await (ms), IOPS et débit par périphérique à partir de /proc/diskstats."""
    par, prec = {}, None
    for ts, t in blocs(os.path.join(d, 'series', 'diskstats.raw')):
        cur = {}
        for l in t.splitlines():
            p = l.split()
            if len(p) < 14:
                continue
            nom = p[2]
            if re.match(r'^(loop|ram|sr|fd)\d*', nom) or re.match(r'^(sd[a-z]+|vd[a-z]+|xvd[a-z]+|hd[a-z]+)\d+$', nom) or re.match(r'^nvme\d+n\d+p\d+$', nom):
                continue   # partitions et pseudo-périphériques : on garde disques entiers, dm-* et md*
            r, rs, rt, w, ws, wt, ios, tio = (int(p[3]), int(p[5]), int(p[6]), int(p[7]), int(p[9]), int(p[10]), int(p[12]), int(p[13]))
            cur[nom] = (r, rs, rt, w, ws, wt, tio)
        if prec:
            el = (ts - prec[0]).total_seconds() or 1
            for nom, v in cur.items():
                if nom not in prec[1]:
                    continue
                dv = [a - b for a, b in zip(v, prec[1][nom])]
                ios = dv[0] + dv[3]
                par.setdefault(nom, []).append({
                    'ts': ts, 'util': min(100.0, 100.0 * dv[6] / (el * 1000)), 'r_s': dv[0] / el, 'w_s': dv[3] / el,
                    'rmo_s': dv[1] * 512 / el / 1048576, 'wmo_s': dv[4] * 512 / el / 1048576,
                    'await': (dv[2] + dv[5]) / ios if ios else 0.0, 'r_await': dv[2] / dv[0] if dv[0] else 0.0,
                    'w_await': dv[5] / dv[3] if dv[3] else 0.0})
        prec = (ts, cur)
    # on ne garde que les périphériques qui ont réellement travaillé
    return {k: v for k, v in par.items() if sum(x['r_s'] + x['w_s'] for x in v) > 0}


def noms_dm(d):
    """dm-3 -> nom LVM/multipath et point de montage, d'après lsblk."""
    res = {}
    txt = lire(os.path.join(d, 'statique', 'disques.txt'))
    for l in txt.splitlines():
        p = l.split()
        if len(p) >= 3 and p[2] in ('lvm', 'disk', 'mpath', 'part', 'raid1', 'raid5', 'raid10', 'crypt'):
            nom, kname = re.sub(r'^[^\w]+', '', p[0]), p[1]
            mnt = p[-1] if p[-1].startswith('/') or p[-1] == '[SWAP]' else ''
            res[kname] = (nom + (' ' + mnt if mnt else '')).strip()
    return res


def serie_reseau(d):
    res, prec = [], None
    for ts, t in blocs(os.path.join(d, 'series', 'snmp.raw')):
        l = [x for x in t.splitlines() if x.startswith('Tcp:')]
        if len(l) < 2:
            continue
        m = dict(zip(l[0].split()[1:], [int(x) for x in l[1].split()[1:]]))
        if prec:
            out = m.get('OutSegs', 0) - prec.get('OutSegs', 0)
            ret = m.get('RetransSegs', 0) - prec.get('RetransSegs', 0)
            res.append({'ts': ts, 'retrans_pct': 100.0 * ret / out if out > 0 else 0.0, 'estab': m.get('CurrEstab')})
        prec = m
    return res


def serie_latence(d):
    res = []
    for ts, t in blocs(os.path.join(d, 'series', 'latence.raw')):
        m = re.search(r'= [\d.]+/([\d.]+)/([\d.]+)/', t)
        perte = re.search(r'(\d+)% packet loss', t)
        tcp = re.search(r'tcp_connect_ms (\S+)', t)
        res.append({'ts': ts, 'ping_ms': num(m.group(1)) if m else None, 'ping_max': num(m.group(2)) if m else None,
                    'perte': num(perte.group(1)) if perte else None,
                    'tcp_ms': num(tcp.group(1)) if tcp and tcp.group(1) != 'ECHEC' else None,
                    'tcp_echec': bool(tcp and tcp.group(1) == 'ECHEC')})
    return res


def serie_irium(d, motifs_batch=r'ipscrond'):
    res, jobs = [], {}
    for ts, t in blocs(os.path.join(d, 'series', 'irium.raw')):
        lignes = [l for l in t.splitlines() if l.strip() and not l.lstrip().startswith('PID')]
        batch = [l for l in lignes if re.search(motifs_batch, l)]
        cpu = sum(num(l.split()[4]) or 0 for l in lignes if len(l.split()) > 5)
        rss = sum(num(l.split()[6]) or 0 for l in lignes if len(l.split()) > 6) / 1024.0
        res.append({'ts': ts, 'processus': len(lignes), 'batch': len(batch), 'cpu': cpu, 'rss_mo': rss})
        for l in batch:
            p = l.split(None, 7)
            if len(p) >= 8 and p[1] != '1':
                cmd = p[7][:140]
                j = jobs.setdefault(cmd, {'cmd': cmd, 'debut': ts, 'fin': ts, 'cpu_max': 0.0, 'vu': 0})
                j['fin'] = ts
                j['cpu_max'] = max(j['cpu_max'], num(p[4]) or 0)
                j['vu'] += 1
    return res, sorted(jobs.values(), key=lambda j: -j['vu'])


def top_processus(d):
    compte = {}
    for _ts, t in blocs(os.path.join(d, 'series', 'top.raw')):
        section = ''
        for l in t.splitlines():
            if l.startswith('# '):
                section = l[2:].strip()
                continue
            p = l.split(None, 7)
            if section == 'CPU' and len(p) >= 7 and p[0].isdigit():
                cle = (p[1], p[6])
                c = compte.setdefault(cle, {'user': p[1], 'cmd': p[6], 'args': p[7][:120] if len(p) > 7 else '', 'n': 0, 'cpu': []})
                c['n'] += 1
                c['cpu'].append(num(p[2]) or 0)
    return sorted(compte.values(), key=lambda c: -sum(c['cpu']))[:12]


def etat_d(d):
    n = {}
    for _ts, t in blocs(os.path.join(d, 'series', 'top.raw')):
        sec = t.split('# ETAT_D', 1)
        if len(sec) == 2:
            for l in sec[1].splitlines():
                p = l.split()
                if len(p) >= 5 and p[0].isdigit():
                    n[(p[4], p[3])] = n.get((p[4], p[3]), 0) + 1
    return sorted(n.items(), key=lambda kv: -kv[1])[:10]


# --------------------------------------------------------------------------------------------
# Informix : onstat
# --------------------------------------------------------------------------------------------
def parse_profil(t):
    """onstat -p : en-têtes de noms suivis d'une ligne de valeurs."""
    res, lignes = {}, [l.split() for l in t.splitlines()]
    for i in range(len(lignes) - 1):
        noms, vals = lignes[i], lignes[i + 1]
        if noms and vals and len(noms) == len(vals) and all(num(v) is not None for v in vals) and not any(num(n) is not None for n in noms):
            vus = {}
            for n, v in zip(noms, vals):
                if n in vus:
                    vus[n] += 1
                    n = '%s_%d' % (n, vus[n])
                else:
                    vus[n] = 1
                res[n] = float(v)
    return res


def serie_profil(d):
    res, prec = [], None
    for ts, t in blocs(os.path.join(d, 'informix', 'onstat_p.raw')):
        p = parse_profil(t)
        if not p:
            continue
        if prec and p.get('bufreads', 0) >= prec[1].get('bufreads', 0):
            el = (ts - prec[0]).total_seconds() or 1
            dl = lambda k: p.get(k, 0) - prec[1].get(k, 0)
            br, bw = dl('bufreads'), dl('bufwrits')
            res.append({'ts': ts, 'cache_lect': 100.0 * (br - dl('dskreads')) / br if br > 0 else None,
                        'cache_ecr': 100.0 * (bw - dl('dskwrits')) / bw if bw > 0 else None,
                        'bufreads_s': br / el, 'dskreads_s': dl('dskreads') / el, 'dskwrits_s': dl('dskwrits') / el,
                        'isam_s': dl('isamtot') / el, 'commit_s': dl('commit') / el, 'rollbk_s': dl('rollbk') / el,
                        'lockwts_min': dl('lokwaits') * 60 / el, 'lockreqs_s': dl('lockreqs') / el, 'deadlks': dl('deadlks'),
                        'dltouts': dl('dltouts'), 'ckpwaits': dl('ckpwaits'), 'seqscans_min': dl('seqscans') * 60 / el,
                        'bufwaits_min': dl('bufwaits') * 60 / el, 'ovlock': dl('ovlock'), 'ovbuff': dl('ovbuff'),
                        'ovuserthread': dl('ovuserthread'), 'lchwaits_min': dl('lchwaits') * 60 / el,
                        'bufwaits_ratio': 100.0 * dl('bufwaits') / (dl('pagreads') + br) if (dl('pagreads') + br) > 0 else None,
                        'ra_eff': 100.0 * dl('RA-pgsused') / (dl('ixda-RA') + dl('idx-RA') + dl('da-RA'))
                        if (dl('ixda-RA') + dl('idx-RA') + dl('da-RA')) > 0 else None})
        prec = (ts, p)
    return res


def serie_sessions(d):
    res = []
    for ts, t in blocs(os.path.join(d, 'informix', 'onstat_u.raw')):
        e = {'ts': ts, 'actives': 0}
        for k in ATTENTES:
            e['att_' + k] = 0
        for l in t.splitlines():
            p = l.split()
            if len(p) >= 7 and re.match(r'^[0-9a-f]{6,}$', p[0]) and len(p[1]) == 7:
                e['actives'] += 1
                if p[1][0] in ATTENTES:
                    e['att_' + p[1][0]] += 1
        m = re.search(r'(\d+) active, (\d+) total, (\d+) maximum concurrent', t)
        if m:
            e['total'], e['max_conc'] = int(m.group(2)), int(m.group(3))
        res.append(e)
    return res


def serie_simple(d, fichier, fonction):
    return [dict(fonction(t), ts=ts) for ts, t in blocs(os.path.join(d, 'informix', fichier))]


def f_verrous(t):
    m = re.search(r'(\d+) active, (\d+) total, (\d+) hash buckets, (\d+) lock table overflows', t)
    return {'verrous': int(m.group(1)), 'verrous_total': int(m.group(2)), 'overflows': int(m.group(4))} if m else {}


def f_ready(t):
    return {'ready': len([l for l in t.splitlines() if re.search(r'\bready\b', l) and re.match(r'^\s*\d+', l)])}


def f_fg(t):
    l = t.splitlines()
    for i, x in enumerate(l):
        if 'Fg Writes' in x and i + 1 < len(l):
            v = [num(y) for y in l[i + 1].split()[:3]]
            if len(v) == 3 and None not in v:
                return {'fg': v[0], 'lru': v[1], 'chunk': v[2]}
    return {}


def f_entete(t):
    m = re.search(r'--\s*(.+?)\s*--\s*Up', t)
    b = re.search(r'Blocked:\s*(\S+)', t)
    u = re.search(r'Up\s+(?:(\d+)\s+days?\s+)?(\d+):(\d\d):(\d\d)', t)
    up = (int(u.group(1) or 0) * 86400 + int(u.group(2)) * 3600 + int(u.group(3)) * 60 + int(u.group(4))) if u else None
    return {'mode': m.group(1) if m else '', 'bloque': b.group(1) if b else '', 'uptime_s': up}


def deltas(serie, cle, par_min=False):
    res, prec = [], None
    for e in serie:
        if cle in e and prec is not None and cle in prec:
            v = e[cle] - prec[cle]
            if v >= 0:
                if par_min:
                    v = v * 60 / ((e['ts'] - prec['ts']).total_seconds() or 1)
                res.append({'ts': e['ts'], cle: v})
        prec = e
    return res


def checkpoints(d):
    vus = {}
    for ts, t in blocs(os.path.join(d, 'informix', 'onstat_ckp.raw')) + [(None, lire(os.path.join(d, 'informix', 'fin_onstat_ckp.txt')))]:
        jour = (ts or dt.datetime.now()).date()
        for l in t.splitlines():
            m = re.match(r'^\s*(\d+)\s+(\d\d:\d\d:\d\d)\s+(\S+)\s+(\S+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+(\d+)', l)
            if m and m.group(1) not in vus:
                h = dt.datetime.combine(jour, dt.datetime.strptime(m.group(2), '%H:%M:%S').time())
                vus[m.group(1)] = {'ts': h, 'declencheur': m.group(3), 'total': float(m.group(5)), 'flush': float(m.group(6)),
                                   'bloque': float(m.group(7)), 'attentes': int(m.group(8))}
    return sorted(vus.values(), key=lambda c: c['ts'])


def vp_cpu(d):
    """Occupation des VP CPU Informix entre le premier et le dernier « onstat -g glo »."""
    b = blocs(os.path.join(d, 'informix', 'onstat_glo.raw'))
    if len(b) < 2:
        return None

    def classes(t):
        res, dans = {}, False
        for l in t.splitlines():
            if 'Virtual processor summary' in l:
                dans = True
                continue
            if dans:
                p = l.split()
                if not p:
                    if res:
                        break
                    continue
                if len(p) >= 5 and num(p[1]) is not None and num(p[-1]) is not None:
                    res[p[0]] = (num(p[1]), num(p[-1]))
        return res
    a, z = classes(b[0][1]), classes(b[-1][1])
    el = (b[-1][0] - b[0][0]).total_seconds() or 1
    res = {}
    for c, (vps, tot) in z.items():
        if c in a and vps:
            if c != 'total':
                res[c] = {'vps': int(vps), 'occupation': 100.0 * (tot - a[c][1]) / el / vps}
    return res


def logs_logiques(d):
    b = blocs(os.path.join(d, 'informix', 'onstat_l.raw'))
    if not b:
        t = lire(os.path.join(d, 'statique', 'informix', 'onstat__l.txt'))
    else:
        t = b[-1][1]
    total = non_sauves = 0
    for l in t.splitlines():
        p = l.split()
        if len(p) >= 7 and re.match(r'^[0-9a-f]{6,}$', p[0]) and re.match(r'^[UFA-]', p[2]) and len(p[2]) == 7:
            total += 1
            if p[2][0] == 'U' and 'B' not in p[2]:
                non_sauves += 1
    return {'total': total, 'non_sauves': non_sauves}


def bascules_logs(d):
    """Nombre de logs logiques remplis par heure (uniqid du log courant, premier et dernier relevé)."""
    pts = []
    for ts, t in blocs(os.path.join(d, 'informix', 'onstat_l.raw')):
        for l in t.splitlines():
            p = l.split()
            if len(p) >= 4 and re.match(r'^[0-9a-f]{6,}$', p[0]) and len(p[2]) == 7 and 'C' in p[2] and p[3].isdigit():
                pts.append((ts, int(p[3])))
    if len(pts) < 2 or (pts[-1][0] - pts[0][0]).total_seconds() < 1800:
        return None
    return (pts[-1][1] - pts[0][1]) * 3600.0 / (pts[-1][0] - pts[0][0]).total_seconds()


def iof(d):
    b = blocs(os.path.join(d, 'informix', 'onstat_iof.raw'))
    t = b[-1][1] if b else lire(os.path.join(d, 'statique', 'informix', 'onstat__g_iof.txt'))
    res, cour = [], None
    for l in t.splitlines():
        p = l.split()
        if len(p) >= 6 and p[0].isdigit() and ('/' in p[1]):
            cour = {'fichier': p[1], 'lectures': 0, 'lect_ms': None, 'ecritures': 0, 'ecr_ms': None}
            res.append(cour)
        elif cour and len(p) >= 3 and p[0] in ('reads', 'writes') and p[1].isdigit():
            ms = num(p[2])
            if p[0] == 'reads':
                cour['lectures'], cour['lect_ms'] = int(p[1]), ms * 1000 if ms is not None else None
            else:
                cour['ecritures'], cour['ecr_ms'] = int(p[1]), ms * 1000 if ms is not None else None
    return res


def replication(d):
    b = blocs(os.path.join(d, 'informix', 'onstat_dri.raw'))
    etats, backlog = [], []
    for ts, t in b:
        m = re.search(r'^\s*(primary|HDR Secondary|secondary|standard)\s+(\w+)\s+(\S+)', t, re.M | re.I)
        if m:
            etats.append((ts, m.group(1), m.group(2), m.group(3)))
        bl = re.search(r'Backlog\s+(\d+)', t)
        if bl:
            backlog.append({'ts': ts, 'backlog': int(bl.group(1))})
    return etats, backlog


def nb_rss(d):
    m = re.search(r'Number of RSS servers:\s*(\d+)', lire(os.path.join(d, 'statique', 'informix', 'onstat__g_rss.txt')) +
                  ''.join(t for _ts, t in blocs(os.path.join(d, 'informix', 'onstat_rss.raw'))[-1:]))
    return int(m.group(1)) if m else 0


def onconfig(d):
    t = lire(os.path.join(d, 'statique', 'informix', 'onconfig.txt')) or lire(os.path.join(d, 'statique', 'informix', 'onstat__c.txt'))
    res = {}
    for l in t.splitlines():
        p = l.split(None, 1)
        if len(p) == 2 and re.match(r'^[A-Z][A-Z0-9_]+$', p[0]):
            v = p[1].split('#')[0].strip()
            if p[0] in ('BUFFERPOOL', 'VPCLASS', 'NETTYPE', 'DBSPACETEMP'):
                res.setdefault(p[0], [])
                if v not in res[p[0]]:
                    res[p[0]].append(v)
            elif p[0] not in res:
                res[p[0]] = v
    return res


def journal_moteur(d, debut, fin):
    t = lire(os.path.join(d, 'informix', 'fin_online_log.txt')) or lire(os.path.join(d, 'statique', 'informix', 'online_log.txt'))
    evenements, ckp = [], []
    jour = debut.date()
    motifs = [('Long Transaction', 'critique'), ('Assert', 'critique'), ('lock table overflow', 'haute'), ('Logical Log Files are Full', 'critique'),
              ('Maximum server connections', 'haute'), ('deadlock', 'moyenne'), ('out of memory', 'critique'), ('Cannot allocate', 'haute'),
              ('DR: ', 'moyenne'), ('RSS', 'info'), ('Physical Log File Overflow', 'haute'), ('virtual memory segment', 'moyenne'),
              ('Dynamically added', 'moyenne'), ('error', 'moyenne'), ('Aborting', 'critique'), ('blocked', 'haute')]
    for l in t.splitlines():
        md = re.match(r'^\w{3} (\w{3})\s+(\d+) (\d\d:\d\d:\d\d) (\d{4})', l)
        if md:
            try:
                jour = dt.datetime.strptime('%s %s %s' % (md.group(1), md.group(2), md.group(4)), '%b %d %Y').date()
            except ValueError:
                pass
            continue
        md2 = re.match(r'^(\d\d/\d\d/\d\d)\s+(\d\d:\d\d:\d\d)\s+(.*)$', l)   # MSG_DATE 1
        if md2:
            for f in ('%m/%d/%y', '%d/%m/%y'):
                try:
                    jour = dt.datetime.strptime(md2.group(1), f).date()
                    break
                except ValueError:
                    pass
            l = md2.group(2) + '  ' + md2.group(3)
        mh = re.match(r'^(\d\d:\d\d:\d\d)\s+(.*)$', l)
        if not mh:
            continue
        h = dt.datetime.combine(jour, dt.datetime.strptime(mh.group(1), '%H:%M:%S').time())
        if not (debut - dt.timedelta(hours=1) <= h <= fin + dt.timedelta(minutes=5)):
            continue
        msg = mh.group(2)
        c = re.search(r'Checkpoint Completed:\s+duration was (\d+) seconds', msg)
        if c:
            ckp.append({'ts': h, 'total': float(c.group(1))})
            continue
        for motif, g in motifs:
            if motif.lower() in msg.lower():
                evenements.append((h, g, msg[:240]))
                break
    return evenements, ckp


# --------------------------------------------------------------------------------------------
# Objets Informix : profils par partition (onstat -g ppf, sysptprof), sessions, inventaire
# --------------------------------------------------------------------------------------------
PPF = ('lkrqs', 'lkwts', 'dlks', 'touts', 'isrd', 'iswrt', 'isrwt', 'isdel', 'bfrd', 'bfwrt', 'seqsc', 'rvscn', 'rhit')
BASES_SYSTEME = ('sysmaster', 'sysadmin', 'sysutils', 'sysuser', 'sysha', 'syscdr')


def entier(v):
    """Compteur onstat ou unload : '123', '1.2e9', '12K', '3M'."""
    v = (v or '').strip()
    m = re.match(r'^(-?[\d.]+(?:e\+?\d+)?)([KMG]?)$', v, re.I)
    if not m:
        return None
    return float(m.group(1)) * {'': 1, 'K': 1e3, 'M': 1e6, 'G': 1e9}[m.group(2).upper()]


def lignes_unl(t):
    res = []
    for l in t.splitlines():
        if '|' in l:
            p = [x.strip() for x in l.split('|')]
            res.append(p[:-1] if p and p[-1] == '' else p)
    return res


def parse_ppf(t):
    res = {}
    for l in t.splitlines():
        p = l.split()
        if len(p) >= 14 and p[0].startswith('0x'):
            try:
                pn = int(p[0], 16)
            except ValueError:
                continue
            v = [entier(x) for x in p[1:14]]
            if None not in v:
                res[pn] = dict(zip(PPF, v))
    return res


def date_sql(v, dmy=True):
    v = (v or '').strip()
    for f in (('%d/%m/%Y', '%m/%d/%Y') if dmy else ('%m/%d/%Y', '%d/%m/%Y')) + ('%Y-%m-%d',):
        try:
            return dt.datetime.strptime(v[:19].split(' ')[0] if f == '%Y-%m-%d' else v[:10], f)
        except ValueError:
            pass
    return None


def inventaire(d):
    inv = os.path.join(d, 'informix', 'inventaire')
    r = {'dbspaces': [], 'tailles': {}, 'stats': {}, 'index': {}, 'noms': {}, 'index_detail': {}, 'bases': {}}
    for x in lignes_unl(lire(os.path.join(inv, 'bases.unl'))):
        if len(x) >= 3:
            r['bases'][x[0]] = {'journalisee': x[1] == '1', 'log_bufferise': x[2] == '1', 'ansi': len(x) > 3 and x[3] == '1'}
    for x in lignes_unl(lire(os.path.join(inv, 'dbspaces.unl'))):
        if len(x) >= 5 and entier(x[3]):
            tot, libre = entier(x[3]), entier(x[4]) or 0
            r['dbspaces'].append({'nom': x[0], 'temp': x[1] == '1', 'blob': x[2] == '1', 'pages': tot, 'libres': libre,
                                  'libre_pct': 100.0 * libre / tot, 'chunks': int(entier(x[5]) or 0) if len(x) > 5 else 0})
    for x in lignes_unl(lire(os.path.join(inv, 'partitions.unl'))):
        if len(x) >= 3 and re.match(r'^-?\d+$', x[0]):
            r['noms'][int(x[0])] = (x[1], x[2])
    for x in lignes_unl(lire(os.path.join(inv, 'tailles.unl'))):
        if len(x) >= 6:
            cle = (x[0], x[1])
            a = r['tailles'].setdefault(cle, {'nptotal': 0, 'npused': 0, 'nrows': 0, 'nextns': 0})
            for i, k in enumerate(('nptotal', 'npused', 'nrows', 'nextns')):
                a[k] += entier(x[2 + i]) or 0
    env = lire(os.path.join(d, 'statique', 'informix', 'environnement.txt'))
    dmy = not re.search(r'^DBDATE=MDY', env, re.M)
    for f in glob.glob(os.path.join(inv, 'stats_*.unl')):
        base = os.path.basename(f)[6:-4]
        distrib = {x[0]: date_sql(x[1], dmy) for x in lignes_unl(lire(os.path.join(inv, 'distrib_%s.unl' % base))) if len(x) >= 2}
        for x in lignes_unl(lire(f)):
            if len(x) >= 4:
                dates = [v for v in (date_sql(x[3], dmy), distrib.get(x[0])) if v]
                r['stats'][(base, x[0])] = {'nrows': entier(x[1]), 'npused': entier(x[2]), 'stats': max(dates) if dates else None,
                                            'distrib': distrib.get(x[0]), 'verrou': x[4] if len(x) > 4 else '', 'taille_ligne': entier(x[5]) if len(x) > 5 else None}
        for x in lignes_unl(lire(os.path.join(inv, 'index_%s.unl' % base))):
            if len(x) >= 2:
                r['index'][(base, x[0])] = x[1]
            if len(x) >= 15:
                r['index_detail'][(base, x[0])] = {'table': x[1], 'type': x[2], 'cluster': x[3], 'niveaux': entier(x[4]), 'feuilles': entier(x[5]),
                                                   'uniques': entier(x[6]), 'colonnes': [int(entier(c) or 0) for c in x[7:15] if (entier(c) or 0) != 0]}
    return r


def objets(d, inv, uptime_s=None):
    """Compteurs par objet (table ou index) : cumul depuis le démarrage et delta sur la fenêtre d'audit."""
    ppf = [(ts, parse_ppf(t)) for ts, t in blocs(os.path.join(d, 'informix', 'onstat_ppf.raw'))]
    ppf = [x for x in ppf if x[1]]
    if not ppf:
        t = parse_ppf(lire(os.path.join(d, 'statique', 'informix', 'onstat__g_ppf.txt')))
        ppf = [(None, t)] if t else []
    prof = [(ts, lignes_unl(t)) for ts, t in blocs(os.path.join(d, 'informix', 'profil_tables.raw'))]
    prof = [x for x in prof if x[1]]

    def regrouper(dic):
        g = {}
        for pn, v in dic.items():
            base, nom = inv['noms'].get(pn, ('?', '0x%x' % pn))
            if base in BASES_SYSTEME:
                continue
            a = g.setdefault((base, nom), dict((k, 0.0) for k in PPF))
            for k in PPF:
                a[k] = a[k] + v[k] * (v['bfrd'] if k == 'rhit' else 1)
        for a in g.values():
            a['rhit'] = a['rhit'] / a['bfrd'] if a['bfrd'] else None
        return g

    def pagreads(rows):
        g = {}
        for x in rows:
            if len(x) >= 5 and x[0] not in BASES_SYSTEME:
                g[(x[0], x[1])] = g.get((x[0], x[1]), 0) + (entier(x[4]) or 0)
        return g

    if not ppf and not prof:
        return None
    fin = regrouper(ppf[-1][1]) if ppf else {}
    deb = regrouper(ppf[0][1]) if len(ppf) > 1 and ppf[0][0] else None
    duree = (ppf[-1][0] - ppf[0][0]).total_seconds() if deb is not None else 0
    pf, pd = (pagreads(prof[-1][1]), pagreads(prof[0][1])) if prof else ({}, {})
    duree_p = (prof[-1][0] - prof[0][0]).total_seconds() if len(prof) > 1 else 0
    liste = []
    for cle in set(fin) | set(pf):
        base, nom = cle
        c = dict(fin.get(cle) or dict((k, 0.0) for k in PPF))
        c['pagreads'] = pf.get(cle)
        dlt = {}
        if deb is not None and cle in deb and duree > 0 and c['bfrd'] >= deb[cle]['bfrd']:
            dlt = dict((k, c[k] - deb[cle][k]) for k in PPF if k != 'rhit')
        if duree_p > 0 and cle in pd and pf.get(cle) is not None and pf[cle] >= pd[cle]:
            dlt['pagreads'] = pf[cle] - pd[cle]
        table = inv['index'].get(cle)
        taille = inv['tailles'].get(cle) or {}
        st = inv['stats'].get((base, table or nom)) or {}
        liste.append({'base': base, 'nom': nom, 'type': 'index' if table else ('table' if not nom.startswith('0x') else '?'),
                      'table': table or nom, 'c': c, 'd': dlt, 'pages': taille.get('npused') or st.get('npused'),
                      'extents': taille.get('nextns'), 'stats': st.get('stats'), 'stats_connues': bool(st)})
    return {'liste': liste, 'duree_s': duree, 'duree_pag_s': duree_p, 'uptime_s': uptime_s,
            'mapping': bool(inv['noms']), 'ts': ppf[-1][0] if ppf else prof[-1][0]}


def sessions_profil(d):
    b = [(ts, lignes_unl(t)) for ts, t in blocs(os.path.join(d, 'informix', 'profil_sessions.raw'))]
    b = [x for x in b if x[1]]
    if not b:
        return None
    champs = ('sid', 'user', 'hote', 'pid', 'pagreads', 'bufreads', 'isreads', 'seqscans', 'lockreqs', 'lockwts', 'tris', 'tris_disque')
    conv = lambda x: dict(zip(champs, x[:4] + [entier(v) or 0 for v in x[4:12]]))
    deb = {x[0]: conv(x) for x in b[0][1] if len(x) >= 12}
    res = []
    for x in b[-1][1]:
        if len(x) < 12:
            continue
        e = conv(x)
        p0 = deb.get(e['sid']) if len(b) > 1 else None
        e['d_pagreads'] = e['pagreads'] - p0['pagreads'] if p0 and e['pagreads'] >= p0['pagreads'] else None
        e['d_bufreads'] = e['bufreads'] - p0['bufreads'] if p0 and e['bufreads'] >= p0['bufreads'] else None
        res.append(e)
    return {'liste': res, 'duree_s': (b[-1][0] - b[0][0]).total_seconds() if len(b) > 1 else 0, 'ts': b[-1][0]}


def ouverture_chunks(d):
    res = []
    for l in lire(os.path.join(d, 'statique', 'informix', 'chunks_ouverture.txt')).splitlines():
        p = l.split('|')
        if len(p) >= 5 and not l.startswith('#'):
            res.append({'chunk': p[0], 'flags': p[2], 'o_direct': p[3] == '1', 'type': p[4]})
    return res


def buddy(t):
    """Plus grand bloc libre (Ko) des zones Normal/DMA32 dans /proc/buddyinfo."""
    plus_grand = None
    for l in t.splitlines():
        m = re.match(r'^Node\s+\d+,\s+zone\s+(\S+)\s+([\d\s]+)$', l.strip())
        if m and m.group(1) in ('Normal', 'DMA32'):
            cpt = [int(x) for x in m.group(2).split()]
            ordre = max([i for i, n in enumerate(cpt) if n > 0] or [-1])
            if ordre >= 0:
                plus_grand = max(plus_grand or 0, 4 * 2 ** ordre)
    return plus_grand


def serie_buddy(d):
    res = [{'ts': ts, 'bloc_ko': buddy(t)} for ts, t in blocs(os.path.join(d, 'series', 'buddyinfo.raw'))]
    return [e for e in res if e['bloc_ko'] is not None]


def classements(ob, n=15):
    """Quatre classements du rapport de référence + verrous. Chaque entrée : (objet, valeur, part %, fréquence /s)."""
    if not ob:
        return {}
    L, up = ob['liste'], ob.get('uptime_s') or 0
    freq = lambda o, k: (o['d'][k] / ob['duree_s']) if ob['duree_s'] and k in o['d'] else ((o['c'][k] / up) if up else None)
    res = {}
    for cle, k, filtre in [('physiques', 'pagreads', None), ('logiques', 'bfrd', None), ('scans', 'seqsc', lambda o: o['type'] != 'index'),
                           ('inverses', 'rvscn', None), ('verrous', 'lkrqs', None)]:
        tot = sum(o['c'].get(k) or 0 for o in L)
        lst = sorted([o for o in L if (o['c'].get(k) or 0) > 0 and (filtre is None or filtre(o))], key=lambda o: -o['c'][k])[:n]
        res[cle] = {'total': tot, 'liste': [(o, o['c'][k], 100.0 * o['c'][k] / tot if tot else 0, freq(o, k)) for o in lst]}
    return res


def pages_par_scan(o):
    """Taille réelle de la table si connue, sinon lectures logiques / scans (surestime si la table est aussi lue par index)."""
    if o['pages']:
        return o['pages']
    return o['c']['bfrd'] / o['c']['seqsc'] if o['c'].get('seqsc') else None


def regles_objets(s):
    """Constats issus des profils par objet, des sessions et de l'inventaire. [(gravité, domaine, constat, preuve, recommandation)]"""
    r, ob, inv = [], s.get('obj'), s.get('inv') or {}
    cl = classements(ob)
    nm = lambda o: '%s%s' % (o['nom'], ' (index de %s)' % o['table'] if o['type'] == 'index' else '')
    if cl:
        ph = cl['physiques']['liste']
        if ph and len(ph) >= 2 and ph[0][2] + ph[1][2] >= 30:
            r.append(('haute', 'Objets', 'Lectures physiques concentrées sur %s et %s' % (ph[0][0]['nom'], ph[1][0]['nom']),
                      '%.0f %% des %s pages lues sur disque ; %s' % (ph[0][2] + ph[1][2], fmt_n(cl['physiques']['total']),
                                                                    ' ; '.join('%s : %s pages, %s scans, hit ratio %s' % (
                                                                        nm(o), fmt_n(v), fmt_n(o['c']['seqsc']), ('%.0f %%' % o['c']['rhit']) if o['c']['rhit'] is not None else '-')
                                                                        for o, v, _p, _f in ph[:2])),
                      'Parcours complets répétés de grandes tables que le cache ne peut absorber : trace SQL ciblée (sysadmin:task « set sql tracing ») pour identifier '
                      'les requêtes et programmes, ajout des critères ou index manquants, contrôle des statistiques ; à défaut, exécution hors pointe ou sur le secondaire.'))
        inv_l = cl['inverses']['liste']
        if inv_l:
            tot_f = sum(f or 0 for _o, _v, _p, f in inv_l[:2])
            part2 = sum(p for _o, _v, p, _f in inv_l[:2])
            if tot_f > 100 or part2 > 80 and cl['inverses']['total'] > 1e7:
                r.append(('haute' if tot_f > 1000 else 'moyenne', 'Objets', 'Parcours inverses d\'index concentrés (%s)' % ', '.join(o['nom'] for o, _v, _p, _f in inv_l[:2]),
                          '%.0f %% des %s parcours inverses, ≈ %s/s ; %s' % (part2, fmt_n(cl['inverses']['total']), fmt_n(tot_f), ' ; '.join(
                              '%s : %.0f %% des accès en sens inverse' % (nm(o), 100.0 * v / o['c']['isrd']) for o, v, _p, _f in inv_l[:2] if o['c']['isrd'])),
                          'Requêtes du type « dernière ligne pour une clé » (ORDER BY … DESC, MAX, FIRST 1) exécutées en boucle : les identifier, créer un index '
                          'décroissant adapté, réécrire la requête ou conserver la valeur en mémoire côté programme.'))
        for o in [o for o in ob['liste'] if o['type'] != 'index' and (o['c']['seqsc'] or 0) >= 10]:
            pps = pages_par_scan(o)
            if pps and pps >= 4000 and pps * o['c']['seqsc'] >= 1e8:
                o['_cout'] = pps * o['c']['seqsc']
        couteux = sorted([o for o in ob['liste'] if o.get('_cout')], key=lambda o: -o['_cout'])[:5]
        if couteux:
            r.append(('haute' if couteux[0]['_cout'] > 1e9 else 'moyenne', 'Objets', 'Scans séquentiels coûteux sur de grandes tables',
                      ' ; '.join('%s : %s scans × %s pages, %s demandes de verrou' % (o['nom'], fmt_n(o['c']['seqsc']), fmt_n(pages_par_scan(o)), fmt_n(o['c']['lkrqs']))
                                 for o in couteux),
                      'Analyser les plans d\'exécution (SET EXPLAIN ON) des requêtes sur ces tables ; créer les index sur les critères de recherche. '
                      'Un volume de verrous élevé sur des lectures signale des parcours sous verrou de ligne : revoir le niveau d\'isolation et les curseurs FOR UPDATE.'))
        up = ob.get('uptime_s') or 0
        fq = lambda o, k: (o['d'][k] / ob['duree_s']) if ob['duree_s'] and k in o['d'] else ((o['c'][k] / up) if up else 0)
        moyens = [o for o in ob['liste'] if o['type'] != 'index' and fq(o, 'seqsc') >= 0.5 and 20 <= (pages_par_scan(o) or 0) < 4000]
        if moyens:
            moyens.sort(key=lambda o: -fq(o, 'seqsc') * pages_par_scan(o))
            r.append(('moyenne', 'Objets', 'Scans fréquents de tables moyennes',
                      ' ; '.join('%s : %s scans/s × %s pages' % (o['nom'], fmt_n(fq(o, 'seqsc')), fmt_n(pages_par_scan(o))) for o in moyens[:5]),
                      'Chaque passage est peu coûteux mais la fréquence en fait un poste significatif : un index sur le critère de recherche ramène l\'accès à quelques pages.'))
        petits = [o for o in ob['liste'] if o['type'] != 'index' and fq(o, 'seqsc') >= 2 and (pages_par_scan(o) or 99) <= 2]
        if petits:
            petits.sort(key=lambda o: -fq(o, 'seqsc'))
            r.append(('info', 'Objets', 'Petites tables relues en boucle',
                      ' ; '.join('%s : %s lectures/s' % (o['nom'], fmt_n(fq(o, 'seqsc'))) for o in petits[:5]),
                      'Paramètres relus à chaque itération : les conserver en mémoire dans le programme (applicatif).'))
        boucle = [o for o in ob['liste'] if o['type'] == 'index' and fq(o, 'isrd') >= 2000 and o['c']['isrd'] and o['c']['bfrd'] / o['c']['isrd'] <= 6]
        if boucle:
            boucle.sort(key=lambda o: -fq(o, 'isrd'))
            r.append(('moyenne', 'Objets', 'Accès unitaires en boucle sur des index',
                      ' ; '.join('%s : %s lectures ISAM/s (%s lectures logiques par lecture)' % (nm(o), fmt_n(fq(o, 'isrd')), fmt_n(o['c']['bfrd'] / o['c']['isrd'])) for o in boucle[:6]),
                      'Le coût unitaire est normal, c\'est la fréquence qui pèse sur les VP CPU : remplacer les traitements ligne à ligne (FOREACH + requête par ligne) '
                      'par des jointures ou un traitement ensembliste, mettre en cache les données de référence (applicatif).'))
        lk = [o for o, v, _p, f in cl['verrous']['liste'] if (f or 0) > 2000 or v > 5e8]
        if lk:
            r.append(('moyenne', 'Objets', 'Volume massif de demandes de verrou',
                      ' ; '.join('%s : %s demandes (%s/s)' % (nm(o), fmt_n(o['c']['lkrqs']), fmt_n(fq(o, 'lkrqs'))) for o in lk[:5]),
                      'Volume inhabituel pour des accès majoritairement en lecture : vérifier le niveau d\'isolation (REPEATABLE READ ?), les curseurs FOR UPDATE '
                      'et USELASTCOMMITTED ; DIRTY READ ou COMMITTED READ LAST COMMITTED sur les lectures de consultation.'))
        bas = [o for o in ob['liste'] if o['c']['rhit'] is not None and o['c']['rhit'] < 85 and (o['c'].get('pagreads') or 0) > 1e6]
        if bas:
            r.append(('info', 'Objets', 'Hit ratio bas sur des objets lus intensivement',
                      ' ; '.join('%s : %.0f %%' % (nm(o), o['c']['rhit']) for o in bas[:5]),
                      'Accès dispersés que le cache absorbe mal : analyser les requêtes d\'accès et l\'ordre des colonnes de l\'index.'))
        # statistiques de l'optimiseur sur les objets en tête des classements
        cibles, vus = [], set()
        for k in ('physiques', 'logiques', 'scans', 'inverses'):
            for o, _v, _p, _f in cl[k]['liste'][:10]:
                if o['table'] not in vus:
                    vus.add(o['table'])
                    cibles.append(o)
        if inv.get('stats'):
            ref = s['fin']
            vieilles = []
            for o in cibles:
                st = inv['stats'].get((o['base'], o['table']))
                if st is None:
                    continue
                if st['stats'] is None or (ref - st['stats']).days > 30:
                    vieilles.append((o['table'], st['stats']))
            jamais = sum(1 for v in inv['stats'].values() if v['stats'] is None and (v['nrows'] or 0) > 1000)
            if vieilles:
                r.append(('haute', 'Objets', 'Statistiques de l\'optimiseur absentes ou anciennes sur des tables sollicitées',
                          ' ; '.join('%s : %s' % (t, d.strftime('%d/%m/%Y') if d else 'jamais') for t, d in vieilles[:10]) +
                          ((' ; %d table(s) de plus de 1 000 lignes sans statistiques' % jamais) if jamais else ''),
                          'Des statistiques obsolètes produisent des plans erronés (scans complets au lieu d\'index). Relancer UPDATE STATISTICS (MEDIUM sur la table, '
                          'HIGH sur les colonnes de tête des index) hors pointe, puis planifier la tâche (AUTO_STAT_MODE / tâche sysadmin « Auto Update Statistics »).'))
            elif cibles:
                r.append(('info', 'Objets', 'Statistiques récentes sur les tables les plus sollicitées', '%d table(s) vérifiée(s)' % len(cibles),
                          'Les plans erronés dus aux statistiques sont peu probables : analyser directement les requêtes (SET EXPLAIN).'))
    se = s.get('ses_prof')
    if se and se['liste']:
        cle = 'd_pagreads' if se['duree_s'] else 'pagreads'
        tot = sum(e[cle] or 0 for e in se['liste'])
        top = max(se['liste'], key=lambda e: e[cle] or 0)
        if tot and (top[cle] or 0) >= 0.4 * tot and top[cle] > 1e5:
            r.append(('haute', 'Objets', 'Une session concentre les lectures physiques (session %s)' % top['sid'],
                      'session %s, utilisateur %s, poste %s, processus %s : %s pages lues (%.0f %% de toutes les sessions%s), %s scans séquentiels' % (
                          top['sid'], top['user'], top['hote'], top['pid'], fmt_n(top[cle]), 100.0 * top[cle] / tot,
                          ' sur la fenêtre' if cle == 'd_pagreads' else '', fmt_n(top['seqscans'])),
                      'Identifier le programme (ps sur le poste client, onstat -g ses %s, onstat -g sql %s) et tracer ses requêtes '
                      '(EXECUTE FUNCTION sysadmin:task(\'set sql user tracing on\', %s)).' % (top['sid'], top['sid'], top['sid'])))
        tris = sum(e['tris'] for e in se['liste'])
        dsk = sum(e['tris_disque'] for e in se['liste'])
        s['_tris'] = (tris, dsk)
    for db in inv.get('dbspaces', []):
        if db['temp'] or db['blob']:
            continue
        if db['libre_pct'] < 1:
            g = 'critique'
        elif db['libre_pct'] < 5:
            g = 'haute'
        elif db['libre_pct'] < 10:
            g = 'moyenne'
        else:
            continue
        r.append((g, 'Stockage Informix', 'Dbspace %s presque plein' % db['nom'],
                  '%.1f %% d\'espace libre (%s pages libres sur %s, %d chunk(s))' % (db['libre_pct'], fmt_n(db['libres']), fmt_n(db['pages']), db['chunks']),
                  'Les allocations d\'extents peuvent échouer et provoquer des erreurs applicatives : ajouter un chunk (onspaces -a) ou activer l\'extension '
                  'automatique via un storage pool (SP_AUTOEXPAND).'))
    ext = sorted([(k, v) for k, v in inv.get('tailles', {}).items() if v['nextns'] >= 50], key=lambda x: -x[1]['nextns'])
    if ext:
        r.append(('info', 'Stockage Informix', 'Tables très fragmentées en extents',
                  ' ; '.join('%s : %d extents' % (k[1], v['nextns']) for k, v in ext[:6]),
                  'Au-delà de quelques dizaines d\'extents, les parcours sont moins efficaces : revoir EXTENT SIZE / NEXT SIZE et réorganiser hors production (ALTER FRAGMENT … INIT).'))
    return r


def fmt_n(v):
    if v is None:
        return '-'
    v = float(v)
    for lim, div, suf in ((1e9, 1e9, ' Md'), (1e6, 1e6, ' M'), (1e4, 1e3, ' k')):
        if abs(v) >= lim:
            return ('%.1f' % (v / div)).replace('.', ',') + suf
    return ('%.0f' % v) if abs(v) >= 10 or v == int(v) else ('%.1f' % v).replace('.', ',')


# --------------------------------------------------------------------------------------------
# Programmes IRIUM (journal applicatif agr_lds : un enregistrement par programme lancé)
# --------------------------------------------------------------------------------------------
ROLES_COLONNES = [('debut', [r'_open$', r'debut', r'date', r'_ts$']), ('fin', [r'_close$', r'_fin$', r'_end$']),
                  ('utilisateur', [r'user', r'util', r'login', r'operat']), ('programme', [r'_prog$', r'prog', r'appli', r'module', r'_cmd']),
                  ('complement', [r'complement', r'_nom$', r'libel']), ('poste', [r'_tty$', r'host', r'poste', r'term'])]


def date_heure(v):
    v = (v or '').strip()
    for f, n in (('%Y-%m-%d %H:%M:%S', 19), ('%Y-%m-%d %H:%M', 16), ('%d/%m/%Y %H:%M:%S', 19), ('%Y-%m-%d', 10), ('%d/%m/%Y', 10)):
        try:
            return dt.datetime.strptime(v[:n], f)
        except ValueError:
            pass
    return None


def programmes(d):
    meta = dict(re.findall(r'^(\w+)=(.*)$', lire(os.path.join(d, 'informix', 'programmes_table.txt')), re.M))
    if not meta.get('colonnes'):
        return None
    cols = [c.strip() for c in meta['colonnes'].split(',')]
    roles = {}
    for role, motifs in ROLES_COLONNES:
        for m in motifs:
            c = [x for x in cols if re.search(m, x, re.I) and x not in roles.values()]
            if c:
                roles[role] = c[0]
                break
    if meta.get('colonne_date') in cols:
        roles['debut'] = meta['colonne_date']
    final = lire(os.path.join(d, 'informix', 'programmes_final.unl'))
    lignes = lignes_unl(final) if final.strip() else [l for _ts, t in blocs(os.path.join(d, 'informix', 'programmes.raw')) for l in lignes_unl(t)]
    vus, res = set(), []
    idx = dict((r, cols.index(c)) for r, c in roles.items())
    for l in lignes:
        if len(l) < len(cols) or tuple(l) in vus:
            continue
        vus.add(tuple(l))
        v = lambda r: l[idx[r]] if r in idx else ''
        deb = date_heure(v('debut'))
        if not deb:
            continue
        nom = v('programme') or v('complement') or '?'
        if v('programme') and v('complement') and v('complement') != v('programme'):
            nom = '%s (%s)' % (v('programme'), v('complement'))
        res.append({'debut': deb, 'fin': date_heure(v('fin')), 'programme': nom, 'utilisateur': v('utilisateur'), 'poste': v('poste')})
    res.sort(key=lambda e: e['debut'])
    return {'base': meta.get('base'), 'table': meta.get('table'), 'roles': roles, 'liste': res, 'avec_fin': 'fin' in roles}


def en_cours(p, t, marge):
    """Programmes en cours à l'instant t (ou lancés dans la marge précédente si la date de fin est inconnue)."""
    res = []
    for e in p['liste']:
        if e['debut'] > t:
            break
        if (e['fin'] and e['debut'] <= t <= e['fin']) or (not e['fin'] and p['avec_fin'] and e['debut'] <= t and t - e['debut'] < dt.timedelta(hours=8)) \
                or (not p['avec_fin'] and t - marge <= e['debut'] <= t):
            res.append(e)
    return res


def analyse_programmes(s):
    """Activité des programmes pendant l'audit, et programmes sur-représentés pendant les pics de la base."""
    p = s.get('prog')
    if not p or not p['liste']:
        return None
    t0, t1 = s['debut'], s['fin']
    fen = [e for e in p['liste'] if t0 <= e['debut'] <= t1]
    par_prog = {}
    for e in fen:
        a = par_prog.setdefault(e['programme'], {'lancements': 0, 'duree_s': 0.0, 'max_s': 0.0, 'utilisateurs': set(), 'ouverts': 0})
        a['lancements'] += 1
        a['utilisateurs'].add(e['utilisateur'])
        if e['fin']:
            du = (e['fin'] - e['debut']).total_seconds()
            a['duree_s'] += du
            a['max_s'] = max(a['max_s'], du)
        else:
            a['ouverts'] += 1
    serie = []
    pas = dt.timedelta(minutes=5)
    t = t0.replace(second=0, microsecond=0)
    while t <= t1:
        serie.append({'ts': t, 'lancements': sum(1 for e in fen if t <= e['debut'] < t + pas)})
        t += pas
    longs = sorted([e for e in p['liste'] if e['debut'] <= t1 and (e['fin'] or t1) >= t0 and ((e['fin'] or t1) - e['debut']).total_seconds() > 600],
                   key=lambda e: -((e['fin'] or t1) - e['debut']).total_seconds())[:25]
    # pics de la base : 10 % des relevés les plus chargés (lectures logiques) et les plus contendus (attentes de verrou)
    marge = dt.timedelta(seconds=max(60, int(s['info'].get('intervalle_s') or 30) * 2))
    pics = []
    for cle, lib in (('bufreads_s', 'charge (lectures logiques)'), ('lockwts_min', 'attentes de verrou')):
        vals = [e for e in s.get('profil', []) if e.get(cle) is not None]
        if len(vals) < 10:
            continue
        seuil = sorted(e[cle] for e in vals)[int(len(vals) * 0.9)]
        if seuil <= 0:
            continue
        haut = [e['ts'] for e in vals if e[cle] >= seuil]
        tous = [e['ts'] for e in vals]
        pres_h, pres_t = {}, {}
        for ens, dico in ((haut, pres_h), (tous, pres_t)):
            for ts in ens:
                for nom in {x['programme'] for x in en_cours(p, ts, marge)}:
                    dico[nom] = dico.get(nom, 0) + 1
        for nom, n in pres_h.items():
            ph, pt = n / float(len(haut)), pres_t.get(nom, 0) / float(len(tous))
            if ph >= 0.3 and pt and ph / pt >= 1.5:
                pics.append({'indicateur': lib, 'programme': nom, 'pic_pct': 100 * ph, 'global_pct': 100 * pt, 'facteur': ph / pt})
    pics.sort(key=lambda x: -x['facteur'] * x['pic_pct'])
    return {'fenetre': fen, 'par_prog': par_prog, 'serie': serie, 'longs': longs, 'pics': pics[:12], 'marge': marge}


def regles_programmes(s):
    a, r = s.get('aprog'), []
    if not a:
        return r
    if a['pics']:
        r.append(('haute' if a['pics'][0]['facteur'] >= 3 else 'moyenne', 'Programmes IRIUM', 'Programmes sur-représentés pendant les pics de la base',
                  ' ; '.join('%s : présent dans %.0f %% des pics de %s (%.0f %% du temps sinon, ×%s)' % (x['programme'], x['pic_pct'], x['indicateur'], x['global_pct'],
                                                                                                fmt_n(x['facteur'])) for x in a['pics'][:4]),
                  'Programmes candidats à l\'origine de la charge ou des verrous : tracer leurs requêtes (onstat -g ses / -g sql pendant leur exécution, '
                  'sysadmin:task « set sql user tracing »), et pour les traitements de masse, les déplacer hors des heures de saisie.'))
    lg = [e for e in a['longs'] if ((e['fin'] or s['fin']) - e['debut']).total_seconds() > 1800]
    if lg:
        r.append(('moyenne', 'Programmes IRIUM', 'Programmes de longue durée pendant les heures d\'activité',
                  ' ; '.join('%s (%s, %s → %s)' % (e['programme'], e['utilisateur'] or '?', e['debut'].strftime('%H:%M'), e['fin'].strftime('%H:%M') if e['fin'] else 'en cours')
                             for e in lg[:5]),
                  'Un traitement long garde des verrous et sollicite le cache pendant toute sa durée : vérifier qu\'il ne s\'exécute pas en même temps que la saisie, '
                  'et qu\'il valide régulièrement ses transactions.'))
    return r


def section_programmes(s, t0, t1, marq):
    a, p = s.get('aprog'), s.get('prog')
    if not a:
        return ''
    o = ['<h3>Programmes IRIUM lancés (journal %s:%s)</h3>' % (esc(p['base']), esc(p['table']))]
    o.append('<p class="d">%d programme(s) lancé(s) pendant l\'audit, %d programme(s) distinct(s). Colonnes utilisées : %s.</p>' % (
        len(a['fenetre']), len(a['par_prog']), esc(', '.join('%s = %s' % (k, v) for k, v in sorted(p['roles'].items())))))
    o.append(courbe('Programmes lancés par tranche de 5 minutes', [('lancements', COULEURS[0], a['serie'], 'lancements')], t0, t1, marq))
    if a['pics']:
        o.append('<h3>Programmes présents pendant les pics de la base</h3>' + tableau(
            ['Programme', 'Pics de', 'Présent pendant les pics', 'Présent le reste du temps', 'Facteur'],
            [[esc(x['programme']), esc(x['indicateur']), '%.0f %%' % x['pic_pct'], '%.0f %%' % x['global_pct'], '×' + fmt_n(x['facteur'])] for x in a['pics']]))
    top = sorted(a['par_prog'].items(), key=lambda x: -(x[1]['duree_s'] or x[1]['lancements']))[:25]
    o.append('<details open><summary>Programmes les plus utilisés</summary>%s</details>' % tableau(
        ['Programme', 'Lancements', 'Utilisateurs', 'Durée cumulée', 'Durée max', 'Non terminés'],
        [[esc(k), str(v['lancements']), str(len(v['utilisateurs'])), duree_txt(v['duree_s']) if p['avec_fin'] else '-',
          duree_txt(v['max_s']) if p['avec_fin'] else '-', str(v['ouverts'])] for k, v in top]))
    if a['longs']:
        o.append('<details><summary>Programmes de plus de 10 minutes</summary>%s</details>' % tableau(
            ['Programme', 'Utilisateur', 'Poste', 'Début', 'Fin', 'Durée'],
            [[esc(e['programme']), esc(e['utilisateur']), esc(e['poste']), e['debut'].strftime('%d/%m %H:%M:%S'), e['fin'].strftime('%H:%M:%S') if e['fin'] else 'en cours',
              duree_txt(((e['fin'] or s['fin']) - e['debut']).total_seconds())] for e in a['longs']]))
    return ''.join(o)


def duree_txt(sec):
    sec = int(sec or 0)
    return '%dh%02d' % (sec // 3600, sec % 3600 // 60) if sec >= 3600 else '%d min %02d s' % (sec // 60, sec % 60)


def programmes_autour(serveurs, quand, minutes=5):
    res = []
    for s in serveurs:
        p = s.get('prog')
        if not p:
            continue
        a, z = quand - dt.timedelta(minutes=minutes), quand + dt.timedelta(minutes=minutes)
        noms = {}
        for e in p['liste']:
            if (a <= e['debut'] <= z) or (e['debut'] <= quand and e['fin'] and e['fin'] >= quand):
                noms[e['programme']] = noms.get(e['programme'], 0) + 1
        res += sorted(noms.items(), key=lambda x: -x[1])[:6]
    return res


# --------------------------------------------------------------------------------------------
# Services / processus applicatifs supervisés (ex. digital_dealer) et services systemd
# --------------------------------------------------------------------------------------------
def serie_services(d, info):
    motifs = [m for m in (info.get('services') or '').split('|') if m.strip()]
    b = blocs(os.path.join(d, 'series', 'services.raw'))
    if not motifs or not b:
        return {}
    clk = float(info.get('clk_tck') or 100)
    page_ko = float(info.get('page_ko') or 4)
    groupe = lambda cmd: next((m for m in motifs if re.search(m, cmd)), None)
    res = dict((m, {'serie': [], 'pids': {}, 'cmds': {}, 'demarrages': [], 'absences': []}) for m in motifs)
    prec = {}
    for ts, t in b:
        cour = {}
        for l in t.splitlines():
            p = l.split('|', 8)
            if len(p) < 9 or not p[0].isdigit():
                continue
            g = groupe(p[8])
            if g is None:
                continue
            cle = (p[0], p[6])   # pid + date de démarrage : un pid réutilisé n'est pas confondu
            cour[cle] = {'g': g, 'ticks': (entier(p[3]) or 0) + (entier(p[4]) or 0), 'threads': int(entier(p[5]) or 0),
                         'rss_mo': (entier(p[7]) or 0) * page_ko / 1024.0, 'etat': p[2], 'cmd': p[8]}
            res[g]['cmds'][p[8][:160]] = res[g]['cmds'].get(p[8][:160], 0) + 1
            if cle not in res[g]['pids']:
                res[g]['pids'][cle] = ts
        for g in motifs:
            mes = [v for v in cour.values() if v['g'] == g]
            e = {'ts': ts, 'n': len(mes), 'rss_mo': sum(v['rss_mo'] for v in mes), 'threads': sum(v['threads'] for v in mes),
                 'etat_D': sum(1 for v in mes if v['etat'] == 'D')}
            if prec.get('ts'):
                el = (ts - prec['ts']).total_seconds() or 1
                e['cpu'] = 100.0 * sum(v['ticks'] - prec['p'][k]['ticks'] for k, v in cour.items() if v['g'] == g and k in prec['p']) / clk / el
            res[g]['serie'].append(e)
        prec = {'ts': ts, 'p': cour}
    debut = b[0][0]
    for g, r in res.items():
        r['demarrages'] = sorted(t for t in r['pids'].values() if t > debut)
        cour = None
        for e in r['serie']:
            if e['n'] == 0 and cour is None:
                cour = e['ts']
            elif e['n'] > 0 and cour is not None:
                r['absences'].append((cour, e['ts']))
                cour = None
        if cour is not None:
            r['absences'].append((cour, r['serie'][-1]['ts']))
    return res


def services_echec(d):
    res = {}
    for moment in ('debut', 'fin'):
        t = lire(os.path.join(d, 'statique', 'services_echec_%s.txt' % moment))
        res[moment] = [l.split()[0] for l in t.splitlines() if l.strip() and ' failed ' in ' %s ' % l and '.service' in l]
    return res


def regles_services(s):
    r = []
    for g, x in sorted((s.get('services') or {}).items()):
        if not x['serie']:
            continue
        nom = g.replace('\\', '')
        jamais = all(e['n'] == 0 for e in x['serie'])
        if jamais:
            r.append(('haute', 'Services', 'Service %s absent pendant tout l\'audit' % nom, 'aucun processus correspondant au motif « %s »' % g,
                      'Vérifier que le service doit bien tourner sur ce serveur ; sinon le retirer de --services.'))
            continue
        if x['absences']:
            r.append(('haute', 'Services', 'Service %s arrêté pendant l\'audit' % nom,
                      'absent : %s' % ', '.join('%s → %s' % (a.strftime('%H:%M'), z.strftime('%H:%M')) for a, z in x['absences'][:6]),
                      'Consulter les journaux du service et du système à ces heures (journalctl, /var/log/messages) ; vérifier la supervision et le redémarrage automatique.'))
        if x['demarrages']:
            r.append(('moyenne', 'Services', 'Processus %s (re)démarrés pendant l\'audit' % nom,
                      '%d démarrage(s) : %s' % (len(x['demarrages']), ', '.join(t.strftime('%H:%M:%S') for t in x['demarrages'][:8])),
                      'Un service qui redémarre en boucle (plantage, script de relance) consomme et coupe ses traitements : lire son journal d\'erreurs.'))
        cpu = stats([e.get('cpu') for e in x['serie']])
        if (cpu['p95'] or 0) >= 80:
            r.append(('moyenne' if cpu['p95'] < 150 else 'haute', 'Services', 'Service %s gros consommateur de CPU' % nom,
                      'CPU p95 %.0f %% d\'un cœur (moyenne %.0f %%, max %.0f %%) sur %d CPU' % (cpu['p95'], cpu['moy'], cpu['max'], s['ncpu']),
                      'Sur le serveur de base, ce service prend du temps CPU aux VP Informix : envisager son déplacement sur un serveur d\'applications ou une limite (cgroup / systemd CPUQuota).'))
        mem = [e['rss_mo'] for e in x['serie'] if e['n']]
        if len(mem) >= 6 and mem[-1] > 200 and mem[-1] > 1.5 * min(mem[:max(1, len(mem) // 5)]):
            r.append(('info', 'Services', 'Mémoire du service %s en hausse continue' % nom, 'RSS %.0f Mo au début → %.0f Mo à la fin' % (mem[0], mem[-1]),
                      'Fuite mémoire possible : surveiller sur plusieurs jours, redémarrage planifié en attendant une correction.'))
        if sum(e['etat_D'] for e in x['serie']) > len(x['serie']) / 2:
            r.append(('info', 'Services', 'Service %s souvent en attente d\'I/O (état D)' % nom, '%d relevés' % sum(1 for e in x['serie'] if e['etat_D']),
                      'Le service attend le disque ou un montage réseau (NFS) : vérifier ses fichiers de travail.'))
    ech = s.get('svc_echec') or {}
    tous = sorted(set(ech.get('debut', [])) | set(ech.get('fin', [])))
    if tous:
        nouveaux = sorted(set(ech.get('fin', [])) - set(ech.get('debut', [])))
        r.append(('moyenne' if nouveaux else 'info', 'Services', 'Services systemd en échec', ', '.join(tous[:10]) + (' ; en échec pendant l\'audit : %s' % ', '.join(nouveaux) if nouveaux else ''),
                  'systemctl status <service> et journalctl -u <service> : corriger ou désactiver les services inutiles.'))
    return r


def section_services(s, t0, t1, marq):
    sv = s.get('services') or {}
    o = []
    if sv:
        lignes = []
        for g, x in sorted(sv.items()):
            cpu = stats([e.get('cpu') for e in x['serie']])
            n = stats([e['n'] for e in x['serie']])
            etat = 'absent' if all(e['n'] == 0 for e in x['serie']) else ('<b style="color:#d03b3b">arrêté %d fois</b>' % len(x['absences']) if x['absences'] else 'présent en continu')
            lignes.append(['<b>%s</b>' % esc(g), etat, '%s-%s' % (fmt(n['min']), fmt(n['max'])), str(len(x['demarrages'])), fmt(cpu['moy']), fmt(cpu['max']),
                           fmt(stats([e['rss_mo'] for e in x['serie']])['max']), fmt(stats([e['threads'] for e in x['serie']])['max']),
                           '<span class="mono">%s</span>' % '<br>'.join(esc(c) for c, _n in sorted(x['cmds'].items(), key=lambda kv: -kv[1])[:4])])
        o.append('<h3>Services supervisés</h3>' + tableau(['Service', 'État', 'Processus', '(Re)démarrages', 'CPU moyen % (1 cœur = 100)', 'CPU max %', 'Mémoire max Mo',
                                                           'Threads max', 'Commandes'], lignes))
        o.append('<div class="g">%s%s</div>' % (
            courbe('Services : CPU (% d\'un cœur)', [(g, COULEURS[i % len(COULEURS)], x['serie'], 'cpu') for i, (g, x) in enumerate(sorted(sv.items()))], t0, t1, marq, ' %'),
            courbe('Services : mémoire (Mo)', [(g, COULEURS[i % len(COULEURS)], x['serie'], 'rss_mo') for i, (g, x) in enumerate(sorted(sv.items()))], t0, t1, marq, ' Mo')))
    stx = os.path.join(s['dossier'], 'statique')
    actifs = [l.split()[0] for l in lire(os.path.join(stx, 'services_systemd_debut.txt')).splitlines() if ' running ' in ' %s ' % l]
    if actifs:
        o.append('<details><summary>Services systemd actifs au début de l\'audit (%d)</summary><pre>%s</pre></details>' % (len(actifs), esc('\n'.join(actifs))))
    ports = lire(os.path.join(stx, 'ports_ecoute_debut.txt'))
    if ports.strip():
        o.append('<details><summary>Ports en écoute</summary><pre>%s</pre></details>' % esc(ports[:30000]))
    return ''.join(o)


# --------------------------------------------------------------------------------------------
# Informix expert : vitesse des chunks, files d'I/O, mutex, buffers, logs, blocages, mémoire,
# dbspaces temporaires, configuration modifiée à chaud, santé des tables et index, trace SQL
# --------------------------------------------------------------------------------------------
def iof_blocs(t):
    res, cour = {}, None
    for l in t.splitlines():
        p = l.split()
        if len(p) >= 6 and p[0].isdigit() and '/' in p[1]:
            cour = res[p[1]] = {'oct_l': entier(p[2]) or 0, 'oct_e': entier(p[4]) or 0, 'nl': 0, 'ne': 0, 'tl': 0.0, 'te': 0.0}
        elif cour is not None and len(p) >= 3 and p[0] in ('reads', 'writes') and p[1].isdigit():
            n, ms = int(p[1]), (num(p[2]) or 0) * 1000
            if p[0] == 'reads':
                cour['nl'], cour['tl'] = n, n * ms
            else:
                cour['ne'], cour['te'] = n, n * ms
    return res


def vitesse_chunks(d):
    """Débit, IOPS et temps de réponse par chunk, par intervalle (deltas de onstat -g iof)."""
    b = [(ts, iof_blocs(t)) for ts, t in blocs(os.path.join(d, 'informix', 'onstat_iof.raw'))]
    b = [x for x in b if x[1]]
    res = {}
    for (t0, a), (t1, z) in zip(b, b[1:]):
        el = (t1 - t0).total_seconds() or 1
        for ch, v in z.items():
            u = a.get(ch)
            if not u or v['nl'] < u['nl'] or v['ne'] < u['ne']:
                continue
            dnl, dne = v['nl'] - u['nl'], v['ne'] - u['ne']
            res.setdefault(ch, []).append({'ts': t1, 'lect_mo_s': (v['oct_l'] - u['oct_l']) / 1048576.0 / el, 'ecr_mo_s': (v['oct_e'] - u['oct_e']) / 1048576.0 / el,
                                           'iops': (dnl + dne) / el, 'lect_ms': (v['tl'] - u['tl']) / dnl if dnl else None,
                                           'ecr_ms': (v['te'] - u['te']) / dne if dne else None})
    return res


def files_io(d):
    res = []
    for ts, t in blocs(os.path.join(d, 'informix', 'onstat_ioq.raw')):
        q = {}
        for l in t.splitlines():
            p = l.split()
            if len(p) >= 8 and p[1].isdigit() and all(entier(x) is not None for x in p[2:8]) and p[0].isalpha():
                q['%s %s' % (p[0], p[1])] = {'len': int(entier(p[2])), 'maxlen': int(entier(p[3])), 'ops': entier(p[4])}
        if q:
            res.append({'ts': ts, 'files': q, 'len_max': max(v['len'] for v in q.values()), 'len_tot': sum(v['len'] for v in q.values())})
    return res


INDICES_MUTEX = [(r'lock', 'table des verrous (nombreux verrous posés : isolation, verrouillage par page, transactions longues)'),
                 (r'lru|bf|bhash|buff', 'pool de buffers (pages très sollicitées, nombre de LRU)'),
                 (r'log|plog|llog', 'buffers de log (validations très fréquentes, LOGBUFF / PHYSBUFF)'),
                 (r'ddh|dict|dd_', 'cache du dictionnaire (DD_HASHSIZE)'), (r'stmt|ssc', 'cache des instructions SQL (STMT_CACHE)'),
                 (r'mem|mpool|shm', 'allocation mémoire partagée (sessions nombreuses / SHMADD)')]


def contention_mutex(d):
    b = blocs(os.path.join(d, 'informix', 'onstat_spi.raw'))
    lire_spi = lambda t: dict(_spi_lignes(t))
    if len(b) < 2:
        return None
    a, z = lire_spi(b[0][1]), lire_spi(b[-1][1])
    mn = ((b[-1][0] - b[0][0]).total_seconds() or 60) / 60.0
    res = []
    for nom, (w, lp) in z.items():
        w0, l0 = a.get(nom, (0, 0))
        if w >= w0 and w - w0 > 0:
            indice = next((txt for m, txt in INDICES_MUTEX if re.search(m, nom, re.I)), '')
            res.append({'nom': nom, 'attentes_min': (w - w0) / mn, 'boucles_par_attente': (lp - l0) / float(w - w0) if w - w0 else 0, 'indice': indice})
    return sorted(res, key=lambda x: -x['attentes_min'])[:15]


def _spi_lignes(t):
    agg = {}
    for l in t.splitlines():
        m = re.match(r'^\s*(\d+)\s+(\d+)\s+[\d.]+\s+(.+?)\s*$', l)
        if m:
            nom = re.sub(r'\[\d+\]', '', m.group(3)).strip()
            w, lp = agg.get(nom, (0, 0))
            agg[nom] = (w + int(m.group(1)), lp + int(m.group(2)))
    return agg.items()


def pool_buffers(d):
    def lire_buf(t):
        res, taille = {}, None
        lignes = t.splitlines()
        for i, l in enumerate(lignes):
            m = re.search(r'page size:\s*(\d+)', l)
            if m:
                taille = m.group(1)
            if 'Fg Writes' in l and i + 1 < len(lignes) and taille:
                v = lignes[i + 1].split()
                if len(v) >= 4:
                    res[taille] = {'fg': entier(v[0]) or 0, 'lru': entier(v[1]) or 0, 'chunk': entier(v[3]) or 0}
        return res
    b = [(ts, lire_buf(t)) for ts, t in blocs(os.path.join(d, 'informix', 'onstat_buf.raw'))]
    b = [x for x in b if x[1]]
    if len(b) < 2:
        return {}
    res = {}
    for k, z in b[-1][1].items():
        a = b[0][1].get(k)
        if a and z['lru'] >= a['lru']:
            tot = (z['fg'] - a['fg']) + (z['lru'] - a['lru']) + (z['chunk'] - a['chunk'])
            res[k] = dict(('d_' + x, z[x] - a[x]) for x in ('fg', 'lru', 'chunk'))
            res[k]['part_chunk'] = 100.0 * (z['chunk'] - a['chunk']) / tot if tot else None
    return res


def buffers_log(d):
    """Efficacité des buffers de log (pages par écriture) et remplissage du log physique, d'après onstat -l."""
    serie = []
    for ts, t in blocs(os.path.join(d, 'informix', 'onstat_l.raw')):
        e = {'ts': ts}
        lignes = t.splitlines()
        for i, l in enumerate(lignes):
            p = l.split()
            if len(p) >= 8 and p[0].startswith('L-'):
                e['l_pages'], e['l_ecr'] = entier(p[4]), entier(p[5])
            elif len(p) >= 6 and p[0].startswith('P-'):
                e['p_pages'], e['p_ecr'] = entier(p[3]), entier(p[4])
            elif 'phybegin' in l and i + 1 < len(lignes):
                v = lignes[i + 1].split()
                if v and num(v[-1]) is not None:
                    e['phys_pct'] = num(v[-1])
        if len(e) > 1:
            serie.append(e)
    res = {'serie': serie}
    avec = [e for e in serie if e.get('l_ecr') is not None]
    if len(avec) >= 2 and avec[-1]['l_ecr'] > avec[0]['l_ecr']:
        res['l_pages_par_io'] = (avec[-1]['l_pages'] - avec[0]['l_pages']) / float(avec[-1]['l_ecr'] - avec[0]['l_ecr'])
    avec = [e for e in serie if e.get('p_ecr') is not None]
    if len(avec) >= 2 and avec[-1]['p_ecr'] > avec[0]['p_ecr']:
        res['p_pages_par_io'] = (avec[-1]['p_pages'] - avec[0]['p_pages']) / float(avec[-1]['p_ecr'] - avec[0]['p_ecr'])
    res['phys_max'] = stats([e.get('phys_pct') for e in serie])['max']
    return res


def chaines_blocage(d):
    """Sessions qui bloquent les autres (sysmaster:syslocks, relevé quand ≥ 2 sessions attendent un verrou)."""
    b = [(ts, lignes_unl(t)) for ts, t in blocs(os.path.join(d, 'informix', 'verrous_attente.raw'))]
    b = [x for x in b if x[1]]
    tenants, tables = {}, {}
    for ts, rows in b:
        vus = set()
        for x in rows:
            if len(x) < 10:
                continue
            cle = (x[3], x[4], x[5], x[6])
            a = tenants.setdefault(cle, {'sid': x[3], 'utilisateur': x[4], 'poste': x[5], 'pid': x[6], 'attentes': 0, 'releves': set(), 'tables': {}, 'bloques': set(),
                                         'premier': ts, 'dernier': ts})
            a['attentes'] += 1
            a['releves'].add(ts)
            a['dernier'] = ts
            a['tables']['%s:%s' % (x[0], x[1])] = a['tables'].get('%s:%s' % (x[0], x[1]), 0) + 1
            a['bloques'].add('%s@%s' % (x[8] or '?', x[9] or '?'))
            if (x[0], x[1], ts) not in vus:
                vus.add((x[0], x[1], ts))
                tables[(x[0], x[1])] = tables.get((x[0], x[1]), 0) + 1
    return {'releves': len(b), 'tenants': sorted(tenants.values(), key=lambda a: -a['attentes']), 'tables': sorted(tables.items(), key=lambda kv: -kv[1])}


def memoire_sessions(d):
    b = blocs(os.path.join(d, 'informix', 'memoire_sessions.raw'))
    res = {}
    for _ts, t in b:
        for x in lignes_unl(t):
            if len(x) >= 6 and (entier(x[4]) or 0) > (res.get(x[0], {}).get('mo', 0) * 1048576):
                res[x[0]] = {'sid': x[0], 'utilisateur': x[1], 'poste': x[2], 'pid': x[3], 'mo': (entier(x[4]) or 0) / 1048576.0}
    return sorted(res.values(), key=lambda e: -e['mo'])[:15]


def temp_dbspaces(d, temp_noms):
    """Occupation des dbspaces temporaires au fil de l'audit (onstat -d toutes les 15 min)."""
    serie = []
    for ts, t in blocs(os.path.join(d, 'informix', 'onstat_d.raw')):
        noms, occ = {}, {}
        for l in t.splitlines():
            p = l.split()
            if len(p) >= 9 and re.match(r'^[0-9a-f]{6,}$', p[0]) and p[1].isdigit() and p[3].isdigit() and not '/' in l:
                noms[p[1]] = p[-1]
            elif len(p) >= 7 and re.match(r'^[0-9a-f]{6,}$', p[0]) and p[-1].startswith('/'):
                dbs = p[2]
                taille, libre = entier(p[4]), entier(p[5])
                if taille:
                    a = occ.setdefault(dbs, [0, 0])
                    a[0] += taille
                    a[1] += libre or 0
        e = {'ts': ts}
        for n, (tot, lib) in occ.items():
            nom = noms.get(n, n)
            if nom in temp_noms:
                e[nom] = 100.0 * (tot - lib) / tot
        if len(e) > 1:
            serie.append(e)
    return serie


def config_a_chaud(d, cf):
    """Paramètres numériques dont la valeur en mémoire (onstat -g cfg) diffère du fichier ONCONFIG."""
    res = []
    for l in lire(os.path.join(d, 'statique', 'informix', 'onstat__g_cfg.txt')).splitlines():
        m = re.match(r'^\s*([A-Z][A-Z0-9_]{2,})\s+(-?\d+)\s*$', l)
        if m and isinstance(cf.get(m.group(1)), str) and re.match(r'^-?\d+$', cf[m.group(1)].strip()):
            if int(cf[m.group(1)].strip()) != int(m.group(2)):
                res.append((m.group(1), cf[m.group(1)].strip(), m.group(2)))
    return res


def requetes_sql(d):
    """Trace SQL (option --trace-sql) : requêtes regroupées par forme normalisée (littéraux remplacés par ?)."""
    cols = [x[0] for x in lignes_unl(lire(os.path.join(d, 'informix', 'trace_sql_colonnes.unl'))) if x]
    b = blocs(os.path.join(d, 'informix', 'trace_sql.raw'))
    if not cols or not b:
        return None
    i = dict((c, n) for n, c in enumerate(cols))
    if 'sql_statement' not in i:
        return None
    vus, groupes = set(), {}
    for _ts, t in b:
        for x in lignes_unl(t):
            if len(x) < len(cols):
                continue
            cle = x[i['sql_id']] if 'sql_id' in i else tuple(x)
            if cle in vus:
                continue
            vus.add(cle)
            v = lambda c: entier(x[i[c]]) if c in i else None
            txt = x[i['sql_statement']]
            norme = re.sub(r'\s+', ' ', re.sub(r'\b\d+(\.\d+)?\b', '?', re.sub(r"'(?:[^']|'')*'|\"(?:[^\"]|\"\")*\"", '?', txt))).strip()
            g = groupes.setdefault(norme[:400], {'texte': norme[:400], 'exemple': txt[:600], 'exec': 0, 'duree': 0.0, 'pgreads': 0, 'bfreads': 0, 'lockwaits': 0,
                                                 'tris_disque': 0, 'lignes': 0, 'sessions': set(), 'isolation': set(), 'base': x[i['sql_database']] if 'sql_database' in i else ''})
            g['exec'] += 1
            g['duree'] += v('sql_runtime') or 0
            g['pgreads'] += v('sql_pgreads') or 0
            g['bfreads'] += v('sql_bfreads') or 0
            g['lockwaits'] += v('sql_lockwaits') or 0
            g['tris_disque'] += v('sql_sortdisk') or 0
            g['lignes'] += v('sql_actualrows') or 0
            if 'sql_sid' in i:
                g['sessions'].add(x[i['sql_sid']])
            if 'sql_isollevel' in i:
                g['isolation'].add(x[i['sql_isollevel']])
    L = list(groupes.values())
    return {'groupes': L, 'nb': len(vus), 'total': dict((k, sum(g[k] for g in L)) for k in ('duree', 'pgreads', 'bfreads', 'lockwaits', 'exec'))}


ISOLATION = {'0': 'sans transaction', '1': 'DIRTY READ', '2': 'COMMITTED READ', '3': 'CURSOR STABILITY', '5': 'REPEATABLE READ', '8': 'DIRTY READ (retain)',
             '9': 'COMMITTED READ (retain)', '10': 'CURSOR STABILITY (retain)', '11': 'COMMITTED READ LAST COMMITTED'}


def expert_informix(s):
    d = s['dossier']
    temp = set()
    for v in s['conf'].get('DBSPACETEMP', []):
        temp |= set(x.strip() for x in re.split(r'[,:]', v) if x.strip())
    temp |= set(x['nom'] for x in (s.get('inv') or {}).get('dbspaces', []) if x['temp'])
    return {'chunks': vitesse_chunks(d), 'ioq': files_io(d), 'mutex': contention_mutex(d), 'buf': pool_buffers(d), 'log': buffers_log(d),
            'blocage': chaines_blocage(d), 'memoire': memoire_sessions(d), 'temp': temp_dbspaces(d, temp), 'cfg': config_a_chaud(d, s['conf']),
            'sql': requetes_sql(d)}


def regles_expert(s):
    x, r, inv = s.get('exp') or {}, [], s.get('inv') or {}
    add = lambda *a: r.append(a)
    # vitesse des chunks
    lents = []
    for ch, serie in (x.get('chunks') or {}).items():
        le, ec = stats([e['lect_ms'] for e in serie]), stats([e['ecr_ms'] for e in serie])
        if (le['p95'] or 0) > 15 or (ec['p95'] or 0) > 15:
            lents.append((ch, le, ec, stats([e['lect_mo_s'] + e['ecr_mo_s'] for e in serie])))
    if lents:
        lents.sort(key=lambda z: -max(z[1]['p95'] or 0, z[2]['p95'] or 0))
        add('haute', 'Informix', 'Temps de réponse des chunks dégradé par moments',
            ' ; '.join('%s : lecture p95 %s ms, écriture p95 %s ms, débit max %s Mo/s' % (c, fmt(a['p95']), fmt(b['p95']), fmt(m['max'])) for c, a, b, m in lents[:4]),
            'Mesuré par Informix sur chaque intervalle : le stockage ne suit pas aux heures de pointe. Croiser avec l\'occupation des disques (iostat) et la baie ; '
            'répartir les chunks chauds (données, index, logs, temporaires) sur des LUN distinctes.')
    q = stats([e['len_max'] for e in x.get('ioq') or []])
    if (q['p95'] or 0) >= 4:
        add('haute' if q['p95'] >= 10 else 'moyenne', 'Informix', 'Files d\'attente d\'I/O du moteur',
            'longueur max d\'une file AIO/KAIO : p95 %s, max %s requêtes en attente' % (fmt(q['p95']), fmt(q['max'])),
            'Les requêtes d\'I/O s\'accumulent : stockage saturé ou trop peu de files (KAIO / AIO VP). Vérifier le temps de réponse disque et AUTO_AIOVPS.')
    mx = [m for m in (x.get('mutex') or []) if m['attentes_min'] >= 500]
    if mx:
        add('moyenne' if mx[0]['attentes_min'] < 5000 else 'haute', 'Informix', 'Contention sur les mutex internes',
            ' ; '.join('%s : %s attentes/min%s' % (m['nom'], fmt_n(m['attentes_min']), (' (%s)' % m['indice']) if m['indice'] else '') for m in mx[:4]),
            'Les threads se disputent une structure interne du moteur : traiter la cause indiquée (ex. table des verrous → isolation et verrouillage par ligne ; '
            'buffers → pages chaudes et nombre de LRU).')
    for taille, b in (x.get('buf') or {}).items():
        if b['d_fg'] > 0:
            add('haute', 'Informix', 'Écritures au premier plan dans le pool %s Ko' % (int(taille) // 1024 if int(taille) >= 1024 else taille),
                '%s écritures au premier plan, %s écritures LRU, %s écritures de chunk sur la période' % (fmt_n(b['d_fg']), fmt_n(b['d_lru']), fmt_n(b['d_chunk'])),
                'Des sessions écrivent elles-mêmes faute de buffer propre : augmenter CLEANERS, abaisser lru_max_dirty du BUFFERPOOL concerné.')
        elif (b['part_chunk'] or 0) > 70:
            add('info', 'Informix', 'Écritures concentrées aux checkpoints (pool %s)' % taille, '%.0f %% des écritures sont des écritures de chunk' % b['part_chunk'],
                'Les pages modifiées s\'accumulent jusqu\'au checkpoint : des checkpoints plus longs sont à prévoir. Abaisser lru_max_dirty répartit les écritures.')
    lg = x.get('log') or {}
    prof = s.get('profil') or []
    commits = stats([e['commit_s'] for e in prof])['moy'] or 0
    if lg.get('l_pages_par_io') is not None and lg['l_pages_par_io'] < 1.5 and commits > 20:
        nb = [b for b, v in inv.get('bases', {}).items() if v['journalisee'] and not v['log_bufferise']]
        add('moyenne', 'Informix', 'Buffer de log logique vidé à chaque validation',
            '%.2f page par écriture de log, %.0f validations/s%s' % (lg['l_pages_par_io'], commits, ' ; journalisation non bufferisée : %s' % ', '.join(nb) if nb else ''),
            'Chaque COMMIT attend une écriture disque du log : le disque des logs doit être très rapide (temps d\'écriture < 2 ms). La journalisation bufferisée '
            '(ondblog buf) réduit ces écritures au prix d\'un risque de perte des dernières transactions en cas d\'arrêt brutal ; regrouper les validations des traitements de masse.')
    if (lg.get('phys_max') or 0) > 75:
        add('moyenne', 'Informix', 'Log physique très rempli', 'occupation max %.0f %%' % lg['phys_max'],
            'Au-delà de 75 %, un checkpoint est déclenché (et devient bloquant s\'il se remplit) : augmenter PHYSFILE.')
    ra = stats([e.get('ra_eff') for e in prof])
    if ra['moy'] is not None and ra['moy'] < 50:
        add('info', 'Informix', 'Lecture anticipée peu efficace', 'pages lues par anticipation réellement utilisées : %.0f %%' % ra['moy'],
            'Les pages lues d\'avance sont en grande partie inutiles (accès dispersés) : AUTO_READAHEAD / RA_PAGES plus bas.')
    bl = x.get('blocage') or {}
    for t in [t for t in bl.get('tenants', []) if len(t['releves']) >= 2 or t['attentes'] >= 2][:3]:
        add('haute', 'Verrous', 'Session %s bloque d\'autres sessions (%s@%s)' % (t['sid'], t['utilisateur'] or '?', t['poste'] or '?'),
            '%d attente(s) causée(s) sur %d relevé(s) entre %s et %s ; tables : %s ; sessions bloquées : %s' % (
                t['attentes'], len(t['releves']), t['premier'].strftime('%H:%M'), t['dernier'].strftime('%H:%M'),
                ', '.join('%s (%d)' % kv for kv in sorted(t['tables'].items(), key=lambda kv: -kv[1])[:3]), ', '.join(sorted(t['bloques'])[:6])),
            'Identifier le programme (processus %s sur %s, onstat -g ses %s / -g sql %s) : transaction trop longue ou verrous posés en lecture ; '
            'valider plus souvent, réduire l\'isolation des lectures, verrouillage par ligne.' % (t['pid'], t['poste'], t['sid'], t['sid']))
    gros = [m for m in (x.get('memoire') or []) if m['mo'] >= 500]
    if gros:
        add('moyenne', 'Informix', 'Sessions très consommatrices de mémoire',
            ' ; '.join('session %s (%s@%s) : %s Mo' % (m['sid'], m['utilisateur'], m['poste'], fmt(m['mo'])) for m in gros[:5]),
            'Mémoire du segment virtuel par session (curseurs, tris, tables temporaires) : vérifier les curseurs non libérés et les tris en mémoire du programme.')
    for nom in sorted({k for e in x.get('temp') or [] for k in e if k != 'ts'}):
        pic = stats([e.get(nom) for e in x['temp']])['max']
        if (pic or 0) > 80:
            add('moyenne', 'Informix', 'Dbspace temporaire %s presque plein' % nom, 'occupation max %.0f %%' % pic,
                'Tris et tables temporaires volumineux : risque d\'erreur « no free space » ; identifier les requêtes (tris disque de la trace SQL), agrandir le dbspace.')
    if x.get('cfg'):
        add('info', 'Configuration', 'Paramètres modifiés à chaud (différents du fichier ONCONFIG)',
            ' ; '.join('%s : fichier %s, en mémoire %s' % c for c in x['cfg'][:8]),
            'Ces valeurs seront perdues au prochain redémarrage : reporter dans l\'ONCONFIG celles à conserver (onmode -wf).')
    # santé des tables et index
    ob = s.get('obj') or {}
    chaudes = set()
    for k in ('verrous', 'logiques', 'scans'):
        for o, _v, _p, _f in classements(ob).get(k, {}).get('liste', [])[:15]:
            chaudes.add((o['base'], o['table']))
    page = [k for k, v in inv.get('stats', {}).items() if v.get('verrou') == 'P']
    page_chaudes = [k for k in page if k in chaudes]
    if page_chaudes:
        contention = (stats([e['lockwts_min'] for e in prof])['moy'] or 0) > 30 or (stats([e['att_L'] for e in s.get('sessions') or []])['p95'] or 0) >= 3
        add('haute' if contention else 'moyenne', 'Objets', 'Tables très sollicitées en verrouillage par page',
            ', '.join(t for _b, t in page_chaudes[:10]) + (' ; %d table(s) en verrouillage par page au total' % len(page)),
            'Un verrou de page bloque toutes les lignes de la page : ALTER TABLE … LOCK MODE (ROW) sur ces tables (opération rapide, à planifier hors activité).')
    elif page:
        add('info', 'Objets', 'Tables en verrouillage par page', '%d table(s), ex. %s' % (len(page), ', '.join(t for _b, t in page[:6])),
            'Le verrouillage par ligne limite la contention en OLTP (ALTER TABLE … LOCK MODE (ROW)).')
    indexees = set((b, v['table']) for (b, _i), v in inv.get('index_detail', {}).items()) | set((b, t) for (b, _i), t in inv.get('index', {}).items())
    sans = sorted([(k, v) for k, v in inv.get('stats', {}).items() if (v['nrows'] or 0) >= 10000 and k not in indexees and inv.get('index')],
                  key=lambda kv: -(kv[1]['nrows'] or 0))
    if sans:
        add('moyenne', 'Objets', 'Grosses tables sans aucun index', ' ; '.join('%s : %s lignes' % (k[1], fmt_n(v['nrows'])) for k, v in sans[:8]),
            'Toute recherche sur ces tables est un scan complet : créer au moins l\'index de la clé d\'accès (à valider avec l\'éditeur).')
    det = inv.get('index_detail', {})
    par_table = {}
    for (b, i), v in det.items():
        par_table.setdefault((b, v['table']), []).append((i, v))
    redond = []
    for (b, t), L in par_table.items():
        for i1, v1 in L:
            for i2, v2 in L:
                if i1 != i2 and v1['colonnes'] and len(v1['colonnes']) < len(v2['colonnes']) + (0 if v1['type'] == 'U' else 1) \
                        and v2['colonnes'][:len(v1['colonnes'])] == v1['colonnes'] and v1['type'] != 'U' and (i1, i2) not in [(z[1], z[0]) for z in redond] \
                        and i1 not in [z[0] for z in redond]:
                    redond.append((i1, i2, t))
    if redond:
        add('info', 'Objets', 'Index probablement redondants', ' ; '.join('%s couvert par %s (%s)' % z for z in redond[:8]),
            'Un index dont les colonnes sont le début d\'un autre index de la même table est en général inutile et coûte à chaque écriture : vérifier son usage avant suppression.')
    profonds = sorted([(i, v) for (_b, i), v in det.items() if (v['niveaux'] or 0) >= 5], key=lambda iv: -(iv[1]['niveaux'] or 0))
    if profonds:
        add('info', 'Objets', 'Index profonds (5 niveaux ou plus)', ', '.join('%s (%d niveaux)' % (i, v['niveaux']) for i, v in profonds[:8]),
            'Chaque recherche traverse plus de pages : clé très large ou index fragmenté ; reconstruire hors production ou revoir la clé.')
    creux = sorted([(k, v) for k, v in inv.get('tailles', {}).items() if v['nptotal'] >= 100000 and v['npused'] < 0.5 * v['nptotal']], key=lambda kv: -kv[1]['nptotal'])
    if creux:
        add('info', 'Stockage Informix', 'Tables avec beaucoup d\'espace alloué non utilisé',
            ' ; '.join('%s : %.0f %% utilisé sur %s pages' % (k[1], 100.0 * v['npused'] / v['nptotal'], fmt_n(v['nptotal'])) for k, v in creux[:6]),
            'Espace libéré par des suppressions : réorganisation (repack/shrink via sysadmin) pour récupérer l\'espace, utile avec un dbspace presque plein.')
    # trace SQL
    sq = x.get('sql')
    if sq and sq['groupes']:
        tot = sq['total']
        for cle, lib in (('pgreads', 'des lectures disque tracées'), ('duree', 'du temps d\'exécution tracé'), ('lockwaits', 'des attentes de verrou tracées')):
            if not tot[cle]:
                continue
            g = max(sq['groupes'], key=lambda g: g[cle])
            part = 100.0 * g[cle] / tot[cle]
            if part >= 20:
                add('haute', 'Requêtes SQL', 'Une requête représente %.0f %% %s' % (part, lib),
                    '%s exécution(s), %s pages lues sur disque, %s lectures en mémoire, %s s cumulées ; isolation %s ; « %s »' % (
                        fmt_n(g['exec']), fmt_n(g['pgreads']), fmt_n(g['bfreads']), fmt(g['duree']),
                        ', '.join(ISOLATION.get(z, z) for z in sorted(g['isolation'])) or '?', g['texte'][:220]),
                    'Analyser le plan (SET EXPLAIN ON sur la requête), les index utilisés et les statistiques des tables citées ; si elle est exécutée en boucle, '
                    'revoir le traitement côté programme.')
        boucles = sorted([g for g in sq['groupes'] if g['exec'] >= 1000 and g['exec'] >= 0.2 * tot['exec']], key=lambda g: -g['exec'])
        if boucles:
            add('moyenne', 'Requêtes SQL', 'Requête exécutée en boucle', '%s exécutions (%.0f %% des requêtes tracées) : « %s »' % (
                fmt_n(boucles[0]['exec']), 100.0 * boucles[0]['exec'] / tot['exec'], boucles[0]['texte'][:200]),
                'Traitement ligne à ligne probable : regrouper (jointure, IN, traitement ensembliste) ou mettre en cache côté programme.')
        rr = [g for g in sq['groupes'] if '5' in g['isolation'] and g['lockwaits']]
        if rr:
            add('moyenne', 'Requêtes SQL', 'Lectures en REPEATABLE READ avec attentes de verrou', ' ; '.join('« %s »' % g['texte'][:120] for g in rr[:3]),
                'REPEATABLE READ verrouille chaque ligne lue jusqu\'à la fin de la transaction : COMMITTED READ suffit en général pour la consultation.')
    return r


def section_expert(s, t0, t1, marq):
    x = s.get('exp') or {}
    o = ['<h3>Analyse experte Informix</h3>']
    prof = s.get('profil') or []
    st = lambda k: stats([e.get(k) for e in prof])
    lg = x.get('log') or {}
    kpi = [('Validations /s', fmt(st('commit_s')['moy'])), ('Opérations ISAM /s', fmt_n(st('isam_s')['moy'])), ('Lectures logiques /s', fmt_n(st('bufreads_s')['moy'])),
           ('Lectures disque /s', fmt_n(st('dskreads_s')['moy'])), ('Écritures disque /s', fmt_n(st('dskwrits_s')['moy'])),
           ('Lecture anticipée utile', pct(st('ra_eff')['moy'])), ('Pages / écriture log logique', fmt(lg.get('l_pages_par_io'))),
           ('Log physique max', pct(lg.get('phys_max')))]
    o.append('<div class="k">%s</div>' % ''.join('<div class="c"><div class="v">%s</div><div class="l">%s</div></div>' % (v, esc(l)) for l, v in kpi))
    ch = x.get('chunks') or {}
    if ch:
        lignes = []
        for c, serie in sorted(ch.items(), key=lambda kv: -stats([e['lect_mo_s'] + e['ecr_mo_s'] for e in kv[1]])['moy']):
            lm, em, io_, la, ea = (stats([e[k] for e in serie]) for k in ('lect_mo_s', 'ecr_mo_s', 'iops', 'lect_ms', 'ecr_ms'))
            lignes.append(['<span class="mono">%s</span>' % esc(c), fmt(lm['moy']), fmt(lm['max']), fmt(em['moy']), fmt(em['max']), fmt(io_['moy']), fmt(io_['max']),
                           fmt(la['moy']), fmt(la['p95']), fmt(ea['moy']), fmt(ea['p95'])])
        o.append('<h3>Vitesse des chunks (par intervalle, onstat -g iof)</h3>' + tableau(
            ['Chunk', 'Lecture Mo/s moy.', 'max', 'Écriture Mo/s moy.', 'max', 'IOPS moy.', 'max', 'Lecture ms moy.', 'p95', 'Écriture ms moy.', 'p95'], lignes[:25]))
    graphes = []
    if ch:
        top = sorted(ch.items(), key=lambda kv: -stats([e['lect_mo_s'] + e['ecr_mo_s'] for e in kv[1]])['moy'])[:4]
        graphes += [
            courbe('Chunks : débit lecture + écriture (Mo/s)', [(os.path.basename(c), COULEURS[i], [dict(ts=e['ts'], v=e['lect_mo_s'] + e['ecr_mo_s']) for e in sv], 'v')
                                                              for i, (c, sv) in enumerate(top)], t0, t1, marq, ' Mo/s'),
            courbe('Chunks : temps de réponse en écriture (ms)', [(os.path.basename(c), COULEURS[i], sv, 'ecr_ms') for i, (c, sv) in enumerate(top)], t0, t1, marq, ' ms')]
    if x.get('ioq'):
        graphes.append(courbe('Files d\'I/O du moteur : plus longue file (onstat -g ioq)', [('requêtes en attente', COULEURS[7], x['ioq'], 'len_max')], t0, t1, marq))
    if x.get('temp'):
        noms = sorted({k for e in x['temp'] for k in e if k != 'ts'})
        graphes.append(courbe('Dbspaces temporaires : occupation (%)', [(n, COULEURS[i % len(COULEURS)], x['temp'], n) for i, n in enumerate(noms)], t0, t1, marq, ' %', ymax=100))
    graphes = [g for g in graphes if g]
    if graphes:
        o.append('<div class="g">%s</div>' % ''.join(graphes))
    if x.get('mutex'):
        o.append('<details open><summary>Contention sur les mutex (onstat -g spi)</summary>%s</details>' % tableau(
            ['Mutex / spin lock', 'Attentes /min', 'Boucles par attente', 'Interprétation'],
            [[esc(m['nom']), fmt_n(m['attentes_min']), fmt(m['boucles_par_attente']), esc(m['indice'])] for m in x['mutex']]))
    if x.get('buf'):
        o.append('<details><summary>Écritures par pool de buffers (onstat -g buf)</summary>%s</details>' % tableau(
            ['Taille de page', 'Premier plan', 'LRU', 'Chunk (checkpoints)', 'Part chunk'],
            [[esc(k), fmt_n(v['d_fg']), fmt_n(v['d_lru']), fmt_n(v['d_chunk']), pct(v['part_chunk'])] for k, v in sorted(x['buf'].items())]))
    bl = x.get('blocage') or {}
    if bl.get('tenants'):
        o.append('<h3>Chaînes de blocage (qui bloque qui)</h3><p class="d">%d relevé(s) effectué(s) quand au moins 2 sessions attendaient un verrou.</p>%s' % (
            bl['releves'], tableau(['Session bloquante', 'Utilisateur', 'Poste', 'PID', 'Attentes causées', 'Relevés', 'De', 'À', 'Tables', 'Sessions bloquées'],
                                   [[esc(t['sid']), esc(t['utilisateur']), esc(t['poste']), esc(t['pid']), str(t['attentes']), str(len(t['releves'])),
                                     t['premier'].strftime('%H:%M:%S'), t['dernier'].strftime('%H:%M:%S'),
                                     esc(', '.join('%s (%d)' % kv for kv in sorted(t['tables'].items(), key=lambda kv: -kv[1])[:4])),
                                     esc(', '.join(sorted(t['bloques'])[:8]))] for t in bl['tenants'][:20]])))
    if x.get('memoire'):
        o.append('<details><summary>Sessions les plus consommatrices de mémoire</summary>%s</details>' % tableau(
            ['Session', 'Utilisateur', 'Poste', 'PID', 'Mémoire max (Mo)'],
            [[esc(m['sid']), esc(m['utilisateur']), esc(m['poste']), esc(m['pid']), fmt(m['mo'])] for m in x['memoire']]))
    if x.get('cfg'):
        o.append('<details><summary>Paramètres modifiés à chaud</summary>%s</details>' % tableau(['Paramètre', 'Fichier ONCONFIG', 'Valeur en mémoire'],
                                                                                          [[esc(a), esc(b), esc(c)] for a, b, c in x['cfg']]))
    inv = s.get('inv') or {}
    if inv.get('index_detail'):
        det = sorted(inv['index_detail'].items(), key=lambda kv: -(kv[1]['feuilles'] or 0))[:25]
        o.append('<details><summary>Structure des plus gros index (sysindexes)</summary>%s</details>' % tableau(
            ['Index', 'Table', 'Type', 'Niveaux', 'Pages feuilles', 'Clés distinctes', 'Colonnes (n° ; négatif = DESC)'],
            [[esc(i), esc(v['table']), 'unique' if v['type'] == 'U' else 'doublons', fmt(v['niveaux']), fmt_n(v['feuilles']), fmt_n(v['uniques']),
              esc(', '.join(str(c) for c in v['colonnes']))] for (_b, i), v in det]))
    sq = x.get('sql')
    if sq and sq['groupes']:
        o.append('<h3>Requêtes SQL tracées (%d exécutions, %d formes distinctes)</h3>' % (sq['nb'], len(sq['groupes'])))
        for cle, titre in (('pgreads', 'par lectures disque'), ('bfreads', 'par lectures en mémoire (CPU)'), ('duree', 'par temps d\'exécution cumulé'),
                           ('lockwaits', 'par attentes de verrou'), ('exec', 'par nombre d\'exécutions')):
            L = [g for g in sorted(sq['groupes'], key=lambda g: -g[cle]) if g[cle]][:12]
            if L:
                o.append('<details%s><summary>Top %s</summary>%s</details>' % (' open' if cle == 'pgreads' else '', esc(titre), tableau(
                    ['Exécutions', 'Pages disque', 'Lectures mémoire', 'Durée cumulée (s)', 'Attentes verrou', 'Tris disque', 'Lignes', 'Sessions', 'Isolation', 'Requête (littéraux → ?)'],
                    [[fmt_n(g['exec']), fmt_n(g['pgreads']), fmt_n(g['bfreads']), fmt(g['duree']), fmt_n(g['lockwaits']), fmt_n(g['tris_disque']), fmt_n(g['lignes']),
                      str(len(g['sessions'])), esc(', '.join(ISOLATION.get(z, z) for z in sorted(g['isolation']))), '<span class="mono">%s</span>' % esc(g['texte'])] for g in L])))
    else:
        o.append('<p class="d">Trace SQL non activée : relancer l\'audit avec <span class="mono">--trace-sql</span> pour relier les objets coûteux aux requêtes '
                 '(top des requêtes par lectures, durée, verrous, tris disque).</p>')
    return ''.join(o)


# --------------------------------------------------------------------------------------------
# Chargement d'un serveur
# --------------------------------------------------------------------------------------------
def charger(d):
    info = dict(re.findall(r'^(\w+)=(.*)$', lire(os.path.join(d, 'info.txt')), re.M))
    s = {'dossier': d, 'info': info, 'nom': info.get('serveur', os.path.basename(d)), 'roles': info.get('roles', ''),
         'ncpu': int(info.get('nb_cpu') or 1), 'informix': info.get('informix') == '1'}
    s['cpu'], s['charge'], s['mem'] = serie_cpu(d), serie_charge(d), serie_memoire(d)
    s['disques'], s['dm'], s['reseau'], s['latence'] = serie_disques(d), noms_dm(d), serie_reseau(d), serie_latence(d)
    s['irium'], s['jobs'] = serie_irium(d)
    s['top'], s['etat_d'] = top_processus(d), etat_d(d)
    s['buddy'] = serie_buddy(d)
    s['services'], s['svc_echec'] = serie_services(d, info), services_echec(d)
    tous = [e['ts'] for e in s['cpu']] or [dt.datetime.now()]
    s['debut'], s['fin'] = min(tous), max(tous)
    s['marqueurs'] = []
    for l in lire(os.path.join(d, 'marqueurs.txt')).splitlines():
        p = l.split('|', 3)
        if len(p) == 4 and p[0].isdigit():
            s['marqueurs'].append((dt.datetime.fromtimestamp(int(p[0])), p[2], p[3]))
    if s['informix']:
        s['profil'], s['sessions'] = serie_profil(d), serie_sessions(d)
        s['verrous'] = serie_simple(d, 'onstat_k.raw', f_verrous)
        s['ready'] = serie_simple(d, 'onstat_rea.raw', f_ready)
        s['fg'] = deltas(serie_simple(d, 'onstat_F.raw', f_fg), 'fg', par_min=True)
        s['entete'] = serie_simple(d, 'onstat_entete.raw', f_entete)
        s['ckp'], s['vp'], s['logs'], s['iof'] = checkpoints(d), vp_cpu(d), logs_logiques(d), iof(d)
        s['logs_h'] = bascules_logs(d)
        s['nb_chunks'] = len([l for l in lire(os.path.join(d, 'statique', 'informix', 'onstat__d.txt')).splitlines()
                              if re.match(r'^[0-9a-f]{6,}\s+\d+\s+\d+\s+\d+', l)])
        s['repl'], s['backlog'] = replication(d)
        s['conf'] = onconfig(d)
        s['journal'], ckp_log = journal_moteur(d, s['debut'], s['fin'])
        s['inv'] = inventaire(d)
        ups = [e['uptime_s'] for e in s['entete'] if e.get('uptime_s')]
        s['obj'] = objets(d, s['inv'], ups[-1] if ups else None)
        s['ses_prof'], s['dio'] = sessions_profil(d), ouverture_chunks(d)
        s['prog'] = programmes(d)
        s['exp'] = expert_informix(s)
        s['aprog'] = analyse_programmes(s)
        if not s['ckp']:
            s['ckp'] = ckp_log
    return s


# --------------------------------------------------------------------------------------------
# Diagnostic
# --------------------------------------------------------------------------------------------
def pire_moment(serie, cle):
    v = [e for e in serie if e.get(cle) is not None]
    return max(v, key=lambda e: e[cle]) if v else None


def fenetres(serie, cle, seuil, min_points=2):
    """Plages horaires où la métrique dépasse le seuil (au moins min_points échantillons consécutifs)."""
    res, cour = [], []
    for e in serie:
        if e.get(cle) is not None and e[cle] > seuil:
            cour.append(e)
        else:
            if len(cour) >= min_points:
                res.append((cour[0]['ts'], cour[-1]['ts'], max(x[cle] for x in cour)))
            cour = []
    if len(cour) >= min_points:
        res.append((cour[0]['ts'], cour[-1]['ts'], max(x[cle] for x in cour)))
    return res


def plages(f):
    return ', '.join('%s-%s (max %.0f)' % (a.strftime('%H:%M'), b.strftime('%H:%M'), m) for a, b, m in f[:6]) + (' …' if len(f) > 6 else '')


def diagnostic(s):
    c = []   # (gravité, domaine, constat, preuve, recommandation)
    add = lambda g, dom, t, p, r: c.append((g, dom, t, p, r))
    cpu_tot = [dict(ts=e['ts'], tot=e['user'] + e['sys']) for e in s['cpu']]
    st = stats([e['tot'] for e in cpu_tot])
    if st['p95'] is not None and st['p95'] > 85:
        add('haute', 'CPU', 'Saturation processeur sur %s' % s['nom'],
            'CPU utilisé p95 %.0f %% (moyenne %.0f %%) ; plages > 90 %% : %s' % (st['p95'], st['moy'], plages(fenetres(cpu_tot, 'tot', 90)) or 'aucune prolongée'),
            'Identifier les processus en tête (tableau « Processus les plus consommateurs »). Sur la base : vérifier les requêtes '
            'à balayage séquentiel et la file d\'attente des VP CPU ; sur les serveurs d\'applications : nombre de sessions IRIUM par CPU.')
    ch = stats([e['load1'] / s['ncpu'] for e in s['charge'] if e['load1'] is not None])
    if ch['p95'] is not None and ch['p95'] > 1.5:
        add('haute', 'CPU', 'Charge supérieure au nombre de CPU', 'charge/CPU p95 %.2f (max %.2f) pour %d CPU' % (ch['p95'], ch['max'], s['ncpu']),
            'File d\'attente d\'exécution trop longue : processus en attente de CPU ou d\'I/O (état D). Croiser avec iowait.')
    io = stats([e['iowait'] for e in s['cpu']])
    if io['p95'] is not None and io['p95'] > 15:
        add('haute' if io['p95'] > 25 else 'moyenne', 'Disques', 'Attente d\'entrées/sorties élevée (iowait)',
            'iowait p95 %.0f %% (max %.0f %%) ; plages > 20 %% : %s' % (io['p95'], io['max'], plages(fenetres(s['cpu'], 'iowait', 20)) or '-'),
            'Les processeurs attendent le stockage : voir les disques à forte occupation ci-dessous.')
    stl = stats([e['steal'] for e in s['cpu']])
    if stl['p95'] is not None and stl['p95'] > 5:
        add('haute' if stl['p95'] > 10 else 'moyenne', 'Virtualisation', 'Temps CPU « volé » par l\'hyperviseur',
            'steal p95 %.1f %% (max %.1f %%)' % (stl['p95'], stl['max']),
            'La VM n\'obtient pas les CPU demandés : surallocation de l\'hôte. Réserver les vCPU (réservation / affinité) auprès de l\'équipe virtualisation.')
    for dev, serie in s['disques'].items():
        u, a = stats([e['util'] for e in serie]), stats([e['await'] for e in serie])
        nom = '%s%s' % (dev, (' (%s)' % s['dm'][dev]) if dev in s['dm'] else '')
        if u['p95'] is not None and u['p95'] > 80 and a['p95'] > 10:
            add('critique' if a['p95'] > 30 else 'haute', 'Disques', 'Goulot d\'étranglement sur le disque %s' % nom,
                'occupation p95 %.0f %%, temps de réponse p95 %.1f ms (max %.1f ms), %.0f IOPS en moyenne'
                % (u['p95'], a['p95'], a['max'], stats([e['r_s'] + e['w_s'] for e in serie])['moy']),
                'Vérifier sur quel dbspace/chunk il porte (tableau « Chunks Informix »), la baie (latence, cache), le multipath et '
                'le planificateur I/O. Envisager de répartir les dbspaces chauds (données, index, logs, temp) sur des LUN distinctes.')
        elif a['p95'] is not None and a['p95'] > 20 and stats([e['r_s'] + e['w_s'] for e in serie])['moy'] > 5:
            add('moyenne', 'Disques', 'Temps de réponse élevé sur %s' % nom, 'temps de réponse p95 %.1f ms, occupation p95 %.0f %%' % (a['p95'], u['p95']),
                'Latence de stockage supérieure à 20 ms : à remonter à l\'équipe stockage (baie, SAN).')
    mem = stats([e['dispo_pct'] for e in s['mem']])
    sw = stats([(e.get('swap_in_s') or 0) + (e.get('swap_out_s') or 0) for e in s['mem']])
    if sw['moy'] is not None and sw['max'] > 50:
        add('haute', 'Mémoire', 'Le serveur utilise le swap (pagination)',
            'swap in+out max %.0f pages/s, moyenne %.1f ; mémoire disponible min %.0f %%' % (sw['max'], sw['moy'], mem['min'] or 0),
            'Mémoire insuffisante : réduire SHMTOTAL/BUFFERPOOL si la base se partage la machine, ou ajouter de la RAM. Sur la base, '
            'activer RESIDENT pour verrouiller la mémoire partagée.')
    elif mem['min'] is not None and mem['min'] < 5:
        add('moyenne', 'Mémoire', 'Mémoire disponible très faible', 'minimum %.1f %%' % mem['min'], 'Surveiller le risque de swap et d\'OOM killer.')
    cps, als = stats([e.get('compact_stall_s') for e in s['mem']]), stats([e.get('allocstall_s') for e in s['mem']])
    rec = stats([e.get('recup_mo_s') for e in s['mem']])
    bud = stats([e['bloc_ko'] for e in s.get('buddy', [])])
    s['_pression_mem'] = (cps['p95'] or 0) > 1 or (als['p95'] or 0) > 10 or (bud['min'] is not None and bud['min'] <= 16)
    if s['_pression_mem']:
        add('haute' if (cps['p95'] or 0) > 10 or (als['p95'] or 0) > 100 else 'moyenne', 'Mémoire', 'Pression mémoire du noyau (récupération et compactage)',
            'compactages bloquants p95 %s/s, allocations bloquantes p95 %s/s, recyclage du cache %s Mo/s en moyenne (max %s) ; plus petit « plus grand bloc libre » observé : %s Ko ; '
            'cache de fichiers %s Mo' % (fmt_n(cps['p95']), fmt_n(als['p95']), fmt_n(rec['moy']), fmt_n(rec['max']), fmt_n(bud['min']),
                                       fmt_n(s['mem'][-1]['cache_mo'] if s['mem'] else None)),
            'Les lectures disque d\'Informix transitent par le cache de pages du noyau, qui recycle et fragmente la mémoire ; les processus système (NFS…) se bloquent en '
            'compactage. Désactiver les Transparent Huge Pages, porter vm.min_free_kbytes à 256 Mo, activer réellement l\'I/O directe sur les chunks (DIRECT_IO 1) '
            'et surtout réduire les lectures physiques (classements des objets).')
    mfk = re.search(r'vm.min_free_kbytes = (\d+)', lire(os.path.join(s['dossier'], 'statique', 'noyau.txt')))
    ram_tot = s['mem'][-1]['total_mo'] if s['mem'] else 0
    if s['informix'] and mfk and ram_tot >= 30000 and int(mfk.group(1)) < 131072:
        add('moyenne' if s['_pression_mem'] else 'info', 'Système', 'Réserve mémoire du noyau faible', 'vm.min_free_kbytes = %s Ko pour %.0f Go de RAM' % (mfk.group(1), ram_tot / 1024),
            'Porter vm.min_free_kbytes à 262144 (256 Mo) via /etc/sysctl.d : réduit les allocations bloquantes des processus système.')
    ret = stats([e['retrans_pct'] for e in s['reseau']])
    if ret['p95'] is not None and ret['p95'] > 1:
        add('moyenne' if ret['p95'] < 3 else 'haute', 'Réseau', 'Retransmissions TCP', 'p95 %.2f %% des segments retransmis' % ret['p95'],
            'Pertes réseau : vérifier cartes, duplex, switches, firewall entre applications et base.')
    lat = stats([e['ping_ms'] for e in s['latence']])
    if lat['moy'] is not None and (lat['p95'] > 2 or any(e['tcp_echec'] for e in s['latence'])):
        add('haute' if lat['p95'] > 5 else 'moyenne', 'Réseau', 'Latence vers le serveur de base',
            'ping moyen %.2f ms, p95 %.2f ms ; échecs de connexion TCP : %d' % (lat['moy'], lat['p95'], sum(1 for e in s['latence'] if e['tcp_echec'])),
            'IRIUM échange de nombreux petits messages avec Informix : chaque milliseconde compte. Vérifier le chemin réseau '
            '(même VLAN/datacenter, pas de firewall intermédiaire inspectant le flux).')
    noyau = lire(os.path.join(s['dossier'], 'statique', 'noyau.txt'))
    if s['informix'] and '[always]' in noyau:
        add('moyenne', 'Système', 'Transparent Huge Pages activées', 'transparent_hugepage = always',
            'Désactiver THP sur le serveur Informix (transparent_hugepage=never via tuned ou grub) : source connue de latences et de pics CPU système.')
    m = re.search(r'vm.swappiness = (\d+)', noyau)
    if s['informix'] and m and int(m.group(1)) > 10:
        add('info', 'Système', 'vm.swappiness élevé pour un serveur de base', 'vm.swappiness = %s' % m.group(1),
            'Positionner vm.swappiness entre 1 et 10 sur le serveur Informix.')
    err = lire(os.path.join(s['dossier'], 'statique', 'erreurs.txt'))
    n_err = len(re.findall(r'(?i)i/o error|hung task|blocked for more|oom|killed process|not responding|soft lockup', err))
    if n_err:
        add('haute', 'Système', 'Erreurs système (I/O, blocages, mémoire)', '%d message(s) dans dmesg/journal (voir « Erreurs système »)' % n_err,
            'Analyser les messages : erreurs SCSI/multipath, tâches bloquées, OOM killer.')
    if s['etat_d'] and sum(n for _k, n in s['etat_d']) > 20:
        add('moyenne', 'Disques', 'Processus bloqués en attente d\'I/O (état D)',
            ', '.join('%s (%s) ×%d' % (k[0], k[1], n) for k, n in s['etat_d'][:4]), 'Confirme une attente du stockage ou d\'un montage réseau (NFS).')

    for x in regles_services(s):
        add(*x)
    if s['informix']:
        p = s['profil']
        cl = stats([e['cache_lect'] for e in p])
        if cl['moy'] is not None and cl['moy'] < 95:
            nb = sum(int(re.search(r'buffers=(\d+)', b).group(1)) * int(re.search(r'size=(\d+)', b).group(1) or 2)
                     for b in s['conf'].get('BUFFERPOOL', []) if re.search(r'buffers=(\d+)', b) and re.search(r'size=(\d+)', b))
            add('haute' if cl['moy'] < 90 else 'moyenne', 'Informix', 'Cache de lecture insuffisant',
                'taux de lecture en cache moyen %.1f %% (min %.1f %%)%s' % (cl['moy'], cl['min'], (' ; BUFFERPOOL ≈ %.0f Mo' % (nb / 1024.0)) if nb else ''),
                'Viser > 95 %% (OLTP > 98 %%) : augmenter le nombre de buffers dans BUFFERPOOL si la RAM le permet, et rechercher les '
                'balayages séquentiels (index manquants) qui vident le cache.')
        ce = stats([e['cache_ecr'] for e in p])
        if ce['moy'] is not None and ce['moy'] < 85:
            add('moyenne', 'Informix', 'Cache d\'écriture faible', 'taux d\'écriture en cache moyen %.1f %%' % ce['moy'],
                'Vérifier lru_min_dirty / lru_max_dirty et les checkpoints trop fréquents.')
        lw = stats([e['lockwts_min'] for e in p])
        dl = sum(e['deadlks'] for e in p)
        to = sum(e['dltouts'] for e in p)
        attL = stats([e['att_L'] for e in s['sessions']])
        if (lw['moy'] or 0) > 30 or dl or (attL['p95'] or 0) >= 3:
            add('haute' if (attL['p95'] or 0) >= 5 or (lw['p95'] or 0) > 300 else 'moyenne', 'Informix', 'Contention sur les verrous',
                'attentes de verrou %.0f/min en moyenne (p95 %.0f) ; sessions en attente de verrou p95 %.0f (max %.0f) ; interblocages %d, '
                'expirations %d ; plages : %s' % (lw['moy'] or 0, lw['p95'] or 0, attL['p95'] or 0, attL['max'] or 0, dl, to,
                                                  plages(fenetres(s['sessions'], 'att_L', 2)) or '-'),
                'Identifier les tables (tableau sysptprof « attentes de verrous ») et les traitements en cause (ipscrond en même temps ?). '
                'Vérifier DEF_TABLE_LOCKMODE (row recommandé), les transactions longues des batchs, et l\'isolation (COMMITTED READ LAST COMMITTED).')
        ov = sum(e['ovlock'] for e in p) + sum(e.get('overflows', 0) for e in s['verrous'][-1:])
        if ov:
            add('haute', 'Informix', 'Débordement de la table des verrous', 'ovlock/overflows = %d' % ov, 'Augmenter LOCKS dans ONCONFIG.')
        ck = s['ckp']
        cks = stats([x['total'] for x in ck])
        blq = [x for x in ck if x.get('bloque', 0) > 0.5 or x.get('attentes', 0) > 0]
        cw = sum(e['ckpwaits'] for e in p)
        attC = stats([e['att_C'] for e in s['sessions']])
        if cw or blq or (cks['max'] or 0) > 10 or (attC['max'] or 0) > 2:
            add('haute' if blq or cw > 10 else 'moyenne', 'Informix', 'Checkpoints pénalisants',
                '%d checkpoint(s) observé(s), durée max %.1f s (moyenne %.1f s) ; %d bloquant(s) ; attentes de checkpoint %d ; '
                'déclencheurs : %s' % (len(ck), cks['max'] or 0, cks['moy'] or 0, len(blq), cw,
                                      ', '.join(sorted({x.get('declencheur', '?') for x in ck}))),
                'Les sessions sont suspendues pendant les sections critiques. Vérifier la vitesse d\'écriture des chunks, '
                'CLEANERS (≥ nombre de chunks actifs), lru_max_dirty, RTO_SERVER_RESTART/AUTO_CKPTS, et la taille du log physique '
                '(déclencheur « Plog » = log physique trop petit).')
        fg = sum(e['fg'] for e in s['fg'])
        if fg > 0:
            add('haute', 'Informix', 'Écritures au premier plan (foreground writes)', '%d écritures au premier plan pendant la supervision' % fg,
                'Une session doit écrire elle-même des pages faute de buffer libre : augmenter CLEANERS, baisser lru_max_dirty, '
                'vérifier l\'AUTO_LRU_TUNING.')
        bw = stats([e['bufwaits_ratio'] for e in p])
        if bw['moy'] is not None and bw['moy'] > 7:
            add('moyenne', 'Informix', 'Attentes sur les buffers', 'ratio bufwaits %.1f %%' % bw['moy'],
                'Contention sur les buffers (pages chaudes, LRU) : augmenter le nombre de LRU, revoir les tables très sollicitées.')
        rq = stats([e['ready'] for e in s['ready']])
        ncpuvp = (s['vp'] or {}).get('cpu', {}).get('vps')
        occ = (s['vp'] or {}).get('cpu', {}).get('occupation')
        if (rq['p95'] or 0) > (ncpuvp or 2) or (occ or 0) > 85:
            add('haute', 'Informix', 'Manque de puissance CPU pour le moteur',
                'threads prêts en attente de CPU VP : p95 %.0f (max %.0f) ; occupation des VP CPU %s pour %s VP' % (
                    rq['p95'] or 0, rq['max'] or 0, ('%.0f %%' % occ) if occ is not None else '?', ncpuvp or '?'),
                'Augmenter le nombre de VP CPU (VPCLASS cpu,num=…) jusqu\'au nombre de cœurs disponibles, ou réduire la charge '
                '(requêtes coûteuses, balayages séquentiels).')
        sq = stats([e['seqscans_min'] for e in p])
        if (sq['moy'] or 0) > 50:
            add('moyenne', 'Informix', 'Nombreux balayages séquentiels', '%.0f balayages séquentiels/min en moyenne (max %.0f)' % (sq['moy'], sq['max']),
                'Index manquants ou statistiques obsolètes : voir les tables en tête (sysptprof) et planifier UPDATE STATISTICS.')
        attG = stats([e['att_G'] for e in s['sessions']])
        if (attG['p95'] or 0) >= 2:
            add('moyenne', 'Informix', 'Attentes d\'écriture du log logique', 'sessions en attente de log p95 %.0f' % attG['p95'],
                'Disque des logs lent ou LOGBUFF trop petit ; avec HDR synchrone, la réplica ralentit les validations.')
        attB = stats([e['att_B'] for e in s['sessions']])
        attS = stats([e['att_S'] for e in s['sessions']])
        if (attB['p95'] or 0) >= 3 or (attS['p95'] or 0) >= 3:
            add('moyenne', 'Informix', 'Sessions en attente de buffers ou de mutex', 'buffer p95 %.0f, mutex p95 %.0f' % (attB['p95'] or 0, attS['p95'] or 0),
                'Contention interne : voir onstat -g ath / -g wai et les pages les plus sollicitées.')
        lg = s['logs']
        if lg['total'] and lg['non_sauves'] >= 0.75 * lg['total']:
            add('critique', 'Informix', 'Logs logiques presque tous non sauvegardés',
                '%d sur %d logs utilisés non sauvegardés' % (lg['non_sauves'], lg['total']),
                'Risque de blocage du moteur (« Logical Log Files are Full »). Vérifier la sauvegarde continue des logs (LTAPEDEV/onbar).')
        bloque = [e for e in s['entete'] if e.get('bloque')]
        if bloque:
            add('critique', 'Informix', 'Moteur bloqué pendant la supervision',
                '%d échantillon(s) « Blocked:%s » (premier à %s)' % (len(bloque), bloque[0]['bloque'], bloque[0]['ts'].strftime('%H:%M')),
                'Le moteur suspend toutes les sessions : lire le journal du moteur à ces heures.')
        lents = [x for x in s['iof'] if (x['ecr_ms'] or 0) > 20 or (x['lect_ms'] or 0) > 20]
        if lents:
            add('haute', 'Informix', 'Chunks à temps de réponse élevé',
                '; '.join('%s : lecture %s ms, écriture %s ms' % (x['fichier'], '%.1f' % x['lect_ms'] if x['lect_ms'] is not None else '-',
                                                                 '%.1f' % x['ecr_ms'] if x['ecr_ms'] is not None else '-') for x in lents[:5]),
                'Temps moyen par I/O mesuré par Informix supérieur à 20 ms : stockage sous-dimensionné ou mal réparti.')
        for e in s['repl'][-1:]:
            if e[2].lower() != 'on' and not nb_rss(s['dossier']):   # avec un secondaire RSS, HDR « off » est normal
                add('haute', 'Réplication', 'Réplication HDR non active', 'type %s, état %s, serveur apparié %s' % (e[1], e[2], e[3]),
                    'Vérifier la liaison avec la réplica (onstat -g dri, journal du moteur).')
        bl = stats([x['backlog'] for x in s['backlog']])
        if (bl['max'] or 0) > 0:
            add('moyenne', 'Réplication', 'Retard de réplication (backlog)', 'backlog max %d' % bl['max'],
                'La réplica ne suit pas : réseau ou disques de la réplica lents.')
        crit = [x for x in s['journal'] if x[1] in ('critique', 'haute')]
        if crit:
            add('haute', 'Informix', 'Messages importants dans le journal du moteur', '%d message(s), ex. %s : %s' % (len(crit), crit[0][0].strftime('%H:%M'), crit[0][2][:120]),
                'Voir la section « Journal du moteur ».')
        cf = s['conf']
        if cf.get('DEF_TABLE_LOCKMODE', '').lower() == 'page':
            add('info', 'Informix', 'Verrouillage par page par défaut', 'DEF_TABLE_LOCKMODE page', 'Le verrouillage par ligne limite la contention en OLTP.')
        if cf.get('RESIDENT', '') in ('0', ''):
            add('info', 'Informix', 'Mémoire partagée non résidente', 'RESIDENT %s' % (cf.get('RESIDENT') or 'absent'),
                'RESIDENT -1 empêche la mise en swap de la mémoire partagée (avec suffisamment de RAM).')
        if not cf.get('DBSPACETEMP'):
            add('info', 'Informix', 'Pas de DBSPACETEMP', 'DBSPACETEMP absent', 'Les tris et tables temporaires vont dans le rootdbs : définir des dbspaces temporaires dédiés.')
        for x in regles_objets(s) + regles_programmes(s) + regles_expert(s):
            add(*x)
        ram = s['mem'][-1]['total_mo'] if s['mem'] else 0
        fich = [x for x in s.get('dio', []) if x['type'] == 'fichier']
        mes = {'contention': any(x[2] == 'Contention sur les verrous' for x in c), 'att_G': attG['p95'] or 0, 'pression_mem': s.get('_pression_mem'),
               'chunks_fichiers': len(fich), 'chunks_sans_odirect': len([x for x in fich if not x['o_direct']]), 'tris': s.get('_tris'),
               'cache_lect': cl['moy'], 'gros_scans': [x for x in c if x[2] == 'Scans séquentiels coûteux sur de grandes tables'],
               'ping_ms': stats([e['ping_ms'] for e in s['latence']])['moy'],
               'hdr_actif': any(e[2].lower() == 'on' for e in s['repl']), 'nb_rss': nb_rss(s['dossier'])}
        for g, t, pv, rec in revue_configuration(cf, ram, s['ncpu'], s.get('nb_chunks', 0), s.get('logs_h'), mes):
            add(g, 'Configuration', t, pv, rec)
    c.sort(key=lambda x: GRAV[x[0]][2])
    return c


def kv_option(v, cle):
    m = re.search(r'(?:^|,)\s*%s\s*=\s*([\w.]+)' % cle, v)
    return m.group(1) if m else None


def revue_configuration(cf, ram_mo, ncpu, nb_chunks=0, logs_h=None, mes=None):
    """Lecture experte de l'ONCONFIG au regard du serveur (RAM, cœurs) et, si fournies, des mesures de l'audit
    (mes : contention, attentes de log, pression mémoire, ouverture des chunks, tris...). Retourne [(gravité, constat, preuve, recommandation)]."""
    r, mes = [], mes or {}
    ent = lambda k, d=None: (lambda x: int(x) if re.match(r'^-?\d+$', x or '') else d)(str(cf.get(k, '')).strip().strip('"'))
    # mémoire partagée
    bp_mo = 0.0
    for b in cf.get('BUFFERPOOL', []):
        n, t = kv_option(b, 'buffers'), kv_option(b, 'size')
        if n:
            bp_mo += int(n) * int(re.sub(r'\D', '', t or '2') or 2) / 1024.0
    virt_mo = (ent('SHMVIRTSIZE', 0) or 0) / 1024.0
    if bp_mo:
        txt = 'BUFFERPOOL %.1f Go + segment virtuel initial %.1f Go (SHMVIRTSIZE)%s' % (bp_mo / 1024, virt_mo / 1024, (' pour %.0f Go de RAM' % (ram_mo / 1024)) if ram_mo else '')
        if ram_mo and bp_mo + virt_mo > 0.75 * ram_mo:
            r.append(('haute' if bp_mo + virt_mo > 0.85 * ram_mo else 'moyenne', 'Mémoire partagée Informix proche de la RAM totale',
                      txt + ' (%.0f %% de la RAM), RESIDENT %s' % (100.0 * (bp_mo + virt_mo) / ram_mo, cf.get('RESIDENT', '?')),
                      'Avec RESIDENT -1 cette mémoire est verrouillée : il reste peu de place pour l\'OS, le cache de fichiers et les sessions '
                      '(le segment virtuel grossit ensuite par pas de SHMADD). Surveiller le swap ; sinon réduire SHMVIRTSIZE ou ajouter de la RAM.'))
        elif False:
            r.append(('haute', 'Mémoire partagée Informix proche de la RAM totale', txt + ', RESIDENT %s' % cf.get('RESIDENT', '?'),
                      'Avec RESIDENT -1 la mémoire est verrouillée : l\'OS et les autres processus sont poussés en swap. Réduire SHMVIRTSIZE ou le BUFFERPOOL, ou ajouter de la RAM.'))
        else:
            r.append(('info', 'Dimensionnement mémoire', txt, 'Cohérent si le taux de lecture en cache reste > 98 % (voir graphique Informix).'))
    for b in cf.get('BUFFERPOOL', []):
        mx = kv_option(b, 'lru_max_dirty')
        if mx and float(mx) <= 5:
            r.append(('info', 'Nettoyage des buffers très agressif', 'lru_min_dirty=%s, lru_max_dirty=%s, lrus=%s' % (kv_option(b, 'lru_min_dirty'), mx, kv_option(b, 'lrus')),
                      'Les pages modifiées sont écrites en continu (écritures LRU) : checkpoints courts, mais charge d\'écriture permanente sur les disques. '
                      'Si les disques sont saturés en écriture, remonter progressivement (ex. 10/20) en surveillant la durée des checkpoints.'))
    # VP CPU et NET
    cpu_vp = 0
    for v in cf.get('VPCLASS', []):
        if v.lower().startswith('cpu'):
            cpu_vp = int(kv_option(v, 'num') or 0)
    net_vp = sum(int(x.split(',')[1]) for x in cf.get('NETTYPE', []) if len(x.split(',')) >= 4 and x.split(',')[3].strip().upper() == 'NET' and x.split(',')[1].isdigit())
    if cpu_vp and ncpu:
        if cpu_vp >= ncpu:
            r.append(('haute', 'Plus de VP CPU que de cœurs', 'VPCLASS cpu,num=%d pour %d CPU visibles, + %d VP réseau (NET)' % (cpu_vp, ncpu, net_vp),
                      'Les VP CPU se disputent les cœurs avec les VP réseau, AIO et l\'OS : prévoir num ≤ cœurs - 1 (et ≤ cœurs - 2 si des processus IRIUM tournent sur ce serveur).'))
        elif cpu_vp + net_vp > ncpu:
            r.append(('moyenne', 'VP CPU + VP réseau supérieurs au nombre de cœurs', '%d VP CPU + %d VP NET pour %d CPU' % (cpu_vp, net_vp, ncpu),
                      'Sous forte charge, les VP NET (NETTYPE …,NET) prennent du temps CPU aux VP CPU. Envisager les threads d\'écoute sur la classe CPU, ou moins de VP NET.'))
        else:
            r.append(('info', 'VP CPU', '%d VP CPU + %d VP NET pour %d CPU' % (cpu_vp, net_vp, ncpu), 'Cohérent ; confirmer avec l\'occupation des VP et la file des threads prêts.'))
    ulc = str(cf.get('USELASTCOMMITTED', '')).strip('"').upper()
    if ulc in ('NONE', '', '0'):
        r.append(('haute' if mes.get('contention') else 'moyenne', 'Lecture de la dernière version validée désactivée',
                  'USELASTCOMMITTED %s%s' % (cf.get('USELASTCOMMITTED') or 'absent', ' ; confirmé par la mesure : contention sur les verrous pendant l\'audit' if mes.get('contention') else ''),
                  'En COMMITTED READ, un lecteur attend la fin des transactions qui modifient les lignes (batchs ipscrond). « COMMITTED READ » réduit fortement '
                  'ces attentes de verrous : à valider avec l\'éditeur IRIUM et à tester sur un environnement de recette.'))
    scope, dri = str(cf.get('HDR_TXN_SCOPE', '')).upper(), cf.get('DRINTERVAL')
    if mes.get('nb_rss') and not mes.get('hdr_actif') and (scope in ('NEAR_SYNC', 'FULL_SYNC') or str(dri) == '-1'):
        r.append(('info', 'Paramètres HDR sans effet : secondaire RSS', 'HDR_TXN_SCOPE %s, DRINTERVAL %s ; %d serveur(s) RSS, pas de paire HDR active' % (scope or '-', dri, mes['nb_rss']),
                  'La réplication RSS est toujours asynchrone : les validations n\'attendent pas le secondaire. Les lenteurs ne viennent pas de la réplication ; '
                  'LOG_INDEX_BUILDS 1 est requis par RSS. Surveiller seulement le retard du secondaire (onstat -g rss).'))
    elif scope in ('NEAR_SYNC', 'FULL_SYNC') or str(dri) == '-1':
        r.append(('haute' if mes.get('att_G', 0) >= 2 else 'moyenne', 'Réplication HDR synchrone',
                  'HDR_TXN_SCOPE %s, DRINTERVAL %s, DRTIMEOUT %s%s' % (scope or '-', dri, cf.get('DRTIMEOUT', '-'),
                                                                    ' ; mesuré : sessions en attente d\'écriture du log p95 %.0f' % mes['att_G'] if mes.get('att_G', 0) >= 2 else ''),
                  'Chaque validation attend la réplica (NEAR_SYNC : réception du log). La latence réseau principale ↔ réplica et la charge de la réplica s\'ajoutent '
                  'à chaque COMMIT : mesurer le ping entre les deux serveurs et comparer avec le rapport de la réplica. ASYNC supprime cette attente au prix d\'un RPO non nul.'))
    if str(cf.get('LTAPEDEV', '')).strip() == '/dev/null':
        r.append(('moyenne', 'Logs logiques non sauvegardés', 'LTAPEDEV /dev/null',
                  'Pas de restauration à un instant donné (perte des transactions depuis la dernière sauvegarde de niveau 0 en cas de sinistre). Sans effet sur les performances, '
                  'mais à faire valider par le client (la réplica HDR ne protège pas d\'une erreur logique).'))
    if (ent('LOGBUFF') or 0) and ent('LOGBUFF') < 256:
        r.append(('info', 'Buffer du log logique petit', 'LOGBUFF %s Ko' % cf.get('LOGBUFF'), 'Valeur courante 256 à 1024 Ko sur un OLTP chargé, surtout avec HDR (moins de vidages et d\'envois).'))
    if (ent('PHYSBUFF') or 0) and ent('PHYSBUFF') < 512:
        r.append(('info', 'Buffer du log physique petit', 'PHYSBUFF %s Ko' % cf.get('PHYSBUFF'), 'Valeur courante 512 Ko et plus (défaut des versions récentes).'))
    if logs_h:
        r.append(('moyenne' if logs_h > 20 else 'info', 'Bascules de logs logiques', '%.0f logs remplis par heure (LOGSIZE %s Ko, %s logs)' % (logs_h, cf.get('LOGSIZE'), cf.get('LOGFILES')),
                  'Au-delà d\'une vingtaine par heure, augmenter LOGSIZE (ex. 100 000 Ko) réduit le travail de bascule et les envois HDR associés.'))
    elif (ent('LOGSIZE') or 0) and ent('LOGSIZE') < 50000:
        r.append(('info', 'Logs logiques de petite taille', 'LOGSIZE %s Ko × %s logs' % (cf.get('LOGSIZE'), cf.get('LOGFILES')),
                  'Vérifier le nombre de bascules par heure (supervision > 30 min) ; des logs de 50 à 100 Mo sont courants.'))
    nonpdq = ent('DS_NONPDQ_QUERY_MEM')
    tris, dsk = mes.get('tris') or (0, 0)
    if nonpdq is not None and nonpdq < 1024:
        r.append(('moyenne' if tris and dsk > 0.05 * tris else 'info', 'Mémoire de tri par requête faible',
                  'DS_NONPDQ_QUERY_MEM %d Ko (PDQ désactivé : MAX_PDQPRIORITY %s)%s' % (nonpdq, cf.get('MAX_PDQPRIORITY', '-'),
                                                                                   ' ; mesuré : %s tris dont %s sur disque (%.0f %%)' % (fmt_n(tris), fmt_n(dsk), 100.0 * dsk / tris) if tris else ''),
                  'Les tris et jointures par hachage débordent vite dans les dbspaces temporaires : comparer « tris » et « tris disque » (sysmaster). 2 à 8 Mo sont fréquents en OLTP.'))
    if str(cf.get('OPTCOMPIND', '')) == '2':
        r.append(('moyenne' if mes.get('gros_scans') else 'info', 'Optimiseur orienté coût global',
                  'OPTCOMPIND 2%s' % (' ; mesuré : scans séquentiels coûteux sur de grandes tables' if mes.get('gros_scans') else ''),
                  'Autorise les jointures par hachage et balayages complets ; en OLTP, 0 favorise les index. À ne changer qu\'après analyse des plans des requêtes lentes.'))
    dio = str(cf.get('DIRECT_IO', '')).strip()
    nf, nsd = mes.get('chunks_fichiers', 0), mes.get('chunks_sans_odirect', 0)
    if nf and nsd and dio not in ('', '0'):
        r.append(('haute' if mes.get('pression_mem') else 'moyenne', 'DIRECT_IO configuré mais inactif sur les chunks',
                  'DIRECT_IO %s dans l\'ONCONFIG, mais %d chunk(s) en fichier sur %d ouverts sans O_DIRECT%s' % (
                      dio, nsd, nf, ' ; mesuré : pression mémoire du noyau' if mes.get('pression_mem') else ''),
                  'Les lectures Informix passent par le cache de pages du système (double mise en cache, recyclage et fragmentation de la mémoire). '
                  'Positionner DIRECT_IO 1 et redémarrer l\'instance (fenêtre de maintenance) ; contrôler ensuite le drapeau O_DIRECT (rapport suivant).'))
    elif nf and nsd and dio in ('', '0'):
        r.append(('moyenne' if mes.get('pression_mem') else 'info', 'I/O directe non utilisée', 'DIRECT_IO %s, %d chunk(s) en fichier' % (dio or 'absent', nf),
                  'DIRECT_IO 1 évite la double mise en cache des chunks (cache Informix + cache de pages du noyau). Redémarrage de l\'instance requis.'))
    elif dio and dio not in ('0', '1'):
        r.append(('info', 'Valeur DIRECT_IO inhabituelle', 'DIRECT_IO %s%s' % (dio, ' ; O_DIRECT actif sur les %d chunk(s) en fichier' % nf if nf else ''),
                  'Valeurs documentées : 0 ou 1. Vérifier dans le journal du moteur (et onstat -g cfg) la valeur réellement retenue.'))
    cl = ent('CLEANERS')
    if cl and nb_chunks and cl < nb_chunks:
        r.append(('moyenne', 'Moins de CLEANERS que de chunks', 'CLEANERS %d pour %d chunks' % (cl, nb_chunks), 'Un thread de nettoyage par chunk actif est la règle usuelle.'))
    if str(cf.get('RTO_SERVER_RESTART', '')) == '0':
        r.append(('info', 'Checkpoints à intervalle fixe', 'RTO_SERVER_RESTART 0, CKPTINTVL %s s' % cf.get('CKPTINTVL', '?'),
                  'Les checkpoints sont déclenchés toutes les CKPTINTVL secondes (ou par le log physique) : surveiller leur durée et les blocages.'))
    return r


def correlation(a, b):
    n = len(a)
    if n < 6:
        return None
    ma, mb = sum(a) / n, sum(b) / n
    va = sum((x - ma) ** 2 for x in a)
    vb = sum((y - mb) ** 2 for y in b)
    if va == 0 or vb == 0:
        return None
    return sum((x - ma) * (y - mb) for x, y in zip(a, b)) / math.sqrt(va * vb)


def par_minute(serie, cle):
    res = {}
    for e in serie:
        if e.get(cle) is not None:
            res[e['ts'].replace(second=0, microsecond=0)] = e[cle]
    return res


def correlations(serveurs):
    """Batch ipscrond (n'importe quel serveur) vs indicateurs de la base."""
    res = []
    batch = {}
    for s in serveurs:
        for k, v in par_minute(s['irium'], 'batch').items():
            batch[k] = batch.get(k, 0) + v
    if not batch or max(batch.values()) == 0:
        return res
    for s in serveurs:
        if not s['informix']:
            continue
        for libelle, serie, cle in [('attentes de verrous/min', s['profil'], 'lockwts_min'), ('lectures logiques/s', s['profil'], 'bufreads_s'),
                                    ('sessions en attente de verrou', s['sessions'], 'att_L'), ('CPU utilisé (%)', [dict(ts=e['ts'], v=e['user'] + e['sys']) for e in s['cpu']], 'v'),
                                    ('iowait (%)', s['cpu'], 'iowait')]:
            m = par_minute(serie, cle)
            commun = sorted(set(m) & set(batch))
            r = correlation([batch[t] for t in commun], [m[t] for t in commun])
            if r is not None and r > 0.5:
                res.append((s['nom'], libelle, r, len(commun)))
    return sorted(res, key=lambda x: -x[2])


def autour(serveurs, quand, minutes=5):
    """Ce qui se passait autour d'un signalement : valeur dans la fenêtre vs moyenne de la journée."""
    res = []
    a, z = quand - dt.timedelta(minutes=minutes), quand + dt.timedelta(minutes=minutes)
    for s in serveurs:
        series = [('CPU %', [dict(ts=e['ts'], v=e['user'] + e['sys']) for e in s['cpu']], 'v'), ('iowait %', s['cpu'], 'iowait'),
                  ('charge/CPU', [dict(ts=e['ts'], v=e['load1'] / s['ncpu']) for e in s['charge'] if e['load1'] is not None], 'v'),
                  ('ping base (ms)', s['latence'], 'ping_ms'), ('traitements ipscrond', s['irium'], 'batch')]
        for dev, serie in list(s['disques'].items())[:6]:
            series.append(('temps disque %s (ms)' % dev, serie, 'await'))
        for g, x in sorted((s.get('services') or {}).items()):
            series.append(('CPU service %s (%%)' % g, x['serie'], 'cpu'))
        if s['informix']:
            series += [('attentes verrous/min', s['profil'], 'lockwts_min'), ('sessions en attente verrou', s['sessions'], 'att_L'),
                       ('sessions en attente checkpoint', s['sessions'], 'att_C'), ('cache lecture %', s['profil'], 'cache_lect'),
                       ('threads prêts (file CPU)', s['ready'], 'ready'), ('lectures logiques/s', s['profil'], 'bufreads_s')]
        for lib, serie, cle in series:
            tout = [e[cle] for e in serie if e.get(cle) is not None]
            fen = [e[cle] for e in serie if e.get(cle) is not None and a <= e['ts'] <= z]
            if not tout or not fen:
                continue
            moy, pic = sum(tout) / len(tout), max(fen)
            ecart = (pic - moy) / moy if moy else (1 if pic > 0 else 0)
            if (lib.startswith('cache') and min(fen) < moy - 3) or (not lib.startswith('cache') and ecart > 0.8 and pic > 0.5):
                res.append((s['nom'], lib, min(fen) if lib.startswith('cache') else pic, moy))
    return sorted(res, key=lambda x: -(abs(x[2] - x[3]) / (x[3] or 1)))[:10]


# --------------------------------------------------------------------------------------------
# Graphiques SVG
# --------------------------------------------------------------------------------------------
def courbe(titre, series, t0, t1, marqueurs, unite='', ymax=None, points=False):
    series = [(n, c, [(e['ts'], e[k]) for e in s if e.get(k) is not None]) for n, c, s, k in series]
    series = [x for x in series if x[2]]
    if not series:
        return ''
    L, H, gx, gy = 640, 170, 46, 22
    vmax = ymax or max([v for _n, _c, pts in series for _t, v in pts] + [1e-9]) * 1.1
    duree = (t1 - t0).total_seconds() or 1
    X = lambda t: gx + (L - gx - 8) * (t - t0).total_seconds() / duree
    Y = lambda v: 8 + (H - 8) * (1 - min(v, vmax) / vmax)
    o = ['<figure class="graph"><figcaption>%s</figcaption><svg viewBox="0 0 %d %d" role="img" aria-label="%s">' % (esc(titre), L, H + gy, esc(titre))]
    for i in range(5):
        v = vmax * i / 4
        o.append('<line x1="%d" x2="%d" y1="%.1f" y2="%.1f" class="gr"/><text x="%d" y="%.1f" class="ax" text-anchor="end">%s</text>'
                 % (gx, L - 8, Y(v), Y(v), gx - 5, Y(v) + 4, fmt(v)))
    pas = max(1, int(duree / 3600 / 6) or 1)
    h = t0.replace(minute=0, second=0, microsecond=0) + dt.timedelta(hours=1)
    while h < t1:
        if h.hour % pas == 0:
            o.append('<line x1="%.1f" x2="%.1f" y1="8" y2="%d" class="gr"/><text x="%.1f" y="%d" class="ax" text-anchor="middle">%s</text>'
                     % (X(h), X(h), H, X(h), H + 15, h.strftime('%H:%M')))
        h += dt.timedelta(minutes=30 if duree < 3 * 3600 else 60)
    for t, _qui, txt in marqueurs:
        if t0 <= t <= t1:
            o.append('<line x1="%.1f" x2="%.1f" y1="4" y2="%d" class="mq"><title>%s : %s</title></line>' % (X(t), X(t), H, t.strftime('%H:%M'), esc(txt)))
    for n, c, pts in series:
        if points:
            o.extend('<circle cx="%.1f" cy="%.1f" r="4" fill="%s"><title>%s %s : %s%s</title></circle>' % (X(t), Y(v), c, t.strftime('%H:%M:%S'), esc(n), fmt(v), unite)
                     for t, v in pts)
        else:
            o.append('<polyline fill="none" stroke="%s" stroke-width="2" stroke-linejoin="round" points="%s"/>'
                     % (c, ' '.join('%.1f,%.1f' % (X(t), Y(v)) for t, v in pts)))
    # zones de survol : valeurs de toutes les séries à cet instant
    ref = series[0][2]
    if not points and len(ref) > 1:
        idx = [{t: v for t, v in pts} for _n, _c, pts in series]
        for i, (t, _v) in enumerate(ref):
            xa = X(ref[i - 1][0]) if i else gx
            xb = X(ref[i + 1][0]) if i + 1 < len(ref) else L - 8
            vals = ' · '.join('%s %s%s' % (series[j][0], fmt(idx[j][t]), unite) for j in range(len(series)) if t in idx[j])
            o.append('<rect x="%.1f" y="8" width="%.1f" height="%d" class="hv"><title>%s — %s</title></rect>' % ((xa + X(t)) / 2, max(1, (xb - xa) / 2), H - 8, t.strftime('%H:%M:%S'), esc(vals)))
    o.append('<line x1="%d" x2="%d" y1="%d" y2="%d" stroke="#999"/></svg>' % (gx, L - 8, H, H))
    if len(series) > 1 or True:
        o.append('<div class="leg">%s</div>' % ''.join('<span><i style="background:%s"></i>%s</span>' % (c, esc(n)) for n, c, _p in series))
    o.append('</figure>')
    return ''.join(o)


def fmt(v):
    if v is None:
        return '-'
    a = abs(v)
    return '%.0f' % v if a >= 100 else '%.1f' % v if a >= 10 else '%.2f' % v if a >= 0.1 or a == 0 else '%.3f' % v


def esc(v):
    v = '' if v is None else str(v)
    return v.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#x27;')


def tableau(entetes, lignes, vide='Aucune donnée.'):
    if not lignes:
        return '<p class="d">%s</p>' % vide
    return '<div class="tw"><table><tr>%s</tr>%s</table></div>' % (''.join('<th>%s</th>' % esc(h) for h in entetes),
                                                                  ''.join('<tr>%s</tr>' % ''.join('<td>%s</td>' % c for c in l) for l in lignes))


def badge(g):
    col, ico, _o = GRAV[g]
    return '<span class="b"><i style="background:%s"></i>%s %s</span>' % (col, ico, g.capitalize())


PARAMS = [
    ('BUFFERPOOL', 'Cache de données (nombre de buffers, LRU, seuils lru_min/max_dirty)'),
    ('VPCLASS', 'Processeurs virtuels (cpu,num=… : idéalement le nombre de cœurs dédiés au moteur)'),
    ('NUMCPUVPS', 'Ancien paramètre du nombre de VP CPU'), ('SINGLE_CPU_VP', '1 = un seul VP CPU (à éviter en production)'),
    ('MULTIPROCESSOR', '1 sur un serveur multiprocesseur'), ('CLEANERS', 'Threads de nettoyage des pages (≥ nombre de chunks actifs)'),
    ('SHMTOTAL', 'Mémoire partagée maximale (Ko, 0 = illimitée)'), ('SHMVIRTSIZE', 'Taille initiale du segment virtuel (Ko)'),
    ('SHMADD', 'Incrément des segments ajoutés (Ko)'), ('RESIDENT', '-1 = mémoire partagée verrouillée en RAM'),
    ('LOCKS', 'Taille initiale de la table des verrous'), ('DEF_TABLE_LOCKMODE', 'row recommandé en OLTP'),
    ('CKPTINTVL', 'Intervalle maximal entre checkpoints (s)'), ('RTO_SERVER_RESTART', 'Objectif de temps de redémarrage (checkpoints automatiques)'),
    ('AUTO_CKPTS', 'Checkpoints automatiques'), ('AUTO_LRU_TUNING', 'Réglage automatique des LRU'), ('AUTO_AIOVPS', 'VP AIO automatiques'),
    ('DIRECT_IO', '1 = E/S directes pour les chunks en fichiers'), ('PHYSBUFF', 'Buffer du log physique (Ko)'), ('LOGBUFF', 'Buffer du log logique (Ko)'),
    ('LOGFILES', 'Nombre de logs logiques'), ('LOGSIZE', 'Taille d\'un log logique (Ko)'), ('DYNAMIC_LOGS', 'Ajout dynamique de logs'),
    ('DBSPACETEMP', 'Dbspaces temporaires (tris, tables temporaires)'), ('DS_TOTAL_MEMORY', 'Mémoire des requêtes PDQ / tris (Ko)'),
    ('DS_MAX_QUERIES', 'Requêtes PDQ simultanées'), ('MAX_PDQPRIORITY', 'Priorité PDQ maximale'), ('OPTCOMPIND', 'Choix des jointures par l\'optimiseur'),
    ('NETTYPE', 'Écouteurs réseau (protocole, threads, connexions, classe VP)'), ('NS_CACHE', 'Cache des noms d\'hôtes/services'),
    ('STACKSIZE', 'Pile des threads (Ko)'), ('VP_MEMORY_CACHE_KB', 'Cache mémoire par VP CPU'), ('USELASTCOMMITTED', 'Lecture de la dernière version validée (moins d\'attentes de verrous)'),
    ('DRINTERVAL', 'HDR : intervalle de vidage (-1 = synchrone)'), ('HDR_TXN_SCOPE', 'HDR : portée de la synchronisation des validations'),
    ('DRTIMEOUT', 'HDR : délai avant de considérer la réplica perdue'), ('LOG_INDEX_BUILDS', 'Journalisation des créations d\'index (RSS)'),
    ('AUTO_STAT_MODE', 'Mise à jour automatique des statistiques'), ('AUTO_TUNE', 'Réglages automatiques (checkpoints, LRU, AIO)'),
    ('PHYSFILE', 'Taille du log physique (Ko)'), ('LTAPEDEV', 'Sauvegarde des logs logiques (/dev/null = aucune)'),
    ('DS_NONPDQ_QUERY_MEM', 'Mémoire de tri par requête hors PDQ (Ko)'), ('STMT_CACHE', 'Cache des instructions SQL'),
    ('BTSCANNER', 'Nettoyage des index (B-tree scanner)'), ('DD_HASHSIZE', 'Cache du dictionnaire de données'),
    ('TXTIMEOUT', 'Délai des transactions distribuées'), ('DEADLOCK_TIMEOUT', 'Délai de détection des interblocages distribués'), ('SQLTRACE', 'Traçage SQL (coût en mémoire)'), ('MSGPATH', 'Journal du moteur'),
]


# --------------------------------------------------------------------------------------------
# Rapport
# --------------------------------------------------------------------------------------------
CSS = """*{box-sizing:border-box}body{margin:0;font:14px/1.45 "Segoe UI",Arial,sans-serif;color:#16181d;background:#f4f5f7}
header{background:#111;color:#fff;padding:22px 32px;border-bottom:4px solid #2a78d6}header h1{margin:0 0 6px;font-size:22px}
header .m{display:flex;flex-wrap:wrap;gap:4px 22px;font-size:13px;opacity:.85}main{max-width:1380px;margin:0 auto;padding:18px 32px 40px}
nav.som{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:14px}nav.som a{background:#fff;border:1px solid #dfe1e5;border-radius:14px;padding:4px 12px;color:#16181d;text-decoration:none;font-size:13px}
section{background:#fff;border:1px solid #dfe1e5;border-radius:8px;padding:16px 20px;margin-bottom:16px}
h2{font-size:17px;margin:0 0 12px}h3{font-size:14.5px;margin:16px 0 8px}
.tw{overflow-x:auto;max-height:520px;overflow-y:auto}table{width:100%;border-collapse:collapse;font-size:13px}
th{background:#1d2733;color:#fff;text-align:left;padding:7px 8px;white-space:nowrap;position:sticky;top:0}td{padding:6px 8px;border-bottom:1px solid #e6e7ea;vertical-align:top}
tr:nth-child(even) td{background:#fafafa}.d{color:#6b6b66;font-size:12.5px}.mono,pre{font-family:Consolas,monospace;font-size:12px}
pre{background:#f6f7f9;border:1px solid #e3e4e8;border-radius:6px;padding:10px;overflow:auto;max-height:420px;white-space:pre}
.b{display:inline-flex;align-items:center;gap:5px;padding:1px 9px;border-radius:10px;font-size:12px;background:#f0f1f3;border:1px solid #dfe1e5;white-space:nowrap;font-weight:600}
.b i,.leg i{width:9px;height:9px;border-radius:50%;display:inline-block}
.g{display:grid;grid-template-columns:repeat(auto-fit,minmax(560px,1fr));gap:14px}.graph{margin:0;border:1px solid #eceef1;border-radius:8px;padding:10px 12px}
.graph figcaption{font-weight:600;font-size:13px;margin-bottom:4px}svg{width:100%;height:auto}.ax{fill:#7a7a76;font-size:11px}.gr{stroke:#eceef1}
.mq{stroke:#d03b3b;stroke-width:2;stroke-dasharray:4 3}.hv{fill:transparent}.hv:hover{fill:rgba(42,120,214,.08)}
.leg{display:flex;flex-wrap:wrap;gap:4px 14px;font-size:12px;color:#52514e;margin-top:4px}.leg span{display:inline-flex;align-items:center;gap:6px}
.k{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin-bottom:12px}.c{border:1px solid #dfe1e5;border-radius:8px;padding:10px 14px}
.c .v{font-size:22px;font-weight:700}.c .l{font-size:12px;color:#52514e}
.syn{border-left:4px solid #2a78d6;background:#f3f8ff;padding:12px 16px;border-radius:6px;margin-bottom:12px}
details{margin:8px 0}summary{cursor:pointer;font-weight:600}
@media print{body{background:#fff}header{-webkit-print-color-adjust:exact;print-color-adjust:exact}.tw{max-height:none}nav.som{display:none}}"""


def section_serveur(s, t0, t1, marq, idx=0):
    nm = s['nom']
    o = ['<section id="srv-%d"><h2>Serveur %s <span class="d">%s · %d CPU · du %s au %s</span></h2>' % (
        idx, esc(nm), esc(s['roles']), s['ncpu'], s['debut'].strftime('%d/%m %H:%M'), s['fin'].strftime('%H:%M'))]
    sys_txt = lire(os.path.join(s['dossier'], 'statique', 'systeme.txt'))
    rel = re.search(r'Red Hat[^\n]*', sys_txt)
    cpu_tot = stats([e['user'] + e['sys'] for e in s['cpu']])
    mem = s['mem'][-1] if s['mem'] else {}
    o.append('<div class="k">%s</div>' % ''.join('<div class="c"><div class="v">%s</div><div class="l">%s</div></div>' % (v, l) for v, l in [
        (esc(rel.group(0).replace('Red Hat Enterprise Linux', 'RHEL')) if rel else '?', 'Système'),
        ('%.0f %%' % (cpu_tot['moy'] or 0), 'CPU moyen (p95 %.0f %%)' % (cpu_tot['p95'] or 0)),
        ('%.0f %%' % (stats([e['iowait'] for e in s['cpu']])['p95'] or 0), 'iowait p95'),
        ('%.0f Go' % (mem.get('total_mo', 0) / 1024.0), 'RAM (dispo. min %.0f %%)' % (stats([e['dispo_pct'] for e in s['mem']])['min'] or 0)),
        ('%.2f' % (stats([e['load1'] / s['ncpu'] for e in s['charge'] if e['load1'] is not None])['p95'] or 0), 'charge/CPU p95')]))
    g = []
    g.append(courbe('CPU (%)', [('utilisateur', COULEURS[0], s['cpu'], 'user'), ('système', COULEURS[1], s['cpu'], 'sys'),
                               ('iowait', COULEURS[2], s['cpu'], 'iowait'), ('steal', COULEURS[3], s['cpu'], 'steal')], t0, t1, marq, ' %', ymax=100))
    g.append(courbe('Charge rapportée au nombre de CPU', [('charge 1 min / CPU', COULEURS[0], [dict(ts=e['ts'], v=e['load1'] / s['ncpu']) for e in s['charge'] if e['load1'] is not None], 'v')], t0, t1, marq))
    g.append(courbe('Mémoire disponible (%) et swap', [('mémoire disponible %', COULEURS[0], s['mem'], 'dispo_pct'),
                                                       ('swap in /s', COULEURS[1], s['mem'], 'swap_in_s'), ('swap out /s', COULEURS[3], s['mem'], 'swap_out_s')], t0, t1, marq))
    top = sorted(s['disques'].items(), key=lambda kv: -sum(e['util'] for e in kv[1]))[:5]
    if top:
        nomd = lambda d: d + (' ' + s['dm'][d] if d in s['dm'] else '')
        g.append(courbe('Occupation des disques (%)', [(nomd(d), COULEURS[i], v, 'util') for i, (d, v) in enumerate(top)], t0, t1, marq, ' %', ymax=100))
        g.append(courbe('Temps de réponse des disques (ms)', [(nomd(d), COULEURS[i], v, 'await') for i, (d, v) in enumerate(top)], t0, t1, marq, ' ms'))
        g.append(courbe('Débit disques (Mo/s)', [(nomd(d) + ' lect.', COULEURS[i], v, 'rmo_s') for i, (d, v) in enumerate(top[:2])] +
                        [(nomd(d) + ' écr.', COULEURS[i + 2], v, 'wmo_s') for i, (d, v) in enumerate(top[:2])], t0, t1, marq, ' Mo/s'))
    if s['latence']:
        g.append(courbe('Latence vers la base (ms)', [('ping moyen', COULEURS[0], s['latence'], 'ping_ms'), ('ping max', COULEURS[1], s['latence'], 'ping_max'),
                                                      ('connexion TCP', COULEURS[2], s['latence'], 'tcp_ms')], t0, t1, marq, ' ms'))
    if s['reseau']:
        g.append(courbe('Retransmissions TCP (%)', [('retransmissions', COULEURS[1], s['reseau'], 'retrans_pct')], t0, t1, marq, ' %'))
    if any(e['processus'] for e in s['irium']):
        g.append(courbe('Processus IRIUM', [('processus IRIUM', COULEURS[0], s['irium'], 'processus'), ('traitements ipscrond', COULEURS[1], s['irium'], 'batch')], t0, t1, marq))
    if s['informix']:
        g.append(courbe('Informix : taux de lecture/écriture en cache (%)', [('lecture', COULEURS[0], s['profil'], 'cache_lect'), ('écriture', COULEURS[1], s['profil'], 'cache_ecr')], t0, t1, marq, ' %', ymax=100))
        g.append(courbe('Informix : activité', [('lectures logiques /s', COULEURS[0], s['profil'], 'bufreads_s'), ('lectures disque /s', COULEURS[1], s['profil'], 'dskreads_s'),
                                               ('écritures disque /s', COULEURS[2], s['profil'], 'dskwrits_s')], t0, t1, marq))
        g.append(courbe('Informix : sessions en attente', [('verrou', COULEURS[1], s['sessions'], 'att_L'), ('buffer', COULEURS[0], s['sessions'], 'att_B'),
                                                          ('checkpoint', COULEURS[7], s['sessions'], 'att_C'), ('log', COULEURS[2], s['sessions'], 'att_G'),
                                                          ('mutex', COULEURS[5], s['sessions'], 'att_S')], t0, t1, marq))
        g.append(courbe('Informix : attentes de verrous et balayages séquentiels (par min)', [('attentes de verrou', COULEURS[1], s['profil'], 'lockwts_min'),
                                                                                            ('balayages séquentiels', COULEURS[0], s['profil'], 'seqscans_min')], t0, t1, marq))
        g.append(courbe('Informix : threads prêts (file d\'attente CPU du moteur)', [('threads prêts', COULEURS[0], s['ready'], 'ready')], t0, t1, marq))
        g.append(courbe('Informix : sessions et verrous', [('sessions', COULEURS[0], s['sessions'], 'actives'), ('verrous (/100)', COULEURS[1],
                                                                                                          [dict(ts=e['ts'], v=e['verrous'] / 100.0) for e in s['verrous'] if 'verrous' in e], 'v')], t0, t1, marq))
        if s['ckp']:
            g.append(courbe('Informix : durée des checkpoints (s)', [('durée totale', COULEURS[0], s['ckp'], 'total'), ('blocage', COULEURS[7], s['ckp'], 'bloque')], t0, t1, marq, ' s', points=True))
        if s['backlog']:
            g.append(courbe('Réplication : backlog', [('backlog', COULEURS[1], s['backlog'], 'backlog')], t0, t1, marq))
    o.append('<div class="g">%s</div>' % ''.join(x for x in g if x))

    if s['top']:
        o.append('<h3>Processus les plus consommateurs (CPU, cumul des relevés)</h3>' + tableau(
            ['Commande', 'Utilisateur', 'Présence (relevés)', 'CPU moyen %', 'CPU max %', 'Arguments'],
            [[esc(c['cmd']), esc(c['user']), str(c['n']), fmt(sum(c['cpu']) / len(c['cpu'])), fmt(max(c['cpu'])), '<span class="mono">%s</span>' % esc(c['args'])] for c in s['top']]))
    o.append(section_services(s, t0, t1, marq))
    if s['jobs']:
        o.append('<h3>Traitements ipscrond observés</h3>' + tableau(['Commande', 'Vu de', 'à', 'Relevés', 'CPU max %'],
                                                                [['<span class="mono">%s</span>' % esc(j['cmd']), j['debut'].strftime('%H:%M:%S'), j['fin'].strftime('%H:%M:%S'), str(j['vu']), fmt(j['cpu_max'])] for j in s['jobs'][:30]]))
    if s['disques']:
        rows = []
        for dev, serie in sorted(s['disques'].items(), key=lambda kv: -stats([e['util'] for e in kv[1]])['p95']):
            u, a = stats([e['util'] for e in serie]), stats([e['await'] for e in serie])
            rows.append(['<b>%s</b> %s' % (esc(dev), esc(s['dm'].get(dev, ''))), fmt(u['moy']), fmt(u['p95']), fmt(a['moy']), fmt(a['p95']), fmt(a['max']),
                         fmt(stats([e['r_s'] for e in serie])['moy']), fmt(stats([e['w_s'] for e in serie])['moy']),
                         fmt(stats([e['r_await'] for e in serie])['p95']), fmt(stats([e['w_await'] for e in serie])['p95'])])
        o.append('<h3>Disques</h3>' + tableau(['Périphérique', 'Occup. moy %', 'Occup. p95 %', 'Temps moy ms', 'Temps p95 ms', 'Temps max ms', 'Lect./s', 'Écr./s', 'Lect. p95 ms', 'Écr. p95 ms'], rows))
    if s['informix']:
        o.append(section_informix(s))
    st = os.path.join(s['dossier'], 'statique')
    o.append('<h3>Configuration et détails bruts</h3>')
    for titre, f in [('Système, virtualisation, NTP', 'systeme.txt'), ('Paramètres noyau (sysctl, THP, huge pages)', 'noyau.txt'), ('CPU / NUMA', 'cpu.txt'),
                     ('Disques, montages, LVM, multipath', 'disques.txt'), ('Réseau', 'reseau.txt'), ('Erreurs système', 'erreurs.txt'),
                     ('Limites (ulimit)', 'limites.txt'), ('Historique sar des jours précédents', 'sar_historique.txt')]:
        t = lire(os.path.join(st, f))
        if t.strip():
            o.append('<details><summary>%s</summary><pre>%s</pre></details>' % (esc(titre), esc(t[:60000])))
    o.append('</section>')
    return ''.join(o)


def section_informix(s):
    o = ['<h3>Informix</h3>']
    ent = s['entete'][-1]['mode'] if s['entete'] else '?'
    vp = s['vp'] or {}
    o.append('<div class="k">%s</div>' % ''.join('<div class="c"><div class="v">%s</div><div class="l">%s</div></div>' % (v, l) for v, l in [
        (esc(ent), 'Mode du moteur'), (fmt(stats([e['cache_lect'] for e in s['profil']])['moy']) + ' %', 'Lecture en cache (moy.)'),
        (fmt(stats([e['actives'] for e in s['sessions']])['max']), 'Sessions (max)'),
        (fmt(stats([e['lockwts_min'] for e in s['profil']])['moy']), 'Attentes de verrou /min'),
        (str(sum(e['deadlks'] for e in s['profil'])), 'Interblocages'),
        (('%.0f %%' % vp['cpu']['occupation']) if 'cpu' in vp else '?', 'Occupation VP CPU (%s VP)' % (vp.get('cpu', {}).get('vps', '?'))),
        ('%d / %d' % (s['logs']['non_sauves'], s['logs']['total']), 'Logs non sauvegardés'),
        (str(len(s['ckp'])), 'Checkpoints observés')]))
    cf = s['conf']
    lignes = []
    for k, desc in PARAMS:
        v = cf.get(k)
        if v is None:
            continue
        lignes.append(['<b>%s</b>' % k, '<span class="mono">%s</span>' % esc('<br>'.join(v) if isinstance(v, list) else v).replace('&lt;br&gt;', '<br>'), esc(desc)])
    o.append('<h3>Paramètres clés ONCONFIG</h3>' + tableau(['Paramètre', 'Valeur', 'Rôle / recommandation'], lignes, 'ONCONFIG non lu.'))
    if s['iof']:
        o.append('<h3>Chunks Informix : temps moyen par I/O (onstat -g iof)</h3>' + tableau(
            ['Fichier / périphérique', 'Lectures', 'Temps lecture ms', 'Écritures', 'Temps écriture ms'],
            [['<span class="mono">%s</span>' % esc(x['fichier']), str(x['lectures']), fmt(x['lect_ms']), str(x['ecritures']), fmt(x['ecr_ms'])]
             for x in sorted(s['iof'], key=lambda x: -((x['ecr_ms'] or 0) + (x['lect_ms'] or 0)))[:25]]))
    chp = lire(os.path.join(s['dossier'], 'statique', 'informix', 'chunks_peripheriques.txt'))
    if chp.strip():
        o.append('<details><summary>Chunks → périphériques</summary><pre>%s</pre></details>' % esc(chp))
    if s['vp']:
        o.append('<h3>Occupation des processeurs virtuels</h3>' + tableau(['Classe', 'VP', 'Occupation moyenne'],
                                                                       [[esc(k), str(v['vps']), '%.0f %%' % v['occupation']] for k, v in sorted(s['vp'].items())]))
    if s['repl']:
        e = s['repl'][-1]
        o.append('<h3>Réplication</h3><p>Type <b>%s</b>, état <b>%s</b>, serveur apparié <b>%s</b>%s</p>' % (
            esc(e[1]), esc(e[2]), esc(e[3]), (' · HDR_TXN_SCOPE <b>%s</b>' % esc(cf['HDR_TXN_SCOPE'])) if cf.get('HDR_TXN_SCOPE') else ''))
    if s['journal']:
        o.append('<h3>Journal du moteur (messages notables)</h3>' + tableau(['Heure', 'Gravité', 'Message'],
                                                                         [[h.strftime('%d/%m %H:%M:%S'), badge(g), '<span class="mono">%s</span>' % esc(m)] for h, g, m in s['journal'][:200]]))
    o.append(section_expert(s, s['debut'], s['fin'], []))
    o.append(section_objets(s))
    o.append(section_programmes(s, s['debut'], s['fin'], []))
    sqlb = blocs(os.path.join(s['dossier'], 'informix', 'sql_sysmaster.raw'))
    if sqlb:
        o.append('<details open><summary>Sessions et tables les plus sollicitées (sysmaster, %s)</summary><pre>%s</pre></details>' % (sqlb[-1][0].strftime('%H:%M'), esc(sqlb[-1][1][:40000])))
    stx = os.path.join(s['dossier'], 'statique', 'informix')
    for titre, f in [('onstat -', 'onstat__.txt'), ('Mémoire partagée (onstat -g seg)', 'onstat__g_seg.txt'), ('Sessions (onstat -u)', 'onstat__u.txt'),
                     ('Réplication (onstat -g repl / dri / rss / cluster)', 'onstat__g_dri.txt'), ('Espaces et chunks (onstat -d)', 'onstat__d.txt'),
                     ('Verrous (onstat -k)', 'onstat__k.txt'), ('Checkpoints (onstat -g ckp)', 'onstat__g_ckp.txt'), ('Logs logiques (onstat -l)', 'onstat__l.txt'),
                     ('Profil (onstat -p)', 'onstat__p.txt'), ('Threads en attente (onstat -g wai)', 'onstat__g_wai.txt'), ('Transactions (onstat -x)', 'onstat__x.txt'),
                     ('SQL en cours (onstat -g sql)', 'onstat__g_sql.txt'), ('Page cleaners (onstat -F)', 'onstat__F.txt'), ('Pool de buffers (onstat -g buf)', 'onstat__g_buf.txt')]:
        t = lire(os.path.join(stx, f))
        if f == 'onstat__g_dri.txt':
            t = '\n'.join(lire(os.path.join(stx, x)) for x in ('onstat__g_repl.txt', 'onstat__g_dri.txt', 'onstat__g_rss.txt', 'onstat__g_cluster.txt'))
        if t.strip():
            o.append('<details><summary>%s</summary><pre>%s</pre></details>' % (esc(titre), esc(t[:60000])))
    return ''.join(o)


def pct(v):
    return '-' if v is None else ('%.1f %%' % v).replace('.', ',')


def lignes_classements(s):
    """Tableaux des classements (aussi utilisés pour l'export CSV) : {clé: (titre, en-têtes, lignes, note)}."""
    ob, cl = s.get('obj'), classements(s.get('obj'), 20)
    if not cl:
        return {}
    fen = ob['duree_s']
    nm = lambda o: '%s%s' % (o['nom'], ' (index de %s)' % o['table'] if o['type'] == 'index' and o['table'] != o['nom'] else (' (index)' if o['type'] == 'index' else ''))
    dl = lambda o, k: o['d'].get(k)
    fq = lambda f: ('%s /s' % fmt_n(f)) if f is not None else '-'
    hit = lambda o: '%.0f %%' % o['c']['rhit'] if o['c']['rhit'] is not None else '-'
    sfen = ' sur %s min' % fmt_n(fen / 60.0) if fen else ''
    t = {}
    t['physiques'] = ('Classement 1 – Lectures physiques (pages lues sur disque)', ['N°', 'Objet', 'Pages lues (cumul)', 'Part', 'Scans séq.', 'Pages lues' + sfen, 'Hit ratio'],
                      [[str(i + 1), nm(o), fmt_n(v), pct(p), fmt_n(o['c']['seqsc']), fmt_n(dl(o, 'pagreads')), hit(o)] for i, (o, v, p, _f) in enumerate(cl['physiques']['liste'])],
                      'Source : sysmaster:sysptprof (pagreads) et onstat -g ppf. Total : %s pages.' % fmt_n(cl['physiques']['total']))
    t['logiques'] = ('Classement 2 – Lectures logiques (pages lues en mémoire, coût CPU)', ['N°', 'Objet', 'Lectures logiques', 'Part', 'Lectures ISAM', 'Logiques / ISAM', 'Scans séq.', 'Verrous', 'Profil'],
                     [[str(i + 1), nm(o), fmt_n(v), pct(p), fmt_n(o['c']['isrd']), ('%.1f' % (v / o['c']['isrd'])).replace('.', ',') if o['c']['isrd'] else '-',
                       fmt_n(o['c']['seqsc']), fmt_n(o['c']['lkrqs']), profil_acces(o)] for i, (o, v, p, _f) in enumerate(cl['logiques']['liste'])],
                     'Source : onstat -g ppf (bfrd). Total : %s.' % fmt_n(cl['logiques']['total']))
    t['scans'] = ('Classement 3 – Scans séquentiels', ['N°', 'Table', 'Scans séq.', 'Part', 'Fréquence', 'Pages par scan', 'Demandes de verrou', 'Extents'],
                  [[str(i + 1), nm(o), fmt_n(v), pct(p), fq(f), fmt_n(pages_par_scan(o)), fmt_n(o['c']['lkrqs']), fmt_n(o['extents'])] for i, (o, v, p, f) in enumerate(cl['scans']['liste'])],
                  'Pages par scan : taille réelle de la table (sysptnhdr) si connue, sinon lectures logiques / scans. Total : %s scans.' % fmt_n(cl['scans']['total']))
    t['inverses'] = ('Classement 4 – Parcours inverses d\'index', ['N°', 'Index', 'Parcours inverses', 'Part', 'Fréquence', 'Lectures ISAM', 'Part des accès inverses', 'Hit ratio'],
                     [[str(i + 1), nm(o), fmt_n(v), pct(p), fq(f), fmt_n(o['c']['isrd']), pct(100.0 * v / o['c']['isrd']) if o['c']['isrd'] else '-', hit(o)]
                      for i, (o, v, p, f) in enumerate(cl['inverses']['liste'])],
                     'Source : onstat -g ppf (rvscn). Un parcours inverse répond à ORDER BY … DESC, MAX ou FIRST 1 … DESC. Total : %s.' % fmt_n(cl['inverses']['total']))
    t['verrous'] = ('Demandes de verrou par objet', ['N°', 'Objet', 'Demandes', 'Part', 'Fréquence', 'Attentes', 'Lectures ISAM'],
                    [[str(i + 1), nm(o), fmt_n(v), pct(p), fq(f), fmt_n(o['c']['lkwts']), fmt_n(o['c']['isrd'])] for i, (o, v, p, f) in enumerate(cl['verrous']['liste'])],
                    'Source : onstat -g ppf (lkrqs, lkwts).')
    se = s.get('ses_prof')
    if se and se['liste']:
        L = sorted(se['liste'], key=lambda e: -((e['d_pagreads'] if se['duree_s'] else e['pagreads']) or 0))[:20]
        t['sessions'] = ('Sessions les plus consommatrices', ['Session', 'Utilisateur', 'Poste', 'PID client', 'Pages lues (cumul)', 'Pages lues sur la fenêtre',
                                                              'Lectures logiques', 'Scans séq.', 'Demandes de verrou', 'Tris (dont disque)'],
                         [[e['sid'], e['user'], e['hote'], e['pid'], fmt_n(e['pagreads']), fmt_n(e['d_pagreads']), fmt_n(e['bufreads']), fmt_n(e['seqscans']),
                           fmt_n(e['lockreqs']), '%s (%s)' % (fmt_n(e['tris']), fmt_n(e['tris_disque']))] for e in L],
                         'Source : sysmaster:syssesprof + syssessions.')
    return t


def profil_acces(o):
    c = o['c']
    if o['type'] == 'index' and c['isrd'] and c['bfrd'] / c['isrd'] <= 6:
        return 'Accès unitaires répétés'
    if c['seqsc'] and (pages_par_scan(o) or 0) > 1000:
        return 'Scans complets répétés' + (', verrouillage massif' if c['lkrqs'] > 1e8 else '')
    if c['lkrqs'] > 5e8:
        return 'Verrouillage massif'
    if o['type'] != 'index' and not c['seqsc']:
        return 'Lue par index'
    return '-'


def section_objets(s):
    t = lignes_classements(s)
    o = []
    if t:
        ob = s['obj']
        o.append('<h3>Objets les plus coûteux</h3><p class="d">Compteurs cumulés depuis le démarrage de l\'instance (%s), et deltas sur la fenêtre de l\'audit (%s). '
                 '%s</p>' % ('%s jours' % fmt_n(ob['uptime_s'] / 86400.0) if ob.get('uptime_s') else 'durée inconnue',
                             '%s min' % fmt_n(ob['duree_s'] / 60.0) if ob['duree_s'] else 'un seul relevé',
                             '' if ob['mapping'] else '<b>Noms des partitions non résolus</b> (requêtes sysmaster désactivées) : identifiants hexadécimaux affichés.'))
        for k in ('physiques', 'logiques', 'scans', 'inverses', 'verrous', 'sessions'):
            if k in t:
                titre, ent, lignes, note = t[k]
                o.append('<details%s><summary>%s</summary>%s<p class="d">%s</p></details>' % (
                    ' open' if k in ('physiques', 'inverses') else '', esc(titre), tableau(ent, [[esc(x) for x in l] for l in lignes]), esc(note)))
    inv = s.get('inv') or {}
    if inv.get('dbspaces'):
        o.append('<h3>Remplissage des dbspaces</h3>' + tableau(['Dbspace', 'Type', 'Chunks', 'Pages', 'Pages libres', 'Libre'],
                 [[esc(d['nom']), 'temporaire' if d['temp'] else ('blobspace' if d['blob'] else 'données'), str(d['chunks']), fmt_n(d['pages']), fmt_n(d['libres']),
                   ('<b style="color:#d03b3b">%s</b>' if d['libre_pct'] < 5 and not d['temp'] else '%s') % pct(d['libre_pct'])]
                  for d in sorted(inv['dbspaces'], key=lambda d: d['libre_pct'])]))
    if s.get('dio'):
        o.append('<details><summary>Ouverture des chunks (O_DIRECT)</summary>%s</details>' % tableau(['Chunk', 'Type', 'Drapeaux', 'O_DIRECT'],
                 [['<span class="mono">%s</span>' % esc(x['chunk']), esc(x['type']), esc(x['flags']), 'oui' if x['o_direct'] else '<b>non</b>'] for x in s['dio']]))
    return ''.join(o)


PRIO = {'critique': 'Immédiat', 'haute': 'P1', 'moyenne': 'P2', 'info': 'P3'}
NATURE = {'CPU': 'Système', 'Disques': 'Système', 'Mémoire': 'Système', 'Système': 'Système', 'Virtualisation': 'Système', 'Réseau': 'Système',
          'Informix': 'Base de données', 'Réplication': 'Base de données', 'Stockage Informix': 'Base de données',
          'Configuration': 'Configuration Informix (ONCONFIG)', 'Objets': 'Base de données et applicatif', 'Programmes IRIUM': 'Applicatif', 'Verrous': 'Base de données et applicatif', 'Requêtes SQL': 'Base de données et applicatif',
          'Services': 'Système et applicatif'}


def plan_recommandations(constats):
    """Constats → plan d'actions priorisé (sans les simples confirmations « cohérent »)."""
    plan = []
    for c in constats:
        nom, g, dom, t, preuve, reco = c
        if reco.startswith('Cohérent') or (g == 'info' and dom == 'Configuration' and t in ('VP CPU', 'Dimensionnement mémoire')):
            continue
        plan.append({'prio': PRIO[g], 'grav': g, 'serveur': nom, 'nature': NATURE.get(dom, dom), 'domaine': dom, 'constat': t, 'preuve': preuve, 'action': reco})
    ordre_n = {'Configuration Informix (ONCONFIG)': 2, 'Base de données': 1, 'Base de données et applicatif': 0, 'Système': 3}
    plan.sort(key=lambda x: (GRAV[x['grav']][2], ordre_n.get(x['nature'], 9)))
    for i, x in enumerate(plan):
        x['ref'] = 'R%02d' % (i + 1)
    return plan


def indicateurs_reference(serveurs):
    """Indicateurs globaux à comparer avant / après correction."""
    res = []
    for s in serveurs:
        ch = stats([e['load1'] for e in s['charge']])
        cpu = stats([e['user'] + e['sys'] for e in s['cpu']])
        l = [('Load average', '%s (max %s)' % (fmt_n(ch['moy']), fmt_n(ch['max']))), ('CPU utilisé', '%s %% (p95 %s %%)' % (fmt_n(cpu['moy']), fmt_n(cpu['p95'])))]
        if s['informix'] and s['profil']:
            br, dr = stats([e['bufreads_s'] for e in s['profil']]), stats([e['dskreads_s'] for e in s['profil']])
            l += [('Lectures logiques /s', '%s (max %s)' % (fmt_n(br['moy']), fmt_n(br['max']))),
                  ('Lectures disque Informix /s', '%s (max %s)' % (fmt_n(dr['moy']), fmt_n(dr['max']))),
                  ('Taux de lecture en cache', pct(stats([e['cache_lect'] for e in s['profil']])['moy'])),
                  ('Attentes de verrou /min', fmt_n(stats([e['lockwts_min'] for e in s['profil']])['moy'])),
                  ('Scans séquentiels /min', fmt_n(stats([e['seqscans_min'] for e in s['profil']])['moy']))]
        rec = stats([e.get('recup_mo_s') for e in s['mem']])
        if rec['moy'] is not None:
            l.append(('Recyclage du cache noyau', '%s Mo/s' % fmt_n(rec['moy'])))
        res.append((s['nom'], l))
    return res


def exporter_csv(dossier, plan, serveurs):
    """Inventaire au format CSV (séparateur « ; », UTF-8 avec BOM : ouverture directe dans Excel)."""
    if not os.path.isdir(dossier):
        os.makedirs(dossier)
    ecr = lambda nom, ent, lignes: _csv(os.path.join(dossier, nom), ent, lignes)
    ecr('00_plan_recommandations.csv', ['Priorité', 'Réf.', 'Serveur', 'Nature', 'Constat', 'Preuves', 'Action recommandée', 'Responsable', 'Échéance', 'Statut'],
        [[x['prio'], x['ref'], x['serveur'], x['nature'], x['constat'], x['preuve'], x['action'], '', '', 'À faire'] for x in plan])
    for s in serveurs:
        for k, (_titre, ent, lignes, _n) in sorted(lignes_classements(s).items()):
            ecr('%s_%s.csv' % (s['nom'], k), ent, lignes)
        inv = s.get('inv') or {}
        if inv.get('stats'):
            ecr('%s_statistiques.csv' % s['nom'], ['Base', 'Table', 'Lignes', 'Pages', 'Dernières statistiques'],
                [[b, t, fmt_n(v['nrows']), fmt_n(v['npused']), v['stats'].strftime('%d/%m/%Y') if v['stats'] else 'jamais']
                 for (b, t), v in sorted(inv['stats'].items(), key=lambda x: -(x[1]['npused'] or 0))])
        if inv.get('dbspaces'):
            ecr('%s_dbspaces.csv' % s['nom'], ['Dbspace', 'Temporaire', 'Pages', 'Pages libres', '% libre'],
                [[d['nom'], 'oui' if d['temp'] else 'non', '%.0f' % d['pages'], '%.0f' % d['libres'], ('%.2f' % d['libre_pct']).replace('.', ',')] for d in inv['dbspaces']])


def _csv(chemin, ent, lignes):
    nettoyer = lambda l: [re.sub(r'<[^>]+>', '', str(x)) for x in l]
    if PY2:   # le module csv de Python 2 n'écrit que des octets
        with open(chemin, 'wb') as f:
            f.write(b'\xef\xbb\xbf')
            w = csv.writer(f, delimiter=b';')
            for l in [ent] + list(lignes):
                w.writerow([x.encode('utf-8') for x in nettoyer(l)])
        return
    with io.open(chemin, 'w', encoding='utf-8-sig', newline='') as f:
        w = csv.writer(f, delimiter=';')
        for l in [ent] + list(lignes):
            w.writerow(nettoyer(l))


def section_recommandations(plan, serveurs, dossier_csv):
    o = ['<section id="reco"><h2>Recommandations</h2><p class="d">Plan d\'actions issu de l\'ensemble des constats : mesures système et Informix, '
         'classements des objets, et revue de la configuration (ONCONFIG) croisée avec les mesures. Priorités : <b>Immédiat</b> (risque d\'incident), '
         '<b>P1</b> (effet majeur sur la charge), <b>P2</b> (effet significatif), <b>P3</b> (amélioration ou point de vigilance).</p>']
    par = {}
    for x in plan:
        par.setdefault(x['prio'], []).append(x)
    o.append('<div class="k">%s</div>' % ''.join('<div class="c"><div class="v">%d</div><div class="l">%s</div></div>' % (len(par.get(p, [])), p)
                                                for p in ('Immédiat', 'P1', 'P2', 'P3')))
    o.append(tableau(['Prio.', 'Réf.', 'Serveur', 'Nature', 'Constat', 'Action recommandée'],
                     [['%s %s' % (badge(x['grav']), esc(x['prio'])), esc(x['ref']), esc(x['serveur']), esc(x['nature']),
                       '<b>%s</b><br><span class="d">%s</span>' % (esc(x['constat']), esc(x['preuve'])), esc(x['action'])] for x in plan], 'Aucune recommandation.'))
    o.append('<h3>Mesure de l\'efficacité</h3><p class="d">Relancer le même audit après chaque correction (même plage horaire) et comparer ces indicateurs '
             'ainsi que les compteurs par objet (classements).</p>')
    o.append(tableau(['Serveur', 'Indicateur', 'Valeur pendant l\'audit'], [[esc(n), esc(k), esc(v)] for n, l in indicateurs_reference(serveurs) for k, v in l]))
    o.append('<h3>Pour aller plus loin</h3><ul class="d"><li>Trace SQL ciblée sur une session : <span class="mono">EXECUTE FUNCTION sysadmin:task(\'set sql tracing on\', 2000, \'4k\', \'high\', \'user\');'
             ' EXECUTE FUNCTION sysadmin:task(\'set sql user tracing on\', &lt;sid&gt;);</span> puis <span class="mono">onstat -g his</span> ou sysmaster:syssqltrace.</li>'
             '<li>Plan d\'exécution d\'une requête : <span class="mono">SET EXPLAIN ON;</span> (fichier sqexplain.out du compte).</li>'
             '<li>Toute modification de l\'ONCONFIG ou du schéma est à valider avec l\'éditeur IRIUM et à tester en recette.</li></ul>')
    if dossier_csv:
        o.append('<p class="d">Plan d\'actions et classements complets exportés au format CSV (Excel) dans <span class="mono">%s</span>.</p>' % esc(dossier_csv))
    o.append('</section>')
    return ''.join(o)


ORDRE_ROLES = ('bdd-principale', 'bdd-replica', 'bdd', 'batch', 'applications')


def rang_role(s):
    return min([i for i, r in enumerate(ORDRE_ROLES) if r in s['roles']] or [9]), s['nom']


def lire_marqueurs(chemin):
    res = []
    for l in lire(chemin).splitlines():
        p = l.split('|', 3)
        if len(p) == 4 and p[0].isdigit():
            res.append((dt.datetime.fromtimestamp(int(p[0])), p[2], p[3]))
    return res


def charger_campagne(d):
    """Dossier de campagne sur le partage : un sous-dossier par serveur, campagne.conf, <serveur>.etat, marqueurs.txt."""
    conf = dict(re.findall(r'^(\w+)=(.*)$', lire(os.path.join(d, 'campagne.conf')), re.M))
    etats = {}
    for f in glob.glob(os.path.join(d, '*.etat')):
        e = dict(re.findall(r'^(\w+)=(.*)$', lire(f), re.M))
        maj = dt.datetime.fromtimestamp(int(e['maj'])) if e.get('maj', '').isdigit() else None
        etat = e.get('etat', '?')
        if etat == 'en_cours' and maj and (dt.datetime.now() - maj).total_seconds() > 900:
            etat = 'silencieux'
        etats[os.path.basename(f)[:-5]] = {'etat': etat, 'maj': maj, 'roles': e.get('roles', ''), 'echantillons': e.get('echantillons', '')}
    dossiers = sorted(x for x in glob.glob(os.path.join(d, '*')) if os.path.isfile(os.path.join(x, 'info.txt')))
    attendus = conf.get('serveurs', '').split()
    return {'nom': conf.get('nom', os.path.basename(os.path.normpath(d))), 'conf': conf, 'etats': etats, 'dossiers': dossiers,
            'attendus': attendus, 'marqueurs': lire_marqueurs(os.path.join(d, 'marqueurs.txt')), 'arret': os.path.exists(os.path.join(d, 'ARRET'))}


def section_campagne(c, serveurs):
    noms = [x for x in c['attendus']]
    noms += [x for x in c['etats'] if x not in noms] + [s['nom'] for s in serveurs if s['nom'] not in noms and s['nom'] not in c['etats']]
    lib = {'en_cours': 'en cours', 'termine': 'terminé', 'silencieux': '<b style="color:#d03b3b">silencieux (> 15 min)</b>'}
    lignes = []
    for n in noms:
        e = c['etats'].get(n)
        s = next((x for x in serveurs if x['nom'] == n), None)
        lignes.append([esc(n), esc((s or {}).get('roles') or (e or {}).get('roles', '-')), lib.get((e or {}).get('etat'), 'pas encore de données') if e else 'pas encore de données',
                       s['debut'].strftime('%H:%M') if s else '-', s['fin'].strftime('%H:%M') if s else '-', esc((e or {}).get('echantillons', '-'))])
    cf = c['conf']
    return ('<section id="campagne"><h2>Campagne %s</h2><p class="d">Créée le %s par %s · début %s · durée %s · relevé toutes les %s s%s. '
            'Ce rapport est régénéré pendant la campagne (toutes les 30 min) et à la fin ; il se recharge seul dans le navigateur tant que la campagne est en cours.</p>%s</section>' % (
                esc(c['nom']), esc(cf.get('creee_le', '?')), esc(cf.get('par', '?')), esc(cf.get('debut') or 'immédiat'), esc(cf.get('duree', '?')),
                esc(cf.get('intervalle', '?')), ' · <b>arrêt demandé</b>' if c['arret'] else '',
                tableau(['Serveur', 'Rôle(s)', 'État', 'Premier relevé', 'Dernier relevé', 'Échantillons'], lignes)))


def generer(serveurs, sortie, campagne=None):
    serveurs = sorted(serveurs, key=rang_role)
    t0 = min(s['debut'] for s in serveurs)
    t1 = max(s['fin'] for s in serveurs)
    marq = sorted([m for s in serveurs for m in s['marqueurs']] + (campagne['marqueurs'] if campagne else []))
    constats = [(s['nom'],) + c for s in serveurs for c in diagnostic(s)]
    constats.sort(key=lambda x: GRAV[x[1]][2])
    cor = correlations(serveurs)
    o = ['<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
         '%s<title>Audit de performance IRIUM</title><style>%s</style></head><body>' % (
             '<meta http-equiv="refresh" content="300">' if campagne and any(e['etat'] == 'en_cours' for e in campagne['etats'].values()) else '', CSS)]
    o.append('<header><h1>Audit de performance ERP IRIUM · Informix · RHEL</h1><div class="m"><span><b>Client :</b> Scania France</span>%s'
             '<span><b>Serveurs :</b> %s</span><span><b>Période :</b> %s, %s → %s</span><span><b>Généré le :</b> %s</span></div></header><main>'
             % ('<span><b>Campagne :</b> %s</span>' % esc(campagne['nom']) if campagne else '',
                esc(', '.join('%s (%s)' % (s['nom'], s['roles']) for s in serveurs)), t0.strftime('%d/%m/%Y'), t0.strftime('%H:%M'), t1.strftime('%H:%M'),
                dt.datetime.now().strftime('%d/%m/%Y %H:%M')))
    o.append('<nav class="som">%s<a href="#diag">Diagnostic</a>%s%s%s<a href="#reco">Recommandations</a></nav>' % (
        '<a href="#campagne">Campagne</a>' if campagne else '', '<a href="#signal">Signalements</a>' if marq else '', '<a href="#corr">Corrélations</a>' if cor else '',
        ''.join('<a href="#srv-%d">%s</a>' % (i, esc('%s (%s)' % (s['nom'], s['roles'].split(',')[0]))) for i, s in enumerate(serveurs))))
    # synthèse
    if campagne:
        o.append(section_campagne(campagne, serveurs))
    principaux = [c for c in constats if c[1] in ('critique', 'haute')]
    synth = ('<b>Causes les plus probables :</b> ' + '; '.join('%s (%s)' % (c[3], c[0]) for c in principaux[:4]) + '.') if principaux else \
        'Aucun goulot majeur détecté sur la période observée : comparer avec une période de lenteur signalée (commande « marquer »).'
    o.append('<section id="diag"><h2>Diagnostic</h2><div class="syn">%s</div>%s</section>' % (synth, tableau(
        ['Gravité', 'Serveur', 'Domaine', 'Constat', 'Preuves', 'Recommandation'],
        [[badge(c[1]), esc(c[0]), esc(c[2]), '<b>%s</b>' % esc(c[3]), esc(c[4]), esc(c[5])] for c in constats], 'Aucun constat.')))
    if marq:
        rows = []
        for t, qui, txt in marq:
            obs = autour(serveurs, t)
            progs = programmes_autour(serveurs, t)
            rows.append([t.strftime('%d/%m %H:%M:%S'), esc(txt), esc(qui),
                         '<br>'.join('%s · %s : <b>%s</b> (moyenne %s)' % (esc(n), esc(l), fmt(v), fmt(m)) for n, l, v, m in obs) or '<span class="d">aucune anomalie nette à ± 5 min</span>',
                         ', '.join('%s (%d)' % (esc(n), k) for n, k in progs) or '-'])
        o.append('<section id="signal"><h2>Signalements de lenteur</h2><p class="d">Pour chaque signalement, les indicateurs qui s\'écartent nettement '
                 'de leur moyenne dans les 5 minutes avant et après. Les signalements sont aussi tracés en pointillés rouges sur les graphiques.</p>%s</section>'
                 % tableau(['Heure', 'Signalement', 'Par', 'Ce qui se passait', 'Programmes IRIUM lancés ou en cours'], rows))
    if cor:
        o.append('<section id="corr"><h2>Corrélations entre serveurs</h2><p class="d">Coefficient de corrélation (minute par minute) entre le nombre de '
                 'traitements ipscrond en cours et les indicateurs de la base. Au-delà de 0,7, la coïncidence est forte.</p>%s</section>' % tableau(
                     ['Base', 'Indicateur', 'Corrélation avec les traitements ipscrond', 'Minutes comparées'],
                     [[esc(n), esc(l), '<b>%.2f</b>' % r, str(k)] for n, l, r, k in cor]))
    for i, s in enumerate(serveurs):
        o.append(section_serveur(s, t0, t1, marq, i))
    plan = plan_recommandations(constats)
    dossier_csv = os.path.splitext(sortie)[0] + '_inventaire'
    try:
        exporter_csv(dossier_csv, plan, serveurs)
    except (IOError, OSError) as e:
        print('Export CSV impossible : %s' % e, file=sys.stderr)
        dossier_csv = None
    o.append(section_recommandations(plan, serveurs, dossier_csv and os.path.basename(dossier_csv)))
    o.append('<p class="d">Seuils utilisés : CPU p95 > 85 %, iowait p95 > 15 %, disque occupé > 80 % avec temps de réponse > 10 ms, '
             'cache de lecture < 95 %, sessions en attente de verrou ≥ 3, checkpoint > 10 s ou bloquant. rapport_audit.py</p></main></body></html>')
    with io.open(sortie, 'w', encoding='utf-8') as f:
        f.write(''.join(o))
    return constats


def ouvrir_source(chemin, tmp):
    if chemin.endswith('.tar.gz') or chemin.endswith('.tgz'):
        with tarfile.open(chemin) as t:
            membres = [m for m in t.getmembers() if not (m.name.startswith('/') or '..' in m.name) and (m.isfile() or m.isdir())]
            for m in membres:
                if m.isfile() and m.size > TAILLE_MAX_FICHIER:
                    print('Ignoré (fichier de %d Mo) : %s' % (m.size // 1048576, m.name), file=sys.stderr)
            membres = [m for m in membres if not (m.isfile() and m.size > TAILLE_MAX_FICHIER)]
            t.extractall(tmp, members=membres)
        racines = {m.name.split('/')[0] for m in membres}
        return os.path.join(tmp, sorted(racines)[0])
    return chemin


def sortie_utf8():
    """Affichage UTF-8 même sous LC_ALL=C (cas d'audit-irium.sh), en Python 2 comme en Python 3.6."""
    enc = (getattr(sys.stdout, 'encoding', None) or '').lower().replace('-', '')
    if enc == 'utf8':
        return
    if PY2:
        import codecs
        sys.stdout = codecs.getwriter('utf-8')(sys.stdout)
        sys.stderr = codecs.getwriter('utf-8')(sys.stderr)
    else:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace', line_buffering=True)
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace', line_buffering=True)


def main():
    sortie_utf8()
    p = argparse.ArgumentParser(description='Rapport d\'audit de performance IRIUM / Informix')
    p.add_argument('sources', nargs='+', help='Dossier de campagne (partage), dossiers ou archives .tar.gz produits par audit-irium.sh')
    p.add_argument('-o', '--sortie', help='fichier HTML (défaut : dossier de rapport_audit.py)',
                   default=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'rapport_audit_irium_%s.html' % dt.datetime.now().strftime('%Y%m%d_%H%M')))
    a = p.parse_args()
    if os.path.isdir(a.sortie):   # -o <dossier> : nom de fichier par défaut dans ce dossier
        a.sortie = os.path.join(a.sortie, 'rapport_audit_irium_%s.html' % dt.datetime.now().strftime('%Y%m%d_%H%M'))
    # archives décompressées à côté du rapport (souvent sur le partage) plutôt que dans /tmp, souvent petit
    base_tmp = os.path.dirname(os.path.abspath(a.sortie))
    try:
        tmp = tempfile.mkdtemp(prefix='.audit_irium_tmp_', dir=base_tmp)
    except (IOError, OSError):
        tmp = tempfile.mkdtemp(prefix='audit_irium_')
    try:
        serveurs, campagne = [], None
        for src in a.sources:
            d = ouvrir_source(src, tmp)
            if os.path.exists(os.path.join(d, 'info.txt')):
                dossiers = [d]
            elif os.path.isdir(d):
                campagne = charger_campagne(d)
                dossiers = campagne['dossiers']
                print('Campagne %s : %d serveur(s)' % (campagne['nom'], len(dossiers)))
            else:
                dossiers = []
            if not dossiers:
                print('Ignoré (ni audit ni campagne) : %s' % src, file=sys.stderr)
            for x in dossiers:
                try:
                    serveurs.append(charger(x))
                except Exception as e:   # un serveur en cours d'écriture ne doit pas empêcher le rapport central
                    print('Serveur ignoré (%s) : %s' % (x, e), file=sys.stderr)
                    continue
                print('Chargé : %s (%s)' % (serveurs[-1]['nom'], serveurs[-1]['roles']))
        if not serveurs:
            sys.exit('Aucun audit valide.')
        constats = generer(serveurs, a.sortie, campagne)
        print('\nRapport : %s' % os.path.abspath(a.sortie))
        print('Plan d\'actions et classements (CSV) : %s_inventaire/' % os.path.abspath(os.path.splitext(a.sortie)[0]))
        for c in constats[:8]:
            print('  [%s] %s - %s' % (c[1].upper(), c[0], c[3]))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == '__main__':
    main()
