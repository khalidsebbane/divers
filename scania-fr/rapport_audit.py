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
  - paramètres clés ONCONFIG commentés, configuration système, détails bruts.
Python 3.6+, aucune dépendance (fonctionne avec /usr/libexec/platform-python).
"""
from __future__ import print_function

import argparse
import datetime as dt
import html
import io
import math
import os
import re
import shutil
import sys
import tarfile
import tempfile

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
                        'bufwaits_ratio': 100.0 * dl('bufwaits') / (dl('pagreads') + br) if (dl('pagreads') + br) > 0 else None})
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
    return {'mode': m.group(1) if m else '', 'bloque': b.group(1) if b else ''}


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
        s['repl'], s['backlog'] = replication(d)
        s['conf'] = onconfig(d)
        s['journal'], ckp_log = journal_moteur(d, s['debut'], s['fin'])
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
            if e[2].lower() != 'on':
                add('haute', 'Réplication', 'Réplication HDR non active', 'type %s, état %s, serveur apparié %s' % (e[1], e[2], e[3]),
                    'Vérifier la liaison avec la réplica (onstat -g dri, journal du moteur).')
        bl = stats([x['backlog'] for x in s['backlog']])
        if (bl['max'] or 0) > 0:
            add('moyenne', 'Réplication', 'Retard de réplication (backlog)', 'backlog max %d' % bl['max'],
                'La réplica ne suit pas : réseau ou disques de la réplica lents.')
        scope = s['conf'].get('HDR_TXN_SCOPE', '')
        if scope.upper() in ('FULL_SYNC', 'NEAR_SYNC') and 'principale' in s['roles']:
            add('info', 'Réplication', 'Réplication HDR synchrone (HDR_TXN_SCOPE=%s)' % scope,
                'chaque validation attend l\'accusé de la réplica',
                'Toute lenteur réseau ou disque de la réplica se répercute sur les validations de la base principale : comparer avec le rapport de la réplica.')
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
        if cf.get('DIRECT_IO', '') in ('0', '') and any('(fichier)' in l for l in lire(os.path.join(s['dossier'], 'statique', 'informix', 'chunks_peripheriques.txt')).splitlines()):
            add('info', 'Informix', 'Chunks en fichiers sans DIRECT_IO', 'DIRECT_IO %s' % (cf.get('DIRECT_IO') or 'absent'),
                'Avec des chunks sur système de fichiers, DIRECT_IO 1 évite la double mise en cache (Informix + Linux).')
        if not cf.get('DBSPACETEMP'):
            add('info', 'Informix', 'Pas de DBSPACETEMP', 'DBSPACETEMP absent', 'Les tris et tables temporaires vont dans le rootdbs : définir des dbspaces temporaires dédiés.')
    c.sort(key=lambda x: GRAV[x[0]][2])
    return c


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
    return html.escape('' if v is None else str(v))


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
    ('AUTO_STAT_MODE', 'Mise à jour automatique des statistiques'), ('SQLTRACE', 'Traçage SQL (coût en mémoire)'), ('MSGPATH', 'Journal du moteur'),
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


def generer(serveurs, sortie):
    t0 = min(s['debut'] for s in serveurs)
    t1 = max(s['fin'] for s in serveurs)
    marq = sorted([m for s in serveurs for m in s['marqueurs']])
    constats = [(s['nom'],) + c for s in serveurs for c in diagnostic(s)]
    constats.sort(key=lambda x: GRAV[x[1]][2])
    cor = correlations(serveurs)
    o = ['<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
         '<title>Audit de performance IRIUM</title><style>%s</style></head><body>' % CSS]
    o.append('<header><h1>Audit de performance ERP IRIUM · Informix · RHEL</h1><div class="m"><span><b>Client :</b> Scania France</span>'
             '<span><b>Serveurs :</b> %s</span><span><b>Période :</b> %s, %s → %s</span><span><b>Généré le :</b> %s</span></div></header><main>'
             % (esc(', '.join('%s (%s)' % (s['nom'], s['roles']) for s in serveurs)), t0.strftime('%d/%m/%Y'), t0.strftime('%H:%M'), t1.strftime('%H:%M'),
                dt.datetime.now().strftime('%d/%m/%Y %H:%M')))
    o.append('<nav class="som"><a href="#diag">Diagnostic</a>%s%s%s</nav>' % (
        '<a href="#signal">Signalements</a>' if marq else '', '<a href="#corr">Corrélations</a>' if cor else '',
        ''.join('<a href="#srv-%d">%s</a>' % (i, esc('%s (%s)' % (s['nom'], s['roles'].split(',')[0]))) for i, s in enumerate(serveurs))))
    # synthèse
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
            rows.append([t.strftime('%H:%M:%S'), esc(txt), esc(qui),
                         '<br>'.join('%s · %s : <b>%s</b> (moyenne %s)' % (esc(n), esc(l), fmt(v), fmt(m)) for n, l, v, m in obs) or '<span class="d">aucune anomalie nette à ± 5 min</span>'])
        o.append('<section id="signal"><h2>Signalements de lenteur</h2><p class="d">Pour chaque signalement, les indicateurs qui s\'écartent nettement '
                 'de leur moyenne dans les 5 minutes avant et après. Les signalements sont aussi tracés en pointillés rouges sur les graphiques.</p>%s</section>'
                 % tableau(['Heure', 'Signalement', 'Par', 'Ce qui se passait'], rows))
    if cor:
        o.append('<section id="corr"><h2>Corrélations entre serveurs</h2><p class="d">Coefficient de corrélation (minute par minute) entre le nombre de '
                 'traitements ipscrond en cours et les indicateurs de la base. Au-delà de 0,7, la coïncidence est forte.</p>%s</section>' % tableau(
                     ['Base', 'Indicateur', 'Corrélation avec les traitements ipscrond', 'Minutes comparées'],
                     [[esc(n), esc(l), '<b>%.2f</b>' % r, str(k)] for n, l, r, k in cor]))
    for i, s in enumerate(serveurs):
        o.append(section_serveur(s, t0, t1, marq, i))
    o.append('<p class="d">Seuils utilisés : CPU p95 > 85 %, iowait p95 > 15 %, disque occupé > 80 % avec temps de réponse > 10 ms, '
             'cache de lecture < 95 %, sessions en attente de verrou ≥ 3, checkpoint > 10 s ou bloquant. rapport_audit.py</p></main></body></html>')
    with io.open(sortie, 'w', encoding='utf-8') as f:
        f.write(''.join(o))
    return constats


def ouvrir_source(chemin, tmp):
    if chemin.endswith('.tar.gz') or chemin.endswith('.tgz'):
        with tarfile.open(chemin) as t:
            membres = [m for m in t.getmembers() if not (m.name.startswith('/') or '..' in m.name) and (m.isfile() or m.isdir())]
            t.extractall(tmp, members=membres)
        racines = {m.name.split('/')[0] for m in membres}
        return os.path.join(tmp, sorted(racines)[0])
    return chemin


def main():
    p = argparse.ArgumentParser(description='Rapport d\'audit de performance IRIUM / Informix')
    p.add_argument('sources', nargs='+', help='Dossiers ou archives .tar.gz produits par audit-irium.sh')
    p.add_argument('-o', '--sortie', default='rapport_audit_irium_%s.html' % dt.datetime.now().strftime('%Y%m%d_%H%M'))
    a = p.parse_args()
    tmp = tempfile.mkdtemp(prefix='audit_irium_')
    try:
        serveurs = []
        for src in a.sources:
            d = ouvrir_source(src, tmp)
            if not os.path.exists(os.path.join(d, 'info.txt')):
                print('Ignoré (pas un dossier d\'audit) : %s' % src, file=sys.stderr)
                continue
            serveurs.append(charger(d))
            print('Chargé : %s (%s)' % (serveurs[-1]['nom'], serveurs[-1]['roles']))
        if not serveurs:
            sys.exit('Aucun audit valide.')
        constats = generer(serveurs, a.sortie)
        print('\nRapport : %s' % os.path.abspath(a.sortie))
        for c in constats[:8]:
            print('  [%s] %s - %s' % (c[1].upper(), c[0], c[3]))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == '__main__':
    main()
