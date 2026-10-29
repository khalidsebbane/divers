#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Tableau de bord KPI de l'infrastructure IRIUM (Scania France), pour la direction.

  python dashboard_kpi.py <dossier de campagne | dossiers d'audit | archives .tar.gz> [-o dashboard.html]
  python dashboard_kpi.py <campagne actuelle> --avant <campagne de référence>     (comparaison avant / après)

À partir des mesures d'audit-irium.sh, il produit une page HTML autonome qui contient :
  - l'indice de santé de l'infrastructure et le nombre d'actions par priorité ;
  - les KPI de capacité (CPU, mémoire, stockage, Informix, réseau), avec leur statut, les seuils et l'évolution ;
  - l'obsolescence : version de RHEL et fin de support, correctifs, abonnement, briques logicielles ;
  - l'argumentaire du passage à RHEL 9 : chaque constat mesuré est relié à l'apport de RHEL 9 ;
  - un renvoi à l'architecture cible et aux prérequis transmis séparément ;
  - la feuille de route de la migration, avec les actions immédiates issues du diagnostic.
Python 2.7 ou 3.6+, aucune dépendance. Réutilise l'analyse de rapport_audit.py, placé dans le même dossier.
"""
from __future__ import division, print_function, unicode_literals

import argparse
import datetime as dt
import io
import json
import math
import os
import re
import shutil
import sys
import tempfile

sys.dont_write_bytecode = True   # pas de __pycache__ sur le partage
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rapport_audit as ra  # noqa: E402

PY2 = sys.version_info[0] < 3
if PY2:
    str = unicode  # noqa: F821

stats, esc, fmt_n, lire = ra.stats, ra.esc, ra.fmt_n, ra.lire

# Cycle de vie Red Hat Enterprise Linux (dates publiques Red Hat, à vérifier sur access.redhat.com/support/policy/updates/errata)
CYCLE_RHEL = {
    6: {'fin_maintenance': dt.date(2020, 11, 30), 'fin_els': dt.date(2024, 6, 30)},
    7: {'fin_maintenance': dt.date(2024, 6, 30), 'fin_els': dt.date(2028, 6, 30)},
    8: {'fin_complet': dt.date(2024, 5, 31), 'fin_maintenance': dt.date(2029, 5, 31), 'fin_els': dt.date(2032, 5, 31)},
    9: {'fin_complet': dt.date(2027, 5, 31), 'fin_maintenance': dt.date(2032, 5, 31), 'fin_els': dt.date(2035, 5, 31)},
}
STATUTS = {'bon': ('Bon', '●', 'var(--good)'), 'vigilance': ('Vigilance', '▲', 'var(--warning)'),
           'degrade': ('Dégradé', '◆', 'var(--serious)'), 'critique': ('Critique', '⬣', 'var(--critical)'), 'na': ('Non mesuré', '○', 'var(--muted)')}
PENALITE = {'bon': 0, 'vigilance': 3, 'degrade': 7, 'critique': 12, 'na': 0}


def niveau(v, seuils, inverse=False):
    """seuils = (vigilance, dégradé, critique) ; inverse : plus la valeur est basse, plus c'est grave."""
    if v is None:
        return 'na'
    a, b, c = seuils
    if inverse:
        return 'bon' if v > a else 'vigilance' if v > b else 'degrade' if v > c else 'critique'
    return 'bon' if v < a else 'vigilance' if v < b else 'degrade' if v < c else 'critique'


def nombre(v, dec=1):
    if v is None:
        return '–'
    if abs(v) >= 10000:
        return fmt_n(v)
    s = ('%.' + str(dec if abs(v) >= 1 or v == 0 else 2) + 'f') % v if abs(v) < 100 else '%.0f' % v
    if '.' in s:
        s = s.rstrip('0').rstrip('.')
    return s.replace('.', ',')


# --------------------------------------------------------------------------------------------
# Extraction des faits
# --------------------------------------------------------------------------------------------
def cycle_de_vie(s):
    d = os.path.join(s['dossier'], 'statique')
    t = lire(os.path.join(d, 'cycle_de_vie.txt')) + '\n' + lire(os.path.join(d, 'systeme.txt'))
    r = {'os': None, 'majeure': None, 'mineure': None, 'noyau': None, 'derniere_maj': None, 'abonnement': None, 'depots': None,
         'python': [], 'openssl': None, 'uptime_j': None}
    m = re.search(r'(Red Hat Enterprise Linux[^\n]*?release\s+(\d+)\.?(\d+)?[^\n]*)', t)
    if m:
        r['os'], r['majeure'], r['mineure'] = m.group(1).strip(), int(m.group(2)), int(m.group(3) or 0)
    m = re.search(r'^noyau=(\S+)', t, re.M) or re.search(r'Linux \S+ (\d+\.\d+\.\d+\S*)', t)
    r['noyau'] = m.group(1) if m else None
    m = re.search(r'^uptime_jours=(\d+)', t, re.M)
    r['uptime_j'] = int(m.group(1)) if m else None
    bloc = t.split('== Derniers paquets installés')[1].split('==')[0] if '== Derniers paquets installés' in t else ''
    for l in bloc.splitlines():
        m = re.search(r'\s(\w{3})\s+(\d{1,2})\s+(\w{3})\s+(\d{4})', l) or re.search(r'(\d{1,2})\s+(\w{3})\s+(\d{4})', l)
        if m:
            g = m.groups()
            try:
                jour, mois, an = (g[1], g[2], g[3]) if len(g) == 4 else g
                r['derniere_maj'] = dt.datetime.strptime('%s %s %s' % (jour, mois, an), '%d %b %Y').date()
            except ValueError:
                pass
            break
    if '== Abonnement' in t:
        ab = t.split('== Abonnement')[1].split('==')[0]
        r['abonnement'] = None if not ab.strip() or re.search(r'(?i)failed to run command|command not found|No such file', ab) else ('actif' if re.search(r'(?i)status:\s*current', ab) else 'expiré / inconnu')
    if '== Dépôts actifs' in t:
        dp = t.split('== Dépôts actifs')[1].split('==')[0]
        r['depots'] = None if not dp.strip() or re.search(r'(?i)failed to run command|command not found|No such file', dp) else ('aucun' if re.search(r'(?i)repolist: 0|no enabled|there are no enabled', dp) else 'présents')
    vus = []
    for x in re.findall(r'^(?:python\w*|platform-python)=(.+)$', t, re.M) + ['SCL ' + os.path.basename(x) for x in re.findall(r'^scl=(.+)$', t, re.M)]:
        if x.strip() not in vus:
            vus.append(x.strip())
    r['python'] = vus
    m = re.search(r'^openssl=(.+)$', t, re.M)
    r['openssl'] = m.group(1).strip() if m and m.group(1).strip() else None
    return r


def version_informix(s):
    textes = [lire(os.path.join(s['dossier'], 'statique', 'informix', f)) for f in ('onstat_.txt', 'onstat__.txt')]
    textes += [t for _ts, t in ra.blocs(os.path.join(s['dossier'], 'informix', 'onstat_entete.raw'))[:1]]
    for t in textes:
        m = re.search(r'Informix Dynamic Server Version\s+(\S+)', t)
        if m:
            return m.group(1)
    return None


def memoire_informix_mo(cf):
    bp = 0.0
    for b in cf.get('BUFFERPOOL', []):
        n, t = ra.kv_option(b, 'buffers'), ra.kv_option(b, 'size')
        if n:
            bp += int(n) * int(re.sub(r'\D', '', t or '2') or 2) / 1024.0
    v = str(cf.get('SHMVIRTSIZE', '')).strip()
    return bp, (int(v) / 1024.0 if v.isdigit() else 0.0)


def serie(points):
    return [(e['ts'], e['v']) for e in points if e.get('v') is not None]


def kpis_serveur(s):
    """KPI d'un serveur : {clé: dict(valeur, unité, statut, seuil, série)}."""
    k = {}
    cpu = [dict(ts=e['ts'], v=e['user'] + e['sys']) for e in s['cpu']]
    def ajoute(cle, libelle, v, unite, statut, seuil, pts=None, detail=''):
        k[cle] = {'libelle': libelle, 'v': v, 'unite': unite, 'statut': statut, 'seuil': seuil, 'serie': pts or [], 'detail': detail}
    st = stats([e['v'] for e in cpu])
    ajoute('cpu', 'CPU utilisé (p95)', st['p95'], '%', niveau(st['p95'], (70, 85, 95)), 'bon < 70 %, critique ≥ 95 %', serie(cpu), 'moyenne %s %%' % nombre(st['moy']))
    ch = [dict(ts=e['ts'], v=e['load1'] / s['ncpu']) for e in s['charge'] if e['load1'] is not None]
    st = stats([e['v'] for e in ch])
    ajoute('charge', 'Charge par CPU (p95)', st['p95'], '', niveau(st['p95'], (0.7, 1.0, 1.5)), 'bon < 0,7, critique ≥ 1,5', serie(ch), '%d CPU' % s['ncpu'])
    io_ = [dict(ts=e['ts'], v=e['iowait']) for e in s['cpu']]
    st = stats([e['v'] for e in io_])
    ajoute('iowait', 'Attente d\'I/O (p95)', st['p95'], '%', niveau(st['p95'], (5, 15, 25)), 'bon < 5 %, critique ≥ 25 %', serie(io_))
    stl = stats([e['steal'] for e in s['cpu']])
    ajoute('steal', 'CPU retenu par l\'hyperviseur (p95)', stl['p95'], '%', niveau(stl['p95'], (2, 5, 10)), 'bon < 2 %, critique ≥ 10 %')
    mem = [dict(ts=e['ts'], v=e['dispo_pct']) for e in s['mem']]
    st = stats([e['v'] for e in mem])
    ajoute('memoire', 'Mémoire disponible (min)', st['min'], '%', niveau(st['min'], (20, 10, 5), inverse=True), 'bon > 20 %, critique ≤ 5 %', serie(mem),
           '%s Go de RAM' % nombre(s['mem'][-1]['total_mo'] / 1024.0, 0) if s['mem'] else '')
    sw = stats([(e.get('swap_in_s') or 0) + (e.get('swap_out_s') or 0) for e in s['mem']])
    ajoute('swap', 'Pagination (swap, max)', sw['max'], 'pages/s', niveau(sw['max'], (1, 50, 500)), 'bon = 0')
    cp = [dict(ts=e['ts'], v=e.get('compact_stall_s')) for e in s['mem']]
    st = stats([e['v'] for e in cp])
    rec = stats([e.get('recup_mo_s') for e in s['mem']])
    ajoute('compaction', 'Compactages mémoire bloquants (p95)', st['p95'], '/s', niveau(st['p95'], (0.1, 1, 10)), 'bon < 0,1/s', serie(cp),
           'recyclage du cache %s Mo/s' % nombre(rec['moy']) if rec['moy'] is not None else '')
    pire = None
    for dev, sr in s['disques'].items():
        if stats([e['r_s'] + e['w_s'] for e in sr])['moy'] < 5:
            continue
        a = stats([e['await'] for e in sr])
        if a['p95'] is not None and (pire is None or a['p95'] > pire[1]):
            pire = (dev, a['p95'], [(e['ts'], e['await']) for e in sr if e.get('await') is not None])
    ajoute('disque', 'Temps de réponse disque (p95, pire disque)', pire[1] if pire else None, 'ms', niveau(pire[1] if pire else None, (5, 10, 20)),
           'bon < 5 ms, critique ≥ 20 ms', pire[2] if pire else [], ('%s%s' % (pire[0], ' (%s)' % s['dm'][pire[0]] if pire[0] in s['dm'] else '')) if pire else '')
    tot = {}
    for sr in s['disques'].values():
        for e in sr:
            tot[e['ts']] = tot.get(e['ts'], 0) + e['r_s'] + e['w_s']
    iops = stats(list(tot.values()))
    k['iops'] = {'libelle': 'IOPS (pic)', 'v': iops['max'], 'unite': '', 'statut': 'na', 'seuil': 'volume de référence', 'serie': sorted(tot.items()), 'detail': 'moyenne %s' % fmt_n(iops['moy'])}
    lat = stats([e['ping_ms'] for e in s['latence']])
    if lat['n']:
        ajoute('reseau', 'Latence vers la base (p95)', lat['p95'], 'ms', niveau(lat['p95'], (0.5, 2, 5)), 'bon < 0,5 ms, critique ≥ 5 ms',
               [(e['ts'], e['ping_ms']) for e in s['latence'] if e['ping_ms'] is not None])
    if s['informix']:
        p = s['profil']
        st = stats([e['cache_lect'] for e in p])
        ajoute('cache', 'Lectures servies par le cache Informix', st['moy'], '%', niveau(st['moy'], (98, 95, 90), inverse=True), 'bon > 98 %, critique ≤ 90 %',
               [(e['ts'], e['cache_lect']) for e in p if e['cache_lect'] is not None])
        st = stats([e['bufreads_s'] for e in p])
        k['lectures'] = {'libelle': 'Lectures logiques Informix (pic)', 'v': st['max'], 'unite': '/s', 'statut': 'na', 'seuil': 'charge du moteur',
                         'serie': [(e['ts'], e['bufreads_s']) for e in p], 'detail': 'moyenne %s/s' % fmt_n(st['moy'])}
        st = stats([e['lockwts_min'] for e in p])
        ajoute('verrous', 'Attentes de verrou (moyenne)', st['moy'], '/min', niveau(st['moy'], (10, 30, 300)), 'bon < 10/min, critique ≥ 300/min',
               [(e['ts'], e['lockwts_min']) for e in p], 'p95 %s/min' % nombre(st['p95'], 0))
        st = stats([x['total'] for x in s['ckp']])
        ajoute('checkpoint', 'Durée de checkpoint (max)', st['max'], 's', niveau(st['max'], (2, 10, 30)), 'bon < 2 s, critique ≥ 30 s')
        rq = stats([e['ready'] for e in s['ready']])
        vps = (s['vp'] or {}).get('cpu', {}).get('vps') or s['ncpu']
        ajoute('file_cpu', 'Threads Informix en attente de CPU (p95)', rq['p95'], '', niveau((rq['p95'] or 0) / float(vps or 1) if rq['n'] else None, (0.5, 1, 2)),
               'bon < 0,5 × nombre de VP CPU', [(e['ts'], e['ready']) for e in s['ready']], '%s VP CPU' % vps)
        db = [x for x in (s.get('inv') or {}).get('dbspaces', []) if not x['temp'] and not x['blob']]
        if db:
            m = min(db, key=lambda x: x['libre_pct'])
            ajoute('dbspace', 'Espace libre du dbspace le plus plein', m['libre_pct'], '%', niveau(m['libre_pct'], (20, 10, 1), inverse=True),
                   'bon > 20 %, critique ≤ 1 %', [], m['nom'])
        ses = stats([e.get('actives') for e in s['sessions']])
        k['sessions'] = {'libelle': 'Sessions Informix (max)', 'v': ses['max'], 'unite': '', 'statut': 'na', 'seuil': 'volume de référence', 'serie': [(e['ts'], e['actives']) for e in s['sessions']], 'detail': ''}
    return k


def statut_os(cv, aujourdhui):
    if not cv['majeure']:
        return 'na', 'version non relevée'
    c = CYCLE_RHEL.get(cv['majeure'])
    if not c:
        return 'na', 'cycle de vie inconnu'
    if aujourdhui > c['fin_maintenance']:
        mois = (aujourdhui.year - c['fin_maintenance'].year) * 12 + aujourdhui.month - c['fin_maintenance'].month
        return 'critique', 'hors maintenance standard depuis %d mois (%s) ; support étendu payant (ELS) jusqu\'au %s' % (
            mois, c['fin_maintenance'].strftime('%d/%m/%Y'), c['fin_els'].strftime('%d/%m/%Y'))
    if c.get('fin_complet') and aujourdhui > c['fin_complet']:
        return 'vigilance', 'en maintenance jusqu\'au %s (plus d\'évolutions)' % c['fin_maintenance'].strftime('%d/%m/%Y')
    return 'bon', 'supporté jusqu\'au %s' % c['fin_maintenance'].strftime('%d/%m/%Y')


# --------------------------------------------------------------------------------------------
# Argumentaire RHEL 9
# --------------------------------------------------------------------------------------------
def argumentaire(serveurs, K, CV, aujourdhui):
    """Lignes (constat mesuré, limite actuelle, apport RHEL 9, gain attendu), seulement quand la mesure le justifie."""
    L = []
    anciens = [(s['nom'], CV[s['nom']]) for s in serveurs if CV[s['nom']]['majeure'] and CV[s['nom']]['majeure'] < 9]
    if anciens:
        txt = ', '.join('%s : RHEL %d.%d' % (n, c['majeure'], c['mineure']) for n, c in anciens)
        L.append(('Sécurité et conformité', txt + ' — ' + statut_os(anciens[0][1], aujourdhui)[1],
                  'Plus de correctifs de sécurité standard ; noyau 3.10 (RHEL 7) ou 4.18 (RHEL 8)',
                  'RHEL 9 : noyau 5.14, maintenance jusqu\'en mai 2032, politiques cryptographiques système, OpenSSL 3 / TLS 1.3, SELinux et audit renforcés',
                  'Retour dans le support Red Hat et l\'éditeur ; correctifs CVE réguliers'))
    sans = [n for n, c in CV.items() if c['depots'] == 'aucun' or (c['abonnement'] or '').startswith('expiré')]
    vieux = [(n, c['derniere_maj']) for n, c in CV.items() if c['derniere_maj'] and (aujourdhui - c['derniere_maj']).days > 180]
    if sans or vieux:
        cause = lambda c: ', '.join(x for x in ('abonnement Red Hat non valide' if (c['abonnement'] or '').startswith('expiré') else '',
                                               'aucun dépôt actif' if c['depots'] == 'aucun' else '') if x)
        L.append(('Maintien en condition', '; '.join(['%s : %s' % (n, cause(CV[n])) for n in sans] +
                                                    ['%s : derniers paquets installés le %s' % (n, d.strftime('%d/%m/%Y')) for n, d in vieux]),
                  'Impossible d\'installer un correctif ou un outil (ex. python3 refusé faute de dépôt)',
                  'Abonnement RHEL 9 et dépôts BaseOS / AppStream ; Satellite déjà présent chez Scania',
                  'Correctifs et outillage disponibles ; serveurs patchables'))
    if any(K[n].get('compaction', {}).get('statut') in ('vigilance', 'degrade', 'critique') or K[n].get('memoire', {}).get('statut') in ('degrade', 'critique') for n in K):
        n = max(K, key=lambda n: K[n].get('compaction', {}).get('v') or 0)
        L.append(('Mémoire', 'Compactages bloquants %s/s sur %s, %s' % (nombre(K[n]['compaction']['v']), n, K[n]['compaction']['detail']),
                  'Noyau 3.10 : compactage à la demande qui bloque les processus (THP, NFS) ; double mise en cache des chunks sans I/O directe',
                  'Noyau 5.14 : compactage proactif (vm.compaction_proactiveness), gestion des pages et de la récupération mémoire revue, '
                  'profils tuned à jour', 'Fin des blocages des processus système ; marge mémoire pour Informix'))
    if any(K[n].get('disque', {}).get('statut') in ('degrade', 'critique') or K[n].get('iowait', {}).get('statut') in ('degrade', 'critique') for n in K):
        n = max(K, key=lambda n: K[n].get('disque', {}).get('v') or 0)
        L.append(('Stockage', 'Temps de réponse disque p95 %s ms sur %s (%s), iowait p95 %s %%' % (
            nombre(K[n]['disque']['v']), n, K[n]['disque']['detail'], nombre(K[n]['iowait']['v'])),
            'Pile d\'I/O ancienne (blk-mq partiel, ordonnanceurs mono-file)', 'Pile multi-files native (blk-mq, mq-deadline / none), pilotes NVMe et '
            'virtio récents, io_uring', 'Moins de latence par I/O, meilleure utilisation de la baie et des SSD'))
    if any(K[n].get('cpu', {}).get('statut') in ('degrade', 'critique') or K[n].get('file_cpu', {}).get('statut') in ('degrade', 'critique') for n in K):
        n = max(K, key=lambda n: K[n].get('cpu', {}).get('v') or 0)
        L.append(('Processeurs', 'CPU p95 %s %% sur %s ; threads Informix en attente de CPU p95 %s' % (
            nombre(K[n]['cpu']['v']), n, nombre(K[n].get('file_cpu', {}).get('v'))),
            'Pas d\'isolation fine des services annexes sur le serveur de base', 'cgroups v2 et systemd : réservation et plafonds CPU / mémoire par service '
            '(CPUQuota, MemoryMax), ordonnanceur récent', 'Les services annexes ne prennent plus le CPU des VP Informix'))
    if any(not [p for p in c['python'] if re.search(r'Python 3', p)] for c in CV.values()):
        L.append(('Outillage', 'Python 3 absent ou seulement via Software Collections sur certains serveurs',
                  'Python 2.7 (fin de vie 2020) par défaut', 'Python 3.9 natif, PCP, Cockpit, outils eBPF (bcc, bpftrace) pour l\'observabilité',
                  'Supervision et automatisation modernes (Ansible, scripts d\'exploitation)'))
    return L


# --------------------------------------------------------------------------------------------
# Rendu
# --------------------------------------------------------------------------------------------
CSS = r"""
:root{color-scheme:light;--bg:#f4f5f7;--surface:#fcfcfb;--surface-2:#f0efec;--border:#e3e2de;--text:#0b0b0b;--text-2:#52514e;--muted:#7a7a76;
--grid:#ecebe7;--s1:#2a78d6;--s2:#eb6834;--s3:#1baf7a;--s4:#eda100;--good:#0ca30c;--warning:#fab219;--serious:#ec835a;--critical:#d03b3b;--accent:#2a78d6}
@media (prefers-color-scheme:dark){:root:where(:not([data-theme="light"])){color-scheme:dark;--bg:#111110;--surface:#1a1a19;--surface-2:#242422;--border:#33332f;
--text:#f0efec;--text-2:#c3c2b7;--muted:#8f8e86;--grid:#2a2a27;--s1:#3987e5;--s2:#d95926;--s3:#199e70;--s4:#c98500;--accent:#3987e5}}
:root[data-theme="dark"]{color-scheme:dark;--bg:#111110;--surface:#1a1a19;--surface-2:#242422;--border:#33332f;--text:#f0efec;--text-2:#c3c2b7;--muted:#8f8e86;
--grid:#2a2a27;--s1:#3987e5;--s2:#d95926;--s3:#199e70;--s4:#c98500;--accent:#3987e5}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,Arial,sans-serif}
.wrap{max-width:1320px;margin:0 auto;padding:24px 20px 48px}
header{display:flex;flex-wrap:wrap;justify-content:space-between;gap:12px;align-items:flex-end;margin-bottom:20px}
h1{font-size:24px;margin:0;letter-spacing:-.01em}h2{font-size:17px;margin:0 0 4px}h3{font-size:14px;margin:0 0 8px}
.sub{color:var(--text-2);font-size:13px}.muted{color:var(--muted)}
.tools button{background:var(--surface);color:var(--text);border:1px solid var(--border);border-radius:8px;padding:6px 12px;font:inherit;cursor:pointer}
section{background:var(--surface);border:1px solid var(--border);border-radius:14px;padding:18px 20px;margin-bottom:16px}
.intro{color:var(--text-2);margin:0 0 14px;font-size:13px}
.hero{display:grid;grid-template-columns:minmax(220px,300px) 1fr;gap:20px;align-items:center}
.score{display:flex;flex-direction:column;gap:6px;align-items:flex-start}.score .n{font-size:64px;font-weight:700;line-height:1}.score .n small{font-size:22px;color:var(--muted);font-weight:500}
.pill{display:inline-flex;align-items:center;gap:6px;border-radius:999px;padding:2px 10px;font-size:12.5px;font-weight:600;border:1px solid var(--border);background:var(--surface-2);white-space:nowrap}
.pill i{font-style:normal}
.prio{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px}
.prio div{border:1px solid var(--border);border-radius:12px;padding:12px 14px}.prio b{display:block;font-size:30px;line-height:1.1}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(250px,1fr));gap:12px}
.tile{border:1px solid var(--border);border-radius:12px;padding:12px 14px 10px;display:flex;flex-direction:column;gap:4px;min-width:0}
.tile .lib{font-size:12.5px;color:var(--text-2)}.tile .val{font-size:28px;font-weight:650;line-height:1.15}.tile .val small{font-size:14px;color:var(--muted);font-weight:500;margin-left:2px}
.tile .meta{font-size:12px;color:var(--muted)}.spark{width:100%;height:34px;display:block}
.cat{margin:18px 0 8px;font-size:12px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);font-weight:600}
table{width:100%;border-collapse:collapse;font-size:13px}th{text-align:left;color:var(--text-2);font-weight:600;border-bottom:1px solid var(--border);padding:8px 10px;white-space:nowrap}
td{border-bottom:1px solid var(--grid);padding:8px 10px;vertical-align:top}.tw{overflow-x:auto}
.charts{display:grid;grid-template-columns:repeat(auto-fit,minmax(520px,1fr));gap:14px}
figure{margin:0;border:1px solid var(--border);border-radius:12px;padding:12px 14px;position:relative;min-width:0}figcaption{font-weight:600;font-size:13px;margin-bottom:6px}
.chart svg{width:100%;height:auto;display:block}.ax{fill:var(--muted);font-size:11px}.gl{stroke:var(--grid);stroke-width:1}.ref{stroke:var(--critical);stroke-width:1;opacity:.7}
.legend{display:flex;flex-wrap:wrap;gap:4px 14px;font-size:12px;color:var(--text-2);margin-top:6px}.legend span{display:inline-flex;align-items:center;gap:6px}
.legend i{width:10px;height:3px;border-radius:2px;display:inline-block}
.tip{position:absolute;pointer-events:none;background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:6px 9px;font-size:12px;box-shadow:0 4px 14px rgba(0,0,0,.12);display:none;white-space:nowrap;z-index:2}
.cross{stroke:var(--muted);stroke-width:1;display:none}
.road{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px}.road div{border:1px solid var(--border);border-radius:12px;padding:12px 14px}
.road b{display:block;color:var(--accent);font-size:12px;text-transform:uppercase;letter-spacing:.05em}.road ul{margin:6px 0 0;padding-left:18px;color:var(--text-2);font-size:13px}
details summary{cursor:pointer;color:var(--text-2);font-size:12.5px;margin-top:8px}
footer{color:var(--muted);font-size:12px;margin-top:20px}
@media (max-width:720px){.hero{grid-template-columns:1fr}.prio{grid-template-columns:repeat(2,1fr)}.charts{grid-template-columns:1fr}}
@media print{body{background:#fff}.tools{display:none}section{break-inside:avoid}}
"""

JS = r"""
document.getElementById('theme').onclick=function(){var r=document.documentElement,d=r.getAttribute('data-theme');
 var sombre=d?d==='dark':matchMedia('(prefers-color-scheme: dark)').matches;r.setAttribute('data-theme',sombre?'light':'dark')};
document.querySelectorAll('figure.chart').forEach(function(f){
 var d=JSON.parse(f.getAttribute('data-serie')),svg=f.querySelector('svg'),tip=f.querySelector('.tip'),cr=f.querySelector('.cross'),zone=f.querySelector('.zone');
 if(!d.x.length)return;
 zone.addEventListener('mousemove',function(e){var b=svg.getBoundingClientRect(),vb=svg.viewBox.baseVal,x=(e.clientX-b.left)*vb.width/b.width;
  var i=0,m=1e18;d.px.forEach(function(p,j){var q=Math.abs(p-x);if(q<m){m=q;i=j}});
  cr.setAttribute('x1',d.px[i]);cr.setAttribute('x2',d.px[i]);cr.style.display='block';
  var h='<b>'+d.x[i]+'</b>';d.s.forEach(function(s){var v=s.v[i];h+='<br><span style="color:'+s.c+'">●</span> '+s.n+' : <b>'+(v===null?'–':v)+'</b> '+d.u});
  tip.innerHTML=h;tip.style.display='block';var l=(e.clientX-f.getBoundingClientRect().left)+14;if(l>f.clientWidth-170)l-=190;tip.style.left=l+'px';tip.style.top='40px'});
 zone.addEventListener('mouseleave',function(){tip.style.display='none';cr.style.display='none'})});
"""


def badge(statut):
    lib, ic, c = STATUTS[statut]
    return '<span class="pill"><i style="color:%s">%s</i>%s</span>' % (c, ic, lib)


def sparkline(pts, statut):
    v = [x for _t, x in pts if x is not None]
    if len(v) < 2:
        return ''
    n = 120
    pas = max(1, len(v) // n)
    v = [max(v[i:i + pas]) for i in range(0, len(v), pas)]
    lo, hi = min(v), max(v)
    hi = hi if hi > lo else lo + 1
    W, H = 240.0, 34.0
    pts_ = ' '.join('%.1f,%.1f' % (i * W / (len(v) - 1), H - 3 - (x - lo) / (hi - lo) * (H - 6)) for i, x in enumerate(v))
    c = STATUTS[statut][2] if statut != 'na' else 'var(--s1)'
    return '<svg class="spark" viewBox="0 0 240 34" preserveAspectRatio="none" aria-hidden="true"><polyline fill="none" stroke="%s" stroke-width="1.6" ' \
           'vector-effect="non-scaling-stroke" stroke-linejoin="round" points="%s"/></svg>' % (c, pts_)


def tuile(k, serveur=None):
    if k is None or k['v'] is None:
        return ''
    return ('<div class="tile"><div class="lib">%s%s</div><div class="val">%s<small>%s</small></div>%s%s<div class="meta">%s%s</div></div>' % (
        esc(k['libelle']), (' · <b>%s</b>' % esc(serveur)) if serveur else '', esc(nombre(k['v']) if k['v'] is not None and abs(k['v']) < 10000 else fmt_n(k['v'])),
        esc(' ' + k['unite'] if k['unite'] and not k['unite'].startswith('%') else k['unite']), badge(k['statut']) if k['statut'] != 'na' else '',
        sparkline(k['serie'], k['statut']), esc(k['seuil']), (' · ' + esc(k['detail'])) if k.get('detail') else ''))


def graphe(titre, series, unite, t0, t1, ref=None, ymax=None):
    """Courbes (≤ 4 séries, une seule échelle) avec réticule et info-bulle ; tableau de données repliable."""
    series = [(n, c, [(t, v) for t, v in pts if v is not None]) for n, c, pts in series]
    series = [x for x in series if x[2]]
    if not series:
        return ''
    W, H, gx, gy, bas = 640, 200, 48, 14, 26
    vmax = ymax or max([v for _n, _c, pts in series for _t, v in pts] + [ref or 0, 1e-9]) * 1.12
    duree = (t1 - t0).total_seconds() or 1
    X = lambda t: gx + (t - t0).total_seconds() / duree * (W - gx - 10)
    Y = lambda v: gy + (1 - min(v, vmax) / vmax) * (H - gy - bas)
    o = ['<svg viewBox="0 0 %d %d" role="img" aria-label="%s">' % (W, H, esc(titre))]
    for i in range(5):
        v = vmax * i / 4.0
        o.append('<line class="gl" x1="%d" x2="%d" y1="%.1f" y2="%.1f"/><text class="ax" x="%d" y="%.1f" text-anchor="end">%s</text>' % (
            gx, W - 10, Y(v), Y(v), gx - 6, Y(v) + 4, esc(nombre(v, 1))))
    for i in range(6):
        t = t0 + dt.timedelta(seconds=duree * i / 5.0)
        o.append('<text class="ax" x="%.1f" y="%d" text-anchor="%s">%s</text>' % (X(t), H - 8, 'end' if i == 5 else 'start' if i == 0 else 'middle', t.strftime('%H:%M')))
    if ref is not None and ref < vmax:
        o.append('<line class="ref" x1="%d" x2="%d" y1="%.1f" y2="%.1f"/><text class="ax" x="%d" y="%.1f" text-anchor="end">seuil</text>' % (
            gx, W - 10, Y(ref), Y(ref), W - 12, Y(ref) - 4))
    for n, c, pts in series:
        o.append('<polyline fill="none" stroke="%s" stroke-width="2" stroke-linejoin="round" stroke-linecap="round" points="%s"/>' % (
            c, ' '.join('%.1f,%.1f' % (X(t), Y(v)) for t, v in pts)))
    o.append('<line class="cross" x1="0" x2="0" y1="%d" y2="%d"/><rect class="zone" x="%d" y="0" width="%d" height="%d" fill="transparent"/></svg>' % (
        gy, H - bas, gx, W - gx - 10, H - bas))
    # données pour l'info-bulle : instants de la première série, valeur la plus proche pour les autres
    ref_ts = [t for t, _v in series[0][2]]
    pas = max(1, len(ref_ts) // 300)
    ref_ts = ref_ts[::pas]
    def proche(pts, t):
        best = min(pts, key=lambda p: abs((p[0] - t).total_seconds()))
        return round(best[1], 2) if abs((best[0] - t).total_seconds()) < 600 else None
    donnees = {'x': [t.strftime('%d/%m %H:%M') for t in ref_ts], 'px': [round(X(t), 1) for t in ref_ts], 'u': unite,
               's': [{'n': n, 'c': c, 'v': [proche(pts, t) for t in ref_ts]} for n, c, pts in series]}
    leg = '<div class="legend">%s</div>' % ''.join('<span><i style="background:%s"></i>%s</span>' % (c, esc(n)) for n, c, _p in series) if len(series) > 1 else ''
    tab = '<details><summary>Voir les données</summary><div class="tw"><table><tr><th>Heure</th>%s</tr>%s</table></div></details>' % (
        ''.join('<th>%s (%s)</th>' % (esc(n), esc(unite)) for n, _c, _p in series),
        ''.join('<tr><td>%s</td>%s</tr>' % (x, ''.join('<td>%s</td>' % ('–' if s['v'][i] is None else esc(nombre(s['v'][i]))) for s in donnees['s']))
                for i, x in enumerate(donnees['x'][::max(1, len(donnees['x']) // 60)])))
    return '<figure class="chart" data-serie="%s"><figcaption>%s</figcaption>%s%s<div class="tip"></div>%s</figure>' % (
        esc(json.dumps(donnees)), esc(titre), ''.join(o), leg, tab)


COULEURS = ['var(--s1)', 'var(--s2)', 'var(--s3)', 'var(--s4)']


def generer(serveurs, sortie, campagne=None, avant=None):
    aujourdhui = dt.date.today()
    serveurs = sorted(serveurs, key=ra.rang_role)
    t0, t1 = min(s['debut'] for s in serveurs), max(s['fin'] for s in serveurs)
    K = dict((s['nom'], kpis_serveur(s)) for s in serveurs)
    CV = dict((s['nom'], cycle_de_vie(s)) for s in serveurs)
    constats = [(s['nom'],) + c for s in serveurs for c in ra.diagnostic(s)]
    plan = ra.plan_recommandations(sorted(constats, key=lambda x: ra.GRAV[x[1]][2]))
    # indice de santé : 100 moins une pénalité par KPI hors norme et par serveur hors support
    etat_de = lambda sc: 'bon' if sc >= 80 else 'vigilance' if sc >= 60 else 'degrade' if sc >= 40 else 'critique'
    scores = {}
    for s in serveurs:
        pen = sum(PENALITE[k['statut']] for k in K[s['nom']].values()) + PENALITE[statut_os(CV[s['nom']], aujourdhui)[0]]
        scores[s['nom']] = max(0, 100 - pen)
    score = min(scores.values())          # l'infrastructure vaut ce que vaut son serveur le plus fragile
    etat = etat_de(score)
    par = {}
    for x in plan:
        par[x['prio']] = par.get(x['prio'], 0) + 1
    bdd = next((s for s in serveurs if s['informix'] and 'principale' in s['roles']), next((s for s in serveurs if s['informix']), serveurs[0]))
    o = ['<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
         '<title>Tableau de bord infrastructure IRIUM</title><style>%s</style></head><body><div class="wrap">' % CSS]
    o.append('<header><div><h1>Infrastructure IRIUM — tableau de bord</h1><div class="sub">Scania France · %s · %s → %s%s · %d serveur(s) : %s</div></div>'
             '<div class="tools"><button id="theme" type="button">Thème clair / sombre</button> <button type="button" onclick="window.print()">Imprimer / PDF</button></div></header>' % (
                 t0.strftime('%d/%m/%Y'), t0.strftime('%H:%M'), t1.strftime('%H:%M'), (' · campagne ' + esc(campagne['nom'])) if campagne else '', len(serveurs),
                 esc(', '.join(s['nom'] for s in serveurs))))
    # 1. synthèse
    prio = ''.join('<div><span class="muted">%s</span><b>%d</b><span class="sub">%s</span></div>' % (p, par.get(p, 0), l) for p, l in (
        ('Immédiat', 'risque d\'incident'), ('P1', 'effet majeur'), ('P2', 'effet significatif'), ('P3', 'amélioration')))
    principaux = [x for x in plan if x['prio'] in ('Immédiat', 'P1')][:4]
    o.append('<section><div class="hero"><div class="score"><span class="sub">Indice de santé de l\'infrastructure</span><div class="n">%d<small> / 100</small></div>%s'
             '<span class="sub">%s</span></div><div><div class="prio">%s</div><p class="sub" style="margin:12px 0 0">%s</p></div></div></section>' % (
                 score, badge(etat), ' · '.join('%s : %d' % (esc(n), scores[n]) for n in [s['nom'] for s in serveurs]) if len(serveurs) > 1 else '', prio, ('<b>Points majeurs :</b> ' + '; '.join('%s (%s)' % (esc(x['constat']), esc(x['serveur'])) for x in principaux)) if principaux else
                 'Aucun point majeur sur la période mesurée.'))
    # 2. obsolescence
    lignes = []
    for s in serveurs:
        c = CV[s['nom']]
        so, txt = statut_os(c, aujourdhui)
        lignes.append('<tr><td><b>%s</b><br><span class="muted">%s</span></td><td>%s<br><span class="muted">noyau %s</span></td><td>%s %s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>' % (
            esc(s['nom']), esc(s['roles']), esc(c['os'] or '–'), esc(c['noyau'] or '–'), badge(so), esc(txt),
            esc(c['derniere_maj'].strftime('%d/%m/%Y') if c['derniere_maj'] else '–'), esc(c['abonnement'] or '–') + ' / dépôts ' + esc(c['depots'] or '–'),
            esc(', '.join(c['python']) or '–'), esc(version_informix(s) or ('–' if not s['informix'] else '?'))))
    o.append('<section><h2>Obsolescence et risques</h2><p class="intro">Cycle de vie du système d\'exploitation et des briques logicielles, relevé sur chaque serveur.</p>'
             '<div class="tw"><table><tr><th>Serveur</th><th>Système</th><th>Support</th><th>Derniers correctifs</th><th>Abonnement / dépôts</th><th>Python</th><th>Informix</th></tr>%s</table></div></section>' % ''.join(lignes))
    # 3. KPI
    def pire(cle):
        cand = [(s['nom'], K[s['nom']][cle]) for s in serveurs if cle in K[s['nom']]]
        if not cand:
            return None, None
        ordre = ['critique', 'degrade', 'vigilance', 'bon', 'na']
        cand.sort(key=lambda x: (ordre.index(x[1]['statut']), -(x[1]['v'] or 0)))
        return cand[0]
    blocs = []
    for titre, cles in (('Processeurs', ('cpu', 'charge', 'steal', 'file_cpu')), ('Mémoire', ('memoire', 'compaction', 'swap')),
                        ('Stockage', ('disque', 'iowait', 'iops', 'dbspace')), ('Base Informix', ('cache', 'lectures', 'verrous', 'checkpoint', 'sessions')),
                        ('Réseau', ('reseau',))):
        tu = []
        for c in cles:
            n, k = pire(c)
            if k:
                tu.append(tuile(k, n if len(serveurs) > 1 else None))
        if tu:
            blocs.append('<div class="cat">%s</div><div class="grid">%s</div>' % (titre, ''.join(tu)))
    o.append('<section><h2>Indicateurs clés</h2><p class="intro">Valeur la plus défavorable parmi les serveurs audités, avec son statut et le seuil utilisé. '
             'La courbe montre l\'évolution sur la période.</p>%s</section>' % ''.join(blocs))
    # 4. graphiques
    gr = []
    sys_srv = serveurs[:4]
    gr.append(graphe('CPU utilisé par serveur (%)', [(s['nom'], COULEURS[i], [(e['ts'], e['user'] + e['sys']) for e in s['cpu']]) for i, s in enumerate(sys_srv)], '%', t0, t1, 85, 100))
    gr.append(graphe('Mémoire disponible par serveur (%)', [(s['nom'], COULEURS[i], [(e['ts'], e['dispo_pct']) for e in s['mem']]) for i, s in enumerate(sys_srv)], '%', t0, t1, 10, 100))
    if K[bdd['nom']].get('disque', {}).get('serie'):
        gr.append(graphe('Temps de réponse disque — %s, %s (ms)' % (bdd['nom'], K[bdd['nom']]['disque']['detail']), [('temps de réponse', COULEURS[0], K[bdd['nom']]['disque']['serie'])], 'ms', t0, t1, 20))
    if bdd['informix']:
        gr.append(graphe('Lectures logiques Informix — %s (par seconde)' % bdd['nom'], [('lectures logiques', COULEURS[0], K[bdd['nom']]['lectures']['serie'])], '/s', t0, t1))
        gr.append(graphe('Attentes de verrou — %s (par minute)' % bdd['nom'], [('attentes', COULEURS[1], K[bdd['nom']]['verrous']['serie'])], '/min', t0, t1, 300))
        if any(v for _t, v in K[bdd['nom']].get('compaction', {}).get('serie', [])):
            gr.append(graphe('Compactages mémoire bloquants — %s (par seconde)' % bdd['nom'], [('compactages', COULEURS[2], K[bdd['nom']]['compaction']['serie'])], '/s', t0, t1, 1))
    o.append('<section><h2>Évolution sur la période</h2><p class="intro">Survoler une courbe pour lire les valeurs. Chaque graphique a une seule échelle ; '
             'le trait rouge fin marque le seuil critique.</p><div class="charts">%s</div></section>' % ''.join(g for g in gr if g))
    # 5. argumentaire RHEL 9
    arg = argumentaire(serveurs, K, CV, aujourdhui)
    if arg:
        o.append('<section><h2>Pourquoi passer à RHEL 9</h2><p class="intro">Chaque ligne part d\'un constat mesuré pendant l\'audit.</p><div class="tw"><table>'
                 '<tr><th>Domaine</th><th>Constat mesuré</th><th>Limite actuelle</th><th>Apport de RHEL 9</th><th>Gain attendu</th></tr>%s</table></div>'
                 '<p class="sub" style="margin-top:10px">Prérequis : version d\'Informix certifiée RHEL 9 (matrice IBM / HCL) et validation de l\'éditeur IRIUM.</p></section>' % ''.join(
                     '<tr><td><b>%s</b></td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>' % tuple(esc(x) for x in a) for a in arg))
    # 6. infrastructure cible : définie séparément (architecture et prérequis transmis au client)
    o.append('<section><h2>Infrastructure cible</h2><p class="intro" style="margin:0">L\'architecture cible et les prérequis ont été transmis séparément. '
             'La nouvelle infrastructure devra <b>respecter ces prérequis</b> ; les mesures de ce tableau de bord servent de référence pour la valider '
             '(même campagne d\'audit avant et après, option --avant).</p></section>')
    # 7. avant / après
    if avant:
        Ka = dict((s['nom'], kpis_serveur(s)) for s in avant)
        lig = []
        for s in serveurs:
            if s['nom'] not in Ka:
                continue
            for c, k in sorted(K[s['nom']].items()):
                a = Ka[s['nom']].get(c)
                if a and a['v'] is not None and k['v'] is not None:
                    lig.append('<tr><td>%s</td><td>%s</td><td>%s %s</td><td>%s %s</td><td>%s</td></tr>' % (
                        esc(s['nom']), esc(k['libelle']), esc(nombre(a['v'])), esc(k['unite']), esc(nombre(k['v'])), esc(k['unite']), badge(k['statut'])))
        if lig:
            o.append('<section><h2>Avant / après</h2><div class="tw"><table><tr><th>Serveur</th><th>Indicateur</th><th>Référence</th><th>Actuel</th><th>Statut</th></tr>%s</table></div></section>' % ''.join(lig))
    # 8. feuille de route
    imm = [x for x in plan if x['prio'] in ('Immédiat', 'P1')][:6]
    o.append('<section><h2>Feuille de route proposée</h2><div class="road">'
             '<div><b>Phase 0 · tout de suite</b><ul>%s</ul></div>'
             '<div><b>Phase 1 · maquette</b><ul><li>Serveurs RHEL 9 conformes à l\'architecture et aux prérequis transmis</li><li>Informix en version certifiée RHEL 9, ONCONFIG revu</li>'
             '<li>Audit de référence sur la maquette</li></ul></div>'
             '<div><b>Phase 2 · recette</b><ul><li>Recette IRIUM avec l\'éditeur (programmes Genero, ipscrond)</li><li>Tests de charge sur les traitements critiques</li></ul></div>'
             '<div><b>Phase 3 · bascule</b><ul><li>Nouveau serveur ajouté comme secondaire de %s, synchronisé en continu</li>'
             '<li>Bascule des rôles en fenêtre courte, ancien serveur conservé en secours</li></ul></div>'
             '<div><b>Phase 4 · mesure</b><ul><li>Même campagne d\'audit, même plage horaire</li><li>Comparaison avant / après (option --avant)</li></ul></div>'
             '</div></section>' % (''.join('<li>%s</li>' % esc(x['constat']) for x in imm) or '<li>Aucune action urgente</li>', esc(bdd['nom'])))
    o.append('<footer>Indice de santé d\'un serveur = 100 − pénalités par indicateur hors norme (vigilance 3, dégradé 7, critique 12) et pour un système hors support ; '
             'l\'indice global est celui du serveur le plus fragile. Seuils indiqués sur chaque indicateur. Dates de cycle de vie Red Hat publiques, à confirmer. '
             'Détail technique complet : rapport d\'audit. Généré le %s par dashboard_kpi.py.</footer></div><script>%s</script></body></html>' % (
                 dt.datetime.now().strftime('%d/%m/%Y %H:%M'), JS))
    with io.open(sortie, 'w', encoding='utf-8') as f:
        f.write(''.join(o))
    return score, etat


def charger_sources(sources, tmp):
    serveurs, campagne = [], None
    for src in sources:
        d = ra.ouvrir_source(src, tmp)
        if os.path.exists(os.path.join(d, 'info.txt')):
            dossiers = [d]
        elif os.path.isdir(d):
            campagne = ra.charger_campagne(d)
            dossiers = campagne['dossiers']
        else:
            dossiers = []
        for x in dossiers:
            try:
                serveurs.append(ra.charger(x))
            except Exception as e:   # un serveur incomplet ne doit pas empêcher le tableau de bord
                print('Serveur ignoré (%s) : %s' % (x, e), file=sys.stderr)
    return serveurs, campagne


def main():
    ra.sortie_utf8()
    p = argparse.ArgumentParser(description='Tableau de bord KPI de l\'infrastructure IRIUM')
    p.add_argument('sources', nargs='+', help='Dossier de campagne, dossiers ou archives .tar.gz d\'audit-irium.sh')
    p.add_argument('--avant', nargs='+', help='Audit de référence (comparaison avant / après)')
    p.add_argument('-o', '--sortie', default=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'dashboard_%s.html' % dt.datetime.now().strftime('%Y%m%d_%H%M')))
    a = p.parse_args()
    if os.path.isdir(a.sortie):
        a.sortie = os.path.join(a.sortie, 'dashboard_%s.html' % dt.datetime.now().strftime('%Y%m%d_%H%M'))
    try:
        tmp = tempfile.mkdtemp(prefix='.dashboard_tmp_', dir=os.path.dirname(os.path.abspath(a.sortie)))
    except (IOError, OSError):
        tmp = tempfile.mkdtemp(prefix='dashboard_')
    try:
        serveurs, campagne = charger_sources(a.sources, tmp)
        if not serveurs:
            sys.exit('Aucun audit valide.')
        avant = None
        if a.avant:
            os.makedirs(os.path.join(tmp, 'avant'))
            avant = charger_sources(a.avant, os.path.join(tmp, 'avant'))[0]
        score, etat = generer(serveurs, a.sortie, campagne, avant)
        print('Tableau de bord : %s (indice de santé %d/100, %s)' % (os.path.abspath(a.sortie), score, STATUTS[etat][0]))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == '__main__':
    main()
