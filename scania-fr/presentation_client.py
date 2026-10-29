#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Présentation client (diaporama HTML) : fusion du rapport d'audit et du tableau de bord KPI, aux couleurs IRIUM.

  python presentation_client.py <dossier de campagne | dossier d'audit | archive .tar.gz>   [-o presentation.html]
  python presentation_client.py --html rapport_x0296se_....html dashboard_x0296se_....html  [-o presentation.html]

La seconde forme part des deux pages HTML déjà générées, sans les données brutes.

Le diaporama contient : la couverture avec les logos Scania et IRIUM, le contexte et la méthode, la synthèse (indice
de santé, priorités), les indicateurs clés, les constats majeurs, les objets Informix les plus coûteux, l'obsolescence,
les raisons de passer à RHEL 9, le plan d'actions, la feuille de route, l'infrastructure cible (prérequis transmis) et
les décisions attendues.

C'est une page autonome : navigation au clavier (← →), plein écran (F), impression en PDF (une diapositive par page).
Logos lus dans assets/ (logo_scania.png, logo_irium.png). Python 2.7 ou 3.6+, aucune dépendance.
"""
from __future__ import division, print_function, unicode_literals

import argparse
import base64
import datetime as dt
import io
import os
import re
import shutil
import sys
import tempfile

sys.dont_write_bytecode = True
ICI = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ICI)
import rapport_audit as ra  # noqa: E402
import dashboard_kpi as dk  # noqa: E402

PY2 = sys.version_info[0] < 3
if PY2:
    str = unicode  # noqa: F821
    from HTMLParser import HTMLParser
    _h = HTMLParser()
    desechapper = _h.unescape
else:
    import html as _html
    desechapper = _html.unescape

esc = ra.esc
MOIS = ['janvier', 'février', 'mars', 'avril', 'mai', 'juin', 'juillet', 'août', 'septembre', 'octobre', 'novembre', 'décembre']
STATUTS = {'bon': ('Bon', '●', '#0ca30c'), 'vigilance': ('Vigilance', '▲', '#e5a00d'), 'degrade': ('Dégradé', '◆', '#ec835a'),
           'critique': ('Critique', '⬣', '#d03b3b'), 'na': ('', '', '#7a8a8a')}
LIB_STATUT = dict((v[0], k) for k, v in STATUTS.items() if v[0])
GRAV_PRIO = {'Immédiat': 'critique', 'P1': 'degrade', 'P2': 'vigilance', 'P3': 'na'}


def date_longue(d):
    return '%d %s %d' % (d.day, MOIS[d.month - 1], d.year)


# --------------------------------------------------------------------------------------------
# Modèle à partir des données d'audit
# --------------------------------------------------------------------------------------------
def modele_audit(serveurs, campagne=None):
    auj = dt.date.today()
    serveurs = sorted(serveurs, key=ra.rang_role)
    t0, t1 = min(s['debut'] for s in serveurs), max(s['fin'] for s in serveurs)
    K = dict((s['nom'], dk.kpis_serveur(s)) for s in serveurs)
    CV = dict((s['nom'], dk.cycle_de_vie(s)) for s in serveurs)
    constats = sorted([(s['nom'],) + c for s in serveurs for c in ra.diagnostic(s)], key=lambda x: ra.GRAV[x[1]][2])
    plan = ra.plan_recommandations(constats)
    scores = {}
    for s in serveurs:
        pen = sum(dk.PENALITE[k['statut']] for k in K[s['nom']].values()) + dk.PENALITE[dk.statut_os(CV[s['nom']], auj)[0]]
        scores[s['nom']] = max(0, 100 - pen)
    score = min(scores.values())
    bdd = next((s for s in serveurs if s['informix'] and 'principale' in s['roles']), next((s for s in serveurs if s['informix']), serveurs[0]))
    m = {'periode': '%s · %s → %s' % (t0.strftime('%d/%m/%Y'), t0.strftime('%H:%M'), t1.strftime('%H:%M')), 'date': auj,
         'duree_min': int((t1 - t0).total_seconds() // 60), 'serveurs': [s['nom'] for s in serveurs], 'campagne': campagne['nom'] if campagne else None,
         'score': score, 'etat': 'bon' if score >= 80 else 'vigilance' if score >= 60 else 'degrade' if score >= 40 else 'critique',
         'scores': scores if len(serveurs) > 1 else {}, 'prio': {}, 'plan': plan, 'bdd': bdd['nom']}
    for x in plan:
        m['prio'][x['prio']] = m['prio'].get(x['prio'], 0) + 1
    cvb = CV[bdd['nom']]
    m['perimetre'] = [('Serveur de base', bdd['nom']), ('Système', cvb['os'] or '–'), ('Processeurs', '%d vCPU' % bdd['ncpu']),
                      ('Mémoire', '%s Go' % dk.nombre(bdd['mem'][-1]['total_mo'] / 1024.0, 0) if bdd['mem'] else '–'),
                      ('Moteur', 'Informix %s' % (dk.version_informix(bdd) or '')), ('Base analysée', ', '.join(sorted({o['base'] for o in (bdd.get('obj') or {}).get('liste', [])} - {'?'})) or '–'),
                      ('Sessions (max)', dk.nombre(K[bdd['nom']].get('sessions', {}).get('v'), 0)), ('Serveurs audités', ', '.join(m['serveurs']))]
    m['kpis'] = []
    for cat, cles in (('Processeurs', ('cpu', 'charge', 'file_cpu')), ('Mémoire', ('memoire', 'compaction')), ('Stockage', ('disque', 'iowait', 'iops', 'dbspace')),
                      ('Base Informix', ('cache', 'lectures', 'verrous', 'checkpoint', 'sessions')), ('Réseau', ('reseau',))):
        for c in cles:
            cand = [(s['nom'], K[s['nom']][c]) for s in serveurs if c in K[s['nom']] and K[s['nom']][c]['v'] is not None]
            if not cand:
                continue
            ordre = ['critique', 'degrade', 'vigilance', 'bon', 'na']
            n, k = sorted(cand, key=lambda x: (ordre.index(x[1]['statut']), -(x[1]['v'] or 0)))[0]
            v = k['v']
            m['kpis'].append({'cat': cat, 'libelle': k['libelle'], 'v': dk.nombre(v) if abs(v) < 10000 else ra.fmt_n(v), 'unite': k['unite'], 'statut': k['statut'],
                              'seuil': k['seuil'], 'detail': k.get('detail', ''), 'serveur': n if len(serveurs) > 1 else '',
                              'spark': [x for _t, x in k['serie'] if x is not None]})
    m['obso'] = []
    for s in serveurs:
        c = CV[s['nom']]
        st, txt = dk.statut_os(c, auj)
        m['obso'].append({'serveur': s['nom'], 'role': s['roles'], 'systeme': c['os'] or '–', 'noyau': c['noyau'] or '', 'statut': st, 'support': txt,
                          'correctifs': c['derniere_maj'].strftime('%d/%m/%Y') if c['derniere_maj'] else '–',
                          'abonnement': '%s / dépôts %s' % (c['abonnement'] or '–', c['depots'] or '–'), 'python': ', '.join(c['python']) or '–',
                          'informix': dk.version_informix(s) or ('–' if not s['informix'] else '?')})
    m['arg'] = dk.argumentaire(serveurs, K, CV, auj)
    m['objets'] = []
    t = ra.lignes_classements(bdd)
    for cle, cols in (('physiques', (1, 2, 3, 4)), ('scans', (1, 2, 4, 5)), ('inverses', (1, 2, 4, 6))):
        if cle in t:
            titre, ent, lignes, _n = t[cle]
            m['objets'].append((titre.split('–')[-1].strip(), [ent[i] for i in cols], [[l[i] for i in cols] for l in lignes[:6]]))
    return m


# --------------------------------------------------------------------------------------------
# Modèle à partir des deux pages HTML (rapport + tableau de bord)
# --------------------------------------------------------------------------------------------
def texte(fragment):
    fragment = re.sub(r'<br\s*/?>', '\n', fragment)
    return desechapper(re.sub(r'<[^>]+>', '', fragment)).strip()


def lignes_tableau(t):
    res = []
    for tr in re.findall(r'<tr>(.*?)</tr>', t, re.S):
        cells = re.findall(r'<t[dh][^>]*>(.*?)</t[dh]>', tr, re.S)
        if cells:
            res.append(cells)
    return res


def statut_depuis(fragment):
    m = re.search(r'</i>\s*(Bon|Vigilance|Dégradé|Critique)', fragment)
    return LIB_STATUT.get(m.group(1), 'na') if m else 'na'


def section(h, titre):
    i = h.find('<h2>%s' % titre)
    if i < 0:
        return ''
    j = h.find('<section', i)
    return h[i:j if j > 0 else len(h)]


def modele_html(rapport, dashboard):
    R = io.open(rapport, encoding='utf-8', errors='replace').read()
    D = io.open(dashboard, encoding='utf-8', errors='replace').read()
    m = {'date': dt.date.today(), 'campagne': None, 'scores': {}}
    sub = re.search(r'<h1>[^<]*</h1><div class="sub">(.*?)</div>', D)
    s = texte(sub.group(1)) if sub else ''
    p = re.search(r'(\d\d/\d\d/\d{4}) · (\d\d:\d\d) → (\d\d:\d\d)', s)
    m['periode'] = ('%s · %s → %s' % p.groups()) if p else ''
    try:
        d0 = dt.datetime.strptime('%s %s' % (p.group(1), p.group(2)), '%d/%m/%Y %H:%M')
        d1 = dt.datetime.strptime('%s %s' % (p.group(1), p.group(3)), '%d/%m/%Y %H:%M')
        m['duree_min'] = int((d1 - d0).total_seconds() // 60)
        m['date'] = d0.date()
    except (AttributeError, ValueError):
        m['duree_min'] = None
    srv = re.search(r'serveur\(s\) : (.+)$', s)
    m['serveurs'] = [x.strip() for x in srv.group(1).split(',')] if srv else []
    c = re.search(r'campagne (\S+)', s)
    m['campagne'] = c.group(1) if c else None
    sc = re.search(r'<div class="n">(\d+)<small>', D)
    m['score'] = int(sc.group(1)) if sc else 0
    m['etat'] = statut_depuis(D[D.find('<div class="n">'):D.find('<div class="n">') + 400])
    for nom, n in re.findall(r'<span class="muted">(Immédiat|P1|P2|P3)</span><b>(\d+)</b>', D):
        m.setdefault('prio', {})[nom] = int(n)
    m.setdefault('prio', {})
    # indicateurs
    m['kpis'] = []
    zone = section(D, 'Indicateurs')
    for cat, bloc in re.findall(r'<div class="cat">(.*?)</div><div class="grid">(.*?)(?=<div class="cat">|$)', zone, re.S):
        for morceau in bloc.split('<div class="tile">')[1:]:
            t = re.match(r'(.*?)<div class="meta">(.*?)</div>', morceau, re.S)
            if not t:
                continue
            t = t.groups()
            lib = re.search(r'<div class="lib">(.*?)</div>', t[0], re.S)
            val = re.search(r'<div class="val">(.*?)<small>(.*?)</small>', t[0], re.S)
            pts = re.search(r'points="([\d., ]+)"', t[0])
            meta = texte(t[1])
            seuil, _, detail = meta.partition(' · ')
            lb = texte(lib.group(1)) if lib else ''
            serveur = ''
            if ' · ' in lb:
                lb, serveur = lb.rsplit(' · ', 1)
            spark = [34 - float(y) for x_y in (pts.group(1).split() if pts else []) for y in [x_y.split(',')[1]]]
            v = texte(val.group(1)) if val else ''
            if lb.startswith('Espace libre') and v == '0':
                v = '< 0,1'
            m['kpis'].append({'cat': texte(cat).capitalize() if texte(cat).isupper() else texte(cat), 'libelle': lb, 'v': v,
                              'unite': texte(val.group(2)) if val else '', 'statut': statut_depuis(t[0]), 'seuil': seuil, 'detail': detail,
                              'serveur': serveur, 'spark': spark})
    # obsolescence
    m['obso'] = []
    for cells in lignes_tableau(section(D, 'Obsolescence'))[1:]:
        if len(cells) >= 7:
            sv = texte(cells[0]).split('\n')
            sy = texte(cells[1]).split('\n')
            m['obso'].append({'serveur': sv[0], 'role': sv[1] if len(sv) > 1 else '', 'systeme': sy[0], 'noyau': sy[1].replace('noyau ', '') if len(sy) > 1 else '',
                              'statut': statut_depuis(cells[2]), 'support': re.sub(r'^(Bon|Vigilance|Dégradé|Critique|[●▲◆⬣○])\s*', '', texte(cells[2])).lstrip('●▲◆⬣ ').replace('Critique', '', 1).strip(),
                              'correctifs': texte(cells[3]), 'abonnement': texte(cells[4]), 'python': texte(cells[5]), 'informix': texte(cells[6])})
    m['arg'] = [tuple(texte(c) for c in cells[:5]) for cells in lignes_tableau(section(D, 'Pourquoi passer'))[1:] if len(cells) >= 5]
    if any('dépôts présents' in o['abonnement'] for o in m['obso']):   # libellé des anciens tableaux de bord
        m['arg'] = [tuple(x.replace('aucun dépôt actif / abonnement non valide', 'abonnement Red Hat non valide') for x in a) for a in m['arg']]
    # plan d'actions (rapport)
    m['plan'] = []
    for cells in lignes_tableau(section(R, 'Recommandations'))[1:]:
        if len(cells) < 6:
            continue
        prio = re.search(r'(Immédiat|P1|P2|P3)', texte(cells[0]))
        if not prio:
            continue
        cp = re.match(r'\s*<b>(.*?)</b>(?:<br>)?(.*)$', cells[4], re.S)
        m['plan'].append({'prio': prio.group(1), 'ref': texte(cells[1]), 'serveur': texte(cells[2]), 'nature': texte(cells[3]),
                          'constat': texte(cp.group(1)) if cp else texte(cells[4]), 'preuve': nettoyer(texte(cp.group(2))) if cp else '', 'action': texte(cells[5]),
                          'grav': GRAV_PRIO[prio.group(1)]})
    # périmètre
    srvh = re.search(r'<h2>Serveur (\S+) <span class="d">(.*?)</span></h2>', R)
    m['bdd'] = srvh.group(1) if srvh else (m['serveurs'][0] if m['serveurs'] else '')
    ncpu = re.search(r'(\d+) CPU', srvh.group(2)) if srvh else None
    kp = dict((k['libelle'], k) for k in m['kpis'])
    ram = re.search(r'(\d+) Go de RAM', kp.get('Mémoire disponible (min)', {}).get('detail', ''))
    base = re.search(r'journal (\w+):', R)
    o = m['obso'][0] if m['obso'] else {}
    m['perimetre'] = [('Serveur de base', m['bdd']), ('Système', o.get('systeme', '–')), ('Processeurs', ('%s vCPU' % ncpu.group(1)) if ncpu else '–'),
                      ('Mémoire', ('%s Go' % ram.group(1)) if ram else '–'), ('Moteur', 'Informix %s' % o.get('informix', '')),
                      ('Base analysée', base.group(1) if base else '–'), ('Sessions (max)', kp.get('Sessions Informix (max)', {}).get('v', '–')),
                      ('Serveurs audités', ', '.join(m['serveurs']))]
    # objets les plus coûteux (rapport)
    m['objets'] = []
    for cle, cols in (('Classement 1', (1, 2, 3, 4)), ('Classement 3', (1, 2, 4, 5)), ('Classement 4', (1, 2, 4, 6))):
        i = R.find('<summary>%s' % cle)
        if i < 0:
            continue
        titre = texte(R[i:R.find('</summary>', i)]).split('–')[-1].strip()
        t = lignes_tableau(R[i:R.find('</details>', i)])
        if len(t) > 1:
            m['objets'].append((titre, [texte(t[0][c]) for c in cols if c < len(t[0])], [[texte(l[c]) for c in cols if c < len(l)] for l in t[1:7]]))
    return m


# --------------------------------------------------------------------------------------------
# Rendu : diaporama aux couleurs IRIUM
# --------------------------------------------------------------------------------------------
CSS = r"""
:root{--deep:#0c3636;--deep-2:#0c5a60;--teal:#42a296;--mint:#6cc096;--ink:#0f1f1f;--ink-2:#4a5c5c;--muted:#7d8f8f;--line:#dfe7e6;
--paper:#ffffff;--paper-2:#f3f7f6;--good:#0ca30c;--warning:#e5a00d;--serious:#ec835a;--critical:#d03b3b}
*{box-sizing:border-box}html,body{margin:0;background:#dfe7e6;color:var(--ink);font:16px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,Arial,sans-serif}
.deck{display:flex;flex-direction:column;align-items:center;gap:28px;padding:28px 16px 80px}
.slide{position:relative;width:min(1280px,100%);aspect-ratio:16/9;background:var(--paper);border-radius:18px;overflow:hidden;box-shadow:0 10px 40px rgba(12,54,54,.14);
 display:flex;flex-direction:column;padding:44px 56px 40px}
.slide>.top{display:flex;justify-content:space-between;align-items:center;margin-bottom:18px}
.kicker{font-size:13px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;background:linear-gradient(90deg,var(--teal),var(--mint));-webkit-background-clip:text;background-clip:text;color:transparent}
.slide h2{font-size:34px;line-height:1.15;margin:4px 0 6px;color:var(--deep);letter-spacing:-.015em}
.slide .lead{color:var(--ink-2);font-size:17px;margin:0 0 18px;max-width:980px}
.logos{display:flex;gap:14px;align-items:center}.logos img{height:44px;width:auto;display:block}
.bar{position:absolute;left:0;right:0;bottom:0;height:6px;background:linear-gradient(90deg,var(--deep),var(--teal),var(--mint))}
.foot{position:absolute;left:56px;right:56px;bottom:16px;display:flex;justify-content:space-between;font-size:11.5px;color:var(--muted)}
.body{flex:1;min-height:0;display:flex;flex-direction:column}
/* couverture */
.cover{background:radial-gradient(1200px 600px at 85% 10%,rgba(108,192,150,.35),transparent 60%),linear-gradient(135deg,#0c3636 0%,#0c5a60 55%,#1f8f86 100%);color:#fff;padding:56px 64px}
.cover .brands{display:flex;gap:16px}.cover .brands span{background:#fff;border-radius:14px;padding:12px 18px;display:flex;align-items:center;box-shadow:0 6px 20px rgba(0,0,0,.18)}
.cover .brands img{height:64px;width:auto;display:block}
.cover h1{font-size:54px;line-height:1.06;margin:auto 0 14px;letter-spacing:-.02em;max-width:980px}
.cover .st{font-size:21px;opacity:.92;max-width:900px}.cover .meta{display:flex;gap:28px;margin-top:30px;font-size:15px;opacity:.9;flex-wrap:wrap}
.cover .meta b{display:block;font-size:12px;letter-spacing:.1em;text-transform:uppercase;opacity:.75;font-weight:600}
.cover .conf{position:absolute;right:64px;bottom:28px;font-size:12px;opacity:.7}
/* éléments */
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:22px;min-height:0}.grid3{display:grid;grid-template-columns:repeat(3,1fr);gap:16px}
.card{border:1px solid var(--line);border-radius:14px;padding:16px 18px;background:var(--paper);min-width:0}
.card.soft{background:var(--paper-2);border-color:transparent}
.card h3{margin:0 0 6px;font-size:16px;color:var(--deep)}
.kv{display:grid;grid-template-columns:auto 1fr;gap:6px 18px;font-size:15px}.kv dt{color:var(--muted)}.kv dd{margin:0;font-weight:600}
.score{display:flex;gap:28px;align-items:center}
.ring{--p:50;width:190px;height:190px;border-radius:50%;background:conic-gradient(var(--c) calc(var(--p)*1%),#e8efee 0);display:grid;place-items:center;flex:none}
.ring div{width:150px;height:150px;border-radius:50%;background:#fff;display:grid;place-items:center;text-align:center}
.ring b{font-size:56px;line-height:1;color:var(--deep)}.ring small{display:block;color:var(--muted);font-size:14px}
.pill{display:inline-flex;align-items:center;gap:6px;border-radius:999px;padding:3px 12px;font-size:13.5px;font-weight:650;background:var(--paper-2);white-space:nowrap}
.prio{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}.prio div{border-radius:14px;padding:14px 16px;background:var(--paper-2)}
.prio b{display:block;font-size:40px;line-height:1.05;color:var(--deep)}.prio span{font-size:13px;color:var(--ink-2)}.prio em{font-style:normal;font-weight:700;font-size:13px}
ul.points{margin:8px 0 0;padding:0;list-style:none}ul.points li{padding:8px 0 8px 22px;position:relative;border-bottom:1px solid var(--line);font-size:15px}
ul.points li:before{content:"";position:absolute;left:4px;top:15px;width:8px;height:8px;border-radius:50%;background:var(--teal)}
.kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}.kpi{border:1px solid var(--line);border-radius:14px;padding:12px 14px;display:flex;flex-direction:column;gap:3px;min-width:0}
.kpi .l{font-size:12.5px;color:var(--ink-2);min-height:34px}.kpi .v{font-size:30px;font-weight:700;line-height:1.1;color:var(--deep)}.kpi .v small{font-size:14px;color:var(--muted);font-weight:500;margin-left:3px}
.kpi .m{font-size:11.5px;color:var(--muted)}.kpi svg{width:100%;height:26px;display:block}
.cat{font-size:11.5px;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);font-weight:700}
table{width:100%;border-collapse:collapse;font-size:13.5px}th{text-align:left;font-size:12px;letter-spacing:.04em;text-transform:uppercase;color:var(--muted);font-weight:700;
 border-bottom:2px solid var(--line);padding:8px 10px}td{border-bottom:1px solid var(--line);padding:8px 10px;vertical-align:top}
td b{color:var(--deep)}.small{font-size:12.5px;color:var(--ink-2)}
.finding{display:grid;grid-template-columns:110px 1fr;gap:14px;padding:10px 0;border-bottom:1px solid var(--line)}
.finding h4{margin:0;font-size:16px;color:var(--deep)}.finding p{margin:3px 0 0;font-size:13px;color:var(--ink-2)}
.road{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;position:relative}
.road .ph{border-radius:14px;padding:14px;background:var(--paper-2);position:relative}
.road .ph b{display:block;font-size:12px;letter-spacing:.08em;text-transform:uppercase;color:var(--deep-2)}.road .ph h4{margin:4px 0 6px;font-size:17px;color:var(--deep)}
.road .ph ul{margin:0;padding-left:16px;font-size:13px;color:var(--ink-2)}.road .ph.now{background:linear-gradient(160deg,#0c3636,#0c5a60);color:#fff}
.road .ph.now b,.road .ph.now h4{color:#bff0dd}.road .ph.now ul{color:#e6f6f1}
.big{font-size:22px;color:var(--deep);font-weight:600;line-height:1.35;max-width:1000px}
.decision{display:flex;gap:14px;align-items:flex-start;padding:12px 0;border-bottom:1px solid var(--line)}.decision i{flex:none;width:34px;height:34px;border-radius:10px;
 background:linear-gradient(135deg,var(--teal),var(--mint));color:#fff;font-style:normal;font-weight:800;display:grid;place-items:center}
.decision h4{margin:2px 0;font-size:17px;color:var(--deep)}.decision p{margin:0;font-size:14px;color:var(--ink-2)}
.nav{position:fixed;right:14px;bottom:14px;display:flex;gap:6px;z-index:5;opacity:.28;transition:opacity .2s}.nav:hover{opacity:1}
.nav button{border:0;border-radius:9px;background:var(--deep);color:#fff;padding:7px 11px;font:inherit;font-size:13px;cursor:pointer}
.progress{position:fixed;left:0;top:0;height:4px;background:linear-gradient(90deg,var(--teal),var(--mint));z-index:5;width:0}
@media (max-width:900px){.slide{aspect-ratio:auto;padding:28px 22px 46px}.grid2,.kpis,.road,.prio,.grid3{grid-template-columns:1fr 1fr}.cover h1{font-size:34px}.foot{left:22px;right:22px}}
@media print{@page{size:13.333in 7.5in;margin:0}html,body{background:#fff}.deck{padding:0;gap:0}.slide{width:13.333in;height:7.5in;aspect-ratio:auto;border-radius:0;box-shadow:none;
 page-break-after:always;break-after:page}.nav,.progress{display:none}.kicker{background:none;color:#2f9e8f}.cover,.road .ph.now,.bar,.ring{-webkit-print-color-adjust:exact;print-color-adjust:exact}}
"""

JS = r"""
var S=[].slice.call(document.querySelectorAll('.slide')),i=0;
function aller(n){i=Math.max(0,Math.min(S.length-1,n));S[i].scrollIntoView({behavior:'smooth',block:'center'});maj()}
function maj(){document.querySelector('.progress').style.width=((i+1)/S.length*100)+'%'}
document.addEventListener('keydown',function(e){if(e.key==='ArrowRight'||e.key==='PageDown'||e.key===' '){e.preventDefault();aller(i+1)}
 else if(e.key==='ArrowLeft'||e.key==='PageUp'){e.preventDefault();aller(i-1)}else if(e.key==='f'||e.key==='F'){if(!document.fullscreenElement)document.documentElement.requestFullscreen();else document.exitFullscreen()}
 else if(e.key==='Home')aller(0);else if(e.key==='End')aller(S.length-1)});
var o=new IntersectionObserver(function(es){es.forEach(function(x){if(x.isIntersecting&&x.intersectionRatio>.55){i=S.indexOf(x.target);maj()}})},{threshold:[.55]});
S.forEach(function(s){o.observe(s)});maj();
"""


def logo_b64(nom, dossier):
    for d in (dossier, os.path.join(ICI, 'assets')):
        if d and os.path.isfile(os.path.join(d, nom)):
            with open(os.path.join(d, nom), 'rb') as f:
                return 'data:image/png;base64,' + base64.b64encode(f.read()).decode('ascii')
    return None


def pill(statut, libelle=None):
    lib, ic, c = STATUTS.get(statut, STATUTS['na'])
    if not (libelle or lib):
        return ''
    return '<span class="pill"><i style="color:%s;font-style:normal">%s</i>%s</span>' % (c, ic or '•', esc(libelle or lib))


def spark(v, statut):
    if len(v) < 2:
        return ''
    lo, hi = min(v), max(v)
    hi = hi if hi > lo else lo + 1
    pts = ' '.join('%.1f,%.1f' % (i * 200.0 / (len(v) - 1), 23 - (x - lo) / (hi - lo) * 20) for i, x in enumerate(v))
    c = STATUTS.get(statut, STATUTS['na'])[2] if statut not in ('na', None) else '#42a296'
    return '<svg viewBox="0 0 200 26" preserveAspectRatio="none" aria-hidden="true"><polyline fill="none" stroke="%s" stroke-width="2" vector-effect="non-scaling-stroke" points="%s"/></svg>' % (c, pts)


def rendre(m, sortie, logos_dir=None, client='Scania France'):
    ls, li = logo_b64('logo_scania.png', logos_dir), logo_b64('logo_irium.png', logos_dir)
    img = lambda src, alt: '<img src="%s" alt="%s">' % (src, alt) if src else '<b>%s</b>' % alt
    slides = []
    total = [0]

    def diapo(kicker, titre, lead, corps, classe=''):
        total[0] += 1
        slides.append(('<section class="slide %s"><div class="top"><span class="kicker">%s</span><div class="logos">%s%s</div></div>'
                       '<h2>%s</h2>%s<div class="body">%s</div><div class="foot"><span>%s · Audit de l\'infrastructure IRIUM · confidentiel</span><span>%%d</span></div>'
                       '<div class="bar"></div></section>') % (classe, esc(kicker), img(ls, 'Scania'), img(li, 'IRIUM'), esc(titre),
                                                              ('<p class="lead">%s</p>' % lead) if lead else '', corps, esc(client)))
    # 1. couverture
    cov = ('<section class="slide cover"><div class="brands"><span>%s</span><span>%s</span></div><h1>Audit de performance<br>de l\'infrastructure IRIUM</h1>'
           '<div class="st">Base %s · serveur %s · constats mesurés, priorités et feuille de route vers RHEL 9</div>'
           '<div class="meta"><div><b>Client</b>%s</div><div><b>Date</b>%s</div><div><b>Mesures</b>%s</div>%s</div>'
           '<div class="conf">Document confidentiel</div></section>') % (
        img(ls, 'Scania'), img(li, 'IRIUM'), esc(dict(m['perimetre']).get('Base analysée', '')), esc(m['bdd']), esc(client), esc(date_longue(m['date'])),
        esc(m['periode']), ('<div><b>Campagne</b>%s</div>' % esc(m['campagne'])) if m.get('campagne') else '')
    # 2. sommaire
    diapo('Sommaire', 'Ce que nous allons partager', '', '<div class="grid2"><ul class="points">%s</ul><ul class="points">%s</ul></div>' % (
        ''.join('<li>%s</li>' % x for x in ('Contexte et méthode', 'Synthèse et indice de santé', 'Indicateurs clés', 'Constats majeurs', 'Base Informix : objets les plus coûteux')),
        ''.join('<li>%s</li>' % x for x in ('Obsolescence et risques', 'Pourquoi passer à RHEL 9', 'Plan d\'actions', 'Feuille de route et infrastructure cible', 'Décisions attendues'))))
    # 3. contexte
    diapo('Contexte et méthode', 'Un audit mesuré, en lecture seule', 'Mesures prises sur le serveur de production pendant l\'activité réelle, '
          'sans aucune modification du système ni de la base.',
          '<div class="grid2"><div class="card soft"><h3>Périmètre</h3><dl class="kv">%s</dl></div><div class="card"><h3>Méthode</h3><ul class="points">%s</ul></div></div>' % (
              ''.join('<dt>%s</dt><dd>%s</dd>' % (esc(k), esc(v)) for k, v in m['perimetre']),
              ''.join('<li>%s</li>' % x for x in (
                  'Système : CPU, mémoire, disques, réseau, pression mémoire du noyau, services',
                  'Moteur Informix : cache, verrous, checkpoints, mutex, vitesse des chunks, sessions',
                  'Base : tables et index les plus coûteux, statistiques, requêtes SQL',
                  'Application : programmes IRIUM lancés (journal agr_lds)',
                  'Période mesurée : %s%s' % (esc(m['periode']), (' (%d min)' % m['duree_min']) if m.get('duree_min') else '')))))
    # 4. synthèse
    st = m['etat']
    pourc = max(0, min(100, m['score']))
    prio = ''.join('<div><em style="color:%s">%s</em><b>%d</b><span>%s</span></div>' % (STATUTS[GRAV_PRIO[p]][2] if p != 'P3' else '#7d8f8f', p, m['prio'].get(p, 0), l)
                   for p, l in (('Immédiat', 'risque d\'incident'), ('P1', 'effet majeur sur la charge'), ('P2', 'effet significatif'), ('P3', 'amélioration')))
    majeurs = [x for x in m['plan'] if x['prio'] in ('Immédiat', 'P1')][:5]
    diapo('Synthèse', 'Indice de santé de l\'infrastructure', '',
          '<div class="grid2" style="grid-template-columns:auto 1fr;align-items:center"><div class="score"><div class="ring" style="--p:%d;--c:%s"><div><span><b>%d</b><small>sur 100</small></span></div></div>'
          '<div>%s<p class="small" style="max-width:240px">%s</p></div></div><div><div class="prio">%s</div><h3 style="margin:18px 0 0;color:#0c3636">Points majeurs</h3><ul class="points">%s</ul></div></div>' % (
              pourc, STATUTS[st][2], m['score'], pill(st), ' · '.join('%s : %d' % (esc(n), v) for n, v in sorted(m['scores'].items())) or
              'Indice calculé à partir des indicateurs mesurés et du support du système.', prio,
              ''.join('<li><b>%s</b> <span class="small">· %s</span></li>' % (esc(x['constat']), esc(x['prio'])) for x in majeurs) or '<li>Aucun point majeur</li>'))
    # 5. indicateurs clés (8 au plus, les plus significatifs d'abord)
    ordre = {'critique': 0, 'degrade': 1, 'vigilance': 2, 'bon': 3, 'na': 4}
    kp = sorted(m['kpis'], key=lambda k: ordre.get(k['statut'], 5))[:8]
    diapo('Indicateurs clés', 'Ce que disent les mesures', 'Statut de chaque indicateur au regard des seuils usuels d\'exploitation.',
          '<div class="kpis">%s</div>' % ''.join(
              '<div class="kpi"><span class="cat">%s</span><span class="l">%s%s</span><span class="v">%s<small>%s</small></span>%s%s<span class="m">%s</span></div>' % (
                  esc(k['cat']), esc(k['libelle']), (' · <b>%s</b>' % esc(k['serveur'])) if k.get('serveur') else '', esc(k['v']), esc(k['unite']), pill(k['statut']),
                  spark(k['spark'], k['statut']), esc(k['seuil'] + ((' · ' + k['detail']) if k.get('detail') else ''))) for k in kp))
    # 6. constats majeurs
    top = [x for x in m['plan'] if x['prio'] in ('Immédiat', 'P1')][:4] or m['plan'][:4]
    diapo('Constats majeurs', 'Les causes de charge identifiées', 'Classées par effet attendu ; chaque constat est appuyé par une mesure.',
          ''.join('<div class="finding"><div>%s<div class="small" style="margin-top:6px">%s</div></div><div><h4>%s</h4><p>%s</p><p><b>Action :</b> %s</p></div></div>' % (
              pill(x['grav'], x['prio']), esc(x['nature']), esc(x['constat']), esc(raccourcir(nettoyer(x['preuve']), 150)), esc(raccourcir(x['action'], 150))) for x in top))
    # 7. objets Informix : lectures physiques et scans coûteux (plus parlants que le nombre brut de scans)
    objets = [o for o in m['objets'] if o[0].lower().startswith('lectures physiques')][:1]
    sc = scans_couteux(m['plan'])
    objets += [sc] if sc else [o for o in m['objets'] if not o[0].lower().startswith('lectures physiques')][:1]
    m = dict(m, objets=objets)
    if m['objets']:
        blocs = ''.join('<div class="card"><h3>%s</h3><table><tr>%s</tr>%s</table></div>' % (
            esc(t.capitalize()), ''.join('<th>%s</th>' % esc(e) for e in ent), ''.join('<tr>%s</tr>' % ''.join(('<td><b>%s</b></td>' if j == 0 else '<td>%s</td>') % esc(c)
                                                                                                     for j, c in enumerate(l)) for l in lignes[:5]))
            for t, ent, lignes in m['objets'][:2])
        diapo('Base Informix', 'Où part la charge de la base', 'Quelques tables concentrent l\'essentiel des lectures : le levier principal est '
              'dans les requêtes et l\'indexation.', '<div class="grid2">%s</div>' % blocs)
    # 8. obsolescence : chiffres clés puis détail par serveur
    o0 = next((o for o in m['obso'] if o['statut'] == 'critique'), m['obso'][0] if m['obso'] else None)
    cles = []
    if o0:
        mo = re.search(r'depuis (\d+) mois', o0['support'])
        els = re.search(r'jusqu\'au (\d\d/\d\d/\d{4})', o0['support'])
        ver = re.search(r'release (\d+\.\d+)', o0['systeme'])
        if mo:
            cles.append((mo.group(1) + ' mois', 'hors maintenance standard Red Hat (%s)' % ('RHEL ' + ver.group(1) if ver else o0['systeme'])))
        if els:
            cles.append((els.group(1), 'fin du support étendu payant (ELS) : plus aucun correctif après cette date'))
        noy = re.match(r'(\d+\.\d+)', o0['noyau'] or '')
        if noy:
            cles.append(('Noyau ' + noy.group(1), 'contre 5.14 sur RHEL 9 ; Python %s par défaut' % ('2.7' if '2.7' in o0['python'] else o0['python'])))
    titre_obso = 'Un socle système hors support' if o0 and o0['statut'] == 'critique' else 'Cycle de vie du socle système'
    diapo('Obsolescence et risques', titre_obso, '',
          ('<div class="grid3" style="margin-bottom:18px">%s</div>' % ''.join('<div class="card soft"><div style="font-size:34px;font-weight:750;color:#0c3636;line-height:1.1">%s</div>'
                                                                           '<div class="small" style="margin-top:6px">%s</div></div>' % (esc(a), esc(b)) for a, b in cles) if cles else '') +
          '<table><tr><th>Serveur</th><th>Système</th><th>Support</th><th>Correctifs</th><th>Abonnement / dépôts</th><th>Informix</th></tr>%s</table>' % ''.join(
              '<tr><td><b>%s</b><div class="small">%s</div></td><td>%s<div class="small">noyau %s</div></td><td>%s<div class="small">%s</div></td><td>%s</td><td>%s</td><td>%s</td></tr>' % (
                  esc(o['serveur']), esc(o['role']), esc(o['systeme']), esc(o['noyau']), pill(o['statut']), esc(o['support']), esc(o['correctifs']), esc(o['abonnement']),
                  esc(o['informix'])) for o in m['obso']))
    # 9. RHEL 9
    if m['arg']:
        diapo('Modernisation', 'Pourquoi passer à RHEL 9', 'Chaque ligne part d\'un constat mesuré pendant l\'audit.',
              '<table><tr><th>Domaine</th><th>Constat mesuré</th><th>Apport de RHEL 9</th><th>Gain attendu</th></tr>%s</table>'
              '<p class="small" style="margin-top:10px">Prérequis : version d\'Informix certifiée RHEL 9 et validation de l\'éditeur IRIUM.</p>' % ''.join(
                  '<tr><td><b>%s</b></td><td>%s</td><td>%s</td><td>%s</td></tr>' % (esc(a[0]), esc(raccourcir(a[1], 160)), esc(raccourcir(a[3], 170)), esc(a[4])) for a in m['arg'][:5]))
    # 10. plan d'actions
    pa = [x for x in m['plan'] if x['prio'] in ('Immédiat', 'P1', 'P2')][:7]
    diapo('Plan d\'actions', 'Priorités recommandées', '%d action(s) au total : %d immédiate(s), %d P1, %d P2, %d P3. Le plan complet est dans le rapport d\'audit.' % (
        len(m['plan']), m['prio'].get('Immédiat', 0), m['prio'].get('P1', 0), m['prio'].get('P2', 0), m['prio'].get('P3', 0)),
          '<table><tr><th>Priorité</th><th>Constat</th><th>Action</th><th>Nature</th></tr>%s</table>' % ''.join(
              '<tr><td>%s</td><td><b>%s</b></td><td class="small">%s</td><td class="small">%s</td></tr>' % (
                  pill(x['grav'], x['prio']), esc(x['constat']), esc(raccourcir(x['action'], 115)), esc(x['nature'])) for x in pa))
    # 11. feuille de route
    imm = [x['constat'] for x in m['plan'] if x['prio'] in ('Immédiat', 'P1')][:4]
    phases = [('Phase 0', 'Tout de suite', imm or ['Aucune action urgente'], True),
              ('Phase 1', 'Maquette', ['Serveurs RHEL 9 conformes aux prérequis transmis', 'Informix en version certifiée RHEL 9', 'Audit de référence'], False),
              ('Phase 2', 'Recette', ['Recette IRIUM avec l\'éditeur', 'Tests de charge des traitements critiques'], False),
              ('Phase 3', 'Bascule', ['Nouveau serveur en secondaire de %s, synchronisé' % m['bdd'], 'Bascule des rôles en fenêtre courte', 'Ancien serveur en secours'], False),
              ('Phase 4', 'Mesure', ['Même campagne d\'audit', 'Comparaison avant / après'], False)]
    diapo('Feuille de route', 'De la correction immédiate à RHEL 9', '',
          '<div class="road">%s</div><div class="card soft" style="margin-top:18px"><h3>Infrastructure cible</h3><p style="margin:0">L\'architecture cible et les prérequis ont été '
          'transmis séparément : la nouvelle infrastructure devra <b>les respecter</b>. Les mesures de cet audit serviront de référence pour la valider.</p></div>' % ''.join(
              '<div class="ph%s"><b>%s</b><h4>%s</h4><ul>%s</ul></div>' % (' now' if now else '', esc(a), esc(b), ''.join('<li>%s</li>' % esc(raccourcir(x, 70)) for x in l))
              for a, b, l, now in phases))
    # 12. décisions
    dec = [('Lancer les actions immédiates', '; '.join(imm[:2]) or 'Aucune action urgente identifiée'),
           ('Valider la migration vers RHEL 9', 'Sur la base de l\'architecture et des prérequis transmis'),
           ('Planifier la maquette et la recette', 'Avec l\'éditeur IRIUM et une version d\'Informix certifiée RHEL 9'),
           ('Programmer une campagne de mesure complète', 'Une matinée chargée, tous les serveurs : elle servira de référence avant / après')]
    diapo('Prochaines étapes', 'Décisions attendues', '', ''.join(
        '<div class="decision"><i>%d</i><div><h4>%s</h4><p>%s</p></div></div>' % (n + 1, esc(a), esc(b)) for n, (a, b) in enumerate(dec)))
    pages = [cov] + [s.replace('<span>%d</span>', '<span>%d / %d</span>' % (n + 2, total[0] + 1)) for n, s in enumerate(slides)]
    page = ('<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
            '<title>Audit infrastructure IRIUM — %s</title><style>%s</style></head><body><div class="progress"></div><main class="deck">%s</main>'
            '<div class="nav"><button type="button" onclick="aller(i-1)" aria-label="Diapositive précédente">←</button><button type="button" onclick="aller(i+1)" aria-label="Diapositive suivante">→</button>'
            '<button type="button" onclick="window.print()">PDF</button></div><script>%s</script></body></html>') % (esc(client), CSS, ''.join(pages), JS)
    with io.open(sortie, 'w', encoding='utf-8') as f:
        f.write(page)
    return total[0] + 1


def nettoyer(t):
    """Corrige les mentions erronées des rapports antérieurs (hit ratio 0 %, espace libre arrondi à 0)."""
    t = re.sub(r',\s*hit ratio 0 %', '', t or '')
    return re.sub(r'(?<![\d,.])0[.,]0 % d\'espace libre', '< 0,1 % d\'espace libre', t)


def scans_couteux(plan):
    """Tableau des scans coûteux, d'après les preuves du constat « Scans séquentiels coûteux »."""
    x = next((x for x in plan if x['constat'].startswith('Scans séquentiels coûteux')), None)
    if not x:
        return None
    lignes = [list(m) for m in re.findall(r'(\w+) : ([\d,. ]+[kMd]*) scans × ([\d,. ]+[kMd]*) pages, ([\d,. ]+[kMd]*) demandes de verrou', x['preuve'])]
    return ('Scans séquentiels coûteux', ['Table', 'Scans', 'Pages par scan', 'Demandes de verrou'], lignes) if lignes else None


def raccourcir(t, n):
    t = re.sub(r'\s+', ' ', t or '').strip()
    return t if len(t) <= n else t[:n].rsplit(' ', 1)[0] + ' …'


def main():
    ra.sortie_utf8()
    p = argparse.ArgumentParser(description='Présentation client (diaporama HTML) aux couleurs IRIUM')
    p.add_argument('sources', nargs='*', help='Dossier de campagne, dossier ou archive d\'audit')
    p.add_argument('--html', nargs=2, metavar=('RAPPORT', 'DASHBOARD'), help='Partir des deux pages HTML générées (rapport puis tableau de bord)')
    p.add_argument('--client', default='Scania France')
    p.add_argument('--logos', help='Dossier contenant logo_scania.png et logo_irium.png (défaut : assets/)')
    p.add_argument('-o', '--sortie', default=os.path.join(ICI, 'presentation_%s.html' % dt.datetime.now().strftime('%Y%m%d_%H%M')))
    a = p.parse_args()
    if os.path.isdir(a.sortie):
        a.sortie = os.path.join(a.sortie, 'presentation_%s.html' % dt.datetime.now().strftime('%Y%m%d_%H%M'))
    if a.html:
        m = modele_html(a.html[0], a.html[1])
    else:
        if not a.sources:
            p.error('indiquer un dossier d\'audit / de campagne, ou --html RAPPORT DASHBOARD')
        try:
            tmp = tempfile.mkdtemp(prefix='.presentation_tmp_', dir=os.path.dirname(os.path.abspath(a.sortie)))
        except (IOError, OSError):
            tmp = tempfile.mkdtemp(prefix='presentation_')
        try:
            serveurs, campagne = dk.charger_sources(a.sources, tmp)
            if not serveurs:
                sys.exit('Aucun audit valide.')
            m = modele_audit(serveurs, campagne)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    n = rendre(m, a.sortie, a.logos, a.client)
    print('Présentation : %s (%d diapositives)' % (os.path.abspath(a.sortie), n))


if __name__ == '__main__':
    main()
