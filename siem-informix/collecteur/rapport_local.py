#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Rapport SIEM local (sans portail) : à partir de l'archive d'événements constituée par la collecte locale,
génère un rapport HTML autonome (un seul fichier, à ouvrir dans un navigateur ou à envoyer) et un CSV.

Contenu : indicateurs, activité par jour, alertes, comptes partagés, adresses IP, sessions (connexion,
déconnexion, durée), fiche par utilisateur, opérations sensibles en base, programmes lancés, chronologie.

Les programmes de la table applicative (agr_lds) sans adresse IP sont rattachés au poste par corrélation
terminal : même pts/N qu'une session ouverte depuis ce poste, à la même heure.

Usage (Python système suffisant) :
  /usr/libexec/platform-python rapport_local.py                                  # 30 derniers jours, tout
  /usr/libexec/platform-python rapport_local.py --depuis 2026-09-01 --jusqua 2026-09-30
  /usr/libexec/platform-python rapport_local.py --ip 10.12.4.21                  # un poste
  /usr/libexec/platform-python rapport_local.py --utilisateur jdupont            # une personne
"""
from __future__ import print_function

import argparse
import csv
import datetime as dt
import glob
import gzip
import html
import io
import json
import os
import re
import shutil
import socket

ICI = os.path.dirname(os.path.abspath(__file__))
RE_TERMINAL = re.compile(r'^(?:/dev/)?((?:pts/\d+)|(?:tty\w*\d+))$')
VOLETS = [('systeme', 'Système', '#2a78d6'), ('base', 'Base', '#eb6834'), ('applicatif', 'Applicatif', '#1baf7a')]
GRAVITES = {'critique': (0, '#d03b3b', '⬣'), 'haute': (1, '#ec835a', '◆'), 'moyenne': (2, '#fab219', '▲'), 'faible': (3, '#8a8a84', 'ℹ')}


# --------------------------------------------------------------------------------------------
# Lecture de l'archive
# --------------------------------------------------------------------------------------------
def lire_archive(dossier, debut, fin):
    vus, evts = set(), []
    for f in sorted(glob.glob(os.path.join(dossier, 'evenements-*.jsonl*'))):
        ouvrir = gzip.open if f.endswith('.gz') else io.open
        with ouvrir(f, 'rt', encoding='utf-8', errors='replace') as fh:
            for ligne in fh:
                try:
                    e = json.loads(ligne)
                    ts = dt.datetime.strptime(e['ts'][:19], '%Y-%m-%dT%H:%M:%S')
                except (ValueError, KeyError):
                    continue
                cle = e.get('empreinte') or ligne
                if cle in vus:
                    continue
                vus.add(cle)
                e['_ts'] = ts
                evts.append(e)
    evts.sort(key=lambda e: e['_ts'])
    couverture = (evts[0]['_ts'], evts[-1]['_ts']) if evts else None
    # on garde un peu avant la période pour retrouver les sessions déjà ouvertes au début
    marge = debut - dt.timedelta(days=2)
    return [e for e in evts if marge <= e['_ts'] <= fin], couverture


def lire_postes(chemin):
    postes = {}
    if chemin and os.path.exists(chemin):
        with io.open(chemin, encoding='utf-8-sig') as f:
            for l in f:
                p = [x.strip() for x in l.strip().split(';')]
                if len(p) >= 2 and p[0] and not p[0].lower().startswith('ip'):
                    postes[p[0]] = (p[1], p[2] if len(p) > 2 else '')
    return postes


# --------------------------------------------------------------------------------------------
# Enrichissement : sessions, corrélation terminal, attribution
# --------------------------------------------------------------------------------------------
def construire_sessions(evts):
    sessions = {}
    for e in evts:
        sid = e.get('session') or ''
        if e['categorie'] == 'connexion' and sid:
            sessions[sid] = {'id': sid, 'debut': e['_ts'], 'fin': None, 'source': e['source'], 'compte': e.get('compte', ''),
                             'utilisateur': e.get('utilisateur', ''), 'ip': e.get('ip', ''), 'poste': e.get('poste', ''),
                             'terminal': (e.get('details') or {}).get('terminal', ''), 'operations': 0, 'action': e['action']}
        elif e['categorie'] == 'deconnexion' and sid in sessions and not sessions[sid]['fin']:
            sessions[sid]['fin'] = e['_ts']
        elif sid in sessions:
            sessions[sid]['operations'] += 1
    return sorted(sessions.values(), key=lambda s: s['debut'])


def correler_terminal(evts, sessions):
    ssh = [s for s in sessions if s['source'] == 'systeme' and RE_TERMINAL.match(s['terminal'] or '')]
    n = 0
    for e in evts:
        if e['source'] != 'applicatif' or e.get('ip'):
            continue
        terms = [RE_TERMINAL.match(str(v).strip()) for v in (e.get('details') or {}).values() if isinstance(v, str)]
        terms = [t.group(1) for t in terms if t]
        if not terms:
            continue
        for s in ssh:
            if s['terminal'] == terms[0] and s['debut'] <= e['_ts'] <= (s['fin'] or dt.datetime.now()):
                e['ip'], e['poste'], e['_lien'] = s['ip'], s['poste'], 'terminal %s de la session ouverte à %s' % (
                    s['terminal'], s['debut'].strftime('%d/%m %H:%M'))
                if not e.get('utilisateur'):
                    e['utilisateur'] = s['utilisateur']
                n += 1
                break
    return n


def attribuer(evts, partages, postes):
    for e in evts:
        u = (e.get('utilisateur') or '').strip()
        if u and u.lower() not in partages:
            e['_personne'], e['_attr'] = u, 'certaine'
        elif e.get('ip') in postes:
            e['_personne'], e['_attr'] = postes[e['ip']][0], 'probable'
        else:
            e['_personne'], e['_attr'] = (u or e.get('compte') or 'inconnu'), 'compte'


def hors_heures(d, h1, h2):
    return d.weekday() >= 5 or not (h1 <= d.hour < h2)


def alertes(evts, partages, h1, h2):
    res, echecs = [], {}
    for e in evts:
        compte = (e.get('compte') or '').lower()
        quand, hh = e['_ts'], hors_heures(e['_ts'], h1, h2)
        qui = e['_personne'] + (' (probable)' if e['_attr'] == 'probable' else '' if e['_attr'] == 'certaine' else ' (non identifié)')
        cle = (e.get('details') or {}).get('cle', '') if isinstance(e.get('details'), dict) else ''
        # côté base, l'application se connecte normalement avec le compte partagé : alerte seulement hors heures
        if compte in partages and e['categorie'] in ('connexion', 'changement_compte', 'sudo') and \
                ((e['source'] == 'systeme' and e['_attr'] != 'certaine') or hh):
            res.append((quand, 'haute' if hh or e['_attr'] == 'compte' else 'moyenne',
                        'Compte partagé %s utilisé%s' % (e['compte'], ' hors heures ouvrées' if hh else ''),
                        '%s depuis %s : %s' % (qui, e.get('ip') or 'origine inconnue', e['action']), e))
        if e['source'] == 'base' and e['categorie'] in ('ddl', 'droits'):
            supp = e['action'].startswith('Suppression') or 'REVOKE' in e['action']
            res.append((quand, 'critique' if supp and hh else 'haute' if supp or e['categorie'] == 'droits' else 'moyenne',
                        '%s : %s' % (e['action'], e.get('objet', '')), '%s (compte %s)' % (qui, e.get('compte')), e))
        if cle in ('siem_identite', 'siem_sudoers', 'siem_conf_informix'):
            res.append((quand, 'haute', e['action'], '%s : %s' % (qui, e.get('objet', '')), e))
        if e['categorie'] == 'echec_connexion' and e.get('ip'):
            liste = [t for t in echecs.get(e['ip'], []) if (quand - t).total_seconds() <= 600] + [quand]
            echecs[e['ip']] = liste
            if len(liste) == 5:
                res.append((quand, 'haute', 'Échecs de connexion répétés depuis %s' % e['ip'],
                            '5 échecs en 10 minutes (dernier compte : %s)' % e.get('compte'), e))
        if e['categorie'] == 'connexion' and hh and e['source'] in ('systeme', 'base') and compte not in partages:
            res.append((quand, 'faible', 'Connexion hors heures ouvrées', '%s depuis %s' % (qui, e.get('ip') or '-'), e))
    res.sort(key=lambda a: (GRAVITES[a[1]][0], -a[0].timestamp()))
    return res


# --------------------------------------------------------------------------------------------
# HTML
# --------------------------------------------------------------------------------------------
def esc(v):
    return html.escape('' if v is None else str(v))


def fr(d, sec=False):
    return d.strftime('%d/%m/%Y %H:%M:%S' if sec else '%d/%m/%Y %H:%M') if d else ''


def duree(s):
    if not s['fin']:
        return 'en cours'
    m = int((s['fin'] - s['debut']).total_seconds() // 60)
    return '%dh%02d' % (m // 60, m % 60)


def tableau(entetes, lignes, cls='', vide='Aucune donnée sur la période.'):
    if not lignes:
        return '<p class="vide">%s</p>' % vide
    return ('<div class="tw"><table class="filtrable %s"><thead><tr>%s</tr></thead><tbody>%s</tbody></table></div>'
            % (cls, ''.join('<th>%s</th>' % esc(h) for h in entetes),
               ''.join('<tr>%s</tr>' % ''.join('<td>%s</td>' % c for c in l) for l in lignes)))


def badge_volet(v):
    d = {k: (n, col) for k, n, col in VOLETS}.get(v, (v, '#999'))
    return '<span class="b"><i style="background:%s"></i>%s</span>' % (d[1], esc(d[0]))


def badge_gravite(g):
    _o, col, ico = GRAVITES[g]
    return '<span class="b g-%s"><i style="background:%s"></i>%s %s</span>' % (g, col, ico, g.capitalize())


def attr(e):
    return '' if e['_attr'] == 'certaine' else ' <span class="b pa">%s</span>' % ('probable (poste)' if e['_attr'] == 'probable' else 'non identifiée')


def graphique(evts, debut, fin):
    jours = []
    d = debut.date()
    while d <= fin.date():
        jours.append(d)
        d += dt.timedelta(days=1)
    par = {}
    for e in evts:
        par.setdefault(e['_ts'].date(), {}).setdefault(e['source'], 0)
        par[e['_ts'].date()][e['source']] += 1
    mx = max([sum(v.values()) for v in par.values()] + [1])
    L, H, g = 900, 200, 42
    w = (L - g) / max(1, len(jours))
    bw = max(2, min(24, w - 2))
    s = ['<svg viewBox="0 0 %d %d" role="img" aria-label="Activité par jour">' % (L, H + 24)]
    for i in range(5):
        y = H - (H - 10) * i / 4
        s.append('<line x1="%d" x2="%d" y1="%.1f" y2="%.1f" stroke="#e3e4e8"/><text x="%d" y="%.1f" text-anchor="end" class="ax">%d</text>'
                 % (g, L, y, y, g - 6, y + 4, round(mx * i / 4)))
    for i, j in enumerate(jours):
        x, y = g + i * w + (w - bw) / 2, H
        vals = par.get(j, {})
        titre = '%s : %s' % (j.strftime('%d/%m'), ', '.join('%s %d' % (n, vals.get(k, 0)) for k, n, _c in VOLETS))
        for k, _n, col in VOLETS:
            v = vals.get(k, 0)
            if v:
                h = (H - 10) * v / mx
                s.append('<rect x="%.1f" y="%.1f" width="%.1f" height="%.1f" fill="%s" rx="2"><title>%s</title></rect>'
                         % (x, y - h, bw, max(1, h - 2), col, esc(titre)))
                y -= h
        if len(jours) <= 12 or i % max(1, len(jours) // 8) == 0:
            s.append('<text x="%.1f" y="%d" text-anchor="middle" class="ax">%s</text>' % (x + bw / 2, H + 16, j.strftime('%d/%m')))
    s.append('<line x1="%d" x2="%d" y1="%d" y2="%d" stroke="#999"/></svg>' % (g, L, H, H))
    leg = ''.join('<span><i style="background:%s"></i>%s</span>' % (c, n) for _k, n, c in VOLETS)
    return '<div class="leg">%s</div>%s' % (leg, ''.join(s))


CSS = """*{box-sizing:border-box}body{margin:0;font:14px/1.45 "Segoe UI",Arial,sans-serif;color:#16181d;background:#f4f5f7}
header{background:#111;color:#fff;padding:22px 32px;border-bottom:4px solid #ffc50c}header h1{margin:0 0 6px;font-size:22px}
header .m{display:flex;flex-wrap:wrap;gap:4px 24px;font-size:13px;opacity:.85}main{max-width:1320px;margin:0 auto;padding:18px 32px 40px}
nav.sommaire{display:flex;flex-wrap:wrap;gap:6px;margin:0 0 16px}nav.sommaire a{background:#fff;border:1px solid #dfe1e5;border-radius:14px;padding:4px 12px;color:#16181d;text-decoration:none;font-size:13px}
nav.sommaire a:hover{border-color:#111}
.k{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-bottom:16px}
.c{background:#fff;border:1px solid #dfe1e5;border-radius:8px;padding:12px 16px}.c .v{font-size:25px;font-weight:700}.c .l{color:#52514e;font-size:12.5px}.c.r .v{color:#d03b3b}
section{background:#fff;border:1px solid #dfe1e5;border-radius:8px;padding:16px 20px;margin-bottom:16px}
h2{font-size:16px;margin:0 0 10px;display:flex;gap:10px;align-items:center}h2 small{font-weight:400;color:#6b6b66;font-size:12.5px}
.tw{overflow-x:auto;max-height:560px;overflow-y:auto}table{width:100%;border-collapse:collapse;font-size:13px}
th{background:#111;color:#fff;text-align:left;padding:7px 8px;white-space:nowrap;position:sticky;top:0}td{padding:6px 8px;border-bottom:1px solid #e6e7ea;vertical-align:top}
tbody tr:nth-child(even) td{background:#fafafa}tbody tr:hover td{background:#fff8e1}.mono{font-family:Consolas,monospace;font-size:12.5px;overflow-wrap:anywhere}
.d{color:#6b6b66;font-size:12px}.e{color:#b3261e;font-weight:600}.vide{color:#6b6b66}
.b{display:inline-flex;align-items:center;gap:5px;padding:1px 8px;border-radius:10px;font-size:11.5px;background:#f0f1f3;border:1px solid #dfe1e5;white-space:nowrap}
.b i,.leg i{width:8px;height:8px;border-radius:50%;display:inline-block}.pa{border-style:dashed}.g-critique{font-weight:700}
.leg{display:flex;gap:16px;font-size:12.5px;color:#52514e;margin-bottom:6px}.leg span{display:inline-flex;align-items:center;gap:6px}
svg{width:100%;height:auto}.ax{fill:#7a7a76;font-size:11px}
.avert{background:#fff8e1;border:1px solid #f3d27a;border-radius:8px;padding:10px 14px;margin-bottom:16px;font-size:13px}
.filtre{width:100%;max-width:420px;padding:7px 10px;border:1px solid #dfe1e5;border-radius:6px;margin-bottom:8px;font:inherit}
details.fiche{border:1px solid #dfe1e5;border-radius:8px;margin-bottom:8px}details.fiche>summary{padding:9px 12px;cursor:pointer;background:#fafafa;border-radius:8px;display:flex;gap:16px;flex-wrap:wrap}
details.fiche[open]>summary{border-bottom:1px solid #dfe1e5;border-radius:8px 8px 0 0}details.fiche .in{padding:10px 12px}
.g2{display:grid;grid-template-columns:repeat(auto-fit,minmax(380px,1fr));gap:12px}
@media print{body{background:#fff}header{-webkit-print-color-adjust:exact;print-color-adjust:exact}.tw{max-height:none}.filtre,nav.sommaire{display:none}details.fiche{break-inside:avoid}}
@media (max-width:700px){main,header{padding-left:14px;padding-right:14px}}"""

JS = """document.querySelectorAll('input.filtre').forEach(function(i){var t=document.getElementById(i.dataset.t);
i.addEventListener('input',function(){var q=i.value.toLowerCase();t.querySelectorAll('tbody tr').forEach(function(r){
r.style.display=!q||r.textContent.toLowerCase().indexOf(q)>=0?'':'none'})})});"""


def generer(evts, sessions, debut, fin, titre, sous_titre, couverture, al, partages, n_corr, serveur):
    periode = [e for e in evts if debut <= e['_ts'] <= fin]
    ses_p = [s for s in sessions if s['debut'] <= fin and (s['fin'] or dt.datetime.now()) >= debut]
    personnes = {}
    for e in periode:
        personnes.setdefault(e['_personne'], []).append(e)
    ips = {}
    for e in periode:
        if e.get('ip') and e['ip'] != 'local':
            ips.setdefault(e['ip'], []).append(e)
    sensibles = [e for e in periode if e['source'] == 'base' and e['categorie'] in ('ddl', 'droits', 'dml', 'admin')]
    programmes = [e for e in periode if e['source'] == 'applicatif']
    commandes = [e for e in periode if e['categorie'] in ('sudo', 'commande', 'changement_compte', 'fichier')]
    partage = [e for e in periode if (e.get('compte') or '').lower() in partages and e['categorie'] in ('connexion', 'changement_compte', 'sudo')]
    al_p = [a for a in al if debut <= a[0] <= fin]
    o = ['<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
         '<title>%s</title><style>%s</style></head><body>' % (esc(titre), CSS)]
    o.append('<header><h1>%s</h1><div class="m"><span><b>Serveur :</b> %s</span><span><b>Période :</b> du %s au %s</span>%s'
             '<span><b>Généré le :</b> %s</span></div></header><main>'
             % (esc(titre), esc(serveur), debut.strftime('%d/%m/%Y'), fin.strftime('%d/%m/%Y'),
                ('<span>%s</span>' % esc(sous_titre)) if sous_titre else '', dt.datetime.now().strftime('%d/%m/%Y %H:%M')))
    o.append('<nav class="sommaire">%s</nav>' % ''.join('<a href="#%s">%s</a>' % (a, b) for a, b in [
        ('alertes', 'Alertes'), ('activite', 'Activité'), ('partages', 'Comptes partagés'), ('ip', 'Adresses IP'),
        ('sessions', 'Sessions'), ('personnes', 'Utilisateurs'), ('base', 'Opérations base'), ('programmes', 'Programmes'),
        ('commandes', 'Commandes / sudo'), ('chrono', 'Chronologie')]))
    if couverture and couverture[0] > debut:
        o.append('<div class="avert"><b>Couverture :</b> l\'archive commence le %s. Les événements antérieurs ne sont pas disponibles '
                 '(rotation des journaux avant la mise en place de la collecte).</div>' % fr(couverture[0]))
    o.append('<div class="k">%s</div>' % ''.join('<div class="c%s"><div class="v">%s</div><div class="l">%s</div></div>' % (r, v, l) for v, l, r in [
        (len(periode), 'Événements', ''), (len(personnes), 'Personnes / comptes', ''), (len(ses_p), 'Sessions', ''),
        (len(ips), 'Adresses IP', ''), (len(partage), 'Utilisations comptes partagés', ''), (len(sensibles), 'Opérations base auditées', ''),
        (len(programmes), 'Programmes lancés', ''), (len([a for a in al_p if a[1] in ('haute', 'critique')]), 'Alertes hautes / critiques', ' r')]))

    o.append('<section id="alertes"><h2>Alertes <small>%d</small></h2>%s</section>' % (len(al_p), tableau(
        ['Date', 'Gravité', 'Alerte', 'Détail'], [[fr(a[0]), badge_gravite(a[1]), '<b>%s</b>' % esc(a[2]), esc(a[3])] for a in al_p[:300]],
        vide='Aucune alerte sur la période.')))
    o.append('<section id="activite"><h2>Activité par jour</h2>%s</section>' % graphique(periode, debut, fin))
    o.append('<section id="partages"><h2>Utilisation des comptes partagés <small>%s</small></h2>%s</section>' % (esc(', '.join(partages)), tableau(
        ['Date', 'Compte', 'Personne', 'IP', 'Poste', 'Volet', 'Action'],
        [[fr(e['_ts']), esc(e.get('compte')), '<b>%s</b>%s' % (esc(e['_personne']), attr(e)), '<span class="mono">%s</span>' % esc(e.get('ip')),
          esc(e.get('poste')), badge_volet(e['source']), esc(e['action'])] for e in reversed(partage[-500:])])))
    lignes_ip = []
    for ip, l in sorted(ips.items(), key=lambda kv: -len(kv[1])):
        lignes_ip.append(['<span class="mono"><b>%s</b></span>' % esc(ip), esc(', '.join(sorted({e.get('poste') for e in l if e.get('poste')}))),
                          esc(', '.join(sorted({e['_personne'] for e in l}))), str(len(l)),
                          str(sum(1 for e in l if e['categorie'] == 'connexion')), str(sum(1 for e in l if e['source'] == 'applicatif')),
                          str(sum(1 for e in l if e.get('resultat') == 'echec')), fr(l[0]['_ts']), fr(l[-1]['_ts'])])
    o.append('<section id="ip"><h2>Adresses IP <small>%d</small></h2><input class="filtre" data-t="t-ip" placeholder="Filtrer...">%s</section>'
             % (len(ips), tableau(['IP', 'Poste', 'Personnes', 'Événements', 'Connexions', 'Programmes', 'Échecs', 'Première', 'Dernière'],
                                  lignes_ip).replace('class="filtrable ', 'id="t-ip" class="filtrable ')))
    o.append('<section id="sessions"><h2>Sessions <small>%d</small></h2><input class="filtre" data-t="t-ses" placeholder="Filtrer (utilisateur, IP, date...)">%s</section>'
             % (len(ses_p), tableau(['Connexion', 'Déconnexion', 'Durée', 'Volet', 'Utilisateur', 'Compte', 'IP', 'Poste / terminal', 'Opérations'],
                                    [[fr(s['debut'], True), fr(s['fin'], True) or '-', duree(s), badge_volet(s['source']), '<b>%s</b>%s' % (esc(s.get('personne') or s['utilisateur']),
                                      ' <span class="b pa">probable (poste)</span>' if s.get('personne') not in (None, s['utilisateur']) else ''),
                                      esc(s['compte']), '<span class="mono">%s</span>' % esc(s['ip']), esc(s['poste'] or s['terminal']), str(s['operations'])]
                                     for s in reversed(ses_p[-1500:])]).replace('class="filtrable ', 'id="t-ses" class="filtrable ')))
    fiches = []
    for p, l in sorted(personnes.items(), key=lambda kv: -len(kv[1])):
        jours = len({e['_ts'].date() for e in l})
        ips_p = sorted({e['ip'] for e in l if e.get('ip')})
        ses_pers = [s for s in ses_p if s.get('personne', s['utilisateur']) == p or (s['compte'] == p and not s['utilisateur'])]
        progs = {}
        for e in l:
            if e['source'] == 'applicatif':
                progs[e.get('objet') or '?'] = progs.get(e.get('objet') or '?', 0) + 1
        fiches.append('<details class="fiche"><summary><b>%s</b><span class="d">%d événement(s) · %d jour(s) actif(s) · IP : %s · du %s au %s</span></summary><div class="in"><div class="g2">'
                      '<div><b>Sessions</b>%s</div><div><b>Programmes les plus lancés</b>%s</div></div><b>Opérations sensibles et commandes</b>%s</div></details>'
                      % (esc(p), len(l), jours, esc(', '.join(ips_p[:6]) + ('…' if len(ips_p) > 6 else '')) or '-', fr(l[0]['_ts']), fr(l[-1]['_ts']),
                         tableau(['Connexion', 'Durée', 'IP', 'Volet'], [[fr(s['debut']), duree(s), esc(s['ip']), badge_volet(s['source'])] for s in ses_pers[-30:]],
                                 vide='Aucune session.'),
                         tableau(['Programme', 'Lancements'], [[esc(k), str(v)] for k, v in sorted(progs.items(), key=lambda kv: -kv[1])[:15]],
                                 vide='Aucun programme applicatif.'),
                         tableau(['Date', 'Action', 'Objet', 'Compte', 'IP'], [[fr(e['_ts']), esc(e['action']), '<span class="mono">%s</span>' % esc(e.get('objet')),
                                                                              esc(e.get('compte')), esc(e.get('ip'))]
                                                                             for e in l if e['categorie'] in ('ddl', 'droits', 'dml', 'admin', 'sudo', 'commande', 'changement_compte', 'fichier')][-50:],
                                 vide='Aucune.')))
    o.append('<section id="personnes"><h2>Utilisateurs <small>%d · cliquer pour ouvrir la fiche</small></h2>%s</section>' % (len(personnes), ''.join(fiches) or '<p class="vide">Aucun.</p>'))
    o.append('<section id="base"><h2>Opérations en base <small>%d</small></h2>%s</section>' % (len(sensibles), tableau(
        ['Date', 'Opération', 'Objet', 'Personne', 'Compte', 'Machine', 'Résultat'],
        [[fr(e['_ts'], True), esc(e['action']), '<span class="mono">%s</span>' % esc(e.get('objet')), '<b>%s</b>%s' % (esc(e['_personne']), attr(e)),
          esc(e.get('compte')), esc(e.get('poste') or e.get('ip')), '<span class="e">Échec</span>' if e.get('resultat') == 'echec' else 'Succès']
         for e in reversed(sensibles[-1000:])],
        vide='Aucune opération auditée. L\'audit Informix (onaudit) doit être activé pour tracer les opérations en base.')))
    o.append('<section id="programmes"><h2>Programmes lancés <small>%d%s</small></h2><input class="filtre" data-t="t-prog" placeholder="Filtrer (programme, utilisateur, IP...)">%s</section>'
             % (len(programmes), (' · %d rattaché(s) au poste par le terminal' % n_corr) if n_corr else '', tableau(
                 ['Date', 'Programme', 'Utilisateur', 'IP', 'Poste', 'Rattachement'],
                 [[fr(e['_ts'], True), '<span class="mono">%s</span>' % esc(e.get('objet')), '<b>%s</b>' % esc(e['_personne']),
                   '<span class="mono">%s</span>' % esc(e.get('ip')), esc(e.get('poste')), '<span class="d">%s</span>' % esc(e.get('_lien', ''))]
                  for e in reversed(programmes[-3000:])]).replace('class="filtrable ', 'id="t-prog" class="filtrable ')))
    o.append('<section id="commandes"><h2>Commandes, sudo, su <small>%d</small></h2>%s</section>' % (len(commandes), tableau(
        ['Date', 'Action', 'Commande / fichier', 'Personne', 'Vers le compte', 'Résultat'],
        [[fr(e['_ts'], True), esc(e['action']), '<span class="mono">%s</span>' % esc(e.get('objet')), '<b>%s</b>' % esc(e['_personne']),
          esc(e.get('compte')), '<span class="e">Échec</span>' if e.get('resultat') == 'echec' else 'Succès'] for e in reversed(commandes[-1500:])])))
    o.append('<section id="chrono"><h2>Chronologie complète <small>%d événement(s)%s</small></h2><input class="filtre" data-t="t-chr" placeholder="Filtrer (texte, date 15/09, IP...)">%s</section>'
             % (len(periode), ' · 5 000 plus récents affichés, tout est dans le CSV' if len(periode) > 5000 else '', tableau(
                 ['Date', 'Volet', 'Action', 'Personne', 'Compte', 'IP', 'Poste', 'Objet', 'Résultat'],
                 [[fr(e['_ts'], True), badge_volet(e['source']), esc(e['action']), '<b>%s</b>%s' % (esc(e['_personne']), attr(e)), esc(e.get('compte')),
                   '<span class="mono">%s</span>' % esc(e.get('ip')), esc(e.get('poste')), '<span class="mono">%s</span>' % esc(e.get('objet')),
                   '<span class="e">Échec</span>' if e.get('resultat') == 'echec' else 'Succès'] for e in reversed(periode[-5000:])]).replace(
                     'class="filtrable ', 'id="t-chr" class="filtrable ')))
    o.append('<p class="d">Sources : wtmp, btmp, secure, auditd, sessions Informix, audit Informix, table applicative · rapport_local.py</p>'
             '</main><script>%s</script></body></html>' % JS)
    return ''.join(o), periode


def main():
    p = argparse.ArgumentParser(description='Rapport SIEM local (HTML + CSV)')
    p.add_argument('--depuis', help='AAAA-MM-JJ (défaut : il y a 30 jours)')
    p.add_argument('--jusqua', help='AAAA-MM-JJ inclus (défaut : aujourd\'hui)')
    p.add_argument('--ip', help='Limiter à un poste')
    p.add_argument('--utilisateur', help='Limiter à une personne ou un compte')
    p.add_argument('--archive', default=os.path.join(ICI, 'donnees'), help='Dossier de l\'archive (evenements-*.jsonl)')
    p.add_argument('--postes', default=os.path.join(ICI, 'postes.csv'), help='Affectation ip;personne;libelle (facultatif)')
    p.add_argument('--partages', default='regix,informix,root', help='Comptes partagés surveillés')
    p.add_argument('--heures', default='08-19', help='Heures ouvrées, ex. 08-19')
    p.add_argument('-o', '--sortie', default='/msdos/ks/rapports', help='Dossier des rapports')
    p.add_argument('--dernier', default='/msdos/ks/rapport-siem.html', help='Copie du dernier rapport global (vide = aucune)')
    a = p.parse_args()

    debut = dt.datetime.strptime(a.depuis, '%Y-%m-%d') if a.depuis else (dt.datetime.now() - dt.timedelta(days=30)).replace(hour=0, minute=0, second=0, microsecond=0)
    fin = (dt.datetime.strptime(a.jusqua, '%Y-%m-%d') + dt.timedelta(days=1, seconds=-1)) if a.jusqua else dt.datetime.now()
    partages = [x.strip().lower() for x in a.partages.split(',') if x.strip()]
    h1, h2 = (int(x) for x in a.heures.split('-'))
    evts, couverture = lire_archive(a.archive, debut, fin)
    if not evts:
        raise SystemExit('Aucun événement dans %s pour cette période. Lancer d\'abord la collecte (siem-local.sh collecter).' % a.archive)
    sessions = construire_sessions(evts)
    n_corr = correler_terminal(evts, sessions)
    postes = lire_postes(a.postes)
    attribuer(evts, partages, postes)
    for x in sessions:   # session d'un compte partagé ouverte depuis un poste affecté : personne probable
        x['personne'] = postes[x['ip']][0] if (x['utilisateur'] or '').lower() in partages and x['ip'] in postes else x['utilisateur']
    al = alertes(evts, partages, h1, h2)

    titre, sous_titre, suffixe = 'Rapport de traçabilité', '', 'global'
    if a.ip:
        ses_ip = [x for x in sessions if x['ip'] == a.ip and x['source'] == 'systeme']
        garde = []
        for e in evts:
            if e.get('ip') == a.ip:
                garde.append(e)
            elif e['categorie'] in ('sudo', 'changement_compte', 'commande', 'fichier'):
                for x in ses_ip:   # commande lancée pendant une session ouverte depuis ce poste, par le même utilisateur
                    if x['utilisateur'] == e.get('utilisateur') and x['debut'] <= e['_ts'] <= (x['fin'] or dt.datetime.now()):
                        e['_lien'] = 'pendant la session %s ouverte à %s' % (x['terminal'] or '', x['debut'].strftime('%d/%m %H:%M'))
                        garde.append(e)
                        break
        evts = garde
        sessions = [s for s in sessions if s['ip'] == a.ip]
        al = [x for x in al if x[4].get('ip') == a.ip]
        try:
            nom = socket.gethostbyaddr(a.ip)[0]
        except (socket.herror, socket.gaierror, OSError):
            nom = ''
        titre, sous_titre, suffixe = 'Historique du poste %s' % a.ip, ('Machine : %s' % nom) if nom else '', 'poste_' + a.ip.replace(':', '_')
    if a.utilisateur:
        u = a.utilisateur.lower()
        evts = [e for e in evts if e['_personne'].lower() == u or (e.get('compte') or '').lower() == u]
        sessions = [s for s in sessions if s['utilisateur'].lower() == u or s['compte'].lower() == u]
        al = [x for x in al if x[4]['_personne'].lower() == u or (x[4].get('compte') or '').lower() == u]
        titre, suffixe = 'Activité de %s' % a.utilisateur, 'utilisateur_' + re.sub(r'\W', '_', a.utilisateur)

    contenu, periode = generer(evts, sessions, debut, fin, titre, sous_titre, couverture, al, partages, n_corr, socket.gethostname().split('.')[0])
    os.makedirs(a.sortie, exist_ok=True)
    base = os.path.join(a.sortie, 'siem_%s_%s_%s' % (suffixe, debut.strftime('%Y%m%d'), fin.strftime('%Y%m%d')))
    with io.open(base + '.html', 'w', encoding='utf-8') as f:
        f.write(contenu)
    with io.open(base + '.csv', 'w', encoding='utf-8-sig', newline='') as f:
        w = csv.writer(f, delimiter=';', quoting=csv.QUOTE_ALL)
        w.writerow(['Date', 'Heure', 'Volet', 'Catégorie', 'Action', 'Personne', 'Attribution', 'Compte', 'IP', 'Poste', 'Objet', 'Résultat', 'Rattachement'])
        for e in periode:
            w.writerow([e['_ts'].strftime('%d/%m/%Y'), e['_ts'].strftime('%H:%M:%S'), e['source'], e['categorie'], e['action'], e['_personne'],
                        e['_attr'], e.get('compte'), e.get('ip'), e.get('poste'), e.get('objet'), e.get('resultat'), e.get('_lien', '')])
    if suffixe == 'global' and a.dernier:
        shutil.copyfile(base + '.html', a.dernier)
    print('Rapport : %s.html (%d événement(s), %d alerte(s))' % (base, len(periode), len([x for x in al if debut <= x[0] <= fin])))
    print('CSV     : %s.csv' % base)
    if suffixe == 'global' and a.dernier:
        print('Copie   : %s' % a.dernier)


if __name__ == '__main__':
    main()
