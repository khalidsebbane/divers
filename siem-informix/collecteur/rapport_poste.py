#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Historique d'un poste (adresse IP) sur le serveur Informix : rapport HTML + CSV, sans le portail.

Croise toutes les traces déjà présentes sur le serveur pour reconstituer ce qu'un poste a fait :
  1. sessions ouvertes depuis l'IP (wtmp) : utilisateur, terminal, heure de connexion / déconnexion ;
  2. authentifications et échecs SSH depuis l'IP (/var/log/secure) ;
  3. sudo / su lancés PENDANT ces sessions (secure, et auditd : session d'audit rattachée à l'IP) ;
  4. commandes surveillées par auditd dans ces sessions (si les règles du SIEM sont actives) ;
  5. programmes lancés dans l'application (table agr_lds) : par colonne IP/poste si elle existe,
     sinon par CORRÉLATION TERMINAL (même pts/N que la session ouverte depuis l'IP, à la même heure) ;
  6. opérations auditées par Informix (onshowaudit) depuis cette machine, si l'audit est actif ;
  7. sessions base actuellement ouvertes depuis cette machine (sysmaster).

Le rapport indique, pour chaque source, la période réellement couverte par les journaux disponibles.

Usage (en root, Python système suffisant) :
  /usr/libexec/platform-python rapport_poste.py --ip 10.12.4.21
  /usr/libexec/platform-python rapport_poste.py --ip 10.12.4.21 --depuis 2026-09-21 --jusqua 2026-10-21 -c collecteur.ini
"""
from __future__ import print_function

import argparse
import configparser
import csv
import datetime as dt
import html
import io
import os
import re
import socket
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import collecteur as c  # noqa: E402

RE_TERMINAL = re.compile(r'^(?:/dev/)?((?:pts/\d+)|(?:tty\w*\d+))$')
RE_SES = re.compile(r'\bses=(\d+)')
RE_ADDR = re.compile(r'\baddr=([0-9a-fA-F:.]+)')
RE_ACCT = re.compile(r'\bacct="?([^"\s]+)')
RE_AUID = re.compile(r'\bauid=(\d+)')


def charger_conf(chemin):
    conf = configparser.ConfigParser(interpolation=None)
    if chemin:
        if not conf.read(chemin, encoding='utf-8'):
            sys.exit('Configuration introuvable : %s' % chemin)
    for s in ('collecteur', 'systeme', 'informix', 'applicatif'):
        if not conf.has_section(s):
            conf.add_section(s)
    return conf


def noms_du_poste(ip, alias):
    noms = {n.lower() for n in alias if n}
    try:
        h = socket.gethostbyaddr(ip)
        noms.add(h[0].lower())
        noms.update(a.lower() for a in h[1])
    except (socket.herror, socket.gaierror, OSError):
        pass
    noms.update({n.split('.')[0] for n in list(noms)})
    return noms


def du_poste(valeur_ip, valeur_poste, ip, noms):
    v1, v2 = (valeur_ip or '').lower().replace('::ffff:', ''), (valeur_poste or '').lower()
    return v1 == ip or v2 == ip or (v2 and (v2 in noms or v2.split('.')[0] in noms)) or (v1 and v1 in noms)


# --------------------------------------------------------------------------------------------
# Sessions depuis le poste (wtmp)
# --------------------------------------------------------------------------------------------
def sessions_du_poste(conf, ip, noms, debut, fin):
    enr, couverture = [], None
    for f in c.fichiers(conf.get('systeme', 'wtmp', fallback='/var/log/wtmp*')):
        try:
            enr.extend(c.lire_utmp(f))
        except (IOError, OSError) as e:
            c.log('wtmp illisible %s : %s' % (f, e))
    enr.sort(key=lambda r: r['date'])
    if enr:
        couverture = (enr[0]['date'], enr[-1]['date'])
    ouvertes, sessions = {}, []
    for r in enr:
        if r['type'] == c.USER_PROCESS and r['user']:
            rip, poste = c.adresse(r['host'], r['ip'])
            s = {'utilisateur': r['user'], 'terminal': r['line'], 'ip': rip, 'poste': poste, 'debut': r['date'], 'fin': None,
                 'motif_fin': ''}
            ouvertes[r['line']] = s
            if du_poste(rip, poste or r['host'], ip, noms):
                sessions.append(s)
        elif r['type'] == c.DEAD_PROCESS and r['line'] in ouvertes:
            ouvertes.pop(r['line'])['fin'] = r['date']
        elif r['type'] == c.BOOT_TIME:
            for s in ouvertes.values():
                s['fin'], s['motif_fin'] = r['date'], 'redémarrage du serveur'
            ouvertes = {}
    garde = [s for s in sessions if s['debut'] <= fin and (s['fin'] or dt.datetime.now()) >= debut]
    return garde, couverture


def pendant(sessions, ts, utilisateur=None, terminal=None):
    """Session du poste active à cet instant (même utilisateur et/ou même terminal si précisés)."""
    for s in sessions:
        if s['debut'] <= ts <= (s['fin'] or dt.datetime.now()):
            if utilisateur and s['utilisateur'] != utilisateur:
                continue
            if terminal and s['terminal'] != terminal:
                continue
            return s
    return None


# --------------------------------------------------------------------------------------------
# auditd : sessions d'audit ouvertes depuis l'IP, puis tout ce qui s'y est passé
# --------------------------------------------------------------------------------------------
def audit_du_poste(conf, ip, debut, fin):
    lignes, couverture = [], None
    sessions_audit = {}   # session d'audit -> utilisateur qui l'a ouverte depuis le poste
    for f in c.fichiers(conf.get('systeme', 'auditd', fallback='/var/log/audit/audit.log*')):
        try:
            fh = c.ouvrir_texte(f)
        except (IOError, OSError) as e:
            c.log('audit.log illisible %s : %s' % (f, e))
            continue
        with fh:
            for ligne in fh:
                m = c.RE_AUDIT.match(ligne.strip())
                if not m:
                    continue
                ts = dt.datetime.fromtimestamp(int(m.group('sec')))
                couverture = (min(couverture[0], ts), max(couverture[1], ts)) if couverture else (ts, ts)
                corps = m.group('corps')
                ses = RE_SES.search(corps)
                addr = RE_ADDR.search(corps)
                if ses and addr and addr.group(1).replace('::ffff:', '') == ip and ses.group(1) not in ('4294967295',):
                    acct, auid = RE_ACCT.search(corps), RE_AUID.search(corps)
                    qui = acct.group(1) if acct else (c._nom_uid(auid.group(1)) if auid else '')
                    if qui or ses.group(1) not in sessions_audit:
                        sessions_audit[ses.group(1)] = qui
                if debut <= ts <= fin:
                    lignes.append((ts, m.group('type'), m.group('serial'), corps, ses.group(1) if ses else ''))
    res = []
    par_serial = {}
    for ts, typ, serial, corps, ses in lignes:
        par_serial.setdefault(serial, []).append((ts, typ, corps, ses))
    for serial, recs in par_serial.items():
        ses = next((r[3] for r in recs if r[3]), '')
        if ses not in sessions_audit:
            continue
        types = {r[1]: r for r in recs}
        champs = dict(c.RE_CHAMP.findall(recs[0][2]))
        auid = sessions_audit.get(ses) or c._nom_uid(champs.get('auid'))
        if 'USER_CMD' in types:
            ch = dict(c.RE_CHAMP.findall(types['USER_CMD'][2]))
            res.append({'ts': recs[0][0], 'source': 'Système (auditd)', 'action': 'sudo',
                        'utilisateur': auid, 'compte': c._nom_uid(ch.get('uid')), 'objet': c._hexdec(ch.get('cmd', '')),
                        'resultat': 'succes' if 'res=success' in types['USER_CMD'][2] else 'echec', 'lien': 'session d\'audit %s' % ses})
        elif 'EXECVE' in types:
            ex = dict(c.RE_CHAMP.findall(types['EXECVE'][2]))
            args = [c._hexdec(ex['a%d' % i]) for i in range(int(ex.get('argc', '0') or 0)) if 'a%d' % i in ex]
            sc = dict(c.RE_CHAMP.findall(types['SYSCALL'][2])) if 'SYSCALL' in types else champs
            res.append({'ts': recs[0][0], 'source': 'Système (auditd)', 'action': 'Commande',
                        'utilisateur': sessions_audit.get(ses) or c._nom_uid(sc.get('auid')),
                        'compte': c._nom_uid(sc.get('uid')), 'objet': ' '.join(args)[:500], 'resultat': 'succes',
                        'lien': 'session d\'audit %s' % ses})
    return res, couverture, len(sessions_audit)


# --------------------------------------------------------------------------------------------
# Rapport
# --------------------------------------------------------------------------------------------
def fr(d):
    return d.strftime('%d/%m/%Y %H:%M:%S') if d else ''


def duree(s):
    if not s['fin']:
        return 'en cours'
    m = int((s['fin'] - s['debut']).total_seconds() // 60)
    return '%dh%02d' % (m // 60, m % 60)


def main():
    p = argparse.ArgumentParser(description='Historique d\'un poste (IP) sur le serveur Informix')
    p.add_argument('--ip', required=True)
    p.add_argument('--nom', action='append', default=[], help='Nom de machine du poste (si le DNS inverse ne le donne pas)')
    p.add_argument('--depuis', help='AAAA-MM-JJ (défaut : il y a 30 jours)')
    p.add_argument('--jusqua', help='AAAA-MM-JJ inclus (défaut : aujourd\'hui)')
    p.add_argument('-c', '--config', help='collecteur.ini (environnement Informix et table agr_lds)')
    p.add_argument('-o', '--sortie', default=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'Rapports'))
    a = p.parse_args()

    ip = a.ip.strip()
    debut = dt.datetime.strptime(a.depuis, '%Y-%m-%d') if a.depuis else (dt.datetime.now() - dt.timedelta(days=30)).replace(hour=0, minute=0, second=0, microsecond=0)
    fin = (dt.datetime.strptime(a.jusqua, '%Y-%m-%d') + dt.timedelta(days=1, seconds=-1)) if a.jusqua else dt.datetime.now()
    conf = charger_conf(a.config)
    noms = noms_du_poste(ip, a.nom)
    print('\n=== Historique du poste %s%s ===' % (ip, (' (' + ', '.join(sorted(noms)) + ')') if noms else ''))
    print('  Période : %s -> %s' % (fr(debut), fr(fin)))

    lignes, sources = [], []

    # 1. Sessions
    sessions, couv = sessions_du_poste(conf, ip, noms, debut, fin)
    sources.append(('Sessions (wtmp)', couv, '%d session(s) depuis le poste' % len(sessions)))
    for s in sessions:
        lignes.append({'ts': s['debut'], 'source': 'Système (wtmp)', 'action': 'Ouverture de session %s' % c.type_ligne(s['terminal']),
                       'utilisateur': s['utilisateur'], 'compte': s['utilisateur'], 'objet': 'terminal %s' % s['terminal'],
                       'resultat': 'succes', 'lien': 'fin : %s (%s)%s' % (fr(s['fin']) or '-', duree(s),
                                                                         ', ' + s['motif_fin'] if s['motif_fin'] else '')})

    # 2-3. secure : authentifications depuis l'IP ; sudo/su pendant une session du poste
    try:
        evts = [e for e in c.collecter_secure(conf, debut) if e['ts'] <= fin.strftime('%Y-%m-%dT%H:%M:%S')]
    except Exception as e:  # noqa
        evts = []
        c.log('secure : %s' % e)
    dates = [e['ts'] for e in evts]
    sources.append(('SSH, sudo, su (secure)', (dt.datetime.strptime(min(dates), '%Y-%m-%dT%H:%M:%S'),
                                               dt.datetime.strptime(max(dates), '%Y-%m-%dT%H:%M:%S')) if dates else None, ''))
    n_sec = 0
    for e in evts:
        ts = dt.datetime.strptime(e['ts'], '%Y-%m-%dT%H:%M:%S')
        if e['categorie'] in ('authentification', 'echec_connexion'):
            if du_poste(e['ip'], e['poste'], ip, noms):
                lignes.append({'ts': ts, 'source': 'Système (secure)', 'action': e['action'], 'utilisateur': e['utilisateur'],
                               'compte': e['compte'], 'objet': '', 'resultat': e['resultat'], 'lien': 'depuis %s' % ip})
                n_sec += 1
        elif e['categorie'] in ('sudo', 'changement_compte'):
            tty = (e.get('details') or {}).get('tty', '')
            s = pendant(sessions, ts, utilisateur=e['utilisateur'], terminal=tty if RE_TERMINAL.match(tty or '') else None) \
                or pendant(sessions, ts, utilisateur=e['utilisateur'])
            if s:
                lignes.append({'ts': ts, 'source': 'Système (secure)', 'action': e['action'], 'utilisateur': e['utilisateur'],
                               'compte': e['compte'], 'objet': e['objet'], 'resultat': e['resultat'],
                               'lien': 'pendant la session %s ouverte à %s' % (s['terminal'], s['debut'].strftime('%d/%m %H:%M'))})
                n_sec += 1
    sources[-1] = (sources[-1][0], sources[-1][1], '%d ligne(s) liée(s) au poste' % n_sec)

    # 4. auditd
    aud, couv, n_ses = audit_du_poste(conf, ip, debut, fin)
    lignes.extend(aud)
    sources.append(('Commandes (auditd)', couv, '%d session(s) d\'audit depuis le poste, %d commande(s)' % (n_ses, len(aud))))

    # 5. Table applicative (agr_lds)
    if conf.get('applicatif', 'base', fallback='').strip():
        try:
            app = [e for e in c.collecter_applicatif(conf, debut) if e['ts'] <= fin.strftime('%Y-%m-%dT%H:%M:%S')]
            n_ip = n_tty = 0
            for e in app:
                ts = dt.datetime.strptime(e['ts'], '%Y-%m-%dT%H:%M:%S')
                det = e.get('details') or {}
                lien = None
                if du_poste(e['ip'], e['poste'], ip, noms):
                    lien, n_ip = 'colonne poste/IP de la table', n_ip + 1
                else:
                    terms = [RE_TERMINAL.match(str(v).strip()) for v in det.values()]
                    terms = [t.group(1) for t in terms if t]
                    s = pendant(sessions, ts, terminal=terms[0]) if terms else None
                    if s:
                        lien, n_tty = 'même terminal %s que la session ouverte depuis le poste à %s' % (
                            s['terminal'], s['debut'].strftime('%d/%m %H:%M')), n_tty + 1
                if lien:
                    lignes.append({'ts': ts, 'source': 'Application (agr_lds)', 'action': 'Programme lancé',
                                   'utilisateur': e['utilisateur'], 'compte': e['compte'], 'objet': e['objet'],
                                   'resultat': 'succes', 'lien': lien})
            dates = [e['ts'] for e in app]
            sources.append(('Programmes (agr_lds)', (dt.datetime.strptime(min(dates), '%Y-%m-%dT%H:%M:%S'),
                                                     dt.datetime.strptime(max(dates), '%Y-%m-%dT%H:%M:%S')) if dates else None,
                            '%d programme(s) du poste (%d par colonne IP/poste, %d par corrélation terminal) sur %d lus'
                            % (n_ip + n_tty, n_ip, n_tty, len(app))))
        except Exception as e:  # noqa
            sources.append(('Programmes (agr_lds)', None, 'non lu : %s' % e))
    else:
        sources.append(('Programmes (agr_lds)', None, 'non lu : renseigner [applicatif] base dans collecteur.ini (-c)'))

    # 6. Audit Informix
    if conf.get('informix', 'commande_onshowaudit', fallback='').strip() or conf.get('informix', 'fichiers_onshowaudit', fallback='').strip():
        try:
            ifx = [e for e in c.collecter_onaudit(conf, debut) if e['ts'] <= fin.strftime('%Y-%m-%dT%H:%M:%S')]
            n = 0
            for e in ifx:
                if du_poste(e['ip'], e['poste'], ip, noms):
                    lignes.append({'ts': dt.datetime.strptime(e['ts'], '%Y-%m-%dT%H:%M:%S'), 'source': 'Base (audit Informix)',
                                   'action': e['action'], 'utilisateur': e['utilisateur'], 'compte': e['compte'], 'objet': e['objet'],
                                   'resultat': e['resultat'], 'lien': 'machine %s' % e['poste']})
                    n += 1
            sources.append(('Opérations base (onaudit)', None, '%d opération(s) du poste sur %d auditées' % (n, len(ifx))))
        except Exception as e:  # noqa
            sources.append(('Opérations base (onaudit)', None, 'non lu : %s' % e))
    else:
        sources.append(('Opérations base (onaudit)', None, 'audit Informix non configuré : les ordres SQL passés ne sont pas tracés'))

    # 7. Sessions base en cours
    if conf.get('informix', 'informixserver', fallback='').strip():
        try:
            ses = [e for e in c.collecter_sessions(conf, {}) if e['categorie'] == 'connexion' and du_poste(e['ip'], e['poste'], ip, noms)]
            for e in ses:
                lignes.append({'ts': dt.datetime.strptime(e['ts'], '%Y-%m-%dT%H:%M:%S'), 'source': 'Base (session en cours)',
                               'action': 'Session base ouverte', 'utilisateur': e['utilisateur'], 'compte': e['compte'],
                               'objet': 'sid %s' % e['details'].get('sid'), 'resultat': 'succes', 'lien': 'machine %s' % e['poste']})
            sources.append(('Sessions base en cours (sysmaster)', None, '%d session(s) ouverte(s) maintenant' % len(ses)))
        except Exception as e:  # noqa
            sources.append(('Sessions base en cours (sysmaster)', None, 'non lu : %s' % e))

    lignes = [l for l in lignes if debut <= l['ts'] <= fin or l['source'] == 'Base (session en cours)']
    lignes.sort(key=lambda l: l['ts'])
    utilisateurs = sorted({l['utilisateur'] for l in lignes if l['utilisateur']})

    os.makedirs(a.sortie, exist_ok=True)
    base = os.path.join(a.sortie, 'Poste_%s_%s_%s' % (ip.replace(':', '_'), debut.strftime('%Y%m%d'), fin.strftime('%Y%m%d')))
    with io.open(base + '.csv', 'w', encoding='utf-8-sig', newline='') as f:
        w = csv.writer(f, delimiter=';', quoting=csv.QUOTE_ALL)
        w.writerow(['Date', 'Heure', 'Source', 'Action', 'Utilisateur', 'Compte', 'Objet / programme / commande', 'Résultat', 'Lien avec le poste'])
        for l in lignes:
            w.writerow([l['ts'].strftime('%d/%m/%Y'), l['ts'].strftime('%H:%M:%S'), l['source'], l['action'], l['utilisateur'],
                        l['compte'], l['objet'], 'Échec' if l['resultat'] == 'echec' else 'Succès', l['lien']])
    ecrire_html(base + '.html', ip, noms, debut, fin, sessions, lignes, sources, utilisateurs)

    print('\n  Sources :')
    for nom, couv, info in sources:
        print('   - %-36s %-42s %s' % (nom, ('couvre du %s au %s' % (couv[0].strftime('%d/%m/%Y'), couv[1].strftime('%d/%m/%Y'))) if couv else '', info))
    print('\n  %d ligne(s), utilisateurs : %s' % (len(lignes), ', '.join(utilisateurs) or '-'))
    print('  Fichiers : %s.html  /  %s.csv\n' % (base, base))


CSS = """body{margin:0;font:14px/1.45 "Segoe UI",Arial,sans-serif;color:#16181d;background:#f4f5f7}
header{background:#111;color:#fff;padding:24px 36px;border-bottom:4px solid #ffc50c}header h1{margin:0 0 6px;font-size:22px}
header .m{display:flex;flex-wrap:wrap;gap:6px 26px;font-size:13px;opacity:.85}main{max-width:1250px;margin:0 auto;padding:20px 36px 40px}
.k{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:14px;margin-bottom:18px}
.c{background:#fff;border:1px solid #dfe1e5;border-radius:8px;padding:14px 18px}.c .v{font-size:26px;font-weight:700}.c .l{color:#52514e;font-size:12.5px}
section{background:#fff;border:1px solid #dfe1e5;border-radius:8px;padding:16px 20px;margin-bottom:18px;overflow-x:auto}
h2{font-size:16px;margin:0 0 10px}table{width:100%;border-collapse:collapse;font-size:13px}
th{background:#111;color:#fff;text-align:left;padding:8px;white-space:nowrap}td{padding:7px 8px;border-bottom:1px solid #e6e7ea;vertical-align:top}
tr:nth-child(even) td{background:#fafafa}.mono{font-family:Consolas,monospace;font-size:12.5px;overflow-wrap:anywhere}
.d{color:#6b6b66;font-size:12px}.e{color:#b3261e;font-weight:600}.b{display:inline-block;padding:1px 8px;border-radius:10px;font-size:11.5px;background:#f0f1f3;border:1px solid #dfe1e5;white-space:nowrap}
.avert{background:#fff8e1;border:1px solid #f3d27a;border-radius:8px;padding:10px 14px;margin-bottom:18px;font-size:13px}
@media print{body{background:#fff}header{-webkit-print-color-adjust:exact;print-color-adjust:exact}}"""


def ecrire_html(chemin, ip, noms, debut, fin, sessions, lignes, sources, utilisateurs):
    e = lambda v: html.escape('' if v is None else str(v))
    n_app = sum(1 for l in lignes if l['source'].startswith('Application'))
    n_base = sum(1 for l in lignes if l['source'].startswith('Base'))
    n_cmd = sum(1 for l in lignes if l['action'] in ('sudo', 'Commande') or l['action'].startswith('sudo') or l['action'].startswith('su '))
    o = ['<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
         '<title>Historique du poste %s</title><style>%s</style></head><body>' % (e(ip), CSS)]
    o.append('<header><h1>Historique du poste %s</h1><div class="m"><span><b>Machine :</b> %s</span><span><b>Serveur :</b> %s</span>'
             '<span><b>Période :</b> du %s au %s</span><span><b>Généré le :</b> %s</span></div></header><main>'
             % (e(ip), e(', '.join(sorted(noms)) or 'nom inconnu'), e(c.SERVEUR), debut.strftime('%d/%m/%Y'), fin.strftime('%d/%m/%Y'),
                dt.datetime.now().strftime('%d/%m/%Y %H:%M')))
    o.append('<div class="k"><div class="c"><div class="v">%d</div><div class="l">Sessions depuis le poste</div></div>'
             '<div class="c"><div class="v">%d</div><div class="l">Utilisateurs</div></div>'
             '<div class="c"><div class="v">%d</div><div class="l">Programmes applicatifs</div></div>'
             '<div class="c"><div class="v">%d</div><div class="l">Commandes / sudo</div></div>'
             '<div class="c"><div class="v">%d</div><div class="l">Opérations base auditées</div></div></div>'
             % (len(sessions), len(utilisateurs), n_app, n_cmd, n_base))
    if not any(s[0].startswith('Opérations base') and s[2][:1].isdigit() for s in sources):
        o.append('<div class="avert"><b>Limite :</b> l\'audit Informix n\'était pas actif. Les ordres SQL lancés depuis ce poste '
                 '(SELECT, UPDATE, DELETE…) ne sont pas conservés par Informix. Ce rapport reconstitue l\'activité à partir des sessions, '
                 'des commandes système et des programmes enregistrés par l\'application.</div>')
    o.append('<section><h2>Sources et période réellement couverte</h2><table><tr><th>Source</th><th>Journaux disponibles</th><th>Résultat</th></tr>')
    for nom, couv, info in sources:
        cv = 'du %s au %s' % (couv[0].strftime('%d/%m/%Y'), couv[1].strftime('%d/%m/%Y')) if couv else '-'
        alerte = couv and couv[0] > debut
        o.append('<tr><td>%s</td><td>%s%s</td><td>%s</td></tr>' % (e(nom), e(cv), ' <span class="e">(ne couvre pas tout le mois)</span>' if alerte else '', e(info)))
    o.append('</table></section>')
    o.append('<section><h2>Sessions ouvertes depuis le poste</h2><table><tr><th>Connexion</th><th>Déconnexion</th><th>Durée</th><th>Utilisateur</th><th>Terminal</th></tr>')
    for s in sessions:
        o.append('<tr><td>%s</td><td>%s</td><td>%s</td><td><b>%s</b></td><td class="mono">%s</td></tr>'
                 % (fr(s['debut']), e(fr(s['fin']) or '-'), e(duree(s)), e(s['utilisateur']), e(s['terminal'])))
    if not sessions:
        o.append('<tr><td colspan="5" class="d">Aucune session depuis ce poste dans les journaux disponibles.</td></tr>')
    o.append('</table></section>')
    o.append('<section><h2>Chronologie détaillée <span class="d">(%d lignes)</span></h2><table><tr><th>Date</th><th>Source</th><th>Action</th>'
             '<th>Utilisateur</th><th>Compte</th><th>Objet / programme / commande</th><th>Lien avec le poste</th></tr>' % len(lignes))
    for l in lignes:
        o.append('<tr><td>%s</td><td><span class="b">%s</span></td><td>%s%s</td><td><b>%s</b></td><td>%s</td><td class="mono">%s</td><td class="d">%s</td></tr>'
                 % (fr(l['ts']), e(l['source']), e(l['action']), ' <span class="e">échec</span>' if l['resultat'] == 'echec' else '',
                    e(l['utilisateur']), e(l['compte']), e(l['objet']), e(l['lien'])))
    o.append('</table></section></main></body></html>')
    with io.open(chemin, 'w', encoding='utf-8') as f:
        f.write(''.join(o))


if __name__ == '__main__':
    main()
