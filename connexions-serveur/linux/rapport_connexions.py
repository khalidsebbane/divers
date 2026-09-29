#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Rapport des connexions utilisateurs sur un serveur Linux (Red Hat / CentOS / Rocky / Alma),
classé par adresse IP.

Sources :
  - /var/log/wtmp*   : ouvertures / fermetures de session (SSH avec terminal, console)
  - /var/log/btmp*   : tentatives échouées (option --echecs)
  - /var/log/secure* : connexions SSH sans terminal (sftp, scp, WinSCP...) et échecs détaillés (option --secure)

Sorties (dossier ./Rapports par défaut) :
  - rapport HTML (synthèse par IP, synthèse par utilisateur, détail par IP)
  - CSV du détail et CSV de la synthèse par IP (séparateur « ; », UTF-8 avec BOM pour Excel)

Exemples :
  sudo python3 rapport_connexions.py --mois 2026-09 --echecs --secure    (tous les utilisateurs)
  sudo python3 rapport_connexions.py --mois 2026-09 -u 'jdupont,adm*'
  sudo python3 rapport_connexions.py --mois 2026-09 --groupes wheel
  python3 rapport_connexions.py --demo --mois 2026-09 --echecs

Compatible Python 3.6+ (RHEL 8 : python3 ou /usr/libexec/platform-python ; RHEL 7 : yum install python3).
"""
from __future__ import print_function

import argparse
import csv
import datetime as dt
import fnmatch
import glob
import grp
import gzip
import html
import io
import os
import pwd
import random
import re
import socket
import struct
import sys

# --------------------------------------------------------------------------------------------
# Lecture wtmp / btmp (struct utmp Linux, 384 octets)
# --------------------------------------------------------------------------------------------
UTMP_FMT = '<hi32s4s32s256shhiii16s20s'
UTMP_SIZE = struct.calcsize(UTMP_FMT)  # 384
BOOT_TIME, USER_PROCESS, DEAD_PROCESS, RUN_LVL = 2, 7, 8, 1

LOCAL = 'Local (console)'


def ouvrir(chemin):
    if chemin.endswith('.gz'):
        return gzip.open(chemin, 'rb')
    return open(chemin, 'rb')


def txt(b):
    return b.split(b'\0', 1)[0].decode('utf-8', 'replace').strip()


def lire_utmp(chemin):
    """Retourne la liste des enregistrements d'un fichier wtmp/btmp."""
    enr = []
    with ouvrir(chemin) as f:
        data = f.read()
    for i in range(0, len(data) - UTMP_SIZE + 1, UTMP_SIZE):
        (typ, pid, line, uid, user, host, _e1, _e2, _sess, sec, usec, addr, _u) = struct.unpack_from(UTMP_FMT, data, i)
        ip = ''
        if addr[4:] == b'\0' * 12:
            if addr[:4] != b'\0' * 4:
                ip = socket.inet_ntop(socket.AF_INET, addr[:4])
        else:
            ip = socket.inet_ntop(socket.AF_INET6, addr)
        enr.append({
            'type': typ, 'pid': pid, 'line': txt(line), 'id': txt(uid), 'user': txt(user),
            'host': txt(host), 'ip': ip, 'date': dt.datetime.fromtimestamp(sec + usec / 1e6),
        })
    return enr


def est_ip(s):
    for fam in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(fam, s)
            return True
        except (OSError, ValueError):
            pass
    return False


def adresse(host, ip):
    """Détermine (IP, poste) à partir des champs host / addr de wtmp."""
    host = host or ''
    if host.startswith('::ffff:'):
        host = host[7:]
    if ip.startswith('::ffff:'):
        ip = ip[7:]
    if est_ip(host):
        return host, ''
    if ip and ip not in ('0.0.0.0', '::'):
        return ip, host
    if not host or host.startswith(':') or host.startswith('tmux') or host.startswith('screen'):
        return LOCAL, host
    return host, host  # nom d'hôte non résolu (UseDNS)


def type_session(line):
    if line.startswith('pts/'):
        return 'SSH (terminal)'
    if line.startswith('tty') or line.startswith(':') or line == 'console':
        return 'Console'
    if line.startswith('ssh'):
        return 'SSH'
    return line or 'Autre'


def fichiers(motif_base, explicites):
    if explicites:
        res = []
        for m in explicites:
            res.extend(glob.glob(m))
        return sorted(set(res))
    return sorted(set(glob.glob(motif_base + '*')))


# --------------------------------------------------------------------------------------------
# Filtre utilisateurs
# --------------------------------------------------------------------------------------------
class Filtre(object):
    def __init__(self, motifs, groupes):
        self.motifs = [m.lower() for m in motifs]
        self.membres = set()
        for g in groupes:
            try:
                gr = grp.getgrnam(g)
            except KeyError:
                print('  ATTENTION : groupe %r introuvable' % g, file=sys.stderr)
                continue
            self.membres.update(u.lower() for u in gr.gr_mem)
            for p in pwd.getpwall():  # membres par groupe principal
                if p.pw_gid == gr.gr_gid:
                    self.membres.add(p.pw_name.lower())
        if groupes:
            print('  %d membre(s) trouvé(s) dans le(s) groupe(s) %s' % (len(self.membres), ', '.join(groupes)))

    def ok(self, user):
        u = (user or '').lower()
        if not u or u in ('reboot', 'shutdown', 'runlevel', 'login', 'unknown'):
            return False
        return u in self.membres or self._explicite(u)

    def _explicite(self, u):
        return any(fnmatch.fnmatchcase(u, m) for m in self.motifs)


# --------------------------------------------------------------------------------------------
# Collecte
# --------------------------------------------------------------------------------------------
def nouvelle(date, user, ip, poste, typ, resultat='Succès', motif='', fin=None, serveur=None):
    return {'serveur': serveur or socket.gethostname().split('.')[0], 'date': date, 'user': user, 'ip': ip,
            'poste': poste, 'type': typ, 'resultat': resultat, 'motif': motif, 'fin': fin,
            'duree': (fin - date) if fin else None}


def collecter_wtmp(fichiers_wtmp, debut, fin, filtre):
    enr = []
    for f in fichiers_wtmp:
        try:
            enr.extend(lire_utmp(f))
            print('  Lecture %s' % f)
        except (IOError, OSError) as e:
            print('  ATTENTION : %s illisible (%s)' % (f, e), file=sys.stderr)
    enr.sort(key=lambda r: r['date'])

    res, ouvertes = [], {}  # line -> connexion en cours
    for r in enr:
        if r['type'] == USER_PROCESS:
            c = None
            if filtre.ok(r['user']) and debut <= r['date'] < fin:
                ip, poste = adresse(r['host'], r['ip'])
                c = nouvelle(r['date'], r['user'], ip, poste, type_session(r['line']))
                res.append(c)
            ouvertes[r['line']] = c
        elif r['type'] == DEAD_PROCESS and r['line'] in ouvertes:
            c = ouvertes.pop(r['line'])
            if c:
                c['fin'], c['duree'] = r['date'], r['date'] - c['date']
        elif r['type'] == BOOT_TIME or (r['type'] == RUN_LVL and r['user'] == 'shutdown'):
            for c in ouvertes.values():
                if c:
                    c['motif'] = 'Session interrompue (arrêt / redémarrage du serveur)'
            ouvertes = {}
    return res


def collecter_btmp(fichiers_btmp, debut, fin, filtre):
    res = []
    for f in fichiers_btmp:
        try:
            enr = lire_utmp(f)
            print('  Lecture %s' % f)
        except (IOError, OSError) as e:
            print('  ATTENTION : %s illisible (%s)' % (f, e), file=sys.stderr)
            continue
        for r in enr:
            if debut <= r['date'] < fin and filtre.ok(r['user']):
                ip, poste = adresse(r['host'], r['ip'])
                res.append(nouvelle(r['date'], r['user'], ip, poste, type_session(r['line']), 'Échec', 'Authentification refusée'))
    return res


MOIS_EN = {m: i for i, m in enumerate(['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'], 1)}
RE_SYSLOG = re.compile(r'^(?:(?P<iso>\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)\S*|(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d+)\s+(?P<hms>\d\d:\d\d:\d\d))\s+\S+\s+sshd\[\d+\]:\s+(?P<msg>.*)$')
RE_OK = re.compile(r'^Accepted (?P<meth>\S+) for (?P<user>\S+) from (?P<ip>\S+) port')
RE_KO = re.compile(r'^Failed (?P<meth>\S+) for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port')
RE_INV = re.compile(r'^Invalid user (?P<user>\S+) from (?P<ip>\S+)')
METHODES = {'password': 'mot de passe', 'publickey': 'clé SSH', 'keyboard-interactive/pam': 'mot de passe (PAM)',
            'gssapi-with-mic': 'Kerberos'}


def collecter_secure(fichiers_secure, debut, fin, filtre, wtmp, echecs):
    succes, ko = [], []
    for f in fichiers_secure:
        try:
            fh = gzip.open(f, 'rt', errors='replace') if f.endswith('.gz') else io.open(f, encoding='utf-8', errors='replace')
            mtime = dt.datetime.fromtimestamp(os.path.getmtime(f))
            print('  Lecture %s' % f)
        except (IOError, OSError) as e:
            print('  ATTENTION : %s illisible (%s)' % (f, e), file=sys.stderr)
            continue
        with fh:
            for ligne in fh:
                m = RE_SYSLOG.match(ligne.rstrip('\n'))
                if not m:
                    continue
                if m.group('iso'):
                    d = dt.datetime.strptime(m.group('iso'), '%Y-%m-%dT%H:%M:%S')
                else:  # syslog classique sans année : déduite de la date du fichier
                    mois = MOIS_EN.get(m.group('mon'))
                    if not mois:
                        continue
                    annee = mtime.year - (1 if mois > mtime.month else 0)
                    h, mi, s = (int(x) for x in m.group('hms').split(':'))
                    try:
                        d = dt.datetime(annee, mois, int(m.group('day')), h, mi, s)
                    except ValueError:
                        continue
                if not (debut <= d < fin):
                    continue
                msg = m.group('msg')
                mo = RE_OK.match(msg)
                if mo and filtre.ok(mo.group('user')):
                    succes.append((d, mo.group('user'), adresse(mo.group('ip'), '')[0], mo.group('meth')))
                    continue
                if echecs:
                    mk = RE_KO.match(msg) or RE_INV.match(msg)
                    if mk and filtre.ok(mk.group('user')):
                        motif = 'Utilisateur inconnu' if ('invalid user' in msg or msg.startswith('Invalid')) else \
                            'Échec d\'authentification (%s)' % METHODES.get(mk.group('meth'), mk.group('meth'))
                        ko.append(nouvelle(d, mk.group('user'), adresse(mk.group('ip'), '')[0], '', 'SSH', 'Échec', motif))

    # Connexions SSH sans terminal (sftp, scp...) : acceptées dans secure mais absentes de wtmp
    res = []
    index = {}
    for c in wtmp:
        index.setdefault((c['user'].lower(), c['ip']), []).append(c['date'])
    for d, user, ip, meth in succes:
        dates = index.get((user.lower(), ip), [])
        if any(abs((x - d).total_seconds()) <= 10 for x in dates):
            continue
        res.append(nouvelle(d, user, ip, '', 'SSH sans terminal (sftp/scp)', motif='Authentification : %s' % METHODES.get(meth, meth)))
    # dédoublonnage des échecs (une tentative = souvent 2 lignes « Invalid user » + « Failed password »)
    vus, ko2 = set(), []
    for c in sorted(ko, key=lambda x: x['date']):
        cle = (c['user'], c['ip'], c['date'].replace(microsecond=0))
        if cle not in vus:
            vus.add(cle)
            ko2.append(c)
    return res, ko2


def demo(debut, fin, echecs):
    rnd = random.Random(42)
    users = ['root', 'jdupont', 'mmartin', 'kbenali', 'oracle', 'sbernard', 'admin01']
    ips = [('10.12.4.21', 'pc-021'), ('10.12.4.35', 'pc-035'), ('10.12.6.110', 'pc-110'),
           ('10.12.6.118', 'pc-118'), ('192.168.50.14', 'vpn-014')]
    res = []
    j = debut
    while j < fin:
        if j.weekday() < 5:
            for n, u in enumerate(users):
                if rnd.random() < 0.25:
                    continue
                ip, poste = ips[(n + (rnd.randint(0, 9) == 0)) % len(ips)]
                h = j + dt.timedelta(hours=7.5 + rnd.random() * 2.5)
                if echecs and rnd.random() < 0.08:
                    res.append(nouvelle(h - dt.timedelta(minutes=2), u, ip, poste, 'SSH', 'Échec', 'Échec d\'authentification (mot de passe)', serveur='srv-demo'))
                if rnd.random() < 0.1:
                    res.append(nouvelle(h + dt.timedelta(hours=1), u, ip, poste, 'SSH sans terminal (sftp/scp)', motif='Authentification : mot de passe', serveur='srv-demo'))
                fs = None if rnd.random() < 0.1 else h + dt.timedelta(minutes=180 + rnd.randint(0, 360))
                res.append(nouvelle(h, u, ip, poste, 'SSH (terminal)', fin=fs, serveur='srv-demo'))
        j += dt.timedelta(days=1)
    return res


# --------------------------------------------------------------------------------------------
# Synthèses
# --------------------------------------------------------------------------------------------
def cle_ip(ip):
    try:
        return (0, tuple(int(x) for x in ip.split('.'))) if re.match(r'^\d+\.\d+\.\d+\.\d+$', ip) else (1, ip)
    except ValueError:
        return (1, ip)


def synthese_ip(conn, resoudre):
    par = {}
    for c in conn:
        par.setdefault(c['ip'], []).append(c)
    res = []
    for ip, lst in par.items():
        postes = sorted({c['poste'] for c in lst if c['poste']})
        nom = ', '.join(postes)
        if resoudre and ip != LOCAL:
            try:
                h = socket.gethostbyaddr(ip)[0]
                nom = '%s (%s)' % (h, nom) if nom and nom != h else h
            except (socket.herror, socket.gaierror, OSError):
                pass
        dates = [c['date'] for c in lst]
        res.append({'ip': ip, 'nom': nom, 'lignes': sorted(lst, key=lambda c: c['date']),
                    'connexions': sum(1 for c in lst if c['resultat'] == 'Succès'),
                    'echecs': sum(1 for c in lst if c['resultat'] != 'Succès'),
                    'users': ', '.join(sorted({c['user'] for c in lst})),
                    'premiere': min(dates), 'derniere': max(dates)})
    res.sort(key=lambda s: (-s['connexions'], cle_ip(s['ip'])))
    return res


def synthese_users(conn):
    par = {}
    for c in conn:
        if c['resultat'] == 'Succès':
            par.setdefault(c['user'], []).append(c)
    res = []
    for u, lst in sorted(par.items()):
        dates = [c['date'] for c in lst]
        res.append({'user': u, 'connexions': len(lst), 'jours': len({d.date() for d in dates}),
                    'ips': ', '.join(sorted({c['ip'] for c in lst}, key=cle_ip)),
                    'premiere': min(dates), 'derniere': max(dates)})
    return res


def fmt_duree(t):
    if t is None:
        return ''
    s = int(t.total_seconds())
    j, s = divmod(s, 86400)
    h, s = divmod(s, 3600)
    m = s // 60
    return '%dj %02dh%02d' % (j, h, m) if j else '%02dh%02d' % (h, m)


# --------------------------------------------------------------------------------------------
# Rapport HTML
# --------------------------------------------------------------------------------------------
CSS = """
:root{--bleu:#1f3a5f;--bleu2:#2d5b8f;--gris:#f4f6f9;--bord:#dde3ea;--texte:#1d2733;--doux:#5f6b7a;--vert:#1e7b4a;--rouge:#b3261e}
*{box-sizing:border-box}
body{margin:0;font-family:"Segoe UI",Calibri,Arial,sans-serif;color:var(--texte);background:var(--gris);font-size:14px}
header{background:linear-gradient(135deg,var(--bleu),var(--bleu2));color:#fff;padding:28px 40px}
header h1{margin:0 0 6px;font-size:24px;font-weight:600}
header .meta{display:flex;flex-wrap:wrap;gap:8px 28px;font-size:13px;opacity:.92}
header .meta b{font-weight:600}
main{max-width:1280px;margin:0 auto;padding:24px 40px 48px}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px;margin-bottom:28px}
.kpi{background:#fff;border:1px solid var(--bord);border-left:4px solid var(--bleu2);border-radius:8px;padding:16px 20px}
.kpi .v{font-size:28px;font-weight:700;color:var(--bleu)}
.kpi .l{color:var(--doux);font-size:12px;text-transform:uppercase;letter-spacing:.04em}
.kpi.ko{border-left-color:var(--rouge)} .kpi.ko .v{color:var(--rouge)}
section{background:#fff;border:1px solid var(--bord);border-radius:8px;padding:20px 24px;margin-bottom:24px;overflow-x:auto}
h2{margin:0 0 14px;font-size:17px;color:var(--bleu);display:flex;align-items:center;gap:10px}
h2 .n{background:var(--gris);color:var(--doux);font-size:12px;border-radius:10px;padding:2px 9px;font-weight:500}
table{width:100%;border-collapse:collapse;font-size:13px}
th{background:var(--bleu);color:#fff;text-align:left;padding:9px 10px;font-weight:600;cursor:pointer;user-select:none;white-space:nowrap}
th:after{content:" \\2195";opacity:.4;font-size:11px}
th.asc:after{content:" \\25B2";opacity:1} th.desc:after{content:" \\25BC";opacity:1}
td{padding:7px 10px;border-bottom:1px solid var(--bord);vertical-align:top}
tbody tr:nth-child(even){background:#fafbfd}
tbody tr:hover{background:#eaf1fb}
td.num{text-align:right;font-variant-numeric:tabular-nums}
.ip{white-space:nowrap;font-family:Consolas,"Courier New",monospace;font-weight:600;color:var(--bleu)}
.badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:600}
.ok{background:#e3f4ea;color:var(--vert)} .err{background:#fbe6e4;color:var(--rouge)}
.muted{color:var(--doux)}
.outils{display:flex;gap:12px;align-items:center;margin-bottom:14px;flex-wrap:wrap}
.outils input{flex:1;min-width:240px;padding:9px 12px;border:1px solid var(--bord);border-radius:6px;font-size:14px}
.outils button{padding:8px 14px;border:1px solid var(--bord);background:#fff;border-radius:6px;cursor:pointer}
details{border:1px solid var(--bord);border-radius:6px;margin-bottom:10px;overflow:hidden}
summary{padding:10px 14px;background:#f7f9fc;cursor:pointer;display:flex;gap:18px;flex-wrap:wrap;align-items:center}
summary .ip{font-size:15px;min-width:150px}
summary .info{color:var(--doux);font-size:13px}
details table{border-top:1px solid var(--bord)}
footer{text-align:center;color:var(--doux);font-size:12px;padding:16px}
@media (max-width:700px){header,main{padding-left:16px;padding-right:16px}}
@media print{body{background:#fff}header{-webkit-print-color-adjust:exact;print-color-adjust:exact}.outils{display:none}section,.kpi{break-inside:avoid;border-color:#ccc}details{break-inside:avoid}}
"""

JS = """
document.querySelectorAll('table.tri').forEach(function(t){
  t.querySelectorAll('th').forEach(function(th,i){
    th.addEventListener('click',function(){
      var asc=!th.classList.contains('asc');
      t.querySelectorAll('th').forEach(function(x){x.classList.remove('asc','desc')});
      th.classList.add(asc?'asc':'desc');
      var tb=t.tBodies[0],rows=Array.prototype.slice.call(tb.rows);
      function val(r){var c=r.cells[i];if(!c)return '';var v=c.getAttribute('data-v');return v!==null?v:c.textContent.trim()}
      rows.sort(function(a,b){var x=val(a),y=val(b),nx=parseFloat(x),ny=parseFloat(y);
        var r=(!isNaN(nx)&&!isNaN(ny)&&String(nx)===x&&String(ny)===y)?nx-ny:x.localeCompare(y,'fr',{numeric:true});
        return asc?r:-r});
      rows.forEach(function(r){tb.appendChild(r)});
    });
  });
});
function basculer(o){document.querySelectorAll('#detail details').forEach(function(d){d.open=o})}
document.getElementById('recherche').addEventListener('input',function(){
  var q=this.value.toLowerCase();
  document.querySelectorAll('#detail details').forEach(function(d){
    var ipMatch=d.querySelector('summary').textContent.toLowerCase().indexOf(q)>=0,vis=0;
    d.querySelectorAll('tbody tr').forEach(function(r){var m=!q||ipMatch||r.textContent.toLowerCase().indexOf(q)>=0;r.style.display=m?'':'none';if(m)vis++});
    d.style.display=vis?'':'none'; if(q&&vis)d.open=true;
  });
});
"""


def e(v):
    return html.escape('' if v is None else str(v))


def rapport_html(conn, sip, susers, args, debut, fin, serveur, chemin):
    F = '%d/%m/%Y %H:%M:%S'
    ok = [c for c in conn if c['resultat'] == 'Succès']
    ko = [c for c in conn if c['resultat'] != 'Succès']
    comptes = 'Tous les utilisateurs' if args.utilisateurs == ['*'] else ', '.join(args.utilisateurs)
    if args.groupes:
        comptes += (' + ' if comptes else '') + 'membres de ' + ', '.join(args.groupes)
    sources = 'wtmp' + (' + btmp' if args.echecs and not args.secure else '') + (' + secure' if args.secure else '')
    o = []
    w = o.append
    w('<!DOCTYPE html>\n<html lang="fr">\n<head>\n<meta charset="utf-8">\n'
      '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
      '<title>Rapport des connexions</title>\n<style>%s</style>\n</head>\n<body>\n' % CSS)
    w('<header><h1>Rapport des connexions utilisateurs</h1><div class="meta">'
      '<span><b>Serveur :</b> %s</span><span><b>Période :</b> du %s au %s</span>'
      '<span><b>Comptes :</b> %s</span><span><b>Sources :</b> %s</span><span><b>Généré le :</b> %s</span></div></header>\n<main>\n'
      % (e(serveur), debut.strftime('%d/%m/%Y %H:%M'), fin.strftime('%d/%m/%Y %H:%M'), e(comptes), e(sources),
         dt.datetime.now().strftime('%d/%m/%Y à %H:%M')))
    w('<div class="kpis"><div class="kpi"><div class="v">%d</div><div class="l">Connexions réussies</div></div>'
      '<div class="kpi"><div class="v">%d</div><div class="l">Utilisateurs distincts</div></div>'
      '<div class="kpi"><div class="v">%d</div><div class="l">Adresses IP distinctes</div></div>'
      % (len(ok), len({c['user'] for c in ok}), len(sip)))
    if args.echecs:
        w('<div class="kpi ko"><div class="v">%d</div><div class="l">Tentatives échouées</div></div>' % len(ko))
    w('</div>\n')

    # Synthèse par IP
    w('<section><h2>Synthèse par adresse IP <span class="n">%d</span></h2>\n<table class="tri"><thead><tr>'
      '<th>Adresse IP</th><th>Nom / poste</th><th>Connexions</th>%s<th>Utilisateurs</th>'
      '<th>Première connexion</th><th>Dernière connexion</th></tr></thead><tbody>\n'
      % (len(sip), '<th>Échecs</th>' if args.echecs else ''))
    for s in sip:
        k = cle_ip(s['ip'])
        tri = '.'.join('%03d' % x for x in k[1]) if k[0] == 0 else 'zzz' + s['ip']
        w('<tr><td class="ip" data-v="%s">%s</td><td>%s</td><td class="num">%d</td>%s<td>%s</td>'
          '<td data-v="%s">%s</td><td data-v="%s">%s</td></tr>\n'
          % (e(tri), e(s['ip']), e(s['nom']), s['connexions'],
             '<td class="num">%d</td>' % s['echecs'] if args.echecs else '', e(s['users']),
             s['premiere'].isoformat(), s['premiere'].strftime(F), s['derniere'].isoformat(), s['derniere'].strftime(F)))
    w('</tbody></table></section>\n')

    # Synthèse par utilisateur
    w('<section><h2>Synthèse par utilisateur <span class="n">%d</span></h2>\n<table class="tri"><thead><tr>'
      '<th>Utilisateur</th><th>Connexions</th><th>Jours de présence</th><th>Adresses IP</th>'
      '<th>Première connexion</th><th>Dernière connexion</th></tr></thead><tbody>\n' % len(susers))
    for s in susers:
        w('<tr><td><b>%s</b></td><td class="num">%d</td><td class="num">%d</td><td class="ip">%s</td>'
          '<td data-v="%s">%s</td><td data-v="%s">%s</td></tr>\n'
          % (e(s['user']), s['connexions'], s['jours'], e(s['ips']), s['premiere'].isoformat(), s['premiere'].strftime(F),
             s['derniere'].isoformat(), s['derniere'].strftime(F)))
    w('</tbody></table></section>\n')

    # Détail par IP
    w('<section><h2>Détail des connexions par adresse IP <span class="n">%d ligne(s)</span></h2>\n'
      '<div class="outils"><input id="recherche" type="search" placeholder="Filtrer : utilisateur, IP, date (ex. 15/09), poste...">'
      '<button onclick="basculer(true)">Tout déplier</button><button onclick="basculer(false)">Tout replier</button></div>\n'
      '<div id="detail">\n' % len(conn))
    for s in sip:
        nom = ' &middot; %s' % e(s['nom']) if s['nom'] else ''
        w('<details open><summary><span class="ip">%s</span><span class="info">%d connexion(s)%s &middot; %s</span></summary>\n'
          '<table class="tri"><thead><tr><th>Date</th><th>Heure</th><th>Utilisateur</th><th>Poste</th><th>Type</th>'
          '<th>Résultat</th><th>Déconnexion</th><th>Durée</th></tr></thead><tbody>\n'
          % (e(s['ip']), s['connexions'], nom, e(s['users'])))
        for c in s['lignes']:
            if c['resultat'] == 'Succès':
                res = '<span class="badge ok">Succès</span>'
                if c['motif']:
                    res += ' <span class="muted">%s</span>' % e(c['motif'])
                deco = c['fin'].strftime('%d/%m %H:%M') if c['fin'] else '<span class="muted">—</span>'
            else:
                res = '<span class="badge err">Échec</span> <span class="muted">%s</span>' % e(c['motif'])
                deco = ''
            w('<tr><td data-v="%s">%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td>'
              '<td class="num" data-v="%d">%s</td></tr>\n'
              % (c['date'].isoformat(), c['date'].strftime('%d/%m/%Y'), c['date'].strftime('%H:%M:%S'), e(c['user']),
                 e(c['poste']), e(c['type']), res, deco, int(c['duree'].total_seconds()) if c['duree'] else -1,
                 fmt_duree(c['duree'])))
        w('</tbody></table></details>\n')
    if not sip:
        w('<p class="muted">Aucune connexion trouvée sur la période pour les comptes demandés.</p>')
    w('</div></section>\n</main>\n<footer>Sources : %s &middot; rapport_connexions.py</footer>\n<script>%s</script>\n</body>\n</html>\n'
      % (e(sources), JS))
    with io.open(chemin, 'w', encoding='utf-8') as f:
        f.write(''.join(o))


def ecrire_csv(chemin, entetes, lignes):
    with io.open(chemin, 'w', encoding='utf-8-sig', newline='') as f:
        wr = csv.writer(f, delimiter=';', quoting=csv.QUOTE_ALL)
        wr.writerow(entetes)
        wr.writerows(lignes)


# --------------------------------------------------------------------------------------------
# Programme principal
# --------------------------------------------------------------------------------------------
def main():
    p = argparse.ArgumentParser(description='Rapport des connexions utilisateurs classé par adresse IP (Linux / Red Hat).')
    p.add_argument('--mois', help='Mois à analyser AAAA-MM (ex. 2026-09)')
    p.add_argument('--debut', help='Date de début AAAA-MM-JJ (incluse)')
    p.add_argument('--fin', help='Date de fin AAAA-MM-JJ (exclue)')
    p.add_argument('-u', '--utilisateurs', default='*',
                   help='Comptes à inclure, séparés par des virgules, jokers acceptés, insensible à la casse (défaut : * = tous les utilisateurs)')
    p.add_argument('-g', '--groupes', default='', help='Groupes Linux dont les membres sont inclus (ex. wheel)')
    p.add_argument('--echecs', action='store_true', help='Inclure les tentatives de connexion échouées')
    p.add_argument('--secure', action='store_true',
                   help='Lire aussi /var/log/secure* : connexions sftp/scp (sans terminal) et motifs des échecs')
    p.add_argument('--wtmp', nargs='*', help='Fichiers wtmp à lire (défaut : /var/log/wtmp*)')
    p.add_argument('--btmp', nargs='*', help='Fichiers btmp à lire (défaut : /var/log/btmp*)')
    p.add_argument('--secure-fichiers', nargs='*', help='Fichiers secure à lire (défaut : /var/log/secure*)')
    p.add_argument('--resoudre-dns', action='store_true', help='Résoudre le nom DNS des adresses IP')
    p.add_argument('-o', '--sortie', help='Dossier de sortie (défaut : ./Rapports à côté du script)')
    p.add_argument('--demo', action='store_true', help='Données fictives pour prévisualiser le rendu')
    args = p.parse_args()

    maintenant = dt.datetime.now()
    if args.mois:
        if not re.match(r'^\d{4}-\d{2}$', args.mois):
            p.error('--mois doit être au format AAAA-MM')
        debut = dt.datetime.strptime(args.mois + '-01', '%Y-%m-%d')
        fin = (debut + dt.timedelta(days=32)).replace(day=1)
    else:
        debut = dt.datetime.strptime(args.debut, '%Y-%m-%d') if args.debut else maintenant.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        fin = dt.datetime.strptime(args.fin, '%Y-%m-%d') if args.fin else maintenant
    if fin <= debut:
        p.error('la date de fin doit être postérieure à la date de début')

    args.groupes = [g.strip() for g in args.groupes.split(',') if g.strip()]
    utils = [u.strip() for u in args.utilisateurs.split(',') if u.strip()]
    if args.groupes and args.utilisateurs == p.get_default('utilisateurs'):
        utils = []
    args.utilisateurs = utils

    sortie = args.sortie or os.path.join(os.path.dirname(os.path.abspath(__file__)), 'Rapports')
    if not os.path.isdir(sortie):
        os.makedirs(sortie)

    serveur = 'srv-demo' if args.demo else socket.gethostname().split('.')[0]
    print('\n=== Rapport des connexions utilisateurs ===')
    print('  Serveur : %s' % serveur)
    print('  Période : %s -> %s' % (debut.strftime('%d/%m/%Y %H:%M'), fin.strftime('%d/%m/%Y %H:%M')))
    print('  Comptes : %s' % (', '.join(utils + ['groupe:' + g for g in args.groupes]).replace('*', 'tous') or 'tous'))

    if args.demo:
        print('  Mode démo : données fictives')
        conn = demo(debut, fin, args.echecs)
    else:
        if os.geteuid() != 0:
            print('  ATTENTION : lancer avec sudo, sinon btmp et secure ne sont pas lisibles.', file=sys.stderr)
        filtre = Filtre(utils, args.groupes)
        conn = collecter_wtmp(fichiers('/var/log/wtmp', args.wtmp), debut, fin, filtre)
        if args.secure:
            sup, ko = collecter_secure(fichiers('/var/log/secure', args.secure_fichiers), debut, fin, filtre, conn, args.echecs)
            conn += sup + ko
        elif args.echecs:
            conn += collecter_btmp(fichiers('/var/log/btmp', args.btmp), debut, fin, filtre)
        if not conn:
            print('  Aucune connexion trouvée. Vérifier que les fichiers wtmp couvrent la période : '
                  'ls -l /var/log/wtmp*  /  last -F -f /var/log/wtmp-XXXX | tail', file=sys.stderr)

    conn.sort(key=lambda c: (cle_ip(c['ip']), c['date']))
    print('  %d connexion(s) retenue(s)' % len(conn))
    sip = synthese_ip(conn, args.resoudre_dns)
    susers = synthese_users(conn)

    suffixe = args.mois or '%s-%s' % (debut.strftime('%Y%m%d'), fin.strftime('%Y%m%d'))
    base = os.path.join(sortie, 'Connexions_%s_%s_%s' % (re.sub(r'[^\w\-]', '_', serveur), suffixe, maintenant.strftime('%Y%m%d-%H%M%S')))

    ecrire_csv(base + '_detail.csv',
               ['Serveur', 'Adresse IP', 'Date', 'Heure', 'Utilisateur', 'Poste', 'Type de connexion', 'Résultat', 'Motif', 'Déconnexion', 'Durée'],
               [[c['serveur'], c['ip'], c['date'].strftime('%d/%m/%Y'), c['date'].strftime('%H:%M:%S'), c['user'], c['poste'],
                 c['type'], c['resultat'], c['motif'], c['fin'].strftime('%d/%m/%Y %H:%M:%S') if c['fin'] else '',
                 fmt_duree(c['duree'])] for c in conn])
    ecrire_csv(base + '_synthese_IP.csv',
               ['Adresse IP', 'Nom / poste', 'Connexions', 'Échecs', 'Utilisateurs', 'Première connexion', 'Dernière connexion'],
               [[s['ip'], s['nom'], s['connexions'], s['echecs'], s['users'], s['premiere'].strftime('%d/%m/%Y %H:%M:%S'),
                 s['derniere'].strftime('%d/%m/%Y %H:%M:%S')] for s in sip])
    rapport_html(conn, sip, susers, args, debut, fin, serveur, base + '.html')

    print('\nFichiers générés :')
    for s in ('.html', '_detail.csv', '_synthese_IP.csv'):
        print('  ' + base + s)
    if sip:
        print('\n  %-18s %11s  %s' % ('Adresse IP', 'Connexions', 'Utilisateurs'))
        for s in sip:
            print('  %-18s %11d  %s' % (s['ip'], s['connexions'], s['users']))
    print()


if __name__ == '__main__':
    main()
