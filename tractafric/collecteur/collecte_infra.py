# -*- coding: utf-8 -*-
"""Collecteur du portail d'infrastructure IRIUM iE (Tractafric).

Lancé par cron sur chaque serveur (BDD, REPL, APP1, APP2, APP3, API), il prend un instantané en lecture seule :
  - système  : OS, charge, CPU, mémoire, disques, processus IRIUM, services, réseau ;
  - cron     : tâches planifiées (crontabs, /etc/cron.d) et exécutions des dernières 24 h (/var/log/cron) ;
  - Informix : état du moteur, réplication, dbspaces, checkpoints, cache, sessions par serveur d'applications ;
  - IRIUM    : journal des connexions agr_lds (interactif ou cron), dernière connexion par utilisateur ;
  - API      : disponibilité et temps de réponse des URL déclarées.

Il écrit <PARTAGE>/donnees/<NOM>/dernier.json et ajoute une ligne à historique.jsonl (tendances).
Rien n'est écrit en dehors du partage, aucun service n'est ajouté. Compatible Python 2.7 et 3.6+ (RHEL 7 à 9).
"""
from __future__ import division, print_function, unicode_literals

import datetime as dt
import io
import json
import os
import re
import socket
import subprocess
import sys
import time

try:
    str = unicode  # noqa: F821  (Python 2.7)
except NameError:
    pass

VERSION = '1.0'
ICI = os.path.dirname(os.path.abspath(__file__))


# --------------------------------------------------------------------------------------------
# Configuration (fichier tractafric.conf, format shell CLE=valeur, partagé par tous les serveurs)
# --------------------------------------------------------------------------------------------
def lire_conf(chemin):
    conf = {}
    if not chemin or not os.path.exists(chemin):
        return conf
    with io.open(chemin, encoding='utf-8') as f:
        for ligne in f:
            ligne = ligne.strip()
            m = re.match(r'^([A-Z_][A-Z0-9_]*)=(.*)$', ligne)
            if not m:
                continue
            val = m.group(2).strip()
            if len(val) >= 2 and val[0] == val[-1] and val[0] in '"\'':
                val = val[1:-1]
            conf[m.group(1)] = val
    return conf


def serveurs_conf(conf):
    """SERVEURS="BDD:srv-bdd01:bdd:10.0.1.11 REPL:srv-bdd02:repl:10.0.1.12 ..." -> liste de dicts (IP facultative)."""
    res = []
    for item in conf.get('SERVEURS', '').split():
        p = item.split(':')
        if len(p) >= 3:
            res.append({'nom': p[0], 'hote': p[1], 'role': p[2].lower(), 'ip': p[3] if len(p) > 3 else ''})
    return res


def adresses_locales():
    code, out = lancer(['hostname', '-I'], 10)
    return set(out.split()) if code == 0 else set()


def identifier(conf, nom=None, role=None):
    if nom and role:
        return nom, role
    court = socket.gethostname().split('.')[0].lower()
    ips = None
    for s in serveurs_conf(conf):
        if nom and s['nom'] == nom:
            return s['nom'], role or s['role']
        if not nom and s['hote'].split('.')[0].lower() == court:
            return s['nom'], role or s['role']
    for s in serveurs_conf(conf):
        if not nom and s['ip']:
            ips = adresses_locales() if ips is None else ips
            if s['ip'] in ips:
                return s['nom'], role or s['role']
    return nom or court.upper(), role or 'app'


# --------------------------------------------------------------------------------------------
# Outils
# --------------------------------------------------------------------------------------------
def existe(cmd):
    return any(os.access(os.path.join(d, cmd), os.X_OK) for d in os.environ.get('PATH', '').split(os.pathsep))


def lancer(cmd, delai=60, entree=None):
    """Exécute une commande (liste), retourne (code, sortie texte). Délai via la commande timeout."""
    if existe('timeout'):
        cmd = ['timeout', str(delai)] + list(cmd)
    try:
        p = subprocess.Popen(cmd, stdin=subprocess.PIPE if entree is not None else None,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        out, _ = p.communicate(entree.encode('utf-8') if entree is not None else None)
        return p.returncode, out.decode('utf-8', 'replace')
    except OSError as e:
        return 127, '%s' % e


def lire(chemin, defaut=''):
    try:
        with io.open(chemin, encoding='utf-8', errors='replace') as f:
            return f.read()
    except (IOError, OSError):
        return defaut


def nombre(v, defaut=None):
    try:
        return float(str(v).replace(',', '.'))
    except (TypeError, ValueError):
        return defaut


# --------------------------------------------------------------------------------------------
# Système
# --------------------------------------------------------------------------------------------
def parse_meminfo(texte):
    m = {}
    for l in texte.splitlines():
        p = l.split()
        if len(p) >= 2 and p[0].endswith(':'):
            m[p[0][:-1]] = int(p[1])
    total = m.get('MemTotal', 0)
    dispo = m.get('MemAvailable', m.get('MemFree', 0) + m.get('Buffers', 0) + m.get('Cached', 0))
    st, sf = m.get('SwapTotal', 0), m.get('SwapFree', 0)
    return {'total_ko': total, 'dispo_ko': dispo,
            'pct': round(100 * (total - dispo) / total, 1) if total else None,
            'swap_total_ko': st, 'swap_pct': round(100 * (st - sf) / st, 1) if st else 0.0,
            'thp': None}


def parse_df(texte):
    res = []
    for l in texte.splitlines()[1:]:
        p = l.split()
        if len(p) < 6 or not p[1].isdigit():
            continue
        taille, util = int(p[1]), int(p[2])
        res.append({'fs': p[0], 'montage': p[5], 'taille_ko': taille, 'utilise_ko': util,
                    'pct': round(100 * util / taille, 1) if taille else 0.0})
    return res


def stat_cpu():
    l = lire('/proc/stat').splitlines()
    v = [int(x) for x in l[0].split()[1:]] if l else []
    return v


def cpu_pct(intervalle=1.0):
    a = stat_cpu()
    time.sleep(intervalle)
    b = stat_cpu()
    if not a or not b:
        return None, None
    d = [y - x for x, y in zip(a, b)]
    tot = sum(d) or 1
    repos = d[3] + (d[4] if len(d) > 4 else 0)
    return round(100 * (tot - repos) / tot, 1), round(100 * (d[4] if len(d) > 4 else 0) / tot, 1)


def os_release():
    t = lire('/etc/redhat-release').strip()
    if t:
        return t
    m = re.search(r'^PRETTY_NAME="?([^"\n]+)', lire('/etc/os-release'), re.M)
    return m.group(1) if m else ''


def collecter_systeme(conf):
    s = {'hote': socket.gethostname(), 'os': os_release(), 'noyau': os.uname()[2],
         'ncpu': len(re.findall(r'^processor\s*:', lire('/proc/cpuinfo'), re.M)) or None}
    up = lire('/proc/uptime').split()
    s['uptime_s'] = int(float(up[0])) if up else None
    s['charge'] = [nombre(x) for x in lire('/proc/loadavg').split()[:3]]
    s['cpu_pct'], s['iowait_pct'] = cpu_pct()
    s['memoire'] = parse_meminfo(lire('/proc/meminfo'))
    thp = lire('/sys/kernel/mm/transparent_hugepage/enabled')
    m = re.search(r'\[(\w+)\]', thp)
    s['memoire']['thp'] = m.group(1) if m else None
    _, out = lancer(['df', '-P', '-k', '-x', 'tmpfs', '-x', 'devtmpfs', '-x', 'squashfs', '-x', 'overlay'], 30)
    s['disques'] = parse_df(out)
    _, out = lancer(['ps', '-eo', 'pid,user,pcpu,pmem,rss,etime,comm', '--sort=-pcpu'], 30)
    top = []
    for l in out.splitlines()[1:9]:
        p = l.split(None, 6)
        if len(p) == 7:
            top.append({'pid': p[0], 'utilisateur': p[1], 'cpu': nombre(p[2]), 'mem': nombre(p[3]),
                        'rss_ko': int(p[4]) if p[4].isdigit() else None, 'duree': p[5], 'commande': p[6]})
    s['top_processus'] = top
    _, out = lancer(['ps', '-eo', 'user,rss,args'], 30)
    motifs = [m for m in conf.get('MOTIFS_PROCESSUS', 'fglrun|ipscrond|oninit|httpd|java').split('|') if m]
    proc = dict((m, {'nombre': 0, 'rss_ko': 0, 'utilisateurs': 0}) for m in motifs)
    utils = dict((m, set()) for m in motifs)
    for l in out.splitlines()[1:]:
        p = l.split(None, 2)
        if len(p) < 3:
            continue
        prog = os.path.basename(p[2].split()[0]) if p[2].split() else ''
        for m in motifs:
            if prog == m or prog.startswith(m) or (' ' + m) in p[2]:
                proc[m]['nombre'] += 1
                proc[m]['rss_ko'] += int(p[1]) if p[1].isdigit() else 0
                utils[m].add(p[0])
                break
    for m in motifs:
        proc[m]['utilisateurs'] = len(utils[m])
    s['processus'] = proc
    services = {}
    for svc in conf.get('SERVICES', 'crond sshd').split():
        if existe('systemctl'):
            code, out = lancer(['systemctl', 'is-active', svc], 15)
            services[svc] = out.strip().splitlines()[-1] if out.strip() else ('active' if code == 0 else 'inconnu')
        else:
            code, _ = lancer(['service', svc, 'status'], 15)
            services[svc] = 'active' if code == 0 else 'inactive'
    s['services'] = services
    code, out = lancer(['who'], 10)
    s['sessions_ssh'] = len([l for l in out.splitlines() if l.strip()]) if code == 0 else None
    if existe('ss'):
        _, out = lancer(['ss', '-tn', 'state', 'established'], 15)
        s['tcp_etablies'] = max(0, len(out.splitlines()) - 1)
        _, out = lancer(['ss', '-ltn'], 15)
        ports = set()
        for l in out.splitlines()[1:]:
            p = l.split()
            if len(p) >= 4 and ':' in p[3]:
                port = p[3].rsplit(':', 1)[1]
                if port.isdigit():
                    ports.add(int(port))
        s['ports_ecoute'] = sorted(ports)
    return s


# --------------------------------------------------------------------------------------------
# Cron : tâches planifiées et exécutions récentes
# --------------------------------------------------------------------------------------------
RE_ENV = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*\s*=')


def parse_crontab(texte, source, utilisateur=None):
    """utilisateur=None : fichier système (/etc/crontab, /etc/cron.d) où la 6e colonne est l'utilisateur."""
    res = []
    for l in texte.splitlines():
        l = l.strip()
        if not l or l.startswith('#') or RE_ENV.match(l):
            continue
        if l.startswith('@'):
            p = l.split(None, 2 if utilisateur is None else 1)
            plan, reste = p[0], p[1:]
        else:
            p = l.split(None, 6 if utilisateur is None else 5)
            if len(p) < (7 if utilisateur is None else 6):
                continue
            plan, reste = ' '.join(p[:5]), p[5:]
        if utilisateur is None:
            if len(reste) < 2:
                continue
            u, cmd = reste[0], reste[1]
        else:
            if not reste:
                continue
            u, cmd = utilisateur, reste[0]
        res.append({'source': source, 'utilisateur': u, 'planification': plan, 'commande': cmd.strip()})
    return res


RE_LOG_CRON = re.compile(r'^(\w{3}\s+\d+\s+[\d:]{8})\s+\S+\s+CROND\[\d+\]:\s+\((\S+)\)\s+CMD\s+\((.*)\)\s*$')


def parse_log_cron(texte, annee=None, maintenant=None):
    """Exécutions par (utilisateur, commande) sur les dernières 24 h : nombre et dernière date."""
    maintenant = maintenant or dt.datetime.now()
    annee = annee or maintenant.year
    limite = maintenant - dt.timedelta(hours=24)
    res = {}
    for l in texte.splitlines():
        m = RE_LOG_CRON.match(l)
        if not m:
            continue
        try:
            t = dt.datetime.strptime('%d %s' % (annee, re.sub(r'\s+', ' ', m.group(1))), '%Y %b %d %H:%M:%S')
        except ValueError:
            continue
        if t > maintenant + dt.timedelta(days=1):  # passage d'année
            t = t.replace(year=annee - 1)
        if t < limite:
            continue
        cle = '%s|%s' % (m.group(2), m.group(3).strip())
        e = res.setdefault(cle, {'nombre': 0, 'derniere': None})
        e['nombre'] += 1
        e['derniere'] = max(e['derniere'] or '', t.strftime('%Y-%m-%d %H:%M:%S'))
    return res


def collecter_cron(conf):
    taches = []
    taches += parse_crontab(lire('/etc/crontab'), '/etc/crontab')
    if os.path.isdir('/etc/cron.d'):
        for f in sorted(os.listdir('/etc/cron.d')):
            taches += parse_crontab(lire(os.path.join('/etc/cron.d', f)), '/etc/cron.d/' + f)
    vus = set()
    spool = '/var/spool/cron'
    if os.path.isdir(spool) and os.access(spool, os.R_OK):
        for u in sorted(os.listdir(spool)):
            if os.path.isfile(os.path.join(spool, u)):
                taches += parse_crontab(lire(os.path.join(spool, u)), 'crontab ' + u, u)
                vus.add(u)
    for u in conf.get('COMPTES_CRONTAB', 'root informix').split():
        if u in vus:
            continue
        code, out = lancer(['crontab', '-l', '-u', u], 15)
        if code == 0:
            taches += parse_crontab(out, 'crontab ' + u, u)
    journal = lire('/var/log/cron')
    execs = parse_log_cron(journal[-5000000:]) if journal else {}
    for t in taches:
        e = execs.get('%s|%s' % (t['utilisateur'], t['commande']))
        t['executions_24h'] = e['nombre'] if e else (None if not journal else 0)
        t['derniere_execution'] = e['derniere'] if e else None
    return {'taches': taches, 'journal_lisible': bool(journal)}


# --------------------------------------------------------------------------------------------
# Informix
# --------------------------------------------------------------------------------------------
def env_informix(conf):
    env = dict(os.environ)
    for k in ('INFORMIXDIR', 'INFORMIXSERVER', 'ONCONFIG', 'INFORMIXSQLHOSTS'):
        if conf.get(k):
            env[k] = conf[k]
    if env.get('INFORMIXDIR'):
        env['PATH'] = os.path.join(env['INFORMIXDIR'], 'bin') + os.pathsep + env.get('PATH', '')
    os.environ.update(env)
    return env


def parse_onstat_entete(texte):
    m = re.search(r'Version\s+(\S+)\s+--\s+(.+?)\s+--\s+Up\s+(.+?)\s+--\s+(\d+)\s+Kbytes', texte)
    if not m:
        return None
    return {'version': m.group(1), 'mode': m.group(2).strip(), 'depuis': m.group(3).strip(),
            'memoire_ko': int(m.group(4))}


def parse_profil(texte):
    """onstat -p : lignes d'en-têtes suivies de leurs valeurs (même nombre de colonnes)."""
    res, lignes = {}, [l.split() for l in texte.splitlines()]
    for i in range(len(lignes) - 1):
        ent, val = lignes[i], lignes[i + 1]
        if ent and val and len(ent) == len(val) and not nombre(ent[0]) and all(nombre(v) is not None for v in val):
            for k, v in zip(ent, val):
                k = k.lower()
                res[k if k not in res else k + '_2'] = nombre(v)
    return res


def ratio_cache(p):
    if not p.get('bufreads'):
        return None
    lus = p.get('pagreads', p.get('dskreads', 0))
    return round(max(0.0, 100 * (1 - lus / p['bufreads'])), 2)


def parse_checkpoints(texte):
    res = []
    for l in texte.splitlines():
        p = l.split()
        if len(p) >= 8 and p[0].isdigit() and re.match(r'^\d\d:\d\d:\d\d$', p[1]):
            res.append({'heure': p[1], 'declencheur': p[2], 'total_s': nombre(p[4]), 'blocage_s': nombre(p[6]),
                        'attentes': int(nombre(p[7], 0))})
    return res


def parse_logs(texte):
    n = utilises = non_sauves = 0
    for l in texte.splitlines():
        p = l.split()
        if len(p) >= 8 and re.match(r'^(0x)?[0-9a-fA-F]+$', p[0]) and p[1].isdigit() and re.match(r'^[UFACBL-]{7}$', p[2]):
            n += 1
            if 'U' in p[2]:
                utilises += 1
                if 'B' not in p[2]:
                    non_sauves += 1
    return {'nombre': n, 'utilises': utilises, 'non_sauvegardes': non_sauves}


def parse_rss(texte):
    info, serveurs = {}, []
    for l in texte.splitlines():
        m = re.match(r'^\s*([A-Za-z][A-Za-z /#\-]+?)\s*:\s*(.+)$', l)
        if m:
            info[m.group(1).strip().lower()] = m.group(2).strip()
    m = re.search(r'Backlog[^:]*:\s*(\d+)', texte, re.I)
    for l in texte.splitlines():
        p = l.split()
        if len(p) >= 3 and p[1].lower() in ('active', 'connecting', 'disconnected', 'defined', 'quiescent'):
            serveurs.append({'nom': p[0], 'etat': p[1]})
    return {'champs': info, 'retard_pages': int(m.group(1)) if m else None, 'serveurs': serveurs}


def dbaccess(conf, base, requete, travail):
    """SELECT en lecture seule via dbaccess, résultat au format unload. Retourne une liste de listes."""
    chemin = os.path.join(travail, 'requete_%d.unl' % os.getpid())
    if os.path.exists(chemin):
        os.unlink(chemin)
    sql = ("SET ISOLATION TO DIRTY READ;\nSET LOCK MODE TO WAIT 5;\nUNLOAD TO '%s' DELIMITER '|' %s;\n"
           % (chemin, requete.strip().rstrip(';')))
    code, out = lancer(['dbaccess', base, '-'], int(conf.get('DELAI_SQL', '120')), sql)
    if code != 0 or not os.path.exists(chemin):
        raise RuntimeError('dbaccess %s : %s' % (base, out.strip()[-300:]))
    try:
        return parse_unload(io.open(chemin, encoding=conf.get('ENCODAGE_BASE', 'latin-1'), errors='replace').read())
    finally:
        os.unlink(chemin)


def parse_unload(texte):
    lignes, tampon = [], ''
    for brut in texte.splitlines(True):
        if brut.endswith('\\\n'):
            tampon += brut[:-2] + '\n'
            continue
        brut = tampon + brut.rstrip('\n')
        tampon = ''
        champs = re.split(r'(?<!\\)\|', brut)
        if champs and champs[-1] == '':
            champs = champs[:-1]
        lignes.append([c.replace('\\|', '|').strip() for c in champs])
    return lignes


def collecter_informix(conf, travail, erreurs):
    env_informix(conf)
    if not existe('onstat'):
        return None
    _, out = lancer(['onstat', '-'], 30)
    ifx = {'entete': parse_onstat_entete(out)}
    if not ifx['entete']:
        ifx['etat'] = 'arrete'
        ifx['message'] = out.strip()[-200:]
        return ifx
    ifx['etat'] = 'actif'
    _, out = lancer(['onstat', '-p'], 30)
    p = parse_profil(out)
    ifx['profil'] = dict((k, p.get(k)) for k in ('dskreads', 'pagreads', 'bufreads', 'dskwrits', 'bufwrits', 'isamtot',
                                                  'lockreqs', 'lockwts', 'deadlks', 'ckpwaits', 'seqscans', 'bufwaits'))
    ifx['cache_pct'] = ratio_cache(p)
    _, out = lancer(['onstat', '-g', 'ckp'], 30)
    ifx['checkpoints'] = parse_checkpoints(out)[-20:]
    _, out = lancer(['onstat', '-l'], 30)
    ifx['logs'] = parse_logs(out)
    _, out = lancer(['onstat', '-g', 'rss', 'verbose'], 30)
    ifx['replication'] = parse_rss(out)
    if not existe('dbaccess') or conf.get('SQL', 'oui') == 'non':
        return ifx
    try:
        ifx['sessions'] = int(dbaccess(conf, 'sysmaster', 'SELECT COUNT(*) FROM syssessions', travail)[0][0])
        ifx['sessions_par_hote'] = [{'hote': l[0].split('.')[0], 'nombre': int(l[1])} for l in dbaccess(
            conf, 'sysmaster', 'SELECT hostname, COUNT(*) FROM syssessions GROUP BY 1 ORDER BY 2 DESC', travail)[:30]]
        ifx['sessions_par_compte'] = [{'compte': l[0], 'nombre': int(l[1])} for l in dbaccess(
            conf, 'sysmaster', 'SELECT username, COUNT(*) FROM syssessions GROUP BY 1 ORDER BY 2 DESC', travail)[:15]]
    except Exception as e:
        erreurs.append('sessions Informix : %s' % e)
    try:
        ifx['dbspaces'] = [{'nom': l[0], 'temp': l[1] == '1', 'sb': l[2] == '1', 'taille_mo': round(nombre(l[3], 0)),
                            'libre_mo': round(nombre(l[4], 0))} for l in dbaccess(
            conf, 'sysmaster', 'SELECT d.name, d.is_temp, d.is_sbspace, SUM(c.chksize * c.pagesize) / 1048576, '
            'SUM(c.nfree * c.pagesize) / 1048576 FROM sysdbspaces d, syschunks c WHERE d.dbsnum = c.dbsnum '
            'GROUP BY 1, 2, 3 ORDER BY 1', travail)]
    except Exception as e:
        erreurs.append('dbspaces : %s' % e)
    return ifx


# --------------------------------------------------------------------------------------------
# Connexions IRIUM : journal agr_lds (un enregistrement par programme lancé)
# --------------------------------------------------------------------------------------------
INDICES_COLONNES = [
    ('date', [r'_open$', r'debut', r'date', r'_ts$']),
    ('fin', [r'_close$', r'_fin$', r'_end$']),
    ('utilisateur', [r'user', r'util', r'login', r'operat']),
    ('programme', [r'prog', r'appli', r'module', r'_cmd', r'_nom']),
    ('poste', [r'host', r'poste', r'term', r'_tty']),
    ('ip', [r'_ip$', r'addr', r'adress']),
    ('complement', [r'compl']),
]


def deviner_colonnes(cols, conf):
    choix = {}
    for role, motifs in INDICES_COLONNES:
        forcee = conf.get('COLONNE_' + role.upper(), '').strip()
        if forcee:
            choix[role] = forcee
            continue
        for motif in motifs:
            trouve = [c for c in cols if re.search(motif, c, re.I) and c not in choix.values()]
            if trouve:
                choix[role] = trouve[0]
                break
    return choix


def expression_cron(roles, conf):
    """Expression SQL qui classe une ligne en 'cron' (lancée par la planification) ou 'interactif'."""
    cond = []
    if 'complement' in roles:
        cond += ["%s MATCHES '%s'" % (roles['complement'], m.replace("'", ''))
                 for m in conf.get('MOTIFS_CRON', 'Xp_cron*').split()]
    if 'utilisateur' in roles and conf.get('COMPTES_CRON'):
        cond.append('%s IN (%s)' % (roles['utilisateur'],
                                    ', '.join("'%s'" % u.replace("'", '') for u in conf['COMPTES_CRON'].split())))
    if 'poste' in roles and conf.get('POSTES_CRON'):
        cond.append('%s IN (%s)' % (roles['poste'],
                                    ', '.join("'%s'" % u.replace("'", '') for u in conf['POSTES_CRON'].split())))
    return ("CASE WHEN %s THEN 'cron' ELSE 'interactif' END" % ' OR '.join(cond)) if cond else "'interactif'"


def collecter_connexions(conf, travail, erreurs):
    base, table = conf.get('BASE', ''), conf.get('TABLE_CONNEXIONS', 'agr_lds')
    if not base or not re.match(r'^\w+$', base) or not re.match(r'^\w+$', table) or not existe('dbaccess'):
        return None
    cols = [l[0] for l in dbaccess(conf, base, "SELECT TRIM(c.colname) FROM syscolumns c, systables t WHERE "
                                   "t.tabname = '%s' AND c.tabid = t.tabid ORDER BY c.colno" % table, travail) if l]
    if not cols:
        raise RuntimeError('table %s introuvable dans %s' % (table, base))
    r = deviner_colonnes(cols, conf)
    if 'date' not in r:
        raise RuntimeError('colonne de date introuvable dans %s (renseigner COLONNE_DATE)' % table)
    typ = expression_cron(r, conf)
    col = lambda k: r.get(k, "''")
    heures = int(conf.get('CONNEXIONS_HEURES', '24'))
    jours = int(conf.get('CONNEXIONS_JOURS_TENDANCE', '7'))
    plafond = int(conf.get('CONNEXIONS_MAX', '20000'))
    maint = dt.datetime.now()
    depuis = (maint - dt.timedelta(hours=heures)).strftime('%Y-%m-%d %H:%M:%S')
    res = {'table': '%s:%s' % (base, table), 'colonnes': r, 'fenetre_heures': heures}
    lignes = dbaccess(conf, base, 'SELECT FIRST %d %s, %s, %s, %s, %s, %s, %s FROM %s WHERE %s >= \'%s\' ORDER BY 1 DESC' % (
        plafond, r['date'], col('fin'), col('utilisateur'), col('programme'), col('poste'), col('ip'), typ,
        table, r['date'], depuis), travail)
    res['detail'] = [{'debut': l[0][:19], 'fin': (l[1] or '')[:19], 'utilisateur': l[2], 'programme': l[3],
                      'poste': l[4], 'ip': l[5], 'type': l[6]} for l in lignes if len(l) >= 7]
    res['tronque'] = len(lignes) >= plafond
    debut_t = (maint - dt.timedelta(days=jours)).strftime('%Y-%m-%d 00:00:00')
    try:
        res['par_heure'] = [{'heure': l[0], 'type': l[1], 'nombre': int(l[2])} for l in dbaccess(
            conf, base, "SELECT TO_CHAR(%s, '%%Y-%%m-%%d %%H'), %s, COUNT(*) FROM %s WHERE %s >= '%s' GROUP BY 1, 2"
            % (r['date'], typ, table, r['date'], debut_t), travail)]
    except Exception as e:
        erreurs.append('connexions par heure : %s' % e)
    if 'utilisateur' in r:
        try:
            d90 = (maint - dt.timedelta(days=int(conf.get('DERNIERE_CONNEXION_JOURS', '90')))).strftime('%Y-%m-%d')
            res['derniere_connexion'] = [{'utilisateur': l[0], 'derniere': l[1][:19], 'nombre': int(l[2]), 'type': l[3]}
                                         for l in dbaccess(
                conf, base, "SELECT %s, MAX(%s), COUNT(*), %s FROM %s WHERE %s >= '%s' GROUP BY 1, 4" % (
                    r['utilisateur'], r['date'], typ, table, r['date'], d90), travail) if len(l) >= 4]
        except Exception as e:
            erreurs.append('dernière connexion : %s' % e)
    return res


# --------------------------------------------------------------------------------------------
# API : disponibilité et temps de réponse
# --------------------------------------------------------------------------------------------
def tester_url(url, verifier=True, delai=10):
    try:
        import urllib.request as rq
        import urllib.error as er
    except ImportError:  # Python 2.7
        import urllib2 as rq
        er = rq
    import ssl
    ctx = None
    if url.startswith('https'):
        ctx = ssl.create_default_context()
        if not verifier:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
    t0 = time.time()
    try:
        r = rq.urlopen(rq.Request(url, headers={'User-Agent': 'portail-infra/%s' % VERSION}), timeout=delai, context=ctx)
        code = r.getcode()
        r.read(65536)
        err = ''
    except er.HTTPError as e:
        code, err = e.code, ''
    except Exception as e:
        code, err = None, ('%s' % e)[:200]
    return {'url': url, 'code': code, 'ms': int((time.time() - t0) * 1000), 'erreur': err,
            'ok': code is not None and code < 500}


def collecter_api(conf):
    urls = conf.get('URLS_API', '').split()
    verif = conf.get('VERIFIER_CERTIFICAT_API', 'oui') != 'non'
    return [tester_url(u, verif) for u in urls]


# --------------------------------------------------------------------------------------------
# Instantané
# --------------------------------------------------------------------------------------------
def conf_serveur(conf, nom):
    """Valeurs propres à un serveur : CLE_<NOM> l'emporte sur CLE (ex. INFORMIXSERVER_REPL=ol_tractafric_rss)."""
    res = dict(conf)
    suffixe = '_' + nom.upper()
    for k, v in conf.items():
        if k.endswith(suffixe) and len(k) > len(suffixe):
            res[k[:-len(suffixe)]] = v
    return res


def instantane(conf, nom, role, travail):
    conf = conf_serveur(conf, nom)
    maint = dt.datetime.now()
    snap = {'collecteur': VERSION, 'nom': nom, 'role': role, 'horodatage': maint.strftime('%Y-%m-%d %H:%M:%S'),
            'epoch': int(time.time()), 'erreurs': []}
    etapes = [('systeme', lambda: collecter_systeme(conf)), ('cron', lambda: collecter_cron(conf))]
    if role in ('bdd', 'repl'):
        etapes.append(('informix', lambda: collecter_informix(conf, travail, snap['erreurs'])))
    if role == 'bdd':
        etapes.append(('connexions', lambda: collecter_connexions(conf, travail, snap['erreurs'])))
    if conf.get('URLS_API') and (role == 'api' or conf.get('API_DEPUIS') == nom):
        etapes.append(('api', lambda: collecter_api(conf)))
    for cle, fn in etapes:
        t0 = time.time()
        try:
            snap[cle] = fn()
        except Exception as e:
            snap[cle] = None
            snap['erreurs'].append('%s : %s' % (cle, e))
        snap.setdefault('durees', {})[cle] = round(time.time() - t0, 2)
    return snap


def resume(snap):
    """Ligne d'historique (tendances sur quelques jours)."""
    s = snap.get('systeme') or {}
    i = snap.get('informix') or {}
    a = snap.get('api') or []
    ckp = [c['total_s'] for c in i.get('checkpoints', []) if c.get('total_s') is not None]
    return {'t': snap['horodatage'], 'cpu': s.get('cpu_pct'), 'iowait': s.get('iowait_pct'),
            'mem': (s.get('memoire') or {}).get('pct'), 'swap': (s.get('memoire') or {}).get('swap_pct'),
            'charge': (s.get('charge') or [None])[0], 'disque_max': max([d['pct'] for d in s.get('disques', [])] or [None]),
            'sessions': i.get('sessions'), 'cache': i.get('cache_pct'), 'ckp_max': max(ckp) if ckp else None,
            'retard_rss': (i.get('replication') or {}).get('retard_pages'),
            'api_ms': max([x['ms'] for x in a] or [None]) if a else None,
            'api_ok': all(x['ok'] for x in a) if a else None}


def ecrire_json(chemin, donnees):
    tmp = chemin + '.tmp'
    with io.open(tmp, 'w', encoding='utf-8') as f:
        f.write(str(json.dumps(donnees, ensure_ascii=False, indent=1, sort_keys=True)))
    os.rename(tmp, chemin)


def ajouter_historique(chemin, ligne, jours):
    limite = (dt.datetime.now() - dt.timedelta(days=jours)).strftime('%Y-%m-%d %H:%M:%S')
    anciennes = []
    if os.path.exists(chemin):
        with io.open(chemin, encoding='utf-8') as f:
            for l in f:
                try:
                    if json.loads(l).get('t', '') >= limite:
                        anciennes.append(l.rstrip('\n'))
                except ValueError:
                    continue
    anciennes.append(str(json.dumps(ligne, ensure_ascii=False, sort_keys=True)))
    tmp = chemin + '.tmp'
    with io.open(tmp, 'w', encoding='utf-8') as f:
        f.write('\n'.join(anciennes) + '\n')
    os.rename(tmp, chemin)


def main(argv):
    import argparse
    ap = argparse.ArgumentParser(description="Collecteur du portail d'infrastructure IRIUM iE")
    ap.add_argument('--conf', default=os.path.join(os.path.dirname(ICI), 'tractafric.conf'))
    ap.add_argument('--nom', help='nom du serveur dans le portail (BDD, REPL, APP1...) ; défaut : déduit de SERVEURS')
    ap.add_argument('--role', choices=['bdd', 'repl', 'app', 'api'])
    ap.add_argument('--partage', help='dossier de stockage (défaut : PARTAGE du fichier de configuration)')
    ap.add_argument('--stdout', action='store_true',
                    help="écrire l'instantané sur la sortie standard (collecte centralisée par SSH) au lieu du partage")
    a = ap.parse_args(argv)
    conf = lire_conf(a.conf)
    nom, role = identifier(conf, a.nom, a.role)
    if a.stdout:  # appel distant : seul un dossier de travail à côté du script (fichiers unload de dbaccess)
        travail = os.path.join(ICI, 'travail')
        if not os.path.isdir(travail):
            os.makedirs(travail)
        snap = instantane(conf, nom, role, travail)
        sys.stdout.write(json.dumps(snap, ensure_ascii=True, sort_keys=True) + '\n')  # ASCII : sûr même sous LANG=C
        return 0
    partage = a.partage or conf.get('PARTAGE') or os.path.join(os.path.dirname(ICI), 'donnees-portail')
    dossier = os.path.join(partage, 'donnees', nom)
    travail = os.path.join(partage, 'travail')
    for d in (dossier, travail):
        if not os.path.isdir(d):
            os.makedirs(d)
    snap = instantane(conf, nom, role, travail)
    ecrire_json(os.path.join(dossier, 'dernier.json'), snap)
    ajouter_historique(os.path.join(dossier, 'historique.jsonl'), resume(snap), int(conf.get('CONSERVATION_JOURS', '7')))
    print('%s %s (%s) : instantané écrit dans %s%s' % (snap['horodatage'], nom, role, dossier,
                                                         ' ; %d erreur(s) : %s' % (len(snap['erreurs']), ' | '.join(snap['erreurs']))
                                                         if snap['erreurs'] else ''))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
