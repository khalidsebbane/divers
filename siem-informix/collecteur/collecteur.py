#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Collecteur SIEM Informix - à installer sur le serveur de base de données (RHEL 7/8/9).

Lit les sources suivantes, les met au format commun et les envoie au portail :

  Volet système     : /var/log/wtmp*, /var/log/btmp*, /var/log/secure*, /var/log/audit/audit.log*
  Volet base        : audit Informix (onshowaudit), sessions sysmaster:syssessions
  Volet applicatif  : table applicative des programmes lancés (ex. agr_lds)

Contraintes : Python 3.6+ uniquement, bibliothèque standard seulement (fonctionne avec
/usr/libexec/platform-python sur RHEL 8, sans rien installer).

Deux modes de fonctionnement :
  - piloté (recommandé) : le portail SIEM, sur un serveur isolé, déclenche la collecte par SSH avec une clé
    à commande forcée (« --distant »). Rien ne tourne en permanence sur le serveur de base, aucun port ouvert.
  - autonome : lancé par cron/systemd, il pousse les événements vers le portail en HTTPS.

Usage :
  /usr/libexec/platform-python collecteur.py --distant                     # mode piloté (appelé par le portail)
  /usr/libexec/platform-python collecteur.py -c collecteur.ini            # une passe (cron / timer)
  /usr/libexec/platform-python collecteur.py -c collecteur.ini --test     # affiche sans envoyer
  /usr/libexec/platform-python collecteur.py -c collecteur.ini --depuis 2026-09-01
"""
from __future__ import print_function

import argparse
import configparser
import datetime as dt
import glob
import gzip
import hashlib
import io
import json
import os
import pwd
import re
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import urllib.request

VERSION = '1.0'
SERVEUR = socket.gethostname().split('.')[0]


def log(msg):
    print('[%s] %s' % (dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S'), msg), file=sys.stderr)


# --------------------------------------------------------------------------------------------
# Format commun des événements
# --------------------------------------------------------------------------------------------
def evenement(ts, source, categorie, action, compte='', utilisateur='', ip='', poste='', session='',
              objet='', resultat='succes', details=None, brut=''):
    """Un événement normalisé. ts : datetime local. source : systeme | base | applicatif."""
    ev = {
        'ts': ts.strftime('%Y-%m-%dT%H:%M:%S'),
        'source': source, 'categorie': categorie, 'action': action,
        'serveur': SERVEUR, 'compte': compte or '', 'utilisateur': utilisateur or compte or '',
        'ip': ip or '', 'poste': poste or '', 'session': session or '', 'objet': objet or '',
        'resultat': resultat, 'details': details or {}, 'brut': (brut or '')[:2000],
    }
    cle = '|'.join(str(ev[k]) for k in ('ts', 'source', 'categorie', 'action', 'serveur', 'compte',
                                         'ip', 'session', 'objet', 'brut'))
    ev['empreinte'] = hashlib.sha1(cle.encode('utf-8', 'replace')).hexdigest()
    return ev


def ouvrir_texte(chemin):
    if chemin.endswith('.gz'):
        return gzip.open(chemin, 'rt', errors='replace')
    return io.open(chemin, encoding='utf-8', errors='replace')


def fichiers(motif):
    return sorted(set(glob.glob(motif)))


# --------------------------------------------------------------------------------------------
# Volet système : wtmp / btmp (struct utmp Linux 384 octets)
# --------------------------------------------------------------------------------------------
UTMP_FMT = '<hi32s4s32s256shhiii16s20s'
UTMP_SIZE = struct.calcsize(UTMP_FMT)
BOOT_TIME, USER_PROCESS, DEAD_PROCESS = 2, 7, 8


def _txt(b):
    return b.split(b'\0', 1)[0].decode('utf-8', 'replace').strip()


def lire_utmp(chemin):
    with (gzip.open(chemin, 'rb') if chemin.endswith('.gz') else open(chemin, 'rb')) as f:
        data = f.read()
    res = []
    for i in range(0, len(data) - UTMP_SIZE + 1, UTMP_SIZE):
        typ, pid, line, _id, user, host, _a, _b, _s, sec, usec, addr, _u = struct.unpack_from(UTMP_FMT, data, i)
        ip = ''
        if addr[4:] == b'\0' * 12:
            if addr[:4] != b'\0' * 4:
                ip = socket.inet_ntop(socket.AF_INET, addr[:4])
        else:
            ip = socket.inet_ntop(socket.AF_INET6, addr)
        res.append({'type': typ, 'line': _txt(line), 'user': _txt(user), 'host': _txt(host), 'ip': ip,
                    'date': dt.datetime.fromtimestamp(sec + usec / 1e6).replace(microsecond=0)})
    return res


def _est_ip(s):
    for fam in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(fam, s)
            return True
        except (OSError, ValueError):
            pass
    return False


def adresse(host, ip):
    host = (host or '').replace('::ffff:', '')
    ip = (ip or '').replace('::ffff:', '')
    if _est_ip(host):
        return host, ''
    if ip and ip not in ('0.0.0.0', '::'):
        return ip, host
    if not host or host.startswith(':') or host.startswith('tmux') or host.startswith('screen'):
        return 'local', host
    return host, host


def type_ligne(line):
    if line.startswith('pts/'):
        return 'SSH (terminal)'
    if line.startswith('tty') or line.startswith(':') or line == 'console':
        return 'Console'
    return line or 'Autre'


def collecter_wtmp(conf, depuis):
    enr = []
    for f in fichiers(conf.get('systeme', 'wtmp', fallback='/var/log/wtmp*')):
        try:
            enr.extend(lire_utmp(f))
        except (IOError, OSError) as e:
            log('wtmp illisible %s : %s' % (f, e))
    enr.sort(key=lambda r: r['date'])
    res, ouvertes = [], {}
    for r in enr:
        if r['type'] == USER_PROCESS and r['user']:
            ip, poste = adresse(r['host'], r['ip'])
            sess = 'ssh:%s:%s' % (r['line'], r['date'].strftime('%Y%m%d%H%M%S'))
            ouvertes[r['line']] = (sess, r['user'], ip, poste, r['date'])
            if r['date'] >= depuis:
                res.append(evenement(r['date'], 'systeme', 'connexion', 'Ouverture de session ' + type_ligne(r['line']),
                                     compte=r['user'], ip=ip, poste=poste, session=sess,
                                     details={'terminal': r['line']}))
        elif r['type'] == DEAD_PROCESS and r['line'] in ouvertes:
            sess, user, ip, poste, debut = ouvertes.pop(r['line'])
            if r['date'] >= depuis:
                res.append(evenement(r['date'], 'systeme', 'deconnexion', 'Fermeture de session',
                                     compte=user, ip=ip, poste=poste, session=sess,
                                     details={'duree_s': int((r['date'] - debut).total_seconds())}))
        elif r['type'] == BOOT_TIME:
            if r['date'] >= depuis:
                res.append(evenement(r['date'], 'systeme', 'serveur', 'Démarrage du serveur', compte='system'))
            ouvertes = {}
    return res


def collecter_btmp(conf, depuis):
    res = []
    for f in fichiers(conf.get('systeme', 'btmp', fallback='/var/log/btmp*')):
        try:
            enr = lire_utmp(f)
        except (IOError, OSError) as e:
            log('btmp illisible %s : %s' % (f, e))
            continue
        for r in enr:
            if r['date'] >= depuis and r['user']:
                ip, poste = adresse(r['host'], r['ip'])
                res.append(evenement(r['date'], 'systeme', 'echec_connexion', 'Échec de connexion',
                                     compte=r['user'], ip=ip, poste=poste, resultat='echec'))
    return res


# --------------------------------------------------------------------------------------------
# Volet système : /var/log/secure (sftp/scp, sudo, su)
# --------------------------------------------------------------------------------------------
MOIS_EN = {m: i for i, m in enumerate(['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'], 1)}
RE_SYSLOG = re.compile(r'^(?:(?P<iso>\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)\S*|(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d+)\s+(?P<hms>\d\d:\d\d:\d\d))'
                       r'\s+\S+\s+(?P<prog>[\w\-/.]+)(?:\[\d+\])?:\s+(?P<msg>.*)$')
RE_ACCEPT = re.compile(r'^Accepted (?P<meth>\S+) for (?P<user>\S+) from (?P<ip>\S+) port')
RE_FAILED = re.compile(r'^Failed (?P<meth>\S+) for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port')
RE_SUDO = re.compile(r'^\s*(?P<user>\S+) : (?:.*?; )?TTY=(?P<tty>\S+) ; PWD=(?P<pwd>.*?) ; USER=(?P<cible>\S+) ; COMMAND=(?P<cmd>.*)$')
RE_SU = re.compile(r"pam_unix\(su(?:-l)?:session\): session opened for user (?P<cible>\S+) by (?P<user>\S*)\(uid=(?P<uid>\d+)\)")


def _date_syslog(m, annee_ref):
    if m.group('iso'):
        return dt.datetime.strptime(m.group('iso'), '%Y-%m-%dT%H:%M:%S')
    mois = MOIS_EN.get(m.group('mon'))
    if not mois:
        return None
    annee = annee_ref.year - (1 if mois > annee_ref.month else 0)
    h, mi, s = (int(x) for x in m.group('hms').split(':'))
    try:
        return dt.datetime(annee, mois, int(m.group('day')), h, mi, s)
    except ValueError:
        return None


def collecter_secure(conf, depuis):
    res = []
    for f in fichiers(conf.get('systeme', 'secure', fallback='/var/log/secure*')):
        try:
            ref = dt.datetime.fromtimestamp(os.path.getmtime(f))
            fh = ouvrir_texte(f)
        except (IOError, OSError) as e:
            log('secure illisible %s : %s' % (f, e))
            continue
        with fh:
            for ligne in fh:
                ligne = ligne.rstrip('\n')
                m = RE_SYSLOG.match(ligne)
                if not m:
                    continue
                d = _date_syslog(m, ref)
                if d is None or d < depuis:
                    continue
                prog, msg = m.group('prog'), m.group('msg')
                if prog == 'sshd':
                    a = RE_ACCEPT.match(msg)
                    if a:
                        res.append(evenement(d, 'systeme', 'authentification', 'Authentification SSH (%s)' % a.group('meth'),
                                             compte=a.group('user'), ip=a.group('ip'), brut=ligne))
                        continue
                    a = RE_FAILED.match(msg)
                    if a:
                        res.append(evenement(d, 'systeme', 'echec_connexion', 'Échec SSH (%s)' % a.group('meth'),
                                             compte=a.group('user'), ip=a.group('ip'), resultat='echec', brut=ligne))
                elif prog == 'sudo':
                    a = RE_SUDO.match(msg)
                    if a:
                        res.append(evenement(d, 'systeme', 'sudo', 'sudo vers %s' % a.group('cible'),
                                             compte=a.group('cible'), utilisateur=a.group('user'),
                                             objet=a.group('cmd')[:500], details={'repertoire': a.group('pwd'), 'tty': a.group('tty')},
                                             resultat='echec' if 'command not allowed' in msg else 'succes', brut=ligne))
                elif prog in ('su', 'su-l'):
                    a = RE_SU.search(msg)
                    if a:
                        res.append(evenement(d, 'systeme', 'changement_compte', 'su vers %s' % a.group('cible'),
                                             compte=a.group('cible'), utilisateur=a.group('user') or _nom_uid(a.group('uid')),
                                             brut=ligne))
    return res


# --------------------------------------------------------------------------------------------
# Volet système : auditd (commandes et fichiers sensibles, avec l'utilisateur d'origine « auid »)
# --------------------------------------------------------------------------------------------
RE_AUDIT = re.compile(r'type=(?P<type>\S+) msg=audit\((?P<sec>\d+)\.\d+:(?P<serial>\d+)\):\s*(?P<corps>.*)$')
RE_CHAMP = re.compile(r'(\w+)=("(?:[^"]*)"|\S+)')
_cache_uid = {}


def _nom_uid(uid):
    try:
        uid = int(uid)
    except (TypeError, ValueError):
        return ''
    if uid in (4294967295, -1):
        return ''
    if uid not in _cache_uid:
        try:
            _cache_uid[uid] = pwd.getpwuid(uid).pw_name
        except KeyError:
            _cache_uid[uid] = 'uid%d' % uid
    return _cache_uid[uid]


def _hexdec(v):
    v = v.strip('"')
    if re.match(r'^[0-9A-Fa-f]+$', v) and len(v) % 2 == 0 and len(v) >= 4:
        try:
            return bytes.fromhex(v).replace(b'\0', b' ').decode('utf-8', 'replace').strip()
        except ValueError:
            pass
    return v


def collecter_auditd(conf, depuis):
    groupes = {}
    for f in fichiers(conf.get('systeme', 'auditd', fallback='/var/log/audit/audit.log*')):
        try:
            fh = ouvrir_texte(f)
        except (IOError, OSError) as e:
            log('audit.log illisible %s : %s' % (f, e))
            continue
        with fh:
            for ligne in fh:
                m = RE_AUDIT.match(ligne.strip())
                if not m:
                    continue
                ts = dt.datetime.fromtimestamp(int(m.group('sec')))
                if ts < depuis:
                    continue
                champs = {}
                for k, v in RE_CHAMP.findall(m.group('corps')):
                    champs.setdefault(k, v.strip('"'))
                g = groupes.setdefault((m.group('sec'), m.group('serial')), {'ts': ts, 'recs': {}})
                g['recs'].setdefault(m.group('type'), []).append((champs, ligne.strip()))

    res = []
    for (_sec, serial), g in sorted(groupes.items(), key=lambda kv: kv[1]['ts']):
        recs, ts = g['recs'], g['ts']
        if 'SYSCALL' in recs:
            sc, brut = recs['SYSCALL'][0]
            cle = sc.get('key', '')
            if not cle.startswith('siem'):
                continue
            auid, uid = _nom_uid(sc.get('auid')), _nom_uid(sc.get('uid'))
            cmd = ''
            if 'EXECVE' in recs:
                ex = recs['EXECVE'][0][0]
                args = []
                for i in range(int(ex.get('argc', '0') or 0)):
                    if 'a%d' % i in ex:
                        args.append(_hexdec(ex['a%d' % i]))
                cmd = ' '.join(args)
            if not cmd and 'PROCTITLE' in recs:
                cmd = _hexdec(recs['PROCTITLE'][0][0].get('proctitle', ''))
            chemins = [p[0].get('name', '').strip('"') for p in recs.get('PATH', []) if p[0].get('name')]
            objet = cmd or ', '.join(chemins) or sc.get('exe', '')
            libelle = {'siem_exec_informix': 'Commande Informix', 'siem_conf_informix': 'Modification config Informix',
                       'siem_identite': 'Modification comptes/mots de passe', 'siem_sudoers': 'Modification sudoers',
                       'siem_cmd': 'Commande exécutée', 'siem_donnees_informix': 'Accès fichiers de données Informix'}.get(cle, cle)
            res.append(evenement(ts, 'systeme', 'commande' if 'EXECVE' in recs else 'fichier', libelle,
                                 compte=uid, utilisateur=auid or uid, objet=objet[:500],
                                 resultat='succes' if sc.get('success', 'yes') == 'yes' else 'echec',
                                 session='audit:%s' % sc.get('ses', ''),
                                 details={'exe': sc.get('exe', '').strip('"'), 'cle': cle, 'chemins': chemins[:5],
                                          'tty': sc.get('tty', ''), 'serial': serial}, brut=brut))
        elif 'USER_CMD' in recs:
            uc, brut = recs['USER_CMD'][0]
            res.append(evenement(ts, 'systeme', 'sudo', 'sudo', compte=_nom_uid(uc.get('uid')),
                                 utilisateur=_nom_uid(uc.get('auid')), objet=_hexdec(uc.get('cmd', ''))[:500],
                                 resultat='succes' if 'res=success' in brut else 'echec', brut=brut))
    return res


# --------------------------------------------------------------------------------------------
# Volet base : utilitaires dbaccess
# --------------------------------------------------------------------------------------------
def env_informix(conf):
    env = dict(os.environ)
    for k in ('INFORMIXDIR', 'INFORMIXSERVER', 'ONCONFIG', 'INFORMIXSQLHOSTS', 'DBDATE', 'CLIENT_LOCALE', 'DB_LOCALE'):
        v = conf.get('informix', k.lower(), fallback='')
        if v:
            env[k] = v
    if env.get('INFORMIXDIR'):
        env['PATH'] = os.path.join(env['INFORMIXDIR'], 'bin') + os.pathsep + env.get('PATH', '')
    env.setdefault('DBDATE', 'Y4MD-')
    return env


def dbaccess_unload(conf, base, requete):
    """Exécute un SELECT via dbaccess et retourne les lignes (liste de listes)."""
    fd, chemin = tempfile.mkstemp(prefix='siem_', suffix='.unl')
    os.close(fd)
    os.unlink(chemin)
    sql = "UNLOAD TO '%s' DELIMITER '|' %s;\n" % (chemin, requete.strip().rstrip(';'))
    try:
        p = subprocess.Popen(['dbaccess', base, '-'], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, env=env_informix(conf), universal_newlines=True)
        _out, err = p.communicate(sql, timeout=int(conf.get('informix', 'timeout', fallback='120')))
        if p.returncode != 0 or not os.path.exists(chemin):
            raise RuntimeError('dbaccess %s : %s' % (base, err.strip()[-400:]))
        lignes = []
        with io.open(chemin, encoding=conf.get('informix', 'encodage', fallback='latin-1'), errors='replace') as f:
            tampon = ''
            for brut in f:
                # un champ peut contenir un retour ligne échappé par « \ »
                if brut.endswith('\\\n'):
                    tampon += brut[:-2] + '\n'
                    continue
                brut = tampon + brut.rstrip('\n')
                tampon = ''
                champs = re.split(r'(?<!\\)\|', brut)
                if champs and champs[-1] == '':
                    champs = champs[:-1]
                lignes.append([c.replace('\\|', '|') for c in champs])
        return lignes
    finally:
        if os.path.exists(chemin):
            os.unlink(chemin)


def parse_date(s):
    s = (s or '').strip()
    for fmt in ('%Y-%m-%d %H:%M:%S.%f', '%Y-%m-%d %H:%M:%S', '%Y-%m-%d %H:%M', '%Y-%m-%d', '%d/%m/%Y %H:%M:%S', '%d/%m/%Y'):
        try:
            return dt.datetime.strptime(s[:26], fmt)
        except ValueError:
            pass
    return None


# --------------------------------------------------------------------------------------------
# Volet base : sessions sysmaster (qui est connecté, depuis quelle machine)
# --------------------------------------------------------------------------------------------
def collecter_sessions(conf, etat):
    req = ('SELECT s.sid, s.username, s.hostname, s.tty, s.pid, s.connected, s.uid '
           'FROM sysmaster:syssessions s WHERE s.sid <> DBINFO("sessionid")')
    lignes = dbaccess_unload(conf, 'sysmaster', req)
    vues = etat.setdefault('sessions_bdd', {})
    actuelles = {}
    res = []
    for l in lignes:
        if len(l) < 6:
            continue
        sid, user, host, tty, pid, connected = l[:6]
        uid = l[6] if len(l) > 6 else ''
        cle = '%s:%s' % (sid, connected)
        actuelles[cle] = [user, host, tty, pid, connected, uid]
        if cle not in vues:
            ts = dt.datetime.fromtimestamp(int(connected)) if connected.isdigit() else dt.datetime.now()
            ip = host if _est_ip(host) else _resoudre(host, conf)
            res.append(evenement(ts, 'base', 'connexion', 'Ouverture de session base', compte=user,
                                 ip=ip, poste=host, session='bdd:' + cle,
                                 details={'sid': sid, 'pid_client': pid, 'terminal': tty,
                                          'compte_os_client': _nom_uid(uid) if uid else ''}))
    maintenant = dt.datetime.now().replace(microsecond=0)
    for cle, (user, host, tty, pid, connected, uid) in vues.items():
        if cle not in actuelles:
            debut = dt.datetime.fromtimestamp(int(connected)) if str(connected).isdigit() else maintenant
            res.append(evenement(maintenant, 'base', 'deconnexion', 'Fin de session base', compte=user,
                                 ip=host if _est_ip(host) else _resoudre(host, conf), poste=host, session='bdd:' + cle,
                                 details={'duree_s': int((maintenant - debut).total_seconds()), 'precision': 'à la minute'}))
    etat['sessions_bdd'] = actuelles
    return res


_cache_dns = {}


def _resoudre(host, conf):
    if not host or conf.get('informix', 'resoudre_ip', fallback='oui') != 'oui':
        return ''
    if host not in _cache_dns:
        try:
            _cache_dns[host] = socket.gethostbyname(host)
        except (socket.gaierror, OSError, UnicodeError):
            _cache_dns[host] = ''
    return _cache_dns[host]


# --------------------------------------------------------------------------------------------
# Volet base : audit Informix (onaudit / onshowaudit)
# --------------------------------------------------------------------------------------------
# Codes d'audit Informix les plus utiles (liste complète : documentation « Audit event mnemonics »).
CODES_AUDIT = {
    'CRDB': ('ddl', 'Création de base'), 'DRDB': ('ddl', 'Suppression de base'),
    'OPDB': ('acces', 'Ouverture de base'), 'CLDB': ('acces', 'Fermeture de base'),
    'CRTB': ('ddl', 'Création de table'), 'DRTB': ('ddl', 'Suppression de table'),
    'ALTB': ('ddl', 'Modification de table'), 'RNTB': ('ddl', 'Renommage de table'),
    'CRVW': ('ddl', 'Création de vue'), 'DRVW': ('ddl', 'Suppression de vue'),
    'CRIX': ('ddl', 'Création d\'index'), 'DRIX': ('ddl', 'Suppression d\'index'),
    'CRSP': ('ddl', 'Création de procédure'), 'DRSP': ('ddl', 'Suppression de procédure'),
    'CRTR': ('ddl', 'Création de trigger'), 'DRTR': ('ddl', 'Suppression de trigger'),
    'GRDB': ('droits', 'GRANT sur base'), 'RVDB': ('droits', 'REVOKE sur base'),
    'GRTB': ('droits', 'GRANT sur table'), 'RVTB': ('droits', 'REVOKE sur table'),
    'CRRL': ('droits', 'Création de rôle'), 'DRRL': ('droits', 'Suppression de rôle'),
    'GRRL': ('droits', 'Attribution de rôle'), 'RVRL': ('droits', 'Retrait de rôle'),
    'INRW': ('dml', 'Insertion de ligne'), 'UPRW': ('dml', 'Modification de ligne'),
    'DLRW': ('dml', 'Suppression de ligne'), 'RDRW': ('lecture', 'Lecture de ligne'),
    'ONAU': ('admin', 'Commande onaudit'), 'ONMN': ('admin', 'Commande onmonitor'),
    'ONMO': ('admin', 'Commande onmode'), 'ONSP': ('admin', 'Commande onspaces'),
    'ONPA': ('admin', 'Commande onparams'), 'ONTP': ('admin', 'Commande ontape'),
    'ONBR': ('admin', 'Commande onbar'), 'ONLD': ('admin', 'Chargement onload'),
    'ONUL': ('admin', 'Déchargement onunload'), 'STSN': ('acces', 'SET SESSION AUTHORIZATION'),
}


def collecter_onaudit(conf, depuis):
    """Lit la sortie de onshowaudit (positions des champs configurables, voir docs/informix-audit.md)."""
    lignes = []
    cmd = conf.get('informix', 'commande_onshowaudit', fallback='')
    if cmd:
        try:
            p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 env=env_informix(conf), universal_newlines=True, errors='replace')
            out, err = p.communicate(timeout=int(conf.get('informix', 'timeout', fallback='120')))
            if p.returncode != 0:
                log('onshowaudit : %s' % err.strip()[-300:])
            lignes = out.splitlines()
        except (OSError, subprocess.TimeoutExpired) as e:
            log('onshowaudit impossible : %s' % e)
    for f in fichiers(conf.get('informix', 'fichiers_onshowaudit', fallback='') or '/nonexistent'):
        with ouvrir_texte(f) as fh:
            lignes.extend(l.rstrip('\n') for l in fh)

    i_date = conf.getint('informix', 'audit_champ_date', fallback=1)
    i_host = conf.getint('informix', 'audit_champ_machine', fallback=2)
    i_pid = conf.getint('informix', 'audit_champ_pid', fallback=3)
    i_user = conf.getint('informix', 'audit_champ_utilisateur', fallback=5)
    i_err = conf.getint('informix', 'audit_champ_erreur', fallback=6)
    i_code = conf.getint('informix', 'audit_champ_code', fallback=7)
    i_obj = conf.getint('informix', 'audit_champ_objet', fallback=8)
    res = []
    for l in lignes:
        champs = [x.strip() for x in l.split('|')]
        if len(champs) <= max(i_date, i_user, i_code) or not re.match(r'^[A-Z]{4}$', champs[0]):
            continue
        # Ligne type : ONLN|date heure|machine|pid|serveur|utilisateur|erreur|CODE|base|objet...
        code = champs[i_code] if re.match(r'^[A-Z]{4}$', champs[i_code]) else champs[0]
        ts = parse_date(champs[i_date])
        if ts is None or ts < depuis:
            continue
        cat, libelle = CODES_AUDIT.get(code, ('audit', 'Audit %s' % code))
        host = champs[i_host] if len(champs) > i_host else ''
        err = champs[i_err] if len(champs) > i_err else '0'
        objet = ':'.join(c for c in champs[i_obj:] if c) if len(champs) > i_obj else ''
        res.append(evenement(ts, 'base', cat, libelle, compte=champs[i_user], ip=_resoudre(host, conf),
                             poste=host, objet=objet[:500], resultat='succes' if err in ('0', '') else 'echec',
                             session='pid:%s' % (champs[i_pid] if len(champs) > i_pid else ''),
                             details={'code': code, 'erreur': err}, brut=l))
    return res


# --------------------------------------------------------------------------------------------
# Volet applicatif : table des programmes lancés (ex. agr_lds)
# --------------------------------------------------------------------------------------------
INDICES_COLONNES = {
    'date': [r'_open$', r'debut', r'date', r'_ts$'],
    'fin': [r'_close$', r'_fin$', r'_end$'],
    'utilisateur': [r'user', r'util', r'login', r'operat'],
    'programme': [r'prog', r'appli', r'module', r'_cmd', r'_nom'],
    'ip': [r'_ip$', r'addr', r'adress'],
    'poste': [r'host', r'poste', r'term', r'_tty'],
}


def colonnes_table(conf, base, table):
    req = ("SELECT c.colname FROM syscolumns c, systables t WHERE t.tabname = '%s' "
           "AND c.tabid = t.tabid ORDER BY c.colno" % table.replace("'", ''))
    return [l[0].strip() for l in dbaccess_unload(conf, base, req) if l]


def deviner_colonnes(cols, conf):
    choix = {}
    for role, motifs in INDICES_COLONNES.items():
        forcee = conf.get('applicatif', 'colonne_' + role, fallback='').strip()
        if forcee:
            choix[role] = forcee
            continue
        for motif in motifs:
            trouve = [c for c in cols if re.search(motif, c, re.I) and c not in choix.values()]
            if trouve:
                choix[role] = trouve[0]
                break
    return choix


def collecter_applicatif(conf, depuis):
    base = conf.get('applicatif', 'base')
    table = conf.get('applicatif', 'table', fallback='agr_lds')
    cols = colonnes_table(conf, base, table)
    if not cols:
        raise RuntimeError('table %s introuvable dans la base %s' % (table, base))
    roles = deviner_colonnes(cols, conf)
    if 'date' not in roles:
        raise RuntimeError('colonne de date introuvable dans %s, renseigner colonne_date' % table)
    filtre = conf.get('applicatif', 'filtre', fallback="(alds_complement IS NULL OR alds_complement NOT MATCHES 'Xp_cron*')")
    req = 'SELECT %s FROM %s WHERE %s >= \'%s\'%s ORDER BY %s' % (
        ', '.join(cols), table, roles['date'], depuis.strftime('%Y-%m-%d %H:%M:%S'),
        (' AND ' + filtre) if filtre.strip() else '', roles['date'])
    comptes_app = conf.get('applicatif', 'compte_base', fallback='')
    res = []
    for l in dbaccess_unload(conf, base, req):
        ligne = dict(zip(cols, l))
        ts = parse_date(ligne.get(roles['date']))
        if ts is None or ts < depuis:
            continue
        val = lambda r: (ligne.get(roles[r], '') or '').strip() if r in roles else ''
        fin = parse_date(val('fin'))
        details = {k: v for k, v in ligne.items() if v not in ('', None)}
        if fin:
            details['duree_s'] = int((fin - ts).total_seconds())
        prog = val('programme') or ligne.get('alds_complement', '')
        res.append(evenement(ts, 'applicatif', 'programme', 'Lancement de programme',
                             compte=comptes_app, utilisateur=val('utilisateur'), ip=val('ip'), poste=val('poste'),
                             objet=prog, details=details, session='app:%s' % (l[0] if l else ''),
                             brut='|'.join(l)))
    return res


# --------------------------------------------------------------------------------------------
# Envoi au portail
# --------------------------------------------------------------------------------------------
def envoyer(conf, evts, spool):
    url = conf.get('portail', 'url', fallback='')
    if not url:  # pas de portail joignable : tout reste en attente (transfert manuel possible)
        ecrire_spool(spool, evts)
        return False
    ctx = ssl.create_default_context(cafile=conf.get('portail', 'ca', fallback=None) or None)
    if conf.get('portail', 'verifier_certificat', fallback='oui') == 'non':
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    lot = int(conf.get('portail', 'taille_lot', fallback='1000'))
    for i in range(0, len(evts), lot):
        corps = json.dumps({'serveur': SERVEUR, 'version': VERSION, 'evenements': evts[i:i + lot]}).encode('utf-8')
        req = urllib.request.Request(url.rstrip('/') + '/api/ingestion', data=corps, method='POST',
                                     headers={'Content-Type': 'application/json',
                                              'X-Jeton': conf.get('portail', 'jeton')})
        try:
            with urllib.request.urlopen(req, timeout=60, context=ctx if url.startswith('https') else None) as r:
                r.read()
        except Exception as e:  # réseau, HTTP : on garde tout en attente pour la passe suivante
            log('envoi impossible (%s), %d événement(s) mis en attente' % (e, len(evts) - i))
            ecrire_spool(spool, evts[i:])
            return False
    return True


def ecrire_spool(spool, evts):
    if not evts:
        return
    os.makedirs(spool, exist_ok=True)
    chemin = os.path.join(spool, 'attente_%s.jsonl' % dt.datetime.now().strftime('%Y%m%d%H%M%S%f'))
    with io.open(chemin, 'w', encoding='utf-8') as f:
        for e in evts:
            f.write(json.dumps(e, ensure_ascii=False) + '\n')


def lire_spool(spool):
    evts, fic = [], sorted(glob.glob(os.path.join(spool, 'attente_*.jsonl')))
    for f in fic:
        with io.open(f, encoding='utf-8') as fh:
            evts.extend(json.loads(l) for l in fh if l.strip())
    return evts, fic


# --------------------------------------------------------------------------------------------
# Programme principal
# --------------------------------------------------------------------------------------------
SOURCES = [
    ('wtmp', 'systeme', collecter_wtmp), ('btmp', 'systeme', collecter_btmp),
    ('secure', 'systeme', collecter_secure), ('auditd', 'systeme', collecter_auditd),
    ('onaudit', 'informix', collecter_onaudit), ('applicatif', 'applicatif', collecter_applicatif),
]


def collecter_tout(conf, etat, reprise=None):
    """Exécute toutes les sources actives. Retourne (événements, nouveaux points de reprise, compte rendu)."""
    defaut = dt.datetime.now() - dt.timedelta(days=int(conf.get('collecteur', 'historique_jours', fallback='35')))
    tous, points, rapport = [], {}, []
    deja = set(etat.get('frontiere', []))   # événements déjà transmis à la seconde du point de reprise
    frontiere = []
    actives = [s.strip() for s in conf.get('collecteur', 'sources', fallback='wtmp,btmp,secure,auditd').split(',') if s.strip()]
    for nom, _section, fonction in SOURCES:
        if nom not in actives:
            continue
        depuis = reprise or (dt.datetime.strptime(etat['points'][nom], '%Y-%m-%dT%H:%M:%S')
                             if etat.get('points', {}).get(nom) else defaut)
        try:
            evts = fonction(conf, depuis)
        except Exception as e:
            log('source %s en erreur : %s' % (nom, e))
            rapport.append({'source': nom, 'statut': 'erreur', 'message': str(e)[:500]})
            continue
        if evts:
            points[nom] = max(e['ts'] for e in evts)
            frontiere.extend(e['empreinte'] for e in evts if e['ts'] == points[nom])
        evts = [e for e in evts if e['empreinte'] not in deja]
        log('%-10s %5d événement(s) depuis %s' % (nom, len(evts), depuis.strftime('%Y-%m-%d %H:%M:%S')))
        rapport.append({'source': nom, 'statut': 'ok', 'evenements': len(evts)})
        tous.extend(evts)
    if 'sessions' in actives:
        try:
            evts = collecter_sessions(conf, etat)
            log('%-10s %5d événement(s)' % ('sessions', len(evts)))
            rapport.append({'source': 'sessions', 'statut': 'ok', 'evenements': len(evts)})
            tous.extend(evts)
        except Exception as e:
            log('source sessions en erreur : %s' % e)
            rapport.append({'source': 'sessions', 'statut': 'erreur', 'message': str(e)[:500]})
    tous.sort(key=lambda e: e['ts'])
    # on garde la frontière des sources sans nouvel événement, pour ne pas renvoyer leurs derniers événements
    anciens = [h for h in deja if h not in frontiere] if not reprise else []
    etat['frontiere'] = (frontiere + anciens)[-5000:]
    return tous, points, rapport


def mode_distant():
    """Collecte pilotée par le portail via SSH (clé à commande forcée).

    Entrée (stdin)  : {"config": {section: {clé: valeur}}, "etat": {...}, "depuis": "AAAA-MM-JJ" | null}
    Sortie (stdout) : une ligne JSON par événement, puis une dernière ligne {"__fin__": {"etat": ..., "rapport": ...}}
    Rien n'est écrit sur le serveur : la configuration et l'état sont conservés par le portail.
    """
    demande = json.loads(sys.stdin.read() or '{}')
    conf = configparser.ConfigParser(interpolation=None)
    conf.read_dict({s: {k: str(v) for k, v in vals.items()} for s, vals in (demande.get('config') or {}).items()})
    etat = demande.get('etat') or {}
    reprise = dt.datetime.strptime(demande['depuis'], '%Y-%m-%d') if demande.get('depuis') else None
    evts, points, rapport = collecter_tout(conf, etat, reprise)
    sortie = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    for e in evts:
        sortie.write(json.dumps(e, ensure_ascii=False) + '\n')
    etat.setdefault('points', {}).update(points)
    sortie.write(json.dumps({'__fin__': {'etat': etat, 'rapport': rapport, 'serveur': SERVEUR, 'version': VERSION}},
                            ensure_ascii=False) + '\n')
    sortie.flush()


def main():
    if '--distant' in sys.argv[1:]:
        return mode_distant()
    p = argparse.ArgumentParser(description='Collecteur SIEM Informix')
    p.add_argument('-c', '--config', default=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'collecteur.ini'))
    p.add_argument('--test', action='store_true', help='Affiche les événements sans les envoyer ni mettre à jour l\'état')
    p.add_argument('--depuis', help='Rejouer depuis une date AAAA-MM-JJ (reprise d\'historique)')
    p.add_argument('--sortie', help='Écrire les événements dans un fichier .jsonl au lieu de les envoyer')
    p.add_argument('--distant', action='store_true', help='Mode piloté par le portail (stdin/stdout JSON)')
    args = p.parse_args()

    conf = configparser.ConfigParser(interpolation=None)
    if not conf.read(args.config, encoding='utf-8'):
        sys.exit('Configuration introuvable : %s' % args.config)
    travail = conf.get('collecteur', 'dossier', fallback=os.path.dirname(os.path.abspath(args.config)))
    fichier_etat = os.path.join(travail, 'etat.json')
    spool = os.path.join(travail, 'attente')
    etat = {}
    if os.path.exists(fichier_etat):
        with io.open(fichier_etat, encoding='utf-8') as f:
            etat = json.load(f)
    reprise = dt.datetime.strptime(args.depuis, '%Y-%m-%d') if args.depuis else None
    tous, nouveaux_points, _rapport = collecter_tout(conf, etat, reprise)

    if args.test:
        for e in tous[-50:]:
            print(json.dumps(e, ensure_ascii=False))
        log('mode test : %d événement(s), rien envoyé' % len(tous))
        return
    if args.sortie:
        with io.open(args.sortie, 'a', encoding='utf-8') as f:
            for e in tous:
                f.write(json.dumps(e, ensure_ascii=False) + '\n')
        log('%d événement(s) écrits dans %s' % (len(tous), args.sortie))
    else:
        en_attente, fic = lire_spool(spool)
        if envoyer(conf, en_attente + tous, spool):
            for f in fic:
                os.unlink(f)
            log('%d événement(s) envoyés au portail' % (len(en_attente) + len(tous)))
        else:
            for f in fic:  # réécrits dans un nouveau fichier d'attente par envoyer()
                os.unlink(f)
    etat.setdefault('points', {}).update(nouveaux_points)
    os.makedirs(travail, exist_ok=True)
    with io.open(fichier_etat + '.tmp', 'w', encoding='utf-8') as f:
        json.dump(etat, f, ensure_ascii=False, indent=1)
    os.replace(fichier_etat + '.tmp', fichier_etat)


if __name__ == '__main__':
    main()
