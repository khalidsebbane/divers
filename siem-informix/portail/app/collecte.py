"""
Collecte pilotée et automatisation.

Le portail, installé sur un serveur isolé, déclenche la collecte sur chaque serveur Informix déclaré :
  ssh -i <clé du portail> siemcollect@serveur   ->   commande forcée côté serveur :
  sudo /usr/libexec/platform-python /opt/siem-informix/collecteur.py --distant

La clé SSH du portail ne peut exécuter que le collecteur (option « command= » de authorized_keys).
La configuration et l'état de chaque source sont conservés par le portail : rien n'est stocké sur le
serveur de base, aucun service n'y tourne, aucun port n'y est ouvert.

Le planificateur (thread) exécute aussi : purge, nettoyage des sessions, envoi des alertes par e-mail.
"""
import datetime as dt
import json
import logging
import os
import subprocess
import sys
import threading
import time

from . import db, notifications
from .config import config

log = logging.getLogger('siem.collecte')
_verrous = {}
_arret = threading.Event()

CONFIG_DEFAUT = {
    'collecteur': {'sources': 'wtmp,btmp,secure,auditd,sessions,applicatif', 'historique_jours': '45'},
    'systeme': {'wtmp': '/var/log/wtmp*', 'btmp': '/var/log/btmp*', 'secure': '/var/log/secure*',
                'auditd': '/var/log/audit/audit.log*'},
    'informix': {'informixdir': '/opt/informix', 'informixserver': '', 'onconfig': '', 'dbdate': 'Y4MD-',
                 'encodage': 'latin-1', 'resoudre_ip': 'oui', 'commande_onshowaudit': '',
                 'audit_champ_date': '1', 'audit_champ_machine': '2', 'audit_champ_pid': '3',
                 'audit_champ_utilisateur': '5', 'audit_champ_erreur': '6', 'audit_champ_code': '7', 'audit_champ_objet': '8'},
    'applicatif': {'base': '', 'table': 'agr_lds', 'compte_base': 'regix', 'colonne_date': 'alds_open',
                   'filtre': "(alds_complement IS NULL OR alds_complement NOT MATCHES 'Xp_cron*')"},
}

CHAMPS_SOURCE = ('nom', 'hote', 'port', 'utilisateur', 'mode', 'python', 'chemin_collecteur', 'intervalle_s', 'actif')


# --------------------------------------------------------------------------------------------
# Clé SSH du portail
# --------------------------------------------------------------------------------------------
def chemin_cle():
    return os.path.join(config.dossier_ssh, 'id_ed25519')


def assurer_cle():
    """Crée la paire de clés du portail au premier démarrage. Retourne la clé publique."""
    cle = chemin_cle()
    if not os.path.exists(cle):
        os.makedirs(config.dossier_ssh, mode=0o700, exist_ok=True)
        try:
            subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', 'portail-siem-informix', '-f', cle],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=30)
        except (OSError, subprocess.SubprocessError) as e:
            log.warning('Impossible de créer la clé SSH du portail (%s). Installer openssh-clients.', e)
            return ''
    try:
        with open(cle + '.pub', encoding='utf-8') as f:
            return f.read().strip()
    except OSError:
        return ''


def ligne_authorized_keys(source, ip_portail='IP_DU_PORTAIL'):
    pub = assurer_cle() or 'ssh-ed25519 <cle-publique-du-portail>'
    cmd = 'sudo %s %s --distant' % (source.get('python') or '/usr/libexec/platform-python',
                                    source.get('chemin_collecteur') or '/opt/siem-informix/collecteur.py')
    return ('from="%s",command="%s",no-pty,no-port-forwarding,no-agent-forwarding,no-X11-forwarding,no-user-rc %s'
            % (ip_portail, cmd, pub))


# --------------------------------------------------------------------------------------------
# Sources
# --------------------------------------------------------------------------------------------
def _decoder(r):
    r = dict(r)
    for k in ('config', 'etat'):
        try:
            r[k] = json.loads(r.get(k) or '{}')
        except ValueError:
            r[k] = {}
    return r


def lister_sources():
    with db.connexion() as cx:
        return [_decoder(r) for r in cx.execute('SELECT * FROM sources_collecte ORDER BY nom')]


def source(id_source):
    with db.connexion() as cx:
        r = cx.execute('SELECT * FROM sources_collecte WHERE id = ?', (id_source,)).fetchone()
        return _decoder(r) if r else None


def enregistrer_source(donnees, id_source=None):
    valeurs = {k: donnees[k] for k in CHAMPS_SOURCE if k in donnees}
    conf = donnees.get('config')
    if conf is not None:
        fusion = json.loads(json.dumps(CONFIG_DEFAUT))
        for section, vals in conf.items():
            fusion.setdefault(section, {}).update({k: str(v) for k, v in (vals or {}).items()})
        valeurs['config'] = json.dumps(fusion, ensure_ascii=False)
    if valeurs.get('mode', 'ssh') not in ('ssh', 'local'):
        raise ValueError('mode invalide')
    with db.connexion() as cx:
        if id_source:
            if valeurs:
                cx.execute('UPDATE sources_collecte SET %s WHERE id = ?' % ', '.join('%s = ?' % k for k in valeurs),
                           list(valeurs.values()) + [id_source])
            return id_source
        if not valeurs.get('nom') or not valeurs.get('hote'):
            raise ValueError('nom et hôte obligatoires')
        valeurs.setdefault('config', json.dumps(CONFIG_DEFAUT, ensure_ascii=False))
        cur = cx.execute('INSERT INTO sources_collecte (%s) VALUES (%s)' % (', '.join(valeurs), ','.join('?' * len(valeurs))),
                         list(valeurs.values()))
        return cur.lastrowid


def supprimer_source(id_source):
    with db.connexion() as cx:
        cx.execute('DELETE FROM sources_collecte WHERE id = ?', (id_source,))


def executions(id_source=None, limite=50):
    with db.connexion() as cx:
        if id_source:
            return db.lignes(cx, 'SELECT * FROM executions_collecte WHERE source_id = ? ORDER BY id DESC LIMIT ?', (id_source, limite))
        return db.lignes(cx, 'SELECT e.*, s.nom FROM executions_collecte e LEFT JOIN sources_collecte s ON s.id = e.source_id'
                             ' ORDER BY e.id DESC LIMIT ?', (limite,))


# --------------------------------------------------------------------------------------------
# Exécution d'une collecte
# --------------------------------------------------------------------------------------------
def commande(src):
    distante = [src.get('python') or '/usr/libexec/platform-python',
                src.get('chemin_collecteur') or '/opt/siem-informix/collecteur.py', '--distant']
    if src.get('mode') == 'local':
        return distante
    return ['ssh', '-i', chemin_cle(), '-p', str(src.get('port') or 22),
            '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', '-o', 'ServerAliveInterval=15',
            '-o', 'StrictHostKeyChecking=accept-new', '-o', 'UserKnownHostsFile=%s' % os.path.join(config.dossier_ssh, 'known_hosts'),
            '%s@%s' % (src.get('utilisateur') or 'siemcollect', src['hote']), 'sudo'] + distante


def executer(id_source, depuis=None, delai=900):
    """Lance une collecte et ingère le résultat. Retourne le compte rendu de l'exécution."""
    verrou = _verrous.setdefault(id_source, threading.Lock())
    if not verrou.acquire(blocking=False):
        return {'statut': 'en_cours', 'message': 'Une collecte est déjà en cours pour cette source.'}
    debut = time.time()
    src = source(id_source)
    res = {'statut': 'erreur', 'recus': 0, 'nouveaux': 0, 'alertes': 0, 'message': '', 'rapport': []}
    try:
        if not src:
            res['message'] = 'source inconnue'
            return res
        if src['mode'] == 'ssh':
            assurer_cle()
        demande = json.dumps({'config': src['config'], 'etat': src['etat'], 'depuis': depuis})
        try:
            p = subprocess.run(commande(src), input=demande.encode('utf-8'), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               timeout=delai)
        except subprocess.TimeoutExpired:
            res['message'] = 'délai dépassé (%d s)' % delai
            return res
        except OSError as e:
            res['message'] = 'lancement impossible : %s' % e
            return res
        evts, fin = [], None
        for ligne in p.stdout.decode('utf-8', 'replace').splitlines():
            if not ligne.strip():
                continue
            try:
                obj = json.loads(ligne)
            except ValueError:
                continue
            if '__fin__' in obj:
                fin = obj['__fin__']
            else:
                evts.append(obj)
        erreur = p.stderr.decode('utf-8', 'replace').strip()
        if fin is None:
            res['message'] = (erreur.splitlines()[-1] if erreur else 'réponse incomplète du collecteur (code %d)' % p.returncode)[:500]
            return res
        for i in range(0, len(evts), 2000):
            n, a = db.ingerer(evts[i:i + 2000])
            res['nouveaux'] += n
            res['alertes'] += a
        res['recus'] = len(evts)
        res['rapport'] = fin.get('rapport', [])
        erreurs = [r for r in res['rapport'] if r.get('statut') == 'erreur']
        res['statut'] = 'partiel' if erreurs else 'ok'
        res['message'] = '; '.join('%s : %s' % (r['source'], r.get('message', '')) for r in erreurs)[:500]
        with db.connexion() as cx:
            cx.execute('UPDATE sources_collecte SET etat = ? WHERE id = ?', (json.dumps(fin.get('etat') or {}), id_source))
        return res
    finally:
        duree = round(time.time() - debut, 1)
        maintenant = dt.datetime.now().strftime('%Y-%m-%dT%H:%M:%S')
        if src:
            with db.connexion() as cx:
                cx.execute('UPDATE sources_collecte SET derniere_execution = ?, statut = ?, message = ?,'
                           ' evenements_total = evenements_total + ? WHERE id = ?',
                           (maintenant, res['statut'], res['message'], res['nouveaux'], id_source))
                cx.execute('INSERT INTO executions_collecte (source_id, debut, fin, duree_s, recus, nouveaux, alertes, statut,'
                           ' message, rapport) VALUES (?,?,?,?,?,?,?,?,?,?)',
                           (id_source, dt.datetime.fromtimestamp(debut).strftime('%Y-%m-%dT%H:%M:%S'), maintenant, duree,
                            res['recus'], res['nouveaux'], res['alertes'], res['statut'], res['message'],
                            json.dumps(res['rapport'], ensure_ascii=False)))
        if res['statut'] == 'erreur':
            log.warning('collecte %s : %s', src['nom'] if src else id_source, res['message'])
        verrou.release()


def tester(id_source):
    """Vérifie la connexion SSH et la présence du collecteur sans collecter (sources vides)."""
    src = source(id_source)
    if not src:
        return {'ok': False, 'message': 'source inconnue'}
    if src['mode'] == 'ssh':
        assurer_cle()
    try:
        p = subprocess.run(commande(src), input=json.dumps({'config': {'collecteur': {'sources': ''}}, 'etat': {}}).encode(),
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
    except (OSError, subprocess.SubprocessError) as e:
        return {'ok': False, 'message': str(e)}
    for ligne in p.stdout.decode('utf-8', 'replace').splitlines():
        if '__fin__' in ligne:
            fin = json.loads(ligne)['__fin__']
            return {'ok': True, 'message': 'Connexion réussie : serveur %s, collecteur %s.' % (fin.get('serveur'), fin.get('version'))}
    err = p.stderr.decode('utf-8', 'replace').strip()
    return {'ok': False, 'message': (err.splitlines()[-1] if err else 'aucune réponse du collecteur (code %d)' % p.returncode)}


# --------------------------------------------------------------------------------------------
# Planificateur
# --------------------------------------------------------------------------------------------
def _echeance(src, maintenant):
    if not src['actif']:
        return False
    if not src['derniere_execution']:
        return True
    return (maintenant - dt.datetime.fromisoformat(src['derniere_execution'])).total_seconds() >= (src['intervalle_s'] or 60)


def tic():
    maintenant = dt.datetime.now()
    for src in lister_sources():
        if _echeance(src, maintenant):
            executer(src['id'])
    notifications.envoyer_alertes()


def _boucle():
    derniere_purge = 0
    log.info('Planificateur démarré')
    while not _arret.is_set():
        try:
            tic()
            if time.time() - derniere_purge > 6 * 3600:
                from . import auth
                db.purger()
                auth.purger_sessions()
                derniere_purge = time.time()
        except Exception:  # le planificateur ne doit jamais s'arrêter
            log.exception('Erreur du planificateur')
        _arret.wait(15)


def demarrer_planificateur():
    if config.planificateur and 'pytest' not in sys.modules:
        threading.Thread(target=_boucle, name='planificateur', daemon=True).start()


def arreter_planificateur():
    _arret.set()


def sante():
    maintenant = dt.datetime.now()
    res = []
    for s in lister_sources():
        retard = None
        if s['derniere_execution']:
            retard = int((maintenant - dt.datetime.fromisoformat(s['derniere_execution'])).total_seconds())
        etat = 'inactive' if not s['actif'] else 'jamais' if retard is None else \
            'retard' if retard > 3 * (s['intervalle_s'] or 60) + 120 else (s['statut'] or 'ok')
        res.append({'id': s['id'], 'nom': s['nom'], 'hote': s['hote'], 'etat': etat, 'derniere_execution': s['derniere_execution'],
                    'message': s['message'], 'evenements_total': s['evenements_total'], 'points': (s['etat'] or {}).get('points', {})})
    return res
