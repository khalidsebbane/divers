"""
Authentification du portail.

  - Active Directory (LDAPS ou LDAP + StartTLS) : recherche du compte avec un compte de service, vérification
    du mot de passe par une connexion au nom de l'utilisateur, rôle déduit de l'appartenance (même indirecte)
    aux groupes AD configurés. Un compte AD hors de ces groupes est refusé.
  - Comptes locaux (secours, si l'AD est indisponible) : fichier d'empreintes PBKDF2. Un nom présent dans le
    fichier local est toujours vérifié localement (ex. « admin.local »).
  - Sessions côté serveur (jeton aléatoire dans un cookie HttpOnly, SameSite=Strict), expiration absolue et
    sur inactivité, verrouillage après plusieurs échecs.
"""
import datetime as dt
import hashlib
import hmac
import logging
import os
import secrets
import ssl
import threading
import time

from . import db
from .config import config

log = logging.getLogger('siem.auth')
COOKIE = 'siem_session'


class RefusAuthentification(Exception):
    pass


# --------------------------------------------------------------------------------------------
# Comptes locaux : « login:pbkdf2_sha256$iterations$sel$empreinte:role »
# --------------------------------------------------------------------------------------------
def hacher(mot_de_passe, sel=None, iterations=310000):
    sel = sel or secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac('sha256', mot_de_passe.encode(), bytes.fromhex(sel), iterations).hex()
    return 'pbkdf2_sha256$%d$%s$%s' % (iterations, sel, h)


def verifier_empreinte(mot_de_passe, empreinte):
    try:
        _algo, it, sel, _h = empreinte.split('$')
        return hmac.compare_digest(hacher(mot_de_passe, sel, int(it)), empreinte)
    except ValueError:
        return False


def lire_comptes():
    comptes = {}
    if os.path.exists(config.fichier_comptes):
        with open(config.fichier_comptes, encoding='utf-8') as f:
            for ligne in f:
                ligne = ligne.strip()
                if ligne and not ligne.startswith('#'):
                    login, empreinte, role = (ligne.split(':') + ['lecteur'])[:3]
                    comptes[login.lower()] = (empreinte, role or 'lecteur')
    return comptes


def ajouter_compte(login, mot_de_passe, role='admin'):
    comptes = lire_comptes()
    comptes[login.lower()] = (hacher(mot_de_passe), role)
    _ecrire_comptes(comptes)


def supprimer_compte(login):
    comptes = lire_comptes()
    comptes.pop(login.lower(), None)
    _ecrire_comptes(comptes)


def _ecrire_comptes(comptes):
    os.makedirs(os.path.dirname(os.path.abspath(config.fichier_comptes)), exist_ok=True)
    tmp = config.fichier_comptes + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        f.write('# Comptes locaux du portail SIEM (login:empreinte:role). Gérer avec : python -m app.outils compte <login>\n')
        for l, (e, r) in sorted(comptes.items()):
            f.write('%s:%s:%s\n' % (l, e, r))
    os.chmod(tmp, 0o600)
    os.replace(tmp, config.fichier_comptes)


# --------------------------------------------------------------------------------------------
# Active Directory
# --------------------------------------------------------------------------------------------
def _serveurs_ad():
    from ldap3 import FIRST, Server, ServerPool, Tls
    tls = Tls(ca_certs_file=config.ad_ca or None,
              validate=ssl.CERT_REQUIRED if config.ad_verifier_certificat else ssl.CERT_NONE,
              version=ssl.PROTOCOL_TLS_CLIENT)
    serveurs = [Server(u, use_ssl=u.lower().startswith('ldaps://'), tls=tls, connect_timeout=5)
                for u in config.ad_serveurs]
    return ServerPool(serveurs, FIRST, active=1, exhaust=60)


def fabrique_connexion(utilisateur, mot_de_passe):
    """Ouvre une connexion LDAP liée (bind). Remplaçable dans les tests."""
    from ldap3 import AUTO_BIND_NO_TLS, AUTO_BIND_TLS_BEFORE_BIND, Connection
    starttls = not all(u.lower().startswith('ldaps://') for u in config.ad_serveurs)
    return Connection(_serveurs_ad(), user=utilisateur, password=mot_de_passe, receive_timeout=10, raise_exceptions=True,
                      auto_bind=AUTO_BIND_TLS_BEFORE_BIND if starttls else AUTO_BIND_NO_TLS)


def _membre(cx, dn_utilisateur, groupe, membre_de):
    if not groupe:
        return False
    if any(g.lower() == groupe.lower() for g in membre_de):
        return True
    from ldap3.core.exceptions import LDAPException
    from ldap3.utils.conv import escape_filter_chars
    # groupes imbriqués : règle LDAP_MATCHING_RULE_IN_CHAIN de l'AD
    try:
        cx.search(config.ad_base_dn, '(&(distinguishedName=%s)(memberOf:1.2.840.113556.1.4.1941:=%s))'
                  % (escape_filter_chars(dn_utilisateur), escape_filter_chars(groupe)), attributes=['cn'])
    except LDAPException:
        return False
    return bool(cx.entries)


def authentifier_ad(login, mot_de_passe):
    from ldap3.core.exceptions import LDAPBindError, LDAPException
    from ldap3.utils.conv import escape_filter_chars
    try:
        svc = fabrique_connexion(config.ad_compte_service, config.ad_mdp_service)
    except LDAPException as e:
        log.error('Active Directory injoignable ou compte de service refusé : %s', e)
        raise RefusAuthentification('Annuaire Active Directory indisponible. Utilisez un compte local de secours.')
    try:
        filtre = '(&(objectClass=user)(%s=%s))' % (config.ad_attribut_login, escape_filter_chars(login))
        svc.search(config.ad_base_dn, filtre, attributes=['displayName', 'mail', 'memberOf', 'userAccountControl'])
        if len(svc.entries) != 1:
            raise RefusAuthentification('Identifiant ou mot de passe incorrect.')
        entree = svc.entries[0]
        try:
            desactive = int(entree.userAccountControl.value or 0) & 2 if 'userAccountControl' in entree else 0
        except (TypeError, ValueError):
            desactive = 0
        if desactive:
            raise RefusAuthentification('Identifiant ou mot de passe incorrect.')
        dn = entree.entry_dn
        try:
            fabrique_connexion(dn, mot_de_passe).unbind()
        except LDAPBindError:
            raise RefusAuthentification('Identifiant ou mot de passe incorrect.')
        membre_de = [str(g) for g in (entree.memberOf.values if 'memberOf' in entree else [])]
        if _membre(svc, dn, config.ad_groupe_admin, membre_de):
            role = 'admin'
        elif _membre(svc, dn, config.ad_groupe_lecteur, membre_de):
            role = 'lecteur'
        else:
            raise RefusAuthentification('Compte non autorisé sur ce portail (groupe AD manquant).')
        nom = str(entree.displayName) if 'displayName' in entree and entree.displayName.value else login
        return {'login': login.lower(), 'role': role, 'source': 'ad', 'nom': nom}
    finally:
        svc.unbind()


# --------------------------------------------------------------------------------------------
# Connexion, verrouillage, sessions
# --------------------------------------------------------------------------------------------
_echecs, _verrou = {}, threading.Lock()


def _bloque(cle):
    with _verrou:
        n, debut = _echecs.get(cle, (0, 0))
        if n >= config.max_echecs and time.time() - debut < config.blocage_min * 60:
            return True
        if time.time() - debut >= config.blocage_min * 60:
            _echecs.pop(cle, None)
        return False


def _echec(cle):
    with _verrou:
        n, debut = _echecs.get(cle, (0, time.time()))
        _echecs[cle] = (n + 1, debut)


def connecter(login, mot_de_passe, ip):
    login = (login or '').strip()
    if '\\' in login:            # DOMAINE\utilisateur
        login = login.split('\\', 1)[1]
    if '@' in login and login.lower() not in lire_comptes():
        login = login.split('@', 1)[0]
    if not login or not mot_de_passe:   # un mot de passe vide ferait une liaison LDAP anonyme : refusé
        raise RefusAuthentification('Identifiant et mot de passe obligatoires.')
    cle = login.lower()
    if _bloque(cle) or _bloque('ip:' + ip):
        db.journaliser(login, 'connexion_bloquee', ip)
        raise RefusAuthentification('Trop de tentatives. Réessayez dans %d minutes.' % config.blocage_min)
    try:
        locaux = lire_comptes()
        if cle in locaux:
            empreinte, role = locaux[cle]
            if not verifier_empreinte(mot_de_passe, empreinte):
                raise RefusAuthentification('Identifiant ou mot de passe incorrect.')
            u = {'login': cle, 'role': role, 'source': 'local', 'nom': login}
        elif config.ad_actif():
            u = authentifier_ad(login, mot_de_passe)
        else:
            raise RefusAuthentification('Identifiant ou mot de passe incorrect.')
    except RefusAuthentification as e:
        _echec(cle)
        _echec('ip:' + ip)
        db.journaliser(login, 'echec_connexion', '%s : %s' % (ip, e))
        raise
    with _verrou:
        _echecs.pop(cle, None)
    db.journaliser(u['login'], 'connexion', '%s (%s, %s)' % (ip, u['source'], u['role']))
    return creer_session(u, ip)


def creer_session(u, ip):
    jeton = secrets.token_urlsafe(32)
    maintenant = dt.datetime.now().strftime('%Y-%m-%dT%H:%M:%S')
    with db.connexion() as cx:
        cx.execute('INSERT INTO sessions_portail (jeton, login, role, source, nom, cree, vu, ip) VALUES (?,?,?,?,?,?,?,?)',
                   (_h(jeton), u['login'], u['role'], u['source'], u['nom'], maintenant, maintenant, ip))
    return jeton, u


def _h(jeton):
    return hashlib.sha256(jeton.encode()).hexdigest()   # seule l'empreinte du jeton est stockée


def session(jeton):
    if not jeton:
        return None
    maintenant = dt.datetime.now()
    with db.connexion() as cx:
        r = cx.execute('SELECT * FROM sessions_portail WHERE jeton = ?', (_h(jeton),)).fetchone()
        if not r:
            return None
        cree, vu = dt.datetime.fromisoformat(r['cree']), dt.datetime.fromisoformat(r['vu'])
        if (maintenant - cree).total_seconds() > config.session_heures * 3600 or \
                (maintenant - vu).total_seconds() > config.session_inactivite_min * 60:
            cx.execute('DELETE FROM sessions_portail WHERE jeton = ?', (_h(jeton),))
            return None
        if (maintenant - vu).total_seconds() > 30:
            cx.execute('UPDATE sessions_portail SET vu = ? WHERE jeton = ?', (maintenant.strftime('%Y-%m-%dT%H:%M:%S'), _h(jeton)))
        return {'login': r['login'], 'role': r['role'], 'source': r['source'], 'nom': r['nom']}


def deconnecter(jeton):
    with db.connexion() as cx:
        cx.execute('DELETE FROM sessions_portail WHERE jeton = ?', (_h(jeton or ''),))


def purger_sessions():
    limite = (dt.datetime.now() - dt.timedelta(hours=config.session_heures)).strftime('%Y-%m-%dT%H:%M:%S')
    with db.connexion() as cx:
        cx.execute('DELETE FROM sessions_portail WHERE cree < ?', (limite,))
