"""Données fictives réalistes pour présenter le portail (aucune donnée réelle)."""
import datetime as dt
import hashlib
import random

from . import db

PERSONNES_APP = {'jdupont': '10.12.4.21', 'sbernard': '10.12.4.35', 'lpetit': '10.12.6.110', 'nrichard': '10.12.6.118'}
DBA, SYS = 'kbenali', 'mmartin'
POSTES = [('10.12.4.21', 'jdupont', 'PC-COMPTA-021'), ('10.12.4.35', 'sbernard', 'PC-COMPTA-035'),
          ('10.12.6.110', 'lpetit', 'PC-ADV-110'), ('10.12.6.118', 'nrichard', 'PC-ADV-118'),
          ('10.12.8.40', DBA, 'PC-DSI-040'), ('10.12.8.41', SYS, 'PC-DSI-041')]
PROGRAMMES = ['Xp_saisie_dossier', 'Xp_consult_client', 'Xp_edition_facture', 'Xp_export_compta', 'Xp_relance_client',
              'Xp_stat_mensuelle', 'Xp_modif_tarif', 'Xp_suppr_dossier']
TABLES = ['dossier', 'client', 'facture', 'tarif', 'reglement', 'agr_lds']


def _ev(ts, source, categorie, action, compte='', utilisateur='', ip='', poste='', session='', objet='',
        resultat='succes', details=None):
    e = {'ts': ts.strftime('%Y-%m-%dT%H:%M:%S'), 'source': source, 'categorie': categorie, 'action': action,
         'serveur': 'srv-fr2-107', 'compte': compte, 'utilisateur': utilisateur or compte, 'ip': ip, 'poste': poste,
         'session': session, 'objet': objet, 'resultat': resultat, 'details': details or {}, 'brut': ''}
    e['empreinte'] = hashlib.sha1(('demo|' + '|'.join(str(v) for v in e.values())).encode()).hexdigest()
    return e


def generer(jours=45, graine=7):
    rnd = random.Random(graine)
    for ip, personne, libelle in POSTES:
        db.definir_poste(ip, personne, libelle)
    evts = []
    fin = dt.datetime.now().replace(second=0, microsecond=0)
    debut = (fin - dt.timedelta(days=jours)).replace(hour=0, minute=0)
    jour = debut
    while jour < fin:
        ouvre = jour.weekday() < 5
        # --- Utilisateurs de l'application : programmes lancés (table agr_lds), compte base regix
        for personne, ip in PERSONNES_APP.items():
            if not ouvre or rnd.random() < 0.12:
                continue
            arrivee = jour + dt.timedelta(hours=8, minutes=rnd.randint(0, 70))
            sid = 'bdd:%d:%d' % (rnd.randint(100, 9999), int(arrivee.timestamp()))
            depart = arrivee + dt.timedelta(hours=rnd.uniform(6.5, 9))
            evts.append(_ev(arrivee, 'base', 'connexion', 'Ouverture de session base', 'regix', '', ip, '', sid,
                            details={'sid': sid.split(':')[1]}))
            t = arrivee + dt.timedelta(minutes=2)
            while t < depart:
                prog = rnd.choices(PROGRAMMES, weights=[30, 40, 12, 4, 8, 3, 2, 1])[0]
                evts.append(_ev(t, 'applicatif', 'programme', 'Lancement de programme', 'regix', personne, ip,
                                session='app:%d' % rnd.randint(1, 10 ** 9), objet=prog,
                                details={'alds_complement': prog, 'alds_user': personne}))
                t += dt.timedelta(minutes=rnd.randint(4, 35))
            if depart < fin:
                evts.append(_ev(depart, 'base', 'deconnexion', 'Fin de session base', 'regix', '', ip, '', sid,
                                details={'duree_s': int((depart - arrivee).total_seconds())}))

        # --- DBA : SSH nominatif, sudo vers informix, sessions base avec regix, DDL
        if ouvre and rnd.random() < 0.85:
            ip = '10.12.8.40'
            h = jour + dt.timedelta(hours=8, minutes=rnd.randint(30, 120))
            s = 'ssh:pts/%d:%s' % (rnd.randint(0, 5), h.strftime('%Y%m%d%H%M%S'))
            evts.append(_ev(h, 'systeme', 'connexion', 'Ouverture de session SSH (terminal)', DBA, '', ip, '', s))
            evts.append(_ev(h + dt.timedelta(minutes=1), 'systeme', 'sudo', 'sudo vers informix', 'informix', DBA,
                            objet='/bin/bash', session=s))
            for k in range(rnd.randint(3, 9)):
                cmd = rnd.choice(['onstat -g ses', 'onstat -p', 'onstat -d', 'ontape -s -L 1', 'dbaccess prod -', 'oncheck -cD prod'])
                evts.append(_ev(h + dt.timedelta(minutes=3 + k * 7), 'systeme', 'commande', 'Commande Informix', 'informix', DBA,
                                objet=cmd, session=s, details={'cle': 'siem_exec_informix'}))
            sb = 'bdd:%d:%d' % (rnd.randint(100, 9999), int(h.timestamp()))
            tb = h + dt.timedelta(minutes=20)
            evts.append(_ev(tb, 'base', 'connexion', 'Ouverture de session base', 'regix', '', ip, '', sb))
            if rnd.random() < 0.35:
                code = rnd.choice([('ddl', 'Création de table'), ('ddl', 'Modification de table'), ('ddl', 'Création d\'index'),
                                   ('droits', 'GRANT sur table')])
                evts.append(_ev(tb + dt.timedelta(minutes=5), 'base', code[0], code[1], 'regix', '', ip, '', sb,
                                objet='prod:%s' % rnd.choice(TABLES)))
            fb = tb + dt.timedelta(minutes=rnd.randint(10, 90))
            evts.append(_ev(fb, 'base', 'deconnexion', 'Fin de session base', 'regix', '', ip, '', sb))
            evts.append(_ev(h + dt.timedelta(hours=rnd.uniform(1, 3)), 'systeme', 'deconnexion', 'Fermeture de session', DBA, '', ip, '', s))

        # --- Admin système : SSH, sudo
        if ouvre and rnd.random() < 0.6:
            ip = '10.12.8.41'
            h = jour + dt.timedelta(hours=rnd.randint(9, 16), minutes=rnd.randint(0, 59))
            s = 'ssh:pts/%d:%s' % (rnd.randint(0, 5), h.strftime('%Y%m%d%H%M%S'))
            evts.append(_ev(h, 'systeme', 'connexion', 'Ouverture de session SSH (terminal)', SYS, '', ip, '', s))
            evts.append(_ev(h + dt.timedelta(minutes=2), 'systeme', 'sudo', 'sudo vers root', 'root', SYS,
                            objet=rnd.choice(['/usr/bin/systemctl status informix', '/usr/bin/dnf check-update', '/usr/bin/df -h']),
                            session=s))
            evts.append(_ev(h + dt.timedelta(minutes=rnd.randint(10, 50)), 'systeme', 'deconnexion', 'Fermeture de session', SYS, '', ip, '', s))
        jour += dt.timedelta(days=1)

    # --- Scénarios notables
    j = lambda n: (fin - dt.timedelta(days=n)).replace(minute=0)
    # 1. regix utilisé directement en SSH, la nuit, depuis un poste non affecté
    t = j(9).replace(hour=22, minute=47)
    s = 'ssh:pts/7:%s' % t.strftime('%Y%m%d%H%M%S')
    evts += [_ev(t, 'systeme', 'connexion', 'Ouverture de session SSH (terminal)', 'regix', '', '10.12.9.77', '', s),
             _ev(t + dt.timedelta(minutes=3), 'base', 'connexion', 'Ouverture de session base', 'regix', '', '10.12.9.77', '', 'bdd:4242:%d' % int(t.timestamp())),
             _ev(t + dt.timedelta(minutes=9), 'base', 'dml', 'Suppression de ligne', 'regix', '', '10.12.9.77', '', 'bdd:4242:%d' % int(t.timestamp()), objet='prod:reglement'),
             _ev(t + dt.timedelta(minutes=11), 'base', 'ddl', 'Suppression de table', 'regix', '', '10.12.9.77', '', 'bdd:4242:%d' % int(t.timestamp()), objet='prod:reglement_hist'),
             _ev(t + dt.timedelta(minutes=25), 'systeme', 'deconnexion', 'Fermeture de session', 'regix', '', '10.12.9.77', '', s)]
    # 2. Tentatives répétées sur regix depuis une adresse inconnue
    t = j(4).replace(hour=3, minute=12)
    for k in range(8):
        evts.append(_ev(t + dt.timedelta(seconds=40 * k), 'systeme', 'echec_connexion', 'Échec SSH (password)',
                        rnd.choice(['regix', 'informix', 'root']), '', '10.12.250.3', resultat='echec'))
    # 3. Le DBA se connecte depuis une nouvelle adresse (VPN) un samedi
    t = j(2).replace(hour=10, minute=5)
    while t.weekday() != 5:
        t -= dt.timedelta(days=1)
    s = 'ssh:pts/2:%s' % t.strftime('%Y%m%d%H%M%S')
    evts += [_ev(t, 'systeme', 'connexion', 'Ouverture de session SSH (terminal)', DBA, '', '192.168.50.14', 'vpn-014', s),
             _ev(t + dt.timedelta(minutes=4), 'systeme', 'commande', 'Modification config Informix', 'informix', DBA,
                 objet='vi /opt/informix/etc/onconfig.ol_prod', session=s, details={'cle': 'siem_conf_informix'}),
             _ev(t + dt.timedelta(minutes=40), 'systeme', 'deconnexion', 'Fermeture de session', DBA, '', '192.168.50.14', 'vpn-014', s)]
    # 4. Modification de sudoers
    t = j(6).replace(hour=15, minute=31)
    evts.append(_ev(t, 'systeme', 'fichier', 'Modification sudoers', 'root', SYS, objet='/etc/sudoers.d/informix',
                    details={'cle': 'siem_sudoers'}))
    evts = [e for e in evts if e['ts'] <= fin.strftime('%Y-%m-%dT%H:%M:%S')]
    evts.sort(key=lambda e: e['ts'])
    return evts
