# -*- coding: utf-8 -*-
"""Collecte centralisée par SSH (sans partage NFS) : lancée par cron sur le serveur CENTRAL (ex. REPL).

  - le serveur central prend son propre instantané localement ;
  - il interroge chaque autre serveur de SERVEURS en SSH, en parallèle. La clé du portail est verrouillée
    côté serveur distant par une commande forcée (authorized_keys) : elle ne peut lancer que le collecteur,
    qui renvoie son instantané sur la sortie standard ;
  - il écrit <PARTAGE>/donnees/<NOM>/dernier.json et historique.jsonl, puis génère <PARTAGE>/portail/index.html.

Un serveur qui ne répond pas garde son dernier instantané : le portail le signale « injoignable » quand il vieillit.
Compatible Python 2.7 et 3.6+.
"""
from __future__ import division, print_function, unicode_literals

import datetime as dt
import json
import os
import sys
import threading

ICI = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ICI)
from collecte_infra import (adresses_locales, ajouter_historique, ecrire_json, identifier, instantane, lancer,  # noqa: E402
                            lire_conf, resume, serveurs_conf)


def commande_ssh(srv, conf):
    """Commande SSH vers un serveur distant. La commande réellement exécutée est imposée par authorized_keys."""
    cle = conf.get('CLE_SSH', '/root/.ssh/portail_infra')
    compte = conf.get('COMPTE_SSH', 'root')
    return ['ssh', '-i', cle, '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=%s' % conf.get('DELAI_CONNEXION_SSH', '10'),
            '-o', 'StrictHostKeyChecking=yes', '-o', 'ServerAliveInterval=15', '-o', 'LogLevel=ERROR',
            '-p', conf.get('PORT_SSH', '22'), '%s@%s' % (compte, srv['ip'] or srv['hote']), 'collecte']


def lire_instantane(texte, srv):
    """Dernière ligne JSON de la sortie (les messages éventuels du profil shell distant sont ignorés)."""
    for ligne in reversed(texte.strip().splitlines()):
        ligne = ligne.strip()
        if ligne.startswith('{'):
            snap = json.loads(ligne)
            if snap.get('nom') != srv['nom']:
                raise ValueError('le serveur %s a répondu sous le nom %s (vérifier --nom dans authorized_keys)'
                                 % (srv['nom'], snap.get('nom')))
            return snap
    raise ValueError('aucun instantané reçu : %s' % (texte.strip()[-300:] or 'sortie vide'))


def collecter_distant(srv, conf, lanceur=lancer):
    code, out = lanceur(commande_ssh(srv, conf), int(conf.get('DELAI_SSH', '300')))
    if code != 0 and '{' not in out:
        raise RuntimeError('SSH %s (%s) : code %s, %s' % (srv['nom'], srv['ip'] or srv['hote'], code, out.strip()[-300:]))
    return lire_instantane(out, srv)


def est_local(srv, conf, ips=None):
    nom_local, _ = identifier(conf)
    if srv['nom'] == conf.get('CENTRAL') or srv['nom'] == nom_local:
        return True
    return bool(srv['ip']) and srv['ip'] in (ips if ips is not None else adresses_locales())


def enregistrer(partage, snap, conf):
    dossier = os.path.join(partage, 'donnees', snap['nom'])
    if not os.path.isdir(dossier):
        os.makedirs(dossier)
    ecrire_json(os.path.join(dossier, 'dernier.json'), snap)
    ajouter_historique(os.path.join(dossier, 'historique.jsonl'), resume(snap), int(conf.get('CONSERVATION_JOURS', '7')))


def collecter_tout(conf, partage, lanceur=lancer, ips=None):
    travail = os.path.join(partage, 'travail')
    if not os.path.isdir(travail):
        os.makedirs(travail)
    resultats, verrou = [], threading.Lock()

    def tache(srv):
        try:
            if est_local(srv, conf, ips):
                snap = instantane(conf, srv['nom'], srv['role'], travail)
            else:
                snap = collecter_distant(srv, conf, lanceur)
            enregistrer(partage, snap, conf)
            msg = 'ok%s' % (' (%d erreur(s) partielle(s) : %s)' % (len(snap['erreurs']), ' | '.join(snap['erreurs']))
                            if snap.get('erreurs') else '')
        except Exception as e:
            msg = 'ÉCHEC : %s' % e
        with verrou:
            resultats.append((srv['nom'], msg))

    fils = [threading.Thread(target=tache, args=(s,)) for s in serveurs_conf(conf)]
    for f in fils:
        f.start()
    for f in fils:
        f.join()
    return sorted(resultats)


def main(argv):
    import argparse
    ap = argparse.ArgumentParser(description='Collecte centralisée par SSH puis génération du portail')
    ap.add_argument('--conf', default=os.path.join(os.path.dirname(ICI), 'tractafric.conf'))
    ap.add_argument('--partage', help='dossier de stockage (défaut : PARTAGE de la configuration)')
    ap.add_argument('--sans-portail', action='store_true', help='collecter sans régénérer le portail')
    a = ap.parse_args(argv)
    conf = lire_conf(a.conf)
    partage = a.partage or conf.get('PARTAGE') or os.path.join(os.path.dirname(ICI), 'donnees-portail')
    t0 = dt.datetime.now()
    res = collecter_tout(conf, partage)
    for nom, msg in res:
        print('%s %s : %s' % (t0.strftime('%Y-%m-%d %H:%M:%S'), nom, msg))
    if not a.sans_portail:
        sys.path.insert(0, os.path.join(os.path.dirname(ICI), 'portail'))
        import generer_portail
        generer_portail.main(['--conf', a.conf, '--partage', partage])
    return 0 if all(m.startswith('ok') for _, m in res) else 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
