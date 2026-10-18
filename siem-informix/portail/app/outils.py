"""
Outils en ligne de commande du portail.

  python -m app.outils compte <login> [--role admin|lecteur]   créer / changer le mot de passe d'un compte
  python -m app.outils importer <fichier.jsonl>                 importer des événements transférés à la main
  python -m app.outils postes <fichier.csv>                     importer l'affectation des postes (ip;personne;libelle)
  python -m app.outils demo [--jours 45]                        générer des données fictives de démonstration
  python -m app.outils purger                                   supprimer les événements plus vieux que la durée de conservation
"""
import argparse
import getpass
import json

from . import db


def main():
    p = argparse.ArgumentParser(prog='python -m app.outils')
    s = p.add_subparsers(dest='cmd', required=True)
    c = s.add_parser('compte'); c.add_argument('login'); c.add_argument('--role', default='admin', choices=['admin', 'lecteur'])
    i = s.add_parser('importer'); i.add_argument('fichier')
    po = s.add_parser('postes'); po.add_argument('fichier')
    d = s.add_parser('demo'); d.add_argument('--jours', type=int, default=45)
    s.add_parser('purger')
    a = p.parse_args()
    db.initialiser()
    if a.cmd == 'compte':
        from .auth import ajouter_compte
        mdp = getpass.getpass('Mot de passe pour %s : ' % a.login)
        if len(mdp) < 12:
            raise SystemExit('Mot de passe trop court (12 caractères minimum).')
        ajouter_compte(a.login, mdp, a.role)
        print('Compte %s (%s) enregistré.' % (a.login, a.role))
    elif a.cmd == 'importer':
        with open(a.fichier, encoding='utf-8') as f:
            evts = [json.loads(l) for l in f if l.strip()]
        print('%d nouveaux événements, %d alerte(s).' % db.ingerer(evts))
    elif a.cmd == 'postes':
        n = 0
        with open(a.fichier, encoding='utf-8-sig') as f:
            for ligne in f:
                champs = [x.strip() for x in ligne.strip().split(';')]
                if len(champs) >= 2 and champs[0] and not champs[0].lower().startswith('ip'):
                    db.definir_poste(champs[0], champs[1], champs[2] if len(champs) > 2 else '')
                    n += 1
        print('%d poste(s) importé(s).' % n)
    elif a.cmd == 'demo':
        from .demo import generer
        print('%d événements de démonstration, %d alerte(s).' % db.ingerer(generer(a.jours)))
    elif a.cmd == 'purger':
        db.purger()
        print('Purge effectuée.')


if __name__ == '__main__':
    main()
