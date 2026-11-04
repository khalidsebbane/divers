# -*- coding: utf-8 -*-
"""Génère le portail d'infrastructure IRIUM iE (un fichier index.html autonome, sans ressource externe).

Lit les instantanés <PARTAGE>/donnees/<NOM>/dernier.json et historique.jsonl de chaque serveur déclaré dans
SERVEURS, calcule les alertes, les scores de santé et les classements, puis écrit <PARTAGE>/portail/index.html.
Lancé par collecte.sh sur le serveur GENERATEUR, ou à la main. Compatible Python 2.7 et 3.6+.

  generer_portail.py --conf ../tractafric.conf                 portail réel
  generer_portail.py --demo --sortie ./demo                    portail de démonstration (données fictives)
"""
from __future__ import division, print_function, unicode_literals

import base64
import datetime as dt
import io
import json
import os
import re
import sys

try:
    str = unicode  # noqa: F821  (Python 2.7)
except NameError:
    pass

ICI = os.path.dirname(os.path.abspath(__file__))
RACINE = os.path.dirname(ICI)
sys.path.insert(0, os.path.join(RACINE, 'collecteur'))
from collecte_infra import lire_conf, serveurs_conf  # noqa: E402

GRAVITES = ['critique', 'haute', 'moyenne', 'faible']
POIDS = {'critique': 25, 'haute': 10, 'moyenne': 4, 'faible': 1}
SEUILS_DEFAUT = {'SEUIL_CPU': 85, 'SEUIL_MEMOIRE': 90, 'SEUIL_DISQUE': 85, 'SEUIL_DBSPACE_LIBRE': 10,
                 'SEUIL_CHECKPOINT_S': 5, 'SEUIL_API_MS': 2000, 'SEUIL_RETARD_RSS': 1000, 'FRAICHEUR_MAX_MIN': 45}
JOURS = ['dimanche', 'lundi', 'mardi', 'mercredi', 'jeudi', 'vendredi', 'samedi']


def seuils(conf):
    return dict((k, float(conf.get(k, v))) for k, v in SEUILS_DEFAUT.items())


# --------------------------------------------------------------------------------------------
# Tâches planifiées : description en clair et catégorie
# --------------------------------------------------------------------------------------------
def _heures(m, h):
    if not (m.isdigit() and re.match(r'^\d+(,\d+)*$', h)):
        return None
    return ', '.join('%02d:%02d' % (int(x), int(m)) for x in h.split(','))


def _jours(d):
    if d in ('1-5', 'MON-FRI', 'mon-fri'):
        return 'du lundi au vendredi'
    if d in ('1-6',):
        return 'du lundi au samedi'
    if re.match(r'^\d(,\d)*$', d):
        noms = [JOURS[int(x) % 7] for x in d.split(',')]
        return 'chaque ' + (', '.join(noms[:-1]) + ' et ' + noms[-1] if len(noms) > 1 else noms[0])
    return None


def decrire_cron(plan):
    speciaux = {'@reboot': 'au démarrage du serveur', '@hourly': 'chaque heure', '@daily': 'tous les jours à 00:00',
                '@midnight': 'tous les jours à 00:00', '@weekly': 'chaque dimanche à 00:00',
                '@monthly': 'le 1er de chaque mois à 00:00', '@yearly': 'le 1er janvier à 00:00',
                '@annually': 'le 1er janvier à 00:00'}
    if plan in speciaux:
        return speciaux[plan]
    p = plan.split()
    if len(p) != 5:
        return plan
    m, h, dom, mon, dow = p
    if mon != '*':
        return plan
    if m == '*' and h == '*' and dom == '*' and dow == '*':
        return 'chaque minute'
    r = re.match(r'^\*/(\d+)$', m)
    if r and dom == '*':
        j = '' if dow == '*' else _jours(dow)
        if j is not None:
            suffixe = ', ' + j if j else ''
            if h == '*':
                return 'toutes les %s min%s' % (r.group(1), suffixe)
            rh = re.match(r'^(\d+)-(\d+)$', h)
            if rh:
                return 'toutes les %s min de %sh à %sh%s' % (r.group(1), rh.group(1), int(rh.group(2)) + 1, suffixe)
    if re.match(r'^\d+(,\d+)+$', m) and h == '*' and dom == '*' and dow == '*':
        return 'chaque heure à ' + ', '.join(':%02d' % int(x) for x in m.split(','))
    if m.isdigit() and h == '*' and dom == '*' and dow == '*':
        return 'chaque heure à :%02d' % int(m)
    r = re.match(r'^\*/(\d+)$', h)
    if m.isdigit() and r and dom == '*' and dow == '*':
        return 'toutes les %s h à :%02d' % (r.group(1), int(m))
    hh = _heures(m, h)
    if hh is None:
        return plan
    if dom == '*' and dow == '*':
        return 'tous les jours à ' + hh
    if dom == '*':
        j = _jours(dow)
        return '%s à %s' % (j, hh) if j else plan
    if dow == '*' and re.match(r'^\d+(,\d+)*$', dom):
        return 'le %s de chaque mois à %s' % (', '.join('1er' if x == '1' else x for x in dom.split(',')), hh)
    return plan


def categorie_tache(cmd):
    c = cmd.lower()
    if 'collecte.sh' in c or 'portail' in c:
        return 'Portail'
    if re.search(r'onbar|ontape|dbexport|archecker|onunload|backup|sauvegard', c):
        return 'Sauvegarde'
    if re.search(r'onstat|onmode|oncheck|dbaccess|update.statistics', c):
        return 'Informix'
    if re.search(r'fglrun|ipscrond|irium|magix|genero|\.42r|\.42m', c):
        return 'IRIUM'
    if 'informix' in c:
        return 'Informix'
    return 'Système'


# --------------------------------------------------------------------------------------------
# Alertes et santé
# --------------------------------------------------------------------------------------------
def alerte(liste, gravite, serveur, domaine, message, valeur=None, seuil=None):
    liste.append({'gravite': gravite, 'serveur': serveur, 'domaine': domaine, 'message': message,
                  'valeur': valeur, 'seuil': seuil})


def fraicheur_min(snap, maintenant):
    try:
        t = dt.datetime.strptime(snap['horodatage'], '%Y-%m-%d %H:%M:%S')
    except (KeyError, ValueError, TypeError):
        return None
    return max(0, int((maintenant - t).total_seconds() // 60))


def dbspace_journaux(nom, conf=None):
    """Dbspaces réservés aux journaux physique et logiques : pleins par construction, sans alerte d'espace."""
    ignores = ((conf or {}).get('DBSPACES_JOURNAUX') or '').split()
    return nom in ignores or bool(re.search(r'(^|_)(p|l|phys|log)?logs?(dbs|db|space)?\d*$|^(plog|llog|phys|logical)', nom, re.I))


def marquer_dbspaces(snap, conf):
    for db in ((snap or {}).get('informix') or {}).get('dbspaces') or []:
        db['journaux'] = dbspace_journaux(db['nom'], conf)


def analyser_serveur(srv, snap, s, maintenant):
    """Retourne la liste des alertes d'un serveur à partir de son instantané."""
    a, nom = [], srv['nom']
    if snap is None:
        alerte(a, 'critique', nom, 'collecte', 'Aucune donnée reçue : collecte non installée ou serveur injoignable')
        return a
    age = fraicheur_min(snap, maintenant)
    if age is None or age > s['FRAICHEUR_MAX_MIN']:
        alerte(a, 'critique', nom, 'collecte', 'Données périmées : dernière collecte il y a %s min' % age,
               age, s['FRAICHEUR_MAX_MIN'])
    sy = snap.get('systeme') or {}
    cpu = sy.get('cpu_pct')
    if cpu is not None and cpu >= s['SEUIL_CPU']:
        alerte(a, 'haute', nom, 'système', 'Processeur saturé', cpu, s['SEUIL_CPU'])
    ncpu, charge = sy.get('ncpu'), (sy.get('charge') or [None])[0]
    if ncpu and charge is not None and charge > 2 * ncpu:
        alerte(a, 'haute', nom, 'système', 'Charge système élevée (%.1f pour %d vCPU)' % (charge, ncpu), charge, 2 * ncpu)
    mem = sy.get('memoire') or {}
    if mem.get('pct') is not None and mem['pct'] >= s['SEUIL_MEMOIRE']:
        alerte(a, 'haute', nom, 'système', 'Mémoire presque saturée', mem['pct'], s['SEUIL_MEMOIRE'])
    if (mem.get('swap_pct') or 0) >= 20:
        alerte(a, 'moyenne', nom, 'système', 'Utilisation du swap', mem['swap_pct'], 20)
    if snap.get('role') in ('bdd', 'repl') and mem.get('thp') == 'always':
        alerte(a, 'faible', nom, 'système', 'Transparent Huge Pages actif (déconseillé pour Informix)')
    for d in sy.get('disques') or []:
        if d['pct'] >= s['SEUIL_DISQUE']:
            alerte(a, 'critique' if d['pct'] >= 95 else 'haute', nom, 'disque',
                   'Système de fichiers %s rempli' % d['montage'], d['pct'], s['SEUIL_DISQUE'])
    for svc, etat in sorted((sy.get('services') or {}).items()):
        if etat not in ('active', 'activating'):
            alerte(a, 'haute', nom, 'service', 'Service %s : %s' % (svc, etat))
    if re.search(r'release 7\.', sy.get('os') or ''):
        alerte(a, 'moyenne', nom, 'système', 'RHEL 7 : support standard terminé (ELS jusqu\'au 30/06/2028)')
    ifx = snap.get('informix')
    if snap.get('role') in ('bdd', 'repl'):
        if not ifx:
            alerte(a, 'critique', nom, 'informix', 'Informix non détecté (onstat absent)')
        elif ifx.get('etat') != 'actif':
            alerte(a, 'critique', nom, 'informix', 'Moteur Informix arrêté ou injoignable')
        else:
            mode = (ifx.get('entete') or {}).get('mode', '')
            attendu = 'On-Line' if snap['role'] == 'bdd' else 'Read-Only'
            if attendu not in mode:
                alerte(a, 'haute', nom, 'informix', 'Mode du moteur inattendu : %s' % mode)
            for db in (ifx.get('dbspaces') or []) if snap['role'] == 'bdd' else []:  # le RSS reprend les dbspaces du primaire
                if db.get('temp') or db.get('sb') or db.get('journaux') or not db.get('taille_mo'):
                    continue
                libre = 100 * db['libre_mo'] / db['taille_mo']
                if libre < s['SEUIL_DBSPACE_LIBRE']:
                    alerte(a, 'critique' if libre < 2 else 'haute', nom, 'informix',
                           'Dbspace %s presque plein (%.1f %% libre)' % (db['nom'], libre), round(libre, 2),
                           s['SEUIL_DBSPACE_LIBRE'])
            ckp = [c['total_s'] for c in ifx.get('checkpoints') or [] if c.get('total_s') is not None]
            if ckp and max(ckp) >= s['SEUIL_CHECKPOINT_S']:
                alerte(a, 'haute' if max(ckp) >= 2 * s['SEUIL_CHECKPOINT_S'] else 'moyenne', nom, 'informix',
                       'Checkpoints longs (max %.1f s)' % max(ckp), max(ckp), s['SEUIL_CHECKPOINT_S'])
            lg = ifx.get('logs') or {}
            if lg.get('nombre') and lg.get('non_sauvegardes', 0) > 0.5 * lg['nombre']:
                alerte(a, 'haute', nom, 'informix', 'Journaux logiques non sauvegardés : %d sur %d' % (
                    lg['non_sauvegardes'], lg['nombre']), lg['non_sauvegardes'])
            rep = ifx.get('replication') or {}
            if snap['role'] == 'bdd':
                for r in rep.get('serveurs') or []:
                    if r['etat'].lower() != 'active':
                        alerte(a, 'critique', nom, 'réplication', 'Secondaire %s : %s' % (r['nom'], r['etat']))
            if rep.get('retard_pages') is not None and rep['retard_pages'] >= s['SEUIL_RETARD_RSS']:
                alerte(a, 'haute', nom, 'réplication', 'Retard de réplication', rep['retard_pages'], s['SEUIL_RETARD_RSS'])
    for api in snap.get('api') or []:
        if not api.get('ok'):
            alerte(a, 'critique', nom, 'api', 'API indisponible : %s (%s)' % (api['url'], api.get('code') or api.get('erreur')))
        elif api['ms'] >= s['SEUIL_API_MS']:
            alerte(a, 'moyenne', nom, 'api', 'API lente : %s' % api['url'], api['ms'], s['SEUIL_API_MS'])
    for e in snap.get('erreurs') or []:
        alerte(a, 'faible', nom, 'collecte', 'Collecte partielle : %s' % e)
    return a


def score(alertes):
    return max(0, 100 - sum(POIDS[x['gravite']] for x in alertes))


def statut(alertes, snap):
    if snap is None or any(x['domaine'] == 'collecte' and x['gravite'] == 'critique' for x in alertes):
        return 'injoignable'
    if any(x['gravite'] == 'critique' for x in alertes):
        return 'critique'
    if any(x['gravite'] == 'haute' for x in alertes):
        return 'attention'
    return 'ok'


# --------------------------------------------------------------------------------------------
# Connexions IRIUM
# --------------------------------------------------------------------------------------------
def synthese_connexions(cx):
    if not cx:
        return None
    det = cx.get('detail') or []
    inter = [d for d in det if d.get('type') != 'cron']
    heures = {}
    for d in det:
        heures[d['debut'][:13]] = heures.get(d['debut'][:13], 0) + 1
    pic = max(heures.items(), key=lambda x: x[1]) if heures else None
    cx['kpi'] = {'programmes': len(det), 'interactif': len(inter), 'cron': len(det) - len(inter),
                 'utilisateurs': len(set(d['utilisateur'] for d in inter if d.get('utilisateur'))),
                 'postes': len(set(d['poste'] for d in inter if d.get('poste'))),
                 'en_cours': len([d for d in det if not d.get('fin')]),
                 'pic_heure': pic[0][11:13] + 'h' if pic else None, 'pic_nombre': pic[1] if pic else 0}
    return cx


# --------------------------------------------------------------------------------------------
# Lecture des données et assemblage
# --------------------------------------------------------------------------------------------
def lire_json(chemin):
    try:
        with io.open(chemin, encoding='utf-8') as f:
            return json.load(f)
    except (IOError, OSError, ValueError):
        return None


def lire_historique(chemin, points=168):
    lignes = []
    try:
        with io.open(chemin, encoding='utf-8') as f:
            for l in f:
                try:
                    lignes.append(json.loads(l))
                except ValueError:
                    continue
    except (IOError, OSError):
        return []
    pas = max(1, len(lignes) // points)
    return lignes[::-1][::pas][::-1]  # échantillonné, la dernière mesure toujours incluse


def assembler(conf, partage, maintenant=None, demo=False):
    maintenant = maintenant or dt.datetime.now()
    s = seuils(conf)
    serveurs, alertes, taches, connexions, liens = [], [], [], None, []
    liste = serveurs_conf(conf)
    hotes = dict((x['hote'].split('.')[0].lower(), x['nom']) for x in liste)
    for srv in liste:
        dossier = os.path.join(partage, 'donnees', srv['nom'])
        snap = lire_json(os.path.join(dossier, 'dernier.json'))
        marquer_dbspaces(snap, conf)
        al = analyser_serveur(srv, snap, s, maintenant)
        alertes += al
        e = dict(srv, statut=statut(al, snap), score=score(al), alertes=len(al),
                 fraicheur_min=fraicheur_min(snap, maintenant) if snap else None,
                 horodatage=(snap or {}).get('horodatage'), systeme=(snap or {}).get('systeme'),
                 informix=(snap or {}).get('informix'), api=(snap or {}).get('api'),
                 erreurs=(snap or {}).get('erreurs', []), historique=lire_historique(os.path.join(dossier, 'historique.jsonl')))
        for t in ((snap or {}).get('cron') or {}).get('taches', []):
            taches.append(dict(t, serveur=srv['nom'], description=decrire_cron(t['planification']),
                               categorie=categorie_tache(t['commande'])))
        e['taches'] = len([t for t in taches if t['serveur'] == srv['nom']])
        if snap and snap.get('connexions'):
            connexions = synthese_connexions(snap['connexions'])
        if srv['role'] == 'bdd' and e['informix']:
            for h in e['informix'].get('sessions_par_hote') or []:
                liens.append({'de': hotes.get(h['hote'].lower(), h['hote']), 'vers': srv['nom'], 'sessions': h['nombre']})
        serveurs.append(e)
    alertes.sort(key=lambda x: (GRAVITES.index(x['gravite']), x['serveur']))
    par_g = dict((g, len([x for x in alertes if x['gravite'] == g])) for g in GRAVITES)
    sc = int(round(sum(x['score'] for x in serveurs) / len(serveurs))) if serveurs else 0
    return {
        'meta': {'client': conf.get('CLIENT', 'Tractafric Equipment'),
                 'titre': conf.get('TITRE', "Portail d'infrastructure IRIUM iE"),
                 'genere': maintenant.strftime('%Y-%m-%d %H:%M:%S'), 'frequence_min': int(conf.get('FREQUENCE_MIN', '15')),
                 'seuils': s, 'demo': demo, 'version': '1.0'},
        'resume': {'score': sc, 'en_ligne': len([x for x in serveurs if x['statut'] != 'injoignable']),
                   'total': len(serveurs), 'alertes': par_g,
                   'statut': 'critique' if par_g['critique'] else 'attention' if par_g['haute'] else 'ok'},
        'serveurs': serveurs, 'alertes': alertes, 'taches': taches, 'connexions': connexions,
        'schema': {'liens': liens},
    }


def b64(chemin):
    with open(chemin, 'rb') as f:
        return 'data:image/png;base64,' + base64.b64encode(f.read()).decode('ascii')


def rendre(donnees, conf):
    with io.open(os.path.join(ICI, 'modele.html'), encoding='utf-8') as f:
        html = f.read()
    js = json.dumps(donnees, ensure_ascii=False, separators=(',', ':'), sort_keys=True)
    js = str(js).replace('</', '<\\/').replace('\u2028', '\\u2028').replace('\u2029', '\\u2029')
    logo_client = conf.get('LOGO_CLIENT') or os.path.join(RACINE, 'assets', 'logo_tractafric.png')
    rempl = {'__DONNEES__': js, '__LOGO_CLIENT__': b64(logo_client),
             '__LOGO_IRIUM__': b64(os.path.join(RACINE, 'assets', 'logo_irium.png')),
             '__TITRE__': esc(donnees['meta']['titre']), '__CLIENT__': esc(donnees['meta']['client'])}
    return re.sub('|'.join(rempl), lambda m: rempl[m.group(0)], html)


def esc(t):
    return (t or '').replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;')


def ecrire(chemin, html):
    d = os.path.dirname(chemin)
    if d and not os.path.isdir(d):
        os.makedirs(d)
    tmp = chemin + '.tmp'
    with io.open(tmp, 'w', encoding='utf-8') as f:
        f.write(html)
    os.rename(tmp, chemin)


def main(argv):
    import argparse
    ap = argparse.ArgumentParser(description="Génère le portail d'infrastructure IRIUM iE")
    ap.add_argument('--conf', default=os.path.join(RACINE, 'tractafric.conf'))
    ap.add_argument('--partage', help='dossier commun (défaut : PARTAGE de la configuration)')
    ap.add_argument('--sortie', help='fichier ou dossier de sortie (défaut : <PARTAGE>/portail/index.html)')
    ap.add_argument('--demo', action='store_true', help='génère des données fictives puis le portail')
    a = ap.parse_args(argv)
    conf = lire_conf(a.conf)
    if a.demo:
        import demo
        dossier = a.sortie or os.path.join(RACINE, 'demo')
        conf = demo.conf_demo()
        partage = os.path.join(dossier, 'partage')
        demo.generer(partage, conf)
        sortie = os.path.join(dossier, 'index.html')
    else:
        partage = a.partage or conf.get('PARTAGE') or os.path.join(RACINE, 'donnees-portail')
        sortie = a.sortie or os.path.join(partage, 'portail', 'index.html')
        if os.path.isdir(sortie):
            sortie = os.path.join(sortie, 'index.html')
    donnees = assembler(conf, partage, demo=a.demo)
    ecrire(sortie, rendre(donnees, conf))
    r = donnees['resume']
    print('%s portail généré : %s (score %d/100, %d/%d serveurs en ligne, alertes : %s)' % (
        donnees['meta']['genere'], sortie, r['score'], r['en_ligne'], r['total'],
        ', '.join('%d %s' % (r['alertes'][g], g) for g in GRAVITES if r['alertes'][g]) or 'aucune'))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
