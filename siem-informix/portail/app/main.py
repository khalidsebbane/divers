"""Portail SIEM Informix : API et interface web."""
import csv
import datetime as dt
import hashlib
import hmac
import io
import logging
import os
import secrets
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.staticfiles import StaticFiles

from . import assistant, db
from .config import config

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(name)s %(message)s')
log = logging.getLogger('siem')

securite = HTTPBasic(realm='Portail SIEM Informix')
STATIC = os.path.join(os.path.dirname(__file__), 'static')


# --------------------------------------------------------------------------------------------
# Comptes du portail : fichier « login:pbkdf2_sha256$iterations$sel$empreinte:role »
# --------------------------------------------------------------------------------------------
def hacher(mot_de_passe, sel=None, iterations=310000):
    sel = sel or secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac('sha256', mot_de_passe.encode(), bytes.fromhex(sel), iterations).hex()
    return 'pbkdf2_sha256$%d$%s$%s' % (iterations, sel, h)


def lire_comptes():
    comptes = {}
    if os.path.exists(config.fichier_comptes):
        with open(config.fichier_comptes, encoding='utf-8') as f:
            for ligne in f:
                ligne = ligne.strip()
                if ligne and not ligne.startswith('#'):
                    login, empreinte, role = (ligne.split(':') + ['lecteur'])[:3]
                    comptes[login] = (empreinte, role or 'lecteur')
    return comptes


def ajouter_compte(login, mot_de_passe, role='admin'):
    comptes = lire_comptes()
    comptes[login] = (hacher(mot_de_passe), role)
    os.makedirs(os.path.dirname(os.path.abspath(config.fichier_comptes)), exist_ok=True)
    with open(config.fichier_comptes, 'w', encoding='utf-8') as f:
        f.write('# Comptes du portail SIEM (login:empreinte:role). Gérer avec : python -m app.outils compte <login>\n')
        for l, (e, r) in sorted(comptes.items()):
            f.write('%s:%s:%s\n' % (l, e, r))
    os.chmod(config.fichier_comptes, 0o600)


def verifier(mot_de_passe, empreinte):
    try:
        _algo, it, sel, h = empreinte.split('$')
        return hmac.compare_digest(hacher(mot_de_passe, sel, int(it)), empreinte)
    except ValueError:
        return False


def utilisateur_courant(cred: HTTPBasicCredentials = Depends(securite)):
    compte = lire_comptes().get(cred.username)
    if not compte or not verifier(cred.password, compte[0]):
        raise HTTPException(401, 'Identifiants invalides', headers={'WWW-Authenticate': 'Basic realm="Portail SIEM Informix"'})
    return {'login': cred.username, 'role': compte[1]}


def admin(u=Depends(utilisateur_courant)):
    if u['role'] != 'admin':
        raise HTTPException(403, 'Réservé aux administrateurs du portail')
    return u


def demarrage():
    db.initialiser()
    if not lire_comptes():
        mdp = secrets.token_urlsafe(12)
        ajouter_compte('admin', mdp, 'admin')
        log.warning('Premier démarrage : compte « admin » créé avec le mot de passe : %s (à changer)', mdp)
    if not config.jeton_collecteur:
        log.warning('SIEM_JETON_COLLECTEUR non défini : l\'ingestion depuis les collecteurs est refusée.')


@asynccontextmanager
async def cycle_de_vie(_app):
    demarrage()
    yield


app = FastAPI(title='Portail SIEM Informix', docs_url=None, redoc_url=None, lifespan=cycle_de_vie)


# --------------------------------------------------------------------------------------------
# Ingestion (collecteurs)
# --------------------------------------------------------------------------------------------
@app.post('/api/ingestion')
async def ingestion(request: Request, x_jeton: str = Header(default='')):
    if not config.jeton_collecteur or not hmac.compare_digest(x_jeton, config.jeton_collecteur):
        raise HTTPException(401, 'Jeton collecteur invalide')
    corps = await request.json()
    evts = corps.get('evenements') or []
    inseres, nb_alertes = db.ingerer(evts)
    log.info('ingestion %s : %d reçus, %d nouveaux, %d alerte(s)', corps.get('serveur'), len(evts), inseres, nb_alertes)
    return {'recus': len(evts), 'inseres': inseres, 'alertes': nb_alertes}


# --------------------------------------------------------------------------------------------
# Consultation
# --------------------------------------------------------------------------------------------
def periode(debut, fin):
    a = dt.date.today()
    return (debut or (a - dt.timedelta(days=29)).isoformat())[:10], (fin or a.isoformat())[:10]


@app.get('/api/moi')
def moi(u=Depends(utilisateur_courant)):
    return dict(u, ia=config.ia_active(), comptes_partages=config.comptes_partages,
                heures_ouvrees=[config.heure_debut, config.heure_fin])


@app.get('/api/tableau-de-bord')
def tableau(debut: str = None, fin: str = None, u=Depends(utilisateur_courant)):
    return db.tableau_de_bord(*periode(debut, fin))


@app.get('/api/personnes')
def liste_personnes(debut: str = None, fin: str = None, texte: str = None, u=Depends(utilisateur_courant)):
    return db.personnes(*periode(debut, fin), texte=texte)


@app.get('/api/personnes/{personne}')
def fiche(personne: str, debut: str = None, fin: str = None, u=Depends(utilisateur_courant)):
    db.journaliser(u['login'], 'fiche', personne)
    return db.profil(personne, *periode(debut, fin))


def _filtres(debut, fin, personne, compte, ip, source, categorie, resultat, texte):
    d, f = periode(debut, fin)
    return dict(debut=d, fin=f, personne=personne, compte=compte, ip=ip, source=source, categorie=categorie,
                resultat=resultat, texte=texte)


@app.get('/api/evenements')
def evenements(debut: str = None, fin: str = None, personne: str = None, compte: str = None, ip: str = None,
               source: str = None, categorie: str = None, resultat: str = None, texte: str = None,
               limite: int = 100, decalage: int = 0, u=Depends(utilisateur_courant)):
    total, rows = db.rechercher(limite=min(limite, 1000), decalage=decalage,
                                **_filtres(debut, fin, personne, compte, ip, source, categorie, resultat, texte))
    return {'total': total, 'evenements': rows}


@app.get('/api/evenements.csv')
def export_csv(debut: str = None, fin: str = None, personne: str = None, compte: str = None, ip: str = None,
               source: str = None, categorie: str = None, resultat: str = None, texte: str = None,
               u=Depends(utilisateur_courant)):
    f = _filtres(debut, fin, personne, compte, ip, source, categorie, resultat, texte)
    db.journaliser(u['login'], 'export_csv', f)
    _total, rows = db.rechercher(limite=200000, ordre='ASC', **f)
    tampon = io.StringIO()
    tampon.write('﻿')
    w = csv.writer(tampon, delimiter=';')
    w.writerow(['Date', 'Heure', 'Volet', 'Catégorie', 'Action', 'Personne', 'Attribution', 'Compte', 'IP', 'Poste',
                'Objet', 'Résultat', 'Serveur'])
    for r in rows:
        w.writerow([r['ts'][8:10] + '/' + r['ts'][5:7] + '/' + r['ts'][:4], r['ts'][11:19], r['source'], r['categorie'],
                    r['action'], r['personne'], r['attribution'], r['compte'], r['ip'], r['poste'], r['objet'],
                    r['resultat'], r['serveur']])
    nom = 'evenements_%s_%s.csv' % (f['debut'], f['fin'])
    return StreamingResponse(iter([tampon.getvalue()]), media_type='text/csv; charset=utf-8',
                             headers={'Content-Disposition': 'attachment; filename="%s"' % nom})


@app.get('/api/alertes')
def liste_alertes(statut: str = None, gravite: str = None, debut: str = None, fin: str = None, u=Depends(utilisateur_courant)):
    return db.alertes(statut, gravite, debut, fin)


@app.post('/api/alertes/{id_alerte}')
async def changer_alerte(id_alerte: int, request: Request, u=Depends(admin)):
    corps = await request.json()
    if corps.get('statut') not in ('ouverte', 'en_cours', 'close'):
        raise HTTPException(400, 'Statut invalide')
    db.maj_alerte(id_alerte, corps['statut'], corps.get('commentaire', ''), u['login'])
    return {'ok': True}


@app.get('/api/postes')
def postes(u=Depends(utilisateur_courant)):
    return db.lister_postes()


@app.post('/api/postes')
async def definir_poste(request: Request, u=Depends(admin)):
    corps = await request.json()
    if not corps.get('ip'):
        raise HTTPException(400, 'IP obligatoire')
    db.journaliser(u['login'], 'poste', corps)
    return {'reattribues': db.definir_poste(corps['ip'].strip(), (corps.get('personne') or '').strip(), corps.get('libelle', ''))}


# --------------------------------------------------------------------------------------------
# Assistant
# --------------------------------------------------------------------------------------------
@app.get('/api/assistant/suggestions')
def sugg(personne: str = None, u=Depends(utilisateur_courant)):
    return {'suggestions': assistant.suggestions(personne), 'ia': config.ia_active()}


@app.post('/api/assistant')
async def demander(request: Request, u=Depends(utilisateur_courant)):
    corps = await request.json()
    personne = corps.get('personne') or None
    sid = corps.get('suggestion')
    question = (corps.get('question') or '').strip()[:2000]
    db.journaliser(u['login'], 'assistant', sid or question)
    if not sid and question and not config.ia_active():
        sid = assistant.mot_cle_vers_suggestion(question, personne)
        if not sid:
            return {'texte': 'L\'assistant IA n\'est pas activé sur ce portail. Choisissez une des questions proposées ci-dessous.',
                    'suggestions': [], 'proposees': assistant.suggestions(personne, 6), 'mode': 'direct'}
    if sid:
        texte, tableau = assistant.repondre_suggestion(sid, personne, corps.get('alerte'))
        return {'texte': texte, 'tableaux': [tableau] if tableau else [], 'proposees': assistant.suivantes(sid, personne),
                'mode': 'direct'}
    if not question:
        raise HTTPException(400, 'Question vide')
    rep = assistant.repondre_ia(question, corps.get('historique'), personne)
    rep['proposees'] = [{'texte': s} for s in rep.get('suggestions', [])] or assistant.suggestions(personne, 4)
    return rep


# --------------------------------------------------------------------------------------------
# Interface web
# --------------------------------------------------------------------------------------------
@app.get('/api/sante')
def sante():
    return {'ok': True, 'version': '1.0'}


app.mount('/static', StaticFiles(directory=STATIC), name='static')


@app.get('/')
def accueil(u=Depends(utilisateur_courant)):
    return FileResponse(os.path.join(STATIC, 'index.html'))
