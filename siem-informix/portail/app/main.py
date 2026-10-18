"""Portail SIEM Informix : API et interface web."""
import csv
import datetime as dt
import hmac
import io
import logging
import mimetypes
import os
import secrets
import threading
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles

from . import assistant, auth, collecte, db
from .auth import ajouter_compte, lire_comptes  # noqa: F401  (utilisés par app.outils et les tests)
from .config import config

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(name)s %(message)s')
log = logging.getLogger('siem')

STATIC = os.path.join(os.path.dirname(__file__), 'static')
VERSION = '2.0'


# --------------------------------------------------------------------------------------------
# Session et droits
# --------------------------------------------------------------------------------------------
def utilisateur_courant(request: Request):
    u = auth.session(request.cookies.get(auth.COOKIE))
    if not u:
        raise HTTPException(401, 'Session expirée, reconnectez-vous.')
    return u


def admin(u=Depends(utilisateur_courant)):
    if u['role'] != 'admin':
        raise HTTPException(403, 'Réservé aux administrateurs du portail')
    return u


def ip_client(request: Request):
    return request.client.host if request.client else '?'


def demarrage():
    db.initialiser()
    if not lire_comptes():
        mdp = secrets.token_urlsafe(12)
        ajouter_compte('admin.local', mdp, 'admin')
        log.warning('Premier démarrage : compte local de secours « admin.local » créé avec le mot de passe : %s (à changer)', mdp)
    if not config.jeton_collecteur:
        log.info('SIEM_JETON_COLLECTEUR non défini : seule la collecte pilotée par le portail est active.')
    if not config.ad_actif():
        log.warning('Active Directory non configuré : seuls les comptes locaux peuvent se connecter.')
    collecte.assurer_cle()
    collecte.demarrer_planificateur()


@asynccontextmanager
async def cycle_de_vie(_app):
    demarrage()
    yield
    collecte.arreter_planificateur()


app = FastAPI(title='Portail SIEM Informix', docs_url=None, redoc_url=None, lifespan=cycle_de_vie)

CSP = ("default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; "
       "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")


@app.middleware('http')
async def securite(request: Request, suite):
    # Protection CSRF : toute écriture de l'interface doit porter l'en-tête X-SIEM (impossible depuis un autre site)
    if request.method not in ('GET', 'HEAD', 'OPTIONS') and request.url.path.startswith('/api/') \
            and request.url.path != '/api/ingestion' and request.headers.get('x-siem') != '1':
        return JSONResponse({'detail': 'Requête refusée'}, status_code=403)
    rep = await suite(request)
    rep.headers['Content-Security-Policy'] = CSP
    rep.headers['X-Content-Type-Options'] = 'nosniff'
    rep.headers['Referrer-Policy'] = 'same-origin'
    rep.headers['X-Frame-Options'] = 'DENY'
    if request.url.path.startswith('/api/'):
        rep.headers['Cache-Control'] = 'no-store'
    return rep


# --------------------------------------------------------------------------------------------
# Marque du client, connexion
# --------------------------------------------------------------------------------------------
def _texte_sur(couleur):
    try:
        c = couleur.lstrip('#')
        r, g, b = (int(c[i:i + 2], 16) / 255 for i in (0, 2, 4))
        lin = [x / 12.92 if x <= 0.04045 else ((x + 0.055) / 1.055) ** 2.4 for x in (r, g, b)]
        return '#111111' if 0.2126 * lin[0] + 0.7152 * lin[1] + 0.0722 * lin[2] > 0.18 else '#ffffff'
    except (ValueError, IndexError):
        return '#ffffff'


@app.get('/api/marque')
def marque():
    return {'nom': config.marque_nom, 'sous_titre': config.marque_sous_titre, 'couleur': config.marque_couleur,
            'logo': '/marque/logo' if config.marque_logo and os.path.exists(config.marque_logo) else None,
            'ad': config.ad_actif(), 'domaine': config.ad_domaine, 'version': VERSION}


@app.get('/marque.css')
def marque_css():
    css = ':root{--marque:%s;--sur-marque:%s}' % (config.marque_couleur, _texte_sur(config.marque_couleur))
    return Response(css, media_type='text/css', headers={'Cache-Control': 'max-age=300'})


@app.get('/marque/logo')
def logo():
    if not config.marque_logo or not os.path.exists(config.marque_logo):
        return FileResponse(os.path.join(STATIC, 'icone.svg'), media_type='image/svg+xml')
    return FileResponse(config.marque_logo, media_type=mimetypes.guess_type(config.marque_logo)[0] or 'image/png',
                        headers={'Cache-Control': 'max-age=3600'})


@app.get('/connexion')
def page_connexion():
    return FileResponse(os.path.join(STATIC, 'connexion.html'))


@app.post('/api/connexion')
async def connexion(request: Request):
    corps = await request.json()
    try:
        jeton, u = auth.connecter(corps.get('login'), corps.get('mot_de_passe'), ip_client(request))
    except auth.RefusAuthentification as e:
        raise HTTPException(401, str(e))
    rep = JSONResponse({'ok': True, 'utilisateur': u})
    rep.set_cookie(auth.COOKIE, jeton, httponly=True, secure=config.cookie_securise, samesite='strict',
                   max_age=config.session_heures * 3600, path='/')
    return rep


@app.post('/api/deconnexion')
def deconnexion(request: Request):
    jeton = request.cookies.get(auth.COOKIE)
    u = auth.session(jeton)
    auth.deconnecter(jeton)
    if u:
        db.journaliser(u['login'], 'deconnexion', ip_client(request))
    rep = JSONResponse({'ok': True})
    rep.delete_cookie(auth.COOKIE, path='/')
    return rep


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
                heures_ouvrees=[config.heure_debut, config.heure_fin], marque=marque())


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
# Administration : collecte, comptes locaux, journal, paramètres
# --------------------------------------------------------------------------------------------
@app.get('/api/collecte/sante')
def sante_collecte(u=Depends(utilisateur_courant)):
    return collecte.sante()


@app.get('/api/admin/sources')
def sources(u=Depends(admin)):
    res = collecte.lister_sources()
    for s in res:
        s['authorized_keys'] = collecte.ligne_authorized_keys(s)
    return res


@app.post('/api/admin/sources')
async def creer_source(request: Request, u=Depends(admin)):
    corps = await request.json()
    try:
        id_source = collecte.enregistrer_source(corps)
    except ValueError as e:
        raise HTTPException(400, str(e))
    db.journaliser(u['login'], 'source_creee', '%s (%s)' % (corps.get('nom'), corps.get('hote')))
    return {'id': id_source}


@app.put('/api/admin/sources/{id_source}')
async def modifier_source(id_source: int, request: Request, u=Depends(admin)):
    corps = await request.json()
    corps.pop('etat', None)
    try:
        collecte.enregistrer_source(corps, id_source)
    except ValueError as e:
        raise HTTPException(400, str(e))
    db.journaliser(u['login'], 'source_modifiee', id_source)
    return {'ok': True}


@app.delete('/api/admin/sources/{id_source}')
def supprimer_source(id_source: int, u=Depends(admin)):
    collecte.supprimer_source(id_source)
    db.journaliser(u['login'], 'source_supprimee', id_source)
    return {'ok': True}


@app.post('/api/admin/sources/{id_source}/tester')
def tester_source(id_source: int, u=Depends(admin)):
    return collecte.tester(id_source)


@app.post('/api/admin/sources/{id_source}/executer')
async def executer_source(id_source: int, request: Request, u=Depends(admin)):
    corps = await request.json()
    depuis = (corps.get('depuis') or '')[:10] or None
    if depuis:
        dt.datetime.strptime(depuis, '%Y-%m-%d')
    db.journaliser(u['login'], 'collecte_manuelle', '%s depuis %s' % (id_source, depuis or 'dernier point'))
    threading.Thread(target=collecte.executer, args=(id_source, depuis), daemon=True).start()
    return {'ok': True, 'message': 'Collecte lancée en arrière-plan.'}


@app.get('/api/admin/sources/{id_source}/executions')
def executions_source(id_source: int, u=Depends(admin)):
    return collecte.executions(id_source)


@app.get('/api/admin/cle-ssh')
def cle_ssh(u=Depends(admin)):
    return {'publique': collecte.assurer_cle()}


@app.get('/api/admin/comptes')
def comptes_locaux(u=Depends(admin)):
    return [{'login': l, 'role': r} for l, (_e, r) in sorted(lire_comptes().items())]


@app.post('/api/admin/comptes')
async def enregistrer_compte(request: Request, u=Depends(admin)):
    corps = await request.json()
    login, mdp, role = (corps.get('login') or '').strip().lower(), corps.get('mot_de_passe') or '', corps.get('role', 'lecteur')
    if not login or ':' in login or role not in ('admin', 'lecteur'):
        raise HTTPException(400, 'Identifiant ou rôle invalide')
    if len(mdp) < 12:
        raise HTTPException(400, 'Mot de passe trop court (12 caractères minimum)')
    ajouter_compte(login, mdp, role)
    db.journaliser(u['login'], 'compte_local', '%s (%s)' % (login, role))
    return {'ok': True}


@app.delete('/api/admin/comptes/{login}')
def supprimer_compte(login: str, u=Depends(admin)):
    comptes = lire_comptes()
    if login.lower() not in comptes:
        raise HTTPException(404)
    if sum(1 for r in comptes.values() if r[1] == 'admin') <= 1 and comptes[login.lower()][1] == 'admin':
        raise HTTPException(400, 'Impossible de supprimer le dernier administrateur local (accès de secours).')
    auth.supprimer_compte(login)
    db.journaliser(u['login'], 'compte_local_supprime', login)
    return {'ok': True}


@app.get('/api/admin/journal')
def journal(texte: str = None, u=Depends(admin)):
    return db.journal(texte=texte)


@app.get('/api/admin/parametres')
def parametres(u=Depends(admin)):
    return {
        'ad': {'actif': config.ad_actif(), 'serveurs': config.ad_serveurs, 'base_dn': config.ad_base_dn,
               'groupe_admin': config.ad_groupe_admin, 'groupe_lecteur': config.ad_groupe_lecteur,
               'certificat_verifie': config.ad_verifier_certificat},
        'sessions': {'duree_h': config.session_heures, 'inactivite_min': config.session_inactivite_min,
                     'verrouillage': '%d échecs -> %d min' % (config.max_echecs, config.blocage_min)},
        'notifications': {'actives': config.smtp_actif(), 'serveur': config.smtp_serveur,
                          'destinataires': config.smtp_destinataires, 'gravites': config.notif_gravites},
        'regles': {'comptes_partages': config.comptes_partages, 'heures_ouvrees': '%dh-%dh' % (config.heure_debut, config.heure_fin),
                   'seuil_echecs': config.seuil_echecs, 'conservation_jours': config.conservation_jours},
        'assistant': {'ia': config.ia_active(), 'modele': config.modele if config.ia_active() else None},
        'collecte': {'planificateur': config.planificateur, 'ingestion_push': bool(config.jeton_collecteur)},
        'version': VERSION,
    }


# --------------------------------------------------------------------------------------------
# Interface web
# --------------------------------------------------------------------------------------------
@app.get('/api/sante')
def sante():
    return {'ok': True, 'version': VERSION}


app.mount('/static', StaticFiles(directory=STATIC), name='static')


@app.get('/')
def accueil(request: Request):
    if not auth.session(request.cookies.get(auth.COOKIE)):
        return RedirectResponse('/connexion', status_code=303)
    return FileResponse(os.path.join(STATIC, 'index.html'))
