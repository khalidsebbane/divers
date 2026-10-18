"""Configuration du portail, lue dans les variables d'environnement (voir .env.exemple)."""
import os


def _liste(nom, defaut=''):
    return [x.strip().lower() for x in os.environ.get(nom, defaut).split(',') if x.strip()]


def _oui(nom, defaut='non'):
    return os.environ.get(nom, defaut).strip().lower() in ('oui', '1', 'true', 'yes')


class Config:
    def __init__(self):
        e = os.environ.get
        self.base = e('SIEM_BASE', os.path.join(os.path.dirname(__file__), '..', 'donnees', 'siem.db'))
        self.dossier_donnees = os.path.dirname(os.path.abspath(self.base))
        self.jeton_collecteur = e('SIEM_JETON_COLLECTEUR', '')
        self.fichier_comptes = e('SIEM_COMPTES_PORTAIL', os.path.join(self.dossier_donnees, 'comptes_portail.txt'))

        # --- Marque du client (logo, nom, couleur)
        self.marque_nom = e('SIEM_MARQUE_NOM', 'SIEM Informix')
        self.marque_sous_titre = e('SIEM_MARQUE_SOUS_TITRE', 'Traçabilité système, base et applicatif')
        self.marque_couleur = e('SIEM_MARQUE_COULEUR', '#1c5cab')
        self.marque_logo = e('SIEM_MARQUE_LOGO', '')          # chemin d'un fichier PNG/SVG/JPG

        # --- Sessions du portail
        self.session_heures = int(e('SIEM_SESSION_HEURES', '8'))
        self.session_inactivite_min = int(e('SIEM_SESSION_INACTIVITE_MIN', '30'))
        self.cookie_securise = _oui('SIEM_COOKIE_SECURISE', 'oui')  # cookie HTTPS uniquement

        # --- Active Directory (LDAP / LDAPS)
        self.ad_serveurs = [s.strip() for s in e('SIEM_AD_SERVEURS', '').split(',') if s.strip()]  # ldaps://dc1:636,...
        self.ad_base_dn = e('SIEM_AD_BASE_DN', '')
        self.ad_compte_service = e('SIEM_AD_COMPTE_SERVICE', '')     # DN ou UPN du compte de lecture
        self.ad_mdp_service = e('SIEM_AD_MDP_SERVICE', '')
        self.ad_groupe_admin = e('SIEM_AD_GROUPE_ADMIN', '')         # DN du groupe des administrateurs du portail
        self.ad_groupe_lecteur = e('SIEM_AD_GROUPE_LECTEUR', '')     # DN du groupe des lecteurs
        self.ad_ca = e('SIEM_AD_CA', '')                             # certificat de l'autorité interne (PEM)
        self.ad_verifier_certificat = _oui('SIEM_AD_VERIFIER_CERTIFICAT', 'oui')
        self.ad_attribut_login = e('SIEM_AD_ATTRIBUT_LOGIN', 'sAMAccountName')
        self.ad_domaine = e('SIEM_AD_DOMAINE', '')                   # affiché sur la page de connexion

        # --- Anti-force brute
        self.max_echecs = int(e('SIEM_MAX_ECHECS_CONNEXION', '5'))
        self.blocage_min = int(e('SIEM_BLOCAGE_MIN', '15'))

        # --- Collecte pilotée (serveurs Informix collectés par SSH)
        self.dossier_ssh = e('SIEM_DOSSIER_SSH', os.path.join(self.dossier_donnees, 'ssh'))
        self.planificateur = _oui('SIEM_PLANIFICATEUR', 'oui')

        # --- Notifications e-mail (alertes hautes et critiques)
        self.smtp_serveur = e('SIEM_SMTP_SERVEUR', '')
        self.smtp_port = int(e('SIEM_SMTP_PORT', '587'))
        self.smtp_starttls = _oui('SIEM_SMTP_STARTTLS', 'oui')
        self.smtp_utilisateur = e('SIEM_SMTP_UTILISATEUR', '')
        self.smtp_mdp = e('SIEM_SMTP_MDP', '')
        self.smtp_expediteur = e('SIEM_SMTP_EXPEDITEUR', 'siem@localhost')
        self.smtp_destinataires = [x.strip() for x in e('SIEM_SMTP_DESTINATAIRES', '').split(',') if x.strip()]
        self.notif_gravites = _liste('SIEM_NOTIF_GRAVITES', 'haute,critique')
        self.url_portail = e('SIEM_URL_PORTAIL', '')

        # --- Règles
        self.comptes_partages = _liste('SIEM_COMPTES_PARTAGES', 'regix,informix,root')
        h = e('SIEM_HEURES_OUVREES', '08-19').split('-')
        self.heure_debut, self.heure_fin = int(h[0]), int(h[1])
        self.alerte_hors_heures = _oui('SIEM_ALERTE_HORS_HEURES', 'oui')
        self.seuil_echecs = int(e('SIEM_SEUIL_ECHECS', '5'))
        self.conservation_jours = int(e('SIEM_CONSERVATION_JOURS', '400'))

        # --- Assistant IA : auto (actif si une clé API est présente), non (désactivé)
        self.assistant_ia = e('SIEM_ASSISTANT_IA', 'auto')
        self.modele = e('SIEM_MODELE', 'claude-opus-5-5')

    def ad_actif(self):
        return bool(self.ad_serveurs and self.ad_base_dn)

    def ia_active(self):
        if self.assistant_ia == 'non':
            return False
        return bool(os.environ.get('ANTHROPIC_API_KEY') or os.environ.get('ANTHROPIC_AUTH_TOKEN')
                    or self.assistant_ia == 'oui')

    def smtp_actif(self):
        return bool(self.smtp_serveur and self.smtp_destinataires)

    def hors_heures(self, d):
        return d.weekday() >= 5 or not (self.heure_debut <= d.hour < self.heure_fin)


config = Config()
