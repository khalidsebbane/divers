"""Configuration du portail, lue dans les variables d'environnement (voir .env.exemple)."""
import os


def _liste(nom, defaut=''):
    return [x.strip().lower() for x in os.environ.get(nom, defaut).split(',') if x.strip()]


class Config:
    def __init__(self):
        self.base = os.environ.get('SIEM_BASE', os.path.join(os.path.dirname(__file__), '..', 'donnees', 'siem.db'))
        self.jeton_collecteur = os.environ.get('SIEM_JETON_COLLECTEUR', '')
        self.fichier_comptes = os.environ.get('SIEM_COMPTES_PORTAIL',
                                              os.path.join(os.path.dirname(self.base), 'comptes_portail.txt'))
        # Comptes partagés : leurs actions sont rattachées à une personne « probable » via le poste
        self.comptes_partages = _liste('SIEM_COMPTES_PARTAGES', 'regix,informix,root')
        # Heures ouvrées : 8h -> 19h du lundi au vendredi
        h = os.environ.get('SIEM_HEURES_OUVREES', '08-19').split('-')
        self.heure_debut, self.heure_fin = int(h[0]), int(h[1])
        self.alerte_hors_heures = os.environ.get('SIEM_ALERTE_HORS_HEURES', 'oui') == 'oui'
        self.seuil_echecs = int(os.environ.get('SIEM_SEUIL_ECHECS', '5'))
        # Assistant IA : auto (actif si une clé API est présente), non (désactivé)
        self.assistant_ia = os.environ.get('SIEM_ASSISTANT_IA', 'auto')
        self.modele = os.environ.get('SIEM_MODELE', 'claude-opus-5-5')
        self.conservation_jours = int(os.environ.get('SIEM_CONSERVATION_JOURS', '400'))

    def ia_active(self):
        if self.assistant_ia == 'non':
            return False
        return bool(os.environ.get('ANTHROPIC_API_KEY') or os.environ.get('ANTHROPIC_AUTH_TOKEN')
                    or self.assistant_ia == 'oui')

    def hors_heures(self, d):
        return d.weekday() >= 5 or not (self.heure_debut <= d.hour < self.heure_fin)


config = Config()
