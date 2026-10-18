"""Envoi des alertes graves par e-mail (résumé groupé, au plus une fois par alerte)."""
import datetime as dt
import html
import logging
import smtplib
import ssl
from email.message import EmailMessage

from . import db
from .config import config

log = logging.getLogger('siem.notifications')


def envoyer_alertes():
    if not config.smtp_actif() or not config.notif_gravites:
        return 0
    depuis = (dt.datetime.now() - dt.timedelta(hours=24)).strftime('%Y-%m-%dT%H:%M:%S')
    with db.connexion() as cx:
        alertes = db.lignes(cx, 'SELECT * FROM alertes WHERE COALESCE(notifiee, 0) = 0 AND ts >= ? AND gravite IN (%s)'
                                ' ORDER BY ts' % ','.join('?' * len(config.notif_gravites)), [depuis] + config.notif_gravites)
    if not alertes:
        return 0
    msg = EmailMessage()
    msg['Subject'] = '[%s] %d alerte(s) de sécurité' % (config.marque_nom, len(alertes))
    msg['From'] = config.smtp_expediteur
    msg['To'] = ', '.join(config.smtp_destinataires)
    lignes = ['- %s [%s] %s : %s' % (a['ts'].replace('T', ' ')[:16], a['gravite'].upper(), a['titre'], a['message'] or '')
              for a in alertes]
    lien = ('\n\nPortail : %s/#/alertes' % config.url_portail.rstrip('/')) if config.url_portail else ''
    msg.set_content('Nouvelles alertes du portail %s :\n\n%s%s\n' % (config.marque_nom, '\n'.join(lignes), lien))
    msg.add_alternative('<p>Nouvelles alertes du portail <b>%s</b> :</p><table cellpadding="6" style="border-collapse:collapse">%s</table>%s'
                        % (html.escape(config.marque_nom), ''.join(
                            '<tr style="border-bottom:1px solid #ddd"><td>%s</td><td><b>%s</b></td><td>%s<br><small>%s</small></td></tr>'
                            % (html.escape(a['ts'].replace('T', ' ')[:16]), html.escape(a['gravite']), html.escape(a['titre']),
                               html.escape(a['message'] or '')) for a in alertes),
                           ('<p><a href="%s/#/alertes">Ouvrir le portail</a></p>' % html.escape(config.url_portail.rstrip('/')))
                           if config.url_portail else ''), subtype='html')
    try:
        with smtplib.SMTP(config.smtp_serveur, config.smtp_port, timeout=20) as s:
            if config.smtp_starttls:
                s.starttls(context=ssl.create_default_context())
            if config.smtp_utilisateur:
                s.login(config.smtp_utilisateur, config.smtp_mdp)
            s.send_message(msg)
    except (OSError, smtplib.SMTPException) as e:
        log.warning('Envoi des alertes par e-mail impossible : %s', e)
        return 0
    with db.connexion() as cx:
        cx.executemany('UPDATE alertes SET notifiee = 1 WHERE id = ?', [(a['id'],) for a in alertes])
    log.info('%d alerte(s) envoyée(s) par e-mail', len(alertes))
    return len(alertes)
