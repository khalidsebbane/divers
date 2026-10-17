"""Tests du collecteur : lecture des sources système et Informix à partir d'extraits."""
import configparser
import datetime as dt
import os
import socket
import struct
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'collecteur'))
import collecteur as c  # noqa: E402


def conf(**sections):
    cp = configparser.ConfigParser(interpolation=None)
    for s, vals in sections.items():
        cp[s] = vals
    return cp


def utmp(typ, line, user, host, ip, d):
    a = socket.inet_aton(ip) + b'\0' * 12 if ip else b'\0' * 16
    return struct.pack(c.UTMP_FMT, typ, 100, line.encode(), line[-4:].encode(), user.encode(), host.encode(),
                       0, 0, 0, int(time.mktime(d.timetuple())), 0, a, b'\0' * 20)


def test_wtmp_sessions(tmp_path):
    D = dt.datetime
    f = tmp_path / 'wtmp'
    f.write_bytes(utmp(7, 'pts/0', 'kbenali', '10.12.8.40', '10.12.8.40', D(2026, 9, 1, 8, 0))
                  + utmp(8, 'pts/0', '', '', '', D(2026, 9, 1, 9, 30))
                  + utmp(7, 'pts/1', 'regix', '', '', D(2026, 9, 2, 22, 0)))
    evts = c.collecter_wtmp(conf(systeme={'wtmp': str(f)}), D(2026, 8, 1))
    assert [e['categorie'] for e in evts] == ['connexion', 'deconnexion', 'connexion']
    assert evts[0]['session'] == evts[1]['session']
    assert evts[1]['details']['duree_s'] == 5400
    assert evts[0]['ip'] == '10.12.8.40' and evts[2]['ip'] == 'local'
    # reprise : rien avant le point de reprise
    assert len(c.collecter_wtmp(conf(systeme={'wtmp': str(f)}), D(2026, 9, 2))) == 1


def test_secure_sudo_su_ssh(tmp_path):
    f = tmp_path / 'secure'
    f.write_text(
        'Sep  1 08:00:00 srv sshd[1]: Accepted publickey for kbenali from 10.12.8.40 port 5000 ssh2\n'
        'Sep  1 08:01:00 srv sudo[2]: kbenali : TTY=pts/0 ; PWD=/home/kbenali ; USER=informix ; COMMAND=/bin/bash\n'
        'Sep  1 08:02:00 srv su[3]: pam_unix(su-l:session): session opened for user regix by kbenali(uid=1000)\n'
        'Sep  1 08:03:00 srv sshd[4]: Failed password for invalid user test from 10.9.9.9 port 22 ssh2\n')
    os.utime(f, (time.mktime(dt.datetime(2026, 9, 20).timetuple()),) * 2)
    evts = c.collecter_secure(conf(systeme={'secure': str(f)}), dt.datetime(2026, 8, 1))
    cats = [(e['categorie'], e['compte'], e['utilisateur']) for e in evts]
    assert cats == [('authentification', 'kbenali', 'kbenali'), ('sudo', 'informix', 'kbenali'),
                    ('changement_compte', 'regix', 'kbenali'), ('echec_connexion', 'test', 'test')]
    assert evts[0]['ts'] == '2026-09-01T08:00:00'


def test_auditd_auid_et_commande(tmp_path):
    f = tmp_path / 'audit.log'
    cmd_hex = 'onmode -ky'.encode().hex().upper()
    f.write_text(
        'type=SYSCALL msg=audit(1788000000.123:555): arch=c000003e syscall=59 success=yes exit=0 auid=0 uid=0 ses=7 '
        'tty=pts0 comm="onmode" exe="/opt/informix/bin/onmode" key="siem_exec_informix"\n'
        'type=EXECVE msg=audit(1788000000.123:555): argc=2 a0="onmode" a1="-ky"\n'
        'type=PROCTITLE msg=audit(1788000000.123:555): proctitle=%s\n'
        'type=SYSCALL msg=audit(1788000001.000:556): arch=c000003e syscall=59 success=yes key=(null) auid=0 uid=0\n' % cmd_hex)
    evts = c.collecter_auditd(conf(systeme={'auditd': str(f)}), dt.datetime(2020, 1, 1))
    assert len(evts) == 1
    e = evts[0]
    assert e['categorie'] == 'commande' and e['objet'] == 'onmode -ky'
    assert e['utilisateur'] == 'root' and e['details']['cle'] == 'siem_exec_informix'
    assert c._hexdec(cmd_hex) == 'onmode -ky'


def test_onshowaudit(tmp_path):
    f = tmp_path / 'audit.txt'
    f.write_text('ONLN|2026-09-03 22:58:10.000|pc-inconnu|4242|ol_prod|regix|0|DRTB|prod|reglement_hist|\n'
                 'en-tete ignoree\n'
                 'ONLN|2026-09-03 23:00:00.000|pc-inconnu|4242|ol_prod|regix|-387|GRTB|prod|client|\n')
    cfg = conf(informix={'fichiers_onshowaudit': str(f), 'resoudre_ip': 'non', 'audit_champ_date': '1',
                         'audit_champ_machine': '2', 'audit_champ_pid': '3', 'audit_champ_utilisateur': '5',
                         'audit_champ_erreur': '6', 'audit_champ_code': '7', 'audit_champ_objet': '8'})
    evts = c.collecter_onaudit(cfg, dt.datetime(2026, 9, 1))
    assert [(e['action'], e['resultat'], e['objet']) for e in evts] == [
        ('Suppression de table', 'succes', 'prod:reglement_hist'), ('GRANT sur table', 'echec', 'prod:client')]
    assert evts[0]['details']['code'] == 'DRTB'
    assert evts[0]['compte'] == 'regix' and evts[0]['poste'] == 'pc-inconnu'


def test_deviner_colonnes_agr_lds():
    cols = ['alds_id', 'alds_user', 'alds_open', 'alds_close', 'alds_prog', 'alds_complement', 'alds_tty']
    roles = c.deviner_colonnes(cols, conf(applicatif={}))
    assert roles['date'] == 'alds_open' and roles['fin'] == 'alds_close'
    assert roles['utilisateur'] == 'alds_user' and roles['programme'] == 'alds_prog'
    assert roles['poste'] == 'alds_tty'
    forcees = c.deviner_colonnes(cols, conf(applicatif={'colonne_programme': 'alds_complement'}))
    assert forcees['programme'] == 'alds_complement'


def test_empreinte_stable():
    t = dt.datetime(2026, 9, 1, 8, 0)
    assert c.evenement(t, 'systeme', 'connexion', 'x', compte='a')['empreinte'] == \
        c.evenement(t, 'systeme', 'connexion', 'x', compte='a')['empreinte']


def test_requete_agr_lds(tmp_path, monkeypatch):
    """La requête du DBA (agr_lds, alds_open, exclusion Xp_cron*) est bien celle envoyée à dbaccess."""
    bin_ = tmp_path / 'bin'
    bin_.mkdir()
    journal = tmp_path / 'sql.log'
    faux = bin_ / 'dbaccess'
    faux.write_text('#!/bin/bash\nsql=$(cat); echo "$sql" >> "%s"\n'
                    'f=$(echo "$sql" | sed -n "s/^UNLOAD TO \'\\([^\']*\\)\'.*/\\1/p")\n'
                    'if echo "$sql" | grep -q syscolumns; then printf "alds_id|\\nalds_user|\\nalds_open|\\nalds_complement|\\n" > "$f";\n'
                    'else printf "101|jdupont|2026-09-01 08:12:03|Xp_saisie_dossier|\\n" > "$f"; fi\n' % journal)
    faux.chmod(0o755)
    cfg = conf(informix={'informixdir': str(tmp_path)},
               applicatif={'base': 'prod', 'table': 'agr_lds', 'compte_base': 'regix', 'colonne_date': 'alds_open',
                           'filtre': "(alds_complement IS NULL OR alds_complement NOT MATCHES 'Xp_cron*')"})
    evts = c.collecter_applicatif(cfg, dt.datetime(2026, 9, 1))
    sql = journal.read_text().splitlines()[-1]
    assert "FROM agr_lds WHERE alds_open >= '2026-09-01 00:00:00'" in sql
    assert "AND (alds_complement IS NULL OR alds_complement NOT MATCHES 'Xp_cron*') ORDER BY alds_open" in sql
    assert [(e['utilisateur'], e['compte'], e['objet']) for e in evts] == [('jdupont', 'regix', 'Xp_saisie_dossier')]
