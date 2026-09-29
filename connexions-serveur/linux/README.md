# Rapport des connexions utilisateurs par adresse IP (Linux / Red Hat)

Version **Red Hat / CentOS / Rocky / Alma** du rapport. Elle extrait la **date et l'heure de connexion**
(et de déconnexion) des utilisateurs sur le serveur, et produit un **rapport HTML classé par adresse IP**
ainsi que des exports CSV pour Excel.

Exemple de rendu (données fictives) : [`exemple/Exemple_rapport_connexions_linux.html`](exemple/Exemple_rapport_connexions_linux.html)

## Utilisation rapide : utilisateurs SDI et SDIA, septembre 2026

```bash
# copier le script sur le serveur (ex. /opt/scripts), puis :
sudo python3 rapport_connexions.py --mois 2026-09 --echecs --secure
```

Fichiers générés dans `Rapports/` à côté du script :

- `Connexions_<serveur>_2026-09_<horodatage>.html` : rapport à ouvrir dans un navigateur ou à envoyer par mail
- `..._detail.csv` : toutes les connexions (date, heure, utilisateur, IP, déconnexion, durée), s'ouvre dans Excel
- `..._synthese_IP.csv` : synthèse par adresse IP

Pour récupérer les fichiers sur un poste Windows : WinSCP, ou `scp user@serveur:/opt/scripts/Rapports/* .`

## D'où viennent les informations

| Source | Contenu | Option |
|---|---|---|
| `/var/log/wtmp*` | Ouvertures et fermetures de session SSH et console, IP, durée | toujours |
| `/var/log/btmp*` | Tentatives de connexion échouées | `--echecs` |
| `/var/log/secure*` | Connexions SSH **sans terminal** (sftp, scp, WinSCP...), méthode d'authentification, motif des échecs | `--secure` |

## Options

| Option | Défaut | Description |
|---|---|---|
| `--mois AAAA-MM` | — | Mois complet à analyser |
| `--debut` / `--fin` `AAAA-MM-JJ` | mois en cours | Période libre (fin exclue) |
| `-u, --utilisateurs` | `sdi*,sdia*` | Comptes (jokers, insensible à la casse). `'*'` = tous |
| `-g, --groupes` | — | Groupes Linux dont les membres sont inclus, ex. `-g sdi,sdia` |
| `--echecs` | non | Ajoute les tentatives échouées |
| `--secure` | non | Lit aussi `/var/log/secure*` (sftp/scp et motifs des échecs) |
| `--wtmp`, `--btmp`, `--secure-fichiers` | `/var/log/...*` | Fichiers à lire (ex. copies d'un autre serveur) |
| `--resoudre-dns` | non | Ajoute le nom DNS des IP |
| `-o, --sortie` | `./Rapports` | Dossier de sortie |
| `--demo` | non | Données fictives |

### Exemples

```bash
sudo python3 rapport_connexions.py --mois 2026-09                        # SDI* / SDIA*, sessions uniquement
sudo python3 rapport_connexions.py --mois 2026-09 -g sdi,sdia --echecs   # par groupes Linux
sudo python3 rapport_connexions.py --debut 2026-09-15 --fin 2026-09-20 -u 'sdi01,sdia*'
sudo python3 rapport_connexions.py --mois 2026-09 -u '*' --resoudre-dns   # tous les comptes

# Analyser les journaux d'un autre serveur copiés en local
python3 rapport_connexions.py --mois 2026-09 --wtmp ./srv2/wtmp* --btmp ./srv2/btmp* --echecs
```

## Prérequis / points d'attention

- **Python 3.6+** : présent par défaut sur RHEL 8/9 (`python3`, sinon `/usr/libexec/platform-python`).
  Sur RHEL 7 : `sudo yum install python3`. Aucune bibliothèque externe n'est nécessaire.
- **Lancer avec `sudo`** : `btmp` et `secure` ne sont lisibles que par root.
- **Rotation des journaux** : `wtmp` et `btmp` sont archivés **tous les mois** par logrotate
  (`/var/log/wtmp-20261001`, etc.) et `secure` **chaque semaine** (4 semaines conservées par défaut).
  Le script lit automatiquement les fichiers archivés, y compris `.gz`. Vérifier que septembre est
  encore couvert : `ls -l /var/log/wtmp* /var/log/secure*`.
- **Déconnexion / durée** : vides si la session est encore ouverte, ou si le serveur a redémarré pendant
  la session (motif « Session interrompue »).
- **sftp / scp / WinSCP** n'apparaissent pas dans `wtmp`. Il faut `--secure` pour les voir (sans heure de fin).
- `Local (console)` : connexion directe sur la console du serveur (ou console de la VM).
- Ce rapport couvre les **connexions au système Linux** (SSH et console). Si l'application « IE » a sa propre
  authentification (application web, base de données), ses connexions sont dans les journaux de
  l'application, pas dans ces fichiers.
