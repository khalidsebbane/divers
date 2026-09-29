# Rapport des connexions utilisateurs (par adresse IP)

> **Deux versions :**
> - **Linux / Red Hat** : [`linux/rapport_connexions.py`](linux/) (journaux wtmp / btmp / secure), voir [`linux/README.md`](linux/README.md)
> - **Windows Server** : `Get-RapportConnexions.ps1` (journal de sécurité), décrit ci-dessous

Script PowerShell qui extrait du **journal de sécurité Windows** la **date et l'heure de connexion**
des utilisateurs sur un serveur, et produit un **rapport HTML professionnel classé par adresse IP**,
avec exports CSV pour Excel.

Cas d'usage d'origine : extraire les connexions de **tous les utilisateurs** du serveur pendant le
**mois de septembre** (demande des sociétés SDI et SDIA).

## Contenu du rapport

| Section | Contenu |
|---|---|
| Indicateurs | Connexions réussies, utilisateurs distincts, IP distinctes, tentatives échouées |
| Synthèse par adresse IP | IP, nom du poste, nb de connexions, échecs, utilisateurs, 1re / dernière connexion |
| Synthèse par utilisateur | Nb de connexions, jours de présence, IP utilisées, 1re / dernière connexion |
| Détail par IP | Date, heure, utilisateur, poste, type (RDP, console...), résultat, déconnexion, durée |

Le rapport HTML est autonome (un seul fichier, à envoyer par mail), avec tri par colonne,
filtre de recherche et mise en page adaptée à l'impression / PDF.
Voir l'exemple : [`exemple/Exemple_rapport_connexions.html`](exemple/Exemple_rapport_connexions.html) (données fictives).

Fichiers générés dans `Rapports\` :

- `Connexions_<serveur>_<période>_<horodatage>.html` — rapport
- `..._detail.csv` — toutes les connexions (séparateur `;`, s'ouvre directement dans Excel)
- `..._synthese_IP.csv` — synthèse par adresse IP

## Utilisation

Sur le serveur, ouvrir PowerShell **en tant qu'administrateur** (nécessaire pour lire le journal de sécurité) :

```powershell
# Connexions de tous les utilisateurs en septembre 2026, avec les échecs, puis ouverture du rapport
.\Get-RapportConnexions.ps1 -Mois 2026-09 -InclureEchecs -Ouvrir
```

Ou double-cliquer / lancer en admin : `Lancer-Rapport.bat 2026-09`

### Autres exemples

```powershell
# Limiter aux membres de groupes AD ou locaux
.\Get-RapportConnexions.ps1 -Mois 2026-09 -Groupes 'Utilisateurs du Bureau à distance'

# Limiter à certains comptes
.\Get-RapportConnexions.ps1 -Mois 2026-09 -Utilisateurs 'adm*','jdupont'

# Période libre
.\Get-RapportConnexions.ps1 -Debut '2026-09-15' -Fin '2026-09-20'

# Plusieurs serveurs à distance
.\Get-RapportConnexions.ps1 -Mois 2026-09 -Serveurs SRV-APP01,SRV-APP02

# Journaux archivés (.evtx) si le journal en ligne ne remonte pas jusqu'au début du mois
.\Get-RapportConnexions.ps1 -Mois 2026-09 -FichiersEvtx 'D:\Archives\Archive-Security-*.evtx'

# Résolution DNS des IP, ajout des déverrouillages de session
.\Get-RapportConnexions.ps1 -Mois 2026-09 -ResoudreDNS -TypesConnexion 2,7,10,11

# Aperçu du rendu avec des données fictives (fonctionne sur n'importe quel poste)
.\Get-RapportConnexions.ps1 -Demo -Mois 2026-09 -InclureEchecs -Ouvrir
```

### Paramètres

| Paramètre | Défaut | Description |
|---|---|---|
| `-Mois` | — | Mois `AAAA-MM` (prioritaire sur `-Debut`/`-Fin`) |
| `-Debut` / `-Fin` | mois en cours | Période libre (fin exclue) |
| `-Utilisateurs` | `*` (tous) | Limiter à certains comptes, jokers acceptés |
| `-Groupes` | — | Groupes AD ou locaux dont les membres sont inclus |
| `-TypesConnexion` | `2,10,11` | 2 = console, 10 = Bureau à distance (RDP), 11 = cache, 7 = déverrouillage, 3 = réseau |
| `-InclureEchecs` | non | Ajoute les échecs (4625) avec le motif (mot de passe incorrect, compte verrouillé...) |
| `-Serveurs` | serveur local | Serveurs distants à interroger |
| `-FichiersEvtx` | — | Analyse de fichiers `.evtx` exportés/archivés |
| `-ResoudreDNS` | non | Ajoute le nom DNS des IP |
| `-DossierSortie` | `.\Rapports` | Dossier des fichiers générés |
| `-Ouvrir` | non | Ouvre le rapport HTML à la fin |
| `-Demo` | non | Données fictives pour prévisualiser |

## Prérequis / points d'attention

- **Windows PowerShell 5.1** (natif sur Windows Server 2016+) ou PowerShell 7, lancé **en administrateur**.
- **Audit des ouvertures de session activé** (sinon aucun événement 4624) :
  `auditpol /get /subcategory:"Ouverture de session"` (ou `"Logon"` sur un système anglais) doit indiquer *Succès et échec*.
  Sinon : GPO *Configuration ordinateur > Stratégies > Paramètres Windows > Paramètres de sécurité >
  Configuration avancée de la stratégie d'audit > Ouverture/Fermeture de session*.
- **Rétention du journal** : le journal Sécurité est circulaire (20 Mo par défaut). Vérifier la date du plus
  ancien événement ; s'il ne couvre pas tout le mois, utiliser les archives `.evtx` (`-FichiersEvtx`) et
  augmenter la taille du journal pour les prochaines fois :
  `wevtutil sl Security /ms:1073741824` (1 Go).
- **Heure de déconnexion / durée** : issues des événements 4634/4647. Elles restent vides si la session
  n'est pas fermée sur la période, ou si la fermeture n'a pas été journalisée (déconnexion RDP sans fermeture de session).
- **Adresse IP** : pour une connexion RDP, c'est l'IP du poste client. `Local (console)` = ouverture de
  session directement sur le serveur (console / VM).
- Ces informations concernent l'**ouverture de session Windows sur le serveur**. Si l'application
  utilisée (ex. « IE ») a sa propre authentification, ses connexions internes sont dans ses propres journaux /
  sa base de données, pas dans le journal Windows.

## Événements Windows utilisés

| ID | Signification |
|---|---|
| 4624 | Ouverture de session réussie |
| 4625 | Échec d'ouverture de session |
| 4634 | Fermeture de session |
| 4647 | Déconnexion initiée par l'utilisateur |
