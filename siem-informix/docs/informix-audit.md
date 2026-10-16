# Activer l'audit Informix (volet base)

Le volet base s'appuie sur deux sources :

1. **Les sessions** (`sysmaster:syssessions`). Elles sont toujours disponibles, sans configuration : utilisateur base,
   machine cliente, heure de connexion. Le collecteur les lit à chaque passe, ce qui donne les ouvertures et fins de session.
2. **L'audit Informix** (`onaudit`). Il est à activer pour tracer les opérations : création ou suppression d'objets, droits,
   modifications de données sur les tables sensibles.

> Les commandes ci-dessous sont à exécuter **par le DBA**, en compte informix, après validation.
> L'audit a un coût en performances et en disque : commencer par les opérations d'administration,
> puis ajouter les tables sensibles une par une.

## 1. Configuration (fichier `adtcfg` dans `$INFORMIXDIR/aaodir`)

```text
ADTMODE  1                    # audit actif, fichiers gérés par Informix
ADTPATH  /informix/audit      # dossier des fichiers d'audit (prévoir de la place)
ADTSIZE  50000000             # taille d'un fichier avant bascule
ADTERR   0                    # en cas d'erreur d'écriture : continuer (1 = bloquer le moteur)
```
Activer ensuite : `onaudit -l 1` (puis `onaudit -c` pour vérifier la configuration).

## 2. Masques d'audit : ce qu'on trace pour qui

Exemple de masque appliqué à tous les utilisateurs (`_default`) : administration, objets et droits.

```bash
onaudit -a -u _default -e +CRDB,DRDB,CRTB,DRTB,ALTB,RNTB,CRVW,DRVW,CRIX,DRIX,CRSP,DRSP,GRDB,RVDB,GRTB,RVTB,CRRL,DRRL,GRRL,RVRL,ONMO,ONSP,ONPA,ONTP,ONBR,ONAU
```

Pour le compte partagé : ajouter les **suppressions et modifications de lignes** (attention au volume) :

```bash
onaudit -a -u regix -e +DLRW,UPRW
onaudit -o -u _default        # afficher les masques
```

Liste complète des codes : documentation IBM / HCL Informix, « Audit event mnemonics ».
Les codes connus du portail (libellés en français) sont dans `CODES_AUDIT`, dans `collecteur/collecteur.py`. Les autres codes sont
affichés tels quels.

## 3. Lecture par le collecteur

Dans `collecteur.ini` :

```ini
[informix]
commande_onshowaudit = onshowaudit -n ol_prod
```

Le collecteur ne garde que les enregistrements postérieurs à sa dernière passe. Le portail ignore les doublons.

### Valider le format sur votre version

Lancer `onshowaudit -n ol_prod | head -5` et comparer avec le format attendu (champs séparés par `|`) :

```text
ONLN|2026-09-03 22:58:10.000|pc-inconnu|4242|ol_prod|regix|0|DRTB|prod|reglement_hist|
 0    1 date heure            2 machine  3 pid 4 serveur 5 util. 6 err. 7 code 8... objet
```

Si les positions diffèrent, ajuster `audit_champ_date`, `audit_champ_machine`, `audit_champ_pid`,
`audit_champ_utilisateur`, `audit_champ_erreur`, `audit_champ_code` et `audit_champ_objet` dans `collecteur.ini`, puis vérifier avec :

```bash
/usr/libexec/platform-python collecteur.py -c collecteur.ini --test
```

## 4. Table applicative `agr_lds` (volet applicatif)

Requête de départ fournie par le DBA :

```sql
SELECT * FROM agr_lds WHERE alds_open > "2026-09-01 00:00:00"
AND (alds_complement IS NULL OR alds_complement NOT MATCHES "Xp_cron*") ORDER BY 1
```

Le collecteur :
- lit la liste des colonnes dans `syscolumns` ;
- repère la date (`alds_open`), la fin, l'utilisateur, le programme et le poste d'après le nom des colonnes ;
- applique le filtre `Xp_cron*` et ne lit que les nouvelles lignes ;
- garde toutes les autres colonnes dans le détail de l'événement.

Si la détection se trompe, forcer les colonnes dans `[applicatif]` (`colonne_utilisateur = ...`). La structure exacte
s'obtient avec `dbschema -d <base> -t agr_lds`.
