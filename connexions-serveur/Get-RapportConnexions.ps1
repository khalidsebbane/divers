<#
.SYNOPSIS
    Rapport des connexions utilisateurs sur un serveur Windows, classé par adresse IP.

.DESCRIPTION
    Lit le journal de sécurité Windows (événements 4624 / 4625 / 4634 / 4647) et produit :
      - un rapport HTML professionnel (synthèse par IP, synthèse par utilisateur, détail par IP)
      - un export CSV du détail (séparateur « ; », ouvrable directement dans Excel)
      - un export CSV de la synthèse par IP

    Pour chaque connexion : date, heure, utilisateur, adresse IP, poste, type de connexion,
    heure de déconnexion et durée de session (quand l'événement de fermeture existe).

.PARAMETER Mois
    Mois à analyser au format AAAA-MM (ex. 2026-09). Prioritaire sur -Debut / -Fin.

.PARAMETER Debut
    Date de début (incluse). Par défaut : 1er jour du mois courant.

.PARAMETER Fin
    Date de fin (exclue). Par défaut : maintenant.

.PARAMETER Utilisateurs
    Comptes à inclure (jokers acceptés). Par défaut : '*' = tous les utilisateurs.

.PARAMETER Groupes
    Groupes (AD ou locaux) dont les membres sont inclus, ex. -Groupes "Utilisateurs du Bureau à distance".

.PARAMETER TypesConnexion
    Types d'ouverture de session retenus. Par défaut : 2 (console), 10 (Bureau à distance / RDP),
    11 (identifiants en cache). Ajouter 7 (déverrouillage) ou 3 (réseau : partages, IIS...) si besoin.

.PARAMETER InclureEchecs
    Ajoute les tentatives de connexion échouées (4625) avec le motif de l'échec.

.PARAMETER Serveurs
    Serveurs à interroger à distance (droits admin + règle pare-feu « Gestion à distance du journal des événements »).
    Par défaut : le serveur local.

.PARAMETER FichiersEvtx
    Analyse des fichiers .evtx archivés/exportés au lieu du journal en direct.

.PARAMETER ResoudreDNS
    Résout le nom DNS de chaque adresse IP.

.PARAMETER DossierSortie
    Dossier des rapports. Par défaut : .\Rapports à côté du script.

.PARAMETER Ouvrir
    Ouvre le rapport HTML à la fin.

.PARAMETER Demo
    Génère un rapport avec des données fictives (pour visualiser le rendu).

.EXAMPLE
    .\Get-RapportConnexions.ps1 -Mois 2026-09
    Connexions de tous les utilisateurs sur le serveur local en septembre 2026.

.EXAMPLE
    .\Get-RapportConnexions.ps1 -Mois 2026-09 -Groupes 'Utilisateurs du Bureau à distance' -InclureEchecs -ResoudreDNS -Ouvrir

.EXAMPLE
    .\Get-RapportConnexions.ps1 -Mois 2026-09 -Serveurs SRV-IE01,SRV-IE02

.EXAMPLE
    .\Get-RapportConnexions.ps1 -FichiersEvtx D:\Archives\Security-*.evtx -Mois 2026-09
#>
[CmdletBinding()]
param(
    [ValidatePattern('^\d{4}-\d{2}$')]
    [string]$Mois,
    [datetime]$Debut,
    [datetime]$Fin,
    [string[]]$Utilisateurs = @('*'),
    [string[]]$Groupes,
    [int[]]$TypesConnexion = @(2, 10, 11),
    [switch]$InclureEchecs,
    [string[]]$Serveurs = @($env:COMPUTERNAME),
    [string[]]$FichiersEvtx,
    [switch]$ResoudreDNS,
    [string]$DossierSortie,
    [switch]$Ouvrir,
    [switch]$Demo
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# --------------------------------------------------------------------------------------------
# Paramètres de période
# --------------------------------------------------------------------------------------------
if ($Mois) {
    $Debut = [datetime]::ParseExact("$Mois-01", 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)
    $Fin   = $Debut.AddMonths(1)
}
if (-not $PSBoundParameters.ContainsKey('Debut') -and -not $Mois) { $Debut = Get-Date -Day 1 -Hour 0 -Minute 0 -Second 0 -Millisecond 0 }
if (-not $PSBoundParameters.ContainsKey('Fin')   -and -not $Mois) { $Fin = Get-Date }
if ($Fin -le $Debut) { throw "La date de fin ($Fin) doit être postérieure à la date de début ($Debut)." }

if (-not $DossierSortie) {
    $base = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    $DossierSortie = Join-Path $base 'Rapports'
}
if (-not (Test-Path $DossierSortie)) { New-Item -ItemType Directory -Path $DossierSortie -Force | Out-Null }

# Si seuls des groupes sont fournis, on ne garde pas le filtre « tous » par défaut
if ($Groupes -and -not $PSBoundParameters.ContainsKey('Utilisateurs')) { $Utilisateurs = @() }

$LibellesTypes = @{
    2 = 'Console (interactive)'; 3 = 'Réseau'; 4 = 'Batch'; 5 = 'Service'; 7 = 'Déverrouillage'
    8 = 'Réseau (texte clair)'; 9 = 'Nouveaux identifiants'; 10 = 'Bureau à distance (RDP)'; 11 = 'Identifiants en cache'
}
$MotifsEchec = @{
    '0XC000006A' = 'Mot de passe incorrect';   '0XC0000064' = 'Utilisateur inconnu'
    '0XC0000234' = 'Compte verrouillé';        '0XC0000072' = 'Compte désactivé'
    '0XC000006F' = 'Hors plage horaire';       '0XC0000070' = 'Poste non autorisé'
    '0XC0000071' = 'Mot de passe expiré';      '0XC0000193' = 'Compte expiré'
    '0XC0000224' = 'Changement de mot de passe requis'
    '0XC000015B' = 'Type de connexion non autorisé'; '0XC000006D' = 'Nom ou mot de passe incorrect'
    '0XC0000133' = 'Horloge désynchronisée';   '0XC000006E' = 'Restriction de compte'
}

# --------------------------------------------------------------------------------------------
# Fonctions utilitaires
# --------------------------------------------------------------------------------------------
function Get-MembresGroupes {
    param([string[]]$Noms)
    $membres = New-Object System.Collections.Generic.HashSet[string]([StringComparer]::OrdinalIgnoreCase)
    foreach ($g in $Noms) {
        $ok = $false
        if (Get-Module -ListAvailable -Name ActiveDirectory) {
            try {
                Import-Module ActiveDirectory -ErrorAction Stop
                Get-ADGroupMember -Identity $g -Recursive | Where-Object objectClass -eq 'user' |
                    ForEach-Object { [void]$membres.Add($_.SamAccountName) }
                $ok = $true
            } catch { Write-Verbose "Groupe AD '$g' introuvable : $($_.Exception.Message)" }
        }
        if (-not $ok) {
            try {
                Get-LocalGroupMember -Group $g | ForEach-Object { [void]$membres.Add(($_.Name -split '\\')[-1]) }
                $ok = $true
            } catch { Write-Verbose "Groupe local '$g' introuvable : $($_.Exception.Message)" }
        }
        if (-not $ok) { Write-Warning "Groupe '$g' introuvable (ni dans l'AD, ni en local)." }
    }
    Write-Host ("  {0} membre(s) trouvé(s) dans le(s) groupe(s) {1}" -f $membres.Count, ($Noms -join ', '))
    return ,$membres
}

function Test-Utilisateur {
    param([string]$Nom)
    if ([string]::IsNullOrEmpty($Nom) -or $Nom -eq '-' -or $Nom.EndsWith('$')) { return $false }
    if ($Nom -in @('SYSTEM', 'SYSTÈME', 'ANONYMOUS LOGON', 'LOCAL SERVICE', 'NETWORK SERVICE', 'DWM-1', 'UMFD-0')) { return $false }
    if ($Nom -like 'DWM-*' -or $Nom -like 'UMFD-*') { return $false }
    if ($script:MembresGroupes -and $script:MembresGroupes.Contains($Nom)) { return $true }
    foreach ($p in $Utilisateurs) { if ($Nom -like $p) { return $true } }
    return $false
}

function Get-DonneesEvenement {
    param($Evenement)
    $x = [xml]$Evenement.ToXml()
    $d = @{}
    foreach ($n in $x.Event.EventData.Data) { $d[$n.Name] = [string]$n.'#text' }
    return $d
}

function Format-IP {
    param([string]$Ip)
    if ([string]::IsNullOrWhiteSpace($Ip) -or $Ip -eq '-' -or $Ip -eq '::1' -or $Ip -eq '127.0.0.1') { return 'Local (console)' }
    return ($Ip -replace '^::ffff:', '')
}

function Format-Duree {
    param($Duree)
    if ($null -eq $Duree) { return '' }
    $t = [timespan]$Duree
    if ($t.TotalDays -ge 1) { return ('{0}j {1:00}h{2:00}' -f [int][math]::Floor($t.TotalDays), $t.Hours, $t.Minutes) }
    return ('{0:00}h{1:00}' -f $t.Hours, $t.Minutes)
}

function Get-EvenementsSource {
    param([hashtable]$Filtre, [string]$Ordinateur)
    try {
        if ($Ordinateur -and $Ordinateur -ne $env:COMPUTERNAME -and -not $Filtre.ContainsKey('Path')) {
            return @(Get-WinEvent -FilterHashtable $Filtre -ComputerName $Ordinateur -ErrorAction Stop)
        }
        return @(Get-WinEvent -FilterHashtable $Filtre -ErrorAction Stop)
    } catch {
        if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*' -or $_.Exception.Message -match 'No events were found|Aucun événement') { return @() }
        if ($_.Exception -is [UnauthorizedAccessException] -or $_.Exception.Message -match 'unauthorized|non autoris|refus') {
            throw "Accès refusé au journal de sécurité ($Ordinateur). Lancer PowerShell « En tant qu'administrateur »."
        }
        throw
    }
}

# --------------------------------------------------------------------------------------------
# Collecte
# --------------------------------------------------------------------------------------------
function Get-Connexions {
    $ids = @(4624, 4634, 4647)
    if ($InclureEchecs) { $ids += 4625 }

    $sources = @()
    if ($FichiersEvtx) {
        foreach ($motif in $FichiersEvtx) {
            foreach ($f in (Get-ChildItem -Path $motif -File)) {
                $sources += [pscustomobject]@{ Nom = $f.BaseName; Filtre = @{ Path = $f.FullName; Id = $ids; StartTime = $Debut; EndTime = $Fin }; Ordinateur = $null }
            }
        }
    } else {
        foreach ($s in $Serveurs) {
            $sources += [pscustomobject]@{ Nom = $s; Filtre = @{ LogName = 'Security'; Id = $ids; StartTime = $Debut; EndTime = $Fin }; Ordinateur = $s }
        }
    }

    $resultat  = New-Object System.Collections.Generic.List[object]
    $dejaVus   = New-Object System.Collections.Generic.HashSet[string]
    foreach ($src in $sources) {
        Write-Host "  Lecture du journal : $($src.Nom) ..." -NoNewline
        $evts = Get-EvenementsSource -Filtre $src.Filtre -Ordinateur $src.Ordinateur
        Write-Host " $($evts.Count) événement(s)"

        $ouvertures  = @{}   # LogonId -> objet connexion
        $fermetures  = @{}   # LogonId -> date de fermeture la plus ancienne
        foreach ($e in ($evts | Sort-Object TimeCreated)) {
            $d = Get-DonneesEvenement $e
            $serveur = if ($src.Ordinateur) { $src.Ordinateur } else { $e.MachineName }
            switch ($e.Id) {
                { $_ -in 4634, 4647 } {
                    $id = $d['TargetLogonId']
                    if ($id -and -not $fermetures.ContainsKey($id) -and (Test-Utilisateur $d['TargetUserName'])) { $fermetures[$id] = $e.TimeCreated }
                    continue
                }
                { $_ -in 4624, 4625 } {
                    $type = 0; [void][int]::TryParse($d['LogonType'], [ref]$type)
                    if ($type -notin $TypesConnexion) { continue }
                    if (-not (Test-Utilisateur $d['TargetUserName'])) { continue }

                    $ip = Format-IP $d['IpAddress']
                    $user = if ($d['TargetDomainName'] -and $d['TargetDomainName'] -ne '-') { "$($d['TargetDomainName'])\$($d['TargetUserName'])" } else { $d['TargetUserName'] }
                    # Déduplication (ex. double jeton admin : 2 événements 4624 à la même seconde)
                    $cle = '{0}|{1}|{2}|{3}|{4}|{5:yyyyMMddHHmmss}' -f $serveur, $user, $ip, $type, $e.Id, $e.TimeCreated
                    if (-not $dejaVus.Add($cle)) { continue }

                    $motif = ''
                    if ($e.Id -eq 4625) {
                        $code = if ($d['SubStatus'] -and $d['SubStatus'] -ne '0x0') { $d['SubStatus'] } else { $d['Status'] }
                        $code = ([string]$code).ToUpper()
                        $motif = if ($MotifsEchec.ContainsKey($code)) { $MotifsEchec[$code] } else { "Code $code" }
                    }
                    $poste = $d['WorkstationName']; if ($poste -eq '-') { $poste = '' }
                    $libelle = if ($LibellesTypes.ContainsKey($type)) { $LibellesTypes[$type] } else { "Type $type" }
                    $obj = [pscustomobject]@{
                        Serveur        = $serveur
                        DateHeure      = $e.TimeCreated
                        Utilisateur    = $user
                        IP             = $ip
                        Poste          = $poste
                        TypeConnexion  = $libelle
                        Resultat       = if ($e.Id -eq 4624) { 'Succès' } else { 'Échec' }
                        Motif          = $motif
                        Deconnexion    = $null
                        Duree          = $null
                    }
                    if ($e.Id -eq 4624 -and $d['TargetLogonId']) { $ouvertures[$d['TargetLogonId']] = $obj }
                    $resultat.Add($obj)
                }
            }
        }
        foreach ($id in $ouvertures.Keys) {
            if ($fermetures.ContainsKey($id) -and $fermetures[$id] -ge $ouvertures[$id].DateHeure) {
                $ouvertures[$id].Deconnexion = $fermetures[$id]
                $ouvertures[$id].Duree = $fermetures[$id] - $ouvertures[$id].DateHeure
            }
        }
    }
    return $resultat
}

function Get-ConnexionsDemo {
    $rnd = New-Object System.Random 42
    $users = 'jdupont', 'mmartin', 'kbenali', 'sbernard', 'Administrateur', 'lpetit', 'admin01'
    $ips = [ordered]@{ '10.12.4.21' = 'PC-021'; '10.12.4.35' = 'PC-035'; '10.12.6.110' = 'PC-110'; '10.12.6.118' = 'PC-118'; '192.168.50.14' = 'VPN-014'; 'Local (console)' = '' }
    $cleIps = @($ips.Keys)
    $liste = New-Object System.Collections.Generic.List[object]
    for ($jour = $Debut.Date; $jour -lt $Fin; $jour = $jour.AddDays(1)) {
        if ($jour.DayOfWeek -in 'Saturday', 'Sunday') { continue }
        foreach ($u in $users) {
            if ($rnd.NextDouble() -lt 0.25) { continue }
            $ip = $cleIps[($users.IndexOf($u) + ($rnd.Next(0, 10) -eq 0)) % ($cleIps.Count - 1)]
            if ($rnd.NextDouble() -lt 0.05) { $ip = 'Local (console)' }
            $h = $jour.AddHours(7.5 + $rnd.NextDouble() * 2.5)
            $echec = $InclureEchecs -and $rnd.NextDouble() -lt 0.08
            if ($echec) {
                $liste.Add([pscustomobject]@{ Serveur = 'SRV-DEMO'; DateHeure = $h.AddMinutes(-2); Utilisateur = "DOMAINE\$u"; IP = $ip; Poste = $ips[$ip]; TypeConnexion = $LibellesTypes[10]; Resultat = 'Échec'; Motif = 'Mot de passe incorrect'; Deconnexion = $null; Duree = $null })
            }
            $duree = [timespan]::FromMinutes(180 + $rnd.Next(0, 360))
            $finSession = if ($rnd.NextDouble() -lt 0.1) { $null } else { $h + $duree }
            $liste.Add([pscustomobject]@{ Serveur = 'SRV-DEMO'; DateHeure = $h; Utilisateur = "DOMAINE\$u"; IP = $ip; Poste = $ips[$ip]
                TypeConnexion = if ($ip -eq 'Local (console)') { $LibellesTypes[2] } else { $LibellesTypes[10] }
                Resultat = 'Succès'; Motif = ''; Deconnexion = $finSession; Duree = if ($finSession) { $finSession - $h } else { $null } })
        }
    }
    return $liste
}

# --------------------------------------------------------------------------------------------
# Rapport HTML
# --------------------------------------------------------------------------------------------
function ConvertTo-Html-Texte { param($Valeur) return [System.Net.WebUtility]::HtmlEncode([string]$Valeur) }

function New-RapportHtml {
    param($Connexions, $SyntheseIP, $SyntheseUsers, [string]$Chemin)
    $h = { param($v) ConvertTo-Html-Texte $v }
    $fmtDate = 'dd/MM/yyyy HH:mm:ss'
    $ok = @($Connexions | Where-Object Resultat -eq 'Succès')
    $ko = @($Connexions | Where-Object Resultat -eq 'Échec')
    $sb = New-Object System.Text.StringBuilder

    $titreServeurs = ($Connexions | Select-Object -ExpandProperty Serveur -Unique) -join ', '
    if (-not $titreServeurs) { $titreServeurs = ($Serveurs -join ', ') }
    $filtre = @()
    if ($Utilisateurs -and ($Utilisateurs -join ',') -eq '*') { $filtre += 'Tous les utilisateurs' }
    elseif ($Utilisateurs) { $filtre += ($Utilisateurs -join ', ') }
    if ($Groupes) { $filtre += 'membres de ' + ($Groupes -join ', ') }
    $types = ($TypesConnexion | ForEach-Object { if ($LibellesTypes.ContainsKey($_)) { $LibellesTypes[$_] } else { "Type $_" } }) -join ', '

    [void]$sb.Append(@"
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Rapport des connexions</title>
<style>
:root{--bleu:#1f3a5f;--bleu2:#2d5b8f;--gris:#f4f6f9;--bord:#dde3ea;--texte:#1d2733;--doux:#5f6b7a;--vert:#1e7b4a;--rouge:#b3261e}
*{box-sizing:border-box}
body{margin:0;font-family:"Segoe UI",Calibri,Arial,sans-serif;color:var(--texte);background:var(--gris);font-size:14px}
header{background:linear-gradient(135deg,var(--bleu),var(--bleu2));color:#fff;padding:28px 40px}
header h1{margin:0 0 6px;font-size:24px;font-weight:600}
header .meta{display:flex;flex-wrap:wrap;gap:8px 28px;font-size:13px;opacity:.92}
header .meta b{font-weight:600}
main{max-width:1280px;margin:0 auto;padding:24px 40px 48px}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px;margin-bottom:28px}
.kpi{background:#fff;border:1px solid var(--bord);border-left:4px solid var(--bleu2);border-radius:8px;padding:16px 20px}
.kpi .v{font-size:28px;font-weight:700;color:var(--bleu)}
.kpi .l{color:var(--doux);font-size:12px;text-transform:uppercase;letter-spacing:.04em}
.kpi.ko{border-left-color:var(--rouge)} .kpi.ko .v{color:var(--rouge)}
section{background:#fff;border:1px solid var(--bord);border-radius:8px;padding:20px 24px;margin-bottom:24px}
h2{margin:0 0 14px;font-size:17px;color:var(--bleu);display:flex;align-items:center;gap:10px}
h2 .n{background:var(--gris);color:var(--doux);font-size:12px;border-radius:10px;padding:2px 9px;font-weight:500}
table{width:100%;border-collapse:collapse;font-size:13px}
th{background:var(--bleu);color:#fff;text-align:left;padding:9px 10px;font-weight:600;cursor:pointer;user-select:none;white-space:nowrap;position:sticky;top:0}
th:after{content:" \2195";opacity:.4;font-size:11px}
th.asc:after{content:" \25B2";opacity:1} th.desc:after{content:" \25BC";opacity:1}
td{padding:7px 10px;border-bottom:1px solid var(--bord);vertical-align:top}
tbody tr:nth-child(even){background:#fafbfd}
tbody tr:hover{background:#eaf1fb}
td.num{text-align:right;font-variant-numeric:tabular-nums}
.ip{white-space:nowrap;font-family:Consolas,"Courier New",monospace;font-weight:600;color:var(--bleu)}
.badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:600}
.ok{background:#e3f4ea;color:var(--vert)} .err{background:#fbe6e4;color:var(--rouge)}
.muted{color:var(--doux)}
.outils{display:flex;gap:12px;align-items:center;margin-bottom:14px;flex-wrap:wrap}
.outils input{flex:1;min-width:240px;padding:9px 12px;border:1px solid var(--bord);border-radius:6px;font-size:14px}
.outils button{padding:8px 14px;border:1px solid var(--bord);background:#fff;border-radius:6px;cursor:pointer}
details{border:1px solid var(--bord);border-radius:6px;margin-bottom:10px;overflow:hidden}
summary{padding:10px 14px;background:#f7f9fc;cursor:pointer;display:flex;gap:18px;flex-wrap:wrap;align-items:center}
summary .ip{font-size:15px;min-width:150px}
summary .info{color:var(--doux);font-size:13px}
details table{border-top:1px solid var(--bord)}
footer{text-align:center;color:var(--doux);font-size:12px;padding:16px}
@media print{body{background:#fff}header{-webkit-print-color-adjust:exact;print-color-adjust:exact}.outils{display:none}section,.kpi{break-inside:avoid;border-color:#ccc}details{break-inside:avoid}th{position:static}}
</style>
</head>
<body>
<header>
  <h1>Rapport des connexions utilisateurs</h1>
  <div class="meta">
    <span><b>Serveur(s) :</b> $(& $h $titreServeurs)</span>
    <span><b>Période :</b> du $($Debut.ToString('dd/MM/yyyy HH:mm')) au $($Fin.ToString('dd/MM/yyyy HH:mm'))</span>
    <span><b>Comptes :</b> $(& $h ($filtre -join ' + '))</span>
    <span><b>Types :</b> $(& $h $types)</span>
    <span><b>Généré le :</b> $((Get-Date).ToString('dd/MM/yyyy à HH:mm'))</span>
  </div>
</header>
<main>
<div class="kpis">
  <div class="kpi"><div class="v">$($ok.Count)</div><div class="l">Connexions réussies</div></div>
  <div class="kpi"><div class="v">$(@($ok | Select-Object -ExpandProperty Utilisateur -Unique).Count)</div><div class="l">Utilisateurs distincts</div></div>
  <div class="kpi"><div class="v">$(@($SyntheseIP).Count)</div><div class="l">Adresses IP distinctes</div></div>
"@)
    if ($InclureEchecs) { [void]$sb.Append("  <div class=`"kpi ko`"><div class=`"v`">$($ko.Count)</div><div class=`"l`">Tentatives échouées</div></div>`n") }
    [void]$sb.Append("</div>`n")

    # --- Synthèse par IP
    [void]$sb.Append("<section><h2>Synthèse par adresse IP <span class=`"n`">$(@($SyntheseIP).Count)</span></h2>`n<table class=`"tri`"><thead><tr><th>Adresse IP</th><th>Nom / poste</th><th>Connexions</th>")
    if ($InclureEchecs) { [void]$sb.Append('<th>Échecs</th>') }
    [void]$sb.Append("<th>Utilisateurs</th><th>Première connexion</th><th>Dernière connexion</th></tr></thead><tbody>`n")
    foreach ($s in $SyntheseIP) {
        [void]$sb.Append("<tr><td class=`"ip`" data-v=`"$(& $h $s.CleTri)`">$(& $h $s.IP)</td><td>$(& $h $s.Nom)</td><td class=`"num`">$($s.Connexions)</td>")
        if ($InclureEchecs) { [void]$sb.Append("<td class=`"num`">$($s.Echecs)</td>") }
        [void]$sb.Append("<td>$(& $h $s.Utilisateurs)</td><td data-v=`"$($s.Premiere.ToString('s'))`">$($s.Premiere.ToString($fmtDate))</td><td data-v=`"$($s.Derniere.ToString('s'))`">$($s.Derniere.ToString($fmtDate))</td></tr>`n")
    }
    [void]$sb.Append("</tbody></table></section>`n")

    # --- Synthèse par utilisateur
    [void]$sb.Append("<section><h2>Synthèse par utilisateur <span class=`"n`">$(@($SyntheseUsers).Count)</span></h2>`n<table class=`"tri`"><thead><tr><th>Utilisateur</th><th>Connexions</th><th>Jours de présence</th><th>Adresses IP</th><th>Première connexion</th><th>Dernière connexion</th></tr></thead><tbody>`n")
    foreach ($s in $SyntheseUsers) {
        [void]$sb.Append("<tr><td><b>$(& $h $s.Utilisateur)</b></td><td class=`"num`">$($s.Connexions)</td><td class=`"num`">$($s.Jours)</td><td class=`"ip`">$(& $h $s.IPs)</td><td data-v=`"$($s.Premiere.ToString('s'))`">$($s.Premiere.ToString($fmtDate))</td><td data-v=`"$($s.Derniere.ToString('s'))`">$($s.Derniere.ToString($fmtDate))</td></tr>`n")
    }
    [void]$sb.Append("</tbody></table></section>`n")

    # --- Détail par IP
    [void]$sb.Append(@"
<section><h2>Détail des connexions par adresse IP <span class="n">$(@($Connexions).Count) ligne(s)</span></h2>
<div class="outils"><input id="recherche" type="search" placeholder="Filtrer : utilisateur, IP, date (ex. 15/09), poste..."><button onclick="basculer(true)">Tout déplier</button><button onclick="basculer(false)">Tout replier</button></div>
<div id="detail">
"@)
    $groupes = $Connexions | Group-Object IP
    foreach ($s in $SyntheseIP) {
        $lignes = ($groupes | Where-Object Name -eq $s.IP).Group | Sort-Object DateHeure
        $nom = if ($s.Nom) { " &middot; $(& $h $s.Nom)" } else { '' }
        [void]$sb.Append("<details open><summary><span class=`"ip`">$(& $h $s.IP)</span><span class=`"info`">$($s.Connexions) connexion(s)$nom &middot; $(& $h $s.Utilisateurs)</span></summary>`n")
        [void]$sb.Append('<table class="tri"><thead><tr><th>Date</th><th>Heure</th><th>Utilisateur</th><th>Poste</th><th>Type</th><th>Résultat</th><th>Déconnexion</th><th>Durée</th></tr></thead><tbody>')
        foreach ($c in $lignes) {
            $res = if ($c.Resultat -eq 'Succès') { '<span class="badge ok">Succès</span>' } else { "<span class=`"badge err`" title=`"$(& $h $c.Motif)`">Échec</span> <span class=`"muted`">$(& $h $c.Motif)</span>" }
            $deco = if ($c.Deconnexion) { $c.Deconnexion.ToString('dd/MM HH:mm') } elseif ($c.Resultat -eq 'Succès') { '<span class="muted">—</span>' } else { '' }
            $dureeTri = if ($c.Duree) { [int]$c.Duree.TotalSeconds } else { -1 }
            [void]$sb.Append("<tr><td data-v=`"$($c.DateHeure.ToString('s'))`">$($c.DateHeure.ToString('dd/MM/yyyy'))</td><td>$($c.DateHeure.ToString('HH:mm:ss'))</td><td>$(& $h $c.Utilisateur)</td><td>$(& $h $c.Poste)</td><td>$(& $h $c.TypeConnexion)</td><td>$res</td><td>$deco</td><td class=`"num`" data-v=`"$dureeTri`">$(Format-Duree $c.Duree)</td></tr>`n")
        }
        [void]$sb.Append("</tbody></table></details>`n")
    }
    if (-not $SyntheseIP) { [void]$sb.Append('<p class="muted">Aucune connexion trouvée sur la période pour les comptes demandés.</p>') }

    [void]$sb.Append(@'
</div></section>
</main>
<footer>Source : journal de sécurité Windows (événements 4624 / 4625 / 4634 / 4647) &middot; Get-RapportConnexions.ps1</footer>
<script>
document.querySelectorAll('table.tri').forEach(function(t){
  t.querySelectorAll('th').forEach(function(th,i){
    th.addEventListener('click',function(){
      var asc=!th.classList.contains('asc');
      t.querySelectorAll('th').forEach(function(x){x.classList.remove('asc','desc')});
      th.classList.add(asc?'asc':'desc');
      var tb=t.tBodies[0],rows=Array.prototype.slice.call(tb.rows);
      function val(r){var c=r.cells[i];if(!c)return '';var v=c.getAttribute('data-v');return v!==null?v:c.textContent.trim()}
      rows.sort(function(a,b){var x=val(a),y=val(b),nx=parseFloat(x),ny=parseFloat(y);
        var r=(!isNaN(nx)&&!isNaN(ny)&&String(nx)===x&&String(ny)===y)?nx-ny:x.localeCompare(y,'fr',{numeric:true});
        return asc?r:-r});
      rows.forEach(function(r){tb.appendChild(r)});
    });
  });
});
function basculer(o){document.querySelectorAll('#detail details').forEach(function(d){d.open=o})}
document.getElementById('recherche').addEventListener('input',function(){
  var q=this.value.toLowerCase();
  document.querySelectorAll('#detail details').forEach(function(d){
    var ipMatch=d.querySelector('summary').textContent.toLowerCase().indexOf(q)>=0,vis=0;
    d.querySelectorAll('tbody tr').forEach(function(r){var m=!q||ipMatch||r.textContent.toLowerCase().indexOf(q)>=0;r.style.display=m?'':'none';if(m)vis++});
    d.style.display=vis?'':'none'; if(q&&vis)d.open=true;
  });
});
</script>
</body>
</html>
'@)
    [System.IO.File]::WriteAllText($Chemin, $sb.ToString(), (New-Object System.Text.UTF8Encoding $true))
}

# --------------------------------------------------------------------------------------------
# Programme principal
# --------------------------------------------------------------------------------------------
Write-Host ''
Write-Host '=== Rapport des connexions utilisateurs ===' -ForegroundColor Cyan
Write-Host ("  Période  : {0:dd/MM/yyyy HH:mm} -> {1:dd/MM/yyyy HH:mm}" -f $Debut, $Fin)
Write-Host ("  Comptes  : {0}" -f ((@($Utilisateurs) + @($Groupes | Where-Object { $_ } | ForEach-Object { "groupe:$_" })) -join ', '))

$script:MembresGroupes = $null
if ($Demo) {
    Write-Host '  Mode démo : données fictives' -ForegroundColor Yellow
    $Serveurs = @('SRV-DEMO')
    $connexions = Get-ConnexionsDemo
} else {
    if ($Groupes) { $script:MembresGroupes = Get-MembresGroupes -Noms $Groupes }
    $connexions = Get-Connexions
}
$connexions = @($connexions | Sort-Object IP, DateHeure)
Write-Host "  $($connexions.Count) connexion(s) retenue(s)" -ForegroundColor Green

# Synthèse par IP
$dns = @{}
$syntheseIP = foreach ($g in ($connexions | Group-Object IP)) {
    $ok = @($g.Group | Where-Object Resultat -eq 'Succès')
    $nom = (@($g.Group | Where-Object Poste | Select-Object -ExpandProperty Poste -Unique) -join ', ')
    if ($ResoudreDNS -and $g.Name -ne 'Local (console)') {
        try { $dns[$g.Name] = [System.Net.Dns]::GetHostEntry($g.Name).HostName } catch { $dns[$g.Name] = '' }
        if ($dns[$g.Name]) { $nom = if ($nom) { "$($dns[$g.Name]) ($nom)" } else { $dns[$g.Name] } }
    }
    # Clé de tri numérique pour les IPv4 (10.0.0.9 avant 10.0.0.10)
    $cle = if ($g.Name -match '^\d+\.\d+\.\d+\.\d+$') { ($g.Name.Split('.') | ForEach-Object { '{0:000}' -f [int]$_ }) -join '.' } else { "zzz$($g.Name)" }
    [pscustomobject]@{
        IP           = $g.Name
        CleTri       = $cle
        Nom          = $nom
        Connexions   = $ok.Count
        Echecs       = @($g.Group | Where-Object Resultat -eq 'Échec').Count
        Utilisateurs = (@($g.Group | Select-Object -ExpandProperty Utilisateur -Unique | Sort-Object) -join ', ')
        Premiere     = ($g.Group | Measure-Object DateHeure -Minimum).Minimum
        Derniere     = ($g.Group | Measure-Object DateHeure -Maximum).Maximum
    }
}
$syntheseIP = @($syntheseIP | Sort-Object @{ Expression = 'Connexions'; Descending = $true }, CleTri)

# Synthèse par utilisateur (connexions réussies)
$syntheseUsers = @(foreach ($g in ($connexions | Where-Object Resultat -eq 'Succès' | Group-Object Utilisateur)) {
    [pscustomobject]@{
        Utilisateur = $g.Name
        Connexions  = $g.Count
        Jours       = @($g.Group | ForEach-Object { $_.DateHeure.Date } | Select-Object -Unique).Count
        IPs         = (@($g.Group | Select-Object -ExpandProperty IP -Unique | Sort-Object) -join ', ')
        Premiere    = ($g.Group | Measure-Object DateHeure -Minimum).Minimum
        Derniere    = ($g.Group | Measure-Object DateHeure -Maximum).Maximum
    }
}) | Sort-Object Utilisateur

# Exports
$suffixe = if ($Mois) { $Mois } else { '{0:yyyyMMdd}-{1:yyyyMMdd}' -f $Debut, $Fin }
$nomServeur = (($Serveurs | Select-Object -First 1) -replace '[^\w\-]', '_')
if ($FichiersEvtx) { $nomServeur = 'evtx' }
$base = Join-Path $DossierSortie ("Connexions_{0}_{1}_{2:yyyyMMdd-HHmmss}" -f $nomServeur, $suffixe, (Get-Date))

$connexions | Select-Object Serveur,
    @{ n = 'Adresse IP'; e = { $_.IP } },
    @{ n = 'Date'; e = { $_.DateHeure.ToString('dd/MM/yyyy') } },
    @{ n = 'Heure'; e = { $_.DateHeure.ToString('HH:mm:ss') } },
    Utilisateur, Poste,
    @{ n = 'Type de connexion'; e = { $_.TypeConnexion } },
    @{ n = 'Résultat'; e = { $_.Resultat } }, Motif,
    @{ n = 'Déconnexion'; e = { if ($_.Deconnexion) { $_.Deconnexion.ToString('dd/MM/yyyy HH:mm:ss') } } },
    @{ n = 'Durée'; e = { Format-Duree $_.Duree } } |
    Export-Csv -Path "$base`_detail.csv" -Delimiter ';' -NoTypeInformation -Encoding UTF8

$syntheseIP | Select-Object @{ n = 'Adresse IP'; e = { $_.IP } }, @{ n = 'Nom / poste'; e = { $_.Nom } }, Connexions,
    @{ n = 'Échecs'; e = { $_.Echecs } }, Utilisateurs,
    @{ n = 'Première connexion'; e = { $_.Premiere.ToString('dd/MM/yyyy HH:mm:ss') } },
    @{ n = 'Dernière connexion'; e = { $_.Derniere.ToString('dd/MM/yyyy HH:mm:ss') } } |
    Export-Csv -Path "$base`_synthese_IP.csv" -Delimiter ';' -NoTypeInformation -Encoding UTF8

New-RapportHtml -Connexions $connexions -SyntheseIP $syntheseIP -SyntheseUsers $syntheseUsers -Chemin "$base.html"

Write-Host ''
Write-Host 'Fichiers générés :' -ForegroundColor Cyan
Write-Host "  $base.html"
Write-Host "  $base`_detail.csv"
Write-Host "  $base`_synthese_IP.csv"
Write-Host ''
$syntheseIP | Format-Table @{ n = 'Adresse IP'; e = { $_.IP } }, Connexions, Utilisateurs, @{ n = 'Première'; e = { $_.Premiere.ToString('dd/MM HH:mm') } }, @{ n = 'Dernière'; e = { $_.Derniere.ToString('dd/MM HH:mm') } } -AutoSize

if ($Ouvrir) { Invoke-Item "$base.html" }
