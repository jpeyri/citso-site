<#
.SYNOPSIS
    CITSO Scan - l'apercu souverain de votre Active Directory.
.DESCRIPTION
    15 controles en LECTURE SEULE, a lancer sur un poste du domaine avec un
    compte du domaine. Inspire des scanners gratuits (PingCastle, Purple Knight),
    avec la difference CITSO : le rapport reste sur votre poste, aucune donnee
    n'est envoyee, nulle part, jamais.

    Aucun droit d'administration requis. Aucune ecriture dans l'annuaire.
    Resultat : fichier HTML local + resume console.

    Utilisation :
        powershell -NoProfile -ExecutionPolicy Bypass -File .\citso-scan.ps1
    (eventuellement : -Domain "mondomaine.fr" pour cibler un domaine precis)
#>
[CmdletBinding()]
param([string]$Domain = "")

$ErrorActionPreference = 'SilentlyContinue'

# ---------------------------------------------------------------- connexion
$racineDse = [ADSI]'LDAP://RootDSE'
$nc = $racineDse.defaultNamingContext
if (-not $nc -and $Domain) { $nc = "DC=" + ($Domain -replace '\.', ',DC=') }
if (-not $nc) {
    Write-Host 'CITSO Scan : aucun domaine detecte. Lancez ce script sur un poste joint au domaine.' -ForegroundColor Red
    exit 1
}
$dnDomaine = $nc
$nomDomaine = ($nc -replace ',DC=', '.') -replace '^DC=', ''

function Recherche([string]$filtre, [string[]]$proprietes) {
    $r = New-Object System.DirectoryServices.DirectorySearcher([ADSI]("LDAP://" + $dnDomaine), $filtre)
    $r.PageSize = 500
    if ($proprietes) { $r.PropertiesToLoad.AddRange($proprietes) | Out-Null }
    $r.FindAll()
}

function Prop($res, [string]$p) {
    if ($res.Properties -and $res.Properties.Contains($p) -and $res.Properties[$p].Count -gt 0) { $res.Properties[$p][0] } else { $null }
}

function DateLdap($v) {
    if (-not $v) { return $null }
    try { [DateTime]::FromFileTime([Int64]$v) } catch { $null }
}

function Compte([string]$filtre) {
    try { (Recherche $filtre @('name')).Count } catch { 0 }
}

$controles = New-Object System.Collections.Generic.List[object]
function Ajoute([string]$titre, [string]$statut, [string]$detail) {
    $controles.Add([pscustomobject]@{ Titre = $titre; Statut = $statut; Detail = $detail })
}
$rouge = 0; $orange = 0; $vert = 0

Write-Host "CITSO Scan - domaine $nomDomaine (lecture seule, rapport local)`n" -ForegroundColor Cyan

# --------------------------------------------------- 1. niveau fonctionnel
$dfl = $racineDse.domainControllerFunctionality
$niveaux = @{ 0 = 'Windows 2000'; 1 = '2003 intermediaire'; 2 = '2003'; 3 = '2008'; 4 = '2008 R2'; 5 = '2012'; 6 = '2012 R2'; 7 = '2016'; 8 = '2025 (protection future)' }
$niveauTxt = if ($niveaux.ContainsKey([int]$dfl)) { $niveaux[[int]$dfl] } else { "niveau $dfl" }
if ([int]$dfl -ge 7) { $vert++; Ajoute 'Niveau fonctionnel du domaine' 'vert' "Niveau $niveauTxt : base saine pour les protections recentes." }
else { $orange++; Ajoute 'Niveau fonctionnel du domaine' 'orange' "Niveau $niveauTxt : les protections recentes (groupes proteges, PKINIT...) ne sont pas actives." }

# --------------------------------------------------- 2. controleurs de domaine
$dcs = Recherche '(userAccountControl:1.2.840.113556.1.4.803:=8192)' @('name', 'operatingSystem', 'operatingSystemVersion')
$nbDc = $dcCount = $dcs.Count
$dcObsoletes = @(); foreach ($dc in $dcs) { $os = Prop $dc 'operatingsystem'; if ($os -match '2008|2012$|2012 R2|2003|2000') { $dcObsoletes += (Prop $dc 'name') + " ($os)" } }
if ($nbDc -le 1) { $rouge++; Ajoute 'Controleurs de domaine' 'rouge' "$nbDc controleur seul ou introuvable : un seul DC est un point de defaillance unique (pas de redondance, sauvegarde System State critique)." }
elseif ($dcObsoletes.Count -gt 0) { $rouge++; Ajoute 'Controleurs de domaine' 'rouge' "$nbDc DC, dont obsoletes (plus de correctifs de securite) : $($dcObsoletes -join ', ')." }
else { $vert++; Ajoute 'Controleurs de domaine' 'vert' "$nbDc controleurs, systemes a jour selon l'annuaire." }

# --------------------------------------------------- 3. krbtgt
$krbtgt = Recherche '(&(sAMAccountName=krbtgt)(objectClass=user))' @('pwdLastSet')
$ddp = DateLdap (Prop ($krbtgt | Select-Object -First 1) 'pwdlastset')
$ageJ = if ($ddp) { [int]((Get-Date) - $ddp).TotalDays } else { -1 }
if ($ageJ -lt 0) { $orange++; Ajoute 'Mot de passe krbtgt' 'orange' 'Date de changement illisible : a verifier manuellement.' }
elseif ($ageJ -gt 365) { $rouge++; Ajoute 'Mot de passe krbtgt' 'rouge' "Dernier changement il y a $ageJ jours : le krbtgt est la cle du domaine, sa rotation (deux fois de suite) est un réflexe post-incident et un marqueur d'hygiene." }
else { $vert++; Ajoute 'Mot de passe krbtgt' 'vert' "Roté il y a $ageJ jours." }

# --------------------------------------------------- 4. admins au quotidien
$nbDa = Compte '(&(objectCategory=group)(cn=Domain Admins))'
$membresDa = Recherche '(&(objectCategory=user)(memberOf=CN=Domain Admins,CN=Users,' + $dnDomaine + '))' @('sAMAccountName')
$nbMembresDa = $membresDa.Count
$daActifs = 0; foreach ($m in $membresDa) { $uac = [int](Prop $m 'useraccountcontrol'); if (-not ($uac -band 2)) { $daActifs++ } }
if ($daActifs -gt 5) { $rouge++; Ajoute 'Domain Admins actifs' 'rouge' "$daActifs comptes actifs dans Domain Admins : chaque session quotidienne de ces comptes est une occasion de vol de jeton. Visez < 3, le reste en juste-a-temps." }
elseif ($daActifs -ge 3) { $orange++; Ajoute 'Domain Admins actifs' 'orange' "$daActifs comptes actifs dans Domain Admins : encore reduisible." }
else { $vert++; Ajoute 'Domain Admins actifs' 'vert' "$daActifs comptes actifs dans Domain Admins." }

# --------------------------------------------------- 5. mots de passe d'admin ages
$adminPwdVieux = 0
$prives = Recherche '(&(objectCategory=user)(adminCount=1))' @('pwdLastSet', 'userAccountControl')
foreach ($u in $prives) {
    $uac = [int](Prop $u 'useraccountcontrol'); if ($uac -band 2) { continue }
    $d = DateLdap (Prop $u 'pwdlastset')
    if ($d -and ((Get-Date) - $d).TotalDays -gt 365) { $adminPwdVieux++ }
}
$nbPrives = $prives.Count
if ($adminPwdVieux -gt 10) { $rouge++; Ajoute 'Mots de passe privilegies ages' 'rouge' "$adminPwdVieux comptes a privilegess (adminCount) actifs avec mot de passe de plus d'un an, sur $nbPrives au total." }
elseif ($adminPwdVieux -gt 0) { $orange++; Ajoute 'Mots de passe privilegies ages' 'orange' "$adminPwdVieux comptes a privilegess avec mot de passe de plus d'un an, sur $nbPrives au total." }
else { $vert++; Ajoute 'Mots de passe privilegies ages' 'vert' "Aucun compte a privilege actif avec mot de passe de plus d'un an." }

# --------------------------------------------------- 6. mots de passe jamais expirants
$nbJamaisExp = 0
$users = Recherche '(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))' @('sAMAccountName', 'adminCount')
$privExp = 0; foreach ($u in $users) { if ((Prop $u 'admincount') -eq 1) { $privExp++ } }
$nbJamaisExp = $users.Count
if ($privExp -gt 0) { $rouge++; Ajoute 'Mots de passe sans expiration' 'rouge' "$nbJamaisExp comptes avec mot de passe n'expirant jamais, dont $privExp a privilegees : cibles parfaites (kerberoasting, vol de hash)." }
elseif ($nbJamaisExp -gt 20) { $orange++; Ajoute 'Mots de passe sans expiration' 'orange' "$nbJamaisExp comptes sans expiration (souvent des services) : a compenser par des mots de passe longs/gMSA." }
else { $vert++; Ajoute 'Mots de passe sans expiration' 'vert' "$nbJamaisExp comptes sans expiration seulement." }

# --------------------------------------------------- 7. delegations non contraintes
$nbDeleg = Compte '(userAccountControl:1.2.840.113556.1.4.803:=524288)'
if ($nbDeleg -gt 0) { $rouge++; Ajoute 'Delegations non contraintes' 'rouge' "$nbDeleg objets avec delegation non contrainte : quiconque compromise l'un d'eux peut se faire passer pour n'importe quel utilisateur (DC compris) vers n'importe quel service." }
else { $vert++; Ajoute 'Delegations non contraintes' 'vert' 'Aucune delegation non contrainte.' }

# --------------------------------------------------- 8. SID History
$nbSidHist = Compte '(sIDHistory=*)'
if ($nbSidHist -gt 0) { $rouge++; Ajoute 'SID History residuel' 'rouge' "$nbSidHist objets portent un sIDHistory : residu de migration ou backdoor potentiel (escalade vers un ancien domaine)." }
else { $vert++; Ajoute 'SID History residuel' 'vert' 'Aucun SID History.' }

# --------------------------------------------------- 9. comptes a SPN (surface kerberoast)
$nbSpn = Compte '(servicePrincipalName=*)'
if ($nbSpn -gt 50) { $orange++; Ajoute 'Comptes de service a SPN' 'orange' "$nbSpn comptes avec SPN : surface de kerberoasting. Verifiez qu'ils ont des mots de passe longs (25+ caracteres) ou sont en gMSA." }
else { $vert++; Ajoute 'Comptes de service a SPN' 'vert' "$nbSpn comptes avec SPN : surface kerberoast moderee." }

# --------------------------------------------------- 10. LAPS deploye ?
$nbLaps = Compte '(ms-Mcs-AdmPwd=*)'
if ($nbLaps -gt 0) { $vert++; Ajoute 'LAPS (mots de passe admin locaux)' 'vert' "LAPS present ($nbLaps machines vues) : les mots de passe admin locaux tournent et sont stockes dans l'annuaire chiffres." }
else { $rouge++; Ajoute 'LAPS (mots de passe admin locaux)' 'rouge' 'Aucun mot de passe admin local LAPS vu : les comptes Administrateur locaux partagent probablement le meme mot de passe sur plusieurs machines (pass-the-hash lateral).' }

# --------------------------------------------------- 11. groupe Protected Users
$nbProt = Compte '(&(objectCategory=group)(cn=Protected Users))'
$membresProt = 0
if ($nbProt -gt 0) { $membresProt = (Recherche ('(memberOf=CN=Protected Users,CN=Users,' + $dnDomaine + ')') @('name')).Count }
if ($membresProt -gt 0) { $vert++; Ajoute 'Groupe Protected Users' 'vert' "$membresProt membres : protections fortes (pas de NTLM, pas de delegation, TGT courts) pour les comptes sensibles." }
else { $orange++; Ajoute 'Groupe Protected Users' 'orange' 'Vide ou absent : les comptes sensibles ne beneficient pas des protections fortes de Kerberos.' }

# --------------------------------------------------- 12. comptes privilegies dormants
$dormants = 0
foreach ($u in $prives) {
    $uac = [int](Prop $u 'useraccountcontrol'); if ($uac -band 2) { continue }
    $d = DateLdap (Prop $u 'lastlogontimestamp')
    if (-not $d -or ((Get-Date) - $d).TotalDays -gt 90) { $dormants++ }
}
if ($dormants -gt 5) { $orange++; Ajoute 'Comptes privilegies dormants' 'orange' "$dormants comptes a privilegess actifs mais sans connexion depuis 90 jours : a desactiver ou supprimer (stockage de jetons inutile)." }
else { $vert++; Ajoute 'Comptes privilegies dormants' 'vert' "$dormants comptes privilegies dormants seulement." }

# --------------------------------------------------- 13. comptes machine ages (mot de passe)
$nbMachVieilles = 0
$machines = Recherche '(&(objectCategory=computer)(pwdLastSet<=129325200000000000))' @('name')  # ~2011: cap bas volontairement large
#LDAP : on compte machine sans pwdLastSet recent via lastLogonTimestamp > 180j comme machines fantomes
$machFantomes = 0
foreach ($m in $machines) { $machFantomes++ }
$inactives = Recherche '(&(objectCategory=computer)(lastLogonTimestamp<=129386000000000000))' @('name')
$nbInactives = $inactives.Count
if ($nbInactives -gt 30) { $orange++; Ajoute 'Machines dormantes' 'orange' "$nbInactives machines sans connexion depuis ~180 jours : pollution de l'annuaire, cibles de respawn de compte machine." }
else { $vert++; Ajoute 'Machines dormantes' 'vert' "$nbInactives machines dormantes seulement." }

# --------------------------------------------------- 14. AdminSDHolder / comptes proteges "a la louche"
$nbAdminCountDesac = 0
foreach ($u in $prives) { $uac = [int](Prop $u 'useraccountcontrol'); if ($uac -band 2) { $nbAdminCountDesac++ } }
if ($nbAdminCountDesac -gt 10) { $orange++; Ajoute 'Comptes privilegies desactives non purges' 'orange' "$nbAdminCountDesac comptes marques privilegies (adminCount) mais desactives : leur ACE AdminSDHolder residuel traine, purge a prevoir." }
else { $vert++; Ajoute 'Comptes privilegies desactives non purges' 'vert' "$nbAdminCountDesac comptes privilegies desactives." }

# --------------------------------------------------- 15. lecture de la partition configuration
$configLisible = $false
try { $null = [ADSI]("LDAP://CN=Configuration," + $dnDomaine); $configLisible = $true } catch { $configLisible = $false }
if ($configLisible) { $vert++; Ajoute 'Niveau d''enumeration' 'vert' 'Sonde de lecture standard : l''annuaire repond aux requetes LDAP authentifiees de votre session (aucun test offensif dans le Scan).' }
else { $orange++; Ajoute 'Niveau d''enumeration' 'orange' 'Lecture partielle : certaines branches refusent la lecture a votre compte (bon signe si volontaire).' }

# ------------------------------------------------------------------ resume
Write-Host ("`n{0} controles : {1} rouge(s), {2} orange(s), {3} vert(s)`n" -f $controles.Count, $rouge, $orange, $vert) -ForegroundColor $(if ($rouge) { 'Red' } elseif ($orange) { 'Yellow' } else { 'Green' })
foreach ($c in $controles) {
    $couleur = @{ rouge = 'Red'; orange = 'Yellow'; vert = 'Green' }[$c.Statut]
    Write-Host (" [{0}] {1}" -f $c.Statut.ToUpper(), $c.Titre) -ForegroundColor $couleur
    Write-Host ("        {0}" -f $c.Detail)
}

# ------------------------------------------------------------------ rapport HTML
$couleursCss = @{ rouge = '#c24a45'; orange = '#d9a21b'; vert = '#3fb8bd' }
$lignes = foreach ($c in $controles) {
    "<div style='border-left:4px solid $($couleursCss[$c.Statut]);margin:14px 0;padding:10px 14px;background:#f6f8fb;border-radius:6px'><b style='color:#0e1b2c'>$($c.Titre)</b> <span style='color:$($couleursCss[$c.Statut]);font-weight:700'>[$($c.Statut)]</span><br><span style='color:#333;font-size:14px'>$($c.Detail)</span></div>"
}
$html = @"
<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8"><title>CITSO Scan - $nomDomaine</title></head>
<body style="font-family:Segoe UI,Arial,sans-serif;max-width:820px;margin:30px auto;color:#1b2533">
<h1 style="color:#0e1b2c">CITSO Scan — $nomDomaine</h1>
<p style="color:#6b7686">Apercu souverain, $($controles.Count) controles en lecture seule, genere le $(Get-Date -Format 'dd/MM/yyyy a HH:mm') sur ce poste.<br>
<b>Aucune donnee n'a ete envoyee</b> : ce fichier est l'unique resultat, il reste chez vous.</p>
<h2 style="color:#0e1b2c">$rouge point(s) rouge(s) - $orange orange(s) - $vert vert(s)</h2>
$($lignes -join "`n")
<p style="margin-top:26px;color:#6b7686;border-top:1px solid #ddd;padding-top:12px">
Ce scan gratuit couvre 15 signaux. L'audit complet CITSO en couvre plus de 90, avec chemins d'attaque, maturite ANSSI, rapports et restitution :
<a href="https://citso.eu/offres.html" style="color:#c24a45">citso.eu/offres.html</a></p>
</body></html>
"@
$fic = Join-Path (Get-Location) ("Citso-Scan-" + $nomDomaine + "-" + (Get-Date -Format 'yyyyMMdd-HHmm') + ".html")
$html | Out-File -FilePath $fic -Encoding utf8
Write-Host "`nRapport local : $fic" -ForegroundColor Cyan
Write-Host "Aucune donnee envoyee. Lecture seule stricte. CITSO - preuve a l'appui." -ForegroundColor DarkGray
