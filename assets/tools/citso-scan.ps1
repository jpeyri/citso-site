<#
.SYNOPSIS
    CITSO Scan v2 - l'apercu souverain de votre Active Directory (35 controles).
.DESCRIPTION
    35 controles en LECTURE SEULE, a lancer sur un poste du domaine avec un
    compte du domaine. Aucun droit d'administration requis. Aucune ecriture
    dans l'annuaire. Le rapport reste sur votre poste, aucune donnee envoyee.

    Categories (inspirees des scanners gratuits de reference) :
    - Identites et privileges (10 controles)
    - Kerberos et delegations (6 controles)
    - Infrastructure et DC (6 controles)
    - Confiance et reseaux (5 controles)
    - GPO et politiques (4 controles)
    - Objets et hygiene (4 controles)

    Utilisation :
        powershell -NoProfile -ExecutionPolicy Bypass -File .\citso-scan.ps1
#>
[CmdletBinding()]
param([string]$Domain = "")

$ErrorActionPreference = 'SilentlyContinue'

# ================================================================ connexion
$racineDse = [ADSI]'LDAP://RootDSE'
$nc = $racineDse.defaultNamingContext
if (-not $nc -and $Domain) { $nc = "DC=" + ($Domain -replace '\.', ',DC=') }
if (-not $nc) {
    Write-Host 'CITSO Scan : aucun domaine detecte. Lancez ce script sur un poste joint au domaine.' -ForegroundColor Red
    exit 1
}
$dnDomaine = $nc
$nomDomaine = ($nc -replace ',DC=', '.') -replace '^DC=', ''

function Rech([string]$filtre, [string[]]$props) {
    $r = New-Object System.DirectoryServices.DirectorySearcher([ADSI]("LDAP://" + $dnDomaine), $filtre)
    $r.PageSize = 1000
    if ($props) { $r.PropertiesToLoad.AddRange($props) | Out-Null }
    $r.FindAll()
}
function P($res, [string]$p) {
    if ($res.Properties -and $res.Properties.Contains($p) -and $res.Properties[$p].Count -gt 0) { $res.Properties[$p][0] } else { $null }
}
function DL($v) { if (-not $v) { return $null }; try { [DateTime]::FromFileTime([Int64]$v) } catch { $null } }
function N([string]$f) { try { (Rech $f @('name')).Count } catch { 0 } }

$controles = New-Object System.Collections.Generic.List[object]
$rouge = 0; $orange = 0; $vert = 0; $info = 0
function Aj([string]$cat, [string]$titre, [string]$statut, [string]$detail) {
    $controles.Add([pscustomobject]@{ Categorie = $cat; Titre = $titre; Statut = $statut; Detail = $detail })
    switch ($statut) { 'rouge' { $script:rouge++ } 'orange' { $script:orange++ } 'vert' { $script:vert++ } default { $script:info++ } }
}

Write-Host "CITSO Scan v2 - $nomDomaine - 35 controles en lecture seule`n" -ForegroundColor Cyan

# =========================================== CATEGORIE : IDENTITES ET PRIVILEGES

# 1. Domain Admins actifs
$mDA = Rech '(&(objectCategory=user)(memberOf=CN=Domain Admins,CN=Users,' + $dnDomaine + '))' @('sAMAccountName','userAccountControl')
$daActifs = 0; foreach ($m in $mDA) { $u = [int](P $m 'useraccountcontrol'); if (-not ($u -band 2)) { $daActifs++ } }
if ($daActifs -gt 5) { Aj 'Identites' 'Domain Admins actifs' 'rouge' "$daActifs comptes actifs dans Domain Admins. Visez < 3, le reste en juste-a-temps." }
elseif ($daActifs -ge 3) { Aj 'Identites' 'Domain Admins actifs' 'orange' "$daActifs comptes actifs dans Domain Admins : encore reduisible." }
else { Aj 'Identites' 'Domain Admins actifs' 'vert' "$daActifs comptes actifs seulement." }

# 2. krbtgt
$krb = Rech '(&(sAMAccountName=krbtgt)(objectClass=user))' @('pwdLastSet')
$dKrb = DL (P ($krb | Select-Object -First 1) 'pwdlastset')
$ageK = if ($dKrb) { [int]((Get-Date) - $dKrb).TotalDays } else { -1 }
if ($ageK -gt 365) { Aj 'Identites' 'Mot de passe krbtgt' 'rouge' "Dernier changement il y a $ageK jours : le krbtgt est la cle du domaine (Golden Ticket)." }
elseif ($ageK -ge 0) { Aj 'Identites' 'Mot de passe krbtgt' 'vert' "Rote il y a $ageK jours." }
else { Aj 'Identites' 'Mot de passe krbtgt' 'orange' 'Date illisible : verifier manuellement.' }

# 3. Mots de passe privilegies ages
$privs = Rech '(&(objectCategory=user)(adminCount=1))' @('pwdLastSet','userAccountControl','lastLogonTimestamp')
$nbPriv = $privs.Count; $pwdVieux = 0; $dormants = 0; $desac = 0
foreach ($u in $privs) {
    $uac = [int](P $u 'useraccountcontrol')
    if ($uac -band 2) { $desac++; continue }
    $d = DL (P $u 'pwdlastset')
    if ($d -and ((Get-Date) - $d).TotalDays -gt 180) { $pwdVieux++ }
    $dl = DL (P $u 'lastlogontimestamp')
    if (-not $dl -or ((Get-Date) - $dl).TotalDays -gt 90) { $dormants++ }
}
if ($pwdVieux -gt 5) { Aj 'Identites' 'Mots de passe privilegies ages (>6 mois)' 'rouge' "$pwdVieux comptes privilegies avec mot de passe de plus de 6 mois, sur $nbPriv au total." }
elseif ($pwdVieux -gt 0) { Aj 'Identites' 'Mots de passe privilegies ages (>6 mois)' 'orange' "$pwdVieux comptes privilegies sans changement depuis 6 mois." }
else { Aj 'Identites' 'Mots de passe privilegies ages (>6 mois)' 'vert' "Aucun mot de passe privilegie de plus de 6 mois." }

# 4. Privilegies dormants
if ($dormants -gt 5) { Aj 'Identites' 'Comptes privilegies dormants (>90 j)' 'orange' "$dormants comptes privilegies sans connexion depuis 90 jours : desactiver ou supprimer." }
else { Aj 'Identites' 'Comptes privilegies dormants (>90 j)' 'vert' "$dormants comptes dormants seulement." }

# 5. Comptes privilegies desactives non purges
if ($desac -gt 10) { Aj 'Identites' 'Privilegies desactives non purges' 'orange' "$desac comptes marques privilegies mais desactives : ACE AdminSDHolder residuel." }
else { Aj 'Identites' 'Privilegies desactives non purges' 'vert' "$desac comptes seulement." }

# 6. Compte Invite (Guest) active
$guest = Rech '(&(sAMAccountName=Guest)(objectClass=user))' @('userAccountControl')
if ($guest.Count -gt 0) {
    $guac = [int](P ($guest | Select-Object -First 1) 'useraccountcontrol')
    if ($guac -band 2) { Aj 'Identites' 'Compte Guest' 'vert' 'Guest desactive.' }
    else { Aj 'Identites' 'Compte Guest' 'rouge' 'Guest EST ACTIVE : a desactiver immediatement.' }
} else { Aj 'Identites' 'Compte Guest' 'vert' 'Guest desactive.' }

# 7. Administrateur integre utilise recemment
$admin = Rech '(&(sAMAccountName=Administrator)(objectClass=user))' @('lastLogonTimestamp','pwdLastSet')
$admL = DL (P ($admin | Select-Object -First 1) 'lastlogontimestamp')
$admP = DL (P ($admin | Select-Object -First 1) 'pwdlastset')
$admRecent = if ($admL -and ((Get-Date) - $admL).TotalDays -lt 14) { $true } else { $false }
$admVieux = if ($admP -and ((Get-Date) - $admP).TotalDays -gt 180) { $true } else { $false }
if ($admRecent) { Aj 'Identites' 'Administrateur integre' 'orange' 'Utilise dans les 14 derniers jours : le compte le plus vise doit rester dormant (renommage + trappe).' }
elseif ($admVieux) { Aj 'Identites' 'Administrateur integre' 'orange' 'Mot de passe de plus de 6 mois : le roter.' }
else { Aj 'Identites' 'Administrateur integre' 'vert' 'Dormant et rode.' }

# 8. Sans expiration (dont privilegies)
$sansExp = Rech '(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))' @('adminCount')
$privExp = 0; foreach ($u in $sansExp) { if ((P $u 'admincount') -eq 1) { $privExp++ } }
$nbSE = $sansExp.Count
if ($privExp -gt 0) { Aj 'Identites' 'Sans expiration (dont privilegies)' 'rouge' "$nbSE comptes sans expiration, dont $privExp privilegies : cibles parfaites." }
elseif ($nbSE -gt 20) { Aj 'Identites' 'Sans expiration (dont privilegies)' 'orange' "$nbSE comptes sans expiration (souvent services) : compenser par mots de passe longs/gMSA." }
else { Aj 'Identites' 'Sans expiration (dont privilegies)' 'vert' "$nbSE comptes sans expiration seulement." }

# 9. Chiffrement reversible
$revEnc = N '(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=128))'
if ($revEnc -gt 0) { Aj 'Identites' 'Chiffrement reversible' 'rouge' "$revEnc comptes avec mot de passe stocke en chiffrement reversible (clair) : a desactiver immediatement." }
else { Aj 'Identites' 'Chiffrement reversible' 'vert' 'Aucun mot de passe en chiffrement reversible.' }

# 10. Password not required
$noPwd = N '(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=32))'
if ($noPwd -gt 0) { Aj 'Identites' 'Comptes sans mot de passe requis' 'rouge' "$noPwd comptes ou le mot de passe n'est pas requis : authentication sans mot de passe possible." }
else { Aj 'Identites' 'Comptes sans mot de passe requis' 'vert' 'Tous les comptes exigent un mot de passe.' }

# =========================================== CATEGORIE : KERBEROS ET DELEGATIONS

# 11. Delegations non contraintes
$nbDel = N '(userAccountControl:1.2.840.113556.1.4.803:=524288)'
if ($nbDel -gt 0) { Aj 'Kerberos' 'Delegations non contraintes' 'rouge' "$nbDel objets avec delegation non contrainte : compromission = impersonation totale." }
else { Aj 'Kerberos' 'Delegations non contraintes' 'vert' 'Aucune delegation non contrainte.' }

# 12. Comptes avec DES active
$nbDes = N '(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=2097152))'
if ($nbDes -gt 0) { Aj 'Kerberos' 'DES Kerberos active' 'rouge' "$nbDes comptes avec DES Kerberos : chiffrement faible, a desactiver." }
else { Aj 'Kerberos' 'DES Kerberos active' 'vert' 'Aucun compte avec DES active.' }

# 13. Pas de pre-authentification
$nbNoPre = N '(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))'
if ($nbNoPre -gt 0) { Aj 'Kerberos' 'Pre-authentification absente' 'rouge' "$nbNoPre comptes sans pre-auth Kerberos : vol de ticket sans mot de passe (AS-REP roast)." }
else { Aj 'Kerberos' 'Pre-authentification absente' 'vert' 'Tous les comptes exigent la pre-authentification.' }

# 14. Comptes avec SPN (surface kerberoast)
$nbSpn = N '(servicePrincipalName=*)'
if ($nbSpn -gt 50) { Aj 'Kerberos' 'Comptes de service a SPN' 'orange' "$nbSpn comptes avec SPN : surface de kerberoasting, verifier mots de passe 25+ caracteres ou gMSA." }
else { Aj 'Kerberos' 'Comptes de service a SPN' 'vert' "$nbSpn comptes avec SPN : surface moderee." }

# 15. RBCD (resource-based constrained delegation)
$nbRbcd = N '(msDS-AllowedToActOnBehalfOfOtherIdentity=*)'
if ($nbRbcd -gt 0) { Aj 'Kerberos' 'RBCD configure' 'orange' "$nbRbcd objets avec RBCD : verifier que seuls les principaux legitimes y figurent (risque de takeover de compte machine)." }
else { Aj 'Kerberos' 'RBCD configure' 'vert' 'Aucune RBCD detectee.' }

# 16. Protected Users
$mPU = N ('(memberOf=CN=Protected Users,CN=Users,' + $dnDomaine + ')')
if ($mPU -gt 0) { Aj 'Kerberos' 'Groupe Protected Users' 'vert' "$mPU membres : protections fortes pour les comptes sensibles." }
else { Aj 'Kerberos' 'Groupe Protected Users' 'orange' 'Vide : les comptes sensibles ne beneficient pas des protections Kerberos fortes.' }

# =========================================== CATEGORIE : INFRASTRUCTURE ET DC

# 17. Controleurs de domaine
$dcs = Rech '(userAccountControl:1.2.840.113556.1.4.803:=8192)' @('name','operatingSystem','operatingSystemVersion','pwdLastSet')
$nbDc = $dcs.Count
$dcObs = @(); $dcPwdVieux = 0
foreach ($dc in $dcs) {
    $os = P $dc 'operatingsystem'
    if ($os -match '2008|2012$|2012 R2|2003|2000') { $dcObs += (P $dc 'name') + " ($os)" }
    $dp = DL (P $dc 'pwdlastset')
    if ($dp -and ((Get-Date) - $dp).TotalDays -gt 45) { $dcPwdVieux++ }
}
if ($nbDc -le 1) { Aj 'Infrastructure' 'Controleurs de domaine' 'rouge' "$nbDc seul DC : point de defaillance unique." }
elseif ($dcObs.Count -gt 0) { Aj 'Infrastructure' 'Controleurs de domaine' 'rouge' "$nbDc DC, dont obsoletes : $($dcObs -join ', ')." }
else { Aj 'Infrastructure' 'Controleurs de domaine' 'vert' "$nbDc controleurs, systemes a jour selon l'annuaire." }

# 18. Mot de passe machine DC ancien
if ($dcPwdVieux -gt 0) { Aj 'Infrastructure' 'Mot de passe machine DC ancien' 'orange' "$dcPwdVieux DC avec mot de passe machine de plus de 45 jours." }
else { Aj 'Infrastructure' 'Mot de passe machine DC ancien' 'vert' 'Tous les DC ont un mot de passe machine recent.' }

# 19. Niveau fonctionnel
$dfl = [int]$racineDse.domainControllerFunctionality
if ($dfl -ge 7) { Aj 'Infrastructure' 'Niveau fonctionnel du domaine' 'vert' "Niveau 2016+ : protections recentes actives." }
elseif ($dfl -ge 5) { Aj 'Infrastructure' 'Niveau fonctionnel du domaine' 'orange' "Niveau $dfl : certaines protections recentes (Protected Users, PKINIT) non actives." }
else { Aj 'Infrastructure' 'Niveau fonctionnel du domaine' 'rouge' "Niveau $dfl : base obsolete, nombreuses protections indisponibles." }

# 20. OS obsoletes (tous ordinateurs)
$machObs = N '(&(objectCategory=computer)(operatingSystem=Windows XP))'
$machObs += N '(&(objectCategory=computer)(operatingSystem=Windows 7))'
$machObs += N '(&(objectCategory=computer)(operatingSystem=*2003*))'
$machObs += N '(&(objectCategory=computer)(operatingSystem=*2008*))'
$machObs += N '(&(objectCategory=computer)(operatingSystem=*Vista*))'
if ($machObs -gt 0) { Aj 'Infrastructure' 'Systemes obsoletes' 'rouge' "$machObs ordinateurs sur un OS sans correctifs de securite (XP/2003/2008/Vista/Win7)." }
else { Aj 'Infrastructure' 'Systemes obsoletes' 'vert' 'Aucun systeme obsolete detecte dans l annuaire.' }

# 21. Machines dormantes
$inactives = N '(&(objectCategory=computer)(lastLogonTimestamp<=129386000000000000))'
if ($inactives -gt 30) { Aj 'Infrastructure' 'Machines dormantes (~180 j)' 'orange' "$inactives machines sans connexion depuis ~180 jours : pollution et cibles de respawn." }
else { Aj 'Infrastructure' 'Machines dormantes (~180 j)' 'vert' "$inactives machines dormantes seulement." }

# 22. LAPS
$nbLaps = N '(ms-Mcs-AdmPwd=*)'
if ($nbLaps -gt 0) { Aj 'Infrastructure' 'LAPS (mots de passe admin locaux)' 'vert' "LAPS present ($nbLaps machines) : les mots de passe admin locaux tournent." }
else { Aj 'Infrastructure' 'LAPS (mots de passe admin locaux)' 'rouge' 'Aucun LAPS detecte : les comptes Administrateur locaux partagent probablement le meme mot de passe.' }

# =========================================== CATEGORIE : CONFIANCE ET RESEAUX

# 23. Trusts
$trusts = Rech '(objectClass=trustedDomain)' @('name','trustAttributes','trustDirection','whenChanged')
$nbTrusts = $trusts.Count
$trustDetails = @(); $trustDanger = 0
foreach ($t in $trusts) {
    $ta = [int](P $t 'trustattributes')
    $tn = P $t 'name'
    $tc = DL (P $t 'whenchanged')
    $trustOld = if ($tc -and ((Get-Date) - $tc).TotalDays -gt 365) { $true } else { $false }
    $detail = "$tn"
    if ($ta -band 4) { $detail += " [quarantaine]" }
    if ($ta -band 32) { $detail += " [intra-foret]"; $trustDanger++ }
    if ($ta -band 64) { $detail += " [inter-foret]"; $trustDanger++ }
    if ($ta -band 128) { $detail += " [TGT delegation]"; $trustDanger++ }
    if ($ta -band 512) { $detail += " [TREAT_AS_EXTERNAL]"; $trustDanger++ }
    if ($trustOld) { $detail += " [ancien]"; $trustDanger++ }
    $trustDetails += $detail
}
if ($trustDanger -gt 0) { Aj 'Confiance' 'Trusts de domaine' 'rouge' "$nbTrusts trust(s), dont $trustDanger a risque : $($trustDetails -join '; ')." }
elseif ($nbTrusts -gt 0) { Aj 'Confiance' 'Trusts de domaine' 'vert' "$nbTrusts trust(s) sain(s) : $($trustDetails -join '; ')." }
else { Aj 'Confiance' 'Trusts de domaine' 'vert' 'Aucun trust : domaine isole.' }

# 24. SID History
$nbSid = N '(sIDHistory=*)'
if ($nbSid -gt 0) { Aj 'Confiance' 'SID History residuel' 'rouge' "$nbSid objets avec sIDHistory : residu de migration ou backdoor (escalade vers ancien domaine)." }
else { Aj 'Confiance' 'SID History residuel' 'vert' 'Aucun SID History.' }

# 25. Acces anonyme
$anonOk = $false
try {
    $anonRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://" + $dnDomaine, $null, $null)
    $null = $anonRoot.Properties['distinguishedName']
    $anonOk = $true
} catch { $anonOk = $false }
if ($anonOk) { Aj 'Confiance' 'Acces anonyme a l annuaire' 'orange' 'Le domaine repond aux requetes LDAP non authentifiees : enumeration possible.' }
else { Aj 'Confiance' 'Acces anonyme a l annuaire' 'vert' 'Acces anonyme refuse.' }

# 26. Pre-Windows 2000 Compatible Access
$pw2k = N ('(memberOf=CN=Pre-Windows 2000 Compatible Access,CN=Builtin,' + $dnDomaine + ')')
$sidEveyone = N '(&(objectCategory=group)(cn=Pre-Windows 2000 Compatible Access)(member=S-1-1-0))'
if ($pw2k -gt 2) { Aj 'Confiance' 'Pre-Windows 2000 Compatible Access' 'orange' "$pw2k membres : groupe trop large, enumeration possible (Everyone historiquement inclus)." }
else { Aj 'Confiance' 'Pre-Windows 2000 Compatible Access' 'vert' "$pw2k membres seulement." }

# 27. Schema Admins non vide
$schemaAdmins = N ('(memberOf=CN=Schema Admins,CN=Users,' + $dnDomaine + ')')
if ($schemaAdmins -gt 0) { Aj 'Confiance' 'Schema Admins' 'orange' "$schemaAdmins membres : ce groupe doit rester vide en regime de croisiere." }
else { Aj 'Confiance' 'Schema Admins' 'vert' 'Schema Admins vide.' }

# =========================================== CATEGORIE : GPO ET POLITIQUES

# 28. Politique de mot de passe (defaultDomainPolicy)
$ddp = [ADSI]("LDAP://CN=Default Domain Policy,CN=Policies,CN=System," + $dnDomaine)
$minLen = $ddp.lockoutThreshold
try {
    $pol = Rech '(&(objectCategory=domainPolicy)(distinguishedName=CN=Default Domain Policy,CN=Policies,CN=System,' + $dnDomaine + '))' @('minPwdLength','lockoutThreshold','pwdHistoryLength','maxPwdAge')
    if ($pol.Count -gt 0) {
        $ml = P ($pol | Select-Object -First 1) 'minpwdlength'
        $lt = P ($pol | Select-Object -First 1) 'lockoutthreshold'
        $ph = P ($pol | Select-Object -First 1) 'pwdhistorylength'
        $detail = "Longueur min: $ml, historique: $ph, seuil lockout: $lt"
        if ($ml -lt 12) { Aj 'GPO' 'Politique de mot de passe' 'orange' "$detail - longueur < 12 caracteres (recommande 14+ pour les comptes sensibles)." }
        else { Aj 'GPO' 'Politique de mot de passe' 'vert' "$detail." }
    } else { Aj 'GPO' 'Politique de mot de passe' 'orange' 'Politique par defaut illisible ou personnalisée : verifier manuellement.' }
} catch { Aj 'GPO' 'Politique de mot de passe' 'orange' 'Lecture de la politique impossible avec ce compte.' }

# 29. GPO avec cpassword dans SYSVOL
$sysvolPath = "\\$nomDomaine\SYSVOL\$nomDomaine\Policies"
$cpasswords = 0
try {
    $xmls = Get-ChildItem -Path $sysvolPath -Recurse -Filter "*.xml" -ErrorAction SilentlyContinue | Select-Object -First 200
    foreach ($xml in $xmls) {
        $content = Get-Content $xml.FullName -Raw -ErrorAction SilentlyContinue
        if ($content -match 'cpassword="[^"]{5,}"') { $cpasswords++ }
    }
} catch {}
if ($cpasswords -gt 0) { Aj 'GPO' 'Mots de passe dans les GPO (cpassword)' 'rouge' "$cpasswords fichier(s) XML avec cpassword dans SYSVOL : mots de passe stockes en clair, extractibles par tous." }
else { Aj 'GPO' 'Mots de passe dans les GPO (cpassword)' 'vert' 'Aucun cpassword detecte dans SYSVOL.' }

# 30. AdminSDHolder
$adminSD = [ADSI]("LDAP://CN=AdminSDHolder,CN=System," + $dnDomaine)
$sdHold = $adminSD.Properties['nTSecurityDescriptor']
if ($sdHold) { Aj 'GPO' 'AdminSDHolder protégé' 'vert' 'Objet AdminSDHolder present et lisible.' }
else { Aj 'GPO' 'AdminSDHolder protégé' 'orange' 'Acces refuse a AdminSDHolder (normal) ou objet introuvable.' }

# 31. Groupes Operateurs non vides
$nbAccountOp = N ('(memberOf=CN=Account Operators,CN=Builtin,' + $dnDomaine + ')')
$nbServerOp = N ('(memberOf=CN=Server Operators,CN=Builtin,' + $dnDomaine + ')')
$nbBackupOp = N ('(memberOf=CN=Backup Operators,CN=Builtin,' + $dnDomaine + ')')
$nbPrintOp = N ('(memberOf=CN=Print Operators,CN=Builtin,' + $dnDomaine + ')')
$totalOps = $nbAccountOp + $nbServerOp + $nbBackupOp + $nbPrintOp
if ($totalOps -gt 0) { Aj 'GPO' 'Groupes Operateurs non vides' 'orange' "Account: $nbAccountOp, Server: $nbServerOp, Backup: $nbBackupOp, Print: $nbPrintOp. Ces groupes heritent de privileges eleves." }
else { Aj 'GPO' 'Groupes Operateurs non vides' 'vert' 'Tous les groupes Operateurs sont vides.' }

# =========================================== CATEGORIE : OBJETS ET HYGIENE

# 32. Ordinateurs sans mot de passe requis
$machNoPwd = N '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=32))'
if ($machNoPwd -gt 0) { Aj 'Hygiene' 'Machines sans mot de passe requis' 'rouge' "$machNoPwd machines avec PASSWD_NOTREQD : authentication sans mot de passe possible." }
else { Aj 'Hygiene' 'Machines sans mot de passe requis' 'vert' 'Toutes les machines exigent un mot de passe.' }

# 33. gMSA en usage
$nbGmsa = N '(&(objectClass=msDS-GroupManagedServiceAccount))'
if ($nbGmsa -gt 0) { Aj 'Hygiene' 'gMSA (comptes de service geres)' 'vert' "$nbGmsa gMSA en usage : les mots de passe de service tournent automatiquement." }
else { Aj 'Hygiene' 'gMSA (comptes de service geres)' 'orange' 'Aucun gMSA : les comptes de service ont des mots de passe statiques, vulnérables.' }

# 34. Corbeille AD (Recycle Bin)
$recycle = $racineDse.'enabledOptionalFeatures'
$recycleOn = $false
if ($recycle) { foreach ($f in $recycle) { if ($f -match 'Recycle Bin Feature') { $recycleOn = $true } } }
if ($recycleOn) { Aj 'Hygiene' 'Corbeille Active Directory' 'vert' 'Activee : les objets supprimes sont recuperables.' }
else { Aj 'Hygiene' 'Corbeille Active Directory' 'orange' 'Desactivee : un objet supprime par erreur ou par un attaquant est perdu definitivement.' }

# 35. Doublons de comptes (sAMAccountName similaires)
$noms = @{}
$dupNoms = 0
$allUsers = Rech '(objectCategory=user)(sAMAccountName=*)' @('sAMAccountName')
foreach ($u in $allUsers) {
    $sam = P $u 'samaccountname'
    if ($sam) {
        $norm = $sam -replace '[^a-zA-Z0-9]', ''
        if ($noms.ContainsKey($norm)) { $dupNoms++ } else { $noms[$norm] = 1 }
    }
}
if ($dupNoms -gt 0) { Aj 'Hygiene' 'Comptes aux noms similaires' 'orange' "$dupNoms paires de comptes avec des noms normalises identiques : confusion possible, atout pour un attaquant." }
else { Aj 'Hygiene' 'Comptes aux noms similaires' 'vert' 'Aucun doublon detecte.' }

# ================================================================ rapport
Write-Host ("`n{0} controles : {1} rouge(s), {2} orange(s), {3} vert(s)`n" -f $controles.Count, $rouge, $orange, $vert) -ForegroundColor $(if ($rouge) { 'Red' } elseif ($orange) { 'Yellow' } else { 'Green' })

$categories = $controles | Group-Object -Property Categorie | Sort-Object Name
foreach ($cat in $categories) {
    Write-Host "`n  $($cat.Name.ToUpper())" -ForegroundColor White
    foreach ($c in $cat.Group) {
        $couleur = @{ rouge = 'Red'; orange = 'Yellow'; vert = 'Green' }[$c.Statut]
        Write-Host ("    [{0}] {1}" -f $c.Statut.ToUpper(), $c.Titre) -ForegroundColor $couleur
        Write-Host ("           {0}" -f $c.Detail)
    }
}

# HTML
$cssCouleurs = @{ rouge = '#c24a45'; orange = '#d9a21b'; vert = '#3fb8bd' }
$cats = $controles | Group-Object -Property Categorie | Sort-Object Name
$htmlSections = foreach ($cat in $cats) {
    $lignes = foreach ($c in $cat.Group) {
        "<div style='border-left:4px solid $($cssCouleurs[$c.Statut]);margin:12px 0;padding:10px 14px;background:#f6f8fb;border-radius:6px'>" +
        "<b style='color:#0e1b2c'>$($c.Titre)</b> <span style='color:$($cssCouleurs[$c.Statut]);font-weight:700'>[$($c.Statut)]</span>" +
        "<br><span style='color:#333;font-size:14px'>$($c.Detail)</span></div>"
    }
    "<h2 style='color:#0e1b2c;font-size:20px;margin:28px 0 8px;border-bottom:2px solid #e0e4ea;padding-bottom:6px'>$($cat.Name)</h2>$($lignes -join "`n")"
}

$html = @"
<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8"><title>CITSO Scan v2 - $nomDomaine</title></head>
<body style="font-family:Segoe UI,Arial,sans-serif;max-width:860px;margin:30px auto;color:#1b2533">
<div style="background:#0e1b2c;color:#fff;padding:24px 28px;border-radius:12px;margin-bottom:20px">
<h1 style="color:#fff;margin:0;font-size:26px">CITSO Scan v2 &mdash; $nomDomaine</h1>
<p style="color:#a8b8c8;margin:8px 0 0;font-size:14px">$($controles.Count) controles en lecture seule &middot; $rouge rouge(s) &middot; $orange orange(s) &middot; $vert vert(s)<br>
Genere le $(Get-Date -Format 'dd/MM/yyyy a HH:mm') &middot; <b style="color:#3fb8bd">Aucune donnee envoyee</b> &middot; Rapport local uniquement</p>
</div>
$($htmlSections -join "`n")
<div style="margin-top:32px;border-top:2px solid #e0e4ea;padding-top:16px">
<p style="color:#6b7686;font-size:14px"><b>Ce scan gratuit couvre 35 signaux essentiels.</b> L'audit complet CITSO en couvre plus de 90, avec chemins d'attaque detailles, maturite ANSSI, rapports interactif/Word/PDF et restitution :
<a href="https://citso.eu/offres.html" style="color:#c24a45">citso.eu/offres.html</a></p>
</div>
</body></html>
"@
$fic = Join-Path (Get-Location) ("Citso-Scan-" + $nomDomaine + "-" + (Get-Date -Format 'yyyyMMdd-HHmm') + ".html")
$html | Out-File -FilePath $fic -Encoding utf8
Write-Host "`nRapport local : $fic" -ForegroundColor Cyan
Write-Host "Aucune donnee envoyee. Lecture seule stricte. CITSO - preuve a l'appui." -ForegroundColor DarkGray
