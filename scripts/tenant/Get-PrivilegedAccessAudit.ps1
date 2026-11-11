#Requires -Version 5.1

<#
.SYNOPSIS
    Entra ID privileged access, MFA posture and workload identity review for one tenant.

.DESCRIPTION
    - Active and PIM-eligible directory role assignments (users, groups, service principals)
    - Per admin: enabled state, last sign-in, sync source, guest status and registered methods
      classified as phishing-resistant / Authenticator / SMS-voice only / none
    - Global Administrator count against the 2-4 guidance
    - Tenant-wide MFA registration report (users relying only on SMS/voice, users with no MFA)
    - Authentication methods policy state (SMS, voice, FIDO2/passkeys, Authenticator, TAP)
    - Security defaults and Conditional Access policies that require MFA for admins
    - Workload identities: app and service principal credentials added within the window,
      apps with credentials expiring soon, and (optional) service principal / user sign-ins from an IOC IP

.PARAMETER AdminUpn
    Admin account used for the interactive Graph sign-in. The tenant is taken from this account.
.PARAMETER StaleDays
    Admins with no sign-in for this many days are flagged.
.PARAMETER CredentialDays
    Credentials added to apps/service principals in this many days are flagged.
.PARAMETER IocIp
    Optional IP address from an advisory. Service principal, managed identity and user sign-ins from it are pulled.
.PARAMETER IocDays
    Days of sign-in logs to search for the IOC IP (max 30).

.NOTES
    Windows PowerShell 5.1 or PowerShell 7. Needs Microsoft.Graph.Authentication only (raw Graph calls).
    Delegated scopes: Directory.Read.All, RoleManagement.Read.Directory, AuditLog.Read.All,
    UserAuthenticationMethod.Read.All, Policy.Read.All, Application.Read.All.
    PIM eligibility needs Entra ID P2. Sign-in activity and registration reports need Entra ID P1.
    Read-only.
#>
[CmdletBinding()]
param(
    [string]$AdminUpn,
    [int]$StaleDays = 90,
    [int]$CredentialDays = 30,
    [string]$IocIp,
    [int]$IocDays = 30
)

#region ---- Common helpers (inline so the script runs standalone or pasted) ----
$ScriptName = 'Get-PrivilegedAccessAudit'
$OutRoot    = Join-Path -Path 'C:\Users\Public\Documents\MspToolkit' -ChildPath (Join-Path -Path $ScriptName -ChildPath (Get-Date -Format 'yyyyMMdd_HHmmss'))
$LogFile    = $null
$Findings   = New-Object System.Collections.Generic.List[object]
try { New-Item -ItemType Directory -Path $OutRoot -Force -ErrorAction Stop | Out-Null; $LogFile = Join-Path -Path $OutRoot -ChildPath 'run.log' }
catch { Write-Host "Could not create output folder $OutRoot : $($_.Exception.Message)" -ForegroundColor Red }

function Write-ToolkitLog {
    param([string]$Message, [ValidateSet('INFO','OK','WARN','ERROR','HEAD')][string]$Level = 'INFO')
    $line  = '{0} [{1}] {2}' -f (Get-Date -Format 'HH:mm:ss'), $Level, $Message
    $color = switch ($Level) { 'OK' {'Green'} 'WARN' {'Yellow'} 'ERROR' {'Red'} 'HEAD' {'Cyan'} default {'Gray'} }
    Write-Host $line -ForegroundColor $color
    if ($LogFile) { try { Add-Content -Path $LogFile -Value $line -Encoding UTF8 -ErrorAction Stop } catch { } }
}
function Add-Finding {
    param([ValidateSet('High','Medium','Low','Info')][string]$Severity, [string]$Area, [string]$Detail)
    $Findings.Add([pscustomobject]@{ Severity = $Severity; Area = $Area; Detail = $Detail })
    $lvl = switch ($Severity) { 'High' {'ERROR'} 'Medium' {'WARN'} default {'INFO'} }
    Write-ToolkitLog ('[{0}] {1}: {2}' -f $Severity, $Area, $Detail) $lvl
}
function Export-Data {
    param([object]$Data, [string]$Name)
    $rows = @($Data)
    if ($rows.Count -eq 0) { Write-ToolkitLog "$Name : no rows"; return }
    $path = Join-Path -Path $OutRoot -ChildPath ($Name + '.csv')
    try { $rows | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8 -ErrorAction Stop; Write-ToolkitLog ('{0}: {1} rows -> {2}' -f $Name, $rows.Count, $path) }
    catch { Write-ToolkitLog "Export of $Name failed: $($_.Exception.Message)" ERROR }
}
function Read-Input {
    param([string]$Value, [string]$Prompt, [switch]$Optional)
    if (-not [string]::IsNullOrWhiteSpace($Value)) { return $Value.Trim() }
    $suffix = ''; if ($Optional) { $suffix = ' (Enter to skip)' }
    $r = Read-Host ($Prompt + $suffix)
    if ([string]::IsNullOrWhiteSpace($r)) { return '' }
    return $r.Trim()
}
function Show-Summary {
    Write-ToolkitLog '==================== FINDINGS ====================' HEAD
    if ($Findings.Count -eq 0) { Write-ToolkitLog 'No findings.' OK }
    else {
        $order  = @{ High = 0; Medium = 1; Low = 2; Info = 3 }
        $sorted = $Findings | Sort-Object @{ Expression = { $order[$_.Severity] } }, Area
        $sorted | Format-Table -AutoSize -Wrap | Out-String -Width 220 | Write-Host
        Export-Data -Data $sorted -Name 'findings'
    }
    Write-ToolkitLog "Output folder: $OutRoot" HEAD
}
function Initialize-Module {
    param([string]$Name)
    if (-not (Get-Module -ListAvailable -Name $Name)) {
        Write-ToolkitLog "Module $Name not installed. Installing for CurrentUser..." WARN
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
            Install-Module -Name $Name -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
        } catch { Write-ToolkitLog "Install of $Name failed: $($_.Exception.Message). Run Install-ToolkitPrereqs.ps1." ERROR; return $false }
    }
    try { Import-Module -Name $Name -ErrorAction Stop -WarningAction SilentlyContinue; return $true }
    catch { Write-ToolkitLog "Import of $Name failed: $($_.Exception.Message)" ERROR; return $false }
}
function Connect-ToolkitGraph {
    param([string]$AdminUpn, [string[]]$Scopes)
    if (-not (Initialize-Module -Name 'Microsoft.Graph.Authentication')) { return $false }
    $tenant = ($AdminUpn -split '@')[-1]
    try {
        $ctx = Get-MgContext
        $missing = @()
        if ($ctx) { $missing = @($Scopes | Where-Object { $ctx.Scopes -notcontains $_ }) }
        if ($ctx -and $ctx.Account -eq $AdminUpn -and $missing.Count -eq 0) { Write-ToolkitLog "Reusing Graph session for $AdminUpn" OK }
        else {
            if ($ctx) { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null }
            Connect-MgGraph -TenantId $tenant -Scopes $Scopes -NoWelcome -ErrorAction Stop
            $ctx = Get-MgContext
        }
        if ($ctx.Account -ne $AdminUpn) { Write-ToolkitLog ('Graph is signed in as {0}, expected {1}. Check which account was picked in the sign-in window.' -f $ctx.Account, $AdminUpn) WARN }
        $org = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/organization?$select=id,displayName' -OutputType PSObject -ErrorAction Stop
        $o = @($org.value)[0]
        Write-ToolkitLog ('Connected to Graph tenant: {0} ({1})' -f $o.displayName, $o.id) OK
        return $true
    } catch { Write-ToolkitLog "Graph connection failed: $($_.Exception.Message)" ERROR; return $false }
}
function Invoke-Graph {
    param([string]$Uri, [string]$Method = 'GET', [object]$Body, [int]$Max = 0, [switch]$Eventual)
    if ($Uri -notmatch '^https://') { $Uri = 'https://graph.microsoft.com/' + $Uri.TrimStart('/') }
    $headers = @{}; if ($Eventual) { $headers['ConsistencyLevel'] = 'eventual' }
    if ($Method -ne 'GET') {
        $p = @{ Method = $Method; Uri = $Uri; Headers = $headers; OutputType = 'PSObject'; ErrorAction = 'Stop' }
        if ($null -ne $Body) { $p.Body = ($Body | ConvertTo-Json -Depth 10); $p.ContentType = 'application/json' }
        return Invoke-MgGraphRequest @p
    }
    $all  = New-Object System.Collections.Generic.List[object]
    $next = $Uri
    while ($next) {
        $resp = Invoke-MgGraphRequest -Method GET -Uri $next -Headers $headers -OutputType PSObject -ErrorAction Stop
        if ($resp.PSObject.Properties.Name -notcontains 'value') { return $resp }
        foreach ($v in @($resp.value)) { $all.Add($v) }
        $next = $resp.'@odata.nextLink'
        if ($Max -gt 0 -and $all.Count -ge $Max) { break }
    }
    return $all
}
function Get-GraphTime { param([datetime]$Date) return $Date.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
#endregion

function Get-MethodClass {
    param([object[]]$Methods)
    $types = @($Methods | ForEach-Object { ([string]$_.'@odata.type') -replace '#microsoft.graph.', '' })
    $phish = @($types | Where-Object { $_ -in @('fido2AuthenticationMethod', 'windowsHelloForBusinessAuthenticationMethod', 'x509CertificateAuthenticationMethod', 'platformCredentialAuthenticationMethod') }).Count -gt 0
    $authApp = $types -contains 'microsoftAuthenticatorAuthenticationMethod'
    $totp    = $types -contains 'softwareOathAuthenticationMethod'
    $phone   = $types -contains 'phoneAuthenticationMethod'
    $class = 'None'
    if ($phish) { $class = 'PhishingResistant' } elseif ($authApp -or $totp) { $class = 'AppOrTotp' } elseif ($phone) { $class = 'SmsVoiceOnly' }
    return [pscustomobject]@{ Class = $class; Types = (($types | Where-Object { $_ -ne 'passwordAuthenticationMethod' } | ForEach-Object { $_ -replace 'AuthenticationMethod$', '' }) -join ', ') }
}

#region ---- Main ----
try {
    Write-ToolkitLog "$ScriptName starting" HEAD
    $AdminUpn = Read-Input -Value $AdminUpn -Prompt 'Admin UPN for Graph sign-in'
    if (-not $AdminUpn) { Write-ToolkitLog 'AdminUpn is required.' ERROR; return }
    if (-not $PSBoundParameters.ContainsKey('IocIp')) { $IocIp = Read-Input -Value $IocIp -Prompt 'IOC IP address to hunt for in sign-in logs' -Optional }
    if ($IocDays -gt 30) { $IocDays = 30 }

    $scopes = @('Directory.Read.All', 'RoleManagement.Read.Directory', 'AuditLog.Read.All', 'UserAuthenticationMethod.Read.All', 'Policy.Read.All', 'Application.Read.All')
    if (-not (Connect-ToolkitGraph -AdminUpn $AdminUpn -Scopes $scopes)) { return }
    $now = Get-Date

    # 1. Role definitions and assignments
    Write-ToolkitLog 'Directory role assignments' HEAD
    $roleDefs = @{}
    foreach ($d in @(Invoke-Graph -Uri 'v1.0/roleManagement/directory/roleDefinitions?$select=id,displayName,isPrivileged,templateId')) { $roleDefs[$d.id] = $d }
    $assignments = New-Object System.Collections.Generic.List[object]
    try {
        foreach ($a in @(Invoke-Graph -Uri 'v1.0/roleManagement/directory/roleAssignments?$expand=principal')) {
            $assignments.Add([pscustomobject]@{ Kind = 'Active'; RoleId = $a.roleDefinitionId; PrincipalId = $a.principalId; Principal = $a.principal; Scope = $a.directoryScopeId })
        }
    } catch { Write-ToolkitLog "Active role assignments failed: $($_.Exception.Message)" ERROR }
    try {
        foreach ($a in @(Invoke-Graph -Uri 'v1.0/roleManagement/directory/roleEligibilitySchedules?$expand=principal')) {
            $assignments.Add([pscustomobject]@{ Kind = 'Eligible'; RoleId = $a.roleDefinitionId; PrincipalId = $a.principalId; Principal = $a.principal; Scope = $a.directoryScopeId })
        }
    } catch { Write-ToolkitLog 'PIM eligible assignments unavailable (needs Entra ID P2)' }

    # 2. Per-principal detail
    $userCache = @{}
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($a in $assignments) {
        $role  = $roleDefs[$a.RoleId]; $roleName = $a.RoleId; if ($role) { $roleName = $role.displayName }
        $ptype = ([string]$a.Principal.'@odata.type') -replace '#microsoft.graph.', ''
        $row = [ordered]@{ Role = $roleName; Privileged = ($role -and $role.isPrivileged); Assignment = $a.Kind; Scope = $a.Scope; PrincipalType = $ptype; Principal = $a.Principal.displayName; UPN = ''; Enabled = ''; UserType = ''; Synced = ''; LastSignIn = ''; MfaClass = ''; Methods = '' }
        if ($ptype -eq 'user') {
            if (-not $userCache.ContainsKey($a.PrincipalId)) {
                $u = $null; $m = $null
                try { $u = Invoke-Graph -Uri ('v1.0/users/{0}?$select=id,userPrincipalName,accountEnabled,userType,onPremisesSyncEnabled,signInActivity' -f $a.PrincipalId) } catch { }
                try { $m = Get-MethodClass -Methods @(Invoke-Graph -Uri ('v1.0/users/{0}/authentication/methods' -f $a.PrincipalId)) } catch { $m = [pscustomobject]@{ Class = 'Unknown'; Types = 'lookup failed' } }
                $userCache[$a.PrincipalId] = @{ User = $u; Methods = $m }
            }
            $c = $userCache[$a.PrincipalId]; $u = $c.User
            if ($u) {
                $last = $u.signInActivity.lastSignInDateTime
                if ($u.signInActivity.lastNonInteractiveSignInDateTime -and (-not $last -or [datetime]$u.signInActivity.lastNonInteractiveSignInDateTime -gt [datetime]$last)) { $last = $u.signInActivity.lastNonInteractiveSignInDateTime }
                $row.UPN = $u.userPrincipalName; $row.Enabled = $u.accountEnabled; $row.UserType = $u.userType; $row.Synced = [bool]$u.onPremisesSyncEnabled; $row.LastSignIn = $last
            }
            $row.MfaClass = $c.Methods.Class; $row.Methods = $c.Methods.Types
        }
        elseif ($ptype -eq 'group') {
            try { $members = @(Invoke-Graph -Uri ('v1.0/groups/{0}/transitiveMembers?$select=userPrincipalName,displayName' -f $a.PrincipalId)); $row.Methods = 'Members: ' + (($members | ForEach-Object { if ($_.userPrincipalName) { $_.userPrincipalName } else { $_.displayName } }) -join '; ') } catch { }
        }
        elseif ($ptype -eq 'servicePrincipal') { $row.UPN = $a.Principal.appId }
        $rows.Add([pscustomobject]$row)
    }
    Export-Data -Data $rows -Name 'role_assignments'
    $rows | Where-Object { $_.Privileged } | Sort-Object Role, Principal | Format-Table Role, Assignment, PrincipalType, Principal, Enabled, LastSignIn, MfaClass -AutoSize | Out-String -Width 220 | Write-Host

    # 3. Admin findings
    $userRows = @($rows | Where-Object { $_.PrincipalType -eq 'user' })
    foreach ($u in ($userRows | Sort-Object UPN -Unique)) {
        $roles = (($userRows | Where-Object { $_.UPN -eq $u.UPN } | Select-Object -ExpandProperty Role -Unique) -join ', ')
        if ($u.Enabled -eq $false) { Add-Finding Medium 'Admin' "$($u.UPN) is disabled but still holds: $roles" }
        if ($u.MfaClass -eq 'None') { Add-Finding High 'Admin MFA' "$($u.UPN) has NO MFA method registered ($roles)" }
        elseif ($u.MfaClass -eq 'SmsVoiceOnly') { Add-Finding High 'Admin MFA' "$($u.UPN) relies on SMS/voice only ($roles)" }
        elseif ($u.MfaClass -eq 'AppOrTotp') { Add-Finding Low 'Admin MFA' "$($u.UPN) has no phishing-resistant method (passkey/FIDO2/WHfB)" }
        if ($u.UserType -eq 'Guest') { Add-Finding High 'Admin' "Guest account $($u.UPN) holds: $roles" }
        if ($u.Synced -eq $true) { Add-Finding Medium 'Admin' "$($u.UPN) is synced from on-prem AD (on-prem compromise reaches the cloud)" }
        if ($u.Enabled -ne $false) {
            if (-not $u.LastSignIn) { Add-Finding Medium 'Admin' "$($u.UPN) has no recorded sign-in ($roles)" }
            elseif (([datetime]$u.LastSignIn) -lt $now.AddDays(-$StaleDays)) { Add-Finding Medium 'Admin' ('{0} last signed in {1} (stale > {2} days)' -f $u.UPN, $u.LastSignIn, $StaleDays) }
        }
    }
    $ga = @($rows | Where-Object { $_.Role -eq 'Global Administrator' -and $_.Assignment -eq 'Active' })
    Write-ToolkitLog "Active Global Administrators: $($ga.Count)"
    if ($ga.Count -lt 2) { Add-Finding Medium 'Global Admin' "Only $($ga.Count) active Global Administrator(s). Microsoft recommends at least 2 (break-glass)." }
    if ($ga.Count -gt 4) { Add-Finding Medium 'Global Admin' "$($ga.Count) active Global Administrators. Microsoft recommends fewer than 5." }
    foreach ($sp in ($rows | Where-Object { $_.PrincipalType -eq 'servicePrincipal' -and $_.Privileged })) { Add-Finding Medium 'Workload identity' "Service principal '$($sp.Principal)' holds privileged role $($sp.Role)" }

    # 4. Tenant MFA registration
    Write-ToolkitLog 'Tenant MFA registration' HEAD
    try {
        $reg = @(Invoke-Graph -Uri 'beta/reports/authenticationMethods/userRegistrationDetails?$top=999')
        $regRows = $reg | Select-Object userPrincipalName, userType, isAdmin, isMfaRegistered, isMfaCapable, isPasswordlessCapable, isSsprRegistered, defaultMfaMethod, @{ n = 'methodsRegistered'; e = { $_.methodsRegistered -join ',' } }, lastUpdatedDateTime
        Export-Data -Data $regRows -Name 'mfa_registration'
        $members = @($reg | Where-Object { $_.userType -eq 'member' })
        $noMfa   = @($members | Where-Object { -not $_.isMfaRegistered })
        $smsOnly = @($members | Where-Object { $_.isMfaRegistered -and @($_.methodsRegistered | Where-Object { $_ -notin @('mobilePhone', 'alternateMobilePhone', 'officePhone', 'email', 'securityQuestion') }).Count -eq 0 })
        Write-ToolkitLog ('Members: {0} | MFA registered: {1} | No MFA: {2} | SMS/voice only: {3} | Passwordless capable: {4}' -f $members.Count, ($members.Count - $noMfa.Count), $noMfa.Count, $smsOnly.Count, @($members | Where-Object { $_.isPasswordlessCapable }).Count)
        if ($noMfa.Count -gt 0)   { Add-Finding Medium 'MFA registration' "$($noMfa.Count) member account(s) have no MFA method (includes shared/room/service accounts, see mfa_registration.csv)" }
        if ($smsOnly.Count -gt 0) { Add-Finding Medium 'MFA registration' "$($smsOnly.Count) member account(s) rely only on phone methods (impacted by SMS/voice retirement)" }
        Export-Data -Data ($smsOnly | Select-Object userPrincipalName, @{ n = 'methods'; e = { $_.methodsRegistered -join ',' } }) -Name 'users_phone_methods_only'
    } catch { Write-ToolkitLog "Registration report unavailable (needs Entra ID P1): $($_.Exception.Message)" WARN }

    # 5. Authentication methods policy
    Write-ToolkitLog 'Authentication methods policy' HEAD
    try {
        $amp = Invoke-Graph -Uri 'v1.0/policies/authenticationMethodsPolicy'
        $ampRows = $amp.authenticationMethodConfigurations | Select-Object id, state
        Export-Data -Data $ampRows -Name 'auth_methods_policy'
        $ampRows | Format-Table -AutoSize | Out-String | Write-Host
        foreach ($c in ($ampRows | Where-Object { $_.id -in @('Sms', 'Voice') -and $_.state -eq 'enabled' })) { Add-Finding Low 'Methods policy' "$($c.id) is enabled in the authentication methods policy" }
        if (-not ($ampRows | Where-Object { $_.id -eq 'Fido2' -and $_.state -eq 'enabled' })) { Add-Finding Low 'Methods policy' 'Passkeys (FIDO2) are not enabled' }
        Write-ToolkitLog ('Policy migration state: {0}' -f $amp.policyMigrationState)
    } catch { Write-ToolkitLog "Authentication methods policy unavailable: $($_.Exception.Message)" WARN }

    # 6. Security defaults and Conditional Access
    Write-ToolkitLog 'Security defaults and Conditional Access' HEAD
    $secDefaults = $false
    try { $sd = Invoke-Graph -Uri 'v1.0/policies/identitySecurityDefaultsEnforcementPolicy'; $secDefaults = [bool]$sd.isEnabled; Write-ToolkitLog "Security defaults enabled: $secDefaults" } catch { Write-ToolkitLog "Security defaults state unavailable: $($_.Exception.Message)" WARN }
    try {
        $ca = @(Invoke-Graph -Uri 'v1.0/identity/conditionalAccess/policies')
        $caRows = foreach ($p in $ca) {
            [pscustomobject]@{
                Name = $p.displayName; State = $p.state
                IncludeUsers = ($p.conditions.users.includeUsers -join ','); IncludeRoles = @($p.conditions.users.includeRoles).Count
                ExcludeUsers = @($p.conditions.users.excludeUsers).Count; ExcludeGroups = @($p.conditions.users.excludeGroups).Count
                Apps = ($p.conditions.applications.includeApplications -join ','); ClientApps = ($p.conditions.clientAppTypes -join ',')
                Grant = ($p.grantControls.builtInControls -join ','); AuthStrength = $p.grantControls.authenticationStrength.displayName
            }
        }
        Export-Data -Data $caRows -Name 'conditional_access'
        $mfaAdmin = @($caRows | Where-Object { $_.State -eq 'enabled' -and ($_.Grant -match 'mfa' -or $_.AuthStrength) -and ($_.IncludeRoles -gt 0 -or $_.IncludeUsers -match 'All') })
        if (-not $secDefaults -and $mfaAdmin.Count -eq 0) { Add-Finding High 'Conditional Access' 'No enabled CA policy requires MFA/auth strength for admins or all users, and security defaults are off' }
        $legacyBlock = @($caRows | Where-Object { $_.State -eq 'enabled' -and $_.ClientApps -match 'exchangeActiveSync|other' -and $_.Grant -match 'block' })
        if (-not $secDefaults -and $legacyBlock.Count -eq 0) { Add-Finding Medium 'Conditional Access' 'No enabled CA policy blocks legacy authentication' }
        foreach ($p in ($caRows | Where-Object { $_.State -eq 'enabledForReportingButNotEnforced' })) { Add-Finding Info 'Conditional Access' "Policy '$($p.Name)' is report-only" }
    } catch { Write-ToolkitLog "Conditional Access unavailable (needs Entra ID P1): $($_.Exception.Message)" WARN }

    # 7. Workload identity credentials
    Write-ToolkitLog 'App and service principal credentials' HEAD
    $credRows = New-Object System.Collections.Generic.List[object]
    foreach ($src in @(@{ Kind = 'Application'; Uri = 'v1.0/applications?$select=id,appId,displayName,passwordCredentials,keyCredentials,createdDateTime&$top=999' }, @{ Kind = 'ServicePrincipal'; Uri = 'v1.0/servicePrincipals?$select=id,appId,displayName,passwordCredentials,keyCredentials,appOwnerOrganizationId,servicePrincipalType&$top=999' })) {
        try {
            foreach ($o in @(Invoke-Graph -Uri $src.Uri)) {
                foreach ($c in @($o.passwordCredentials)) { if ($c) { $credRows.Add([pscustomobject]@{ Kind = $src.Kind; Name = $o.displayName; AppId = $o.appId; CredType = 'Secret'; CredName = $c.displayName; Start = $c.startDateTime; End = $c.endDateTime; KeyId = $c.keyId }) } }
                foreach ($c in @($o.keyCredentials))      { if ($c) { $credRows.Add([pscustomobject]@{ Kind = $src.Kind; Name = $o.displayName; AppId = $o.appId; CredType = 'Certificate'; CredName = $c.displayName; Start = $c.startDateTime; End = $c.endDateTime; KeyId = $c.keyId }) } }
            }
        } catch { Write-ToolkitLog "$($src.Kind) credential query failed: $($_.Exception.Message)" WARN }
    }
    Export-Data -Data $credRows -Name 'workload_credentials'
    foreach ($c in ($credRows | Where-Object { $_.Start -and ([datetime]$_.Start) -gt $now.AddDays(-$CredentialDays) })) { Add-Finding Medium 'Workload identity' ('{0} credential added to {1} "{2}" on {3}' -f $c.CredType, $c.Kind, $c.Name, $c.Start) }
    foreach ($c in ($credRows | Where-Object { $_.End -and ([datetime]$_.End) -gt $now -and ([datetime]$_.End) -lt $now.AddDays(30) })) { Add-Finding Low 'Workload identity' ('{0} on "{1}" expires {2}' -f $c.CredType, $c.Name, $c.End) }
    $spWithSecret = @($credRows | Where-Object { $_.Kind -eq 'ServicePrincipal' -and $_.CredType -eq 'Secret' -and $_.End -and ([datetime]$_.End) -gt $now })
    foreach ($c in $spWithSecret) { Add-Finding Low 'Workload identity' "Service principal '$($c.Name)' has a secret on the SP object itself (not visible in App registrations blade)" }

    # 8. IOC hunt
    if ($IocIp) {
        Write-ToolkitLog "IOC sign-in hunt for $IocIp (last $IocDays days)" HEAD
        $since = Get-GraphTime ((Get-Date).AddDays(-$IocDays))
        $iocRows = New-Object System.Collections.Generic.List[object]
        foreach ($t in 'servicePrincipal', 'managedIdentity', 'interactiveUser', 'nonInteractiveUser') {
            $f = "ipAddress eq '$IocIp' and createdDateTime ge $since and signInEventTypes/any(t: t eq '$t')"
            try {
                foreach ($s in @(Invoke-Graph -Uri ('beta/auditLogs/signIns?$filter={0}&$top=999' -f [uri]::EscapeDataString($f)) -Max 5000)) {
                    $who = $s.userPrincipalName; if (-not $who) { $who = $s.servicePrincipalName }
                    $iocRows.Add([pscustomobject]@{ EventType = $t; Time = $s.createdDateTime; Identity = $who; AppId = $s.appId; App = $s.appDisplayName; Resource = $s.resourceDisplayName; ErrorCode = $s.status.errorCode; Country = $s.location.countryOrRegion })
                }
            } catch { Write-ToolkitLog "IOC query ($t) failed: $($_.Exception.Message)" WARN }
        }
        Export-Data -Data $iocRows -Name 'ioc_signins'
        if ($iocRows.Count -eq 0) { Add-Finding Info 'IOC' "No sign-ins from $IocIp in the last $IocDays days" }
        foreach ($g in ($iocRows | Group-Object EventType, Identity)) {
            $ok = @($g.Group | Where-Object { $_.ErrorCode -eq 0 }).Count
            $sev = 'Medium'; if ($ok -gt 0) { $sev = 'High' }
            Add-Finding $sev 'IOC' ('{0}: {1} sign-in(s) from {2}, {3} successful' -f $g.Name, $g.Count, $IocIp, $ok)
        }
    }
}
catch { Write-ToolkitLog "Unhandled error: $($_.Exception.Message) at line $($_.InvocationInfo.ScriptLineNumber)" ERROR }
finally { Show-Summary }
#endregion
