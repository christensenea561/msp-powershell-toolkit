#Requires -Version 5.1

<#
.SYNOPSIS
    Business email compromise / account takeover investigation for one user, with optional guided remediation.

.DESCRIPTION
    Entra ID (Microsoft Graph):
      - Account state, last password change, risky user state (Entra ID P2)
      - Interactive and non-interactive sign-ins: countries, IPs, legacy auth, suspicious user agents,
        risky sign-ins, failures
      - Authentication methods, including methods added inside the investigation window
      - Directory audit events for the user (security info, password resets, role/app changes)
      - OAuth delegated grants and app role assignments
    Exchange Online:
      - Inbox rules (hidden included) flagged for forward, redirect, delete, RSS/Archive moves, mark-as-read
      - Mailbox forwarding, FullAccess, SendAs, SendOnBehalf
      - Unified audit log for rule, forwarding and permission changes
      - Outbound mail volume per day (spam / phish burst detection)
    Lure (optional): finds every recipient of a phish by sender and/or subject, and can soft-delete it
    from all mailboxes with a compliance search purge.
    Remediation (optional, every action asks first): revoke sessions, block sign-in, disable suspicious
    inbox rules, clear mailbox forwarding.

.PARAMETER AdminUpn
    Admin account for the interactive sign-ins. The tenant is taken from this account.
.PARAMETER UserUpn
    The user being investigated.
.PARAMETER DaysBack
    Investigation window in days (sign-in logs keep 30 days max with Entra ID P1/P2, 7 without).
.PARAMETER SuspectSender
    Sender address of the phishing lure, to find all recipients.
.PARAMETER SuspectSubject
    Subject text of the lure (Contains).
.PARAMETER PurgeLure
    After showing the hit count, offers to soft-delete the lure from all mailboxes (asks for confirmation).
.PARAMETER Remediate
    Offers containment actions at the end, one confirmation per action.
.PARAMETER SkipNonInteractive
    Skip non-interactive sign-ins (they can be very large for busy users).

.NOTES
    Windows PowerShell 5.1 or PowerShell 7. Needs Microsoft.Graph.Authentication and ExchangeOnlineManagement 3.x.
    Graph delegated scopes: User.Read.All, AuditLog.Read.All, Directory.Read.All, UserAuthenticationMethod.Read.All,
    IdentityRiskyUser.Read.All (plus User.ReadWrite.All when -Remediate is used).
    Read-only unless -Remediate or -PurgeLure is used and you confirm.
#>
[CmdletBinding()]
param(
    [string]$AdminUpn,
    [string]$UserUpn,
    [int]$DaysBack = 7,
    [string]$SuspectSender,
    [string]$SuspectSubject,
    [switch]$PurgeLure,
    [switch]$Remediate,
    [switch]$SkipNonInteractive
)

#region ---- Common helpers (inline so the script runs standalone or pasted) ----
$ScriptName = 'Invoke-CompromiseInvestigation'
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
function Confirm-Action {
    param([string]$Text)
    $a = Read-Host ($Text + ' [y/N]')
    return ($a -match '^(y|yes)$')
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
function Connect-ToolkitExo {
    param([string]$AdminUpn)
    if (-not (Initialize-Module -Name 'ExchangeOnlineManagement')) { return $false }
    try {
        $existing = @(Get-ConnectionInformation -ErrorAction SilentlyContinue | Where-Object { $_.State -eq 'Connected' })
        $match    = @($existing | Where-Object { $_.UserPrincipalName -eq $AdminUpn })
        if ($match.Count -gt 0) { Write-ToolkitLog "Reusing Exchange Online session for $AdminUpn" OK }
        else {
            if ($existing.Count -gt 0) { Write-ToolkitLog 'Disconnecting existing Exchange Online session for a different account/tenant' WARN; Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null }
            Connect-ExchangeOnline -UserPrincipalName $AdminUpn -ShowBanner:$false -ErrorAction Stop
        }
        $org = Get-OrganizationConfig -ErrorAction Stop
        Write-ToolkitLog ('Connected to Exchange Online org: {0}' -f $org.DisplayName) OK
        return $true
    } catch { Write-ToolkitLog "Exchange Online connection failed: $($_.Exception.Message)" ERROR; return $false }
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

#region ---- Main ----
try {
    Write-ToolkitLog "$ScriptName starting" HEAD
    $AdminUpn = Read-Input -Value $AdminUpn -Prompt 'Admin UPN for sign-in'
    $UserUpn  = Read-Input -Value $UserUpn  -Prompt 'UPN of the user being investigated'
    if (-not $AdminUpn -or -not $UserUpn) { Write-ToolkitLog 'AdminUpn and UserUpn are required.' ERROR; return }
    if (-not $PSBoundParameters.ContainsKey('SuspectSender'))  { $SuspectSender  = Read-Input -Value $SuspectSender  -Prompt 'Phish lure sender address' -Optional }
    if (-not $PSBoundParameters.ContainsKey('SuspectSubject')) { $SuspectSubject = Read-Input -Value $SuspectSubject -Prompt 'Phish lure subject text'   -Optional }
    if ($DaysBack -lt 1) { $DaysBack = 1 }; if ($DaysBack -gt 30) { $DaysBack = 30; Write-ToolkitLog 'DaysBack capped at 30 (sign-in log retention)' WARN }
    $winStart = (Get-Date).AddDays(-$DaysBack); $winEnd = Get-Date
    $gStart   = Get-GraphTime $winStart

    $scopes = @('User.Read.All', 'AuditLog.Read.All', 'Directory.Read.All', 'UserAuthenticationMethod.Read.All', 'IdentityRiskyUser.Read.All')
    if ($Remediate) { $scopes += 'User.ReadWrite.All' }
    $graphOk = Connect-ToolkitGraph -AdminUpn $AdminUpn -Scopes $scopes
    $exoOk   = Connect-ToolkitExo   -AdminUpn $AdminUpn
    if (-not $graphOk -and -not $exoOk) { return }

    $user = $null
    $suspiciousRules = New-Object System.Collections.Generic.List[object]

    if ($graphOk) {
        # 1. Account
        Write-ToolkitLog 'Account' HEAD
        try {
            $sel  = 'id,displayName,userPrincipalName,accountEnabled,createdDateTime,lastPasswordChangeDateTime,onPremisesSyncEnabled,userType,signInActivity'
            $user = Invoke-Graph -Uri ('v1.0/users/{0}?$select={1}' -f [uri]::EscapeDataString($UserUpn), $sel)
            Write-ToolkitLog ('{0} | enabled={1} | created={2} | pwdChanged={3} | synced={4}' -f $user.displayName, $user.accountEnabled, $user.createdDateTime, $user.lastPasswordChangeDateTime, $user.onPremisesSyncEnabled) OK
            if ($user.lastPasswordChangeDateTime -and ([datetime]$user.lastPasswordChangeDateTime) -gt $winStart) { Add-Finding Info 'Account' "Password changed inside the window: $($user.lastPasswordChangeDateTime)" }
        } catch { Write-ToolkitLog "User lookup failed: $($_.Exception.Message)" ERROR }

        if ($user) {
            try {
                $risk = Invoke-Graph -Uri ('v1.0/identityProtection/riskyUsers/{0}' -f $user.id)
                if ($risk.riskLevel -and $risk.riskLevel -ne 'none') { Add-Finding High 'Identity Protection' ('Risky user: level={0} state={1} detail={2} updated={3}' -f $risk.riskLevel, $risk.riskState, $risk.riskDetail, $risk.riskLastUpdatedDateTime) }
            } catch { Write-ToolkitLog 'Risky user data unavailable (needs Entra ID P2 or user has no risk record)' }

            # 2. Sign-ins
            Write-ToolkitLog 'Sign-in logs' HEAD
            $signIns = New-Object System.Collections.Generic.List[object]
            $queries = @(@{ Label = 'interactive'; Filter = "userId eq '$($user.id)' and createdDateTime ge $gStart"; Version = 'v1.0' })
            if (-not $SkipNonInteractive) { $queries += @{ Label = 'noninteractive'; Filter = "userId eq '$($user.id)' and createdDateTime ge $gStart and signInEventTypes/any(t: t eq 'nonInteractiveUser')"; Version = 'beta' } }
            foreach ($q in $queries) {
                try {
                    $res = @(Invoke-Graph -Uri ('{0}/auditLogs/signIns?$filter={1}&$top=999' -f $q.Version, [uri]::EscapeDataString($q.Filter)) -Max 10000)
                    Write-ToolkitLog ('{0} sign-ins: {1}' -f $q.Label, $res.Count)
                    foreach ($s in $res) {
                        $signIns.Add([pscustomobject]@{
                            Type = $q.Label; Time = $s.createdDateTime; App = $s.appDisplayName; Resource = $s.resourceDisplayName
                            IP = $s.ipAddress; City = $s.location.city; Country = $s.location.countryOrRegion
                            ClientApp = $s.clientAppUsed; UserAgent = $s.userAgent; OS = $s.deviceDetail.operatingSystem; Browser = $s.deviceDetail.browser
                            ErrorCode = $s.status.errorCode; FailureReason = $s.status.failureReason; CAStatus = $s.conditionalAccessStatus
                            AuthRequirement = $s.authenticationRequirement; Risk = $s.riskLevelDuringSignIn; RiskState = $s.riskState
                        })
                    }
                } catch { Write-ToolkitLog ("{0} sign-in query failed: {1}" -f $q.Label, $_.Exception.Message) WARN }
            }
            Export-Data -Data $signIns -Name 'signins'
            $ok = @($signIns | Where-Object { $_.ErrorCode -eq 0 })
            $countries = @($ok | Where-Object { $_.Country } | Group-Object Country | Sort-Object Count -Descending)
            if ($countries.Count -gt 1) { Add-Finding Medium 'Sign-ins' ('Successful sign-ins from {0} countries: {1}' -f $countries.Count, (($countries | ForEach-Object { '{0}({1})' -f $_.Name, $_.Count }) -join ', ')) }
            $ipSummary = $ok | Group-Object IP | Sort-Object Count -Descending | ForEach-Object {
                $f = $_.Group | Select-Object -First 1
                [pscustomobject]@{ IP = $_.Name; Count = $_.Count; City = $f.City; Country = $f.Country; Apps = (($_.Group | Select-Object -ExpandProperty App -Unique) -join '; '); First = ($_.Group | Sort-Object Time | Select-Object -First 1).Time; Last = ($_.Group | Sort-Object Time -Descending | Select-Object -First 1).Time }
            }
            Export-Data -Data $ipSummary -Name 'signins_by_ip'
            Write-Host 'Successful sign-ins by IP (top 15):' -ForegroundColor Cyan
            $ipSummary | Select-Object -First 15 | Format-Table IP, Count, City, Country, Last -AutoSize | Out-String -Width 200 | Write-Host
            $legacy = @($signIns | Where-Object { $_.ClientApp -and $_.ClientApp -notin @('Browser', 'Mobile Apps and Desktop clients') })
            foreach ($g in ($legacy | Group-Object ClientApp)) {
                $succ = @($g.Group | Where-Object { $_.ErrorCode -eq 0 }).Count
                $sev = 'Low'; if ($succ -gt 0) { $sev = 'High' }
                Add-Finding $sev 'Legacy auth' ('{0}: {1} attempt(s), {2} successful' -f $g.Name, $g.Count, $succ)
            }
            $ua = @($signIns | Where-Object { $_.UserAgent -match '(?i)axios|python-requests|BAV2ROPC|curl/|Go-http-client|node-fetch|okhttp' })
            foreach ($g in ($ua | Group-Object UserAgent)) { Add-Finding High 'User agent' ('{0} sign-in(s) with tooling user agent "{1}" from {2}' -f $g.Count, $g.Name, (($g.Group | Select-Object -ExpandProperty IP -Unique) -join ', ')) }
            $risky = @($signIns | Where-Object { $_.Risk -and $_.Risk -notin @('none', 'hidden') })
            foreach ($r in $risky) { Add-Finding High 'Risky sign-in' ('{0} {1} {2} {3} risk={4} result={5}' -f $r.Time, $r.IP, $r.Country, $r.App, $r.Risk, $r.ErrorCode) }
            $mfaDenied = @($signIns | Where-Object { $_.ErrorCode -in @(500121, 50074, 50076) })
            if ($mfaDenied.Count -ge 5) { Add-Finding Medium 'MFA' "$($mfaDenied.Count) MFA-required/failed events (possible MFA fatigue)" }

            # 3. Authentication methods
            Write-ToolkitLog 'Authentication methods' HEAD
            try {
                $methods = @(Invoke-Graph -Uri ('v1.0/users/{0}/authentication/methods' -f $user.id))
                $mRows = foreach ($m in $methods) {
                    $type = ([string]$m.'@odata.type') -replace '#microsoft.graph.', ''
                    [pscustomobject]@{ Type = $type; DisplayName = $m.displayName; Phone = $m.phoneNumber; Device = $m.deviceTag; Created = $m.createdDateTime; Id = $m.id }
                }
                Export-Data -Data $mRows -Name 'auth_methods'
                $mRows | Format-Table Type, DisplayName, Phone, Created -AutoSize | Out-String -Width 200 | Write-Host
                foreach ($m in ($mRows | Where-Object { $_.Created -and ([datetime]$_.Created) -gt $winStart })) { Add-Finding High 'Auth method' ('{0} "{1}" registered {2} (inside window)' -f $m.Type, $m.DisplayName, $m.Created) }
            } catch { Write-ToolkitLog "Auth methods unavailable: $($_.Exception.Message)" WARN }

            # 4. Directory audits
            Write-ToolkitLog 'Directory audit events' HEAD
            $audits = New-Object System.Collections.Generic.List[object]
            foreach ($f in @("targetResources/any(t:t/id eq '$($user.id)') and activityDateTime ge $gStart", "initiatedBy/user/id eq '$($user.id)' and activityDateTime ge $gStart")) {
                try {
                    foreach ($a in @(Invoke-Graph -Uri ('v1.0/auditLogs/directoryAudits?$filter={0}&$top=999' -f [uri]::EscapeDataString($f)) -Max 5000)) {
                        $by = $a.initiatedBy.user.userPrincipalName; if (-not $by) { $by = $a.initiatedBy.app.displayName }
                        $audits.Add([pscustomobject]@{ Time = $a.activityDateTime; Activity = $a.activityDisplayName; Result = $a.result; InitiatedBy = $by; IP = $a.initiatedBy.user.ipAddress; Targets = (($a.targetResources | ForEach-Object { $_.displayName }) -join '; '); Id = $a.id })
                    }
                } catch { Write-ToolkitLog "Directory audit query failed: $($_.Exception.Message)" WARN }
            }
            $audits = @($audits | Sort-Object Id -Unique | Sort-Object Time)
            Export-Data -Data $audits -Name 'directory_audits'
            foreach ($a in ($audits | Where-Object { $_.Activity -match '(?i)security info|reset password|change password|consent|add member to role|add app role|add owner|update application|add service principal credentials|authentication method' })) {
                Add-Finding Medium 'Directory audit' ('{0} {1} by {2} ({3})' -f $a.Time, $a.Activity, $a.InitiatedBy, $a.Targets)
            }

            # 5. OAuth grants and app assignments
            Write-ToolkitLog 'OAuth grants and app assignments' HEAD
            try {
                $grants = @(Invoke-Graph -Uri ('v1.0/users/{0}/oauth2PermissionGrants' -f $user.id))
                $spCache = @{}
                $gRows = foreach ($g in $grants) {
                    if (-not $spCache.ContainsKey($g.clientId)) {
                        try { $sp = Invoke-Graph -Uri ('v1.0/servicePrincipals/{0}?$select=displayName,appId,appOwnerOrganizationId,verifiedPublisher' -f $g.clientId); $spCache[$g.clientId] = $sp } catch { $spCache[$g.clientId] = $null }
                    }
                    $sp = $spCache[$g.clientId]
                    [pscustomobject]@{ App = $sp.displayName; AppId = $sp.appId; Publisher = $sp.verifiedPublisher.displayName; Scope = $g.scope; ConsentType = $g.consentType; ClientSpId = $g.clientId }
                }
                Export-Data -Data $gRows -Name 'oauth_grants'
                foreach ($g in ($gRows | Where-Object { $_.Scope -match '(?i)Mail\.(Read|Send|ReadWrite)|full_access_as_user|offline_access|Files\.ReadWrite' -and -not $_.Publisher })) {
                    Add-Finding Medium 'OAuth' ('Unverified app "{0}" holds delegated scopes: {1}' -f $g.App, $g.Scope)
                }
                $assign = @(Invoke-Graph -Uri ('v1.0/users/{0}/appRoleAssignments' -f $user.id))
                Export-Data -Data ($assign | Select-Object resourceDisplayName, createdDateTime, appRoleId) -Name 'app_role_assignments'
                foreach ($a in ($assign | Where-Object { $_.createdDateTime -and ([datetime]$_.createdDateTime) -gt $winStart })) { Add-Finding Medium 'OAuth' ('App assignment "{0}" created {1} (inside window)' -f $a.resourceDisplayName, $a.createdDateTime) }
            } catch { Write-ToolkitLog "OAuth review failed: $($_.Exception.Message)" WARN }
        }
    }

    $accepted = @()
    if ($exoOk) {
        $accepted = @(Get-AcceptedDomain -ErrorAction SilentlyContinue | ForEach-Object { ([string]$_.DomainName).ToLower() })
        # 6. Mailbox
        Write-ToolkitLog 'Mailbox rules, forwarding and permissions' HEAD
        try {
            $mbx = Get-EXOMailbox -Identity $UserUpn -PropertySets All -ErrorAction Stop
            if ($mbx.ForwardingSmtpAddress -or $mbx.ForwardingAddress) { Add-Finding High 'Forwarding' ('Mailbox forwarding set: {0} {1} (DeliverToMailboxAndForward={2})' -f $mbx.ForwardingSmtpAddress, $mbx.ForwardingAddress, $mbx.DeliverToMailboxAndForward) }
            if (@($mbx.GrantSendOnBehalfTo).Count -gt 0) { Add-Finding Info 'Permissions' "SendOnBehalf: $($mbx.GrantSendOnBehalfTo -join ', ')" }
        } catch { Write-ToolkitLog "Mailbox lookup failed: $($_.Exception.Message)" ERROR }
        try {
            $rules = @(Get-InboxRule -Mailbox $UserUpn -IncludeHidden -ErrorAction Stop)
            $rRows = foreach ($r in $rules) {
                $flags = New-Object System.Collections.Generic.List[string]
                if ($r.ForwardTo -or $r.ForwardAsAttachmentTo -or $r.RedirectTo) { $flags.Add('forwards') }
                if ($r.DeleteMessage -or $r.SoftDeleteMessage) { $flags.Add('deletes') }
                if ([string]$r.MoveToFolder -match '(?i)RSS|Archive|Conversation History|Deleted Items|Junk|Notes') { $flags.Add('moves to ' + $r.MoveToFolder) }
                if ($r.MarkAsRead) { $flags.Add('marks read') }
                if ($r.Name -match '^[\W_]{0,3}$' -or $r.Name.Length -le 2) { $flags.Add('suspicious name') }
                $row = [pscustomobject]@{
                    Name = $r.Name; Enabled = $r.Enabled; Identity = [string]$r.Identity; Flags = ($flags -join ', ')
                    ForwardTo = ($r.ForwardTo -join '; '); RedirectTo = ($r.RedirectTo -join '; '); ForwardAsAttachmentTo = ($r.ForwardAsAttachmentTo -join '; ')
                    MoveToFolder = $r.MoveToFolder; Description = (([string]$r.Description) -replace '\s+', ' ')
                }
                if ($flags.Count -gt 0 -and ($flags -join ',') -ne 'marks read') { $suspiciousRules.Add($row) }
                $row
            }
            Export-Data -Data $rRows -Name 'inbox_rules'
            foreach ($r in $suspiciousRules) { Add-Finding High 'Inbox rule' ('"{0}" (enabled={1}): {2}' -f $r.Name, $r.Enabled, $r.Flags) }
        } catch { Write-ToolkitLog "Inbox rules unavailable: $($_.Exception.Message)" WARN }
        try {
            $fa = @(Get-EXOMailboxPermission -Identity $UserUpn -ErrorAction Stop | Where-Object { -not $_.IsInherited -and $_.User -notmatch '^NT AUTHORITY' })
            Export-Data -Data ($fa | Select-Object User, @{ n = 'AccessRights'; e = { $_.AccessRights -join ',' } }) -Name 'mailbox_fullaccess'
            foreach ($p in $fa) { Add-Finding Info 'Permissions' ('{0} has {1}' -f $p.User, ($p.AccessRights -join ',')) }
            $sa = @(Get-EXORecipientPermission -Identity $UserUpn -ErrorAction Stop | Where-Object { $_.Trustee -notmatch '^NT AUTHORITY' })
            foreach ($p in $sa) { Add-Finding Info 'Permissions' ('{0} has SendAs' -f $p.Trustee) }
        } catch { Write-ToolkitLog "Mailbox permissions unavailable: $($_.Exception.Message)" WARN }

        # 7. Unified audit log
        Write-ToolkitLog 'Unified audit log (mailbox changes)' HEAD
        try {
            $ops = 'New-InboxRule', 'Set-InboxRule', 'UpdateInboxRules', 'Set-Mailbox', 'Add-MailboxPermission', 'Add-RecipientPermission', 'Remove-InboxRule', 'Consent to application.'
            $ual = @(Search-UnifiedAuditLog -StartDate $winStart -EndDate $winEnd -UserIds $UserUpn -Operations $ops -ResultSize 5000 -ErrorAction Stop)
            $uRows = foreach ($u in $ual) {
                $ip = ''; $params = ''
                try { $j = $u.AuditData | ConvertFrom-Json; $ip = $j.ClientIP; if ($j.Parameters) { $params = (($j.Parameters | ForEach-Object { '{0}={1}' -f $_.Name, $_.Value }) -join '; ') } } catch { }
                [pscustomobject]@{ Time = $u.CreationDate; Operation = $u.Operations; User = $u.UserIds; ClientIP = $ip; Parameters = $params }
            }
            Export-Data -Data $uRows -Name 'unified_audit'
            foreach ($u in $uRows) { Add-Finding Medium 'Audit log' ('{0} {1} from {2} {3}' -f $u.Time, $u.Operation, $u.ClientIP, $u.Parameters) }
        } catch { Write-ToolkitLog "Unified audit log search failed (auditing disabled or no permission): $($_.Exception.Message)" WARN }

        # 8. Outbound volume
        Write-ToolkitLog 'Outbound mail volume' HEAD
        $sent = New-Object System.Collections.Generic.List[object]
        $cursor = $winStart
        while ($cursor -lt $winEnd) {
            $sliceEnd = $cursor.AddDays(10); if ($sliceEnd -gt $winEnd) { $sliceEnd = $winEnd }
            try { foreach ($m in @(Get-MessageTraceV2 -SenderAddress $UserUpn -StartDate $cursor -EndDate $sliceEnd -ResultSize 5000 -ErrorAction Stop)) { $sent.Add($m) } }
            catch { Write-ToolkitLog "Outbound trace failed: $($_.Exception.Message)" WARN }
            $cursor = $sliceEnd
        }
        Export-Data -Data ($sent | Select-Object Received, RecipientAddress, Subject, Status, FromIP) -Name 'outbound_trace'
        $perDay = @($sent | Group-Object { ([datetime]$_.Received).ToString('yyyy-MM-dd') } | Sort-Object Name)
        foreach ($d in $perDay) {
            $ext = @($d.Group | Where-Object { $accepted -notcontains (([string]$_.RecipientAddress) -split '@')[-1].ToLower() }).Count
            Write-ToolkitLog ('{0}: {1} sent ({2} external)' -f $d.Name, $d.Count, $ext)
        }
        if ($perDay.Count -gt 0) {
            $avg = ($perDay | Measure-Object Count -Average).Average
            foreach ($d in ($perDay | Where-Object { $_.Count -ge 100 -and $_.Count -ge (3 * $avg) })) { Add-Finding High 'Outbound' ('Send spike on {0}: {1} messages (average {2:N0}/day)' -f $d.Name, $d.Count, $avg) }
        }
        $sentIps = @($sent | Where-Object { $_.FromIP } | Select-Object -ExpandProperty FromIP -Unique)
        if ($sentIps.Count -gt 0) { Write-ToolkitLog ('Client IPs seen on outbound mail: {0}' -f ($sentIps -join ', ')) }

        # 9. Lure
        if ($SuspectSender -or $SuspectSubject) {
            Write-ToolkitLog 'Phish lure recipients' HEAD
            $lure = New-Object System.Collections.Generic.List[object]
            $cursor = $winStart
            while ($cursor -lt $winEnd) {
                $sliceEnd = $cursor.AddDays(10); if ($sliceEnd -gt $winEnd) { $sliceEnd = $winEnd }
                $p = @{ StartDate = $cursor; EndDate = $sliceEnd; ResultSize = 5000; ErrorAction = 'Stop' }
                if ($SuspectSender)  { $p.SenderAddress = $SuspectSender }
                if ($SuspectSubject) { $p.Subject = $SuspectSubject; $p.SubjectFilterType = 'Contains' }
                try { foreach ($m in @(Get-MessageTraceV2 @p)) { $lure.Add($m) } } catch { Write-ToolkitLog "Lure trace failed: $($_.Exception.Message)" WARN }
                $cursor = $sliceEnd
            }
            Export-Data -Data ($lure | Select-Object Received, SenderAddress, RecipientAddress, Subject, Status, FromIP) -Name 'lure_recipients'
            $delivered = @($lure | Where-Object { $_.Status -eq 'Delivered' })
            if ($lure.Count -gt 0) { Add-Finding High 'Lure' ('{0} lure message(s) found, {1} delivered to {2} unique recipient(s)' -f $lure.Count, $delivered.Count, @($delivered | Select-Object -ExpandProperty RecipientAddress -Unique).Count) }
            else { Add-Finding Info 'Lure' 'No messages matched the lure sender/subject in the window' }

            if ($PurgeLure -and $delivered.Count -gt 0) {
                try {
                    Connect-IPPSSession -UserPrincipalName $AdminUpn -ErrorAction Stop
                    $parts = @()
                    if ($SuspectSender)  { $parts += ('from:"{0}"' -f $SuspectSender) }
                    if ($SuspectSubject) { $parts += ('subject:"{0}"' -f $SuspectSubject) }
                    $parts += ('received>={0}' -f $winStart.ToString('yyyy-MM-dd'))
                    $query = $parts -join ' AND '
                    $name  = 'MspToolkit-Lure-' + (Get-Date -Format 'yyyyMMddHHmmss')
                    Write-ToolkitLog "Compliance search '$name' query: $query"
                    New-ComplianceSearch -Name $name -ExchangeLocation All -ContentMatchQuery $query -ErrorAction Stop | Out-Null
                    Start-ComplianceSearch -Identity $name -ErrorAction Stop
                    $deadline = (Get-Date).AddMinutes(15)
                    do { Start-Sleep -Seconds 15; $cs = Get-ComplianceSearch -Identity $name; Write-ToolkitLog "Search status: $($cs.Status)" } while ($cs.Status -ne 'Completed' -and (Get-Date) -lt $deadline)
                    Write-ToolkitLog ('Search found {0} item(s)' -f $cs.Items) OK
                    if ($cs.Status -eq 'Completed' -and $cs.Items -gt 0 -and (Confirm-Action ("Soft-delete {0} item(s) matching the lure from all mailboxes?" -f $cs.Items))) {
                        New-ComplianceSearchAction -SearchName $name -Purge -PurgeType SoftDelete -Confirm:$false -ErrorAction Stop | Out-Null
                        Add-Finding Info 'Lure' "Purge (SoftDelete) submitted for search $name. Check status with Get-ComplianceSearchAction '${name}_Purge'. Purge removes max 10 items per mailbox per run."
                    }
                } catch { Write-ToolkitLog "Lure purge failed: $($_.Exception.Message)" ERROR }
            }
        }
    }

    # 10. Remediation
    if ($Remediate) {
        Write-ToolkitLog 'Remediation (each action asks first)' HEAD
        if ($graphOk -and $user) {
            if (Confirm-Action "Revoke all sign-in sessions and refresh tokens for $UserUpn?") {
                try { Invoke-Graph -Method POST -Uri ('v1.0/users/{0}/revokeSignInSessions' -f $user.id) | Out-Null; Add-Finding Info 'Remediation' 'Sign-in sessions revoked' } catch { Write-ToolkitLog "Revoke failed: $($_.Exception.Message)" ERROR }
            }
            if ($user.accountEnabled -and (Confirm-Action "Block sign-in (accountEnabled = false) for $UserUpn?")) {
                if ($user.onPremisesSyncEnabled) { Write-ToolkitLog 'User is synced from AD: disable the AD account too or the next sync re-enables it.' WARN }
                try { Invoke-Graph -Method PATCH -Uri ('v1.0/users/{0}' -f $user.id) -Body @{ accountEnabled = $false } | Out-Null; Add-Finding Info 'Remediation' 'Sign-in blocked' } catch { Write-ToolkitLog "Block sign-in failed: $($_.Exception.Message)" ERROR }
            }
        }
        if ($exoOk) {
            foreach ($r in ($suspiciousRules | Where-Object { $_.Enabled })) {
                if (Confirm-Action ('Disable inbox rule "{0}" ({1})?' -f $r.Name, $r.Flags)) {
                    try { Disable-InboxRule -Identity $r.Identity -Confirm:$false -ErrorAction Stop; Add-Finding Info 'Remediation' "Inbox rule '$($r.Name)' disabled" } catch { Write-ToolkitLog "Disable rule failed: $($_.Exception.Message)" ERROR }
                }
            }
            try {
                $mbx = Get-EXOMailbox -Identity $UserUpn -Properties ForwardingSmtpAddress, ForwardingAddress -ErrorAction Stop
                if (($mbx.ForwardingSmtpAddress -or $mbx.ForwardingAddress) -and (Confirm-Action 'Clear mailbox forwarding?')) {
                    Set-Mailbox -Identity $UserUpn -ForwardingSmtpAddress $null -ForwardingAddress $null -DeliverToMailboxAndForward $false -ErrorAction Stop
                    Add-Finding Info 'Remediation' 'Mailbox forwarding cleared'
                }
            } catch { Write-ToolkitLog "Forwarding remediation failed: $($_.Exception.Message)" ERROR }
        }
        Write-ToolkitLog 'Still manual: reset the password (and in AD if synced), review/remove unknown MFA methods and OAuth grants listed above.' WARN
    }
}
catch { Write-ToolkitLog "Unhandled error: $($_.Exception.Message) at line $($_.InvocationInfo.ScriptLineNumber)" ERROR }
finally { Show-Summary }
#endregion
