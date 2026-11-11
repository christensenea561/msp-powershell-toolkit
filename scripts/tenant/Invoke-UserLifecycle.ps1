#Requires -Version 5.1

<#
.SYNOPSIS
    Cloud-only user onboarding and offboarding for Microsoft 365 (Entra ID, Exchange Online, OneDrive).

.DESCRIPTION
    Onboard:
      - Validates the UPN domain, checks the UPN is free, generates a strong temporary password
      - Creates the user with profile fields, sets the manager and usage location
      - Assigns licenses by SKU part number after checking available seats
      - Copies group memberships from a template user and/or adds named groups
        (Graph for security/M365 groups, Exchange for distribution lists and mail-enabled security groups)
      - Skips dynamic and AD-synced groups and reports them
    Offboard (asks you to type the UPN before any change):
      - Snapshot of groups, licenses, owned devices and mailbox permissions to CSV first
      - Blocks sign-in, revokes sessions, resets the password (cloud-only accounts)
      - Exchange: auto-reply, forwarding, FullAccess delegate, hide from GAL, convert to shared,
        removes distribution list memberships, lists mobile devices
      - Removes Entra group memberships (assigned membership only) and flags owned groups
      - Grants a delegate site collection admin on the user's OneDrive
      - Removes directly assigned licenses when the shared mailbox does not need one

.PARAMETER AdminUpn
    Admin account for the interactive sign-ins. The tenant is taken from this account.
.PARAMETER Action
    Onboard or Offboard.
.PARAMETER UserUpn
    UPN of the user to create or offboard.
.PARAMETER FirstName
    Onboard: given name.
.PARAMETER LastName
    Onboard: surname.
.PARAMETER DisplayName
    Onboard: display name (defaults to "First Last").
.PARAMETER JobTitle
    Onboard: job title (defaults to the template user's).
.PARAMETER Department
    Onboard: department (defaults to the template user's).
.PARAMETER Office
    Onboard: office location (defaults to the template user's).
.PARAMETER MobilePhone
    Onboard: mobile phone.
.PARAMETER ManagerUpn
    Onboard: manager UPN (defaults to the template user's manager).
.PARAMETER UsageLocation
    Onboard: two-letter usage location, required for licensing.
.PARAMETER LicenseSkus
    Onboard: comma-separated SKU part numbers, for example SPE_E3,EXCHANGESTANDARD. Defaults to the template user's direct licenses.
.PARAMETER CopyFromUpn
    Onboard: template user whose groups (and blank profile fields) are copied.
.PARAMETER Groups
    Onboard: extra groups by display name or email, comma-separated.
.PARAMETER ForwardToUpn
    Offboard: internal recipient to forward mail to (copy kept in the mailbox).
.PARAMETER MailboxAccessUpn
    Offboard: user granted FullAccess to the mailbox.
.PARAMETER OneDriveAccessUpn
    Offboard: user granted site collection admin on the OneDrive.
.PARAMETER AutoReplyMessage
    Offboard: auto-reply text for internal and external senders.
.PARAMETER SharePointAdminUrl
    Offboard: override for the SharePoint admin URL, e.g. https://contoso-admin.sharepoint.com
.PARAMETER KeepLicenses
    Offboard: do not remove licenses.
.PARAMETER SkipConvertToShared
    Offboard: leave the mailbox as a user mailbox.
.PARAMETER SkipGroupRemoval
    Offboard: keep group and distribution list memberships.

.NOTES
    Windows PowerShell 5.1 or PowerShell 7. Microsoft.Graph.Authentication, ExchangeOnlineManagement 3.x,
    and Microsoft.Online.SharePoint.PowerShell for the OneDrive step.
    Graph delegated scopes: User.ReadWrite.All, Group.ReadWrite.All, Directory.ReadWrite.All, Organization.Read.All.
    MAKES CHANGES. Hybrid (AD-synced) users must be handled in AD for identity and group changes.
#>
[CmdletBinding()]
param(
    [string]$AdminUpn,
    [ValidateSet('Onboard', 'Offboard')][string]$Action,
    [string]$UserUpn,
    [string]$FirstName,
    [string]$LastName,
    [string]$DisplayName,
    [string]$JobTitle,
    [string]$Department,
    [string]$Office,
    [string]$MobilePhone,
    [string]$ManagerUpn,
    [string]$UsageLocation = 'US',
    [string]$LicenseSkus,
    [string]$CopyFromUpn,
    [string]$Groups,
    [string]$ForwardToUpn,
    [string]$MailboxAccessUpn,
    [string]$OneDriveAccessUpn,
    [string]$AutoReplyMessage,
    [string]$SharePointAdminUrl,
    [switch]$KeepLicenses,
    [switch]$SkipConvertToShared,
    [switch]$SkipGroupRemoval
)

#region ---- Common helpers (inline so the script runs standalone or pasted) ----
$ScriptName = 'Invoke-UserLifecycle'
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
    Write-ToolkitLog '==================== RESULTS ====================' HEAD
    if ($Findings.Count -eq 0) { Write-ToolkitLog 'No findings.' OK }
    else {
        $order  = @{ High = 0; Medium = 1; Low = 2; Info = 3 }
        $sorted = $Findings | Sort-Object @{ Expression = { $order[$_.Severity] } }, Area
        $sorted | Format-Table -AutoSize -Wrap | Out-String -Width 220 | Write-Host
        Export-Data -Data $sorted -Name 'results'
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
        $org = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/organization?$select=id,displayName,verifiedDomains' -OutputType PSObject -ErrorAction Stop
        $script:TenantOrg = @($org.value)[0]
        Write-ToolkitLog ('Connected to Graph tenant: {0} ({1})' -f $script:TenantOrg.displayName, $script:TenantOrg.id) OK
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
#endregion

function New-TempPassword {
    param([int]$Length = 16)
    $sets = @('ABCDEFGHJKLMNPQRSTUVWXYZ', 'abcdefghijkmnopqrstuvwxyz', '23456789', '!@#$%*-_=+?')
    $all  = -join $sets
    $rng  = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
    $buf  = New-Object byte[] 4
    $pick = { param($s) $rng.GetBytes($buf); $s[[int]([BitConverter]::ToUInt32($buf, 0) % [uint32]$s.Length)] }
    $chars = New-Object System.Collections.Generic.List[char]
    foreach ($s in $sets) { $chars.Add((& $pick $s)) }
    while ($chars.Count -lt $Length) { $chars.Add((& $pick $all)) }
    $shuffled = $chars | Sort-Object { $rng.GetBytes($buf); [BitConverter]::ToUInt32($buf, 0) }
    return (-join $shuffled)
}
function Get-GroupKind {
    param([object]$G)
    if (@($G.groupTypes) -contains 'DynamicMembership') { return 'Dynamic' }
    if ($G.onPremisesSyncEnabled) { return 'Synced' }
    if (@($G.groupTypes) -contains 'Unified') { return 'Graph' }
    if ($G.mailEnabled) { return 'Exchange' }
    if ($G.securityEnabled) { return 'Graph' }
    return 'Unknown'
}
function Resolve-GraphUser {
    param([string]$Upn, [string]$Select = 'id,userPrincipalName,displayName')
    try { return Invoke-Graph -Uri ('v1.0/users/{0}?$select={1}' -f [uri]::EscapeDataString($Upn), $Select) } catch { return $null }
}

#region ---- Onboard ----
function Invoke-Onboard {
    Write-ToolkitLog "Onboarding $UserUpn" HEAD
    $domain = ($UserUpn -split '@')[-1].ToLower()
    $verified = @($script:TenantOrg.verifiedDomains | ForEach-Object { ([string]$_.name).ToLower() })
    if ($verified -notcontains $domain) { Add-Finding High 'Validation' "$domain is not a verified domain in this tenant"; return }
    if (Resolve-GraphUser -Upn $UserUpn) { Add-Finding High 'Validation' "$UserUpn already exists"; return }

    $tpl = $null; $tplGroups = @(); $tplSkus = @(); $tplManager = $null
    if ($CopyFromUpn) {
        $tpl = Resolve-GraphUser -Upn $CopyFromUpn -Select 'id,userPrincipalName,displayName,jobTitle,department,officeLocation,usageLocation,companyName'
        if (-not $tpl) { Add-Finding High 'Template' "Template user $CopyFromUpn not found"; return }
        $tplGroups = @(Invoke-Graph -Uri ('v1.0/users/{0}/memberOf/microsoft.graph.group?$select=id,displayName,mail,groupTypes,mailEnabled,securityEnabled,onPremisesSyncEnabled,isAssignableToRole' -f $tpl.id))
        $tplSkus   = @(Invoke-Graph -Uri ('v1.0/users/{0}/licenseDetails?$select=skuPartNumber' -f $tpl.id) | ForEach-Object { $_.skuPartNumber })
        try { $tplManager = Invoke-Graph -Uri ('v1.0/users/{0}/manager?$select=id,userPrincipalName' -f $tpl.id) } catch { }
        Write-ToolkitLog ('Template {0}: {1} group(s), licenses: {2}' -f $CopyFromUpn, $tplGroups.Count, ($tplSkus -join ', '))
        if (-not $JobTitle)   { $script:JobTitle   = $tpl.jobTitle }
        if (-not $Department) { $script:Department = $tpl.department }
        if (-not $Office)     { $script:Office     = $tpl.officeLocation }
    }

    if (-not $DisplayName) { $script:DisplayName = ('{0} {1}' -f $FirstName, $LastName).Trim() }
    $alias = (($UserUpn -split '@')[0]) -replace '[^A-Za-z0-9._-]', ''
    $tempPass   = New-TempPassword
    $body = @{
        accountEnabled = $true; displayName = $DisplayName; mailNickname = $alias; userPrincipalName = $UserUpn; usageLocation = $UsageLocation.ToUpper()
        passwordProfile = @{ forceChangePasswordNextSignIn = $true; password = $tempPass }
    }
    if ($FirstName)   { $body.givenName = $FirstName }
    if ($LastName)    { $body.surname = $LastName }
    if ($JobTitle)    { $body.jobTitle = $JobTitle }
    if ($Department)  { $body.department = $Department }
    if ($Office)      { $body.officeLocation = $Office }
    if ($MobilePhone) { $body.mobilePhone = $MobilePhone }
    if ($tpl -and $tpl.companyName) { $body.companyName = $tpl.companyName }

    try { $new = Invoke-Graph -Method POST -Uri 'v1.0/users' -Body $body; Add-Finding Info 'User' "Created $UserUpn ($($new.id))" }
    catch { Add-Finding High 'User' "Create failed: $($_.Exception.Message)"; return }

    # Manager
    $mgrId = $null
    if ($ManagerUpn) { $m = Resolve-GraphUser -Upn $ManagerUpn; if ($m) { $mgrId = $m.id } else { Add-Finding Medium 'Manager' "$ManagerUpn not found" } }
    elseif ($tplManager) { $mgrId = $tplManager.id; Write-ToolkitLog "Using template manager $($tplManager.userPrincipalName)" }
    if ($mgrId) {
        try { Invoke-Graph -Method PUT -Uri ('v1.0/users/{0}/manager/$ref' -f $new.id) -Body @{ '@odata.id' = ('https://graph.microsoft.com/v1.0/users/{0}' -f $mgrId) } | Out-Null; Add-Finding Info 'Manager' 'Manager set' }
        catch { Add-Finding Medium 'Manager' "Set manager failed: $($_.Exception.Message)" }
    }

    # Licenses
    $wanted = @($LicenseSkus -split '[,;\s]+' | Where-Object { $_ })
    if ($wanted.Count -eq 0) { $wanted = $tplSkus }
    if ($wanted.Count -gt 0) {
        $skus = @(Invoke-Graph -Uri 'v1.0/subscribedSkus?$select=skuId,skuPartNumber,prepaidUnits,consumedUnits')
        $add = @()
        foreach ($w in $wanted) {
            $s = $skus | Where-Object { $_.skuPartNumber -eq $w } | Select-Object -First 1
            if (-not $s) { Add-Finding High 'License' "SKU $w is not in this tenant"; continue }
            $free = [int]$s.prepaidUnits.enabled - [int]$s.consumedUnits
            if ($free -le 0) { Add-Finding High 'License' "No free seats for $w ($($s.consumedUnits)/$($s.prepaidUnits.enabled) used)"; continue }
            $add += @{ skuId = $s.skuId; disabledPlans = @() }
        }
        if ($add.Count -gt 0) {
            try { Invoke-Graph -Method POST -Uri ('v1.0/users/{0}/assignLicense' -f $new.id) -Body @{ addLicenses = $add; removeLicenses = @() } | Out-Null; Add-Finding Info 'License' ('Assigned: {0}' -f ($wanted -join ', ')) }
            catch { Add-Finding High 'License' "Assign failed: $($_.Exception.Message)" }
        }
    } else { Add-Finding Medium 'License' 'No licenses specified or found on the template user' }

    # Groups
    $targets = New-Object System.Collections.Generic.List[object]
    foreach ($g in $tplGroups) { $targets.Add($g) }
    foreach ($name in @($Groups -split '[,;]' | ForEach-Object { $_.Trim() } | Where-Object { $_ })) {
        $f = "displayName eq '{0}' or mail eq '{0}'" -f ($name -replace "'", "''")
        $hit = @(Invoke-Graph -Uri ('v1.0/groups?$filter={0}&$select=id,displayName,mail,groupTypes,mailEnabled,securityEnabled,onPremisesSyncEnabled,isAssignableToRole' -f [uri]::EscapeDataString($f)))
        if ($hit.Count -eq 0) { Add-Finding Medium 'Group' "Group '$name' not found" } else { $targets.Add($hit[0]) }
    }
    $targets = @($targets | Sort-Object id -Unique)
    $exoQueue = New-Object System.Collections.Generic.List[object]
    foreach ($g in $targets) {
        switch (Get-GroupKind -G $g) {
            'Dynamic'  { Add-Finding Info 'Group' "Skipped dynamic group '$($g.displayName)' (rule-based)" }
            'Synced'   { Add-Finding Medium 'Group' "'$($g.displayName)' is synced from AD: add the user in AD" }
            'Exchange' { $exoQueue.Add($g) }
            'Graph'    {
                try { Invoke-Graph -Method POST -Uri ('v1.0/groups/{0}/members/$ref' -f $g.id) -Body @{ '@odata.id' = ('https://graph.microsoft.com/v1.0/directoryObjects/{0}' -f $new.id) } | Out-Null; Write-ToolkitLog "Added to $($g.displayName)" OK }
                catch { Add-Finding Medium 'Group' "Add to '$($g.displayName)' failed: $($_.Exception.Message)" }
            }
            default    { Add-Finding Low 'Group' "Unknown group type for '$($g.displayName)', skipped" }
        }
    }
    if ($exoQueue.Count -gt 0) {
        if (Connect-ToolkitExo -AdminUpn $AdminUpn) {
            Write-ToolkitLog 'Waiting for the mailbox/recipient to provision before adding distribution lists (up to 10 minutes)...'
            $deadline = (Get-Date).AddMinutes(10); $rcpt = $null
            while (-not $rcpt -and (Get-Date) -lt $deadline) { $rcpt = Get-EXORecipient -Identity $UserUpn -ErrorAction SilentlyContinue; if (-not $rcpt) { Start-Sleep -Seconds 30 } }
            foreach ($g in $exoQueue) {
                if (-not $rcpt) { Add-Finding Medium 'Distribution list' "Recipient not provisioned yet: add to '$($g.displayName)' later"; continue }
                try { Add-DistributionGroupMember -Identity $g.id -Member $UserUpn -BypassSecurityGroupManagerCheck -ErrorAction Stop; Write-ToolkitLog "Added to DL $($g.displayName)" OK }
                catch { Add-Finding Medium 'Distribution list' "Add to '$($g.displayName)' failed: $($_.Exception.Message)" }
            }
        } else { foreach ($g in $exoQueue) { Add-Finding Medium 'Distribution list' "Exchange not connected: add to '$($g.displayName)' manually" } }
    }

    Write-Host ''
    Write-Host ('Temporary password for {0} (shown once, not logged): {1}' -f $UserUpn, $tempPass) -ForegroundColor Yellow
    Write-Host 'User must change it at first sign-in.' -ForegroundColor Yellow
}
#endregion

#region ---- Offboard ----
function Invoke-Offboard {
    Write-ToolkitLog "Offboarding $UserUpn" HEAD
    $u = Resolve-GraphUser -Upn $UserUpn -Select 'id,userPrincipalName,displayName,accountEnabled,onPremisesSyncEnabled,licenseAssignmentStates,assignedLicenses'
    if (-not $u) { Add-Finding High 'Validation' "$UserUpn not found"; return }
    Write-ToolkitLog ('{0} | enabled={1} | synced={2}' -f $u.displayName, $u.accountEnabled, [bool]$u.onPremisesSyncEnabled)
    $confirm = Read-Host "Type the UPN ($UserUpn) to confirm offboarding"
    if ($confirm -ne $UserUpn) { Add-Finding Info 'Validation' 'Confirmation did not match. No changes made.'; return }
    $synced = [bool]$u.onPremisesSyncEnabled

    # Snapshot
    $groups = @(Invoke-Graph -Uri ('v1.0/users/{0}/memberOf/microsoft.graph.group?$select=id,displayName,mail,groupTypes,mailEnabled,securityEnabled,onPremisesSyncEnabled' -f $u.id))
    Export-Data -Data ($groups | Select-Object displayName, mail, id, @{ n = 'Kind'; e = { Get-GroupKind -G $_ } }) -Name 'snapshot_groups'
    $lic = @(Invoke-Graph -Uri ('v1.0/users/{0}/licenseDetails?$select=skuId,skuPartNumber' -f $u.id))
    Export-Data -Data ($lic | Select-Object skuPartNumber, skuId) -Name 'snapshot_licenses'
    try { Export-Data -Data (@(Invoke-Graph -Uri ('v1.0/users/{0}/ownedDevices?$select=displayName,operatingSystem,deviceId' -f $u.id)) | Select-Object displayName, operatingSystem, deviceId) -Name 'snapshot_owned_devices' } catch { }
    $owned = @()
    try { $owned = @(Invoke-Graph -Uri ('v1.0/users/{0}/ownedObjects/microsoft.graph.group?$select=id,displayName' -f $u.id)) } catch { }
    foreach ($o in $owned) { Add-Finding Medium 'Ownership' "User owns group '$($o.displayName)': assign a new owner" }

    # Identity
    if ($synced) { Add-Finding High 'Identity' 'User is synced from AD: disable the AD account and reset the password on-prem, or the next sync re-enables sign-in' }
    try { Invoke-Graph -Method PATCH -Uri ('v1.0/users/{0}' -f $u.id) -Body @{ accountEnabled = $false } | Out-Null; Add-Finding Info 'Identity' 'Sign-in blocked' } catch { Add-Finding High 'Identity' "Block sign-in failed: $($_.Exception.Message)" }
    try { Invoke-Graph -Method POST -Uri ('v1.0/users/{0}/revokeSignInSessions' -f $u.id) | Out-Null; Add-Finding Info 'Identity' 'Sessions revoked' } catch { Add-Finding Medium 'Identity' "Revoke failed: $($_.Exception.Message)" }
    if (-not $synced) {
        try { Invoke-Graph -Method PATCH -Uri ('v1.0/users/{0}' -f $u.id) -Body @{ passwordProfile = @{ forceChangePasswordNextSignIn = $true; password = (New-TempPassword -Length 24) } } | Out-Null; Add-Finding Info 'Identity' 'Password reset to a random value' }
        catch { Add-Finding Medium 'Identity' "Password reset failed: $($_.Exception.Message)" }
    }

    # Exchange
    $licenseSafe = $true
    if (Connect-ToolkitExo -AdminUpn $AdminUpn) {
        $mbx = $null
        try { $mbx = Get-EXOMailbox -Identity $UserUpn -PropertySets All -ErrorAction Stop } catch { Add-Finding Info 'Mailbox' 'No mailbox found' }
        if ($mbx) {
            try { Export-Data -Data (Get-EXOMailboxPermission -Identity $UserUpn -ErrorAction Stop | Where-Object { -not $_.IsInherited } | Select-Object User, @{ n = 'AccessRights'; e = { $_.AccessRights -join ',' } }) -Name 'snapshot_mailbox_permissions' } catch { }
            if ($AutoReplyMessage) {
                try { Set-MailboxAutoReplyConfiguration -Identity $UserUpn -AutoReplyState Enabled -InternalMessage $AutoReplyMessage -ExternalMessage $AutoReplyMessage -ExternalAudience All -ErrorAction Stop; Add-Finding Info 'Mailbox' 'Auto-reply enabled' }
                catch { Add-Finding Medium 'Mailbox' "Auto-reply failed: $($_.Exception.Message)" }
            }
            if ($ForwardToUpn) {
                try { Set-Mailbox -Identity $UserUpn -ForwardingAddress $ForwardToUpn -DeliverToMailboxAndForward $true -ErrorAction Stop; Add-Finding Info 'Mailbox' "Forwarding to $ForwardToUpn (copy kept)" }
                catch { Add-Finding Medium 'Mailbox' "Forwarding failed: $($_.Exception.Message)" }
            }
            try {
                $st = Get-EXOMailboxStatistics -Identity $UserUpn -ErrorAction Stop
                $m = [regex]::Match([string]$st.TotalItemSize, '\(([\d,]+) bytes\)'); $gb = 0
                if ($m.Success) { $gb = [math]::Round(([int64]($m.Groups[1].Value -replace ',', '')) / 1GB, 1) }
                Write-ToolkitLog "Mailbox size: $gb GB"
                if ($gb -ge 50) { $licenseSafe = $false; Add-Finding High 'License' "Mailbox is $gb GB: a shared mailbox over 50 GB needs a license" }
            } catch { }
            if ($mbx.LitigationHoldEnabled -or @($mbx.InPlaceHolds).Count -gt 0) { $licenseSafe = $false; Add-Finding High 'License' 'Mailbox is on hold: keep an Exchange Plan 2 / E3+ license' }
            if ([string]$mbx.ArchiveStatus -eq 'Active') { $licenseSafe = $false; Add-Finding Medium 'License' 'Archive mailbox is active: a shared mailbox with an archive needs a license' }
            if (-not $SkipConvertToShared -and $mbx.RecipientTypeDetails -eq 'UserMailbox') {
                try { Set-Mailbox -Identity $UserUpn -Type Shared -ErrorAction Stop; Add-Finding Info 'Mailbox' 'Converted to shared' } catch { $licenseSafe = $false; Add-Finding High 'Mailbox' "Convert to shared failed: $($_.Exception.Message)" }
            } elseif ($SkipConvertToShared) { $licenseSafe = $false }
            if ($MailboxAccessUpn) {
                try { Add-MailboxPermission -Identity $UserUpn -User $MailboxAccessUpn -AccessRights FullAccess -InheritanceType All -AutoMapping $true -ErrorAction Stop | Out-Null; Add-Finding Info 'Mailbox' "FullAccess granted to $MailboxAccessUpn" }
                catch { Add-Finding Medium 'Mailbox' "FullAccess grant failed: $($_.Exception.Message)" }
            }
            try { Set-Mailbox -Identity $UserUpn -HiddenFromAddressListsEnabled $true -ErrorAction Stop; Add-Finding Info 'Mailbox' 'Hidden from address lists' }
            catch { Add-Finding Medium 'Mailbox' "Hide from GAL failed (synced users need msExchHideFromAddressLists in AD): $($_.Exception.Message)" }
            try { Export-Data -Data (Get-MobileDevice -Mailbox $UserUpn -ErrorAction Stop | Select-Object FriendlyName, DeviceModel, DeviceOS, DeviceAccessState, FirstSyncTime) -Name 'mobile_devices' } catch { }
        }
        if (-not $SkipGroupRemoval) {
            try {
                $r = Get-EXORecipient -Identity $UserUpn -Properties DistinguishedName -ErrorAction Stop
                $dls = @(Get-Recipient -Filter ("Members -eq '{0}'" -f $r.DistinguishedName) -RecipientTypeDetails MailUniversalDistributionGroup, MailUniversalSecurityGroup -ResultSize Unlimited -ErrorAction Stop)
                Export-Data -Data ($dls | Select-Object DisplayName, PrimarySmtpAddress, RecipientTypeDetails) -Name 'snapshot_distribution_lists'
                foreach ($d in $dls) {
                    try { Remove-DistributionGroupMember -Identity $d.Identity -Member $UserUpn -BypassSecurityGroupManagerCheck -Confirm:$false -ErrorAction Stop; Write-ToolkitLog "Removed from DL $($d.DisplayName)" OK }
                    catch { Add-Finding Medium 'Distribution list' "Remove from '$($d.DisplayName)' failed: $($_.Exception.Message)" }
                }
            } catch { Add-Finding Medium 'Distribution list' "DL lookup failed: $($_.Exception.Message)" }
        }
    } else { $licenseSafe = $false; Add-Finding High 'Mailbox' 'Exchange not connected: mailbox steps skipped and licenses kept' }

    # Entra groups
    if (-not $SkipGroupRemoval) {
        foreach ($g in $groups) {
            $kind = Get-GroupKind -G $g
            if ($kind -eq 'Graph') {
                try { Invoke-Graph -Method DELETE -Uri ('v1.0/groups/{0}/members/{1}/$ref' -f $g.id, $u.id) | Out-Null; Write-ToolkitLog "Removed from $($g.displayName)" OK }
                catch { Add-Finding Medium 'Group' "Remove from '$($g.displayName)' failed: $($_.Exception.Message)" }
            }
            elseif ($kind -eq 'Synced') { Add-Finding Medium 'Group' "'$($g.displayName)' is synced from AD: remove in AD" }
            elseif ($kind -eq 'Dynamic') { Add-Finding Info 'Group' "'$($g.displayName)' is dynamic: drops off when attributes change or account is disabled (if the rule checks it)" }
        }
    }

    # OneDrive
    if ($OneDriveAccessUpn) {
        $adminUrl = $SharePointAdminUrl
        if (-not $adminUrl) {
            $initial = @($script:TenantOrg.verifiedDomains | Where-Object { $_.isInitial }) | Select-Object -First 1
            $adminUrl = 'https://{0}-admin.sharepoint.com' -f (([string]$initial.name) -split '\.')[0]
        }
        $odHost = $adminUrl -replace '-admin\.sharepoint\.com', '-my.sharepoint.com'
        $odUrl  = '{0}/personal/{1}' -f $odHost.TrimEnd('/'), ($UserUpn.ToLower() -replace '[\.@]', '_')
        if ($PSVersionTable.PSVersion.Major -ge 7) { Add-Finding Medium 'OneDrive' "SharePoint Online module needs Windows PowerShell 5.1. Run in 5.1 or grant manually: $odUrl" }
        elseif (Initialize-Module -Name 'Microsoft.Online.SharePoint.PowerShell') {
            try {
                Connect-SPOService -Url $adminUrl -ErrorAction Stop
                $site = $null
                try { $site = Get-SPOSite -Identity $odUrl -ErrorAction Stop } catch { $site = Get-SPOSite -IncludePersonalSite $true -Limit All -Filter ("Owner -eq '{0}'" -f $UserUpn) -ErrorAction SilentlyContinue | Select-Object -First 1 }
                if ($site) {
                    Set-SPOUser -Site $site.Url -LoginName $OneDriveAccessUpn -IsSiteCollectionAdmin $true -ErrorAction Stop | Out-Null
                    Add-Finding Info 'OneDrive' "$OneDriveAccessUpn is now site admin on $($site.Url)"
                } else { Add-Finding Medium 'OneDrive' "OneDrive not found (never provisioned?) at $odUrl" }
            } catch { Add-Finding Medium 'OneDrive' "OneDrive access failed: $($_.Exception.Message)" }
        }
    }

    # Licenses
    if ($KeepLicenses) { Add-Finding Info 'License' 'Licenses kept (-KeepLicenses)' }
    elseif (-not $licenseSafe) { Add-Finding Medium 'License' 'Licenses kept because the mailbox still needs one (see above)' }
    else {
        $direct = @($u.licenseAssignmentStates | Where-Object { -not $_.assignedByGroup } | Select-Object -ExpandProperty skuId -Unique)
        $viaGroup = @($u.licenseAssignmentStates | Where-Object { $_.assignedByGroup })
        if ($viaGroup.Count -gt 0) { Add-Finding Medium 'License' "$($viaGroup.Count) license(s) are group-based: removed when the user leaves the licensing group" }
        if ($direct.Count -gt 0) {
            try { Invoke-Graph -Method POST -Uri ('v1.0/users/{0}/assignLicense' -f $u.id) -Body @{ addLicenses = @(); removeLicenses = $direct } | Out-Null; Add-Finding Info 'License' ('Removed {0} direct license(s): {1}' -f $direct.Count, (($lic | Where-Object { $direct -contains $_.skuId } | Select-Object -ExpandProperty skuPartNumber) -join ', ')) }
            catch { Add-Finding Medium 'License' "License removal failed: $($_.Exception.Message)" }
        }
    }
}
#endregion

#region ---- Main ----
try {
    Write-ToolkitLog "$ScriptName starting" HEAD
    $AdminUpn = Read-Input -Value $AdminUpn -Prompt 'Admin UPN for sign-in'
    if (-not $Action) {
        $a = Read-Input -Value '' -Prompt 'Action: Onboard or Offboard'
        if ($a -notin @('Onboard', 'Offboard')) { Write-ToolkitLog "Invalid action '$a'" ERROR; return }
        $Action = $a
    }
    $UserUpn = Read-Input -Value $UserUpn -Prompt "UPN of the user to $($Action.ToLower())"
    if (-not $AdminUpn -or -not $UserUpn) { Write-ToolkitLog 'AdminUpn and UserUpn are required.' ERROR; return }

    if ($Action -eq 'Onboard') {
        $FirstName   = Read-Input -Value $FirstName   -Prompt 'First name'
        $LastName    = Read-Input -Value $LastName    -Prompt 'Last name'
        if (-not $PSBoundParameters.ContainsKey('CopyFromUpn')) { $CopyFromUpn = Read-Input -Value $CopyFromUpn -Prompt 'Template user to copy groups/licenses from' -Optional }
        if (-not $PSBoundParameters.ContainsKey('LicenseSkus') -and -not $CopyFromUpn) { $LicenseSkus = Read-Input -Value $LicenseSkus -Prompt 'License SKU part numbers (comma-separated)' -Optional }
        if (-not $PSBoundParameters.ContainsKey('ManagerUpn') -and -not $CopyFromUpn) { $ManagerUpn = Read-Input -Value $ManagerUpn -Prompt 'Manager UPN' -Optional }
    } else {
        if (-not $PSBoundParameters.ContainsKey('MailboxAccessUpn'))  { $MailboxAccessUpn  = Read-Input -Value $MailboxAccessUpn  -Prompt 'Grant mailbox FullAccess to' -Optional }
        if (-not $PSBoundParameters.ContainsKey('ForwardToUpn'))      { $ForwardToUpn      = Read-Input -Value $ForwardToUpn      -Prompt 'Forward mail to' -Optional }
        if (-not $PSBoundParameters.ContainsKey('OneDriveAccessUpn')) { $OneDriveAccessUpn = Read-Input -Value $OneDriveAccessUpn -Prompt 'Grant OneDrive access to' -Optional }
        if (-not $PSBoundParameters.ContainsKey('AutoReplyMessage'))  { $AutoReplyMessage  = Read-Input -Value $AutoReplyMessage  -Prompt 'Auto-reply message' -Optional }
    }

    $scopes = @('User.ReadWrite.All', 'Group.ReadWrite.All', 'Directory.ReadWrite.All', 'Organization.Read.All')
    if (-not (Connect-ToolkitGraph -AdminUpn $AdminUpn -Scopes $scopes)) { return }
    if ($Action -eq 'Onboard') { Invoke-Onboard } else { Invoke-Offboard }
}
catch { Write-ToolkitLog "Unhandled error: $($_.Exception.Message) at line $($_.InvocationInfo.ScriptLineNumber)" ERROR }
finally { Show-Summary }
#endregion
