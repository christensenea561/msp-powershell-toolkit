#Requires -Version 5.1

<#
.SYNOPSIS
    Explains why users are or are not in a dynamic group, and previews the impact of a new or changed rule.

.DESCRIPTION
    Works with both Entra ID dynamic groups and Exchange Online dynamic distribution groups (auto-detected).

    Entra ID groups:
      - Group type, rule, processing state and last membership update
      - Per-user evaluation with the rule breakdown (which clause passed or failed and the actual attribute value)
      - Proposed rule preview: evaluates every enabled member user against the rule and outputs
        WouldAdd / WouldRemove compared to current membership (use it before converting a static group)
    Exchange dynamic distribution groups:
      - RecipientFilter, member count and per-user membership check
      - Proposed OPATH filter preview with WouldAdd / WouldRemove

.PARAMETER AdminUpn
    Admin account for the interactive sign-in. The tenant is taken from this account.
.PARAMETER Group
    Group display name, email address or object ID.
.PARAMETER TestUpns
    Comma-separated UPNs to evaluate against the group (or against ProposedRule when given).
.PARAMETER ProposedRule
    Optional new rule. Entra syntax for Entra groups, e.g. (user.department -eq "Sales"). OPATH for Exchange DDGs.
.PARAMETER PreviewAllUsers
    With ProposedRule: evaluate every enabled member user and output the full WouldAdd / WouldRemove diff.
.PARAMETER MaxUsers
    Safety cap on users evaluated by PreviewAllUsers (one Graph call per user).

.NOTES
    Windows PowerShell 5.1 or PowerShell 7. Microsoft.Graph.Authentication (and ExchangeOnlineManagement for DDGs).
    Uses the Graph beta evaluateDynamicMembership action. Read-only.
#>
[CmdletBinding()]
param(
    [string]$AdminUpn,
    [string]$Group,
    [string]$TestUpns,
    [string]$ProposedRule,
    [switch]$PreviewAllUsers,
    [int]$MaxUsers = 2000
)

#region ---- Common helpers (inline so the script runs standalone or pasted) ----
$ScriptName = 'Test-DynamicGroupMembership'
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
#endregion

function Format-EvalDetail {
    param([object]$Node, [int]$Depth = 0)
    if ($null -eq $Node) { return }
    $pad = '  ' * $Depth
    $res = 'FAIL'; if ($Node.expressionResult) { $res = 'PASS' }
    $val = ''
    if ($Node.propertyToEvaluate) { $val = ' [actual {0} = "{1}"]' -f $Node.propertyToEvaluate.propertyName, $Node.propertyToEvaluate.propertyValue }
    '{0}{1}  {2}{3}' -f $pad, $res, $Node.expression, $val
    foreach ($c in @($Node.expressionEvaluationDetails)) { if ($c) { Format-EvalDetail -Node $c -Depth ($Depth + 1) } }
}

#region ---- Main ----
try {
    Write-ToolkitLog "$ScriptName starting" HEAD
    $AdminUpn = Read-Input -Value $AdminUpn -Prompt 'Admin UPN for sign-in'
    $Group    = Read-Input -Value $Group    -Prompt 'Group display name, email or object ID'
    if (-not $AdminUpn -or -not $Group) { Write-ToolkitLog 'AdminUpn and Group are required.' ERROR; return }
    if (-not $PSBoundParameters.ContainsKey('TestUpns'))     { $TestUpns     = Read-Input -Value $TestUpns     -Prompt 'UPNs to test (comma-separated)' -Optional }
    if (-not $PSBoundParameters.ContainsKey('ProposedRule')) { $ProposedRule = Read-Input -Value $ProposedRule -Prompt 'Proposed rule/filter to preview' -Optional }
    $testList = @($TestUpns -split '[,;\s]+' | Where-Object { $_ })

    if (-not (Connect-ToolkitGraph -AdminUpn $AdminUpn -Scopes @('Group.Read.All', 'GroupMember.Read.All', 'User.Read.All'))) { return }

    # Resolve group in Entra
    $g = $null
    $sel = 'id,displayName,mail,groupTypes,membershipRule,membershipRuleProcessingState,mailEnabled,securityEnabled,onPremisesSyncEnabled'
    try {
        if ($Group -match '^[0-9a-fA-F-]{36}$') { $g = Invoke-Graph -Uri ('v1.0/groups/{0}?$select={1}' -f $Group, $sel) }
        else {
            $f = "mail eq '{0}' or displayName eq '{0}' or proxyAddresses/any(p:p eq 'smtp:{0}')" -f ($Group -replace "'", "''")
            $hits = @(Invoke-Graph -Uri ('v1.0/groups?$filter={0}&$select={1}&$count=true' -f [uri]::EscapeDataString($f), $sel) -Eventual)
            if ($hits.Count -gt 1) { Write-ToolkitLog "$($hits.Count) groups match '$Group'. Using the first; pass the object ID to be exact." WARN }
            if ($hits.Count -gt 0) { $g = $hits[0] }
        }
    } catch { Write-ToolkitLog "Entra group lookup failed: $($_.Exception.Message)" WARN }

    $isEntraDynamic = $false
    if ($g) {
        $isEntraDynamic = (@($g.groupTypes) -contains 'DynamicMembership')
        $kind = 'Security'; if (@($g.groupTypes) -contains 'Unified') { $kind = 'Microsoft 365' } elseif ($g.mailEnabled -and -not $g.securityEnabled) { $kind = 'Distribution list' } elseif ($g.mailEnabled) { $kind = 'Mail-enabled security' }
        Write-ToolkitLog ('Entra group: {0} | {1} | dynamic={2} | synced={3} | id={4}' -f $g.displayName, $kind, $isEntraDynamic, [bool]$g.onPremisesSyncEnabled, $g.id) OK
        if ($kind -eq 'Distribution list' -or $kind -eq 'Mail-enabled security') { Add-Finding Info 'Group' 'This is an Exchange-managed group. Entra dynamic membership needs a security or Microsoft 365 group; for a DL, use an Exchange dynamic distribution group instead.' }
    }

    if ($g) {
        # Entra path
        if ($isEntraDynamic) {
            Write-ToolkitLog ('Rule: {0}' -f $g.membershipRule)
            Write-ToolkitLog ('Processing state: {0}' -f $g.membershipRuleProcessingState)
            if ($g.membershipRuleProcessingState -ne 'On') { Add-Finding Medium 'Rule' "Rule processing is '$($g.membershipRuleProcessingState)' (membership is frozen)" }
            try {
                $st = Invoke-Graph -Uri ('beta/groups/{0}?$select=membershipRuleProcessingStatus' -f $g.id)
                $s = $st.membershipRuleProcessingStatus
                if ($s) {
                    Write-ToolkitLog ('Processing status: {0} | last updated: {1} | error: {2}' -f $s.status, $s.lastMembershipUpdated, $s.errorMessage)
                    if ($s.status -match '(?i)fail|error') { Add-Finding High 'Rule' "Rule processing error: $($s.errorMessage)" }
                }
            } catch { }
        } else { Write-ToolkitLog 'Group has assigned (static) membership.' }

        $members = @(Invoke-Graph -Uri ('v1.0/groups/{0}/members?$select=id,userPrincipalName,displayName,accountEnabled&$top=999' -f $g.id))
        Write-ToolkitLog "Current direct members: $($members.Count)"
        Export-Data -Data ($members | Select-Object displayName, userPrincipalName, accountEnabled, id) -Name 'current_members'
        $memberIds = @{}; foreach ($m in $members) { $memberIds[$m.id] = $true }

        # Per-user evaluation
        $evalRows = New-Object System.Collections.Generic.List[object]
        foreach ($upn in $testList) {
            try { $u = Invoke-Graph -Uri ('v1.0/users/{0}?$select=id,userPrincipalName' -f [uri]::EscapeDataString($upn)) }
            catch { Add-Finding Medium 'Test user' "$upn not found"; continue }
            $isMember = $memberIds.ContainsKey($u.id)
            $target = ''; $res = $null
            try {
                if ($ProposedRule) { $res = Invoke-Graph -Method POST -Uri 'beta/groups/evaluateDynamicMembership' -Body @{ memberId = $u.id; membershipRule = $ProposedRule }; $target = 'proposed rule' }
                elseif ($isEntraDynamic) { $res = Invoke-Graph -Method POST -Uri ('beta/groups/{0}/evaluateDynamicMembership' -f $g.id) -Body @{ memberId = $u.id }; $target = 'current rule' }
            } catch { Write-ToolkitLog "Evaluation failed for $upn : $($_.Exception.Message)" ERROR }
            if ($res) {
                Write-Host ''
                Write-Host ('{0} vs {1}: {2} (currently member: {3})' -f $upn, $target, $res.membershipRuleEvaluationResult, $isMember) -ForegroundColor Cyan
                $lines = @(Format-EvalDetail -Node $res.membershipRuleEvaluationDetails)
                $lines | ForEach-Object { Write-Host $_ }
                $evalRows.Add([pscustomobject]@{ UPN = $upn; Target = $target; Result = $res.membershipRuleEvaluationResult; CurrentMember = $isMember; Breakdown = ($lines -join ' | ') })
                if ($isEntraDynamic -and -not $ProposedRule -and ([bool]$res.membershipRuleEvaluationResult -ne $isMember)) { Add-Finding Medium 'Membership' "$upn evaluates $($res.membershipRuleEvaluationResult) but member=$isMember (processing lag or paused rule)" }
            } else {
                $evalRows.Add([pscustomobject]@{ UPN = $upn; Target = 'membership only'; Result = ''; CurrentMember = $isMember; Breakdown = '' })
                Write-ToolkitLog ('{0}: currently member = {1}' -f $upn, $isMember)
            }
        }
        Export-Data -Data $evalRows -Name 'user_evaluations'

        # Full preview
        if ($ProposedRule -and $PreviewAllUsers) {
            Write-ToolkitLog 'Proposed rule preview across all enabled member users' HEAD
            $users = @(Invoke-Graph -Uri ('v1.0/users?$filter={0}&$select=id,userPrincipalName,displayName&$count=true&$top=999' -f [uri]::EscapeDataString("accountEnabled eq true and userType eq 'Member'")) -Eventual -Max $MaxUsers)
            if ($users.Count -ge $MaxUsers) { Add-Finding Medium 'Preview' "User count reached MaxUsers ($MaxUsers). Preview is partial; raise -MaxUsers." }
            $diff = New-Object System.Collections.Generic.List[object]
            $i = 0
            foreach ($u in $users) {
                $i++
                if ($i % 50 -eq 0) { Write-ToolkitLog "Evaluated $i / $($users.Count)" }
                try {
                    $r = Invoke-Graph -Method POST -Uri 'beta/groups/evaluateDynamicMembership' -Body @{ memberId = $u.id; membershipRule = $ProposedRule }
                    $match = [bool]$r.membershipRuleEvaluationResult; $cur = $memberIds.ContainsKey($u.id)
                    $change = 'NoChange'; if ($match -and -not $cur) { $change = 'WouldAdd' } elseif ($cur -and -not $match) { $change = 'WouldRemove' }
                    if ($change -ne 'NoChange' -or $match) { $diff.Add([pscustomobject]@{ UPN = $u.userPrincipalName; DisplayName = $u.displayName; MatchesRule = $match; CurrentMember = $cur; Change = $change }) }
                } catch { Write-ToolkitLog "Evaluation failed for $($u.userPrincipalName): $($_.Exception.Message)" WARN }
            }
            Export-Data -Data $diff -Name 'proposed_rule_diff'
            $add = @($diff | Where-Object { $_.Change -eq 'WouldAdd' }); $rem = @($diff | Where-Object { $_.Change -eq 'WouldRemove' })
            $nonUser = @($members | Where-Object { -not $_.userPrincipalName }).Count
            Add-Finding Info 'Preview' ('Proposed rule matches {0} user(s): {1} would be added, {2} would be removed' -f @($diff | Where-Object { $_.MatchesRule }).Count, $add.Count, $rem.Count)
            if ($rem.Count -gt 0) { Write-Host 'Would be REMOVED:' -ForegroundColor Yellow; $rem | Select-Object -First 50 | Format-Table UPN, DisplayName -AutoSize | Out-String | Write-Host }
            if ($nonUser -gt 0) { Add-Finding Medium 'Preview' "$nonUser current member(s) are groups/devices/contacts and would be dropped by a user rule" }
        }
    }
    else {
        # Exchange DDG path
        Write-ToolkitLog "No Entra group matched '$Group'. Checking Exchange dynamic distribution groups." WARN
        if (-not (Connect-ToolkitExo -AdminUpn $AdminUpn)) { return }
        try { $ddg = Get-DynamicDistributionGroup -Identity $Group -ErrorAction Stop }
        catch { Add-Finding High 'Group' "'$Group' was not found as an Entra group or an Exchange dynamic distribution group"; return }
        Write-ToolkitLog ('DDG: {0} <{1}>' -f $ddg.DisplayName, $ddg.PrimarySmtpAddress) OK
        Write-ToolkitLog ('RecipientFilter: {0}' -f $ddg.RecipientFilter)
        if ($ddg.IncludedRecipients) { Write-ToolkitLog ('Precanned: IncludedRecipients={0} Conditional filters set: Company={1} Dept={2} State={3}' -f $ddg.IncludedRecipients, ($ddg.ConditionalCompany -join ','), ($ddg.ConditionalDepartment -join ','), ($ddg.ConditionalStateOrProvince -join ',')) }
        $members = @(Get-DynamicDistributionGroupMember -Identity $Group -ResultSize Unlimited -ErrorAction SilentlyContinue)
        Write-ToolkitLog "Current members (Exchange refreshes DDG membership about every 24 hours): $($members.Count)"
        Export-Data -Data ($members | Select-Object DisplayName, PrimarySmtpAddress, RecipientTypeDetails) -Name 'current_members'
        $memberSet = @{}; foreach ($m in $members) { $memberSet[([string]$m.PrimarySmtpAddress).ToLower()] = $true }
        foreach ($upn in $testList) {
            try {
                $r = Get-EXORecipient -Identity $upn -ErrorAction Stop
                $isMember = $memberSet.ContainsKey(([string]$r.PrimarySmtpAddress).ToLower())
                Write-ToolkitLog ('{0} ({1}): member = {2}' -f $upn, $r.RecipientTypeDetails, $isMember)
                if (-not $isMember) {
                    $full = Get-Recipient -Identity $upn -ErrorAction SilentlyContinue
                    Write-ToolkitLog ('  Department={0} Company={1} Office={2} City={3} State={4} CustomAttribute1={5} HiddenFromGAL={6}' -f $full.Department, $full.Company, $full.Office, $full.City, $full.StateOrProvince, $full.CustomAttribute1, $full.HiddenFromAddressListsEnabled)
                }
            } catch { Add-Finding Medium 'Test user' "$upn not found as a recipient" }
        }
        if ($ProposedRule) {
            try {
                $preview = @(Get-Recipient -RecipientPreviewFilter $ProposedRule -ResultSize Unlimited -ErrorAction Stop)
                $pSet = @{}; foreach ($p in $preview) { $pSet[([string]$p.PrimarySmtpAddress).ToLower()] = $true }
                $diff = New-Object System.Collections.Generic.List[object]
                foreach ($p in $preview) { $k = ([string]$p.PrimarySmtpAddress).ToLower(); $c = 'NoChange'; if (-not $memberSet.ContainsKey($k)) { $c = 'WouldAdd' }; $diff.Add([pscustomobject]@{ Address = $k; DisplayName = $p.DisplayName; Type = $p.RecipientTypeDetails; Change = $c }) }
                foreach ($m in $members) { $k = ([string]$m.PrimarySmtpAddress).ToLower(); if (-not $pSet.ContainsKey($k)) { $diff.Add([pscustomobject]@{ Address = $k; DisplayName = $m.DisplayName; Type = $m.RecipientTypeDetails; Change = 'WouldRemove' }) } }
                Export-Data -Data $diff -Name 'proposed_filter_diff'
                Add-Finding Info 'Preview' ('Proposed filter returns {0} recipient(s): {1} would be added, {2} would be removed' -f $preview.Count, @($diff | Where-Object { $_.Change -eq 'WouldAdd' }).Count, @($diff | Where-Object { $_.Change -eq 'WouldRemove' }).Count)
            } catch { Add-Finding High 'Preview' "Proposed OPATH filter rejected: $($_.Exception.Message)" }
        }
    }
}
catch { Write-ToolkitLog "Unhandled error: $($_.Exception.Message) at line $($_.InvocationInfo.ScriptLineNumber)" ERROR }
finally { Show-Summary }
#endregion
