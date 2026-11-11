#Requires -Version 5.1

<#
.SYNOPSIS
    End-to-end Exchange Online mail flow triage for a sender, recipient, message ID or subject.

.DESCRIPTION
    Covers the usual causes of "mail not arriving" or "mail going to the wrong place" in one pass:
      - Message trace (Get-MessageTraceV2) in 10-day slices, up to 90 days back
      - Per-hop trace detail for every non-delivered message (and optionally all messages)
      - Transport rules that reference the sender, recipient or their domains
      - Inbound and outbound connectors
      - Recipient checks: existence, forwarding, inbox rules, junk blocked senders, quota,
        group delivery restrictions and moderation
      - Sender checks: restricted sender list, SMTP AUTH state, mailbox state
      - Quarantine, Tenant Allow/Block List, anti-spam and connection filter allow/block entries
      - DNS: MX, SPF (top-level lookup count), DMARC and DKIM for both domains
      - OME / IRM configuration
    Prints a severity-ranked findings table and writes CSVs for anything large.

    Any parameter left empty is prompted for, so the script can be pasted into VS Code and run.

.PARAMETER AdminUpn
    Admin account used for the interactive Exchange Online sign-in. The tenant is taken from this account.
.PARAMETER SenderAddress
    Sender email address to trace.
.PARAMETER RecipientAddress
    Recipient email address to trace.
.PARAMETER MessageId
    Internet Message-ID header value (include angle brackets if present).
.PARAMETER Subject
    Subject text to match (Contains).
.PARAMETER DaysBack
    How many days back to trace when StartDate/EndDate are not given. Max 90.
.PARAMETER StartDate
    Optional explicit start date/time, for example "11/10/2026 8:00 AM".
.PARAMETER EndDate
    Optional explicit end date/time.
.PARAMETER DnsServer
    Public resolver used for DNS checks so internal split DNS does not skew results.
.PARAMETER DetailAll
    Pull hop-by-hop detail for delivered messages too (slower).
.PARAMETER SkipDns
    Skip the MX/SPF/DMARC/DKIM checks.

.NOTES
    Runs in Windows PowerShell 5.1 or PowerShell 7. Requires ExchangeOnlineManagement 3.x.
    Read-only. Makes no changes to the tenant.
#>
[CmdletBinding()]
param(
    [string]$AdminUpn,
    [string]$SenderAddress,
    [string]$RecipientAddress,
    [string]$MessageId,
    [string]$Subject,
    [int]$DaysBack = 2,
    [string]$StartDate,
    [string]$EndDate,
    [string]$DnsServer = '1.1.1.1',
    [switch]$DetailAll,
    [switch]$SkipDns
)

#region ---- Common helpers (inline so the script runs standalone or pasted) ----
$ScriptName = 'Invoke-MailFlowTriage'
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
function ConvertTo-Bytes {
    param([object]$SizeValue)
    if ($null -eq $SizeValue) { return $null }
    $m = [regex]::Match([string]$SizeValue, '\(([\d,]+) bytes\)')
    if ($m.Success) { return [int64]($m.Groups[1].Value -replace ',', '') }
    return $null
}
#endregion

#region ---- Checks ----
function Test-MailDomainDns {
    param([string]$Domain, [bool]$IsInternal)
    $rows = New-Object System.Collections.Generic.List[object]
    # MX
    try {
        $mx = @(Resolve-DnsName -Name $Domain -Type MX -Server $DnsServer -DnsOnly -ErrorAction Stop | Where-Object { $_.Type -eq 'MX' } | Sort-Object Preference)
        if ($mx.Count -eq 0) { Add-Finding High 'DNS' "$Domain has no MX record" }
        foreach ($r in $mx) { $rows.Add([pscustomobject]@{ Domain = $Domain; Type = 'MX'; Value = ('{0} {1}' -f $r.Preference, $r.NameExchange) }) }
        if ($IsInternal -and $mx.Count -gt 0 -and -not ($mx | Where-Object { $_.NameExchange -like '*.mail.protection.outlook.com' })) {
            Add-Finding Info 'DNS' "$Domain MX does not point to Exchange Online ($($mx[0].NameExchange)). Third-party gateway in path: check inbound connector and Enhanced Filtering."
        }
    } catch { Add-Finding Medium 'DNS' "MX lookup failed for $Domain : $($_.Exception.Message)" }
    # SPF
    try {
        $txt = @(Resolve-DnsName -Name $Domain -Type TXT -Server $DnsServer -DnsOnly -ErrorAction Stop | Where-Object { $_.Type -eq 'TXT' })
        $spf = @($txt | ForEach-Object { ($_.Strings -join '') } | Where-Object { $_ -like 'v=spf1*' })
        if ($spf.Count -eq 0) { Add-Finding Medium 'SPF' "$Domain has no SPF record" }
        elseif ($spf.Count -gt 1) { Add-Finding High 'SPF' "$Domain has $($spf.Count) SPF records (SPF permerror)" }
        foreach ($s in $spf) {
            $rows.Add([pscustomobject]@{ Domain = $Domain; Type = 'SPF'; Value = $s })
            $lookups = @(($s -split '\s+') | Where-Object { $_ -match '^[+\-~?]?(include:|exists:|redirect=|a$|a:|a/|mx$|mx:|mx/|ptr)' }).Count
            if ($lookups -gt 10) { Add-Finding High 'SPF' "$Domain SPF has $lookups top-level DNS lookups (limit 10, nested includes add more)" }
            elseif ($lookups -ge 8) { Add-Finding Low 'SPF' "$Domain SPF has $lookups top-level lookups (nested includes may push it past 10)" }
            if ($IsInternal -and $s -notmatch 'spf\.protection\.outlook\.com') { Add-Finding Medium 'SPF' "$Domain SPF does not include spf.protection.outlook.com" }
            if ($s -match '\+all') { Add-Finding High 'SPF' "$Domain SPF ends in +all (allows any sender)" }
        }
    } catch { Add-Finding Low 'SPF' "TXT lookup failed for $Domain : $($_.Exception.Message)" }
    # DMARC
    try {
        $d = @(Resolve-DnsName -Name ('_dmarc.' + $Domain) -Type TXT -Server $DnsServer -DnsOnly -ErrorAction Stop | Where-Object { $_.Type -eq 'TXT' } | ForEach-Object { ($_.Strings -join '') } | Where-Object { $_ -like 'v=DMARC1*' })
        if ($d.Count -eq 0) { Add-Finding Medium 'DMARC' "$Domain has no DMARC record" }
        foreach ($v in $d) {
            $rows.Add([pscustomobject]@{ Domain = $Domain; Type = 'DMARC'; Value = $v })
            $p = [regex]::Match($v, '(?i)\bp=(\w+)')
            if ($p.Success -and $p.Groups[1].Value -eq 'none' -and $IsInternal) { Add-Finding Low 'DMARC' "$Domain DMARC policy is p=none (monitor only)" }
        }
    } catch { Add-Finding Medium 'DMARC' "$Domain has no DMARC record (lookup returned: $($_.Exception.Message))" }
    # DKIM (Microsoft 365 selectors)
    foreach ($sel in 'selector1', 'selector2') {
        try {
            $c = @(Resolve-DnsName -Name ('{0}._domainkey.{1}' -f $sel, $Domain) -Server $DnsServer -DnsOnly -ErrorAction Stop | Where-Object { $_.Type -eq 'CNAME' -or $_.Type -eq 'TXT' })
            $val = ($c | ForEach-Object { if ($_.Type -eq 'CNAME') { $_.NameHost } else { 'TXT record' } }) -join '; '
            $rows.Add([pscustomobject]@{ Domain = $Domain; Type = "DKIM $sel"; Value = $val })
        } catch {
            $rows.Add([pscustomobject]@{ Domain = $Domain; Type = "DKIM $sel"; Value = 'Not found' })
            if ($IsInternal) { Add-Finding Medium 'DKIM' "$Domain is missing the $sel._domainkey record" }
        }
    }
    return $rows
}

function Test-Recipient {
    param([string]$Address, [bool]$SenderIsExternal)
    Write-ToolkitLog "Recipient checks: $Address" HEAD
    $rcpt = $null
    try { $rcpt = Get-EXORecipient -Identity $Address -ErrorAction Stop }
    catch { Add-Finding High 'Recipient' "$Address does not resolve to any recipient in this tenant (expect NDR 550 5.1.10 / 5.1.1). Check aliases, typos, or a deleted/unlicensed user."; return }
    Write-ToolkitLog ('Recipient type: {0}  Primary: {1}' -f $rcpt.RecipientTypeDetails, $rcpt.PrimarySmtpAddress) OK
    if ([string]$rcpt.PrimarySmtpAddress -ne $Address) { Add-Finding Info 'Recipient' "$Address is a secondary alias of $($rcpt.PrimarySmtpAddress)" }

    $type = [string]$rcpt.RecipientTypeDetails
    if ($type -like '*Mailbox') {
        try {
            $mbx = Get-EXOMailbox -Identity $Address -PropertySets All -ErrorAction Stop
            if ($mbx.ForwardingSmtpAddress -or $mbx.ForwardingAddress) {
                $fwd = @($mbx.ForwardingSmtpAddress, $mbx.ForwardingAddress) | Where-Object { $_ }
                $keep = 'NOT kept in mailbox'; if ($mbx.DeliverToMailboxAndForward) { $keep = 'copy kept in mailbox' }
                Add-Finding Medium 'Forwarding' ("Mailbox forwards to {0} ({1})" -f ($fwd -join ', '), $keep)
            }
            if ($mbx.AcceptMessagesOnlyFromSendersOrMembers.Count -gt 0) { Add-Finding Medium 'Restriction' "Mailbox only accepts mail from: $($mbx.AcceptMessagesOnlyFromSendersOrMembers -join ', ')" }
            if ($mbx.RejectMessagesFromSendersOrMembers.Count -gt 0)     { Add-Finding Medium 'Restriction' "Mailbox rejects mail from: $($mbx.RejectMessagesFromSendersOrMembers -join ', ')" }
            if ($mbx.RequireSenderAuthenticationEnabled -and $SenderIsExternal) { Add-Finding High 'Restriction' 'Mailbox requires sender authentication, so external senders are rejected' }
            if ($mbx.AccountDisabled -and $type -eq 'UserMailbox') { Add-Finding Info 'Recipient' 'Account is disabled (mail still delivers)' }
            if ($mbx.HiddenFromAddressListsEnabled) { Add-Finding Info 'Recipient' 'Hidden from address lists' }
            Write-ToolkitLog ('MaxReceiveSize: {0}  RecipientLimits: {1}' -f $mbx.MaxReceiveSize, $mbx.RecipientLimits)
            try {
                $st    = Get-EXOMailboxStatistics -Identity $Address -ErrorAction Stop
                $used  = ConvertTo-Bytes $st.TotalItemSize
                $quota = ConvertTo-Bytes $mbx.ProhibitSendReceiveQuota
                if ($used -and $quota) {
                    $pct = [math]::Round(($used / $quota) * 100, 1)
                    Write-ToolkitLog ('Mailbox size: {0} ({1}% of ProhibitSendReceive)' -f $st.TotalItemSize, $pct)
                    if ($pct -ge 100) { Add-Finding High 'Quota' "Mailbox is at $pct% of ProhibitSendReceiveQuota (inbound mail rejected)" }
                    elseif ($pct -ge 90) { Add-Finding Medium 'Quota' "Mailbox is at $pct% of ProhibitSendReceiveQuota" }
                }
            } catch { Write-ToolkitLog "Mailbox statistics unavailable: $($_.Exception.Message)" WARN }
        } catch { Write-ToolkitLog "Get-EXOMailbox failed: $($_.Exception.Message)" ERROR }

        try {
            $rules = @(Get-InboxRule -Mailbox $Address -IncludeHidden -ErrorAction Stop)
            $ruleRows = foreach ($r in $rules) {
                [pscustomobject]@{
                    Name = $r.Name; Enabled = $r.Enabled; Priority = $r.Priority
                    From = ($r.From -join '; '); SubjectContains = ($r.SubjectContainsWords -join '; ')
                    MoveToFolder = $r.MoveToFolder; Delete = $r.DeleteMessage; MarkAsRead = $r.MarkAsRead
                    ForwardTo = ($r.ForwardTo -join '; '); RedirectTo = ($r.RedirectTo -join '; '); ForwardAsAttachmentTo = ($r.ForwardAsAttachmentTo -join '; ')
                    Description = (([string]$r.Description) -replace '\s+', ' ')
                }
            }
            Export-Data -Data $ruleRows -Name 'recipient_inbox_rules'
            foreach ($r in ($ruleRows | Where-Object { $_.Enabled })) {
                if ($r.ForwardTo -or $r.RedirectTo -or $r.ForwardAsAttachmentTo) { Add-Finding Medium 'Inbox rule' "Rule '$($r.Name)' forwards/redirects: $($r.ForwardTo)$($r.RedirectTo)$($r.ForwardAsAttachmentTo)" }
                if ($r.Delete) { Add-Finding Medium 'Inbox rule' "Rule '$($r.Name)' deletes messages" }
                if ($r.MoveToFolder) {
                    $hit = $false
                    if ($SenderAddress -and ($r.Description -match [regex]::Escape($SenderAddress) -or $r.Description -match [regex]::Escape(($SenderAddress -split '@')[-1]))) { $hit = $true }
                    if ($hit) { Add-Finding Medium 'Inbox rule' "Rule '$($r.Name)' matches the sender and moves mail to $($r.MoveToFolder)" }
                }
            }
        } catch { Write-ToolkitLog "Inbox rules unavailable: $($_.Exception.Message)" WARN }

        try {
            $junk = Get-MailboxJunkEmailConfiguration -Identity $Address -ErrorAction Stop
            if ($SenderAddress) {
                $sDom = ($SenderAddress -split '@')[-1]
                if (@($junk.BlockedSendersAndDomains) -contains $SenderAddress -or @($junk.BlockedSendersAndDomains) -contains $sDom) { Add-Finding High 'Junk' "Sender or domain is on the recipient's Blocked Senders list (goes to Junk)" }
                if (@($junk.TrustedSendersAndDomains) -contains $SenderAddress -or @($junk.TrustedSendersAndDomains) -contains $sDom) { Add-Finding Info 'Junk' 'Sender or domain is on the recipient Safe Senders list' }
            }
            if (-not $junk.Enabled) { Add-Finding Info 'Junk' 'Junk email rule is disabled for this mailbox' }
        } catch { Write-ToolkitLog "Junk config unavailable: $($_.Exception.Message)" WARN }
    }
    elseif ($type -like '*Group' -or $type -eq 'MailUniversalDistributionGroup' -or $type -eq 'MailUniversalSecurityGroup' -or $type -eq 'GroupMailbox') {
        try {
            if ($type -eq 'GroupMailbox') { $g = Get-UnifiedGroup -Identity $Address -ErrorAction Stop }
            else { $g = Get-DistributionGroup -Identity $Address -ErrorAction Stop }
            if ($g.RequireSenderAuthenticationEnabled -and $SenderIsExternal) { Add-Finding High 'Group' 'Group only accepts mail from authenticated (internal) senders, external sender is rejected (5.7.1 / 5.7.133)' }
            if (@($g.AcceptMessagesOnlySendersOrMembers).Count -gt 0) { Add-Finding Medium 'Group' "Group only accepts mail from: $($g.AcceptMessagesOnlySendersOrMembers -join ', ')" }
            if ($g.ModerationEnabled) { Add-Finding Medium 'Group' "Group is moderated by: $($g.ModeratedBy -join ', ') (mail waits for approval)" }
            if ($type -ne 'GroupMailbox') {
                $members = @(Get-DistributionGroupMember -Identity $Address -ResultSize Unlimited -ErrorAction SilentlyContinue)
                Write-ToolkitLog "Group member count: $($members.Count)"
                if ($members.Count -eq 0) { Add-Finding Medium 'Group' 'Distribution group has no members' }
            }
        } catch { Write-ToolkitLog "Group checks failed: $($_.Exception.Message)" WARN }
    }
    elseif ($type -eq 'MailContact' -or $type -eq 'MailUser') {
        Add-Finding Info 'Recipient' ("Recipient is a {0} routing to external address {1}" -f $type, $rcpt.ExternalEmailAddress)
    }
}

function Test-Sender {
    param([string]$Address)
    Write-ToolkitLog "Internal sender checks: $Address" HEAD
    try {
        $blocked = @(Get-BlockedSenderAddress -SenderAddress $Address -ErrorAction Stop)
        if ($blocked.Count -gt 0) { Add-Finding High 'Sender' "$Address is on the Restricted entities list (blocked from sending after outbound spam). Release in Defender > Restricted entities." }
    } catch { Write-ToolkitLog "Restricted sender check unavailable: $($_.Exception.Message)" WARN }
    try {
        $r = Get-EXORecipient -Identity $Address -ErrorAction Stop
        Write-ToolkitLog ('Sender recipient type: {0}' -f $r.RecipientTypeDetails)
    } catch { Add-Finding Medium 'Sender' "$Address does not exist as a recipient in this tenant (app, device or spoofed sender?)" }
    try {
        $cas = Get-CASMailbox -Identity $Address -ErrorAction Stop
        $tc  = Get-TransportConfig -ErrorAction Stop
        $state = 'follows org setting'
        if ($cas.SmtpClientAuthenticationDisabled -eq $true) { $state = 'disabled on mailbox' } elseif ($cas.SmtpClientAuthenticationDisabled -eq $false) { $state = 'enabled on mailbox' }
        Add-Finding Info 'SMTP AUTH' ("Mailbox SMTP AUTH: {0}. Org SmtpClientAuthenticationDisabled: {1}" -f $state, $tc.SmtpClientAuthenticationDisabled)
    } catch { Write-ToolkitLog "SMTP AUTH check unavailable: $($_.Exception.Message)" WARN }
}
#endregion

#region ---- Main ----
try {
    Write-ToolkitLog "$ScriptName starting" HEAD
    $AdminUpn = Read-Input -Value $AdminUpn -Prompt 'Admin UPN for Exchange Online sign-in'
    if (-not $AdminUpn) { Write-ToolkitLog 'Admin UPN is required.' ERROR; return }
    if (-not ($SenderAddress -or $RecipientAddress -or $MessageId -or $Subject)) {
        $SenderAddress    = Read-Input -Value $SenderAddress    -Prompt 'Sender address'    -Optional
        $RecipientAddress = Read-Input -Value $RecipientAddress -Prompt 'Recipient address' -Optional
        $MessageId = Read-Input -Value $MessageId -Prompt 'Message-ID'        -Optional
        $Subject   = Read-Input -Value $Subject   -Prompt 'Subject contains'  -Optional
    }
    if (-not ($SenderAddress -or $RecipientAddress -or $MessageId -or $Subject)) { Write-ToolkitLog 'Provide at least one of Sender, Recipient, MessageId or Subject.' ERROR; return }

    # Time window
    $now = Get-Date
    if ($StartDate) { try { $winStart = [datetime]::Parse($StartDate) } catch { Write-ToolkitLog "Could not parse StartDate '$StartDate'" ERROR; return } }
    else { if ($DaysBack -lt 1) { $DaysBack = 1 }; if ($DaysBack -gt 90) { $DaysBack = 90 }; $winStart = $now.AddDays(-$DaysBack) }
    if ($EndDate) { try { $winEnd = [datetime]::Parse($EndDate) } catch { Write-ToolkitLog "Could not parse EndDate '$EndDate'" ERROR; return } } else { $winEnd = $now }
    if ($winStart -lt $now.AddDays(-90)) { $winStart = $now.AddDays(-90); Write-ToolkitLog 'StartDate clamped to 90 days (message trace retention)' WARN }
    Write-ToolkitLog ('Window: {0} to {1}' -f $winStart, $winEnd)

    if (-not (Connect-ToolkitExo -AdminUpn $AdminUpn)) { return }

    # Org context
    $accepted = @(Get-AcceptedDomain -ErrorAction SilentlyContinue)
    Export-Data -Data ($accepted | Select-Object DomainName, DomainType, Default) -Name 'accepted_domains'
    $acceptedNames = @($accepted | ForEach-Object { ([string]$_.DomainName).ToLower() })
    $senderDomain    = ''; if ($SenderAddress)    { $senderDomain    = ($SenderAddress -split '@')[-1].ToLower() }
    $recipientDomain = ''; if ($RecipientAddress) { $recipientDomain = ($RecipientAddress -split '@')[-1].ToLower() }
    $senderInternal    = ($senderDomain -and ($acceptedNames -contains $senderDomain))
    $recipientInternal = ($recipientDomain -and ($acceptedNames -contains $recipientDomain))
    Write-ToolkitLog ('Sender internal: {0}  Recipient internal: {1}' -f $senderInternal, $recipientInternal)
    if ($recipientDomain -and $recipientInternal) {
        $ad = $accepted | Where-Object { ([string]$_.DomainName).ToLower() -eq $recipientDomain }
        if ($ad.DomainType -ne 'Authoritative') { Add-Finding Info 'Accepted domain' "$recipientDomain is $($ad.DomainType): unresolved recipients are relayed out via connector" }
    }

    # 1. Message trace
    Write-ToolkitLog 'Message trace' HEAD
    $trace  = New-Object System.Collections.Generic.List[object]
    $cursor = $winStart
    while ($cursor -lt $winEnd) {
        $sliceEnd = $cursor.AddDays(10); if ($sliceEnd -gt $winEnd) { $sliceEnd = $winEnd }
        $p = @{ StartDate = $cursor; EndDate = $sliceEnd; ResultSize = 5000; ErrorAction = 'Stop' }
        if ($SenderAddress)    { $p.SenderAddress = $SenderAddress }
        if ($RecipientAddress) { $p.RecipientAddress = $RecipientAddress }
        if ($MessageId) { $p.MessageId = $MessageId }
        if ($Subject)   { $p.Subject = $Subject; $p.SubjectFilterType = 'Contains' }
        try {
            $res = @(Get-MessageTraceV2 @p)
            foreach ($r in $res) { $trace.Add($r) }
            if ($res.Count -ge 5000) { Add-Finding Low 'Trace' ('Slice {0} to {1} hit the 5000 row cap. Narrow the window or filters.' -f $cursor, $sliceEnd) }
        } catch { Write-ToolkitLog "Get-MessageTraceV2 failed for slice starting $cursor : $($_.Exception.Message)" ERROR }
        $cursor = $sliceEnd
    }
    $traceRows = $trace | Select-Object Received, SenderAddress, RecipientAddress, Subject, Status, FromIP, ToIP, Size, MessageId, MessageTraceId
    Export-Data -Data $traceRows -Name 'message_trace'
    if ($trace.Count -eq 0) {
        Add-Finding High 'Trace' 'No messages found in the window. If the sender says it was sent: it never reached EOP (sender side issue, wrong MX, or blocked before acceptance), or filters are off.'
    } else {
        $byStatus = $trace | Group-Object Status | Sort-Object Count -Descending
        foreach ($s in $byStatus) { Write-ToolkitLog ('Status {0}: {1}' -f $s.Name, $s.Count) }
        Write-Host ''
        Write-Host 'Latest 15 messages:' -ForegroundColor Cyan
        $trace | Sort-Object Received -Descending | Select-Object -First 15 Received, SenderAddress, RecipientAddress, Status, @{ n = 'Subject'; e = { if ($_.Subject.Length -gt 60) { $_.Subject.Substring(0, 60) } else { $_.Subject } } } |
            Format-Table -AutoSize | Out-String -Width 220 | Write-Host
        foreach ($s in $byStatus) {
            if ($s.Name -in 'Failed', 'Quarantined', 'FilteredAsSpam') { Add-Finding Medium 'Trace' ('{0} message(s) with status {1}' -f $s.Count, $s.Name) }
            if ($s.Name -eq 'Pending') { Add-Finding Medium 'Trace' ('{0} message(s) Pending (deferred, retrying). Check detail for the remote server response.' -f $s.Count) }
        }
    }

    # 2. Trace detail
    $toDetail = @($trace | Where-Object { $DetailAll -or $_.Status -ne 'Delivered' } | Select-Object -First 25)
    if ($toDetail.Count -gt 0) {
        Write-ToolkitLog "Trace detail for $($toDetail.Count) message(s)" HEAD
        $detailRows = New-Object System.Collections.Generic.List[object]
        foreach ($m in $toDetail) {
            try {
                $dStart = ([datetime]$m.Received).AddDays(-1); $dEnd = ([datetime]$m.Received).AddDays(1)
                $det = @(Get-MessageTraceDetailV2 -MessageTraceId $m.MessageTraceId -RecipientAddress $m.RecipientAddress -StartDate $dStart -EndDate $dEnd -ErrorAction Stop)
                foreach ($d in $det) {
                    $detailRows.Add([pscustomobject]@{ Received = $m.Received; Sender = $m.SenderAddress; Recipient = $m.RecipientAddress; Status = $m.Status; EventDate = $d.Date; Event = $d.Event; Action = $d.Action; Detail = $d.Detail })
                }
                $key = @($det | Where-Object { $_.Event -match 'Fail|Drop|Defer|Quarantine|Spam|Transport rule|Redirect|Reject|Malware|Moderat' -or $_.Detail -match '\b[45]\.\d+\.\d+\b' })
                foreach ($k in $key) {
                    $txt = ([string]$k.Detail); if ($txt.Length -gt 300) { $txt = $txt.Substring(0, 300) + '...' }
                    Add-Finding Medium 'Trace detail' ('{0} -> {1} | {2}: {3}' -f $m.SenderAddress, $m.RecipientAddress, $k.Event, $txt)
                }
            } catch { Write-ToolkitLog "Trace detail failed for $($m.MessageTraceId): $($_.Exception.Message)" WARN }
        }
        Export-Data -Data $detailRows -Name 'message_trace_detail'
    }

    # 3. Transport rules
    Write-ToolkitLog 'Transport rules' HEAD
    try {
        $rules = @(Get-TransportRule -ResultSize Unlimited -ErrorAction Stop)
        $ruleRows = $rules | Select-Object Priority, Name, State, Mode, SetSCL, RejectMessageReasonText, DeleteMessage, Quarantine, @{ n = 'RedirectMessageTo'; e = { $_.RedirectMessageTo -join '; ' } },
            @{ n = 'BlindCopyTo'; e = { $_.BlindCopyTo -join '; ' } }, @{ n = 'ModerateMessageByUser'; e = { $_.ModerateMessageByUser -join '; ' } }, @{ n = 'GenerateIncidentReport'; e = { $_.GenerateIncidentReport } },
            @{ n = 'RouteMessageOutboundConnector'; e = { $_.RouteMessageOutboundConnector } }, @{ n = 'Description'; e = { ([string]$_.Description) -replace '\s+', ' ' } }
        Export-Data -Data $ruleRows -Name 'transport_rules'
        $needles = @($SenderAddress, $RecipientAddress, $senderDomain, $recipientDomain) | Where-Object { $_ }
        foreach ($r in ($ruleRows | Where-Object { $_.State -eq 'Enabled' })) {
            foreach ($n in $needles) {
                if ($r.Description -match [regex]::Escape($n)) { Add-Finding Medium 'Transport rule' ("Enabled rule '{0}' (priority {1}) references {2}" -f $r.Name, $r.Priority, $n); break }
            }
            if ($r.RouteMessageOutboundConnector) { Add-Finding Info 'Transport rule' ("Rule '{0}' routes mail to connector {1}" -f $r.Name, $r.RouteMessageOutboundConnector) }
        }
        Write-ToolkitLog "$($rules.Count) transport rule(s), $(@($ruleRows | Where-Object { $_.State -eq 'Enabled' }).Count) enabled"
    } catch { Write-ToolkitLog "Transport rules unavailable: $($_.Exception.Message)" WARN }

    # 4. Connectors
    Write-ToolkitLog 'Connectors' HEAD
    try {
        $in  = @(Get-InboundConnector -ErrorAction Stop)
        $out = @(Get-OutboundConnector -ErrorAction Stop)
        Export-Data -Data ($in  | Select-Object Name, Enabled, ConnectorType, ConnectorSource, @{ n = 'SenderDomains'; e = { $_.SenderDomains -join '; ' } }, @{ n = 'SenderIPAddresses'; e = { $_.SenderIPAddresses -join '; ' } }, RequireTls, RestrictDomainsToIPAddresses, RestrictDomainsToCertificate, TlsSenderCertificateName, EFSkipLastIP, @{ n = 'EFSkipIPs'; e = { $_.EFSkipIPs -join '; ' } }) -Name 'connectors_inbound'
        Export-Data -Data ($out | Select-Object Name, Enabled, ConnectorType, @{ n = 'RecipientDomains'; e = { $_.RecipientDomains -join '; ' } }, @{ n = 'SmartHosts'; e = { $_.SmartHosts -join '; ' } }, UseMXRecord, TlsSettings, IsTransportRuleScoped, RouteAllMessagesViaOnPremises) -Name 'connectors_outbound'
        foreach ($c in ($out | Where-Object { $_.Enabled })) {
            if (@($c.RecipientDomains) -contains '*') { Add-Finding Info 'Connector' ("Outbound connector '{0}' routes ALL external mail to {1}" -f $c.Name, ($c.SmartHosts -join ', ')) }
            elseif ($recipientDomain -and (@($c.RecipientDomains) | Where-Object { $recipientDomain -like $_ })) { Add-Finding Medium 'Connector' ("Outbound connector '{0}' handles {1} via {2}" -f $c.Name, $recipientDomain, ($c.SmartHosts -join ', ')) }
        }
        foreach ($c in ($in | Where-Object { $_.Enabled })) {
            if ($c.RestrictDomainsToIPAddresses -or $c.RestrictDomainsToCertificate) { Add-Finding Info 'Connector' ("Inbound connector '{0}' restricts its sender domains ({1}) to specific IPs/cert: mail from those domains via other paths is rejected" -f $c.Name, ($c.SenderDomains -join ', ')) }
            if ($c.EFSkipLastIP -or @($c.EFSkipIPs).Count -gt 0) { Add-Finding Info 'Connector' "Inbound connector '$($c.Name)' has Enhanced Filtering configured" }
        }
        Write-ToolkitLog "$($in.Count) inbound, $($out.Count) outbound connector(s)"
    } catch { Write-ToolkitLog "Connectors unavailable: $($_.Exception.Message)" WARN }

    # 5. Recipient / sender checks
    if ($RecipientAddress -and $recipientInternal) { Test-Recipient -Address $RecipientAddress -SenderIsExternal (-not $senderInternal) }
    if ($SenderAddress -and $senderInternal) { Test-Sender -Address $SenderAddress }

    # 6. Quarantine (30-day retention)
    Write-ToolkitLog 'Quarantine' HEAD
    try {
        $qStart = $winStart; if ($qStart -lt $now.AddDays(-30)) { $qStart = $now.AddDays(-30) }
        $q = @{ StartReceivedDate = $qStart; EndReceivedDate = $winEnd; PageSize = 1000; ErrorAction = 'Stop' }
        if ($RecipientAddress) { $q.RecipientAddress = $RecipientAddress }
        if ($SenderAddress)    { $q.SenderAddress = $SenderAddress }
        $qm = @(Get-QuarantineMessage @q)
        Export-Data -Data ($qm | Select-Object ReceivedTime, SenderAddress, @{ n = 'RecipientAddress'; e = { $_.RecipientAddress -join '; ' } }, Subject, Type, PolicyName, ReleaseStatus, Expires, Identity) -Name 'quarantine'
        if ($qm.Count -gt 0) { Add-Finding High 'Quarantine' ("{0} quarantined message(s). Types: {1}" -f $qm.Count, (($qm | Group-Object Type | ForEach-Object { '{0}={1}' -f $_.Name, $_.Count }) -join ', ')) }
    } catch { Write-ToolkitLog "Quarantine query failed: $($_.Exception.Message)" WARN }

    # 7. Allow / block lists
    Write-ToolkitLog 'Allow/Block lists and filter policies' HEAD
    if ($SenderAddress) {
        try {
            $tabl = @(Get-TenantAllowBlockListItems -ListType Sender -ErrorAction Stop | Where-Object { $_.Value -eq $SenderAddress -or $_.Value -eq $senderDomain })
            foreach ($t in $tabl) { $act = 'Allow'; if ($t.Action) { $act = $t.Action }; Add-Finding Medium 'TABL' ("Tenant Allow/Block List entry: {0} = {1} (expires {2})" -f $t.Value, $act, $t.ExpirationDate) }
        } catch { Write-ToolkitLog "Tenant Allow/Block List unavailable: $($_.Exception.Message)" WARN }
        try {
            foreach ($pol in @(Get-HostedContentFilterPolicy -ErrorAction Stop)) {
                $as  = @($pol.AllowedSenders | ForEach-Object { [string]$_ });  $ad = @($pol.AllowedSenderDomains | ForEach-Object { [string]$_ })
                $bs  = @($pol.BlockedSenders | ForEach-Object { [string]$_ });  $bd = @($pol.BlockedSenderDomains | ForEach-Object { [string]$_ })
                if ($as -contains $SenderAddress -or $ad -contains $senderDomain) { Add-Finding Medium 'Anti-spam' "Sender/domain is in the allow list of anti-spam policy '$($pol.Name)' (bypasses spam filtering)" }
                if ($bs -contains $SenderAddress -or $bd -contains $senderDomain) { Add-Finding High 'Anti-spam' "Sender/domain is BLOCKED in anti-spam policy '$($pol.Name)'" }
            }
        } catch { Write-ToolkitLog "Anti-spam policies unavailable: $($_.Exception.Message)" WARN }
    }
    try {
        $cf = Get-HostedConnectionFilterPolicy -Identity Default -ErrorAction Stop
        $ips = @($trace | Where-Object { $_.FromIP } | Select-Object -ExpandProperty FromIP -Unique)
        foreach ($ip in $ips) {
            if (@($cf.IPBlockList) -contains $ip) { Add-Finding High 'Connection filter' "Source IP $ip is in the connection filter IP Block List" }
            if (@($cf.IPAllowList) -contains $ip) { Add-Finding Info 'Connection filter' "Source IP $ip is in the connection filter IP Allow List" }
        }
    } catch { Write-ToolkitLog "Connection filter policy unavailable: $($_.Exception.Message)" WARN }

    # 8. DNS
    if (-not $SkipDns) {
        Write-ToolkitLog "DNS checks (resolver $DnsServer)" HEAD
        $dnsRows = New-Object System.Collections.Generic.List[object]
        foreach ($dom in (@($senderDomain, $recipientDomain) | Where-Object { $_ } | Select-Object -Unique)) {
            foreach ($row in (Test-MailDomainDns -Domain $dom -IsInternal ($acceptedNames -contains $dom))) { $dnsRows.Add($row) }
            if ($acceptedNames -contains $dom) {
                try {
                    $dk = Get-DkimSigningConfig -Identity $dom -ErrorAction Stop
                    if (-not $dk.Enabled) { Add-Finding Medium 'DKIM' "DKIM signing is not enabled in Exchange Online for $dom" }
                } catch { Add-Finding Low 'DKIM' "No DKIM signing config found for $dom" }
            }
        }
        Export-Data -Data $dnsRows -Name 'dns_records'
        $dnsRows | Format-Table -AutoSize -Wrap | Out-String -Width 220 | Write-Host
    }

    # 9. OME / IRM
    try {
        $irm = Get-IRMConfiguration -ErrorAction Stop
        Write-ToolkitLog ('IRM: AzureRMSLicensingEnabled={0} InternalLicensingEnabled={1} SimplifiedClientAccessEnabled={2}' -f $irm.AzureRMSLicensingEnabled, $irm.InternalLicensingEnabled, $irm.SimplifiedClientAccessEnabled)
        if (-not $irm.AzureRMSLicensingEnabled) { Add-Finding Info 'OME' 'AzureRMSLicensingEnabled is False: encrypted (OME) mail will fail' }
    } catch { Write-ToolkitLog "IRM configuration unavailable: $($_.Exception.Message)" WARN }
}
catch { Write-ToolkitLog "Unhandled error: $($_.Exception.Message) at line $($_.InvocationInfo.ScriptLineNumber)" ERROR }
finally { Show-Summary }
#endregion
