#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Decommission readiness audit: who still uses this server, what depends on it, and what it hosts.

.DESCRIPTION
    Built for RMM use (runs as SYSTEM, no prompts). Collects:
      - Interactive, RDP, unlock and cached logons (Security 4624) per user with first/last seen and a per-week trend
      - RDP session history (TerminalServices LocalSessionManager 21/25) which outlives a rolled Security log
      - Network logons (type 3) grouped by account and source (SMB / app dependencies), capped
      - Current sessions, SMB shares, open SMB sessions/files, and recent file writes per share
      - Services and scheduled tasks running as non-built-in accounts (hidden dependencies)
      - Listening ports and established inbound connections by remote host
      - Hosted roles: DC, DNS, DHCP, IIS sites, SQL instances, shared printers, Hyper-V VMs, file server
    Produces a per-user summary, a weekly trend (to spot a usage cliff) and a findings table.

.PARAMETER DaysBack
    Event log window in days.
.PARAMETER MaxNetworkEvents
    Cap on type-3 logon events read (they can be millions on a busy file server).
.PARAMETER SkipFileScan
    Skip the recent-file-activity scan of share paths.
.PARAMETER FileScanLimit
    Max files examined per share for the activity scan.

.NOTES
    NinjaOne: run as SYSTEM. Script variables daysBack, skipFileScan are read from environment variables.
    Windows PowerShell 5.1. Read-only. Output: C:\Users\Public\Documents\MspToolkit\Get-ServerUsageAudit (last 5 runs kept).
#>
[CmdletBinding()]
param(
    [int]$DaysBack = 0,
    [int]$MaxNetworkEvents = 50000,
    [switch]$SkipFileScan,
    [int]$FileScanLimit = 200000
)

#region ---- Common helpers (inline for RMM use) ----
$ScriptName = 'Get-ServerUsageAudit'
$BaseOut    = Join-Path -Path 'C:\Users\Public\Documents\MspToolkit' -ChildPath $ScriptName
$OutRoot    = Join-Path -Path $BaseOut -ChildPath (Get-Date -Format 'yyyyMMdd_HHmmss')
$LogFile    = $null
$Findings   = New-Object System.Collections.Generic.List[object]
try {
    New-Item -ItemType Directory -Path $OutRoot -Force -ErrorAction Stop | Out-Null
    $LogFile = Join-Path -Path $OutRoot -ChildPath 'run.log'
    Get-ChildItem -Path $BaseOut -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending | Select-Object -Skip 5 | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
} catch { Write-Host "Could not create output folder $OutRoot : $($_.Exception.Message)" }

function Write-ToolkitLog {
    param([string]$Message, [ValidateSet('INFO','OK','WARN','ERROR','HEAD')][string]$Level = 'INFO')
    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'HH:mm:ss'), $Level, $Message
    Write-Host $line
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
    if ($rows.Count -eq 0) { return }
    $path = Join-Path -Path $OutRoot -ChildPath ($Name + '.csv')
    try { $rows | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8 -ErrorAction Stop; Write-ToolkitLog ('{0}: {1} rows -> {2}' -f $Name, $rows.Count, $path) }
    catch { Write-ToolkitLog "Export of $Name failed: $($_.Exception.Message)" ERROR }
}
function Get-InputValue {
    param([string]$Current, [string]$EnvName, [string]$Default)
    if (-not [string]::IsNullOrWhiteSpace($Current)) { return $Current }
    $e = [Environment]::GetEnvironmentVariable($EnvName)
    if (-not [string]::IsNullOrWhiteSpace($e)) { return $e }
    return $Default
}
function Test-Truthy { param([string]$Value) return ($Value -match '^(?i)(1|true|yes|y|on)$') }
function Show-Summary {
    Write-ToolkitLog '==================== FINDINGS ====================' HEAD
    if ($Findings.Count -eq 0) { Write-ToolkitLog 'No findings.' OK }
    else {
        $order  = @{ High = 0; Medium = 1; Low = 2; Info = 3 }
        $sorted = $Findings | Sort-Object @{ Expression = { $order[$_.Severity] } }, Area
        $sorted | Format-Table -AutoSize -Wrap | Out-String -Width 200 | Write-Host
        Export-Data -Data $sorted -Name 'findings'
    }
    Write-ToolkitLog "Output folder: $OutRoot" HEAD
}
#endregion

$SystemAccounts = '^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE|ANONYMOUS LOGON|DWM-\d+|UMFD-\d+|-|.*\$)$'

function Get-LogonEvents {
    param([string[]]$LogonTypes, [int]$Max)
    $ms = [int64]$DaysBack * 86400000
    $typeClause = ($LogonTypes | ForEach-Object { "Data[@Name='LogonType']='$_'" }) -join ' or '
    $xpath = "*[System[(EventID=4624) and TimeCreated[timediff(@SystemTime) <= $ms]]] and *[EventData[$typeClause]]"
    $rows = New-Object System.Collections.Generic.List[object]
    try {
        foreach ($e in @(Get-WinEvent -LogName Security -FilterXPath $xpath -MaxEvents $Max -ErrorAction Stop)) {
            $x = [xml]$e.ToXml(); $d = @{}
            foreach ($n in $x.Event.EventData.Data) { $d[$n.Name] = $n.'#text' }
            if ($d['TargetUserName'] -match $SystemAccounts) { continue }
            $rows.Add([pscustomobject]@{ Time = $e.TimeCreated; User = ('{0}\{1}' -f $d['TargetDomainName'], $d['TargetUserName']); LogonType = $d['LogonType']; SourceIP = $d['IpAddress']; Workstation = $d['WorkstationName']; Process = $d['ProcessName'] })
        }
    } catch { if ($_.Exception.Message -notmatch 'No events were found') { Write-ToolkitLog "Security log query failed: $($_.Exception.Message)" WARN } }
    return $rows
}

#region ---- Main ----
try {
    Write-ToolkitLog "$ScriptName starting on $env:COMPUTERNAME" HEAD
    if ($DaysBack -le 0) { $DaysBack = [int](Get-InputValue -Current '' -EnvName 'daysBack' -Default '90') }
    $doSkipScan = $SkipFileScan.IsPresent -or (Test-Truthy ([Environment]::GetEnvironmentVariable('skipFileScan')))
    $since = (Get-Date).AddDays(-$DaysBack)
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    Write-ToolkitLog ('{0} | {1} | domain {2} | uptime {3:N1} days' -f $env:COMPUTERNAME, $os.Caption, $cs.Domain, ((Get-Date) - $os.LastBootUpTime).TotalDays)

    # Log coverage
    try {
        $oldest = Get-WinEvent -LogName Security -MaxEvents 1 -Oldest -ErrorAction Stop
        Write-ToolkitLog "Security log oldest event: $($oldest.TimeCreated)"
        if ($oldest.TimeCreated -gt $since) { Add-Finding Medium 'Coverage' ("Security log only goes back to {0}, not the full {1} days. RDP history below covers longer." -f $oldest.TimeCreated, $DaysBack) }
    } catch { Write-ToolkitLog "Security log not readable: $($_.Exception.Message)" WARN }

    # 1. Interactive / RDP logons
    Write-ToolkitLog 'Interactive and RDP logons' HEAD
    $inter = @(Get-LogonEvents -LogonTypes @('2', '10', '11', '7') -Max 100000)
    Export-Data -Data $inter -Name 'logons_interactive'
    $typeName = @{ '2' = 'Console'; '7' = 'Unlock'; '10' = 'RDP'; '11' = 'Cached' }
    $userSum = $inter | Group-Object User | ForEach-Object {
        $g = @($_.Group | Sort-Object Time)
        [pscustomobject]@{ User = $_.Name; Logons = $_.Count; First = $g[0].Time; Last = $g[-1].Time; Types = (($g | Group-Object LogonType | ForEach-Object { '{0}={1}' -f $typeName[$_.Name], $_.Count }) -join ' '); Sources = (($g | Where-Object { $_.SourceIP -and $_.SourceIP -ne '-' } | Select-Object -ExpandProperty SourceIP -Unique) -join ', ') }
    } | Sort-Object Last -Descending
    Export-Data -Data $userSum -Name 'users_summary'
    $userSum | Select-Object -First 25 | Format-Table User, Logons, Last, Types -AutoSize | Out-String -Width 200 | Write-Host

    # 2. RDP session history
    $rdp = New-Object System.Collections.Generic.List[object]
    try {
        foreach ($e in @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'; Id = 21, 25; StartTime = $since } -MaxEvents 50000 -ErrorAction Stop)) {
            $x = [xml]$e.ToXml()
            $u = $x.Event.UserData.EventXML.User
            if ($u -and $u -notmatch $SystemAccounts) { $rdp.Add([pscustomobject]@{ Time = $e.TimeCreated; Event = $(if ($e.Id -eq 21) { 'Logon' } else { 'Reconnect' }); User = $u; Address = $x.Event.UserData.EventXML.Address }) }
        }
    } catch { }
    Export-Data -Data $rdp -Name 'rdp_sessions'

    # Weekly trend
    $all = @($inter | Select-Object Time, User) + @($rdp | Select-Object Time, User)
    if ($all.Count -gt 0) {
        $cal = [System.Globalization.CultureInfo]::InvariantCulture.Calendar
        $trend = $all | Group-Object { $d = [datetime]$_.Time; '{0}-W{1:D2}' -f $d.Year, $cal.GetWeekOfYear($d, 'FirstFourDayWeek', 'Monday') } | Sort-Object Name | ForEach-Object {
            [pscustomobject]@{ Week = $_.Name; Events = $_.Count; DistinctUsers = @($_.Group | Select-Object -ExpandProperty User -Unique).Count }
        }
        Export-Data -Data $trend -Name 'weekly_trend'
        $trend | Format-Table -AutoSize | Out-String | Write-Host
        $lastSeen = ($all | Sort-Object Time -Descending | Select-Object -First 1).Time
        $recentUsers = @($all | Where-Object { [datetime]$_.Time -gt (Get-Date).AddDays(-14) } | Select-Object -ExpandProperty User -Unique)
        if ($recentUsers.Count -gt 0) { Add-Finding High 'Usage' ('{0} user(s) logged on interactively in the last 14 days: {1}' -f $recentUsers.Count, ($recentUsers -join ', ')) }
        else { Add-Finding Info 'Usage' "No interactive/RDP logons in the last 14 days (last seen $lastSeen)" }
    } else { Add-Finding Info 'Usage' "No interactive or RDP logons found in $DaysBack days" }

    # Current sessions
    try { $q = (& quser.exe 2>$null) | Out-String; if ($q.Trim()) { Write-ToolkitLog "Current sessions:`n$q" } } catch { }

    # 3. Network logons
    Write-ToolkitLog "Network logons (type 3, max $MaxNetworkEvents events)" HEAD
    $net = @(Get-LogonEvents -LogonTypes @('3') -Max $MaxNetworkEvents)
    if ($net.Count -ge $MaxNetworkEvents) { Add-Finding Low 'Coverage' "Network logon read hit the $MaxNetworkEvents cap: counts are a sample of the most recent events" }
    $netSum = $net | Group-Object User, SourceIP | ForEach-Object { $g = @($_.Group | Sort-Object Time); [pscustomobject]@{ User = $g[0].User; SourceIP = $g[0].SourceIP; Workstation = $g[0].Workstation; Count = $_.Count; First = $g[0].Time; Last = $g[-1].Time } } | Sort-Object Count -Descending
    Export-Data -Data $netSum -Name 'network_logons_summary'
    $netSum | Select-Object -First 20 | Format-Table User, SourceIP, Workstation, Count, Last -AutoSize | Out-String -Width 200 | Write-Host
    $svcAccts = @($netSum | Where-Object { $_.User -match '(?i)svc|service|sql|backup|scan|app' } | Select-Object -ExpandProperty User -Unique)
    if ($svcAccts.Count -gt 0) { Add-Finding Medium 'Dependency' ('Service-style accounts authenticating over the network: {0}' -f ($svcAccts -join ', ')) }

    # 4. Shares and file activity
    Write-ToolkitLog 'SMB shares' HEAD
    $shares = @()
    try { $shares = @(Get-SmbShare -ErrorAction Stop | Where-Object { -not $_.Special -and $_.Name -notin @('print$', 'NETLOGON', 'SYSVOL') -and $_.Path }) } catch { Write-ToolkitLog "Get-SmbShare failed: $($_.Exception.Message)" WARN }
    $openFiles = @(); try { $openFiles = @(Get-SmbOpenFile -ErrorAction Stop) } catch { }
    $sessions  = @(); try { $sessions  = @(Get-SmbSession -ErrorAction Stop) } catch { }
    Export-Data -Data ($sessions | Select-Object ClientComputerName, ClientUserName, NumOpens, SecondsExists, SecondsIdle) -Name 'smb_sessions'
    $shareRows = foreach ($s in $shares) {
        $open = @($openFiles | Where-Object { $_.ShareRelativePath -and $_.Path -like ($s.Path.TrimEnd('\') + '*') })
        $recent = ''; $newest = ''
        if (-not $doSkipScan -and (Test-Path $s.Path)) {
            $n = 0; $cnt = 0; $nw = [datetime]::MinValue
            foreach ($f in (Get-ChildItem -Path $s.Path -Recurse -File -Force -ErrorAction SilentlyContinue | Select-Object -First $FileScanLimit)) {
                $n++; if ($f.LastWriteTime -gt $since) { $cnt++ }; if ($f.LastWriteTime -gt $nw) { $nw = $f.LastWriteTime }
            }
            $recent = $cnt; if ($nw -gt [datetime]::MinValue) { $newest = $nw }
            if ($n -ge $FileScanLimit) { $recent = "$cnt (first $FileScanLimit files)" }
        }
        [pscustomobject]@{ Share = $s.Name; Path = $s.Path; OpenFiles = $open.Count; FilesWrittenInWindow = $recent; NewestWrite = $newest; Description = $s.Description }
    }
    Export-Data -Data $shareRows -Name 'shares'
    $shareRows | Format-Table Share, Path, OpenFiles, FilesWrittenInWindow, NewestWrite -AutoSize | Out-String -Width 200 | Write-Host
    foreach ($r in $shareRows) { if ($r.OpenFiles -gt 0 -or ($r.NewestWrite -and [datetime]$r.NewestWrite -gt (Get-Date).AddDays(-14))) { Add-Finding High 'File share' ('Share {0} is active (open files {1}, newest write {2})' -f $r.Share, $r.OpenFiles, $r.NewestWrite) } }
    if ($sessions.Count -gt 0) { Add-Finding High 'File share' ('{0} SMB session(s) open from: {1}' -f $sessions.Count, (($sessions | Select-Object -ExpandProperty ClientComputerName -Unique) -join ', ')) }

    # 5. Services and tasks with custom accounts
    Write-ToolkitLog 'Services and scheduled tasks running as custom accounts' HEAD
    $builtIn = '(?i)^(LocalSystem|NT AUTHORITY\\.*|NT SERVICE\\.*|LocalService|NetworkService|)$'
    $svc = @(Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue | Where-Object { [string]$_.StartName -notmatch $builtIn })
    Export-Data -Data ($svc | Select-Object Name, DisplayName, StartName, State, StartMode, PathName) -Name 'services_custom_accounts'
    foreach ($s in $svc) { Add-Finding Medium 'Dependency' ('Service {0} runs as {1} ({2})' -f $s.Name, $s.StartName, $s.State) }
    $tasks = @()
    try {
        $tasks = @(Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.TaskPath -notlike '\Microsoft\*' -and $_.Principal.UserId -and $_.Principal.UserId -notmatch '(?i)^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE|S-1-5-18|S-1-5-19|S-1-5-20)$' } | ForEach-Object {
            $i = $_ | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue
            [pscustomobject]@{ Task = $_.TaskPath + $_.TaskName; RunAs = $_.Principal.UserId; State = $_.State; LastRun = $i.LastRunTime; LastResult = $i.LastTaskResult; Action = (($_.Actions | ForEach-Object { ($_.Execute + ' ' + $_.Arguments).Trim() }) -join ' | ') }
        })
    } catch { Write-ToolkitLog "Scheduled task enumeration failed: $($_.Exception.Message)" WARN }
    Export-Data -Data $tasks -Name 'scheduled_tasks_custom'
    foreach ($t in $tasks) { Add-Finding Medium 'Dependency' ('Task {0} runs as {1}, last run {2}' -f $t.Task, $t.RunAs, $t.LastRun) }

    # 6. Network
    Write-ToolkitLog 'Listening ports and inbound connections' HEAD
    try {
        $procMap = @{}; foreach ($p in Get-Process -ErrorAction SilentlyContinue) { $procMap[$p.Id] = $p.ProcessName }
        $listen = @(Get-NetTCPConnection -State Listen -ErrorAction Stop | Where-Object { $_.LocalAddress -notin @('127.0.0.1', '::1') })
        $lPorts = @($listen | Select-Object -ExpandProperty LocalPort -Unique)
        Export-Data -Data ($listen | Sort-Object LocalPort -Unique | Select-Object LocalAddress, LocalPort, @{ n = 'Process'; e = { $procMap[[int]$_.OwningProcess] } }) -Name 'listening_ports'
        $inbound = @(Get-NetTCPConnection -State Established -ErrorAction Stop | Where-Object { $lPorts -contains $_.LocalPort -and $_.RemoteAddress -notin @('127.0.0.1', '::1') -and $_.RemoteAddress -ne $_.LocalAddress })
        $inSum = $inbound | Group-Object LocalPort, RemoteAddress | ForEach-Object { $c = $_.Group[0]; $hostName = ''; try { $hostName = [System.Net.Dns]::GetHostEntry($c.RemoteAddress).HostName } catch { }; [pscustomobject]@{ LocalPort = $c.LocalPort; Process = $procMap[[int]$c.OwningProcess]; RemoteAddress = $c.RemoteAddress; RemoteHost = $hostName; Connections = $_.Count } }
        Export-Data -Data $inSum -Name 'inbound_connections'
        $inSum | Format-Table -AutoSize | Out-String -Width 200 | Write-Host
        foreach ($c in ($inSum | Where-Object { $_.LocalPort -notin @(3389, 5985, 5986, 135) })) { Add-Finding Medium 'Dependency' ('Inbound connection to port {0} ({1}) from {2} {3}' -f $c.LocalPort, $c.Process, $c.RemoteAddress, $c.RemoteHost) }
    } catch { Write-ToolkitLog "Network enumeration failed: $($_.Exception.Message)" WARN }

    # 7. Hosted roles
    Write-ToolkitLog 'Hosted roles and services' HEAD
    if ($cs.DomainRole -ge 4) { Add-Finding High 'Role' 'This server is a DOMAIN CONTROLLER: transfer FSMO roles, update DNS/DHCP options and demote before decommission' }
    foreach ($pair in @(@('DNS', 'DNS Server'), @('DHCPServer', 'DHCP Server'), @('MSSQLSERVER', 'SQL Server (default instance)'), @('W3SVC', 'IIS'), @('Spooler', 'Print Spooler'), @('vmms', 'Hyper-V'), @('TermService', 'Remote Desktop'), @('TermServLicensing', 'RDS Licensing'), @('CertSvc', 'Certificate Authority'), @('WSUSService', 'WSUS'), @('ADSync', 'Entra Connect Sync'), @('AzureADConnectAuthenticationAgent', 'Entra Pass-through Auth agent'))) {
        $s = Get-Service -Name $pair[0] -ErrorAction SilentlyContinue
        if ($s -and $s.Status -eq 'Running' -and $pair[0] -notin @('Spooler', 'TermService')) { Add-Finding High 'Role' "$($pair[1]) is running on this server" }
    }
    try {
        $inst = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL' -ErrorAction Stop).PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object { $_.Name }
        if ($inst) { Add-Finding High 'Role' ('SQL instance(s): {0}' -f ($inst -join ', ')) }
    } catch { }
    try { $printers = @(Get-Printer -ErrorAction Stop | Where-Object { $_.Shared }); if ($printers.Count -gt 0) { Add-Finding High 'Role' ('{0} shared printer(s): {1}' -f $printers.Count, (($printers | Select-Object -ExpandProperty Name) -join ', ')) } } catch { }
    if (Get-Command -Name Get-Website -ErrorAction SilentlyContinue) { try { foreach ($w in @(Get-Website -ErrorAction Stop | Where-Object { $_.State -eq 'Started' })) { Add-Finding High 'Role' ('IIS site {0} bindings {1}' -f $w.Name, (($w.Bindings.Collection | ForEach-Object { $_.bindingInformation }) -join ', ')) } } catch { } }
    if (Get-Command -Name Get-VM -ErrorAction SilentlyContinue) { try { $vms = @(Get-VM -ErrorAction Stop); if ($vms.Count -gt 0) { Add-Finding High 'Role' ('Hyper-V host with {0} VM(s): {1}' -f $vms.Count, (($vms | ForEach-Object { '{0}({1})' -f $_.Name, $_.State }) -join ', ')) } } catch { } }
    if (Get-Command -Name Get-WindowsFeature -ErrorAction SilentlyContinue) {
        try { Export-Data -Data (Get-WindowsFeature -ErrorAction Stop | Where-Object { $_.Installed -and $_.FeatureType -eq 'Role' } | Select-Object Name, DisplayName) -Name 'installed_roles' } catch { }
    }
    $sw = foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*') { Get-ItemProperty -Path $k -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -and -not $_.SystemComponent } | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate }
    Export-Data -Data ($sw | Sort-Object DisplayName -Unique) -Name 'installed_software'
}
catch { Write-ToolkitLog "Unhandled error: $($_.Exception.Message) at line $($_.InvocationInfo.ScriptLineNumber)" ERROR }
finally { Show-Summary }
#endregion
