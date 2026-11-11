#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Hyper-V host and RDS health check, plus post-incident triage around a hang or outage time.

.DESCRIPTION
    Built for RMM use (runs as SYSTEM, no prompts). Sections run only where the role exists:
    Hyper-V host
      - VM state, uptime, CPU, memory assigned vs demand, dynamic memory, integration services status
      - Host memory oversubscription, VHD/VHDX sizes and free space on the volumes holding them
      - Checkpoints older than 7 days (AVHDX growth)
      - Replica state, health and last replication time, and replica certificate expiry
    Any server (host or guest)
      - Performance snapshot: CPU, available memory, disk latency, queue length
      - Volume free space and physical disk health
      - Critical/error events around IncidentTime (or the last DaysBack days): unexpected shutdowns, bugchecks,
        resource exhaustion, disk resets/timeouts, NTFS, Hyper-V VMMS/Worker errors
      - Top memory processes and memory per user (RDS session hosts)
    RDS
      - Licensing mode, configured license servers, grace period days left
      - License server key packs: total / issued / available CALs
      - Logons (1149) and disconnect reasons (LocalSessionManager 40) in the window

.PARAMETER IncidentTime
    Optional time of the hang/outage, e.g. "11/10/2026 2:15 PM". Events are pulled for +/- WindowMinutes around it.
.PARAMETER WindowMinutes
    Minutes either side of IncidentTime.
.PARAMETER DaysBack
    Event window when IncidentTime is not given.

.NOTES
    NinjaOne: run as SYSTEM. Script variables incidentTime, windowMinutes, daysBack are read from environment variables.
    Windows PowerShell 5.1. Read-only. Output: C:\Users\Public\Documents\MspToolkit\Get-HyperVRdsHealth (last 5 runs kept).
#>
[CmdletBinding()]
param(
    [string]$IncidentTime,
    [int]$WindowMinutes = 0,
    [int]$DaysBack = 0
)

#region ---- Common helpers (inline for RMM use) ----
$ScriptName = 'Get-HyperVRdsHealth'
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

#region ---- Main ----
try {
    Write-ToolkitLog "$ScriptName starting on $env:COMPUTERNAME" HEAD
    $IncidentTime = Get-InputValue -Current $IncidentTime -EnvName 'incidentTime' -Default ''
    if ($WindowMinutes -le 0) { $WindowMinutes = [int](Get-InputValue -Current '' -EnvName 'windowMinutes' -Default '60') }
    if ($DaysBack -le 0)      { $DaysBack      = [int](Get-InputValue -Current '' -EnvName 'daysBack' -Default '7') }
    if ($IncidentTime) {
        try { $t = [datetime]::Parse($IncidentTime); $evStart = $t.AddMinutes(-$WindowMinutes); $evEnd = $t.AddMinutes($WindowMinutes) }
        catch { Write-ToolkitLog "Could not parse IncidentTime '$IncidentTime', using DaysBack" WARN; $evStart = (Get-Date).AddDays(-$DaysBack); $evEnd = Get-Date }
    } else { $evStart = (Get-Date).AddDays(-$DaysBack); $evEnd = Get-Date }
    Write-ToolkitLog ('Event window: {0} to {1}' -f $evStart, $evEnd)

    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem
    $totalGb = [math]::Round($cs.TotalPhysicalMemory / 1GB, 1)
    $freeGb  = [math]::Round($os.FreePhysicalMemory * 1KB / 1GB, 1)
    Write-ToolkitLog ('{0} | {1} | {2} GB RAM ({3} GB free) | {4} logical CPUs | uptime {5:N1} days | model {6}' -f $env:COMPUTERNAME, $os.Caption, $totalGb, $freeGb, $cs.NumberOfLogicalProcessors, ((Get-Date) - $os.LastBootUpTime).TotalDays, $cs.Model)

    # ---- Performance snapshot ----
    Write-ToolkitLog 'Performance snapshot (5 samples, 2s apart)' HEAD
    $counters = '\Processor(_Total)\% Processor Time', '\Memory\Available MBytes', '\Memory\Pages/sec', '\LogicalDisk(*)\Avg. Disk sec/Read', '\LogicalDisk(*)\Avg. Disk sec/Write', '\LogicalDisk(*)\Current Disk Queue Length'
    try {
        $samples = Get-Counter -Counter $counters -SampleInterval 2 -MaxSamples 5 -ErrorAction SilentlyContinue
        $perf = $samples.CounterSamples | Where-Object { $_.InstanceName -ne '_total' -or $_.Path -match 'processor' } | Group-Object Path | ForEach-Object { [pscustomobject]@{ Counter = $_.Name -replace '^\\\\[^\\]+', ''; Avg = [math]::Round(($_.Group | Measure-Object CookedValue -Average).Average, 4); Max = [math]::Round(($_.Group | Measure-Object CookedValue -Maximum).Maximum, 4) } }
        Export-Data -Data $perf -Name 'perf_snapshot'
        $perf | Format-Table -AutoSize | Out-String -Width 200 | Write-Host
        foreach ($p in $perf) {
            if ($p.Counter -match 'Processor Time' -and $p.Avg -gt 85) { Add-Finding High 'CPU' "CPU averaging $($p.Avg)%" }
            if ($p.Counter -match 'Available MBytes' -and $p.Avg -lt 1024) { Add-Finding High 'Memory' "Only $($p.Avg) MB RAM available" }
            if ($p.Counter -match 'Avg\. Disk sec/(Read|Write)' -and $p.Avg -gt 0.025) { Add-Finding Medium 'Disk latency' ('{0} averaging {1:N0} ms (>25 ms is slow)' -f $p.Counter, ($p.Avg * 1000)) }
            if ($p.Counter -match 'Queue Length' -and $p.Avg -gt 4) { Add-Finding Medium 'Disk queue' "$($p.Counter) averaging $($p.Avg)" }
        }
    } catch { Write-ToolkitLog "Performance counters unavailable: $($_.Exception.Message)" WARN }

    # ---- Storage ----
    Write-ToolkitLog 'Storage' HEAD
    try {
        $vols = @(Get-Volume -ErrorAction Stop | Where-Object { $_.DriveLetter -and $_.Size -gt 0 })
        $volRows = foreach ($v in $vols) { [pscustomobject]@{ Drive = $v.DriveLetter; Label = $v.FileSystemLabel; SizeGB = [math]::Round($v.Size / 1GB, 1); FreeGB = [math]::Round($v.SizeRemaining / 1GB, 1); FreePct = [math]::Round(($v.SizeRemaining / $v.Size) * 100, 1); Health = $v.HealthStatus } }
        $volRows | Format-Table -AutoSize | Out-String | Write-Host
        Export-Data -Data $volRows -Name 'volumes'
        foreach ($v in $volRows) {
            if ($v.FreePct -lt 10) { Add-Finding High 'Storage' "Volume $($v.Drive): only $($v.FreePct)% free ($($v.FreeGB) GB)" } elseif ($v.FreePct -lt 20) { Add-Finding Medium 'Storage' "Volume $($v.Drive): $($v.FreePct)% free" }
            if ($v.Health -ne 'Healthy') { Add-Finding High 'Storage' "Volume $($v.Drive): health $($v.Health)" }
        }
        foreach ($d in @(Get-PhysicalDisk -ErrorAction SilentlyContinue)) { if ($d.HealthStatus -ne 'Healthy' -or [string]$d.OperationalStatus -ne 'OK') { Add-Finding High 'Storage' ('Physical disk {0} ({1}): {2} / {3}' -f $d.FriendlyName, $d.MediaType, $d.HealthStatus, $d.OperationalStatus) } }
    } catch { Write-ToolkitLog "Volume info unavailable: $($_.Exception.Message)" WARN }

    # ---- Hyper-V ----
    if (Get-Command -Name Get-VM -ErrorAction SilentlyContinue) {
        Write-ToolkitLog 'Hyper-V host' HEAD
        try {
            $vms = @(Get-VM -ErrorAction Stop)
            $vmRows = foreach ($vm in $vms) {
                $isvc = (@($vm.VMIntegrationService | Where-Object { $_.Enabled -and $_.PrimaryStatusDescription -ne 'OK' } | ForEach-Object { $_.Name }) -join ', ')
                [pscustomobject]@{
                    Name = $vm.Name; State = [string]$vm.State; Status = $vm.Status; UptimeH = [math]::Round($vm.Uptime.TotalHours, 1); CPU = $vm.CPUUsage; vCPU = $vm.ProcessorCount
                    AssignedGB = [math]::Round($vm.MemoryAssigned / 1GB, 1); DemandGB = [math]::Round($vm.MemoryDemand / 1GB, 1); DynamicMemory = $vm.DynamicMemoryEnabled
                    StartupGB = [math]::Round($vm.MemoryStartup / 1GB, 1); MaxGB = [math]::Round($vm.MemoryMaximum / 1GB, 1); Generation = $vm.Generation; Version = $vm.Version; IntegrationIssues = $isvc
                }
            }
            $vmRows | Format-Table Name, State, UptimeH, CPU, AssignedGB, DemandGB, DynamicMemory, Status -AutoSize | Out-String -Width 200 | Write-Host
            Export-Data -Data $vmRows -Name 'hyperv_vms'
            $assigned = ($vmRows | Measure-Object AssignedGB -Sum).Sum
            $startup = ($vmRows | Where-Object { $_.State -eq 'Running' } | Measure-Object StartupGB -Sum).Sum
            Write-ToolkitLog ('Host RAM {0} GB | assigned to running VMs {1} GB | free {2} GB' -f $totalGb, $assigned, $freeGb)
            if ($freeGb -lt 2) { Add-Finding High 'Hyper-V memory' "Host has only $freeGb GB free: VMs cannot grow or start" }
            foreach ($v in $vmRows) {
                if ($v.State -eq 'Running' -and $v.DemandGB -gt 0 -and $v.AssignedGB -gt 0 -and $v.DemandGB -ge ($v.AssignedGB * 0.95)) { Add-Finding High 'VM memory' ('{0}: demand {1} GB vs assigned {2} GB (memory pressure)' -f $v.Name, $v.DemandGB, $v.AssignedGB) }
                if ($v.DynamicMemory -and $v.State -eq 'Running' -and $v.AssignedGB -ge $v.MaxGB) { Add-Finding Medium 'VM memory' ('{0}: at dynamic memory maximum ({1} GB)' -f $v.Name, $v.MaxGB) }
                if ($v.Status -and $v.Status -ne 'Operating normally') { Add-Finding Medium 'VM' "$($v.Name): $($v.Status)" }
                if ($v.IntegrationIssues) { Add-Finding Low 'VM' "$($v.Name): integration services not OK: $($v.IntegrationIssues)" }
                if ($v.State -notin @('Running', 'Off')) { Add-Finding Medium 'VM' "$($v.Name) is $($v.State)" }
            }
            # Disks
            $vhdRows = New-Object System.Collections.Generic.List[object]
            foreach ($vm in $vms) {
                foreach ($hd in @(Get-VMHardDiskDrive -VM $vm -ErrorAction SilentlyContinue)) {
                    if (-not $hd.Path) { continue }
                    try { $vhd = Get-VHD -Path $hd.Path -ErrorAction Stop; $vhdRows.Add([pscustomobject]@{ VM = $vm.Name; Path = $hd.Path; Type = [string]$vhd.VhdType; MaxGB = [math]::Round($vhd.Size / 1GB, 1); FileGB = [math]::Round($vhd.FileSize / 1GB, 1); Fragmentation = $vhd.FragmentationPercentage; Parent = $vhd.ParentPath }) }
                    catch { $vhdRows.Add([pscustomobject]@{ VM = $vm.Name; Path = $hd.Path; Type = 'unreadable'; MaxGB = ''; FileGB = ''; Fragmentation = ''; Parent = $_.Exception.Message }) }
                }
            }
            Export-Data -Data $vhdRows -Name 'hyperv_disks'
            foreach ($drv in ($vhdRows | Where-Object { $_.Type -eq 'Dynamic' -or $_.Type -eq 'Differencing' } | Group-Object { ([string]$_.Path).Substring(0, 1) })) {
                $growth = ($drv.Group | ForEach-Object { [double]$_.MaxGB - [double]$_.FileGB } | Measure-Object -Sum).Sum
                $vol = Get-Volume -DriveLetter $drv.Name -ErrorAction SilentlyContinue
                if ($vol -and $growth -gt ($vol.SizeRemaining / 1GB)) { Add-Finding High 'Hyper-V storage' ('Dynamic disks on {0}: can grow {1:N0} GB more but only {2:N0} GB free (VMs pause when the volume fills)' -f $drv.Name, $growth, ($vol.SizeRemaining / 1GB)) }
            }
            foreach ($u in ($vhdRows | Where-Object { $_.Type -eq 'unreadable' })) { Add-Finding Medium 'Hyper-V storage' "$($u.VM): cannot read $($u.Path): $($u.Parent)" }
            # Checkpoints
            $snaps = @(Get-VMSnapshot -VM $vms -ErrorAction SilentlyContinue)
            Export-Data -Data ($snaps | Select-Object VMName, Name, SnapshotType, CreationTime) -Name 'hyperv_checkpoints'
            foreach ($s in ($snaps | Where-Object { $_.CreationTime -lt (Get-Date).AddDays(-7) })) { Add-Finding Medium 'Checkpoint' ('{0}: checkpoint "{1}" from {2} (AVHDX keeps growing; merge it)' -f $s.VMName, $s.Name, $s.CreationTime) }
            # Replica
            $rep = @(Get-VMReplication -ErrorAction SilentlyContinue)
            if ($rep.Count -gt 0) {
                $repRows = foreach ($r in $rep) {
                    $m = $null; try { $m = Measure-VMReplication -VMName $r.VMName -ErrorAction Stop } catch { }
                    [pscustomobject]@{ VM = $r.VMName; Mode = [string]$r.Mode; State = [string]$r.State; Health = [string]$r.Health; Primary = $r.PrimaryServer; Replica = $r.ReplicaServer; LastReplication = $m.LastReplicationTime; CertThumbprint = $r.CertificateThumbprint; AuthType = [string]$r.AuthenticationType }
                }
                $repRows | Format-Table VM, Mode, State, Health, LastReplication -AutoSize | Out-String -Width 200 | Write-Host
                Export-Data -Data $repRows -Name 'hyperv_replica'
                foreach ($r in $repRows) {
                    if ($r.Health -ne 'Normal') { Add-Finding High 'Replica' "$($r.VM): replication health $($r.Health), state $($r.State)" }
                    if ($r.LastReplication -and ([datetime]$r.LastReplication) -lt (Get-Date).AddHours(-24)) { Add-Finding High 'Replica' "$($r.VM): last replication $($r.LastReplication)" }
                }
                $thumbs = @($repRows | Where-Object { $_.CertThumbprint } | Select-Object -ExpandProperty CertThumbprint -Unique)
                try { $srv = Get-VMReplicationServer -ErrorAction Stop; if ($srv.CertificateThumbprint) { $thumbs += $srv.CertificateThumbprint } } catch { }
                foreach ($th in ($thumbs | Select-Object -Unique)) {
                    $cert = Get-ChildItem -Path ('Cert:\LocalMachine\My\{0}' -f $th) -ErrorAction SilentlyContinue
                    if (-not $cert) { Add-Finding High 'Replica cert' "Replica certificate $th not found in LocalMachine\My" }
                    elseif ($cert.NotAfter -lt (Get-Date)) { Add-Finding High 'Replica cert' "Replica certificate $th EXPIRED $($cert.NotAfter)" }
                    elseif ($cert.NotAfter -lt (Get-Date).AddDays(30)) { Add-Finding Medium 'Replica cert' "Replica certificate $th expires $($cert.NotAfter)" }
                    else { Write-ToolkitLog "Replica certificate $th valid until $($cert.NotAfter)" OK }
                }
            }
        } catch { Write-ToolkitLog "Hyper-V checks failed: $($_.Exception.Message)" ERROR }
    }

    # ---- Events ----
    Write-ToolkitLog 'Critical and error events in window' HEAD
    $evRows = New-Object System.Collections.Generic.List[object]
    $queries = @(
        @{ LogName = 'System'; Level = 1, 2; StartTime = $evStart; EndTime = $evEnd },
        @{ LogName = 'System'; Id = 41, 1074, 1076, 6005, 6006, 6008, 1001, 2004, 129, 153, 157; StartTime = $evStart; EndTime = $evEnd },
        @{ LogName = 'Application'; Level = 1, 2; StartTime = $evStart; EndTime = $evEnd }
    )
    foreach ($ln in 'Microsoft-Windows-Hyper-V-VMMS-Admin', 'Microsoft-Windows-Hyper-V-Worker-Admin') { if (Get-WinEvent -ListLog $ln -ErrorAction SilentlyContinue) { $queries += @{ LogName = $ln; Level = 1, 2, 3; StartTime = $evStart; EndTime = $evEnd } } }
    foreach ($q in $queries) {
        try { foreach ($e in @(Get-WinEvent -FilterHashtable $q -MaxEvents 1000 -ErrorAction Stop)) { $evRows.Add([pscustomobject]@{ Time = $e.TimeCreated; Log = $e.LogName; Id = $e.Id; Level = $e.LevelDisplayName; Provider = $e.ProviderName; Message = (([string]$e.Message) -replace '\s+', ' ') }) } } catch { }
    }
    $evRows = @($evRows | Sort-Object Time, Id, Provider -Unique)
    Export-Data -Data $evRows -Name 'events'
    $known = @{ 41 = 'Kernel-Power: unexpected reboot (hard hang, power loss or reset)'; 6008 = 'previous shutdown was unexpected'; 1001 = 'bugcheck / crash'; 2004 = 'resource exhaustion (low virtual memory)'; 129 = 'storage reset to device (timeout)'; 153 = 'disk IO retried'; 157 = 'disk surprise removed'; 1074 = 'planned restart/shutdown initiated' }
    foreach ($g in ($evRows | Where-Object { $known.ContainsKey([int]$_.Id) -and ($_.Provider -notmatch 'Application' ) } | Group-Object Id)) {
        $sev = 'High'; if ([int]$g.Name -eq 1074) { $sev = 'Info' } elseif ([int]$g.Name -in @(153)) { $sev = 'Medium' }
        $last = ($g.Group | Sort-Object Time -Descending | Select-Object -First 1)
        Add-Finding $sev 'Events' ('Event {0} x{1} ({2}), last {3}' -f $g.Name, $g.Count, $known[[int]$g.Name], $last.Time)
    }
    $top = $evRows | Where-Object { $_.Level -in @('Critical', 'Error') } | Group-Object Provider, Id | Sort-Object Count -Descending | Select-Object -First 10
    Write-Host 'Top error sources in window:'
    $top | ForEach-Object { $s = $_.Group[0]; '{0,5}x {1} {2}: {3}' -f $_.Count, $s.Provider, $s.Id, ($s.Message.Substring(0, [math]::Min(140, $s.Message.Length))) } | Write-Host
    $hvErr = @($evRows | Where-Object { $_.Log -like '*Hyper-V*' -and $_.Level -in @('Critical', 'Error') })
    if ($hvErr.Count -gt 0) { Add-Finding Medium 'Hyper-V events' "$($hvErr.Count) Hyper-V VMMS/Worker error(s) in window (see events.csv)" }

    # ---- Memory consumers ----
    Write-ToolkitLog 'Top memory consumers' HEAD
    try {
        $procs = @(Get-Process -IncludeUserName -ErrorAction Stop)
        $procs | Sort-Object WorkingSet64 -Descending | Select-Object -First 15 Name, Id, UserName, @{ n = 'WorkingSetMB'; e = { [math]::Round($_.WorkingSet64 / 1MB) } }, @{ n = 'PrivateMB'; e = { [math]::Round($_.PrivateMemorySize64 / 1MB) } } | Format-Table -AutoSize | Out-String -Width 200 | Write-Host
        $perUser = $procs | Where-Object { $_.UserName } | Group-Object UserName | ForEach-Object { [pscustomobject]@{ User = $_.Name; Processes = $_.Count; WorkingSetGB = [math]::Round((($_.Group | Measure-Object WorkingSet64 -Sum).Sum) / 1GB, 2) } } | Sort-Object WorkingSetGB -Descending
        Export-Data -Data $perUser -Name 'memory_by_user'
        $perUser | Select-Object -First 10 | Format-Table -AutoSize | Out-String | Write-Host
        $hog = $procs | Sort-Object PrivateMemorySize64 -Descending | Select-Object -First 1
        if ($hog -and $hog.PrivateMemorySize64 -gt ($cs.TotalPhysicalMemory * 0.3)) { Add-Finding High 'Memory' ('{0} (PID {1}, {2}) is using {3:N1} GB private memory (>30% of RAM)' -f $hog.Name, $hog.Id, $hog.UserName, ($hog.PrivateMemorySize64 / 1GB)) }
    } catch { Write-ToolkitLog "Process enumeration failed: $($_.Exception.Message)" WARN }

    # ---- RDS ----
    $rdsSh = Get-Service -Name TermService -ErrorAction SilentlyContinue
    $tsSetting = $null
    try { $tsSetting = Get-CimInstance -Namespace 'root/cimv2/terminalservices' -ClassName Win32_TerminalServiceSetting -ErrorAction Stop } catch { }
    if ($tsSetting) {
        Write-ToolkitLog 'RDS' HEAD
        $mode = switch ([int]$tsSetting.LicensingType) { 2 {'Per Device'} 4 {'Per User'} 5 {'Not configured'} 6 {'AAD Per User'} default { [string]$tsSetting.LicensingType } }
        Write-ToolkitLog "Licensing mode: $mode | TerminalServerMode: $($tsSetting.TerminalServerMode)"
        if ([int]$tsSetting.TerminalServerMode -eq 1) {
            if ([int]$tsSetting.LicensingType -eq 5) { Add-Finding High 'RDS licensing' 'Session host licensing mode is not configured' }
            try { $ls = Invoke-CimMethod -InputObject $tsSetting -MethodName GetSpecifiedLicenseServerList -ErrorAction Stop; Write-ToolkitLog ('License servers: {0}' -f (@($ls.SpecifiedLSList) -join ', ')); if (@($ls.SpecifiedLSList).Count -eq 0) { Add-Finding High 'RDS licensing' 'No license server specified' } } catch { }
            try { $gp = Get-CimInstance -Namespace 'root/cimv2/terminalservices' -ClassName Win32_TerminalServiceSetting | Invoke-CimMethod -MethodName GetGracePeriodDays -ErrorAction Stop; if ($gp.DaysLeft -gt 0) { Add-Finding Medium 'RDS licensing' "Grace period active: $($gp.DaysLeft) day(s) left" } } catch { }
        }
        try {
            $packs = @(Get-CimInstance -ClassName Win32_TSLicenseKeyPack -ErrorAction Stop)
            $packRows = $packs | Select-Object ProductVersion, TypeAndModel, KeyPackType, TotalLicenses, IssuedLicenses, AvailableLicenses, ExpirationDate
            Export-Data -Data $packRows -Name 'rds_cal_packs'
            $packRows | Format-Table -AutoSize | Out-String -Width 200 | Write-Host
            foreach ($p in ($packs | Where-Object { $_.TotalLicenses -gt 0 -and $_.TotalLicenses -lt 4294967295 })) { if ($p.AvailableLicenses -le 0) { Add-Finding High 'RDS CALs' ('{0} {1}: 0 available ({2}/{3} issued)' -f $p.ProductVersion, $p.TypeAndModel, $p.IssuedLicenses, $p.TotalLicenses) } }
        } catch { Write-ToolkitLog 'Not an RDS license server (no key packs)' }
        try {
            $lg = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'; Id = 1149; StartTime = $evStart; EndTime = $evEnd } -MaxEvents 5000 -ErrorAction Stop)
            Write-ToolkitLog "RDP authentications (1149) in window: $($lg.Count)"
        } catch { }
        try {
            $dc = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'; Id = 40; StartTime = $evStart; EndTime = $evEnd } -MaxEvents 5000 -ErrorAction Stop)
            $reasons = @{ 0 = 'no additional info'; 2 = 'admin disconnected the session'; 3 = 'admin logged off the session'; 5 = 'another connection replaced this one'; 11 = 'user disconnected'; 12 = 'user logged off'; 1026 = 'client disconnected (network or client closed)'; 1030 = 'network / security layer error'; 1032 = 'client initiated'; 2056 = 'licensing: could not get a license'; 2055 = 'licensing protocol error'; 2058 = 'license store error'; 7 = 'server ran out of memory' }
            $dcRows = foreach ($e in $dc) { $x = [xml]$e.ToXml(); $code = [int]$x.Event.UserData.EventXML.Reason; [pscustomobject]@{ Time = $e.TimeCreated; Session = $x.Event.UserData.EventXML.Session; Reason = $code; Meaning = $reasons[$code] } }
            Export-Data -Data $dcRows -Name 'rds_disconnects'
            foreach ($g in ($dcRows | Group-Object Reason | Sort-Object Count -Descending)) {
                $sev = 'Info'; if ([int]$g.Name -in @(2055, 2056, 2058, 7, 1030)) { $sev = 'High' } elseif ([int]$g.Name -eq 1026) { $sev = 'Low' }
                Add-Finding $sev 'RDS disconnects' ('Reason {0} ({1}): {2}x' -f $g.Name, $reasons[[int]$g.Name], $g.Count)
            }
        } catch { }
    } elseif ($rdsSh) { Write-ToolkitLog 'RDS session host WMI not available (not a session host)' }
}
catch { Write-ToolkitLog "Unhandled error: $($_.Exception.Message) at line $($_.InvocationInfo.ScriptLineNumber)" ERROR }
finally { Show-Summary }
#endregion
