#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Windows Update triage for a device with failed or missing patches, with optional component reset.

.DESCRIPTION
    Built for RMM use (runs as SYSTEM, no prompts). Checks:
      - OS build/UBR, uptime, free space on the system drive and SoftwareDistribution size
      - Pending reboot sources (CBS, Windows Update, pending file renames, computer rename)
      - Update-related services and their start types
      - Windows Update / WSUS policy that can conflict with RMM patching
      - Update history with HRESULTs decoded to likely cause, plus WindowsUpdateClient failure events
      - Whether specific KBs are installed (Get-HotFix and update history)
      - Component store health (DISM /CheckHealth)
      - Optional: pending updates search (slow)
    Remediation (opt-in): stops update services, renames SoftwareDistribution and catroot2,
    runs DISM /RestoreHealth and SFC when the store is flagged, restarts services and triggers a scan.

.PARAMETER KbList
    Comma-separated KB numbers to verify, for example KB5044284,KB5043050.
.PARAMETER DaysBack
    Update history and event log window.
.PARAMETER SearchPending
    Run a pending update search through the Windows Update Agent (can take several minutes).
.PARAMETER Remediate
    Reset Windows Update components (and repair the component store if it is flagged).

.NOTES
    NinjaOne: run as SYSTEM. Script variables with the same names (kbList, daysBack, searchPending, remediate)
    are read from environment variables when parameters are not passed.
    Windows PowerShell 5.1. Output: C:\Users\Public\Documents\MspToolkit\Invoke-PatchTriage (last 5 runs kept).
#>
[CmdletBinding()]
param(
    [string]$KbList,
    [int]$DaysBack = 0,
    [switch]$SearchPending,
    [switch]$Remediate
)

#region ---- Common helpers (inline for RMM use) ----
$ScriptName = 'Invoke-PatchTriage'
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

$HResultHints = @{
    '0x800F0922' = 'Servicing stack / boot partition or WinRE space, or VPN/proxy blocking'
    '0x80073712' = 'Component store corruption (DISM /RestoreHealth)'
    '0x800F081F' = 'Source files missing (component store corruption)'
    '0x800F0831' = 'Missing baseline package (component store corruption)'
    '0x800F0988' = 'Component cleanup needed (DISM /StartComponentCleanup)'
    '0x8007000D' = 'Corrupt data in update store (reset SoftwareDistribution)'
    '0x80070002' = 'File not found in update store (reset SoftwareDistribution)'
    '0x80070003' = 'Path not found in update store (reset SoftwareDistribution)'
    '0x80070005' = 'Access denied (AV/EDR interference or permissions)'
    '0x80070070' = 'Not enough disk space'
    '0x80070643' = 'Install failure (MSI or WinRE partition too small for WinRE updates)'
    '0x8024402C' = 'Proxy or DNS problem reaching Windows Update'
    '0x80244022' = 'Windows Update service returned 503 (retry)'
    '0x8024401C' = 'Timeout reaching update server (network / WSUS)'
    '0x80240034' = 'Download failed (network, proxy or delivery optimization)'
    '0x80242016' = 'Post-reboot operation failed (pending reboot / retry)'
    '0x8024A105' = 'Update agent internal error (reset components)'
    '0x80240FFF' = 'Update not applicable or policy conflict'
    '0x8024200D' = 'Update needs to be downloaded again (reset SoftwareDistribution)'
    '0x800705B4' = 'Operation timed out'
    '0x80070BC9' = 'Pending reboot blocks install'
    '0x800F0920' = 'Update timed out (often pending reboot or slow disk)'
}

#region ---- Main ----
try {
    Write-ToolkitLog "$ScriptName starting on $env:COMPUTERNAME" HEAD
    $KbList        = Get-InputValue -Current $KbList -EnvName 'kbList' -Default ''
    if ($DaysBack -le 0) { $DaysBack = [int](Get-InputValue -Current '' -EnvName 'daysBack' -Default '60') }
    $doSearch      = $SearchPending.IsPresent -or (Test-Truthy ([Environment]::GetEnvironmentVariable('searchPending')))
    $doRemediate   = $Remediate.IsPresent -or (Test-Truthy ([Environment]::GetEnvironmentVariable('remediate')))
    $since         = (Get-Date).AddDays(-$DaysBack)

    # OS and basics
    $os  = Get-CimInstance -ClassName Win32_OperatingSystem
    $cv  = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue
    $up  = (Get-Date) - $os.LastBootUpTime
    Write-ToolkitLog ('{0} {1} build {2}.{3} | uptime {4:N1} days' -f $os.Caption, $cv.DisplayVersion, $os.BuildNumber, $cv.UBR, $up.TotalDays)
    if ($up.TotalDays -gt 30) { Add-Finding Medium 'Uptime' ('No reboot in {0:N0} days' -f $up.TotalDays) }
    $sysDrive = Get-CimInstance -ClassName Win32_LogicalDisk -Filter ("DeviceID='{0}'" -f $env:SystemDrive)
    $freeGb = [math]::Round($sysDrive.FreeSpace / 1GB, 1)
    Write-ToolkitLog "Free space on $($env:SystemDrive): $freeGb GB"
    if ($freeGb -lt 10) { Add-Finding High 'Disk' "Only $freeGb GB free on $($env:SystemDrive) (feature/cumulative updates need 10+ GB)" }
    $sd = Join-Path -Path $env:windir -ChildPath 'SoftwareDistribution'
    try { $sdGb = [math]::Round(((Get-ChildItem -Path $sd -Recurse -Force -File -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum) / 1GB, 2); Write-ToolkitLog "SoftwareDistribution size: $sdGb GB" } catch { }

    # Pending reboot
    $pending = @()
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $pending += 'CBS' }
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $pending += 'WindowsUpdate' }
    $pfro = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations
    if ($pfro) { $pending += 'PendingFileRename' }
    $cn1 = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName' -ErrorAction SilentlyContinue).ComputerName
    $cn2 = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName' -ErrorAction SilentlyContinue).ComputerName
    if ($cn1 -and $cn2 -and $cn1 -ne $cn2) { $pending += 'ComputerRename' }
    if ($pending.Count -gt 0) { Add-Finding High 'Reboot' ('Reboot pending: {0}. Reboot before retrying updates.' -f ($pending -join ', ')) }

    # Services
    $svcRows = foreach ($n in 'wuauserv', 'bits', 'cryptsvc', 'TrustedInstaller', 'UsoSvc', 'WaaSMedicSvc', 'DoSvc', 'msiserver') {
        $s = Get-CimInstance -ClassName Win32_Service -Filter ("Name='{0}'" -f $n) -ErrorAction SilentlyContinue
        if ($s) {
            if ($s.StartMode -eq 'Disabled' -and $n -in @('wuauserv', 'bits', 'cryptsvc', 'TrustedInstaller', 'UsoSvc')) { Add-Finding High 'Service' "$n is Disabled" }
            [pscustomobject]@{ Name = $n; State = $s.State; StartMode = $s.StartMode; Account = $s.StartName }
        }
    }
    $svcRows | Format-Table -AutoSize | Out-String | Write-Host
    Export-Data -Data $svcRows -Name 'services'

    # Policy
    $wuPol = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -ErrorAction SilentlyContinue
    $auPol = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -ErrorAction SilentlyContinue
    if ($auPol.UseWUServer -eq 1 -and $wuPol.WUServer) { Add-Finding Medium 'Policy' "Device points at WSUS ($($wuPol.WUServer)). Conflicts with RMM patching if WSUS is gone or not approving." }
    if ($wuPol.DisableWindowsUpdateAccess -eq 1) { Add-Finding Medium 'Policy' 'DisableWindowsUpdateAccess = 1' }
    if ($auPol.NoAutoUpdate -eq 1) { Add-Finding Info 'Policy' 'NoAutoUpdate = 1 (expected when RMM manages patching)' }
    if ($wuPol.TargetReleaseVersion -eq 1) { Add-Finding Info 'Policy' "Feature update pinned to $($wuPol.ProductVersion) $($wuPol.TargetReleaseVersionInfo)" }
    if ($wuPol.DoNotConnectToWindowsUpdateInternetLocations -eq 1) { Add-Finding Medium 'Policy' 'DoNotConnectToWindowsUpdateInternetLocations = 1 (blocks Microsoft Update when WSUS is unreachable)' }
    if ($wuPol.DeferQualityUpdates -eq 1) { Add-Finding Info 'Policy' "Quality updates deferred $($wuPol.DeferQualityUpdatesPeriodInDays) days" }

    # Update history
    $history = New-Object System.Collections.Generic.List[object]
    try {
        $session  = New-Object -ComObject 'Microsoft.Update.Session'
        $searcher = $session.CreateUpdateSearcher()
        $count    = $searcher.GetTotalHistoryCount()
        if ($count -gt 0) {
            foreach ($h in $searcher.QueryHistory(0, [math]::Min($count, 500))) {
                if ($h.Date -lt $since) { continue }
                $rc = switch ($h.ResultCode) { 1 {'InProgress'} 2 {'Succeeded'} 3 {'SucceededWithErrors'} 4 {'Failed'} 5 {'Aborted'} default {'Unknown'} }
                $hex = ''; if ($h.HResult -ne 0) { $hex = '0x{0:X8}' -f $h.HResult }
                $hint = ''; if ($hex -and $HResultHints.ContainsKey($hex)) { $hint = $HResultHints[$hex] }
                $history.Add([pscustomobject]@{ Date = $h.Date; Result = $rc; HResult = $hex; Hint = $hint; Title = $h.Title })
            }
        }
    } catch { Write-ToolkitLog "Update history unavailable: $($_.Exception.Message)" WARN }
    Export-Data -Data $history -Name 'update_history'
    $failed = @($history | Where-Object { $_.Result -in @('Failed', 'Aborted') })
    $lastOk = $history | Where-Object { $_.Result -eq 'Succeeded' } | Sort-Object Date -Descending | Select-Object -First 1
    if ($lastOk) { Write-ToolkitLog ('Last successful install: {0} {1}' -f $lastOk.Date, $lastOk.Title) } else { Add-Finding Medium 'History' "No successful update installs in the last $DaysBack days" }
    foreach ($g in ($failed | Group-Object Title)) {
        $f = $g.Group | Sort-Object Date -Descending | Select-Object -First 1
        $ok = @($history | Where-Object { $_.Title -eq $g.Name -and $_.Result -eq 'Succeeded' -and $_.Date -gt $f.Date }).Count -gt 0
        if (-not $ok) { Add-Finding High 'Failed update' ('{0} failed {1}x, last {2} {3} {4}' -f $g.Name, $g.Count, $f.Date, $f.HResult, $f.Hint) }
    }

    # Events
    try {
        $ev = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-WindowsUpdateClient/Operational'; Id = 20, 25, 31; StartTime = $since } -MaxEvents 200 -ErrorAction Stop)
        Export-Data -Data ($ev | Select-Object TimeCreated, Id, @{ n = 'Message'; e = { ($_.Message -replace '\s+', ' ') } }) -Name 'wu_failure_events'
        if ($ev.Count -gt 0) { Write-ToolkitLog "$($ev.Count) WindowsUpdateClient failure event(s) since $since" }
    } catch { }

    # KB check
    $kbs = @($KbList -split '[,;\s]+' | Where-Object { $_ } | ForEach-Object { if ($_ -notmatch '^(?i)KB') { 'KB' + $_ } else { $_.ToUpper() } })
    if ($kbs.Count -gt 0) {
        $hotfix = @(Get-HotFix -ErrorAction SilentlyContinue | Select-Object -ExpandProperty HotFixID)
        foreach ($kb in $kbs) {
            $inHist = @($history | Where-Object { $_.Title -match [regex]::Escape($kb) -and $_.Result -eq 'Succeeded' }).Count -gt 0
            if ($hotfix -contains $kb -or $inHist) { Add-Finding Info 'KB' "$kb installed" }
            else { Add-Finding High 'KB' "$kb NOT installed (a later cumulative update supersedes older KBs: check the build/UBR)" }
        }
    }

    # Component store
    $storeBad = $false
    try {
        $dism = & dism.exe /Online /Cleanup-Image /CheckHealth 2>&1 | Out-String
        if ($dism -match '(?i)repairable|corrupt') { $storeBad = $true; Add-Finding High 'Component store' 'DISM CheckHealth reports the component store is repairable/corrupt' }
        elseif ($dism -match '(?i)No component store corruption detected') { Write-ToolkitLog 'Component store: healthy' OK }
        else { Write-ToolkitLog ('DISM CheckHealth: ' + ($dism -replace '\s+', ' ')) WARN }
    } catch { Write-ToolkitLog "DISM CheckHealth failed: $($_.Exception.Message)" WARN }

    # Pending search
    if ($doSearch) {
        Write-ToolkitLog 'Searching for pending updates (can take several minutes)...'
        try {
            $s = (New-Object -ComObject 'Microsoft.Update.Session').CreateUpdateSearcher()
            $r = $s.Search('IsInstalled=0 and IsHidden=0')
            $pend = foreach ($u in $r.Updates) { [pscustomobject]@{ Title = $u.Title; KB = ($u.KBArticleIDs -join ','); Severity = $u.MsrcSeverity; Downloaded = $u.IsDownloaded; RebootBehavior = $u.InstallationBehavior.RebootBehavior } }
            Export-Data -Data $pend -Name 'pending_updates'
            Write-ToolkitLog "$(@($pend).Count) pending update(s)"
            foreach ($p in @($pend)) { Write-ToolkitLog ('  pending: {0}' -f $p.Title) }
        } catch { Add-Finding Medium 'Search' ('Update search failed: 0x{0:X8} {1}' -f $_.Exception.HResult, $_.Exception.Message) }
    }

    # Remediation
    if ($doRemediate) {
        Write-ToolkitLog 'Remediation: resetting Windows Update components' HEAD
        $stamp = Get-Date -Format 'yyyyMMddHHmmss'
        foreach ($n in 'wuauserv', 'bits', 'cryptsvc', 'UsoSvc') { try { Stop-Service -Name $n -Force -ErrorAction Stop } catch { Write-ToolkitLog "Stop $n : $($_.Exception.Message)" WARN } }
        Start-Sleep -Seconds 3
        foreach ($p in @($sd, (Join-Path -Path $env:windir -ChildPath 'System32\catroot2'))) {
            if (Test-Path $p) {
                try { Rename-Item -Path $p -NewName ((Split-Path $p -Leaf) + '.old_' + $stamp) -ErrorAction Stop; Write-ToolkitLog "Renamed $p" OK }
                catch { Add-Finding Medium 'Remediation' "Could not rename $p : $($_.Exception.Message)" }
            }
        }
        foreach ($n in 'cryptsvc', 'bits', 'wuauserv', 'UsoSvc') { try { Start-Service -Name $n -ErrorAction Stop } catch { Write-ToolkitLog "Start $n : $($_.Exception.Message)" WARN } }
        if ($storeBad) {
            Write-ToolkitLog 'Running DISM /RestoreHealth (10-30 minutes)...'
            $rh = & dism.exe /Online /Cleanup-Image /RestoreHealth 2>&1 | Out-String
            if ($rh -match '(?i)restore operation completed successfully') { Add-Finding Info 'Remediation' 'DISM RestoreHealth completed successfully' } else { Add-Finding High 'Remediation' ('DISM RestoreHealth did not complete: ' + (($rh -split "`n" | Select-Object -Last 3) -join ' ')) }
            Write-ToolkitLog 'Running SFC /scannow...'
            $sfc = & sfc.exe /scannow 2>&1 | Out-String
            $sfc = $sfc -replace "`0", ''
            Add-Finding Info 'Remediation' ('SFC: ' + (($sfc -split "`n" | Where-Object { $_ -match '(?i)Windows Resource Protection' } | Select-Object -First 1)))
        }
        try { Start-Process -FilePath (Join-Path $env:windir 'System32\UsoClient.exe') -ArgumentList 'StartScan' -WindowStyle Hidden -ErrorAction Stop; Write-ToolkitLog 'Triggered update scan (UsoClient StartScan)' OK } catch { Write-ToolkitLog "Scan trigger failed: $($_.Exception.Message)" WARN }
        Add-Finding Info 'Remediation' 'Components reset. Reboot, then re-run patching from the RMM. Old folders (*.old_*) can be deleted after a successful install.'
    }
}
catch { Write-ToolkitLog "Unhandled error: $($_.Exception.Message) at line $($_.InvocationInfo.ScriptLineNumber)" ERROR }
finally { Show-Summary }
#endregion
