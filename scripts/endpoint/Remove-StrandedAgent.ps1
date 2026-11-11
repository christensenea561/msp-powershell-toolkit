#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Silently removes stranded software agents (orphaned AV/EDR, old RMM agents, OEM utilities) by display name,
    including hung Windows Installer cleanup and leftover service/folder reporting.

.DESCRIPTION
    Built for RMM use (runs as SYSTEM, no prompts):
      1. Windows Installer health: reports msiexec processes running longer than the threshold and
         optionally kills them (a hung msiexec holds the installer mutex and blocks every MSI install/uninstall)
      2. Finds matching uninstall entries in 64-bit, 32-bit and per-user (HKU) registry hives
      3. Uninstalls each match silently:
           MSI    -> msiexec /x {ProductCode} /qn /norestart with a verbose log
           EXE    -> QuietUninstallString, or UninstallString plus the silent switch for Inno Setup / NSIS
           Vendor -> known vendor uninstallers for the selected profile (Sophos, Webroot)
      4. Re-scans and reports leftover uninstall entries, services, processes and folders
      5. Optional ForceCleanup: stops/deletes leftover services and removes leftover folders
    ReportOnly shows what would run without changing anything.

.PARAMETER DisplayName
    Wildcard pattern matched against the uninstall DisplayName, e.g. "Realtek*DASH*" or "*Webroot*".
.PARAMETER VendorProfile
    Optional built-in profile that adds the vendor uninstaller and leftover patterns: None, Sophos, Webroot.
.PARAMETER ReportOnly
    List what would be removed and exit without changes.
.PARAMETER KillHungMsi
    Kill msiexec install/uninstall processes older than HungMsiMinutes before uninstalling.
.PARAMETER HungMsiMinutes
    Age threshold for hung msiexec detection.
.PARAMETER ForceCleanup
    After uninstall, stop and delete leftover services and remove leftover folders matching the pattern.
.PARAMETER TimeoutMinutes
    Max wait per uninstaller.

.NOTES
    NinjaOne: run as SYSTEM. Script variables displayName, vendorProfile, reportOnly, killHungMsi, forceCleanup
    are read from environment variables when parameters are not passed.
    Tamper-protected agents (Sophos, many EDRs) must have tamper protection disabled in their console first.
    Windows PowerShell 5.1. Output and MSI logs: C:\Users\Public\Documents\MspToolkit\Remove-StrandedAgent (last 5 runs kept).
#>
[CmdletBinding()]
param(
    [string]$DisplayName,
    [ValidateSet('None', 'Sophos', 'Webroot')][string]$VendorProfile = 'None',
    [switch]$ReportOnly,
    [switch]$KillHungMsi,
    [int]$HungMsiMinutes = 30,
    [switch]$ForceCleanup,
    [int]$TimeoutMinutes = 15
)

#region ---- Common helpers (inline for RMM use) ----
$ScriptName = 'Remove-StrandedAgent'
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

function Get-UninstallEntries {
    param([string[]]$Patterns)
    $roots = New-Object System.Collections.Generic.List[string]
    $roots.Add('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall')
    $roots.Add('HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')
    foreach ($h in @(Get-ChildItem -Path 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^S-1-5-21-[\d-]+$' })) {
        $roots.Add(('Registry::HKEY_USERS\{0}\Software\Microsoft\Windows\CurrentVersion\Uninstall' -f $h.PSChildName))
    }
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($r in $roots) {
        foreach ($k in @(Get-ChildItem -Path $r -ErrorAction SilentlyContinue)) {
            $p = Get-ItemProperty -Path $k.PSPath -ErrorAction SilentlyContinue
            if (-not $p.DisplayName) { continue }
            $hit = $false; foreach ($pat in $Patterns) { if ($p.DisplayName -like $pat) { $hit = $true; break } }
            if (-not $hit) { continue }
            $isMsi = ($k.PSChildName -match '^\{[0-9A-Fa-f-]{36}\}$') -and ($p.WindowsInstaller -eq 1 -or [string]$p.UninstallString -match '(?i)msiexec')
            $out.Add([pscustomobject]@{ DisplayName = $p.DisplayName; Version = $p.DisplayVersion; Publisher = $p.Publisher; KeyName = $k.PSChildName; IsMsi = $isMsi; UninstallString = $p.UninstallString; QuietUninstallString = $p.QuietUninstallString; Hive = $r; RegPath = $k.PSPath })
        }
    }
    return $out
}
function Split-CommandLine {
    param([string]$Command)
    $c = $Command.Trim()
    if ($c.StartsWith('"')) { $end = $c.IndexOf('"', 1); return @($c.Substring(1, $end - 1), $c.Substring($end + 1).Trim()) }
    $m = [regex]::Match($c, '^(.+?\.exe)\s*(.*)$', 'IgnoreCase')
    if ($m.Success) { return @($m.Groups[1].Value, $m.Groups[2].Value) }
    return @($c, '')
}
function Invoke-Uninstaller {
    param([string]$FilePath, [string]$Arguments, [string]$Label)
    Write-ToolkitLog ('Running: "{0}" {1}' -f $FilePath, $Arguments)
    try {
        $proc = Start-Process -FilePath $FilePath -ArgumentList $Arguments -PassThru -WindowStyle Hidden -ErrorAction Stop
        if (-not $proc.WaitForExit($TimeoutMinutes * 60 * 1000)) { Add-Finding High 'Uninstall' "$Label timed out after $TimeoutMinutes min (still running, PID $($proc.Id))"; return $null }
        $code = $proc.ExitCode
        $msg = switch ($code) { 0 {'success'} 1605 {'product not installed'} 1614 {'product uninstalled'} 1618 {'another install in progress (msiexec mutex)'} 1641 {'success, reboot initiated'} 3010 {'success, reboot required'} 1603 {'fatal error during uninstall (see MSI log)'} default {'see vendor docs'} }
        $sev = 'Info'; if ($code -notin @(0, 1605, 1614, 1641, 3010)) { $sev = 'High' }
        Add-Finding $sev 'Uninstall' ('{0}: exit {1} ({2})' -f $Label, $code, $msg)
        return $code
    } catch { Add-Finding High 'Uninstall' "$Label failed to start: $($_.Exception.Message)"; return $null }
}

#region ---- Main ----
try {
    Write-ToolkitLog "$ScriptName starting on $env:COMPUTERNAME" HEAD
    $DisplayName   = Get-InputValue -Current $DisplayName   -EnvName 'displayName'   -Default ''
    $VendorProfile = Get-InputValue -Current $(if ($VendorProfile -ne 'None') { $VendorProfile } else { '' }) -EnvName 'vendorProfile' -Default 'None'
    $doReport = $ReportOnly.IsPresent   -or (Test-Truthy ([Environment]::GetEnvironmentVariable('reportOnly')))
    $doKill   = $KillHungMsi.IsPresent  -or (Test-Truthy ([Environment]::GetEnvironmentVariable('killHungMsi')))
    $doForce  = $ForceCleanup.IsPresent -or (Test-Truthy ([Environment]::GetEnvironmentVariable('forceCleanup')))

    $patterns = New-Object System.Collections.Generic.List[string]
    $leftoverRegex = ''
    $vendorUninstallers = @()
    if ($DisplayName) { $patterns.Add($DisplayName) }
    switch ($VendorProfile) {
        'Sophos'  {
            $patterns.Add('Sophos*'); $leftoverRegex = '(?i)Sophos'
            $vendorUninstallers = @(@{ Path = (Join-Path $env:ProgramFiles 'Sophos\Sophos Endpoint Agent\SophosUninstall.exe'); Args = '--quiet' }, @{ Path = (Join-Path $env:ProgramFiles 'Sophos\Sophos Endpoint Agent\uninstallcli.exe'); Args = '' })
        }
        'Webroot' {
            $patterns.Add('*Webroot*'); $leftoverRegex = '(?i)Webroot|WRSA|WRSVC|WRCore'
            $vendorUninstallers = @(@{ Path = (Join-Path ${env:ProgramFiles(x86)} 'Webroot\WRSA.exe'); Args = '-uninstall' }, @{ Path = (Join-Path $env:ProgramFiles 'Webroot\WRSA.exe'); Args = '-uninstall' })
        }
        'None'    { }
        default   { Write-ToolkitLog "Unknown VendorProfile '$VendorProfile', ignoring" WARN }
    }
    if ($patterns.Count -eq 0) { Write-ToolkitLog 'Provide DisplayName and/or VendorProfile.' ERROR; return }
    if (-not $leftoverRegex) { $leftoverRegex = [regex]::Escape(($DisplayName -replace '\*', ' ').Trim()) -replace '\\ ', '.*' ; $leftoverRegex = '(?i)' + $leftoverRegex }
    Write-ToolkitLog ('Patterns: {0} | Profile: {1} | ReportOnly: {2}' -f ($patterns -join ', '), $VendorProfile, $doReport)

    # 1. Windows Installer health
    $msi = @(Get-CimInstance -ClassName Win32_Process -Filter "Name='msiexec.exe'" -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -notmatch '(?i)/V\s*$' })
    foreach ($p in $msi) {
        $age = (Get-Date) - $p.CreationDate
        $line = 'msiexec PID {0} running {1:N0} min: {2}' -f $p.ProcessId, $age.TotalMinutes, $p.CommandLine
        if ($age.TotalMinutes -ge $HungMsiMinutes) {
            if ($doKill -and -not $doReport) { try { Stop-Process -Id $p.ProcessId -Force -ErrorAction Stop; Add-Finding Medium 'Installer' "Killed hung $line" } catch { Add-Finding High 'Installer' "Could not kill $line" } }
            else { Add-Finding High 'Installer' "Hung $line (use KillHungMsi)" }
        } else { Write-ToolkitLog $line }
    }

    # 2. Find entries
    $entries = @(Get-UninstallEntries -Patterns $patterns)
    Export-Data -Data ($entries | Select-Object DisplayName, Version, Publisher, IsMsi, KeyName, UninstallString, QuietUninstallString, Hive) -Name 'matches_before'
    if ($entries.Count -eq 0) { Write-ToolkitLog 'No matching uninstall entries found.' }
    foreach ($e in $entries) { Write-ToolkitLog ('Match: {0} {1} | MSI={2} | {3}' -f $e.DisplayName, $e.Version, $e.IsMsi, $e.UninstallString) }

    if ($doReport) { Add-Finding Info 'ReportOnly' "$($entries.Count) entry(ies) would be uninstalled. No changes made." }
    else {
        # 3a. Vendor uninstallers first
        foreach ($v in $vendorUninstallers) {
            if ($v.Path -and (Test-Path $v.Path)) { [void](Invoke-Uninstaller -FilePath $v.Path -Arguments $v.Args -Label ('Vendor uninstaller ' + (Split-Path $v.Path -Leaf))) }
        }
        if ($vendorUninstallers.Count -gt 0) { Start-Sleep -Seconds 10; $entries = @(Get-UninstallEntries -Patterns $patterns) }

        # 3b. Registry entries
        foreach ($e in $entries) {
            $label = '{0} {1}' -f $e.DisplayName, $e.Version
            if ($e.IsMsi) {
                $log = Join-Path $OutRoot ('msi_' + ($e.KeyName -replace '[{}]', '') + '.log')
                [void](Invoke-Uninstaller -FilePath (Join-Path $env:windir 'System32\msiexec.exe') -Arguments ('/x {0} /qn /norestart REBOOT=ReallySuppress /L*v "{1}"' -f $e.KeyName, $log) -Label $label)
            }
            elseif ($e.QuietUninstallString) { $c = Split-CommandLine $e.QuietUninstallString; [void](Invoke-Uninstaller -FilePath $c[0] -Arguments $c[1] -Label $label) }
            elseif ($e.UninstallString) {
                $c = Split-CommandLine $e.UninstallString
                $exe = Split-Path $c[0] -Leaf
                if ($c[0] -match '(?i)msiexec') {
                    $guid = [regex]::Match($e.UninstallString, '\{[0-9A-Fa-f-]{36}\}').Value
                    if ($guid) { [void](Invoke-Uninstaller -FilePath (Join-Path $env:windir 'System32\msiexec.exe') -Arguments ('/x {0} /qn /norestart REBOOT=ReallySuppress' -f $guid) -Label $label) }
                }
                elseif ($exe -match '(?i)^unins\d*\.exe$') { [void](Invoke-Uninstaller -FilePath $c[0] -Arguments (($c[1] + ' /VERYSILENT /SUPPRESSMSGBOXES /NORESTART').Trim()) -Label "$label (Inno Setup)") }
                elseif ($exe -match '(?i)^(uninstall|uninst)\.exe$') { [void](Invoke-Uninstaller -FilePath $c[0] -Arguments (($c[1] + ' /S').Trim()) -Label "$label (NSIS)") }
                else { Add-Finding Medium 'Uninstall' ('{0}: no known silent switch for "{1}". Get the vendor silent switch and set it as QuietUninstallString or run manually.' -f $label, $e.UninstallString) }
            }
            else { Add-Finding Medium 'Uninstall' "$label has no uninstall string (orphaned registry entry): $($e.RegPath)" }
        }
    }

    # 4. Leftovers
    Write-ToolkitLog 'Leftover scan' HEAD
    $after = @(Get-UninstallEntries -Patterns $patterns)
    foreach ($e in $after) { Add-Finding Medium 'Leftover' "Uninstall entry still present: $($e.DisplayName) $($e.Version)" }
    $svc = @(Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -match $leftoverRegex -or $_.Name -match $leftoverRegex -or $_.PathName -match $leftoverRegex })
    $procs = @(Get-CimInstance -ClassName Win32_Process -ErrorAction SilentlyContinue | Where-Object { $_.Name -match $leftoverRegex -or $_.ExecutablePath -match $leftoverRegex })
    $folders = @()
    foreach ($root in @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramData) | Where-Object { $_ }) {
        $folders += @(Get-ChildItem -Path $root -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -match $leftoverRegex })
    }
    Export-Data -Data ($svc | Select-Object Name, DisplayName, State, StartMode, PathName) -Name 'leftover_services'
    Export-Data -Data ($folders | Select-Object FullName, LastWriteTime) -Name 'leftover_folders'
    foreach ($s in $svc)   { Add-Finding Medium 'Leftover' "Service: $($s.Name) ($($s.State), $($s.StartMode))" }
    foreach ($p in $procs) { Add-Finding Medium 'Leftover' "Process: $($p.Name) PID $($p.ProcessId)" }
    foreach ($f in $folders) { Add-Finding Low 'Leftover' "Folder: $($f.FullName)" }

    $literal = ($leftoverRegex -replace '\(\?i\)|\.\*|\\|\|', '')
    if ($doForce -and $literal.Length -lt 5) { Add-Finding High 'Cleanup' "ForceCleanup refused: pattern '$DisplayName' is too broad (needs 5+ literal characters)"; $doForce = $false }
    $svc     = @($svc     | Where-Object { [string]$_.PathName -notmatch '(?i)\\Windows\\(System32|SysWOW64)\\(svchost|lsass|services)\.exe' })
    $folders = @($folders | Where-Object { $_.FullName -notmatch '(?i)\\(Microsoft|Windows Defender|Windows NT|Common Files)$' })
    if ($doForce -and -not $doReport) {
        Write-ToolkitLog 'ForceCleanup' HEAD
        foreach ($p in $procs) { try { Stop-Process -Id $p.ProcessId -Force -ErrorAction Stop; Write-ToolkitLog "Stopped process $($p.Name)" OK } catch { Add-Finding Medium 'Cleanup' "Could not stop $($p.Name): $($_.Exception.Message)" } }
        foreach ($s in $svc) {
            try { Stop-Service -Name $s.Name -Force -ErrorAction SilentlyContinue } catch { }
            $o = & sc.exe delete $s.Name 2>&1 | Out-String
            if ($o -match '(?i)SUCCESS') { Add-Finding Info 'Cleanup' "Deleted service $($s.Name)" } else { Add-Finding Medium 'Cleanup' ('Service {0} delete: {1}' -f $s.Name, ($o -replace '\s+', ' ')) }
        }
        foreach ($f in $folders) {
            try { Remove-Item -Path $f.FullName -Recurse -Force -ErrorAction Stop; Add-Finding Info 'Cleanup' "Removed $($f.FullName)" }
            catch { Add-Finding Medium 'Cleanup' "Could not remove $($f.FullName) (in use or protected; retry after reboot): $($_.Exception.Message)" }
        }
    }

    $reboot = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or [bool](Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue)
    if ($reboot) { Add-Finding Info 'Reboot' 'Reboot pending: reboot to finish removal, then re-run with ReportOnly to confirm' }
}
catch { Write-ToolkitLog "Unhandled error: $($_.Exception.Message) at line $($_.InvocationInfo.ScriptLineNumber)" ERROR }
finally { Show-Summary }
#endregion
