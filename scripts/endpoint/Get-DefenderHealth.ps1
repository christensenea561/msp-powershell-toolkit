#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Microsoft Defender Antivirus health and Intune compliance signal check, including Windows Security Center state.

.DESCRIPTION
    Built for RMM use (runs as SYSTEM, no prompts). Checks:
      - Defender running mode (Normal / Passive / EDR block / disabled), real-time, behavior, IOAV, NIS, tamper protection
      - Platform, engine and signature versions and ages, last quick/full scan
      - Windows Security Center (workstations): every registered AV product, enabled and up-to-date bits decoded
      - Mismatch where Defender reports healthy but Security Center reports it off (breaks Intune compliance)
      - Third-party AV / EDR still installed or registered
      - Defender and MDE services, policy registry overrides, passive mode, MDE onboarding state
      - Defender event log: protection disabled, signature update failures, detections
    Remediation (opt-in): signature update, starts WinDefend if it is stopped and not disabled.

.PARAMETER MinPlatformVersion
    Flag the device if the Defender platform (AMProductVersion) is below this, e.g. 4.18.24090.11
.PARAMETER DaysBack
    Event log window.
.PARAMETER Remediate
    Update signatures and start WinDefend when stopped.

.NOTES
    NinjaOne: run as SYSTEM. Script variables minPlatformVersion, daysBack, remediate are read from
    environment variables when parameters are not passed.
    Windows PowerShell 5.1. Output: C:\Users\Public\Documents\MspToolkit\Get-DefenderHealth (last 5 runs kept).
#>
[CmdletBinding()]
param(
    [string]$MinPlatformVersion,
    [int]$DaysBack = 0,
    [switch]$Remediate
)

#region ---- Common helpers (inline for RMM use) ----
$ScriptName = 'Get-DefenderHealth'
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

#region ---- Main ----
try {
    Write-ToolkitLog "$ScriptName starting on $env:COMPUTERNAME" HEAD
    $MinPlatformVersion = Get-InputValue -Current $MinPlatformVersion -EnvName 'minPlatformVersion' -Default ''
    if ($DaysBack -le 0) { $DaysBack = [int](Get-InputValue -Current '' -EnvName 'daysBack' -Default '7') }
    $doRemediate = $Remediate.IsPresent -or (Test-Truthy ([Environment]::GetEnvironmentVariable('remediate')))
    $since = (Get-Date).AddDays(-$DaysBack)
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $isServer = ($os.ProductType -ne 1)
    Write-ToolkitLog ('{0} build {1} | server={2}' -f $os.Caption, $os.BuildNumber, $isServer)

    # Defender status
    $mp = $null
    try { $mp = Get-MpComputerStatus -ErrorAction Stop } catch { Add-Finding High 'Defender' "Get-MpComputerStatus failed: $($_.Exception.Message) (Defender not installed, removed, or WinDefend stopped)" }
    if ($mp) {
        $status = [ordered]@{
            AMRunningMode = $mp.AMRunningMode; AntivirusEnabled = $mp.AntivirusEnabled; RealTimeProtectionEnabled = $mp.RealTimeProtectionEnabled
            BehaviorMonitorEnabled = $mp.BehaviorMonitorEnabled; IoavProtectionEnabled = $mp.IoavProtectionEnabled; OnAccessProtectionEnabled = $mp.OnAccessProtectionEnabled
            NISEnabled = $mp.NISEnabled; IsTamperProtected = $mp.IsTamperProtected; AMServiceEnabled = $mp.AMServiceEnabled
            AMProductVersion = $mp.AMProductVersion; AMEngineVersion = $mp.AMEngineVersion; AntivirusSignatureVersion = $mp.AntivirusSignatureVersion
            AntivirusSignatureAge = $mp.AntivirusSignatureAge; AntivirusSignatureLastUpdated = $mp.AntivirusSignatureLastUpdated
            QuickScanAge = $mp.QuickScanAge; FullScanAge = $mp.FullScanAge; DefenderSignaturesOutOfDate = $mp.DefenderSignaturesOutOfDate
            ComputerState = $mp.ComputerState
        }
        $status.GetEnumerator() | ForEach-Object { Write-ToolkitLog ('{0,-30} {1}' -f $_.Key, $_.Value) }
        Export-Data -Data ([pscustomobject]$status) -Name 'defender_status'
        if ($mp.AMRunningMode -ne 'Normal') { Add-Finding Medium 'Defender' "Running mode is '$($mp.AMRunningMode)' (Passive/EDR Block mode means another AV is primary)" }
        if (-not $mp.AntivirusEnabled)          { Add-Finding High 'Defender' 'AntivirusEnabled = False' }
        if (-not $mp.RealTimeProtectionEnabled) { Add-Finding High 'Defender' 'Real-time protection is off' }
        if (-not $mp.BehaviorMonitorEnabled)    { Add-Finding Medium 'Defender' 'Behavior monitoring is off' }
        if (-not $mp.IoavProtectionEnabled)     { Add-Finding Medium 'Defender' 'IOAV (downloads/attachments) protection is off' }
        if (-not $mp.IsTamperProtected)         { Add-Finding Medium 'Defender' 'Tamper protection is off' }
        if ($mp.AntivirusSignatureAge -gt 3 -or $mp.DefenderSignaturesOutOfDate) { Add-Finding High 'Signatures' "Signatures are $($mp.AntivirusSignatureAge) day(s) old (out of date for Intune compliance)" }
        if ($mp.ComputerState -ne 0) { Add-Finding Medium 'Defender' "ComputerState = $($mp.ComputerState) (1 clean pending, 2 full scan pending, 4 reboot pending, 8 manual steps, 16 offline scan pending)" }
        if ($MinPlatformVersion) {
            try { if ([version]$mp.AMProductVersion -lt [version]$MinPlatformVersion) { Add-Finding High 'Platform' "Platform $($mp.AMProductVersion) is below required $MinPlatformVersion" } else { Write-ToolkitLog "Platform $($mp.AMProductVersion) meets $MinPlatformVersion" OK } }
            catch { Write-ToolkitLog "Version compare failed: $($_.Exception.Message)" WARN }
        }
    }

    # Security Center
    $wscRows = New-Object System.Collections.Generic.List[object]
    if (-not $isServer) {
        try {
            foreach ($p in @(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction Stop)) {
                $hex = '{0:X6}' -f [int]$p.productState
                $enabled  = $hex.Substring(2, 2) -in @('10', '11')
                $upToDate = $hex.Substring(4, 2) -eq '00'
                $wscRows.Add([pscustomobject]@{ Product = $p.displayName; ProductState = $p.productState; Hex = $hex; Enabled = $enabled; UpToDate = $upToDate; Exe = $p.pathToSignedReportingExe; Timestamp = $p.timestamp })
            }
        } catch { Write-ToolkitLog "Security Center query failed: $($_.Exception.Message)" WARN }
        $wscRows | Format-Table Product, Hex, Enabled, UpToDate -AutoSize | Out-String | Write-Host
        Export-Data -Data $wscRows -Name 'security_center'
        $wscDef = $wscRows | Where-Object { $_.Product -match 'Defender' } | Select-Object -First 1
        $others = @($wscRows | Where-Object { $_.Product -notmatch 'Defender' })
        if (-not $wscDef) { Add-Finding Medium 'Security Center' 'Windows Defender is not registered in Security Center' }
        elseif ($mp -and $mp.RealTimeProtectionEnabled -and $mp.AMRunningMode -eq 'Normal' -and -not $wscDef.Enabled) {
            Add-Finding High 'Security Center' 'Defender reports healthy but Security Center reports it OFF. Intune compliance reads WSC: this is the Defender/WSC mismatch. Update the Defender platform, restart the Security Center service (wscsvc) or reboot.'
        }
        elseif ($wscDef -and -not $wscDef.UpToDate) { Add-Finding Medium 'Security Center' 'Security Center reports Defender definitions out of date' }
        foreach ($o in $others) { Add-Finding Medium 'Security Center' ('Third-party AV registered: {0} (enabled={1}). Defender goes passive while it is registered.' -f $o.Product, $o.Enabled) }
    } else { Write-ToolkitLog 'Server OS: Security Center not available, skipping WSC checks' }

    # Installed security software
    $avPattern = '(?i)Sophos|Webroot|OpenText Core|SentinelOne|CrowdStrike|Symantec|Norton|McAfee|Trellix|Trend Micro|ESET|Bitdefender|Malwarebytes|Kaspersky|Avast|AVG |Cylance|Carbon Black|Cortex XDR|Panda|F-Secure|Vipre|Huntress'
    $sw = foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*') {
        Get-ItemProperty -Path $k -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -match $avPattern } | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
    }
    $sw = @($sw | Sort-Object DisplayName -Unique)
    Export-Data -Data $sw -Name 'security_software'
    foreach ($s in $sw) {
        if ($s.DisplayName -match '(?i)Huntress') { Add-Finding Info 'Software' "$($s.DisplayName) installed (EDR, runs alongside Defender)" }
        else { Add-Finding Medium 'Software' "$($s.DisplayName) $($s.DisplayVersion) installed" }
    }

    # Services
    $svc = foreach ($n in 'WinDefend', 'WdNisSvc', 'Sense', 'SecurityHealthService', 'wscsvc', 'MDCoreSvc') {
        $s = Get-CimInstance -ClassName Win32_Service -Filter ("Name='{0}'" -f $n) -ErrorAction SilentlyContinue
        if ($s) { [pscustomobject]@{ Name = $n; State = $s.State; StartMode = $s.StartMode } }
    }
    $svc | Format-Table -AutoSize | Out-String | Write-Host
    Export-Data -Data $svc -Name 'services'
    $wd = $svc | Where-Object { $_.Name -eq 'WinDefend' }
    if ($wd -and $wd.State -ne 'Running') { Add-Finding High 'Service' "WinDefend is $($wd.State) ($($wd.StartMode))" }
    $wsc = $svc | Where-Object { $_.Name -eq 'wscsvc' }
    if (-not $isServer -and $wsc -and $wsc.State -ne 'Running') { Add-Finding High 'Service' "Security Center service (wscsvc) is $($wsc.State)" }

    # Policy overrides
    $pol = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
    $p1 = Get-ItemProperty -Path $pol -ErrorAction SilentlyContinue
    $p2 = Get-ItemProperty -Path (Join-Path $pol 'Real-Time Protection') -ErrorAction SilentlyContinue
    if ($p1.DisableAntiSpyware -eq 1) { Add-Finding High 'Policy' 'Policy DisableAntiSpyware = 1' }
    if ($p1.DisableAntiVirus -eq 1)   { Add-Finding High 'Policy' 'Policy DisableAntiVirus = 1' }
    if ($p2.DisableRealtimeMonitoring -eq 1) { Add-Finding High 'Policy' 'Policy DisableRealtimeMonitoring = 1' }
    $passive = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection' -ErrorAction SilentlyContinue).ForceDefenderPassiveMode
    if ($passive -eq 1) { Add-Finding Medium 'Policy' 'ForceDefenderPassiveMode = 1' }
    $excl = @()
    try { $pref = Get-MpPreference -ErrorAction Stop; $excl = @($pref.ExclusionPath) + @($pref.ExclusionProcess) + @($pref.ExclusionExtension) | Where-Object { $_ -and $_ -notmatch 'N/A' } } catch { }
    if ($excl.Count -gt 0) { Export-Data -Data ($excl | ForEach-Object { [pscustomobject]@{ Exclusion = $_ } }) -Name 'exclusions'; Add-Finding Info 'Exclusions' "$($excl.Count) exclusion(s) configured (see exclusions.csv)" }

    # MDE onboarding
    $onb = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status' -ErrorAction SilentlyContinue).OnboardingState
    if ($null -ne $onb) { Write-ToolkitLog "MDE OnboardingState: $onb"; if ($onb -ne 1) { Add-Finding Medium 'MDE' 'Defender for Endpoint not onboarded (OnboardingState != 1)' } } else { Write-ToolkitLog 'MDE onboarding key not present' }

    # Events
    try {
        $ev = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Windows Defender/Operational'; Id = 1116, 1117, 1118, 1119, 2001, 2003, 2004, 3002, 5001, 5004, 5007, 5010, 5012; StartTime = $since } -MaxEvents 500 -ErrorAction Stop)
        Export-Data -Data ($ev | Select-Object TimeCreated, Id, @{ n = 'Message'; e = { ($_.Message -replace '\s+', ' ') } }) -Name 'defender_events'
        foreach ($g in ($ev | Group-Object Id)) {
            $meaning = switch ([int]$g.Name) { 1116 {'malware detected'} 1117 {'action taken on malware'} 1118 {'remediation failed'} 1119 {'critical remediation error'} 2001 {'signature update failed'} 2003 {'engine update failed'} 2004 {'reverted to old signatures'} 3002 {'real-time protection failure'} 5001 {'real-time protection disabled'} 5004 {'RTP config changed'} 5007 {'configuration changed'} 5010 {'antispyware scanning disabled'} 5012 {'antivirus scanning disabled'} default {''} }
            $sev = 'Info'; if ([int]$g.Name -in @(1116, 1118, 1119, 3002, 5001, 5010, 5012)) { $sev = 'Medium' }; if ([int]$g.Name -in @(1118, 1119)) { $sev = 'High' }
            Add-Finding $sev 'Events' ('Event {0} ({1}): {2} in last {3} days' -f $g.Name, $meaning, $g.Count, $DaysBack)
        }
    } catch { Write-ToolkitLog 'No Defender events in window (or log unavailable)' }

    # Remediation
    if ($doRemediate) {
        Write-ToolkitLog 'Remediation' HEAD
        if ($wd -and $wd.State -ne 'Running' -and $wd.StartMode -ne 'Disabled') { try { Start-Service -Name WinDefend -ErrorAction Stop; Add-Finding Info 'Remediation' 'WinDefend started' } catch { Add-Finding Medium 'Remediation' "Could not start WinDefend: $($_.Exception.Message)" } }
        try { Update-MpSignature -ErrorAction Stop; Add-Finding Info 'Remediation' 'Signature update completed' }
        catch {
            Write-ToolkitLog "Update-MpSignature failed: $($_.Exception.Message). Trying MpCmdRun." WARN
            $mpcmd = Join-Path $env:ProgramFiles 'Windows Defender\MpCmdRun.exe'
            if (Test-Path $mpcmd) { $o = & $mpcmd -SignatureUpdate 2>&1 | Out-String; Add-Finding Info 'Remediation' ('MpCmdRun -SignatureUpdate: ' + (($o -split "`n" | Where-Object { $_.Trim() } | Select-Object -Last 1))) }
        }
        try { $mp2 = Get-MpComputerStatus -ErrorAction Stop; Write-ToolkitLog ('After: RTP={0} SigAge={1} Sig={2}' -f $mp2.RealTimeProtectionEnabled, $mp2.AntivirusSignatureAge, $mp2.AntivirusSignatureVersion) OK } catch { }
    }
}
catch { Write-ToolkitLog "Unhandled error: $($_.Exception.Message) at line $($_.InvocationInfo.ScriptLineNumber)" ERROR }
finally { Show-Summary }
#endregion
