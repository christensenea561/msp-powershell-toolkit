#Requires -Version 5.1

<#
.SYNOPSIS
    Installs or updates the PowerShell modules the toolkit uses, for the current user, and reports versions.

.DESCRIPTION
    Windows PowerShell 5.1:
      - ExchangeOnlineManagement           (Exchange Online / Security & Compliance)
      - Microsoft.Graph.Authentication     (all Graph calls are raw requests, so the full Graph SDK is not needed)
      - Microsoft.Online.SharePoint.PowerShell (OneDrive access during offboarding)
    PowerShell 7 (if pwsh.exe is installed):
      - PnP.PowerShell                     (SharePoint permission report)
    Also enables TLS 1.2 and the NuGet provider so Install-Module works on older builds.

.PARAMETER UpdateExisting
    Update modules that are already installed.

.NOTES
    No admin rights needed (CurrentUser scope). Safe to re-run.
#>
[CmdletBinding()]
param([switch]$UpdateExisting)

function Write-Step { param([string]$Text, [string]$Color = 'Cyan') Write-Host $Text -ForegroundColor $Color }

try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    Write-Step "PowerShell $($PSVersionTable.PSVersion) ($($PSVersionTable.PSEdition))"

    if ($PSVersionTable.PSEdition -eq 'Desktop') {
        try {
            $nuget = Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction SilentlyContinue | Sort-Object Version -Descending | Select-Object -First 1
            if (-not $nuget -or $nuget.Version -lt [version]'2.8.5.201') { Write-Step 'Installing NuGet provider...'; Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Scope CurrentUser -Force -ErrorAction Stop | Out-Null }
        } catch { Write-Step "NuGet provider install failed: $($_.Exception.Message)" 'Red' }
    }

    $modules = @('ExchangeOnlineManagement', 'Microsoft.Graph.Authentication')
    if ($PSVersionTable.PSEdition -eq 'Desktop') { $modules += 'Microsoft.Online.SharePoint.PowerShell' }
    else { $modules += 'PnP.PowerShell' }

    $results = foreach ($m in $modules) {
        $have = Get-Module -ListAvailable -Name $m | Sort-Object Version -Descending | Select-Object -First 1
        $action = 'OK'
        try {
            if (-not $have) { Write-Step "Installing $m..."; Install-Module -Name $m -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop; $action = 'Installed' }
            elseif ($UpdateExisting) {
                $online = Find-Module -Name $m -ErrorAction Stop
                if ([version]$online.Version -gt $have.Version) { Write-Step "Updating $m $($have.Version) -> $($online.Version)..."; Install-Module -Name $m -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop; $action = 'Updated' }
            }
        } catch { $action = 'FAILED: ' + $_.Exception.Message }
        $now = Get-Module -ListAvailable -Name $m | Sort-Object Version -Descending | Select-Object -First 1
        [pscustomobject]@{ Module = $m; Version = $now.Version; Result = $action }
    }
    $results | Format-Table -AutoSize | Out-String | Write-Host

    if ($PSVersionTable.PSEdition -eq 'Desktop') {
        $pwsh = Get-Command -Name pwsh.exe -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($pwsh) {
            Write-Step 'PowerShell 7 found. Installing PnP.PowerShell there...'
            $cmd = 'if (-not (Get-Module -ListAvailable PnP.PowerShell)) { Install-Module PnP.PowerShell -Scope CurrentUser -Force -ErrorAction Stop }; (Get-Module -ListAvailable PnP.PowerShell | Sort-Object Version -Descending | Select-Object -First 1).Version.ToString()'
            $v = & $pwsh.Source -NoProfile -Command $cmd 2>&1
            Write-Step ("PnP.PowerShell (PS7): {0}" -f ($v -join ' ')) 'Green'
        } else { Write-Step 'PowerShell 7 not found. Get-SharePointPermissionReport needs it: winget install Microsoft.PowerShell' 'Yellow' }
    }
    Write-Step 'Done.' 'Green'
} catch { Write-Step "Unhandled error: $($_.Exception.Message)" 'Red' }
