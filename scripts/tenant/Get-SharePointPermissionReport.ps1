#Requires -Version 7.2

<#
.SYNOPSIS
    SharePoint Online permission report for a site, library or folder: site groups, broken inheritance,
    sharing links, external users and Everyone grants.

.DESCRIPTION
    - Site-level role assignments and SharePoint group membership
    - Every list/library (or one library) scanned for folders (and optionally files) with unique permissions
    - For each unique-permission item: every principal and permission level
    - Flags: sharing links, guests (#ext#), Everyone / Everyone except external users, direct user grants
      with Full Control, and broken inheritance counts per library

.PARAMETER SiteUrl
    Full site URL, for example https://contoso.sharepoint.com/sites/Finance
.PARAMETER ClientId
    Application (client) ID of the Entra app registration used for PnP interactive sign-in in this tenant.
    PnP.PowerShell 2.x+ requires your own app registration per tenant.
.PARAMETER Library
    Optional library/list title to limit the scan.
.PARAMETER FolderPath
    Optional server-relative folder URL to limit the scan, for example /sites/Finance/Shared Documents/Closed 2026
.PARAMETER IncludeFiles
    Also check files for unique permissions (slower on large libraries).
.PARAMETER IncludeLimitedAccess
    Include "Limited Access" entries (normally noise created by item-level sharing).
.PARAMETER MaxItems
    Safety cap on items checked per library.

.NOTES
    Requires PowerShell 7.2+ and PnP.PowerShell (3.x requires PS 7.4). Read-only.
#>
[CmdletBinding()]
param(
    [string]$SiteUrl,
    [string]$ClientId,
    [string]$Library,
    [string]$FolderPath,
    [switch]$IncludeFiles,
    [switch]$IncludeLimitedAccess,
    [int]$MaxItems = 50000
)

#region ---- Common helpers (inline so the script runs standalone or pasted) ----
$ScriptName = 'Get-SharePointPermissionReport'
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
#endregion

$PermRows = New-Object System.Collections.Generic.List[object]

function Add-RoleAssignmentRows {
    param([object]$SecurableObject, [string]$Scope, [string]$Path, [string]$ObjectType)
    try { $ras = Get-PnPProperty -ClientObject $SecurableObject -Property RoleAssignments -ErrorAction Stop } catch { Write-ToolkitLog "RoleAssignments failed for $Path : $($_.Exception.Message)" WARN; return }
    foreach ($ra in $ras) {
        try { Get-PnPProperty -ClientObject $ra -Property RoleDefinitionBindings, Member -ErrorAction Stop | Out-Null } catch { continue }
        $levels = @($ra.RoleDefinitionBindings | ForEach-Object { $_.Name })
        if (-not $IncludeLimitedAccess) { $levels = @($levels | Where-Object { $_ -ne 'Limited Access' -and $_ -ne 'Web-Only Limited Access' }) }
        if ($levels.Count -eq 0) { continue }
        $m = $ra.Member
        $row = [pscustomobject]@{ Scope = $Scope; ObjectType = $ObjectType; Path = $Path; Principal = $m.Title; LoginName = $m.LoginName; PrincipalType = [string]$m.PrincipalType; Permissions = ($levels -join ', ') }
        $PermRows.Add($row)
        if ($m.Title -like 'SharingLinks.*' -or $m.LoginName -like '*SharingLinks*') { Add-Finding Medium 'Sharing link' "$Path has a sharing link ($($row.Permissions))" }
        elseif ($m.LoginName -like '*#ext#*' -or $m.LoginName -like '*urn%3aspo%3aguest*') { Add-Finding Medium 'External' "Guest $($m.Title) has $($row.Permissions) on $Path" }
        elseif ($m.LoginName -match 'spo-grid-all-users|c:0\(\.s\|true') { Add-Finding High 'Everyone' "'$($m.Title)' (Everyone / Everyone except external users) has $($row.Permissions) on $Path" }
        elseif ([string]$m.PrincipalType -eq 'User' -and $levels -contains 'Full Control' -and $ObjectType -ne 'Site') { Add-Finding Low 'Direct grant' "$($m.Title) has Full Control directly on $Path" }
    }
}

#region ---- Main ----
try {
    Write-ToolkitLog "$ScriptName starting" HEAD
    $SiteUrl  = Read-Input -Value $SiteUrl  -Prompt 'Site URL (https://tenant.sharepoint.com/sites/...)'
    $ClientId = Read-Input -Value $ClientId -Prompt 'Client ID of your PnP app registration in this tenant'
    if (-not $SiteUrl -or -not $ClientId) { Write-ToolkitLog 'SiteUrl and ClientId are required.' ERROR; return }
    if (-not $PSBoundParameters.ContainsKey('Library'))    { $Library    = Read-Input -Value $Library    -Prompt 'Limit to library title' -Optional }
    if (-not $PSBoundParameters.ContainsKey('FolderPath')) { $FolderPath = Read-Input -Value $FolderPath -Prompt 'Limit to server-relative folder URL' -Optional }

    if (-not (Get-Module -ListAvailable -Name PnP.PowerShell)) {
        Write-ToolkitLog 'PnP.PowerShell not installed. Installing for CurrentUser...' WARN
        try { Install-Module -Name PnP.PowerShell -Scope CurrentUser -Force -ErrorAction Stop } catch { Write-ToolkitLog "Install failed: $($_.Exception.Message)" ERROR; return }
    }
    try { Import-Module PnP.PowerShell -ErrorAction Stop } catch { Write-ToolkitLog "Import failed: $($_.Exception.Message)" ERROR; return }
    try { Connect-PnPOnline -Url $SiteUrl -Interactive -ClientId $ClientId -ErrorAction Stop } catch { Write-ToolkitLog "Connect-PnPOnline failed: $($_.Exception.Message)" ERROR; return }
    $web = Get-PnPWeb -ErrorAction Stop
    Write-ToolkitLog ('Connected to {0} ({1})' -f $web.Title, $web.Url) OK

    # Site level
    Write-ToolkitLog 'Site permissions and groups' HEAD
    Add-RoleAssignmentRows -SecurableObject $web -Scope 'Site' -Path $web.ServerRelativeUrl -ObjectType 'Site'
    $groupRows = New-Object System.Collections.Generic.List[object]
    foreach ($grp in @(Get-PnPGroup -ErrorAction SilentlyContinue)) {
        if ($grp.Title -like 'SharingLinks.*' -or $grp.Title -like 'Limited Access System Group*') { continue }
        foreach ($mem in @(Get-PnPGroupMember -Group $grp -ErrorAction SilentlyContinue)) {
            $groupRows.Add([pscustomobject]@{ Group = $grp.Title; Member = $mem.Title; LoginName = $mem.LoginName; Email = $mem.Email; PrincipalType = [string]$mem.PrincipalType })
            if ($mem.LoginName -match 'spo-grid-all-users|c:0\(\.s\|true') { Add-Finding High 'Everyone' "'$($mem.Title)' is a member of site group '$($grp.Title)'" }
            if ($mem.LoginName -like '*#ext#*') { Add-Finding Low 'External' "Guest $($mem.Title) is in site group '$($grp.Title)'" }
        }
    }
    Export-Data -Data $groupRows -Name 'site_group_members'

    # Lists and libraries
    $lists = @(Get-PnPList -ErrorAction Stop | Where-Object { -not $_.Hidden -and $_.BaseTemplate -in @(100, 101, 119, 700, 851) })
    if ($Library) { $lists = @($lists | Where-Object { $_.Title -eq $Library }); if ($lists.Count -eq 0) { Write-ToolkitLog "Library '$Library' not found" ERROR; return } }
    $libSummary = New-Object System.Collections.Generic.List[object]
    foreach ($l in $lists) {
        Write-ToolkitLog "Scanning $($l.Title) ($($l.ItemCount) items)" HEAD
        $lUnique = Get-PnPProperty -ClientObject $l -Property HasUniqueRoleAssignments
        if ($lUnique) { Add-RoleAssignmentRows -SecurableObject $l -Scope 'List' -Path $l.Title -ObjectType 'Library'; Add-Finding Info 'Inheritance' "Library '$($l.Title)' has unique permissions" }
        $p = @{ List = $l; PageSize = 2000; Fields = @('FileRef', 'FileLeafRef', 'FSObjType'); ErrorAction = 'Stop' }
        try { $items = @(Get-PnPListItem @p) } catch { Write-ToolkitLog "Item enumeration failed: $($_.Exception.Message)" WARN; continue }
        if ($FolderPath) {
            $fp = $FolderPath.TrimEnd('/')
            $items = @($items | Where-Object { ([string]$_['FileRef']) -eq $fp -or ([string]$_['FileRef']).StartsWith($fp + '/', [System.StringComparison]::OrdinalIgnoreCase) })
            if ($items.Count -eq 0) { Write-ToolkitLog "No items under $fp in $($l.Title)"; continue }
        }
        if (-not $IncludeFiles) { $items = @($items | Where-Object { [string]$_['FSObjType'] -eq '1' }) }
        if ($items.Count -gt $MaxItems) { Add-Finding Medium 'Scan' "$($l.Title): $($items.Count) items, only the first $MaxItems were checked"; $items = @($items | Select-Object -First $MaxItems) }
        $unique = 0; $i = 0
        foreach ($it in $items) {
            $i++; if ($i % 500 -eq 0) { Write-ToolkitLog "  checked $i / $($items.Count)" }
            try { $hu = Get-PnPProperty -ClientObject $it -Property HasUniqueRoleAssignments -ErrorAction Stop } catch { continue }
            if ($hu) {
                $unique++
                $otype = 'File'; if ([string]$it['FSObjType'] -eq '1') { $otype = 'Folder' }
                Add-RoleAssignmentRows -SecurableObject $it -Scope 'Item' -Path ([string]$it['FileRef']) -ObjectType $otype
            }
        }
        $libSummary.Add([pscustomobject]@{ Library = $l.Title; ItemsChecked = $items.Count; UniquePermissionItems = $unique; LibraryUnique = $lUnique })
        if ($unique -gt 0) { Add-Finding Info 'Inheritance' "$($l.Title): $unique item(s) with broken inheritance" }
    }
    Export-Data -Data $libSummary -Name 'library_summary'
    Export-Data -Data $PermRows -Name 'permissions'
    $libSummary | Format-Table -AutoSize | Out-String | Write-Host
}
catch { Write-ToolkitLog "Unhandled error: $($_.Exception.Message) at line $($_.InvocationInfo.ScriptLineNumber)" ERROR }
finally { Show-Summary }
#endregion
