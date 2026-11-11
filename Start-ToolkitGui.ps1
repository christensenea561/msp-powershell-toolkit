#Requires -Version 5.1

<#
.SYNOPSIS
    WPF launcher for the toolkit: pick a script, fill in its parameters, run it in its own console window.

.DESCRIPTION
    - Discovers every script under .\scripts\tenant and .\scripts\endpoint
    - Reads each script's param() block and comment help to build the form automatically:
        [switch]       -> checkbox
        [ValidateSet]  -> dropdown
        anything else  -> editable box with your recent values
    - Runs the script in a new console window (so interactive sign-in pop-ups and prompts work),
      in PowerShell 7 when the script declares #Requires -Version 7, elevated when it declares
      #Requires -RunAsAdministrator
    - Copy Command puts the equivalent command line on the clipboard
    - Remembers recent values per parameter in %APPDATA%\MspToolkit\gui-state.json
    Adding a new script to the scripts folder adds it to the GUI. No changes to this file needed.

.PARAMETER ToolkitPath
    Repo root. Defaults to the folder this script is in.

.NOTES
    Windows PowerShell 5.1 (WPF). Double-click Start-ToolkitGui.cmd to launch without a console.
#>
[CmdletBinding()]
param([string]$ToolkitPath)

if ([System.Threading.Thread]::CurrentThread.ApartmentState -ne 'STA') {
    if ($PSCommandPath) { Start-Process -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -ArgumentList ('-NoProfile -STA -ExecutionPolicy Bypass -File "{0}"' -f $PSCommandPath) }
    else { Write-Host 'The GUI needs an STA thread. Run it from Windows PowerShell 5.1 or Start-ToolkitGui.cmd.' -ForegroundColor Red }
    return
}

try {
    Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase -ErrorAction Stop
} catch { Write-Host "WPF is not available: $($_.Exception.Message)" -ForegroundColor Red; return }

if (-not $ToolkitPath) { $ToolkitPath = $PSScriptRoot }
if (-not $ToolkitPath) { Write-Host 'Run this from the saved file (it needs to know where the scripts folder is), or pass -ToolkitPath.' -ForegroundColor Red; return }
$ScriptsRoot = Join-Path -Path $ToolkitPath -ChildPath 'scripts'
$OutputRoot  = 'C:\Users\Public\Documents\MspToolkit'
$StateDir    = Join-Path -Path $env:APPDATA -ChildPath 'MspToolkit'
$StateFile   = Join-Path -Path $StateDir -ChildPath 'gui-state.json'

#region ---- State ----
$script:History = @{}
if (Test-Path $StateFile) {
    try {
        $j = Get-Content -Path $StateFile -Raw -ErrorAction Stop | ConvertFrom-Json
        foreach ($p in $j.PSObject.Properties) { $script:History[$p.Name] = @($p.Value) }
    } catch { }
}
function Save-History {
    try {
        if (-not (Test-Path $StateDir)) { New-Item -ItemType Directory -Path $StateDir -Force | Out-Null }
        $script:History | ConvertTo-Json -Depth 3 | Set-Content -Path $StateFile -Encoding UTF8
    } catch { }
}
function Add-ValueHistory {
    param([string]$Name, [string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return }
    $list = @($Value) + @($script:History[$Name] | Where-Object { $_ -and $_ -ne $Value })
    $script:History[$Name] = @($list | Select-Object -First 10)
}
#endregion

#region ---- Script discovery ----
function Get-ScriptInfo {
    param([System.IO.FileInfo]$File, [string]$Category)
    $tokens = $null; $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($File.FullName, [ref]$tokens, [ref]$errors)
    $help = $null; try { $help = $ast.GetHelpContent() } catch { }
    $params = New-Object System.Collections.Generic.List[object]
    if ($ast.ParamBlock) {
        foreach ($p in $ast.ParamBlock.Parameters) {
            $name = $p.Name.VariablePath.UserPath
            $set = $null
            foreach ($a in $p.Attributes) {
                if ($a -is [System.Management.Automation.Language.AttributeAst] -and $a.TypeName.Name -eq 'ValidateSet') { $set = @($a.PositionalArguments | ForEach-Object { $_.Value }) }
            }
            $default = ''
            if ($p.DefaultValue) { try { $default = [string]$p.DefaultValue.SafeGetValue() } catch { $default = '' } }
            $desc = ''
            if ($help -and $help.Parameters -and $help.Parameters.ContainsKey($name.ToUpper())) { $desc = ($help.Parameters[$name.ToUpper()] -replace '\s+', ' ').Trim() }
            $params.Add([pscustomobject]@{ Name = $name; Type = $p.StaticType.Name; Set = $set; Default = $default; Description = $desc })
        }
    }
    $ps7 = $false; $elevated = $false
    if ($ast.ScriptRequirements) {
        if ($ast.ScriptRequirements.RequiredPSVersion -and $ast.ScriptRequirements.RequiredPSVersion.Major -ge 7) { $ps7 = $true }
        if ($ast.ScriptRequirements.IsElevationRequired) { $elevated = $true }
    }
    $syn = ''; $descr = ''
    if ($help) { $syn = ([string]$help.Synopsis).Trim(); $descr = ([string]$help.Description).Trim() }
    return [pscustomobject]@{ Name = $File.BaseName; Path = $File.FullName; Category = $Category; Synopsis = $syn; Description = $descr; Params = $params; Ps7 = $ps7; Elevated = $elevated; ParseErrors = @($errors).Count }
}
$AllScripts = New-Object System.Collections.Generic.List[object]
foreach ($cat in 'tenant', 'endpoint') {
    $dir = Join-Path -Path $ScriptsRoot -ChildPath $cat
    foreach ($f in @(Get-ChildItem -Path $dir -Filter '*.ps1' -File -ErrorAction SilentlyContinue | Sort-Object Name)) { $AllScripts.Add((Get-ScriptInfo -File $f -Category $cat)) }
}
if ($AllScripts.Count -eq 0) { Write-Host "No scripts found under $ScriptsRoot" -ForegroundColor Red; return }
#endregion

#region ---- Window ----
[xml]$xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="MSP PowerShell Toolkit" Width="1180" Height="760" MinWidth="900" MinHeight="560"
        WindowStartupLocation="CenterScreen" FontFamily="Segoe UI" FontSize="13" Background="#F4F5F7">
  <Grid Margin="12">
    <Grid.ColumnDefinitions>
      <ColumnDefinition Width="300"/>
      <ColumnDefinition Width="12"/>
      <ColumnDefinition Width="*"/>
    </Grid.ColumnDefinitions>
    <DockPanel Grid.Column="0">
      <TextBlock DockPanel.Dock="Top" Text="Scripts" FontSize="16" FontWeight="SemiBold" Margin="0,0,0,6"/>
      <TextBox x:Name="Filter" DockPanel.Dock="Top" Margin="0,0,0,8" Padding="4" ToolTip="Filter scripts"/>
      <ListBox x:Name="ScriptList" BorderBrush="#D0D4DA" Background="White"/>
    </DockPanel>
    <Grid Grid.Column="2">
      <Grid.RowDefinitions>
        <RowDefinition Height="Auto"/>
        <RowDefinition Height="Auto"/>
        <RowDefinition Height="*"/>
        <RowDefinition Height="Auto"/>
        <RowDefinition Height="Auto"/>
      </Grid.RowDefinitions>
      <TextBlock x:Name="Title" Grid.Row="0" FontSize="20" FontWeight="SemiBold" Text="Select a script"/>
      <TextBlock x:Name="Synopsis" Grid.Row="1" TextWrapping="Wrap" Foreground="#444" Margin="0,4,0,10"/>
      <Border Grid.Row="2" BorderBrush="#D0D4DA" BorderThickness="1" Background="White" CornerRadius="4">
        <ScrollViewer VerticalScrollBarVisibility="Auto">
          <StackPanel x:Name="ParamPanel" Margin="12"/>
        </ScrollViewer>
      </Border>
      <TextBox x:Name="Preview" Grid.Row="3" Margin="0,10,0,0" IsReadOnly="True" TextWrapping="Wrap" FontFamily="Consolas" FontSize="12" Background="#EEF0F3" Padding="6" MinHeight="48"/>
      <StackPanel Grid.Row="4" Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,10,0,0">
        <Button x:Name="BtnHelp"   Content="Full help"      Width="110" Margin="0,0,8,0" Padding="6"/>
        <Button x:Name="BtnEdit"   Content="Open script"    Width="110" Margin="0,0,8,0" Padding="6"/>
        <Button x:Name="BtnOutput" Content="Output folder"  Width="120" Margin="0,0,8,0" Padding="6"/>
        <Button x:Name="BtnCopy"   Content="Copy command"   Width="120" Margin="0,0,8,0" Padding="6"/>
        <Button x:Name="BtnRun"    Content="Run"            Width="120" Padding="6" FontWeight="SemiBold" Background="#2B6CB0" Foreground="White"/>
      </StackPanel>
    </Grid>
  </Grid>
</Window>
'@
try { $window = [Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader $xaml)) }
catch { Write-Host "Could not load the window: $($_.Exception.Message)" -ForegroundColor Red; return }
$ui = @{}
foreach ($n in 'Filter', 'ScriptList', 'Title', 'Synopsis', 'ParamPanel', 'Preview', 'BtnHelp', 'BtnEdit', 'BtnOutput', 'BtnCopy', 'BtnRun') { $ui[$n] = $window.FindName($n) }
$script:Current = $null
$script:Controls = New-Object System.Collections.Generic.List[object]
#endregion

#region ---- UI logic ----
function Update-ScriptList {
    $ui.ScriptList.Items.Clear()
    $filter = $ui.Filter.Text
    foreach ($cat in 'tenant', 'endpoint') {
        $items = @($AllScripts | Where-Object { $_.Category -eq $cat -and (-not $filter -or $_.Name -like "*$filter*" -or $_.Synopsis -like "*$filter*") })
        if ($items.Count -eq 0) { continue }
        $hdr = New-Object System.Windows.Controls.ListBoxItem
        $label = 'TENANT (run from your workstation)'; if ($cat -eq 'endpoint') { $label = 'ENDPOINT (RMM / run as admin)' }
        $hdr.Content = $label; $hdr.IsEnabled = $false; $hdr.FontWeight = 'Bold'; $hdr.Margin = '0,6,0,2'
        [void]$ui.ScriptList.Items.Add($hdr)
        foreach ($s in $items) {
            $li = New-Object System.Windows.Controls.ListBoxItem
            $suffix = ''; if ($s.Ps7) { $suffix = '  [PS7]' }
            $li.Content = $s.Name + $suffix; $li.Tag = $s; $li.ToolTip = $s.Synopsis; $li.Padding = '8,3,4,3'
            [void]$ui.ScriptList.Items.Add($li)
        }
    }
}

function Show-ScriptForm {
    param([object]$Info)
    $script:Current = $Info
    $script:Controls.Clear()
    $ui.ParamPanel.Children.Clear()
    $ui.Title.Text = $Info.Name
    $notes = @()
    if ($Info.Ps7) { $notes += 'Runs in PowerShell 7.' }
    if ($Info.Elevated) { $notes += 'Runs elevated (UAC prompt).' }
    if ($Info.ParseErrors -gt 0) { $notes += "WARNING: $($Info.ParseErrors) parse error(s) in this script." }
    $ui.Synopsis.Text = ($Info.Synopsis + '  ' + ($notes -join ' ')).Trim()
    if ($Info.Params.Count -eq 0) {
        $t = New-Object System.Windows.Controls.TextBlock; $t.Text = 'This script has no parameters.'; [void]$ui.ParamPanel.Children.Add($t)
    }
    foreach ($p in $Info.Params) {
        $row = New-Object System.Windows.Controls.StackPanel; $row.Margin = '0,0,0,12'
        $lbl = New-Object System.Windows.Controls.TextBlock; $lbl.Text = $p.Name; $lbl.FontWeight = 'SemiBold'
        [void]$row.Children.Add($lbl)
        if ($p.Type -eq 'SwitchParameter') {
            $ctl = New-Object System.Windows.Controls.CheckBox; $ctl.Content = 'Enabled'; $ctl.Margin = '0,3,0,0'
            $kind = 'Switch'
        } elseif ($p.Set) {
            $ctl = New-Object System.Windows.Controls.ComboBox; $ctl.Margin = '0,3,0,0'; $ctl.MaxWidth = 420; $ctl.HorizontalAlignment = 'Left'; $ctl.MinWidth = 220
            [void]$ctl.Items.Add('')
            foreach ($v in $p.Set) { [void]$ctl.Items.Add($v) }
            if ($p.Default) { $ctl.SelectedItem = $p.Default } else { $ctl.SelectedIndex = 0 }
            $kind = 'Set'
        } else {
            $ctl = New-Object System.Windows.Controls.ComboBox; $ctl.IsEditable = $true; $ctl.Margin = '0,3,0,0'; $ctl.Padding = '4,3,4,3'
            foreach ($h in @($script:History[$p.Name])) { if ($h) { [void]$ctl.Items.Add($h) } }
            $ctl.Text = $p.Default
            if ($p.Name -eq 'AdminUpn' -and @($script:History['AdminUpn']).Count -gt 0) { $ctl.Text = @($script:History['AdminUpn'])[0] }
            $kind = 'Text'
        }
        [void]$row.Children.Add($ctl)
        if ($p.Description) {
            $d = New-Object System.Windows.Controls.TextBlock; $d.Text = $p.Description; $d.TextWrapping = 'Wrap'; $d.Foreground = '#666'; $d.FontSize = 12; $d.Margin = '0,3,0,0'
            [void]$row.Children.Add($d)
        }
        [void]$ui.ParamPanel.Children.Add($row)
        $script:Controls.Add([pscustomobject]@{ Name = $p.Name; Kind = $kind; Control = $ctl })
    }
    $ui.Preview.Text = ''
}

function Get-ArgumentList {
    $list = New-Object System.Collections.Generic.List[object]
    foreach ($c in $script:Controls) {
        if ($c.Kind -eq 'Switch') { if ($c.Control.IsChecked) { $list.Add([pscustomobject]@{ Name = $c.Name; Value = $null }) } }
        else {
            $v = ''
            if ($c.Kind -eq 'Set') { $v = [string]$c.Control.SelectedItem } else { $v = [string]$c.Control.Text }
            if (-not [string]::IsNullOrWhiteSpace($v)) { $list.Add([pscustomobject]@{ Name = $c.Name; Value = $v.Trim() }) }
        }
    }
    return $list
}
function Get-PowerShellCommand {
    param([object[]]$ArgList)
    $parts = @("& '{0}'" -f ($script:Current.Path -replace "'", "''"))
    foreach ($a in $ArgList) {
        if ($null -eq $a.Value) { $parts += ('-{0}' -f $a.Name) }
        elseif ($a.Value -match '^\d+$') { $parts += ('-{0} {1}' -f $a.Name, $a.Value) }
        else { $parts += ("-{0} '{1}'" -f $a.Name, ($a.Value -replace "'", "''")) }
    }
    return ($parts -join ' ')
}
function Get-Host7 {
    $p = Get-Command -Name pwsh.exe -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($p) { return $p.Source }
    $fallback = Join-Path $env:ProgramFiles 'PowerShell\7\pwsh.exe'
    if (Test-Path $fallback) { return $fallback }
    return $null
}
#endregion

#region ---- Events ----
$ui.Filter.Add_TextChanged({ Update-ScriptList })
$ui.ScriptList.Add_SelectionChanged({
    $sel = $ui.ScriptList.SelectedItem
    if ($sel -and $sel.Tag) { Show-ScriptForm -Info $sel.Tag }
})
$ui.BtnCopy.Add_Click({
    if (-not $script:Current) { return }
    $cmd = Get-PowerShellCommand -ArgList @(Get-ArgumentList)
    $ui.Preview.Text = $cmd
    try { [System.Windows.Clipboard]::SetText($cmd) } catch { }
})
$ui.BtnRun.Add_Click({
    if (-not $script:Current) { return }
    $argList = @(Get-ArgumentList)
    $exe = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
    if ($script:Current.Ps7) {
        $exe = Get-Host7
        if (-not $exe) { [System.Windows.MessageBox]::Show('This script needs PowerShell 7 (pwsh.exe), which was not found. Install it with: winget install Microsoft.PowerShell', 'PowerShell 7 required') | Out-Null; return }
    }
    $cmd = Get-PowerShellCommand -ArgList $argList
    $title = ($script:Current.Name -replace "'", '')
    $launch = "`$Host.UI.RawUI.WindowTitle = '$title'; $cmd"
    $encoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($launch))
    $psArgs = '-NoExit -NoProfile -ExecutionPolicy Bypass -EncodedCommand ' + $encoded
    $ui.Preview.Text = $cmd
    foreach ($a in $argList) { if ($null -ne $a.Value) { Add-ValueHistory -Name $a.Name -Value $a.Value } }
    Save-History
    try {
        if ($script:Current.Elevated) { Start-Process -FilePath $exe -ArgumentList $psArgs -Verb RunAs -ErrorAction Stop }
        else { Start-Process -FilePath $exe -ArgumentList $psArgs -ErrorAction Stop }
    } catch { [System.Windows.MessageBox]::Show("Launch failed: $($_.Exception.Message)", 'Run') | Out-Null }
})
$ui.BtnOutput.Add_Click({
    try { if (-not (Test-Path $OutputRoot)) { New-Item -ItemType Directory -Path $OutputRoot -Force | Out-Null }; Start-Process -FilePath explorer.exe -ArgumentList ('"{0}"' -f $OutputRoot) } catch { }
})
$ui.BtnEdit.Add_Click({
    if (-not $script:Current) { return }
    $code = Get-Command -Name code -ErrorAction SilentlyContinue | Select-Object -First 1
    try { if ($code) { Start-Process -FilePath $code.Source -ArgumentList ('"{0}"' -f $script:Current.Path) } else { Start-Process -FilePath notepad.exe -ArgumentList ('"{0}"' -f $script:Current.Path) } } catch { }
})
$ui.BtnHelp.Add_Click({
    if (-not $script:Current) { return }
    $text = $script:Current.Synopsis + "`r`n`r`n" + $script:Current.Description
    [System.Windows.MessageBox]::Show($text, $script:Current.Name) | Out-Null
})
#endregion

Update-ScriptList
[void]$window.ShowDialog()
