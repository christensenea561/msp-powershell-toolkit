#Requires -Version 5.1

<#
.SYNOPSIS
    Static checks for every script in the toolkit.

.DESCRIPTION
    - Parses each .ps1 and reports parse errors
    - Flags PowerShell 7-only syntax (??, ??=, ?., ?[], &&, ||, ternary) in scripts that do not declare #Requires -Version 7
    - Flags non-ASCII characters (Windows PowerShell 5.1 reads BOM-less files as ANSI)
    - Flags exit statements (they close the host session in VS Code / ISE)
    Use -CI in a pipeline to throw when any issue is found.

.PARAMETER Path
    Root folder to scan. Defaults to the repo root (parent of this tests folder).
.PARAMETER CI
    Throw at the end if any issue is found, so a CI job fails.
#>
[CmdletBinding()]
param(
    [string]$Path,
    [switch]$CI
)

if (-not $Path) {
    if ($PSScriptRoot) { $Path = Split-Path -Path $PSScriptRoot -Parent } else { $Path = (Get-Location).Path }
}

$ps7Tokens = @('QuestionQuestion', 'QuestionQuestionEquals', 'QuestionDot', 'QuestionLBracket', 'AndAnd', 'OrOr', 'QuestionMark')
$issues    = New-Object System.Collections.Generic.List[object]
$files     = @(Get-ChildItem -Path $Path -Filter '*.ps1' -Recurse -File | Where-Object { $_.FullName -notmatch '[\\/]\.git[\\/]' })

foreach ($f in $files) {
    $tokens = $null; $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$tokens, [ref]$errors)
    $rel = $f.FullName.Substring($Path.Length).TrimStart('\', '/')

    foreach ($e in $errors) { $issues.Add([pscustomobject]@{ File = $rel; Line = $e.Extent.StartLineNumber; Issue = 'Parse error: ' + $e.Message }) }

    $isPs7 = $false
    if ($ast.ScriptRequirements -and $ast.ScriptRequirements.RequiredPSVersion -and $ast.ScriptRequirements.RequiredPSVersion.Major -ge 7) { $isPs7 = $true }
    if (-not $isPs7) {
        foreach ($t in $tokens) {
            if ($ps7Tokens -contains [string]$t.Kind) { $issues.Add([pscustomobject]@{ File = $rel; Line = $t.Extent.StartLineNumber; Issue = 'PS7-only operator: ' + $t.Text }) }
        }
    }

    foreach ($t in $tokens) {
        if ([string]$t.Kind -eq 'Exit') { $issues.Add([pscustomobject]@{ File = $rel; Line = $t.Extent.StartLineNumber; Issue = 'exit statement (closes the host session)' }) }
    }

    $bytes = [System.IO.File]::ReadAllBytes($f.FullName)
    $line = 1
    for ($i = 0; $i -lt $bytes.Length; $i++) {
        if ($bytes[$i] -eq 10) { $line++ }
        elseif ($bytes[$i] -gt 127) { $issues.Add([pscustomobject]@{ File = $rel; Line = $line; Issue = 'Non-ASCII character' }); break }
    }
}

Write-Host ('Scanned {0} script(s)' -f $files.Count) -ForegroundColor Cyan
if ($issues.Count -eq 0) { Write-Host 'No issues found.' -ForegroundColor Green }
else {
    $issues | Format-Table -AutoSize -Wrap | Out-String -Width 200 | Write-Host
    Write-Host ('{0} issue(s) found.' -f $issues.Count) -ForegroundColor Red
    if ($CI) { throw ('{0} issue(s) found by Test-ToolkitSyntax' -f $issues.Count) }
}
