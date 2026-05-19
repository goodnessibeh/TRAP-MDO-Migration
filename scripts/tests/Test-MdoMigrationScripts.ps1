#Requires -Version 7.0

<#
.SYNOPSIS
    Run PSScriptAnalyzer against every script in the migration toolkit.

.DESCRIPTION
    Wraps Invoke-ScriptAnalyzer with the toolkit's PSScriptAnalyzerSettings.psd1
    against every .ps1, .psm1, and .psd1 file under scripts/. Returns
    exit code 1 if any error- or warning-level finding is reported.

.PARAMETER ScriptRoot
    Path to scan. Defaults to the parent of this script (i.e. scripts/).

.PARAMETER SettingsPath
    Path to PSScriptAnalyzerSettings.psd1. Defaults to scripts/PSScriptAnalyzerSettings.psd1.

.PARAMETER OutputCsv
    If specified, writes the findings to a CSV at this path.

.PARAMETER Fix
    Pass-through to Invoke-ScriptAnalyzer -Fix. Auto-applies
    formatter-style fixes (whitespace, brace placement, indentation).

.EXAMPLE
    .\tests\Test-MdoMigrationScripts.ps1

.EXAMPLE
    .\tests\Test-MdoMigrationScripts.ps1 -Fix

.EXAMPLE
    .\tests\Test-MdoMigrationScripts.ps1 -OutputCsv .\pssa-findings.csv

.NOTES
    Prerequisite: Install-Module PSScriptAnalyzer -Scope CurrentUser -Force
#>

[CmdletBinding()]
param(
    [string]$ScriptRoot   = (Split-Path -Parent $PSScriptRoot),
    [string]$SettingsPath = (Join-Path (Split-Path -Parent $PSScriptRoot) 'PSScriptAnalyzerSettings.psd1'),
    [string]$OutputCsv,
    [switch]$Fix
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Get-Module PSScriptAnalyzer -ListAvailable)) {
    Write-Error 'PSScriptAnalyzer not installed. Run: Install-Module PSScriptAnalyzer -Scope CurrentUser -Force'
    exit 2
}
Import-Module PSScriptAnalyzer -Force

if (-not (Test-Path -Path $SettingsPath)) {
    Write-Error "Settings file not found: $SettingsPath"
    exit 2
}

Write-Host "Scanning: $ScriptRoot" -ForegroundColor Cyan
Write-Host "Settings: $SettingsPath" -ForegroundColor Cyan
Write-Host ''

$targets = Get-ChildItem -Path $ScriptRoot -Recurse -File -Include *.ps1,*.psm1,*.psd1 |
           Where-Object { $_.FullName -notmatch '\\tests\\Test-MdoMigrationScripts\.ps1$' }

if (-not $targets) {
    Write-Warning 'No script files found.'
    exit 0
}

$findings = [System.Collections.Generic.List[object]]::new()

foreach ($file in $targets) {
    Write-Host ('  -> {0}' -f $file.FullName) -ForegroundColor DarkGray
    $analyzerParams = @{
        Path     = $file.FullName
        Settings = $SettingsPath
    }
    if ($Fix) { $analyzerParams['Fix'] = $true }

    $result = Invoke-ScriptAnalyzer @analyzerParams
    foreach ($r in $result) {
        $findings.Add([pscustomobject]@{
            File       = (Resolve-Path -Path $r.ScriptPath -Relative -ErrorAction SilentlyContinue) ?? $r.ScriptPath
            Line       = $r.Line
            Column     = $r.Column
            Severity   = $r.Severity
            RuleName   = $r.RuleName
            Message    = $r.Message
            ScriptName = $r.ScriptName
        })
    }
}

$errorCount   = ($findings | Where-Object Severity -eq 'Error').Count
$warningCount = ($findings | Where-Object Severity -eq 'Warning').Count
$infoCount    = ($findings | Where-Object Severity -eq 'Information').Count

Write-Host ''
Write-Host 'PSScriptAnalyzer summary:' -ForegroundColor White
Write-Host ('  Error:       {0}' -f $errorCount)   -ForegroundColor (($errorCount -gt 0)   ? 'Red'    : 'Green')
Write-Host ('  Warning:     {0}' -f $warningCount) -ForegroundColor (($warningCount -gt 0) ? 'Yellow' : 'Green')
Write-Host ('  Information: {0}' -f $infoCount)    -ForegroundColor DarkGray

if ($findings) {
    $findings |
        Sort-Object Severity, File, Line |
        Format-Table -AutoSize Severity, RuleName, File, Line, Message
}

if ($OutputCsv) {
    $findings | Export-Csv -Path $OutputCsv -NoTypeInformation -Encoding UTF8
    Write-Host "`nFindings written to $OutputCsv" -ForegroundColor Green
}

if ($errorCount -gt 0 -or $warningCount -gt 0) { exit 1 } else { exit 0 }
