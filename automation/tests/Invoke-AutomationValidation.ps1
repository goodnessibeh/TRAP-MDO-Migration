#Requires -Version 7.0

<#
.SYNOPSIS
    Run all automation validators (Logic Apps + Workbooks) in one pass.

.DESCRIPTION
    Runs Test-LogicAppTemplate.ps1 against ../logic-apps and
    Test-WorkbookSchema.ps1 against ../workbooks. Returns non-zero if
    any validator reports a failure.

.PARAMETER OutputCsv
    Optional. Writes a combined CSV at this path.

.EXAMPLE
    .\Invoke-AutomationValidation.ps1

.EXAMPLE
    .\Invoke-AutomationValidation.ps1 -OutputCsv ../findings.csv
#>

[CmdletBinding()]
param(
    [string]$OutputCsv
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$here = $PSScriptRoot
$logicApps = Join-Path $here '..\logic-apps'
$workbooks = Join-Path $here '..\workbooks'

$exit = 0

Write-Host '=== Logic App ARM templates ===' -ForegroundColor Cyan
& (Join-Path $here 'Test-LogicAppTemplate.ps1') -Path $logicApps
if ($LASTEXITCODE -ne 0) { $exit = 1 }

Write-Host ''
Write-Host '=== Sentinel workbooks ===' -ForegroundColor Cyan
& (Join-Path $here 'Test-WorkbookSchema.ps1') -Path $workbooks
if ($LASTEXITCODE -ne 0) { $exit = 1 }

exit $exit
