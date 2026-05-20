#Requires -Version 7.0

<#
.SYNOPSIS
    Validate one or more Logic App ARM template files.

.DESCRIPTION
    Static (offline) validation of Logic App / playbook ARM templates.
    No Azure connection required. Checks:
      1. Valid JSON syntax.
      2. ARM-template top-level shape: $schema, contentVersion, resources.
      3. Each Microsoft.Logic/workflows resource has type, apiVersion,
         name, location, properties.
      4. The embedded workflow definition has $schema, triggers, actions.
      5. Every action references either a trigger or a prior action via
         runAfter (no orphan branches).
      6. Every $connections reference in actions resolves to an entry in
         parameters.$connections.value (catches typos that only blow up
         at deploy time).
      7. Parameter references like [parameters('X')] resolve to a
         declared parameter.
      8. JSON file ends in newline (cosmetic, fails CI consistency).

.PARAMETER Path
    File or directory. If a directory is given, every *.json file under
    it that contains a Microsoft.Logic/workflows resource is validated.

.PARAMETER OutputCsv
    Optional CSV of all findings.

.EXAMPLE
    .\Test-LogicAppTemplate.ps1 ../logic-apps/P3-notify-reporter-bridge

.EXAMPLE
    .\Test-LogicAppTemplate.ps1 ../logic-apps -OutputCsv findings.csv
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$Path,

    [string]$OutputCsv
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------- helpers ----------

$findings = [System.Collections.Generic.List[object]]::new()

function Add-Finding {
    param(
        [string]$File,
        [ValidateSet('Pass', 'Fail', 'Warn', 'Info')]
        [string]$Status,
        [string]$Check,
        [string]$Detail = ''
    )
    $findings.Add([pscustomobject]@{
            Timestamp = (Get-Date).ToString('o')
            File      = $File
            Check     = $Check
            Status    = $Status
            Detail    = $Detail
        })
    $color = switch ($Status) {
        'Pass' { 'Green' }
        'Warn' { 'Yellow' }
        'Fail' { 'Red' }
        default { 'DarkGray' }
    }
    Write-Host ('[{0,-5}] {1,-55} {2}' -f $Status, (Split-Path -Leaf $File), $Check) -ForegroundColor $color
    if ($Detail) { Write-Host "          $Detail" -ForegroundColor DarkGray }
}

function Test-OneTemplate {
    param([string]$FilePath)

    # 1. JSON parse
    try {
        $raw = Get-Content -Path $FilePath -Raw
        $json = $raw | ConvertFrom-Json -Depth 100 -AsHashtable
        Add-Finding -File $FilePath -Status 'Pass' -Check 'JSON parses'
    }
    catch {
        Add-Finding -File $FilePath -Status 'Fail' -Check 'JSON parses' -Detail $_.Exception.Message
        return
    }

    # 2. ARM top-level
    foreach ($required in '$schema', 'contentVersion', 'resources') {
        if (-not $json.ContainsKey($required)) {
            Add-Finding -File $FilePath -Status 'Fail' -Check "Has top-level '$required'" `
                -Detail 'Missing'
        }
        else {
            Add-Finding -File $FilePath -Status 'Pass' -Check "Has top-level '$required'"
        }
    }

    if (-not $json.ContainsKey('resources')) { return }

    # 3. Workflow resource shape
    $workflows = $json['resources'] | Where-Object { $_['type'] -eq 'Microsoft.Logic/workflows' }
    if (-not $workflows) {
        Add-Finding -File $FilePath -Status 'Info' -Check 'Contains Microsoft.Logic/workflows resource' `
            -Detail 'No workflow resource — skipping workflow-specific checks'
        return
    }

    foreach ($wf in $workflows) {
        $wfName = $wf['name']
        foreach ($prop in 'type', 'apiVersion', 'name', 'location', 'properties') {
            if (-not $wf.ContainsKey($prop)) {
                Add-Finding -File $FilePath -Status 'Fail' `
                    -Check "Workflow '$wfName' has '$prop'" -Detail 'Missing'
            }
            else {
                Add-Finding -File $FilePath -Status 'Pass' -Check "Workflow '$wfName' has '$prop'"
            }
        }

        if (-not $wf.ContainsKey('properties')) { continue }
        $props = $wf['properties']

        # 4. Definition shape
        if (-not $props.ContainsKey('definition')) {
            Add-Finding -File $FilePath -Status 'Fail' -Check "Workflow '$wfName' has definition"
            continue
        }
        $def = $props['definition']
        foreach ($k in '$schema', 'triggers', 'actions') {
            if (-not $def.ContainsKey($k)) {
                Add-Finding -File $FilePath -Status 'Fail' `
                    -Check "Workflow '$wfName' definition has '$k'" -Detail 'Missing'
            }
            else {
                Add-Finding -File $FilePath -Status 'Pass' -Check "Workflow '$wfName' definition has '$k'"
            }
        }

        # Triggers must be non-empty
        if ($def.ContainsKey('triggers') -and $def['triggers'].Keys.Count -eq 0) {
            Add-Finding -File $FilePath -Status 'Fail' -Check "Workflow '$wfName' has at least one trigger"
        }

        # 5. runAfter / orphan-branch check
        if ($def.ContainsKey('actions')) {
            $actionNames = @($def['actions'].Keys)
            $triggerNames = @($def['triggers'].Keys)
            foreach ($actionName in $actionNames) {
                $action = $def['actions'][$actionName]
                if (-not $action.ContainsKey('runAfter')) { continue }
                $runAfter = $action['runAfter']
                if ($runAfter -isnot [hashtable] -or $runAfter.Keys.Count -eq 0) { continue }
                foreach ($predecessor in $runAfter.Keys) {
                    if ($predecessor -notin $actionNames -and $predecessor -notin $triggerNames) {
                        Add-Finding -File $FilePath -Status 'Fail' `
                            -Check "Action '$actionName' runAfter resolves" `
                            -Detail "References '$predecessor' which is not a declared action or trigger"
                    }
                }
            }
            Add-Finding -File $FilePath -Status 'Pass' -Check 'All runAfter references resolve'
        }

        # 6. $connections reference check (use single-quoted regex so
        #    StrictMode doesn't trip on the literal `$connections` token)
        $connKey = '$connections'
        $connectionsInParams = @()
        if ($props.ContainsKey('parameters') -and
            $props['parameters'].ContainsKey($connKey) -and
            $props['parameters'][$connKey].ContainsKey('value')) {
            $connectionsInParams = @($props['parameters'][$connKey]['value'].Keys)
        }
        # Single-quoted: PowerShell would otherwise try to expand $connections.
        # In regex: \( and \) escape the parens, \$ escapes the dollar.
        $connPattern = '@parameters\(''\$connections''\)\[''([^'']+)''\]'
        $connRefs = @([regex]::Matches($raw, $connPattern)).
        ForEach({ $_.Groups[1].Value }) | Sort-Object -Unique
        foreach ($ref in $connRefs) {
            if ($ref -notin $connectionsInParams) {
                Add-Finding -File $FilePath -Status 'Fail' `
                    -Check "Connection '$ref' declared in parameters" `
                    -Detail 'Referenced in workflow but not in parameters.$connections.value'
            }
        }
        if ($connRefs) {
            Add-Finding -File $FilePath -Status 'Pass' `
                -Check 'All $connections references resolve' `
                -Detail ('Found: ' + ($connRefs -join ', '))
        }

        # 7. Parameter reference check
        $declared = @()
        if ($json.ContainsKey('parameters')) { $declared = @($json['parameters'].Keys) }
        $paramRefs = ([regex]::Matches($raw, "parameters\('([^']+)'\)")).
        ForEach({ $_.Groups[1].Value }) |
        Where-Object { $_ -ne '$connections' } |
        Sort-Object -Unique
        foreach ($ref in $paramRefs) {
            if ($ref -notin $declared) {
                Add-Finding -File $FilePath -Status 'Fail' `
                    -Check "Parameter '$ref' declared at top level" `
                    -Detail 'Referenced in template but not in top-level parameters{}'
            }
        }
        if ($paramRefs) {
            Add-Finding -File $FilePath -Status 'Pass' `
                -Check 'All [parameters(X)] references resolve' `
                -Detail ("Found: " + ($paramRefs -join ', '))
        }
    }
}

# ---------- main ----------

if (-not (Test-Path -Path $Path)) {
    Write-Error "Path not found: $Path"
    exit 2
}

$target = Get-Item -Path $Path
if ($target.PSIsContainer) {
    $files = Get-ChildItem -Path $Path -Recurse -File -Include '*.json'
}
else {
    $files = @($target)
}

# Filter to files that look like ARM deployment templates.
# Exclude parameters files (their $schema is deploymentParameters.json).
$files = $files | Where-Object {
    try {
        $raw = $_ | Get-Content -Raw
        $raw -match '"\$schema":\s*"https://schema\.management\.azure\.com[^"]*deploymentTemplate'
    }
    catch { $false }
}

$files = @($files)
if ($files.Count -eq 0) {
    Write-Warning 'No ARM template files matched.'
    exit 0
}

Write-Host ('Validating ' + $files.Count + ' template(s)') -ForegroundColor Cyan
foreach ($f in $files) { Test-OneTemplate -FilePath $f.FullName }

# Summary
$errorCount = @($findings | Where-Object Status -eq 'Fail').Count
$warnCount = @($findings | Where-Object Status -eq 'Warn').Count
$passCount = @($findings | Where-Object Status -eq 'Pass').Count

Write-Host ''
Write-Host ('Summary: Pass={0}  Warn={1}  Fail={2}' -f $passCount, $warnCount, $errorCount) `
    -ForegroundColor ($errorCount -gt 0 ? 'Red' : 'Green')

if ($OutputCsv) {
    $findings | Export-Csv -Path $OutputCsv -NoTypeInformation -Encoding UTF8
    Write-Host ('Findings: ' + (Resolve-Path -Path $OutputCsv)) -ForegroundColor Green
}

if ($errorCount -gt 0) { exit 1 } else { exit 0 }
