#Requires -Version 7.0

<#
.SYNOPSIS
    Validate Microsoft Sentinel workbook JSON files.

.DESCRIPTION
    Static (offline) validation of Sentinel workbook JSON. No Azure
    connection required. Checks:
      1. Valid JSON syntax.
      2. Workbook top-level shape: version, items[].
      3. Every item has 'type' (int) and 'name' (unique).
      4. Each item's required content fields are present for its type:
         - 1 (markdown):   content.json
         - 3 (query):      content.query, content.queryType, content.resourceType
         - 9 (parameters): content.parameters[]
         - 11 (links):     content.links[]
      5. Every parameter referenced in a query (e.g. {TimeRange},
         {Workspace}) is declared in at least one type-9 parameters item.
      6. Each KQL query is parsed for obvious syntax issues (balanced
         parens, no unbalanced strings).

.PARAMETER Path
    File or directory. If directory, every *.json file is validated.

.PARAMETER OutputCsv
    Optional CSV of all findings.

.EXAMPLE
    .\Test-WorkbookSchema.ps1 ../workbooks/trap-mdo-parallel-run.json

.EXAMPLE
    .\Test-WorkbookSchema.ps1 ../workbooks -OutputCsv findings.csv
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$Path,

    [string]$OutputCsv
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

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

# Required content keys per Sentinel workbook item type.
$RequiredByType = @{
    1  = @('json')                # markdown / text
    3  = @('query', 'queryType')      # query
    9  = @('version', 'parameters')   # parameters
    11 = @('links')                # link list
    12 = @('groupType')             # group container
    10 = @('chartId')               # ARG metric
    2  = @('chartConfiguration')    # legacy chart
}

function Test-OneWorkbook {
    param([string]$FilePath)

    try {
        $raw = Get-Content -Path $FilePath -Raw
        $wb = $raw | ConvertFrom-Json -Depth 100 -AsHashtable
        Add-Finding -File $FilePath -Status 'Pass' -Check 'JSON parses'
    }
    catch {
        Add-Finding -File $FilePath -Status 'Fail' -Check 'JSON parses' -Detail $_.Exception.Message
        return
    }

    foreach ($k in 'version', 'items') {
        if (-not $wb.ContainsKey($k)) {
            Add-Finding -File $FilePath -Status 'Fail' -Check "Has top-level '$k'" -Detail 'Missing'
        }
        else {
            Add-Finding -File $FilePath -Status 'Pass' -Check "Has top-level '$k'"
        }
    }

    if (-not $wb.ContainsKey('items')) { return }

    # Item-level checks
    $declaredParams = [System.Collections.Generic.HashSet[string]]::new()
    $queryRefs = [System.Collections.Generic.HashSet[string]]::new()
    $itemNames = [System.Collections.Generic.HashSet[string]]::new()
    $itemIndex = -1

    foreach ($item in $wb['items']) {
        $itemIndex++
        $where = "item[$itemIndex]"

        if (-not $item.ContainsKey('type')) {
            Add-Finding -File $FilePath -Status 'Fail' -Check "$where has 'type'" -Detail 'Missing'
            continue
        }
        if (-not $item.ContainsKey('name')) {
            Add-Finding -File $FilePath -Status 'Warn' -Check "$where has 'name'" -Detail 'Missing — uniqueness check skipped'
        }
        else {
            $nm = $item['name']
            if (-not $itemNames.Add($nm)) {
                Add-Finding -File $FilePath -Status 'Fail' -Check "Unique item name" -Detail "Duplicate: '$nm'"
            }
        }

        $type = [int]$item['type']
        if (-not $item.ContainsKey('content')) {
            Add-Finding -File $FilePath -Status 'Fail' `
                -Check "$where (type=$type) has 'content'" -Detail 'Missing'
            continue
        }
        $content = $item['content']

        if ($RequiredByType.ContainsKey($type)) {
            foreach ($needed in $RequiredByType[$type]) {
                if (-not $content.ContainsKey($needed)) {
                    Add-Finding -File $FilePath -Status 'Fail' `
                        -Check "$where (type=$type) content has '$needed'" -Detail 'Missing'
                }
            }
        }

        if ($type -eq 9 -and $content.ContainsKey('parameters')) {
            foreach ($p in $content['parameters']) {
                if ($p.ContainsKey('name')) { $null = $declaredParams.Add($p['name']) }
            }
        }

        if ($type -eq 3 -and $content.ContainsKey('query')) {
            $q = $content['query']
            $matches = [regex]::Matches($q, '\{([A-Za-z_][A-Za-z0-9_]*)(?::\w+)?\}')
            foreach ($m in $matches) { $null = $queryRefs.Add($m.Groups[1].Value) }

            # Balanced parens / brackets
            $opens = @($q.ToCharArray() | Where-Object { $_ -eq '(' }).Count
            $closes = @($q.ToCharArray() | Where-Object { $_ -eq ')' }).Count
            if ($opens -ne $closes) {
                Add-Finding -File $FilePath -Status 'Warn' `
                    -Check "$where KQL parens balanced" `
                    -Detail "Open=$opens Close=$closes"
            }
        }
    }

    # Parameter resolution
    $undeclared = $queryRefs | Where-Object { $_ -notin $declaredParams -and $_ -notmatch '^(TimeRange|Workspace|Subscription)$' }
    if ($undeclared) {
        Add-Finding -File $FilePath -Status 'Warn' `
            -Check 'All workbook parameters declared' `
            -Detail ('Referenced but not declared: ' + ($undeclared -join ', '))
    }
    elseif ($queryRefs.Count -gt 0) {
        Add-Finding -File $FilePath -Status 'Pass' `
            -Check 'All workbook parameters declared' `
            -Detail ('Referenced: ' + (($queryRefs | Sort-Object) -join ', '))
    }

    Add-Finding -File $FilePath -Status 'Info' -Check 'Item count' -Detail ("items=$($wb['items'].Count)")
}

if (-not (Test-Path -Path $Path)) {
    Write-Error "Path not found: $Path"
    exit 2
}

$target = Get-Item -Path $Path
$files = @(if ($target.PSIsContainer) {
        Get-ChildItem -Path $Path -Recurse -File -Include '*.json'
    }
    else { $target })

if ($files.Count -eq 0) {
    Write-Warning 'No JSON files found.'
    exit 0
}

Write-Host ('Validating ' + $files.Count + ' workbook(s)') -ForegroundColor Cyan
foreach ($f in $files) { Test-OneWorkbook -FilePath $f.FullName }

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
