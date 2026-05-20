#Requires -Version 7.0

<#
.SYNOPSIS
    Bootstrap the GitHub Issues board for the TRAP -> MDO migration:
    labels, milestones, and every task from the blueprint roadmap.

.DESCRIPTION
    Idempotent setup over the GitHub CLI (`gh`):

      1. Creates phase labels (phase-0 through phase-5) and area labels
         (licensing, sentinel, exchange, defender-xdr, logic-apps,
         workbooks, soc-process, procurement, legal).
      2. Creates one milestone per phase.
      3. Creates ~45 issues — one per task in the migration roadmap —
         labelled, milestoned, and cross-referenced via "blocks" /
         "blocked by" notes in the body.

    Runs in DRY-RUN mode by default (lists what would be created,
    makes no changes). Pass -Apply to actually create them.

    Existing labels / milestones / issues with matching names are left
    untouched — running the script twice doesn't duplicate.

.PARAMETER Repo
    GitHub repository in OWNER/NAME form.
    Default: goodnessibeh/TRAP-MDO-Migration

.PARAMETER Apply
    If set, actually creates the labels / milestones / issues.
    Without this, the script prints what it would create.

.PARAMETER Only
    Optional filter — only create issues with IDs that match the
    given prefix. Examples: '0', '1', '3.4'. Useful for incremental
    rollout (e.g. create Phase 0 issues now, do Phase 1 later).

.EXAMPLE
    .\scripts\Setup-GitHubIssues.ps1
    # Dry run — lists everything that would be created. Safe.

.EXAMPLE
    .\scripts\Setup-GitHubIssues.ps1 -Apply

.EXAMPLE
    .\scripts\Setup-GitHubIssues.ps1 -Only '0' -Apply
    # Only create Phase 0 issues.

.NOTES
    Prerequisites:
      - GitHub CLI installed:  https://cli.github.com/
      - gh auth status         (logged in)
      - Repo permission:        write
#>

[CmdletBinding()]
param(
    [string]$Repo = 'goodnessibeh/TRAP-MDO-Migration',
    [switch]$Apply,
    [string]$Only = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Pre-flight
# ---------------------------------------------------------------------------

if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
    Write-Error 'GitHub CLI (gh) is not installed. Install from https://cli.github.com/'
    exit 2
}

$authStatus = gh auth status 2>&1 | Out-String
if ($authStatus -notmatch 'Logged in to github\.com') {
    Write-Error 'gh is not authenticated. Run: gh auth login'
    exit 2
}

Write-Host "Repo: $Repo" -ForegroundColor Cyan
Write-Host "Mode: $(if ($Apply) { 'APPLY' } else { 'DRY RUN' })" -ForegroundColor $(if ($Apply) { 'Yellow' } else { 'Gray' })
if ($Only) { Write-Host "Filter: ID prefix '$Only'" -ForegroundColor Cyan }
Write-Host ''

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

function Test-LabelExist {
    param([string]$Name)
    $existing = gh label list --repo $Repo --limit 200 --json name 2>$null |
                ConvertFrom-Json -ErrorAction SilentlyContinue
    return @($existing | Where-Object name -eq $Name).Count -gt 0
}

function New-LabelIdempotent {
    param([string]$Name, [string]$Color, [string]$Description)
    if (Test-LabelExist -Name $Name) {
        Write-Host ('  [skip ] label "{0}" exists' -f $Name) -ForegroundColor DarkGray
        return
    }
    if ($Apply) {
        gh label create $Name --repo $Repo --color $Color --description $Description | Out-Null
        Write-Host ('  [made ] label "{0}"' -f $Name) -ForegroundColor Green
    }
    else {
        Write-Host ('  [would] label "{0}" color={1}' -f $Name, $Color) -ForegroundColor Yellow
    }
}

function Get-MilestoneId {
    param([string]$Title)
    $owner, $name = $Repo -split '/'
    $milestones = gh api "repos/$owner/$name/milestones?state=all&per_page=100" 2>$null |
                  ConvertFrom-Json -ErrorAction SilentlyContinue
    $hit = @($milestones | Where-Object title -eq $Title)
    if ($hit.Count -gt 0) { return $hit[0].number }
    return $null
}

function New-MilestoneIdempotent {
    param([string]$Title, [string]$Description)
    if (Get-MilestoneId -Title $Title) {
        Write-Host ('  [skip ] milestone "{0}" exists' -f $Title) -ForegroundColor DarkGray
        return
    }
    if ($Apply) {
        $owner, $name = $Repo -split '/'
        gh api "repos/$owner/$name/milestones" -f title="$Title" -f description="$Description" -f state='open' | Out-Null
        Write-Host ('  [made ] milestone "{0}"' -f $Title) -ForegroundColor Green
    }
    else {
        Write-Host ('  [would] milestone "{0}"' -f $Title) -ForegroundColor Yellow
    }
}

function Test-IssueExist {
    param([string]$Title)
    $existing = gh issue list --repo $Repo --state all --limit 200 --search "$Title in:title" --json title 2>$null |
                ConvertFrom-Json -ErrorAction SilentlyContinue
    return @($existing | Where-Object title -eq $Title).Count -gt 0
}

function New-IssueIdempotent {
    param(
        [string]$Title,
        [string]$Body,
        [string[]]$Labels,
        [string]$Milestone
    )
    if (Test-IssueExist -Title $Title) {
        Write-Host ('  [skip ] issue "{0}" exists' -f $Title) -ForegroundColor DarkGray
        return
    }
    if ($Apply) {
        $tmpFile = New-TemporaryFile
        Set-Content -Path $tmpFile -Value $Body -Encoding UTF8
        $ghArgs = @('issue', 'create', '--repo', $Repo, '--title', $Title, '--body-file', $tmpFile)
        foreach ($l in $Labels) { $ghArgs += @('--label', $l) }
        if ($Milestone) { $ghArgs += @('--milestone', $Milestone) }
        $url = & gh @ghArgs
        Remove-Item $tmpFile -Force
        Write-Host ('  [made ] {0}' -f $Title) -ForegroundColor Green
        Write-Host ('          {0}' -f $url) -ForegroundColor DarkGray
    }
    else {
        Write-Host ('  [would] {0}' -f $Title) -ForegroundColor Yellow
        Write-Host ('          labels: {0}; milestone: {1}' -f ($Labels -join ','), $Milestone) -ForegroundColor DarkGray
    }
}

# ---------------------------------------------------------------------------
# 1. Labels
# ---------------------------------------------------------------------------

Write-Host '=== Labels ===' -ForegroundColor White

$labels = @(
    @{ Name = 'phase-0-preflight';      Color = '7057FF'; Description = 'Phase 0: pre-flight audits and decisions' }
    @{ Name = 'phase-1-ootb';           Color = '0E8A16'; Description = 'Phase 1: out-of-the-box MDO deployment' }
    @{ Name = 'phase-2-parallel-run';   Color = 'FBCA04'; Description = 'Phase 2: TRAP and MDO running side-by-side' }
    @{ Name = 'phase-3-engineering';    Color = 'D93F0B'; Description = 'Phase 3: engineered enhancements (playbooks, watchlists)' }
    @{ Name = 'phase-4-cutover';        Color = 'B60205'; Description = 'Phase 4: flip reporting path from PhishAlarm to MDO' }
    @{ Name = 'phase-5-decommission';   Color = '5319E7'; Description = 'Phase 5: remove TRAP and clean up' }

    @{ Name = 'area:licensing';         Color = 'C5DEF5'; Description = '' }
    @{ Name = 'area:exchange';          Color = 'C5DEF5'; Description = '' }
    @{ Name = 'area:sentinel';          Color = 'C5DEF5'; Description = '' }
    @{ Name = 'area:defender-xdr';      Color = 'C5DEF5'; Description = '' }
    @{ Name = 'area:logic-apps';        Color = 'C5DEF5'; Description = '' }
    @{ Name = 'area:workbooks';         Color = 'C5DEF5'; Description = '' }
    @{ Name = 'area:soc-process';       Color = 'C5DEF5'; Description = '' }
    @{ Name = 'area:procurement';       Color = 'C5DEF5'; Description = '' }
    @{ Name = 'area:legal';             Color = 'C5DEF5'; Description = '' }

    @{ Name = 'gate';                   Color = 'BFD4F2'; Description = 'Exit criterion for the phase' }
    @{ Name = 'blocker';                Color = 'B60205'; Description = 'Blocking work in another phase' }
    @{ Name = 'conditional';            Color = 'EEEEEE'; Description = 'Only do this if Phase 2 data justifies it' }
    @{ Name = 'decision';               Color = 'FBCA04'; Description = 'Awaiting a decision' }
    @{ Name = 'needs-owner';            Color = 'D93F0B'; Description = 'No named owner yet' }
)

foreach ($l in $labels) {
    New-LabelIdempotent -Name $l.Name -Color $l.Color -Description $l.Description
}

# ---------------------------------------------------------------------------
# 2. Milestones
# ---------------------------------------------------------------------------

Write-Host ''
Write-Host '=== Milestones ===' -ForegroundColor White

$milestones = @(
    @{ Title = 'Phase 0 — Pre-flight';                 Description = 'License audit, hybrid posture, TRAP inventory, steward, historic data decision.' }
    @{ Title = 'Phase 1 — OOTB deployment';            Description = 'Native MDO config (Strict preset, ZAP, user-reported pipeline, SecOps overrides) + Sentinel connector + Reporter Thanks Bridge. T1-T7 must pass.' }
    @{ Title = 'Phase 2 — Parallel run';               Description = 'TRAP and MDO live in parallel; collect MTTR / FP rate / coverage data; identify Phase 3 enhancement priorities.' }
    @{ Title = 'Phase 3 — Engineering enhancements';   Description = 'Deploy the engineered playbooks (P1-P7) and watchlists chosen during Phase 2.' }
    @{ Title = 'Phase 4 — Cutover';                    Description = 'Disable PhishAlarm, disable TRAP poller, update SOC runbook, re-point external SOAR integrations.' }
    @{ Title = 'Phase 5 — Decommission';               Description = 'Cancel TRAP licence, remove app registration, archive logs, clean up residual config.' }
)

foreach ($m in $milestones) {
    New-MilestoneIdempotent -Title $m.Title -Description $m.Description
}

# ---------------------------------------------------------------------------
# 3. Issues
# ---------------------------------------------------------------------------

Write-Host ''
Write-Host '=== Issues ===' -ForegroundColor White

# Each issue: Id (for filtering), Title, Body, Labels (array), Milestone (string).
# Bodies reference blueprint docs by path; GitHub renders the links.

$issues = @(
    # ---- Phase 0 ----
    @{
        Id = '0.1'
        Title = '[Phase 0.1] Audit per-mailbox MDO P2 coverage'
        Milestone = 'Phase 0 — Pre-flight'
        Labels = @('phase-0-preflight','area:licensing','gate')
        Body = @"
## What

Confirm MDO Plan 2 (service plan ``THREAT_INTELLIGENCE``) is assigned
to >=99% of in-scope mailboxes.

## Why

Tenant-level P2 is already confirmed (Campaigns alert visible). Per-mailbox
coverage gaps are the #1 cause of "AIR silently fails to investigate
this user's reports" once Phase 2 starts. See
[``11-implementation-roadmap.md``](../blob/main/11-implementation-roadmap.md)
Phase 0 -> "Dependencies and risks".

## How

``````powershell
.\scripts\Invoke-MdoMigrationAudit.ps1  # see Phase 0 license-coverage section
``````

Or run the Graph block directly (see
[``15-exchange-online-powershell-commands.md``](../blob/main/15-exchange-online-powershell-commands.md) §1.1).

## Acceptance criteria

- [ ] CSV of any mailboxes without P2 produced
- [ ] >=99% coverage confirmed OR specific mailbox exceptions documented
- [ ] CSV attached to this issue (or path in repo if you prefer)
"@
    }
    @{
        Id = '0.2'
        Title = '[Phase 0.2] Audit hybrid posture (on-prem mailbox count)'
        Milestone = 'Phase 0 — Pre-flight'
        Labels = @('phase-0-preflight','area:exchange','gate')
        Body = @"
## What

Group every mailbox by ``RecipientTypeDetails`` and count anything that's
not ``UserMailbox`` / ``SharedMailbox`` in EXO (especially
``RemoteUserMailbox`` = on-prem).

## Why

ZAP, AIR, Defender XDR Take Action, and Compliance Search-Action only act
on EXO mailboxes. On-prem mailboxes are uncovered by the entire blueprint;
they're a Phase 4 cutover blocker if not resolved. See
[``12-limitations-and-gaps.md``](../blob/main/12-limitations-and-gaps.md) §2
and [``14-open-questions.md``](../blob/main/14-open-questions.md) §1.

## How

``````powershell
Get-Mailbox -ResultSize Unlimited | Group-Object RecipientTypeDetails
``````

## Acceptance criteria

- [ ] Count of on-prem (Remote*) mailboxes documented
- [ ] If count > 0, follow-up decision recorded (migrate / accept gap / bridge)
"@
    }
    @{
        Id = '0.3'
        Title = '[Phase 0.3] Document the current TRAP deployment'
        Milestone = 'Phase 0 — Pre-flight'
        Labels = @('phase-0-preflight','area:soc-process','area:procurement')
        Body = @"
## What

Inventory everything about the existing TRAP install before any change.
Capture: Exchange server entries, abuse mailbox addresses, active TRAP TI
lists, SOAR integrations pointing at TRAP REST API, SIEM forwarding,
audit-trail export schedule, service account, app registration.

## Why

Needed for Phase 2 parallel-run wiring and Phase 5 decommission cleanup.

## Acceptance criteria

- [ ] Inventory document committed under ``./inventory/trap-deployment.md`` (or wherever you prefer)
- [ ] Reviewed by SOC ops
"@
    }
    @{
        Id = '0.4'
        Title = '[Phase 0.4] Name the migration steward + confirm executive sponsor'
        Milestone = 'Phase 0 — Pre-flight'
        Labels = @('phase-0-preflight','area:soc-process','gate','needs-owner')
        Body = @"
## What

One named person owns the migration end-to-end. One named exec sponsor
backs procurement and decommission decisions.

## Why

The roadmap is explicit: ""trying to run this by committee fails reliably."

## Acceptance criteria

- [ ] Steward named in this issue
- [ ] Sponsor named in this issue
- [ ] Both confirmed in writing
"@
    }
    @{
        Id = '0.5'
        Title = '[Phase 0.5] Decide on historic TRAP incident-data export'
        Milestone = 'Phase 0 — Pre-flight'
        Labels = @('phase-0-preflight','area:soc-process','area:legal','decision')
        Body = @"
## What

Decide whether to export TRAP ``/api/incidents`` history for
compliance / audit retention before Phase 5 cancels the licence.

## Why

After Phase 5, the TRAP installation is gone. If an auditor later asks
for incident records from before the migration, the only source is the
export.

## Options

- Export to blob storage (PTR ``/api/incidents``, 30-day windows). Most teams.
- Skip export; rely on TRAP's own retention before cancellation.
- Re-import into Sentinel as a custom log type. Rare, expensive.

## Acceptance criteria

- [ ] Decision recorded with date + decider
- [ ] If export chosen, blob container provisioned and export tested
"@
    }

    # ---- Phase 1 ----
    @{
        Id = '1.01'
        Title = '[Phase 1.01] Run PowerShell pre-flight checks'
        Milestone = 'Phase 1 — OOTB deployment'
        Labels = @('phase-1-ootb','area:exchange')
        Body = @"
## What

Verify the admin workstation has the right tooling: EXO Management
v3+, Microsoft.Graph v2+, Unified Audit Log ingestion enabled,
Defender portal reachable.

## How

[``15-exchange-online-powershell-commands.md``](../blob/main/15-exchange-online-powershell-commands.md) §0
+ §1.3. Or run the Phase 0 / Phase 1 sections of
[``scripts/README.md``](../blob/main/scripts/README.md).

## Acceptance criteria

- [ ] ``Get-Module ExchangeOnlineManagement -ListAvailable`` >= 3.x
- [ ] ``Get-Module Microsoft.Graph -ListAvailable`` >= 2.x
- [ ] ``Get-AdminAuditLogConfig`` shows ``UnifiedAuditLogIngestionEnabled=True``
- [ ] security.microsoft.com loads with the right role mix
"@
    }
    @{
        Id = '1.02'
        Title = '[Phase 1.02] Enable Email* streams on the Sentinel Defender XDR connector'
        Milestone = 'Phase 1 — OOTB deployment'
        Labels = @('phase-1-ootb','area:sentinel','area:defender-xdr','gate','blocker')
        Body = @"
## What

Tick ``EmailEvents``, ``EmailUrlInfo``, ``EmailAttachmentInfo``, and
``EmailPostDeliveryEvents`` on the Microsoft Defender XDR data
connector in Sentinel. These are opt-in even when the connector is
"Connected" — by default only incidents + alerts flow.

## Why

Without this, every workbook + analytic rule that queries the
``Email*`` tables returns empty. This is the single most common cause
of a dead workbook in tenants with MDO P2 licensed.

## How

Azure portal → Sentinel workspace → **Data connectors** → **Microsoft
Defender XDR** → Open connector page → **Connect events** section →
tick the four Email* boxes → Apply changes.

## Acceptance criteria

- [ ] All four Email* streams ticked
- [ ] ``EmailEvents | take 1`` returns data when run from Sentinel Logs
      (not just Defender XDR Advanced Hunting)
- [ ] Operational dashboard workbook populates
"@
    }
    @{
        Id = '1.03'
        Title = '[Phase 1.03] Apply Strict preset security policy (pilot then widen)'
        Milestone = 'Phase 1 — OOTB deployment'
        Labels = @('phase-1-ootb','area:defender-xdr','gate')
        Body = @"
## What

Enable the Strict preset and scope it to all recipients in all accepted
domains. Recommended pilot rollout: scope to a handful of test users
first, validate for ~1 week, then widen.

## Why

The Strict preset is the OOTB baseline that the blueprint assumes.
It enables ZAP, high-confidence-phish quarantine, Safe Attachments,
Safe Links, mailbox intelligence — most of the value the migration
delivers.

## How

``````powershell
# Pilot
.\scripts\Invoke-MdoThreatPolicyAudit.ps1 -Mode Live -PilotUsers alice@<tenant>,bob@<tenant>

# After validation, widen
.\scripts\Invoke-MdoThreatPolicyAudit.ps1 -Mode Live -WidenToAll
``````

## Acceptance criteria

- [ ] Pilot users validated for ~1 week
- [ ] Strict preset widened to all accepted domains
- [ ] ``Invoke-MdoThreatPolicyAudit.ps1`` reports Pass for the Strict preset row
"@
    }
    @{
        Id = '1.04'
        Title = '[Phase 1.04] Verify ZAP enabled across anti-phish, anti-spam, anti-malware'
        Milestone = 'Phase 1 — OOTB deployment'
        Labels = @('phase-1-ootb','area:defender-xdr')
        Body = @"
## What

Confirm ``ZapEnabled``, ``PhishZapEnabled``, ``SpamZapEnabled`` are
``True`` across all policies. Confirm ``HighConfidencePhishAction=Quarantine``.

## How

``````powershell
.\scripts\Invoke-MdoThreatPolicyAudit.ps1   # check the ZAP rows
``````

## Acceptance criteria

- [ ] All three ZAP toggles ``True`` on every applicable policy
- [ ] HighConfidencePhishAction = Quarantine
"@
    }
    @{
        Id = '1.05'
        Title = '[Phase 1.05] Create the reporting mailbox'
        Milestone = 'Phase 1 — OOTB deployment'
        Labels = @('phase-1-ootb','area:exchange')
        Body = @"
## What

Create a shared mailbox ``reportedmessages@<tenant>`` that receives
user-reported phish from the built-in Outlook Report button.

## How

[``15-exchange-online-powershell-commands.md``](../blob/main/15-exchange-online-powershell-commands.md) §2.4.

## Acceptance criteria

- [ ] Mailbox exists
- [ ] SOC team has FullAccess + Send-As
- [ ] Test send-to-mailbox succeeds
"@
    }
    @{
        Id = '1.06'
        Title = '[Phase 1.06] Configure user-reported messages settings'
        Milestone = 'Phase 1 — OOTB deployment'
        Labels = @('phase-1-ootb','area:defender-xdr')
        Body = @"
## What

Create / set ``ReportSubmissionPolicy`` and ``ReportSubmissionRule`` to
route the built-in Outlook Report button to **Microsoft and our
reporting mailbox**, with user-notification email enabled.

## How

[``15-exchange-online-powershell-commands.md``](../blob/main/15-exchange-online-powershell-commands.md) §2.5.

## Acceptance criteria

- [ ] ``Get-ReportSubmissionPolicy`` shows the reporting mailbox
- [ ] ``Get-ReportSubmissionRule`` exists with the right routing
- [ ] End-user test report lands in both Microsoft Submissions and the mailbox
"@
    }
    @{
        Id = '1.07'
        Title = '[Phase 1.07] Add reporting mailbox to SecOps overrides (Advanced Delivery)'
        Milestone = 'Phase 1 — OOTB deployment'
        Labels = @('phase-1-ootb','area:defender-xdr','blocker')
        Body = @"
## What

Configure ``SecOpsOverridePolicy`` + ``ExoSecOpsOverrideRule`` to
include the reporting mailbox. Without this, Strict preset filters
incoming user reports and they never arrive.

> Note the ``Exo`` prefix on the rule cmdlets — the existing OOTB
> guide in this repo previously documented the wrong name; corrected in
> [``15-exchange-online-powershell-commands.md``](../blob/main/15-exchange-online-powershell-commands.md) §7.

## How

[``15-exchange-online-powershell-commands.md``](../blob/main/15-exchange-online-powershell-commands.md) §2.6.

## Acceptance criteria

- [ ] ``Get-SecOpsOverridePolicy`` shows the mailbox in SentTo
- [ ] ``Get-ExoSecOpsOverrideRule`` shows Mode=Enforce
- [ ] Test phish forwarded to the mailbox is not filtered
"@
    }
    @{
        Id = '1.08'
        Title = '[Phase 1.08] Verify AIR fires for user-reported phish (and tune)'
        Milestone = 'Phase 1 — OOTB deployment'
        Labels = @('phase-1-ootb','area:defender-xdr','gate')
        Body = @"
## What

Submit a test phish via the Report button; confirm an AIR investigation
shows up at security.microsoft.com/airinvestigation within ~1 hour.

If silent, disable any ``Auto-Resolve - Email reported by user as
malware or phish`` ProtectionAlert that's suppressing it.

## How

``````powershell
.\scripts\Invoke-MdoAlertPolicyAudit.ps1            # spot the rule
.\scripts\Invoke-MdoAlertPolicyAudit.ps1 -Mode Live # disable it
``````

## Acceptance criteria

- [ ] Test AIR investigation visible
- [ ] AIR Auto Feedback email sent back to the reporter
"@
    }
    @{
        Id = '1.09'
        Title = '[Phase 1.09] Grant SOC roles (Search and Purge, et al)'
        Milestone = 'Phase 1 — OOTB deployment'
        Labels = @('phase-1-ootb','area:soc-process','area:defender-xdr')
        Body = @"
## What

Assign Security Administrator (SOC leads), Security Reader (all SOC),
Data Investigator (SOC L2/L3 — gives the Search and Purge role needed
for the Take Action wizard), Quarantine Administrator (SOC L1).

## How

[``00-MDO-out-of-the-box-deployment-guide.md``](../blob/main/00-MDO-out-of-the-box-deployment-guide.md) §2.6.

## Acceptance criteria

- [ ] Each role group has the expected members
- [ ] At least one L2 analyst can run Take Action from Threat Explorer
"@
    }
    @{
        Id = '1.10'
        Title = '[Phase 1.10] Verify Defender XDR Take Action wizard end-to-end (T3)'
        Milestone = 'Phase 1 — OOTB deployment'
        Labels = @('phase-1-ootb','area:defender-xdr','gate')
        Body = @"
## What

Send a benign test message to 5 internal recipients; locate via Threat
Explorer; Take Action → Soft delete. Confirm Action Center History
shows 5 actions.

## How

[``00-MDO-out-of-the-box-deployment-guide.md``](../blob/main/00-MDO-out-of-the-box-deployment-guide.md) §2.7.

## Acceptance criteria

- [ ] All 5 recipient mailboxes have the message soft-deleted
- [ ] Action Center History records 5 entries
"@
    }
    @{
        Id = '1.11'
        Title = '[Phase 1.11] Deploy P3 (Reporter Thanks Bridge) Logic App'
        Milestone = 'Phase 1 — OOTB deployment'
        Labels = @('phase-1-ootb','area:logic-apps','area:sentinel')
        Body = @"
## What

Deploy the Reporter Thanks Bridge playbook so reporters get an
acknowledgement even when AIR Auto Feedback doesn't fire.

## How

``````powershell
cd .\automation\logic-apps\P3-notify-reporter-bridge
New-AzResourceGroupDeployment -ResourceGroupName <rg> ``
  -TemplateFile .\playbook.json ``
  -TemplateParameterFile .\parameters.example.json
``````

Then wire an automation rule per the folder README.

## Acceptance criteria

- [ ] Playbook deployed
- [ ] MI granted Microsoft Sentinel Responder on the workspace
- [ ] Automation rule wired
- [ ] T7 test pass
"@
    }
    @{
        Id = '1.12'
        Title = '[Phase 1.12] Run T1–T7 functional validation tests'
        Milestone = 'Phase 1 — OOTB deployment'
        Labels = @('phase-1-ootb','gate')
        Body = @"
## What

Run the seven functional tests in
[``00-MDO-out-of-the-box-deployment-guide.md``](../blob/main/00-MDO-out-of-the-box-deployment-guide.md) §4.1:

- T1 ZAP retroactive remediation
- T2 user-reported phish → AIR
- T3 cross-recipient Take Action
- T4 TABL block
- T5 Submissions API
- T6 audit trail to Sentinel
- T7 Reporter Thanks Bridge

All 7 must pass before declaring Phase 1 done.

## Acceptance criteria

- [ ] T1 ✅
- [ ] T2 ✅
- [ ] T3 ✅
- [ ] T4 ✅
- [ ] T5 ✅
- [ ] T6 ✅
- [ ] T7 ✅
- [ ] Evidence captured (screenshots / Sentinel queries / Action Center entries)
"@
    }

    # ---- Phase 2 ----
    @{
        Id = '2.1'
        Title = '[Phase 2.1] Import the operational dashboard workbook into Sentinel'
        Milestone = 'Phase 2 — Parallel run'
        Labels = @('phase-2-parallel-run','area:workbooks','area:sentinel')
        Body = @"
## What

Import ``automation/workbooks/mdo-operational-dashboard.json`` into
Sentinel via Advanced editor / Gallery template.

## Acceptance criteria

- [ ] Workbook visible to SOC analysts
- [ ] All panels return data (verifies #1.02 worked)
"@
    }
    @{
        Id = '2.2'
        Title = '[Phase 2.2] Import the parallel-run workbook and start daily tracking'
        Milestone = 'Phase 2 — Parallel run'
        Labels = @('phase-2-parallel-run','area:workbooks','area:soc-process','gate')
        Body = @"
## What

Import ``automation/workbooks/trap-mdo-parallel-run.json``. Fill the
TRAP-side numbers daily during the parallel period.

## Acceptance criteria

- [ ] Workbook imported
- [ ] Daily tracking spreadsheet/doc set up alongside
- [ ] At least 5 working days of data collected
"@
    }
    @{
        Id = '2.3'
        Title = '[Phase 2.3] Run parallel-run period for 2-4 weeks'
        Milestone = 'Phase 2 — Parallel run'
        Labels = @('phase-2-parallel-run','area:soc-process','gate')
        Body = @"
## What

Both TRAP and MDO live; representative incident sample captured.

## Acceptance criteria

- [ ] Sample contains representative mix: user-reported phish,
      ZAP retroactive, IOC sweeps, DL/VIP incidents
- [ ] MDO MTTR ≤ TRAP MTTR (or delta acceptable to SOC)
- [ ] False-positive rate not worse than TRAP
- [ ] SOC analysts comfortable in Defender XDR Action Center as primary console
"@
    }
    @{
        Id = '2.4'
        Title = '[Phase 2.4] Identify which Phase 3 enhancements are needed'
        Milestone = 'Phase 2 — Parallel run'
        Labels = @('phase-2-parallel-run','decision','gate')
        Body = @"
## What

Based on the parallel-run workbook's gap-candidate panel (panel 5),
decide which of the engineered playbooks to deploy in Phase 3.

## Acceptance criteria

- [ ] Decision recorded for each playbook (deploy / skip / defer):
  - [ ] P2 TI Sweep
  - [ ] P4 Forward Trace
  - [ ] P1 + P1b Workhorse + Paginator
  - [ ] P5 DL Expand
  - [ ] P6 Two-Stage VIP Approval
  - [ ] P7 Custom Abuse Mailbox
"@
    }

    # ---- Phase 3 ----
    @{
        Id = '3.1'
        Title = '[Phase 3.1] Deploy P2 (TI Sweep Remediate)'
        Milestone = 'Phase 3 — Engineering enhancements'
        Labels = @('phase-3-engineering','area:logic-apps')
        Body = @"
ARM template + README:
[``automation/logic-apps/P2-ti-sweep-remediate/``](../blob/main/automation/logic-apps/P2-ti-sweep-remediate/)

Deploy + grant MI ``AdvancedHunting.Read.All`` on WindowsDefenderATP +
``Microsoft Sentinel Responder`` on the workspace.

## Acceptance criteria

- [ ] Playbook deployed
- [ ] MI role assignments done
- [ ] Test sweep produces a Teams approval card
"@
    }
    @{
        Id = '3.2'
        Title = '[Phase 3.2] Deploy P4 (Forward Trace Remediate)'
        Milestone = 'Phase 3 — Engineering enhancements'
        Labels = @('phase-3-engineering','area:logic-apps')
        Body = @"
ARM template + README:
[``automation/logic-apps/P4-forward-trace-remediate/``](../blob/main/automation/logic-apps/P4-forward-trace-remediate/)

## Acceptance criteria

- [ ] Playbook deployed
- [ ] MI role assignments done
- [ ] Entity-page playbook run from a real MailMessage works end-to-end
"@
    }
    @{
        Id = '3.3'
        Title = '[Phase 3.3] Deploy P1 + P1b (Phish-Remediate + paginator)'
        Milestone = 'Phase 3 — Engineering enhancements'
        Labels = @('phase-3-engineering','area:logic-apps')
        Body = @"
ARM templates + READMEs:
[``automation/logic-apps/P1-phish-remediate/``](../blob/main/automation/logic-apps/P1-phish-remediate/)
[``automation/logic-apps/P1b-phish-remediate-bulk/``](../blob/main/automation/logic-apps/P1b-phish-remediate-bulk/)

## Acceptance criteria

- [ ] Both playbooks deployed
- [ ] Sentinel ``VIP_Mailboxes`` watchlist populated
- [ ] End-to-end run from a test incident succeeds
"@
    }
    @{
        Id = '3.4'
        Title = '[Phase 3.4] (Conditional) Deploy P5 (DL Expand Remediate)'
        Milestone = 'Phase 3 — Engineering enhancements'
        Labels = @('phase-3-engineering','area:logic-apps','conditional')
        Body = @"
Only deploy if Phase 2 data shows DL fan-out incidents.

[``automation/logic-apps/P5-dl-expand-remediate/``](../blob/main/automation/logic-apps/P5-dl-expand-remediate/)

## Acceptance criteria

- [ ] Phase 2 decision recorded
- [ ] Playbook deployed (if Yes)
- [ ] MI ``Group.Read.All`` on Microsoft Graph
"@
    }
    @{
        Id = '3.5'
        Title = '[Phase 3.5] (Conditional) Deploy P6 (Two-Stage VIP Approval)'
        Milestone = 'Phase 3 — Engineering enhancements'
        Labels = @('phase-3-engineering','area:logic-apps','conditional')
        Body = @"
Only deploy if SOC operates a tiered approval model.

[``automation/logic-apps/P6-two-stage-approval-vip/``](../blob/main/automation/logic-apps/P6-two-stage-approval-vip/)
"@
    }
    @{
        Id = '3.6'
        Title = '[Phase 3.6] (Conditional) Deploy P7 (Custom Abuse Mailbox Ingest)'
        Milestone = 'Phase 3 — Engineering enhancements'
        Labels = @('phase-3-engineering','area:logic-apps','conditional')
        Body = @"
Only deploy if the built-in custom reporting mailbox path doesn't reach
all the report sources (legacy clients, external partner forwards).

[``automation/logic-apps/P7-custom-abuse-mailbox-ingest/``](../blob/main/automation/logic-apps/P7-custom-abuse-mailbox-ingest/)
"@
    }
    @{
        Id = '3.7'
        Title = '[Phase 3.7] Populate Sentinel watchlists'
        Milestone = 'Phase 3 — Engineering enhancements'
        Labels = @('phase-3-engineering','area:sentinel')
        Body = @"
## What

Create + populate the watchlists the engineered playbooks depend on:

- ``VIP_Mailboxes`` (used by P1, P6)
- ``VAP`` (Very Attacked People — used for severity boosting)
- ``KnownBad_Senders`` (used by P2 auto-approve path)
- ``Frequent_Reporters`` (used by P3 throttling)
- ``EnabledPlaybooks`` (the feature-flag watchlist for Phase 3 toggles)

## Acceptance criteria

- [ ] Watchlists created with the alias names above
- [ ] Initial populations done (CSV upload or Sentinel API)
- [ ] Refresh cadence documented (manual / automation / auto-promote)
"@
    }
    @{
        Id = '3.8'
        Title = '[Phase 3.8] Wire automation rules to playbooks'
        Milestone = 'Phase 3 — Engineering enhancements'
        Labels = @('phase-3-engineering','area:sentinel')
        Body = @"
## What

Create Sentinel automation rules that fire each playbook on the right
incident shape. Example: P3 on incidents titled
"Email reported by user as malware or phish", P4 on incidents
containing a MailMessage entity, etc.

## Acceptance criteria

- [ ] Each deployed playbook has at least one automation rule routing
      to it
- [ ] Rules use conditions (not just title match) where useful — e.g.
      severity threshold, presence of MailMessage entity
"@
    }

    # ---- Phase 4 ----
    @{
        Id = '4.1'
        Title = '[Phase 4.1] Communicate user-visible change (Outlook Report button)'
        Milestone = 'Phase 4 — Cutover'
        Labels = @('phase-4-cutover','area:soc-process')
        Body = @"
## What

Tenant-wide comms: announce that the legacy PhishAlarm button is being
replaced by the built-in Outlook Report button.

## Acceptance criteria

- [ ] Email + intranet notice sent
- [ ] Lunch-and-learn for power users scheduled
- [ ] Support desk briefed
"@
    }
    @{
        Id = '4.2'
        Title = '[Phase 4.2] Disable the PhishAlarm add-in deployment'
        Milestone = 'Phase 4 — Cutover'
        Labels = @('phase-4-cutover','area:exchange')
        Body = @"
## What

Remove the PhishAlarm add-in from Microsoft 365 admin centre →
Integrated apps, so users no longer see it in Outlook.

## Acceptance criteria

- [ ] Add-in deployment disabled
- [ ] Verified in a test mailbox
"@
    }
    @{
        Id = '4.3'
        Title = '[Phase 4.3] Disable the TRAP abuse-mailbox poller'
        Milestone = 'Phase 4 — Cutover'
        Labels = @('phase-4-cutover','area:soc-process')
        Body = @"
## What

Disable the TRAP-side process that polls the abuse mailbox. Do **not**
delete the mailbox or the poller — they remain for rollback.

## Acceptance criteria

- [ ] Poller disabled
- [ ] Configuration captured so we could re-enable in <1h if needed
"@
    }
    @{
        Id = '4.4'
        Title = '[Phase 4.4] Update SOC runbook to use Defender XDR + Sentinel'
        Milestone = 'Phase 4 — Cutover'
        Labels = @('phase-4-cutover','area:soc-process')
        Body = @"
## What

The canonical incident workflow is now the Defender XDR portal +
Sentinel, not the TRAP UI.

## Acceptance criteria

- [ ] Runbook updated with the new tools
- [ ] All on-call analysts briefed
"@
    }
    @{
        Id = '4.5'
        Title = '[Phase 4.5] Migrate TRAP TI lists to TABL / Sentinel watchlists'
        Milestone = 'Phase 4 — Cutover'
        Labels = @('phase-4-cutover','area:defender-xdr','area:sentinel')
        Body = @"
## What

Export every TRAP TI list (senders, URLs, hashes, IPs) and import into
TABL ([``New-TenantAllowBlockListItems``](../blob/main/15-exchange-online-powershell-commands.md#3-tenant-allowblock-list-tabl))
or Sentinel watchlists as appropriate.

## Acceptance criteria

- [ ] Inventory of TRAP TI list contents
- [ ] TABL populated (within the P2 limits: 5k allow / 10k block / 1k spoof pairs)
- [ ] Sentinel watchlists populated for anything that doesn't fit TABL
"@
    }
    @{
        Id = '4.6'
        Title = '[Phase 4.6] Re-point external SOAR integrations to Sentinel / Defender XDR APIs'
        Milestone = 'Phase 4 — Cutover'
        Labels = @('phase-4-cutover','area:soc-process')
        Body = @"
## What

If you have XSOAR / Splunk SOAR / QRadar previously calling the TRAP
REST API, re-point them at the Sentinel + Defender XDR APIs.

## Acceptance criteria

- [ ] Inventory of integrations done (from #0.3)
- [ ] Each integration re-pointed and tested
- [ ] Old TRAP API keys revoked
"@
    }

    # ---- Phase 5 ----
    @{
        Id = '5.1'
        Title = '[Phase 5.1] Cancel the Proofpoint TRAP licence'
        Milestone = 'Phase 5 — Decommission'
        Labels = @('phase-5-decommission','area:procurement','blocker')
        Body = @"
**Hard requirement:** Phase 4 must be stable across a representative
incident sample before this happens — it's the last point of safe
rollback.

## Acceptance criteria

- [ ] Procurement notified, cancellation effective date set
- [ ] Vendor confirmation received
"@
    }
    @{
        Id = '5.2'
        Title = '[Phase 5.2] Remove TRAP service account'
        Milestone = 'Phase 5 — Decommission'
        Labels = @('phase-5-decommission','area:exchange')
        Body = @"
Remove the TRAP service account from Exchange / Entra. If the account
had RBAC for Applications role assignments, remove them. If it was
dual-purpose, sanitise carefully.

## Acceptance criteria

- [ ] Service account inventory confirmed from #0.3
- [ ] Account removed
"@
    }
    @{
        Id = '5.3'
        Title = '[Phase 5.3] Remove TRAP app registration in Entra'
        Milestone = 'Phase 5 — Decommission'
        Labels = @('phase-5-decommission','area:exchange')
        Body = @"
## Acceptance criteria

- [ ] App registration found and removed
- [ ] Any service principal references in transport rules / connectors cleaned up
"@
    }
    @{
        Id = '5.4'
        Title = '[Phase 5.4] Remove TRAP-only SecOps mailbox / quarantine mailboxes'
        Milestone = 'Phase 5 — Decommission'
        Labels = @('phase-5-decommission','area:exchange')
        Body = @"
Only remove mailboxes that are not also used by the OOTB MDO deployment.

## Acceptance criteria

- [ ] Mailboxes inventoried against current OOTB usage
- [ ] Pure-TRAP mailboxes removed
"@
    }
    @{
        Id = '5.5'
        Title = '[Phase 5.5] Remove TRAP-specific ApplicationAccessPolicy'
        Milestone = 'Phase 5 — Decommission'
        Labels = @('phase-5-decommission','area:exchange')
        Body = @"
Any ``New-ApplicationAccessPolicy`` that scoped TRAP's Mail.* access.

## How

``````powershell
Get-ApplicationAccessPolicy
``````

## Acceptance criteria

- [ ] No remaining ApplicationAccessPolicy entries reference the TRAP appId
"@
    }
    @{
        Id = '5.6'
        Title = '[Phase 5.6] Archive TRAP installation logs + audit trail to long-term storage'
        Milestone = 'Phase 5 — Decommission'
        Labels = @('phase-5-decommission','area:legal','area:procurement')
        Body = @"
## Acceptance criteria

- [ ] Logs exported to blob storage (immutable container if required by compliance)
- [ ] Retention period set
- [ ] Access controls documented
"@
    }
    @{
        Id = '5.7'
        Title = '[Phase 5.7] Update vendor risk register and SOC tool inventory'
        Milestone = 'Phase 5 — Decommission'
        Labels = @('phase-5-decommission','area:soc-process')
        Body = @"
## Acceptance criteria

- [ ] Vendor risk register updated (Proofpoint TRAP removed)
- [ ] SOC tool inventory updated (Defender XDR + Sentinel as primary)
- [ ] CMDB updated
"@
    }
)

$created = 0
$skipped = 0

foreach ($i in $issues) {
    if ($Only -and -not $i.Id.StartsWith($Only)) { $skipped++; continue }
    New-IssueIdempotent -Title $i.Title -Body $i.Body -Labels $i.Labels -Milestone $i.Milestone
    $created++
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

Write-Host ''
Write-Host '=== Summary ===' -ForegroundColor White
Write-Host ('Labels processed:     {0}' -f $labels.Count)
Write-Host ('Milestones processed: {0}' -f $milestones.Count)
Write-Host ('Issues processed:     {0} (skipped by -Only filter: {1})' -f $created, $skipped)

if (-not $Apply) {
    Write-Host ''
    Write-Host 'DRY RUN — no changes made. Rerun with -Apply to create.' -ForegroundColor Yellow
}
