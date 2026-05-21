# Automation. Logic Apps + Workbooks

End-to-end automation artefacts to replace Proofpoint TRAP using
Microsoft Defender for Office 365, Sentinel, and the engineered
playbooks documented in
[`../10-logic-apps-playbook-library.md`](../10-logic-apps-playbook-library.md).

```
automation/
├── logic-apps/                    # ARM templates per playbook (all 8 shipped)
│   ├── P3-notify-reporter-bridge/      [Phase 1: OOTB]
│   ├── P2-ti-sweep-remediate/          [Phase 3: TI gap]
│   ├── P4-forward-trace-remediate/     [Phase 3: forward-follow gap]
│   ├── P1-phish-remediate/             [Phase 3: workhorse, optional P6 escalation]
│   ├── P1b-phish-remediate-bulk/       [Phase 3: Paginator for P1]
│   ├── P5-dl-expand-remediate/         [Phase 3: Graph transitiveMembers, no Function App]
│   ├── P6-two-stage-approval-vip/      [Phase 3: Only if SOC operates a tiered model]
│   ├── P7-custom-abuse-mailbox-ingest/ [Phase 3: Only if built-in path insufficient]
│   └── README.md                       # Per-playbook status + build order
├── workbooks/
│   ├── mdo-operational-dashboard.json    [shipped]
│   ├── trap-mdo-parallel-run.json        [shipped]
│   └── README.md
└── tests/
    ├── Test-LogicAppTemplate.ps1        # ARM static validator
    ├── Test-WorkbookSchema.ps1          # Sentinel workbook static validator
    └── Invoke-AutomationValidation.ps1  # one-shot runner for both
```

## What this directory ships

* **Eight production-ready Logic App ARM templates** covering the full
  TRAP replacement: P1 (workhorse), P1b (bulk paginator), P2 (TI
  sweep), P3 (reporter bridge), P4 (forward trace), P5 (DL expand),
  P6 (two-stage VIP approval), P7 (custom abuse mailbox).
* **Two production-ready Sentinel workbooks**: a daily MDO operational
  dashboard and the Phase 2 parallel-run comparison framework.
* **Two static validators** that check structure and references
  without needing an Azure connection. Combined run: 127 checks pass.

All templates use system-assigned managed identity (no client
secrets), default to soft-delete (never hard-delete from a playbook),
and require explicit human approval before any tenant-state change.

## Validate everything

```powershell
# From repo root
cd automation
.\tests\Invoke-AutomationValidation.ps1
```

Or per category:

```powershell
.\tests\Test-LogicAppTemplate.ps1 -Path .\logic-apps
.\tests\Test-WorkbookSchema.ps1   -Path .\workbooks
```

Both validators exit non-zero on any Fail finding so they plug into
CI cleanly. Findings include the ARM `$connections` reference check,
`[parameters(X)]` resolution, `runAfter` graph integrity (Logic Apps),
and workbook item-type required-field checks (workbooks).

## Build / deploy order

| Phase | Action | Artefact |
|---|---|---|
| Phase 1 (OOTB) | Deploy the Reporter Thanks Bridge | `logic-apps/P3-notify-reporter-bridge/` |
| Phase 1 (OOTB) | Import the operational dashboard into Sentinel | `workbooks/mdo-operational-dashboard.json` |
| Phase 2 | Import the parallel-run workbook, fill the comparison table daily | `workbooks/trap-mdo-parallel-run.json` |
| Phase 3 (engineering) | Deploy the TI Sweep playbook | `logic-apps/P2-ti-sweep-remediate/` |
| Phase 3 (engineering) | Deploy the Forward Trace playbook | `logic-apps/P4-forward-trace-remediate/` |
| Phase 3 (engineering) | Deploy the workhorse + paginator | `logic-apps/P1-phish-remediate/` + `P1b-phish-remediate-bulk/` |
| Phase 3 (conditional) | Deploy DL expansion if Phase 2 data shows DL fan-out | `logic-apps/P5-dl-expand-remediate/` |
| Phase 3 (conditional) | Deploy two-stage VIP approval if SOC operates a tiered model | `logic-apps/P6-two-stage-approval-vip/` |
| Phase 3 (conditional) | Deploy custom abuse-mailbox ingest only if built-in path is insufficient | `logic-apps/P7-custom-abuse-mailbox-ingest/` |
| Phase 4 (cutover) | Re-point any external SOAR integrations to Sentinel API | n/a |

## Standard-practice defaults

Every shipped playbook ships with conservative defaults that work for
most tenants. The most-likely-to-tune parameters and where they live:

| Playbook | Default | Tune via |
|---|---|---|
| **P1** | Single-stage Teams approval, SoftDelete only | `-VipEscalationPlaybook` (route VIPs through P6); change `ActionType` in `Call_TakeAction_softdelete` action |
| **P1b** | Chunk size 50, inter-chunk delay 12s | `-ChunkSize`, `-DelaySeconds` |
| **P2** | Hourly recurrence, 14-day lookback excluding last 48h | `-LookbackDays`; change `Recurrence_hourly` trigger interval |
| **P3** | Acknowledge every Account entity on the incident | Throttle via upstream automation-rule condition (e.g. exclude `Frequent_Reporters` watchlist) |
| **P4** | 14-day same-subject same-sender lookback | Edit the `Run_internal_forward_query` query body |
| **P5** | Graph `transitiveMembers`, 500-member cap | `-MaxMembers`; needs Graph `Group.Read.All` on MI |
| **P6** | Two Teams approvals: SOC L1 → SOC Manager | `-SocL1*` and `-SocManager*` Teams IDs |
| **P7** | Polls abuse mailbox every 5 minutes | Change the trigger's `recurrence.interval` |

The deeper customisations the blueprint discusses (cross-vendor
enrichment, hard-delete-with-legal-sign-off, per-business-unit
approver routing, the auto-approve confidence threshold) are
deliberately **not** baked in. they're decisions that change the
playbook's risk profile and need explicit SOC ownership before they
land in our repo's main branch.

## What "validated" means here

The two test scripts perform static (offline) validation:

**`Test-LogicAppTemplate.ps1`** checks:
1. JSON parses.
2. ARM top-level shape (`$schema`, `contentVersion`, `resources`).
3. `Microsoft.Logic/workflows` resource has `type`, `apiVersion`,
   `name`, `location`, `properties`.
4. Embedded workflow definition has `$schema`, `triggers`, `actions`.
5. Every action's `runAfter` reference resolves to a declared action
   or trigger (catches orphan branches that only blow up at runtime).
6. Every `@parameters('$connections')['X']` reference has a matching
   entry in `parameters.$connections.value`.
7. Every `[parameters(X)]` reference resolves to a declared top-level
   parameter.

**`Test-WorkbookSchema.ps1`** checks:
1. JSON parses.
2. Workbook top-level shape (`version`, `items[]`).
3. Every item has `type` (int) and `name` (unique).
4. Required content fields per item type (markdown → `json`; query →
   `query` + `queryType`; parameters → `version` + `parameters[]`;
   etc.).
5. Every `{ParamName}` placeholder in a query is declared in at least
   one type-9 parameters block (`TimeRange`/`Workspace` are
   well-known and excluded from this check).
6. KQL parens are balanced (catches obvious truncation).

What the validators **don't** do:

* No actual Azure deploy / dry-run (`Test-AzResourceGroupDeployment`
  needs an Azure connection. run separately when ready).
* No KQL semantic check beyond paren balance. bad column names slip
  through. Run the query against Sentinel directly to catch those.
* No `$expressions` evaluation. If we reference a workflow variable
  that doesn't exist, the validator can't catch it; the deploy will.

For full pre-flight before deploy, also run:

```powershell
Test-AzResourceGroupDeployment `
  -ResourceGroupName <rg> `
  -TemplateFile .\logic-apps\<Pn>\playbook.json `
  -TemplateParameterFile .\logic-apps\<Pn>\parameters.example.json
```

That talks to Azure Resource Manager and catches deploy-time errors
(unknown connection refs, malformed expressions, missing resource
references) the static validator can't see.
