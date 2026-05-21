# Logic App Playbooks

ARM templates for the seven Logic App playbooks that, together with
the OOTB MDO baseline, replace Proofpoint TRAP end-to-end. Every
playbook here maps to one entry in
[`../../10-logic-apps-playbook-library.md`](../../10-logic-apps-playbook-library.md).

## Status by playbook

| ID | Name | Status | Folder |
|----|------|--------|--------|
| P3 | Notify Reporter Bridge | **shipped** | `P3-notify-reporter-bridge/` |
| P2 | TI Sweep Remediate | **shipped** | `P2-ti-sweep-remediate/` |
| P4 | Forward Trace Remediate | **shipped** | `P4-forward-trace-remediate/` |
| P1 | Phish-Remediate (workhorse) | **shipped**: single-stage approval, soft-delete defaults; optional P6 escalation when VIP touched | `P1-phish-remediate/` |
| P1b | Phish-Remediate-Bulk | **shipped**: HTTP-callable paginator, chunks of 50, 12-second inter-chunk delay | `P1b-phish-remediate-bulk/` |
| P5 | DL-Expand-Remediate | **shipped**: Graph `transitiveMembers` (no Function App), 500-member safety cap | `P5-dl-expand-remediate/` |
| P6 | Two-Stage-Approval-VIP | **shipped**: Teams approval to SOC L1, then SOC Manager / Legal; HTTP-callable from P1 | `P6-two-stage-approval-vip/` |
| P7 | Custom-Abuse-Mailbox-Ingest | **shipped**: Polls shared abuse mailbox, submits via Graph, replies thanks | `P7-custom-abuse-mailbox-ingest/` |

All 8 templates have been validated against
`../tests/Test-LogicAppTemplate.ps1`. 119 checks pass, 0 fail.

> **Conservative defaults baked in.** Every template that mutates
> tenant state uses **soft-delete only** (never hard-delete from a
> playbook. Manual SOC action via Defender Action Center is required
> for hard-delete). All approval flows default to a single Teams
> channel; widen to two-stage via P6 if our SOC operates a tiered
> approval model. P5 caps DL expansion at 500 members by default to
> guard against unbounded fan-out.

## Deploy any shipped template

```powershell
Connect-AzAccount -UseDeviceAuthentication
$rg   = '<resource-group>'
$path = '.\<Pn-name>\playbook.json'
$pP   = '.\<Pn-name>\parameters.example.json'

Test-AzResourceGroupDeployment      -ResourceGroupName $rg -TemplateFile $path -TemplateParameterFile $pP
New-AzResourceGroupDeployment       -ResourceGroupName $rg -TemplateFile $path -TemplateParameterFile $pP -Verbose
```

## Validate all templates locally before deploying

From `automation/`:

```powershell
.\tests\Test-LogicAppTemplate.ps1 -Path .\logic-apps
```

Or run all automation validators at once:

```powershell
.\tests\Invoke-AutomationValidation.ps1
```

## Why some playbooks are design-only

This repo ships **structural shape** for the highest-impact gap-closers
(P2 TI Sweep, P3 Reporter Bridge, P4 Forward Trace). they're
near-identical across organisations. The remaining four (P1, P1b, P5,
P6, P7) need organisation-specific decisions baked in:

* P1: VIP routing, approver routing, soft-vs-hard delete policy, optional
  cross-vendor enrichment
* P5: An Azure Function App with EXO PowerShell + managed identity for
  recursive DL expansion
* P6: A named L2/L3 approval chain; not all SOCs run a two-tier model
* P7: Only relevant if we have a legacy abuse-mailbox flow Microsoft's
  built-in path doesn't cover

Each folder's README points to the blueprint pseudocode and to the
shipped template we should copy the action shape from.

## Recommended build order

1. Phase 1 (OOTB): **P3** ships during the Phase 1 deployment per
   [`00-MDO-out-of-the-box-deployment-guide.md`](../../00-MDO-out-of-the-box-deployment-guide.md) §3.3.
2. Phase 3 (engineering): **P2 first**, then **P4**. These close the
   biggest Phase 2 gaps (TI sweep beyond ZAP's 48h, forward-following).
3. After 30 days of P2/P4 stable: **P1**. By now we know which P1
   design questions matter.
4. As-needed: **P1b** (only if P1 is hitting recipient counts that
   need pagination), **P5** (only if our incident corpus has DL
   fan-out), **P6** (only if we actually run a tiered approval
   chain), **P7** (only if the built-in path is insufficient).

## Cross-cutting patterns

Every shipped template uses:

* **System-assigned managed identity** on the workflow resource (the
  outputs include `managedIdentityPrincipalId` for downstream role
  assignment).
* **Sentinel + Office 365 / Teams API connections** referenced via
  `parameters('$connections')`. The static validator checks every such
  reference resolves to a declared connection.
* **HTTP step with managed identity authentication** for calling
  Defender XDR Take Action. No client secrets stored anywhere.
* **`runAfter` discipline**. Every action has an explicit predecessor;
  the validator catches orphans and broken graphs.
