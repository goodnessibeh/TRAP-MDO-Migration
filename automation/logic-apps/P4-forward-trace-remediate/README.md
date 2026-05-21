# P4. Forward Trace Remediate

Walks every internal forward of a malicious message and remediates the
internal copies via Defender XDR Take Action. Flags external forwards
to the SOC (cannot remediate; out of tenant scope).

Closes the forward-following gap that TRAP filled natively.
Documented in:

* [`09-kql-detection-library.md`](../../../09-kql-detection-library.md) Q4
* [`10-logic-apps-playbook-library.md`](../../../10-logic-apps-playbook-library.md) P4

## Flow

1. **Sentinel entity trigger** on `MailMessage`. Fire it from the
   incident or by running the playbook directly against the malicious
   message.
2. Run a hunting query (Q4 internal-forward tracking) using
   `Subject` + `SenderFromAddress` of the original message; gather
   every same-subject same-sender copy in the last 14 days.
3. Split results into `Intraorg` (internal forwards) vs `Inbound`
   (external. out of reach).
4. For internal copies: call Defender XDR
   `api/messages/takeAction` with `SoftDelete` per `NetworkMessageId`.
5. For external copies: post a Teams adaptive notification to the SOC
   channel with the recipient list and the recommendation to block at
   the receiving organisation. No remediation attempted; this is a
   telemetry boundary, not a workflow one.
6. Comment back to the incident with the counts.

## Why entity trigger (not incident trigger)?

A Sentinel incident may bundle multiple `MailMessage` entities. The
entity trigger lets we fan out P4 once per malicious message. If we
need incident-level, wire P4 from P1 (the workhorse) instead of from
an automation rule.

## Prerequisites

| Item | Notes |
|---|---|
| Sentinel workspace + `EmailEvents` stream | Phase 1 |
| Defender XDR API permission for the Logic App MI | `AdvancedHunting.Read.All` + `Mail.ReadWrite` |
| Sentinel + Teams API connections | Standard |
| Q4 KQL implemented as a hunting query in the Sentinel workspace | Not strictly required. The playbook embeds the same query inline |

## Permissions to grant the MI

```powershell
$miPid = '<principalId from deployment output>'

# Sentinel. Read workspace, write incident comments
New-AzRoleAssignment -ObjectId $miPid `
  -RoleDefinitionName 'Microsoft Sentinel Responder' -Scope <workspace-resource-id>

# Defender XDR. Take Action API
# See P2 README for the WindowsDefenderATP role assignment recipe.
```

## Deploy

```powershell
New-AzResourceGroupDeployment `
  -ResourceGroupName 'rg-sentinel-prod' `
  -TemplateFile .\playbook.json `
  -TemplateParameterFile .\parameters.example.json
```

## Wire to an automation rule (optional)

Automation rule that fires on incidents containing `MailMessage` entities:

* Trigger: When incident is created
* Conditions: incident contains entity `MailMessage`; Severity ≥ Medium
* Actions: Run playbook → P4

Or invoke manually from the entity page in the Defender XDR portal
("Run playbook on this entity").

## Validate

```powershell
.\automation\tests\Test-LogicAppTemplate.ps1 -Path .\automation\logic-apps\P4-forward-trace-remediate
```

## Known limits

* P4 cannot find forwards that bypassed Microsoft mail flow (e.g. the
  user manually copied the message to a personal mailbox). That's a
  data-egress problem, not a remediation problem. The sister control
  is Q7 (auto-forward configuration alerting): catch the leak channel
  before it carries any messages.
* If the malicious message had its subject or sender modified between
  inbound and forward (rare, but BEC operators do it), the
  same-subject same-sender query misses. The trade-off is precision
  over recall; broaden to `MessageId` matching if we can tolerate
  more false-positives.
