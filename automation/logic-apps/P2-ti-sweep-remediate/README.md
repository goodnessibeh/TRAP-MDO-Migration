# P2. TI Sweep Remediate

Closes the biggest TRAP-vs-MDO gap that Phase 2 typically surfaces:
remediation of messages older than ZAP's 48-hour window when fresh
threat intelligence reveals they were malicious all along.

Documented in:

* [`09-kql-detection-library.md`](../../../09-kql-detection-library.md) Q5
* [`10-logic-apps-playbook-library.md`](../../../10-logic-apps-playbook-library.md) P2

## Flow

1. **Hourly recurrence** trigger.
2. **Run hunting query** via Sentinel API. Joins `EmailEvents` ∪
   `EmailAttachmentInfo` ∪ `EmailUrlInfo` against the
   `ThreatIntelIndicators` table (the new STIX-aligned TI schema,
   populated by MDTI / TAXII / MISP). The legacy
   `ThreatIntelligenceIndicator` table stopped ingesting on
   2025-07-31, so the query targets the new table and matches on
   `ObservableKey` / `ObservableValue`. Lookback default 14 days;
   excludes the last 48h (ZAP covers that natively).
3. If matches found:
   * Post an **adaptive-card approval** to the SOC's Teams channel
     summarising the count and sample.
   * On **Approve**. Iterate matches and call the Microsoft Graph
     `analyzedEmails/remediate` API with `action: softDelete` per
     `{networkMessageId, recipientEmailAddress}` pair. Concurrency capped to 5 to respect API
     throttling.
   * On **Reject**. Record decision and exit.
4. If no matches found, exit silently (no Teams noise).

## Why the human-in-the-loop?

TI feeds vary in quality. False positives during the early weeks of
operating P2 are common until we've populated the `KnownBad_Senders`
watchlist (which gets auto-promoted entries from previous TI hits we
approved). Operationally, after ~30 days >70 % of P2 fires auto-approve
through an upstream Sentinel automation rule with a watchlist
short-circuit. The Teams card only appears for novel detections.

## Prerequisites

| Item | Notes |
|---|---|
| Sentinel workspace + workspace ResourceId | Passed as parameter |
| `EmailEvents` + `EmailAttachmentInfo` + `EmailUrlInfo` streams enabled on M365 Defender connector | See Phase 1 task #7 |
| MDTI or TAXII connector populating `ThreatIntelIndicators` (new STIX TI schema) | Or import via TI Graph API |
| Teams API connection | For approval card |
| Sentinel API connection | For hunting query + incident comments |
| Graph API permission for the Logic App's managed identity | Grant `SecurityAnalyzedMessage.ReadWrite.All` (Microsoft Graph application permission) so the HTTP step can call `POST https://graph.microsoft.com/beta/security/collaboration/analyzedEmails/remediate`. The hunting query itself runs through the Microsoft Sentinel API connection, not a Defender app role. **Note:** the remediate endpoint is currently Graph **beta**. |

## Permissions to grant the Logic App's managed identity

After deploy, the workflow's system-assigned identity needs:

```powershell
$miPid = '<principalId from deployment output>'

# Sentinel. Read the workspace, write incident comments
New-AzRoleAssignment -ObjectId $miPid `
  -RoleDefinitionName 'Microsoft Sentinel Responder' `
  -Scope <workspace-resource-id>

# Email remediation via Microsoft Graph (analyzedEmails/remediate, beta).
# Grant the Graph application role to the playbook's managed identity:
$msi   = Get-MgServicePrincipal -Filter "appId eq '<our-MI-clientId>'"
$graph = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"  # Microsoft Graph
$role  = $graph.AppRoles | Where-Object Value -eq 'SecurityAnalyzedMessage.ReadWrite.All'

New-MgServicePrincipalAppRoleAssignment `
  -ServicePrincipalId $msi.Id `
  -PrincipalId $msi.Id `
  -ResourceId $graph.Id `
  -AppRoleId $role.Id
```

## Deploy

```powershell
Connect-AzAccount -UseDeviceAuthentication
New-AzResourceGroupDeployment `
  -ResourceGroupName 'rg-sentinel-prod' `
  -TemplateFile .\playbook.json `
  -TemplateParameterFile .\parameters.example.json
```

## Tuning

* `LookbackDays`. Default 14, raise to 30 if our TI feeds are slow.
  Don't go past 30. `EmailEvents` retention is 30 days in Sentinel by
  default.
* Recurrence. Default 1 hour. Make it 30 minutes during a critical
  campaign, daily for low-volume environments.
* Auto-approve threshold. Add an automation rule upstream that
  short-circuits the Teams card when sender domain is in the
  `KnownBad_Senders` watchlist.

## Validate before deploying

```powershell
.\automation\tests\Test-LogicAppTemplate.ps1 -Path .\automation\logic-apps\P2-ti-sweep-remediate
```

## Known limits

* Microsoft Graph throttling applies to `analyzedEmails/remediate`.
  The repetitions cap of 5 keeps us at a conservative pace even on big
  sweeps. The endpoint is asynchronous: it returns `202 Accepted` with
  a `Location` header pointing at the Action center, so the call
  succeeding means the remediation was queued, not yet completed.
* The hunting query has a 30-second timeout in the Sentinel API. If
  our environment has very high email volume, narrow the query
  further (e.g. Add `| where ThreatTypes != ''` to limit candidates).
