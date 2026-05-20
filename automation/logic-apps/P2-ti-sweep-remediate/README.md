# P2 — TI Sweep Remediate

Closes the biggest TRAP-vs-MDO gap that Phase 2 typically surfaces:
remediation of messages older than ZAP's 48-hour window when fresh
threat intelligence reveals they were malicious all along.

Documented in:

* [`09-kql-detection-library.md`](../../../09-kql-detection-library.md) Q5
* [`10-logic-apps-playbook-library.md`](../../../10-logic-apps-playbook-library.md) P2

## Flow

1. **Hourly recurrence** trigger.
2. **Run hunting query** via Sentinel API — joins `EmailEvents` ∪
   `EmailAttachmentInfo` ∪ `EmailUrlInfo` against the
   `ThreatIntelligenceIndicator` table (populated by MDTI / TAXII /
   MISP). Lookback default 14 days; excludes the last 48h (ZAP covers
   that natively).
3. If matches found:
   * Post an **adaptive-card approval** to the SOC's Teams channel
     summarising the count and sample.
   * On **Approve** — iterate matches and call the Defender XDR
     `messages/takeAction` API with `ActionType: SoftDelete` per
     `NetworkMessageId`. Concurrency capped to 5 to respect API
     throttling.
   * On **Reject** — record decision and exit.
4. If no matches found, exit silently (no Teams noise).

## Why the human-in-the-loop?

TI feeds vary in quality. False positives during the early weeks of
operating P2 are common until you've populated the `KnownBad_Senders`
watchlist (which gets auto-promoted entries from previous TI hits we
approved). Operationally, after ~30 days >70 % of P2 fires auto-approve
through an upstream Sentinel automation rule with a watchlist
short-circuit — the Teams card only appears for novel detections.

## Prerequisites

| Item | Notes |
|---|---|
| Sentinel workspace + workspace ResourceId | Passed as parameter |
| `EmailEvents` + `EmailAttachmentInfo` + `EmailUrlInfo` streams enabled on M365 Defender connector | See Phase 1 task #7 |
| MDTI or TAXII connector populating `ThreatIntelligenceIndicator` | Or import via TI graph API |
| Teams API connection | For approval card |
| Sentinel API connection | For hunting query + incident comments |
| Defender XDR API permission for the Logic App's managed identity | Grant `ThreatHunting.Read.All` + `Mail.ReadWrite` (Defender XDR application permissions) so the HTTP step can call `api.security.microsoft.com/api/messages/takeAction` |

## Permissions to grant the Logic App's managed identity

After deploy, the workflow's system-assigned identity needs:

```powershell
$miPid = '<principalId from deployment output>'

# Sentinel — read the workspace, write incident comments
New-AzRoleAssignment -ObjectId $miPid `
  -RoleDefinitionName 'Microsoft Sentinel Responder' `
  -Scope <workspace-resource-id>

# Defender XDR (via Microsoft Graph) — Take Action API access
# Done via Microsoft.Graph PowerShell against the WindowsDefenderATP
# enterprise app:
$msi  = Get-MgServicePrincipal -Filter "appId eq '<your-MI-clientId>'"
$wdat = Get-MgServicePrincipal -Filter "appId eq 'fc780465-2017-40d4-a0c5-307022471b92'"  # WindowsDefenderATP
$role = $wdat.AppRoles | Where-Object Value -eq 'AdvancedHunting.Read.All'

New-MgServicePrincipalAppRoleAssignment `
  -ServicePrincipalId $msi.Id `
  -PrincipalId $msi.Id `
  -ResourceId $wdat.Id `
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

* `LookbackDays` — default 14, raise to 30 if your TI feeds are slow.
  Don't go past 30 — `EmailEvents` retention is 30 days in Sentinel by
  default.
* Recurrence — default 1 hour. Make it 30 minutes during a critical
  campaign, daily for low-volume environments.
* Auto-approve threshold — add an automation rule upstream that
  short-circuits the Teams card when sender domain is in the
  `KnownBad_Senders` watchlist.

## Validate before deploying

```powershell
.\automation\tests\Test-LogicAppTemplate.ps1 -Path .\automation\logic-apps\P2-ti-sweep-remediate
```

## Known limits

* `messages/takeAction` is rate-limited to ~300 actions/minute by
  Microsoft. The repetitions cap of 5 keeps us well under that even
  on big sweeps.
* The hunting query has a 30-second timeout in the Sentinel API. If
  your environment has very high email volume, narrow the query
  further (e.g. add `| where ThreatTypes != ''` to limit candidates).
