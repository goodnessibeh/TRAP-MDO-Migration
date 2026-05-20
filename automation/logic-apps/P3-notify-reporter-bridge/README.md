# P3 — Notify Reporter Bridge

Acknowledges users who report suspected phishing via the built-in
Outlook Report button. Bridges the gap where AIR Auto Feedback
Response does not fire (the message was already remediated before
AIR ran, or the alert was suppressed by tuning).

This is the **only** Logic App in the OOTB deployment and is the
simplest of the seven playbooks. Documented in:

* [`00-MDO-out-of-the-box-deployment-guide.md`](../../../00-MDO-out-of-the-box-deployment-guide.md) §3.3
* [`10-logic-apps-playbook-library.md`](../../../10-logic-apps-playbook-library.md) P3

## Flow

1. Sentinel-incident trigger fires on the analytic rule that creates
   incidents from `Email reported by user as malware or phish`.
2. Filter the incident's related entities to the Account type
   (these are the reporters).
3. For each reporter, send a single thank-you email from the SOC
   service mailbox.
4. Add a Sentinel incident comment recording the count of acknowledged
   reporters and timestamp.

Operationally complements Microsoft's own AIR Auto Feedback Response —
the reporter sees either Microsoft's verdict (when AIR fires
successfully) or this bridge's thank-you (when AIR was suppressed or
ran too fast).

## Prerequisites

| Item | Notes |
|---|---|
| Sentinel workspace | This playbook is incident-triggered |
| Office 365 API connection | Authorise against a real EXO mailbox (the SOC service account); needs Send-As on `SocFromAddress` |
| Sentinel API connection | Uses Sentinel built-in connector for the trigger and the incident-comment action |
| Sentinel analytic rule | Must create incidents from the `Email reported by user as malware or phish` alert (Microsoft built-in); not in scope of this template |

## Parameters

| Name | Required | Description |
|---|---|---|
| `PlaybookName` | no | Resource name. Default: `trap-mdo-P3-notify-reporter-bridge` |
| `Office365ConnectionName` | no | Name of the existing Office 365 API connection in the same resource group |
| `SentinelConnectionName` | no | Name of the existing Sentinel API connection |
| `SocFromAddress` | **yes** | Send-as mailbox for the acknowledgement email |
| `Location` | no | Azure region. Default: resource group region |

## Deploy

```powershell
Connect-AzAccount -UseDeviceAuthentication

$rg       = 'rg-sentinel-prod'
$location = 'uksouth'
$path     = '.\playbook.json'
$pPath    = '.\parameters.example.json'

# Optional: validate before deploy
Test-AzResourceGroupDeployment `
  -ResourceGroupName $rg `
  -TemplateFile $path `
  -TemplateParameterFile $pPath

# Deploy
New-AzResourceGroupDeployment `
  -ResourceGroupName $rg `
  -TemplateFile $path `
  -TemplateParameterFile $pPath `
  -Verbose
```

The deployment outputs `managedIdentityPrincipalId`. Grant that
identity **Microsoft Sentinel Responder** on the Sentinel workspace
so it can post incident comments:

```powershell
$miPid = (Get-AzResourceGroupDeployment -ResourceGroupName $rg `
  | Sort-Object Timestamp -Descending | Select-Object -First 1).Outputs.managedIdentityPrincipalId.Value

New-AzRoleAssignment `
  -ObjectId $miPid `
  -RoleDefinitionName 'Microsoft Sentinel Responder' `
  -Scope (Get-AzOperationalInsightsWorkspace -ResourceGroupName $rg -Name <ws>).ResourceId
```

## Wire to an automation rule

Sentinel → Automation → Create automation rule:

* Trigger: When incident is created
* Conditions: Title contains `Email reported by user as malware or phish`
* Actions: Run playbook → select `trap-mdo-P3-notify-reporter-bridge`

## Validate before deploying

From `automation/tests/`:

```powershell
.\Test-LogicAppTemplate.ps1 ..\logic-apps\P3-notify-reporter-bridge
```

Static checks: JSON parses, ARM shape, workflow definition, runAfter
graph, `$connections` references resolve, `[parameters(X)]` references
resolve.

## Throttling for high-volume reporters

If the tenant sees >500 reports/day, gate the playbook upstream via
an automation-rule condition that excludes reporters in a Sentinel
watchlist named `Frequent_Reporters`. Those get a weekly summary
instead of a per-report email. See blueprint §P3 "Operational notes".
