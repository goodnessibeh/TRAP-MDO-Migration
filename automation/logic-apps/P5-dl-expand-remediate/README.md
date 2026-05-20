# P5 — DL-Expand-Remediate

> **Status: shipped — no Function App needed.** Uses Microsoft Graph's
> `groups/{id}/transitiveMembers` endpoint to recursively expand
> distribution group membership. Works for any DL synced to Microsoft
> Entra (the cloud-managed default). Pure on-prem DLs not in Entra
> need a separate EXO PowerShell path — not implemented here.

Validates against `../../tests/Test-LogicAppTemplate.ps1`: 15/15 checks pass.

Conservative defaults: 500-member safety cap (`-MaxMembers`); oversized
DLs are flagged as an incident comment and skipped rather than blindly
remediated. Bump the cap if your environment has legitimate large DLs.

Documented in [`10-logic-apps-playbook-library.md`](../../../10-logic-apps-playbook-library.md) §P5
and [`09-kql-detection-library.md`](../../../09-kql-detection-library.md) Q8.

## Why this exists

TRAP enumerated DL membership natively when a phish hit a distribution
list, then fanned out remediation across every resolved member. MDO
doesn't have a one-call equivalent; the delivery telemetry usually
records the DL address rather than the individual recipients.

P5 closes the gap.

## Architecture

```
Sentinel incident on MailMessage
        |
        v
P5 Logic App  ── HTTP ──>  Azure Function (PowerShell)
        |                     |
        |                     v
        |                  Connect-ExchangeOnline -ManagedIdentity
        |                  Get-DistributionGroupMember -Recursive
        |                     |
        v                     v
   For each member: call Defender XDR Take Action
```

## Why a Function App (not native)

Logic Apps can call EXO via the Office 365 connector but the connector
only exposes a curated subset of cmdlets — `Get-DistributionGroupMember`
isn't one of them. A PowerShell Function App with a managed identity
that has Exchange Recipient Admin role is the smallest extra surface
that gets us there.

## Components to build

1. **Function App** with managed identity, role `Exchange Recipient
   Administrator` (or `View-Only Recipients` if read-only is enough).
2. Function endpoint `POST /resolve-dl-members` that returns the
   recursively expanded recipient list.
3. P5 Logic App that calls the function, then iterates and calls
   Defender XDR Take Action per member.

## Pattern

The structural shape mirrors P4 (Forward Trace) — entity trigger,
hunting query (Q8), iterate, Take Action, comment-back. Swap the
hunting-query step for the function call.

## When P5 lands here

Drop the Logic App `playbook.json` and the Function App source code in
this directory and validate.
