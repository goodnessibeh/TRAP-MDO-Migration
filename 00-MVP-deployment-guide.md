# MVP Deployment Guide: Native MDO First, Engineering Later

> Our starting point for the TRAP retirement. Most of what TRAP does for
> us is already in MDO P2 with policy configuration alone, no engineering.
> This doc captures what we deploy in week 1 to get the bulk of the value,
> what we validate, and what we defer to Phase 2/3 for full TRAP-equivalent
> behaviour.
>
> Every "Native" item below is a config change in the Defender portal or a
> single PowerShell line. Every "Engineered" item is a Logic App or
> Function App we build later.

---

## TL;DR: what MDO already gives us, native, no engineering

If we have **MDO P2** (or M365 E5), the following TRAP-equivalent
behaviours are **already in our tenant** and just need to be turned on
and tuned:

| TRAP outcome | Native MDO equivalent | Action required |
|---|---|---|
| Auto-pull on verdict change (within 48 h) | **ZAP** (Zero-hour Auto Purge) | Confirm enabled in anti-spam/anti-phish/anti-malware policies (default ON) |
| Investigation graph + recommended remediation | **AIR** | Default-enabled with MDO P2; just confirm not disabled by alert tuning |
| Cross-recipient remediation from a single click | **Defender XDR Take Action wizard** | Permission grant: Search and Purge role |
| User-reported phish auto-investigation | **AIR triggered by user-report alert** | Default; confirm "Auto-Resolve" tuning rule disabled |
| Reporter "Thanks for reporting" + verdict back | **AIR Auto Feedback Response** + customisable banners | Toggle in *Settings → User reported* |
| Custom abuse mailbox ingestion | **Defender custom reporting mailbox** | Configure mailbox in *Settings → User reported* |
| One-click report from Outlook | **Built-in Outlook Report button** | Toggle in *Settings → User reported* |
| Campaign clustering | **Campaigns view** | Already running; just learn it |
| Sender / URL / hash / IP block | **Tenant Allow/Block List** | PowerShell `New-TenantAllowBlockListItems` |
| Approval queue for risky actions | **Action Center pending tab** | Permission grant only |
| Audit trail of every action | **Action Center History + Unified Audit Log** | Already on |
| Submit messages programmatically | **Microsoft Graph `/security/threatSubmission/emailThreats`** | App registration with `ThreatSubmission.ReadWrite.All` |
| Email entity drill-down (headers, raw, detonation) | **Defender XDR Email entity page** | Permission grant only |
| Per-recipient delivery state | **`EmailEvents` in Advanced Hunting** | Already populated |
| URL click telemetry | **`UrlClickEvents` in Advanced Hunting** | Already populated; requires Safe Links |
| 30-day audit log search | **Unified Audit Log** | Already on |
| SIEM streaming | **Defender XDR streaming connector** | Configure when wiring Sentinel |
| Two-step approval for high-risk actions | **Defender Action Center "Add to remediation"** workflow | No engineering needed for the basic case |
| Quarantine release self-service | **Quarantine policies** | Default behaviour; tune per audience |

**This list represents ≈ 85 % of the operational outcomes TRAP delivers.** The
remaining ≈ 15 % is the engineered Phase 2/3 work, listed at the bottom of
this document.

---

## MVP scope (what "minimum viable" actually means here)

The MVP is the **smallest configuration change set** that lets us turn off
TRAP without losing protection. It is **all-native MDO** plus one Sentinel
workspace + one Logic App for SIEM ingest. It does **not** cover:

* Forward-following beyond Microsoft's native cluster expansion.
* Distribution-list enumeration beyond Microsoft's native delivery telemetry.
* External TI feed-driven retroactive sweeps beyond MDTI's native matching.
* Reporter feedback for the edge case of "already-remediated message."
* VAP-driven incident severity boosting.
* Two-stage approvals with VIP-aware routing.

These are Phase 2/3 enhancements. If our environment has any of those as
**hard requirements** (regulator/audit/contractual), see the gating
checklist in §5.

---

## 1. MVP Pre-flight checks (Day 0)

| Check | How |
|---|---|
| MDO P2 licensing assigned to all mailboxes | `Get-MgUserLicenseDetail` per user; confirm SKU contains `THREAT_INTELLIGENCE` (MDO P2) or `ENTERPRISEPREMIUM_NOPSTNCONF` (E5) |
| All target mailboxes in EXO (no on-prem) | `Get-Mailbox -ResultSize Unlimited \| Group-Object RecipientTypeDetails` should return ~all `UserMailbox` / `SharedMailbox`, no `RemoteUserMailbox` |
| Audit logging enabled tenant-wide | `Get-AdminAuditLogConfig \| FL UnifiedAuditLogIngestionEnabled` → `True` |
| EXO Management module v3+ on admin host | `Get-Module ExchangeOnlineManagement -ListAvailable` |
| Microsoft Graph PowerShell SDK v2+ | `Get-Module Microsoft.Graph -ListAvailable` |
| Defender XDR portal accessible | navigate to `https://security.microsoft.com` |

If any of these fail, fix before continuing.

---

## 2. MVP Day 1: Native MDO configuration

### 2.1 Enable presets (anti-phish + anti-spam + anti-malware + Safe Links + Safe Attachments)

```powershell
# Apply Strict preset to all users
$presetParams = @{
  Identity = "Strict Preset Security Policy"
  PreventiveStateConditions = @{
    SafeAttachmentEnabled = $true
    SafeLinksEnabled = $true
    AntiPhishEnabled = $true
    AntiSpamEnabled = $true
    AntiMalwareEnabled = $true
  }
}
# In portal: Email & collaboration → Policies → Threat policies →
#            Preset security policies → Strict protection → Manage protection settings
```

UI path: `https://security.microsoft.com/presetSecurityPolicies` →
*Strict protection* → *Manage protection settings* → scope to *All recipients*
in *all domains* → enable.

### 2.2 Confirm ZAP enabled (default ON; verify)

```powershell
# Anti-malware ZAP
Get-MalwareFilterPolicy | Format-Table Identity, ZapEnabled

# Anti-spam ZAP (PhishZapEnabled, SpamZapEnabled)
Get-HostedContentFilterPolicy | Format-Table Identity, PhishZapEnabled, SpamZapEnabled

# Confirm SpamAction = Quarantine, HighConfidencePhishAction = Quarantine
Get-HostedContentFilterPolicy | Format-Table Identity, SpamAction, HighConfidenceSpamAction, PhishSpamAction, HighConfidencePhishAction
```

Expected on Strict preset: all `*ZapEnabled` = `$true`,
`HighConfidencePhishAction = Quarantine`.

### 2.3 Configure user-reported messages

UI path: `https://security.microsoft.com/securitysettings/userSubmission`

Settings to apply for the MVP:

| Setting | Value |
|---|---|
| Monitor reported messages in Outlook | **ON** |
| Outlook report button configuration | **Use the built-in Report button in Outlook** |
| Send reported items to | **Microsoft and my reporting mailbox** |
| Reporting mailbox | `reportedmessages@<our-tenant>.com` (create as EXO mailbox first) |
| Ask the user to confirm before reporting | **ON** (Phish + Junk + Not junk) |
| Show a success message after the message is reported | **ON** |
| Customize messages | Tenant-branded text, our logo |
| **Automatically email users the results of the investigation** | **ON** for Phishing/malware AND No threats found |

PowerShell equivalent:

```powershell
$mb = "reportedmessages@contoso.com"
New-ReportSubmissionPolicy `
  -ReportJunkAddresses $mb `
  -ReportNotJunkAddresses $mb `
  -ReportPhishAddresses $mb `
  -PreSubmitMessageEnabled $true `
  -PostSubmitMessageEnabled $true `
  -EnableUserEmailNotification $true `
  -UserNotificationCustomFromAddress "soc@contoso.com"

New-ReportSubmissionRule `
  -Name DefaultReportSubmissionRule `
  -ReportSubmissionPolicy DefaultReportSubmissionPolicy `
  -SentTo $mb
```

### 2.4 Add reporting mailbox to Advanced Delivery (SecOps mailbox)

Critical, without this, reports get filtered:

```powershell
New-SecOpsOverridePolicy `
  -Name "SecOps Mailboxes" `
  -SentTo "reportedmessages@contoso.com","soc-quarantine@contoso.com"

New-SecOpsOverrideRule `
  -Name "SecOps Mailboxes Rule" `
  -Policy "SecOps Mailboxes" `
  -SentTo "reportedmessages@contoso.com","soc-quarantine@contoso.com"
```

Also exclude the reporting mailbox from DLP and from any retention policy
that might quarantine reports.

### 2.5 Confirm AIR is firing for user-reported phish

```powershell
# Look at alert tuning rules and disable any rule that suppresses
# "Email reported by user as malware or phish"
Get-ProtectionAlert | Where-Object { $_.Name -like "*Auto-Resolve*Email reported*" } |
  ForEach-Object { Disable-ProtectionAlert -Identity $_.Identity }
```

Confirm AIR investigations appear at `https://security.microsoft.com/airinvestigation`
within 1 to 2 hours after submitting a test phish via the Report button.

### 2.6 Grant SOC role: Search and Purge + Email & collaboration roles

Defender portal → *Permissions & roles → Email & collaboration roles → Roles*:

| Role group | Members | Purpose |
|---|---|---|
| Security Administrator | SOC leads | Tune policies, manage submissions, review TABL |
| Security Reader | All SOC analysts | Read alerts, incidents, hunting |
| Data Investigator | SOC L2/L3 | Has Search and Purge role assigned (required for Take Action wizard, Compliance Search-Action) |
| Quarantine Administrator | SOC L1 | Release/delete from Quarantine |

### 2.7 Verify Defender XDR Take Action wizard works

1. Send yourself a test email with a benign attachment from an external
   throwaway sender.
2. In Defender → *Threat Explorer*, find the message.
3. *Take action → Soft delete*.
4. Confirm action shows up in *Action Center → History*.

---

## 3. MVP Day 2: Sentinel for SIEM and audit retention

The MVP needs Sentinel **only** for two reasons:

1. SIEM/audit storage beyond the Action Center 30-day window.
2. A single Logic App that bridges the AIR feedback gap (see §3.3).

### 3.1 Workspace

* Provision a Log Analytics workspace in the same region as our tenant.
* Onboard Microsoft Sentinel.
* Onboard to the **unified Defender portal** (recommended. Microsoft is
  retiring the Azure-portal Sentinel UI on 31 Mar 2027).

### 3.2 Connectors (MVP set)

| Connector | Purpose |
|---|---|
| **Microsoft Defender XDR** | Incidents + alerts + raw email tables |
| **Office 365** | OfficeActivity audit (mailbox rules, mail-flow rule changes) |
| (optional) **MDTI** | Microsoft Defender Threat Intelligence. only if we have the SKU |

For the **Defender XDR connector**, the MVP enables:

* Incidents and alerts: **ON**
* Tables: `EmailEvents`, `EmailPostDeliveryEvents`, `AlertInfo`, `AlertEvidence`
* **Defer**: `EmailUrlInfo`, `EmailAttachmentInfo`, `UrlClickEvents` (high
  cardinality; turn on in Phase 2 when we need URL/attachment hunting).

When connecting, tick **"Turn off all Microsoft incident creation rules for
these products"** to prevent double-incidenting.

### 3.3 The one Logic App in the MVP. Reporter Thanks Bridge

This is the **only** engineered piece in the MVP. It exists because the
native AIR Auto Feedback Response does **not** fire when the message was
already remediated before AIR ran. leaving the reporter without
acknowledgement.

```
Trigger: Microsoft Sentinel incident
Conditions: Title contains "Email reported by user as malware or phish"
Action 1: Compose: extract reporter email from incident entities
Action 2: Office 365 Outlook (SOC service mailbox connection):
  Send email V2 to: <reporter>
  Subject: "Thanks for reporting that email"
  Body: "We received your report. Our security team is investigating; you'll
         receive a follow-up email with the verdict shortly."
```

This **deduplicates** with AIR's Auto Feedback Response: the reporter sees
either Microsoft's auto-feedback (if AIR fired and remediated) or this
playbook's thank-you (if AIR found nothing or was suppressed). The AIR
feedback then provides the verdict-back later if/when the investigation
closes.

> If our tenant is small and we accept the edge case where reporters
> sometimes don't receive a verdict, we can skip even this Logic App and
> have a **fully native MVP**.

---

## 4. MVP Day 3: validation

### 4.1 Functional tests

Run these tests end-to-end before declaring MVP done:

| Test | Procedure | Pass criteria |
|---|---|---|
| **T1. ZAP retroactive remediation** | Send self a test message that will trigger a verdict change (e.g., a known-bad URL that gets condemned post-delivery, or use Microsoft's [test phish samples](https://learn.microsoft.com/en-us/defender-office-365/safe-attachments-policies-configure)) | Message moves to Junk/Quarantine within 48 h; visible in Threat Explorer with `Additional action = ZAP` |
| **T2. User-reported phish → AIR** | Use Outlook Report → Phishing on a test message | Submission visible in *Submissions → User reported* within 5 min; AIR investigation appears within 1 h; Auto Feedback email arrives at reporter on completion |
| **T3. Cross-recipient Take Action** | Send same test phish to 5 internal recipients; from Defender XDR Email entity, *Take action → Soft delete* | All 5 recipient mailboxes have message removed; Action Center History shows 5 actions |
| **T4. TABL block** | Add a test sender domain to TABL block; send mail from that domain | Mail rejected at delivery |
| **T5. Submissions API** | `POST /beta/security/threatSubmission/emailThreats` with a known-bad sample | 201 Created; `result.detail` populates within 30 min |
| **T6. Audit trail to Sentinel** | Perform a Take Action → Soft delete; query Sentinel | `OfficeActivity` row visible within 5 min |
| **T7. Reporter Thanks Bridge** | Submit a test phish via Outlook Report | Reporter receives the bridge thank-you email |

### 4.2 Operational shape after MVP

* SOC analyst phish triage time: comparable to TRAP baseline (5 to 10 min per
  incident).
* MTTR for user-reported phish: 2 to 10 min (AIR latency + remediation fan-out).
* False-positive recovery: Defender quarantine self-service release.

If T1 to T7 pass, **we can run TRAP and the MVP in parallel for 2 weeks,
compare incident outcomes, and decommission TRAP if the MVP equals or
exceeds TRAP for our incident corpus.**

---

## 5. What is NOT in the MVP. Phase 2/3 enhancements

If any of the following are **hard requirements** for our SOC, plan them as
Phase 2 / 3 work *before* TRAP decommission. Each is documented in detail
elsewhere in this blueprint.

### Phase 2: engineered enhancements (≈ 8 weeks effort, 2 senior engineers)

| Capability | Why TRAP did this and we might still need it | Effort | Document |
|---|---|---|---|
| **VAP / VIP-aware severity boosting** | TRAP profiled Very Attacked People; we may want auto-escalation when a VIP reports phish | 24 h | [`06-sentinel-soar-orchestration.md`](./06-sentinel-soar-orchestration.md) §4 |
| **TI-driven retroactive sweep beyond ZAP's 48 h window** | TRAP could remediate any-age message; ZAP is hardcoded to 48 h | 60 h | [`02-architecture-overview.md`](./02-architecture-overview.md) Workflow C, [`09-kql-detection-library.md`](./09-kql-detection-library.md) Q5 |
| **Forward-following internal copies** | TRAP walked internal forwards that ZAP misses | 80 h | [`02-architecture-overview.md`](./02-architecture-overview.md) Workflow D |
| **Distribution-list enumeration for fan-out** | TRAP did `Get-DistributionGroupMember -Recursive` for explicit fan-out | 40 h | [`02-architecture-overview.md`](./02-architecture-overview.md) Workflow E |
| **Two-stage approval for VIP-mailbox actions** | TRAP supported tiered approvals; Defender Action Center is single-tier | 16 h | [`10-logic-apps-playbook-library.md`](./10-logic-apps-playbook-library.md) P5 |
| **Read-status visibility per recipient** | TRAP showed pre-pull `IsRead` per recipient | 16 h | [`03-trap-capability-matrix.md`](./03-trap-capability-matrix.md) §G |
| **Custom abuse-mailbox ingestion (when not using built-in Report)** | If we have legacy `abuse@` mail flowing from non-Outlook clients or hybrid mailboxes | 60 h | [`08-abuse-mailbox-and-user-reporting.md`](./08-abuse-mailbox-and-user-reporting.md) |
| **Cross-vendor enrichment in incident playbook** (VirusTotal, MDTI, AbuseIPDB) | TRAP/PTR had built-in enrichment connectors | 16 h | [`10-logic-apps-playbook-library.md`](./10-logic-apps-playbook-library.md) P1 |

### Phase 3: advanced / situational (deploy only if needed)

| Capability | When we need it | Effort | Document |
|---|---|---|---|
| **Cross-tenant remediation** (M&A, MSSP) | We operate >1 tenant and want unified incident view | 80 h per tenant | [`12-limitations-and-gaps.md`](./12-limitations-and-gaps.md) §3 |
| **On-prem hybrid mailbox remediation** | We still have on-prem mailboxes that ZAP/AIR cannot touch | 80 to 160 h custom EWS agent (deprecating) | [`12-limitations-and-gaps.md`](./12-limitations-and-gaps.md) §2 |
| **Mass migration of historical TRAP incident data** | We need TRAP incident history for compliance | 40 h ETL | [`11-implementation-roadmap.md`](./11-implementation-roadmap.md) Phase 0 |
| **External forward egress alerting** | We worry about already-forwarded phishes | 8 h alert rule | [`09-kql-detection-library.md`](./09-kql-detection-library.md) Q7 |

---

## 6. MVP gating checklist

Before declaring MVP done and beginning TRAP decommission, confirm:

- [ ] All MDO P2 licenses assigned, all target mailboxes in EXO.
- [ ] Strict preset (or tuned custom equivalent) applied to all users.
- [ ] ZAP enabled across anti-phish, anti-spam, anti-malware policies.
- [ ] User reported settings configured: built-in Report button + custom
      mailbox + AIR Auto Feedback Response.
- [ ] Reporting mailbox added to SecOps overrides.
- [ ] AIR confirmed firing on a real test report; investigation closes
      cleanly.
- [ ] Defender XDR Take Action wizard exercised and working.
- [ ] Search and Purge role assigned to all who need it.
- [ ] Sentinel workspace + Defender XDR connector + Office 365 connector live.
- [ ] (Optional) Reporter Thanks Bridge Logic App deployed.
- [ ] T1 to T7 functional tests pass.
- [ ] Operational dashboards built (Sentinel workbook on `OfficeActivity`,
      Action Center History, Submissions metrics).
- [ ] SOC playbook updated to use new tools; analysts trained.
- [ ] TRAP and MVP run in parallel for 2 weeks; outcomes compared.

If all boxes are ticked, **we can decommission TRAP**: The Phase 2/3 work
is then a continuous improvement programme on top of a working baseline.

---

## 7. Anti-pattern: do not skip the MVP

The temptation here is to design the full Phase 1+2+3 architecture upfront
and ship it as one project. We should not. The native MDO surface is
mature; engineering effort we spend reproducing what MDO already does is
engineering time wasted.

Two specific traps we have to avoid:

1. **Building a custom abuse-mailbox Logic App when the built-in custom
   reporting mailbox is sufficient.** The native path is one config
   screen. If we build the Logic App first, we own polling, retry,
   parsing, dedup, and submission lifecycle for no reason.
2. **Building a custom AIR-equivalent investigation engine.** AIR already
   clusters by sender, subject, URL, and attachment. If we re-implement
   that in KQL ourselves, we get the same answers more slowly and we own
   tuning indefinitely.

Plan: run the MVP for 2 to 4 weeks. Then look at what TRAP actually did for
us during that window that the MVP did not, and let those gaps drive Phase
2 scope. In most pilots we have seen, the MVP covers ~70 % of historical
TRAP work without any Phase 2 build.
