# Executive Summary

For: SOC director, CISO staff, security architecture leadership. One page;
every claim is expanded in the downstream documents.

## The question

Can we replace Proofpoint Threat Response Auto-Pull (TRAP) with Microsoft
Defender for Office 365 plus the broader Microsoft security ecosystem,
without a measurable drop in SOC operational outcomes?

## The answer

Yes for about 90 percent of TRAP capabilities, with two genuinely difficult
gaps that have engineered workarounds. The remaining 10 percent is custom
orchestration in Sentinel + Logic Apps + Microsoft Graph. No third-party
tooling required.

## What we get natively (no engineering)

| Outcome | Microsoft component |
|---|---|
| Post-delivery message removal from cloud mailboxes | AIR + Defender XDR Take Action wizard |
| Zero-hour retroactive delete of newly-condemned mail | Zero-hour Auto Purge (ZAP) |
| User-reported phishing → automated investigation | Built-in Outlook Report button + AIR |
| Submissions with verdict feedback to Microsoft | Submissions API (Graph `/security/threatSubmission/emailThreats`) |
| Tenant-wide block of sender / URL / file hash / IP | Tenant Allow/Block List (TABL) |
| Campaign clustering (sender / subject / URL / attachment) | MDO P2 Campaigns view + AIR cluster graph |
| Auto-remediation approval workflow | Defender Action Center (one-click approve/reject) |
| Audit trail of every action (CSV / SIEM) | Unified Audit Log + Action Center + Sentinel `OfficeActivity` |
| SIEM forwarding | Sentinel is the SIEM (Defender XDR streaming connector) |

## What requires custom engineering

| Outcome | Engineered approach | Effort |
|---|---|---|
| Forward-following remediation (multi-hop) | KQL on `EmailEvents.NetworkMessageId` chain + recursive `Get-MessageTraceV2` to discover forwarded copies | ~80 hr |
| Distribution-list expansion across nested DLs | `Get-DistributionGroupMember -Recursive` + Compliance Search by recipient set | ~40 hr |
| Custom abuse mailbox ingestion (if rejecting built-in Defender path) | Logic App polling shared mailbox → parse `.eml` → call Submissions API → trigger remediation playbook | ~60 hr |
| Reporter "thanks" + verdict-back notification (CLEAR-equivalent) | Logic App: pre-report banner is built-in; verdict-back requires playbook that posts to reporter on AIR investigation completion | ~40 hr |
| VAP / Very Attacked People prioritisation | Sentinel watchlist (`VAP_Users`) + automation rule to escalate severity when reporter ∈ watchlist | ~24 hr |
| Read-status visibility for reported messages across recipients | Graph `/users/{id}/messages/{id}?$select=isRead` per recipient enumerated by KQL | ~16 hr |
| IOC-driven retroactive sweeps from external TI feed | Sentinel TI ingestion + scheduled hunting rule + remediation playbook | ~60 hr |

Total bespoke engineering: **~320 hours** (≈ 2 senior engineers × 5 weeks).

## What is genuinely impossible (and the closest workaround)

| TRAP capability | Why impossible in MDO | Closest workaround |
|---|---|---|
| Cross-tenant remediation in a single console | Defender XDR is single-tenant; no cross-tenant action API | Microsoft 365 Lighthouse + per-tenant Sentinel; manual playbook fan-out via service principal per tenant |
| Remediation of on-prem (hybrid) Exchange mailboxes | ZAP, AIR, and Defender Take Action operate on cloud mailboxes only | Custom EWS / on-prem PowerShell remediation via on-prem agent triggered by Logic App webhook (legacy, deprecated by Microsoft direction) |
| True multi-hop external forward following | Once a message leaves the tenant boundary, Microsoft has no telemetry | Block at egress with mail-flow rule; alert on auto-forward configuration changes (Sentinel rule on `Set-Mailbox -ForwardingSmtpAddress`) |
| Real-time read-status across recipients in a single view (TRAP UI) | Graph reports per-recipient state; no aggregated UI | KQL summarisation or PowerBI dashboard backed by hunting query |

## License floor

**Required, minimum, for full parity:**

* Microsoft 365 E5, **or** E3 + EMS E5 + MDO P2 + Sentinel pay-as-you-go
* Sentinel ingestion budget. assume ≈ 50 GB / day for 10k mailbox tenant
  with EmailEvents + EmailUrlInfo + UrlClickEvents enabled (see
  [`13-licensing-and-operations.md`](./13-licensing-and-operations.md))
* Microsoft Graph: free; throttling applies (10k requests / 10 min / app).

**Optional but recommended:**

* Microsoft Defender Threat Intelligence (MDTI) Premium gives premium IOC
  context that the open MDTI does not.
* Microsoft 365 Lighthouse, required only if we operate multi-tenant.

## Operational shape after migration

* SOC analyst time per phishing incident: **target 60 % reduction** vs. TRAP
  (one console, Defender XDR, replaces TRAP UI plus email gateway UI;
  AIR auto-remediates ~70 % of high-confidence cases without analyst).
* MTTR (mean time to remediate) for user-reported phish:
  TRAP baseline ≈ **3 to 8 minutes**; MDO + AIR target ≈ **2 to 5 minutes**
  (dominant latency is AIR investigation, ~30 to 120 s, plus Compliance Search
  fan-out, ~30 to 60 s for ≤500 recipients).
* Approval workflow: Action Center one-click is faster than TRAP's incident
  list approve flow.
* False-positive recovery: Defender quarantine release (admin or user
  self-service) replaces TRAP's "restore" capability.

## Risk register (top five)

1. **Compliance Search-Action 10-item-per-mailbox limit.** For very large
   campaigns (more than 10 messages to one mailbox), the playbook must
   batch. Design for it. (See `07-graph-and-exchange-remediation.md`.)
2. **ApplicationImpersonation removal (Feb 2025).** Any TRAP-era automation
   that used EWS Impersonation must move to Graph + RBAC application
   permissions. This affects custom abuse-mailbox tooling, not Microsoft
   AIR/ZAP.
3. **Sentinel ingestion cost overrun.** EmailUrlInfo + UrlClickEvents are
   high-cardinality. Use the Defender XDR connector's per-table opt-in.
4. **AIR concurrent-investigation cap (undocumented but observed ≈ 50
   simultaneous in large tenants).** During campaign storms, queue depth
   matters; supplement with Sentinel scheduled hunting.
5. **Approval connector dependency in Logic Apps.** Outlook approval connector
   requires per-user OAuth; design playbooks to fall back to Teams adaptive
   cards or a SOC distribution list shared-mailbox approval.

## Recommended decision

**Proceed with phased migration over 12 to 16 weeks.** Run TRAP and the Microsoft
stack in parallel for ≥ 4 weeks, comparing remediation outcomes per incident,
before decommissioning TRAP. Detailed phasing in
[`11-implementation-roadmap.md`](./11-implementation-roadmap.md).

## When NOT to migrate

* We operate a heavily on-premises Exchange estate with no plan to move to
  EXO. ZAP and AIR do not work on on-prem mailboxes; TRAP is purpose-built
  for hybrid.
* We depend on TAP for sandboxing and have no plan to replace it. (MDO Safe
  Attachments is the equivalent; this blueprint assumes TAP→MDO sandboxing
  migration is in scope.)
* We require true multi-tenant cross-organisation remediation in a single
  console (e.g. an MSSP serving customers without per-tenant onboarding).

For everyone else, the engineering economics favour the Microsoft stack , 
because the licences are largely already paid for in any Microsoft 365 E5
estate, and the orchestration components (Sentinel, Logic Apps) are general-
purpose investments rather than email-specific tools.
