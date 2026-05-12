# Open Questions

This is the running list of decisions we have not yet made and constraints
we have not yet confirmed. Every item here can change the shape of the
migration. We close items as they are answered, and we add items as we
find them. None of this should block the OOTB deployment, but several
items have to be answered before we can go past the parallel-run phase.

Use this doc as the standing input to the next architecture review.

---

## 1. On-prem and hybrid Exchange scope

### Q1.1 Do we still have on-prem mailboxes in production?

What we need to know: the count of mailboxes whose `RecipientTypeDetails`
is anything other than `UserMailbox` or `SharedMailbox` (in Exchange
Online), broken out by business unit.

How to answer: run

```powershell
Get-Mailbox -ResultSize Unlimited |
  Group-Object RecipientTypeDetails |
  Sort-Object Count -Descending
```

Why it matters: ZAP, AIR, Defender XDR Take Action, and Compliance
Search-Action all operate on EXO mailboxes only. Anything still on-prem
is uncovered by the core remediation surface. This is documented in
[`12-limitations-and-gaps.md`](./12-limitations-and-gaps.md) §2.

### Q1.2 If on-prem mailboxes exist, what is the migration plan for them?

The honest answer paths:

* **Migrate to EXO.** Best long-term answer. Runs alongside this project
  but on its own track. Decision input: how many mailboxes, how
  business-critical, how complex (public folders, calendar delegations,
  shared mailbox dependencies).
* **Keep them on-prem and accept the gap.** Acceptable only if the
  mailboxes in scope are out of TRAP's protection target anyway (rare).
* **Custom on-prem worker.** EWS-based agent triggered by webhook from
  Sentinel. We do not recommend this; EWS is being retired in EXO in
  October 2026 and the on-prem direction follows. Treat as a tactical
  bridge only.

We need a named owner for this decision and a written commitment before
Phase 4 (cutover). If we do not have one, we cannot decommission TRAP.

### Q1.3 Do we have hybrid mail flow (journaling, transport rules) that affects what reaches EXO?

What we need to know: full inbound and outbound mail flow diagram, with
every transport rule, journal recipient, and connector that could
re-route mail between on-prem and cloud. Particularly relevant for any
"bypass spam filtering" rules, which override ZAP and HC-phish handling.

Why it matters: ZAP eligibility and AIR cluster membership both depend on
the message landing inside EXO with the correct headers. Hybrid mail flow
that introduces re-injection points or strips Microsoft headers will
silently break our remediation coverage in places we do not see.

---

## 2. The `Mail-Advanced.ReadWrite` Graph scope (Dec 2026)

### Q2.1 Do we run any forensic preservation tool that mutates message headers via Graph?

What we need to know: an inventory of every internal tool, third-party
SaaS, and consultant-built script that calls Microsoft Graph against
mail messages with permissions broader than `Mail.Read` or `Mail.Send`.
Particularly anything that:

* Modifies `internetMessageHeaders` (X-headers added for tagging,
  classification, or chain-of-custody).
* Modifies `internetMessageId` or other immutable-by-default properties.
* Performs mailbox export with full envelope preservation (forensic
  preservation, eDiscovery export tooling, legal-hold export).

Why it matters: from December 31, 2026, Microsoft requires the elevated
**`Mail-Advanced.ReadWrite`** Graph permission for any app that modifies
sensitive message properties. Apps using only `Mail.ReadWrite` will lose
the ability to write those properties on that date. Documented in
[`07-graph-and-exchange-remediation.md`](./07-graph-and-exchange-remediation.md) §1.4.

### Q2.2 What forensic / eDiscovery tools are in scope and who owns them?

The question is not just whether they need the new scope, but who in our
org is on the hook for requesting it before the deadline. Candidate
tools we have seen in similar estates:

* In-house custom scripts (often unowned by anyone after the original
  engineer left).
* Compliance / legal eDiscovery tools (Veritas, Mimecast eDiscovery,
  Smarsh, etc.).
* Forensic chain-of-custody tools (anything that stamps messages with a
  hash for evidentiary continuity).
* Custom message-tagging tools used for finance / legal review flows.

We need an inventory and a named owner per tool. The output of this
question feeds the Phase 5 decommission audit and a separate change
ticket per tool.

### Q2.3 Are any of our remediation playbooks doing header mutation today?

Likely no, since the playbook library is delete-only, but worth confirming
before we lock the design. If any playbook mutates headers, it must be
re-scoped to `Mail-Advanced.ReadWrite` before December 2026.

---

## 3. MDO licensing posture

### Q3.1 What MDO SKU does each mailbox actually have?

What we need to know: a per-user table of MDO licence assignment, with
counts grouped by SKU. We are checking specifically for the boundary
between **MDO P1** (insufficient for this blueprint) and **MDO P2**
(required).

How to answer:

```powershell
Connect-MgGraph -Scopes "User.Read.All"
$users = Get-MgUser -All -Property assignedLicenses,userPrincipalName
$users | ForEach-Object {
  $skus = ($_.assignedLicenses.skuId | ForEach-Object {
    (Get-MgSubscribedSku -SubscribedSkuId $_).SkuPartNumber
  }) -join ", "
  [PSCustomObject]@{
    Upn  = $_.UserPrincipalName
    Skus = $skus
  }
} | Group-Object Skus | Sort-Object Count -Descending
```

Look for SKU strings containing `THREAT_INTELLIGENCE` (MDO P2
standalone), `ENTERPRISEPREMIUM_NOPSTNCONF` (E5 family), or
`SPE_E5` / `M365_E5_*` patterns. Anything assigned only `STREAM`,
`ATP_ENTERPRISE` (MDO P1), or no MDO SKU at all is a gap.

Why it matters: every capability in
[`04-mdo-native-capabilities.md`](./04-mdo-native-capabilities.md) is
gated by SKU. AIR, Threat Explorer remediation actions, the Campaigns
view, Attack Simulation Training, Advanced Hunting on the Email* tables,
Priority Account Protection, and AIR Auto Feedback Response all require
MDO P2. MDO P1 alone is not enough.

### Q3.2 Are there pockets of users on lower SKUs?

Common patterns we have seen:

* Service mailboxes and shared mailboxes assigned MDO P1 (or no MDO at
  all) for cost reasons. These need uplift if they are reachable by
  reporters or by bulk-mailing campaigns.
* Contractor / partner accounts assigned a smaller SKU than full-time
  staff. These are often the highest-risk mailboxes (external-facing).
* A residual Microsoft 365 Business Premium tenant from an acquisition,
  bundling MDO P1 only.

Whatever the cause, we need a per-mailbox plan to either uplift the
licence or accept and document the gap.

### Q3.3 Do we have headroom in the Tenant Allow/Block List quotas?

Quotas (per
[`04-mdo-native-capabilities.md`](./04-mdo-native-capabilities.md) §4):

* MDO P1: 1,000 block plus 1,000 allow per category.
* MDO P2: 10,000 block plus 5,000 allow per category.

If our TI sweep playbook is going to push hits into TABL, we need to
budget against the P2 ceiling and decide whether to age out old entries
aggressively or to maintain a parallel block list outside TABL (e.g. in
Defender for Endpoint indicators).

### Q3.4 Are we licensed for Microsoft Defender Threat Intelligence Premium?

Optional, not strictly required by this blueprint. But MDTI Premium
gives us curated indicators that the Sentinel TI sweep playbook can use
without a third-party feed. Worth confirming whether it is in our
Microsoft contract; sometimes it is bundled and unused.

---

## 4. Other open questions that may impact delivery

### Q4.1 What is our compliance posture on hard delete?

Some teams require legal sign-off before any hard-delete action runs,
even on confirmed phishing. If this applies to us:

* Default Playbook P1 to soft delete only.
* Add an explicit approval gate for hard delete.
* Document the approval chain in the SOC runbook.

Decision needed: who is the approver, and what is the SLA for response?

### Q4.2 What does our Conditional Access posture look like for service accounts?

The Office 365 Outlook connector for Logic Apps requires per-user OAuth.
Our SOC service mailbox account will trip CA policies that require:

* MFA on every authentication.
* Compliant device.
* Specific named locations.

We need an explicit CA exclusion (or a hardware-token bypass) for the
service account. Otherwise the playbook silently fails the next time
the OAuth token refreshes.

Decision needed: which CA policy excludes the SOC service account, and
who maintains it?

### Q4.3 Do we have a multi-tenant footprint?

Mergers and acquisitions, separate brands, regulated subsidiaries: any
of these can create more than one Microsoft 365 tenant. Defender XDR
Take Action and Compliance Search-Action are both single-tenant; we
cannot remediate across the boundary in one call.

If multi-tenant: we need a per-tenant deployment of this blueprint, plus
either a central Sentinel cross-workspace setup or a service-principal
fan-out pattern. The cost is operational; the architecture is in
[`12-limitations-and-gaps.md`](./12-limitations-and-gaps.md) §3.

Decision needed: list every tenant in scope and the priority order.

### Q4.4 What is our Sentinel ingestion budget?

Phase 1 turns on a small subset of Defender XDR tables. Phase 3 turns on
the high-cardinality ones (`EmailUrlInfo`, `EmailAttachmentInfo`,
`UrlClickEvents`). Each adds non-trivial GB/day at scale. The full set
runs into hundreds of dollars per month for a 10k-mailbox tenant.

Decision needed: who owns the Sentinel cost line, and what is the
threshold above which we need Finance approval to enable the next set
of tables?

### Q4.5 Do we have third-party SOAR (XSOAR / Splunk SOAR / IBM Resilient) that integrates with TRAP today?

If yes, those integrations need to be re-pointed at Sentinel and
Defender XDR APIs as part of Phase 4 (cutover). The work is mechanical
but non-trivial; there is no Microsoft-equivalent of the TRAP REST API,
so existing playbooks need to be ported, not migrated.

Decision needed: list every external SOAR integration that touches
TRAP today, with named owners, so each can be re-pointed before TRAP
goes quiet.

### Q4.6 What is the SOC analyst training plan for Defender XDR?

The Defender XDR portal is functionally different from the TRAP UI. The
Action Center, Threat Explorer, and Email entity page have a different
ergonomic model. Analysts need real reps before Phase 2 ends.

Decision needed: who runs training, when, and what does "trained"
look like as a gate?

### Q4.7 What happens to the existing PhishAlarm reports archive?

PhishAlarm has been collecting user reports for years. The data has
forensic and audit value (especially the per-incident activity lists).
We need a decision on:

* Whether to export the archive before TRAP decommission.
* Where to store it (blob storage, a separate Sentinel workspace,
  archive tier).
* How long to retain it under our retention schedule.

Decision needed: data owner, retention class, target storage.

### Q4.8 Do we want to keep PhishAlarm Analyzer's auto-classification while we wait for AIR?

PhishAlarm Analyzer auto-classified reports as malicious/suspicious/bulk/
clean/spam. AIR provides an equivalent, but the verdict surface is
different (4 verdicts vs PhishAlarm's 5). Some teams will miss the
finer-grained classification.

Decision needed: do we accept the verdict-mapping change as part of the
migration, or do we build a Logic App that adds a custom intermediate
classification on top of AIR's verdicts?

### Q4.9 How long do we keep TRAP installed but quiet after Phase 4?

The roadmap says TRAP stays installed-but-quiet through the early
stability window of Phase 5. The trigger for actual decommission is the
Phase 5 exit criteria, not a calendar date. But there is a real cost to
keeping the licence alive.

Decision needed: who signs off on TRAP licence cancellation, and what
specific evidence do they need to see?

### Q4.10 Do we have any data residency or sovereign-cloud constraints?

The Submissions API (`/security/threatSubmission/emailThreats`) is
**not available** in GCC L4/L5, DoD, or 21Vianet. If any of our
tenants are in those clouds, we cannot use the standard
"Microsoft and my reporting mailbox" routing; we are forced to
"My reporting mailbox only" plus the custom Logic App ingestion path.

Decision needed: which clouds are our tenants in, and which routing
applies per tenant?

---

## How to use this doc

Owners: every question above needs a named owner. Add the owner inline
when assigned. Items with no owner are not tracked anywhere; they fall
through.

Closure: when a question is answered, replace the question text with the
answer and the date the decision was recorded. Move the closed item to
an "Answered" section at the bottom of this doc (do not delete; we want
the audit trail).

Discovery: as we find new constraints during Phase 1, 2, or 3, add them
here rather than burying them in playbook comments. This is the
standing list.
