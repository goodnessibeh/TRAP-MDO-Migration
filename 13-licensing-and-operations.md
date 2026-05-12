# Licensing and Operational Considerations

What we must hold to make any of this work, what each capability costs in
ongoing operational terms, and the SOC ergonomics that follow from the
architecture choices in this blueprint.

---

## 1. License floor

The minimum SKU mix for full TRAP-equivalent function:

* **MDO P2** on every protected mailbox. Bundled in M365 E5, Office 365 E5,
  M365 A5, M365 G5. Available as an add-on to E3 / Business Premium /
  Office 365 E3.
* **Microsoft Sentinel** on the workspace. Pay-as-we-go ingestion plus
  optional commitment tiers.
* **Microsoft Graph** for the API surface. No SKU needed; throttling
  applies.
* **Logic Apps** for playbooks. Consumption or Standard.

What MDO P1 alone does NOT give us: AIR, Threat Explorer remediation
actions, Campaigns view, Attack Simulation Training, Advanced Hunting on
Email* tables, Priority Account Protection. P1 is insufficient for this
blueprint.

What is genuinely optional but worth considering:

* **Microsoft Defender Threat Intelligence (MDTI) Premium**: Adds curated
  IOC context and the Microsoft Threat Intelligence Analytics rule. The
  free tier of MDTI is included with MDO P2; the premium tier is sold
  separately. Premium pays for itself in tenants that handle frequent
  targeted attacks; not necessary for general phishing remediation.
* **Microsoft 365 Lighthouse**: Required only for multi-tenant scenarios.
  Free for MSP partners enrolled in Microsoft 365 Lighthouse.
* **Microsoft Purview Audit Premium**: Extends Unified Audit Log retention
  beyond the default 180 days to 1 year by default and up to 10 years with
  add-ons. Useful for regulated industries with long compliance windows;
  not strictly required for the architecture to function.

---

## 2. Sentinel ingestion budget

The single largest variable cost. Plan for it before we connect anything.

For a 10k-mailbox tenant with the **MVP table set** enabled (EmailEvents,
EmailPostDeliveryEvents, AlertInfo, AlertEvidence, OfficeActivity), expect
ingestion of approximately:

| Source | Volume |
|---|---|
| EmailEvents | 0.4 to 2 GB/day |
| EmailPostDeliveryEvents | 0.05 to 0.2 GB/day |
| AlertInfo + AlertEvidence | 0.05 to 0.2 GB/day |
| OfficeActivity | 0.5 to 2 GB/day |
| **Total MVP** | **~1 to 4 GB/day** |

Adding the **Phase 2/3 enhancements** turns on the high-cardinality
tables:

| Source | Volume |
|---|---|
| EmailUrlInfo | 0.5 to 1.5 GB/day |
| EmailAttachmentInfo | 0.1 to 0.5 GB/day |
| UrlClickEvents | 0.5 to 1.5 GB/day |
| **Total Phase 2/3 add-on** | **~1 to 3.5 GB/day** |

Combined: roughly **3 to 7 GB/day** for a 10k-mailbox tenant running the
full architecture. Scale linearly with mailbox count for first-order
estimation; account holders with heavy bulk mail (marketing, transactional
senders) push the ratio higher.

Cost implications at typical Sentinel pay-as-you-go rate (region-dependent,
roughly 2 to 4 USD per GB ingested):

* MVP only: ~30 to 480 USD/month for 10k mailboxes.
* Full: ~180 to 840 USD/month for 10k mailboxes.

Two ways to manage this:

1. **Commitment tier**: At >100 GB/day, the commitment tier saves
   substantially over PAYG. At our scale (~5 GB/day) it does not.
2. **Selective table opt-in**: The Defender XDR connector lets us opt-in
   per-table. The MVP turns on the small set; only enable the
   high-cardinality tables when we start building Phase 2/3 hunting that
   needs them.
3. **Auxiliary log tier**: Sentinel introduced an auxiliary tier with
   substantially lower per-GB ingestion cost but higher query cost.
   Useful for tables we want for compliance but rarely query (audit
   logs primarily). Switch high-volume / low-query tables there once
   we understand our query patterns.

---

## 3. Storage and retention

* **Sentinel workspace retention.** Default 90 days; extendable to 730
  days. Beyond 90 days we pay a per-GB-month rate. For Email* tables we
  recommend 90 days hot, archive tier for 180+ days for compliance.
* **Defender XDR Advanced Hunting retention.** 30 days. This is the
  Microsoft-managed window inside Defender XDR; if we need longer, the
  tables must be ingested into Sentinel.
* **Action Center History.** 30 days in the UI. Longer history is in the
  Unified Audit Log.
* **Unified Audit Log.** 180 days default; 1 year with E5; 10 years with
  Audit Premium add-on.
* **Logic App run history.** Consumption: 90 days max; Standard: configurable
  via `RetentionInDays`. For long-running approval flows that span >90
  days, design escalation timeouts inside that window.

For SOC operations the practical retention we need:

* **Hot, queryable** (last 90 days): Sentinel hot tier.
* **Warm, occasionally queryable** (90 days to 1 year): Sentinel archive
  or Auxiliary tier.
* **Cold, compliance-only** (1 year to 7 years): blob storage export.

---

## 4. Graph throttling and API budgets

Recap of the limits that matter (full detail in
[`07-graph-and-exchange-remediation.md`](./07-graph-and-exchange-remediation.md) §1.3):

| Limit | Value | Implication |
|---|---|---|
| Global per app | 130k requests / 10s | Plenty for a single SOC tenant; design for it in MSSP scenarios |
| Outlook per-mailbox concurrency | 4 | Constrains Logic App ForEach concurrency to ~5 |
| Submissions API | 150 / 15-min | Bulk submissions need pacing |
| Defender XDR Take Action | 50 concurrent jobs, 1M cap, 40% recipient coverage rule, 50k batch recommended | Plan campaign storms accordingly |
| Compliance Search-Action | 10 items / mailbox / action | Loop or use Graph eDiscovery purgeData (100/location) |
| Tenant Allow/Block List | P1 1k/1k; P2 10k/5k entries per category | Be selective; do not dump every TI hit into TABL |

Build a Sentinel workbook that tracks daily Graph + Defender XDR API call
counts per playbook. This is the operational metric that tells us when
we are about to hit a wall.

---

## 5. SOC operating shape after migration

Drawing on the four pilot deployments we have observed:

| Metric | TRAP baseline | MDO + Sentinel (this blueprint) |
|---|---|---|
| Phish triage time per incident | 5 to 10 min | 2 to 5 min (Defender XDR portal is faster than TRAP UI for most cases) |
| MTTR for user-reported phish | 3 to 8 min | 2 to 5 min (AIR latency dominates, ~30 to 120s; Take Action fan-out 30 to 60s for ≤500 recipients) |
| Time to retract a 1000-recipient campaign | 5 to 15 min | 1 to 3 min (Defender XDR Take Action handles this in one API call) |
| False positive recovery | 1 to 3 min via TRAP UI undo | 1 to 3 min via Action Center undo |
| Analyst console count | TRAP UI + email gateway UI + SIEM | Defender XDR + Sentinel (+ optional Logic App run history viewer) |
| Daily SOC FTE for phishing | 0.5 to 1 FTE for 10k mailbox tenant | 0.3 to 0.7 FTE for 10k mailbox tenant |

The biggest contributor to the FTE saving is the unified Defender XDR
console replacing the TRAP UI plus the email gateway UI. Analysts spend
less time hopping between tools. The gain shows up in week 4 or 5 of the
parallel run, not immediately.

Where the operational picture gets worse, not better:

* **Investigating a "did it actually do what we wanted?" question for a
  Logic App run** is heavier than reading TRAP's per-incident activity
  list. Logic App run history is detailed but verbose. We invested in a
  Sentinel workbook that summarises run state per incident; it took 8
  hours of effort and was worth it.
* **First-week analyst comfort with Defender XDR portal** is uneven. Some
  analysts take to it immediately; some take 2 weeks. Plan training and
  pair-shifts.

---

## 6. Workbook recommendations

Sentinel workbooks worth building during Phase 1 and 2:

* **Email remediation summary**: counts of soft-delete, hard-delete, ZAP,
  TABL adds per day, sourced from `OfficeActivity` and `EmailPostDelivery
  Events`. Replaces the TRAP daily-actions report.
* **AIR queue health**: count of AIR investigations open / closed /
  recommendation-pending per hour. Surfaces the queue-depth issue
  documented in [`12-limitations-and-gaps.md`](./12-limitations-and-gaps.md) §12.
* **User reporter scoreboard**: KQL Q9 surfaced as a workbook tile. Helps
  the SOC identify who reports well and who reports a lot.
* **Logic App run health**: per-playbook run counts, success rate, average
  duration, P95 duration. Catches drift before it becomes an incident.
* **TI sweep effectiveness**: count of TI sweeps that resulted in
  remediation vs that were rejected by approver. Informs TI confidence
  threshold tuning.
* **Permission audit**: every app and account with mail.* or eDiscovery
  permissions. Refresh weekly. Flag drift.

The Microsoft `Azure-Sentinel` GitHub repo has starter workbooks for
several of these in the Solutions/SentinelSOARessentials and the
Solutions/MicrosoftDefenderForOffice365 trees.

---

## 7. Permissions ongoing review

Quarterly permissions review checklist:

* Every Entra app with `Mail.*`, `Mail-Advanced.*`, `ThreatSubmission.*`,
  `ThreatHunting.*`, `MachineActions.*` consented. Confirm scope is still
  needed and Application Access Policy (or RBAC for Applications scope) is
  still correct.
* Every service principal with EXO directory roles (Compliance Admin,
  Exchange Admin). Confirm assignment is justified.
* Every managed identity with workspace permissions. Confirm Sentinel
  Reader / Responder / Contributor scope is still appropriate.
* Search and Purge role group membership. Confirm the SOC L2/L3 tier
  membership is current (people leave; access does not).
* SecOps mailbox list in Advanced Delivery. Confirm only current SOC
  mailboxes are listed.
* PhishSim override list. Confirm only current simulation vendor IPs and
  domains are listed.

Most of these can be Sentinel hunting queries. Some of them have to be
manual portal walks because the underlying API is missing or unreliable.

---

## 8. Operational risk register

The top items the SOC director will want to see in the migration risk
register:

| Risk | Probability | Impact | Mitigation |
|---|---|---|---|
| Compliance Search-Action 10/mb cap blocks a large campaign remediation | Medium | High | Default to Defender XDR Take Action; reserve Compliance Search for legal/forensic cases; loop the action when needed |
| AIR queue saturation during a campaign storm | Low to Medium | Medium | Volumetric anomaly KQL fires; Sentinel scheduled hunting supplements AIR |
| Logic App ForEach concurrency exceeds Graph 4-per-mailbox cap | Medium | Low | Cap at 5; honour `Retry-After` |
| Sentinel ingestion cost overrun | Medium | Medium | Per-table opt-in; auxiliary tier for low-query high-volume tables |
| Built-in Outlook Report button rolls out unevenly across client versions | Medium | Low | Communicate; track add-in deprecation timeline; keep Microsoft Report Message add-in as fallback during transition |
| Approval connector dependency in Logic Apps fails (OAuth account locked, MFA challenge unhandled) | Medium | Medium | Switch to Teams adaptive cards (preferred); keep Outlook approval as fallback; password rotation calendar |
| EWS retirement (Oct 2026) breaks legacy custom integration | High | High if not migrated | Audit and migrate to Graph during 2025-2026 |
| ApplicationImpersonation residue creates audit finding | Medium | Low to Medium | Audit during Phase 5; remove all residue |
| Hybrid mailbox segment uncovered by ZAP/AIR | High in mixed tenants | Medium to High | Migrate mailboxes to EXO; if blocked, build small custom on-prem worker (dying technology, plan to retire) |

---

## 9. Cost summary

Rough monthly run-rate cost increase (over baseline M365 E5) for the full
architecture:

| Item | Cost (USD/month, 10k-mailbox tenant) |
|---|---|
| Sentinel ingestion (full table set) | 180 to 840 |
| Sentinel retention (90 days hot, archive thereafter) | 50 to 200 |
| Logic App Standard plan (1 instance, P0v3 SKU) | ~150 |
| Azure Function (Consumption, low usage) | <50 |
| Key Vault | <10 |
| Storage (run history exports) | <50 |
| **Total** | **~440 to 1300** |

Compared to TRAP licensing (typically priced per-user-per-year and varying
by procurement), a 10k-user TRAP licence runs in the range of low five to
low six figures USD/year. Replacing TRAP with this stack is typically a
**net cost reduction**, even before accounting for the SOC FTE savings.

For larger tenants the net savings compound. For smaller (<2k mailbox)
tenants the savings are smaller but the operational consolidation (one
console, one identity model, one audit trail) is still worth it.

---

## 10. What a "good" operational state looks like at month 6

If everything in this blueprint is working as designed, six months in we
should see:

* The SOC operates from one console (Defender XDR) for routine work and
  drops into Sentinel for hunting.
* AIR auto-remediates roughly 60-70% of high-confidence phishing
  incidents without human approval.
* Median user-reported-phish MTTR is under 5 minutes.
* TI sweep playbook is auto-approving roughly 70% of triggers (the
  KnownBad_Senders watchlist has matured).
* Reporter Thanks Bridge fires for 100% of user reports; reporter
  satisfaction surveys (if we do them) trend upward.
* The Logic App run-health dashboard shows consistent runs with no
  retry-storm or throttling spikes.
* The permissions review surfaces zero unauthorised additions.
* Sentinel ingestion cost is stable and within budget.
* The TRAP installation has been gone for four months and nobody asks
  about it.

If two or three of these are not true at month 6, revisit the relevant
phase output. Usually the gap is a tuning problem (analytics rule
threshold, automation rule condition) rather than an architecture problem.
