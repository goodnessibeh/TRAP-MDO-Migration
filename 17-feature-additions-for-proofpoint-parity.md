# Re: Additional MDO features required to match Proofpoint (TRAP/CLEAR)

Hi [Name],

Thanks for your email. As requested, below is the list of the additional
features we are building on top of Microsoft Defender for Office 365 (MDO)
to match the Proofpoint TRAP/CLEAR functionality that MDO does not provide
natively, set out in the table format you asked for so you can review,
agree what is required for Day 1, and fold the agreed items into the
overall project plan.

A few notes before the table so the scope is clear:

- MDO covers most of what TRAP/CLEAR did out of the box (Report button,
  Safe Links/Attachments, ZAP, AIR, Campaigns, Take Action, Tenant
  Allow/Block List). Those are enabled by configuration during Phase 1 and
  are not listed below, because they ship with the licence and are not
  "additions". The table is only the engineered layer (Logic App
  playbooks, Sentinel analytics rules, watchlists, Function Apps, and
  mail-flow controls) that we have to build to close the remaining gaps.
- The final column ("Critical vs Maturity") is my engineering
  recommendation for your review, not a decision already taken.
  "Critical for roll-out" means it is needed for functional parity with
  TRAP/CLEAR before Proofpoint is decommissioned; if we skip it, the SOC is
  measurably behind where it is today at cutover. "Maturity enhancement"
  means it improves the platform beyond TRAP parity, or is only required
  under a specific condition (VIP tiering, multi-tenant, legacy clients),
  and is safe to schedule after parity is reached.
- The full designs already exist in the blueprint; this is the one-page
  summary for prioritisation. Detail sits in
  [`10-logic-apps-playbook-library.md`](./10-logic-apps-playbook-library.md),
  [`12-limitations-and-gaps.md`](./12-limitations-and-gaps.md), and
  [`03-trap-capability-matrix.md`](./03-trap-capability-matrix.md).

| Feature Name | Description and Implementation process | Critical for roll-out OR maturity enhancement |
|---|---|---|
| **Reporter Thanks Bridge** (Playbook P3) | Guarantees every user who clicks the Report button gets an acknowledgement. MDO's native AIR Auto-Feedback only fires if an investigation closes *with* actions, so if the message was already remediated, the reporter hears nothing. **Implementation:** Logic App (Standard) triggered by the "Email reported by user" Sentinel incident; sends a "thanks for reporting" mail from the SOC service mailbox via Graph `sendMail`. Roughly 5 actions. Ships during Phase 1. | **Critical for roll-out.** Closes a CLEAR parity gap; without it reporters lose acknowledgement they have today. |
| **TI-Sweep Remediation** (Playbook P2) | Retroactively pulls already-delivered mail when a threat-intel indicator matches, beyond ZAP's hard 48-hour window (TRAP had no time limit). **Implementation:** scheduled Sentinel analytics rule (KQL Q5) joins `EmailEvents` against threat-intel indicators every 30 min, raises an incident, a Logic App posts a Teams approval card, and on approval it calls the Defender XDR Take Action API (soft-delete) and blocks the IOCs in the Tenant Allow/Block List. Auto-approve path for repeat-bad senders. | **Critical for roll-out.** Replaces ZAP for the over-48h case, the single biggest remediation gap versus TRAP. |
| **Forward-Trace Remediation** (Playbook P4) | Follows a phish through internal forwards and redirects and pulls every internal copy; detects (but cannot pull) external forwards and flags them. **Implementation:** Logic App runs hunting query Q4 to enumerate forwarded copies, soft-deletes each via the Take Action API, then a second query flags external forwards to the SOC for manual follow-up. | **Critical for roll-out.** Internal forward-following is core TRAP behaviour. The residual external-forward gap is a telemetry boundary no tool can close. |
| **Phish-Remediate workhorse** (Playbook P1) | The core automated remediation orchestration: takes a phish incident, enumerates recipients, and pulls the message tenant-wide with the right tool for the volume. MDO gives the *manual* Take Action wizard natively; this automates it end-to-end the way TRAP did. **Implementation:** Sentinel incident trigger, recipient enumeration (Q1), volume switch (10 or fewer / 11 to 200 / over 200 hands off to P1b), Take Action API soft-delete, URL-click correlation (Q2), then incident comment plus Teams summary. Single-stage approval, soft-delete default. | **Critical for roll-out.** This is the automated pull that replaces TRAP's auto-remediation. (Manual Take Action covers Day 1; P1 is needed for parity before decommission.) |
| **Phish-Remediate-Bulk** (Playbook P1b) | Companion to P1 for large campaigns that exceed direct-API thresholds (over 200 recipients or over 10 messages per mailbox, where the Compliance Search-Action 10-item cap bites). **Implementation:** HTTP-callable paginator; chunks of 50 with a 12-second inter-chunk delay; falls back to a Compliance Search loop where Take Action is unavailable. | **Critical for roll-out.** Ship alongside P1; without it, large campaigns hit the per-mailbox cap and remediation stalls. |
| **External auto-forward detection and block** (Sentinel rule Q7 plus mail-flow rule) | TRAP surfaced data leaks via forwards; the only way to close the external-forward class in MDO is to prevent and detect it. **Implementation:** near-real-time Sentinel analytics rule on `Set-Mailbox -ForwardingSmtpAddress` and inbox-rule `ForwardTo`/`RedirectTo` audit events (severity High; automation rule disables the rule and forces password reset), plus an Exchange mail-flow rule that blocks external auto-forward by default with per-exception approval. | **Critical for roll-out.** Our gap analysis shows organisations that do not simply accept the leak class always end up implementing this; it is the mitigation for the un-closeable external-forward gap. |
| **VIP / Two-Stage Approval** (Playbook P6) | Adds a tiered human-approval gate for actions touching VIP mailboxes (TRAP supported approval queues). **Implementation:** Sentinel incident condition checks the `VIP_Users` watchlist, sends a Teams adaptive-card approval to SOC L1, escalates to SOC Manager / Legal on timeout or escalate, and logs every state transition to a custom Sentinel `ApprovalAudit_CL` table. HTTP-callable from P1. | **Maturity enhancement** *(conditional: Critical if you operate a VIP tier or tiered-approval governance model).* Native Action Center "Pending actions" covers single-stage approval on Day 1. |
| **DL-Expand-Remediate** (Playbook P5) | Confirms full coverage when a phish was sent to a distribution list, including nested DLs (TRAP did recursive DL expansion). **Implementation:** Logic App resolves members via Graph `transitiveMembers` (500-member safety cap), confirms delivery per member (Q8), then runs Take Action on the cluster. | **Maturity enhancement** *(conditional: Critical only if your incident corpus shows DL fan-out).* Take Action already fans out across the message cluster natively; this adds audit-grade coverage proof. |
| **Reporter / VAP prioritisation** (Sentinel watchlist plus automation rule) | Boosts incident severity based on who reported or who was targeted (TRAP's VAP scoring). **Implementation:** `VIP_Users` and `Frequent_Reporters` watchlists drive automation-rule severity adjustment and reporter-volume throttling. | **Maturity enhancement.** A prioritisation and quality-of-life improvement, not a parity blocker. |
| **Read-status visibility** (KQL Q6 plus Logic App into workbook) | Shows whether each recipient had read the message before it was pulled (TRAP showed this inline in the incident UI). MDO's `EmailEvents` lacks read state. **Implementation:** Logic App fans out per recipient via Graph `/messages?$select=isRead` (app-only `Mail.Read`, scoped by Application Access Policy) and aggregates into a Sentinel workbook tile. | **Maturity enhancement.** Useful investigation context; not required to remediate. |
| **Auto-hard-delete playbook** (extension of P1) | AIR's native auto-action set is soft-delete only; this adds policy-gated automatic hard-delete for high-confidence clusters (TRAP supported auto hard-delete). **Implementation:** Sentinel automation rule calls the Take Action API with `hardDelete`, behind an approval gate per governance. | **Maturity enhancement.** Soft-delete default is the deliberately conservative baseline; hard-delete automation is an opt-in escalation. |
| **AIR storm fallback** (Sentinel rule Q11 plus scheduled hunt) | Resilience for campaign storms where AIR's investigation queue falls behind (over 50 simultaneous). **Implementation:** volumetric-anomaly analytics rule (severity High, pages on-call) plus a scheduled hunt (Q1 and Q3) that fires the same Take Action call directly if AIR has not produced a recommended action within 5 minutes. | **Maturity enhancement.** Operational resilience; matters at scale, not for Day 1 parity. |
| **Custom campaign clustering** (KQL Q3 plus workbook) | Analyst-defined clustering heuristics beyond the native Campaigns view (TRAP allowed custom clustering). **Implementation:** KQL grouping on hashed subject, sender domain, URL host, and attachment hash, persisted in a Sentinel workbook for history beyond the 30-day Campaigns window. | **Maturity enhancement.** Native MDO Campaigns view covers the common case. |
| **Incident enrichment playbooks** (per F7) | Auto-attaches VirusTotal, MDTI, AbuseIPDB, and WHOIS context to incidents (TRAP enrichment). **Implementation:** Sentinel automation rule calls Logic App connectors and posts the enrichment as an incident comment. Starter patterns in the Azure-Sentinel repo. | **Maturity enhancement.** The Defender entity page already provides native sender, URL, and file intelligence on Day 1. |
| **Submissions API thin-client wrapper** | Hardens our use of the Graph `threatSubmission` API, which is currently `/beta` only and may change. **Implementation:** wrap the Graph call in one internal client library so a schema change is a single update, not a sweep across playbooks. | **Maturity enhancement.** Engineering hygiene and future-proofing, not user-facing parity. |
| **Custom Abuse-Mailbox Ingest** (Playbook P7) | Polls a shared abuse mailbox, submits to Microsoft via Graph, and replies with thanks, for environments the built-in Report button cannot reach. **Implementation:** Logic App with the Office 365 Outlook connector (per-user OAuth on a SOC service account) polls the mailbox, submits via Graph, and replies. | **Maturity enhancement** *(conditional: only needed for legacy clients or hybrid mailboxes that cannot use the built-in Report path).* Most modern tenants do not need it. |
| **Cross-tenant remediation fan-out** (per I2/I3) | Single-console action across multiple tenants (TRAP-per-tenant plus a unified SOC). No Microsoft API spans tenants in one call. **Implementation:** per-tenant Sentinel and playbook copies with central reporting, or a central service-principal fan-out from a management tenant. | **Maturity enhancement** *(conditional: only relevant if we run a multi-tenant or MSSP estate; not applicable to a single-tenant rollout).* |

**My recommended Day 1 set (for your sign-off)**

If you agree with the recommendation, the Critical-for-roll-out rows are
the parity-before-decommission set:

1. Reporter Thanks Bridge (P3): Phase 1.
2. TI-Sweep Remediation (P2): Phase 3, build first.
3. Forward-Trace Remediation (P4): Phase 3.
4. Phish-Remediate workhorse (P1) plus Phish-Remediate-Bulk (P1b): Phase 3, after P2/P4 are stable.
5. External auto-forward detection and block (Q7 plus mail-flow rule): Phase 1 to 2 (config plus analytics rule).

Everything else is recommended as a maturity enhancement, or is conditional
on a specific environment characteristic (VIP tiering, a DL-heavy incident
corpus, a multi-tenant estate, or legacy clients). Could you confirm which
of those conditionals apply to our environment, so I can move the relevant
ones into the Day 1 set?

Build order, dependencies, and phase mapping for all of these sit in
[`11-implementation-roadmap.md`](./11-implementation-roadmap.md), and the
shipped-template status is tracked in
[`automation/logic-apps/README.md`](./automation/logic-apps/README.md).
Happy to walk through any of it on a call.

Thanks,

Goodness
