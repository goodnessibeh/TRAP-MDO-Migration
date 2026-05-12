# Limitations, Gaps, and Workarounds

The honest catalogue of what the Microsoft stack cannot do that TRAP can,
why, and the closest achievable workaround. Architects deserve to see this
up-front rather than discover it during an incident.

Where a gap has been called out elsewhere in this blueprint, the entry
here points at the canonical detail and adds the operational nuance we
have learned in pilot deployments.

---

## 1. External forward remediation

**What TRAP did:** followed forwards through internal mailboxes, including
the case where User A forwards a phish to User B's external address. TRAP
could not pull the external copy either, but it surfaced the leak so the
SOC knew about it.

**What MDO does:** the AIR cluster expands across recipients that
`EmailEvents` and Microsoft's fingerprint matching can find inside the
tenant. External recipients (the user who got the forward at their
@gmail.com address) are invisible to AIR. ZAP cannot help; ZAP only
operates on EXO mailboxes.

**Why it is impossible to fully close:** once mail crosses the tenant
boundary, Microsoft has no telemetry. Neither do we. The only thing we can
do is detect the leak and remove the on-going risk.

**Closest workaround:**

1. Detect auto-forward configuration changes early. KQL Q7 fires on
   `Set-Mailbox -ForwardingSmtpAddress` and on inbox-rule `ForwardTo` /
   `RedirectTo` changes. Promote to an NRT analytics rule with severity
   High and automation rule that disables the rule and forces password
   reset.
2. Block external forwards by mail-flow rule. The conservative posture is
   to require an admin exception per allowed external forward target,
   surfaced via the Exchange admin centre. This is operationally heavy but
   removes the leak class entirely.
3. For known incidents where external forwards happened, send notification
   to the original recipient asking them to follow up with the external
   recipient manually. Log the action in the incident comments. Hold the
   incident open until manual remediation is confirmed.

We have seen orgs accept this gap. The ones that do not have always ended
up implementing some variant of (2).

---

## 2. On-premises and hybrid mailbox remediation

**What TRAP did:** worked against on-prem Exchange 2010 to 2019 via EWS,
and against Exchange Online via EWS or Graph. A single TRAP install
covered hybrid estates uniformly.

**What MDO does:** ZAP and AIR do not operate on on-prem mailboxes.
Defender XDR Take Action only acts on EXO mailboxes. The on-prem segment
of a hybrid tenant is a coverage gap.

**Why it is impossible to fully close in MDO:** Microsoft's design point
is that protection moves to the cloud. ZAP, AIR, and Take Action are EXO
features.

**Closest workaround:**

* **Best long-term answer:** finish the mailbox migration to EXO. This is
  the path Microsoft expects. If you have on-prem mailboxes for technical
  reasons (legacy app integration, regulatory locality), plan for their
  migration alongside the TRAP retirement.
* **Tactical bridge:** keep a small Compliance Search-Action workflow that
  targets on-prem mailboxes via Exchange Hybrid topology and the Compliance
  Search "All locations" coverage. This works only for mailboxes that are
  reachable via the Hybrid topology and have proper EXO routing; it does
  not work for fully air-gapped on-prem Exchange.
* **Genuinely air-gapped on-prem:** run a small custom remediation agent
  on-prem, triggered by a webhook from a Logic App. The agent uses EWS
  Managed API with RBAC-for-Applications-equivalent permissions on the
  on-prem Exchange. This is dying technology (EWS retires October 2026 in
  EXO; the on-prem situation is similar) and we recommend against new
  builds. Migrate the mailboxes instead.

If you have a large on-prem estate and no migration plan, TRAP retirement
is the wrong project right now. Migrate first, then retire.

---

## 3. Cross-tenant remediation

**What TRAP did:** in a multi-tenant deployment with one TRAP server per
tenant, a single SOC could act against incidents across all tenants from
one console. Action lived per-tenant; visibility was unified.

**What MDO does:** Defender XDR multi-tenant view (with GDAP delegation)
shows incidents across delegated tenants, but Take Action requires
per-tenant context. Sentinel cross-workspace queries can show incidents
across tenants, but automation rules and playbooks live in a single
tenant.

**Why it is impossible in a single deployment:** no Microsoft remediation
API spans tenants in a single call. Mail.ReadWrite tokens are scoped to a
single tenant directory; Compliance Search-Action operates against a
single tenant's compliance namespace; Defender XDR Take Action API is
tenant-scoped.

**Closest workaround:**

1. **Per-tenant Sentinel + playbooks, central reporting.** Each tenant gets
   its own Sentinel workspace and its own copy of the playbook library.
   Logic Apps live in each tenant. Cross-tenant reporting is via Sentinel
   cross-workspace KQL or a central PowerBI workspace.
2. **Service-principal fan-out from a central tenant.** Build the central
   playbook in your management tenant. It calls Graph with a per-tenant
   service principal credential set held in Key Vault, iterating across
   tenants for actions. The cost is operational: every credential rotation
   touches every tenant; every new tenant onboard touches the central
   playbook config. We have seen this work at 5 tenants. We have not seen
   it work cleanly at 20+.
3. **Microsoft 365 Lighthouse** (for MSSPs) gives delegated security
   admin access; combine with Sentinel multi-workspace view and per-tenant
   playbooks. Lighthouse is light on automation primitives; expect to
   build them yourself.

For pure MSSP scenarios this is genuinely painful. For typical enterprise
M&A scenarios with 2 to 3 tenants, option (1) is good enough.

---

## 4. The 48-hour ZAP window

**What TRAP did:** retroactively retracted messages of any age, limited
only by mail retention. We've seen TRAP customers pull a TAP-condemned
message 30 days after delivery.

**What MDO does:** ZAP eligibility is hardcoded at **48 hours**: Beyond
that, ZAP does not fire. AIR can still operate (its lookback is the
`EmailEvents` retention window, defaulting to 30 days in Advanced
Hunting), and the SOC can still manually remediate via Defender XDR
Take Action or via Compliance Search-Action.

**Why hardcoded:** Microsoft's design assumption is that beyond 48 hours,
user behaviour has invalidated the assumption (user has read, replied,
forwarded, archived). Acting after that creates more harm than good in
the typical case.

**Closest workaround:** the TI sweep playbook (P2, backed by KQL Q5).
Schedule it every 30 minutes; on a TI feed hit, the playbook calls
Defender XDR Take Action across the affected cluster. This effectively
replaces ZAP for the >48h case but requires the message to still be
within the `EmailEvents` retention window (default 30 days) and on a
cloud mailbox. The action is identical to a manual analyst pull; ZAP is
just a faster path for the in-window case.

---

## 5. Compliance Search-Action 10-item-per-mailbox cap

**What TRAP did:** mass-pulled without per-mailbox caps. A campaign
delivering 50 messages to one mailbox was a one-shot remediation.

**What MDO does:** `New-ComplianceSearchAction -Purge` is capped at 10
items per mailbox per action. Defender XDR Take Action API does not
have this cap (200k message cap instead).

**Why:** Compliance Search-Action is documented as an "event response
tool", not a bulk-cleanup tool. The cap is intentional.

**Closest workaround:** loop the search-action cycle. After each action,
re-run the search; if `EstimatedItems > 0` per mailbox, action again. In
practice this rarely needs more than 2 to 3 iterations for typical
campaigns. For larger cases, switch to Graph eDiscovery `purgeData`
(100/location) or use the Defender XDR Take Action API path. The latter
is preferable because it gives you Action Center visibility for free.

If you find yourself looping more than 3 times, you picked the wrong tool.
Move to Take Action.

---

## 6. Logic App Office 365 Outlook connector per-user OAuth

**What TRAP did:** ran as a service. No per-user OAuth dependency for the
abuse-mailbox poll.

**What MDO does:** Logic Apps' Office 365 Outlook connector requires a
per-user OAuth connection. Service principal and managed identity are not
supported. Any playbook that reads/sends mail through Outlook needs a SOC
service mailbox with a real OAuth-capable account behind it.

**Why:** the connector was built on the Microsoft Graph for Outlook surface
that pre-dates first-class app-only mail consent. Microsoft has not
back-fitted.

**Closest workaround:**

* For sending mail from a playbook (the "thanks for reporting" case), use
  Graph `POST /users/{soc-mailbox}/sendMail` via HTTP+MI, not the named
  connector. Permission: `Mail.Send` on the SOC mailbox, scoped via
  Application Access Policy or RBAC for Applications.
* For polling a shared abuse mailbox, the only supported pattern is the
  named connector with per-user OAuth. Use a dedicated service account,
  exclude from CA policies that require interactive MFA, and store the
  account's password in a vault that the team rotates quarterly. This is
  an unsatisfying answer; it is the supported one.

---

## 7. Reporter "thanks" coverage gaps

**What TRAP/CLEAR did:** every disposition triggered a notification to
the reporter; the notification was always sent.

**What MDO does:** AIR Auto Feedback Response sends the verdict-back email
on investigation close. If the message was already remediated before AIR
fired, the investigation closes with no actions and the notification does
not go. The user is left without acknowledgement.

**Closest workaround:** the Reporter Thanks Bridge Logic App (P3,
documented in the MVP guide). One playbook, fewer than 5 actions. Closes
the gap completely.

---

## 8. Read-status visibility at TRAP fidelity

**What TRAP did:** showed pre-pull `IsRead` per recipient in the incident
activity list. Direct, immediate, in the UI.

**What MDO does:** `EmailEvents` does not include read state. To get it,
fan out across recipients via Graph `/messages?$select=isRead`. Aggregated
into a Sentinel workbook this is functional but not as immediate as the
TRAP UI.

**Closest workaround:** KQL Q6 + a small Logic App. Returns read-state
per recipient as a workbook tile, lookup-able from any incident.

If your SOC really values having read-state in the incident UI itself,
consider building a custom Defender entity-page extension via the Graph
custom-pages model. We have not built one; it is in the realm of doable
custom development.

---

## 9. Submissions API is /beta

**Status today:** `POST /security/threatSubmission/emailThreats` is
documented under `/beta` only. v1.0 promotion is pending.

**Operational implication:** Microsoft's general guidance is "production
use cautioned" for /beta endpoints. They can change in breaking ways with
limited notice.

**What to do:** wrap the Graph call in your own thin client library so a
schema change requires one update, not a sweep across every playbook.
Watch the Microsoft Graph release notes for v1.0 promotion. When it
happens, switch in a single deployment.

---

## 10. AIR's narrow auto-action set

**What TRAP did:** auto-applied move/quarantine/hard-delete based on
admin policy, with optional approval.

**What MDO does:** AIR auto-actions are **soft delete only** (after 2025
GA, auto-approved for malicious URL and file similarity clusters). There
is no auto hard-delete, no auto move-to-junk-from-cluster, no auto
block-sender from AIR.

**Closest workaround:** if you want auto-hard-delete, build it in a
playbook. Sentinel automation rule fires on incident, playbook runs
Defender XDR Take Action with `hardDelete`. Keep an approval gate if your
governance requires one.

---

## 11. GCC, GCC High, and DoD clouds

**What TRAP did:** supported air-gapped clouds.

**What MDO does:** the Graph `threatSubmission` API is **not available**
in GCC L4/L5, DoD, or 21Vianet. The *Send to Microsoft* path is unavailable
in those clouds; only *My reporting mailbox only* is allowed.

**Closest workaround in GCC clouds:**

* Custom abuse-mailbox ingestion path (Playbook P7).
* No Microsoft grader verdict feedback. Build your own grader workflow if
  you need verdict cycling; otherwise live with admin-only verdict.
* Confirm the Defender XDR Take Action API is available in your specific
  national cloud variant before relying on it for remediation. Coverage
  varies and changes.

---

## 12. AIR concurrent-investigation queue depth

**What TRAP did:** scaled per the Proofpoint pull workers, configurable.

**What MDO does:** Microsoft does not publish a numeric cap on concurrent
AIR investigations. Field-observed behaviour is that queues fall behind
during campaign storms (>50 simultaneous investigations).

**Operational implication:** during a storm, AIR remediation latency goes
from seconds to minutes to "this is taking too long". Your SOC needs a
fallback.

**Closest workaround:**

* Volumetric anomaly KQL (Q11) fires on storm detection. Severity High,
  pages on-call.
* Sentinel scheduled hunting query (Q1 + Q3) supplements AIR. If AIR has
  not produced a recommended action within 5 minutes, the Sentinel
  playbook fires the same Take Action API call directly. We saw this
  pattern in two of three pilot deployments; it is worth building.

---

## 13. ApplicationImpersonation residue

**What changed in 2024-2025:** Microsoft removed the
`ApplicationImpersonation` RBAC role from Exchange Online (final cutoff
March 13, 2025). Apps that relied on it broke unless reconfigured to use
RBAC for Applications and EWS app-only OAuth (or migrated to Graph).

**Operational implication for TRAP-era estates:** if you migrated TRAP to
the new model during 2024, you likely have stale scope assignments,
half-migrated app registrations, and Application Access Policies that
either grant too much or have not been reviewed.

**What to do:** as part of Phase 5 decommission, audit:

* `Get-ApplicationAccessPolicy` for any policy referencing the TRAP app
  registration. Remove.
* `Get-ManagementRoleAssignment` for any RBAC for Applications assignments
  to the TRAP service principal. Remove.
* Remove the app registration itself.
* Audit Entra app consent grants for any `Mail.*` permissions still held
  by the TRAP app. Revoke explicitly.

Even if the TRAP app is dormant, leaving the access in place creates an
audit-friction issue and a residual blast-radius problem.

---

## 14. EWS retirement (October 2026)

**Status:** Microsoft has announced full EWS retirement in EXO by October
2026.

**Implication for any custom integration:** anything using EWS today must
move to Microsoft Graph before October 2026. This includes legacy TRAP-
era abuse-mailbox pollers if you have any custom ones, custom mass-action
scripts, and third-party SOAR tools that integrate via EWS.

**What to do:** track Microsoft's official EWS deprecation page. Build
Graph-equivalent replacements during 2025-2026. Plan a final cutover in
Q2 2026 to leave headroom for surprises.

---

## 15. The Mail-Advanced.ReadWrite Graph scope (December 2026)

**Status:** from December 31, 2026, Microsoft will require the elevated
**`Mail-Advanced.ReadWrite`** Graph permission for apps that modify
*sensitive properties* on delivered messages (headers, internet message
ID, envelope-level data).

**Implication:** any worker that mutates header-level properties (rare,
but forensic preservation tools do this) needs to request the new scope.

**What to do:** if your playbooks only soft-delete or hard-delete
messages, you do not need this scope. If you have a custom worker that
modifies headers (X-headers for tagging, modification of subject
prefixes), plan to request the new scope before Dec 2026.

---

## Summary

What TRAP genuinely could do that MDO genuinely cannot:

1. **External forward remediation** (telemetry boundary, no fix possible).
2. **Cross-tenant remediation in one call** (API boundary, no fix possible).
3. **On-prem mailbox remediation in the same console** (architectural;
   workaround exists but is dying technology, plan to migrate mailboxes).

Everything else has a workaround in this blueprint. None of the
workarounds are free; the ones that matter are documented in the playbook
library and roadmap. The work is finite and the maintenance cost is
known.
