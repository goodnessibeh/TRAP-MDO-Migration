# Implementation Roadmap

A phased plan to retire Proofpoint TRAP and stand up the Microsoft
equivalent. The shape is conservative: native MDO first, then parallel run
against TRAP, then engineering layered on top once we know what gaps are
worth closing.

We treat this as urgent. There is no calendar in this document. We move
each phase as fast as it can go without losing the safety net of TRAP
behind us. The gating criteria below tell us when to advance, not how long
to wait.

---

## Phase 0. Pre-flight

**Goal:** know what we have, get the licences right, get the people in a
room.

What we do:

* Inventory the current TRAP deployment. Capture the configured Exchange
  server entries, the abuse mailbox addresses, the active list types and
  their contents, the SOAR integrations (XSOAR, Splunk, QRadar), the SIEM
  forwarding configuration, the audit-trail export schedule, and the
  service-account / app-registration configuration. We need this when
  wiring the parallel run in Phase 2.
* Audit MDO licensing. Run `Get-MgUserLicenseDetail` across the user base
  and confirm MDO P2 (or M365 E5) is assigned to every mailbox we want
  protected. MDO P1 alone is not enough; AIR, Campaigns, and Threat
  Explorer remediation actions all require P2.
* Audit hybrid posture. `Get-Mailbox -ResultSize Unlimited |
  Group-Object RecipientTypeDetails`. Anything not in EXO is out of scope
  for ZAP and AIR; we need a separate plan for it (see
  [`12-limitations-and-gaps.md`](./12-limitations-and-gaps.md) §2 and the
  open questions doc).
* Decide the migration steward. One named person owns the migration.
  Trying to run this by committee fails reliably.
* Pull historic incident data out of TRAP if compliance requires it.
  PTR's `/api/incidents` is the canonical export; iterate over the 30-day
  windows the API allows. Stash the export in blob storage. We do not
  re-import it into Sentinel unless an auditor asks. Most do not.

**Exit criteria:**

* MDO P2 confirmed on >=99 % of in-scope mailboxes.
* Inventory of TRAP configuration documented and shared.
* Migration steward named, executive sponsor confirmed.
* Decision recorded on whether to migrate historic TRAP incident data.
* Hybrid scope decision recorded (see open questions doc).

---

## Phase 1. Out-of-the-box deployment

**Goal:** stand up the MDO baseline and validate it, while TRAP keeps
running unchanged.

This is the
[`00-MDO-out-of-the-box-deployment-guide.md`](./00-MDO-out-of-the-box-deployment-guide.md)
work in full. Summary of what changes in our tenant:

* Strict preset (or tuned equivalent) applied to anti-phish, anti-spam,
  anti-malware, Safe Links, Safe Attachments.
* ZAP confirmed enabled across all three policy families.
* User-reported settings configured: built-in Outlook Report button,
  custom reporting mailbox in EXO, AIR Auto Feedback Response on for all
  three verdicts.
* Reporting mailbox added to SecOps overrides and excluded from DLP.
* Sentinel workspace provisioned and connected to Defender XDR (incidents
  and alerts plus the small `EmailEvents` / `EmailPostDeliveryEvents` /
  `AlertInfo` / `AlertEvidence` table set).
* Search and Purge role assigned to the Data Investigator role group.
* Reporter Thanks Bridge Logic App deployed (one playbook, fewer than 5
  actions).

What does **not** change in this phase:

* TRAP keeps running. Reporters who hit the legacy PhishAlarm button still
  flow into TRAP normally.
* The existing SOAR integration into TRAP keeps working.
* No engineered enhancements (forward-tracking, DL expansion, TI sweep,
  VAP scoring) yet.

**Validation tests** are T1 to T7 in the OOTB deployment guide. All seven
must pass before we exit Phase 1. If T2 (user-reported phish to AIR)
intermittently fails to fire, the most likely cause is the
`Auto-Resolve - Email reported by user as malware or phish` alert tuning
rule still being enabled.

**Exit criteria:**

* T1 to T7 functional tests pass.
* OOTB deployment and TRAP both operating; no protection gap during the
  dual-run period.
* Defender XDR Action Center showing typical incident volume for our
  environment.

---

## Phase 2. Parallel run and observation

**Goal:** prove the MDO stack matches or beats TRAP across our real
incident corpus, before turning anything off.

What we do:

* Both stacks live for the entire phase. Reporters using PhishAlarm end up
  in TRAP; reporters using the built-in Outlook Report button end up in
  MDO. Instrument both surfaces and reconcile incident counts daily.
* Capture a realistic sample of incidents under both stacks. The shape
  matters more than the duration: the sample must contain a representative
  mix of user-reported phish, ZAP retroactive removals, IOC sweeps, and
  any DL or VIP cases that historically hit TRAP. Until that mix is
  represented in the parallel data, we have not seen enough to compare
  honestly.
* Track per-incident:
  - Total reported messages per stack
  - Mean time to remediation per stack
  - False positive rate per stack
  - Analyst minutes spent per incident per stack
  - Recipient coverage achieved per stack (TRAP forward-following will
    win here; capture the delta honestly)
* Build a Sentinel workbook that lays both numbers next to each other.
  Workbook design notes in
  [`13-licensing-and-operations.md`](./13-licensing-and-operations.md).
* Identify the cases where MDO under-performed TRAP. The usual list:
  - Retroactive sweeps where ZAP cannot help (older than 48 h)
  - Forward-following beyond cluster expansion
  - DL fan-out where TRAP enumerated the membership and Microsoft did not
  - Reporters who did not get a thank-you because AIR closed before
    Auto Feedback fired (the Thanks Bridge handles this; confirm it does)
  - VIP-touching incidents where we wanted higher severity automatically
* Decide which Phase 3 enhancements we actually need based on the
  observed gaps, not on the comprehensive list.

What does not change yet:

* TRAP is still running. We do not decommission anything.
* The Phase 3 engineering work has not started (or has only started for
  the most obvious gaps).

**Exit criteria:**

* Side-by-side data captured covering a representative incident mix.
* Documented list of cases where MDO under-performed, with severity rating
  (blocking vs nice-to-have).
* SOC analysts comfortable with the Defender XDR portal and Action Center.
* Decision made on which Phase 3 enhancements to build.

---

## Phase 3. Engineering enhancements

**Goal:** close the specific gaps Phase 2 surfaced. Do not build for
hypothetical needs.

The work breaks into independent workstreams. We run them in parallel
where capacity allows. Order is by typical impact: TI sweep first (it
covers the >48 h ZAP gap, which is Phase 2's most common complaint),
forward-trace and DL expansion next, the rest as needed.

| Workstream | Document |
|---|---|
| TI sweep playbook (Q5 + P2) | KQL Q5, Playbook P2 |
| VAP scoring and automation rule | Sentinel SOAR §4 |
| Forward-trace remediation (Q4 + P4) | KQL Q4, Playbook P4 |
| DL expand remediation (Q8 + P5) | KQL Q8, Playbook P5 |
| Two-stage approval for VIP (P6) | Playbook P6 |
| Reporter precision scoreboard (Q9) | KQL Q9 |
| Read-state per recipient (Q6 + helper Function) | KQL Q6 |
| Custom abuse-mailbox ingestion (P7) | User-reported §8.2 (only if needed) |

**Engineering rules during this phase:**

* Work in source control. Logic App workflow JSON belongs in git, deployed
  via ARM/Bicep. Hand-edited workflows in the portal are a maintenance
  trap.
* Deploy each workstream behind a feature toggle. We use a Sentinel
  watchlist `EnabledPlaybooks` keyed on playbook name with an
  `enabled: true|false` column. Lets us roll back without redeploying.
* Each playbook ships with a runbook page in our SOC wiki. The page
  documents what the playbook does, what entities it expects, what
  permissions it needs, and what the rollback looks like.
* Test against staged Sentinel incidents that mirror real entity shapes.
  Synthetic test incidents miss too much.

**Exit criteria:**

* Selected enhancements live and exercised against real or staged
  incidents.
* All playbooks idempotent: replaying the same incident does not
  double-act.
* Permissions reviewed and least-privilege enforced.
* Audit logging confirmed end to end (Logic App run history visible in
  Sentinel `LogicAppsLog`, Defender XDR Action Center History showing the
  remediation steps).

---

## Phase 4. Cutover

**Goal:** flip the canonical reporting path from PhishAlarm to MDO, retire
the TRAP-side processing of reports, keep TRAP installed but quiet as a
rollback option.

What we do:

* Communicate to all users in advance. The user-visible change is small
  (the Outlook Report button looks slightly different) but some users
  will notice and need a heads-up.
* Disable the PhishAlarm add-in deployment from tenant management. New
  reports flow through the built-in Report button only.
* Disable the TRAP abuse-mailbox poller. Do not delete the abuse mailbox;
  keep it around for the parallel-run rollback option.
* Update the SOC runbook so the canonical incident workflow is the
  Defender XDR portal and Sentinel, not the TRAP UI.
* Migrate any TRAP TI lists that are not yet replicated in TABL or
  Sentinel watchlists.
* Update any external SOAR integrations (XSOAR, Splunk SOAR) to point at
  Sentinel and Defender XDR APIs instead of the TRAP REST API.
* Confirm with our monitoring team that incident volume and MTTR
  dashboards are now sourced from Sentinel.

What does NOT change yet:

* TRAP itself remains installed and licensed. We can re-enable the
  abuse-mailbox poller within an hour if Phase 4 turns up an unexpected
  problem.

**Exit criteria:**

* Built-in Report button is the only reporting surface end users see.
* TRAP poller off; TRAP installation idle.
* SOC runbook updated and referenced.
* External SOAR integrations re-pointed.
* No incident-handling regression observed across a sample of fresh
  incidents the SOC accepts as representative.

---

## Phase 5. Decommission

**Goal:** remove TRAP and clean up the residual configuration in
Exchange and Entra.

What we do:

* Cancel the Proofpoint TRAP licence.
* Remove the TRAP service account from Exchange / Entra. If it had RBAC
  for Applications role assignments, remove them. If the service account
  is dual-purpose, sanitise it carefully.
* Remove the TRAP app registration in Entra.
* Remove the SecOps mailbox / quarantine mailbox addresses TRAP used (if
  not also used by the OOTB deployment).
* Remove any `New-ApplicationAccessPolicy` that scoped TRAP's `Mail.*`
  access.
* Archive the TRAP installation logs and audit trail to long-term storage.
* Update vendor risk register and SOC tool inventory.

What does NOT need cleanup:

* Mail-flow rules that route reports to the abuse mailbox (the same
  mailbox is now used by the Defender custom-mailbox path).
* PhishAlarm reports already submitted into TRAP (they remain in the TRAP
  archive; the audit trail is preserved by the export from Phase 0).

**Exit criteria:**

* TRAP licence cancelled, app uninstalled.
* Service account removed.
* Documentation updated.
* No residual Proofpoint references in tenant configuration.

---

## Sequencing rules (the only schedule we keep)

We do not commit to a calendar; we commit to gates. The sequencing rules
that matter:

* Phase 1 cannot start until Phase 0 exit criteria are met.
* Phase 2 cannot start until Phase 1 T1 to T7 are green.
* Phase 3 can run in parallel with Phase 2; it should not gate Phase 2's
  observations.
* Phase 4 cannot start until Phase 2 has a representative incident sample
  and the Phase 3 workstreams the SOC flagged as blocking are live.
* Phase 5 cannot start until Phase 4 has been stable across a sample of
  fresh incidents the SOC accepts as enough.

If a phase blocks, the question is what is blocking it, not how long it
will take to unblock. Track blockers as separate tickets; do not bake
them into a roadmap timeline.

---

## Dependencies and risks

A few things that have killed migrations elsewhere:

* **License gap.** A pocket of mailboxes assigned MDO P1 instead of P2.
  Catch in Phase 0; the alternative is finding out in Phase 2 when AIR
  silently fails to investigate those users' reports.
* **ApplicationImpersonation residue.** If TRAP was migrated to RBAC for
  Applications during 2024, lingering scope assignments may give a
  defunct app more access than expected. Audit and clean up before
  Phase 5.
* **Conditional access for the Outlook approval connection.** The OAuth
  account used for Logic App approvals will trip CA policies that
  require MFA or device compliance. Either exclude the account
  explicitly, or switch to Teams adaptive cards (recommended).
* **Compliance / legal sign-off on hard delete.** Some teams require
  legal approval before any hard-delete. Bake this into Playbook P1 with
  a conditional approval step rather than soft-delete-by-default.
* **Reporter behaviour change.** Some users who liked the PhishAlarm
  button get confused by the built-in Report button. Plan an internal
  comms cycle and a lunch-and-learn for power users.
* **SOC analyst muscle memory.** Analysts need real reps in Defender XDR
  Action Center as the primary console before we can declare Phase 2
  done. Build that exposure into the parallel run.
* **Hybrid mailbox segment.** ZAP and AIR do not act on on-prem
  mailboxes. If we still have on-prem mailboxes in scope, see the open
  questions doc and resolve before Phase 4.

---

## Rollback strategy

Each phase has a clean rollback:

* **Phase 1 to 4 rollback:** disable the Logic App playbooks and
  re-enable the TRAP abuse-mailbox poller. The dual-run posture means
  TRAP has been receiving its own copy of reports throughout; nothing is
  lost.
* **Phase 5 rollback:** TRAP is gone. The last point of safe rollback is
  the start of Phase 5. After cancellation, re-onboarding TRAP is a
  vendor-side procurement and a non-trivial reinstall.

We keep TRAP in the install-but-quiet state through Phase 4 and into the
early stability window of Phase 5. If nothing has gone wrong by the time
the Phase 5 exit criteria are met, we proceed to cancel the licence.
