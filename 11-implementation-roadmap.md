# Implementation Roadmap

A phased plan to retire Proofpoint TRAP and stand up the Microsoft
equivalent. The shape is conservative: native MDO first, parallel run for
weeks, then engineering layered on top. The total calendar window is 12 to
16 weeks for a typical 5k to 25k mailbox tenant. Larger and multi-tenant
estates take longer; the gating constraint there is identity model
migration rather than configuration work.

The phases are deliberately ordered so that you have a working safety net
at every step. At no point are you flying without one of either TRAP or the
MDO MVP.

---

## Phase 0. Pre-flight (Week 0, 1 to 2 weeks)

**Goal:** know what you have, get the licences right, get the people in a
room.

What to do:

* Inventory current TRAP deployment. Capture the configured Exchange server
  entries, the abuse mailbox addresses, the active list types and their
  contents, the SOAR integrations (XSOAR / Splunk / QRadar), the SIEM
  forwarding configuration, the audit-trail export schedule, and the
  service-account / app-registration configuration. Save this somewhere
  the migration team can reference; you will need it when wiring the
  parallel run in Phase 2.
* Audit MDO licensing. Run `Get-MgUserLicenseDetail` across your user base
  and confirm MDO P2 (or M365 E5) is assigned to every mailbox you want
  protected. Note that MDO P1 alone is not enough; AIR, Campaigns,
  Threat Explorer remediation actions all require P2.
* Audit hybrid posture. `Get-Mailbox -ResultSize Unlimited |
  Group-Object RecipientTypeDetails`. Any mailbox that is not in EXO is
  out of scope for ZAP and AIR; you will need a separate plan for it
  (see [`12-limitations-and-gaps.md`](./12-limitations-and-gaps.md) §2).
* Decide the migration steward. One named person owns the migration
  programme. Trying to migrate by committee fails reliably.
* Pull the historic incident data out of TRAP if you need it for compliance.
  PTR's `/api/incidents` is the canonical export; iterate over the 30-day
  windows that the API allows. Stash the export in blob storage; you do
  not need to re-import it into Sentinel unless an auditor asks. Most do
  not.

**Exit criteria:**

* MDO P2 confirmed on >=99% of in-scope mailboxes.
* Inventory of TRAP configuration documented and shared.
* Migration steward named, executive sponsor confirmed.
* Decision recorded on whether to migrate historic TRAP incident data.

---

## Phase 1. Native MDO MVP (Weeks 1 to 3)

**Goal:** get the MDO baseline live and validated, while TRAP keeps running
unchanged.

This is the [`00-MVP-deployment-guide.md`](./00-MVP-deployment-guide.md)
work in full. Summary of what changes in your tenant:

* Strict preset (or tuned equivalent) applied to anti-phish, anti-spam,
  anti-malware, Safe Links, Safe Attachments.
* ZAP confirmed enabled across all three policy families.
* User reported settings configured: built-in Outlook Report button,
  custom reporting mailbox in EXO, AIR Auto Feedback Response on for all
  three verdicts.
* Reporting mailbox added to SecOps overrides and excluded from DLP.
* Sentinel workspace provisioned and connected to Defender XDR (incidents
  + alerts + the small EmailEvents/EmailPostDeliveryEvents/AlertInfo/
  AlertEvidence table set).
* Search and Purge role assigned to your Data Investigator role group.
* Reporter Thanks Bridge Logic App deployed (one playbook, fewer than 5
  actions).

What does **not** change in this phase:

* TRAP keeps running. Reporters who hit the legacy PhishAlarm button still
  flow into TRAP normally.
* Your existing SOAR integration into TRAP keeps working.
* No engineered enhancements (forward-tracking, DL expansion, TI sweep,
  VAP scoring) yet.

**Validation tests** are T1 to T7 in the MVP guide. All seven must pass
before you exit Phase 1. If T2 (user-reported phish to AIR) intermittently
fails to fire, the most likely cause is the `Auto-Resolve - Email reported
by user as malware or phish` alert tuning rule still being enabled.

**Exit criteria:**

* T1 to T7 functional tests pass.
* MDO MVP and TRAP both operating; no protection gap during the dual-run
  period.
* Defender XDR Action Center showing typical incident volume for your
  environment.

---

## Phase 2. Parallel run and observation (Weeks 4 to 7)

**Goal:** prove the MDO stack matches or beats TRAP across a real
incident corpus, before turning anything off.

What to do:

* Both stacks are live for the entire phase. Reporters using PhishAlarm
  end up in TRAP; reporters using the built-in Outlook Report button end
  up in MDO. Plan to instrument both surfaces and reconcile incident
  counts daily.
* Pick a measurement window of at least 2 weeks. Track:
  - Total reported messages per stack
  - Mean time to remediation per stack (MTTR)
  - False positive rate per stack
  - Analyst minutes spent per incident per stack
  - Recipient coverage achieved per stack (TRAP forward-following will
    win here; capture the delta honestly)
* Build a Sentinel workbook that lays both numbers next to each other.
  Workbook design notes in [`13-licensing-and-operations.md`](./13-licensing-and-operations.md).
* Identify the cases where MDO under-performed TRAP. The usual list:
  - >48 hour retroactive sweeps where ZAP cannot help
  - Forward-following beyond cluster expansion
  - DL fan-out where TRAP enumerated the membership and Microsoft did not
  - Reporters who did not get a thank-you because AIR closed before the
    auto-feedback rule fired (Reporter Thanks Bridge handles this; confirm
    it is)
  - VIP-touching incidents where you wanted higher severity automatically
* Decide which Phase 3 enhancements you actually need based on the
  observed gaps, not on the comprehensive list.

What does not change yet:

* TRAP is still running. Do not decommission anything.
* The Phase 3 engineering work has not started.

**Exit criteria:**

* At least 2 weeks of side-by-side data captured.
* Documented list of cases where MDO under-performed, with severity rating
  (blocking vs nice-to-have).
* SOC analysts comfortable with the Defender XDR portal and Action Center.
* Decision made on which Phase 3 enhancements to build.

---

## Phase 3. Engineering enhancements (Weeks 5 to 12, overlapping Phase 2)

**Goal:** close the specific gaps Phase 2 surfaced. Do not build for
hypothetical needs.

The work breaks into independent workstreams; the order below is the one
we found most efficient. You can run them in parallel if you have the
engineering capacity.

| Workstream | Effort (sr eng hr) | Document |
|---|---|---|
| TI sweep playbook (Q5 + P2) | 60 | KQL Q5, Playbook P2 |
| VAP scoring + automation rule | 24 | Sentinel SOAR §4 |
| Forward-trace remediation (Q4 + P4) | 80 | KQL Q4, Playbook P4 |
| DL expand remediation (Q8 + P5) | 40 | KQL Q8, Playbook P5 |
| Two-stage approval for VIP (P6) | 16 | Playbook P6 |
| Reporter precision scoreboard (Q9) | 8 | KQL Q9 |
| Read-state per recipient (Q6 + helper Function) | 16 | KQL Q6 |
| Custom abuse mailbox ingestion (P7) | 60 (only if needed) | User-reported §8.2 |

**Engineering rules during this phase:**

* Work in source control. Logic App workflow JSON belongs in git, deployed
  via ARM/Bicep. Hand-edited workflows in the portal are a maintenance
  trap.
* Deploy each workstream behind a feature toggle (we used a Sentinel
  watchlist `EnabledPlaybooks` keyed on playbook name with an `enabled:
  true|false` column). Lets you roll back without redeploying.
* Each playbook ships with a runbook page in the SOC wiki. The page
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

## Phase 4. Cutover (Weeks 13 to 14)

**Goal:** flip the canonical reporting path from PhishAlarm to MDO, retire
the TRAP-side processing of reports, keep TRAP installed but quiet for two
weeks as a rollback option.

What to do:

* Communicate to all users at least one week in advance. The user-visible
  change is small (the Outlook Report button looks slightly different) but
  some users will notice and need a heads-up.
* Disable the PhishAlarm add-in deployment from your tenant management.
  New mail should now use the built-in Report button only.
* Disable the TRAP abuse-mailbox poller. Do not delete the abuse mailbox;
  keep it around for the parallel-run rollback option.
* Update the SOC runbook so the canonical incident workflow is the
  Defender XDR portal and Sentinel, not the TRAP UI.
* Migrate any TRAP TI lists that are not yet replicated in TABL or
  Sentinel watchlists.
* Update any external SOAR integrations (XSOAR, Splunk SOAR) to point at
  Sentinel and Defender XDR APIs instead of TRAP REST API.
* Confirm with your monitoring team that incident volume and MTTR
  dashboards are now sourced from Sentinel.

What does NOT change yet:

* TRAP itself remains installed and licensed. You can re-enable the
  abuse-mailbox poller within an hour if Phase 4 turns up an unexpected
  problem.

**Exit criteria:**

* Built-in Report button is the only reporting surface end users see.
* TRAP poller off; TRAP installation idle.
* SOC runbook updated and referenced.
* External SOAR integrations re-pointed.
* No incident-handling regression observed for at least 3 days.

---

## Phase 5. Decommission (Weeks 15 to 16)

**Goal:** remove TRAP and clean up the residual configuration in
Exchange / Entra.

What to do:

* Cancel the Proofpoint TRAP licence.
* Remove the TRAP service account from Exchange / Entra. If it had RBAC
  for Applications role assignments, remove them. If the service account
  is dual-purpose, sanitise it carefully.
* Remove the TRAP app registration in Entra.
* Remove the SecOps mailbox / quarantine mailbox addresses TRAP used (if
  not also used by the MDO MVP).
* Remove any `New-ApplicationAccessPolicy` that scoped TRAP's Mail.* access.
* Archive the TRAP installation logs and audit trail to long-term storage.
* Update vendor risk register and SOC tool inventory.

What does NOT need cleanup:

* Mail-flow rules that route reports to the abuse mailbox (the same
  mailbox is now used by the Defender custom-mailbox path).
* PhishAlarm reports already submitted into TRAP (they remain in the
  TRAP archive; the audit trail is preserved by the export from Phase 0).

**Exit criteria:**

* TRAP licence cancelled, app uninstalled.
* Service account removed.
* Documentation updated.
* No residual Proofpoint references in tenant configuration.

---

## Estimated calendar and effort

| Phase | Calendar | Sr eng hr | SOC hr |
|---|---|---|---|
| 0. Pre-flight | 1 to 2 weeks | 40 | 16 |
| 1. MDO MVP | 2 to 3 weeks | 80 | 40 |
| 2. Parallel run | 2 to 4 weeks | 16 (instrumentation) | 80 (observation) |
| 3. Engineering | 4 to 8 weeks (overlapping 2) | 240 to 360 (depends on selected enhancements) | 24 |
| 4. Cutover | 1 to 2 weeks | 24 | 16 |
| 5. Decommission | 1 to 2 weeks | 16 | 8 |
| **Total** | **11 to 16 weeks** | **~440 to 580 hr** | **~180 hr** |

Assumes one tenant, one estate. Multi-tenant adds roughly 80 engineering
hours per additional tenant. If you have a hybrid Exchange estate that you
also need to handle, add another 80 to 160 hours and adjust expectations
accordingly (see [`12-limitations-and-gaps.md`](./12-limitations-and-gaps.md) §2).

---

## Dependencies and risks

A few things that have killed migrations we have seen:

* **License gap.** A pocket of mailboxes assigned MDO P1 instead of P2.
  Catch in Phase 0; the alternative is discovering it in Phase 2 when AIR
  silently fails to investigate those users' reports.
* **ApplicationImpersonation residue.** If you migrated TRAP to RBAC for
  Applications during 2024, you may have lingering scope assignments that
  give a defunct app more access than expected. Audit and clean up before
  Phase 5.
* **Conditional access for the Outlook approval connection.** The OAuth
  account used for Logic App approvals will trip CA policies that require
  MFA or device compliance. Either exclude the account explicitly, or
  switch to Teams adaptive cards (recommended).
* **Compliance / legal sign-off on hard delete.** Some orgs require legal
  approval before any hard-delete. Bake this into Playbook P1 with a
  conditional approval step rather than soft-delete-by-default.
* **Reporter behaviour change.** Some users who liked the PhishAlarm
  button workflow get confused by the built-in Report button. Plan an
  internal comms cycle and a lunch-and-learn session for power users.
* **SOC analyst muscle memory.** Two weeks of parallel run is the floor
  for analysts to get comfortable with Defender XDR Action Center as the
  primary console. Build that time in.

---

## Rollback strategy

Each phase has a clean rollback:

* **Phase 1 to 4 rollback:** disable the Logic App playbooks and re-enable
  the TRAP abuse-mailbox poller. The dual-run posture means TRAP has been
  receiving its own copy of reports throughout; nothing is lost.
* **Phase 5 rollback:** TRAP is gone. The last point of safe rollback is
  the start of Phase 5. After cancellation, re-onboarding TRAP is a
  vendor-side procurement and a 1 to 2 week reinstall.

Plan to keep TRAP in the install-but-quiet state for 2 weeks after Phase 4
completes. If nothing has gone wrong by then, proceed to Phase 5 with
confidence.
