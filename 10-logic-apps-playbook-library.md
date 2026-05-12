# Logic App Playbook Library

Reference designs for the SOAR layer that bridges Sentinel incidents to the
Microsoft remediation APIs. Each playbook is presented as an action graph
(not a full ARM template, that is downstream engineering work) plus the
identity, scope, and operational caveats. We deliberately keep the action
count low: most playbooks here are 5 to 15 actions. Anything larger is a
sign you should split into a parent / child pattern.

All playbooks assume Logic App **Standard** with system-assigned managed
identity. Where a step requires the Office 365 Outlook connector,
remember it does not support service principals; you will need a SOC
service mailbox with an OAuth connection and a CA carve-out for that
account.

---

## P1. Phish-Remediate-v3 (the workhorse)

**Trigger:** Microsoft Sentinel incident.
**Conditions (in the automation rule):** incident title contains
"Phish-detected" or "Email reported by user as malware or phish".
**Identity:** Logic App MI; runs against
`https://api.security.microsoft.com` via HTTP+MI.

```
1. Initialize variables: NetworkMessageId, Subject, SenderDomain,
   RecipientCount (extracted from incident.Entities)

2. HTTP+MI POST /security/runHuntingQuery
   Query: enumerate recipients (Q1 from the KQL library)

3. Compose: count recipients, count VIPs (lookup against VIP_Users watchlist
   via Sentinel REST or via a second runHuntingQuery)

4. Switch on recipient count:
     case ≤10:                 go to step 5
     case 11..200:             go to step 6
     case >200:                go to step 7 (bulk path)

5. Direct soft-delete:
   HTTP+MI POST /api/email/take-action
   { action: "softDelete",
     sourceFilters: { networkMessageId: <id> },
     scope: "tenant" }
   Continue to step 8.

6. Same as step 5 with batched issuance (50 recipients per call,
   serialized to respect the 4-concurrent-per-mailbox cap).

7. Bulk path: invoke child playbook P1b "Phish-Remediate-Bulk"
   (compliance search action with looped 10/mb purge).

8. HTTP+MI POST /security/runHuntingQuery
   Query: Q2 (URL click correlation). Identify users who clicked.

9. If clicker count > 0, branch to Defender for Endpoint isolation
   playbook (out of scope for this document; pattern in azure-sentinel
   repo Solutions/MicrosoftDefenderForEndpoint/Playbooks).

10. Add comment to incident: remediation summary
    "Soft-deleted N messages across M recipients. K clicked."

11. Update incident: status = Active, owner = on-call, severity = ...

12. (Conditional) Send Teams adaptive card to SOC channel with summary.
```

**Operational notes:**

* Step 7 calling P1b is the gate where the Compliance Search-Action 10/mb
  limit forces a different code path. Keep the boundary explicit: at >200
  recipients OR >10 messages-per-mailbox the direct API is the wrong
  tool.
* The Defender XDR Take Action API takes the cluster and applies tenant-
  wide on its own, so step 5 does not need a per-recipient ForEach. That is
  the single biggest reason to prefer it over the Compliance Search path.
* Steps 8 to 9 are a "while we have you here" enrichment. They add 5 to 10
  seconds of run time. Worth it for compliance, optional otherwise.

---

## P1b. Phish-Remediate-Bulk (called by P1)

For campaigns where the per-mailbox count exceeds 10 messages, or
recipient count exceeds 200. Defender XDR Take Action handles this
gracefully under the 200k message cap, so use that first. The Compliance
Search path below is the fallback for cases where Take Action is
unavailable (rare, mostly licensing edge cases).

```
1. HTTP+MI POST to Function App endpoint /run-compliance-search
   Body: { networkMessageId, subject, senderDomain, recipientList }

2. The Function App (PowerShell, MI, ExchangeOnlineManagement v3+):
   2a. Connect-IPPSSession -ManagedIdentity -EnableSearchOnlySession
   2b. Build ContentMatchQuery from inputs
   2c. New-ComplianceSearch + Start-ComplianceSearch
   2d. Poll Get-ComplianceSearch until Status -eq 'Completed'
   2e. New-ComplianceSearchAction -Purge -PurgeType HardDelete
   2f. Loop: Get-ComplianceSearchAction; if EstimatedItems still > 0,
       create another search-action against the residue
   2g. Return summary { searches: [...], purgedItemCount, errors: [...] }

3. Logic App: parse the response, attach as incident comment,
   update status.
```

**Operational notes:**

* Polling in step 2d is unavoidable; the search must be `Completed` before
  you can action. In our testing, a search across `ExchangeLocation All`
  in a 10k-mailbox tenant takes 30 to 90 seconds.
* The 10/mb loop in 2f rarely needs more than 2 iterations for typical
  campaigns. If you find yourself looping more than 3 times, the campaign
  is large enough that you should be using Graph eDiscovery purgeData
  instead (100/location).
* Function App MI must have `Exchange.ManageAsApp` granted plus the
  Compliance Administrator + Exchange Administrator directory roles.
  Allow 24 hours after grant for the role cache to refresh.

---

## P2. TI-Sweep-Remediate

**Trigger:** Microsoft Sentinel incident from the scheduled TI-sweep
analytics rule (KQL Q5).
**Conditions:** title starts with "TI Sweep". Severity inherited from rule.

```
1. Parse incident.Entities to extract NetworkMessageIds[].

2. Send Teams adaptive card to #soc-approvals:
   "TI sweep matched N messages across M recipients.
    Sender domain: <d>. URL: <u>. Confidence: <c>.
    [Approve] [Reject] [Investigate first]"
   Wait for response.

3. On Approve:
   3a. ForEach NetworkMessageId (concurrency 5):
       HTTP+MI to Defender XDR Take Action API → soft-delete
   3b. ForEach unique IOC:
       HTTP+MI POST /api/security/threatSubmission/emailThreats
       with tenantAllowOrBlockListAction = block
   3c. Add incident comment: "Approved by <user>; remediated N messages,
       blocked K IOCs."

4. On Reject:
   Add comment "Rejected by <user>". Close incident.

5. On Investigate first:
   Add comment "Pending investigation". Reassign to incident owner.
```

**Operational notes:**

* The 5-concurrency cap on ForEach in step 3a is intentional: respects the
  Graph 4-concurrent-per-mailbox cap and leaves headroom for other
  playbooks running in parallel.
* If the TI feed is noisy, you will get a lot of these. Add an automation-
  rule pre-condition that auto-approves when sender domain is on the
  `KnownBad_Senders` watchlist (which gets populated by previous TI hits
  that the SOC approved). After 30 days, ~70% of TI sweeps auto-approve
  with no human in the loop.

---

## P3. Notify-Reporter-Bridge

**Trigger:** Microsoft Sentinel incident.
**Conditions:** title equals "Email reported by user as malware or phish".
This is the MVP playbook. Documented in
[`00-MVP-deployment-guide.md`](./00-MVP-deployment-guide.md) §3.3.

```
1. Extract Reporter UPN from incident.Entities[].Account.UPN

2. Office 365 Outlook → Send email V2
   To: <Reporter>
   Subject: "Thanks for reporting that email"
   Body: "We received your report. Our security team is investigating;
          you'll receive a follow-up email with the verdict shortly."
   From: SOC service mailbox

3. Add incident task: "Reporter acknowledged at <timestamp>"
```

**Operational notes:**

* The acknowledgement is delivered before AIR has finished investigating,
  so the user sees a "thanks" email within a minute or two of clicking
  Report. The verdict-back arrives later from Microsoft's AIR Auto Feedback
  Response. Two emails is fine; the user understands them as different
  steps.
* If your tenant has heavy reporter volume (>500/day), throttle this
  playbook with an automation-rule pre-condition that fires only when
  the reporter is not in `Frequent_Reporters` watchlist (auto-populated).
  Frequent reporters get a single weekly summary instead.

---

## P4. Forward-Trace-Remediate

**Trigger:** Microsoft Sentinel incident OR manual entity playbook run.
**Identity:** Logic App MI plus Function App MI.

```
1. Input: NetworkMessageId, original sender, original subject.

2. HTTP+MI POST /security/runHuntingQuery
   Query: Q4 (internal forward tracking).

3. ForEach forwarded message in result:
   3a. HTTP+MI to Defender XDR Take Action API → soft-delete
   3b. Add comment to incident: forwarded message remediated

4. HTTP+MI POST /security/runHuntingQuery
   Query: external-forward detection (subset of Q4 with EmailDirection != "Intraorg")

5. If external forwards found:
   Send Teams adaptive card to SOC: "External forward detected,
   cannot remediate. Recipients: <list>. Recommend block at sender
   organisation."
   Add severity "High" tag to incident.
   (No remediation action; out of our reach.)
```

**Operational notes:**

* This is the playbook that closes the biggest TRAP-vs-MDO gap that we can
  reasonably close. The remaining gap (external forwards) is a telemetry
  boundary, not a workflow problem. The best mitigation is the sister
  control in Q7: alert on auto-forward configuration changes so you catch
  the leak before it happens.
* Step 4 adds an unfortunate operational reality to the SOC inbox. Many
  external forwards are legitimate (user forwarded to personal email,
  forwarded to vendor for action). Tag rather than escalate by default.

---

## P5. DL-Expand-Remediate

**Trigger:** Microsoft Sentinel incident OR manual entity playbook run.
**Identity:** Logic App MI plus Function App MI for EXO PowerShell.

```
1. Input: NetworkMessageId, list of DL recipient SMTP addresses.

2. ForEach DL address:
   2a. HTTP to Function App /resolve-dl-members
       The Function calls:
         Connect-ExchangeOnline -ManagedIdentity
         Get-DistributionGroupMember -Identity $dl -ResultSize Unlimited |
           ForEach-Object {
             if ($_.RecipientType -like "*Group*") {
               # nested DL. recurse
             } else {
               $expanded += $_
             }
           }
         Get-DynamicDistributionGroupMember -Identity $dl  # if dynamic
       Returns flat list of expanded recipient UPNs.

3. Concatenate all expansions, dedupe.

4. HTTP+MI POST /security/runHuntingQuery (Q8 from the KQL library)
   Confirm each member actually received the message.

5. HTTP+MI to Defender XDR Take Action API → soft-delete cluster
   (the cluster API will fan-out across all recipients automatically;
    we just need to know we have full coverage).

6. Add comment with expansion summary:
   "DL <name> expanded to N members. Delivery confirmed for K of N.
    Pulled from K mailboxes."
```

**Operational notes:**

* Recursion in 2a needs a cycle-detection guard (parent DL contains child
  DL contains parent DL). We've seen tenants where this loops infinitely
  if you do not check.
* Step 4 (delivery confirmation) is what catches the edge cases:
  forwarding rules, journaling exclusions, recipients moved to on-prem.
  Without it, you assume DL coverage equals cluster coverage. They are
  not always equal.
* Defender XDR Take Action operates on the cluster (NetworkMessageId), not
  the DL. The DL expansion is therefore audit information for the SOC, not
  input to the remediation API. This is a non-obvious design point.

---

## P6. Two-Stage-Approval-VIP

**Trigger:** Microsoft Sentinel incident.
**Condition:** any entity in `Mailbox` is on `VIP_Users` watchlist, OR
any entity in `Account` is on `VIP_Users` watchlist.
**Identity:** Logic App MI plus per-user OAuth for Outlook approval if you
go that route, or Teams app for adaptive card approval (recommended).

```
1. Extract VIP recipients/accounts.

2. Teams "Post adaptive card and wait for a response" to
   #soc-vip-approvals channel:
   "VIP-touching incident. Recipient(s): <list>.
    Proposed action: <soft-delete / hard-delete / quarantine>.
    [Approve] [Reject] [Escalate to L3]"
   Timeout: 1 hour.

3. On Approve:
   3a. Run remediation (P1).
   3b. Add comment: "VIP-tier action approved by <user>".

4. On Reject:
   Close incident. Add comment with rejection reason.

5. On Escalate or Timeout:
   Send second adaptive card to SOC manager DL channel
   (or escalation phone number via Service Bus + paging service).
   Set incident severity to High.

6. Audit: log every approval state transition to Sentinel custom table
   ApprovalAudit_CL (use Log Ingestion API).
```

**Operational notes:**

* Adaptive card timeout matters. Microsoft Teams holds the card for the
  duration; Logic App holds the run. A 1 hour timeout fits within
  Consumption's 90-day max comfortably; for longer (>4 hr) approvals,
  switch to the durable functions pattern.
* The audit log to a custom Sentinel table is non-optional for VIP-tier
  actions. Auditors will ask who approved what; Action Center History is
  too coarse-grained for VIP-tier scrutiny.
* Some orgs require dual approval for VIP actions (one analyst, one
  manager). Add a second adaptive card after step 3, gated on first
  approval, before step 3a runs.

---

## P7. Custom-Abuse-Mailbox-Ingest (optional)

Documented in [`08-abuse-mailbox-and-user-reporting.md`](./08-abuse-mailbox-and-user-reporting.md) §8.2.
Use only when the built-in Outlook Report button is insufficient (legacy
clients, hybrid mailboxes that cannot reach the Defender custom mailbox
path). For most modern tenants, this playbook is unnecessary because the
built-in path covers the use case.

---

## Cross-cutting design rules we wish we knew earlier

A handful of things we learned the hard way during pilot deployments:

* **Idempotency is non-negotiable.** Logic App runs can be retried by
  Sentinel automation rules under failure conditions you do not control.
  Key every remediation step on `NetworkMessageId + RecipientAddress` and
  short-circuit if the action has already been applied (check
  `EmailPostDeliveryEvents` first).
* **Approval cards in Teams beat Outlook.** No per-user OAuth, no
  conditional access friction, lower run-blocking duration impact. Outlook
  approvals work but the operational tax is real.
* **HTTP+MI to Graph beats the named connectors for Microsoft APIs.** The
  named connector for Defender XDR is a thin wrapper that adds nothing but
  some token caching; you lose the ability to add custom headers and to
  include the `Prefer: return=representation` header that Graph supports
  for some endpoints. Going direct via HTTP+MI gives you full control.
* **Always include a "do nothing" branch with a reason.** Auditors will
  ask why a playbook decided not to act. If the decision logic returns
  nothing, you cannot answer.
* **Graph throttling tells you to slow down before it tells you to stop.**
  Watch `x-ms-throttle-limit-percentage` in Graph response headers; if it
  climbs above 80%, slow your concurrency. Waiting for 429 is too late.
* **Compliance Search-Action looped more than 3 times means you picked the
  wrong tool.** Switch to Graph eDiscovery purgeData (100/location) or to
  Defender XDR Take Action (200k cap).
* **Logic App run history retention defaults to 90 days on Consumption and
  is the only forensic record of what your playbook did.** Set up a
  scheduled export to blob storage if you need longer retention. (Long-
  running approvals that span >90 days will lose the head end of their
  history.)
* **Test playbooks against a Sentinel incident with realistic entities,
  not against a synthetic one.** Synthetic incidents miss the entity
  ordering quirks that real Defender XDR-sourced incidents have.

---

## Reference repositories

The following upstream repos contain ARM templates and worked examples that
align with the patterns above. Do not blindly copy them; many predate the
unified portal and use the Sentinel alert trigger which is no longer
available for Defender XDR alerts.

* `github.com/Azure/Azure-Sentinel/tree/master/Playbooks` plays well as a
  starter set; the SOAR Essentials solution has the most reusable patterns.
* `github.com/Azure/Azure-Sentinel/tree/master/Solutions/SentinelSOARessentials/Playbooks`
  for the Teams adaptive card / Slack post / Send-basic-email primitives.
* `github.com/Azure/Azure-Sentinel/tree/master/Solutions/MicrosoftDefenderForEndpoint/Playbooks`
  for the Isolate / Unisolate patterns referenced in P1 step 9.
* `github.com/Azure/Azure-Sentinel/tree/master/Solutions/Microsoft%20Defender%20Threat%20Intelligence/Playbooks`
  for MDTI enrichment patterns referenced inline.
