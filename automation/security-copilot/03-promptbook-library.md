# 03. Project promptbook library

Reusable prompts and promptbooks tailored to the incident types this
project actually handles. A promptbook is a saved, ordered sequence of
prompts for a repeatable workflow (triage, hunt, report). Sources:
[Using promptbooks](https://learn.microsoft.com/en-us/copilot/security/using-promptbooks),
[Prompting in Security Copilot](https://learn.microsoft.com/en-us/copilot/security/prompting-security-copilot).

These are authored against our architecture: the same `EmailEvents`,
`EmailUrlInfo`, `EmailPostDeliveryEvents` tables and the same incident
types our KQL library (doc [`09`](../../09-kql-detection-library.md)) and
playbooks (doc [`10`](../../10-logic-apps-playbook-library.md)) target.
Treat the prompts below as a starting set to refine in the standalone
portal, then save as promptbooks for the SOC.

Naming convention here mirrors our playbook IDs so a promptbook and the
playbook it supports are easy to pair.

## PB-A. User-reported phishing investigation

Pairs with: the Phishing Triage Agent (doc
[`01`](./01-phishing-triage-agent.md)) and P1
([`../logic-apps/P1-phish-remediate/`](../logic-apps/P1-phish-remediate/)).
Use when an analyst picks up a true-positive the agent escalated, or
when validating the agent during the Phase 2 observe period.

```
1. Summarise incident {IncidentId}: who reported it, the email entity,
   sender, subject, URLs, attachments, and the current verdict.
2. What does Microsoft Threat Intelligence say about the sender domain
   and any URLs in this email?
3. How many other recipients in our tenant received mail matching this
   sender and subject in the last 14 days? List them.
4. Did any recipient click a URL from this campaign? Use UrlClickEvents.
5. Recommend a remediation action set and the blast radius it would
   cover.
6. Write a short incident summary suitable for the reporter notification.
```

Prompts 3 and 4 are natural-language-to-KQL (doc
[`02`](./02-copilot-in-defender-and-sentinel.md)) against the same
tables doc 09 hunts use. Prompt 6 feeds the reporter-bridge playbook P3.

## PB-B. Forward-trace investigation

Pairs with: P4
([`../logic-apps/P4-forward-trace-remediate/`](../logic-apps/P4-forward-trace-remediate/))
and doc [`09`](../../09-kql-detection-library.md) forward-tracking
queries. Use to scope internal forwarding of a malicious message before
running the remediation playbook.

```
1. For NetworkMessageId {Nmid}, trace internal forwards and replies in
   the last 14 days. Show the recipient chain.
2. Which of those forwarded copies still exist in mailboxes (not yet
   ZAP-purged)?
3. Summarise the forward fan-out: how many distinct mailboxes hold a
   copy, and which are VIP or VAP watchlist members?
```

The honest limit from doc [`12`](../../12-limitations-and-gaps.md)
still applies: once a message leaves the tenant boundary, Microsoft has
no telemetry, so Copilot can only trace internal hops. The promptbook
makes that boundary explicit rather than hiding it.

## PB-C. Distribution-list blast-radius

Pairs with: P5
([`../logic-apps/P5-dl-expand-remediate/`](../logic-apps/P5-dl-expand-remediate/)).
Use when a phishing message was sent to a distribution list and we need
the expanded recipient set before remediating.

```
1. Expand distribution list {DLAddress} including nested lists, and give
   the full member count.
2. Of those members, who actually received NetworkMessageId {Nmid}?
3. Flag any members on the VIP or VAP watchlist so we can route through
   the two-stage approval (P6).
```

The 500-member safety cap that P5 enforces is a playbook guard, not a
Copilot guard. If the expansion is large, prefer P5 for the
remediation; use this promptbook for the read-side blast-radius picture.

## PB-D. Threat-intelligence retroactive sweep

Pairs with: P2
([`../logic-apps/P2-ti-sweep-remediate/`](../logic-apps/P2-ti-sweep-remediate/))
and doc [`09`](../../09-kql-detection-library.md) Q5. Use when fresh TI
reveals that already-delivered mail (older than ZAP's 48-hour window)
was malicious.

```
1. Given indicator {IOC} (domain / URL / file hash / sender), find all
   mail in the last 14 days that matched it, excluding the last 48 hours
   that ZAP already covers.
2. Group the matches by recipient and by campaign. How many mailboxes
   are affected?
3. Draft the approval-card summary an analyst would post to the SOC
   Teams channel before authorising the sweep.
```

The **Threat Intelligence Briefing Agent** (catalogued in the
[README](./README.md#agent-catalogue-relevant-subset)) can run the
proactive side of this: a scheduled briefing that surfaces emerging
threats, which an analyst then turns into a sweep via P2. That is a
Phase 3+ evaluation, not a Phase 2 commitment.

## PB-E. Reporter and stakeholder communications

Pairs with: P3
([`../logic-apps/P3-notify-reporter-bridge/`](../logic-apps/P3-notify-reporter-bridge/)).
Copilot is strong at audience-targeted summarisation, which is exactly
what reporter-thanks and management-update messages need.

```
1. Write a short thank-you to the user who reported incident
   {IncidentId}, stating whether their report was a real threat or a
   false alarm, in plain non-technical language.
2. Write a one-paragraph management update on this incident: impact,
   action taken, residual risk.
```

Microsoft's own sample shows this pattern: `Write an executive report
summarizing this investigation. It should be suited for a nontechnical
audience.`
([Sentinel prompts](https://learn.microsoft.com/en-us/azure/sentinel/sentinel-security-copilot)).

## PB-F. Parallel-run reporting

Pairs with: doc [`11`](../../11-implementation-roadmap.md) and
`automation/workbooks/trap-mdo-parallel-run.json`. Use during Phase 2 to
generate the human-readable narrative that sits alongside the workbook
metrics.

```
1. Summarise all user-reported phishing incidents from the last 7 days:
   count, how many the Phishing Triage Agent auto-resolved as false
   positives, how many were confirmed true positives.
2. For the true positives, what was the mean time to triage and the mean
   time to remediate?
3. Write an executive summary of the SOC's week handling phishing, for a
   non-technical audience.
```

## Reference starting points

* The built-in **Microsoft Sentinel incident investigation** promptbook
  is a good base to fork: it returns a report on an incident with
  related alerts, reputation scores, users, and devices
  ([Sentinel prompts](https://learn.microsoft.com/en-us/azure/sentinel/sentinel-security-copilot)).
* Rod Trent's community prompt library is a useful external source for
  patterns to adapt:
  [Copilot-for-Security/Prompts](https://github.com/rod-trent/Copilot-for-Security/tree/main/Prompts).

## How to operationalise these

1. Refine each prompt set in the standalone portal against a real
   incident until the output is reliable.
2. Save it as a promptbook with the PB-x name above so the pairing to
   the playbook is obvious.
3. Parameterise the inputs (IncidentId, NetworkMessageId, DLAddress,
   IOC) so analysts only fill the blanks.
4. Review SCU cost per run on the usage dashboard (doc
   [`04`](./04-licensing-scu-governance.md)); promptbooks that fan out
   many prompts cost more, so keep them tight.
