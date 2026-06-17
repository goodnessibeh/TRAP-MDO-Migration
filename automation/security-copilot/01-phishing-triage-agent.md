# 01. Phishing Triage Agent

The single highest-value Copilot enhancement for this project. It
inserts an autonomous LLM triage tier in front of the SOC analyst for
every user-reported phishing email, classifies each as a true threat or
a false alarm, auto-resolves the false alarms, and explains every
verdict. Source:
[Phishing Triage Agent](https://learn.microsoft.com/en-us/defender-xdr/phishing-triage-agent).

This is the same engine as the
[Security Alert Triage Agent](https://learn.microsoft.com/en-us/defender-xdr/security-alert-triage-agent),
scoped here to the user-reported-phish alert.

## What it does, in our terms

Our current user-reported pipeline (doc
[`08`](../../08-abuse-mailbox-and-user-reporting.md)) is: user clicks
the built-in Report button, an alert and incident are created, AIR
auto-investigates, and an analyst works the incident queue. The bulk of
that queue is false alarms (legitimate mail, spam, newsletters) that an
analyst still has to read and close. Microsoft cites up to ~30 minutes
of manual triage per reported message.

The Phishing Triage Agent sits between the alert and the analyst:

1. It triggers automatically when a user reports a suspected phishing
   email and the **Email reported by user as malware or phish** alert
   is created.
2. It assesses the message with LLM reasoning plus a tool set: email
   content analysis, file and URL detonation, screenshot analysis,
   Microsoft Threat Intelligence, and advanced hunting across our data
   sources.
3. It classifies the alert:
   * **False Positive**: the agent resolves the alert and the incident.
     The analyst never has to touch it.
   * **True Positive**: the agent leaves the incident open and in
     progress, tags it, and hands it to an analyst, who then drives our
     existing remediation (AIR, Take Action, or a Logic App playbook).
4. For every verdict it writes a plain-language rationale plus a visual
   decision tree, and it logs the full activity to Microsoft Purview
   audit.

The net effect on doc [`01`](../../01-executive-summary.md): the
analyst-load and MTTR claims get a concrete, measurable lever. The agent
removes the false-positive reading load entirely and front-loads the
true positives.

## How it sits relative to AIR, ZAP, and our playbooks

It does not replace any of them. It is a triage filter, not a
remediation engine.

| Component | Role | Changed by the agent? |
|---|---|---|
| AIR (doc [`05`](../../05-defender-xdr-air-zap.md)) | Auto-investigation graph, evidence collection | No. AIR still runs. The agent reasons over the same incident |
| ZAP | Zero-hour retroactive purge | No |
| Defender XDR Take Action | Analyst remediation surface | No. The agent hands confirmed phish here |
| P1 / P1b (workhorse) | Approval-gated soft-delete | No. Still the remediation path for confirmed phish |
| P3 (reporter bridge) | Reporter "thanks" / verdict-back | Complementary. The agent's verdict is what P3 can report back |

The boundary is clean: the agent is **read-and-classify plus resolve
false positives**. It never deletes mail from a mailbox. Every
state-changing remediation stays behind the human-approval gates the
playbooks already enforce. That is the same conservative posture as the
rest of `automation/`.

## The capability-matrix upgrade

The agent's per-organisation **feedback loop** is the closest
Microsoft-native analog to Proofpoint CLEAR's analyst-tuning behaviour
that doc [`03`](../../03-trap-capability-matrix.md) currently rates
**Partial**. Analysts give natural-language feedback on a verdict (for
example, "any email claiming to be from benefits providers must
originate from @benefits.company.com"). The agent converts that into a
stored *lesson* in its memory and applies it to similar future alerts.

When we are ready to revise the matrix, the candidate change is:

| Row | Current verdict | Proposed verdict with the agent |
|---|---|---|
| Reporter / analyst verdict-feedback tuning (CLEAR-equivalent) | Partial: built-in banners; verdict-back via Logic App | Mostly Native: agent feedback lessons provide the per-org tuning loop; P3 still handles reporter notification |
| Analyst triage load on user-reported phish | Manual queue work | Autonomous TP/FP triage; FP auto-resolved |

We do not edit doc 03 from here. This is the running rationale for that
edit when the parallel-run data supports it.

## Prerequisites

Source:
[Phishing Triage Agent prerequisites](https://learn.microsoft.com/en-us/defender-xdr/phishing-triage-agent).

| Component | Requirement | Where we stand |
|---|---|---|
| Products | Security Copilot with provisioned SCU capacity (or E5 inclusion entitlement), and **MDO Plan 2** deployed | MDO P2 confirmed present (Phase 0 licensing gate). SCU entitlement to confirm in [doc 04](./04-licensing-scu-governance.md) |
| URBAC | Unified role-based access control enabled for Defender for Office 365 | Activate the Defender for Office 365 workload in Defender XDR settings |
| User reported settings | **Monitor reported messages in Outlook** enabled, with a reported-message destination set | Part of our Phase 1 user-reporting setup (doc 08) |
| Alert policy | **Email reported by user as malware or phish** alert policy turned on | Confirm enabled |
| Plugins | The agent auto-activates the Microsoft Defender XDR, Microsoft Threat Intelligence, and Phishing Triage Agent plugins | Automatic on setup |

### The alert-tuning gotcha (do not skip)

The agent **does not triage alerts that are resolved by alert tuning**.
Microsoft ships a built-in tuning rule, **Auto-Resolve - Email reported
by user as malware or phish**, that silently resolves exactly the alert
the agent needs to see. We must **disable that built-in rule and any
custom tuning rule** that resolves this alert, or the agent never fires.

This is worth a one-line note in doc
[`12`](../../12-limitations-and-gaps.md) when we update it: enabling the
agent and leaving the auto-resolve tuning rule on is a silent
misconfiguration that looks like the agent "doing nothing."

## Identity and permissions model

At setup the agent is given an identity and a least-privilege role.
Source:
[Phishing Triage Agent permissions](https://learn.microsoft.com/en-us/defender-xdr/phishing-triage-agent).

**Identity** (pick one):

* **Create a new agent identity (recommended)**. Microsoft Entra Agent
  ID, scoped specifically to this agent. Easiest to manage and audit.
* **Connect an existing user account**. The agent inherits that
  account's access. If chosen, use a dedicated account with a distinct
  display name (for example "Phishing Triage Agent"), a long expiry,
  and a Conditional Access policy that permits Security Copilot. Not
  compatible with PIM or TAP, because those do not support long-running
  background operation.

**Permissions** (Security operations group, scoped to the Microsoft
Defender for Office 365 data source):

| Permission | Why |
|---|---|
| Security Copilot (read) | Access Copilot capabilities |
| Security data basics (read) | Read alerts and incidents |
| Alerts (manage) | Classify and update alert state without override |
| Email & collaboration metadata (read) | Read reported-email metadata |
| Email & collaboration content (read) | Read reported-email body for analysis |

Management actions (set up, pause, remove, manage identity, reject
feedback) require **Security Administrator** in Entra ID. Microsoft's
guidance: the user group overseeing the agent must hold permissions
equal to or higher than the agent itself.

This identity model is consistent with our playbook posture in
[`../logic-apps/`](../logic-apps/): scoped identity, least privilege,
no stored secrets, full audit trail.

## Setup runbook

This is an operator runbook for when we reach the Phase 2 step in the
[README enable order](./README.md#recommended-enable-order). It changes
tenant state, so it runs under the same governance as any other tenant
change. We are not asserting it has been done.

1. **Confirm prerequisites** above, especially MDO P2, URBAC for
   Defender for Office 365, user-reported settings, and the reported-
   phish alert policy.
2. **Disable the auto-resolve tuning rule** for "Email reported by user
   as malware or phish" (and any custom equivalents).
3. **Open the setup wizard**: Defender portal, either from the Security
   Store, or from the Phishing Triage card above the **Incidents**
   queue, select **Set up agent**.
4. **Assign identity**: choose **Create a new agent identity**
   (recommended). If using an existing account instead, pre-create it
   and pre-assign the permissions above before this step.
5. **Assign the role**: select or auto-create a role carrying the five
   Security operations permissions, scoped to the MDO data source.
6. **Run in observe mode first**. During the Phase 2 parallel run, treat
   the agent as advisory: compare its TP/FP verdicts against analyst
   ground truth before we rely on its auto-resolve. The trial period
   consumes SCUs once it ends; track this on the Performance tab.
7. **Teach it our context**. As analysts correct verdicts, capture
   feedback as lessons (see below). A handful of well-written lessons in
   the first weeks materially reduces repeat false positives.
8. **Promote to trusted** once the parallel-run sample shows acceptable
   precision and recall on our mail. Document the decision in the
   roadmap, not here.

## Teaching the agent (feedback lessons)

Feedback is how we encode our organisation's context. Analysts change a
verdict, give a natural-language reason, and choose **Use this feedback
to teach the agent**. The agent translates it into a lesson stored in
its memory and applies it to matching future alerts. Feedback can be
given **once per alert**, and only to set True Positive (phishing) or
False Positive (not malicious).

Microsoft's best-practice rules, restated for our analysts:

* **Be specific and contextual.** Reference the sender domain, subject
  pattern, body cue, or recipient pattern. "Any email claiming to be
  from benefits providers must originate from @benefits.company.com"
  works. "The sender is not legitimate" does not.
* **Be decisive.** Avoid "might be" and "looks different from usual."
  State the rule.
* **Stay consistent.** New lessons that contradict existing lessons land
  in a Conflict state and must be reconciled on the feedback management
  page.
* **Review the generated lesson** before saving. Use **Evaluate
  feedback** to preview how the agent interpreted the input.

Project-specific lessons worth seeding early (tie these to our own
domains and naming):

* Internal finance/benefits/HR senders must originate from our owned
  domains; lookalikes are phishing.
* File-share and document-access invitations should only come from our
  authorised provider domain.
* Billing or payment-change requests in the subject line are treated as
  phishing pending verification.
* Contractor onboarding mail follows our recipient convention (for
  example v- prefixed accounts); deviations are suspect.

All feedback is logged for audit whether or not it is promoted to a
lesson, which fits our audit-trail parity requirement.

## Measuring it during the parallel run

Doc [`11`](../../11-implementation-roadmap.md) Phase 2 is where we prove
parity before cutover. The agent gives us first-party metrics for that,
on the **Performance** tab and the incident-queue card:

* **Incidents addressed** and **Incidents resolved** (false alarms the
  agent closed).
* **Mean time to triage (MTTT)**.
* **SCU consumption** and **cost per email processed**, exportable to
  Excel for capacity planning (feeds [doc 04](./04-licensing-scu-governance.md)).

Suggested parallel-run comparison, to add as a panel to the existing
`automation/workbooks/trap-mdo-parallel-run.json` when we revise it:

| Metric | TRAP (CLEAR) | MDO + Phishing Triage Agent |
|---|---|---|
| Analyst minutes per reported message | baseline | agent MTTT + analyst time on TPs only |
| False positives auto-closed | n/a | Incidents resolved (agent) |
| Verdict explainability | CLEAR verdict | per-alert rationale + decision tree |
| Tuning mechanism | CLEAR rules | feedback lessons |

We do not edit the workbook from this doc. This is the spec for that
panel when the parallel-run data is flowing.

## Limits and honest caveats

* **Scope.** Today it triages the user-reported-phish alert. It is not a
  general "remediate everything" agent. Confirmed phish still routes to
  our remediation plane.
* **Trust ramp.** Auto-resolve of false positives means a wrong FP call
  closes an incident. That is why we run it in observe mode first and
  promote only on measured precision. The decision tree makes wrong
  calls auditable.
* **One feedback per alert.** Tuning is deliberate and analyst-driven,
  not bulk. Plan analyst time for it in the first weeks.
* **SCU dependency.** No SCUs, no agent. Capacity planning is not
  optional; see [doc 04](./04-licensing-scu-governance.md).
* **Does not extend telemetry.** It reasons over what Defender already
  sees. It does not help with external-forward-following or
  cross-tenant remediation, which remain in doc
  [`12`](../../12-limitations-and-gaps.md).
