# 04. Licensing, SCU sizing, and governance

What Security Copilot costs, how much capacity we need, and how we keep
the autonomous agent inside our governance model. This is the doc that
turns "Copilot would help" into a defensible capacity and control plan.
It extends doc [`13`](../../13-licensing-and-operations.md), it does not
replace it. Sources are cited inline.

## How Security Copilot is licensed

Three ways to obtain capacity
([pricing](https://learn.microsoft.com/en-us/copilot/security/security-compute-units-capacity),
[E5 inclusion](https://learn.microsoft.com/en-us/copilot/security/security-copilot-inclusion)):

1. **Included with Microsoft 365 E5** (and E7, which includes E5). This
   is the relevant path for us, because our license floor (doc
   [`13`](../../13-licensing-and-operations.md)) is already E5 or
   E3 + EMS E5 + MDO P2.
2. **Standalone provisioned SCUs**. ~$4/hour per SCU, roughly
   $2,920/month or ~$35,000/year per SCU running 24/7.
3. **Pay-as-you-go overage** at ~$6 per SCU, optional, with 30-day
   advance notice before it applies.

Security Compute Units (SCUs) are the unit of capacity. Every Copilot
feature, including the agents, consumes SCUs
([agents overview](https://learn.microsoft.com/en-us/copilot/security/agents-overview)).
There is no separate per-agent license: if we have Copilot capacity, the
Phishing Triage Agent runs against it.

## The E5 inclusion benefit

Announced at Ignite 2025
([E5 inclusion](https://learn.microsoft.com/en-us/copilot/security/security-copilot-inclusion)):

* **400 SCUs per month for every 1,000 paid E5 licences**, scaling for
  customers with fewer than 1,000 licences.
* Capped at **10,000 SCUs/month**.
* **No additional cost.**
* **No overage billing today.** If we exhaust the monthly allocation,
  analysts and agents are throttled until the next reset, rather than
  generating a surprise bill. The optional PAYG path above exists if we
  choose to scale past the allocation.

For our project this is the headline: in an E5 estate the SCU floor for
a pilot is very likely already paid for. The agent and the embedded
features can be evaluated on included capacity before any spend
decision.

## Sizing for our tenant

We do not guess SCU need, we measure it. Microsoft exposes the data:

* The **Phishing Triage Agent Performance tab** reports daily activity,
  mean time to triage, **SCU consumption**, and **cost per email
  processed**
  ([Phishing Triage Agent](https://learn.microsoft.com/en-us/defender-xdr/phishing-triage-agent)).
* The **usage monitoring dashboard** in the Security Copilot portal
  (securitycopilot.microsoft.com/usage-monitoring) shows cost per email
  processed and capacity consumption over time, exportable to Excel and
  filterable to agent operations only.

Sizing procedure for Phase 2:

1. Enable the agent in the trial/observe window. The trial does not
   consume provisioned SCUs until it ends.
2. Let it process a representative volume of real user-reported mail.
3. Read **cost per email processed** off the Performance tab.
4. Multiply by our daily reported-mail volume to get steady-state SCU
   demand for the agent.
5. Add the embedded-feature and promptbook usage (doc
   [`02`](./02-copilot-in-defender-and-sentinel.md), doc
   [`03`](./03-promptbook-library.md)), read from the usage dashboard.
6. Compare the total against our E5 inclusion allocation. If it fits, no
   spend. If not, decide between provisioned SCUs or PAYG overage and
   record the decision in doc
   [`13`](../../13-licensing-and-operations.md).

The point of measuring before buying is that reported-phish volume
varies widely by tenant. Our risk-register concern about cost overrun
(doc [`01`](../../01-executive-summary.md), Sentinel ingestion) applies
in spirit here too: instrument first, commit second.

## Agent identity and RBAC

The autonomous agent runs under its own identity, scoped least
privilege. This is the same discipline as our Logic App managed
identities in [`../logic-apps/`](../logic-apps/), applied to an AI
agent.

* **Identity**: prefer a **Microsoft Entra Agent ID** created at setup,
  not a borrowed user account. It is scoped to the agent and easier to
  audit. If a user account is used instead, it must be dedicated, long-
  lived, named distinctly, covered by a Conditional Access policy that
  permits Security Copilot, and is incompatible with PIM/TAP.
* **Permissions**: the five Security operations permissions in doc
  [`01`](./01-phishing-triage-agent.md), scoped to the MDO data source,
  and nothing more.
* **Oversight rule**: the group monitoring the agent must hold
  permissions equal to or greater than the agent's, per Microsoft
  guidance. Management actions require Security Administrator in Entra.

## Audit and traceability

This is where Copilot fits our audit-trail parity requirement (doc
[`03`](../../03-trap-capability-matrix.md), doc
[`08`](../../08-abuse-mailbox-and-user-reporting.md)):

* Every agent decision, its reasoning, and its actions are documented as
  a decision tree in Defender and recorded in **Microsoft Purview audit
  logs**
  ([Phishing Triage Agent FAQ](https://learn.microsoft.com/en-us/defender-xdr/phishing-triage-agent)).
* All feedback to the agent is logged whether or not it becomes a
  lesson, with feedback ID, alert ID, incident ID, author, and date.
* Agent verdicts surface on the incident as a tagged, assigned task with
  a viewable activity workflow.

That gives us the same "every action is auditable" property we claim for
the playbook plane, extended to the autonomous tier.

## Responsible AI and control posture

Per Microsoft's Responsible AI commitments for these agents
([Phishing Triage Agent FAQ](https://learn.microsoft.com/en-us/defender-xdr/phishing-triage-agent),
[agents overview](https://learn.microsoft.com/en-us/copilot/security/agents-overview)):

* The agent operates in a zero-trust model: organisational policy is
  enforced on every action by evaluating the intent and scope of the
  operation.
* Administrators configure identity, access, and capacity limits, and
  can pause or remove the agent at any time.
* Removing the agent stops triage and deletes its feedback memory, while
  retaining the history of previously triaged incidents.

Our control levers, summarised:

| Lever | Control |
|---|---|
| Scope | Agent is read-and-classify plus FP auto-resolve only; no mailbox deletion |
| Identity | Entra Agent ID, least privilege, MDO data source only |
| Pause/stop | Pause or Remove from the agent page at any time |
| Trust ramp | Observe mode in Phase 2 before relying on auto-resolve |
| Audit | Purview audit logs + per-decision tree + feedback log |
| Cost | E5 inclusion first; measure on the usage dashboard before provisioning |

## Open items to resolve before we enable

Tracking these here so they land in doc
[`14`](../../14-open-questions.md) when we next revise it:

1. **Confirm our exact Security Copilot entitlement.** E5 inclusion
   allocation for our licence count, versus any need for provisioned
   SCUs.
2. **Confirm URBAC is activated for Defender for Office 365**, a hard
   prerequisite for the agent.
3. **Confirm the auto-resolve tuning rule is disabled** for the reported-
   phish alert (doc [`01`](./01-phishing-triage-agent.md)).
4. **Decide the observe-to-trust promotion criteria** (precision and
   recall thresholds on our parallel-run sample) before allowing
   auto-resolve to close incidents unattended.
5. **Assign the oversight group** with permissions at or above the
   agent's, and name the Security Administrator owners.

None of these are asserted as done. They are the gate list for enabling
Copilot inside the existing roadmap governance.
