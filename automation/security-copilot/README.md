# Security Copilot. Agentic uplift for the MDO stack

How Microsoft Security Copilot extends the TRAP-to-MDO architecture in
this repo. This directory is an architecture and operations reference,
not a set of deployable templates. Security Copilot agents are
configured in the Defender, Sentinel, and Entra portals, not deployed
as ARM, so there is nothing here to `New-AzResourceGroupDeployment`.
What we ship instead is the decision record, the setup runbooks, the
permission and identity model, the SCU sizing, and the project-specific
promptbook library.

Security Copilot is **additive uplift on top of the existing design**.
It does not replace AIR, ZAP, Defender XDR Take Action, or any of the
eight Logic App playbooks in [`../logic-apps/`](../logic-apps/). It
inserts an autonomous reasoning tier in front of the analyst and a
natural-language tier in front of our KQL and incident-investigation
work. Everything below maps a Copilot capability to a document we
already have and to the operational outcome it improves.

**The objective driving this directory is to eliminate manual SOC work
on user-reported phishing as far as is safe.** The Phishing Triage Agent
removes the triage toil, the embedded features remove the gather-and-
write toil, and a conditional auto-approve rule lets the low-risk
majority remediate without a human keystroke. The end-to-end chain, the
toil removed at each stage, and the small set of human gates we keep on
purpose are in [doc 05](./05-zero-touch-phishing-pipeline.md). Read that
for the through-line; the other docs are the components it assembles.

## Where Copilot sits in our architecture

```
User report ─► "Email reported by user as malware or phish" alert
                         │
                         ▼
          ┌──────────────────────────────┐
          │  Phishing Triage Agent        │  ◄── NEW autonomous tier
          │  (LLM triage: TP / FP)        │      (this directory, doc 01)
          └──────────────────────────────┘
              │ FP: auto-resolve        │ TP: keep open, tag, explain
              ▼                         ▼
          (queue noise removed)   AIR / ZAP / Defender XDR Take Action
                                  + Logic App playbooks P1..P7
                                  (../logic-apps/, unchanged)

Across the whole SOC surface:
  Copilot in Defender + Sentinel  ─► incident summary, guided response,
                                     natural-language-to-KQL, promptbooks
                                     (doc 02, doc 03)
```

The Phishing Triage Agent decides *what is worth remediating* and
explains why. Our existing remediation plane still does the *pulling*.
That separation is deliberate: it keeps the autonomous component
read-and-classify only, and leaves every tenant-state change behind the
human-approval gates the playbooks already enforce.

## Documents in this directory

| # | Document | Purpose |
|---|----------|---------|
| 00 | **[README](./README.md)** (this file) | Capability-to-project map, agent catalogue, enable order, SCU sizing summary |
| 01 | [Phishing Triage Agent](./01-phishing-triage-agent.md) | The flagship uplift. Setup runbook, prerequisites, the alert-tuning gotcha, how it sits vs. AIR and P1/P3, capability-matrix upgrade, parallel-run measurement |
| 02 | [Copilot in Defender and Sentinel](./02-copilot-in-defender-and-sentinel.md) | Embedded experiences: incident summarisation, guided response, natural-language-to-KQL, incident reports. Mapped to our docs 06 and 09 |
| 03 | [Project promptbook library](./03-promptbook-library.md) | Reusable prompts and promptbooks tailored to our incident types: phishing investigation, forward-trace, DL expansion, TI sweep, reporter comms |
| 04 | [Licensing, SCU sizing, and governance](./04-licensing-scu-governance.md) | E5 inclusion maths, SCU capacity planning for our tenant size, agent identity model, RBAC, audit, Responsible AI posture |
| 05 | [Toward a zero-touch phishing pipeline](./05-zero-touch-phishing-pipeline.md) | **The automation through-line.** End-to-end chain, manual work removed at each stage, the conditional auto-approve, the human gates we keep on purpose, and how we prove the elimination in Phase 2 |

## Capability-to-project map

| Copilot capability | Enhances | Existing doc | Net effect |
|---|---|---|---|
| **Phishing Triage Agent** | User-reported phishing pipeline | [`08`](../../08-abuse-mailbox-and-user-reporting.md) | Autonomous TP/FP triage before the analyst. Removes FP queue load, explains every verdict |
| Agent feedback lessons | Reporter / analyst tuning loop (CLEAR-equivalent) | [`03`](../../03-trap-capability-matrix.md), [`12`](../../12-limitations-and-gaps.md) | Moves the analyst-tuning parity row from Partial toward Native |
| Incident summarisation | Analyst load, MTTR | [`01`](../../01-executive-summary.md), [`06`](../../06-sentinel-soar-orchestration.md) | One-paragraph incident summary with TI context, reduces read-in time |
| Guided response | Action selection in Defender XDR | [`05`](../../05-defender-xdr-air-zap.md) | Next-best-action recommendations on the incident page |
| Natural-language-to-KQL | Ad-hoc hunting beyond the static library | [`09`](../../09-kql-detection-library.md) | Analysts express hunts in English, Copilot writes the KQL against our tables |
| Incident-investigation promptbook | Repeatable triage and reporting | [`06`](../../06-sentinel-soar-orchestration.md) | One promptbook produces related alerts, reputation, users, devices, exec summary |
| Logic Apps Copilot connector | Enrichment inside playbooks | [`10`](../../10-logic-apps-playbook-library.md) | Optional summarisation step inside P1/P6 before the approval card |
| Conditional Access Optimization Agent | Identity posture (adjacent) | [`13`](../../13-licensing-and-operations.md) | Out of core scope, noted for completeness |
| Threat Intelligence Briefing Agent | TI-driven retroactive sweeps | [`09`](../../09-kql-detection-library.md) Q5, [`P2`](../logic-apps/P2-ti-sweep-remediate/) | Proactive daily TI briefing that can seed P2 sweep priorities |

## Agent catalogue (relevant subset)

Security Copilot ships a growing set of first-party agents across the
Microsoft security products. Source:
[Security Copilot agents overview](https://learn.microsoft.com/en-us/copilot/security/agents-overview).
The ones that touch this project:

| Agent | Runs in | Relevance to us |
|---|---|---|
| **Phishing Triage Agent** | Defender XDR | **Core.** Autonomous triage of user-reported phish. See doc 01 |
| Security Alert Triage Agent | Defender XDR | Same engine as Phishing Triage, extended to a broader alert set (identity and cloud alerts, preview). Future scope |
| Threat Intelligence Briefing Agent | Security Copilot standalone | Generates proactive TI briefings. Can prioritise our P2 TI-sweep targets |
| Conditional Access Optimization Agent | Microsoft Entra | Identity-posture adjacent. Out of core email scope, listed for completeness |
| Vulnerability Remediation Agent | Microsoft Intune | Endpoint posture. Not in email-remediation scope |

Agents need no special licensing beyond Security Copilot itself, and
consume SCUs like any other Copilot feature
([agents overview](https://learn.microsoft.com/en-us/copilot/security/agents-overview)).
Each agent is assigned a scoped identity (Microsoft Entra Agent ID
recommended) and least-privilege permissions at setup. The identity and
RBAC model is in [doc 04](./04-licensing-scu-governance.md).

## Recommended enable order

This slots into the phased roadmap in
[`../../11-implementation-roadmap.md`](../../11-implementation-roadmap.md).
We do not enable Copilot before the MDO baseline is stable, because the
Phishing Triage Agent depends on user-reported settings and the
reported-phish alert policy being live.

| When | Action | Doc |
|---|---|---|
| Phase 1 (after OOTB baseline) | Confirm Security Copilot entitlement (E5 inclusion or provisioned SCUs); set default Sentinel workspace for Copilot | [04](./04-licensing-scu-governance.md), [02](./02-copilot-in-defender-and-sentinel.md) |
| Phase 2 (parallel run) | Stand up Copilot in Defender and Sentinel (summary, guided response, NL2KQL). Low risk, read-only, immediate analyst value | [02](./02-copilot-in-defender-and-sentinel.md) |
| Phase 2 (parallel run) | Enable the Phishing Triage Agent in **trial/observe** mode; measure its TP/FP calls against analyst ground truth before trusting auto-resolve | [01](./01-phishing-triage-agent.md) |
| Phase 3 | Import the project promptbooks; wire the optional Copilot enrichment step into P1/P6 if the parallel-run data justifies it | [03](./03-promptbook-library.md) |
| Phase 3+ | Evaluate the Threat Intelligence Briefing Agent as a feed into P2 sweep prioritisation | [03](./03-promptbook-library.md) |

## SCU sizing in one line

For an E5 estate the SCU floor is likely already covered: the E5
inclusion benefit grants **400 SCUs/month per 1,000 paid E5 licences**
(scaling for smaller tenants, capped at 10,000/month), with no overage
billing today
([Security Copilot inclusion](https://learn.microsoft.com/en-us/copilot/security/security-copilot-inclusion)).
Standalone provisioned SCUs run **~$4/hour** (~$2,920/month each running
24/7). The Phishing Triage Agent's Performance tab reports
cost-per-email-processed and SCU consumption so we can size from real
usage during the Phase 2 trial. Full maths in
[doc 04](./04-licensing-scu-governance.md).

## What this directory deliberately does not claim

* It does not claim Copilot is deployed or that any sign-off exists.
  These are proposed enhancements, sequenced behind the existing
  roadmap gates. Enabling the Phishing Triage Agent in a tenant is a
  change that needs the same governance any other tenant change needs.
* It does not change our two genuinely-impossible gaps (cross-tenant
  remediation, external-forward-following). Copilot reasons over our
  telemetry; it does not extend the telemetry boundary.
* It does not move remediation authority to an autonomous agent. The
  Phishing Triage Agent classifies and resolves false positives only.
  Every state-changing remediation stays behind the human-approval
  gates the playbooks already enforce.
