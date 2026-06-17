# 05. Toward a zero-touch phishing pipeline

The design goal stated plainly: **eliminate manual SOC work on
user-reported phishing as far as is safe, and make every remaining
manual touch a deliberate exception rather than the default.** This doc
is the end-to-end automation chain that gets us there, the manual work
removed at each stage, and the small set of human gates we keep on
purpose.

It ties together the autonomous agent (doc
[`01`](./01-phishing-triage-agent.md)), the embedded read-side features
(doc [`02`](./02-copilot-in-defender-and-sentinel.md)), and the existing
remediation playbooks ([`../logic-apps/`](../logic-apps/)) into one
pipeline.

## The principle

Not all manual work should be eliminated. Some of it is the control that
keeps an autonomous pipeline safe. So we split SOC manual work into two
kinds:

* **Toil**: reading false alarms, copying entities between consoles,
  writing the same hunt again, drafting the same reporter reply. This we
  drive to zero.
* **Judgement**: approving an irreversible action, signing off a VIP
  mailbox purge, deciding a novel campaign's blast radius. This we keep,
  but we make it rare, fast, and well-informed.

The aim is a pipeline where an analyst only ever sees an item when their
judgement is genuinely required, and when they do, everything they need
to decide is already on the card.

## The end-to-end chain

```
User reports email
   │
   ▼
[1] Alert created: "Email reported by user as malware or phish"
   │
   ▼
[2] Phishing Triage Agent triages autonomously (LLM + detonation + TI)
   │
   ├── False Positive ──► [3] Auto-resolved. Analyst never sees it.   ✔ toil removed
   │
   └── True Positive ───► [4] Incident kept open, tagged, full rationale attached
                              │
                              ▼
                          [5] AIR auto-investigates; Copilot summary +
                              guided response pre-compute the blast radius   ✔ toil removed
                              │
                              ▼
                          [6] Sentinel automation rule routes:
                              │
                ┌───────────┴───────────────────────────────┐
                │                                            │
   High-confidence + no VIP + within policy        VIP touched, novel campaign,
                │                                   or irreversible action
                ▼                                            ▼
   [7a] Auto-approve path:                         [7b] Human gate (kept on purpose):
        P1/P2 soft-delete fires with a              P6 two-stage approval, or P1 single
        watchlist short-circuit, comment            Teams card, pre-filled with the
        back to incident   ✔ toil removed           Copilot summary   ◄ judgement, fast
                │                                            │
                └───────────────────┬────────────────────────┘
                                    ▼
                          [8] Remediation executed, incident auto-commented,
                              reporter auto-thanked (P3)   ✔ toil removed
```

## Where manual work is removed, stage by stage

| Stage | Manual work today | Removed by | Net |
|---|---|---|---|
| 2 | Analyst reads and triages every reported email (~30 min each) | Phishing Triage Agent autonomous TP/FP classification | Eliminated for the whole queue |
| 3 | Analyst closes false alarms | Agent auto-resolves FPs | Eliminated |
| 4 | Analyst writes up why it is/ isn't phish | Agent's per-verdict rationale + decision tree | Eliminated |
| 5 | Analyst gathers entities, runs blast-radius hunts by hand | AIR + Copilot summary + natural-language-to-KQL pre-compute it | Eliminated for routine cases |
| 6 | Analyst decides routing | Sentinel automation rule with watchlist short-circuit | Eliminated for the in-policy majority |
| 7a | Analyst approves routine soft-delete | Conditional auto-approve (same pattern P2 already uses after ~30 days) | Eliminated for low-risk cases |
| 7b | Analyst approves high-risk action | **Kept**, but pre-filled with Copilot context so it is a fast yes/no | Minimised, not removed |
| 8 | Analyst comments the incident and thanks the reporter | Playbook auto-comment + P3 reporter bridge | Eliminated |

The result: an analyst's only routine interaction is stage 7b, and only
for the genuinely high-risk minority.

## The conditional auto-approve, made explicit

The biggest remaining lever after the agent is **stage 7a**: letting
confirmed, low-risk phish remediate without a human clicking approve.
The repo already has the mechanism, it is just described for P2:

> after ~30 days >70% of P2 fires auto-approve through an upstream
> Sentinel automation rule with a watchlist short-circuit. The Teams
> card only appears for novel detections.
> ([`../logic-apps/P2-ti-sweep-remediate/README.md`](../logic-apps/P2-ti-sweep-remediate/README.md))

We generalise that same pattern to the user-reported path. A Sentinel
automation rule sits between the agent's True-Positive verdict and the
remediation playbook and decides auto-approve vs. human gate from
explicit conditions:

| Condition | Routing |
|---|---|
| Recipient set contains a VIP or VAP watchlist member | Human gate (P6 two-stage) |
| Sender/URL/hash already on a `KnownBad_*` watchlist | Auto-approve (P1/P2 soft-delete) |
| Action is hard-delete or otherwise irreversible | Human gate, always |
| Novel campaign (no prior watchlist or agent-lesson match) | Human gate for the first occurrence, then promote to watchlist |
| Everything else within policy | Auto-approve, soft-delete, comment back |

This keeps the conservative defaults the repo insists on
([`../logic-apps/README.md`](../logic-apps/README.md)): soft-delete only
from a playbook, hard-delete always manual, VIPs always escalated. We
are not loosening the safety rails, we are letting the in-policy
majority flow through them without a human keystroke.

## The human gates we keep on purpose

These stay manual by design. Removing them would trade safety for speed
in the wrong direction.

1. **Irreversible actions.** Hard-delete (purge) never fires from a
   playbook. It stays a deliberate SOC action in the Defender Action
   Center, per the existing repo posture.
2. **VIP and VAP mailboxes.** Anything touching a watchlisted high-value
   person routes through P6 two-stage approval.
3. **Novel campaigns.** The first instance of an unseen campaign gets a
   human look; once judged, it becomes an agent lesson or a watchlist
   entry, so the *second* instance is automatic. The human cost is paid
   once per campaign, not once per message.
4. **Agent verdict disputes.** When an analyst disagrees with the agent,
   they correct it and teach it (doc
   [`01`](./01-phishing-triage-agent.md)), which removes that class of
   manual correction going forward.

Every one of these is a judgement gate, not toil, and three of the four
are self-extinguishing: the work teaches the system, so the same
decision does not come back.

## What still needs a human, honestly

Two things from doc [`12`](../../12-limitations-and-gaps.md) are not
solved by any amount of agent autonomy, because they are telemetry
limits, not workload limits:

* **External-forward-following.** Once mail leaves the tenant, there is
  nothing to automate against. We block at egress and alert on
  auto-forward config changes, but the investigation of an external leak
  stays human.
* **Cross-tenant remediation.** Single-tenant Defender means a
  multi-tenant action is still a per-tenant fan-out.

Naming these keeps the "eliminate manual work" goal honest: we remove
the toil, we minimise the judgement gates, and we are explicit about the
residue that the platform cannot automate.

## How we prove the elimination during Phase 2

The parallel run (doc [`11`](../../11-implementation-roadmap.md)) is
where we measure how much manual work actually went away, using
first-party metrics rather than assertion:

| Measure | Source | Target direction |
|---|---|---|
| % of reported mail auto-resolved as FP | Agent Performance tab / incident card | High, removes the biggest toil block |
| % of true positives auto-approved at stage 7a | Sentinel automation-rule run history | Rises over time as watchlists/lessons mature |
| Analyst minutes per reported message | parallel-run workbook | Falls toward agent MTTT + occasional 7b |
| Human gates hit per 100 reports | automation-rule history | Falls and stabilises at the genuine-judgement rate |

If those move the right way on a representative sample, we have evidence
that the pipeline eliminated the toil without giving up the controls.
That evidence, not a claim, is what justifies promoting auto-approve
from observe to trusted.

## Sequencing this safely

We do not switch on full auto-approve on day one. The ramp:

1. **Phase 2, observe.** Agent triages; all true positives still go to a
   human gate. Measure agent precision.
2. **Phase 2 to 3, assisted.** Auto-approve only for items matching a
   `KnownBad_*` watchlist (highest confidence). Everything else gated.
3. **Phase 3, conditional auto.** Widen auto-approve to the in-policy
   conditions above as watchlists and agent lessons mature, exactly as
   P2 widened after ~30 days.
4. **Steady state.** Humans see only stage 7b. The pipeline runs itself
   for the rest.

This is the same crawl-walk-run the repo already applies to P2,
extended across the whole user-reported pipeline with the agent doing
the triage that used to be the analyst's largest manual cost.
