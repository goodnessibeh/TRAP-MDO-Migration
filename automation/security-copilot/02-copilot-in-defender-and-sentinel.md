# 02. Copilot in Defender and Sentinel

The embedded, analyst-driven side of Security Copilot. Where the
Phishing Triage Agent (doc [`01`](./01-phishing-triage-agent.md)) runs
autonomously, these features sit inside the consoles our analysts
already use and accelerate the work a human is doing right now:
understanding an incident, choosing the next action, and writing the
hunt. Sources:
[Copilot in Defender](https://learn.microsoft.com/en-us/defender-xdr/security-copilot-in-microsoft-365-defender),
[Security Copilot with Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/sentinel-security-copilot).

All of this is **read-side**. It summarises, recommends, and generates
queries. It does not change tenant state, so it carries the lowest risk
of anything in this directory and is the first thing we turn on (Phase 2
in the [enable order](./README.md#recommended-enable-order)).

## Incident summarisation

On any Defender XDR incident page (including Sentinel incidents once
Sentinel is onboarded to the Defender portal), Copilot generates a
plain-language summary that fuses our internal telemetry with Microsoft
Threat Intelligence. Source:
[Summarize incidents with Copilot](https://learn.microsoft.com/en-us/defender-xdr/security-copilot-m365d-incident-summary).

Why it matters for us:

* Cuts the read-in time per incident, which is part of the MTTR story in
  doc [`01`](../../01-executive-summary.md). One paragraph replaces
  scrolling the alert timeline and entity graph.
* Produces an **executive incident report** for non-technical audiences,
  which we can attach to the parallel-run evidence in doc
  [`11`](../../11-implementation-roadmap.md) without an analyst
  hand-writing it.

## Guided response

On the incident page Copilot recommends next-best actions, sequenced.
For a confirmed phishing incident that typically means the path into our
existing remediation: take action on the email entity, block the sender
or URL in the Tenant Allow/Block List, and so on. This complements doc
[`05`](../../05-defender-xdr-air-zap.md) (the eligible action set) by
putting the recommendation next to the action, rather than leaving the
analyst to recall the runbook.

Guided response **recommends**; the analyst still approves and executes.
That keeps it consistent with our soft-delete-and-approve posture.

## Natural-language-to-KQL

This is the direct uplift to doc
[`09`](../../09-kql-detection-library.md). Our KQL library is the
curated, production-grade set of hunts (campaign clustering,
forward-tracking, DL expansion, IOC sweeps). Natural-language-to-KQL
covers the **long tail**: the one-off hunt an analyst needs mid-incident
that is not worth adding to the library.

Two plugins provide it (source:
[Security Copilot with Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/sentinel-security-copilot)):

* **Microsoft Sentinel (Preview)** plugin: lets Copilot read our
  Sentinel incidents and data.
* **Natural language to KQL for Microsoft Sentinel (Preview)** plugin:
  generates and runs KQL hunting queries against Sentinel data. Works in
  the standalone portal and in the advanced-hunting section of the
  Defender portal.

In the unified Defender portal, Copilot can generate advanced-hunting
queries across both Defender XDR and Sentinel tables, though not every
Sentinel table is supported yet.

Practical division of labour for our team:

| Need | Use |
|---|---|
| A hunt we run repeatedly (campaign cluster, forward-trace) | The curated query in doc [`09`](../../09-kql-detection-library.md) |
| A novel mid-incident question ("show me all mail from this sender to VIPs in the last 3 days") | Natural-language-to-KQL, then refine |
| Promoting a good ad-hoc hunt to the library | Copy the generated KQL into doc 09 after review |

The static library stays authoritative. Copilot does not replace it; it
shortens the path to the queries that never make it into a library.

## Setup to get full value

Source:
[Security Copilot with Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/sentinel-security-copilot).

1. **Onboard Sentinel to the Defender portal** so Sentinel incidents
   unify with Defender XDR incidents. This is what lets Copilot in
   Defender summarise and guide on Sentinel incidents, and it aligns
   with the single-console outcome we describe in doc
   [`02`](../../02-architecture-overview.md).
2. **Set a default Sentinel workspace for Copilot**. In the standalone
   portal (securitycopilot.microsoft.com), open **Sources**, enable the
   **Microsoft Sentinel (Preview)** plugin, and configure the default
   workspace. This sharpens prompt accuracy. Override per prompt when
   needed, for example: `What are the top 5 high priority Sentinel
   incidents in workspace "soc-sentinel-workspace"?`
3. **Enable the natural-language-to-KQL plugin** for advanced hunting.

## Standalone vs. embedded

* **Embedded** (inside Defender / Sentinel): summary, guided response,
  inline query generation. This is where analysts spend their day, so it
  is where most of the value lands for us.
* **Standalone** (securitycopilot.microsoft.com): the full chat surface
  and promptbooks (doc [`03`](./03-promptbook-library.md)). Better for
  cross-incident questions, reporting, and running our project
  promptbooks.

## The optional Logic Apps hook

Security Copilot exposes a Logic Apps connector, which means a playbook
can call Copilot for enrichment or summarisation as a step. The
realistic use for us is a **read-only summary step inside P1 or P6**
(doc [`10`](../../10-logic-apps-playbook-library.md)): before the Teams
approval card is posted, call Copilot to summarise the email entity and
TI context, and include that summary on the card so the approver decides
with full context.

We do not bake this into the shipped templates. Per the existing
convention in [`../logic-apps/README.md`](../logic-apps/README.md),
enrichment that changes a playbook's behaviour is an opt-in decision the
SOC owns, not a default. This is noted as an available enhancement, to
add behind that same gate if the parallel-run data shows approvers want
more context on the card.

## Risk posture

Everything in this doc is read-side and recommend-side. It does not
delete mail, does not change policy, and does not act autonomously. The
only cost is SCU consumption per prompt, tracked in
[doc 04](./04-licensing-scu-governance.md). That makes it the safe first
step: real analyst value, no tenant-state risk.
