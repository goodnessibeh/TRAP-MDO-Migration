# P6 — Two-Stage-Approval-VIP

> **Status: shipped.** HTTP-callable from P1 (pass the resource URL via
> P1's `-VipEscalationPlaybook` parameter). Two Teams adaptive cards:
> Stage 1 → SOC L1 channel; on approve, Stage 2 → SOC Manager / Legal
> channel. Both must approve. Either rejection halts with an incident
> comment.

Validates against `../../tests/Test-LogicAppTemplate.ps1`: 15/15 checks pass.

Deploy only if your SOC operates a tiered approval model — most teams
find single-stage approval (P1's default) sufficient.

Documented in [`10-logic-apps-playbook-library.md`](../../../10-logic-apps-playbook-library.md) §P6.

## Purpose

Defender Action Center is single-tier — a Data Investigator clicks
Approve and the action runs. For incidents that touch a CEO/CFO
mailbox, some organisations want a second approval (SOC manager or
Legal) before remediation lands.

P6 inserts that second tier.

## Flow

1. **Trigger:** called by P1 (the workhorse) when the recipient set
   contains a VIP watchlist match.
2. **Stage 1:** Teams adaptive card to the SOC-L2 channel.
3. On L2 approve: **Stage 2:** Teams adaptive card to the SOC-L3 /
   Manager channel.
4. On L3 approve: forward the original Take Action call (or call P1b
   for bulk).
5. On reject at any stage: comment back to incident with the rejecting
   approver and reason.

## Pattern to copy from

The P2 template's `Post_Teams_approval_card` and `On_approval_branch`
sections give you the structural shape. Stack two of them in P6.

## When P6 lands here

Drop `playbook.json` here. The validator's `runAfter` graph check will
catch any orphan branches the two-stage logic introduces.
