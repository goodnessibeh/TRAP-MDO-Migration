# P1 — Phish-Remediate (the workhorse)

> **Status: shipped** with conservative defaults — single-stage Teams
> approval, soft-delete only, VIP detection via the Sentinel
> `VIP_Mailboxes` watchlist. Optional escalation to P6 when a VIP is
> touched (set `-VipEscalationPlaybook` parameter).

Validates against `../../tests/Test-LogicAppTemplate.ps1`: 15/15 checks pass.

## Conservative defaults

The blueprint specifies the full P1 action graph; this template bakes
in safe choices that work for most tenants. Adjust as you discover
your SOC's specifics.

| Decision | Default | Override how |
|---|---|---|
| Delete type | `SoftDelete` | Change `ActionType` in `Call_TakeAction_softdelete` action — but get legal sign-off first |
| Approval tiers | Single Teams card | Deploy P6 and pass its callback URL as `VipEscalationPlaybook` |
| VIP detection | Sentinel watchlist `VIP_Mailboxes` (column `SearchKey`) | Edit `Query_VIP_watchlist` action or pass `-VipWatchlistAlias` |
| Cross-vendor enrichment | None | Add an HTTP step before `Compute_VIP_intersection` calling VirusTotal/MDTI/AbuseIPDB |

Documented in:

* [`10-logic-apps-playbook-library.md`](../../../10-logic-apps-playbook-library.md) §P1 and §P1b
* [`02-architecture-overview.md`](../../../02-architecture-overview.md) Workflow A

## What P1 does (target shape)

1. **Trigger:** Sentinel incident on `MailMessage` entity.
2. **Enrich:** Pull AIR verdict, threat indicators, recipient set, sender
   reputation. Optional cross-vendor enrichment (VirusTotal, MDTI,
   AbuseIPDB).
3. **Severity decision:** If recipient set contains a VIP watchlist
   match OR sender domain is in a known-bad watchlist, escalate.
4. **Approval:** Teams adaptive card OR (for VIP cases) two-stage
   approval that routes via P6.
5. **Remediation:** Iterate recipients and call Defender XDR Take
   Action; for very large sets (>50 recipients) hand off to P1b
   `Phish-Remediate-Bulk` which chunks the call set.
6. **Optional fan-out:** Trigger P4 (forward trace) on the
   `NetworkMessageId` and P5 (DL expand) if any recipient is a DL.
7. **Audit:** Sentinel incident comments per stage; `OfficeActivity`
   already captures the underlying Take Action API call.

## Why not shipped here

Each item in the list above has at least one organisation-specific
decision baked in:

- VIP watchlist composition and update mechanism
- Approver routing (single SOC channel vs role-tiered)
- Soft-vs-hard delete policy (legal sign-off?)
- Cross-vendor enrichment vendor choice (and that vendor's API key
  rotation policy)
- "Auto-approve if confidence > X" thresholds

The blueprint's pseudocode in §P1 gives you the full action list. The
shape of the working JSON looks like P2/P4 concatenated — the actual
shape isn't the hard part; the policy decisions are. Treat the
existing P2/P3/P4 templates as the structural reference and add the
P1 specifics as you decide them.

## Recommended sequence

1. Ship P3 (Reporter Bridge) in Phase 1 (the OOTB deployment).
2. Ship P2 (TI Sweep) and P4 (Forward Trace) in Phase 3 once the SOC
   confirms they want them.
3. After 30 days of operation, write P1 — by then you know which of
   the P1 design questions actually need to be answered and which are
   theoretical.
4. P1b is just a pagination helper for P1; build them together.

## When P1 lands here

Drop the production-ready ARM template at `playbook.json` in this
directory and run `..\..\tests\Test-LogicAppTemplate.ps1` against it.
The validator in this repo will check shape (`$connections` references
resolve, `runAfter` graph, parameter references) automatically.
