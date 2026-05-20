# P1b — Phish-Remediate-Bulk (pagination helper for P1)

> **Status: shipped.** HTTP-callable from P1 (or any caller) with a
> body of `{ "networkMessageIds": ["...","..."], "actionType":
> "SoftDelete", "justification": "..." }`. Returns aggregate
> per-chunk status.

Validates against `../../tests/Test-LogicAppTemplate.ps1`: 14/14 checks pass.

Defaults: chunk size 50, 12-second inter-chunk delay → ~250 actions/min,
under the Defender XDR ~300/min ceiling.

Documented in [`10-logic-apps-playbook-library.md`](../../../10-logic-apps-playbook-library.md) §P1b.

## Purpose

The Defender XDR `messages/takeAction` API accepts a `NetworkMessageIds`
array but throttles at ~300 actions/minute. For incidents with a large
recipient set (DL fan-out, broadcast campaigns), P1 calls P1b to chunk
the action set and apply rate-limiting.

## What P1b does

1. **Trigger:** HTTP request from P1 with payload `{ messageIds: [...], action: "SoftDelete" }`.
2. **Chunk:** Split the array into pages of 50.
3. **For each page:** Call `messages/takeAction`; wait 12 seconds between
   pages to stay under the 300/min ceiling.
4. **Return:** Aggregate per-page status to the caller (P1).

## Pattern to copy from

The P2 template's `For_each_matched_message` loop has the same shape.
Set `runtimeConfiguration.concurrency.repetitions = 1` (sequential) and
add a 12-second delay between iterations via a `Delay` action.

## When P1b lands here

Drop `playbook.json` here and validate.
