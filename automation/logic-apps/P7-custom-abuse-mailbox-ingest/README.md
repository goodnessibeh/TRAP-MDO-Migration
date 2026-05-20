# P7 — Custom-Abuse-Mailbox-Ingest

> **Status: shipped — but most teams should skip this.** Microsoft's
> built-in custom reporting mailbox (configured in
> [`00-MDO-out-of-the-box-deployment-guide.md`](../../../00-MDO-out-of-the-box-deployment-guide.md) §2.3)
> covers ~95 % of the use case natively. Deploy P7 only when reports
> arrive at a shared abuse mailbox from non-Outlook clients that
> can't reach the built-in Report button, or from external partners.

Validates against `../../tests/Test-LogicAppTemplate.ps1`: 14/14 checks pass.

Polls the abuse mailbox every 5 minutes, submits each new message via
`POST /security/threatSubmission/emailThreats`, replies thank-you,
marks as read.

Documented in [`08-abuse-mailbox-and-user-reporting.md`](../../../08-abuse-mailbox-and-user-reporting.md)
and [`10-logic-apps-playbook-library.md`](../../../10-logic-apps-playbook-library.md) §P7.

## When you actually need this

* Reports arrive at a legacy `abuse@<domain>` shared mailbox from
  non-Outlook clients (mobile clients, third-party mail apps) that the
  built-in Report button can't reach.
* Hybrid mailboxes where the on-prem side still routes reports via
  legacy transport.
* You want to process reports forwarded as attachments from external
  partners.

If none of those apply, **stop**. Use Microsoft's built-in path —
P7 is a maintenance burden you don't need.

## Flow

1. **Trigger:** Office 365 Outlook "When a new email arrives" against
   the abuse mailbox.
2. **Parse:** Extract the original message from `.eml` attachment (or
   from the forwarded body if no attachment).
3. **Submit:** Microsoft Graph `POST /security/threatSubmission/emailThreats`
   with category=Phishing.
4. **Notify reporter:** Same thank-you as P3.
5. **Create incident:** Sentinel API to surface in the SOC queue.

## Pattern to copy from

P3 (Reporter Bridge) gives you the Outlook Send-email shape.
The Submissions API call is a standard HTTP+MI step like P2/P4.

## When P7 lands here

Drop `playbook.json` here. Document the abuse mailbox address and the
external partners (if any) that forward to it.
