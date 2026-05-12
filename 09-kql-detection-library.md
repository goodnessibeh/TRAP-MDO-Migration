# KQL Detection and Hunting Library

Production queries that back the analytics rules, automation rules, and
playbooks elsewhere in this blueprint. Every query is annotated with the
intent, the table dependencies, and the operational caveats that bit us
in testing.

These are written for the **Defender XDR Advanced Hunting unified schema**.
Anything that says `let X = _GetWatchlist('...')` assumes you have already
created the named watchlist in Sentinel; queries against
`ThreatIntelIndicators` assume the new TI schema (May 2025+) is live in
the workspace.

A few conventions used throughout:

* `NetworkMessageId` is the Microsoft-internal pivot. It joins all `Email*`
  tables and is unique per (recipient, original message). Use it instead of
  `InternetMessageId` when correlating inside the tenant.
* `InternetMessageId` is RFC 5322 `Message-ID:`. Use it when a message
  arrived from outside or when a third party (a TI feed, a user-supplied
  forensic artefact) gives you the ID.
* All time pivots use `Timestamp` for `EmailEvents` family and
  `TimeGenerated` for everything else. The two are usually within seconds
  of each other but not always.

---

## Q1. Same-message multi-recipient enumeration

**Use it for:** finding every recipient of a known phish so the remediation
playbook can fan out across them. This is the foundation query for
Workflow A in the architecture overview.

```kusto
let target = "00000000-0000-0000-0000-000000000000"; // NetworkMessageId
EmailEvents
| where Timestamp > ago(7d)
| where NetworkMessageId == target
| project Timestamp,
          NetworkMessageId,
          InternetMessageId,
          Subject,
          SenderFromAddress,
          RecipientEmailAddress,
          DeliveryAction,
          DeliveryLocation,
          LatestDeliveryAction,
          LatestDeliveryLocation,
          ThreatTypes
| summarize Recipients = make_set(RecipientEmailAddress),
            DeliveryStates = make_set(LatestDeliveryLocation),
            FirstSeen = min(Timestamp),
            LastSeen = max(Timestamp)
            by NetworkMessageId, Subject, SenderFromAddress
```

If the result returns zero rows, the message is older than the
`EmailEvents` retention window (default 30 days in Advanced Hunting). Fall
back to `Get-MessageTraceV2` in EXO PowerShell, which gives you a 90-day
ceiling at the cost of much weaker filtering.

---

## Q2. URL click correlation

**Use it for:** answering "did anyone click the bad link before we pulled
the message?". Sister query to Q1; both should run as part of the
remediation playbook so you can flag clicked-on recipients for
endpoint and identity follow-up.

```kusto
let target = "00000000-0000-0000-0000-000000000000";
let recipients = EmailEvents
    | where Timestamp > ago(7d)
    | where NetworkMessageId == target
    | distinct RecipientEmailAddress;
UrlClickEvents
| where Timestamp > ago(7d)
| where AccountUpn in (recipients)
| join kind=inner (
    EmailUrlInfo | where Timestamp > ago(7d) | where NetworkMessageId == target
  ) on Url
| project Timestamp, AccountUpn, Url, ActionType, IsClickedThrough, NetworkMessageId
| order by Timestamp asc
```

`UrlClickEvents` only populates for URLs that Safe Links wrapped. If the
message bypassed Safe Links (an Allow rule, a SecOps mailbox exclusion, a
URL list that includes the host), this query will under-count clicks.
That is a Safe Links coverage problem, not a query problem.

---

## Q3. Custom campaign clustering

**Use it for:** finding TRAP-style campaigns that Microsoft's native
Campaigns view did not group. Useful when an attacker rotates subject
lines but reuses URL infrastructure, or vice versa.

```kusto
let lookback = 7d;
let recent = EmailEvents
    | where Timestamp > ago(lookback)
    | where ThreatTypes has_any ("Phish", "Malware")
    | extend SubjectHash = hash_sha256(Subject)
    | extend SenderDomain = tolower(extract(@"@(.+)$", 1, SenderFromAddress));
let urls = EmailUrlInfo
    | where Timestamp > ago(lookback)
    | extend UrlHost = tolower(tostring(parse_url(Url).Host));
recent
| join kind=leftouter urls on NetworkMessageId
| extend ClusterKey = strcat(coalesce(SenderDomain, "?"),
                              "|", coalesce(SubjectHash, "?"),
                              "|", coalesce(UrlHost, "?"))
| summarize MessageCount = dcount(NetworkMessageId),
            Recipients = make_set(RecipientEmailAddress, 100),
            FirstSeen = min(Timestamp),
            LastSeen = max(Timestamp)
        by ClusterKey, SenderDomain, SubjectHash, UrlHost
| where MessageCount >= 3
| order by MessageCount desc
```

Tuning notes:

* The `ClusterKey` collapses sender domain, subject hash, and URL host into
  a single string. That is intentional: any rotated component still produces
  a unique key. If you want broader grouping (e.g. ignore subject hash
  rotation), drop `SubjectHash` from the strcat.
* `make_set(..., 100)` caps the recipient list at 100 to keep entity
  payloads under the 64 KB Sentinel entity field cap. Adjust if you want
  fewer / more.
* `MessageCount >= 3` is a reasonable noise floor. Drop to 2 if you are
  hunting low-volume targeted campaigns; raise to 10+ for bulk filtering.

---

## Q4. Internal forward tracking

**Use it for:** finding the messages an internal recipient forwarded to
other internal users after the original phish landed. This is the closest
KQL gets to TRAP's forward-following. It is fundamentally limited by what
`EmailEvents` records: forwards that never went through EXO transport
(e.g. a user copy-pasted into a new message) are invisible.

```kusto
let target_message_id = "<original Internet Message ID>";
let target_subject = "Q4 Bonus Letter";
let original = EmailEvents
    | where Timestamp > ago(7d)
    | where InternetMessageId == target_message_id
    | distinct RecipientEmailAddress, SenderFromAddress, Subject;
let suspected_forwarders = original | distinct RecipientEmailAddress;
EmailEvents
| where Timestamp > ago(7d)
| where SenderFromAddress in (suspected_forwarders)
| where EmailDirection == "Intraorg"
| where Subject startswith "Fwd:" or Subject startswith "FW:" or Subject contains target_subject
| project Timestamp, NetworkMessageId, SenderFromAddress, RecipientEmailAddress,
          Subject, InternetMessageId
| order by Timestamp asc
```

Honest caveats:

* `Subject` matching on `Fwd:` / `FW:` is heuristic. Some clients localise
  the prefix or strip it entirely. The fallback is a body-fingerprint match
  but `EmailEvents` does not expose body content.
* `EmailDirection == "Intraorg"` excludes external forwards. We cannot
  remediate external recipients regardless, but if you want them in the
  result for auditing, drop this filter.
* The `In-Reply-To` / `References` headers would be the gold-standard
  correlation, but Microsoft does not expose those columns in `EmailEvents`.
  For that level you need `Get-MessageTraceV2` or a Graph
  `/users/{id}/messages?$select=internetMessageHeaders` per-recipient call.

---

## Q5. Threat intelligence retroactive sweep (the big one)

**Use it for:** finding every message in the last 7 days that touched any
URL or sender on a TI feed. This is the closest analogue to TRAP's
TAP-driven retroactive sweep. Schedule it to run every 30 minutes. The
output drives the TI sweep playbook (Workflow C).

```kusto
let lookback = 7d;
let high_conf_url_iocs = ThreatIntelIndicators
    | where ValidUntil > now()
    | where ObservableType == "url"
    | where ConfidenceScore >= 70
    | distinct ObservableValue, ThreatType, ConfidenceScore;
let high_conf_domain_iocs = ThreatIntelIndicators
    | where ValidUntil > now()
    | where ObservableType in ("domain-name", "hostname")
    | where ConfidenceScore >= 70
    | distinct ObservableValue;
let url_hits = EmailUrlInfo
    | where Timestamp > ago(lookback)
    | join kind=inner high_conf_url_iocs on $left.Url == $right.ObservableValue
    | project Timestamp, NetworkMessageId, Url, ThreatType, ConfidenceScore;
let domain_hits = EmailEvents
    | where Timestamp > ago(lookback)
    | extend SenderDomain = tolower(extract(@"@(.+)$", 1, SenderFromAddress))
    | where SenderDomain in (high_conf_domain_iocs)
    | project Timestamp, NetworkMessageId, SenderDomain;
union url_hits, domain_hits
| join kind=inner (
    EmailEvents | where Timestamp > ago(lookback)
                | project NetworkMessageId, Subject, SenderFromAddress,
                          RecipientEmailAddress, LatestDeliveryLocation
  ) on NetworkMessageId
| summarize Recipients = make_set(RecipientEmailAddress, 100),
            HitTypes = make_set(strcat(coalesce(Url, ""), "/", coalesce(SenderDomain, ""))),
            FirstSeen = min(Timestamp),
            LastSeen = max(Timestamp),
            MessageCount = dcount(NetworkMessageId)
        by Subject, SenderFromAddress
| order by MessageCount desc
```

This query is intentionally aggressive on confidence (>=70). Drop to 50 if
your TI feed is well curated, raise to 80 if you are getting noisy hits.
The `union` is cheap because both legs are small after the IOC filter; the
expensive operation is the final `EmailEvents` join, which you should
constrain by lookback rather than by additional filters (Microsoft
optimises window queries on `Timestamp`).

If your TI feed is large (millions of indicators), the `join kind=inner` on
`Url` will degrade. Two mitigations:

1. Pre-filter IOCs to `ThreatType in ("Phishing", "MalwareHost")` before
   the join.
2. Use `lookup` instead of `join` and supply a `SearchKey` on the IOC
   side. `lookup` is cheaper for left-skewed joins.

---

## Q6. Per-recipient read state

**Use it for:** the TRAP "did the recipient read it before we pulled?"
question. KQL alone cannot answer it, because `EmailEvents` does not record
mail item state. The hybrid pattern below uses KQL to enumerate recipients
and a Logic App fan-out to query Graph per-recipient.

```kusto
// Step 1. enumerate recipients in KQL
let target = "00000000-0000-0000-0000-000000000000";
EmailEvents
| where Timestamp > ago(7d)
| where NetworkMessageId == target
| project RecipientEmailAddress, InternetMessageId
```

Then in the playbook, for each recipient row, call:

```http
GET https://graph.microsoft.com/v1.0/users/{recipient}/messages?
    $filter=internetMessageId eq '<id>'
    &$select=id,isRead,receivedDateTime
```

This requires `Mail.Read` (application) scoped via RBAC for Applications to
the recipients you care about. Without scope, you are granting a remediation
worker tenant-wide read of every mailbox, which is unacceptable.

Fanning out across thousands of recipients hits the Graph 4-concurrent-
per-mailbox cap and the 130k-per-10s tenant cap quickly. Use a Logic App
ForEach with `concurrency = 5` and accept the resulting ~10-second
turnaround for a 50-recipient cluster.

---

## Q7. Auto-forward configuration abuse alerting

**Use it for:** detecting when a user (or an attacker who has compromised a
user) sets an auto-forward to an external address. Run as an NRT rule
because the time-to-detect matters; once a forward is in place, all future
phish that lands in that mailbox is also leaked outside.

```kusto
OfficeActivity
| where TimeGenerated > ago(1h)
| where Operation in ("Set-Mailbox", "New-InboxRule", "Set-InboxRule")
| where Parameters has_any ("ForwardingSmtpAddress", "ForwardTo", "RedirectTo")
| extend ParamObj = parse_json(Parameters)
| mv-expand ParamObj
| where tostring(ParamObj.Name) in ("ForwardingSmtpAddress", "ForwardTo", "RedirectTo")
| extend ForwardTarget = tostring(ParamObj.Value)
| where ForwardTarget != ""
| extend ForwardDomain = tolower(extract(@"@(.+)$", 1, ForwardTarget))
| extend IsExternal = iff(ForwardDomain !endswith "contoso.com", true, false)
| where IsExternal == true
| project TimeGenerated, UserId, Operation, ForwardTarget, ForwardDomain
```

Substitute your accepted domains in the `IsExternal` calculation. If you
have many accepted domains, store them in a `AcceptedDomains` watchlist
and look up against that.

This query catches both the legitimate-looking `Set-Mailbox` PowerShell
path (typical of admin-driven mailbox config) and the more common
inbox-rule path that attackers use post-compromise. Both should fire on
the same alert with severity High and an automation rule that disables the
rule and forces a password reset.

---

## Q8. Distribution-list expansion and recipient enumeration

**Use it for:** the case where a phish was sent to a DL, you've pulled the
DL members, and you want to confirm every member actually received the
mail (delivery to a DL fans out at the gateway, but if a member has a
forwarding rule or is on retention/legal-hold, behaviour can differ).

```kusto
let target = "00000000-0000-0000-0000-000000000000";
let dl_address = "all-staff@contoso.com";
EmailEvents
| where Timestamp > ago(7d)
| where NetworkMessageId == target or InternetMessageId in (
    EmailEvents | where NetworkMessageId == target | distinct InternetMessageId
  )
| project RecipientEmailAddress, OriginalDeliveryAction, LatestDeliveryAction,
          DeliveryLocation, LatestDeliveryLocation, RecipientObjectId
| extend Status = strcat(LatestDeliveryAction, " / ", LatestDeliveryLocation)
| summarize Recipients = make_set(RecipientEmailAddress) by Status
```

This is also a useful sanity check after a bulk pull: re-run the query,
expect every row to show `Removed` or similar.

For the actual DL member enumeration (which is not a KQL job, it is an
EXO PowerShell job), see the playbook in
[`10-logic-apps-playbook-library.md`](./10-logic-apps-playbook-library.md).
The KQL job is the second half of the workflow: confirm everyone the DL
expanded to actually got the mail.

---

## Q9. Reporter precision scoreboard

**Use it for:** ranking your reporters by how often their reports turn out
to be real phish. The output drives a `HighPrecision_Reporters` watchlist
that you use to escalate severity automatically.

```kusto
let lookback = 30d;
SecurityAlert
| where TimeGenerated > ago(lookback)
| where AlertName == "Email reported by user as malware or phish"
| extend ext = parse_json(ExtendedProperties)
| extend Reporter = tostring(ext.["Reporter"]),
         Verdict = tostring(ext.["Verdict"])
| summarize Reports = count(),
            TruePositives = countif(Verdict in ("Phishing", "Malware")),
            FalsePositives = countif(Verdict == "NoThreatsFound"),
            Pending = countif(Verdict == "")
        by Reporter
| where Reports >= 3
| extend PrecisionPct = round(100.0 * TruePositives / Reports, 1)
| order by PrecisionPct desc, Reports desc
```

Reporters with `>= 80%` precision and `>= 5` reports go on the
`HighPrecision_Reporters` watchlist. Reports from those users get severity
boosted to High by an automation rule. This is the closest functional
analogue to a "trusted reporter" tier.

---

## Q10. Action Center audit hunting

**Use it for:** asking "what did the Defender XDR action engine actually
do over the last week?". Useful for compliance reporting and for spotting
when an automation rule is firing more than it should.

```kusto
OfficeActivity
| where TimeGenerated > ago(7d)
| where RecordType == 28 // ThreatIntelligenceAtpContent
       or RecordType == 47 // AirInvestigation
       or RecordType == 50 // AirManualInvestigation
       or RecordType == 64 // AirAdminActionInvestigation
| project TimeGenerated, Operation, UserId, ResultStatus, Parameters
| summarize ActionCount = count() by Operation, UserId, bin(TimeGenerated, 1d)
| order by TimeGenerated desc, ActionCount desc
```

The RecordType numbers are the audit log record categories. They change
occasionally; if a category goes missing in your tenant, look up the
current set in the Microsoft Audit Log schema reference.

---

## Q11. Volumetric anomaly on inbound phish

**Use it for:** detecting campaign storms before AIR's queue saturates.
Compares the last hour's phish volume against the 7-day baseline; fires
when the spike is large enough to worry about.

```kusto
let baseline = EmailEvents
    | where Timestamp between (ago(7d) .. ago(1h))
    | where ThreatTypes has "Phish"
    | summarize HourlyAvg = avg(toreal(count_per_hour))
        by SenderFromDomain = tolower(extract(@"@(.+)$", 1, SenderFromAddress))
    ;
let recent = EmailEvents
    | where Timestamp > ago(1h)
    | where ThreatTypes has "Phish"
    | summarize CurrentCount = count() by SenderFromDomain = tolower(extract(@"@(.+)$", 1, SenderFromAddress))
    ;
recent
| join kind=leftouter baseline on SenderFromDomain
| where CurrentCount >= 50 and CurrentCount > 5 * coalesce(HourlyAvg, 0.0)
| project SenderFromDomain, CurrentCount, BaselineHourlyAvg = HourlyAvg
| order by CurrentCount desc
```

Threshold of 50 messages and a 5x multiplier will catch most worth-acting-
on storms in a 10k-mailbox tenant. Tune both values for your size. If your
baseline is very low (small tenant, executive-mailbox-only scope), the 5x
rule will fire on noise; switch to a fixed-threshold rule.

---

## Q12. Look-alike sender domain detection (display-name spoof)

**Use it for:** catching display-name spoofs of internal executives. MDO's
anti-phish impersonation policy already handles this for users you have
explicitly tagged in `TargetedUsersToProtect`, but coverage is patchy and
the limit is 350 protected users per policy. This query is the safety net.

```kusto
let executives = _GetWatchlist('VIP_Users')
    | project ExecName = tolower(SearchKey),
              ExecUpn = tolower(UserPrincipalName);
EmailEvents
| where Timestamp > ago(1h)
| extend FromDisplayLower = tolower(SenderDisplayName)
| join kind=inner executives on $left.FromDisplayLower == $right.ExecName
| extend SenderDomain = tolower(extract(@"@(.+)$", 1, SenderFromAddress))
| extend IsLegit = iff(SenderFromAddress == ExecUpn, true, false)
| where IsLegit == false
| project Timestamp, NetworkMessageId, SenderDisplayName, SenderFromAddress,
          ExecUpn, RecipientEmailAddress, Subject
```

The query joins on display name, which is the spoof surface that bypasses
SPF/DKIM/DMARC. False positives are rare (exact display-name collisions
between legitimate non-employee senders and your executives). When they
happen, allowlist the sender domain in the `Sender_Allowlist` watchlist
and add a NOT clause on join.
