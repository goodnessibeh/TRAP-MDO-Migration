# Microsoft Sentinel and Logic Apps: SOAR Orchestration Layer

> The control plane for the TRAP-replacement architecture. Sentinel is the
> SIEM and analytics engine; Logic App playbooks are the action graphs;
> Sentinel automation rules wire them together. This document covers data
> connectors, analytics rule design, automation rules, watchlists, threat
> intelligence (TI), and the identity and permissions model. Code-level
> KQL (Kusto Query Language) and playbook examples live in
> [`09-kql-detection-library.md`](./09-kql-detection-library.md) and
> [`10-logic-apps-playbook-library.md`](./10-logic-apps-playbook-library.md).

> **Strategic note (2026)**: Microsoft Sentinel in the Azure portal is
> being retired on 31 March 2027. New customers onboarded since July 2025
> auto-route to the Microsoft Defender portal (the unified SecOps
> experience). All design decisions in this document target the unified
> portal as the end state.
> ([Sentinel onboarding guide](https://learn.microsoft.com/en-us/azure/sentinel/microsoft-sentinel-defender-portal).)

---

## 1. Data connectors

### 1.1 Microsoft Defender XDR connector

The single most load-bearing connector. Three jobs:

1. **Incidents and alerts sync** (bi-directional). Surfaces in
   `SecurityIncident` (`ProviderName == "Microsoft XDR"`) and
   `SecurityAlert`.
2. **Entities for UEBA (User and Entity Behaviour Analytics)**: on-prem
   Active Directory via Microsoft Defender for Identity (MDI) into
   Sentinel UEBA.
3. **Raw advanced-hunting events**: opt-in per table.

Email-relevant tables (opt-in):

| Table | Purpose | Approx. volume per 10k mailbox tenant |
|---|---|---|
| `EmailEvents` | Delivery and blocking events for every message | 0.4 to 2 GB/day |
| `EmailAttachmentInfo` | Per-attachment metadata plus SHA256 | 0.1 to 0.5 GB/day |
| `EmailUrlInfo` | URLs in body | 0.5 to 1.5 GB/day |
| `EmailPostDeliveryEvents` | Post-delivery actions (ZAP — Zero-hour Auto Purge, manual remediation) | 0.05 to 0.2 GB/day |
| `UrlClickEvents` | Safe Links click telemetry | 0.5 to 1.5 GB/day |
| `AlertInfo`, `AlertEvidence` | Multi-product alert metadata plus entities | 0.05 to 0.2 GB/day |

**Deduplication rule**: when we connect this connector, tick **"Turn off
all Microsoft incident creation rules for these products"** to stop
double-incidenting. In unified-portal mode, all `Microsoft Security`,
`Fusion`, and `Anomaly` incident-creation rule types are auto-disabled;
Defender XDR becomes the only incident creator.

Source: [`connect-microsoft-365-defender`](https://learn.microsoft.com/en-us/azure/sentinel/connect-microsoft-365-defender).

### 1.2 Office 365 connector

Streams Exchange, SharePoint, and Teams audit activity into the
`OfficeActivity` table. Use it for mail-flow rule changes, mailbox
permission changes, and inbox-rule auto-forwarding (events not in
`EmailEvents`). It overlaps with `CloudAppEvents` (sourced from
Microsoft Defender for Cloud Apps) for SharePoint and Teams.

### 1.3 Threat Intelligence (TI) connectors

Four ingestion paths
([`threat-intelligence-integration`](https://learn.microsoft.com/en-us/azure/sentinel/threat-intelligence-integration)):

* **TAXII 2.x** (Trusted Automated Exchange of Indicator Information):
  built-in connector, polls feeds.
* **MDTI** (Microsoft Defender Threat Intelligence): first-party feed,
  drives the `Microsoft Threat Intelligence Analytics` matching rule.
* **MISP** (Malware Information Sharing Platform) via Logic Apps: the
  `MISP2Sentinel` add-on, which calls the Threat Intelligence Upload
  Indicators API.
* **Direct REST upload**: STIX 2.1 (Structured Threat Information
  Expression) bundles to the Threat Intelligence Upload API. Requires
  an Entra app plus the `Microsoft Sentinel Contributor` role at the
  workspace.

**Two TI tables in flight**:

* `ThreatIntelligenceIndicator` (legacy schema), still populated for
  back-compat.
* `ThreatIntelIndicators` plus `ThreatIntelObjects` (new schema, May
  2025+), STIX 2.1-aligned, supports more object types. Use for new
  rules. Back-compat queries can `union` both.

---

## 2. Analytics rules

Source: [`scheduled-rules-overview`](https://learn.microsoft.com/en-us/azure/sentinel/scheduled-rules-overview),
[`near-real-time-rules`](https://learn.microsoft.com/en-us/azure/sentinel/near-real-time-rules).

### 2.1 Scheduled rules

| Setting | Range / limit |
|---|---|
| Run interval | 5 min to 14 days |
| Lookback | 5 min to 14 days |
| Built-in execution delay | 5 min (ingestion latency buffer) |
| Query length | 1 to 10 000 chars; `search *` and `union *` disallowed |
| Alerts per run | 150 max (149 individual + 1 aggregate) |
| Entity mappings | 10 mappings × 3 identifiers each, 500 entities total per alert, 64 KB Entities cap |
| Alert grouping | 5 min to 7 days window (default 5 h); 150 alerts max per incident |
| Suppression after fire | up to 24 h |

### 2.2 NRT (near-real-time) rules

* Hard-coded 1-minute cadence; 2-minute ingestion delay.
* **Max 50 NRT rules per workspace.**
* Multi-table joins now allowed; cross-workspace queries supported.
* Up to 30 single-event alerts per run.

### 2.3 Microsoft Security rules (passthrough)

Auto-create incidents from another Microsoft product's alerts in real time.
**Disabled** when XDR connector is active or workspace is in unified portal , 
that path becomes XDR-native.

### 2.4 Defender XDR Custom Detections

In unified portal mode, **Defender XDR Custom Detections** are Microsoft's
unified replacement for Sentinel scheduled rules ([custom-detections-overview](https://learn.microsoft.com/en-us/defender-xdr/custom-detections-overview)).
Same KQL surface, same Action Center integration, native cross-product
correlation. Author all *new* analytics here in unified-portal tenants.

### 2.5 Entity mapping for email scenarios

Source: [`entities-reference`](https://learn.microsoft.com/en-us/azure/sentinel/entities-reference).

| Entity | Strong identifier | Other useful identifiers |
|---|---|---|
| **Mailbox** | `MailboxPrimaryAddress` | `Upn`, `AadId`, `RiskLevel` |
| **MailMessage** | `NetworkMessageId + Recipient` | `Sender`, `P1Sender`, `P2Sender`, `SenderIP`, `Subject`, `InternetMessageId`, `Urls`, `Files`, `Threats`, `DeliveryAction`, `DeliveryLocation` (`Inbox|JunkFolder|DeletedFolder|Quarantine|External|Failed|Dropped|Forwarded`), `AntispamDirection` (`Inbound|Outbound|Intraorg`) |
| **MailCluster** | `Query + Source` | `NetworkMessageIds[]`, `CountByDeliveryStatus`, `CountByDeliveryLocation`, `IsVolumeAnomaly`, `MailCount` |
| **SubmissionMail** | `SubmissionId + Submitter + NetworkMessageId + Recipient` | |
| **Account** | `Name+UPNSuffix`, `AadUserId`, `Sid` | ⚠ From **1 July 2026** `Name` holds *only the UPN prefix*. Audit all comparisons. |
| **URL** | `Url` (absolute) | |
| **FileHash** | `Algorithm + Value` | |

---

## 3. Automation rules + playbooks

Source: [`automate-incident-handling-with-automation-rules`](https://learn.microsoft.com/en-us/azure/sentinel/automate-incident-handling-with-automation-rules),
[`automation/automate-responses-with-playbooks`](https://learn.microsoft.com/en-us/azure/sentinel/automation/automate-responses-with-playbooks).

### 3.1 Automation rules

Three triggers: *When incident is created*, *When incident is updated*,
*When alert is created* (this last one fires only for Scheduled,
NRT — Near Real Time — and Microsoft Security analytics rules; it does
not fire for Defender XDR alerts in the unified portal).

Native actions (no playbook needed):

* Add an incident task (checklist).
* Change status (with closing reason and comment).
* Change severity.
* Assign owner.
* Add tag.
* Run playbook.

**Order matters**: rules are sequential. Each trigger has its own queue.
**In-rule playbook timeout: 2 minutes**: the rule advances after that;
the playbook keeps running.

### 3.2 Playbook triggers

Three Sentinel triggers in the Microsoft Sentinel connector:

| Trigger | Receives | Use case |
|---|---|---|
| Microsoft Sentinel incident | full incident object + `Entities[]` | The default for incident-driven flows |
| Microsoft Sentinel alert | alert only | Pre-incident automation |
| Microsoft Sentinel entity | manual "run on entity" from investigation page | Analyst-on-demand enrichment |

Both **Logic Apps Consumption** and **Standard** are supported. Use
**Standard** for VNet integration, lower per-action cost, and stateful +
stateless workflow co-hosting.

### 3.3 Identity and connection model

* **Managed identity** (MI; system-assigned or user-assigned, the latter
  abbreviated UAMI) is the recommended pattern. Grant the playbook's MI
  the **Microsoft Sentinel Responder** role on the workspace.
* The platform **Microsoft Sentinel Automation Contributor** role must
  be granted to the **Azure Security Insights** service principal on
  the resource group containing playbooks, so automation rules can
  invoke them.
* **OAuth API connections (per-user)** are still required for the
  Office 365 Outlook connector. Service principals and managed identity
  are not supported on that connector. Plan a SOC service-mailbox
  account with a conditional-access carve-out and MFA (Multi-Factor
  Authentication) exemption.

### 3.4 Approvals and human-in-the-loop

* **Outlook "Send approval email"**: actionable card; per-user OAuth
  required.
* **Teams "Post adaptive card and wait for a response"**: preferred for
  SOC channels (no per-user mailbox needed). Adaptive cards block the
  run until the user responds or the timeout fires.
* **Defender for Office 365 native two-step approval**: use the
  `Add to remediation` flow, then have a reviewer approve in the Action
  Center. An alternative when we do not need custom branching in the
  approval graph.

---

## 4. Watchlists

Source: [`watchlists`](https://learn.microsoft.com/en-us/azure/sentinel/watchlists).

Recommended phishing watchlists:

* `VIP_Users`. executive + sensitive-role accounts.
* `VAP_Users`: VAP (Very Attacked People), analytic-derived from MDTI
  and Defender XDR.
* `Sender_Allowlist`: pen-test senders, partner mail systems.
* `Sender_Blocklist`: known-bad senders, sourced from the TI feed.
* `Trusted_Partner_Domains`: auto-allow upstream from TABL (Tenant
  Allow/Block List).
* `High_Value_Mailboxes`: finance, legal, M&A.
* `PhishSim_Vendor_IPs`: addresses used by phishing-simulation vendors
  (Cofense, KnowBe4, and similar), held as an exclusion list.

**Hard limits**:

| Limit | Value |
|---|---|
| Active items per workspace | **10 million** (across all watchlists) |
| Local file upload | 3.8 MB |
| Azure Storage upload (preview) | 500 MB |
| Refresh interval | every 12 days (TimeGenerated updates) |
| `Watchlist` table data retention | 28 days (refresh keeps it alive) |
| Cross-workspace via Lighthouse | **Not supported** |

**KQL usage**: every watchlist gets a function `_GetWatchlist('<alias>')`.
Designate a `SearchKey` column for join performance:

```kusto
EmailEvents
| where TimeGenerated > ago(1d)
| where ThreatTypes has "Phish"
| lookup kind=leftouter _GetWatchlist('VAP_Users')
    on $left.RecipientEmailAddress == $right.SearchKey
| where isnotempty(VAP_Score)
```

**Updates are replace-style**: there is no append-row API. Update via Logic
App writing CSV to blob storage, then re-pointing the watchlist.

---

## 5. Threat Intelligence and join patterns

KQL pattern for joining email events with TI:

```kusto
let phishUrls = ThreatIntelIndicators
  | where ValidUntil > now()
  | where ObservableType == "url"
  | where ConfidenceScore >= 70
  | project IocUrl = ObservableValue, ConfidenceScore, ThreatType;
EmailUrlInfo
| where TimeGenerated > ago(7d)
| join kind=inner phishUrls on $left.Url == $right.IocUrl
| project TimeGenerated, NetworkMessageId, Url, ThreatType, ConfidenceScore
```

Wrap this in a scheduled analytics rule that runs every 30 min over a 1-hour
lookback to drive the TI sweep playbook (Workflow C in
[`02-architecture-overview.md`](./02-architecture-overview.md)).

---

## 6. Logic App connector reference

### 6.1 Office 365 Outlook

Per-user OAuth only. Throttling:

| Limit | Value |
|---|---|
| API calls per connection | 300 / 60 sec |
| Max mail content | 49 MB per message |
| Max sent content per connection | 500 MB / 5 min |
| Max all-action content | 2 GB / 5 min |
| Concurrent requests | 70 |
| Concurrent data transfer | 300 MB |

Plus EXO service-side per-mailbox limits. Stack with the connector caps;
the binding is the smaller of the two.

### 6.2 Microsoft Defender XDR connector

Actions: `Run hunting query`, `Get incident`, `Update incident`, `Get alert`,
`Update alert`, `Take action on email` (move/soft-delete/hard-delete/submit).
These actions hit the same Action Center pipeline that Threat Explorer uses,
so they're visible at `https://security.microsoft.com/action-center/history`.

### 6.3 HTTP + managed identity

For anything not in a connector, the **HTTP** action with **Managed
Identity** auth targeting `https://graph.microsoft.com` or
`https://api.security.microsoft.com` covers it. Grant the playbook MI the
right Graph application permissions (see [`02-architecture-overview.md`](./02-architecture-overview.md) §6).

---

## 7. Logic App hard limits (gotcha catalogue)

Source: [`logic-apps-limits-and-config`](https://learn.microsoft.com/en-us/azure/logic-apps/logic-apps-limits-and-config).

| Limit | Value |
|---|---|
| Consumption run duration max | **90 days** (hard cap) |
| Standard stateful run duration | configurable (`RetentionInDays`) |
| Actions per workflow | 500 (extend via nested workflows) |
| Action nesting depth | 8 |
| Single trigger/action input or output | 105 MB |
| Action inputs+outputs combined | 210 MB |
| ForEach concurrency | 20 default, 50 max |
| ForEach array items | 100 000 stateful / 100 stateless |
| Until iterations | 5 000 stateful / 100 stateless; default timeout 1 hour |
| Action executions per 5 min | 100 000 default / 300 000 high-throughput preview |

---

## 8. Multi-tenant via Microsoft 365 Lighthouse

Sentinel actions stop at the workspace's tenant boundary. Defender XDR
Email take-action only purges mailboxes in the same tenant as the
connector. For multi-tenant orgs (mergers and acquisitions, or MSSP
— Managed Security Service Provider — scenarios):

* One playbook per tenant, each with its own managed identity and
  Microsoft Graph application permission grants.
* **Azure Lighthouse** delegation must include the **Azure Security
  Insights** app plus the **Microsoft Sentinel Automation Contributor**
  role on the playbook resource group.
* Centralised Sentinel via cross-workspace queries; alerts and incidents
  do not flow back automatically.

Detailed in [`12-limitations-and-gaps.md`](./12-limitations-and-gaps.md) §3.

---

## 9. Sentinel-specific design rules

1. **Use the Microsoft Sentinel incident trigger, not the alert
   trigger**, for all production playbooks. The alert trigger is not
   available for Defender XDR alerts in unified portal mode.
2. **Map `MailMessage` and `Mailbox` entities** in every email analytics
   rule. Playbooks key off these to drive the take-action flow without
   re-deriving IDs.
3. **Coalesce updates**: Defender XDR coalesces multiple incident
   updates within a 5-to-10-minute window into one event sent to
   Sentinel. Automation rules see only the most recent state. Design
   idempotently.
4. **Re-audit `Account.Name` comparisons before July 2026**: the
   post-change value is the UPN (User Principal Name) prefix only;
   `Account.Name + Account.UPNSuffix` is the new full UPN.
5. **Author new detections as Defender XDR Custom Detections** in
   unified-portal tenants; they natively cross-correlate and reduce
   sync-lag.

---

## 10. Reference deployment shape

```text
Sentinel workspace (LAW: Log Analytics Workspace)
├─ Connectors:
│   ├─ Microsoft Defender XDR (raw + incidents + UEBA)
│   ├─ Office 365 (audit logs)
│   ├─ TAXII (third-party TI)
│   └─ MDTI (Microsoft Defender Threat Intelligence)
├─ Watchlists:
│   ├─ VIP_Users / VAP_Users / Sender_Allowlist / Sender_Blocklist
│   ├─ Trusted_Partner_Domains / High_Value_Mailboxes / PhishSim_Vendor_IPs
├─ Analytics rules (or XDR Custom Detections):
│   ├─ TI sweep (scheduled, 30 min)
│   ├─ Forward-following on phish (scheduled, 1h)
│   ├─ Auto-forward rule abuse (NRT)
│   ├─ DL recipient enumeration trigger (manual + scheduled)
│   └─ VAP report severity boost (when-incident-created automation rule)
├─ Automation rules:
│   ├─ Phish-incident-VIP → escalate to High, run Phish-Remediate-v3
│   ├─ Phish-incident-mass → run Phish-Remediate-Bulk
│   ├─ TI sweep incident → run TI-Sweep-Remediate
│   └─ User-reported alert → run Notify-Reporter-Bridge
└─ Playbooks (Logic App Standard, MI auth):
    ├─ Phish-Remediate-v3 (P1). full reactive remediation
    ├─ TI-Sweep-Remediate (P2). IOC-driven retroactive
    ├─ Notify-Reporter-Bridge (P3). reporter feedback bridge
    ├─ Forward-Trace-Remediate (P4). multi-hop forward
    ├─ DL-Expand-Remediate (P5). distribution list expansion
    └─ Two-Stage-Approval-VIP (P6). VIP-aware approval routing
```

Detailed playbook designs in
[`10-logic-apps-playbook-library.md`](./10-logic-apps-playbook-library.md).
