# Target-State Architecture Overview

The reference architecture diagram set. Read this before the deeper docs;
every component here is expanded later.

## 1. System context

What runs inside the tenant, what does not, and where the trust boundaries
sit.

```mermaid
flowchart LR
    subgraph External["External world"]
        Sender["Internet sender\n(legitimate or hostile)"]
        Reporter["End user\n(at their Outlook client)"]
        TIfeed["External TI feed\n(MISP / TAXII / vendor)"]
        OnPrem["On-prem Exchange\n(hybrid only)"]
    end

    subgraph Tenant["Microsoft 365 Tenant Boundary"]
        EOP["Exchange Online Protection"]
        MDO["Defender for Office 365"]
        EXO["Exchange Online mailboxes"]
        XDR["Defender XDR"]
        Sent["Microsoft Sentinel"]
        LA["Logic App / Power Automate"]
        Func["Azure Function\n(Graph / EXO PowerShell host)"]
    end

    subgraph Identity["Azure / Entra control plane"]
        Entra["Entra ID app registrations"]
        MI["Managed identities"]
        RBAC["RBAC + Application access policies"]
    end

    Sender -- SMTP --> EOP
    EOP --> MDO
    MDO --> EXO
    Reporter -- "Report button / abuse mailbox" --> XDR
    OnPrem -. journaling / hybrid mail flow .-> EXO
    TIfeed -- TAXII / API --> Sent

    MDO --> XDR
    XDR --> Sent
    Sent --> LA
    LA --> Func
    Func --> EXO
    LA --> XDR
    LA --> MDO

    Entra -- tokens --> LA
    Entra -- tokens --> Func
    MI -- tokens --> LA
    RBAC -- scopes --> EXO
```

**Trust boundaries**

| Boundary | Crossing rule |
|---|---|
| Internet → EOP | All inbound mail terminates here. SPF/DKIM/DMARC enforced at this layer. |
| EOP → MDO → EXO | Internal handoff inside the tenant. MDO verdicts attach as message headers. |
| EXO ↔ Defender XDR | Telemetry one way (EmailEvents to XDR); actions other way (Take Action → mailbox). |
| Defender XDR ↔ Sentinel | Streaming connector; bidirectional incident sync. |
| Sentinel → Logic Apps → Graph / EXO | All remediation passes through a managed-identity-authenticated Logic App or Function. |
| External TI → Sentinel | TAXII / Defender TI / custom Logic App ingestion. Indicator confidence scored on ingest. |

---

## 2. Logical layered architecture

The system has five logical layers. Every TRAP capability that we replicate
maps onto a layer transition.

```mermaid
flowchart TB
    subgraph L1["Layer 1. Mail flow & detection"]
        L1a["EOP\n(connection / SPF / RBL)"]
        L1b["MDO Anti-phish / Safe Links / Safe Attachments"]
        L1c["MDO anti-malware + anti-spam"]
    end

    subgraph L2["Layer 2. Post-delivery investigation"]
        L2a["ZAP\n(zero-hour auto purge)"]
        L2b["AIR\n(automated investigation graph)"]
        L2c["Defender XDR email entity\n(Take Action wizard)"]
    end

    subgraph L3["Layer 3. Telemetry & hunting"]
        L3a["Advanced Hunting\nEmailEvents / EmailUrlInfo /\nEmailAttachmentInfo /\nEmailPostDeliveryEvents /\nUrlClickEvents"]
        L3b["Unified Audit Log\n(OfficeActivity)"]
        L3c["MessageTraceV2\n(EXO PowerShell + Graph)"]
    end

    subgraph L4["Layer 4. Orchestration & SOAR"]
        L4a["Sentinel analytics rules\n(scheduled / NRT / Microsoft Security)"]
        L4b["Sentinel automation rules\n(when-incident-created)"]
        L4c["Logic App playbooks\n(approval, enrichment, fan-out remediation)"]
        L4d["Sentinel watchlists\n(VIP / VAP / Allow / Block)"]
    end

    subgraph L5["Layer 5. Action surfaces"]
        L5a["Defender XDR Action Center\n(approve / reject / undo)"]
        L5b["Microsoft Graph\n(messages / submissions / TABL)"]
        L5c["Compliance Search-Action\n(-Purge HardDelete)"]
        L5d["Tenant Allow/Block List\n(senders, URLs, hashes, IPs)"]
    end

    L1 --> L2
    L2 --> L3
    L3 --> L4
    L4 --> L5
    L5 -. feedback .-> L3
```

---

## 3. The five canonical workflows

Every TRAP capability maps to one of these five orchestrated workflows in the
target architecture. Each is decomposed below.

### Workflow A: Reactive remediation from MDO/AIR detection

The "always-on" path: MDO catches a phish post-delivery, AIR investigates,
recommended actions go to Action Center, Sentinel mirrors the incident.

```mermaid
sequenceDiagram
    autonumber
    participant Sender as Internet Sender
    participant EOP as EOP
    participant MDO as MDO P2
    participant EXO as EXO Mailbox
    participant ZAP as ZAP
    participant AIR as AIR
    participant XDR as Defender XDR
    participant Sent as Sentinel
    participant AC as Action Center
    participant Analyst as SOC Analyst

    Sender->>EOP: SMTP
    EOP->>MDO: scan
    MDO-->>EOP: verdict = Clean
    MDO->>EXO: deliver
    Note over MDO,EXO: T+0: message in inbox

    Note over MDO: T+10m: TI feed updates,\nsender reclassified Phish
    MDO->>ZAP: trigger
    ZAP->>EXO: move to Junk / Quarantine
    MDO->>AIR: alert "Email reported as phish post-ZAP"
    AIR->>XDR: investigation graph\n(sender, URL, attachment, similar messages)
    XDR->>AC: recommended actions\n(soft delete, block sender)
    XDR->>Sent: incident streamed
    AC->>Analyst: queued for approval
    Analyst->>AC: Approve
    AC->>EXO: hard delete across recipients
    AC->>Sent: action update
```

**Notes**

* Step 6: ZAP is autonomous. no analyst in the loop.
* Step 7 to 8: AIR is autonomous; only the recommended action queue requires
  human approval (configurable: some actions can be set to auto-apply).
* Step 11 to 12: bulk hard-delete uses Compliance Search-Action under the hood;
  see [`07-graph-and-exchange-remediation.md`](./07-graph-and-exchange-remediation.md).

---

### Workflow B: User-reported phishing (the TRAP/CLEAR equivalent)

```mermaid
sequenceDiagram
    autonumber
    participant User as End User
    participant Outlook as Outlook (Report btn)
    participant ReportMb as Reporting Mailbox\n(Microsoft + custom)
    participant Sub as Submissions API
    participant AIR as AIR
    participant XDR as Defender XDR
    participant Sent as Sentinel
    participant LA as Logic App\n("notify reporter")
    participant Reporter as Reporter inbox

    User->>Outlook: click Report → Phishing
    Outlook->>ReportMb: forward as .eml/.msg
    Outlook->>Sub: POST /security/threatSubmission/emailThreats
    Sub->>AIR: trigger user-reported investigation
    AIR->>XDR: cluster + recommended actions
    XDR->>Sent: incident
    Sent->>LA: trigger playbook "notify-reporter"
    LA->>Reporter: "Thanks. verdict: confirmed phish, removed from N mailboxes"
```

* Built-in pre-report banner is configurable in
  *Defender → Settings → Email & collaboration → User reported*.
* Verdict-back notification is **not** native; the Logic App at step 7
  closes the loop. Logic App design in
  [`10-logic-apps-playbook-library.md`](./10-logic-apps-playbook-library.md).

---

### Workflow C: TI-driven retroactive sweep (the IOC hunt-and-purge case)

```mermaid
sequenceDiagram
    autonumber
    participant TI as External TI Feed
    participant Sent as Sentinel
    participant Hunt as Advanced Hunting\n(via Sentinel KQL or Graph)
    participant LA as Logic App\n("ti-sweep")
    participant Approver as SOC Lead
    participant XDR as Defender XDR / Graph
    participant EXO as EXO mailboxes

    TI->>Sent: TAXII / MDTI ingest →\nThreatIntelIndicators table
    Sent->>Sent: scheduled rule joins\nEmailEvents × ThreatIntelIndicators
    Sent->>LA: incident created
    LA->>Hunt: count affected messages / recipients
    LA->>Approver: Outlook/Teams approval card\n(N msgs / N recipients)
    Approver-->>LA: Approve
    LA->>XDR: POST /api/email/take-action\n(or compliance search-action)
    XDR->>EXO: hard-delete fan-out
    LA->>Sent: incident closed + audit
```

This is the closest functional analogue to TRAP's IOC-driven mass-pull. KQL
hunt query in [`09-kql-detection-library.md`](./09-kql-detection-library.md).

---

### Workflow D: Forward-following remediation

The "this phish was forwarded to four other people, including external" case.

```mermaid
sequenceDiagram
    autonumber
    participant Trigger as Incident Trigger\n(AIR or analyst)
    participant LA as Logic App "fwd-trace"
    participant Hunt as Advanced Hunting
    participant EXOPS as EXO PowerShell\n(MessageTraceV2)
    participant Graph as Microsoft Graph
    participant EXO as EXO mailboxes

    Trigger->>LA: NetworkMessageId / InternetMessageId
    LA->>Hunt: EmailEvents | where InternetMessageId == X\n→ original recipients
    LA->>EXOPS: Get-MessageTraceV2 -RecipientAddress R\n→ outbound messages where\nMessageId == In-Reply-To/References
    EXOPS-->>LA: list of forward-destination messages\n(internal recipients only)
    loop for each internal forwardee
        LA->>Hunt: locate forwarded message\nin recipient mailbox
        LA->>Graph: DELETE /users/{id}/messages/{id}\nor compliance search-action
    end
    LA->>Hunt: external forwardees → log only\n(out of remediation scope)
```

External forward following is the **fundamental gap**: Once mail leaves the
tenant boundary, Microsoft has no telemetry. TRAP, similarly, can only
follow forwards inside customers it integrates with. We log and alert; we do
not pretend to remediate. Mitigations in
[`12-limitations-and-gaps.md`](./12-limitations-and-gaps.md).

---

### Workflow E: Distribution-list expansion

```mermaid
sequenceDiagram
    autonumber
    participant LA as Logic App "dl-expand"
    participant EXOPS as EXO PowerShell
    participant Graph as Microsoft Graph
    participant Compl as Compliance Search-Action

    LA->>EXOPS: Get-DistributionGroupMember -Recursive\nfor each DL recipient
    EXOPS-->>LA: flat recipient list
    LA->>Graph: resolve guest / external members\n(Get-Recipient)
    LA->>Compl: New-ComplianceSearch -ContentMatchQuery\n(InternetMessageId AND From:X)\n-ExchangeLocation [recipient list]
    Compl-->>LA: search complete
    LA->>Compl: New-ComplianceSearchAction -Purge\n-PurgeType HardDelete
    Compl->>EXO: bulk delete (≤10/mailbox per action)
```

The 10-item-per-mailbox limit on Compliance Search-Action is the gotcha here.
For large campaigns the playbook must loop the action; alternatively, the
Defender XDR Take Action wizard handles this transparently for messages
matched by `NetworkMessageId`. Tradeoff in
[`07-graph-and-exchange-remediation.md`](./07-graph-and-exchange-remediation.md).

---

## 4. Data flow: how telemetry, control, and audit flow

```mermaid
flowchart LR
    subgraph DataPlane["Data plane (telemetry, hunting, audit)"]
        EmailEvents[("EmailEvents\n30-day Defender retention")]
        EmailUrl[("EmailUrlInfo")]
        EmailAtt[("EmailAttachmentInfo")]
        EmailPD[("EmailPostDeliveryEvents")]
        UrlClick[("UrlClickEvents")]
        UAL[("Unified Audit Log /\nOfficeActivity")]
        SentLog[("Sentinel workspace\n(LAW)")]
    end

    subgraph ControlPlane["Control plane (decisions, actions)"]
        AIRctl["AIR investigation engine"]
        XDRctl["Defender XDR Action API\nhttps://api.security.microsoft.com"]
        Graphctl["Microsoft Graph\nhttps://graph.microsoft.com"]
        EXOctl["EXO PowerShell\nConnect-ExchangeOnline"]
        ComplCtl["Compliance PowerShell\nConnect-IPPSSession"]
    end

    subgraph AuditPlane["Audit plane (forensic record)"]
        AuditLog[("AuditLog table in Sentinel")]
        ActionLog[("Defender Action Center log")]
        PlaybookLog[("Logic App run history")]
    end

    EmailEvents --> SentLog
    EmailUrl --> SentLog
    EmailAtt --> SentLog
    EmailPD --> SentLog
    UrlClick --> SentLog
    UAL --> SentLog

    AIRctl --> XDRctl
    XDRctl --> Graphctl
    Graphctl --> EXOctl
    EXOctl --> ComplCtl

    AIRctl --> ActionLog
    XDRctl --> ActionLog
    Graphctl --> AuditLog
    EXOctl --> AuditLog
    ComplCtl --> AuditLog
    ActionLog --> SentLog
    AuditLog --> SentLog
    PlaybookLog --> SentLog
```

**Sizing notes**

* `EmailEvents` ≈ 1 to 4 KB per row × messages-per-day. A 10k-mailbox tenant
  averages 200 to 500 k inbound messages/day → 0.4 to 2 GB/day in this single
  table. `EmailUrlInfo` and `UrlClickEvents` add another 1 to 3 GB/day combined.
* `OfficeActivity` (audit log) ≈ 0.5 to 2 GB/day per 10k-user tenant.
* Plan a Sentinel workspace at **3-month retention** for these tables, with
  long-term retention to Azure Data Explorer / Log Analytics archive tier
  for compliance windows beyond 90 days.

---

## 5. Component matrix

Every component, what it does, what document expands it.

| Component | Role in TRAP-equivalent | Detail document |
|---|---|---|
| EOP | Gateway filtering (was Proofpoint EOP / TAP gateway role) | [`04-mdo-native-capabilities.md`](./04-mdo-native-capabilities.md) |
| MDO P2 | Detection: Safe Links, Safe Attachments, anti-phish, Campaigns view | [`04-mdo-native-capabilities.md`](./04-mdo-native-capabilities.md) |
| ZAP | Post-delivery autonomous purge (was TRAP's auto-pull on TAP verdict) | [`05-defender-xdr-air-zap.md`](./05-defender-xdr-air-zap.md) |
| AIR | Investigation graph + recommended actions (was TRAP incident workflow) | [`05-defender-xdr-air-zap.md`](./05-defender-xdr-air-zap.md) |
| Defender XDR | Unified incident, email entity, Take Action (was TRAP UI) | [`05-defender-xdr-air-zap.md`](./05-defender-xdr-air-zap.md) |
| Submissions API | Programmatic submit-and-act (was TRAP API) | [`08-abuse-mailbox-and-user-reporting.md`](./08-abuse-mailbox-and-user-reporting.md) |
| Built-in Outlook Report btn | Reporter input (was PhishAlarm) | [`08-abuse-mailbox-and-user-reporting.md`](./08-abuse-mailbox-and-user-reporting.md) |
| Custom abuse mailbox | Optional ingestion path (was TRAP abuse mailbox) | [`08-abuse-mailbox-and-user-reporting.md`](./08-abuse-mailbox-and-user-reporting.md) |
| Sentinel | SIEM, automation rules, watchlists (was Splunk/QRadar + TRAP integration) | [`06-sentinel-soar-orchestration.md`](./06-sentinel-soar-orchestration.md) |
| Logic Apps | Playbooks (was TRAP custom workflow + 3rd-party SOAR) | [`10-logic-apps-playbook-library.md`](./10-logic-apps-playbook-library.md) |
| Microsoft Graph | Programmatic email/submission/TABL access | [`07-graph-and-exchange-remediation.md`](./07-graph-and-exchange-remediation.md) |
| EXO PowerShell | Compliance Search-Action, MessageTraceV2, DL expansion | [`07-graph-and-exchange-remediation.md`](./07-graph-and-exchange-remediation.md) |
| Tenant Allow/Block List | TI-driven block (was TRAP blocklists) | [`04-mdo-native-capabilities.md`](./04-mdo-native-capabilities.md) |
| Action Center | Approval surface (was TRAP approval queue) | [`05-defender-xdr-air-zap.md`](./05-defender-xdr-air-zap.md) |
| Watchlists | VIP / VAP / known-bad sender (was TRAP user prioritization) | [`06-sentinel-soar-orchestration.md`](./06-sentinel-soar-orchestration.md) |

---

## 6. Identity & authorisation model

Every action surface needs a credential. Use the matrix below to design
least-privilege.

```mermaid
flowchart TB
    subgraph Identities["Workload identities"]
        MILogic["Logic App\nSystem-assigned MI"]
        SPRemed["Service Principal\n'remediation-app'"]
        SPSubmit["Service Principal\n'submissions-app'"]
        SPHunt["Service Principal\n'hunting-app'"]
        FuncMI["Azure Function\nUser-assigned MI"]
    end

    subgraph Scopes["Scoped permissions"]
        MailRW["Mail.ReadWrite\n(Application access policy → SOC mailboxes only)"]
        ThreatSub["ThreatSubmission.ReadWrite.All"]
        ThreatHunt["ThreatHunting.Read.All"]
        SecAlert["SecurityAlert.ReadWrite.All"]
        ExoMgr["EXO RBAC: Mailbox Search,\nCompliance Search role"]
        SentReader["Microsoft Sentinel Reader"]
        SentResp["Microsoft Sentinel Responder"]
    end

    MILogic --> SentResp
    MILogic --> SecAlert
    SPRemed --> MailRW
    SPRemed --> ExoMgr
    SPSubmit --> ThreatSub
    SPHunt --> ThreatHunt
    FuncMI --> ExoMgr
    FuncMI --> SentReader
```

**Least-privilege rules**

1. **Application access policies** scope `Mail.ReadWrite` to a security group
   that only contains SOC-relevant mailboxes (e.g. service mailboxes). Never
   grant tenant-wide `Mail.ReadWrite` to a remediation app.
2. **Separation**: do not reuse the submissions service principal for hunt
   queries or for remediation. Per-purpose SPs make audit + revocation easy.
3. **EXO Application access policy** (`New-ApplicationAccessPolicy`) is the
   only modern way to limit Graph mail scope per service principal.
4. **Compliance Search-Action** requires the EXO + Compliance "eDiscovery
   Manager" role *plus* the "Compliance Search" role. Use a dedicated
   security group; assign the SP via `Add-RoleGroupMember`.
5. **Connect-ExchangeOnline -ManagedIdentity** is supported from Exchange
   Online Management module v3+; prefer it over certificate-based app-only
   for any in-Azure Function host.

---

## 7. Failure modes by design

What breaks, what we do about it.

| Failure | Detection | Mitigation |
|---|---|---|
| Logic App run fails mid-fan-out | Sentinel workbook on `AzureDiagnostics \| where Resource startswith "playbook-"` | Idempotent design: each remediation step keyed by `NetworkMessageId + RecipientAddress`; replay-safe. |
| Compliance Search-Action stuck in "InProgress" > 30 min | Function App polling `Get-ComplianceSearch` status | Cancel and recreate after 60 min; alert SOC. |
| Graph throttled (429) | Logic App "On error" branch on the HTTP action | Honour `Retry-After` header; exponential backoff; degrade to Compliance Search-Action path. |
| AIR queue saturated (concurrent investigation cap) | Defender XDR alert "AIR investigation queue depth high" + Sentinel rule | Sentinel scheduled hunting picks up the slack; manual Take Action wizard. |
| ApplicationImpersonation removed but legacy script still uses EWS | Sentinel rule on AzureAD audit `application removed` + EWS HTTP 401 telemetry from Function App logs | Replace with Graph + RBAC application policy (this blueprint assumes done). |
| Approver out of office, approval card never answered | Logic App timeout on Approval action (default 30d, override to 1h) | Escalate to Teams channel @SOC group; auto-approve after 4h for confirmed-malicious-by-Defender verdicts only. |

---

## 8. Where to read next

* **Capability mapping**: [`03-trap-capability-matrix.md`](./03-trap-capability-matrix.md)
* **What MDO does on its own**: [`04-mdo-native-capabilities.md`](./04-mdo-native-capabilities.md)
* **Action engine internals**: [`05-defender-xdr-air-zap.md`](./05-defender-xdr-air-zap.md)
* **SOAR design**: [`06-sentinel-soar-orchestration.md`](./06-sentinel-soar-orchestration.md)
* **API/PowerShell-level remediation**: [`07-graph-and-exchange-remediation.md`](./07-graph-and-exchange-remediation.md)
* **User-report ingestion**: [`08-abuse-mailbox-and-user-reporting.md`](./08-abuse-mailbox-and-user-reporting.md)
* **KQL library**: [`09-kql-detection-library.md`](./09-kql-detection-library.md)
* **Playbook library**: [`10-logic-apps-playbook-library.md`](./10-logic-apps-playbook-library.md)
* **Migration plan**: [`11-implementation-roadmap.md`](./11-implementation-roadmap.md)
* **What we cannot do**: [`12-limitations-and-gaps.md`](./12-limitations-and-gaps.md)
* **What it costs**: [`13-licensing-and-operations.md`](./13-licensing-and-operations.md)
