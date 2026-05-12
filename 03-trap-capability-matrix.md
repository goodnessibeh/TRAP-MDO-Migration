# TRAP → Microsoft Capability Parity Matrix

> The single source of truth for "what TRAP does and how we replicate it."
> Each row is implementation-grade: the **Implementation method** column is
> precise enough to start engineering against.Legend: 🟢 Native · 🟡 Partial / native + config · 🟠 Engineering required ·
🔴 Impossible (with closest workaround)

---

## A. Post-delivery email remediation

| # | TRAP capability | What it does | Microsoft equivalent | Verdict | Implementation method | License floor | Operational limits |
|---|---|---|---|---|---|---|--- |
| A1 | Auto-pull on TAP verdict | Quarantines/removes already-delivered mail when TAP re-classifies sender/URL | ZAP + AIR auto-actions on Defender XDR alert | 🟡 | Default behaviour. ZAP set to "Move to Junk" or "Quarantine" in anti-spam/anti-phish/anti-malware policies. AIR triggered by `Email reported by user as malware or phish` and ZAP alerts. | MDO P2 (E5 / equivalent) | **ZAP eligibility window: 48 hours hardcoded** (vs TRAP unlimited). On-prem mailboxes excluded. Beyond 48 h → must use Compliance Search-Action or Defender XDR Take Action. |
| A2 | Manual analyst remediation per incident | Analyst clicks "Quarantine" → message removed from N mailboxes | Defender XDR Take Action wizard, or Threat Explorer "Take action" | 🟢 | `security.microsoft.com → Email & collaboration → Explorer → select messages → Take action`. Actions: Soft delete, Hard delete, Move to Junk/Inbox/Deleted, Submit. | MDO P2 | Bulk select capped per page; for very large fan-outs, prefer Compliance Search-Action. Requires Search and Purge role. |
| A3 | Programmatic remediation by API | TRAP REST API for SOAR-driven pull | Defender XDR Email Take Action API + Microsoft Graph + EXO PowerShell | 🟢 | Defender XDR Email take-action API (`https://api.security.microsoft.com`) **or** `New-ComplianceSearchAction -Purge -PurgeType HardDelete` **or** Graph `DELETE /users/{id}/messages/{id}`. | MDO P2 + EXO RBAC role | Compliance Search-Action: **10 items/mailbox** per action (Graph eDiscovery `purgeData` raises to 100/location). Defender XDR Email API: 50 concurrent jobs, 1 M-message hard cap per job, 40 % recipient-coverage rule, 50 k batch recommended, 200 k cap on query-select. |
| A4 | Soft delete vs hard delete | TRAP supports recoverable vs purged | Compliance Search-Action `-PurgeType SoftDelete` vs `HardDelete`; Graph DELETE moves to Deleted Items | 🟢 | Soft = recoverable from Deleted; Hard = removes from Recoverable Items dumpster (subject to retention policies). | MDO P2 | HardDelete bypassed by litigation/in-place hold. items stay in dumpster regardless. |
| A5 | Restore/release after false positive | Undo a pull | Defender XDR Action Center "Undo" or Quarantine "Release" | 🟢 | Action Center retains action history with one-click Undo for 30 days. Quarantine release is admin or user self-service. | MDO P2 | Hard-deleted items past Recoverable Items retention cannot be restored. |

---

## B. Discovery: finding all copies of a message

| # | TRAP capability | Microsoft equivalent | Verdict | Implementation method |
|---|---|---|---|--- |
| B1 | Same-message multi-recipient enumeration | KQL on `EmailEvents` keyed on `NetworkMessageId` (or `InternetMessageId`) | 🟢 | `EmailEvents \| where NetworkMessageId == X \| project RecipientEmailAddress, DeliveryAction, LatestDeliveryLocation` |
| B2 | Forwarded copy detection (internal) | KQL `EmailEvents` joined with `EmailPostDeliveryEvents` for forwards; `Get-MessageTraceV2` correlates by `In-Reply-To` / `References` | 🟠 | Sentinel hunting query in [`09-kql-detection-library.md`](./09-kql-detection-library.md). Q4. |
| B3 | Forwarded copy detection (external) | Egress message trace; cannot remediate external recipients | 🔴 | Block at egress (mail-flow rule on auto-forward); alert in Sentinel on `Set-Mailbox -ForwardingSmtpAddress` audit event. |
| B4 | Distribution list expansion | `Get-DistributionGroupMember -Recursive` + `Get-DynamicDistributionGroupMember` | 🟠 | Logic App + EXO PowerShell function; design in `02-architecture-overview.md` Workflow E. |
| B5 | Nested DL traversal | Recursive `Get-DistributionGroupMember` (parent → child DLs) | 🟠 | Same as B4; recursion depth in Logic App control flow with cycle detection. |
| B6 | Shared mailbox & delegated mailbox follow-on | Compliance Search includes shared/delegated mailboxes when `-AllowNotFoundExchangeLocationsEnabled $true` | 🟢 | Default behaviour for Compliance Search; shared mailboxes have their own EXO mailbox object. |
| B7 | Public folder messages | Compliance Search supports `-PublicFolderLocation All` | 🟢 | `New-ComplianceSearch -PublicFolderLocation All`. |
| B8 | Calendar items / meeting invites | Compliance Search by Subject/Sender across mailbox; calendar items live in mailbox | 🟡 | Compliance Search-Action treats calendar messages like any mailbox item, but **HardDelete on a meeting series is not supported**: must use `New-MailboxSearch` (deprecated) or per-item Graph delete. |
| B9 | Encrypted (Microsoft Purview Message Encryption) messages | Compliance Search & remediation operate on metadata; cannot decrypt content but *can* delete | 🟢 | Hard-delete works without content access; content-match queries fail on encrypted items. |
| B10 | Sensitivity-labelled / IRM messages | Same. metadata-only access | 🟡 | Same as B9. Subject + sender matches fine; content-keyword matches do not. |

---

## C. User-reported phishing pipeline (CLEAR equivalent)

| # | TRAP capability | Microsoft equivalent | Verdict | Implementation method |
|---|---|---|---|--- |
| C1 | One-click report from Outlook | Built-in Outlook Report button (replaces Report Message / Report Phishing add-ins) | 🟢 | Enable in Defender → *Settings → Email & collaboration → User reported → Use the built-in "Report" button*. |
| C2 | Custom abuse mailbox ingestion | Defender supports Microsoft + custom reporting mailbox in same tenant | 🟢 | Same settings page → *Send reports to → Microsoft and my reporting mailbox* + specify shared mailbox SMTP. |
| C3 | Pre-report user banner ("are you sure?") | Built-in customisable banner | 🟢 | *User reported → "Customize confirmation message"*. |
| C4 | Reporter "thanks" confirmation | Built-in customisable post-report message | 🟢 | Same settings page → "Customize result message". |
| C5 | Reporter verdict-back ("we removed it from N mailboxes") | **AIR Automatic Feedback Response** (MDO P2). native | 🟢 | *Defender → Settings → User reported → Automatically email users the results of the investigation*. Caveat: not sent if the message was already remediated before AIR ran. Bridge gap with Logic App for guaranteed thank-you. |
| C6 | Auto-investigate user-reported messages | AIR auto-trigger on user-reported alert | 🟢 | Default behaviour for MDO P2. Investigation graph clusters similar messages. |
| C7 | Auto-pull verdict-confirmed reported messages | AIR recommended action → Action Center → approve | 🟢 | Some actions (move to junk on user-reported) can be configured to auto-apply; admin policy. |
| C8 | Bulk admin submission | Defender Submissions page → Bulk submit (CSV) | 🟢 | `security.microsoft.com → Submissions → Email → Submit to Microsoft → Bulk`. |
| C9 | Submissions API integration | Microsoft Graph `/security/threatSubmission/emailThreats` | 🟢 | `POST` with `recipientEmailAddress`, `messageUri` (or full message). Permission: `ThreatSubmission.ReadWrite.All`. |
| C10 | Reporter scoring / VAP-on-reporter prioritisation | Sentinel watchlist `VAP_Users` + automation rule severity boost | 🟠 | Watchlist-driven incident automation; design in [`06-sentinel-soar-orchestration.md`](./06-sentinel-soar-orchestration.md). |

---

## D. Threat intelligence and indicator-driven hunts

| # | TRAP capability | Microsoft equivalent | Verdict | Implementation method |
|---|---|---|---|--- |
| D1 | TAP-verdict-driven block | Tenant Allow/Block List. sender, domain, URL, file hash, IP | 🟢 | `New-TenantAllowBlockListItems -ListType Sender -Block -Entries ...`. URL list and file-hash list supported. IP list added 2024. |
| D2 | IOC retroactive sweep | Sentinel scheduled rule joining `EmailEvents` × `ThreatIntelIndicators` | 🟢 | KQL pattern in [`09-kql-detection-library.md`](./09-kql-detection-library.md). |
| D3 | TAP detonation / sandbox feedback to remediation | MDO Safe Attachments dynamic delivery + ZAP | 🟢 | Native. Safe Attachments verdict change triggers ZAP if mail already delivered. |
| D4 | URL click protection | Safe Links wrapping + click-time scan + UrlClickEvents | 🟢 | Native MDO P1+; `UrlClickEvents` table in Advanced Hunting. |
| D5 | Click-time block on already-delivered URLs | Safe Links time-of-click decision can re-evaluate | 🟢 | Native; URLs in TABL applied dynamically. |
| D6 | TI feed ingestion (TAXII) | Sentinel TAXII data connector | 🟢 | `Threat Intelligence. TAXII` connector in Sentinel; ingests to `ThreatIntelligenceIndicator` (legacy) / `ThreatIntelIndicators` (new schema, 2025). |
| D7 | MDTI premium IOC enrichment | Microsoft Defender Threat Intelligence (Premium SKU) | 🟢 | MDTI portal + Sentinel content hub + Logic App connector for ad-hoc enrichment. |
| D8 | Custom IOC upload from analyst | Defender XDR Indicators, Sentinel ThreatIntelligenceUpload-Indicators-API, TABL | 🟢 | `POST /security/tiIndicators` (Graph) or Defender XDR Indicators page. |
| D9 | Indicator confidence scoring | Sentinel TI confidence field; analytics rule conditional on confidence ≥ N | 🟡 | Field is in indicator schema; rule logic must consume it explicitly. |

---

## E. Campaign and cluster correlation

| # | TRAP capability | Microsoft equivalent | Verdict | Implementation method |
|---|---|---|---|--- |
| E1 | Subject/sender/URL clustering | MDO P2 Campaigns view | 🟢 | `security.microsoft.com → Email & collaboration → Campaigns`. Microsoft-managed clustering. |
| E2 | Custom clustering (analyst-defined heuristics) | KQL on `EmailEvents` group by hashed subject + sender domain + URL host + attachment hash | 🟠 | KQL in [`09-kql-detection-library.md`](./09-kql-detection-library.md) Q3. |
| E3 | Cluster → bulk action | MDO Campaigns view "Take action on this campaign" | 🟢 | One-click action on campaign-grouped messages. |
| E4 | Cluster → Sentinel incident | Sentinel automation rule promotes Defender campaign incidents | 🟢 | Defender XDR connector forwards campaign incidents to Sentinel. |
| E5 | Cluster persisted across days | Campaigns view shows historical campaign view; supplemented by Sentinel KQL stored in workbook | 🟡 | Campaigns view 30-day window; deeper history via Sentinel workspace retention. |

---

## F. Investigation, enrichment, audit

| # | TRAP capability | Microsoft equivalent | Verdict | Implementation method |
|---|---|---|---|--- |
| F1 | Incident timeline | Defender XDR incident graph + Sentinel incident timeline | 🟢 | Native both surfaces. |
| F2 | Email entity drill-down (headers, body preview, raw, attachments) | Defender XDR Email entity page | 🟢 | `security.microsoft.com → Investigations & responses → .., or Threat Explorer email entity`. preview, download `.eml`, header analysis, URL list, attachment hashes. |
| F3 | Attachment detonation in entity view | Safe Attachments detonation results inline | 🟢 | Native, MDO P2. |
| F4 | URL detonation in entity view | Safe Links detonation results inline | 🟢 | Native, MDO P2. |
| F5 | Per-action audit trail | Defender Action Center + Unified Audit Log + Sentinel `OfficeActivity` / `BehaviorAnalytics` | 🟢 | Action Center: 30 days UI; UAL: 180 days E5 (1 year+ with Audit Premium); Sentinel: configurable retention. |
| F6 | CSV / SIEM export of actions | UAL CSV export; Sentinel Logic App → blob storage; Defender Action Center page export | 🟢 | All three surfaces export. Sentinel is the canonical SIEM source. |
| F7 | Incident enrichment (geoIP, WHOIS, VirusTotal, MDTI) | Logic App connectors for VirusTotal, MDTI, AbuseIPDB; Sentinel automation rule attaches enrichment as comment | 🟢 | Sample playbooks in `Azure/Azure-Sentinel` repo; design in [`10-logic-apps-playbook-library.md`](./10-logic-apps-playbook-library.md). |
| F8 | Reputation lookup on sender | MDTI / Defender XDR sender intelligence | 🟢 | Native enrichment in entity page. |

---

## G. Read-status visibility

| # | TRAP capability | Microsoft equivalent | Verdict | Implementation method |
|---|---|---|---|--- |
| G1 | Show whether each recipient read the message | Per-recipient `Get-MessageTraceDetail` does **not** include read state. Graph `GET /users/{id}/messages/{id}?$select=isRead,receivedDateTime` does. | 🟠 | KQL → list of recipients → Logic App fan-out → Graph per-recipient read query → aggregate report. |
| G2 | Show whether each recipient clicked URL | `UrlClickEvents` table | 🟢 | KQL: `UrlClickEvents \| where NetworkMessageId == X` (UrlClickEvents joins via NetworkMessageId where Safe Links wrapped the URL). |

Note: the per-recipient `isRead` query requires `Mail.Read` (or `Mail.ReadWrite`)
**application** permission, scoped via Application Access Policy to the
relevant mailboxes. see security model in `02-architecture-overview.md` §6.

---

## H. Approval workflows and analyst acceleration

| # | TRAP capability | Microsoft equivalent | Verdict | Implementation method |
|---|---|---|---|--- |
| H1 | Approval queue for risky actions | Defender XDR Action Center "Pending actions" tab | 🟢 | All recommended (non-auto) AIR actions land here. Approve/Reject buttons. |
| H2 | Two-stage approval (e.g., for VIP mailboxes) | Logic App with sequential approval steps; Outlook / Teams approval cards | 🟠 | Design in [`10-logic-apps-playbook-library.md`](./10-logic-apps-playbook-library.md). playbook P5. |
| H3 | Auto-approve high-confidence remediation | AIR full-automation mode | 🟢 | `Set-MdoSettings` (or in portal *Settings → Endpoints → Advanced features*); per-action thresholds in AIR config. |
| H4 | One-click approve from email/Teams | Outlook approval connector or Teams adaptive card | 🟢 | Logic App "Send approval email" or "Post adaptive card and wait for response". both natively supported. |
| H5 | Approval audit trail | Logic App run history + Sentinel `AzureActivity` + Action Center | 🟢 | Native. |

---

## I. Cross-tenant / multi-tenant

| # | TRAP capability | Microsoft equivalent | Verdict | Implementation method |
|---|---|---|---|--- |
| I1 | Single console serving multiple tenants (MSSP) | Microsoft 365 Lighthouse (limited) + Defender XDR multi-tenant management | 🟡 | Defender XDR multi-tenant view shows incidents across customer tenants we have GDAP delegation to; Take Action requires per-tenant. |
| I2 | Cross-tenant single-action remediation | Not supported by any Microsoft API | 🔴 | Closest: Logic App fan-out across per-tenant service principals; central Sentinel collects via cross-tenant log routing. |
| I3 | Cross-tenant TI sharing | Sentinel workspace-to-workspace TI sync; MDTI tenant-shared indicators | 🟡 | Manual workspace setup; not automatic. |

---

## J. SOAR orchestration

| # | TRAP capability | Microsoft equivalent | Verdict | Implementation method |
|---|---|---|---|--- |
| J1 | Webhook on incident creation | Sentinel automation rule → playbook trigger (Microsoft Sentinel incident trigger) | 🟢 | Native. |
| J2 | Programmatic incident lifecycle (assign, comment, close) | Sentinel REST API + Defender XDR Graph API (`/security/incidents`) | 🟢 | Native. |
| J3 | Custom playbook on incident type | Sentinel automation rule with conditions on `Title`, `Tactics`, `EntityType` | 🟢 | Native. |
| J4 | Splunk / QRadar / Cortex XSOAR forward | Defender XDR streaming connector (Event Hub) → 3rd-party SIEM; Sentinel Continuous Data Export → Event Hub | 🟢 | Native. |
| J5 | Conditional remediation (sender domain → action map) | Sentinel watchlist + Logic App switch action | 🟢 | Native pattern. |

---

## K. Operational and audit

| # | TRAP capability | Microsoft equivalent | Verdict | Implementation method |
|---|---|---|---|--- |
| K1 | Detailed action audit (who, when, what, scope) | Defender Action Center + Unified Audit Log | 🟢 | Native. |
| K2 | Per-mailbox remediation report | Sentinel workbook on `OfficeActivity` filtered by `MailboxOwnerUPN` | 🟢 | Workbook design in [`06-sentinel-soar-orchestration.md`](./06-sentinel-soar-orchestration.md). |
| K3 | Daily SOC operating report | Sentinel workbook + Logic App scheduled email | 🟢 | Native. |
| K4 | Remediation effectiveness metrics (MTTR, FP rate) | Sentinel workbook over `SecurityIncident` + Defender XDR action telemetry | 🟢 | Workbook in [`13-licensing-and-operations.md`](./13-licensing-and-operations.md). |

---

## Summary

**Truly impossible** (no Microsoft API can deliver):

* I2: single-action cross-tenant remediation (architectural; no Microsoft
  API spans tenant boundary in one call).
* B3: remediation of external forwarded copies (telemetry boundary).

**Possible but engineered** (custom Logic Apps and KQL):

B2 (forward-following internal), B4 and B5 (DL expansion), B8 (calendar
series), C5 (verdict feedback gap), C10 (VAP), G1 (read-status), H2
(two-stage approval), I3 (cross-tenant TI), J4 (third-party SIEM forward).

Everything else is native or near-native with policy configuration only.
