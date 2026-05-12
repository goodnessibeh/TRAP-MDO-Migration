# Microsoft Defender for Office 365: Native Capability Reference

> Implementation reference for the MDO surface area that replaces TRAP's
> detection, prevention, and built-in remediation primitives. Cited
> against Microsoft Learn throughout. Reading order: plan tier matrix,
> ZAP, anti-phish and anti-spam policies, TABL, Quarantine, Submissions
> surface, Threat Explorer, Campaigns, Email entity.---

## 1. Plan tier feature matrix

Source: [`mdo-about`](https://learn.microsoft.com/en-us/defender-office-365/mdo-about),
[Defender for Office 365 service description](https://learn.microsoft.com/en-us/office365/servicedescriptions/microsoft-defender-for-office-365-features).

| Capability | EOP (built-in) | MDO P1 | MDO P2 | M365 E5 |
|---|:-:|:-:|:-:|:-:|
| Anti-malware, anti-spam, anti-phish (basic) | ✅ | ✅ | ✅ | ✅ |
| Tenant Allow/Block List (TABL) | ✅ (1k/1k entries) | ✅ (1k/1k) | ✅ (10k/5k) | ✅ |
| Quarantine + admin/user release | ✅ | ✅ | ✅ | ✅ |
| **ZAP for email (Phish / Spam / Malware / HC phish)** | ✅ | ✅ | ✅ | ✅ |
| Anti-phish impersonation (mailbox + user + domain) | ❌ | ✅ | ✅ | ✅ |
| **Safe Links** (mail + Office + Teams) | ❌ | ✅ | ✅ | ✅ |
| **Safe Attachments** (mail + SPO + OneDrive + Teams) | ❌ | ✅ | ✅ | ✅ |
| **Email entity page** | ❌ | ✅ | ✅ | ✅ |
| **Real-time detections** (light Explorer) | ❌ | ✅ | ❌ | ❌ |
| **Threat Explorer** (full) | ❌ | ❌ | ✅ | ✅ |
| **Campaigns view** | ❌ | ❌ | ✅ | ✅ |
| **AIR (Automated Investigation and Response)** | ❌ | ❌ | ✅ | ✅ |
| **Attack Simulation Training** | ❌ | ❌ | ✅ | ✅ |
| Advanced Hunting (Email* tables, UrlClickEvents) | ❌ | ❌ | ✅ | ✅ |
| Priority Account Protection | ❌ | ❌ | ✅ | ✅ |
| ZAP for Teams chats | ❌ | ❌ | ✅ | ✅ |
| Safe Documents (Office Protected View) | ❌ | ❌ | ❌ | ✅ |
| AIR Auto-feedback to reporter | ❌ | ❌ | ✅ | ✅ |

**Practical implication**: TRAP-equivalent operational outcomes start at
**MDO P2** (or M365 E5, which includes P2). MDO P1 alone is insufficient , 
it lacks AIR, Campaigns, and Threat Explorer remediation actions.

License purchase paths:

* M365 / O365 E5 / A5 / G5. bundles MDO P2.
* M365 E3 + MDO P2 add-on. equivalent.
* M365 Business Premium. bundles MDO P1 only; insufficient.

---

## 2. Anti-phishing, anti-spam, anti-malware policy structure

Each is a `policy + rule` pair. The rule scopes the policy to recipients
(domains, groups, users), the policy carries the verdict actions.

### Anti-phishing policy (the most complex)

`Get-AntiPhishPolicy` / `Set-AntiPhishPolicy`. Key knobs:

| Setting | Effect |
|---|---|
| `EnableMailboxIntelligence` | Builds a per-user "usual senders" graph; enables impersonation detection. |
| `EnableMailboxIntelligenceProtection` | Acts on mailbox-intel anomalies. |
| `EnableImpersonationProtection` (`UserImpersonation`, `DomainImpersonation`) | Blocks display-name look-alikes and homoglyph domains. |
| `TargetedUsersToProtect`, `TargetedDomainsToProtect` | Per-user/domain protect list (max 350 each). |
| `AuthenticationFailAction` | What to do on SPF/DKIM/DMARC fail (`MoveToJmf` or `Quarantine`). |
| `PhishThresholdLevel` | 1 (Standard) → 4 (Most aggressive). |

Defender presets. **Standard** and **Strict**: overlay these and
auto-update. Use presets as a baseline; create a custom policy only for
**Priority Accounts** (executives) where Strict is too noisy in one direction
or another.

### Anti-spam policy

`Get-HostedContentFilterPolicy` / `Set-HostedContentFilterPolicy`. Key:

| Setting | Effect |
|---|---|
| `BulkThreshold` | 1 to 9; 7 default; lower = more aggressive |
| `MarkAsSpamSpfRecordHardFail` | True/False |
| `SpamAction`, `HighConfidenceSpamAction`, `PhishSpamAction`, `HighConfidencePhishAction` | `Quarantine`/`MoveToJmf`/`AddXHeader`/`PrependSubject`/`Redirect`/`Delete` |
| `EnableLanguageBlockList`, `LanguageBlockList`, `EnableRegionBlockList`, `RegionBlockList` | Geofencing |

**ZAP behaviour follows the action setting**: if `PhishSpamAction = Quarantine`,
ZAP quarantines retroactively; if `MoveToJmf`, ZAP moves to Junk; if
`AddXHeader`/`PrependSubject`/`Delete`/`Redirect`, **ZAP is a no-op for the
Phish verdict** ([zero-hour-auto-purge](https://learn.microsoft.com/en-us/defender-office-365/zero-hour-auto-purge)).

### Anti-malware policy

`Set-MalwareFilterPolicy`. Common Attachment Filter, ZAP-on-malware (always
quarantines), Internal Sender Notifications.

---

## 3. Safe Attachments + Safe Links

### Safe Attachments

* Detonates attachments in a sandbox before delivery (Block) or simultaneously
  (Dynamic Delivery. body delivers immediately, attachments held).
* Verdict-change retroactive remediation is via ZAP. if Safe Attachments
  delivers a benign verdict, then re-classifies as malicious, the message
  is ZAP'd if still in mailbox.
* Settings: `Set-SafeAttachmentPolicy`. `Action = Block | Replace |
  DynamicDelivery`, `Enable = $true`, `Redirect = $true`,
  `RedirectAddress = soc-quarantine@contoso.com`.
* Telemetry in `EmailAttachmentInfo` and `EmailEvents` (`ThreatTypes`
  contains `Malware`).

### Safe Links

* URL wrapping and **time-of-click** evaluation. URLs in body get rewritten
  to `https://*.safelinks.protection.outlook.com/?url=...`.
* On click, MDO re-checks against TI; can block at click time even if the
  URL was clean at delivery.
* Settings: `Set-SafeLinksPolicy`. `EnableSafeLinksForEmail`,
  `EnableSafeLinksForOffice`, `EnableSafeLinksForTeams`,
  `ScanUrls = $true`, `EnableForInternalSenders = $true`,
  `DeliverMessageAfterScan = $true` (block-mode), `DoNotRewriteUrls`
  (allowlist).
* Click telemetry → `UrlClickEvents` table in Advanced Hunting (the only
  source of "did the user click?" truth).

---

## 4. Tenant Allow/Block List (TABL)

The TI-driven block surface. EOP-baseline. Source:
[`tenant-allow-block-list-about`](https://learn.microsoft.com/en-us/defender-office-365/tenant-allow-block-list-about).

| Entity | Block expiry | Allow expiry | Notes |
|---|---|---|---|
| Domains & email addresses | 30 d default; 1/7/30/90 d / Never | 45 d after last clean signal | High-confidence phish quarantine + outbound NDR `550 5.7.703` |
| File hashes (SHA256) | Same | Same | Malware quarantine |
| URLs | Same | Same | URL allow auto-broadens to variants |
| Spoofed senders | **Never expires** | **Never** | Live in **Spoofed senders** TABL tab |
| IPv6 addresses | **Never** | n/a | Drop at edge |
| Teams domains/addresses | **Never** | n/a | MDO P2 only |

**Quotas** (admin-submission-driven):
* **MDO P1**: 1 000 block + 1 000 allow per category.
* **MDO P2**: 10 000 block + 5 000 allow per category.

**API surfaces**:

* Exchange Online PowerShell: `New-TenantAllowBlockListItems`,
  `Get-TenantAllowBlockListItems`, `Remove-TenantAllowBlockListItems`,
  `New-TenantAllowBlockListSpoofItems`. Module: `ExchangeOnlineManagement`.
* Microsoft Graph: **no v1.0 TABL CRUD endpoint**: The closest surface is
  the `tenantAllowOrBlockListAction` payload on a submission (POST
  `/security/threatSubmission/emailThreats`) which can create an entry as a
  side-effect of submitting a verdict.

**Allow-create restriction**: allow entries for **malware** and
**high-confidence phishing** can only be created by admin **submission**
marked "I've confirmed it's clean." Direct allow-create is blocked for
those categories.

---

## 5. Quarantine

* Per-policy quarantine policies (`Set-QuarantinePolicy`,
  `Get-QuarantinePolicy`) define what end users can do (release request,
  preview, delete, block sender).
* Built-in policies: `AdminOnlyAccessPolicy`, `DefaultFullAccessPolicy`,
  `NotificationEnabledPolicy`, `DefaultFullAccessWithNotificationPolicy`.
* End-user quarantine notifications (digest emails) are configurable per
  policy and per recipient organization.
* Release flow: admin via `https://security.microsoft.com/quarantine`;
  user via the digest link or the Quarantine portal.
* PowerShell: `Get-QuarantineMessage`, `Release-QuarantineMessage`,
  `Delete-QuarantineMessage`.
* Graph: limited. `POST /security/threatSubmission/emailThreats` plus
  `tenantAllowOrBlockListAction` is the typical pattern; direct
  quarantine-release endpoints are not currently in v1.0 Graph.

---

## 6. Submissions (admin and user)

Already deep-dived in [`08-abuse-mailbox-and-user-reporting.md`](./08-abuse-mailbox-and-user-reporting.md).
Summary here:

* **User-reported settings**: `https://security.microsoft.com/securitysettings/userSubmission`
 . toggle built-in Outlook Report button, configure custom mailbox, design
  pre/post-report banners, configure AIR auto-feedback emails.
* **Submissions page**: `https://security.microsoft.com/reportsubmission` , 
  User reported, Emails, Email attachments, URLs, Files, Teams messages tabs.
* **PowerShell**: `*-ReportSubmissionPolicy` and `*-ReportSubmissionRule`. one
  default of each per tenant.
* **Graph beta**: `POST /beta/security/threatSubmission/emailThreats` with two
  payload types. `emailUrlThreatSubmission` (references mail by URI) and
  `emailContentThreatSubmission` (uploads `.eml`).
* **Throttling**: 150 submissions / 15 min; 3 of the same submission / 24 h;
  1 of the same / 15 min. Email submissions ≤ 30 days old (≤ 7 d for hybrid
  on-prem).

---

## 7. Threat Explorer / Real-time detections

Source:
[`threat-explorer-threat-hunting`](https://learn.microsoft.com/en-us/defender-office-365/threat-explorer-threat-hunting).

* Path: `https://security.microsoft.com/threatexplorerv3`.
* Default lookback 7 d, extendable to 30 d.
* **Take action wizard** quotas:
  * **Handpicked mode**: max **100** messages per action, multiple action
    types in one wizard.
  * **Query-selected mode** (select all matching filter): max **200 000**
    messages per action, but only **Move/delete** OR **Propose remediation**
    (mutually exclusive).
* Action types: Soft delete, Hard delete, Move to Inbox/Junk/Deleted,
  Submit to Microsoft, Block sender/URL/file (writes TABL), Trigger
  investigation.
* Permission floor: **Search and Purge** role (in Data Investigator or
  Organization Management role groups), or under Defender XDR Unified RBAC
  the **Security operations / Email & collaboration advanced actions
  (manage)** scope.

---

## 8. Campaigns view (MDO P2)

Source: [`campaigns`](https://learn.microsoft.com/en-us/defender-office-365/campaigns).

* Path: `https://security.microsoft.com/campaigns`.
* Microsoft-managed clustering on:
  * Sender IPs + sender email domains
  * Message body fingerprint (style, content, tone. LLM-content analysis
    is now an explicit detection technology)
  * Recipient pattern (Targeted % by industry/role)
  * Payload (URL, attachment SHA256)
* Sankey diagram visualisation of Sender IPs → Sender domains →
  Filter verdicts → Message destinations → URL clicks.
* Filters: `Campaign ID`, `Cluster ID`, `Network Message ID`, `Internet
  Message ID`, `Attachment SHA256`, `URL domain and path`.
* "Take action on this campaign" applies bulk remediation to all messages
  in the cluster.

---

## 9. Email entity page

Source: [`mdo-email-entity-page`](https://learn.microsoft.com/en-us/defender-office-365/mdo-email-entity-page).

* Path: reached via the **Email summary panel "Open email entity"** action
  from Threat Explorer, Alerts, Incidents, Quarantine, Submissions, Threat
  Protection Status report, or Advanced Hunting (click NetworkMessageId).
* Two key correlation IDs:
  * **`NetworkMessageId`**: Microsoft-internal GUID stamped in
    `X-MS-Exchange-Organization-Network-Message-Id`. Joins all `Email*`
    Advanced Hunting tables.
  * **`InternetMessageId`**: RFC 5322 `Message-ID:` header. Originator-set;
    survives external relays.
* Views:
  * **Timeline**: delivery + post-delivery system/admin/user events
    (`Original delivery`, `ZAP`, `Quarantine Release`, etc.). The most
    important forensic view.
  * **Analysis**: full headers, auth results, override sources, alert ID
    linkage.
  * **Attachments**: per-file SHA256, detonation chain, screenshots,
    behavior CSV.
  * **URL**: per-URL detonation chain.
  * **Similar emails**: same-body fingerprint across the tenant. The
    lateral-spread pivot for cluster-style remediation.
* **Take action** wizard accessible directly. Same actions as Threat
  Explorer; same permission floor (Search and Purge).

---

## 10. Built-in alert policies that matter

Source:
[`alert-policies`](https://learn.microsoft.com/en-us/defender-xdr/alert-policies).
The following are **default-enabled** and should be left enabled (and
audited not to be suppressed by an alert tuning rule that would gate AIR):

| Alert policy | Severity | AIR triggered? |
|---|---|---|
| Email reported by user as malware or phish | Medium | **Yes** |
| Email messages containing malware removed after delivery (ZAP) | Informational | **Yes** |
| Email messages containing phish URLs removed after delivery (ZAP) | Informational | **Yes** |
| A potentially malicious URL click was detected | High | **Yes** |
| User restricted from sending email | High | Yes |
| Suspicious email forwarding activity | Low | Yes |
| Suspicious email-sending patterns detected | Medium | Yes |
| Tenant restricted from sending unprovisioned email | High | No |

Audit `Get-ProtectionAlert` for any custom suppressions; particularly the
built-in alert tuning rule **"Auto-Resolve - Email reported by user as
malware or phish"**. disable it if we need AIR to react to user-reported
phish (the AIR docs explicitly call this out).

---

## 11. Advanced Delivery Policy (SecOps + Phish Sim exclusions)

`Set-PhishSimOverridePolicy` and `New-SecOpsOverridePolicy`. Two classes
of exclusion:

* **SecOps mailboxes**: abuse mailbox + reporting mailboxes; bypasses
  Malware/HC-Phish ZAP; bypasses Safe Links wrapping; preserves the
  full original message for analysis.
* **Phishing simulation overrides**: vendor-IP + sender-domain + URL
  triple. Required when running 3rd-party PhishSim platforms; not needed
  for MDO Attack Simulation (which is excluded automatically).

---

## 12. Where each TRAP outcome lives in MDO

| TRAP outcome | MDO surface | Doc |
|---|---|---|
| Auto-pull post-condemnation | ZAP + AIR auto-action | [`05-defender-xdr-air-zap.md`](./05-defender-xdr-air-zap.md) |
| Manual auto-pull from incident UI | Defender XDR Email entity → Take Action | this doc § 9 |
| TI-driven block | TABL | this doc § 4 |
| Campaign bulk-pull | Campaigns view → Take action | this doc § 8 |
| Investigative drill-down | Email entity (Timeline + Analysis + Similar) | this doc § 9 |
| Per-recipient delivery state | EmailEvents in Advanced Hunting | [`09-kql-detection-library.md`](./09-kql-detection-library.md) |
| Reporter "thanks" + verdict | User reported settings + AIR auto-feedback | [`08-abuse-mailbox-and-user-reporting.md`](./08-abuse-mailbox-and-user-reporting.md) |

---

## 13. Configuration baseline (recommended starting set)

```text
Anti-phishing  : MDO Strict preset on all users
                 + custom policy on Priority Accounts with PhishThresholdLevel = 4
Anti-spam      : MDO Strict preset; SpamAction = Quarantine,
                 HighConfidencePhishAction = Quarantine, BulkThreshold = 6
Anti-malware   : Default policy with ZAP enabled
Safe Links     : Strict preset; ScanUrls = $true; EnableForInternalSenders = $true
Safe Attach.   : Strict preset; Action = DynamicDelivery; Redirect = $true to
                 soc-quarantine@contoso.com
TABL           : managed entirely via Sentinel TI playbook (do not allow
                 ad-hoc admin-portal entries; require change control)
User reported  : built-in Report button + custom mailbox
                 (reportedmessages@contoso.com); AIR auto-feedback ON for
                 Phish/Malware + Spam
SecOps mb-list : reportedmessages@contoso.com + soc-quarantine@contoso.com
Quarantine     : DefaultFullAccessWithNotificationPolicy for non-priority;
                 AdminOnlyAccessPolicy for Priority Accounts
```

This baseline is the configuration on top of which the SOAR layer
(Sentinel + Logic Apps) and the manual remediation surface (Defender XDR
Email entity) compose.
