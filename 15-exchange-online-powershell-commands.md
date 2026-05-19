# Exchange Online PowerShell Commands for the TRAP → MDO Migration

A single working reference for every command we run from PowerShell during
this migration. Grouped by phase so we can work top-down. Every cmdlet
shape here is cited against Microsoft Learn so we are not relying on
training-data drift.

Authoritative cmdlet docs live at
`https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/`.
Authoritative feature docs live at
`https://learn.microsoft.com/en-us/defender-office-365/`. Both sources
are cited inline beside each section.

---

## Runnable scripts

For everything in this reference, there is also a focused audit /
remediation script in `./scripts/`. Each script is read-only by
default, takes an `-OutputCsv` parameter, and writes one row per check
with a `DefenderPortalUrl` column linking to the relevant page in
`security.microsoft.com`.

| Script | Mode default | Scope |
|---|---|---|
| `Invoke-MdoThreatPolicyAudit.ps1`  | Audit | Strict preset rules, ZAP, anti-malware policies, Safe Attachments, Safe Links. `-Mode Live` + `-PilotUsers` / `-PilotGroups` / `-WidenToAll` pilots or widens scope. |
| `Invoke-MdoAntiPhishAudit.ps1`     | Audit | Anti-phish policies (impersonation, mailbox intelligence, spoof, DMARC, first-contact tip). `-Mode Live` + `-PolicyNames` / `-IncludeDefaultPolicy` / `-IncludeAllPolicies` applies Strict baseline to scoped policies. |
| `Invoke-MdoOutboundSpamAudit.ps1`  | Audit | Outbound spam policies + tenant-wide auto-forwarding inventory. `-Mode Live` + `-PolicyNames` / `-IncludeDefaultPolicy` / `-IncludeAllPolicies` applies Strict baseline (lower recipient limits, AutoForwardingMode=Off). |
| `Invoke-MdoAlertPolicyAudit.ps1`   | Audit | ProtectionAlert inventory, the AIR-suppressing Auto-Resolve rule, critical alert coverage. `-Mode Live` disables the Auto-Resolve rule. |
| `common/MdoMigration.Common.psm1`  | n/a | Shared module: `Connect-MdoServices`, `Add-MdoAuditRow`, `Export-MdoAuditReport`, portal URL map. |
| `tests/Test-MdoMigrationScripts.ps1` | n/a | Runs PSScriptAnalyzer with `PSScriptAnalyzerSettings.psd1` over every script. |

> **Live-mode safety.** For the anti-phish and outbound spam scripts,
> `-Mode Live` with no scope flag (`-PolicyNames`, `-IncludeDefaultPolicy`,
> `-IncludeAllPolicies`) deliberately does **nothing**. This prevents a
> blanket overwrite of SOC-tuned custom policies. Pick the scope
> explicitly. Default policies (`Office365 AntiPhish Default`, the
> outbound-spam `Default` policy) need `-IncludeDefaultPolicy` to be
> touched.

### Mode parameter — safe defaults for ISE / VS Code F5

Every script that can change tenant state takes `-Mode`:

* `-Mode Audit` (default): read-only. Produces a CSV report, makes no
  changes. Safe to run from any editor with no flags.
* `-Mode Live`: idempotent writes (scope preset to pilot, widen, enable
  preset rules, disable Auto-Resolve rule etc.).

This means you can open any of these scripts in VS Code or `pwsh` and
hit Run / F5 — they default to Audit. Switch to `-Mode Live` only when
you intend to apply changes.

> Use `pwsh` 7+ (or VS Code with the PowerShell extension), **not**
> Windows PowerShell ISE. The scripts use PS7 features
> (`#Requires -Version 7.0`, ternary operator). ISE runs PS5.1 and
> Microsoft is no longer adding features to it.

### Pilot scoping pattern

Roll out Strict preset to test users first, then widen:

```powershell
# Phase 1a — pilot
.\scripts\Invoke-MdoThreatPolicyAudit.ps1 `
    -PilotUsers alice@<tenant>,bob@<tenant>,charlie@<tenant> `
    -Mode Live

# Validate for a week. When happy:

# Phase 1b — widen to all accepted domains
.\scripts\Invoke-MdoThreatPolicyAudit.ps1 -WidenToAll -Mode Live
```

### Validation

```powershell
# One-off setup
Install-Module PSScriptAnalyzer -Scope CurrentUser -Force

# Lint everything against PSScriptAnalyzerSettings.psd1
.\scripts\tests\Test-MdoMigrationScripts.ps1

# Auto-fix formatter-style issues
.\scripts\tests\Test-MdoMigrationScripts.ps1 -Fix
```

Exits non-zero if any error- or warning-level finding is reported, so it
plugs into pipelines.

---

## 0. Module install and session setup

```powershell
# One-off install on a fresh admin workstation
Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force
Install-Module Microsoft.Graph -Scope CurrentUser -Force

# Every session
Connect-ExchangeOnline -ShowBanner:$false
# Some compliance cmdlets live in the Security & Compliance endpoint:
Connect-IPPSSession
# Graph (for licensing audit):
Connect-MgGraph -Scopes "User.Read.All","Organization.Read.All","Directory.Read.All"
```

> Docs: [Connect to Exchange Online PowerShell](https://learn.microsoft.com/en-us/powershell/exchange/connect-to-exchange-online-powershell)

We use **PowerShell 7** (`pwsh`), not Windows PowerShell 5.1. The Graph
SDK v2+ behaves better on PS7 and `Connect-ExchangeOnline` is fully
cross-platform.

---

## 1. Phase 0 — Pre-migration audits

### 1.1 MDO P2 licence coverage

Tenant-level P2 is already confirmed (Campaigns alerts visible). What we
still owe Phase 0 is per-mailbox coverage — we need to find any user
sitting on P1 or unassigned.

```powershell
# 1. Tenant-level: which Defender SKUs are present
Connect-MgGraph -Scopes "Organization.Read.All"
Get-MgSubscribedSku |
  Where-Object { $_.ServicePlans.ServicePlanName -match 'ATP_ENTERPRISE|THREAT_INTELLIGENCE' } |
  Select-Object SkuPartNumber,
                @{n='ServicePlans';e={ ($_.ServicePlans | Where-Object ProvisioningStatus -eq 'Success').ServicePlanName -join ',' }},
                @{n='Total';e={$_.PrepaidUnits.Enabled}},
                @{n='Assigned';e={$_.ConsumedUnits}}

# 2. Per-user: who actually has the P2 service-plan assigned and active?
#    Service plan name to check: THREAT_INTELLIGENCE  (MDO P2)
#    P1-only would show ATP_ENTERPRISE without THREAT_INTELLIGENCE
$p2Plan = "THREAT_INTELLIGENCE"
Get-MgUser -All -Property UserPrincipalName,AssignedPlans |
  Select-Object UserPrincipalName,
                @{n='HasMdoP2';e={ ($_.AssignedPlans | Where-Object { $_.Service -eq 'exchange' -and $_.CapabilityStatus -eq 'Enabled' }).Service -contains 'exchange' -and
                                   ($_.AssignedPlans | Where-Object { $_.ServicePlanId } | ForEach-Object {
                                       (Get-MgSubscribedSku | ForEach-Object ServicePlans | Where-Object ServicePlanId -eq $_.ServicePlanId).ServicePlanName
                                   }) -contains $p2Plan }} |
  Where-Object HasMdoP2 -eq $false |
  Export-Csv ~/phase0-mailboxes-without-mdo-p2.csv -NoTypeInformation
```

> Phase 0 exit criterion: ≥99 % of in-scope mailboxes have
> `THREAT_INTELLIGENCE` assigned. Anything in the CSV above is a gap.

### 1.2 Hybrid posture

```powershell
# Group every mailbox by recipient type to find on-prem residue
Get-Mailbox -ResultSize Unlimited |
  Group-Object RecipientTypeDetails |
  Sort-Object Count -Descending |
  Format-Table Count,Name

# Anything that's not UserMailbox / SharedMailbox / RoomMailbox / EquipmentMailbox
# is out of scope for ZAP, AIR, Defender XDR Take Action and Compliance Search-Action.
# Most common offender is RemoteUserMailbox (mailbox still on-prem).
Get-Mailbox -ResultSize Unlimited -Filter "RecipientTypeDetails -eq 'RemoteUserMailbox'" |
  Select-Object DisplayName,UserPrincipalName,RecipientTypeDetails |
  Export-Csv ~/phase0-onprem-mailboxes.csv -NoTypeInformation
```

> If the CSV is non-empty, see
> [`12-limitations-and-gaps.md`](./12-limitations-and-gaps.md) §2 and
> resolve before Phase 4 (cutover). On-prem mailboxes are not covered
> by any native MDO remediation surface.

### 1.3 Audit log ingestion

```powershell
Get-AdminAuditLogConfig | Format-List UnifiedAuditLogIngestionEnabled,
                                        AdminAuditLogEnabled,
                                        AdminAuditLogCmdlets,
                                        AdminAuditLogParameters

# If UnifiedAuditLogIngestionEnabled is False (rare in modern tenants):
Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true
```

---

## 2. Phase 1 — Out-of-the-box MDO configuration

### 2.1 Preset security policies (Strict)

The Strict preset is the OOTB baseline. Most config is via the portal at
`https://security.microsoft.com/presetSecurityPolicies` — the PowerShell
surface is read-only for the preset assignment itself, but we can inspect
and verify.

```powershell
# Inspect which preset is applied where. Strict preset uses the
# "Standard Preset Security Policy" / "Strict Preset Security Policy"
# internal names plus matched anti-* rules with the
# Preset:Strict comment.
Get-EOPProtectionPolicyRule | Format-Table Name,State,Conditions
Get-ATPProtectionPolicyRule | Format-Table Name,State,Conditions

# After applying Strict via the portal, confirm the underlying policies
# inherited the Strict values:
Get-AntiPhishPolicy   | Format-Table Identity,Enabled,PhishThresholdLevel
Get-MalwareFilterPolicy | Format-Table Identity,EnableFileFilter,Action
Get-HostedContentFilterPolicy | Format-Table Identity,SpamAction,HighConfidenceSpamAction,PhishSpamAction,HighConfidencePhishAction
Get-SafeAttachmentPolicy | Format-Table Identity,Enable,Action
Get-SafeLinksPolicy   | Format-Table Identity,EnableSafeLinksForEmail,EnableForInternalSenders
```

> Docs: [Preset security policies in EOP and MDO](https://learn.microsoft.com/en-us/defender-office-365/preset-security-policies)

### 2.2 ZAP verification (TRAP's core function in MDO)

ZAP is the OOTB equivalent of TRAP's auto-pull on verdict change. It
needs to be on across all three policy families.

```powershell
# Anti-malware ZAP
Get-MalwareFilterPolicy |
  Select-Object Identity, @{n='ZapEnabled';e={$_.ZapEnabled}}

# Anti-spam ZAP (separate toggles for spam vs phish)
Get-HostedContentFilterPolicy |
  Select-Object Identity, PhishZapEnabled, SpamZapEnabled,
                SpamAction, HighConfidenceSpamAction,
                PhishSpamAction, HighConfidencePhishAction

# Single-line all-policies overview
Get-HostedContentFilterPolicy | Format-Table Identity,PhishZapEnabled,SpamZapEnabled
```

> Expected on Strict preset: every `*ZapEnabled` returns `$true`, and
> `HighConfidencePhishAction` returns `Quarantine`.
>
> Docs: [Zero-hour auto purge (ZAP) in Microsoft 365](https://learn.microsoft.com/en-us/defender-office-365/zero-hour-auto-purge)

### 2.3 Safe Attachments and Safe Links inspection

```powershell
# Safe Attachments policies and rules
Get-SafeAttachmentPolicy | Format-Table Identity,Enable,Action,Redirect,RedirectAddress
Get-SafeAttachmentRule   | Format-Table Name,SafeAttachmentPolicy,State,Priority

# Safe Links policies and rules
Get-SafeLinksPolicy | Format-Table Identity,EnableSafeLinksForEmail,
                                    EnableSafeLinksForTeams,
                                    EnableSafeLinksForOffice,
                                    EnableForInternalSenders,
                                    DeliverMessageAfterScan,
                                    DisableUrlRewrite,
                                    EnableOrganizationBranding
Get-SafeLinksRule   | Format-Table Name,SafeLinksPolicy,State,Priority
```

> Docs:
> [Safe Attachments policies](https://learn.microsoft.com/en-us/defender-office-365/safe-attachments-policies-configure) ·
> [Safe Links policies](https://learn.microsoft.com/en-us/defender-office-365/safe-links-policies-configure)

### 2.4 Create the reporting mailbox

```powershell
# Reporting mailbox for the built-in Outlook Report button. We create as
# a shared mailbox so no licence cost.
New-Mailbox -Shared -Name "Reported Messages" `
            -DisplayName "Reported Messages" `
            -Alias "reportedmessages" `
            -PrimarySmtpAddress "reportedmessages@<our-tenant>.com"

# Disable login on the shared mailbox account (default for -Shared,
# but verify):
Get-User -Identity reportedmessages |
  Format-List UserPrincipalName,AccountDisabled

# Grant SOC the Full Access + Send As (if they need to release msgs):
Add-MailboxPermission -Identity "reportedmessages@<our-tenant>.com" `
                      -User "soc-team@<our-tenant>.com" `
                      -AccessRights FullAccess -InheritanceType All
Add-RecipientPermission -Identity "reportedmessages@<our-tenant>.com" `
                        -Trustee "soc-team@<our-tenant>.com" `
                        -AccessRights SendAs
```

### 2.5 User-reported messages (built-in Outlook Report button)

The OOTB choice is **Microsoft and my reporting mailbox**, with the
built-in Outlook Report button.

```powershell
$reportingMailbox = "reportedmessages@<our-tenant>.com"

# If Get-ReportSubmissionPolicy returns nothing, the policy hasn't been
# created yet (the portal creates it on first visit). Create it:
New-ReportSubmissionPolicy `
  -EnableReportToMicrosoft $true `
  -EnableThirdPartyAddress $false `
  -ReportJunkToCustomizedAddress $true `
  -ReportNotJunkToCustomizedAddress $true `
  -ReportPhishToCustomizedAddress $true `
  -ReportJunkAddresses $reportingMailbox `
  -ReportNotJunkAddresses $reportingMailbox `
  -ReportPhishAddresses $reportingMailbox `
  -PreSubmitMessageEnabled $true `
  -PostSubmitMessageEnabled $true `
  -EnableUserEmailNotification $true

# Bind the policy to a rule that actually routes reported items to the
# mailbox. The rule name MUST be DefaultReportSubmissionRule, the policy
# name MUST be DefaultReportSubmissionPolicy.
New-ReportSubmissionRule `
  -Name DefaultReportSubmissionRule `
  -ReportSubmissionPolicy DefaultReportSubmissionPolicy `
  -SentTo $reportingMailbox

# To verify
Get-ReportSubmissionPolicy | Format-List
Get-ReportSubmissionRule   | Format-List
```

To **change** existing settings instead of creating:

```powershell
Set-ReportSubmissionPolicy -Identity DefaultReportSubmissionPolicy `
  -EnableReportToMicrosoft $true `
  -EnableUserEmailNotification $true
```

> Important defaults that bite us:
> * If no reporting mailbox is named, reports land in the **global
>   admin's mailbox** silently. The mailbox is not shown in any
>   `Get-ReportSubmission*` output until the first user reports a
>   message.
> * The portal default for **Send reported items to** is "Microsoft and
>   my reporting mailbox" but the mailbox field is blank, which is the
>   silent-to-global-admin trap above.
>
> Docs: [Configure user reported message settings](https://learn.microsoft.com/en-us/defender-office-365/submissions-user-reported-messages-custom-mailbox)

### 2.6 SecOps mailbox override (advanced delivery policy)

Without this, the reporting mailbox gets filtered by the Strict preset
and reports never arrive. The two-step structure (policy first, then
rule) is mandatory.

> Note: the rule cmdlets carry the `Exo` prefix. `New-SecOpsOverrideRule`
> does **not** exist — it is `New-ExoSecOpsOverrideRule`. The blueprint's
> `00-MDO-out-of-the-box-deployment-guide.md` §2.4 currently has the
> wrong name; see the note at the bottom of this file.

```powershell
# Step 1 — create the policy. Name must be SecOpsOverridePolicy.
New-SecOpsOverridePolicy `
  -Name SecOpsOverridePolicy `
  -SentTo "reportedmessages@<our-tenant>.com",
          "soc-quarantine@<our-tenant>.com"

# Step 2 — create the rule that binds the policy
New-ExoSecOpsOverrideRule `
  -Name SecOpsOverrideRule `
  -Policy SecOpsOverridePolicy

# Verify
Get-SecOpsOverridePolicy | Format-List Name,SentTo,Mode
Get-ExoSecOpsOverrideRule | Format-Table Name,Mode

# Adding another address later (modifies BOTH policy and rule in one
# call — do not edit the rule directly)
Set-SecOpsOverridePolicy -Identity SecOpsOverridePolicy `
                          -AddSentTo "extra-soc@<our-tenant>.com"

# Removing addresses
Set-SecOpsOverridePolicy -Identity SecOpsOverridePolicy `
                          -RemoveSentTo "old-soc@<our-tenant>.com"

# Full teardown (policy removal cascades to the rule)
Remove-SecOpsOverridePolicy -Identity SecOpsOverridePolicy
```

> Also exclude the reporting mailbox from DLP and retention. SecOps
> override stops anti-phish / anti-spam filtering, not DLP or retention.
>
> Docs: [Configure the advanced delivery policy](https://learn.microsoft.com/en-us/defender-office-365/advanced-delivery-policy-configure)

### 2.7 Phishing simulation override (if we run KnowBe4 / Proofpoint PSAT / etc.)

Same shape as SecOps override but for simulated-phish vendors. Skip if
we don't run a non-Microsoft phishing simulation programme.

```powershell
New-PhishSimOverridePolicy -Name PhishSimOverridePolicy

New-ExoPhishSimOverrideRule `
  -Name PhishSimOverrideRule `
  -Policy PhishSimOverridePolicy `
  -Domains "phishsim-vendor.com" `
  -SenderIpRanges "203.0.113.55","203.0.113.0/24"

# Allow vendor click-tracking URLs not to be detonated by Safe Links
# (only needed for non-email channels like Teams / docs):
New-TenantAllowBlockListItems `
  -Allow -ListType Url -ListSubType AdvancedDelivery `
  -Entries "*.phishsim-vendor.com" -NoExpiration
```

### 2.8 Alert tuning — make sure AIR can fire on user-reported phish

```powershell
# Find any tuning rule that auto-resolves the "Email reported by user"
# alert. If one exists and is enabled, AIR effectively never fires.
Get-ProtectionAlert |
  Where-Object { $_.Name -like "*Auto-Resolve*Email reported*" } |
  Format-Table Name,Disabled,Severity

# Disable any that exist
Get-ProtectionAlert |
  Where-Object { $_.Name -like "*Auto-Resolve*Email reported*" } |
  ForEach-Object { Disable-ProtectionAlert -Identity $_.Identity }
```

> Docs: [Alert policies in Microsoft Defender XDR](https://learn.microsoft.com/en-us/defender-xdr/alert-policies)

---

## 3. Tenant Allow/Block List (TABL)

The MDO equivalent of TRAP's TI lists. Supports senders, URLs, file
hashes, IPs (preview), and spoofed-sender pairs. PowerShell is the only
way to bulk-load entries.

```powershell
# === Domains and email addresses ===
# Block a domain
New-TenantAllowBlockListItems -ListType Sender -Block `
  -Entries "badactor.example" -NoExpiration `
  -Notes "Phishing campaign reported 2026-05-20"

# Block a specific email address with auto-expiry
New-TenantAllowBlockListItems -ListType Sender -Block `
  -Entries "attacker@badactor.example" `
  -ExpirationDate (Get-Date).AddDays(90) `
  -Notes "BEC attempt, ticket SOC-1234"

# Allow (use sparingly — overrides spam/phish but NOT malware/high-conf phish)
New-TenantAllowBlockListItems -ListType Sender -Allow `
  -Entries "false-positive-sender@partner.com" `
  -ExpirationDate (Get-Date).AddDays(30) `
  -Notes "False-positive under review per ticket SOC-1235"

# === URLs ===
New-TenantAllowBlockListItems -ListType Url -Block `
  -Entries "https://badurl.example/login" -NoExpiration

# === File hashes (SHA256) ===
New-TenantAllowBlockListItems -ListType FileHash -Block `
  -Entries "<SHA256>","<SHA256>" -NoExpiration

# === Spoofed senders ===
New-TenantAllowBlockListSpoofItems -Identity Default -Action Block `
  -SendingInfrastructure "172.17.17.17/24" `
  -SpoofedUser "ceo@<our-tenant>.com" `
  -SpoofType External

# === Inspect ===
Get-TenantAllowBlockListItems -ListType Sender
Get-TenantAllowBlockListItems -ListType Url
Get-TenantAllowBlockListItems -ListType FileHash
Get-TenantAllowBlockListItems -ListType Sender -Block
Get-TenantAllowBlockListSpoofItems

# === Remove ===
Remove-TenantAllowBlockListItems -ListType Sender -Entries "old-sender@example.com"
```

> Limits we care about (P2 tenant): 5,000 sender allow + 10,000 sender
> block + 1,024 spoof pairs in total.
>
> Docs: [Allow or block email using TABL](https://learn.microsoft.com/en-us/defender-office-365/tenant-allow-block-list-email-spoof-configure) ·
> [Manage TABL overall](https://learn.microsoft.com/en-us/defender-office-365/tenant-allow-block-list-about)

---

## 4. Phase 2 — Engineered enhancements: PowerShell building blocks

These are what the engineered playbooks call. Keep them in source
control; do not hand-edit in the portal.

### 4.1 Compliance Search-Action (TRAP's "pull" in MDO)

Lives in the Security & Compliance endpoint, not EXO.

```powershell
Connect-IPPSSession

# 1. Build a search by NetworkMessageId (the most precise) — from
#    AIR / Threat Explorer / KQL EmailEvents row
$nmid = "abc123..."
$searchName = "TRAP-replace-SOC-1234-$(Get-Date -Format yyyyMMdd-HHmm)"

New-ComplianceSearch -Name $searchName `
  -ExchangeLocation All `
  -ContentMatchQuery "(NetworkMessageId:$nmid)"

Start-ComplianceSearch -Identity $searchName
# Wait until JobStatus = Completed (poll)
Get-ComplianceSearch -Identity $searchName |
  Format-List Status,Items,Size,JobStartTime,JobEndTime

# 2. Purge — SoftDelete (recoverable) or HardDelete (permanent)
New-ComplianceSearchAction -SearchName $searchName -Purge -PurgeType SoftDelete

# Verify
Get-ComplianceSearchAction -Identity "$searchName_Purge" | Format-List
```

> SoftDelete moves to Deleted Items (recoverable for ~14 days).
> HardDelete bypasses recovery — get legal sign-off before using by
> default.
>
> Docs: [New-ComplianceSearchAction](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/new-compliancesearchaction)

### 4.2 Distribution-list enumeration (the DL fan-out gap)

```powershell
# Recursive expand a DL to a flat user list (TRAP did this natively)
function Get-DistributionGroupMemberRecursive {
  param([Parameter(Mandatory)][string]$Identity)
  $members = Get-DistributionGroupMember -Identity $Identity -ResultSize Unlimited
  foreach ($m in $members) {
    if ($m.RecipientType -match 'Group') {
      Get-DistributionGroupMemberRecursive -Identity $m.PrimarySmtpAddress
    } else {
      $m
    }
  }
}

# Use:
$recipients = Get-DistributionGroupMemberRecursive -Identity "all-staff@<our-tenant>.com" |
              Select-Object -ExpandProperty PrimarySmtpAddress -Unique
```

### 4.3 Forward-following

```powershell
# Find auto-forwarding rules on a mailbox (per-mailbox)
Get-InboxRule -Mailbox <upn> |
  Where-Object { $_.ForwardTo -or $_.ForwardAsAttachmentTo -or $_.RedirectTo } |
  Format-Table Name,Enabled,ForwardTo,ForwardAsAttachmentTo,RedirectTo

# Tenant-wide forwarding configuration
Get-Mailbox -ResultSize Unlimited |
  Where-Object { $_.ForwardingAddress -or $_.ForwardingSmtpAddress } |
  Select-Object PrimarySmtpAddress,ForwardingAddress,ForwardingSmtpAddress,DeliverToMailboxAndForward |
  Export-Csv ~/forwarding-tenantwide.csv -NoTypeInformation

# Message trace by Internet message id — find every internal copy
Get-MessageTraceV2 -MessageId "<internetMessageId>" -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date)
```

> `Get-MessageTrace` (without V2) is on the EXO retirement track —
> use `Get-MessageTraceV2` for any new code. Both still exist as of
> 2026-Q2.

### 4.4 Application access policy (legacy `Mail.*` scope-down)

```powershell
# What does TRAP / any other app have access to?
Get-ApplicationAccessPolicy | Format-Table Identity,AppId,PolicyScopeGroupId,AccessRight

# Scope an app to specific mailboxes (used for new automation, and for
# scoping down the TRAP service principal before Phase 5 decommission)
New-ApplicationAccessPolicy `
  -AppId <clientId> `
  -PolicyScopeGroupId "soc-mailboxes@<our-tenant>.com" `
  -AccessRight RestrictAccess `
  -Description "TRAP / replacement app scoped to SOC mailboxes only"

# Remove on decommission (Phase 5)
Remove-ApplicationAccessPolicy -Identity <identity-from-Get-ApplicationAccessPolicy>
```

> Docs: [New-ApplicationAccessPolicy](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/new-applicationaccesspolicy)

---

## 5. Phase 4 / 5 — Cutover and decommission

### 5.1 Sanity-check before decommission

```powershell
# Anyone still using TRAP's service account?
Get-MailboxPermission -Identity * |
  Where-Object User -eq "trap-svc@<our-tenant>.com" |
  Format-Table Identity,User,AccessRights

Get-ApplicationAccessPolicy |
  Where-Object PolicyScopeGroupId -match "trap" |
  Format-Table Identity,AppId,PolicyScopeGroupId

# Inbound mail-flow rules still pointing at TRAP infra
Get-TransportRule | Where-Object { $_.Description -match "TRAP" -or
                                    $_.RedirectMessageTo -match "trap" } |
  Format-Table Name,State,RedirectMessageTo,Description
```

### 5.2 Decommission

```powershell
# 1. Remove ApplicationAccessPolicy for TRAP service principal
Get-ApplicationAccessPolicy |
  Where-Object AppId -eq <trap-app-id> |
  Remove-ApplicationAccessPolicy

# 2. Remove RBAC for Applications role assignment, if any
Get-ManagementRoleAssignment -RoleAssignee <trap-app-id> |
  Remove-ManagementRoleAssignment

# 3. Drop any TRAP-specific transport rule
Get-TransportRule | Where-Object Name -like "*TRAP*" | Disable-TransportRule
# Verify quiet for 24h before remove
Get-TransportRule | Where-Object Name -like "*TRAP*" | Remove-TransportRule

# 4. Service mailbox(es) TRAP used (if not shared with the OOTB flow)
Remove-Mailbox -Identity "trap-svc@<our-tenant>.com" -PermanentlyDelete:$false
```

> Do **not** remove the abuse mailbox / reporting mailbox. The OOTB
> deployment continues to use it.

---

## 6. Validation queries we run repeatedly

These are read-only and safe to run anytime.

```powershell
# All anti-phish, anti-spam, anti-malware policies and their order
Get-AntiPhishRule         | Format-Table Name,Priority,State,AntiPhishPolicy
Get-HostedContentFilterRule | Format-Table Name,Priority,State,HostedContentFilterPolicy
Get-MalwareFilterRule     | Format-Table Name,Priority,State,MalwareFilterPolicy

# Effective policy for a specific user (which policies actually apply)
Get-AntiPhishRule | Where-Object { $_.SentTo -contains "user@<our-tenant>.com" -or
                                     $_.RecipientDomainIs -contains "<our-tenant>.com" }

# Quarantine inspection
Get-QuarantineMessage -StartReceivedDate (Get-Date).AddHours(-24) -EndReceivedDate (Get-Date) |
  Format-Table Received,SenderAddress,Subject,Type

# A specific quarantined message in detail
Get-QuarantineMessage -Identity <messageId> | Format-List

# Release a quarantined message (admin override)
Release-QuarantineMessage -Identity <messageId> -ReleaseToAll

# Submissions in the last 7 days
Get-QuarantinePolicy | Format-Table Identity,EndUserQuarantinePermissionsValue
```

---

## 7. Bug discovered in `00-MDO-out-of-the-box-deployment-guide.md` §2.4

While checking these cmdlets against Microsoft Learn, the OOTB
deployment guide currently uses `New-SecOpsOverrideRule` and references
`Set-SecOpsOverrideRule`. Both are wrong. Microsoft's docs (and the
actual cmdlets in the EXO management module) use:

| Wrong (in current OOTB guide) | Correct (per Microsoft Learn, 2026-05) |
|---|---|
| `New-SecOpsOverrideRule` | `New-ExoSecOpsOverrideRule` |
| `Set-SecOpsOverrideRule` | `Set-ExoSecOpsOverrideRule` |
| `Remove-SecOpsOverrideRule` | `Remove-ExoSecOpsOverrideRule` |
| `Get-SecOpsOverrideRule` | `Get-ExoSecOpsOverrideRule` |

The policy cmdlets (`*-SecOpsOverridePolicy`) are unprefixed and correct
in the OOTB guide. Only the rule cmdlets carry the `Exo` prefix.

Source: [Configure the advanced delivery policy → PowerShell procedures](https://learn.microsoft.com/en-us/defender-office-365/advanced-delivery-policy-configure#powershell-procedures-for-secops-mailboxes-in-the-advanced-delivery-policy).

Fix the OOTB guide before anyone runs §2.4 verbatim.

---

## 8. References

Every section above cites a specific Microsoft Learn page. The
canonical landing pages we keep going back to:

- [Microsoft Defender for Office 365 docs](https://learn.microsoft.com/en-us/defender-office-365/)
- [ExchangePowerShell module reference](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/)
- [Connect to Exchange Online PowerShell](https://learn.microsoft.com/en-us/powershell/exchange/connect-to-exchange-online-powershell)
- [Configure user reported message settings](https://learn.microsoft.com/en-us/defender-office-365/submissions-user-reported-messages-custom-mailbox)
- [Advanced delivery policy (SecOps mailbox)](https://learn.microsoft.com/en-us/defender-office-365/advanced-delivery-policy-configure)
- [Tenant Allow/Block List — email/spoof](https://learn.microsoft.com/en-us/defender-office-365/tenant-allow-block-list-email-spoof-configure)
- [Zero-hour auto purge (ZAP)](https://learn.microsoft.com/en-us/defender-office-365/zero-hour-auto-purge)
- [Preset security policies](https://learn.microsoft.com/en-us/defender-office-365/preset-security-policies)
- [Safe Attachments policies](https://learn.microsoft.com/en-us/defender-office-365/safe-attachments-policies-configure)
- [Safe Links policies](https://learn.microsoft.com/en-us/defender-office-365/safe-links-policies-configure)
- [Anti-phish policies in MDO](https://learn.microsoft.com/en-us/defender-office-365/anti-phishing-policies-mdo-configure)
- [New-ComplianceSearchAction (Purge)](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/new-compliancesearchaction)
