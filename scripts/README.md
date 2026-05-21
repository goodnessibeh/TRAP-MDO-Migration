# MDO Migration Audit Scripts. Setup

PowerShell commands to set up the toolchain and connect to the tenant
before running the audit scripts in this folder.

> **Use PowerShell 7+ (`pwsh`) or VS Code with the PowerShell extension.**
> Windows PowerShell ISE runs PS 5.1 and the scripts have
> `#Requires -Version 7.0`. The Exchange Online Management module is
> also moving its preferred runtime to PS 7.

---

## TL;DR. paste into an elevated `pwsh`

```powershell
# 1. Trust scripts and PSGallery (one-time per machine)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force
Set-PSRepository    -Name PSGallery -InstallationPolicy Trusted

# 2. Install required modules
Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force -AllowClobber
Install-Module Microsoft.Graph          -Scope CurrentUser -Force -AllowClobber
Install-Module PSScriptAnalyzer         -Scope CurrentUser -Force -AllowClobber

# 3. Connect (browser sign-in opens for each)
Connect-ExchangeOnline
Connect-IPPSSession                                      # alert policy script needs this
Connect-MgGraph -Scopes "User.Read.All","Organization.Read.All"

# 4. Sanity check
Get-ConnectionInformation | Format-Table UserPrincipalName, State, ConnectionUri
Get-MgContext             | Format-List Account, Scopes, TenantId

# 5. cd to the repo's scripts folder, then run an audit (Audit mode by default)
cd <path-to>\TRAP-MDO-Migration\scripts
.\Invoke-MdoThreatPolicyAudit.ps1
```

If everything above succeeds we'll get a CSV report next to the script
and zero red text in the console.

---

## Step 1. Install PowerShell 7

If `pwsh --version` reports nothing, install PowerShell 7 first.

* **Windows (winget):**
  ```powershell
  winget install --id Microsoft.PowerShell --source winget
  ```
* **Windows (MSI):** download the latest LTS MSI from
  [github.com/PowerShell/PowerShell/releases](https://github.com/PowerShell/PowerShell/releases),
  install, then open a new terminal.
* **macOS (Homebrew):** `brew install powershell/tap/powershell`
* **Linux (deb-based):** see
  [aka.ms/powershell-release-debian](https://learn.microsoft.com/en-us/powershell/scripting/install/install-debian).

Confirm:
```powershell
pwsh --version    # want 7.4.x or later
```

---

## Step 2. Execution policy

Default on Windows is `Restricted` (no scripts run). Set per-user once:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

Confirm `Y`. `RemoteSigned` lets local scripts run unsigned; scripts
downloaded from the internet stay blocked until we `Unblock-File`
them. that's the right safe default.

> If we got the repo as a ZIP from GitHub (not `git clone`), unblock
> the downloaded files once:
> ```powershell
> Get-ChildItem -Path .\scripts -Recurse -File | Unblock-File
> ```

Check current policy:
```powershell
Get-ExecutionPolicy -List
```

---

## Step 3. Trust PSGallery

So we don't get the "untrusted repository" prompt on every install:

```powershell
Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
```

Modern (PSResourceGet) form, if our PS 7 has it:
```powershell
Set-PSResourceRepository -Name PSGallery -Trusted
```

---

## Step 4. Install the required modules

```powershell
Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force -AllowClobber
Install-Module Microsoft.Graph          -Scope CurrentUser -Force -AllowClobber
Install-Module PSScriptAnalyzer         -Scope CurrentUser -Force -AllowClobber
```

| Module | Used by | Why |
|---|---|---|
| `ExchangeOnlineManagement` | Every audit script | Provides `Connect-ExchangeOnline`, `Connect-IPPSSession`, and every `*-AntiPhishPolicy` / `*-HostedContentFilterPolicy` / `*-MalwareFilterPolicy` / `*-SafeAttachmentPolicy` / `*-SafeLinksPolicy` / `*-ReportSubmission*` / `*-SecOpsOverride*` / `*-ProtectionAlert` cmdlet. |
| `Microsoft.Graph` | Phase 0 licensing audit | Provides `Connect-MgGraph`, `Get-MgSubscribedSku`, `Get-MgUser`. |
| `PSScriptAnalyzer` | `tests/Test-MdoMigrationScripts.ps1` | Lints every script against `PSScriptAnalyzerSettings.psd1`. |

Confirm versions:
```powershell
Get-Module ExchangeOnlineManagement, Microsoft.Graph, PSScriptAnalyzer -ListAvailable |
  Sort-Object Name, Version |
  Format-Table Name, Version, ModuleType -AutoSize
```

Targets: **EXO ≥ 3.0**, **Microsoft.Graph ≥ 2.0**, **PSScriptAnalyzer ≥ 1.20**.

---

## Step 5. Connect to the tenant

Each connection opens a browser window for modern-auth sign-in the
first time. Sign in with an account that has **Security Administrator**
+ **Exchange Administrator** roles.

```powershell
# Exchange Online. needed by every audit script
Connect-ExchangeOnline -ShowBanner:$false

# Security & Compliance. needed by the Alert Policy audit
# (it queries Get-ProtectionAlert, which only exists in this endpoint)
Connect-IPPSSession -ShowBanner:$false

# Microsoft Graph. needed by the optional licensing inspection in
# Phase 0 (per-mailbox MDO P2 coverage)
Connect-MgGraph -Scopes "User.Read.All","Organization.Read.All"
```

Verify:
```powershell
Get-ConnectionInformation | Format-Table UserPrincipalName, State, ConnectionUri
# Expect two rows: outlook.office365.com (EXO) and ps.compliance.protection.outlook.com (S&C)

Get-MgContext | Format-List Account, Scopes, TenantId
```

If `Get-ConnectionInformation` shows only EXO and not the S&C endpoint,
the alert-policy script will error out. Run `Connect-IPPSSession` once
more.

---

## Step 6. Run an audit

All four audit scripts default to `-Mode Audit` (read-only). They write
a CSV with one row per check, including a `DefenderPortalUrl` column
linking each finding to the relevant page in `security.microsoft.com`.

```powershell
cd <path-to>\TRAP-MDO-Migration\scripts

# Read-only. safe to F5 from any editor.
.\Invoke-MdoThreatPolicyAudit.ps1
.\Invoke-MdoAntiPhishAudit.ps1
.\Invoke-MdoOutboundSpamAudit.ps1
.\Invoke-MdoAlertPolicyAudit.ps1
```

Each script writes its own CSV file in the working directory and exits
non-zero on Fail/Error so they chain cleanly in pipelines.

### Writes (apply mode)

| Script | Live-mode action | Flags |
|---|---|---|
| `Invoke-MdoThreatPolicyAudit.ps1`  | Scope the Strict preset to pilot users / groups, or widen to all domains | `-Mode Live -PilotUsers a@x,b@x` / `-PilotGroups g@x` / `-WidenToAll` |
| `Invoke-MdoAntiPhishAudit.ps1`     | Apply Strict baseline to scoped anti-phish policies | `-Mode Live -PolicyNames 'Custom'` / `-IncludeDefaultPolicy` / `-IncludeAllPolicies` |
| `Invoke-MdoOutboundSpamAudit.ps1`  | Apply Strict baseline (recipient limits, AutoForwardingMode=Off) | `-Mode Live -PolicyNames 'Custom'` / `-IncludeDefaultPolicy` / `-IncludeAllPolicies` |
| `Invoke-MdoAlertPolicyAudit.ps1`   | Disable the AIR-suppressing Auto-Resolve rule | `-Mode Live` |

> `-Mode Live` with no scope flag deliberately applies to nothing.
> Always pair Live with an explicit scope to avoid blanket overwrites.
> Add `-Confirm` if we want per-change Y/N prompts.

---

## Step 7. Run the validator

```powershell
.\tests\Test-MdoMigrationScripts.ps1
```

Runs PSScriptAnalyzer over every script in `scripts/` against
`PSScriptAnalyzerSettings.psd1`. Exits non-zero on any Error or
Warning. Use `-Fix` for auto-formatter fixes and `-OutputCsv
.\findings.csv` to write a machine-readable report.

## Step 8. Bootstrap GitHub Issues for the migration

If we're tracking the migration on GitHub Issues, this script creates
every label, milestone, and issue in one pass. idempotent, dry-run by
default.

```powershell
# Prereq: install GitHub CLI and log in
# https://cli.github.com/
gh auth login

# Dry run. prints what would be created, makes no changes
.\Setup-GitHubIssues.ps1

# Apply. creates ~45 issues + 6 milestones + 20 labels
.\Setup-GitHubIssues.ps1 -Apply

# Or roll out one phase at a time
.\Setup-GitHubIssues.ps1 -Only '0' -Apply   # Phase 0 only
.\Setup-GitHubIssues.ps1 -Only '1' -Apply   # Phase 1 only
```

The script is idempotent: rerunning it skips anything that already
exists (matched by name / title). Safe to keep around as a "redeploy
the board if it gets lost" tool.

See [`.github/ISSUE_TEMPLATE/`](../.github/ISSUE_TEMPLATE/) for the
issue templates used for new ad-hoc tasks beyond this bootstrap.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `cannot be loaded because running scripts is disabled` | Execution policy is Restricted | `Set-ExecutionPolicy RemoteSigned -Scope CurrentUser` |
| `Untrusted repository` prompt on every install | PSGallery not marked trusted | `Set-PSRepository -Name PSGallery -InstallationPolicy Trusted` |
| `'Get-ProtectionAlert' is not recognised` while running alert audit | Not connected to Security & Compliance | `Connect-IPPSSession` |
| `Get-MgUser` returns nothing | Graph connection or scope missing | `Connect-MgGraph -Scopes "User.Read.All","Organization.Read.All"` |
| `Connect-ExchangeOnline` says "could not acquire token" / browser doesn't open | Headless context (WSL, SSH, container) or broken browser handoff | Use device-code auth: `Connect-ExchangeOnline -Device`. opens nothing, gives we a URL + 8-char code to enter on any browser. Same for `Connect-IPPSSession -Device` and `Connect-MgGraph -UseDeviceCode`. |
| `Connect-ExchangeOnline` hangs then fails after some time | Conditional Access requires device compliance / MFA refresh | Sign in via the Azure portal first to satisfy any pending MFA challenge, then retry. Or get a CA exclusion for the admin account. |
| Browser opens but loops back to "Pick an account" | Stale MSAL token cache | `Disconnect-ExchangeOnline -Confirm:$false; Remove-Item ~/.IdentityService -Recurse -Force -ErrorAction SilentlyContinue; Connect-ExchangeOnline -Device` |
| The remote certificate is invalid because of errors in the certificate chain: `UntrustedRoot` | Corporate TLS-inspection proxy (e.g. Cloudflare WARP, Zscaler) intercepting PSGallery / login endpoints | Install the proxy CA in the system trust store, or pause TLS inspection for this device |
| Scripts work in `pwsh` but not in ISE | ISE runs PS 5.1. features in our `#Requires -Version 7.0` are unsupported | Open in VS Code or run `pwsh -File .\Invoke-Mdo*.ps1` |
| `New-ReportSubmissionPolicy: A parameter cannot be found that matches parameter name 'EnableThirdPartyAddress'` | EXO Management module is older than v3 | `Update-Module ExchangeOnlineManagement -Force` then close and reopen `pwsh` |

---

## Roles required for the connecting account

| Role | Why |
|---|---|
| **Security Administrator** | Read/write anti-phish, anti-spam, anti-malware, Safe Links / Safe Attachments, ProtectionAlert, ReportSubmission, SecOps override |
| **Exchange Administrator** | New-Mailbox (reporting mailbox), inspect transport rules / ApplicationAccessPolicy, mailbox-level forwarding inspection |
| **Global Reader** (read-only audit only) | Sufficient for `-Mode Audit` runs across all four scripts |

For `-Mode Live` runs we need the first two. Global Reader is enough
when we just want the CSV.

---

## Where to look in the portal

The `DefenderPortalUrl` column in every audit CSV links a row to the
exact page in `security.microsoft.com` where we can change the setting.
Quick reference:

| Area | URL |
|---|---|
| Preset security policies | https://security.microsoft.com/presetSecurityPolicies |
| Anti-phish policies | https://security.microsoft.com/antiphishing |
| Inbound anti-spam policies | https://security.microsoft.com/antispam |
| Outbound anti-spam policies | https://security.microsoft.com/antispam?type=outbound |
| Anti-malware policies | https://security.microsoft.com/antimalwarev2 |
| Safe Attachments | https://security.microsoft.com/safeattachmentv2 |
| Safe Links | https://security.microsoft.com/safelinksv2 |
| Advanced Delivery (SecOps overrides) | https://security.microsoft.com/advanceddelivery |
| User-reported settings | https://security.microsoft.com/securitysettings/userSubmission |
| Alert policies | https://security.microsoft.com/alertpoliciesv2 |
| Tenant Allow/Block List | https://security.microsoft.com/tenantAllowBlockList |
| Submissions | https://security.microsoft.com/reportsubmission |
| AIR investigations | https://security.microsoft.com/airinvestigation |
| Action Center history | https://security.microsoft.com/action-center/history |
