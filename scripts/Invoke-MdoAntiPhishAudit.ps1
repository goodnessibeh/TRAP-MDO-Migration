#Requires -Version 7.0
#Requires -Modules ExchangeOnlineManagement

<#
.SYNOPSIS
    Audit anti-phishing policies in Microsoft Defender for Office 365.

.DESCRIPTION
    Inspects every anti-phish policy and its rule:
      - PhishThresholdLevel (Strict expects 4 / Most aggressive)
      - Impersonation protection: targeted users / domains, trusted senders
      - Mailbox intelligence and mailbox intelligence protection
      - Spoof intelligence
      - DMARC actions for quarantine and reject
      - First-contact safety tip
      - Honor DMARC policy

    Read-only. Reports gaps and gives the exact Set-AntiPhishPolicy
    command to remediate.

.PARAMETER OutputCsv
    Destination CSV. Default:
    .\mdo-antiphish-audit-YYYYMMDD-HHmm.csv

.PARAMETER VipUsers
    Optional list of user mailboxes whose impersonation should be
    protected. The script will flag policies missing these users in the
    TargetedUsersToProtect collection.

.PARAMETER VipDomains
    Optional list of domains (often partner/customer) whose
    impersonation should be protected.

.PARAMETER Mode
    Audit (default) — read-only.
    Live  — apply Strict baseline to in-scope policies (see -PolicyNames,
            -IncludeDefaultPolicy, -IncludeAllPolicies). Live with no
            scope flags applies to no policies (safe default).

.PARAMETER PolicyNames
    Explicit list of anti-phish policy names to remediate when
    -Mode Live. Use this to target named custom policies.

.PARAMETER IncludeDefaultPolicy
    When -Mode Live, also remediate "Office365 AntiPhish Default" (the
    catch-all global policy).

.PARAMETER IncludeAllPolicies
    When -Mode Live, remediate every policy that has gaps. Use with
    care — overrides any SOC tuning on custom policies.

.EXAMPLE
    .\Invoke-MdoAntiPhishAudit.ps1

.EXAMPLE
    .\Invoke-MdoAntiPhishAudit.ps1 -VipUsers ceo@contoso.com,cfo@contoso.com -VipDomains contoso.com,subsidiary.com

.EXAMPLE
    # Apply Strict baseline to the global default only — least invasive Live mode.
    .\Invoke-MdoAntiPhishAudit.ps1 -Mode Live -IncludeDefaultPolicy

.EXAMPLE
    # Apply to a named custom policy.
    .\Invoke-MdoAntiPhishAudit.ps1 -Mode Live -PolicyNames 'AntiPhish-VIP'

.EXAMPLE
    # Apply to every policy that has gaps (nuclear).
    .\Invoke-MdoAntiPhishAudit.ps1 -Mode Live -IncludeAllPolicies
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$OutputCsv = ".\mdo-antiphish-audit-$(Get-Date -Format yyyyMMdd-HHmm).csv",
    [string[]]$VipUsers,
    [string[]]$VipDomains,

    [ValidateSet('Audit','Live')]
    [string]$Mode = 'Audit',

    [string[]]$PolicyNames,
    [switch]$IncludeDefaultPolicy,
    [switch]$IncludeAllPolicies
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Apply = $Mode -eq 'Live'

if ($Apply -and -not ($PolicyNames -or $IncludeDefaultPolicy -or $IncludeAllPolicies)) {
    Write-Warning 'Mode=Live but no scope flags supplied — no policies will be remediated. Use -PolicyNames, -IncludeDefaultPolicy, or -IncludeAllPolicies.'
}

Import-Module (Join-Path $PSScriptRoot 'common\MdoMigration.Common.psm1') -Force

if (-not (Connect-MdoServices)) { exit 1 }
Reset-MdoAuditRows

$section = 'Anti-Phishing'

# Strict-aligned target values
$strictThreshold     = 4   # PhishThresholdLevel (1 standard - 4 most aggressive)
$expectSpoofIntel    = $true
$expectMailboxIntel  = $true
$expectMailboxIntelProtect = $true
$expectHonorDmarc    = $true
$expectDmarcRejectAct    = 'Quarantine'
$expectDmarcQuarantineAct = 'Quarantine'
$expectFirstContactTip = $true

# --- 1. Policy-by-policy inspection ---------------------------------------

try {
    $policies = Get-AntiPhishPolicy
    foreach ($p in $policies) {
        $gaps = New-Object System.Collections.Generic.List[string]

        if ($p.PhishThresholdLevel -lt $strictThreshold) {
            $gaps.Add("PhishThresholdLevel=$($p.PhishThresholdLevel) (expected >=$strictThreshold for Strict)")
        }
        if ($p.EnableSpoofIntelligence -ne $expectSpoofIntel) {
            $gaps.Add("EnableSpoofIntelligence=$($p.EnableSpoofIntelligence)")
        }
        if ($p.EnableMailboxIntelligence -ne $expectMailboxIntel) {
            $gaps.Add("EnableMailboxIntelligence=$($p.EnableMailboxIntelligence)")
        }
        if ($p.EnableMailboxIntelligenceProtection -ne $expectMailboxIntelProtect) {
            $gaps.Add("EnableMailboxIntelligenceProtection=$($p.EnableMailboxIntelligenceProtection)")
        }
        if ($p.HonorDmarcPolicy -ne $expectHonorDmarc) {
            $gaps.Add("HonorDmarcPolicy=$($p.HonorDmarcPolicy)")
        }
        if ($p.DmarcRejectAction -ne $expectDmarcRejectAct) {
            $gaps.Add("DmarcRejectAction=$($p.DmarcRejectAction)")
        }
        if ($p.DmarcQuarantineAction -ne $expectDmarcQuarantineAct) {
            $gaps.Add("DmarcQuarantineAction=$($p.DmarcQuarantineAction)")
        }
        if ($p.EnableFirstContactSafetyTips -ne $expectFirstContactTip) {
            $gaps.Add("EnableFirstContactSafetyTips=$($p.EnableFirstContactSafetyTips)")
        }
        if (-not $p.EnableTargetedUserProtection) {
            $gaps.Add('EnableTargetedUserProtection=False (impersonation protection off)')
        }

        # VIP coverage if requested
        if ($VipUsers) {
            $missing = $VipUsers | Where-Object { ($p.TargetedUsersToProtect -split ',') -notcontains $_ }
            if ($missing) {
                $gaps.Add("Missing TargetedUsersToProtect: $($missing -join ', ')")
            }
        }
        if ($VipDomains) {
            $missing = $VipDomains | Where-Object { ($p.TargetedDomainsToProtect -split ',') -notcontains $_ }
            if ($missing) {
                $gaps.Add("Missing TargetedDomainsToProtect: $($missing -join ', ')")
            }
        }

        if ($gaps.Count -eq 0) {
            Add-MdoAuditRow -Section $section -Check "Anti-phish policy: $($p.Identity)" `
                            -Status 'Pass' -Value 'Aligned with Strict baseline' `
                            -PortalArea 'AntiPhish'
            continue
        }

        $remediateCmd = "Set-AntiPhishPolicy -Identity `"$($p.Identity)`" -PhishThresholdLevel $strictThreshold -EnableSpoofIntelligence `$true -EnableMailboxIntelligence `$true -EnableMailboxIntelligenceProtection `$true -HonorDmarcPolicy `$true -DmarcRejectAction Quarantine -DmarcQuarantineAction Quarantine -EnableFirstContactSafetyTips `$true -EnableTargetedUserProtection `$true"

        # Decide whether this policy is in scope for -Mode Live
        $inScope = $false
        if ($Apply) {
            if ($IncludeAllPolicies)                                       { $inScope = $true }
            elseif ($PolicyNames -and ($PolicyNames -contains $p.Identity)) { $inScope = $true }
            elseif ($IncludeDefaultPolicy -and $p.Identity -eq 'Office365 AntiPhish Default') { $inScope = $true }
        }

        if (-not $inScope) {
            Add-MdoAuditRow -Section $section -Check "Anti-phish policy: $($p.Identity)" `
                            -Status 'Warn' -Value ($gaps -join '; ') `
                            -Recommendation $remediateCmd -PortalArea 'AntiPhish'
            continue
        }

        # Build Set-AntiPhishPolicy splat. Only override Targeted* if the
        # caller supplied VIP lists — never silently blank existing tuning.
        $setParams = @{
            Identity                              = $p.Identity
            PhishThresholdLevel                   = $strictThreshold
            EnableSpoofIntelligence               = $true
            EnableMailboxIntelligence             = $true
            EnableMailboxIntelligenceProtection   = $true
            HonorDmarcPolicy                      = $true
            DmarcRejectAction                     = 'Quarantine'
            DmarcQuarantineAction                 = 'Quarantine'
            EnableFirstContactSafetyTips          = $true
            EnableTargetedUserProtection          = $true
        }
        if ($VipUsers)   { $setParams['TargetedUsersToProtect']   = $VipUsers }
        if ($VipDomains) { $setParams['TargetedDomainsToProtect'] = $VipDomains }

        if ($PSCmdlet.ShouldProcess($p.Identity, 'Set-AntiPhishPolicy (Strict baseline)')) {
            try {
                Set-AntiPhishPolicy @setParams -ErrorAction Stop | Out-Null
                Add-MdoAuditRow -Section $section -Check "Anti-phish policy: $($p.Identity)" `
                                -Status 'Applied' `
                                -Value "Closed gaps: $($gaps -join '; ')" `
                                -PortalArea 'AntiPhish'
            }
            catch {
                Add-MdoAuditRow -Section $section -Check "Anti-phish policy: $($p.Identity)" `
                                -Status 'Error' -Value $_.Exception.Message `
                                -Recommendation $remediateCmd -PortalArea 'AntiPhish'
            }
        }
    }

    if (-not $policies) {
        Add-MdoAuditRow -Section $section -Check 'Anti-phish policy inventory' -Status 'Fail' `
                        -Value 'No anti-phish policies returned' `
                        -Recommendation 'Apply Strict preset (creates one automatically), or New-AntiPhishPolicy' `
                        -PortalArea 'AntiPhish'
    }
}
catch {
    Add-MdoAuditRow -Section $section -Check 'Anti-phish inspection' -Status 'Error' -Value $_.Exception.Message
}

# --- 2. Rule scope --------------------------------------------------------

try {
    $rules = Get-AntiPhishRule
    foreach ($r in $rules) {
        $scopeParts = @()
        if ($r.SentTo)            { $scopeParts += "SentTo=$($r.SentTo.Count) recipients" }
        if ($r.SentToMemberOf)    { $scopeParts += "SentToMemberOf=$($r.SentToMemberOf.Count) groups" }
        if ($r.RecipientDomainIs) { $scopeParts += "RecipientDomainIs=$(($r.RecipientDomainIs) -join ',')" }
        if (-not $scopeParts)     { $scopeParts += '(no scope set)' }

        Add-MdoAuditRow -Section $section -Check "Anti-phish rule: $($r.Name)" `
                        -Status 'Info' `
                        -Value "State=$($r.State); Priority=$($r.Priority); Policy=$($r.AntiPhishPolicy); Scope=$($scopeParts -join '; ')" `
                        -PortalArea 'AntiPhish'
    }
}
catch {
    Add-MdoAuditRow -Section $section -Check 'Anti-phish rule inspection' -Status 'Error' -Value $_.Exception.Message
}

# --- 3. Default policy sanity --------------------------------------------

try {
    $default = Get-AntiPhishPolicy -Identity 'Office365 AntiPhish Default' -ErrorAction SilentlyContinue
    if ($default) {
        if ($default.PhishThresholdLevel -ge 3) {
            Add-MdoAuditRow -Section $section -Check 'Default anti-phish policy (catches gaps)' `
                            -Status 'Pass' `
                            -Value "PhishThresholdLevel=$($default.PhishThresholdLevel) (>=3)" `
                            -PortalArea 'AntiPhish'
        }
        else {
            Add-MdoAuditRow -Section $section -Check 'Default anti-phish policy (catches gaps)' `
                            -Status 'Warn' `
                            -Value "PhishThresholdLevel=$($default.PhishThresholdLevel) too low" `
                            -Recommendation 'Set-AntiPhishPolicy -Identity "Office365 AntiPhish Default" -PhishThresholdLevel 3' `
                            -PortalArea 'AntiPhish'
        }
    }
}
catch {
    Add-MdoAuditRow -Section $section -Check 'Default anti-phish inspection' -Status 'Error' -Value $_.Exception.Message
}

# --- Output ---------------------------------------------------------------

Export-MdoAuditReport -Path $OutputCsv
if ((Get-MdoFailCount) -gt 0) { exit 1 } else { exit 0 }
