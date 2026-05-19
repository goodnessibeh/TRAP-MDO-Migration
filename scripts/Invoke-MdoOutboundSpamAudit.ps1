#Requires -Version 7.0
#Requires -Modules ExchangeOnlineManagement

<#
.SYNOPSIS
    Audit outbound spam protection policies (the egress side of EOP).

.DESCRIPTION
    Outbound spam policies guard against compromised internal accounts
    blasting messages out. The TRAP -> MDO migration roadmap assumes
    these are aligned to the Strict baseline because compromised internal
    mailboxes are a recurring SOC ticket source.

    Inspects every Get-HostedOutboundSpamFilterPolicy for:
      - RecipientLimitPerHour (external + internal) <= Strict
      - RecipientLimitPerDay <= Strict
      - AutoForwardingMode: Off (forwarding-to-external blocked)
      - ActionWhenThresholdReached: BlockUserForToday or BlockUser
      - NotifyOutboundSpam + recipients populated

.PARAMETER OutputCsv
    Destination CSV. Default:
    .\mdo-outbound-spam-audit-YYYYMMDD-HHmm.csv

.PARAMETER NotifyRecipients
    Optional list of mailboxes that should receive outbound-spam
    notifications. The script flags any policy whose notification
    recipients differ.

.PARAMETER Mode
    Audit (default) — read-only.
    Live  — apply Strict baseline to in-scope policies (see -PolicyNames,
            -IncludeDefaultPolicy, -IncludeAllPolicies). Live with no
            scope flags applies to no policies.

.PARAMETER PolicyNames
    Explicit list of outbound spam policy names to remediate when
    -Mode Live.

.PARAMETER IncludeDefaultPolicy
    When -Mode Live, also remediate the "Default" outbound spam policy
    (the catch-all global one).

.PARAMETER IncludeAllPolicies
    When -Mode Live, remediate every policy that has gaps. Use with
    care — lowers recipient limits which may impact legitimate
    bulk-sending workloads.

.EXAMPLE
    .\Invoke-MdoOutboundSpamAudit.ps1

.EXAMPLE
    .\Invoke-MdoOutboundSpamAudit.ps1 -NotifyRecipients soc-alerts@contoso.com

.EXAMPLE
    # Apply Strict baseline to the global default only.
    .\Invoke-MdoOutboundSpamAudit.ps1 -Mode Live -IncludeDefaultPolicy `
        -NotifyRecipients soc-alerts@contoso.com
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$OutputCsv = ".\mdo-outbound-spam-audit-$(Get-Date -Format yyyyMMdd-HHmm).csv",
    [string[]]$NotifyRecipients,

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

$section = 'Outbound Spam'

# Strict baseline (per Microsoft's preset policies docs)
$strictExternalPerHour = 400
$strictInternalPerHour = 800
$strictPerDay          = 800
$strictActionThreshold = 'BlockUser'
$strictAutoForwarding  = 'Off'

try {
    $policies = Get-HostedOutboundSpamFilterPolicy
    foreach ($p in $policies) {
        $gaps = New-Object System.Collections.Generic.List[string]

        if ($p.RecipientLimitExternalPerHour -gt $strictExternalPerHour) {
            $gaps.Add("RecipientLimitExternalPerHour=$($p.RecipientLimitExternalPerHour) (Strict: $strictExternalPerHour)")
        }
        if ($p.RecipientLimitInternalPerHour -gt $strictInternalPerHour) {
            $gaps.Add("RecipientLimitInternalPerHour=$($p.RecipientLimitInternalPerHour) (Strict: $strictInternalPerHour)")
        }
        if ($p.RecipientLimitPerDay -gt $strictPerDay) {
            $gaps.Add("RecipientLimitPerDay=$($p.RecipientLimitPerDay) (Strict: $strictPerDay)")
        }
        if ($p.ActionWhenThresholdReached -ne $strictActionThreshold -and
            $p.ActionWhenThresholdReached -ne 'BlockUserForToday') {
            $gaps.Add("ActionWhenThresholdReached=$($p.ActionWhenThresholdReached) (Strict: BlockUser or BlockUserForToday)")
        }
        if ($p.AutoForwardingMode -ne $strictAutoForwarding) {
            $gaps.Add("AutoForwardingMode=$($p.AutoForwardingMode) (Strict: Off — blocks all external auto-forwarding)")
        }

        if ($NotifyRecipients) {
            if (-not $p.NotifyOutboundSpam) {
                $gaps.Add('NotifyOutboundSpam=$false')
            }
            $missingRecipients = $NotifyRecipients | Where-Object { $p.NotifyOutboundSpamRecipients -notcontains $_ }
            if ($missingRecipients) {
                $gaps.Add("NotifyOutboundSpamRecipients missing: $($missingRecipients -join ', ')")
            }
        }
        elseif (-not $p.NotifyOutboundSpam) {
            $gaps.Add('NotifyOutboundSpam=$false (consider enabling and specifying SOC recipients)')
        }

        if ($gaps.Count -eq 0) {
            Add-MdoAuditRow -Section $section -Check "Outbound spam policy: $($p.Identity)" `
                            -Status 'Pass' -Value 'Aligned with Strict baseline' `
                            -PortalArea 'AntiSpamOutbound'
            continue
        }

        $fixCmd = "Set-HostedOutboundSpamFilterPolicy -Identity `"$($p.Identity)`" -RecipientLimitExternalPerHour $strictExternalPerHour -RecipientLimitInternalPerHour $strictInternalPerHour -RecipientLimitPerDay $strictPerDay -ActionWhenThresholdReached $strictActionThreshold -AutoForwardingMode Off"
        if ($NotifyRecipients) {
            $fixCmd += " -NotifyOutboundSpam `$true -NotifyOutboundSpamRecipients $($NotifyRecipients -join ',')"
        }

        # Decide whether this policy is in scope for -Mode Live
        $inScope = $false
        if ($Apply) {
            if ($IncludeAllPolicies)                                       { $inScope = $true }
            elseif ($PolicyNames -and ($PolicyNames -contains $p.Identity)) { $inScope = $true }
            elseif ($IncludeDefaultPolicy -and $p.Identity -eq 'Default')   { $inScope = $true }
        }

        if (-not $inScope) {
            Add-MdoAuditRow -Section $section -Check "Outbound spam policy: $($p.Identity)" `
                            -Status 'Warn' -Value ($gaps -join '; ') `
                            -Recommendation $fixCmd -PortalArea 'AntiSpamOutbound'
            continue
        }

        $setParams = @{
            Identity                       = $p.Identity
            RecipientLimitExternalPerHour  = $strictExternalPerHour
            RecipientLimitInternalPerHour  = $strictInternalPerHour
            RecipientLimitPerDay           = $strictPerDay
            ActionWhenThresholdReached     = $strictActionThreshold
            AutoForwardingMode             = 'Off'
        }
        if ($NotifyRecipients) {
            $setParams['NotifyOutboundSpam']             = $true
            $setParams['NotifyOutboundSpamRecipients']   = $NotifyRecipients
        }

        if ($PSCmdlet.ShouldProcess($p.Identity, 'Set-HostedOutboundSpamFilterPolicy (Strict baseline)')) {
            try {
                Set-HostedOutboundSpamFilterPolicy @setParams -ErrorAction Stop | Out-Null
                Add-MdoAuditRow -Section $section -Check "Outbound spam policy: $($p.Identity)" `
                                -Status 'Applied' `
                                -Value "Closed gaps: $($gaps -join '; ')" `
                                -PortalArea 'AntiSpamOutbound'
            }
            catch {
                Add-MdoAuditRow -Section $section -Check "Outbound spam policy: $($p.Identity)" `
                                -Status 'Error' -Value $_.Exception.Message `
                                -Recommendation $fixCmd -PortalArea 'AntiSpamOutbound'
            }
        }
    }
}
catch {
    Add-MdoAuditRow -Section $section -Check 'Outbound spam inspection' -Status 'Error' -Value $_.Exception.Message
}

# Rule scope
try {
    $rules = Get-HostedOutboundSpamFilterRule
    foreach ($r in $rules) {
        Add-MdoAuditRow -Section $section -Check "Outbound spam rule: $($r.Name)" -Status 'Info' `
                        -Value "State=$($r.State); Policy=$($r.HostedOutboundSpamFilterPolicy); From=$(($r.From) -join ','); FromMemberOf=$(($r.FromMemberOf) -join ',')" `
                        -PortalArea 'AntiSpamOutbound'
    }
}
catch {
    Add-MdoAuditRow -Section $section -Check 'Outbound spam rule inspection' -Status 'Error' -Value $_.Exception.Message
}

# Tenant-wide auto-forwarding inspection (sensitive for outbound spam)
try {
    $acceptedDomains = (Get-AcceptedDomain).DomainName
    $domainPattern   = '@(' + (($acceptedDomains | ForEach-Object { [regex]::Escape($_) }) -join '|') + ')$'

    $fwdMailboxes = Get-Mailbox -ResultSize Unlimited |
                    Where-Object { $_.ForwardingAddress -or $_.ForwardingSmtpAddress }
    if ($fwdMailboxes) {
        $external = $fwdMailboxes | Where-Object {
            $_.ForwardingSmtpAddress -and ($_.ForwardingSmtpAddress -notmatch $domainPattern)
        }
        $fwdStatus = $external ? 'Warn' : 'Info'
        $fwdRec    = $external ? 'Review and disable external auto-forwarding via Set-Mailbox -ForwardingAddress $null -ForwardingSmtpAddress $null' : ''
        Add-MdoAuditRow -Section $section -Check 'Mailboxes with auto-forwarding configured' `
                        -Status $fwdStatus `
                        -Value "Total=$($fwdMailboxes.Count); externally-forwarding=$(($external).Count)" `
                        -Recommendation $fwdRec `
                        -PortalArea 'AntiSpamOutbound'
    }
    else {
        Add-MdoAuditRow -Section $section -Check 'Mailboxes with auto-forwarding configured' `
                        -Status 'Pass' -Value '0' -PortalArea 'AntiSpamOutbound'
    }
}
catch {
    Add-MdoAuditRow -Section $section -Check 'Auto-forwarding inspection' -Status 'Error' -Value $_.Exception.Message
}

Export-MdoAuditReport -Path $OutputCsv
if ((Get-MdoFailCount) -gt 0) { exit 1 } else { exit 0 }
