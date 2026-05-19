#Requires -Version 7.0
#Requires -Modules ExchangeOnlineManagement

<#
.SYNOPSIS
    Audit Microsoft Defender for Office 365 threat-protection policies
    against the TRAP -> MDO migration blueprint baseline.

.DESCRIPTION
    Inspects:
      - Preset security policy rules (Strict and Standard) and their scope
      - ZAP state across anti-malware and anti-spam policies
      - Anti-malware policy actions and quarantine routing
      - Safe Attachments policies and rules
      - Safe Links policies and rules

    With -Apply and -PilotUsers / -PilotGroups, scopes the Strict preset
    rules to the named pilot population (instead of all recipients).

    Read-only by default. Every change pathway is gated on -Apply +
    ShouldProcess.

.PARAMETER OutputCsv
    Destination CSV. Default: .\mdo-threat-policy-audit-YYYYMMDD-HHmm.csv

.PARAMETER PilotUsers
    Email addresses / UPNs to use as Strict preset pilot scope.

.PARAMETER PilotGroups
    Mail-enabled groups (SMTP) to use as Strict preset pilot scope.

.PARAMETER WidenToAll
    Remove pilot scope and apply Strict preset to all accepted domains.

.PARAMETER Mode
    Audit (default) — read-only. Reports gaps without changing anything.
    Live  — idempotent write: scope Strict preset to pilot users/groups,
            widen scope, enable preset rules.

    The default is Audit so the script is safe to F5 / Run from any
    PowerShell editor without flags. Switch to -Mode Live only when
    you intend to change tenant state.

.EXAMPLE
    .\Invoke-MdoThreatPolicyAudit.ps1
    # Audit mode by default — produces a CSV, makes no changes.

.EXAMPLE
    .\Invoke-MdoThreatPolicyAudit.ps1 -Mode Live -PilotUsers alice@contoso.com,bob@contoso.com

.EXAMPLE
    .\Invoke-MdoThreatPolicyAudit.ps1 -Mode Live -PilotGroups mdo-pilot@contoso.com

.EXAMPLE
    .\Invoke-MdoThreatPolicyAudit.ps1 -Mode Live -WidenToAll
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$OutputCsv = ".\mdo-threat-policy-audit-$(Get-Date -Format yyyyMMdd-HHmm).csv",
    [string[]]$PilotUsers,
    [string[]]$PilotGroups,
    [switch]$WidenToAll,

    [ValidateSet('Audit','Live')]
    [string]$Mode = 'Audit'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Apply = $Mode -eq 'Live'

if (($PilotUsers -or $PilotGroups) -and $WidenToAll) {
    throw 'Specify either -PilotUsers/-PilotGroups OR -WidenToAll, not both.'
}

if ($Apply -and -not ($PilotUsers -or $PilotGroups -or $WidenToAll)) {
    Write-Warning 'Mode=Live but no scoping flags supplied — nothing to apply. Set -PilotUsers, -PilotGroups, or -WidenToAll.'
}

Import-Module (Join-Path $PSScriptRoot 'common\MdoMigration.Common.psm1') -Force

if (-not (Connect-MdoServices)) { exit 1 }
Reset-MdoAuditRows

$section = 'Threat Policies'

# --- 1. Preset security policy rules ---------------------------------------

function Get-RuleScopeDescription {
    param($Rule)
    if (-not $Rule) { return 'rule missing' }
    $parts = @()
    if ($Rule.SentTo)             { $parts += "SentTo($(($Rule.SentTo) -join ','))" }
    if ($Rule.SentToMemberOf)     { $parts += "SentToMemberOf($(($Rule.SentToMemberOf) -join ','))" }
    if ($Rule.RecipientDomainIs)  { $parts += "RecipientDomainIs($(($Rule.RecipientDomainIs) -join ','))" }
    if (-not $parts) { return 'no scope set (effectively none)' }
    return ($parts -join '; ')
}

try {
    $eopStrict = Get-EOPProtectionPolicyRule -Identity 'Strict Preset Security Policy' -ErrorAction SilentlyContinue
    $atpStrict = Get-ATPProtectionPolicyRule -Identity 'Strict Preset Security Policy' -ErrorAction SilentlyContinue

    foreach ($pair in @(@('EOP',$eopStrict), @('ATP',$atpStrict))) {
        $stack = $pair[0]
        $rule  = $pair[1]
        if ($rule) {
            $statusValue = 'Pass'
            $recommendation = ''
            if ($rule.State -ne 'Enabled') {
                $statusValue = 'Warn'
                $recommendation = 'Enable via portal -> Preset security policies, or via Enable-EOPProtectionPolicyRule / Enable-ATPProtectionPolicyRule'
            }
            Add-MdoAuditRow -Section $section `
                            -Check "Strict preset rule ($stack)" `
                            -Status $statusValue `
                            -Value "State=$($rule.State); $(Get-RuleScopeDescription -Rule $rule)" `
                            -Recommendation $recommendation `
                            -PortalArea 'PresetSecurityPolicies'
        }
        else {
            Add-MdoAuditRow -Section $section `
                            -Check "Strict preset rule ($stack)" -Status 'Fail' `
                            -Value 'Not present (preset never applied)' `
                            -Recommendation 'Enable Strict preset via the Defender portal -> Preset security policies' `
                            -PortalArea 'PresetSecurityPolicies'
        }
    }
}
catch {
    Add-MdoAuditRow -Section $section -Check 'Strict preset inspection' -Status 'Error' -Value $_.Exception.Message
}

# --- 2. Pilot scoping (optional, only on -Apply) ---------------------------

if ($Apply -and ($PilotUsers -or $PilotGroups)) {
    foreach ($stack in @('EOP','ATP')) {
        $cmdlet = "Set-${stack}ProtectionPolicyRule"
        $enableCmdlet = "Enable-${stack}ProtectionPolicyRule"
        $params = @{ Identity = 'Strict Preset Security Policy' }
        if ($PilotUsers)  { $params['SentTo'] = $PilotUsers }
        if ($PilotGroups) { $params['SentToMemberOf'] = $PilotGroups }
        # Clear any prior RecipientDomainIs so scope is the named pilot only
        $params['RecipientDomainIs'] = $null

        if ($PSCmdlet.ShouldProcess("Strict preset rule ($stack)", "Scope to pilot population")) {
            try {
                & $cmdlet @params -ErrorAction Stop | Out-Null
                & $enableCmdlet -Identity 'Strict Preset Security Policy' -ErrorAction Stop | Out-Null
                $scopeText = @()
                if ($PilotUsers)  { $scopeText += "users=$(($PilotUsers) -join ',')" }
                if ($PilotGroups) { $scopeText += "groups=$(($PilotGroups) -join ',')" }
                Add-MdoAuditRow -Section $section `
                                -Check "Scope Strict preset ($stack) to pilot" `
                                -Status 'Applied' -Value ($scopeText -join '; ') `
                                -PortalArea 'PresetSecurityPolicies'
            }
            catch {
                Add-MdoAuditRow -Section $section `
                                -Check "Scope Strict preset ($stack) to pilot" `
                                -Status 'Error' -Value $_.Exception.Message
            }
        }
    }
}
elseif ($Apply -and $WidenToAll) {
    foreach ($stack in @('EOP','ATP')) {
        $cmdlet = "Set-${stack}ProtectionPolicyRule"
        $params = @{
            Identity          = 'Strict Preset Security Policy'
            SentTo            = $null
            SentToMemberOf    = $null
            RecipientDomainIs = (Get-AcceptedDomain | ForEach-Object DomainName)
        }
        if ($PSCmdlet.ShouldProcess("Strict preset rule ($stack)", 'Widen scope to all accepted domains')) {
            try {
                & $cmdlet @params -ErrorAction Stop | Out-Null
                Add-MdoAuditRow -Section $section `
                                -Check "Widen Strict preset ($stack) to all domains" `
                                -Status 'Applied' `
                                -Value "RecipientDomainIs=$(($params['RecipientDomainIs']) -join ',')" `
                                -PortalArea 'PresetSecurityPolicies'
            }
            catch {
                Add-MdoAuditRow -Section $section `
                                -Check "Widen Strict preset ($stack) to all domains" `
                                -Status 'Error' -Value $_.Exception.Message
            }
        }
    }
}

# --- 3. ZAP state ----------------------------------------------------------

try {
    $malZapBad = Get-MalwareFilterPolicy | Where-Object { -not $_.ZapEnabled }
    if ($malZapBad) {
        Add-MdoAuditRow -Section $section -Check 'Anti-malware ZAP enabled' -Status 'Warn' `
                        -Value "Disabled on: $(($malZapBad.Identity) -join ', ')" `
                        -Recommendation 'Set-MalwareFilterPolicy -Identity <name> -ZapEnabled $true' `
                        -PortalArea 'AntiMalware'
    }
    else {
        Add-MdoAuditRow -Section $section -Check 'Anti-malware ZAP enabled' -Status 'Pass' `
                        -Value 'On for all policies' -PortalArea 'AntiMalware'
    }

    $contentBad = Get-HostedContentFilterPolicy |
                  Where-Object { -not ($_.PhishZapEnabled -and $_.SpamZapEnabled) }
    if ($contentBad) {
        Add-MdoAuditRow -Section $section -Check 'Anti-spam/phish ZAP enabled' -Status 'Warn' `
                        -Value "Phish/Spam ZAP off on: $(($contentBad.Identity) -join ', ')" `
                        -Recommendation 'Set-HostedContentFilterPolicy -Identity <name> -PhishZapEnabled $true -SpamZapEnabled $true' `
                        -PortalArea 'AntiSpamInbound'
    }
    else {
        Add-MdoAuditRow -Section $section -Check 'Anti-spam/phish ZAP enabled' -Status 'Pass' `
                        -Value 'On for all policies' -PortalArea 'AntiSpamInbound'
    }

    $phishActionBad = Get-HostedContentFilterPolicy |
                      Where-Object { $_.HighConfidencePhishAction -ne 'Quarantine' }
    if ($phishActionBad) {
        Add-MdoAuditRow -Section $section -Check 'HighConfidencePhishAction = Quarantine' -Status 'Warn' `
                        -Value (($phishActionBad | ForEach-Object { "$($_.Identity)=$($_.HighConfidencePhishAction)" }) -join ', ') `
                        -Recommendation 'Set-HostedContentFilterPolicy -Identity <name> -HighConfidencePhishAction Quarantine' `
                        -PortalArea 'AntiSpamInbound'
    }
    else {
        Add-MdoAuditRow -Section $section -Check 'HighConfidencePhishAction = Quarantine' -Status 'Pass' `
                        -PortalArea 'AntiSpamInbound'
    }
}
catch {
    Add-MdoAuditRow -Section $section -Check 'ZAP / action inspection' -Status 'Error' -Value $_.Exception.Message
}

# --- 4. Anti-malware policies ----------------------------------------------

try {
    $malPolicies = Get-MalwareFilterPolicy
    foreach ($p in $malPolicies) {
        $row = "EnableFileFilter=$($p.EnableFileFilter); FileTypes=$(($p.FileTypes | Select-Object -First 5) -join ',')..."
        Add-MdoAuditRow -Section $section -Check "Anti-malware policy: $($p.Identity)" -Status 'Info' `
                        -Value $row -PortalArea 'AntiMalware'
    }
}
catch {
    Add-MdoAuditRow -Section $section -Check 'Anti-malware policy inventory' -Status 'Error' -Value $_.Exception.Message
}

# --- 5. Safe Attachments ---------------------------------------------------

try {
    $saPolicies = Get-SafeAttachmentPolicy
    foreach ($p in $saPolicies) {
        $statusVal = 'Info'
        $rec = ''
        if (-not $p.Enable) {
            $statusVal = 'Warn'
            $rec = 'Set-SafeAttachmentPolicy -Identity <name> -Enable $true'
        }
        Add-MdoAuditRow -Section $section -Check "Safe Attachments policy: $($p.Identity)" `
                        -Status $statusVal `
                        -Value "Enable=$($p.Enable); Action=$($p.Action); Redirect=$($p.Redirect)" `
                        -Recommendation $rec -PortalArea 'SafeAttachments'
    }
}
catch {
    Add-MdoAuditRow -Section $section -Check 'Safe Attachments inventory' -Status 'Error' -Value $_.Exception.Message
}

# --- 6. Safe Links ----------------------------------------------------------

try {
    $slPolicies = Get-SafeLinksPolicy
    foreach ($p in $slPolicies) {
        $statusVal = 'Info'
        $rec = ''
        if (-not $p.EnableSafeLinksForEmail) {
            $statusVal = 'Warn'
            $rec = 'Set-SafeLinksPolicy -Identity <name> -EnableSafeLinksForEmail $true'
        }
        $row = "Email=$($p.EnableSafeLinksForEmail); Teams=$($p.EnableSafeLinksForTeams); Office=$($p.EnableSafeLinksForOffice); ScanAfterDeliver=$($p.DeliverMessageAfterScan); UrlRewriteDisabled=$($p.DisableUrlRewrite)"
        Add-MdoAuditRow -Section $section -Check "Safe Links policy: $($p.Identity)" `
                        -Status $statusVal -Value $row -Recommendation $rec -PortalArea 'SafeLinks'
    }
}
catch {
    Add-MdoAuditRow -Section $section -Check 'Safe Links inventory' -Status 'Error' -Value $_.Exception.Message
}

# --- Output ----------------------------------------------------------------

Export-MdoAuditReport -Path $OutputCsv
if ((Get-MdoFailCount) -gt 0) { exit 1 } else { exit 0 }
