#Requires -Version 7.0
#Requires -Modules ExchangeOnlineManagement

<#
.SYNOPSIS
    Audit Microsoft 365 alert policies (the ProtectionAlert layer).

.DESCRIPTION
    Alert policies in Microsoft 365 are managed via the ProtectionAlert
    cmdlets in the Security & Compliance endpoint. This script:
      - Enumerates every ProtectionAlert with state and severity
      - Calls out the AIR-suppressing "Auto-Resolve - Email reported by
        user as malware or phish" rule (the single most common reason
        AIR fails to fire in newly-migrated tenants)
      - Confirms that critical incident-policy alerts are enabled (mail
        forwarding, mailbox manipulation rules, suspicious sign-ins,
        creation of forwarding/redirect rule)
      - Optionally disables the AIR-suppressing rule (-Apply switch)

.PARAMETER OutputCsv
    Destination CSV. Default: .\mdo-alert-policy-audit-YYYYMMDD-HHmm.csv

.PARAMETER CriticalAlertNames
    Names (or substrings) of alert policies that MUST be enabled for the
    blueprint to be healthy. The defaults cover the high-value SOC
    alerts. Override if your environment uses different names.

.PARAMETER Mode
    Audit (default) — read-only. Reports the Auto-Resolve rule state
    without disabling it.
    Live  — disable the Auto-Resolve rule that suppresses the
    user-reported-phish alert (per OOTB guide §2.5).

.EXAMPLE
    .\Invoke-MdoAlertPolicyAudit.ps1
    # Audit mode by default.

.EXAMPLE
    .\Invoke-MdoAlertPolicyAudit.ps1 -Mode Live
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$OutputCsv = ".\mdo-alert-policy-audit-$(Get-Date -Format yyyyMMdd-HHmm).csv",

    [string[]]$CriticalAlertNames = @(
        'Email reported by user as malware or phish',
        'A potentially malicious URL click was detected',
        'Suspicious email sending patterns detected',
        'Creation of forwarding/redirect rule',
        'Phish delivered due to an ETR override',
        'Phish not zapped because ZAP is disabled',
        'Tenant restricted from sending unprovisioned email',
        'Tenant restricted from sending email'
    ),

    [ValidateSet('Audit', 'Live')]
    [string]$Mode = 'Audit'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Apply = $Mode -eq 'Live'

Import-Module (Join-Path $PSScriptRoot 'common\MdoMigration.Common.psm1') -Force

if (-not (Connect-MdoService -IncludeIPPSSession)) { exit 1 }
Reset-MdoAuditRow

$section = 'Alert Policies'

# --- 1. Inventory ---------------------------------------------------------

try {
    $alerts = Get-ProtectionAlert
    $totalCount = $alerts.Count
    $disabledCount = ($alerts | Where-Object { $_.Disabled }).Count
    $enabledCount = $totalCount - $disabledCount

    Add-MdoAuditRow -Section $section -Check 'Alert policy inventory' -Status 'Info' `
        -Value "Total=$totalCount; Enabled=$enabledCount; Disabled=$disabledCount" `
        -PortalArea 'AlertPolicies'
}
catch {
    Add-MdoAuditRow -Section $section -Check 'Alert policy inventory' -Status 'Error' -Value $_.Exception.Message
    Export-MdoAuditReport -Path $OutputCsv
    exit 1
}

# --- 2. The AIR-suppressing auto-resolve rule -----------------------------

try {
    $autoResolve = Get-ProtectionAlert |
        Where-Object { $_.Name -like '*Auto-Resolve*Email reported*' }

    if (-not $autoResolve) {
        Add-MdoAuditRow -Section $section -Check 'Auto-Resolve rule for user-reported phish' `
            -Status 'Pass' -Value 'No matching rule found (AIR can fire)' `
            -PortalArea 'AlertPolicies'
    }
    else {
        $enabled = $autoResolve | Where-Object { -not $_.Disabled }
        if (-not $enabled) {
            Add-MdoAuditRow -Section $section -Check 'Auto-Resolve rule for user-reported phish' `
                -Status 'Pass' -Value "Rule present but disabled: $(($autoResolve.Name) -join ', ')" `
                -PortalArea 'AlertPolicies'
        }
        elseif ($Apply) {
            foreach ($r in $enabled) {
                if ($PSCmdlet.ShouldProcess($r.Name, 'Disable-ProtectionAlert')) {
                    Disable-ProtectionAlert -Identity $r.Identity -ErrorAction Stop | Out-Null
                    Add-MdoAuditRow -Section $section -Check 'Auto-Resolve rule for user-reported phish' `
                        -Status 'Applied' -Value "Disabled: $($r.Name)" `
                        -PortalArea 'AlertPolicies'
                }
            }
        }
        else {
            Add-MdoAuditRow -Section $section -Check 'Auto-Resolve rule for user-reported phish' `
                -Status 'Warn' `
                -Value "Enabled rule(s) will suppress AIR: $(($enabled.Name) -join ', ')" `
                -Recommendation 'Rerun with -Apply, or run: Disable-ProtectionAlert -Identity <name>' `
                -PortalArea 'AlertPolicies'
        }
    }
}
catch {
    Add-MdoAuditRow -Section $section -Check 'Auto-Resolve rule inspection' -Status 'Error' -Value $_.Exception.Message
}

# --- 3. Critical alerts present & enabled --------------------------------

try {
    foreach ($name in $CriticalAlertNames) {
        $matching = Get-ProtectionAlert | Where-Object { $_.Name -like "*$name*" }
        if (-not $matching) {
            Add-MdoAuditRow -Section $section -Check "Critical alert: $name" `
                -Status 'Warn' -Value 'Alert policy not present' `
                -Recommendation 'Microsoft built-in alerts auto-provision once Defender is licensed; if missing for >24h, open a support case' `
                -PortalArea 'AlertPolicies'
            continue
        }
        $enabled = $matching | Where-Object { -not $_.Disabled }
        if (-not $enabled) {
            Add-MdoAuditRow -Section $section -Check "Critical alert: $name" `
                -Status 'Warn' `
                -Value "All matching policies disabled: $(($matching.Name) -join ', ')" `
                -Recommendation 'Enable-ProtectionAlert -Identity <name>' `
                -PortalArea 'AlertPolicies'
        }
        else {
            $detail = ($enabled | ForEach-Object { "$($_.Name) [Severity=$($_.Severity)]" }) -join '; '
            Add-MdoAuditRow -Section $section -Check "Critical alert: $name" `
                -Status 'Pass' -Value $detail `
                -PortalArea 'AlertPolicies'
        }
    }
}
catch {
    Add-MdoAuditRow -Section $section -Check 'Critical alert inspection' -Status 'Error' -Value $_.Exception.Message
}

# --- 4. Severity / category breakdown ------------------------------------

try {
    $byCategory = Get-ProtectionAlert |
        Where-Object { -not $_.Disabled } |
        Group-Object Category |
        ForEach-Object { "$($_.Name)=$($_.Count)" }
    Add-MdoAuditRow -Section $section -Check 'Enabled alerts by category' -Status 'Info' `
        -Value ($byCategory -join '; ') -PortalArea 'AlertPolicies'

    $bySeverity = Get-ProtectionAlert |
        Where-Object { -not $_.Disabled } |
        Group-Object Severity |
        ForEach-Object { "$($_.Name)=$($_.Count)" }
    Add-MdoAuditRow -Section $section -Check 'Enabled alerts by severity' -Status 'Info' `
        -Value ($bySeverity -join '; ') -PortalArea 'AlertPolicies'
}
catch {
    Add-MdoAuditRow -Section $section -Check 'Alert breakdown' -Status 'Error' -Value $_.Exception.Message
}

# --- 5. Custom (non-default) alerts the SOC has built --------------------

try {
    $custom = Get-ProtectionAlert | Where-Object { -not $_.IsSystemRule }
    if ($custom) {
        $list = ($custom | Select-Object -First 25 | ForEach-Object { $_.Name }) -join '; '
        Add-MdoAuditRow -Section $section -Check 'Custom alert policies present' -Status 'Info' `
            -Value "Total=$($custom.Count); first 25=$list" -PortalArea 'AlertPolicies'
    }
    else {
        Add-MdoAuditRow -Section $section -Check 'Custom alert policies present' -Status 'Info' `
            -Value 'None — only Microsoft built-ins active' -PortalArea 'AlertPolicies'
    }
}
catch {
    Add-MdoAuditRow -Section $section -Check 'Custom alert inspection' -Status 'Error' -Value $_.Exception.Message
}

Export-MdoAuditReport -Path $OutputCsv
if ((Get-MdoFailCount) -gt 0) { exit 1 } else { exit 0 }
