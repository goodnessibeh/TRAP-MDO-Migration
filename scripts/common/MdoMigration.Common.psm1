#Requires -Version 7.0

<#
.SYNOPSIS
    Shared helpers for the TRAP -> MDO migration audit scripts.

.DESCRIPTION
    Common functions used by every Invoke-Mdo*Audit.ps1 script:
      - Connection management for EXO and IPPSSession
      - Audit-row buffering with Defender portal URLs per check
      - CSV export with consistent column layout

.NOTES
    Import-Module .\common\MdoMigration.Common.psm1 -Force
#>

Set-StrictMode -Version Latest

# Module-scoped state ---------------------------------------------------------

$script:AuditRows = [System.Collections.Generic.List[object]]::new()

# Canonical Defender portal URLs (used as defaults when callers don't override)
$script:PortalUrls = @{
    PresetSecurityPolicies = 'https://security.microsoft.com/presetSecurityPolicies'
    AntiPhish = 'https://security.microsoft.com/antiphishing'
    AntiSpamInbound = 'https://security.microsoft.com/antispam'
    AntiSpamOutbound = 'https://security.microsoft.com/antispam?type=outbound'
    AntiMalware = 'https://security.microsoft.com/antimalwarev2'
    SafeAttachments = 'https://security.microsoft.com/safeattachmentv2'
    SafeLinks = 'https://security.microsoft.com/safelinksv2'
    AdvancedDelivery = 'https://security.microsoft.com/advanceddelivery'
    UserSubmission = 'https://security.microsoft.com/securitysettings/userSubmission'
    QuarantinePolicies = 'https://security.microsoft.com/quarantinePolicies'
    AlertPolicies = 'https://security.microsoft.com/alertpoliciesv2'
    TenantAllowBlockList = 'https://security.microsoft.com/tenantAllowBlockList'
    ThreatPolicies = 'https://security.microsoft.com/threatpolicy'
    Submissions = 'https://security.microsoft.com/reportsubmission'
    AirInvestigations = 'https://security.microsoft.com/airinvestigation'
    ActionCenterHistory = 'https://security.microsoft.com/action-center/history'
    Permissions = 'https://security.microsoft.com/emailandcollabpermissions'
    Settings = 'https://security.microsoft.com/securitysettings'
}

function Get-MdoPortalUrl {
    <#
    .SYNOPSIS
        Returns the canonical Defender portal URL for a given area key.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Area
    )
    if ($script:PortalUrls.ContainsKey($Area)) {
        return $script:PortalUrls[$Area]
    }
    return 'https://security.microsoft.com'
}

function Connect-MdoService {
    <#
    .SYNOPSIS
        Connect to Exchange Online and Security & Compliance.
    .DESCRIPTION
        Idempotent — reuses existing sessions when present. Returns
        $true on success, $false otherwise.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [switch]$IncludeIPPSSession,
        [switch]$Quiet
    )

    try {
        if (-not (Get-Module ExchangeOnlineManagement -ListAvailable)) {
            Write-Error 'ExchangeOnlineManagement module not installed. Run: Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force'
            return $false
        }
        $exoInfo = Get-ConnectionInformation -ErrorAction SilentlyContinue |
            Where-Object { $_.State -eq 'Connected' -and $_.TokenStatus -eq 'Active' }
        if (-not $exoInfo) {
            if (-not $Quiet) { Write-Information 'Connecting to Exchange Online...' -InformationAction Continue }
            Connect-ExchangeOnline -ShowBanner:$false | Out-Null
        }
    }
    catch {
        Write-Error "Failed to connect to Exchange Online: $($_.Exception.Message)"
        return $false
    }

    if ($IncludeIPPSSession) {
        try {
            $ippsInfo = Get-ConnectionInformation -ErrorAction SilentlyContinue |
                Where-Object { $_.State -eq 'Connected' -and $_.ConnectionUri -match 'ps.compliance.protection' }
            if (-not $ippsInfo) {
                if (-not $Quiet) { Write-Information 'Connecting to Security & Compliance...' -InformationAction Continue }
                Connect-IPPSSession -ShowBanner:$false -WarningAction SilentlyContinue | Out-Null
            }
        }
        catch {
            Write-Warning "IPPSSession connection failed: $($_.Exception.Message). Compliance Search-Action commands will be unavailable."
        }
    }

    return $true
}

function Add-MdoAuditRow {
    <#
    .SYNOPSIS
        Buffer one row of audit output. The buffer is flushed via Export-MdoAuditReport.

    .PARAMETER Section
        Logical grouping (e.g. 'Threat Policies').

    .PARAMETER Check
        Short label for the check.

    .PARAMETER Status
        Pass / Warn / Fail / Info / Applied / Skipped / Error.

    .PARAMETER Value
        The observed value (free text).

    .PARAMETER Recommendation
        What to do if Status is not Pass.

    .PARAMETER PortalArea
        Key from the canonical URL map (e.g. 'AntiPhish'). Resolves to a
        Defender portal URL written into DefenderPortalUrl column.

    .PARAMETER PortalUrl
        Override the resolved portal URL with a custom URL (e.g. deep
        link with a policy id).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Section,

        [Parameter(Mandatory)]
        [string]$Check,

        [Parameter(Mandatory)]
        [ValidateSet('Pass', 'Warn', 'Fail', 'Info', 'Applied', 'Skipped', 'Error')]
        [string]$Status,

        [string]$Value = '',

        [string]$Recommendation = '',

        [string]$PortalArea,

        [string]$PortalUrl
    )

    if (-not $PortalUrl) {
        if ($PortalArea) {
            $PortalUrl = Get-MdoPortalUrl -Area $PortalArea
        }
        else {
            $PortalUrl = 'https://security.microsoft.com'
        }
    }

    $row = [pscustomobject]@{
        Timestamp = (Get-Date).ToString('o')
        Section = $Section
        Check             = $Check
        Status            = $Status
        Value             = $Value
        Recommendation    = $Recommendation
        DefenderPortalUrl = $PortalUrl
    }
    $script:AuditRows.Add($row)

    $color = switch ($Status) {
        'Pass' { 'Green' }
        'Applied' { 'Cyan' }
        'Warn' { 'Yellow' }
        'Fail' { 'Red' }
        'Error' { 'Red' }
        'Skipped' { 'DarkGray' }
        default { 'White' }
    }

    Write-Host ('[{0,-7}] {1,-28} {2}' -f $Status, $Section, $Check) -ForegroundColor $color
    if ($Value) { Write-Host "          value: $Value" -ForegroundColor DarkGray }
    if ($Recommendation) { Write-Host "          fix:   $Recommendation" -ForegroundColor DarkGray }
    if ($PortalUrl) { Write-Host "          url:   $PortalUrl" -ForegroundColor DarkGray }
}

function Get-MdoAuditRow {
    <#
    .SYNOPSIS
        Returns the in-memory buffer of audit rows.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param()
    return $script:AuditRows.ToArray()
}

function Reset-MdoAuditRow {
    <#
    .SYNOPSIS
        Clear the audit-row buffer.
    #>
    [CmdletBinding()]
    param()
    $script:AuditRows.Clear()
}

function Export-MdoAuditReport {
    <#
    .SYNOPSIS
        Flush the audit-row buffer to a CSV file.

    .PARAMETER Path
        Destination CSV path.

    .PARAMETER PassThru
        Emit the path as output.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [switch]$PassThru
    )

    if ($PSCmdlet.ShouldProcess($Path, 'Write audit CSV')) {
        $script:AuditRows | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8

        # Console summary
        Write-Host ''
        Write-Host "Report saved: $(Resolve-Path -Path $Path)" -ForegroundColor Green
        $script:AuditRows | Group-Object Status | Sort-Object Name |
            ForEach-Object { Write-Host ('  {0,-8} {1}' -f $_.Name, $_.Count) }

        if ($PassThru) { return (Resolve-Path -Path $Path).Path }
    }
}

function Get-MdoFailCount {
    <#
    .SYNOPSIS
        Count of rows with Status in Fail or Error.
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param()
    return ($script:AuditRows | Where-Object { $_.Status -in @('Fail', 'Error') }).Count
}

Export-ModuleMember -Function `
    Connect-MdoService,
Add-MdoAuditRow,
Get-MdoAuditRow,
Reset-MdoAuditRow,
Export-MdoAuditReport,
Get-MdoFailCount,
Get-MdoPortalUrl
