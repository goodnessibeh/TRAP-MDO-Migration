@{
    # PSScriptAnalyzer settings for the TRAP -> MDO migration scripts.
    # https://learn.microsoft.com/en-us/powershell/module/psscriptanalyzer/

    Severity = @('Error','Warning','Information')

    IncludeDefaultRules = $true

    # Rules we intentionally suppress, with reasons.
    ExcludeRules = @(
        # We use Write-Host deliberately for colorised interactive output;
        # the audit rows are buffered separately and exported via CSV.
        'PSAvoidUsingWriteHost',

        # Audit scripts are not designed to be piped — they execute,
        # write a CSV, and exit. ShouldProcess is applied where needed.
        'PSUseShouldProcessForStateChangingFunctions',

        # Convert-To-SecureString with -AsPlainText is fine for the
        # places we use it (test fixtures only); not used in production.
        'PSAvoidUsingConvertToSecureStringWithPlainText',

        # Cosmetic-only formatter rules that PSScriptAnalyzer's own -Fix
        # can detect but not always fully auto-resolve (multi-line splat
        # hashtables, mixed-alignment param blocks, etc.). They are not
        # correctness or security signals; we don't want them blocking
        # CI. Enable individually if you want to hand-polish formatting.
        'PSAlignAssignmentStatement',
        'PSUseConsistentWhitespace',
        'PSUseConsistentIndentation'
    )

    Rules = @{
        PSPlaceOpenBrace = @{
            Enable             = $true
            OnSameLine         = $true
            NewLineAfter       = $true
            IgnoreOneLineBlock = $true
        }
        PSPlaceCloseBrace = @{
            Enable             = $true
            NewLineAfter       = $true
            IgnoreOneLineBlock = $true
            NoEmptyLineBefore  = $false
        }
        PSUseConsistentIndentation = @{
            Enable          = $true
            IndentationSize = 4
            Kind            = 'space'
        }
        PSUseConsistentWhitespace = @{
            Enable                          = $true
            CheckOpenBrace                  = $true
            CheckOpenParen                  = $true
            CheckOperator                   = $true
            CheckSeparator                  = $true
            CheckPipe                       = $true
            CheckInnerBrace                 = $true
            CheckParameter                  = $false
        }
        PSAlignAssignmentStatement = @{
            Enable         = $true
            CheckHashtable = $true
        }
    }
}
