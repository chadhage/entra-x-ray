function Get-XrayValue {
    param([AllowNull()]$InputObject, [Parameter(Mandatory)][string]$Path)
    if ($InputObject -is [System.Collections.IDictionary] -and $InputObject.Contains($Path)) { return ,$InputObject[$Path] }
    if ($null -ne $InputObject -and $null -ne $InputObject.PSObject.Properties[$Path]) { return ,$InputObject.PSObject.Properties[$Path].Value }
    $current = $InputObject
    foreach ($part in $Path.Split('.')) {
        if ($null -eq $current) { return $null }
        if ($current -is [System.Collections.IDictionary]) {
            $current = $current[$part]
        }
        else {
            $property = $current.PSObject.Properties[$part]
            if ($null -eq $property) { return $null }
            $current = $property.Value
        }
    }
    return ,$current
}

function Assert-XrayFields {
    param([AllowNull()]$InputObject, [string[]]$Paths)
    foreach ($path in $Paths) {
        if ($InputObject -is [System.Collections.IDictionary] -and $InputObject.Contains($path)) { continue }
        $current = $InputObject
        foreach ($part in $path.Split('.')) {
            if ($current -is [System.Collections.IDictionary]) {
                if (-not $current.Contains($part)) { throw [System.IO.InvalidDataException]::new("Missing evidence field '$path'.") }
                $current = $current[$part]
            }
            elseif ($null -ne $current -and $null -ne $current.PSObject.Properties[$part]) {
                $current = $current.PSObject.Properties[$part].Value
            }
            else {
                throw [System.IO.InvalidDataException]::new("Missing evidence field '$path'.")
            }
        }
    }
}

function Get-XrayBoolean {
    param($InputObject, [string]$Path)
    $value = Get-XrayValue $InputObject $Path
    if ($value -isnot [bool]) { throw [System.IO.InvalidDataException]::new("Evidence field '$Path' must be a Boolean, not missing, null, or text.") }
    $value
}

function Test-XrayRoleAssignableGroup {
    param($Group)
    Assert-XrayFields $Group @('isAssignableToRole')
    # This optional Graph property grants role eligibility only when explicitly true.
    if ($null -eq (Get-XrayValue $Group 'isAssignableToRole')) { return $false }
    Get-XrayBoolean $Group 'isAssignableToRole'
}

function Get-XrayNumber {
    param($InputObject, [string]$Path, [switch]$Integer)
    $value = Get-XrayValue $InputObject $Path
    if (($value -isnot [int] -and $value -isnot [long] -and $value -isnot [double] -and
            $value -isnot [single] -and $value -isnot [decimal]) -or
        [double]::IsNaN([double]$value) -or [double]::IsInfinity([double]$value) -or [double]$value -lt 0 -or
        ($Integer -and [Math]::Truncate([double]$value) -ne [double]$value)) {
        throw [System.IO.InvalidDataException]::new("Evidence field '$Path' must be a nonnegative finite numeric value of the required precision.")
    }
    [double]$value
}

function ConvertTo-XrayAbsoluteUri {
    param([string]$Value)
    $uri = $null
    if (-not [uri]::TryCreate($Value, [UriKind]::Absolute, [ref]$uri)) {
        throw [System.IO.InvalidDataException]::new('Invalid absolute URI in evidence.')
    }
    $uri
}

function ConvertTo-XrayDate {
    param([AllowNull()]$Value)
    if ($null -eq $Value -or $Value -eq '') { return $null }
    if ($Value -is [datetimeoffset]) { return $Value.ToUniversalTime() }
    if ($Value -is [datetime]) { return [datetimeoffset]::new($Value.ToUniversalTime()) }
    $parsed = [datetimeoffset]::MinValue
    $style = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
    if (-not [datetimeoffset]::TryParse([string]$Value, [cultureinfo]::InvariantCulture, $style, [ref]$parsed)) {
        throw [System.IO.InvalidDataException]::new('Invalid evidence timestamp; an ISO 8601 date is required.')
    }
    $parsed
}

function Format-XrayUtc {
    param([datetimeoffset]$Value)
    $Value.UtcDateTime.ToString('o', [cultureinfo]::InvariantCulture)
}

function New-XraySettings {
    param([System.Collections.IDictionary]$Overrides = @{})
    $settings = [ordered]@{
        StaleUserDays = 90
        StaleGuestDays = 90
        StaleDeviceDays = 90
        GuestInvitationAgeDays = 30
        CredentialWarningDays = 30
        MaxCredentialLifetimeDays = 180
        MaxGlobalAdministrators = 5
        HybridSyncMaxHours = 24
        SecureScoreThreshold = 0.7
        EmergencyAccessAccountId = @()
    }
    foreach ($key in $Overrides.Keys) {
        if (-not $settings.Contains($key)) { throw [System.ArgumentException]::new("Unknown setting '$key'.") }
        $value = $Overrides[$key]
        if ($key -eq 'EmergencyAccessAccountId') {
            if ($null -eq $value -or $value -is [string] -or $value -isnot [System.Collections.IList]) {
                throw [System.ArgumentException]::new('EmergencyAccessAccountId must be an array of object GUIDs.')
            }
            foreach ($id in $value) {
                $guid = [guid]::Empty
                if (-not [guid]::TryParse([string]$id, [ref]$guid) -or $guid -eq [guid]::Empty) {
                    throw [System.ArgumentException]::new('EmergencyAccessAccountId contains an invalid object GUID.')
                }
            }
            $settings[$key] = @($value | ForEach-Object { ([guid]$_).ToString() } | Select-Object -Unique)
        }
        elseif ($key -eq 'SecureScoreThreshold') {
            if ($value -is [string] -or $value -is [bool] -or $null -eq $value -or $value -isnot [ValueType] -or
                [double]::IsNaN([double]$value) -or [double]$value -lt 0 -or [double]$value -gt 1) {
                throw [System.ArgumentException]::new('SecureScoreThreshold must be a number from 0 to 1.')
            }
            $settings[$key] = [double]$value
        }
        else {
            if (($value -isnot [int] -and $value -isnot [long]) -or $value -lt 1 -or $value -gt 3650) {
                throw [System.ArgumentException]::new("$key must be an integer from 1 to 3650.")
            }
            $settings[$key] = [int]$value
        }
    }
    $settings
}

function ConvertTo-XrayMarkdownText {
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return '' }
    $text = [System.Net.WebUtility]::HtmlEncode([string]$Value)
    $text = $text.Replace('\', '\\').Replace('|', '\|').Replace('[', '\[').Replace(']', '\]').Replace('`', '&#96;')
    $text -replace '\r\n|\r|\n', '<br>'
}

function ConvertTo-XrayCsvText {
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return '' }
    $text = [string]$Value
    if ($text -match '^\s*[=+\-@]') { return "'$text" }
    $text
}

function New-XrayEntity {
    param($Item, [string]$Detail)
    $id = Get-XrayValue $Item 'id'
    if (-not $id) { $id = Get-XrayValue $Item 'tenantId' }
    if (-not $id) { $id = 'configuration' }
    $name = Get-XrayValue $Item 'displayName'
    if (-not $name) { $name = Get-XrayValue $Item 'userDisplayName' }
    if (-not $name) { $name = Get-XrayValue $Item 'userPrincipalName' }
    if (-not $name) { $name = $id }
    [ordered]@{ Id = [string]$id; DisplayName = [string]$name; Detail = $Detail }
}

function Find-XrayIssue {
    param([AllowEmptyCollection()][object[]]$Items = @(), [string[]]$Fields = @(), [Parameter(Mandatory)][scriptblock]$Test)
    foreach ($item in $Items) {
        Assert-XrayFields $item $Fields
        $detail = & $Test $item
        if ($detail) { New-XrayEntity $item ([string]$detail) }
    }
}
