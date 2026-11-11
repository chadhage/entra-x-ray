function Invoke-EntraXray {
    [CmdletBinding(DefaultParameterSetName = 'Live')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Live')]
        [ValidateScript({
            $parsed = [guid]::Empty
            if (-not [guid]::TryParse($_, [ref]$parsed) -or $parsed -eq [guid]::Empty) { throw 'TenantId must be a nonempty tenant GUID, not common, organizations, or a domain alias.' }
            $true
        })][string]$TenantId,
        [Parameter(Mandatory, ParameterSetName = 'Offline')][string]$EvidencePath,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$OutputDirectory,
        [string]$ConfigurationPath,
        [Parameter(ParameterSetName = 'Live')][string[]]$SourceId,
        [Parameter(ParameterSetName = 'Live')][switch]$IncludeBeta,
        [Parameter(ParameterSetName = 'Live')][ValidateSet('Global', 'USGov', 'USGovDoD', 'China')][string]$Environment = 'Global',
        [Parameter(ParameterSetName = 'Live')][ValidateSet('Interactive', 'DeviceCode', 'Certificate', 'ExistingContext')][string]$AuthenticationMode = 'Interactive',
        [Parameter(ParameterSetName = 'Live')][string]$ClientId,
        [Parameter(ParameterSetName = 'Live')][string]$CertificateThumbprint,
        [Parameter(ParameterSetName = 'Live')][ValidateRange(1, 30)][int]$LogDays = 30,
        [Parameter(ParameterSetName = 'Live')][ValidateRange(1, 1000000)][int]$MaxPagesPerSource = 10000,
        [Parameter(ParameterSetName = 'Live')][ValidateRange(1, 10000000)][int]$MaxRequests = 100000,
        [Parameter(ParameterSetName = 'Live')][ValidateRange(0, 10)][int]$MaxRetries = 3
    )
    $out = Assert-XrayOutputDirectory $OutputDirectory
    $overrides = @{}
    if ($ConfigurationPath) { $overrides = Read-XrayJsonObject $ConfigurationPath }
    Write-Warning 'Entra X-Ray outputs contain sensitive tenant inventory and audit data. Use a restricted, encrypted output location and an appropriate retention policy.'
    if ($PSCmdlet.ParameterSetName -eq 'Offline') {
        $evidence = Import-XrayEvidence $EvidencePath
        $merged = Copy-XrayObject $evidence.Settings
        foreach ($key in $overrides.Keys) { $merged[$key] = $overrides[$key] }
        $settings = New-XraySettings $merged
    }
    else {
        $settings = New-XraySettings $overrides
        $plan = Get-EntraXrayPlan -SourceId $SourceId -IncludeBeta:$IncludeBeta -Environment $Environment
        $evidence = Invoke-XrayLiveScan -TenantId ([guid]$TenantId).ToString() -Plan $plan -Settings $settings -AuthenticationMode $AuthenticationMode -ClientId $ClientId -CertificateThumbprint $CertificateThumbprint -LogDays $LogDays -MaxPagesPerSource $MaxPagesPerSource -MaxRequests $MaxRequests -MaxRetries $MaxRetries
    }
    Write-XrayFile (Join-Path $out 'evidence.json') ($evidence | ConvertTo-Json -Depth 100)
    $findings = @(Invoke-XrayAssessment $evidence $settings)
    $result = Export-XrayReport -Evidence $evidence -Findings $findings -Settings $settings -OutputDirectory $out -EvidenceAlreadyWritten
    if ($result.Incomplete) { Write-Warning "Assessment saved with incomplete evidence or unknown tests. Review collection errors and the $($result.UnknownCount) Unknown results; do not interpret this run as complete tenant assurance." }
    $result
}
