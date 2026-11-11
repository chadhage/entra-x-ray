#requires -Version 7.2
[CmdletBinding(DefaultParameterSetName = 'Live')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Live')][string]$TenantId,
    [Parameter(Mandatory, ParameterSetName = 'Offline')][string]$EvidencePath,
    [Parameter(Mandatory)][string]$OutputDirectory,
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

Import-Module "$PSScriptRoot\src\EntraXray.psd1" -ErrorAction Stop
Invoke-EntraXray @PSBoundParameters
