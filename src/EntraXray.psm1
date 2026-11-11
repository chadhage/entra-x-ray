Set-StrictMode -Version Latest

foreach ($file in @('Private\Common.ps1', 'Private\Catalog.ps1', 'Private\Graph.ps1', 'Private\Assessment.ps1', 'Private\Reporting.ps1', 'Public.ps1')) {
    . (Join-Path $PSScriptRoot $file)
}

Export-ModuleMember -Function Get-EntraXrayPlan, Get-EntraXrayCheck, Invoke-EntraXray
