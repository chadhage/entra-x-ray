#requires -Version 7.2
[CmdletBinding()]
param([string]$ReportDirectory = (Join-Path $PSScriptRoot 'TestResults'))

Import-Module Pester -MinimumVersion 5.7.1 -ErrorAction Stop
New-Item -Path $ReportDirectory -ItemType Directory -Force -ErrorAction Stop | Out-Null
$configuration = New-PesterConfiguration
$configuration.Run.Path = Join-Path $PSScriptRoot 'tests'
$configuration.Run.PassThru = $true
$configuration.Output.Verbosity = 'Normal'
$configuration.CodeCoverage.Enabled = $true
$configuration.CodeCoverage.Path = @(
    Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'src') -Recurse -File |
        Where-Object Extension -In @('.ps1', '.psm1') | ForEach-Object FullName
    Join-Path $PSScriptRoot 'Invoke-EntraXray.ps1'
    Join-Path $PSScriptRoot 'docs\Build-Guide.ps1'
)
$configuration.CodeCoverage.CoveragePercentTarget = 100
$configuration.CodeCoverage.OutputFormat = 'JaCoCo'
$configuration.CodeCoverage.OutputPath = Join-Path $ReportDirectory 'coverage.xml'
$configuration.TestResult.Enabled = $true
$configuration.TestResult.OutputPath = Join-Path $ReportDirectory 'tests.xml'
$result = Invoke-Pester -Configuration $configuration
[pscustomobject]@{
    Total = $result.TotalCount; Passed = $result.PassedCount; Failed = $result.FailedCount
    Skipped = $result.SkippedCount; CoveragePercent = $result.CodeCoverage.CoveragePercent
    CommandsAnalyzed = $result.CodeCoverage.CommandsAnalyzedCount
    CommandsExecuted = $result.CodeCoverage.CommandsExecutedCount
    Reports = $ReportDirectory
}
if ($result.Result -ne 'Passed' -or $result.FailedContainersCount -gt 0) { throw 'The test suite failed. See the test report for details.' }
if ($result.SkippedCount -gt 0 -or $result.NotRunCount -gt 0) { throw 'The test suite contains skipped or unexecuted tests.' }
if ($result.CodeCoverage.CoveragePercent -lt 100) {
    $result.CodeCoverage.CommandsMissed | Select-Object File, Line, Command | Format-Table -Wrap
    throw 'Production command coverage is below the required 100 percent.'
}
