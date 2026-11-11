function Read-XrayJsonObject {
    param([Parameter(Mandatory)][string]$Path)
    $value = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop | ConvertFrom-Json -AsHashtable -NoEnumerate -Depth 100 -ErrorAction Stop
    if ($value -isnot [System.Collections.IDictionary]) { throw [System.IO.InvalidDataException]::new('The JSON document must contain an object, not null, an array, or a scalar.') }
    $value
}

function Import-XrayEvidence {
    param([Parameter(Mandatory)][string]$Path)
    $evidence = Read-XrayJsonObject $Path
    Assert-XrayFields $evidence @('SchemaVersion', 'ToolVersion', 'TenantId', 'Environment', 'StartedAtUtc', 'CompletedAtUtc', 'Settings', 'LogWindow', 'Sources')
    if ($evidence.SchemaVersion -ne '1.0') { throw [System.IO.InvalidDataException]::new('Unsupported evidence SchemaVersion. Expected 1.0.') }
    $tenant = [guid]::Empty
    if (-not [guid]::TryParse([string]$evidence.TenantId, [ref]$tenant) -or $tenant -eq [guid]::Empty) { throw [System.IO.InvalidDataException]::new('Evidence TenantId must be a nonempty tenant GUID.') }
    if ($evidence.Environment -notin @('Global', 'USGov', 'USGovDoD', 'China')) { throw [System.IO.InvalidDataException]::new('Unsupported evidence Environment.') }
    $started = ConvertTo-XrayDate $evidence.StartedAtUtc
    $completed = ConvertTo-XrayDate $evidence.CompletedAtUtc
    if ($null -eq $started -or $null -eq $completed -or $completed -lt $started) { throw [System.IO.InvalidDataException]::new('Evidence start/completion time interval is invalid.') }
    Assert-XrayFields $evidence.LogWindow @('StartUtc', 'EndUtc')
    $logStart = ConvertTo-XrayDate $evidence.LogWindow.StartUtc
    $logEnd = ConvertTo-XrayDate $evidence.LogWindow.EndUtc
    if ($null -eq $logStart -or $null -eq $logEnd -or $logStart -gt $logEnd -or $logEnd -gt $completed) { throw [System.IO.InvalidDataException]::new('Evidence log time interval is invalid.') }
    if ($evidence.Settings -isnot [System.Collections.IDictionary]) { throw [System.IO.InvalidDataException]::new('Evidence Settings must be an object.') }
    $evidence.Settings = New-XraySettings $evidence.Settings
    if ($evidence.Sources -isnot [System.Collections.IDictionary] -or $evidence.Sources.Count -eq 0) { throw [System.IO.InvalidDataException]::new('Evidence Sources must be a nonempty object.') }
    $known = @((Get-XraySourceCatalog) | ForEach-Object Id)
    foreach ($id in $evidence.Sources.Keys) {
        if ($id -notin $known) { throw [System.IO.InvalidDataException]::new("Unknown evidence source '$id'; a compatible toolkit version is required.") }
        $source = $evidence.Sources[$id]
        Assert-XrayFields $source @('Id', 'State', 'Items', 'ItemCount', 'Pages', 'Errors', 'Requested', 'ApiVersion', 'Uri', 'CollectedAtUtc', 'Scope')
        if ($source.Id -ne $id) { throw [System.IO.InvalidDataException]::new("Source '$id' has an inconsistent Id.") }
        if ($source.State -notin @('Complete', 'Partial', 'Unavailable', 'Skipped')) { throw [System.IO.InvalidDataException]::new("Source '$id' has an invalid State.") }
        if ($source.Items -isnot [System.Collections.IList]) { throw [System.IO.InvalidDataException]::new("Source '$id' Items must be an array.") }
        foreach ($item in $source.Items) {
            if ($item -isnot [System.Collections.IDictionary]) { throw [System.IO.InvalidDataException]::new("Source '$id' Items must contain objects.") }
        }
        if (($source.ItemCount -isnot [int] -and $source.ItemCount -isnot [long]) -or $source.ItemCount -ne $source.Items.Count) { throw [System.IO.InvalidDataException]::new("Source '$id' ItemCount does not match Items.") }
        if (($source.Pages -isnot [int] -and $source.Pages -isnot [long]) -or $source.Pages -lt 0) { throw [System.IO.InvalidDataException]::new("Source '$id' Pages is invalid.") }
        if ($source.Errors -isnot [System.Collections.IList]) { throw [System.IO.InvalidDataException]::new("Source '$id' Errors must be an array.") }
        if ($source.State -eq 'Complete' -and $source.Errors.Count -gt 0) { throw [System.IO.InvalidDataException]::new("Source '$id' is marked Complete but contains collection errors.") }
        if ($source.Requested -isnot [bool]) { throw [System.IO.InvalidDataException]::new("Source '$id' Requested must be a Boolean.") }
        if (-not $source.Requested -and $source.State -ne 'Skipped') { throw [System.IO.InvalidDataException]::new("Source '$id' has inconsistent Requested/State values; an unrequested source must be Skipped.") }
        if ($source.ApiVersion -notin @('v1.0', 'beta')) { throw [System.IO.InvalidDataException]::new("Source '$id' ApiVersion is invalid.") }
        if ($null -eq (ConvertTo-XrayDate $source.CollectedAtUtc)) { throw [System.IO.InvalidDataException]::new("Source '$id' collection timestamp is missing.") }
    }
    $evidence
}

function Get-XrayCoverage {
    param($Evidence)
    $counts = [ordered]@{
        Declared = $Evidence.Sources.Count; Requested = 0; Complete = 0; Partial = 0
        Unavailable = 0; Skipped = 0; NotRequested = 0; PercentComplete = 0.0; IsComplete = $false
    }
    foreach ($source in $Evidence.Sources.Values) {
        if (-not $source.Requested) { $counts.NotRequested++; continue }
        $counts.Requested++
        $counts[$source.State]++
    }
    if ($counts.Requested -gt 0) {
        $counts.PercentComplete = [Math]::Round(100.0 * $counts.Complete / $counts.Requested, 2)
        $counts.IsComplete = $counts.Complete -eq $counts.Requested
    }
    $counts
}

function Assert-XrayOutputDirectory {
    param([string]$OutputDirectory, [switch]$AllowEvidence)
    $fullPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputDirectory)
    if (Test-Path -LiteralPath $fullPath -PathType Leaf) { throw [System.IO.IOException]::new('OutputDirectory points to a file, not a directory.') }
    foreach ($name in @('evidence.json', 'findings.json', 'findings.csv', 'report.md', 'manifest.json')) {
        if ($AllowEvidence -and $name -eq 'evidence.json') { continue }
        if (Test-Path -LiteralPath (Join-Path $fullPath $name)) { throw [System.IO.IOException]::new("Output file '$name' already exists. Choose a new output directory; existing deliverables are never overwritten.") }
    }
    if (-not (Test-Path -LiteralPath $fullPath -PathType Container)) { New-Item -Path $fullPath -ItemType Directory -ErrorAction Stop | Out-Null }
    $fullPath
}

function Write-XrayFile {
    param([string]$Path, [string]$Content)
    if (Test-Path -LiteralPath $Path) { throw [System.IO.IOException]::new("Output file already exists: $Path") }
    $temporary = "$Path.$([guid]::NewGuid().ToString('N')).tmp"
    try {
        Set-Content -LiteralPath $temporary -Value $Content -Encoding utf8 -NoNewline -ErrorAction Stop
        Move-Item -LiteralPath $temporary -Destination $Path -ErrorAction Stop
    }
    finally {
        if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -ErrorAction Stop }
    }
}

function Export-XrayReport {
    param(
        [Parameter(Mandatory)]$Evidence, [AllowEmptyCollection()][object[]]$Findings,
        [Parameter(Mandatory)]$Settings, [Parameter(Mandatory)][string]$OutputDirectory,
        [switch]$EvidenceAlreadyWritten
    )
    $out = Assert-XrayOutputDirectory $OutputDirectory -AllowEvidence:$EvidenceAlreadyWritten
    $evidencePath = Join-Path $out 'evidence.json'
    if (-not $EvidenceAlreadyWritten) { Write-XrayFile $evidencePath ($Evidence | ConvertTo-Json -Depth 100) }
    $coverage = Get-XrayCoverage $Evidence
    $statusCounts = [ordered]@{ Pass = 0; Fail = 0; Review = 0; Unknown = 0; NotApplicable = 0 }
    foreach ($finding in $Findings) { $statusCounts[$finding.Status]++ }
    $assessment = [ordered]@{
        SchemaVersion = '1.0'; ToolVersion = '1.0.0'; TenantId = $Evidence.TenantId; Environment = $Evidence.Environment
        AssessmentAsOfUtc = $Evidence.CompletedAtUtc; Settings = $Settings; Coverage = $coverage
        Counts = $statusCounts; Findings = @($Findings)
        EvidenceSha256 = (Get-FileHash -LiteralPath $evidencePath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
        Assurance = 'Read-only configuration and retained-telemetry assessment, not a certification, penetration test, or guarantee that a tenant is secure.'
    }
    Write-XrayFile (Join-Path $out 'findings.json') ($assessment | ConvertTo-Json -Depth 100)
    $csvRows = @(foreach ($finding in $Findings) {
        $entities = @($finding.Entities)
        if ($entities.Count -eq 0) { $entities = @(@{ Id = ''; DisplayName = ''; Detail = ($finding.Limitations -join '; ') }) }
        foreach ($entity in $entities) {
            [pscustomobject][ordered]@{
                CheckId = (ConvertTo-XrayCsvText $finding.Id); Status = $finding.Status; Severity = $finding.Severity
                Category = $finding.Category; Title = (ConvertTo-XrayCsvText $finding.Title)
                EntityId = (ConvertTo-XrayCsvText $entity.Id); DisplayName = (ConvertTo-XrayCsvText $entity.DisplayName)
                Detail = (ConvertTo-XrayCsvText $entity.Detail); Sources = ($finding.Sources -join ';')
            }
        }
    })
    Write-XrayFile (Join-Path $out 'findings.csv') (($csvRows | ConvertTo-Csv -NoTypeInformation) -join [Environment]::NewLine)
    $md = [System.Collections.Generic.List[string]]::new()
    $md.Add('# Microsoft Entra ID X-Ray')
    $md.Add('')
    $md.Add("Tenant: $(ConvertTo-XrayMarkdownText $Evidence.TenantId) | Cloud: $(ConvertTo-XrayMarkdownText $Evidence.Environment)")
    $md.Add("Assessment as of UTC: $(ConvertTo-XrayMarkdownText $Evidence.CompletedAtUtc)")
    $md.Add('')
    $md.Add('**This is not a certification, proof of effective policy coverage, penetration test, or guarantee of security.** All assessment Graph requests are GET. OAuth authentication can prompt for operator consent and create normal audit/sign-in activity. Outputs contain sensitive tenant data; restrict access and retention.')
    $md.Add('')
    $md.Add('## Interpretation')
    $md.Add('- **Pass**: this narrowly stated test passed within its collected scope, not that the tenant is safe.')
    $md.Add('- **Fail**: a documented adverse condition was observed; not automatically an exploitable vulnerability.')
    $md.Add('- **Review**: business context, intent, or external evidence is required. Do not remediate automatically.')
    $md.Add('- **Unknown**: missing/incomplete evidence, permissions, service availability, or malformed fields prevent a defensible result.')
    $md.Add('- **NotApplicable**: no applicable objects existed in the complete collected scope.')
    $md.Add('')
    $md.Add("Results: Pass=$($statusCounts.Pass); Fail=$($statusCounts.Fail); Review=$($statusCounts.Review); Unknown=$($statusCounts.Unknown); NotApplicable=$($statusCounts.NotApplicable).")
    $md.Add('')
    $md.Add('## Collection coverage')
    $md.Add("Requested sources complete: $($coverage.Complete)/$($coverage.Requested) ($($coverage.PercentComplete)%); partial=$($coverage.Partial); unavailable=$($coverage.Unavailable); requested-but-skipped=$($coverage.Skipped); deliberately not requested=$($coverage.NotRequested). This denominator is the requested catalog, not every possible tenant surface.")
    $md.Add("Requested log window (UTC): $(ConvertTo-XrayMarkdownText $Evidence.LogWindow.StartUtc) through $(ConvertTo-XrayMarkdownText $Evidence.LogWindow.EndUtc). Empty results do not prove that the entire interval was retained or accessible.")
    $md.Add('')
    $md.Add('| Source | State | Requested | Items | Pages | API | Scope / errors |')
    $md.Add('|---|---|---|---:|---:|---|---|')
    foreach ($id in $Evidence.Sources.Keys) {
        $source = $Evidence.Sources[$id]
        $notes = $source.Scope
        if ($source.Errors.Count -gt 0) { $notes += '; ' + (($source.Errors | ForEach-Object { "$($_.Code): $($_.Message)" }) -join '; ') }
        $md.Add("| $(ConvertTo-XrayMarkdownText $id) | $($source.State) | $($source.Requested) | $($source.ItemCount) | $($source.Pages) | $(ConvertTo-XrayMarkdownText $source.ApiVersion) | $(ConvertTo-XrayMarkdownText $notes) |")
    }
    $md.Add('')
    $md.Add('## Results index')
    $md.Add('| Check | Status | Severity / priority | Test | Evidence rows |')
    $md.Add('|---|---|---|---|---:|')
    foreach ($finding in $Findings) {
        $md.Add("| $($finding.Id) | $($finding.Status) | $($finding.Severity) | $(ConvertTo-XrayMarkdownText $finding.Title) | $($finding.AffectedCount) |")
    }
    $md.Add('')
    $md.Add('## Detailed evidence and recommendations')
    foreach ($finding in $Findings) {
        $md.Add('')
        $md.Add("### $($finding.Id): $(ConvertTo-XrayMarkdownText $finding.Title)")
        $md.Add("**$($finding.Status)** | $($finding.Severity) | Confidence: $($finding.Confidence)")
        $md.Add((ConvertTo-XrayMarkdownText $finding.Summary))
        $md.Add("Sources: $($finding.Sources -join ', ').")
        foreach ($limitation in $finding.Limitations) { $md.Add("Limitation: $(ConvertTo-XrayMarkdownText $limitation)") }
        if ($finding.Entities.Count -gt 0) {
            $md.Add('')
            $md.Add('| Entity ID | Name | Observed evidence |')
            $md.Add('|---|---|---|')
            foreach ($entity in $finding.Entities) {
                $md.Add("| $(ConvertTo-XrayMarkdownText $entity.Id) | $(ConvertTo-XrayMarkdownText $entity.DisplayName) | $(ConvertTo-XrayMarkdownText $entity.Detail) |")
            }
        }
        $md.Add('')
        $md.Add("**Recommended investigation:** $(ConvertTo-XrayMarkdownText $finding.Remediation)")
        foreach ($reference in $finding.References) { $md.Add("- [Microsoft documentation]($reference)") }
    }
    $md.Add('')
    $md.Add('## Mandatory blind spots and follow-up')
    $md.Add('- Configuration snapshots are not transactional. Changes during collection, service eventual consistency, partial visibility, and API limitations can affect joins.')
    $md.Add('- Conditional Access What If, policy combinations, authentication/session context, external federation signing/MFA assurance, emergency access usability, and incident legitimacy require independent validation.')
    $md.Add('- Retention, log export, alerting effectiveness, on-premises AD/AD FS, endpoint integrity, external IdPs and CI/CD systems, Azure subscriptions, and Microsoft 365 workload security are not comprehensively tested here.')
    $md.Add('- Some inventories intentionally have no automated verdict: deleted objects, administrative units, consent condition sets, token/app-management policies, access-review decisions, entitlement assignments, terms of use, lifecycle run history, and preview recommendations. Review the raw evidence.')
    $md.Add('- Preview APIs are opt-in, can change without notice, and are not supported for production dependencies. Disabled-user registration rows are not available. Null activity is not a clean result.')
    $md.Add('- No sign-in attempt, password test, consent grant, secret-value retrieval, recovery-key retrieval, remediation, or tenant mutation is performed.')
    $md.Add('')
    $md.Add('## Artifacts and integrity')
    $md.Add('[Raw evidence](./evidence.json) | [Structured findings](./findings.json) | [CSV evidence rows](./findings.csv) | [SHA-256 manifest](./manifest.json)')
    $md.Add('The manifest detects accidental changes when compared with a trusted copy; it is not a signature or proof of authenticity. All evidence rows are retained; reports do not silently truncate entities.')
    Write-XrayFile (Join-Path $out 'report.md') ($md -join [Environment]::NewLine)
    $files = @(foreach ($name in @('evidence.json', 'findings.json', 'findings.csv', 'report.md')) {
        [ordered]@{ Name = $name; Sha256 = (Get-FileHash -LiteralPath (Join-Path $out $name) -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant() }
    })
    Write-XrayFile (Join-Path $out 'manifest.json') ([ordered]@{
        SchemaVersion = '1.0'; TenantId = $Evidence.TenantId; AssessmentAsOfUtc = $Evidence.CompletedAtUtc
        Algorithm = 'SHA256'; Files = $files
    } | ConvertTo-Json -Depth 10)
    $incomplete = -not $coverage.IsComplete -or $statusCounts.Unknown -gt 0
    $exitCode = 0
    if ($incomplete) { $exitCode = 2 }
    elseif ($statusCounts.Fail -gt 0) { $exitCode = 3 }
    [pscustomobject]@{
        TenantId = $Evidence.TenantId; OutputDirectory = $out; AssessmentAsOfUtc = $Evidence.CompletedAtUtc
        CheckCount = $Findings.Count; PassCount = $statusCounts.Pass; FailCount = $statusCounts.Fail
        ReviewCount = $statusCounts.Review; UnknownCount = $statusCounts.Unknown
        NotApplicableCount = $statusCounts.NotApplicable; Incomplete = $incomplete
        RecommendedExitCode = $exitCode; CollectionCoverage = $coverage
    }
}
