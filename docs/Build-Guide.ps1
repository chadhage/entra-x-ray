#requires -Version 7.2
[CmdletBinding()]
param(
    [ValidateScript({
        if ([System.IO.Path]::GetExtension($_) -ine '.html') { throw 'OutputPath must name an .html file.' }
        $true
    })]
    [string]$OutputPath = (Join-Path $PSScriptRoot 'index.html'),
    [string]$GuidePath = (Join-Path $PSScriptRoot 'guide.md'),
    [string]$TemplatePath = (Join-Path $PSScriptRoot 'site.template.html')
)

$ErrorActionPreference = 'Stop'
$repository = Split-Path $PSScriptRoot -Parent
$module = Import-Module (Join-Path $repository 'src\EntraXray.psd1') -PassThru -ErrorAction Stop

function ConvertTo-GuideText {
    param([AllowNull()]$Value)
    [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function New-GuideCheckEntry {
    param($Check)
    $id = ConvertTo-GuideText $Check.Id
    $search = ConvertTo-GuideText (@(
        $Check.Id, $Check.Category, $Check.Title, $Check.Severity, $Check.AdverseStatus,
        ($Check.Sources -join ' '), $Check.Remediation
    ) -join ' ')
    $links = @($Check.Sources | ForEach-Object {
        $sourceId = ConvertTo-GuideText $_
        "<a href=`"#source-$sourceId`"><code>$sourceId</code></a>"
    }) -join ' '
    $references = @($Check.References | ForEach-Object {
        "<a href=`"$(ConvertTo-GuideText $_)`">Microsoft documentation</a>"
    }) -join ' / '
    @"
<details class="reference-item check-entry" id="check-$id" data-search="$search">
  <summary><span class="item-id">$id</span>$(ConvertTo-GuideText $Check.Title)<span class="item-meta">$(ConvertTo-GuideText $Check.Category) / $(ConvertTo-GuideText $Check.Severity) priority</span></summary>
  <div class="entry-body"><dl>
    <dt>Observed-condition outcome</dt><dd>$(ConvertTo-GuideText $Check.AdverseStatus)</dd>
    <dt>Prerequisites</dt><dd class="source-links">$links</dd>
    <dt>Investigation</dt><dd>$(ConvertTo-GuideText $Check.Remediation)</dd>
    <dt>Reference</dt><dd>$references</dd>
  </dl></div>
</details>
"@
}

function New-GuideSourceEntry {
    param($Source)
    $id = ConvertTo-GuideText $Source.Id
    $search = ConvertTo-GuideText (@(
        $Source.Id, $Source.Method, $Source.Path, $Source.ApiVersion, $Source.Parent,
        ($Source.Permissions -join ' '), $Source.Scope, $Source.Licensing
    ) -join ' ')
    $parent = 'None (direct source)'
    if ($Source.Parent) {
        $parentId = ConvertTo-GuideText $Source.Parent
        $parent = "<a href=`"#source-$parentId`"><code>$parentId</code></a> / filter: <code>$(ConvertTo-GuideText $Source.ParentFilter)</code>"
    }
    @"
<details class="reference-item source-entry" id="source-$id" data-search="$search">
  <summary><span class="item-id">$id</span><span class="item-meta">$(ConvertTo-GuideText $Source.ApiVersion) / $(ConvertTo-GuideText $Source.Method) / $(ConvertTo-GuideText $Source.Shape)</span></summary>
  <div class="entry-body"><dl>
    <dt>Request template</dt><dd><code>$(ConvertTo-GuideText $Source.Method) $(ConvertTo-GuideText $Source.Path)</code></dd>
    <dt>Permissions</dt><dd><code>$(ConvertTo-GuideText ($Source.Permissions -join ', '))</code></dd>
    <dt>Parent</dt><dd>$parent</dd>
    <dt>Scope</dt><dd>$(ConvertTo-GuideText $Source.Scope)</dd>
    <dt>Availability</dt><dd>$(ConvertTo-GuideText $Source.Licensing)</dd>
    <dt>Reference</dt><dd><a href="$(ConvertTo-GuideText $Source.Reference)">Microsoft API documentation</a></dd>
  </dl></div>
</details>
"@
}

$sourceText = Get-Content -LiteralPath $GuidePath -Raw -ErrorAction Stop
$guideHtml = (ConvertFrom-Markdown -InputObject $sourceText -ErrorAction Stop).Html
$headings = [regex]::Matches($guideHtml, '<h2 id="(?<id>[^"]+)">(?<name>.*?)</h2>')
if ($headings.Count -eq 0) { throw [System.IO.InvalidDataException]::new('The guide must contain level-two section headings.') }
$navigation = @($headings | ForEach-Object {
    $id = ConvertTo-GuideText $_.Groups['id'].Value
    $name = ConvertTo-GuideText ([System.Net.WebUtility]::HtmlDecode(($_.Groups['name'].Value -replace '<[^>]+>', '')))
    "<a href=`"#$id`">$name</a>"
}) -join "`n"

$checks = @(Get-EntraXrayCheck)
$sources = @((Get-EntraXrayPlan -IncludeBeta).Sources)
$command = Get-Command Invoke-EntraXray
$parameterAst = (Get-Command (Join-Path $repository 'Invoke-EntraXray.ps1')).ScriptBlock.Ast.ParamBlock.Parameters
$parameterRows = @(foreach ($name in @('LogDays', 'MaxPagesPerSource', 'MaxRequests', 'MaxRetries')) {
    $declaration = $parameterAst | Where-Object { $_.Name.VariablePath.UserPath -eq $name }
    $default = $declaration.DefaultValue.SafeGetValue()
    $range = $command.Parameters[$name].Attributes |
        Where-Object { $_ -is [System.Management.Automation.ValidateRangeAttribute] }
    "<tr data-parameter=`"$name`"><td><code>-$name</code></td><td><code>$default</code></td><td>$(ConvertTo-GuideText $range.MinRange) to $(ConvertTo-GuideText $range.MaxRange)</td></tr>"
}) -join "`n"
$parameterTable = @"
<table><thead><tr><th>Parameter</th><th>Default</th><th>Accepted range</th></tr></thead><tbody>
$parameterRows
</tbody></table>
"@
$cloudRows = @(foreach ($environment in @('Global', 'USGov', 'USGovDoD', 'China')) {
    $cloud = Get-EntraXrayPlan -Environment $environment
    "<tr><td><code>$environment</code></td><td><code>$(ConvertTo-GuideText ([uri]$cloud.GraphBaseUri).Host)</code></td></tr>"
}) -join "`n"
$cloudTable = @"
<table><thead><tr><th>Environment</th><th>Graph host</th></tr></thead><tbody>
$cloudRows
</tbody></table>
"@
$configuration = Get-Content -LiteralPath (Join-Path $repository 'config.example.json') -Raw -ErrorAction Stop
$guideSubstitutions = [ordered]@{
    '<!-- CLOUD_REFERENCE -->' = $cloudTable
    '<!-- COLLECTION_PARAMETERS -->' = $parameterTable
    '<!-- CONFIGURATION_EXAMPLE -->' = "<pre><code class=`"language-json`">$(ConvertTo-GuideText $configuration.TrimEnd())</code></pre>"
}
foreach ($marker in $guideSubstitutions.Keys) {
    if (-not $guideHtml.Contains($marker)) { throw [System.IO.InvalidDataException]::new("Missing guide content marker: $marker") }
    $guideHtml = $guideHtml.Replace($marker, $guideSubstitutions[$marker])
}

$template = Get-Content -LiteralPath $TemplatePath -Raw -ErrorAction Stop
$substitutions = [ordered]@{
    '@@VERSION@@' = (ConvertTo-GuideText $module.Version.ToString())
    '@@NAV_LINKS@@' = $navigation
    '@@GUIDE_HTML@@' = $guideHtml
    '@@CHECK_COUNT@@' = [string]$checks.Count
    '@@STABLE_COUNT@@' = [string]@($sources | Where-Object ApiVersion -EQ 'v1.0').Count
    '@@BETA_COUNT@@' = [string]@($sources | Where-Object ApiVersion -EQ 'beta').Count
    '@@CHECK_ENTRIES@@' = (@($checks | ForEach-Object { New-GuideCheckEntry $_ }) -join "`n")
    '@@SOURCE_ENTRIES@@' = (@($sources | ForEach-Object { New-GuideSourceEntry $_ }) -join "`n")
}
foreach ($token in $substitutions.Keys) {
    if (-not $template.Contains($token)) { throw [System.IO.InvalidDataException]::new("Missing template token: $token") }
    $template = $template.Replace($token, $substitutions[$token])
}
if ($template -match '@@[A-Z_]+@@') { throw [System.IO.InvalidDataException]::new('An unresolved template token remains in the generated guide.') }
$fullPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
$directory = Split-Path $fullPath -Parent
if (-not (Test-Path -LiteralPath $directory -PathType Container)) {
    New-Item -Path $directory -ItemType Directory -ErrorAction Stop | Out-Null
}
Set-Content -LiteralPath $fullPath -Value ($template -replace '\r\n', "`n") -Encoding utf8 -NoNewline -ErrorAction Stop
[pscustomobject]@{
    OutputPath = $fullPath
    CheckCount = $checks.Count
    SourceCount = $sources.Count
    ModuleVersion = $module.Version.ToString()
}
