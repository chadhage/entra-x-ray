BeforeAll {
    Import-Module "$PSScriptRoot\..\src\EntraXray.psd1"
    $script:GuideRoot = Join-Path $PSScriptRoot '..\docs'
    $script:GuideBuilder = Join-Path $script:GuideRoot 'Build-Guide.ps1'
    $script:GuideSource = Join-Path $script:GuideRoot 'guide.md'
    $script:GuideTemplate = Join-Path $script:GuideRoot 'site.template.html'
    $script:GraphModulesBeforeGuide = @(Get-Module Microsoft.Graph.Authentication | ForEach-Object Name)
}

Describe 'Engineering guide build contract' {
    BeforeAll {
        $script:GuideOutput = Join-Path $TestDrive 'site\index.html'
        $script:GuideResult = & $script:GuideBuilder -OutputPath $script:GuideOutput
        $script:GuideHtml = Get-Content -LiteralPath $script:GuideOutput -Raw
    }

    It 'builds a self-contained HTML page without loading Graph authentication' {
        $script:GuideResult.CheckCount | Should -Be @(Get-EntraXrayCheck).Count
        $script:GuideResult.SourceCount | Should -Be (Get-EntraXrayPlan -IncludeBeta).Sources.Count
        $script:GuideResult.OutputPath | Should -Be $script:GuideOutput
        $script:GuideHtml | Should -Match '(?i)^<!doctype html>'
        $script:GuideHtml | Should -Not -Match '(?i)<script[^>]+\bsrc=|<link[^>]+rel="stylesheet"|@import|<iframe|<form\b'
        $script:GuideHtml | Should -Match "connect-src 'none'"
        $script:GuideHtml | Should -Not -Match '@@[A-Z_]+@@'
        @(Get-Module Microsoft.Graph.Authentication | ForEach-Object Name).Count | Should -Be $script:GraphModulesBeforeGuide.Count
    }

    It 'includes every check and source once with metadata-derived detail links' {
        $sourceIds = @((Get-EntraXrayPlan -IncludeBeta).Sources.Id)
        foreach ($check in Get-EntraXrayCheck) {
            [regex]::Matches($script:GuideHtml, 'id="check-' + [regex]::Escape($check.Id) + '"').Count | Should -Be 1
            foreach ($sourceId in $check.Sources) {
                $script:GuideHtml | Should -Match ('href="#source-' + [regex]::Escape($sourceId) + '"')
            }
        }
        foreach ($id in $sourceIds) {
            [regex]::Matches($script:GuideHtml, 'id="source-' + [regex]::Escape($id) + '"').Count | Should -Be 1
        }
    }

    It 'provides working internal anchors and unique element IDs' {
        $ids = @([regex]::Matches($script:GuideHtml, '\bid="([^"]+)"') | ForEach-Object { $_.Groups[1].Value })
        @($ids | Select-Object -Unique).Count | Should -Be $ids.Count
        $links = @([regex]::Matches($script:GuideHtml, 'href="#([^"]+)"') | ForEach-Object { $_.Groups[1].Value })
        foreach ($id in $links) { $id | Should -BeIn $ids }
    }

    It 'covers execution, permissions, interpretation, recovery, and maintenance as procedures' {
        foreach ($id in @(
            'scope-and-data-handling', 'prepare-powershell', 'inspect-permissions-and-source-selection',
            'run-an-assessment', 'choose-authentication', 'select-a-cloud', 'set-limits-and-thresholds',
            'read-the-output-files', 'interpret-and-triage-findings', 'replay-evidence-offline',
            'troubleshoot-a-run', 'automate-exit-handling', 'validate-the-toolkit', 'maintain-this-guide'
        )) {
            $script:GuideHtml | Should -Match ('id="' + $id + '"')
            $script:GuideHtml | Should -Match ('href="#' + $id + '"')
        }
        $script:GuideHtml | Should -Match 'materialized in memory'
        $script:GuideHtml | Should -Match 'accepting a consent prompt'
        $script:GuideHtml | Should -Match 'not proof of effective'
        $script:GuideHtml | Should -Match 'Unknown'
        $script:GuideHtml | Should -Match 'Workload ID Premium'
    }

    It 'uses the required theme, keyboard affordances, and progressive enhancement' {
        $script:GuideHtml | Should -Match 'clawpilotTheme'
        $script:GuideHtml | Should -Match 'prefers-color-scheme: dark'
        $script:GuideHtml | Should -Match '--cp-bg: #f7f4ef'
        $script:GuideHtml | Should -Match 'html\[data-theme="dark"\]'
        $script:GuideHtml | Should -Match '"Segoe UI", Aptos, Calibri'
        $script:GuideHtml | Should -Match 'Consolas, "Courier New", Courier'
        $script:GuideHtml | Should -Match 'class="skip-link"'
        $script:GuideHtml | Should -Match 'aria-live="polite"'
        $script:GuideHtml | Should -Match '<noscript>'
        $script:GuideHtml | Should -Match '@media print'
        $script:GuideHtml | Should -Not -Match '<script[^>]*>[\s\S]*?<script[^>]*\bsrc='
    }

    It 'uses factual guide copy rather than promotional claims' {
        $source = Get-Content -LiteralPath $script:GuideSource -Raw
        $template = Get-Content -LiteralPath $script:GuideTemplate -Raw
        ($source + $template) | Should -Not -Match '(?i)\b(revolutionary|world.class|best.in.class|game.chang\w*|effortless|seamless|supercharg\w*|unmatched|ultimate|enterprise.grade|cutting.edge|unlock)\b'
        $source | Should -Not -Match '(?i)100% (secure|safe|tenant coverage)|every (threat|vulnerability)|leave no stone'
    }

    It 'keeps documented invocation examples parseable and within the actual CLI parameter contract' {
        $source = Get-Content -LiteralPath $script:GuideSource -Raw
        $examples = [regex]::Matches($source, '(?s)```powershell\r?\n(.*?)```')
        $examples.Count | Should -BeGreaterThan 10
        $command = Get-Command Invoke-EntraXray
        foreach ($example in $examples) {
            $tokens = $null
            $errors = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseInput($example.Groups[1].Value, [ref]$tokens, [ref]$errors)
            $errors.Count | Should -Be 0
            $invocations = $ast.FindAll({
                param($node)
                $node -is [System.Management.Automation.Language.CommandAst] -and
                    $node.GetCommandName() -match '(^|[\\])Invoke-EntraXray(\.ps1)?$'
            }, $true)
            foreach ($invocation in $invocations) {
                foreach ($parameter in $invocation.CommandElements | Where-Object { $_ -is [System.Management.Automation.Language.CommandParameterAst] }) {
                    $command.Parameters.ContainsKey($parameter.ParameterName) | Should -BeTrue
                }
            }
        }
    }

    It 'renders the current parameter defaults and configuration example' {
        $script:GuideHtml | Should -Match 'data-parameter="LogDays"[^>]*>[\s\S]*?<code>30</code>'
        $script:GuideHtml | Should -Match 'data-parameter="MaxRequests"[^>]*>[\s\S]*?<code>100000</code>'
        $script:GuideHtml | Should -Match 'data-parameter="MaxPagesPerSource"[^>]*>[\s\S]*?<code>10000</code>'
        foreach ($key in (Get-Content "$PSScriptRoot\..\config.example.json" -Raw | ConvertFrom-Json -AsHashtable).Keys) {
            $script:GuideHtml | Should -Match ([regex]::Escape($key))
        }
    }

    It 'rebuilds deterministically from the same source files' {
        $second = Join-Path $TestDrive 'second.html'
        $null = & $script:GuideBuilder -OutputPath $second
        (Get-FileHash $second).Hash | Should -Be (Get-FileHash $script:GuideOutput).Hash
    }

    It 'keeps the checked-in site synchronized with the source files and runtime catalog' {
        (Get-FileHash (Join-Path $script:GuideRoot 'index.html')).Hash |
            Should -Be (Get-FileHash $script:GuideOutput).Hash
    }

    It 'targets the documentation entry page by default without requiring output arguments' {
        Mock Set-Content {}
        $result = & $script:GuideBuilder
        $expected = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath((Join-Path $script:GuideRoot 'index.html'))
        $result.OutputPath | Should -Be $expected
        Should -Invoke Set-Content -Times 1 -Exactly -ParameterFilter { $LiteralPath -eq $expected }
    }

    It 'escapes metadata used in text and search attributes' {
        . $script:GuideBuilder -OutputPath (Join-Path $TestDrive 'escaping.html') | Out-Null
        $check = @{
            Id = 'TEST-001'; Category = 'Test'; Severity = 'Low'; AdverseStatus = 'Review'
            Title = '<img src=x onerror=alert(1)> "quoted"'
            Sources = @('users'); Remediation = 'Literal <script> text'
            References = @('https://learn.microsoft.com/en-us/graph/overview')
        }
        $html = New-GuideCheckEntry $check
        $html | Should -Not -Match '<img|<script>'
        $html | Should -Match '&lt;img'
        $html | Should -Match '&quot;quoted&quot;'
        (ConvertTo-GuideText $null) | Should -Be ''
    }
}

Describe 'Guide build failures' {
    It 'rejects a non-HTML output path without replacing that file' {
        $path = Join-Path $TestDrive 'keep.txt'
        Set-Content $path 'keep'
        { & $script:GuideBuilder -OutputPath $path } | Should -Throw '*html*'
        Get-Content $path | Should -Be 'keep'
    }

    It 'rejects a source document without section headings' {
        $path = Join-Path $TestDrive 'no-sections.md'
        Set-Content $path 'Text without headings.'
        { & $script:GuideBuilder -GuidePath $path -OutputPath (Join-Path $TestDrive 'invalid-source.html') } |
            Should -Throw '*section headings*'
    }

    It 'rejects an incomplete template instead of leaving unresolved substitutions' {
        $path = Join-Path $TestDrive 'invalid.template.html'
        Set-Content $path '<!doctype html><html></html>'
        { & $script:GuideBuilder -TemplatePath $path -OutputPath (Join-Path $TestDrive 'invalid-template.html') } |
            Should -Throw '*template token*'
    }

    It 'surfaces an unavailable source file explicitly' {
        { & $script:GuideBuilder -GuidePath (Join-Path $TestDrive 'missing.md') -OutputPath (Join-Path $TestDrive 'missing.html') } |
            Should -Throw
    }

    It 'rejects a document that omits generated reference markers' {
        $path = Join-Path $TestDrive 'missing-markers.md'
        Set-Content $path "## A section`n`nText."
        { & $script:GuideBuilder -GuidePath $path -OutputPath (Join-Path $TestDrive 'missing-markers.html') } |
            Should -Throw '*guide content marker*'
    }

    It 'rejects an unknown template token after applying the known substitutions' {
        $path = Join-Path $TestDrive 'unknown-token.template.html'
        ((Get-Content $script:GuideTemplate -Raw) + "`n<!-- @@UNKNOWN_TOKEN@@ -->") | Set-Content $path
        { & $script:GuideBuilder -TemplatePath $path -OutputPath (Join-Path $TestDrive 'unknown-token.html') } |
            Should -Throw '*unresolved template token*'
    }
}
