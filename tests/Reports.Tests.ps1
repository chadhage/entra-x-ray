BeforeAll {
    Import-Module "$PSScriptRoot\..\src\EntraXray.psd1"
    . "$PSScriptRoot\TestHelpers.ps1"
}

Describe 'Persistent, replayable evidence and reports' {
    It 'writes complete JSON, safe CSV, detailed Markdown, and verifiable SHA-256 hashes' {
        $e = New-TestEvidence
        Set-TestItems $e users @((New-TestUser @{ displayName = '=HYPERLINK("https://evil.test")'; passwordPolicies = 'DisableStrongPassword' }))
        $out = Join-Path $TestDrive 'reports'
        $result = & (Get-Module EntraXray) {
            param($e, $out)
            $s = New-XraySettings
            $checks = @(Invoke-XrayAssessment $e $s)
            Export-XrayReport -Evidence $e -Findings $checks -Settings $s -OutputDirectory $out
        } $e $out
        foreach ($name in @('evidence.json', 'findings.json', 'findings.csv', 'report.md', 'manifest.json')) {
            Test-Path (Join-Path $out $name) | Should -BeTrue
        }
        $raw = Get-Content (Join-Path $out 'evidence.json') -Raw | ConvertFrom-Json -AsHashtable
        $raw.Sources.users.Items[0].displayName | Should -Be '=HYPERLINK("https://evil.test")'
        $csv = Import-Csv (Join-Path $out 'findings.csv')
        ($csv | Where-Object { $_.CheckId -eq 'ID-005' }).DisplayName | Should -Match "^'="
        $manifest = Get-Content (Join-Path $out 'manifest.json') -Raw | ConvertFrom-Json -AsHashtable
        foreach ($entry in $manifest.Files) {
            (Get-FileHash (Join-Path $out $entry.Name) -Algorithm SHA256).Hash.ToLowerInvariant() | Should -Be $entry.Sha256
        }
        $report = Get-Content (Join-Path $out 'report.md') -Raw
        $report | Should -Match 'Unknown|NotApplicable'
        $report | Should -Match 'AUTH-001'
        $report | Should -Match 'not a certification'
        $report | Should -Match 'Collection'
        $result.OutputDirectory | Should -Be $out
        $result.CheckCount | Should -Be 69
        $result.FailCount | Should -BeGreaterThan 0
    }

    It 'refuses to overwrite any existing deliverable before writing evidence' {
        $out = Join-Path $TestDrive 'existing'
        New-Item $out -ItemType Directory | Out-Null
        Set-Content (Join-Path $out 'findings.csv') 'user data'
        {
            & (Get-Module EntraXray) {
                param($out, $e)
                Export-XrayReport -Evidence $e -Findings @() -Settings (New-XraySettings) -OutputDirectory $out
            } $out (New-TestEvidence)
        } | Should -Throw '*already exists*'
        Test-Path (Join-Path $out 'evidence.json') | Should -BeFalse
        Get-Content (Join-Path $out 'findings.csv') | Should -Be 'user data'
    }

    It 'round-trips evidence and evaluates offline without a Graph module or any network access' {
        $e = New-TestEvidence
        $e.Settings = @{ StaleUserDays = 120 }
        $inputPath = Join-Path $TestDrive 'input.json'
        $e | ConvertTo-Json -Depth 100 | Set-Content $inputPath
        $out = Join-Path $TestDrive 'offline'
        $result = Invoke-EntraXray -EvidencePath $inputPath -OutputDirectory $out -WarningAction SilentlyContinue
        $result.CheckCount | Should -Be 69
        (Get-Content (Join-Path $out 'findings.json') -Raw | ConvertFrom-Json -AsHashtable).Settings.StaleUserDays | Should -Be 120
    }

    It 'allows explicit validated JSON configuration overrides during replay' {
        $e = New-TestEvidence
        $inputPath = Join-Path $TestDrive 'config-input.json'
        $e | ConvertTo-Json -Depth 100 | Set-Content $inputPath
        $configPath = Join-Path $TestDrive 'config.json'
        '{"StaleUserDays":150}' | Set-Content $configPath
        $out = Join-Path $TestDrive 'configured'
        $null = Invoke-EntraXray -EvidencePath $inputPath -ConfigurationPath $configPath -OutputDirectory $out -WarningAction SilentlyContinue
        (Get-Content (Join-Path $out 'findings.json') -Raw | ConvertFrom-Json -AsHashtable).Settings.StaleUserDays | Should -Be 150
    }

    It 'rejects corrupt, incompatible, or internally inconsistent evidence' -ForEach @(
        @{ Mutation = { param($e) $e.SchemaVersion = '99' }; Expected = '*SchemaVersion*' }
        @{ Mutation = { param($e) $e.TenantId = 'common' }; Expected = '*TenantId*' }
        @{ Mutation = { param($e) $e.Sources.users.State = 'Healthy' }; Expected = '*State*' }
        @{ Mutation = { param($e) $e.Sources.users.Items = 'wrong' }; Expected = '*Items*' }
        @{ Mutation = { param($e) $e.Sources.users.ItemCount = 5 }; Expected = '*ItemCount*' }
        @{ Mutation = { param($e) $e.Sources.users.Errors = @(@{ Code = 'error' }) }; Expected = '*Complete*' }
        @{ Mutation = { param($e) $e.CompletedAtUtc = '2020-01-01T00:00:00Z' }; Expected = '*time*' }
        @{ Mutation = { param($e) $e.Settings = @{ UnknownSetting = 1 } }; Expected = '*setting*' }
    ) {
        param($Mutation, $Expected)
        $e = New-TestEvidence
        & $Mutation $e
        $path = Join-Path $TestDrive ([guid]::NewGuid().ToString() + '.json')
        $e | ConvertTo-Json -Depth 100 | Set-Content $path
        { & (Get-Module EntraXray) { param($p) Import-XrayEvidence $p } $path } | Should -Throw $Expected
    }

    It 'distinguishes requested coverage from deliberately unrequested surfaces' {
        $e = New-TestEvidence
        $e.Sources.users.State = 'Partial'
        $e.Sources.users.Errors = @(@{ Code = 'PageLimit'; Message = 'Limit reached' })
        $e.Sources.directoryRecommendations.State = 'Skipped'
        $e.Sources.directoryRecommendations.Requested = $false
        $r = & (Get-Module EntraXray) { param($e) Get-XrayCoverage $e } $e
        $r.IsComplete | Should -BeFalse
        $r.Partial | Should -Be 1
        $r.NotRequested | Should -Be 1
        $r.Requested | Should -Be ($e.Sources.Count - 1)
    }

    It 'runs the user-facing script for an offline assessment' {
        $path = Join-Path $TestDrive 'cli-input.json'
        New-TestEvidence | ConvertTo-Json -Depth 100 | Set-Content $path
        $result = & "$PSScriptRoot\..\Invoke-EntraXray.ps1" -EvidencePath $path -OutputDirectory (Join-Path $TestDrive 'cli-output') -WarningAction SilentlyContinue
        $result.CheckCount | Should -Be 69
    }

    It 'loads the complete module from disk and exports only the supported public commands' {
        Import-Module "$PSScriptRoot\..\src\EntraXray.psd1" -Force -ErrorAction Stop
        @(Get-Command -Module EntraXray | Sort-Object Name | ForEach-Object Name) |
            Should -Be @('Get-EntraXrayCheck', 'Get-EntraXrayPlan', 'Invoke-EntraXray')
    }
}
