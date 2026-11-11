Import-Module "$PSScriptRoot\..\src\EntraXray.psd1"
BeforeAll { . "$PSScriptRoot\TestHelpers.ps1" }

Describe 'Read-only source planning' {
    It 'publishes versioned, documented, permissioned sources without write scopes' {
        $p = Get-EntraXrayPlan
        $p.Sources.Count | Should -BeGreaterThan 60
        $p.Permissions.Count | Should -BeGreaterThan 5
        foreach ($s in $p.Sources) {
            $s.Method | Should -Be 'GET'
            $s.Path | Should -Match '^/'
            $s.ApiVersion | Should -Be 'v1.0'
            $s.Reference | Should -Match '^https://learn.microsoft.com/'
            $s.Permissions.Count | Should -BeGreaterThan 0
        }
        ($p.Permissions -join ' ') | Should -Not -Match 'ReadWrite|Write\.|\.Manage'
    }

    It 'makes beta opt-in, resolves cloud endpoints, and rejects unknown source identifiers' {
        $p = Get-EntraXrayPlan -IncludeBeta -Environment USGov
        $p.GraphBaseUri | Should -Be 'https://graph.microsoft.us'
        @($p.Sources | Where-Object ApiVersion -EQ beta).Count | Should -Be 7
        { Get-EntraXrayPlan -SourceId 'not-a-source' } | Should -Throw '*Unknown source*'
        { Get-EntraXrayPlan -SourceId deviceRegistrationPolicy } | Should -Throw '*IncludeBeta*'
        (Get-EntraXrayPlan -Environment USGovDoD).GraphBaseUri | Should -Be 'https://dod-graph.microsoft.us'
        (Get-EntraXrayPlan -Environment China).GraphBaseUri | Should -Be 'https://microsoftgraph.chinacloudapi.cn'
    }

    It 'automatically includes ancestors, preserves collection order, and minimizes requested permissions' {
        $p = Get-EntraXrayPlan -SourceId accessReviewDecisions
        @($p.Sources.Id) | Should -Be @('accessReviewDefinitions', 'accessReviewInstances', 'accessReviewDecisions')
        @($p.Permissions) | Should -Be @('AccessReview.Read.All')
        $p = Get-EntraXrayPlan -SourceId organization, organization
        $p.Sources.Count | Should -Be 1
    }

    It 'supports exact check lookup and rejects misspelled checks' {
        (Get-EntraXrayCheck -Id 'AUTH-001').Id | Should -Be 'AUTH-001'
        { Get-EntraXrayCheck -Id 'TYPO-001' } | Should -Throw '*Unknown check*'
    }
}

Describe 'Configuration and data helpers' {
    InModuleScope EntraXray {
        It 'has unique source identities, known shapes, and topologically ordered relationship dependencies' {
            $catalog = @(Get-XraySourceCatalog)
            $catalog.Count | Should -Be 77
            @($catalog.Id | Select-Object -Unique).Count | Should -Be 77
            $visited = [System.Collections.Generic.HashSet[string]]::new()
            $byId = @{}
            foreach ($source in $catalog) {
                $source.Shape | Should -BeIn @('Collection', 'Singleton')
                $source.Method | Should -Be 'GET'
                $source.Scope | Should -Not -BeNullOrEmpty
                $source.Licensing | Should -Not -BeNullOrEmpty
                if ($source.Parent) {
                    $visited.Contains($source.Parent) | Should -BeTrue
                    $source.Path | Should -Match '\{id\}'
                    if ($source.Path.Contains('{parentId}')) { $byId[$source.Parent].Parent | Should -Not -BeNullOrEmpty }
                }
                $byId[$source.Id] = $source
                [void]$visited.Add($source.Id)
            }
        }

        It 'reads dictionary and PSObject paths without conflating absent and false values' {
            (Get-XrayValue @{ a = @{ b = $false } } 'a.b') | Should -BeFalse
            (Get-XrayValue ([pscustomobject]@{ a = [pscustomobject]@{ b = 4 } }) 'a.b') | Should -Be 4
            (Get-XrayValue @{ a = $null } 'a.b') | Should -Be $null
            (Get-XrayValue @{} 'absent') | Should -Be $null
            (Get-XrayValue ([pscustomobject]@{}) 'absent') | Should -Be $null
            (Get-XrayValue @{ '@odata.nextLink' = 'page-2' } '@odata.nextLink') | Should -Be 'page-2'
            (Get-XrayValue ([pscustomobject]@{ '@odata.nextLink' = 'page-2' }) '@odata.nextLink') | Should -Be 'page-2'
            { Assert-XrayFields @{ a = 1 } @('a', 'b.c') } | Should -Throw '*b.c*'
            { Assert-XrayFields @{ a = @{ b = $null } } @('a.b') } | Should -Not -Throw
            (Get-XrayBoolean @{ enabled = $false } 'enabled') | Should -BeFalse
            { Get-XrayBoolean @{ enabled = $null } 'enabled' } | Should -Throw '*Boolean*'
            { Get-XrayBoolean @{ enabled = 'false' } 'enabled' } | Should -Throw '*Boolean*'
        }

        It 'validates configurable thresholds and explicit emergency account IDs' {
            $s = New-XraySettings
            $s.StaleUserDays | Should -Be 90
            (New-XraySettings @{ StaleUserDays = 120 }).StaleUserDays | Should -Be 120
            (New-XraySettings @{ SecureScoreThreshold = 0 }).SecureScoreThreshold | Should -Be 0
            (New-XraySettings @{ EmergencyAccessAccountId = @('22222222-2222-4222-8222-222222222222') }).EmergencyAccessAccountId.Count | Should -Be 1
            { New-XraySettings @{ Typo = 10 } } | Should -Throw '*Unknown setting*'
            { New-XraySettings @{ StaleUserDays = 0 } } | Should -Throw '*StaleUserDays*'
            { New-XraySettings @{ StaleUserDays = '90' } } | Should -Throw '*StaleUserDays*'
            { New-XraySettings @{ StaleUserDays = 2.5 } } | Should -Throw '*StaleUserDays*'
            { New-XraySettings @{ SecureScoreThreshold = 1.1 } } | Should -Throw '*SecureScoreThreshold*'
            { New-XraySettings @{ EmergencyAccessAccountId = @('not-a-guid') } } | Should -Throw '*EmergencyAccessAccountId*'
            { New-XraySettings @{ EmergencyAccessAccountId = $null } } | Should -Throw '*EmergencyAccessAccountId*'
        }

        It 'uses invariant UTC dates and rejects malformed timestamps' {
            (ConvertTo-XrayDate '2026-01-01T02:00:00+02:00').ToString('o') | Should -Match '^2026-01-01T00:00:00'
            (ConvertTo-XrayDate ([datetime]::SpecifyKind([datetime]'2026-01-01', 'Utc'))).Year | Should -Be 2026
            (ConvertTo-XrayDate ([datetimeoffset]'2026-01-01T00:00:00Z')).Year | Should -Be 2026
            (ConvertTo-XrayDate $null) | Should -Be $null
            { ConvertTo-XrayDate 'yesterday-ish' } | Should -Throw '*timestamp*'
        }

        It 'escapes markdown and spreadsheet formulas without mutating raw evidence' {
            (ConvertTo-XrayMarkdownText "<script>x</script>|[link](javascript:x)`nnext") | Should -Not -Match '<script>|\[link\]'
            (ConvertTo-XrayMarkdownText $null) | Should -Be ''
            foreach ($value in @('=1+1', '+cmd', '-cmd', '@SUM(A1)', " `t=2+2")) {
                (ConvertTo-XrayCsvText $value).StartsWith("'") | Should -BeTrue
            }
            (ConvertTo-XrayCsvText 'normal') | Should -Be 'normal'
            (ConvertTo-XrayCsvText $null) | Should -Be ''
        }
    }
}

Describe 'HTTP safety, retries, pagination, and budgets' {
    InModuleScope EntraXray {
        BeforeAll { . "$PSScriptRoot\TestHelpers.ps1" }
        BeforeEach {
            $script:Calls = 0
            $script:Sleeps = [System.Collections.Generic.List[double]]::new()
            $script:Budget = @{ Used = 0; Limit = 100 }
            $script:NoSleep = { param($seconds) $script:Sleeps.Add($seconds) }
            $script:FixedClock = { [datetimeoffset]'2026-01-01T00:00:00Z' }
        }

        It 'reads every page exactly once and preserves singleton and empty collection shapes' {
            $request = {
                param($uri)
                $script:Calls++
                if ($uri -like '*skiptoken*') { return @{ value = @(@{ id = 'two' }) } }
                @{ value = @(@{ id = 'one' }); '@odata.nextLink' = 'https://graph.microsoft.com/v1.0/users?$skiptoken=2' }
            }
            $r = Invoke-XrayPagedGet -Uri 'https://graph.microsoft.com/v1.0/users' -Request $request -Budget $script:Budget
            $r.State | Should -Be 'Complete'
            @($r.Items.id) | Should -Be @('one', 'two')
            $r.Pages | Should -Be 2
            $script:Calls | Should -Be 2
            $r = Invoke-XrayPagedGet -Uri 'https://graph.microsoft.com/v1.0/policies/authorizationPolicy' -Shape Singleton -Request { @{ id = 'policy'; isEnabled = $false } } -Budget $script:Budget
            $r.Items.Count | Should -Be 1
            $r = Invoke-XrayPagedGet -Uri 'https://graph.microsoft.com/v1.0/users' -Request { @{ value = @() } } -Budget $script:Budget
            $r.State | Should -Be 'Complete'
            $r.Items.Count | Should -Be 0
        }

        It 'rejects unsafe initial and pagination URLs before sending a request' -ForEach @(
            @{ Url = 'http://graph.microsoft.com/v1.0/users' }
            @{ Url = 'https://evil.example.test/v1.0/users' }
            @{ Url = 'https://graph.microsoft.com.evil.example.test/v1.0/users' }
            @{ Url = 'https://user@graph.microsoft.com/v1.0/users' }
            @{ Url = 'https://graph.microsoft.com:444/v1.0/users' }
            @{ Url = 'https://graph.microsoft.com/v1.0/users#fragment' }
            @{ Url = '/v1.0/users' }
            @{ Url = 'https://graph.microsoft.com/not-graph/users' }
        ) {
            param($Url)
            { Assert-XrayGraphUri -Uri $Url -GraphBaseUri 'https://graph.microsoft.com' } | Should -Throw
            $r = Invoke-XrayPagedGet -Uri 'https://graph.microsoft.com/v1.0/users' -Request {
                param($uri) $script:Calls++; @{ value = @(@{ id = 'one' }); '@odata.nextLink' = $Url }
            }.GetNewClosure() -Budget $script:Budget
            $r.State | Should -Be 'Partial'
            $script:Budget.Used | Should -Be 1
        }

        It 'rejects pagination that switches API versions or resource paths' -ForEach @(
            @{ Url = 'https://graph.microsoft.com/beta/users?$skiptoken=2' }
            @{ Url = 'https://graph.microsoft.com/v1.0/applications?$skiptoken=2' }
        ) {
            param($Url)
            $r = Invoke-XrayPagedGet -Uri 'https://graph.microsoft.com/v1.0/users' -Request {
                @{ value = @(@{ id = 'one' }); '@odata.nextLink' = $Url }
            }.GetNewClosure() -Budget $script:Budget
            $r.State | Should -Be 'Partial'
            $r.Errors[0].Code | Should -Be 'UnsafeNextLink'
        }

        It 'stops looping pagination and records truncation at a page limit' {
            $request = { @{ value = @(@{ id = 'one' }); '@odata.nextLink' = 'https://graph.microsoft.com/v1.0/users' } }
            $r = Invoke-XrayPagedGet -Uri 'https://graph.microsoft.com/v1.0/users' -Request $request -Budget $script:Budget
            $r.State | Should -Be 'Partial'
            $r.Errors[0].Code | Should -Be 'PaginationLoop'
            $request = { @{ value = @(@{ id = 'one' }); '@odata.nextLink' = 'https://graph.microsoft.com/v1.0/users?$skiptoken=2' } }
            $r = Invoke-XrayPagedGet -Uri 'https://graph.microsoft.com/v1.0/users' -Request $request -Budget $script:Budget -MaxPages 1
            $r.State | Should -Be 'Partial'
            $r.Errors[0].Code | Should -Be 'PageLimit'
        }

        It 'records authorization and capability failures without inventing a licensing diagnosis' -ForEach @(
            @{ HttpStatus = 400; Code = 'BadRequest' }
            @{ HttpStatus = 401; Code = 'Unauthenticated' }
            @{ HttpStatus = 403; Code = 'AccessDenied' }
            @{ HttpStatus = 404; Code = 'NotFound' }
            @{ HttpStatus = 409; Code = 'HttpError' }
        ) {
            param($HttpStatus, $Code)
            $httpError = New-TestHttpError $HttpStatus
            $request = { throw $httpError }.GetNewClosure()
            $r = Invoke-XrayPagedGet -Uri 'https://graph.microsoft.com/v1.0/users' -Request $request -Budget $script:Budget
            $r.State | Should -Be 'Unavailable'
            $r.Errors[0].StatusCode | Should -Be $HttpStatus
            $r.Errors[0].Code | Should -Be $Code
            $r.Errors[0].Message | Should -Not -Match 'Synthetic|token|Bearer'
            $script:Budget.Used | Should -Be 1
        }

        It 'honors Retry-After seconds and HTTP dates and retries transient failures only' -ForEach @(
            @{ HttpStatus = 429; RetryAfter = '3'; Seconds = 3 }
            @{ HttpStatus = 503; RetryAfter = 'Thu, 01 Jan 2026 00:00:04 GMT'; Seconds = 4 }
            @{ HttpStatus = 502; RetryAfter = 'invalid'; Seconds = 1 }
            @{ HttpStatus = 500; RetryAfter = ''; Seconds = 1 }
            @{ HttpStatus = 504; RetryAfter = ''; Seconds = 1 }
            @{ HttpStatus = 408; RetryAfter = ''; Seconds = 1 }
        ) {
            param($HttpStatus, $RetryAfter, $Seconds)
            $httpError = New-TestHttpError $HttpStatus $RetryAfter
            $counter = @{ Calls = 0 }
            $request = {
                $counter.Calls++
                if ($counter.Calls -eq 1) { throw $httpError }
                @{ value = @(@{ id = 'ok' }) }
            }.GetNewClosure()
            $r = Invoke-XrayPagedGet -Uri 'https://graph.microsoft.com/v1.0/users' -Request $request -Budget $script:Budget -Sleep $script:NoSleep -Clock $script:FixedClock
            $r.State | Should -Be 'Complete'
            $script:Sleeps[0] | Should -Be $Seconds
            $script:Budget.Used | Should -Be 2
        }

        It 'does not retry before an excessive Retry-After and surfaces retry exhaustion' {
            $r = Invoke-XrayPagedGet -Uri 'https://graph.microsoft.com/v1.0/users' -Request { throw (New-TestHttpError 429 '3600') } -Budget $script:Budget -Sleep $script:NoSleep
            $r.Errors[0].Code | Should -Be 'RetryDelayLimit'
            $script:Sleeps.Count | Should -Be 0
            $r = Invoke-XrayPagedGet -Uri 'https://graph.microsoft.com/v1.0/users' -Request { throw (New-TestHttpError 503) } -Budget $script:Budget -MaxRetries 1 -Sleep $script:NoSleep
            $r.Errors[0].Code | Should -Be 'ServiceUnavailable'
            $r.State | Should -Be 'Unavailable'
        }

        It 'keeps records already retrieved when a later page fails' {
            $request = {
                param($uri)
                if ($uri -match 'skiptoken') { throw (New-TestHttpError 403) }
                @{ value = @(@{ id = 'retained' }); '@odata.nextLink' = 'https://graph.microsoft.com/v1.0/users?$skiptoken=2' }
            }
            $r = Invoke-XrayPagedGet -Uri 'https://graph.microsoft.com/v1.0/users' -Request $request -Budget $script:Budget
            $r.State | Should -Be 'Partial'
            $r.Items[0].id | Should -Be 'retained'
        }

        It 'rejects malformed response shapes rather than treating them as empty collections' -ForEach @(
            @{ Response = $null }
            @{ Response = @{} }
            @{ Response = @{ value = $null } }
            @{ Response = @{ value = 'not-an-array' } }
            @{ Response = @{ value = @('not-an-object') } }
        ) {
            param($Response)
            $r = Invoke-XrayPagedGet -Uri 'https://graph.microsoft.com/v1.0/users' -Request { $Response }.GetNewClosure() -Budget $script:Budget
            $r.State | Should -Be 'Unavailable'
            $r.Errors[0].Code | Should -Be 'InvalidResponse'
        }

        It 'enforces a global request budget including retry attempts' {
            $script:Budget = @{ Used = 1; Limit = 1 }
            $r = Invoke-XrayPagedGet -Uri 'https://graph.microsoft.com/v1.0/users' -Request { throw 'must not run' } -Budget $script:Budget
            $r.Errors[0].Code | Should -Be 'RequestLimit'
            $script:Budget.Used | Should -Be 1
        }

        It 'does not silently suppress unexpected programming errors' {
            { Invoke-XrayPagedGet -Uri 'https://graph.microsoft.com/v1.0/users' -Request { throw [System.InvalidOperationException]::new('bug') } -Budget $script:Budget } | Should -Throw '*bug*'
        }
    }
}

Describe 'Collection dependency and scope accounting' {
    InModuleScope EntraXray {
        BeforeAll { . "$PSScriptRoot\TestHelpers.ps1" }

        It 'preserves basic user inventory when premium sign-in activity is denied' {
            $p = Get-EntraXrayPlan -SourceId users, userSignInActivity
            $request = {
                param($uri)
                if ($uri -match 'signInActivity') { throw (New-TestHttpError 403) }
                @{ value = @(@{ id = 'user-1'; accountEnabled = $true; displayName = 'Basic inventory' }) }
            }
            $e = Invoke-XrayCollection -TenantId $script:TestTenantId -Plan $p -Request $request
            $e.Sources.users.State | Should -Be 'Complete'
            $e.Sources.users.ItemCount | Should -Be 1
            $e.Sources.userSignInActivity.State | Should -Be 'Unavailable'
            (Get-EntraXrayPlan -SourceId users).Permissions | Should -Be @('Directory.Read.All')
        }

        It 'collects child relationships only for appropriate parents with escaped identifiers' {
            $plan = Get-EntraXrayPlan -SourceId federationConfigurations
            $script:Uris = [System.Collections.Generic.List[string]]::new()
            $request = {
                param($uri)
                $script:Uris.Add($uri)
                if ($uri -match '/domains\?') {
                    return @{ value = @(@{ id = 'managed.test'; authenticationType = 'Managed' }, @{ id = 'fed.test'; authenticationType = 'Federated' }) }
                }
                @{ value = @(@{ id = 'fed-config'; issuerUri = 'https://issuer.test' }) }
            }
            $e = Invoke-XrayCollection -TenantId $script:TestTenantId -Plan $plan -Request $request -Clock { [datetimeoffset]'2026-01-01T00:00:00Z' }
            $e.Sources.federationConfigurations.State | Should -Be 'Complete'
            $e.Sources.federationConfigurations.Items[0]._ParentId | Should -Be 'fed.test'
            $script:Uris.Count | Should -Be 2
            $e.Sources.users.State | Should -Be 'Skipped'
            $e.Sources.users.Requested | Should -BeFalse
            $e.LogWindow.StartUtc | Should -Be '2025-12-02T00:00:00.0000000Z'
        }

        It 'marks dependent evidence incomplete when parents are denied or truncated' {
            $p = Get-EntraXrayPlan -SourceId applicationOwners
            $e = Invoke-XrayCollection -TenantId $script:TestTenantId -Plan $p -Request { throw (New-TestHttpError 403) }
            $e.Sources.applications.State | Should -Be 'Unavailable'
            $e.Sources.applicationOwners.State | Should -Be 'Skipped'
            $e.Sources.applicationOwners.Errors[0].Code | Should -Be 'ParentIncomplete'
        }

        It 'preserves per-parent failures and continues collecting other parents' {
            $p = Get-EntraXrayPlan -SourceId applicationOwners
            $request = {
                param($uri)
                if ($uri -match '/applications\?') { return @{ value = @(@{ id = 'a-1' }, @{ id = 'a-2' }) } }
                if ($uri -match '/a-1/') { throw (New-TestHttpError 403) }
                @{ value = @(@{ id = 'owner-2' }) }
            }
            $e = Invoke-XrayCollection -TenantId $script:TestTenantId -Plan $p -Request $request
            $e.Sources.applicationOwners.State | Should -Be 'Partial'
            $e.Sources.applicationOwners.Items[0]._ParentId | Should -Be 'a-2'
            $e.Sources.applicationOwners.Errors[0].ParentId | Should -Be 'a-1'
        }

        It 'does not mark malformed parent identities or filter fields complete' {
            $p = Get-EntraXrayPlan -SourceId roleGroupMembers
            $e = Invoke-XrayCollection -TenantId $script:TestTenantId -Plan $p -Request { @{ value = @(@{ displayName = 'broken parent' }) } }
            $e.Sources.roleGroupMembers.State | Should -Be 'Partial'
            $e.Sources.roleGroupMembers.Errors[0].Code | Should -Be 'InvalidParent'
        }

        It 'records requested beta sources, exact log windows, and budget exhaustion' {
            $p = Get-EntraXrayPlan -IncludeBeta -SourceId nonInteractiveSignIns, directoryAudits
            $script:Uris = [System.Collections.Generic.List[string]]::new()
            $request = { param($uri) $script:Uris.Add($uri); @{ value = @() } }
            $e = Invoke-XrayCollection -TenantId $script:TestTenantId -Plan $p -Request $request -MaxRequests 1 -LogDays 3 -Clock { [datetimeoffset]'2026-01-01T00:00:00Z' }
            $script:Uris[0] | Should -Match '2025-12-29'
            $e.Sources.nonInteractiveSignIns.State | Should -Be 'Unavailable'
            $e.Sources.nonInteractiveSignIns.Errors[0].Code | Should -Be 'RequestLimit'
        }
    }
}
