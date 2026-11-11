Import-Module "$PSScriptRoot\..\src\EntraXray.psd1"

Describe 'Malformed evidence cannot become a healthy verdict' {
    InModuleScope EntraXray {
        BeforeAll { . "$PSScriptRoot\TestHelpers.ps1" }

        It 'handles PSObject field validation and rejects missing nested properties' {
            { Assert-XrayFields ([pscustomobject]@{ a = [pscustomobject]@{ b = 1 } }) @('a.b') } | Should -Not -Throw
            { Assert-XrayFields ([pscustomobject]@{}) @('missing') } | Should -Throw '*missing*'
            { Assert-XrayFields @{ a = $null } @('a.b') } | Should -Throw '*a.b*'
        }

        It 'validates numerical evidence rather than coercing null, text, or Boolean values' {
            (Get-XrayNumber @{ n = 1 } 'n') | Should -Be 1
            (Get-XrayNumber @{ n = 0.5 } 'n') | Should -Be 0.5
            foreach ($value in @($null, '0', $true, -1, [double]::NaN, [double]::PositiveInfinity)) {
                { Get-XrayNumber @{ n = $value } 'n' } | Should -Throw '*numeric*'
            }
            { Get-XrayNumber @{ n = 0.5 } 'n' -Integer } | Should -Throw '*precision*'
        }

        It 'does not prove an older account is active or inactive when successful activity is null' {
            $e = New-TestEvidence
            Set-TestItems $e users @((New-TestUser @{ signInActivity = $null }))
            (Invoke-XrayAssessment $e (New-XraySettings) 'ID-001').Status | Should -Be 'Unknown'
        }

        It 'uses the documented tenantId key for cross-tenant partners and does not invent an id requirement for defaults' {
            $e = New-TestHealthyEvidence
            $e.Sources.crossTenantDefault.Items[0].Remove('id')
            Set-TestItems $e crossTenantPartners @(@{ tenantId = 'partner-tenant'; inboundTrust = @{ isMfaAccepted = $true } })
            $r = Invoke-XrayAssessment $e (New-XraySettings) 'EXT-003'
            $r.Status | Should -Be 'Review'
            $r.Entities[0].Id | Should -Be 'partner-tenant'
            $e.Sources.crossTenantDefault.Items[0].inboundTrust.isMfaAccepted = $true
            $r = Invoke-XrayAssessment $e (New-XraySettings) 'EXT-003'
            $r.Entities[0].Id | Should -Be 'configuration'
        }

        It 'distinguishes narrow, absent, malformed, and alternative grant-control configurations' {
            $p = New-TestCaPolicy
            $p.state = 'disabled'
            (Test-XrayCaUnqualified $p) | Should -BeFalse
            $p = New-TestCaPolicy
            $p.conditions.users = $null
            (Test-XrayCaUnqualified $p) | Should -BeFalse
            $p = New-TestCaPolicy
            $p.conditions.users.includeUsers = @('specific-user')
            (Test-XrayCaUnqualified $p) | Should -BeFalse
            $p = New-TestCaPolicy
            $p.conditions.applications.includeUserActions = @('urn:user:registersecurityinfo')
            (Test-XrayCaUnqualified $p) | Should -BeFalse
            (Test-XrayCaMfa @{ grantControls = $null } @()) | Should -BeFalse
            $p = New-TestCaPolicy
            $p.grantControls.operator = 'invalid'
            { Test-XrayCaMfa $p @() } | Should -Throw '*operator*'
            $p.grantControls.operator = 'OR'
            (Test-XrayCaMfa $p @()) | Should -BeTrue
            $p.grantControls.authenticationStrength = @{ id = '00000000-0000-0000-0000-000000000004' }
            (Test-XrayCaMfa $p @() -PhishingResistant) | Should -BeFalse
            $p.grantControls.builtInControls = @()
            (Test-XrayCaMfa $p @(@{ id = 'unrelated-strength' }) -PhishingResistant) | Should -BeTrue
        }

        It 'distinguishes malformed payloads from legitimate null activity' -ForEach @(
            @{ Id = 'TEN-001'; Source = 'organization'; Item = @{ onPremisesSyncEnabled = $true; onPremisesLastSyncDateTime = $null } }
            @{ Id = 'TEN-004'; Source = 'subscribedSkus'; Item = @{ id = 'sku'; consumedUnits = $null; prepaidUnits = @{ enabled = 10 } } }
            @{ Id = 'AUTH-001'; Source = 'securityDefaults'; Item = @{} }
            @{ Id = 'AUTH-007'; Source = 'authenticationMethodsPolicy'; Item = @{} }
            @{ Id = 'DEV-001'; Source = 'devices'; Item = @{ id = 'd'; accountEnabled = $true; approximateLastSignInDateTime = $null } }
            @{ Id = 'DEV-002'; Source = 'devices'; Item = @{ id = 'd'; accountEnabled = $true; isCompliant = $null } }
            @{ Id = 'DEV-003'; Source = 'devices'; Item = @{ id = 'd'; accountEnabled = $true; isManaged = 'true' } }
            @{ Id = 'OPS-001'; Source = 'riskyUsers'; Item = @{ id = 'u'; riskState = 'dismissed'; riskLevel = 'hidden' } }
            @{ Id = 'OPS-003'; Source = 'signIns'; Item = @{ id = 's'; status = @{ errorCode = $null }; clientAppUsed = 'Browser' } }
            @{ Id = 'OPS-004'; Source = 'signIns'; Item = @{ id = 's'; status = @{ errorCode = $null }; authenticationRequirement = 'multiFactorAuthentication' } }
            @{ Id = 'OPS-007'; Source = 'secureScores'; Item = @{ id = 's'; currentScore = 0; maxScore = 0 } }
        ) {
            param($Id, $Source, $Item)
            $e = New-TestHealthyEvidence
            Set-TestItems $e $Source @($Item)
            (Invoke-XrayAssessment $e (New-XraySettings) $Id).Status | Should -Be 'Unknown'
        }

        It 'requires exactly one tenant organization instead of passing an empty or ambiguous collection' -ForEach @(
            @{ Count = 0 }, @{ Count = 2 }
        ) {
            param($Count)
            $e = New-TestEvidence
            Set-TestItems $e organization @(for ($n = 0; $n -lt $Count; $n++) { @{ id = "org-$n"; onPremisesSyncEnabled = $false; onPremisesLastSyncDateTime = $null } })
            (Invoke-XrayAssessment $e (New-XraySettings) 'TEN-001').Status | Should -Be 'Unknown'
        }

        It 'rejects malformed or contradictory credential dates and redirect/issuer URIs' {
            $e = New-TestHealthyEvidence
            $app = New-TestApplication @{ passwordCredentials = @(@{ keyId = 'k'; startDateTime = $null; endDateTime = '2027-01-01T00:00:00Z' }) }
            Set-TestItems $e applications @($app)
            (Invoke-XrayAssessment $e (New-XraySettings) 'APP-003').Status | Should -Be 'Unknown'
            $app.passwordCredentials[0].endDateTime = $null
            (Invoke-XrayAssessment $e (New-XraySettings) 'APP-002').Status | Should -Be 'Unknown'
            $app.passwordCredentials = @(@{ keyId = 'k'; startDateTime = '2027-01-01T00:00:00Z'; endDateTime = '2026-01-15T00:00:00Z' })
            (Invoke-XrayAssessment $e (New-XraySettings) 'APP-003').Status | Should -Be 'Unknown'
            $app.web.redirectUris = @('not an absolute URI')
            (Invoke-XrayAssessment $e (New-XraySettings) 'APP-007').Status | Should -Be 'Unknown'
            Set-TestItems $e federatedIdentityCredentials @(@{ id = 'fic'; issuer = 'not a URI' })
            (Invoke-XrayAssessment $e (New-XraySettings) 'APP-012').Status | Should -Be 'Unknown'
        }

        It 'does not silently ignore unresolved granted resources or permission definitions' {
            $e = New-TestHealthyEvidence
            $e.Sources.appRoleAssignments.Items[0].resourceId = 'missing-resource'
            (Invoke-XrayAssessment $e (New-XraySettings) 'APP-009').Status | Should -Be 'Unknown'
            $e.Sources.appRoleAssignments.Items[0].resourceId = 'graph-sp'
            $e.Sources.appRoleAssignments.Items[0].appRoleId = 'missing-permission'
            (Invoke-XrayAssessment $e (New-XraySettings) 'APP-009').Status | Should -Be 'Unknown'
            $e.Sources.servicePrincipals.Items[1].appId = 'third-party-resource'
            (Invoke-XrayAssessment $e (New-XraySettings) 'APP-009').Status | Should -Be 'Pass'
        }

        It 'classifies custom write roles and preserves scoped group-to-guest privilege paths' {
            $e = New-TestHealthyEvidence
            Set-TestItems $e roleDefinitions @(
                @{ id = 'custom-write'; rolePermissions = @(@{ allowedResourceActions = @('microsoft.directory/applications/credentials/update') }) }
                @{ id = 'custom-reader'; rolePermissions = @(@{ allowedResourceActions = @('microsoft.directory/users/standard/read') }) }
            )
            @(Get-XrayPrivilegedRoleIds $e.Sources.roleDefinitions.Items) | Should -Be @('custom-write')
            Set-TestItems $e users @((New-TestUser @{ userType = 'Guest' }))
            Set-TestItems $e roleAssignments @(@{ id = 'r'; principalId = 'role-group'; roleDefinitionId = 'custom-write'; directoryScopeId = '/administrativeUnits/unit' })
            Set-TestItems $e roleGroupMembers @(@{ id = $script:TestUserId; _ParentId = 'role-group' })
            (Invoke-XrayAssessment $e (New-XraySettings) 'PRIV-004').Status | Should -Be 'Review'
        }

        It 'rejects unresolved administrators and excludes disabled and future-eligible users' {
            $e = New-TestHealthyEvidence
            $e.Sources.roleAssignments.Items[0].principalId = 'unresolved'
            (Invoke-XrayAssessment $e (New-XraySettings) 'PRIV-002').Status | Should -Be 'Unknown'
            $e = New-TestHealthyEvidence
            $e.Sources.users.Items[0].accountEnabled = $false
            Set-TestItems $e roleEligibilityScheduleInstances @(@{
                id = 'future'; principalId = $script:TestUserId; roleDefinitionId = $script:GlobalAdminRoleId
                directoryScopeId = '/'; startDateTime = '2026-02-01T00:00:00Z'; endDateTime = $null
            })
            (Invoke-XrayAssessment $e (New-XraySettings) 'PRIV-002').Status | Should -Be 'Review'
        }

        It 'ignores disabled or newly created accounts for stale signals and applies guest invitation fallback explicitly' {
            $e = New-TestEvidence
            Set-TestItems $e users @(
                (New-TestUser @{ accountEnabled = $false; createdDateTime = $null })
                (New-TestUser @{ id = 'new-user'; createdDateTime = '2025-12-31T23:59:00Z'; signInActivity = $null })
                (New-TestUser @{ id = 'new-guest'; userType = 'Guest'; externalUserState = 'PendingAcceptance'; externalUserStateChangeDateTime = $null })
            )
            (Invoke-XrayAssessment $e (New-XraySettings) 'ID-002').Status | Should -Be 'Pass'
            (Invoke-XrayAssessment $e (New-XraySettings) 'ID-004').Status | Should -Be 'Review'
            $e.Sources.users.Items[1].createdDateTime = $null
            (Invoke-XrayAssessment $e (New-XraySettings) 'ID-001').Status | Should -Be 'Unknown'
            $e = New-TestEvidence
            Set-TestItems $e users @((New-TestUser @{ userType = 'Guest' }))
            (Invoke-XrayAssessment $e (New-XraySettings) 'AUTH-004').Status | Should -Be 'NotApplicable'
        }

        It 'selects the most recent Secure Score snapshot, not the most favorable or first returned' {
            $e = New-TestEvidence
            Set-TestItems $e secureScores @(
                @{ id = 'old'; currentScore = 100; maxScore = 100; createdDateTime = '2025-01-01T00:00:00Z' }
                @{ id = 'new'; currentScore = 10; maxScore = 100; createdDateTime = '2025-12-31T00:00:00Z' }
            )
            $r = Invoke-XrayAssessment $e (New-XraySettings) 'OPS-007'
            $r.Status | Should -Be 'Review'
            $r.Entities[0].Id | Should -Be 'new'
        }

        It 'rejects unsupported internal evaluators instead of silently returning a pass' {
            { Invoke-XrayRule @{ Id = 'not-implemented'; Sources = @(); Severity = 'Low'; AdverseStatus = 'Review' } (New-TestEvidence) (New-XraySettings) } | Should -Throw '*No evaluator*'
        }
    }
}

Describe 'Transport and relationship boundaries' {
    InModuleScope EntraXray {
        BeforeAll { . "$PSScriptRoot\TestHelpers.ps1" }

        It 'handles genuine network exceptions with bounded retries and a visible error' {
            Mock Start-Sleep {}
            $r = Invoke-XrayPagedGet -Uri 'https://graph.microsoft.com/v1.0/users' -Budget @{ Used = 0; Limit = 10 } -Request {
                throw [System.Net.Http.HttpRequestException]::new('Do not persist this potentially sensitive exception text')
            } -MaxRetries 1
            $r.State | Should -Be 'Unavailable'
            $r.Errors[0].Code | Should -Be 'NetworkError'
            Should -Invoke Start-Sleep -Times 1
            (New-XrayHttpError 408).Code | Should -Be 'RequestTimeout'
            (Get-XrayRetryDelay 'Wed, 31 Dec 2025 23:59:59 GMT' 0 ([datetimeoffset]'2026-01-01T00:00:00Z')) | Should -Be 0
        }

        It 'uses the default collection retry adapter without an actual sleep or live tenant' {
            Mock Start-Sleep {}
            $script:Attempts = 0
            $request = {
                $script:Attempts++
                if ($script:Attempts -eq 1) { throw (New-TestHttpError 429 '0') }
                @{ value = @(@{ id = $script:TestTenantId }) }
            }
            $e = Invoke-XrayCollection -TenantId $script:TestTenantId -Plan (Get-EntraXrayPlan -SourceId organization) -Request $request
            $e.Sources.organization.State | Should -Be 'Complete'
            Should -Invoke Start-Sleep -Times 1
        }

        It 'rejects non-string continuation values and error-shaped singleton payloads' {
            $r = Invoke-XrayPagedGet -Uri 'https://graph.microsoft.com/v1.0/users' -Budget @{ Used = 0; Limit = 10 } -Request { @{ value = @(); '@odata.nextLink' = 42 } }
            $r.Errors[0].Code | Should -Be 'UnsafeNextLink'
            $r = Invoke-XrayPagedGet -Uri 'https://graph.microsoft.com/v1.0/policies/authorizationPolicy' -Shape Singleton -Budget @{ Used = 0; Limit = 10 } -Request { @{ error = @{ code = 'denied' } } }
            $r.Errors[0].Code | Should -Be 'InvalidResponse'
            (Copy-XrayObject ([pscustomobject]@{ id = 'copy'; enabled = $false })).enabled | Should -BeFalse
        }

        It 'expands relationship IDs safely and requires both identities for a two-hop relationship' {
            (Resolve-XrayChildUri '/applications/{id}/owners' @{ id = 'a/b ?' }) | Should -Be '/applications/a%2Fb%20%3F/owners'
            (Resolve-XrayChildUri '/reviews/{parentId}/instances/{id}/decisions' @{ id = 'instance'; _ParentId = 'definition' }) | Should -Be '/reviews/definition/instances/instance/decisions'
            { Resolve-XrayChildUri '/reviews/{parentId}/instances/{id}' @{ id = 'instance' } } | Should -Throw '*ancestor*'
            { Resolve-XrayChildUri '/applications/{id}' @{ id = '' } } | Should -Throw '*ID*'
        }

        It 'records partial parent scope and applies one page budget across all child requests' {
            $p = Get-EntraXrayPlan -SourceId applicationOwners
            $request = {
                param($uri)
                if ($uri -match '/applications\?') {
                    return @{ value = @(@{ id = 'a-1' }, @{ id = 'a-2' }); '@odata.nextLink' = ($uri + '&$skiptoken=more') }
                }
                @{ value = @(@{ id = 'owner' }) }
            }
            $e = Invoke-XrayCollection -TenantId $script:TestTenantId -Plan $p -Request $request -MaxPagesPerSource 1
            $e.Sources.applications.State | Should -Be 'Partial'
            $e.Sources.applicationOwners.State | Should -Be 'Partial'
            @($e.Sources.applicationOwners.Errors.Code) | Should -Contain 'ParentIncomplete'
            @($e.Sources.applicationOwners.Errors.Code) | Should -Contain 'PageLimit'
        }

        It 'handles managed/non-role groups, malformed filter fields, and real nested review traversal' {
            $p = Get-EntraXrayPlan -SourceId roleGroupMembers
            $e = Invoke-XrayCollection -TenantId $script:TestTenantId -Plan $p -Request { @{ value = @(@{ id = 'normal'; isAssignableToRole = $false }) } }
            $e.Sources.roleGroupMembers.ItemCount | Should -Be 0
            $e.Sources.roleGroupMembers.State | Should -Be 'Complete'
            $p = Get-EntraXrayPlan -SourceId federationConfigurations
            $e = Invoke-XrayCollection -TenantId $script:TestTenantId -Plan $p -Request { @{ value = @(@{ id = 'unknown.test'; authenticationType = 'Unknown' }) } }
            $e.Sources.federationConfigurations.State | Should -Be 'Partial'
            $p = Get-EntraXrayPlan -SourceId accessReviewDecisions
            $request = {
                param($uri)
                if ($uri -match '/decisions$') { return @{ value = @(@{ id = 'decision' }) } }
                if ($uri -match '/instances$') { return @{ value = @(@{ id = 'instance' }) } }
                @{ value = @(@{ id = 'definition' }) }
            }
            $e = Invoke-XrayCollection -TenantId $script:TestTenantId -Plan $p -Request $request
            $e.Sources.accessReviewDecisions.Items[0]._ParentId | Should -Be 'instance'
            $e.Sources.accessReviewDecisions.Requests[0].Uri | Should -Match '/definitions/definition/instances/instance/decisions'
        }

        It 'handles an unset optional role-assignable flag without misclassifying ordinary groups' {
            $p = Get-EntraXrayPlan -SourceId roleGroupMembers
            $e = Invoke-XrayCollection -TenantId $script:TestTenantId -Plan $p -Request {
                @{ value = @(@{ id = 'ordinary-group'; isAssignableToRole = $null }) }
            }
            $e.Sources.roleGroupMembers.State | Should -Be 'Complete'
            $e.Sources.roleGroupMembers.ItemCount | Should -Be 0
            (Invoke-XrayAssessment $e (New-XraySettings) 'PRIV-007').Status | Should -Be 'Unknown'
            $e = New-TestEvidence
            Set-TestItems $e groups @(@{ id = 'ordinary-group'; isAssignableToRole = $null })
            (Invoke-XrayAssessment $e (New-XraySettings) 'PRIV-007').Status | Should -Be 'Pass'
            Set-TestItems $e groups @(@{ id = 'invalid-group'; isAssignableToRole = 'false' })
            (Invoke-XrayAssessment $e (New-XraySettings) 'PRIV-007').Status | Should -Be 'Unknown'
        }
    }
}

Describe 'Offline contract rejection and output durability' {
    InModuleScope EntraXray {
        BeforeAll { . "$PSScriptRoot\TestHelpers.ps1" }

        It 'rejects non-object JSON, including single-element arrays that a pipeline might unwrap' -ForEach @(
            @{ Text = 'null' }, @{ Text = '[]' }, @{ Text = '[{}]' }, @{ Text = '"text"' }
        ) {
            param($Text)
            $path = Join-Path $TestDrive ([guid]::NewGuid().ToString() + '.json')
            Set-Content $path $Text
            { Read-XrayJsonObject $path } | Should -Throw '*JSON document must contain an object*'
        }

        It 'rejects structurally malformed snapshots before evaluating checks' -ForEach @(
            @{ Mutation = { param($e) $e.Environment = 'other' } }
            @{ Mutation = { param($e) $e.LogWindow.EndUtc = '2030-01-01T00:00:00Z' } }
            @{ Mutation = { param($e) $e.Settings = @() } }
            @{ Mutation = { param($e) $e.Sources = @{} } }
            @{ Mutation = { param($e) $e.Sources.unknown = $e.Sources.users } }
            @{ Mutation = { param($e) $e.Sources.users.Id = 'different' } }
            @{ Mutation = { param($e) $e.Sources.users.Items = @('not an object'); $e.Sources.users.ItemCount = 1 } }
            @{ Mutation = { param($e) $e.Sources.users.Pages = -1 } }
            @{ Mutation = { param($e) $e.Sources.users.Errors = 'not an array' } }
            @{ Mutation = { param($e) $e.Sources.users.Requested = 'yes' } }
            @{ Mutation = { param($e) $e.Sources.users.Requested = $false } }
            @{ Mutation = { param($e) $e.Sources.users.ApiVersion = 'unknown' } }
            @{ Mutation = { param($e) $e.Sources.users.CollectedAtUtc = $null } }
        ) {
            param($Mutation)
            $e = New-TestEvidence
            & $Mutation $e
            $path = Join-Path $TestDrive ([guid]::NewGuid().ToString() + '.json')
            $e | ConvertTo-Json -Depth 100 | Set-Content $path
            { Import-XrayEvidence $path } | Should -Throw
        }

        It 'refuses a file as an output directory and atomically cleans a failed file write' {
            $path = Join-Path $TestDrive 'existing-file'
            Set-Content $path 'original'
            { Assert-XrayOutputDirectory $path } | Should -Throw '*not a directory*'
            { Write-XrayFile $path 'replacement' } | Should -Throw '*already exists*'
            Mock Move-Item { throw [System.IO.IOException]::new('Synthetic disk failure') }
            { Write-XrayFile (Join-Path $TestDrive 'failed.json') 'test' } | Should -Throw '*disk failure*'
            @(Get-ChildItem $TestDrive -Filter '*.tmp').Count | Should -Be 0
        }

        It 'keeps raw evidence durable even when assessment fails unexpectedly' {
            $e = New-TestHealthyEvidence
            $path = Join-Path $TestDrive 'durability-input.json'
            $e | ConvertTo-Json -Depth 100 | Set-Content $path
            Mock Invoke-XrayAssessment { throw [System.InvalidOperationException]::new('Synthetic evaluator bug') }
            $out = Join-Path $TestDrive 'durable'
            { Invoke-EntraXray -EvidencePath $path -OutputDirectory $out -WarningAction SilentlyContinue } | Should -Throw '*evaluator bug*'
            Test-Path (Join-Path $out 'evidence.json') | Should -BeTrue
            Test-Path (Join-Path $out 'manifest.json') | Should -BeFalse
        }

        It 'exercises the validated live entry point without contacting a tenant' {
            Mock Invoke-XrayLiveScan { New-TestHealthyEvidence }
            $result = Invoke-EntraXray -TenantId $script:TestTenantId -SourceId organization -OutputDirectory (Join-Path $TestDrive 'live-mock') -WarningAction SilentlyContinue
            $result.RecommendedExitCode | Should -Be 0
            Should -Invoke Invoke-XrayLiveScan -Times 1 -ParameterFilter { $Plan.Sources.Count -eq 1 -and $TenantId -eq '11111111-1111-4111-8111-111111111111' }
            { Invoke-EntraXray -TenantId common -OutputDirectory (Join-Path $TestDrive 'invalid') } | Should -Throw '*TenantId*'
        }

        It 'does not impose a tenant mutation or a process exit on module consumers' {
            $e = New-TestHealthyEvidence
            $e.Sources.securityDefaults.Items[0].isEnabled = $false
            Set-TestItems $e conditionalAccessPolicies @()
            $path = Join-Path $TestDrive 'fail-input.json'
            $e | ConvertTo-Json -Depth 100 | Set-Content $path
            $r = Invoke-EntraXray -EvidencePath $path -OutputDirectory (Join-Path $TestDrive 'fail-report') -WarningAction SilentlyContinue
            $r.RecommendedExitCode | Should -Be 3
            $r.Incomplete | Should -BeFalse
        }

        It 'persists and clearly reports collection failures without interpreting denied data as healthy' {
            $e = New-TestHealthyEvidence
            $e.Sources.userSignInActivity.State = 'Unavailable'
            $e.Sources.userSignInActivity.Errors = @(@{ Code = 'AccessDenied'; Message = '<untrusted>|failure'; StatusCode = 403 })
            $path = Join-Path $TestDrive 'denied-input.json'
            $e | ConvertTo-Json -Depth 100 | Set-Content $path
            $out = Join-Path $TestDrive 'denied-output'
            $r = Invoke-EntraXray -EvidencePath $path -OutputDirectory $out -WarningAction SilentlyContinue
            $r.Incomplete | Should -BeTrue
            $r.RecommendedExitCode | Should -Be 2
            $report = Get-Content (Join-Path $out 'report.md') -Raw
            $report | Should -Match 'AccessDenied'
            $report | Should -Not -Match '<untrusted>'
        }
    }
}
