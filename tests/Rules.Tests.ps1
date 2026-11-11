BeforeDiscovery {
    . "$PSScriptRoot\TestHelpers.ps1"
    $ruleCases = Get-TestRuleCases
}

BeforeAll {
    Import-Module "$PSScriptRoot\..\src\EntraXray.psd1"
    . "$PSScriptRoot\TestHelpers.ps1"
}

Describe 'Evidence-backed assessment contract' {
    It '<Id> distinguishes a benign, applicable scenario from its adverse condition' -ForEach $ruleCases {
        param($Id)
        $e = New-TestHealthyEvidence
        $expected = 'Pass'
        if ($Id -eq 'PRIV-008') { $expected = 'Review' }
        if ($Id -eq 'APP-013') { $expected = 'NotApplicable' }
        $r = & (Get-Module EntraXray) { param($e, $id) Invoke-XrayAssessment $e (New-XraySettings) $id } $e $Id
        $r.Status | Should -Be $expected
    }

    It 'has one independently specified adverse scenario for every published check' {
        $expected = @(Get-TestRuleCases | ForEach-Object Id | Sort-Object)
        $actual = @(Get-EntraXrayCheck | ForEach-Object Id | Sort-Object)
        $actual | Should -Be $expected
        $actual.Count | Should -Be 69
    }

    It '<Id> discriminates its documented adverse condition as <Status>' -ForEach $ruleCases {
        param($Id, $Status, $Mutate)
        $e = New-TestEvidence
        & $Mutate $e
        $result = & (Get-Module EntraXray) {
            param($e, $id)
            Invoke-XrayAssessment -Evidence $e -Settings (New-XraySettings) -CheckId $id
        } $e $Id
        $result.Status | Should -Be $Status
        $result.Id | Should -Be $Id
        $result.Summary | Should -Not -BeNullOrEmpty
        $result.Remediation | Should -Not -BeNullOrEmpty
        $result.References.Count | Should -BeGreaterThan 0
        $result.Sources.Count | Should -BeGreaterThan 0
        $result.Confidence | Should -BeIn @('High', 'Medium', 'ContextRequired')
    }

    It '<Id> never passes when a prerequisite is unavailable' -ForEach $ruleCases {
        param($Id, $Mutate)
        $e = New-TestEvidence
        & $Mutate $e
        $definition = Get-EntraXrayCheck -Id $Id
        foreach ($source in $definition.Sources) {
            $e.Sources[$source].State = 'Unavailable'
            $e.Sources[$source].Errors = @(@{ Code = 'AccessDenied'; Message = 'Synthetic denial'; StatusCode = 403 })
        }
        $result = & (Get-Module EntraXray) {
            param($e, $id)
            Invoke-XrayAssessment -Evidence $e -Settings (New-XraySettings) -CheckId $id
        } $e $Id
        $result.Status | Should -Be 'Unknown'
        $result.Limitations.Count | Should -BeGreaterThan 0
    }

    It 'emits all checks, stable identifiers, complete provenance, and explicit status counts' {
        $r = & (Get-Module EntraXray) {
            param($e)
            Invoke-XrayAssessment -Evidence $e -Settings (New-XraySettings)
        } (New-TestEvidence)
        @($r).Count | Should -Be 69
        @($r.Id | Select-Object -Unique).Count | Should -Be 69
        foreach ($check in $r) {
            $check.Status | Should -BeIn @('Pass', 'Fail', 'Review', 'Unknown', 'NotApplicable')
            $check.Severity | Should -BeIn @('Critical', 'High', 'Medium', 'Low', 'Informational')
            ($check.Entities -is [array]) | Should -BeTrue
        }
    }
}

Describe 'Discriminating identity and policy semantics' {
    It 'does not mistake a recent failed sign-in for recent successful activity' {
        $e = New-TestEvidence
        Set-TestItems $e users @((New-TestUser @{
            signInActivity = @{ lastSuccessfulSignInDateTime = '2025-01-01T00:00:00Z'; lastSignInDateTime = '2025-12-31T23:59:00Z' }
        }))
        $r = & (Get-Module EntraXray) { param($e) Invoke-XrayAssessment $e (New-XraySettings) 'ID-001' } $e
        $r.Status | Should -Be 'Review'
    }

    It 'treats missing successful-activity telemetry as unknown activity, not proven inactivity' {
        $e = New-TestEvidence
        Set-TestItems $e users @((New-TestUser @{ signInActivity = @{ lastSuccessfulSignInDateTime = $null } }))
        $r = & (Get-Module EntraXray) { param($e) Invoke-XrayAssessment $e (New-XraySettings) 'ID-001' } $e
        $r.Status | Should -Not -Be 'Review'
        $r.Status | Should -Not -Be 'Fail'
        $r = & (Get-Module EntraXray) { param($e) Invoke-XrayAssessment $e (New-XraySettings) 'ID-002' } $e
        $r.Status | Should -Be 'Review'
    }

    It 'ignores disabled users for registration gaps and does not infer a report row for them' {
        $e = New-TestEvidence
        Set-TestItems $e users @((New-TestUser @{ accountEnabled = $false }))
        foreach ($id in @('AUTH-002', 'AUTH-003', 'AUTH-004')) {
            $r = & (Get-Module EntraXray) { param($e, $id) Invoke-XrayAssessment $e (New-XraySettings) $id } $e $id
            $r.Status | Should -Be 'NotApplicable'
        }
    }

    It 'does not pass missing or null registration telemetry for an enabled user' {
        $e = New-TestEvidence
        Set-TestItems $e users @((New-TestUser))
        $r = & (Get-Module EntraXray) { param($e) Invoke-XrayAssessment $e (New-XraySettings) 'AUTH-002' } $e
        $r.Status | Should -Be 'Unknown'
        Set-TestItems $e registrationDetails @(@{ id = $script:TestUserId; isMfaRegistered = $null })
        $r = & (Get-Module EntraXray) { param($e) Invoke-XrayAssessment $e (New-XraySettings) 'AUTH-002' } $e
        $r.Status | Should -Be 'Unknown'
    }

    It 'does not recommend password expiration contrary to modern Microsoft guidance' {
        $e = New-TestEvidence
        Set-TestItems $e users @((New-TestUser))
        $r = & (Get-Module EntraXray) { param($e) Invoke-XrayAssessment $e (New-XraySettings) 'ID-005' } $e
        $r.Status | Should -Be 'Pass'
    }

    It 'does not equate MFA registration with enforcement or SSPR disabled with a registration failure' {
        $e = New-TestEvidence
        Set-TestItems $e users @((New-TestUser))
        Set-TestItems $e registrationDetails @(@{ id = $script:TestUserId; isMfaRegistered = $true; isMfaCapable = $true; isSsprEnabled = $false; isSsprRegistered = $false })
        Set-TestItems $e securityDefaults @(@{ isEnabled = $false })
        $r = & (Get-Module EntraXray) { param($e) Invoke-XrayAssessment $e (New-XraySettings) 'AUTH-001' } $e
        $r.Status | Should -Be 'Fail'
        $r = & (Get-Module EntraXray) { param($e) Invoke-XrayAssessment $e (New-XraySettings) 'AUTH-004' } $e
        $r.Status | Should -Be 'Pass'
    }

    It 'requires an unqualified enabled all-user/all-resource MFA configuration, not OR-compliant-device' {
        $e = New-TestEvidence
        Set-TestItems $e securityDefaults @(@{ isEnabled = $false })
        $p = New-TestCaPolicy
        Set-TestItems $e conditionalAccessPolicies @($p)
        $r = & (Get-Module EntraXray) { param($e) Invoke-XrayAssessment $e (New-XraySettings) 'AUTH-001' } $e
        $r.Status | Should -Be 'Pass'
        $p.grantControls.operator = 'OR'
        $p.grantControls.builtInControls = @('mfa', 'compliantDevice')
        $r = & (Get-Module EntraXray) { param($e) Invoke-XrayAssessment $e (New-XraySettings) 'AUTH-001' } $e
        $r.Status | Should -Be 'Review'
    }

    It 'does not declare universal coverage for each narrowing CA condition' -ForEach @(
        @{ Field = 'excludeUsers'; Kind = 'users'; Value = @('break-glass') }
        @{ Field = 'excludeGroups'; Kind = 'users'; Value = @('excluded-group') }
        @{ Field = 'excludeRoles'; Kind = 'users'; Value = @('excluded-role') }
        @{ Field = 'excludeGuestsOrExternalUsers'; Kind = 'users'; Value = @{ guestOrExternalUserTypes = 'b2bCollaborationGuest' } }
        @{ Field = 'excludeApplications'; Kind = 'applications'; Value = @('excluded-app') }
        @{ Field = 'applicationFilter'; Kind = 'applications'; Value = @{ mode = 'exclude'; rule = 'x' } }
        @{ Field = 'platforms'; Kind = 'conditions'; Value = @{ includePlatforms = @('windows') } }
        @{ Field = 'locations'; Kind = 'conditions'; Value = @{ includeLocations = @('trusted') } }
        @{ Field = 'devices'; Kind = 'conditions'; Value = @{ deviceFilter = @{ mode = 'include'; rule = 'x' } } }
        @{ Field = 'signInRiskLevels'; Kind = 'conditions'; Value = @('high') }
        @{ Field = 'userRiskLevels'; Kind = 'conditions'; Value = @('high') }
        @{ Field = 'clientAppTypes'; Kind = 'conditions'; Value = @('browser') }
        @{ Field = 'authenticationFlows'; Kind = 'conditions'; Value = @{ transferMethods = 'deviceCodeFlow' } }
        @{ Field = 'futureNarrowingCondition'; Kind = 'conditions'; Value = @{ value = 'limited' } }
    ) {
        param($Field, $Kind, $Value)
        $e = New-TestEvidence
        Set-TestItems $e securityDefaults @(@{ isEnabled = $false })
        $p = New-TestCaPolicy
        if ($Kind -eq 'conditions') { $p.conditions[$Field] = $Value } else { $p.conditions[$Kind][$Field] = $Value }
        Set-TestItems $e conditionalAccessPolicies @($p)
        $r = & (Get-Module EntraXray) { param($e) Invoke-XrayAssessment $e (New-XraySettings) 'AUTH-001' } $e
        $r.Status | Should -Be 'Review'
    }

    It 'accepts an AND MFA requirement and distinguishes report-only and disabled controls' {
        $e = New-TestEvidence
        Set-TestItems $e securityDefaults @(@{ isEnabled = $false })
        $p = New-TestCaPolicy
        $p.grantControls.builtInControls = @('mfa', 'compliantDevice')
        Set-TestItems $e conditionalAccessPolicies @($p)
        $r = & (Get-Module EntraXray) { param($e) Invoke-XrayAssessment $e (New-XraySettings) 'AUTH-001' } $e
        $r.Status | Should -Be 'Pass'
        $p.state = 'enabledForReportingButNotEnforced'
        $r = & (Get-Module EntraXray) { param($e) Invoke-XrayAssessment $e (New-XraySettings) 'AUTH-001' } $e
        $r.Status | Should -Be 'Fail'
        $p.state = 'disabled'
        $r = & (Get-Module EntraXray) { param($e) Invoke-XrayAssessment $e (New-XraySettings) 'AUTH-001' } $e
        $r.Status | Should -Be 'Fail'
    }

    It 'resolves authentication strengths instead of treating any strength identifier as MFA' {
        $e = New-TestEvidence
        Set-TestItems $e securityDefaults @(@{ isEnabled = $false })
        $p = New-TestCaPolicy
        $p.grantControls.builtInControls = @()
        $p.grantControls.authenticationStrength = @{ id = 'custom-strength' }
        Set-TestItems $e conditionalAccessPolicies @($p)
        Set-TestItems $e authenticationStrengthPolicies @(@{ id = 'custom-strength'; requirementsSatisfied = 'mfa'; allowedCombinations = @('fido2') })
        $r = & (Get-Module EntraXray) { param($e) Invoke-XrayAssessment $e (New-XraySettings) 'AUTH-001' } $e
        $r.Status | Should -Be 'Pass'
        $r = & (Get-Module EntraXray) { param($e) Invoke-XrayAssessment $e (New-XraySettings) 'CA-005' } $e
        $r.Status | Should -Be 'Pass'
        $e.Sources.authenticationStrengthPolicies.Items[0].requirementsSatisfied = 'none'
        $r = & (Get-Module EntraXray) { param($e) Invoke-XrayAssessment $e (New-XraySettings) 'AUTH-001' } $e
        $r.Status | Should -Be 'Review'
    }

    It 'requires both legacy client types and blocking rather than a scoped or report-only policy' {
        $e = New-TestEvidence
        Set-TestItems $e securityDefaults @(@{ isEnabled = $false })
        $p = New-TestCaPolicy
        $p.conditions.clientAppTypes = @('exchangeActiveSync', 'other')
        $p.grantControls.builtInControls = @('block')
        Set-TestItems $e conditionalAccessPolicies @($p)
        $r = & (Get-Module EntraXray) { param($e) Invoke-XrayAssessment $e (New-XraySettings) 'CA-004' } $e
        $r.Status | Should -Be 'Pass'
        $p.conditions.clientAppTypes = @('other')
        $r = & (Get-Module EntraXray) { param($e) Invoke-XrayAssessment $e (New-XraySettings) 'CA-004' } $e
        $r.Status | Should -Be 'Review'
    }

    It 'treats missing critical fields and invalid dates as Unknown, never as Pass' {
        $e = New-TestEvidence
        Set-TestItems $e users @(@{ id = 'malformed' })
        $r = & (Get-Module EntraXray) { param($e) Invoke-XrayAssessment $e (New-XraySettings) 'ID-005' } $e
        $r.Status | Should -Be 'Unknown'
        Set-TestItems $e users @((New-TestUser @{ signInActivity = @{ lastSuccessfulSignInDateTime = 'not-a-date' } }))
        $r = & (Get-Module EntraXray) { param($e) Invoke-XrayAssessment $e (New-XraySettings) 'ID-001' } $e
        $r.Status | Should -Be 'Unknown'
        $r.Limitations.Count | Should -BeGreaterThan 0
    }

    It 'does not pass an absent singleton policy or borrow premium activity from a basic user record' {
        $e = New-TestEvidence
        Set-TestItems $e authorizationPolicy @()
        $r = & (Get-Module EntraXray) { param($e) Invoke-XrayAssessment $e (New-XraySettings) 'AUTH-009' } $e
        $r.Status | Should -Be 'Unknown'
        Set-TestItems $e users @((New-TestUser))
        Set-TestItems $e userSignInActivity @()
        $r = & (Get-Module EntraXray) { param($e) Invoke-XrayAssessment $e (New-XraySettings) 'ID-001' } $e
        $r.Status | Should -Be 'Unknown'
    }
}

Describe 'Privilege and application relationships' {
    It 'counts distinct effective group members, not group objects or duplicate assignments' {
        $e = New-TestEvidence
        Set-TestItems $e users @((New-TestUser @{ id = 'admin-1' }), (New-TestUser @{ id = 'admin-2' }))
        Set-TestItems $e groups @(@{ id = 'role-group'; isAssignableToRole = $true })
        Set-TestItems $e roleGroupMembers @(
            @{ id = 'admin-1'; '@odata.type' = '#microsoft.graph.user'; _ParentId = 'role-group' }
            @{ id = 'admin-2'; '@odata.type' = '#microsoft.graph.user'; _ParentId = 'role-group' }
        )
        Set-TestItems $e roleAssignments @(
            @{ id = 'ra-1'; principalId = 'role-group'; roleDefinitionId = $script:GlobalAdminRoleId; directoryScopeId = '/' }
            @{ id = 'ra-2'; principalId = 'admin-1'; roleDefinitionId = $script:GlobalAdminRoleId; directoryScopeId = '/' }
        )
        $r = & (Get-Module EntraXray) { param($e) Invoke-XrayAssessment $e (New-XraySettings) 'PRIV-002' } $e
        $r.Status | Should -Be 'Pass'
    }

    It 'does not count scoped roles, expired eligibility, or service principals as available emergency human admins' {
        $e = New-TestEvidence
        Set-TestItems $e servicePrincipals @(@{ id = 'sp-admin' })
        Set-TestItems $e roleAssignments @(
            @{ id = 'ra-1'; principalId = 'sp-admin'; roleDefinitionId = $script:GlobalAdminRoleId; directoryScopeId = '/' }
            @{ id = 'ra-2'; principalId = 'scoped-user'; roleDefinitionId = $script:GlobalAdminRoleId; directoryScopeId = '/administrativeUnits/unit-1' }
        )
        Set-TestItems $e roleEligibilityScheduleInstances @(@{ id = 'eligible-1'; principalId = 'expired-user'; roleDefinitionId = $script:GlobalAdminRoleId; directoryScopeId = '/'; startDateTime = '2024-01-01T00:00:00Z'; endDateTime = '2025-12-01T00:00:00Z' })
        $r = & (Get-Module EntraXray) { param($e) Invoke-XrayAssessment $e (New-XraySettings) 'PRIV-002' } $e
        $r.Status | Should -Be 'Review'
    }

    It 'keeps current eligible assignments distinct from active grants and honors declared emergency exceptions' {
        $e = New-TestEvidence
        Set-TestItems $e users @((New-TestUser @{ id = 'human-1' }), (New-TestUser @{ id = 'human-2' }))
        Set-TestItems $e roleEligibilityScheduleInstances @(
            @{ id = 'el-1'; principalId = 'human-1'; roleDefinitionId = $script:GlobalAdminRoleId; directoryScopeId = '/'; startDateTime = '2025-01-01T00:00:00Z'; endDateTime = $null }
            @{ id = 'el-2'; principalId = 'human-2'; roleDefinitionId = $script:GlobalAdminRoleId; directoryScopeId = '/'; startDateTime = '2025-01-01T00:00:00Z'; endDateTime = '2026-02-01T00:00:00Z' }
        )
        $r = & (Get-Module EntraXray) { param($e) Invoke-XrayAssessment $e (New-XraySettings) 'PRIV-002' } $e
        $r.Status | Should -Be 'Pass'
        $r = & (Get-Module EntraXray) { param($e) Invoke-XrayAssessment $e (New-XraySettings) 'PRIV-001' } $e
        $r.Status | Should -Be 'Pass'
        Set-TestItems $e roleAssignmentScheduleInstances @(@{ id = 'standing-1'; principalId = $script:TestUserId; roleDefinitionId = $script:GlobalAdminRoleId; assignmentType = 'Assigned'; endDateTime = $null; directoryScopeId = '/' })
        $r = & (Get-Module EntraXray) {
            param($e, $id)
            Invoke-XrayAssessment $e (New-XraySettings @{ EmergencyAccessAccountId = @($id) }) 'PRIV-003'
        } $e $script:TestUserId
        $r.Status | Should -Be 'Pass'
    }

    It 'does not report merely requested API permissions as consented or privileged grants' {
        $e = New-TestEvidence
        $a = New-TestApplication
        $a.requiredResourceAccess = @(@{ resourceAppId = '00000003-0000-0000-c000-000000000000'; resourceAccess = @(@{ id = 'permission-1'; type = 'Role' }) })
        Set-TestItems $e applications @($a)
        $r = & (Get-Module EntraXray) { param($e) Invoke-XrayAssessment $e (New-XraySettings) 'APP-009' } $e
        $r.Status | Should -Be 'Pass'
    }

    It 'allows native loopback redirects and does not label multitenancy itself a confirmed vulnerability' {
        $e = New-TestEvidence
        $a = New-TestApplication @{ signInAudience = 'AzureADMultipleOrgs' }
        $a.web.redirectUris = @('http://localhost:5000/callback', 'http://127.0.0.1/callback', 'https://example.test/callback')
        Set-TestItems $e applications @($a)
        $r = & (Get-Module EntraXray) { param($e) Invoke-XrayAssessment $e (New-XraySettings) 'APP-007' } $e
        $r.Status | Should -Be 'Pass'
        $r = & (Get-Module EntraXray) { param($e) Invoke-XrayAssessment $e (New-XraySettings) 'APP-006' } $e
        $r.Status | Should -Be 'Review'
    }

    It 'does not treat failed legacy sign-ins as successful legacy authentication' {
        $e = New-TestEvidence
        Set-TestItems $e signIns @(@{ id = 'failed'; clientAppUsed = 'Exchange ActiveSync'; status = @{ errorCode = 50126 }; authenticationRequirement = 'singleFactorAuthentication' })
        $r = & (Get-Module EntraXray) { param($e) Invoke-XrayAssessment $e (New-XraySettings) 'OPS-003' } $e
        $r.Status | Should -Be 'Pass'
    }

    It 'never upgrades partial, skipped, absent, or malformed source evidence to a healthy finding' -ForEach @(
        @{ State = 'Partial' }, @{ State = 'Skipped' }, @{ State = 'Absent' }
    ) {
        param($State)
        $e = New-TestEvidence
        if ($State -eq 'Absent') { $e.Sources.Remove('users') } else { $e.Sources.users.State = $State }
        $r = & (Get-Module EntraXray) { param($e) Invoke-XrayAssessment $e (New-XraySettings) 'ID-001' } $e
        $r.Status | Should -Be 'Unknown'
    }
}
