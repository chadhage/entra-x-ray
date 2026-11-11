$script:TestTenantId = '11111111-1111-4111-8111-111111111111'
$script:TestUserId = '22222222-2222-4222-8222-222222222222'
$script:TestNow = '2026-01-01T00:00:00Z'
$script:GlobalAdminRoleId = '62e90394-69f5-4237-9190-012177145e10'

function New-TestEvidence {
    $sources = [ordered]@{}
    $ids = @(
        'organization', 'domains', 'federationConfigurations', 'subscribedSkus',
        'users', 'userSignInActivity', 'deletedUsers', 'deletedGroups', 'deletedApplications', 'deletedServicePrincipals',
        'groups', 'groupOwners', 'roleGroupMembers', 'groupLifecyclePolicies',
        'applications', 'applicationOwners', 'federatedIdentityCredentials',
        'servicePrincipals', 'servicePrincipalOwners', 'appRoleAssignments', 'oauth2PermissionGrants',
        'roleDefinitions', 'roleAssignments', 'roleAssignmentScheduleInstances',
        'roleEligibilityScheduleInstances', 'roleGroupAssignmentScheduleInstances', 'roleGroupEligibilityScheduleInstances',
        'roleManagementPolicies', 'roleManagementPolicyAssignments',
        'administrativeUnits', 'administrativeUnitMembers', 'authorizationPolicy', 'securityDefaults',
        'authenticationMethodsPolicy', 'authenticationMethodConfigurations', 'authenticationStrengthPolicies',
        'conditionalAccessPolicies', 'namedLocations', 'authenticationContextClassReferences',
        'adminConsentRequestPolicy', 'permissionGrantPolicies', 'crossTenantDefault', 'crossTenantPartners',
        'activityBasedTimeoutPolicies', 'tokenLifetimePolicies', 'appManagementPolicy', 'appManagementPolicies',
        'identityProviders', 'devices', 'registrationDetails', 'riskyUsers', 'riskDetections',
        'signIns', 'directoryAudits', 'provisioningLogs', 'secureScores', 'secureScoreControlProfiles',
        'accessReviewDefinitions', 'accessReviewInstances', 'accessReviewDecisions', 'entitlementCatalogs',
        'accessPackages', 'accessPackageAssignmentPolicies', 'accessPackageAssignments', 'connectedOrganizations',
        'termsOfUse', 'lifecycleWorkflows', 'lifecycleWorkflowRuns',
        'deviceRegistrationPolicy', 'directoryRecommendations', 'riskyServicePrincipals',
        'servicePrincipalRiskDetections', 'nonInteractiveSignIns', 'servicePrincipalSignIns', 'managedIdentitySignIns'
    )
    foreach ($id in $ids) {
        $sources[$id] = @{
            Id = $id; State = 'Complete'; Items = @(); ItemCount = 0; Pages = 1
            Errors = @(); Requested = $true; ApiVersion = 'v1.0'; Uri = "https://graph.microsoft.com/v1.0/$id"
            CollectedAtUtc = $script:TestNow; Scope = 'Test fixture'
        }
    }
    $e = @{
        SchemaVersion = '1.0'; ToolVersion = '1.0.0'; TenantId = $script:TestTenantId
        Environment = 'Global'; StartedAtUtc = '2025-12-31T23:59:00Z'; CompletedAtUtc = $script:TestNow
        Settings = @{}; LogWindow = @{ StartUtc = '2025-12-25T00:00:00Z'; EndUtc = $script:TestNow }
        Sources = $sources
    }
    Set-TestItems $e organization @(@{
        id = $script:TestTenantId; displayName = 'Test tenant'; onPremisesSyncEnabled = $false
        onPremisesLastSyncDateTime = $null
    })
    Set-TestItems $e securityDefaults @(@{ id = 'default'; isEnabled = $true })
    Set-TestItems $e authorizationPolicy @(@{
        id = 'authorizationPolicy'; allowEmailVerifiedUsersToJoinOrganization = $false
        allowInvitesFrom = 'adminsAndGuestInviters'
        guestUserRoleId = '2af84b1e-32c8-42b7-82bc-daa82404023b'
        defaultUserRolePermissions = @{ allowedToCreateApps = $false; permissionGrantPoliciesAssigned = @() }
    })
    Set-TestItems $e authenticationMethodsPolicy @(@{ id = 'authenticationMethodsPolicy'; policyMigrationState = 'migrationComplete' })
    Set-TestItems $e authenticationMethodConfigurations @(@{ id = 'Fido2'; state = 'enabled' })
    Set-TestItems $e adminConsentRequestPolicy @(@{ id = 'adminConsentRequestPolicy'; isEnabled = $true })
    Set-TestItems $e crossTenantDefault @(@{
        id = 'default'; inboundTrust = @{ isMfaAccepted = $false }
        b2bCollaborationInbound = @{
            applications = @{ accessType = 'blocked'; targets = @(@{ target = 'AllApplications'; targetType = 'application' }) }
            usersAndGroups = @{ accessType = 'blocked'; targets = @(@{ target = 'AllUsers'; targetType = 'user' }) }
        }
    })
    Set-TestItems $e roleDefinitions @(@{
        id = $script:GlobalAdminRoleId; templateId = $script:GlobalAdminRoleId
        displayName = 'Global Administrator'; isPrivileged = $true
    })
    $e
}

function Set-TestItems {
    param($Evidence, [string]$Source, [object[]]$Items)
    $Evidence.Sources[$Source].Items = @($Items)
    $Evidence.Sources[$Source].ItemCount = @($Items).Count
    if ($Source -eq 'users') {
        $activity = @(foreach ($user in $Items) {
            $record = @{ id = $user['id'] }
            if ($user.Contains('signInActivity')) { $record.signInActivity = $user['signInActivity'] }
            $record
        })
        $Evidence.Sources.userSignInActivity.Items = $activity
        $Evidence.Sources.userSignInActivity.ItemCount = $activity.Count
    }
}

function New-TestUser {
    param([hashtable]$Override = @{})
    $u = @{
        id = $script:TestUserId; displayName = 'Test member'; userPrincipalName = 'member@example.test'
        accountEnabled = $true; userType = 'Member'; onPremisesSyncEnabled = $false
        createdDateTime = '2025-01-01T00:00:00Z'; externalUserState = 'Accepted'
        externalUserStateChangeDateTime = '2025-01-01T00:00:00Z'; passwordPolicies = 'DisablePasswordExpiration'
        signInActivity = @{ lastSuccessfulSignInDateTime = '2025-12-31T00:00:00Z'; lastSignInDateTime = '2025-12-31T00:00:00Z' }
    }
    foreach ($key in $Override.Keys) { $u[$key] = $Override[$key] }
    $u
}

function New-TestApplication {
    param([hashtable]$Override = @{})
    $a = @{
        id = 'app-1'; appId = 'client-1'; displayName = 'Test application'; signInAudience = 'AzureADMyOrg'
        passwordCredentials = @(); keyCredentials = @()
        web = @{ redirectUris = @('https://example.test/callback'); implicitGrantSettings = @{ enableIdTokenIssuance = $false; enableAccessTokenIssuance = $false } }
        spa = @{ redirectUris = @() }; publicClient = @{ redirectUris = @() }
    }
    foreach ($key in $Override.Keys) { $a[$key] = $Override[$key] }
    $a
}

function New-TestCaPolicy {
    param([hashtable]$Override = @{})
    $p = @{
        id = 'ca-1'; displayName = 'Test policy'; state = 'enabled'
        conditions = @{
            users = @{ includeUsers = @('All'); excludeUsers = @(); includeGroups = @(); excludeGroups = @(); includeRoles = @(); excludeRoles = @() }
            applications = @{ includeApplications = @('All'); excludeApplications = @(); includeUserActions = @(); applicationFilter = $null; includeAuthenticationContextClassReferences = @() }
            clientAppTypes = @('all'); platforms = $null; locations = $null; devices = $null
            signInRiskLevels = @(); userRiskLevels = @(); servicePrincipalRiskLevels = @()
            clientApplications = $null; authenticationFlows = $null
        }
        grantControls = @{ operator = 'AND'; builtInControls = @('mfa'); authenticationStrength = $null; termsOfUse = @(); customAuthenticationFactors = @() }
        sessionControls = $null
    }
    foreach ($key in $Override.Keys) { $p[$key] = $Override[$key] }
    $p
}

function New-TestHttpError {
    param([int]$Status, [string]$RetryAfter = '')
    $ex = [System.Net.Http.HttpRequestException]::new("Synthetic HTTP $Status")
    $ex.Data['StatusCode'] = $Status
    if ($RetryAfter) { $ex.Data['RetryAfter'] = $RetryAfter }
    $ex
}

function Get-TestRuleCases {
    @(
        @{ Id = 'TEN-001'; Status = 'Fail'; Mutate = { param($e) Set-TestItems $e organization @(@{ id = $script:TestTenantId; onPremisesSyncEnabled = $true; onPremisesLastSyncDateTime = '2025-12-29T00:00:00Z' }) } }
        @{ Id = 'TEN-002'; Status = 'Fail'; Mutate = { param($e) Set-TestItems $e federationConfigurations @(@{ id = 'fed-1'; issuerUri = 'http://idp.example.test'; passiveSignInUri = 'http://idp.example.test/login'; activeSignInUri = 'https://idp.example.test/ws' }) } }
        @{ Id = 'TEN-003'; Status = 'Review'; Mutate = { param($e) Set-TestItems $e domains @(@{ id = 'example.test'; isVerified = $false }) } }
        @{ Id = 'TEN-004'; Status = 'Review'; Mutate = { param($e) Set-TestItems $e subscribedSkus @(@{ id = 'sku-1'; skuPartNumber = 'TEST'; consumedUnits = 11; prepaidUnits = @{ enabled = 10 } }) } }
        @{ Id = 'AUTH-001'; Status = 'Fail'; Mutate = { param($e) Set-TestItems $e securityDefaults @(@{ isEnabled = $false }) } }
        @{ Id = 'AUTH-002'; Status = 'Fail'; Mutate = { param($e) Set-TestItems $e users @((New-TestUser)); Set-TestItems $e registrationDetails @(@{ id = $script:TestUserId; isMfaRegistered = $false; isMfaCapable = $true; isSsprEnabled = $true; isSsprRegistered = $true }) } }
        @{ Id = 'AUTH-003'; Status = 'Fail'; Mutate = { param($e) Set-TestItems $e users @((New-TestUser)); Set-TestItems $e registrationDetails @(@{ id = $script:TestUserId; isMfaRegistered = $true; isMfaCapable = $false; isSsprEnabled = $true; isSsprRegistered = $true }) } }
        @{ Id = 'AUTH-004'; Status = 'Review'; Mutate = { param($e) Set-TestItems $e users @((New-TestUser)); Set-TestItems $e registrationDetails @(@{ id = $script:TestUserId; isMfaRegistered = $true; isMfaCapable = $true; isSsprEnabled = $true; isSsprRegistered = $false }) } }
        @{ Id = 'AUTH-005'; Status = 'Review'; Mutate = { param($e) Set-TestItems $e authenticationMethodConfigurations @(@{ id = 'Fido2'; state = 'disabled' }) } }
        @{ Id = 'AUTH-006'; Status = 'Review'; Mutate = { param($e) Set-TestItems $e authenticationMethodConfigurations @(@{ id = 'Sms'; state = 'enabled' }) } }
        @{ Id = 'AUTH-007'; Status = 'Review'; Mutate = { param($e) Set-TestItems $e authenticationMethodsPolicy @(@{ policyMigrationState = 'migrationInProgress' }) } }
        @{ Id = 'AUTH-008'; Status = 'Review'; Mutate = { param($e) Set-TestItems $e authenticationMethodConfigurations @(@{ id = 'TemporaryAccessPass'; state = 'enabled'; defaultLifetimeInMinutes = 120; isUsableOnce = $false }) } }
        @{ Id = 'AUTH-009'; Status = 'Review'; Mutate = { param($e) $e.Sources.authorizationPolicy.Items[0].allowEmailVerifiedUsersToJoinOrganization = $true } }
        @{ Id = 'AUTH-010'; Status = 'Review'; Mutate = { param($e) $e.Sources.authorizationPolicy.Items[0].defaultUserRolePermissions.allowedToCreateApps = $true } }
        @{ Id = 'AUTH-011'; Status = 'Review'; Mutate = { param($e) $e.Sources.authorizationPolicy.Items[0].defaultUserRolePermissions.permissionGrantPoliciesAssigned = @('managePermissionGrantsForSelf.microsoft-user-default-low') } }
        @{ Id = 'AUTH-012'; Status = 'Review'; Mutate = { param($e) Set-TestItems $e adminConsentRequestPolicy @(@{ isEnabled = $false }) } }
        @{ Id = 'CA-001'; Status = 'Review'; Mutate = { param($e) Set-TestItems $e conditionalAccessPolicies @((New-TestCaPolicy @{ state = 'enabledForReportingButNotEnforced' })) } }
        @{ Id = 'CA-002'; Status = 'Review'; Mutate = { param($e) Set-TestItems $e conditionalAccessPolicies @((New-TestCaPolicy @{ state = 'disabled' })) } }
        @{ Id = 'CA-003'; Status = 'Review'; Mutate = { param($e) $p = New-TestCaPolicy; $p.conditions.users.excludeUsers = @($script:TestUserId); Set-TestItems $e conditionalAccessPolicies @($p) } }
        @{ Id = 'CA-004'; Status = 'Review'; Mutate = { param($e) Set-TestItems $e securityDefaults @(@{ isEnabled = $false }) } }
        @{ Id = 'CA-005'; Status = 'Review'; Mutate = { param($e) Set-TestItems $e conditionalAccessPolicies @((New-TestCaPolicy)) } }
        @{ Id = 'CA-006'; Status = 'Review'; Mutate = { param($e) Set-TestItems $e conditionalAccessPolicies @((New-TestCaPolicy)) } }
        @{ Id = 'CA-007'; Status = 'Fail'; Mutate = { param($e) Set-TestItems $e namedLocations @(@{ id = 'loc-1'; isTrusted = $true; ipRanges = @(@{ cidrAddress = '0.0.0.0/0' }) }) } }
        @{ Id = 'CA-008'; Status = 'Review'; Mutate = { param($e) $p = New-TestCaPolicy; $p.sessionControls = @{ persistentBrowser = @{ isEnabled = $true; mode = 'always' } }; Set-TestItems $e conditionalAccessPolicies @($p) } }
        @{ Id = 'ID-001'; Status = 'Review'; Mutate = { param($e) Set-TestItems $e users @((New-TestUser @{ signInActivity = @{ lastSuccessfulSignInDateTime = '2025-01-01T00:00:00Z'; lastSignInDateTime = '2025-12-31T00:00:00Z' } })) } }
        @{ Id = 'ID-002'; Status = 'Review'; Mutate = { param($e) Set-TestItems $e users @((New-TestUser @{ signInActivity = @{ lastSuccessfulSignInDateTime = $null } })) } }
        @{ Id = 'ID-003'; Status = 'Review'; Mutate = { param($e) Set-TestItems $e users @((New-TestUser @{ userType = 'Guest'; signInActivity = @{ lastSuccessfulSignInDateTime = '2025-01-01T00:00:00Z' } })) } }
        @{ Id = 'ID-004'; Status = 'Review'; Mutate = { param($e) Set-TestItems $e users @((New-TestUser @{ userType = 'Guest'; externalUserState = 'PendingAcceptance'; externalUserStateChangeDateTime = '2025-01-01T00:00:00Z' })) } }
        @{ Id = 'ID-005'; Status = 'Fail'; Mutate = { param($e) Set-TestItems $e users @((New-TestUser @{ passwordPolicies = 'DisableStrongPassword' })) } }
        @{ Id = 'PRIV-001'; Status = 'Review'; Mutate = { param($e) $a = @(1..6 | ForEach-Object { @{ id = "ra-$_"; principalId = "admin-$_"; roleDefinitionId = $script:GlobalAdminRoleId; directoryScopeId = '/' } }); Set-TestItems $e roleAssignments $a; Set-TestItems $e users @(1..6 | ForEach-Object { New-TestUser @{ id = "admin-$_" } }) } }
        @{ Id = 'PRIV-002'; Status = 'Review'; Mutate = { param($e) } }
        @{ Id = 'PRIV-003'; Status = 'Review'; Mutate = { param($e) Set-TestItems $e roleAssignmentScheduleInstances @(@{ id = 'standing-1'; principalId = $script:TestUserId; roleDefinitionId = $script:GlobalAdminRoleId; assignmentType = 'Assigned'; endDateTime = $null; directoryScopeId = '/' }) } }
        @{ Id = 'PRIV-004'; Status = 'Review'; Mutate = { param($e) Set-TestItems $e users @((New-TestUser @{ userType = 'Guest' })); Set-TestItems $e roleAssignments @(@{ id = 'ra-1'; principalId = $script:TestUserId; roleDefinitionId = $script:GlobalAdminRoleId; directoryScopeId = '/' }) } }
        @{ Id = 'PRIV-005'; Status = 'Review'; Mutate = { param($e) Set-TestItems $e servicePrincipals @(@{ id = 'sp-1'; displayName = 'Automation' }); Set-TestItems $e roleAssignments @(@{ id = 'ra-1'; principalId = 'sp-1'; roleDefinitionId = $script:GlobalAdminRoleId; directoryScopeId = '/' }) } }
        @{ Id = 'PRIV-006'; Status = 'Review'; Mutate = { param($e) Set-TestItems $e roleManagementPolicies @(@{ id = 'pim-1'; rules = @(@{ id = 'Enablement_EndUser_Assignment'; '@odata.type' = '#microsoft.graph.unifiedRoleManagementPolicyEnablementRule'; enabledRules = @(); target = @{ caller = 'EndUser'; level = 'Assignment' } }) }) } }
        @{ Id = 'PRIV-007'; Status = 'Review'; Mutate = { param($e) Set-TestItems $e groups @(@{ id = 'group-1'; displayName = 'Admins'; isAssignableToRole = $true }) } }
        @{ Id = 'PRIV-008'; Status = 'Review'; Mutate = { param($e) } }
        @{ Id = 'APP-001'; Status = 'Review'; Mutate = { param($e) Set-TestItems $e applications @((New-TestApplication @{ passwordCredentials = @(@{ keyId = 'k1'; startDateTime = '2025-01-01T00:00:00Z'; endDateTime = '2025-12-01T00:00:00Z' }) })) } }
        @{ Id = 'APP-002'; Status = 'Review'; Mutate = { param($e) Set-TestItems $e servicePrincipals @(@{ id = 'sp-1'; displayName = 'SAML app'; passwordCredentials = @(); keyCredentials = @(@{ keyId = 'k1'; startDateTime = '2025-12-01T00:00:00Z'; endDateTime = '2026-01-15T00:00:00Z' }) }) } }
        @{ Id = 'APP-003'; Status = 'Review'; Mutate = { param($e) Set-TestItems $e applications @((New-TestApplication @{ passwordCredentials = @(@{ keyId = 'k1'; startDateTime = '2025-12-01T00:00:00Z'; endDateTime = '2027-01-01T00:00:00Z' }) })) } }
        @{ Id = 'APP-004'; Status = 'Review'; Mutate = { param($e) Set-TestItems $e applications @((New-TestApplication)) } }
        @{ Id = 'APP-005'; Status = 'Review'; Mutate = { param($e) Set-TestItems $e servicePrincipals @(@{ id = 'sp-1'; displayName = 'Local app'; servicePrincipalType = 'Application'; accountEnabled = $true; appOwnerOrganizationId = $script:TestTenantId }) } }
        @{ Id = 'APP-006'; Status = 'Review'; Mutate = { param($e) Set-TestItems $e applications @((New-TestApplication @{ signInAudience = 'AzureADMultipleOrgs' })) } }
        @{ Id = 'APP-007'; Status = 'Fail'; Mutate = { param($e) $a = New-TestApplication; $a.web.redirectUris = @('http://evil.example.test/callback'); Set-TestItems $e applications @($a) } }
        @{ Id = 'APP-008'; Status = 'Review'; Mutate = { param($e) $a = New-TestApplication; $a.web.implicitGrantSettings.enableAccessTokenIssuance = $true; Set-TestItems $e applications @($a) } }
        @{ Id = 'APP-009'; Status = 'Review'; Mutate = { param($e) Set-TestItems $e servicePrincipals @(@{ id = 'graph-sp'; appId = '00000003-0000-0000-c000-000000000000'; displayName = 'Microsoft Graph'; appRoles = @(@{ id = 'permission-1'; value = 'RoleManagement.ReadWrite.Directory' }) }); Set-TestItems $e appRoleAssignments @(@{ id = 'grant-1'; principalId = 'client-sp'; resourceId = 'graph-sp'; appRoleId = 'permission-1'; _ParentId = 'client-sp' }) } }
        @{ Id = 'APP-010'; Status = 'Review'; Mutate = { param($e) Set-TestItems $e oauth2PermissionGrants @(@{ id = 'consent-1'; consentType = 'AllPrincipals'; clientId = 'client-sp'; resourceId = 'graph-sp'; scope = 'Directory.ReadWrite.All User.Read' }) } }
        @{ Id = 'APP-011'; Status = 'Fail'; Mutate = { param($e) Set-TestItems $e servicePrincipals @(@{ id = 'legacy-sp'; appId = '00000002-0000-0000-c000-000000000000' }); Set-TestItems $e appRoleAssignments @(@{ id = 'grant-1'; principalId = 'client-sp'; resourceId = 'legacy-sp'; appRoleId = 'old-perm' }) } }
        @{ Id = 'APP-012'; Status = 'Fail'; Mutate = { param($e) Set-TestItems $e federatedIdentityCredentials @(@{ id = 'fic-1'; issuer = 'http://issuer.example.test'; subject = 'repo:org/repo:ref:refs/heads/main'; audiences = @('api://AzureADTokenExchange'); _ParentId = 'app-1' }) } }
        @{ Id = 'APP-013'; Status = 'Review'; Mutate = { param($e) Set-TestItems $e federatedIdentityCredentials @(@{ id = 'fic-1'; issuer = 'https://token.actions.githubusercontent.com'; subject = 'repo:org/repo:ref:refs/heads/main'; audiences = @('api://AzureADTokenExchange'); _ParentId = 'app-1' }) } }
        @{ Id = 'APP-014'; Status = 'Review'; Mutate = { param($e) Set-TestItems $e servicePrincipals @(@{ id = 'sp-1'; appId = 'client-1'; displayName = 'Enterprise app'; servicePrincipalType = 'Application'; accountEnabled = $true; appRoleAssignmentRequired = $false }) } }
        @{ Id = 'DEV-001'; Status = 'Review'; Mutate = { param($e) Set-TestItems $e devices @(@{ id = 'dev-1'; accountEnabled = $true; approximateLastSignInDateTime = '2025-01-01T00:00:00Z' }) } }
        @{ Id = 'DEV-002'; Status = 'Review'; Mutate = { param($e) Set-TestItems $e devices @(@{ id = 'dev-1'; accountEnabled = $true; isCompliant = $false }) } }
        @{ Id = 'DEV-003'; Status = 'Review'; Mutate = { param($e) Set-TestItems $e devices @(@{ id = 'dev-1'; accountEnabled = $true; isManaged = $false }) } }
        @{ Id = 'EXT-001'; Status = 'Review'; Mutate = { param($e) $e.Sources.authorizationPolicy.Items[0].allowInvitesFrom = 'everyone' } }
        @{ Id = 'EXT-002'; Status = 'Review'; Mutate = { param($e) $e.Sources.authorizationPolicy.Items[0].guestUserRoleId = '10dae51f-b6af-4016-8d66-8c2a99b929b3' } }
        @{ Id = 'EXT-003'; Status = 'Review'; Mutate = { param($e) $e.Sources.crossTenantDefault.Items[0].inboundTrust.isMfaAccepted = $true } }
        @{ Id = 'EXT-004'; Status = 'Review'; Mutate = { param($e) $p = $e.Sources.crossTenantDefault.Items[0]; $p.b2bCollaborationInbound.applications.accessType = 'allowed'; $p.b2bCollaborationInbound.usersAndGroups.accessType = 'allowed' } }
        @{ Id = 'GOV-001'; Status = 'Review'; Mutate = { param($e) } }
        @{ Id = 'GOV-002'; Status = 'Review'; Mutate = { param($e) Set-TestItems $e accessReviewDefinitions @(@{ id = 'review-1'; displayName = 'Review'; settings = @{ defaultDecisionEnabled = $true; defaultDecision = 'Approve' } }) } }
        @{ Id = 'GOV-003'; Status = 'Review'; Mutate = { param($e) Set-TestItems $e accessPackageAssignmentPolicies @(@{ id = 'package-policy-1'; displayName = 'Policy'; expiration = @{ type = 'noExpiration' } }) } }
        @{ Id = 'GOV-004'; Status = 'Review'; Mutate = { param($e) Set-TestItems $e lifecycleWorkflows @(@{ id = 'workflow-1'; displayName = 'Offboarding'; isEnabled = $false }) } }
        @{ Id = 'OPS-001'; Status = 'Fail'; Mutate = { param($e) Set-TestItems $e riskyUsers @(@{ id = $script:TestUserId; userDisplayName = 'At risk'; riskState = 'confirmedCompromised'; riskLevel = 'high' }) } }
        @{ Id = 'OPS-002'; Status = 'Fail'; Mutate = { param($e) Set-TestItems $e riskDetections @(@{ id = 'risk-1'; riskState = 'atRisk'; riskLevel = 'high'; riskEventType = 'unfamiliarFeatures' }) } }
        @{ Id = 'OPS-003'; Status = 'Fail'; Mutate = { param($e) Set-TestItems $e signIns @(@{ id = 'sign-in-1'; status = @{ errorCode = 0 }; clientAppUsed = 'Exchange ActiveSync'; authenticationRequirement = 'singleFactorAuthentication' }) } }
        @{ Id = 'OPS-004'; Status = 'Review'; Mutate = { param($e) Set-TestItems $e signIns @(@{ id = 'sign-in-1'; status = @{ errorCode = 0 }; clientAppUsed = 'Browser'; authenticationRequirement = 'singleFactorAuthentication' }) } }
        @{ Id = 'OPS-005'; Status = 'Review'; Mutate = { param($e) Set-TestItems $e provisioningLogs @(@{ id = 'prov-1'; statusInfo = @{ status = 'failure' } }) } }
        @{ Id = 'OPS-006'; Status = 'Review'; Mutate = { param($e) Set-TestItems $e directoryAudits @(@{ id = 'audit-1'; activityDisplayName = 'Add member to role'; result = 'success' }) } }
        @{ Id = 'OPS-007'; Status = 'Review'; Mutate = { param($e) Set-TestItems $e secureScores @(@{ id = 'score-1'; currentScore = 30; maxScore = 100 }) } }
    )
}

function New-TestHealthyEvidence {
    $e = New-TestEvidence
    $second = New-TestUser @{ id = '44444444-4444-4444-8444-444444444444'; displayName = 'Second administrator' }
    Set-TestItems $e users @((New-TestUser), $second)
    Set-TestItems $e registrationDetails @(
        @{ id = $script:TestUserId; isMfaRegistered = $true; isMfaCapable = $true; isSsprEnabled = $true; isSsprRegistered = $true }
        @{ id = $second.id; isMfaRegistered = $true; isMfaCapable = $true; isSsprEnabled = $true; isSsprRegistered = $true }
    )
    Set-TestItems $e domains @(@{ id = 'example.test'; isVerified = $true; authenticationType = 'Federated' })
    Set-TestItems $e federationConfigurations @(@{ id = 'fed-1'; passiveSignInUri = 'https://idp.example.test'; activeSignInUri = 'https://idp.example.test/ws' })
    Set-TestItems $e subscribedSkus @(@{ id = 'sku-1'; consumedUnits = 5; prepaidUnits = @{ enabled = 10 } })
    Set-TestItems $e groups @(@{ id = 'role-group'; displayName = 'Role group'; isAssignableToRole = $true })
    Set-TestItems $e groupOwners @(@{ id = $script:TestUserId; _ParentId = 'role-group' })
    Set-TestItems $e roleAssignments @(
        @{ id = 'ra-1'; principalId = $script:TestUserId; roleDefinitionId = $script:GlobalAdminRoleId; directoryScopeId = '/' }
        @{ id = 'ra-2'; principalId = $second.id; roleDefinitionId = $script:GlobalAdminRoleId; directoryScopeId = '/' }
    )
    Set-TestItems $e roleAssignmentScheduleInstances @(@{
        id = 'activation-1'; principalId = $script:TestUserId; roleDefinitionId = $script:GlobalAdminRoleId
        directoryScopeId = '/'; assignmentType = 'Activated'; endDateTime = '2026-01-02T00:00:00Z'
    })
    Set-TestItems $e roleManagementPolicies @(@{
        id = 'pim-1'; rules = @(@{ id = 'Enablement_EndUser_Assignment'; enabledRules = @('MultiFactorAuthentication') })
    })
    Set-TestItems $e authenticationMethodConfigurations @(
        @{ id = 'Fido2'; state = 'enabled' }, @{ id = 'Sms'; state = 'disabled' }
        @{ id = 'TemporaryAccessPass'; state = 'enabled'; defaultLifetimeInMinutes = 30; isUsableOnce = $true }
    )
    $legacy = New-TestCaPolicy @{ id = 'legacy-block' }
    $legacy.conditions.clientAppTypes = @('exchangeActiveSync', 'other')
    $legacy.grantControls.builtInControls = @('block')
    $resistant = New-TestCaPolicy @{ id = 'phishing-resistant' }
    $resistant.grantControls.builtInControls = @()
    $resistant.grantControls.authenticationStrength = @{ id = '00000000-0000-0000-0000-000000000004' }
    $risk = New-TestCaPolicy @{ id = 'risk-mfa' }
    $risk.conditions.signInRiskLevels = @('high')
    Set-TestItems $e conditionalAccessPolicies @((New-TestCaPolicy), $legacy, $resistant, $risk)
    Set-TestItems $e authenticationStrengthPolicies @(@{
        id = '00000000-0000-0000-0000-000000000004'; requirementsSatisfied = 'mfa'; allowedCombinations = @('fido2', 'windowsHelloForBusiness')
    })
    Set-TestItems $e namedLocations @(@{ id = 'office'; isTrusted = $true; ipRanges = @(@{ cidrAddress = '192.0.2.0/24' }) })
    Set-TestItems $e applications @((New-TestApplication))
    Set-TestItems $e applicationOwners @(@{ id = $script:TestUserId; _ParentId = 'app-1' })
    Set-TestItems $e servicePrincipals @(
        @{
            id = 'local-sp'; appId = 'client-1'; displayName = 'Local app'; servicePrincipalType = 'Application'
            accountEnabled = $true; appOwnerOrganizationId = $script:TestTenantId; appRoleAssignmentRequired = $true
            passwordCredentials = @(); keyCredentials = @(); appRoles = @()
        }
        @{
            id = 'graph-sp'; appId = '00000003-0000-0000-c000-000000000000'; displayName = 'Microsoft Graph'
            servicePrincipalType = 'Application'; accountEnabled = $true
            appOwnerOrganizationId = '55555555-5555-4555-8555-555555555555'; appRoleAssignmentRequired = $false
            passwordCredentials = @(); keyCredentials = @(); appRoles = @(@{ id = 'read-permission'; value = 'User.Read.All' })
        }
    )
    Set-TestItems $e servicePrincipalOwners @(@{ id = $script:TestUserId; _ParentId = 'local-sp' })
    Set-TestItems $e appRoleAssignments @(@{ id = 'read-grant'; resourceId = 'graph-sp'; principalId = 'local-sp'; appRoleId = 'read-permission' })
    Set-TestItems $e oauth2PermissionGrants @(@{ id = 'consent-1'; resourceId = 'graph-sp'; clientId = 'local-sp'; consentType = 'AllPrincipals'; scope = 'User.Read' })
    Set-TestItems $e devices @(@{ id = 'dev-1'; accountEnabled = $true; isManaged = $true; isCompliant = $true; approximateLastSignInDateTime = '2025-12-31T00:00:00Z' })
    Set-TestItems $e accessReviewDefinitions @(@{ id = 'review-1'; settings = @{ defaultDecisionEnabled = $true; defaultDecision = 'Deny' } })
    Set-TestItems $e accessPackageAssignmentPolicies @(@{ id = 'package-policy'; expiration = @{ type = 'afterDuration'; duration = 'P90D' } })
    Set-TestItems $e lifecycleWorkflows @(@{ id = 'workflow'; isEnabled = $true })
    Set-TestItems $e riskyUsers @(@{ id = 'dismissed-user'; riskState = 'dismissed'; riskLevel = 'none' })
    Set-TestItems $e riskDetections @(@{ id = 'remediated-risk'; riskState = 'remediated'; riskLevel = 'none' })
    Set-TestItems $e signIns @(@{ id = 'modern'; status = @{ errorCode = 0 }; clientAppUsed = 'Browser'; authenticationRequirement = 'multiFactorAuthentication' })
    Set-TestItems $e provisioningLogs @(@{ id = 'provisioning-ok'; statusInfo = @{ status = 'success' } })
    Set-TestItems $e directoryAudits @(@{ id = 'audit-ok'; activityDisplayName = 'Ordinary directory operation'; result = 'success' })
    Set-TestItems $e secureScores @(@{ id = 'score'; currentScore = 100; maxScore = 100; createdDateTime = $script:TestNow })
    $e
}
