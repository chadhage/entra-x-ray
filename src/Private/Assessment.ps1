function Get-XrayItems {
    param($Evidence, [string]$SourceId)
    return ,$Evidence.Sources[$SourceId].Items
}

function Get-XrayPrivilegedRoleIds {
    param([object[]]$Definitions)
    $known = @(
        '62e90394-69f5-4237-9190-012177145e10', 'e8611ab8-c189-46e8-94e1-60213ab1f814',
        '7be44c8a-adaf-4e2a-84d6-ab2649e08a13', '9b7fa17d-e63e-47b0-bb0a-15c516ac86ec',
        '158c047a-c907-4556-b7ef-446551a6b5f7', 'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9'
    )
    foreach ($role in $Definitions) {
        Assert-XrayFields $role @('id')
        $flag = Get-XrayValue $role 'isPrivileged'
        if ($flag -eq $true -or (Get-XrayValue $role 'templateId') -in $known -or $role['id'] -in $known) {
            $role['id']
        }
        elseif ($null -eq $flag) {
            $permissions = Get-XrayValue $role 'rolePermissions'
            foreach ($permission in $permissions) {
                $actions = Get-XrayValue $permission 'allowedResourceActions'
                if (@($actions | Where-Object { $_ -notmatch '/read$' }).Count -gt 0) { $role['id']; break }
            }
        }
    }
}

function Expand-XrayRoleAssignments {
    param([object[]]$Assignments, [object[]]$Groups, [object[]]$Members)
    $groupIds = @($Groups | ForEach-Object { Get-XrayValue $_ 'id' })
    foreach ($assignment in $Assignments) {
        Assert-XrayFields $assignment @('id', 'principalId', 'roleDefinitionId', 'directoryScopeId')
        $principal = $assignment['principalId']
        if ($principal -in $groupIds) {
            foreach ($member in $Members) {
                Assert-XrayFields $member @('id', '_ParentId')
                if ($member['_ParentId'] -eq $principal) {
                    $copy = Copy-XrayObject $assignment
                    $copy['effectivePrincipalId'] = $member['id']
                    $copy['viaGroupId'] = $principal
                    $copy
                }
            }
        }
        else {
            $copy = Copy-XrayObject $assignment
            $copy['effectivePrincipalId'] = $principal
            $copy['viaGroupId'] = ''
            $copy
        }
    }
}

function Get-XrayGlobalAdmins {
    param($Evidence, [switch]$IncludeEligible)
    $globalRoleIds = @(
        foreach ($role in (Get-XrayItems $Evidence roleDefinitions)) {
            if ((Get-XrayValue $role 'templateId') -eq '62e90394-69f5-4237-9190-012177145e10' -or
                (Get-XrayValue $role 'id') -eq '62e90394-69f5-4237-9190-012177145e10') { $role['id'] }
        }
    )
    $assignments = Get-XrayItems $Evidence roleAssignments
    if ($IncludeEligible) {
        $now = ConvertTo-XrayDate $Evidence.CompletedAtUtc
        foreach ($eligible in (Get-XrayItems $Evidence roleEligibilityScheduleInstances)) {
            Assert-XrayFields $eligible @('startDateTime', 'endDateTime')
            $start = ConvertTo-XrayDate $eligible['startDateTime']
            $end = ConvertTo-XrayDate $eligible['endDateTime']
            if (($null -eq $start -or $start -le $now) -and ($null -eq $end -or $end -gt $now)) { $assignments += $eligible }
        }
    }
    $expanded = @(Expand-XrayRoleAssignments $assignments (Get-XrayItems $Evidence groups) (Get-XrayItems $Evidence roleGroupMembers))
    $spIds = @(foreach ($sp in (Get-XrayItems $Evidence servicePrincipals)) { Get-XrayValue $sp 'id' })
    $users = @{}
    foreach ($user in (Get-XrayItems $Evidence users)) { $users[[string](Get-XrayValue $user 'id')] = $user }
    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($assignment in $expanded) {
        if ($assignment['directoryScopeId'] -ne '/' -or $assignment['roleDefinitionId'] -notin $globalRoleIds) { continue }
        $principal = $assignment['effectivePrincipalId']
        if ($principal -in $spIds) { continue }
        if (-not $users.ContainsKey($principal)) {
            throw [System.IO.InvalidDataException]::new('A Global Administrator principal could not be resolved to a current human user, group member, or service principal.')
        }
        if ((Get-XrayBoolean $users[$principal] 'accountEnabled') -and $seen.Add($principal)) { $users[$principal] }
    }
}

function Test-XrayCaUnqualified {
    param($Policy, [switch]$LegacyClients)
    Assert-XrayFields $Policy @('state', 'conditions.users', 'conditions.applications', 'conditions.clientAppTypes')
    if ($Policy['state'] -ne 'enabled') { return $false }
    $users = Get-XrayValue $Policy 'conditions.users'
    $apps = Get-XrayValue $Policy 'conditions.applications'
    if ($null -eq $users -or $null -eq $apps) { return $false }
    Assert-XrayFields $users @('includeUsers', 'excludeUsers', 'excludeGroups', 'excludeRoles')
    Assert-XrayFields $apps @('includeApplications', 'excludeApplications')
    if ('All' -notin $users['includeUsers'] -or 'All' -notin $apps['includeApplications']) { return $false }
    foreach ($field in @('excludeUsers', 'excludeGroups', 'excludeRoles')) {
        if (@($users[$field]).Count -gt 0) { return $false }
    }
    if (Get-XrayValue $users 'excludeGuestsOrExternalUsers') { return $false }
    if (@($apps['excludeApplications']).Count -gt 0 -or (Get-XrayValue $apps 'applicationFilter')) { return $false }
    if ((Get-XrayValue $apps 'includeUserActions') -or (Get-XrayValue $apps 'includeAuthenticationContextClassReferences')) { return $false }
    $knownConditions = @('users', 'applications', 'clientAppTypes', 'platforms', 'locations', 'devices', 'signInRiskLevels', 'userRiskLevels', 'servicePrincipalRiskLevels', 'authenticationFlows', 'clientApplications')
    foreach ($field in $Policy['conditions'].Keys) {
        if ($field -notin $knownConditions -and $null -ne $Policy['conditions'][$field] -and @($Policy['conditions'][$field]).Count -gt 0) { return $false }
    }
    foreach ($field in @('platforms', 'locations', 'devices', 'signInRiskLevels', 'userRiskLevels', 'servicePrincipalRiskLevels', 'authenticationFlows', 'clientApplications')) {
        $value = Get-XrayValue $Policy "conditions.$field"
        if ($null -ne $value -and @($value).Count -gt 0) { return $false }
    }
    $clients = Get-XrayValue $Policy 'conditions.clientAppTypes'
    if ($LegacyClients) { return ('all' -in $clients -or ('exchangeActiveSync' -in $clients -and 'other' -in $clients)) }
    return ('all' -in $clients)
}

function Test-XrayCaMfa {
    param($Policy, [object[]]$Strengths, [switch]$PhishingResistant)
    $grant = Get-XrayValue $Policy 'grantControls'
    if ($null -eq $grant) { return $false }
    Assert-XrayFields $grant @('operator', 'builtInControls')
    $builtIns = $grant['builtInControls']
    if ('block' -in $builtIns) { return $false }
    $strength = Get-XrayValue $grant 'authenticationStrength'
    $strengthMfa = $false
    $strengthPhishing = $false
    if ($strength) {
        $id = Get-XrayValue $strength 'id'
        if ($id -in @('00000000-0000-0000-0000-000000000002', '00000000-0000-0000-0000-000000000003', '00000000-0000-0000-0000-000000000004')) { $strengthMfa = $true }
        if ($id -eq '00000000-0000-0000-0000-000000000004') { $strengthPhishing = $true }
        foreach ($definition in $Strengths) {
            if ((Get-XrayValue $definition 'id') -ne $id) { continue }
            $strengthMfa = (Get-XrayValue $definition 'requirementsSatisfied') -eq 'mfa'
            $combinations = Get-XrayValue $definition 'allowedCombinations'
            $resistant = @('fido2', 'windowsHelloForBusiness', 'x509CertificateMultiFactor')
            $strengthPhishing = $strengthMfa -and @($combinations).Count -gt 0 -and @($combinations | Where-Object { $_ -notin $resistant }).Count -eq 0
        }
    }
    $target = ('mfa' -in $builtIns) -or $strengthMfa
    if ($PhishingResistant) { $target = $strengthPhishing }
    if (-not $target) { return $false }
    if ($grant['operator'] -eq 'AND') { return $true }
    if ($grant['operator'] -ne 'OR') { throw [System.IO.InvalidDataException]::new('Unknown Conditional Access grant operator.') }
    $alternatives = @($builtIns | Where-Object { $_ -ne 'mfa' }).Count
    $alternatives += @((Get-XrayValue $grant 'termsOfUse')).Count
    $alternatives += @((Get-XrayValue $grant 'customAuthenticationFactors')).Count
    if ($PhishingResistant -and 'mfa' -in $builtIns) { $alternatives++ }
    return $alternatives -eq 0
}

function Get-XrayHighImpactPermissions {
    @(
        'Directory.ReadWrite.All', 'Directory.AccessAsUser.All', 'RoleManagement.ReadWrite.Directory',
        'RoleManagementPolicy.ReadWrite.Directory', 'AppRoleAssignment.ReadWrite.All', 'Application.ReadWrite.All',
        'Application.ReadWrite.OwnedBy', 'User.ReadWrite.All', 'UserAuthenticationMethod.ReadWrite.All',
        'Policy.ReadWrite.ConditionalAccess', 'Policy.ReadWrite.AuthenticationMethod', 'DelegatedPermissionGrant.ReadWrite.All',
        'PrivilegedAccess.ReadWrite.AzureAD', 'Group.ReadWrite.All', 'GroupMember.ReadWrite.All',
        'Mail.Read', 'Mail.ReadWrite', 'Mail.Send', 'Files.Read.All', 'Files.ReadWrite.All',
        'Sites.Read.All', 'Sites.ReadWrite.All', 'Sites.FullControl.All', 'Chat.Read.All', 'Chat.ReadWrite.All',
        'ChannelMessage.Read.All'
    )
}

function Get-XrayCredentialIssues {
    param($Evidence, $Settings, [string]$Mode)
    $now = ConvertTo-XrayDate $Evidence.CompletedAtUtc
    foreach ($sourceId in @('applications', 'servicePrincipals')) {
        foreach ($app in (Get-XrayItems $Evidence $sourceId)) {
            Assert-XrayFields $app @('id', 'passwordCredentials', 'keyCredentials')
            foreach ($kind in @('passwordCredentials', 'keyCredentials')) {
                foreach ($credential in $app[$kind]) {
                    Assert-XrayFields $credential @('keyId', 'startDateTime', 'endDateTime')
                    $start = ConvertTo-XrayDate $credential['startDateTime']
                    $end = ConvertTo-XrayDate $credential['endDateTime']
                    if ($null -eq $end) { throw [System.IO.InvalidDataException]::new('Credential expiration metadata is unavailable.') }
                    if ($null -ne $start -and $end -lt $start) { throw [System.IO.InvalidDataException]::new('Credential end timestamp precedes its start timestamp.') }
                    $match = $false
                    switch ($Mode) {
                        'Expired' { $match = $end -le $now }
                        'Expiring' { $match = $end -gt $now -and $end -le $now.AddDays($Settings.CredentialWarningDays) }
                        'LongLived' {
                            if ($null -eq $start) { throw [System.IO.InvalidDataException]::new('Credential start timestamp is unavailable.') }
                            $match = ($end - $start).TotalDays -gt $Settings.MaxCredentialLifetimeDays
                        }
                    }
                    if ($match) { New-XrayEntity $app "$sourceId; $kind; keyId=$($credential['keyId']); start=$start; end=$end. Metadata only; active use is not inferred." }
                }
            }
        }
    }
}

function Invoke-XrayRule {
    param($Definition, $Evidence, $Settings)
    $d = @{}
    foreach ($id in $Definition.Sources) { $d[$id] = Get-XrayItems $Evidence $id }
    $now = ConvertTo-XrayDate $Evidence.CompletedAtUtc
    $issues = @()
    $passStatus = 'Pass'
    $adverse = $Definition.AdverseStatus
    $severity = $Definition.Severity
    $tenant = @{ id = $Evidence.TenantId; displayName = 'Tenant configuration' }
    switch ($Definition.Id) {
        'TEN-001' {
            if ($d.organization.Count -ne 1) { throw [System.IO.InvalidDataException]::new('Exactly one organization is required to assess tenant synchronization state.') }
            $issues = @(Find-XrayIssue $d.organization @('onPremisesSyncEnabled', 'onPremisesLastSyncDateTime') {
                param($r)
                if ($r['onPremisesSyncEnabled'] -eq $true) {
                    $last = ConvertTo-XrayDate $r['onPremisesLastSyncDateTime']
                    if ($null -eq $last) { throw [System.IO.InvalidDataException]::new('Hybrid synchronization is enabled but its last sync timestamp is unavailable.') }
                    if (($now - $last).TotalHours -gt $Settings.HybridSyncMaxHours) { "Last successful directory sync=$last; organizational maximum=$($Settings.HybridSyncMaxHours) hours." }
                }
            })
        }
        'TEN-002' {
            $issues = @(Find-XrayIssue $d.federationConfigurations @('id', 'passiveSignInUri') {
                param($r)
                foreach ($field in @('passiveSignInUri', 'activeSignInUri', 'metadataExchangeUri', 'signOutUri')) {
                    $value = Get-XrayValue $r $field
                    if ($value -and (ConvertTo-XrayAbsoluteUri $value).Scheme -ne 'https') { "$field=$value; federation protocol endpoint is not HTTPS." }
                }
            })
            if ($d.federationConfigurations.Count -eq 0) { $passStatus = 'NotApplicable' }
        }
        'TEN-003' { $issues = @(Find-XrayIssue $d.domains @('id', 'isVerified') { param($r) if (-not (Get-XrayBoolean $r 'isVerified')) { 'Domain verification is incomplete.' } }) }
        'TEN-004' {
            $issues = @(Find-XrayIssue $d.subscribedSkus @('id', 'consumedUnits', 'prepaidUnits.enabled') {
                param($r)
                if ((Get-XrayNumber $r 'consumedUnits' -Integer) -gt (Get-XrayNumber $r 'prepaidUnits.enabled' -Integer)) { "Consumed=$($r['consumedUnits']); enabled capacity=$($r['prepaidUnits']['enabled'])." }
            })
        }
        'AUTH-001' {
            if (-not (Get-XrayBoolean $d.securityDefaults[0] 'isEnabled')) {
                $mfa = @($d.conditionalAccessPolicies | Where-Object {
                    (Get-XrayValue $_ 'state') -eq 'enabled' -and (Test-XrayCaMfa $_ $d.authenticationStrengthPolicies)
                })
                $unqualified = @($mfa | Where-Object { Test-XrayCaUnqualified $_ })
                if ($unqualified.Count -eq 0) {
                    $signals = @($d.conditionalAccessPolicies | Where-Object {
                        (Get-XrayValue $_ 'state') -eq 'enabled' -and
                        ('mfa' -in (Get-XrayValue $_ 'grantControls.builtInControls') -or
                            $null -ne (Get-XrayValue $_ 'grantControls.authenticationStrength'))
                    })
                    if ($signals.Count -gt 0) { $adverse = 'Review' }
                    $issues = @(New-XrayEntity $tenant "Security defaults disabled; no unqualified all-user/all-resource MFA configuration was proven. Enabled MFA-requiring policy count=$($mfa.Count). Scoped or combined policies may still protect access; this is not effective-access simulation.")
                }
            }
        }
        { $_ -in @('AUTH-002', 'AUTH-003', 'AUTH-004') } {
            $field = @{ 'AUTH-002' = 'isMfaRegistered'; 'AUTH-003' = 'isMfaCapable'; 'AUTH-004' = 'isSsprRegistered' }[$Definition.Id]
            $registrations = @{}
            foreach ($r in $d.registrationDetails) { Assert-XrayFields $r @('id'); $registrations[$r['id']] = $r }
            $applicable = 0
            $issues = @(foreach ($user in $d.users) {
                Assert-XrayFields $user @('id', 'accountEnabled', 'userType')
                if (-not (Get-XrayBoolean $user 'accountEnabled')) { continue }
                if ($Definition.Id -eq 'AUTH-004' -and $user['userType'] -ne 'Member') { continue }
                $applicable++
                if (-not $registrations.ContainsKey($user['id'])) { throw [System.IO.InvalidDataException]::new('Enabled user is absent from the registration report; registration state cannot be inferred.') }
                $r = $registrations[$user['id']]
                if ($Definition.Id -eq 'AUTH-004' -and -not (Get-XrayBoolean $r 'isSsprEnabled')) { continue }
                if (-not (Get-XrayBoolean $r $field)) { New-XrayEntity $user "$field=false in the authentication methods registration report. Registration/capability is distinct from enforcement." }
            })
            if ($applicable -eq 0) { $passStatus = 'NotApplicable' }
        }
        'AUTH-005' {
            $fido = @($d.authenticationMethodConfigurations | Where-Object { (Get-XrayValue $_ 'id') -eq 'Fido2' })
            if ($fido.Count -eq 0 -or (Get-XrayValue $fido[0] 'state') -ne 'enabled') { $issues = @(New-XrayEntity $tenant 'FIDO2/passkey method is not enabled in the collected authentication methods policy. Other phishing-resistant methods may exist.') }
        }
        'AUTH-006' {
            $issues = @(Find-XrayIssue $d.authenticationMethodConfigurations @('id', 'state') {
                param($r)
                if ($r['id'] -in @('Sms', 'Voice') -and $r['state'] -eq 'enabled') { "$($r['id']) is enabled; review include/exclude targets and actual usage." }
            })
        }
        'AUTH-007' {
            $issues = @(Find-XrayIssue $d.authenticationMethodsPolicy @('policyMigrationState') { param($r) if ($r['policyMigrationState'] -ne 'migrationComplete') { "policyMigrationState=$($r['policyMigrationState'])." } })
        }
        'AUTH-008' {
            $issues = @(Find-XrayIssue $d.authenticationMethodConfigurations @('id', 'state') {
                param($r)
                if ($r['id'] -eq 'TemporaryAccessPass' -and $r['state'] -eq 'enabled') {
                    Assert-XrayFields $r @('defaultLifetimeInMinutes', 'isUsableOnce')
                    if ((Get-XrayNumber $r 'defaultLifetimeInMinutes' -Integer) -gt 60 -or -not (Get-XrayBoolean $r 'isUsableOnce')) { "TAP default lifetime=$($r['defaultLifetimeInMinutes']) minutes; single-use=$($r['isUsableOnce']). Review signal, not proof of unsafe issuance." }
                }
            })
        }
        'AUTH-009' { $issues = @(Find-XrayIssue $d.authorizationPolicy @('allowEmailVerifiedUsersToJoinOrganization') { param($r) if (Get-XrayBoolean $r 'allowEmailVerifiedUsersToJoinOrganization') { 'Email-verified self-service joining is allowed.' } }) }
        'AUTH-010' { $issues = @(Find-XrayIssue $d.authorizationPolicy @('defaultUserRolePermissions.allowedToCreateApps') { param($r) if (Get-XrayBoolean $r 'defaultUserRolePermissions.allowedToCreateApps') { 'Default member role can create application registrations.' } }) }
        'AUTH-011' {
            $issues = @(Find-XrayIssue $d.authorizationPolicy @('defaultUserRolePermissions.permissionGrantPoliciesAssigned') {
                param($r)
                $assigned = Get-XrayValue $r 'defaultUserRolePermissions.permissionGrantPoliciesAssigned'
                if (@($assigned).Count -gt 0) { "Default consent-policy assignments=$($assigned -join ', '). Inspect condition sets; this is not a finding of unrestricted consent." }
            })
        }
        'AUTH-012' { $issues = @(Find-XrayIssue $d.adminConsentRequestPolicy @('isEnabled') { param($r) if (-not (Get-XrayBoolean $r 'isEnabled')) { 'Admin consent request workflow is disabled; alternative approval processes require validation.' } }) }
        'CA-001' { $issues = @(Find-XrayIssue $d.conditionalAccessPolicies @('id', 'state') { param($r) if ($r['state'] -eq 'enabledForReportingButNotEnforced') { 'Policy is report-only and does not enforce its grant/session controls.' } }) }
        'CA-002' { $issues = @(Find-XrayIssue $d.conditionalAccessPolicies @('id', 'state') { param($r) if ($r['state'] -eq 'disabled') { 'Policy is disabled. This may be an intentional contingency policy.' } }) }
        'CA-003' {
            $issues = @(Find-XrayIssue $d.conditionalAccessPolicies @('id', 'state', 'conditions') {
                param($r)
                if ($r['state'] -ne 'enabled') { return }
                foreach ($path in @('users.excludeUsers', 'users.excludeGroups', 'users.excludeRoles', 'applications.excludeApplications', 'applications.applicationFilter')) {
                    $value = Get-XrayValue $r "conditions.$path"
                    if ($null -ne $value -and @($value).Count -gt 0) { "$path=$($value | ConvertTo-Json -Depth 20 -Compress). Review justified exceptions and overlapping controls." }
                }
            })
        }
        'CA-004' {
            if (-not (Get-XrayBoolean $d.securityDefaults[0] 'isEnabled')) {
                $blocks = @($d.conditionalAccessPolicies | Where-Object {
                    (Test-XrayCaUnqualified $_ -LegacyClients) -and 'block' -in (Get-XrayValue $_ 'grantControls.builtInControls')
                })
                if ($blocks.Count -eq 0) { $issues = @(New-XrayEntity $tenant 'No unqualified enabled legacy-authentication block was proven. Scoped/combined policies and workload-level blocks require separate evaluation.') }
            }
        }
        'CA-005' {
            $resistant = @($d.conditionalAccessPolicies | Where-Object {
                (Get-XrayValue $_ 'state') -eq 'enabled' -and (Test-XrayCaMfa $_ $d.authenticationStrengthPolicies -PhishingResistant)
            })
            if ($resistant.Count -eq 0) { $issues = @(New-XrayEntity $tenant 'No enabled policy requiring a resolved phishing-resistant authentication strength was observed. Effective administrator coverage is not inferred.') }
        }
        'CA-006' {
            $riskPolicies = @($d.conditionalAccessPolicies | Where-Object {
                (Get-XrayValue $_ 'state') -eq 'enabled' -and
                (@((Get-XrayValue $_ 'conditions.signInRiskLevels')).Count -gt 0 -or @((Get-XrayValue $_ 'conditions.userRiskLevels')).Count -gt 0) -and
                $null -ne (Get-XrayValue $_ 'grantControls')
            })
            if ($riskPolicies.Count -eq 0) { $issues = @(New-XrayEntity $tenant 'No enabled risk-conditioned grant-control policy was observed. Licensing and other risk response controls require validation.') }
        }
        'CA-007' {
            $issues = @(Find-XrayIssue $d.namedLocations @('id') {
                param($r)
                if ((Get-XrayValue $r 'isTrusted') -eq $true) {
                    $ranges = Get-XrayValue $r 'ipRanges'
                    foreach ($range in $ranges) {
                        if ((Get-XrayValue $range 'cidrAddress') -in @('0.0.0.0/0', '::/0')) { "Trusted location contains $($range['cidrAddress']); this trusts an entire address family, but does not itself prove a policy bypass." }
                    }
                }
            })
        }
        'CA-008' {
            $issues = @(Find-XrayIssue $d.conditionalAccessPolicies @('id', 'state') {
                param($r)
                if ($r['state'] -eq 'enabled' -and (Get-XrayValue $r 'sessionControls.persistentBrowser.isEnabled') -eq $true -and
                    (Get-XrayValue $r 'sessionControls.persistentBrowser.mode') -eq 'always') { 'Enabled policy always permits persistent browser sessions for its scoped population.' }
            })
        }
        { $_ -in @('ID-001', 'ID-002', 'ID-003', 'ID-004') } {
            $activities = @{}
            if ($Definition.Id -ne 'ID-004') {
                foreach ($entry in $d.userSignInActivity) {
                    Assert-XrayFields $entry @('id', 'signInActivity')
                    $activities[$entry['id']] = $entry['signInActivity']
                }
            }
            $issues = @(Find-XrayIssue $d.users @('id', 'accountEnabled', 'userType', 'createdDateTime') {
                param($r)
                if (-not (Get-XrayBoolean $r 'accountEnabled')) { return }
                $created = ConvertTo-XrayDate $r['createdDateTime']
                if ($null -eq $created) { throw [System.IO.InvalidDataException]::new('User creation timestamp is unavailable.') }
                if ($Definition.Id -eq 'ID-004') {
                    if ($r['userType'] -eq 'Guest' -and (Get-XrayValue $r 'externalUserState') -eq 'PendingAcceptance') {
                        $invited = ConvertTo-XrayDate (Get-XrayValue $r 'externalUserStateChangeDateTime')
                        if ($null -eq $invited) { $invited = $created }
                        if (($now - $invited).TotalDays -gt $Settings.GuestInvitationAgeDays) { "Guest invitation remains unredeemed since $invited." }
                    }
                    return
                }
                if (-not $activities.ContainsKey($r['id'])) { throw [System.IO.InvalidDataException]::new('Enabled user is absent from the separately collected sign-in activity inventory.') }
                $activity = $activities[$r['id']]
                if ($null -ne $activity) { Assert-XrayFields $activity @('lastSuccessfulSignInDateTime') }
                $last = ConvertTo-XrayDate (Get-XrayValue $activity 'lastSuccessfulSignInDateTime')
                if ($Definition.Id -eq 'ID-002') {
                    if ($null -eq $last -and ($now - $created).TotalDays -gt $Settings.StaleUserDays) { 'No successful-activity timestamp is available for this older enabled account. This is not proof of inactivity or of never having signed in.' }
                    return
                }
                $days = $Settings.StaleUserDays
                if ($Definition.Id -eq 'ID-003') { $days = $Settings.StaleGuestDays; if ($r['userType'] -ne 'Guest') { return } }
                elseif ($r['userType'] -ne 'Member') { return }
                if ($null -eq $last -and ($now - $created).TotalDays -gt $days) { throw [System.IO.InvalidDataException]::new('An older enabled account has no successful-activity timestamp; inactivity cannot be confirmed or ruled out.') }
                if ($null -ne $last -and ($now - $last).TotalDays -gt $days) { "Last successful sign-in=$last; threshold=$days days. Failed sign-in attempts are deliberately ignored." }
            })
        }
        'ID-005' {
            $issues = @(Find-XrayIssue $d.users @('id', 'accountEnabled', 'onPremisesSyncEnabled', 'passwordPolicies') {
                param($r)
                if ((Get-XrayBoolean $r 'accountEnabled') -and $r['onPremisesSyncEnabled'] -ne $true -and
                    'DisableStrongPassword' -in ([string]$r['passwordPolicies'] -split ',\s*')) { 'Enabled cloud-managed user has DisableStrongPassword configured.' }
            })
        }
        'PRIV-001' {
            $admins = @(Get-XrayGlobalAdmins $Evidence)
            if ($admins.Count -gt $Settings.MaxGlobalAdministrators) {
                $issues = @($admins | ForEach-Object { New-XrayEntity $_ "Active enabled human tenant-wide Global Administrator; distinct population=$($admins.Count), review maximum=$($Settings.MaxGlobalAdministrators)." })
            }
        }
        'PRIV-002' {
            $admins = @(Get-XrayGlobalAdmins $Evidence -IncludeEligible)
            if ($admins.Count -lt 2) { $issues = @(New-XrayEntity $tenant "Only $($admins.Count) distinct enabled human tenant-wide Global Administrator principals were resolved from active and current eligible assignments. This does not verify emergency-access usability.") }
        }
        'PRIV-003' {
            $roles = @(Get-XrayPrivilegedRoleIds $d.roleDefinitions)
            $issues = @(Find-XrayIssue $d.roleAssignmentScheduleInstances @('id', 'principalId', 'roleDefinitionId', 'assignmentType', 'endDateTime') {
                param($r)
                if ($r['roleDefinitionId'] -in $roles -and $r['assignmentType'] -eq 'Assigned' -and
                    $null -eq $r['endDateTime'] -and $r['principalId'] -notin $Settings.EmergencyAccessAccountId) { "Standing privileged assignment without expiration; principal=$($r['principalId']); role=$($r['roleDefinitionId'])." }
            })
        }
        'PRIV-004' {
            $roles = @(Get-XrayPrivilegedRoleIds $d.roleDefinitions)
            $expanded = @(Expand-XrayRoleAssignments $d.roleAssignments $d.groups $d.roleGroupMembers)
            $guestIds = @($d.users | Where-Object { (Get-XrayValue $_ 'userType') -eq 'Guest' } | ForEach-Object { $_['id'] })
            $issues = @(foreach ($assignment in $expanded) {
                if ($assignment['roleDefinitionId'] -in $roles -and $assignment['effectivePrincipalId'] -in $guestIds) { New-XrayEntity $assignment "Guest=$($assignment['effectivePrincipalId']); role=$($assignment['roleDefinitionId']); via group=$($assignment['viaGroupId']); scope=$($assignment['directoryScopeId'])." }
            })
        }
        'PRIV-005' {
            $roles = @(Get-XrayPrivilegedRoleIds $d.roleDefinitions)
            $spIds = @($d.servicePrincipals | ForEach-Object { Get-XrayValue $_ 'id' })
            $issues = @(Find-XrayIssue $d.roleAssignments @('id', 'principalId', 'roleDefinitionId') {
                param($r)
                if ($r['roleDefinitionId'] -in $roles -and $r['principalId'] -in $spIds) { "Service principal=$($r['principalId']); privileged directory role=$($r['roleDefinitionId'])." }
            })
        }
        'PRIV-006' {
            $issues = @(Find-XrayIssue $d.roleManagementPolicies @('id', 'rules') {
                param($r)
                foreach ($rule in $r['rules']) {
                    if ((Get-XrayValue $rule 'id') -eq 'Enablement_EndUser_Assignment') {
                        Assert-XrayFields $rule @('enabledRules')
                        if ('MultiFactorAuthentication' -notin $rule['enabledRules']) { 'End-user activation enablement rule does not explicitly require MFA. Authentication-context policies or other controls may supply assurance; inspect role mappings and approvals.' }
                    }
                }
            })
        }
        'PRIV-007' {
            $owned = @($d.groupOwners | ForEach-Object { Get-XrayValue $_ '_ParentId' })
            $issues = @(Find-XrayIssue $d.groups @('id', 'isAssignableToRole') {
                param($r)
                if ((Test-XrayRoleAssignableGroup $r) -and $r['id'] -notin $owned) { 'Role-assignable group has no owners visible in the collected relationship.' }
            })
        }
        'PRIV-008' {
            $declared = $Settings.EmergencyAccessAccountId
            $issues = @(New-XrayEntity $tenant "Declared emergency object IDs=$($declared -join ', '); count=$($declared.Count). Existence, independent authentication, lockout resilience, monitoring, secure credential storage, and tested usability require human validation. Naming or exclusions alone are not proof.")
        }
        'APP-001' { $issues = @(Get-XrayCredentialIssues $Evidence $Settings Expired) }
        'APP-002' { $issues = @(Get-XrayCredentialIssues $Evidence $Settings Expiring) }
        'APP-003' { $issues = @(Get-XrayCredentialIssues $Evidence $Settings LongLived) }
        'APP-004' {
            $owned = @($d.applicationOwners | ForEach-Object { Get-XrayValue $_ '_ParentId' })
            $issues = @(Find-XrayIssue $d.applications @('id') { param($r) if ($r['id'] -notin $owned) { 'Application registration has no visible owner.' } })
            if ($d.applications.Count -eq 0) { $passStatus = 'NotApplicable' }
        }
        'APP-005' {
            $owned = @($d.servicePrincipalOwners | ForEach-Object { Get-XrayValue $_ '_ParentId' })
            $issues = @(Find-XrayIssue $d.servicePrincipals @('id', 'servicePrincipalType', 'accountEnabled', 'appOwnerOrganizationId') {
                param($r)
                if ($r['servicePrincipalType'] -eq 'Application' -and (Get-XrayBoolean $r 'accountEnabled') -and
                    $r['appOwnerOrganizationId'] -eq $Evidence.TenantId -and $r['id'] -notin $owned) { 'Enabled locally owned enterprise application has no visible owner.' }
            })
        }
        'APP-006' { $issues = @(Find-XrayIssue $d.applications @('id', 'signInAudience') { param($r) if ($r['signInAudience'] -ne 'AzureADMyOrg') { "Application signInAudience=$($r['signInAudience']); verify intended audience and authorization." } }) }
        'APP-007' {
            $issues = @(Find-XrayIssue $d.applications @('id', 'web', 'spa', 'publicClient') {
                param($r)
                foreach ($client in @('web', 'spa', 'publicClient')) {
                    $redirects = Get-XrayValue $r "$client.redirectUris"
                    foreach ($redirect in $redirects) {
                        $uri = ConvertTo-XrayAbsoluteUri $redirect
                        if ($uri.Scheme -eq 'http' -and -not $uri.IsLoopback) { "$client redirect=$redirect is HTTP and not a native loopback redirect." }
                    }
                }
            })
        }
        'APP-008' {
            $issues = @(Find-XrayIssue $d.applications @('id', 'web') {
                param($r)
                if ((Get-XrayValue $r 'web.implicitGrantSettings.enableAccessTokenIssuance') -eq $true -or
                    (Get-XrayValue $r 'web.implicitGrantSettings.enableIdTokenIssuance') -eq $true) { 'Implicit grant access-token or ID-token issuance is enabled.' }
            })
        }
        'APP-009' {
            $resources = @{}
            foreach ($sp in $d.servicePrincipals) { Assert-XrayFields $sp @('id', 'appId'); $resources[$sp['id']] = $sp }
            $high = Get-XrayHighImpactPermissions
            $issues = @(Find-XrayIssue $d.appRoleAssignments @('id', 'resourceId', 'principalId', 'appRoleId') {
                param($r)
                if (-not $resources.ContainsKey($r['resourceId'])) { throw [System.IO.InvalidDataException]::new('Granted application permission references an unresolved resource service principal.') }
                $resource = $resources[$r['resourceId']]
                if ($resource['appId'] -ne '00000003-0000-0000-c000-000000000000') { return }
                Assert-XrayFields $resource @('appRoles')
                $permission = @($resource['appRoles'] | Where-Object { (Get-XrayValue $_ 'id') -eq $r['appRoleId'] })
                if ($permission.Count -ne 1) { throw [System.IO.InvalidDataException]::new('Granted Microsoft Graph app role could not be resolved to a permission name.') }
                if ((Get-XrayValue $permission[0] 'value') -in $high) { "Client service principal=$($r['principalId']); granted Microsoft Graph application permission=$($permission[0]['value']). Requested manifest permissions are not used." }
            })
        }
        'APP-010' {
            $high = Get-XrayHighImpactPermissions
            $issues = @(Find-XrayIssue $d.oauth2PermissionGrants @('id', 'consentType', 'scope', 'clientId') {
                param($r)
                if ($r['consentType'] -eq 'AllPrincipals') {
                    $scopes = @(([string]$r['scope'] -split '\s+') | Where-Object { $_ -in $high })
                    if ($scopes.Count -gt 0) { "Tenant-wide delegated grant; client=$($r['clientId']); high-impact scope names=$($scopes -join ', '). Effective access also depends on the signed-in user and resource." }
                }
            })
        }
        'APP-011' {
            $legacyIds = @($d.servicePrincipals | Where-Object { (Get-XrayValue $_ 'appId') -eq '00000002-0000-0000-c000-000000000000' } | ForEach-Object { $_['id'] })
            $issues = @(foreach ($grant in @($d.appRoleAssignments) + @($d.oauth2PermissionGrants)) {
                Assert-XrayFields $grant @('id', 'resourceId')
                if ($grant['resourceId'] -in $legacyIds) { New-XrayEntity $grant "Granted permission references retired Azure AD Graph resource=$($grant['resourceId'])." }
            })
        }
        'APP-012' {
            $issues = @(Find-XrayIssue $d.federatedIdentityCredentials @('id', 'issuer') {
                param($r)
                $uri = ConvertTo-XrayAbsoluteUri $r['issuer']
                if ($uri.Scheme -ne 'https') { "Federated credential issuer=$($r['issuer']) is not HTTPS." }
            })
        }
        'APP-013' {
            $issues = @(Find-XrayIssue $d.federatedIdentityCredentials @('id', 'issuer', 'subject', 'audiences', '_ParentId') {
                param($r)
                "Application=$($r['_ParentId']); issuer=$($r['issuer']); subject=$($r['subject']); audiences=$($r['audiences'] -join ', '). External trust security cannot be proven from this tenant snapshot."
            })
            if ($d.federatedIdentityCredentials.Count -eq 0) { $passStatus = 'NotApplicable' }
        }
        'APP-014' {
            $issues = @(Find-XrayIssue $d.servicePrincipals @('id', 'appId', 'servicePrincipalType', 'accountEnabled', 'appRoleAssignmentRequired') {
                param($r)
                if ($r['servicePrincipalType'] -eq 'Application' -and (Get-XrayBoolean $r 'accountEnabled') -and
                    -not (Get-XrayBoolean $r 'appRoleAssignmentRequired') -and
                    $r['appId'] -notin @('00000003-0000-0000-c000-000000000000', '00000002-0000-0000-c000-000000000000')) { 'User assignment is not required for this enabled enterprise application. Review resource-side authorization and consent.' }
            })
        }
        'DEV-001' {
            $issues = @(Find-XrayIssue $d.devices @('id', 'accountEnabled', 'approximateLastSignInDateTime') {
                param($r)
                if (Get-XrayBoolean $r 'accountEnabled') {
                    $last = ConvertTo-XrayDate $r['approximateLastSignInDateTime']
                    if ($null -eq $last) { throw [System.IO.InvalidDataException]::new('Enabled device activity timestamp is unavailable.') }
                    if (($now - $last).TotalDays -gt $Settings.StaleDeviceDays) { "Approximate last device sign-in=$last; threshold=$($Settings.StaleDeviceDays) days." }
                }
            })
        }
        { $_ -in @('DEV-002', 'DEV-003') } {
            $field = 'isCompliant'
            if ($Definition.Id -eq 'DEV-003') { $field = 'isManaged' }
            $issues = @(Find-XrayIssue $d.devices @('id', 'accountEnabled', $field) {
                param($r)
                if ((Get-XrayBoolean $r 'accountEnabled') -and -not (Get-XrayBoolean $r $field)) { "Enabled device explicitly reports $field=false. Correlate with management authority and access policy." }
            })
        }
        'EXT-001' { $issues = @(Find-XrayIssue $d.authorizationPolicy @('allowInvitesFrom') { param($r) if ($r['allowInvitesFrom'] -eq 'everyone') { 'Guest invitations may be sent by everyone, including guests.' } }) }
        'EXT-002' { $issues = @(Find-XrayIssue $d.authorizationPolicy @('guestUserRoleId') { param($r) if ($r['guestUserRoleId'] -ne '2af84b1e-32c8-42b7-82bc-daa82404023b') { "guestUserRoleId=$($r['guestUserRoleId']); not the most restricted guest directory role. Default guest visibility can be intentional." } }) }
        'EXT-003' {
            Assert-XrayFields $d.crossTenantDefault[0] @('inboundTrust')
            foreach ($partner in $d.crossTenantPartners) { Assert-XrayFields $partner @('tenantId') }
            $policies = @($d.crossTenantDefault) + @($d.crossTenantPartners)
            $issues = @(Find-XrayIssue $policies @() {
                param($r)
                if ((Get-XrayValue $r 'inboundTrust.isMfaAccepted') -eq $true) { 'Inbound partner MFA claims are trusted for this policy; review partner assurance and overrides.' }
            })
        }
        'EXT-004' {
            $issues = @(Find-XrayIssue $d.crossTenantDefault @('b2bCollaborationInbound.applications', 'b2bCollaborationInbound.usersAndGroups') {
                param($r)
                $apps = Get-XrayValue $r 'b2bCollaborationInbound.applications'
                $users = Get-XrayValue $r 'b2bCollaborationInbound.usersAndGroups'
                if ((Get-XrayValue $apps 'accessType') -eq 'allowed' -and (Get-XrayValue $users 'accessType') -eq 'allowed' -and
                    @($apps['targets'] | Where-Object { $_['target'] -eq 'AllApplications' }).Count -gt 0 -and
                    @($users['targets'] | Where-Object { $_['target'] -eq 'AllUsers' }).Count -gt 0) { 'Default inbound B2B collaboration allows all external users and all applications. Resource permissions and partner overrides still apply.' }
            })
        }
        'GOV-001' { if ($d.accessReviewDefinitions.Count -eq 0) { $issues = @(New-XrayEntity $tenant 'No access review definitions were returned in the complete collected scope. Alternative review processes require validation.') } }
        'GOV-002' {
            $issues = @(Find-XrayIssue $d.accessReviewDefinitions @('id', 'settings') {
                param($r)
                if ((Get-XrayValue $r 'settings.defaultDecisionEnabled') -eq $true -and (Get-XrayValue $r 'settings.defaultDecision') -eq 'Approve') { 'Review default decision approves access when reviewers do not respond; inspect auto-apply behavior.' }
            })
        }
        'GOV-003' { $issues = @(Find-XrayIssue $d.accessPackageAssignmentPolicies @('id', 'expiration.type') { param($r) if ((Get-XrayValue $r 'expiration.type') -eq 'noExpiration') { 'Access-package policy has no assignment expiration; review recurrence and business justification.' } }) }
        'GOV-004' { $issues = @(Find-XrayIssue $d.lifecycleWorkflows @('id', 'isEnabled') { param($r) if (-not (Get-XrayBoolean $r 'isEnabled')) { 'Lifecycle workflow is disabled; validate alternate lifecycle controls and intended status.' } }) }
        'OPS-001' {
            $issues = @(Find-XrayIssue $d.riskyUsers @('id', 'riskState', 'riskLevel') {
                param($r)
                if ($r['riskState'] -in @('atRisk', 'confirmedCompromised')) { "Unresolved user risk; state=$($r['riskState']); level=$($r['riskLevel'])." }
                elseif ($r['riskLevel'] -eq 'hidden') { throw [System.IO.InvalidDataException]::new('Risk details are hidden by the service; adequate risk visibility cannot be established.') }
            })
            if (@($d.riskyUsers | Where-Object { (Get-XrayValue $_ 'riskState') -eq 'confirmedCompromised' }).Count -gt 0) { $severity = 'Critical' }
        }
        'OPS-002' { $issues = @(Find-XrayIssue $d.riskDetections @('id', 'riskState', 'riskLevel') { param($r) if ($r['riskState'] -in @('atRisk', 'confirmedCompromised')) { "Unresolved risk detection; state=$($r['riskState']); level=$($r['riskLevel']); type=$(Get-XrayValue $r 'riskEventType')." } }) }
        'OPS-003' {
            $issues = @(Find-XrayIssue $d.signIns @('id', 'status.errorCode', 'clientAppUsed') {
                param($r)
                if ((Get-XrayNumber $r 'status.errorCode' -Integer) -eq 0 -and $r['clientAppUsed'] -in @('Exchange ActiveSync', 'Other clients')) { "Successful legacy authentication; client=$($r['clientAppUsed']). Assertion is limited to the collected sign-in scope and window." }
            })
        }
        'OPS-004' {
            $issues = @(Find-XrayIssue $d.signIns @('id', 'status.errorCode', 'authenticationRequirement') {
                param($r)
                if ((Get-XrayNumber $r 'status.errorCode' -Integer) -eq 0 -and $r['authenticationRequirement'] -eq 'singleFactorAuthentication') { 'Successful sign-in is reported as single-factor. Session/token context and effective policy require investigation; this is not proof of a bypass.' }
            })
        }
        'OPS-005' { $issues = @(Find-XrayIssue $d.provisioningLogs @('id', 'statusInfo.status') { param($r) if ((Get-XrayValue $r 'statusInfo.status') -in @('failure', 'warning')) { "Provisioning status=$(Get-XrayValue $r 'statusInfo.status'). Inspect error details and lifecycle impact in raw evidence." } }) }
        'OPS-006' {
            $issues = @(Find-XrayIssue $d.directoryAudits @('id', 'activityDisplayName', 'result') {
                param($r)
                if ($r['result'] -eq 'success' -and $r['activityDisplayName'] -match '(?i)(member to role|role assignment|conditional access|consent to application|credentials|federation|authentication method)') { "Sensitive directory change=$($r['activityDisplayName']); result=$($r['result']). Correlate with approved changes; not inherently malicious." }
            })
        }
        'OPS-007' {
            if ($d.secureScores.Count -eq 0) { throw [System.IO.InvalidDataException]::new('No Secure Score snapshot was returned; a score cannot be inferred.') }
            $scores = @($d.secureScores)
            if ($scores.Count -gt 1) {
                foreach ($score in $scores) { Assert-XrayFields $score @('createdDateTime') }
                $scores = @($scores | Sort-Object { ConvertTo-XrayDate $_['createdDateTime'] } -Descending)
            }
            Assert-XrayFields $scores[0] @('currentScore', 'maxScore')
            $maximum = Get-XrayNumber $scores[0] 'maxScore'
            $current = Get-XrayNumber $scores[0] 'currentScore'
            if ($maximum -le 0 -or $current -gt $maximum) { throw [System.IO.InvalidDataException]::new('Secure Score maximum is unavailable, zero, or less than the current score.') }
            $ratio = $current / $maximum
            if ($ratio -lt $Settings.SecureScoreThreshold) { $issues = @(New-XrayEntity $scores[0] "Cross-workload Secure Score ratio=$($ratio.ToString('P1', [cultureinfo]::InvariantCulture)); organizational review threshold=$($Settings.SecureScoreThreshold). Not an Entra-only rating.") }
        }
        default { throw [System.InvalidOperationException]::new("No evaluator is implemented for check '$($Definition.Id)'.") }
    }
    $status = $passStatus
    if ($issues.Count -gt 0) { $status = $adverse }
    [ordered]@{ Status = $status; Entities = $issues; Severity = $severity }
}

function New-XrayFinding {
    param($Definition, [string]$Status, [object[]]$Entities = @(), [string[]]$Limitations = @(), [string]$Severity = '')
    if (-not $Severity) { $Severity = $Definition.Severity }
    $summary = switch ($Status) {
        'Pass' { 'The stated configuration/observation test passed in the complete collected scope. Effective protection is not certified.' }
        'Fail' { "The stated adverse condition was observed ($($Entities.Count) evidence rows). A failed test is not automatically an exploitable vulnerability." }
        'Review' { "Contextual review is required ($($Entities.Count) evidence rows). This condition can be intentional; do not remediate automatically." }
        'Unknown' { 'A defensible result could not be established from complete, valid prerequisite evidence.' }
        'NotApplicable' { 'No applicable objects were present in the complete collected scope.' }
    }
    $confidence = 'High'
    if ($Status -in @('Review', 'Unknown')) { $confidence = 'ContextRequired' }
    [pscustomobject]@{
        Id = $Definition.Id; Category = $Definition.Category; Title = $Definition.Title
        Status = $Status; Severity = $Severity; Confidence = $confidence; Summary = $summary
        AffectedCount = $Entities.Count; Entities = @($Entities); Sources = @($Definition.Sources)
        Limitations = @($Limitations); Remediation = $Definition.Remediation; References = @($Definition.References)
    }
}

function Invoke-XrayAssessment {
    param([Parameter(Mandatory)]$Evidence, [Parameter(Mandatory)]$Settings, [string]$CheckId)
    $checks = @(Get-EntraXrayCheck)
    if ($CheckId) { $checks = @(Get-EntraXrayCheck -Id $CheckId) }
    $catalog = @{}
    foreach ($definition in (Get-XraySourceCatalog)) { $catalog[$definition.Id] = $definition }
    foreach ($check in $checks) {
        $limitations = [System.Collections.Generic.List[string]]::new()
        foreach ($sourceId in $check.Sources) {
            $source = $Evidence.Sources[$sourceId]
            if ($null -eq $source) { $limitations.Add("Required source '$sourceId' is absent.") }
            elseif ($source.State -ne 'Complete') { $limitations.Add("Required source '$sourceId' is $($source.State); partial or absent evidence cannot establish this test.") }
            elseif ($catalog[$sourceId].Shape -eq 'Singleton' -and $source.Items.Count -ne 1) { $limitations.Add("Required singleton source '$sourceId' does not contain exactly one policy or configuration object.") }
        }
        if ($limitations.Count -gt 0) {
            New-XrayFinding -Definition $check -Status Unknown -Limitations $limitations.ToArray()
            continue
        }
        try {
            $result = Invoke-XrayRule $check $Evidence $Settings
            New-XrayFinding -Definition $check -Status $result.Status -Entities $result.Entities -Severity $result.Severity
        }
        catch [System.IO.InvalidDataException] {
            New-XrayFinding -Definition $check -Status Unknown -Limitations @($_.Exception.Message)
        }
    }
}
