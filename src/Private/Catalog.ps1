function New-XraySource {
    param(
        [string]$Id, [string]$Path, [string]$Documentation,
        [string[]]$Permission = @('Directory.Read.All'), [string]$Shape = 'Collection',
        [string]$Parent = '', [string]$ParentFilter = 'All', [string]$ApiVersion = 'v1.0',
        [string]$Scope = 'Configuration or directory inventory at collection time.',
        [string]$Licensing = 'API availability depends on permissions, supported directory roles, cloud, and licensing.'
    )
    $view = 'graph-rest-1.0'
    if ($ApiVersion -eq 'beta') { $view = 'graph-rest-beta' }
    [ordered]@{
        Id = $Id; Method = 'GET'; Path = $Path; Shape = $Shape
        Permissions = @($Permission); Parent = $Parent; ParentFilter = $ParentFilter; ApiVersion = $ApiVersion
        Scope = $Scope; Licensing = $Licensing
        Reference = "https://learn.microsoft.com/en-us/graph/api/$($Documentation)?view=$view"
    }
}

function Get-XraySourceCatalog {
    @(
        New-XraySource organization '/organization?$select=id,displayName,verifiedDomains,onPremisesSyncEnabled,onPremisesLastSyncDateTime,technicalNotificationMails,securityComplianceNotificationMails' 'organization-list'
        New-XraySource domains '/domains?$select=id,isVerified,isDefault,authenticationType,supportedServices,passwordValidityPeriodInDays' 'domain-list'
        New-XraySource federationConfigurations '/domains/{id}/federationConfiguration' 'domain-list-federationconfiguration' -Parent domains -ParentFilter FederatedDomain
        New-XraySource subscribedSkus '/subscribedSkus' 'subscribedsku-list'
        New-XraySource users '/users?$select=id,displayName,userPrincipalName,userType,accountEnabled,createdDateTime,onPremisesSyncEnabled,onPremisesLastSyncDateTime,passwordPolicies,externalUserState,externalUserStateChangeDateTime,assignedLicenses,identities,creationType' 'user-list'
        New-XraySource userSignInActivity '/users?$select=id,signInActivity' 'user-list' -Permission @('Directory.Read.All', 'AuditLog.Read.All') -Scope 'Separately permissioned successful sign-in activity; premium licensing applies. Failure does not discard basic user inventory. Null activity is not proof of inactivity.'
        New-XraySource deletedUsers '/directory/deletedItems/microsoft.graph.user' 'directory-deleteditems-list' -Scope 'Soft-deleted objects still retained by Microsoft Graph; not permanent deletion history.'
        New-XraySource deletedGroups '/directory/deletedItems/microsoft.graph.group' 'directory-deleteditems-list'
        New-XraySource deletedApplications '/directory/deletedItems/microsoft.graph.application' 'directory-deleteditems-list'
        New-XraySource deletedServicePrincipals '/directory/deletedItems/microsoft.graph.servicePrincipal' 'directory-deleteditems-list'
        New-XraySource groups '/groups?$select=id,displayName,groupTypes,isAssignableToRole,membershipRule,membershipRuleProcessingState,visibility,onPremisesSyncEnabled,createdDateTime,securityEnabled,mailEnabled' 'group-list'
        New-XraySource groupOwners '/groups/{id}/owners?$select=id,displayName' 'group-list-owners' -Parent groups -Scope 'Owners exposed by this API. Microsoft Graph v1.0 has documented service-principal ownership limitations.'
        New-XraySource roleGroupMembers '/groups/{id}/transitiveMembers?$select=id,displayName' 'group-list-transitivemembers' -Parent groups -ParentFilter RoleAssignableGroup -Permission @('Directory.Read.All', 'Member.Read.Hidden')
        New-XraySource groupLifecyclePolicies '/groupLifecyclePolicies' 'grouplifecyclepolicy-list'
        New-XraySource applications '/applications?$select=id,appId,displayName,signInAudience,passwordCredentials,keyCredentials,requiredResourceAccess,web,spa,publicClient,api,verifiedPublisher,publisherDomain,isFallbackPublicClient' 'application-list' -Scope 'Application configuration and credential metadata only. Requested permissions are not granted permissions; secretText is never requested.'
        New-XraySource applicationOwners '/applications/{id}/owners?$select=id,displayName' 'application-list-owners' -Parent applications
        New-XraySource federatedIdentityCredentials '/applications/{id}/federatedIdentityCredentials' 'application-list-federatedidentitycredentials' -Parent applications
        New-XraySource servicePrincipals '/servicePrincipals?$select=id,appId,displayName,servicePrincipalType,accountEnabled,appOwnerOrganizationId,appRoleAssignmentRequired,appRoles,oauth2PermissionScopes,passwordCredentials,keyCredentials,preferredSingleSignOnMode,verifiedPublisher,tags' 'serviceprincipal-list'
        New-XraySource servicePrincipalOwners '/servicePrincipals/{id}/owners?$select=id,displayName' 'serviceprincipal-list-owners' -Parent servicePrincipals
        New-XraySource appRoleAssignments '/servicePrincipals/{id}/appRoleAssignments' 'serviceprincipal-list-approleassignments' -Parent servicePrincipals -Scope 'Granted application permissions, collected from each client service principal; does not infer grants from application manifests.'
        New-XraySource oauth2PermissionGrants '/oauth2PermissionGrants' 'oauth2permissiongrant-list'
        New-XraySource roleDefinitions '/roleManagement/directory/roleDefinitions' 'rbacapplication-list-roledefinitions' -Permission RoleManagement.Read.Directory
        New-XraySource roleAssignments '/roleManagement/directory/roleAssignments' 'rbacapplication-list-roleassignments' -Permission RoleManagement.Read.Directory
        New-XraySource roleAssignmentScheduleInstances '/roleManagement/directory/roleAssignmentScheduleInstances' 'rbacapplication-list-roleassignmentscheduleinstances' -Permission RoleAssignmentSchedule.Read.Directory
        New-XraySource roleEligibilityScheduleInstances '/roleManagement/directory/roleEligibilityScheduleInstances' 'rbacapplication-list-roleeligibilityscheduleinstances' -Permission RoleEligibilitySchedule.Read.Directory
        New-XraySource roleGroupAssignmentScheduleInstances '/identityGovernance/privilegedAccess/group/assignmentScheduleInstances?$filter=groupId eq ''{id}''' 'privilegedaccessgroup-list-assignmentscheduleinstances' -Permission PrivilegedAssignmentSchedule.Read.AzureADGroup -Parent groups -ParentFilter RoleAssignableGroup
        New-XraySource roleGroupEligibilityScheduleInstances '/identityGovernance/privilegedAccess/group/eligibilityScheduleInstances?$filter=groupId eq ''{id}''' 'privilegedaccessgroup-list-eligibilityscheduleinstances' -Permission PrivilegedEligibilitySchedule.Read.AzureADGroup -Parent groups -ParentFilter RoleAssignableGroup -Scope 'PIM eligibility for role-assignable groups. Review potential activation/ownership paths separately; eligibility is not active membership.'
        New-XraySource roleManagementPolicies '/policies/roleManagementPolicies?$filter=scopeId eq ''/'' and scopeType eq ''DirectoryRole''&$expand=rules' 'policyroot-list-rolemanagementpolicies' -Permission RoleManagementPolicy.Read.Directory
        New-XraySource roleManagementPolicyAssignments '/policies/roleManagementPolicyAssignments?$filter=scopeId eq ''/'' and scopeType eq ''DirectoryRole''' 'policyroot-list-rolemanagementpolicyassignments' -Permission RoleManagementPolicy.Read.Directory
        New-XraySource administrativeUnits '/directory/administrativeUnits' 'directory-list-administrativeunits'
        New-XraySource administrativeUnitMembers '/directory/administrativeUnits/{id}/members?$select=id,displayName' 'administrativeunit-list-members' -Parent administrativeUnits
        New-XraySource authorizationPolicy '/policies/authorizationPolicy' 'authorizationpolicy-get' -Permission Policy.Read.All -Shape Singleton
        New-XraySource securityDefaults '/policies/identitySecurityDefaultsEnforcementPolicy' 'identitysecuritydefaultsenforcementpolicy-get' -Permission Policy.Read.All -Shape Singleton
        New-XraySource authenticationMethodsPolicy '/policies/authenticationMethodsPolicy' 'authenticationmethodspolicy-get' -Permission Policy.Read.AuthenticationMethod -Shape Singleton
        New-XraySource authenticationMethodConfigurations '/policies/authenticationMethodsPolicy/authenticationMethodConfigurations' 'resources/authenticationmethodspolicy' -Permission Policy.Read.AuthenticationMethod
        New-XraySource authenticationStrengthPolicies '/policies/authenticationStrengthPolicies' 'authenticationstrengthroot-list-policies' -Permission Policy.Read.All
        New-XraySource conditionalAccessPolicies '/identity/conditionalAccess/policies' 'conditionalaccessroot-list-policies' -Permission Policy.Read.All
        New-XraySource namedLocations '/identity/conditionalAccess/namedLocations' 'conditionalaccessroot-list-namedlocations' -Permission Policy.Read.All
        New-XraySource authenticationContextClassReferences '/identity/conditionalAccess/authenticationContextClassReferences' 'conditionalaccessroot-list-authenticationcontextclassreferences' -Permission Policy.Read.All
        New-XraySource adminConsentRequestPolicy '/policies/adminConsentRequestPolicy' 'adminconsentrequestpolicy-get' -Permission Policy.Read.All -Shape Singleton
        New-XraySource permissionGrantPolicies '/policies/permissionGrantPolicies' 'permissiongrantpolicy-list' -Permission Policy.Read.All
        New-XraySource permissionGrantIncludes '/policies/permissionGrantPolicies/{id}/includes' 'permissiongrantpolicy-list-includes' -Permission Policy.Read.All -Parent permissionGrantPolicies
        New-XraySource permissionGrantExcludes '/policies/permissionGrantPolicies/{id}/excludes' 'permissiongrantpolicy-list-excludes' -Permission Policy.Read.All -Parent permissionGrantPolicies
        New-XraySource crossTenantDefault '/policies/crossTenantAccessPolicy/default' 'crosstenantaccesspolicyconfigurationdefault-get' -Permission Policy.Read.All -Shape Singleton
        New-XraySource crossTenantPartners '/policies/crossTenantAccessPolicy/partners' 'crosstenantaccesspolicy-list-partners' -Permission Policy.Read.All
        New-XraySource activityBasedTimeoutPolicies '/policies/activityBasedTimeoutPolicies' 'activitybasedtimeoutpolicy-list' -Permission Policy.Read.All
        New-XraySource tokenLifetimePolicies '/policies/tokenLifetimePolicies' 'tokenlifetimepolicy-list' -Permission Policy.Read.All
        New-XraySource appManagementPolicy '/policies/defaultAppManagementPolicy' 'tenantappmanagementpolicy-get' -Permission Policy.Read.All -Shape Singleton
        New-XraySource appManagementPolicies '/policies/appManagementPolicies' 'appmanagementpolicy-list' -Permission Policy.Read.All
        New-XraySource identityProviders '/identity/identityProviders?$select=id,displayName' 'identitycontainer-list-identityproviders' -Permission IdentityProvider.Read.All -Scope 'Provider identifiers, names, and returned types only; client secrets are not selected.'
        New-XraySource devices '/devices?$select=id,deviceId,displayName,operatingSystem,operatingSystemVersion,accountEnabled,isManaged,isCompliant,trustType,registrationDateTime,approximateLastSignInDateTime,onPremisesSyncEnabled' 'device-list'
        New-XraySource registrationDetails '/reports/authenticationMethods/userRegistrationDetails' 'authenticationmethodsroot-list-userregistrationdetails' -Permission AuditLog.Read.All -Licensing 'Authentication methods activity/reporting licensing and a supported reader role are required. Disabled users are not returned.'
        New-XraySource riskyUsers '/identityProtection/riskyUsers' 'riskyuser-list' -Permission IdentityRiskyUser.Read.All -Licensing 'Full Identity Protection data generally requires Microsoft Entra ID P2.'
        New-XraySource riskDetections '/identityProtection/riskDetections?$filter=detectedDateTime ge {start} and detectedDateTime le {end}' 'riskdetection-list' -Permission IdentityRiskEvent.Read.All -Scope 'Risk detections detected in the requested UTC window, subject to service retention and licensing.'
        New-XraySource signIns '/auditLogs/signIns?$filter=createdDateTime ge {start} and createdDateTime le {end}' 'signin-list' -Permission AuditLog.Read.All -Scope 'v1.0 default interactive user sign-ins only, within the requested UTC window and service retention. Other sign-in types are separate beta opt-ins.'
        New-XraySource directoryAudits '/auditLogs/directoryAudits?$filter=activityDateTime ge {start} and activityDateTime le {end}' 'directoryaudit-list' -Permission AuditLog.Read.All -Scope 'Directory audit events in the requested UTC window, subject to retention. Not a complete forensic history.'
        New-XraySource provisioningLogs '/auditLogs/provisioning?$filter=activityDateTime ge {start} and activityDateTime le {end}' 'provisioningobjectsummary-list' -Permission AuditLog.Read.All -Scope 'Provisioning events in the requested UTC window, subject to retention.'
        New-XraySource secureScores '/security/secureScores' 'security-list-securescores' -Permission SecurityEvents.Read.All -Scope 'Graph-retained Microsoft Secure Score history. Cross-workload context, not an Entra-only security rating.'
        New-XraySource secureScoreControlProfiles '/security/secureScoreControlProfiles' 'security-list-securescorecontrolprofiles' -Permission SecurityEvents.Read.All
        New-XraySource accessReviewDefinitions '/identityGovernance/accessReviews/definitions' 'accessreviewset-list-definitions' -Permission AccessReview.Read.All
        New-XraySource accessReviewInstances '/identityGovernance/accessReviews/definitions/{id}/instances' 'accessreviewscheduledefinition-list-instances' -Permission AccessReview.Read.All -Parent accessReviewDefinitions
        New-XraySource accessReviewDecisions '/identityGovernance/accessReviews/definitions/{parentId}/instances/{id}/decisions' 'accessreviewinstance-list-decisions' -Permission AccessReview.Read.All -Parent accessReviewInstances
        New-XraySource entitlementCatalogs '/identityGovernance/entitlementManagement/catalogs' 'entitlementmanagement-list-catalogs' -Permission EntitlementManagement.Read.All
        New-XraySource accessPackages '/identityGovernance/entitlementManagement/accessPackages' 'entitlementmanagement-list-accesspackages' -Permission EntitlementManagement.Read.All
        New-XraySource accessPackageAssignmentPolicies '/identityGovernance/entitlementManagement/assignmentPolicies' 'entitlementmanagement-list-assignmentpolicies' -Permission EntitlementManagement.Read.All
        New-XraySource accessPackageAssignments '/identityGovernance/entitlementManagement/assignments?$expand=target' 'entitlementmanagement-list-assignments' -Permission EntitlementManagement.Read.All
        New-XraySource connectedOrganizations '/identityGovernance/entitlementManagement/connectedOrganizations' 'entitlementmanagement-list-connectedorganizations' -Permission EntitlementManagement.Read.All
        New-XraySource termsOfUse '/identityGovernance/termsOfUse/agreements' 'termsofusecontainer-list-agreements' -Permission Agreement.Read.All
        New-XraySource lifecycleWorkflows '/identityGovernance/lifecycleWorkflows/workflows' 'identitygovernance-lifecycleworkflowscontainer-list-workflows' -Permission LifecycleWorkflows.Read.All
        New-XraySource lifecycleWorkflowRuns '/identityGovernance/lifecycleWorkflows/workflows/{id}/runs' 'identitygovernance-workflow-list-runs' -Permission LifecycleWorkflows.Read.All -Parent lifecycleWorkflows
        New-XraySource deviceRegistrationPolicy '/policies/deviceRegistrationPolicy' 'deviceregistrationpolicy-get' -Permission Policy.Read.All -Shape Singleton -ApiVersion beta
        New-XraySource directoryRecommendations '/directory/recommendations' 'directory-list-recommendation' -Permission DirectoryRecommendations.Read.All -ApiVersion beta
        New-XraySource riskyServicePrincipals '/identityProtection/riskyServicePrincipals' 'identityprotectionroot-list-riskyserviceprincipals' -Permission IdentityRiskyServicePrincipal.Read.All -ApiVersion beta -Licensing 'Microsoft Entra Workload ID Premium is required; availability also varies by cloud.'
        New-XraySource servicePrincipalRiskDetections '/identityProtection/servicePrincipalRiskDetections?$filter=detectedDateTime ge {start} and detectedDateTime le {end}' 'identityprotectionroot-list-serviceprincipalriskdetections' -Permission IdentityRiskEvent.Read.All -ApiVersion beta -Licensing 'Microsoft Entra Workload ID Premium is required; availability also varies by cloud.'
        New-XraySource nonInteractiveSignIns '/auditLogs/signIns?$filter=createdDateTime ge {start} and createdDateTime le {end} and signInEventTypes/any(t:t eq ''nonInteractiveUser'')' 'signin-list' -Permission AuditLog.Read.All -ApiVersion beta -Scope 'Non-interactive user sign-ins in the requested UTC window; preview API, retention and licensing apply.'
        New-XraySource servicePrincipalSignIns '/auditLogs/signIns?$filter=createdDateTime ge {start} and createdDateTime le {end} and signInEventTypes/any(t:t eq ''servicePrincipal'')' 'signin-list' -Permission AuditLog.Read.All -ApiVersion beta -Scope 'Service-principal sign-ins in the requested UTC window; preview API, retention and licensing apply.'
        New-XraySource managedIdentitySignIns '/auditLogs/signIns?$filter=createdDateTime ge {start} and createdDateTime le {end} and signInEventTypes/any(t:t eq ''managedIdentity'')' 'signin-list' -Permission AuditLog.Read.All -ApiVersion beta -Scope 'Managed-identity sign-ins in the requested UTC window; preview API, retention and licensing apply.'
    )
}

function Get-EntraXrayPlan {
    [CmdletBinding()]
    param(
        [string[]]$SourceId,
        [switch]$IncludeBeta,
        [ValidateSet('Global', 'USGov', 'USGovDoD', 'China')][string]$Environment = 'Global'
    )
    $clouds = @{
        Global = 'https://graph.microsoft.com'; USGov = 'https://graph.microsoft.us'
        USGovDoD = 'https://dod-graph.microsoft.us'; China = 'https://microsoftgraph.chinacloudapi.cn'
    }
    $catalog = @(Get-XraySourceCatalog)
    $byId = @{}
    foreach ($source in $catalog) { $byId[$source.Id] = $source }
    $selected = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    if ($SourceId) {
        foreach ($id in $SourceId) {
            if (-not $byId.ContainsKey($id)) { throw [System.ArgumentException]::new("Unknown source '$id'. Use Get-EntraXrayPlan to inspect supported sources.") }
            if ($byId[$id].ApiVersion -eq 'beta' -and -not $IncludeBeta) {
                throw [System.ArgumentException]::new("Source '$id' requires explicit -IncludeBeta.")
            }
            $next = $id
            while ($next) {
                [void]$selected.Add($next)
                $next = $byId[$next].Parent
            }
        }
    }
    else {
        foreach ($source in $catalog) {
            if ($source.ApiVersion -eq 'v1.0' -or $IncludeBeta) { [void]$selected.Add($source.Id) }
        }
    }
    $sources = @($catalog | Where-Object { $selected.Contains($_.Id) })
    [pscustomobject]@{
        Environment = $Environment; GraphBaseUri = $clouds[$Environment]; Sources = $sources
        Permissions = @($sources | ForEach-Object Permissions | Sort-Object -Unique)
        Note = 'All assessment requests are GET. Read-only permissions still expose sensitive information and require appropriate consent and reader roles. No Graph write or permission-grant API is invoked; SDK OAuth authentication can prompt for operator consent.'
    }
}

function New-XrayCheckDefinition {
    param(
        [string]$Id, [string]$Category, [string]$Title, [string[]]$Sources,
        [string]$Severity, [string]$Remediation, [string]$Reference,
        [string]$AdverseStatus = 'Review'
    )
    [pscustomobject]@{
        Id = $Id; Category = $Category; Title = $Title; Sources = $Sources; Severity = $Severity
        AdverseStatus = $AdverseStatus; Remediation = $Remediation; References = @($Reference)
    }
}

function Get-EntraXrayCheck {
    [CmdletBinding()]
    param([string]$Id)
    $entra = 'https://learn.microsoft.com/en-us/entra'
    $auth = "$entra/identity/authentication"
    $ca = "$entra/identity/conditional-access"
    $apps = "$entra/identity/enterprise-apps"
    $roles = "$entra/identity/role-based-access-control"
    $governance = "$entra/id-governance"
    $checks = @(
        New-XrayCheckDefinition TEN-001 'Tenant' 'Hybrid synchronization freshness' organization High 'Investigate the last completed synchronization and sync health; the threshold is organizational policy, not proof of a sync failure.' "$entra/identity/hybrid/connect/how-to-connect-health-sync" -AdverseStatus Fail
        New-XrayCheckDefinition TEN-002 'Tenant' 'Federation transport security' federationConfigurations High 'Review the complete federation trust, signing certificates, MFA claims, and IdP controls. Replace non-HTTPS protocol endpoints where applicable.' "$entra/identity/hybrid/connect/how-to-connect-fed-management" -AdverseStatus Fail
        New-XrayCheckDefinition TEN-003 'Tenant' 'Unverified custom domains' domains Low 'Confirm whether each unverified domain is intentional or abandoned; do not delete domains without dependency analysis.' "$entra/fundamentals/add-custom-domain"
        New-XrayCheckDefinition TEN-004 'Tenant' 'License capacity' subscribedSkus Low 'Reconcile enabled license capacity and consumed units. Licensing is operational context, not a vulnerability.' 'https://learn.microsoft.com/en-us/graph/api/resources/subscribedsku?view=graph-rest-1.0'
        New-XrayCheckDefinition AUTH-001 'Authentication' 'Security defaults or unqualified tenant-wide MFA configuration' @('securityDefaults', 'conditionalAccessPolicies', 'authenticationStrengthPolicies') High 'Evaluate MFA coverage using Conditional Access What If, sign-in logs, exclusions, authentication strengths, and emergency-access requirements. Do not enable a blanket policy without lockout testing.' "$ca/plan-conditional-access" -AdverseStatus Fail
        New-XrayCheckDefinition AUTH-002 'Authentication' 'Enabled users without registered MFA' @('users', 'registrationDetails') High 'Investigate enabled accounts without MFA registration. Registration is not enforcement; service identities and guests require contextual handling.' "$auth/howto-authentication-methods-activity" -AdverseStatus Fail
        New-XrayCheckDefinition AUTH-003 'Authentication' 'Enabled users not MFA-capable under current policy' @('users', 'registrationDetails') High 'Investigate method registration and authentication-method policy eligibility. Capability does not establish that MFA is required at sign-in.' "$auth/howto-authentication-methods-activity" -AdverseStatus Fail
        New-XrayCheckDefinition AUTH-004 'Authentication' 'SSPR-enabled members lacking SSPR registration' @('users', 'registrationDetails') Medium 'Complete SSPR registration for users actually enabled for SSPR; review helpdesk identity-verification and recovery processes.' "$auth/concept-sspr-howitworks"
        New-XrayCheckDefinition AUTH-005 'Authentication' 'Passkey (FIDO2) policy availability' authenticationMethodConfigurations Medium 'Consider phishing-resistant authentication. FIDO2 disabled is not proof that Windows Hello or certificate-based MFA is unavailable.' "$auth/concept-authentication-passkeys-fido2"
        New-XrayCheckDefinition AUTH-006 'Authentication' 'SMS or voice authentication enabled' authenticationMethodConfigurations Medium 'Review permitted populations and migrate sensitive access to phishing-resistant methods. An enabled method does not prove it is used or accepted by every resource.' "$auth/concept-authentication-methods"
        New-XrayCheckDefinition AUTH-007 'Authentication' 'Authentication-method policy migration' authenticationMethodsPolicy Medium 'Validate migration from legacy MFA/SSPR method management to the authentication methods policy.' "$auth/how-to-authentication-methods-manage"
        New-XrayCheckDefinition AUTH-008 'Authentication' 'Temporary Access Pass lifetime and reuse' authenticationMethodConfigurations Medium 'Review TAP issuance, lifetime, permitted groups, and single-use settings against onboarding and recovery needs; this check uses a 60-minute review threshold.' "$auth/howto-authentication-temporary-access-pass"
        New-XrayCheckDefinition AUTH-009 'Authentication' 'Email-verified self-service tenant joining' authorizationPolicy Medium 'Confirm that email-verified joining is intentional and governed; its availability alone is not unauthorized access.' "$entra/identity/users/directory-self-service-signup"
        New-XrayCheckDefinition AUTH-010 'Authentication' 'Default member application-registration permission' authorizationPolicy Low 'Review whether all members should register applications; preserve legitimate development workflows and assigned application developer roles.' "$entra/fundamentals/users-default-permissions"
        New-XrayCheckDefinition AUTH-011 'Authentication' 'Default user consent policy assignments' @('authorizationPolicy', 'permissionGrantPolicies') Medium 'Review assigned permission-grant policies and their include/exclude conditions. Low-risk verified-publisher consent can be intentional; assignments alone do not prove unrestricted consent.' "$apps/configure-user-consent"
        New-XrayCheckDefinition AUTH-012 'Authentication' 'Admin consent request workflow' adminConsentRequestPolicy Low 'Review the admin-consent workflow and alternative approval processes; a disabled workflow is not proof of uncontrolled grants.' "$apps/configure-admin-consent-workflow"
        New-XrayCheckDefinition CA-001 'Conditional Access' 'Report-only policies are not enforced' conditionalAccessPolicies Medium 'Validate report-only results, rollout plans, and overlapping enforced policies before activation.' "$ca/concept-conditional-access-report-only"
        New-XrayCheckDefinition CA-002 'Conditional Access' 'Disabled Conditional Access policies' conditionalAccessPolicies Low 'Classify disabled policies as contingency, retired, or unintentionally inactive; never enable them automatically.' "$ca/plan-conditional-access"
        New-XrayCheckDefinition CA-003 'Conditional Access' 'Conditional Access exclusions' conditionalAccessPolicies High 'Review excluded users, groups, roles, applications, and filters, including justified emergency-access exclusions and their monitoring.' "$ca/plan-conditional-access"
        New-XrayCheckDefinition CA-004 'Conditional Access' 'Unqualified legacy-authentication block configuration' @('securityDefaults', 'conditionalAccessPolicies') High 'Validate all-user/all-resource blocking for both legacy client types and test emergency access. Absence of one broad policy does not prove absence of protection from a combination of policies.' "$ca/policy-block-legacy-authentication"
        New-XrayCheckDefinition CA-005 'Conditional Access' 'Enabled phishing-resistant authentication-strength requirements' @('conditionalAccessPolicies', 'authenticationStrengthPolicies') High 'Review effective scope and require appropriate phishing-resistant strengths for sensitive access; the existence of a policy does not establish administrator coverage.' "$auth/concept-authentication-strengths"
        New-XrayCheckDefinition CA-006 'Conditional Access' 'Enabled risk-conditioned access controls' conditionalAccessPolicies Medium 'Review user-risk and sign-in-risk policies, actual grant controls, licensing, exclusions, and remediation workflows.' "$ca/policy-risk-based-sign-in"
        New-XrayCheckDefinition CA-007 'Conditional Access' 'Trusted named locations containing the entire address space' namedLocations High 'Investigate trusted ranges of 0.0.0.0/0 or ::/0 and their policy dependencies. A named location alone does not establish an authentication bypass.' "$ca/concept-assignment-network" -AdverseStatus Fail
        New-XrayCheckDefinition CA-008 'Conditional Access' 'Always-persistent browser sessions' conditionalAccessPolicies Medium 'Review device trust, session lifetime, and sensitive populations. Persistent sessions can be intentional.' "$ca/howto-conditional-access-session-lifetime"
        New-XrayCheckDefinition ID-001 'Identity' 'Enabled stale member accounts (successful activity only)' @('users', 'userSignInActivity') Medium 'Validate account ownership and business need using successful sign-ins, workload activity, and provisioning history before disabling anything.' "$entra/identity/monitoring-health/howto-manage-inactive-user-accounts"
        New-XrayCheckDefinition ID-002 'Identity' 'Older enabled accounts with no observed successful-activity timestamp' @('users', 'userSignInActivity') Medium 'Investigate missing activity telemetry, service retention/backfill limits, and legitimate non-interactive use. Null timestamps do not prove that an account has never signed in.' "$entra/identity/monitoring-health/howto-manage-inactive-user-accounts"
        New-XrayCheckDefinition ID-003 'Identity' 'Enabled stale guest accounts' @('users', 'userSignInActivity') Medium 'Use sponsors, access reviews, and workload activity to validate guest access before revocation.' "$governance/manage-guest-access-with-access-reviews"
        New-XrayCheckDefinition ID-004 'Identity' 'Old unredeemed guest invitations' users Low 'Review pending invitations, sponsors, and current access requirements before removing invited guests.' "$entra/external-id/redemption-experience"
        New-XrayCheckDefinition ID-005 'Identity' 'Cloud accounts with strong-password policy disabled' users High 'Investigate DisableStrongPassword on enabled cloud-managed accounts. DisablePasswordExpiration is deliberately not treated as an exposure.' "$auth/concept-sspr-policy" -AdverseStatus Fail
        New-XrayCheckDefinition PRIV-001 'Privileged access' 'Active tenant-wide Global Administrator population' @('roleDefinitions', 'roleAssignments', 'groups', 'roleGroupMembers', 'servicePrincipals', 'users') High 'Minimize standing Global Administrator access and review effective group membership. The configurable maximum is a review threshold for enabled human principals, not a universal compliance mandate.' "$roles/best-practices"
        New-XrayCheckDefinition PRIV-002 'Privileged access' 'At least two available human Global Administrator principals' @('roleDefinitions', 'roleAssignments', 'roleEligibilityScheduleInstances', 'groups', 'roleGroupMembers', 'servicePrincipals', 'users') High 'Verify resilient administrative access. Eligible principals are counted separately from standing grants and do not substitute for independently usable emergency accounts.' "$roles/security-emergency-access"
        New-XrayCheckDefinition PRIV-003 'Privileged access' 'Unbounded standing privileged assignments' @('roleDefinitions', 'roleAssignmentScheduleInstances') High 'Prefer time-bound or eligible privileged access. Declared emergency accounts are excluded from this review signal, not exempted from monitoring.' "$governance/privileged-identity-management/pim-configure"
        New-XrayCheckDefinition PRIV-004 'Privileged access' 'Guest principals with active privileged roles' @('roleDefinitions', 'roleAssignments', 'users', 'groups', 'roleGroupMembers') High 'Verify sponsorship, cross-tenant controls, and business justification for guest administrators; delegated administration can be intentional.' "$roles/best-practices"
        New-XrayCheckDefinition PRIV-005 'Privileged access' 'Service principals with active privileged directory roles' @('roleDefinitions', 'roleAssignments', 'servicePrincipals') High 'Review app identity ownership, credential lifecycle, workload protections, and least privilege; service principals cannot satisfy user MFA.' "$entra/workload-id/workload-identities-overview"
        New-XrayCheckDefinition PRIV-006 'Privileged access' 'PIM activation enablement controls' roleManagementPolicies High 'Review activation MFA requirements alongside authentication-context policies, approval, role mappings, and emergency access. This check is not a simulation of PIM enforcement.' "$governance/privileged-identity-management/pim-how-to-change-default-settings"
        New-XrayCheckDefinition PRIV-007 'Privileged access' 'Role-assignable groups without visible owners' @('groups', 'groupOwners') Medium 'Establish accountable ownership and review privileged group membership and administration; API ownership visibility has limitations.' "$roles/groups-concept"
        New-XrayCheckDefinition PRIV-008 'Privileged access' 'Emergency-access assurance requires human validation' @('users', 'roleAssignments', 'roleDefinitions') High 'Independently verify at least two cloud-only emergency accounts, phishing-resistant credentials independent of normal admin methods, Conditional Access resilience, alerting, secure storage, and regular tested access.' "$roles/security-emergency-access"
        New-XrayCheckDefinition APP-001 'Applications' 'Expired application or service-principal credential metadata' @('applications', 'servicePrincipals') Medium 'Review expired password and key credentials and active alternatives. Expired metadata does not prove an application outage; never export secret values.' "$apps/what-is-application-management"
        New-XrayCheckDefinition APP-002 'Applications' 'Application or service-principal credentials expiring soon' @('applications', 'servicePrincipals') Medium 'Plan credential rotation, owner notification, and dependency testing before the configurable expiry window; SAML signing keys are included as metadata.' "$apps/what-is-application-management"
        New-XrayCheckDefinition APP-003 'Applications' 'Long-lived application or service-principal credentials' @('applications', 'servicePrincipals') Medium 'Prefer managed identity or carefully scoped federation where supported; otherwise rotate credentials within the organizational maximum lifetime.' "$entra/identity-platform/security-best-practices-for-app-registration"
        New-XrayCheckDefinition APP-004 'Applications' 'Application registrations without visible owners' @('applications', 'applicationOwners') Medium 'Assign accountable application owners and review owner privileges and operational contacts.' "$apps/assign-app-owners"
        New-XrayCheckDefinition APP-005 'Applications' 'Enabled locally owned enterprise applications without visible owners' @('servicePrincipals', 'servicePrincipalOwners') Medium 'Review locally owned enterprise-app ownership. Managed identities and vendor-owned applications are not treated as missing local app ownership.' "$apps/assign-app-owners"
        New-XrayCheckDefinition APP-006 'Applications' 'Multitenant or consumer-capable application registrations' applications Low 'Confirm intended account audiences, publisher verification, authorization, and tenant restrictions. Multitenancy itself is not a vulnerability.' "$entra/identity-platform/single-and-multi-tenant-apps"
        New-XrayCheckDefinition APP-007 'Applications' 'Non-loopback HTTP redirect URIs' applications High 'Use HTTPS for non-loopback redirects and review redirect ownership. Native loopback HTTP is a supported exception.' "$entra/identity-platform/reply-url" -AdverseStatus Fail
        New-XrayCheckDefinition APP-008 'Applications' 'Implicit-grant token issuance enabled' applications Medium 'Review whether implicit flow remains necessary and migrate appropriate clients to authorization code with PKCE; do not break legacy clients blindly.' "$entra/identity-platform/v2-oauth2-implicit-grant-flow"
        New-XrayCheckDefinition APP-009 'Applications' 'Granted high-impact Microsoft Graph application permissions' @('appRoleAssignments', 'servicePrincipals') High 'Validate actual granted application permissions, owner control paths, credentials, and workload identity protections. Legitimate high-privilege automation requires explicit justification.' "$entra/identity-platform/permissions-consent-overview"
        New-XrayCheckDefinition APP-010 'Applications' 'Tenant-wide high-impact delegated consent grants' oauth2PermissionGrants High 'Review AllPrincipals grants and effective delegated user privileges. Broad consent does not confer application-only access.' "$apps/manage-application-permissions"
        New-XrayCheckDefinition APP-011 'Applications' 'Granted permissions to retired Azure AD Graph' @('servicePrincipals', 'appRoleAssignments', 'oauth2PermissionGrants') High 'Migrate dependencies and granted permissions from Azure AD Graph to Microsoft Graph; requested permissions alone are not counted as grants.' 'https://learn.microsoft.com/en-us/graph/migrate-azure-ad-graph-overview' -AdverseStatus Fail
        New-XrayCheckDefinition APP-012 'Applications' 'Non-HTTPS workload-federation issuers' federatedIdentityCredentials High 'Review federated identity issuer, exact subject or claims expression, audience, external repository/pipeline controls, and trust ownership.' "$entra/workload-id/workload-identity-federation" -AdverseStatus Fail
        New-XrayCheckDefinition APP-013 'Applications' 'External workload-federation trust requires validation' federatedIdentityCredentials High 'Validate external issuer security, subject scoping, mutable branch/environment protections, audiences, and external administrators. Entra configuration alone cannot validate those external controls.' "$entra/workload-id/workload-identity-federation"
        New-XrayCheckDefinition APP-014 'Applications' 'Enabled enterprise applications not requiring user assignment' servicePrincipals Medium 'Review assignment requirements together with app-side authorization and consent; this setting does not by itself prove unauthorized data access.' "$apps/assign-user-or-group-access-portal"
        New-XrayCheckDefinition DEV-001 'Devices' 'Enabled stale registered devices' devices Medium 'Confirm device ownership, Intune/workload activity, and recovery dependencies before disabling or deleting stale device objects.' "$entra/identity/devices/manage-stale-devices"
        New-XrayCheckDefinition DEV-002 'Devices' 'Enabled devices explicitly reported noncompliant' devices Medium 'Correlate Entra metadata with the device-management authority and effective Conditional Access. Null is not interpreted as compliant or noncompliant.' "$entra/identity/devices/overview"
        New-XrayCheckDefinition DEV-003 'Devices' 'Enabled devices explicitly reported unmanaged' devices Medium 'Review unmanaged access with device trust type, BYOD policy, app protection, and Conditional Access; unmanaged is not automatically unauthorized.' "$entra/identity/devices/overview"
        New-XrayCheckDefinition EXT-001 'External identities' 'Guest invitations allowed from everyone' authorizationPolicy Medium 'Review invitation rights, sponsors, cross-tenant policy, and collaboration needs; choose restrictions deliberately.' "$entra/external-id/external-collaboration-settings-configure"
        New-XrayCheckDefinition EXT-002 'External identities' 'Guest directory visibility beyond the most restricted guest role' authorizationPolicy Low 'Review the selected guest directory role against collaboration requirements; default guest visibility can be intentional.' "$entra/fundamentals/users-default-permissions"
        New-XrayCheckDefinition EXT-003 'External identities' 'Inbound trust of partner MFA claims' @('crossTenantDefault', 'crossTenantPartners') Medium 'Validate partner assurance, targeted populations, and effective Conditional Access before trusting inbound MFA. Partner overrides must be reviewed independently.' "$entra/external-id/cross-tenant-access-settings-b2b-collaboration"
        New-XrayCheckDefinition EXT-004 'External identities' 'Default inbound B2B collaboration allows all users and applications' crossTenantDefault Medium 'Review default and partner-specific inbound/outbound settings, organization restrictions, and resource authorization. Allowed collaboration is not automatic resource access.' "$entra/external-id/cross-tenant-access-overview"
        New-XrayCheckDefinition GOV-001 'Governance' 'Access review definitions present' accessReviewDefinitions Medium 'Review recurring coverage, reviewers, decision application, exceptions, and licenses. A definition alone does not prove that reviews are effective.' "$governance/access-reviews-overview"
        New-XrayCheckDefinition GOV-002 'Governance' 'Access reviews automatically approve when reviewers do not respond' accessReviewDefinitions Medium 'Validate default decisions and whether results are applied; nonresponse approval can preserve unnecessary access.' "$governance/create-access-review"
        New-XrayCheckDefinition GOV-003 'Governance' 'Access-package assignment policies without expiration' accessPackageAssignmentPolicies Medium 'Review assignment duration, recurring reviews, and external-user lifecycle. Permanent access can be justified.' "$governance/entitlement-management-overview"
        New-XrayCheckDefinition GOV-004 'Governance' 'Disabled lifecycle workflows' lifecycleWorkflows Medium 'Confirm intentional disabled workflows and alternative joiner/mover/leaver controls; inspect run history and failures in the evidence.' "$governance/what-are-lifecycle-workflows"
        New-XrayCheckDefinition OPS-001 'Operations' 'Unresolved risky or confirmed-compromised users' riskyUsers High 'Investigate in Identity Protection, correlate sign-ins and incident evidence, and contain confirmed compromises through an approved response process.' "$entra/id-protection/howto-identity-protection-investigate-risk" -AdverseStatus Fail
        New-XrayCheckDefinition OPS-002 'Operations' 'Unresolved risk detections in the requested window' riskDetections High 'Correlate risk events with users, service activity, investigation state, and incident response. Detection is not automatically proof of compromise.' "$entra/id-protection/concept-identity-protection-risks" -AdverseStatus Fail
        New-XrayCheckDefinition OPS-003 'Operations' 'Successful legacy authentication observed' signIns High 'Investigate successful Exchange ActiveSync or Other clients sign-ins and migrate legacy dependencies before enforcing blocks. Only the collected interactive sign-in scope is asserted.' "$ca/block-legacy-authentication" -AdverseStatus Fail
        New-XrayCheckDefinition OPS-004 'Operations' 'Successful sign-ins reported as single-factor' signIns Medium 'Review authentication details, token/session context, per-user MFA, security defaults, and Conditional Access. Single-factor metadata alone does not prove a bypass.' "$entra/identity/monitoring-health/concept-sign-in-log-activity-details"
        New-XrayCheckDefinition OPS-005 'Operations' 'Provisioning failures in the requested window' provisioningLogs Medium 'Investigate provisioning errors, affected identities, retries, and upstream/downstream lifecycle impact.' "$entra/identity/monitoring-health/concept-provisioning-logs"
        New-XrayCheckDefinition OPS-006 'Operations' 'Sensitive directory changes in the requested window' directoryAudits Medium 'Correlate role, consent, credential, federation, and Conditional Access changes with approved change records. Sensitive changes are not inherently malicious.' "$entra/identity/monitoring-health/concept-audit-logs"
        New-XrayCheckDefinition OPS-007 'Operations' 'Microsoft Secure Score context below the organizational threshold' secureScores Low 'Review individual improvement actions and licensing. Secure Score spans workloads and is neither a complete security assessment nor an Entra-only rating.' 'https://learn.microsoft.com/en-us/defender-xdr/microsoft-secure-score'
    )
    if ($Id) {
        $match = @($checks | Where-Object Id -EQ $Id)
        if ($match.Count -eq 0) { throw [System.ArgumentException]::new("Unknown check '$Id'.") }
        return $match[0]
    }
    $checks
}
