# Microsoft Entra ID X-Ray

A read-only PowerShell toolkit for collecting a defensible picture of a Microsoft Entra ID tenant: the healthy configuration, confirmed adverse conditions, operational debt, suspicious observations, and things that cannot be established from the available evidence.

**69 assessment checks. 70 Microsoft Graph v1.0 evidence sources. Seven additional, explicitly opt-in beta sources.** Every check has a stable identifier, prerequisites, severity/priority, evidence rows, investigation guidance, and Microsoft documentation references.

This is deliberately **not** a certification, penetration test, exhaustive attack-path engine, or promise that every tenant weakness is discoverable through Microsoft Graph. Configuration evidence is not proof of effective protection. Azure subscriptions and Microsoft 365 workload configuration are outside this project's scope.

## Safety contract

- Every assessment Graph request is `GET`. No Graph remediation, role/consent-write endpoints, user changes, sign-in probes, or password testing.
- No password/secret values, private keys, tokens, or recovery keys are intentionally requested. Application credential **metadata** is collected.
- Tenant GUID and cloud are explicit. The authenticated context must match both before collection.
- No tenant connection is needed for offline replay or automated tests. No real tenant was contacted during development.
- Incomplete, unavailable, deliberately omitted, or malformed prerequisite evidence produces **Unknown**, not a fabricated healthy result.
- Outputs are local files. There is no telemetry, upload, hosted service, or external analysis service.
- Existing report files are never overwritten. Choose a new output directory for each run.

**The reports still contain highly sensitive identity, application, consent, role, device, and audit information.** Prepare a restricted, encrypted output location. ACLs are inherited, not automatically hardened by this script. Do not commit tenant reports, place them in broadly shared folders, or upload them to issue trackers. Apply an appropriate retention policy.

## Requirements and installation

- PowerShell **7.2 or newer**; Windows PowerShell 5.1 is not supported.
- Live collection: `Microsoft.Graph.Authentication` **2.0.0 or newer**.
- Tests: Pester **5.7.1 or newer**.
- OAuth permissions, supported Entra reader roles for delegated authentication, appropriate licenses, and access to the selected national-cloud APIs.

Dependencies are declared in [requirements.psd1](requirements.psd1). Offline use does not import the Graph module.

```powershell
Install-Module Microsoft.Graph.Authentication -MinimumVersion 2.0.0 -Scope CurrentUser
Install-Module Pester -MinimumVersion 5.7.1 -Scope CurrentUser
```

Review packages and follow your organization's repository, signing, installation, and execution policies. The toolkit does not provision an app registration or call permission-grant APIs. Standard SDK OAuth authentication can present consent prompts; accepting a prompt can create a consent grant. Preprovision approved consent or use an already-authorized context for strictly read-only collection. Authentication also creates ordinary sign-in/audit activity.

## Quick start

Use a fresh PowerShell process for a live assessment.

```powershell
$tenant = '11111111-1111-4111-8111-111111111111' # Replace with the actual tenant GUID.
$out = ".\reports\$(Get-Date -Format 'yyyyMMdd-HHmmss')"

$result = .\Invoke-EntraXray.ps1 `
    -TenantId $tenant `
    -OutputDirectory $out

$result | Format-List
```

This opens interactive authentication, collects **all 70 stable sources and their per-object relationships**, requests the last **30 days** of retained logs, assesses all 69 checks, and writes five deliverables. Expect significant API activity in large tenants: application and enterprise-app owners, granted app roles, group owners, access-review decisions, and other relationships require additional paginated requests.

**Large-tenant limitation:** evidence and reports are materialized in memory, not streamed to a database. Request/page budgets are not memory limits. Large log windows and relationship inventories can require substantial RAM; use shorter windows and separate source subsets when necessary. Collection does not checkpoint or resume individual pages: durable raw evidence is written after collection returns, before assessment. A process termination or unexpected failure during collection can therefore lose that unfinished collection.

The script returns an object; it does not exit the calling PowerShell session.

### Device code

```powershell
.\Invoke-EntraXray.ps1 -TenantId $tenant `
    -AuthenticationMode DeviceCode `
    -OutputDirectory '.\reports\device-code-run'
```

An optional `-ClientId` selects your organization's public-client registration. Device code can be prohibited by tenant policy; the toolkit does not bypass that policy.

### Certificate / unattended application authentication

```powershell
.\Invoke-EntraXray.ps1 -TenantId $tenant `
    -AuthenticationMode Certificate `
    -ClientId '22222222-2222-4222-8222-222222222222' `
    -CertificateThumbprint 'YOUR_CERTIFICATE_THUMBPRINT' `
    -OutputDirectory '.\reports\certificate-run'
```

Both client ID and certificate thumbprint are required. The certificate/private key must be accessible to the execution identity. Provision the corresponding **application** permissions with approved admin consent separately; delegated scopes are not application permissions. No plaintext client-secret mode is provided.

### Explicitly reuse an existing Graph context

```powershell
.\Invoke-EntraXray.ps1 -TenantId $tenant `
    -AuthenticationMode ExistingContext `
    -OutputDirectory '.\reports\existing-context-run'
```

This does not connect, disconnect, switch tenants, or grant permissions. It verifies the existing context's tenant and cloud. Authentication created by the toolkit is process-scoped and disconnected in `finally`, including on a failed collection. An explicitly reused context is not disconnected.

### National clouds

| `-Environment` | Microsoft Graph host |
|---|---|
| `Global` (default) | `graph.microsoft.com` |
| `USGov` | `graph.microsoft.us` |
| `USGovDoD` | `dod-graph.microsoft.us` |
| `China` | `microsoftgraph.chinacloudapi.cn` |

Example:

```powershell
.\Invoke-EntraXray.ps1 -TenantId $tenant -Environment USGov `
    -OutputDirectory '.\reports\usgov-run'
```

Cloud selection is not a claim that every API or license exists in that cloud. Unavailable APIs remain visible as collection gaps.

## Inspect the plan before granting access

```powershell
Import-Module .\src\EntraXray.psd1

$plan = Get-EntraXrayPlan
$plan.Permissions
$plan.Sources |
    Select-Object Id, Method, ApiVersion, Path, Permissions, Licensing, Reference |
    Format-List

Get-EntraXrayCheck |
    Select-Object Id, Category, Severity, Title, Sources, Remediation, References |
    Format-List
```

The [source and check catalog](src/Private/Catalog.ps1) is the authoritative inventory of what this version requests and evaluates. Source-specific Microsoft API documentation is recorded in evidence; each check links to Microsoft investigation guidance.

### Read-only permission families

The full stable plan requests the union of the following read permissions. A subset plan requests only its selected sources and required ancestors.

| Surface | Permissions |
|---|---|
| Directory and activity | `Directory.Read.All`, `AuditLog.Read.All`, `Member.Read.Hidden` |
| Policy and authentication methods | `Policy.Read.All`, `Policy.Read.AuthenticationMethod` |
| Directory roles and PIM | `RoleManagement.Read.Directory`, `RoleAssignmentSchedule.Read.Directory`, `RoleEligibilitySchedule.Read.Directory`, `RoleManagementPolicy.Read.Directory` |
| PIM for role-assignable groups | `PrivilegedAssignmentSchedule.Read.AzureADGroup`, `PrivilegedEligibilitySchedule.Read.AzureADGroup` |
| Identity Protection | `IdentityRiskyUser.Read.All`, `IdentityRiskEvent.Read.All` |
| Governance | `AccessReview.Read.All`, `EntitlementManagement.Read.All`, `Agreement.Read.All`, `LifecycleWorkflows.Read.All` |
| External identity providers | `IdentityProvider.Read.All` |
| Secure Score | `SecurityEvents.Read.All` |

Beta adds `DirectoryRecommendations.Read.All` and `IdentityRiskyServicePrincipal.Read.All` where applicable.

These are powerful **read** permissions, not low-sensitivity permissions. Admin consent, the caller's Entra role, API availability, licensing, and the token's permission type are separate requirements. Global Reader and Security Reader cover many scenarios but are not asserted to satisfy every endpoint. Consult each source's documentation rather than assigning Global Administrator indiscriminately.

A `403` is recorded as access denied; it is **not** automatically diagnosed as a missing license. Basic user inventory and premium sign-in activity are separate sources, so denial of activity data does not discard the user inventory.

### Select a smaller collection

```powershell
Get-EntraXrayPlan -SourceId applicationOwners
# Automatically includes applications before applicationOwners.

.\Invoke-EntraXray.ps1 -TenantId $tenant `
    -SourceId organization, domains, authorizationPolicy, securityDefaults `
    -OutputDirectory '.\reports\limited-run'
```

All 69 checks are still reported. Checks whose prerequisites were not requested are **Unknown**. "100% of requested sources collected" does not mean "100% of the tenant assessed."

## Evidence surfaces

| Area | Collected evidence |
|---|---|
| Tenant and hybrid identity | Organization, verified/custom domains, domain federation configurations, hybrid sync metadata, subscribed SKUs |
| Users | Users, separately permissioned successful-sign-in activity, guest invitation/redemption state, authentication registration/capability report, soft-deleted users |
| Groups | Group settings and dynamic membership rules, owners, transitive role-group members, group expiration policies, soft-deleted groups |
| Privileged access | Built-in/custom role definitions, active assignments, PIM active/eligible schedule instances, role policies/rules and assignments, role-group PIM membership/ownership schedules, administrative units and members |
| Application identity | App registrations, enterprise apps/managed identities, owners, credential metadata, redirect/flow/audience settings, requested permissions, actual app-role grants, delegated consent grants, workload federated identity credentials, soft-deleted apps/SPs |
| Authentication and access policy | Security defaults, authentication methods/migration/TAP policy, authentication strengths, Conditional Access, named locations, authentication context classes, authorization/default member/guest permissions, admin consent workflow |
| Other policy inventory | Consent policies and include/exclude condition sets, token lifetime/activity timeout policies, tenant/application app-management policies |
| External identities | Default and partner cross-tenant policy, inbound MFA trust, identity-provider identifiers/types/names |
| Devices | Registration, trust, management/compliance indicators, approximate activity, enabled state |
| Identity Protection and operations | Risky users, risk detections, interactive sign-ins, directory changes, provisioning results, Secure Score history and control profiles |
| Identity governance | Access reviews, instances and decisions; entitlement catalogs/packages/policies/assignments/connected organizations; terms of use; lifecycle workflows and run history |

**Collection is not the same as automated assessment.** Inventories such as access-review decisions, token/app-management policies, administrative units, consent condition sets, entitlement assignments, PIM group eligibility, workflow runs, and deleted objects are retained for investigation but do not each have a separate automated security verdict. Current role-group membership is distinguished from potential PIM group activation paths; this is not a complete transitive privilege-escalation graph.

### Explicit beta collection

```powershell
.\Invoke-EntraXray.ps1 -TenantId $tenant -IncludeBeta `
    -OutputDirectory '.\reports\preview-run'
```

This adds device-registration policy, directory recommendations, risky service principals, service-principal risk detections, and separate non-interactive user, service-principal, and managed-identity sign-in collections.

Beta APIs can change and Microsoft does not support production dependencies on them. Workload risk APIs require **Microsoft Entra Workload ID Premium**. These sources add raw investigation evidence; the 69 stable checks do not automatically evaluate every beta record. In particular, review workload-risk and non-interactive sign-in evidence separately instead of assuming a clean interactive-user result covers those identities.

## Assessment catalog

| IDs | Count | Tests |
|---|---:|---|
| `TEN-001` through `TEN-004` | 4 | Sync freshness, federation transport, domain verification, license capacity |
| `AUTH-001` through `AUTH-012` | 12 | MFA baseline configuration, registration/capability gaps, SSPR, phishing-resistant method availability, SMS/voice, migration, TAP, default member and consent settings |
| `CA-001` through `CA-008` | 8 | Report-only/disabled policies, exclusions, legacy-auth blocking configuration, phishing-resistant strengths, risk-conditioned controls, dangerous trusted ranges, persistent sessions |
| `ID-001` through `ID-005` | 5 | Successful-activity-based member/guest staleness, absent activity telemetry, unredeemed invitations, disabled strong-password policy |
| `PRIV-001` through `PRIV-008` | 8 | Effective human GA population and resilience, standing privilege, guest/workload privilege, PIM enablement controls, privileged group ownership, emergency-access assurance |
| `APP-001` through `APP-014` | 14 | Credential expiry/lifetime, ownership, audiences, redirects, implicit flows, high-impact actual grants, tenant-wide delegated consent, retired Azure AD Graph, federation trust, assignment requirements |
| `DEV-001` through `DEV-003` | 3 | Stale, explicitly noncompliant, and explicitly unmanaged devices |
| `EXT-001` through `EXT-004` | 4 | Invitations, guest visibility, partner MFA trust, default inbound B2B scope |
| `GOV-001` through `GOV-004` | 4 | Review definitions, nonresponse approval, nonexpiring package policies, disabled lifecycle workflows |
| `OPS-001` through `OPS-007` | 7 | Unresolved risk, observed successful legacy auth, single-factor observations, provisioning failures, sensitive changes, Secure Score context |

Use `Get-EntraXrayCheck -Id APP-009` for the precise prerequisites and investigation instructions. Every run's report includes all check definitions, outcomes, individual evidence rows, recommendations, and references.

### Discriminating semantics

- A recent **failed** sign-in does not make an inactive account active. Staleness uses `lastSuccessfulSignInDateTime`, never `lastSignInDateTime`.
- Null successful-activity timestamps do not prove that an account never signed in. Older accounts with unavailable activity cannot receive a confirmed active/inactive verdict.
- Disabled users are excluded from MFA-registration gaps; the Microsoft registration API does not return disabled users. Missing enabled-user rows are Unknown.
- MFA registration/capability is not MFA enforcement. SSPR registration is assessed only for SSPR-enabled members.
- A Conditional Access policy name, report-only state, scoped policy, unresolved authentication strength, or `MFA OR compliant device` is not proof of universal MFA.
- User/group/role/app/guest exclusions, device/location/platform/risk/client conditions, app filters, and unknown future conditions prevent a broad unqualified-policy conclusion.
- Even an unqualified policy or security-defaults result is a **configuration test**, not effective-access simulation or a claim that every sign-in requires MFA.
- Current eligible roles are not standing grants. Disabled users, service principals, scoped GA assignments, and expired/future eligibility do not establish available human tenant-wide administrative access.
- The optional group role-eligibility flag grants eligibility only when explicitly true. An unset/null flag on an ordinary group is not treated as a collection failure; missing or malformed flags still prevent a defensible result.
- Privileged role classification uses Graph's `isPrivileged` when present, known high-impact templates, and a conservative custom-role write-action fallback. Review definitions/actions directly for comprehensive analysis.
- Emergency-access names, a list of IDs, or policy exclusions do not prove independently usable break-glass access. `PRIV-008` deliberately remains a human-review requirement.
- Requested app permissions are **not** granted permissions. Actual grants are joined to resource service-principal permission definitions.
- The high-impact permission-name list is curated, not every possible sensitive permission or custom API authorization path. All actual grants are retained.
- Multitenancy, user consent, inbound partner MFA trust, unassigned enterprise-app access, and unmanaged devices can be intentional: contextual **Review**, not automatically a vulnerability.
- Native HTTP loopback redirects are not flagged as insecure remote HTTP redirects.
- Expired credentials do not by themselves prove an outage. Other usable credentials and actual application activity require investigation.
- `DisablePasswordExpiration` is not treated as an exposure; modern password guidance is not replaced with blanket password-expiration advice.
- Successful legacy sign-ins are distinguished from failed attempts. Single-factor metadata is not asserted to prove a bypass.
- Sensitive audit events are review leads, not automatic incident attribution.
- Secure Score spans workloads; it is not an Entra-only security rating or proof of tenant safety.

## Outcomes and severity

| Outcome | Meaning |
|---|---|
| `Pass` | This narrowly stated test passed within complete collected prerequisites, not that the tenant is safe. |
| `Fail` | A stated adverse condition was observed; not automatically an exploitable vulnerability. |
| `Review` | Intent, business justification, effective control combinations, or external evidence is needed. |
| `Unknown` | Required collection is incomplete/unavailable/omitted, relationships cannot be resolved, or required data is malformed/unavailable. |
| `NotApplicable` | No applicable objects exist within the complete collected scope. |

Severity is remediation/triage priority, not a probability that an intentional configuration is exploitable. Confirmed-compromised user evidence escalates the corresponding finding to Critical. Review-priority High is deliberately not relabeled a confirmed vulnerability.

Findings dependent on partial sources are conservatively Unknown even when some interesting records were retrieved. Partial raw records remain available for immediate manual investigation.

## Configuration and collection budgets

Copy and edit [config.example.json](config.example.json):

```powershell
.\Invoke-EntraXray.ps1 -TenantId $tenant `
    -ConfigurationPath '.\config.example.json' `
    -LogDays 30 -MaxPagesPerSource 10000 -MaxRequests 100000 -MaxRetries 3 `
    -OutputDirectory '.\reports\configured-run'
```

| Setting | Default | Interpretation |
|---|---:|---|
| `StaleUserDays` | 90 | Member activity and old/unobserved-account review |
| `StaleGuestDays` | 90 | Guest successful-activity review |
| `StaleDeviceDays` | 90 | Approximate device activity review |
| `GuestInvitationAgeDays` | 30 | Pending guest invitation review |
| `CredentialWarningDays` | 30 | Upcoming password/key metadata expiry |
| `MaxCredentialLifetimeDays` | 180 | Organizational credential-lifetime review |
| `MaxGlobalAdministrators` | 5 | Enabled human standing tenant-wide GA population review |
| `HybridSyncMaxHours` | 24 | Organizational sync-freshness threshold |
| `SecureScoreThreshold` | 0.7 | Cross-workload contextual score threshold |
| `EmergencyAccessAccountId` | `[]` | Explicit GUID array; exceptions from standing-assignment review, never automatic emergency-assurance passes |

Thresholds are organizational policy choices, not claimed universal Microsoft/CIS compliance requirements. Unknown keys, wrong types, malformed GUIDs, and invalid ranges are rejected. Day/count/hour settings accept integers 1-3650; score threshold accepts 0-1.

- `LogDays`: 1-30, default 30; a **requested** historical interval, not guaranteed retention. Choose a smaller interval to reduce collection volume.
- `MaxPagesPerSource`: 1-1,000,000, default 10,000, shared across a source's per-parent requests.
- `MaxRequests`: 1-10,000,000, default 100,000 logical transport attempts, including this toolkit's retries. The SDK can have additional internal HTTP behavior.
- `MaxRetries`: 0-10, default 3. Transient network/timeouts, 408, 429, 500, 502, 503, and 504 are retryable.
- Retry-After seconds and HTTP dates are honored. A delay exceeding 120 seconds ends that source attempt visibly rather than retrying before the server requested.
- All pagination is followed unless a documented budget/error stops collection. Repeated links and continuation URLs that change host, cloud, scheme, port, resource path, or API version are rejected before another request.

Default sign-in collection is the v1.0 interactive-user scope. Retention and availability vary by license and API. Empty logs cannot establish retention/export/alerting health. The log interval ends when collection starts, not whenever each page happens to be requested.

## Deliverables and offline replay

| File | Contents |
|---|---|
| `evidence.json` | Versioned tenant/cloud/time/settings envelope; every source's requested state, rows, counts, pages, scope, errors, request/parent provenance, and API reference |
| `findings.json` | All 69 verdicts, complete evidence rows, priorities, limitations, applied assessment settings, counts, collection coverage, and evidence SHA-256 |
| `findings.csv` | One row per check evidence entity, or a status row when no entity exists; spreadsheet-formula-leading text is apostrophe-prefixed |
| `report.md` | Human-readable full collection matrix, check index, detailed evidence, investigation recommendations, references, and mandatory blind spots |
| `manifest.json` | SHA-256 hashes of the other four deliverables |

JSON retains original entity values rather than applying CSV presentation escaping. Markdown escapes untrusted HTML/table content. Evidence lists are not silently truncated.

Raw evidence is persisted **before assessment**, so an unexpected evaluator/report failure does not destroy a completed collection. Files are staged and renamed individually; the report set is not a filesystem-wide transaction. A missing manifest indicates that the full output pipeline did not finish. An interrupted or failed write can leave completed deliverables but does not silently overwrite an earlier run.

```powershell
.\Invoke-EntraXray.ps1 `
    -EvidencePath '.\reports\original-run\evidence.json' `
    -OutputDirectory '.\reports\offline-replay'
```

Offline replay imports neither Graph authentication nor tenant connections. It validates schema, tenant/cloud identifiers, source states/types/counts, timestamp intervals, and settings. Evaluation uses the captured completion time, not today's clock, and preserves captured thresholds unless an explicit configuration file overrides them. Replay reserializes the validated evidence; it does not claim byte-for-byte copying.

The manifest is **not signed**. It detects changes only against a trusted copy; an attacker able to replace both evidence and hashes can forge the set. Replay does not authenticate provenance or automatically trust a neighboring manifest. Treat snapshots as trusted-input artifacts from a controlled collector, not external attestations.

### Automation outcomes

The result object includes `Incomplete`, per-status counts, collection coverage, and `RecommendedExitCode`:

| Recommended code | Meaning |
|---|---|
| 0 | Requested collection complete, no Unknown checks, no Fail results; Review may still require action |
| 2 | Incomplete requested evidence or one or more Unknown checks |
| 3 | Complete requested evidence/assessment with at least one Fail |

Fatal input/authentication/filesystem/programming errors throw instead of returning success-shaped results. An unhandled terminating error in a `pwsh -File` invocation fails the process. Module/script consumers can choose their own policy:

```powershell
$r = .\Invoke-EntraXray.ps1 -TenantId $tenant -OutputDirectory '.\reports\pipeline-run'
exit $r.RecommendedExitCode
```

## TDD and coverage

[Invoke-Tests.ps1](Invoke-Tests.ps1) runs Pester, writes NUnit test results and JaCoCo coverage to `TestResults`, fails on failed/discovery/skipped/unexecuted tests, and enforces **100% measured Pester command coverage** across **every executable production `.ps1`/`.psm1`, including the entry script and module loader**. No production files or functions are excluded to reach the target. Dependency manifests/configuration data and the test harness are not represented as executable production coverage.

```powershell
.\Invoke-Tests.ps1

# Fast behavioral iteration without coverage instrumentation:
Invoke-Pester -Path .\tests -Output Detailed
```

The tests were authored before implementation, demonstrated failing behavior against stubs, and expanded with failing regression cases before corresponding fixes. Every published check has independently specified benign, adverse, and unavailable-prerequisite scenarios. Additional tests exercise privilege joins, eligibility/time boundaries, actual versus requested consent, policy AND/OR semantics, missing/null/malformed data, HTTP failures, retries/budgets, hostile pagination, national clouds, authentication cleanup, replay rejection, CSV/Markdown escaping, durable evidence, and no-overwrite behavior.

Tests use synthetic fixtures and mocked Graph transport/authentication; they do not prove production tenant APIs or permissions have been exercised. **100% command coverage is not 100% branch coverage, every possible input, every possible identity attack path, or complete tenant-security assurance.** Validate first against an authorized nonproduction tenant and examine every collection failure and Unknown result.

## Mandatory manual follow-up

1. Validate effective Conditional Access combinations with What If, real sign-in authentication details, resource policies, session/token context, and carefully controlled tests.
2. Independently test emergency access, credential custody, alerting, phishing resistance, and recovery procedures.
3. Review federation signing certificates, MFA claims behavior, external IdP controls, external CI/CD subject ownership, and repository/environment protection.
4. Review all privileged role definitions/actions/scopes, app/group owner control paths, PIM group eligibility/ownership, consent conditions, resource-specific permissions, and residual/deleted identities.
5. Inspect governance decisions, whether review results were applied, lifecycle run failures, package assignments, sponsors, and external-user offboarding.
6. Validate log retention/export, monitoring and incident response effectiveness, risk visibility/licensing, and historical activity outside the requested window.
7. Assess on-premises AD/AD FS and synchronization servers, endpoint integrity/management, Azure subscriptions/resources, Exchange, SharePoint, Teams, Defender workloads, and other external dependencies separately.
8. Re-run after material changes. This is a nontransactional snapshot subject to service eventual consistency and changes during collection.

Nothing in this toolkit should be interpreted as permission to assess a tenant you are not authorized to inspect.
