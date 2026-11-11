## Scope and data handling

This guide describes how to run the PowerShell collector, inspect its evidence, and interpret its results. The browser page is documentation. It does not authenticate, execute commands, accept tenant files, or query a tenant.

The assessment scope is Microsoft Entra ID. Azure subscriptions, Microsoft 365 workload configuration, on-premises AD, endpoint integrity, and external identity-provider controls require separate investigation. A configuration snapshot is not proof of effective protection.

Before collecting:

1. Confirm authorization to inspect the tenant.
2. Obtain the tenant GUID and identify its national cloud. Domain aliases, `common`, and `organizations` are not accepted as target identifiers.
3. Prepare an encrypted output location with restricted filesystem access. The collector inherits directory ACLs; it does not harden them.
4. Define who may read the evidence and when it must be deleted.
5. Keep assessment output outside the documentation directory and outside any published static-site root.

Assessment Graph requests use `GET`. OAuth authentication is a separate operation: accepting a consent prompt can create a permission grant, and authentication creates ordinary sign-in or audit activity. Arrange approved consent before collection, or reuse an already-authorized context when consent changes are not permitted.

Outputs contain identity, application, consent, role, device, and audit information. Do not commit them to source control or upload them to issue trackers. This guide has no file-upload facility.

## Prepare PowerShell

Run the examples from the **repository root**, not from the `docs` directory. Replace angle-bracket placeholders before execution.

| Component | Requirement | Used for |
|---|---|---|
| PowerShell | 7.2 or newer | Collector, offline replay, guide build |
| Microsoft.Graph.Authentication | 2.0.0 or newer | Live authentication and Graph requests |
| Pester | 5.7.1 or newer | Automated tests and PowerShell command coverage |

Check the current shell:

```powershell
$PSVersionTable.PSVersion
Get-Module -ListAvailable Microsoft.Graph.Authentication, Pester |
    Select-Object Name, Version
```

Install the required modules from an organization-approved repository:

```powershell
Install-Module Microsoft.Graph.Authentication -MinimumVersion 2.0.0 -Scope CurrentUser
Install-Module Pester -MinimumVersion 5.7.1 -Scope CurrentUser
```

Do not bypass execution policy or package-review requirements to run these examples. Follow local signing and installation procedures.

Offline replay and guide generation do not require the Graph authentication module. Importing the assessment module does not connect to a tenant:

```powershell
Import-Module .\src\EntraXray.psd1
Get-Command -Module EntraXray
```

The public commands are `Get-EntraXrayPlan`, `Get-EntraXrayCheck`, and `Invoke-EntraXray`.

## Inspect permissions and source selection

Generate a collection plan before requesting access:

```powershell
$plan = Get-EntraXrayPlan
$plan.Permissions
$plan.Sources |
    Select-Object Id, ApiVersion, Path, Permissions, Licensing, Reference |
    Format-List
```

Four separate conditions affect collection:

1. The token must contain the appropriate delegated or application permission.
2. Delegated authentication can also require a supported Entra directory role.
3. The tenant must have the applicable license or feature.
4. The endpoint must be available in the selected cloud.

Do not assume that a single reader role satisfies every API. Use each source's Microsoft reference to check its requirements. A `403` records access denied; the toolkit does not infer a licensing diagnosis from that status alone.

For certificate authentication, provision approved **application permissions** on the app registration. Delegated scopes are not application permissions. The toolkit does not create an app registration or invoke permission-grant APIs.

Select a subset when reviewing access requirements or limiting collection:

```powershell
$subset = Get-EntraXrayPlan -SourceId applicationOwners
$subset.Sources | Select-Object Id, Parent, Permissions
```

This includes `applications` before `applicationOwners`. Required ancestors are added automatically. Source selection changes collection, not the set of published checks. A check with an omitted prerequisite is `Unknown`.

The source catalog below lists the API version, request path, permissions, parent dependency, scope, and licensing note for each source. Collection of an inventory does not imply that every record receives an automated verdict.

## Run an assessment

Use a fresh PowerShell process when creating a new authenticated session. Set the target and choose an output directory that does not contain previous deliverables:

```powershell
$tenant = '<tenant-guid>'
$out = ".\reports\$(Get-Date -Format 'yyyyMMdd-HHmmssfff')"

$result = .\Invoke-EntraXray.ps1 `
    -TenantId $tenant `
    -OutputDirectory $out

$result | Format-List
```

The default mode is interactive authentication. The default plan requests the stable sources and a 30-day log interval. Retention and access restrictions can shorten the available history. A requested interval is not a retention guarantee.

The script returns a result object. It does not exit the calling shell. Read `Incomplete`, `UnknownCount`, `FailCount`, and `CollectionCoverage`; the absence of a terminating exception does not mean that all evidence was obtained.

For a limited run:

```powershell
.\Invoke-EntraXray.ps1 `
    -TenantId $tenant `
    -SourceId organization, domains, authorizationPolicy, securityDefaults `
    -OutputDirectory '.\reports\policy-subset'
```

Expect `Unknown` results for checks outside that subset. Collection coverage uses the requested sources as its denominator, not every possible tenant surface.

Existing deliverables are not overwritten. If a directory contains a previous report or an interrupted run, retain it for inspection and choose another directory.

## Choose authentication

### Interactive

Use the default mode when a person can complete browser authentication:

```powershell
.\Invoke-EntraXray.ps1 -TenantId $tenant `
    -AuthenticationMode Interactive `
    -OutputDirectory '.\reports\interactive-run'
```

The SDK can display consent prompts. Review them according to the approved access plan; consent is not a prerequisite the collector silently provisions.

### Device code

Use device code only when tenant policy permits it:

```powershell
.\Invoke-EntraXray.ps1 -TenantId $tenant `
    -AuthenticationMode DeviceCode `
    -ClientId '<public-client-application-id>' `
    -OutputDirectory '.\reports\device-code-run'
```

`ClientId` is optional for interactive and device-code modes. It selects a public-client registration. The toolkit does not bypass a policy that blocks device code.

### Certificate

For an unattended application, provide both the app's client ID and a certificate thumbprint:

```powershell
.\Invoke-EntraXray.ps1 -TenantId $tenant `
    -AuthenticationMode Certificate `
    -ClientId '<application-client-id>' `
    -CertificateThumbprint '<certificate-thumbprint>' `
    -OutputDirectory '.\reports\certificate-run'
```

The execution identity must be able to access the certificate and private key. Use approved application permissions and admin consent. There is no plaintext client-secret parameter.

### Existing context

If authentication has already been established:

```powershell
Get-MgContext | Select-Object TenantId, Environment, AuthType, ContextScope

.\Invoke-EntraXray.ps1 -TenantId $tenant `
    -AuthenticationMode ExistingContext `
    -OutputDirectory '.\reports\existing-context-run'
```

The requested tenant and cloud must match the context. A mismatch stops collection. This mode does not connect, switch contexts, or disconnect the supplied context.

Authentication created by the toolkit uses process scope and is disconnected in `finally`. An explicitly reused context is left connected.

## Select a cloud

Use the environment corresponding to the target tenant:

<!-- CLOUD_REFERENCE -->

```powershell
.\Invoke-EntraXray.ps1 -TenantId $tenant `
    -Environment USGov `
    -OutputDirectory '.\reports\usgov-run'
```

Specify the same environment when reusing an existing context. Cloud selection does not imply that every endpoint, feature, or license is available there. Inspect unavailable sources instead of treating them as empty inventories.

## Set limits and thresholds

These are collection controls, not security ratings. The defaults and accepted ranges below are generated from the current PowerShell declarations:

<!-- COLLECTION_PARAMETERS -->

For a shorter log window and lower request budget:

```powershell
.\Invoke-EntraXray.ps1 -TenantId $tenant `
    -LogDays 7 `
    -MaxPagesPerSource 2000 `
    -MaxRequests 20000 `
    -MaxRetries 3 `
    -OutputDirectory '.\reports\bounded-run'
```

- Pagination is followed until completion, an error, or a configured budget.
- The page budget is shared across a source's per-parent relationship requests.
- The request budget counts this toolkit's logical attempts, including retries. The SDK can have additional internal HTTP behavior.
- Transient network/timeouts and HTTP 408, 429, 500, 502, 503, and 504 can be retried.
- `Retry-After` seconds and HTTP dates are honored. A delay over 120 seconds ends that source attempt visibly instead of retrying early.
- A loop or a continuation URL that changes cloud, scheme, port, resource path, or API version is rejected.

Evidence and reports are materialized in memory. Request and page limits are **not memory limits**. Large log windows or relationship inventories can require substantial RAM. Use shorter windows and separate source subsets when necessary.

Collection does not checkpoint or resume individual pages. Raw evidence is persisted after collection returns, before assessment. An unexpected failure during collection can lose that unfinished collection.

### Assessment configuration

Copy the JSON configuration and edit organizational thresholds:

```powershell
Copy-Item .\config.example.json .\assessment-policy.json

.\Invoke-EntraXray.ps1 -TenantId $tenant `
    -ConfigurationPath '.\assessment-policy.json' `
    -OutputDirectory '.\reports\configured-run'
```

The current example is:

<!-- CONFIGURATION_EXAMPLE -->

Day, count, and hour settings accept integers from 1 to 3650. `SecureScoreThreshold` accepts a number from 0 to 1. `EmergencyAccessAccountId` is an explicit array of object GUIDs. Unknown keys and invalid types or ranges are rejected.

Declared emergency accounts are excluded from the standing-assignment review signal; they do not automatically pass emergency-access assurance. `PRIV-008` requires independent validation.

These thresholds are organizational choices. They are not represented as universal Microsoft or CIS compliance requirements.

### Beta inventories

Beta collection is opt-in:

```powershell
.\Invoke-EntraXray.ps1 -TenantId $tenant `
    -IncludeBeta `
    -OutputDirectory '.\reports\beta-inventory'
```

This requests additional device-registration, recommendation, workload-risk, and non-interactive/workload sign-in inventories. Microsoft does not support production dependencies on beta APIs. Workload-risk APIs require Microsoft Entra Workload ID Premium.

These sources add investigation evidence. The stable checks do not automatically evaluate every beta record. A clean interactive-user observation does not establish a clean workload-identity or non-interactive history.

## Read the output files

| File | Purpose | Inspection notes |
|---|---|---|
| `report.md` | Human-readable findings, evidence rows, collection matrix, recommendations, limitations | Begin with collection coverage, then triage findings |
| `findings.json` | Structured outcomes, applied settings, evidence rows, counts, evidence hash | Use for local filtering or an approved processing pipeline |
| `evidence.json` | Captured source data, states, counts, pages, errors, request and parent provenance | Contains sensitive raw inventory and audit records |
| `findings.csv` | Per-entity evidence rows or a status row when no entity exists | Formula-leading text is apostrophe-prefixed; JSON retains original values |
| `manifest.json` | SHA-256 hashes of the other four files | Not a signature or proof of authenticity |

Inspect counts and source states locally:

```powershell
$run = '.\reports\<run-directory>'
$assessment = Get-Content (Join-Path $run 'findings.json') -Raw |
    ConvertFrom-Json -AsHashtable
$evidence = Get-Content (Join-Path $run 'evidence.json') -Raw |
    ConvertFrom-Json -AsHashtable

$assessment.Counts
$evidence.Sources.Values |
    Select-Object Id, Requested, State, ItemCount, Pages |
    Format-Table
```

| Source state | Meaning |
|---|---|
| `Complete` | The declared API scope was collected without a recorded truncation or collection error |
| `Partial` | Some collection or parent inventory is incomplete; retained rows remain available |
| `Unavailable` | The source could not be collected |
| `Skipped` | The source was not requested or its parent could not be used; check `Requested` and `Errors` |

`Complete` is not proof that the service exposed every tenant fact. Licensing, service semantics, eventual consistency, and API limitations still apply.

Files are staged and renamed individually. The report set is not a single filesystem transaction. A missing manifest indicates that the full output pipeline did not finish. Preserve partial output for investigation and use a new directory when retrying.

Hashes can detect a change against a trusted copy. Anyone able to replace both the files and manifest can forge the set. Offline replay does not authenticate the collector or automatically trust a neighboring manifest.

## Interpret and triage findings

Use the outcome and its scope before using severity to prioritize work:

| Outcome | Interpretation | Next action |
|---|---|---|
| `Pass` | This particular test passed within its collected prerequisites | Read its scope; do not infer general tenant safety |
| `Fail` | A stated adverse condition was observed | Confirm context, affected identities, and response ownership |
| `Review` | Intent, business justification, effective controls, or external evidence is needed | Investigate before changing configuration |
| `Unknown` | Required evidence is omitted, unavailable, incomplete, unresolvable, or malformed | Resolve the collection/data gap or record a manual assessment |
| `NotApplicable` | No applicable objects exist within the complete collected scope | Confirm that the scope matches the intended investigation |

Severity is triage priority, not the probability that a condition is exploitable. A failed configuration test is not automatically a vulnerability. A review-priority High does not establish compromise.

Inspect a specific check:

```powershell
Get-EntraXrayCheck -Id APP-009 | Format-List

$assessment.Findings |
    Where-Object Id -EQ 'APP-009' |
    Format-List
```

Apply these distinctions:

- Registered or MFA-capable does not mean MFA was required at sign-in.
- A policy name, report-only state, scoped policy, unresolved strength, or `MFA OR compliant device` does not prove broad MFA coverage.
- Conditional Access configuration is not proof of effective policy combinations, session/token context, or resource-side protection. Use What If and actual authentication details.
- Recent failed sign-ins do not establish recent successful activity. Null successful-activity timestamps do not prove that an account never signed in.
- Current eligible roles are not standing grants. PIM group eligibility and owner-controlled privilege paths require separate review.
- Requested app permissions are not granted permissions. Inspect actual grants and resource permission definitions.
- Multitenancy, user consent, partner MFA trust, unmanaged devices, and unassigned enterprise-app access can be intentional.
- Sensitive audit events are investigation leads, not automatic incident attribution.
- Secure Score spans workloads; it is not an Entra-only assessment.

Findings dependent on partial sources remain `Unknown`, even if retained records are of interest. Review those records directly. Inventory collection also does not imply an automated verdict for every access-review decision, entitlement assignment, deleted object, lifecycle run, or beta record.

Before remediation, validate emergency-access usability, external IdP and federation assurance, external CI/CD subject ownership, log retention/export, monitoring, and incident-response effectiveness. The collector does not perform those validations or modify the tenant.

## Replay evidence offline

Replay a retained snapshot without Graph authentication:

```powershell
.\Invoke-EntraXray.ps1 `
    -EvidencePath '.\reports\<original-run>\evidence.json' `
    -OutputDirectory '.\reports\offline-replay'
```

To apply a different, explicit assessment configuration:

```powershell
.\Invoke-EntraXray.ps1 `
    -EvidencePath '.\reports\<original-run>\evidence.json' `
    -ConfigurationPath '.\assessment-policy.json' `
    -OutputDirectory '.\reports\offline-policy-review'
```

Replay validates the supported schema, source states and counts, identifiers, time intervals, and settings. Evaluation uses the captured completion time, not the current clock. Captured settings are retained unless a configuration file overrides them.

Replay reserializes the validated evidence. It does not promise byte-for-byte copying or fresh tenant information. It cannot retrieve a source that was absent from the original collection.

## Troubleshoot a run

Inspect source errors before retrying:

```powershell
$evidence.Sources.Values |
    Where-Object { $_.Errors.Count -gt 0 } |
    ForEach-Object {
        $source = $_.Id
        $_.Errors | Select-Object @{ Name = 'Source'; Expression = { $source } },
            Code, StatusCode, ParentId, Message
    } |
    Format-List
```

| Symptom or code | Check | Response |
|---|---|---|
| Authentication context mismatch | Tenant GUID and environment in the active context | Authenticate to the intended tenant/cloud; the collector does not switch a reused context |
| `Unauthenticated` / 401 | Token, session state, and execution identity | Re-establish approved authentication |
| `AccessDenied` / 403 | Permission type, consent, caller role, license, feature, and cloud | Verify each independently; do not infer licensing from the status |
| `NotFound` / 404 or `BadRequest` / 400 | Source API reference, cloud availability, and API version | Record the gap and check current Microsoft documentation |
| `Throttled`, `ServiceUnavailable`, or `RetryDelayLimit` | Service health and the requested retry delay | Retry later; reduce scope/window where appropriate; do not bypass the delay |
| `PageLimit` or `RequestLimit` | Budgets and dataset size | Decide whether to increase the budget or split collection; the previous result is incomplete |
| `ParentIncomplete` or `InvalidParent` | Parent source and required identity/filter fields | Resolve the upstream problem; a child cannot establish absence from an incomplete parent |
| `InvalidResponse`, `UnsafeNextLink`, or `PaginationLoop` | API behavior and recorded source context | Preserve the evidence and investigate; do not relax continuation validation |
| Registration/activity gaps | Disabled-user report behavior, missing rows, premium permissions, retention/backfill | Use the check limitations and manual evidence; do not invent a healthy result |
| Existing output file | Previous or interrupted output in the selected directory | Use a new directory; the collector will not overwrite it |
| Memory exhaustion or interrupted collection | Log interval, source selection, relationships, available RAM | Use narrower runs; there is no per-page resume/checkpoint |
| Terminating script error | The reported input, dependency, authentication, filesystem, or programming error | Preserve any completed output; no successful result object is implied |

Do not publish evidence, tokens, private keys, or sensitive tenant identifiers when reporting a problem. Provide the toolkit version, source/check identifiers, sanitized error classification, and a synthetic reproduction where possible.

## Automate exit handling

The script returns `RecommendedExitCode`; it does not terminate a caller's shell.

| Recommended code | Meaning |
|---|---|
| `0` | Requested collection complete, no `Unknown` checks, no `Fail` results; `Review` can still require action |
| `2` | Incomplete requested evidence or one or more `Unknown` checks |
| `3` | Complete requested evidence/assessment with at least one `Fail` |

Make the pipeline policy explicit:

```powershell
$ErrorActionPreference = 'Stop'
$result = .\Invoke-EntraXray.ps1 `
    -TenantId $tenant `
    -OutputDirectory '.\reports\pipeline-run'

exit $result.RecommendedExitCode
```

Terminating errors must be handled separately from a saved assessment result. Decide whether review-required findings should also fail a particular pipeline; they are not automatically treated as confirmed vulnerabilities.

## Validate the toolkit

Run the existing Pester suite:

```powershell
.\Invoke-Tests.ps1
```

The runner writes NUnit results and JaCoCo coverage to `TestResults`. It fails for failed, skipped, or unexecuted tests and enforces 100% measured PowerShell command coverage over its declared production paths, including the guide builder.

For behavioral iteration without coverage instrumentation:

```powershell
Invoke-Pester -Path .\tests -Output Detailed
```

Tests use synthetic fixtures and mocked Graph authentication/transport. Command coverage is not branch coverage, proof of live API access, or complete tenant-security assurance. Validate against an authorized nonproduction tenant before operational use.

Guide tests check catalog synchronization, links, example syntax and parameters, theme structure, build determinism, and build failures. They do not execute the browser JavaScript. After changing layout or browser code, verify navigation, reference filtering, copy success and fallback feedback, keyboard interaction, themes, print-state restoration, and narrow-screen layout in a browser. Browser behavior is not represented as PowerShell command coverage.

## Maintain this guide

The page is generated from three sources:

- `docs\guide.md`: procedures and explanatory text.
- `docs\site.template.html`: layout, styles, and browser behavior.
- The module's public plan/check metadata, current CLI declarations, and `config.example.json`: reference content.

Rebuild from the repository root:

```powershell
.\docs\Build-Guide.ps1
```

Open the generated page:

```powershell
Start-Process .\docs\index.html
```

The generated HTML includes its styles, scripts, procedures, and catalogs. It can be opened from disk or served as static content without a backend, tenant configuration, external fonts, analytics, or runtime package installation. Do not edit the generated HTML directly.

When hosting, publish **only the documentation output**. Do not publish the repository root or assessment reports. No Azure resource or hosting configuration is created by the guide build.

After changing a command parameter, source, check, or configuration default, rebuild and run the guide tests. Check copyable examples against the actual parameter sets. Keep prose procedural and specific about assumptions, side effects, scope, and failure modes.
