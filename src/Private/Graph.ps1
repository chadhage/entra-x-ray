function Assert-XrayGraphUri {
    param(
        [string]$Uri,
        [ValidateSet('https://graph.microsoft.com', 'https://graph.microsoft.us', 'https://dod-graph.microsoft.us', 'https://microsoftgraph.chinacloudapi.cn')]
        [string]$GraphBaseUri = 'https://graph.microsoft.com',
        [string]$ResourcePath = ''
    )
    $parsed = $null
    if (-not [uri]::TryCreate($Uri, [UriKind]::Absolute, [ref]$parsed) -or
        $parsed.Scheme -ne 'https' -or $parsed.Host -ne ([uri]$GraphBaseUri).Host -or
        $parsed.Port -ne 443 -or $parsed.UserInfo -or $parsed.Fragment -or
        $parsed.AbsolutePath -notmatch '^/(v1\.0|beta)/' -or
        ($ResourcePath -and $parsed.AbsolutePath -ne $ResourcePath)) {
        throw [System.IO.InvalidDataException]::new('Unsafe Microsoft Graph URI: only HTTPS on the selected Graph cloud and original API resource is permitted.')
    }
}

function Get-XrayHttpFailure {
    param([System.Management.Automation.ErrorRecord]$Record)
    $exception = $Record.Exception
    while ($null -ne $exception) {
        $code = $exception.Data['StatusCode']
        if ($null -eq $code) { $code = Get-XrayValue $exception 'Response.StatusCode' }
        if ($null -eq $code) { $code = Get-XrayValue $exception 'ResponseStatusCode' }
        if ($null -eq $code) { $code = Get-XrayValue $exception 'StatusCode' }
        if ($null -ne $code) {
            $retryAfter = $exception.Data['RetryAfter']
            if (-not $retryAfter) { $retryAfter = Get-XrayValue $exception 'Response.Headers.RetryAfter' }
            return @{ StatusCode = [int]$code; RetryAfter = [string]$retryAfter; Network = $false }
        }
        if ($exception -is [System.Net.Http.HttpRequestException] -or $exception -is [TimeoutException] -or
            $exception -is [System.Threading.Tasks.TaskCanceledException]) {
            return @{ StatusCode = 0; RetryAfter = ''; Network = $true }
        }
        $exception = $exception.InnerException
    }
    return $null
}

function New-XrayHttpError {
    param([int]$StatusCode)
    $code = switch ($StatusCode) {
        0 { 'NetworkError' }
        400 { 'BadRequest' }
        401 { 'Unauthenticated' }
        403 { 'AccessDenied' }
        404 { 'NotFound' }
        408 { 'RequestTimeout' }
        429 { 'Throttled' }
        { $_ -ge 500 } { 'ServiceUnavailable' }
        default { 'HttpError' }
    }
    [ordered]@{
        Code = $code; StatusCode = $StatusCode
        Message = "Collection failed ($code; HTTP $StatusCode). Check the source permissions, supported reader role, cloud availability, license requirements, and service health. No licensing cause is inferred from this status alone."
    }
}

function Get-XrayRetryDelay {
    param([string]$RetryAfter, [int]$Attempt, [datetimeoffset]$Now)
    $seconds = 0.0
    if ($RetryAfter -and [double]::TryParse($RetryAfter, [System.Globalization.NumberStyles]::Number, [cultureinfo]::InvariantCulture, [ref]$seconds) -and $seconds -ge 0) {
        return $seconds
    }
    $date = [datetimeoffset]::MinValue
    if ($RetryAfter -and [datetimeoffset]::TryParse($RetryAfter, [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$date)) {
        return [Math]::Max(0, [Math]::Ceiling(($date - $Now).TotalSeconds))
    }
    [Math]::Min(60, [Math]::Pow(2, $Attempt))
}

function Invoke-XrayPagedGet {
    param(
        [Parameter(Mandatory)][string]$Uri,
        [ValidateSet('Collection', 'Singleton')][string]$Shape = 'Collection',
        [Parameter(Mandatory)][scriptblock]$Request,
        [Parameter(Mandatory)][System.Collections.IDictionary]$Budget,
        [int]$MaxPages = 10000, [int]$MaxRetries = 3, [int]$MaxRetryDelaySeconds = 120,
        [string]$GraphBaseUri = 'https://graph.microsoft.com',
        [scriptblock]$Sleep = { param($seconds) Start-Sleep -Seconds $seconds },
        [scriptblock]$Clock = { [datetimeoffset]::UtcNow }
    )
    Assert-XrayGraphUri -Uri $Uri -GraphBaseUri $GraphBaseUri
    $resource = ([uri]$Uri).AbsolutePath
    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $items = [System.Collections.Generic.List[object]]::new()
    $errors = [System.Collections.Generic.List[object]]::new()
    $pages = 0
    $next = $Uri
    :pages while ($next) {
        if (-not $seen.Add($next)) {
            $errors.Add(@{ Code = 'PaginationLoop'; StatusCode = 0; Message = 'Repeated continuation URL; collection stopped without discarding earlier pages.' })
            break
        }
        if ($pages -ge $MaxPages) {
            $errors.Add(@{ Code = 'PageLimit'; StatusCode = 0; Message = 'Configured per-source page limit reached; remaining records were not collected.' })
            break
        }
        $response = $null
        $failure = $null
        for ($attempt = 0; $attempt -le $MaxRetries; $attempt++) {
            if ($Budget.Used -ge $Budget.Limit) {
                $failure = @{ Code = 'RequestLimit'; StatusCode = 0; Message = 'Configured global request-attempt limit reached; collection is incomplete.' }
                break
            }
            $Budget.Used++
            try {
                $response = & $Request $next
                break
            }
            catch {
                $http = Get-XrayHttpFailure $_
                if ($null -eq $http) { throw }
                $failure = New-XrayHttpError $http.StatusCode
                $transient = $http.Network -or $http.StatusCode -in @(408, 429, 500, 502, 503, 504)
                if (-not $transient -or $attempt -ge $MaxRetries) { break }
                $delay = Get-XrayRetryDelay $http.RetryAfter $attempt (& $Clock)
                if ($delay -gt $MaxRetryDelaySeconds) {
                    $failure = @{ Code = 'RetryDelayLimit'; StatusCode = $http.StatusCode; Message = "Retry-After exceeds the $MaxRetryDelaySeconds-second retry-wait budget. No early retry was sent." }
                    break
                }
                & $Sleep $delay
                $failure = $null
            }
        }
        if ($null -ne $failure) { $errors.Add($failure); break }
        try {
            if (($response -isnot [System.Collections.IDictionary] -and $response -isnot [pscustomobject]) -or
                $null -ne (Get-XrayValue $response 'error')) {
                throw [System.IO.InvalidDataException]::new('Graph response is not a successful object payload.')
            }
            if ($Shape -eq 'Singleton') {
                $items.Add((Copy-XrayObject $response))
                $pages++
                break
            }
            Assert-XrayFields $response @('value')
            $values = Get-XrayValue $response 'value'
            if ($values -isnot [System.Collections.IList]) { throw [System.IO.InvalidDataException]::new('Graph collection value is not an array.') }
            foreach ($value in $values) {
                if ($value -isnot [System.Collections.IDictionary] -and $value -isnot [pscustomobject]) {
                    throw [System.IO.InvalidDataException]::new('Graph collection contains a non-object record.')
                }
            }
            foreach ($value in $values) { $items.Add((Copy-XrayObject $value)) }
            $pages++
        }
        catch [System.IO.InvalidDataException] {
            $errors.Add(@{ Code = 'InvalidResponse'; StatusCode = 0; Message = $_.Exception.Message })
            break
        }
        $continuation = Get-XrayValue $response '@odata.nextLink'
        if ($null -eq $continuation -or $continuation -eq '') { break }
        try {
            if ($continuation -isnot [string]) { throw [System.IO.InvalidDataException]::new('Continuation URL is not text.') }
            Assert-XrayGraphUri -Uri $continuation -GraphBaseUri $GraphBaseUri -ResourcePath $resource
        }
        catch [System.IO.InvalidDataException] {
            $errors.Add(@{ Code = 'UnsafeNextLink'; StatusCode = 0; Message = 'Unsafe or malformed continuation URL was rejected before sending a request.' })
            break
        }
        $next = $continuation
    }
    $state = 'Complete'
    if ($errors.Count -gt 0) {
        $state = 'Unavailable'
        if ($pages -gt 0) { $state = 'Partial' }
    }
    [ordered]@{ State = $state; Items = $items.ToArray(); Pages = $pages; Errors = $errors.ToArray() }
}

function Copy-XrayObject {
    param($InputObject)
    $copy = [ordered]@{}
    if ($InputObject -is [System.Collections.IDictionary]) {
        foreach ($key in $InputObject.Keys) { $copy[$key] = $InputObject[$key] }
    }
    else {
        foreach ($property in $InputObject.PSObject.Properties) { $copy[$property.Name] = $property.Value }
    }
    $copy
}

function Resolve-XrayChildUri {
    param([string]$Template, $Parent)
    $id = Get-XrayValue $Parent 'id'
    if ($id -isnot [string] -or [string]::IsNullOrWhiteSpace($id)) { throw [System.IO.InvalidDataException]::new('Parent record has no usable object ID.') }
    $uri = $Template.Replace('{id}', [uri]::EscapeDataString($id))
    if ($uri.Contains('{parentId}')) {
        $ancestor = Get-XrayValue $Parent '_ParentId'
        if (-not $ancestor) { throw [System.IO.InvalidDataException]::new('Nested relationship is missing its ancestor ID.') }
        $uri = $uri.Replace('{parentId}', [uri]::EscapeDataString($ancestor))
    }
    $uri
}

function Invoke-XrayCollection {
    param(
        [string]$TenantId, [Parameter(Mandatory)]$Plan, [Parameter(Mandatory)][scriptblock]$Request,
        [System.Collections.IDictionary]$Settings = (New-XraySettings),
        [int]$LogDays = 30, [int]$MaxPagesPerSource = 10000, [int]$MaxRequests = 100000, [int]$MaxRetries = 3,
        [scriptblock]$Clock = { [datetimeoffset]::UtcNow },
        [scriptblock]$Sleep = { param($seconds) Start-Sleep -Seconds $seconds }
    )
    $started = & $Clock
    $startText = Format-XrayUtc $started.AddDays(-$LogDays)
    $endText = Format-XrayUtc $started
    $budget = @{ Used = 0; Limit = $MaxRequests }
    $requested = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($source in $Plan.Sources) { [void]$requested.Add($source.Id) }
    $sources = [ordered]@{}
    foreach ($definition in (Get-XraySourceCatalog)) {
        $path = $definition.Path.Replace('{start}', $startText).Replace('{end}', $endText)
        $uri = "$($Plan.GraphBaseUri)/$($definition.ApiVersion)$path"
        $source = [ordered]@{
            Id = $definition.Id; Requested = $requested.Contains($definition.Id); State = 'Skipped'
            ApiVersion = $definition.ApiVersion; Method = 'GET'; Uri = $uri
            Scope = $definition.Scope; Permissions = $definition.Permissions
            Reference = $definition.Reference; Licensing = $definition.Licensing
            Items = @(); ItemCount = 0; Pages = 0; Errors = @(); Requests = @()
            CollectedAtUtc = $endText
        }
        $sources[$definition.Id] = $source
        if (-not $source.Requested) {
            $source.Errors = @(@{ Code = 'NotRequested'; StatusCode = 0; Message = 'Not requested by this collection plan; preview sources require explicit opt-in.' })
            continue
        }
        if (-not $definition.Parent) {
            $result = Invoke-XrayPagedGet -Uri ([uri]$uri).AbsoluteUri -Shape $definition.Shape -Request $Request -Budget $budget -MaxPages $MaxPagesPerSource -MaxRetries $MaxRetries -GraphBaseUri $Plan.GraphBaseUri -Clock $Clock -Sleep $Sleep
            $source.State = $result.State
            $source.Items = $result.Items
            $source.Pages = $result.Pages
            $source.Errors = $result.Errors
            $source.Requests = @(@{ Uri = ([uri]$uri).AbsoluteUri; ParentId = ''; State = $result.State; Pages = $result.Pages })
        }
        else {
            $parent = $sources[$definition.Parent]
            if ($parent.State -ne 'Complete' -and $parent.Items.Count -eq 0) {
                $source.Errors = @(@{ Code = 'ParentIncomplete'; StatusCode = 0; Message = "Parent source '$($definition.Parent)' has no usable complete inventory." })
                continue
            }
            $records = [System.Collections.Generic.List[object]]::new()
            $errors = [System.Collections.Generic.List[object]]::new()
            $requests = [System.Collections.Generic.List[object]]::new()
            if ($parent.State -ne 'Complete') {
                $errors.Add(@{ Code = 'ParentIncomplete'; StatusCode = 0; Message = "Parent source '$($definition.Parent)' is incomplete; absence cannot be inferred." })
            }
            foreach ($item in $parent.Items) {
                $parentId = Get-XrayValue $item 'id'
                try {
                    $childUri = Resolve-XrayChildUri $uri $item
                    if ($definition.ParentFilter -eq 'FederatedDomain') {
                        Assert-XrayFields $item @('authenticationType')
                        if ($item['authenticationType'] -notin @('Federated', 'Managed')) { throw [System.IO.InvalidDataException]::new('Unknown domain authenticationType.') }
                        if ($item['authenticationType'] -eq 'Managed') { continue }
                    }
                    if ($definition.ParentFilter -eq 'RoleAssignableGroup' -and -not (Test-XrayRoleAssignableGroup $item)) { continue }
                }
                catch [System.IO.InvalidDataException] {
                    $errors.Add(@{ Code = 'InvalidParent'; StatusCode = 0; ParentId = [string]$parentId; Message = $_.Exception.Message })
                    continue
                }
                if ($source.Pages -ge $MaxPagesPerSource) {
                    $errors.Add(@{ Code = 'PageLimit'; StatusCode = 0; ParentId = $parentId; Message = 'Per-source page budget exhausted before all parent relationships could be collected.' })
                    break
                }
                $result = Invoke-XrayPagedGet -Uri ([uri]$childUri).AbsoluteUri -Shape $definition.Shape -Request $Request -Budget $budget -MaxPages ($MaxPagesPerSource - $source.Pages) -MaxRetries $MaxRetries -GraphBaseUri $Plan.GraphBaseUri -Clock $Clock -Sleep $Sleep
                $source.Pages += $result.Pages
                $requests.Add(@{ Uri = ([uri]$childUri).AbsoluteUri; ParentId = $parentId; State = $result.State; Pages = $result.Pages })
                foreach ($record in $result.Items) {
                    $copy = Copy-XrayObject $record
                    $copy['_ParentId'] = $parentId
                    $copy['_ParentSource'] = $definition.Parent
                    $records.Add($copy)
                }
                foreach ($errorItem in $result.Errors) {
                    $copy = Copy-XrayObject $errorItem
                    $copy['ParentId'] = $parentId
                    $errors.Add($copy)
                }
                if ($budget.Used -ge $budget.Limit -and $result.State -ne 'Complete') { break }
            }
            $source.State = 'Complete'
            if ($errors.Count -gt 0) { $source.State = 'Partial' }
            $source.Items = $records.ToArray()
            $source.Errors = $errors.ToArray()
            $source.Requests = $requests.ToArray()
        }
        $source.ItemCount = $source.Items.Count
        $source.CollectedAtUtc = Format-XrayUtc (& $Clock)
    }
    [ordered]@{
        SchemaVersion = '1.0'; ToolVersion = '1.0.0'; TenantId = ([guid]$TenantId).ToString()
        Environment = $Plan.Environment; StartedAtUtc = $endText; CompletedAtUtc = (Format-XrayUtc (& $Clock))
        Settings = $Settings; LogWindow = @{ StartUtc = $startText; EndUtc = $endText }
        CollectionLimits = @{ MaxPagesPerSource = $MaxPagesPerSource; MaxRequests = $MaxRequests; MaxRetries = $MaxRetries; RequestsUsed = $budget.Used }
        RequestedPermissions = $Plan.Permissions; Sources = $sources
    }
}

function Invoke-XrayLiveScan {
    param(
        [string]$TenantId, [Parameter(Mandatory)]$Plan, [System.Collections.IDictionary]$Settings,
        [ValidateSet('Interactive', 'DeviceCode', 'Certificate', 'ExistingContext')][string]$AuthenticationMode = 'Interactive',
        [string]$ClientId, [string]$CertificateThumbprint,
        [int]$LogDays = 30, [int]$MaxPagesPerSource = 10000, [int]$MaxRequests = 100000, [int]$MaxRetries = 3
    )
    if ($AuthenticationMode -eq 'Certificate' -and (-not $ClientId -or -not $CertificateThumbprint)) {
        throw [System.ArgumentException]::new('Certificate authentication requires both ClientId and CertificateThumbprint.')
    }
    try { Import-Module Microsoft.Graph.Authentication -MinimumVersion 2.0.0 -ErrorAction Stop }
    catch [System.IO.FileNotFoundException] {
        throw [System.IO.FileNotFoundException]::new('Microsoft.Graph.Authentication 2.0.0 or later is required for live collection. Install-Module Microsoft.Graph.Authentication -Scope CurrentUser')
    }
    $ownsContext = $false
    try {
        if ($AuthenticationMode -ne 'ExistingContext') {
            $connection = @{
                TenantId = $TenantId; Environment = $Plan.Environment; ContextScope = 'Process'
                NoWelcome = $true; ErrorAction = 'Stop'
            }
            if ($AuthenticationMode -eq 'Certificate') {
                $connection.ClientId = $ClientId
                $connection.CertificateThumbprint = $CertificateThumbprint
            }
            else {
                $connection.Scopes = $Plan.Permissions
                if ($ClientId) { $connection.ClientId = $ClientId }
                if ($AuthenticationMode -eq 'DeviceCode') { $connection.UseDeviceAuthentication = $true }
            }
            Connect-MgGraph @connection | Out-Null
            $ownsContext = $true
        }
        $context = Get-MgContext -ErrorAction Stop
        if ($null -eq $context -or (Get-XrayValue $context 'TenantId') -ne $TenantId -or
            (Get-XrayValue $context 'Environment') -ne $Plan.Environment) {
            throw [System.InvalidOperationException]::new('The authenticated Microsoft Graph context does not match the explicitly requested tenant and cloud. No collection was started.')
        }
        $request = {
            param($uri)
            Invoke-MgGraphRequest -Uri $uri -Method GET -OutputType Hashtable -ErrorAction Stop
        }
        Invoke-XrayCollection -TenantId $TenantId -Plan $Plan -Request $request -Settings $Settings -LogDays $LogDays -MaxPagesPerSource $MaxPagesPerSource -MaxRequests $MaxRequests -MaxRetries $MaxRetries
    }
    finally {
        if ($ownsContext) { Disconnect-MgGraph -ErrorAction Stop | Out-Null }
    }
}
