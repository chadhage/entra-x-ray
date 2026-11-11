Import-Module "$PSScriptRoot\..\src\EntraXray.psd1"

Describe 'Explicit target binding and read-only authentication' {
    InModuleScope EntraXray {
        BeforeAll {
            . "$PSScriptRoot\TestHelpers.ps1"
            function Connect-MgGraph { param($TenantId, $ClientId, $Scopes, $CertificateThumbprint, $ContextScope, $Environment, [switch]$NoWelcome, [switch]$UseDeviceAuthentication) }
            function Get-MgContext { }
            function Disconnect-MgGraph { }
            function Invoke-MgGraphRequest { param($Uri, $Method, $OutputType) }
        }
        BeforeEach {
            Mock Import-Module {}
            Mock Connect-MgGraph {}
            Mock Get-MgContext { @{ TenantId = '11111111-1111-4111-8111-111111111111'; Environment = 'Global' } }
            Mock Disconnect-MgGraph {}
            Mock Invoke-MgGraphRequest { @{ value = @(@{ id = '11111111-1111-4111-8111-111111111111'; displayName = 'Tenant' }) } }
        }

        It 'uses process-scoped interactive authentication and GET requests only' {
            $e = Invoke-XrayLiveScan -TenantId $script:TestTenantId -Plan (Get-EntraXrayPlan -SourceId organization) -Settings (New-XraySettings)
            $e.TenantId | Should -Be $script:TestTenantId
            Should -Invoke Connect-MgGraph -Times 1 -Exactly -ParameterFilter { $ContextScope -eq 'Process' -and $TenantId -eq '11111111-1111-4111-8111-111111111111' -and $Scopes.Count -gt 0 }
            Should -Invoke Invoke-MgGraphRequest -Times 1 -Exactly -ParameterFilter { $Method -eq 'GET' -and $OutputType -eq 'Hashtable' }
            Should -Invoke Disconnect-MgGraph -Times 1 -Exactly
        }

        It 'supports device code and app-only certificate authentication without plaintext credentials' {
            $p = Get-EntraXrayPlan -SourceId organization
            $null = Invoke-XrayLiveScan -TenantId $script:TestTenantId -Plan $p -Settings (New-XraySettings) -AuthenticationMode DeviceCode -ClientId $script:TestUserId
            Should -Invoke Connect-MgGraph -Times 1 -ParameterFilter { $UseDeviceAuthentication -and $ClientId }
            $null = Invoke-XrayLiveScan -TenantId $script:TestTenantId -Plan $p -Settings (New-XraySettings) -AuthenticationMode Certificate -ClientId $script:TestUserId -CertificateThumbprint 'ABC123'
            Should -Invoke Connect-MgGraph -Times 1 -ParameterFilter { $CertificateThumbprint -eq 'ABC123' -and -not $Scopes }
            { Invoke-XrayLiveScan -TenantId $script:TestTenantId -Plan $p -Settings (New-XraySettings) -AuthenticationMode Certificate } | Should -Throw '*ClientId*CertificateThumbprint*'
        }

        It 'never disconnects an explicitly reused context' {
            $null = Invoke-XrayLiveScan -TenantId $script:TestTenantId -Plan (Get-EntraXrayPlan -SourceId organization) -Settings (New-XraySettings) -AuthenticationMode ExistingContext
            Should -Invoke Connect-MgGraph -Times 0
            Should -Invoke Disconnect-MgGraph -Times 0
        }

        It 'refuses a mismatched tenant or cloud before collecting any evidence' -ForEach @(
            @{ Context = @{ TenantId = '33333333-3333-4333-8333-333333333333'; Environment = 'Global' } }
            @{ Context = @{ TenantId = '11111111-1111-4111-8111-111111111111'; Environment = 'USGov' } }
            @{ Context = $null }
        ) {
            param($Context)
            Mock Get-MgContext { $Context }.GetNewClosure()
            { Invoke-XrayLiveScan -TenantId $script:TestTenantId -Plan (Get-EntraXrayPlan -SourceId organization) -Settings (New-XraySettings) } | Should -Throw '*context*'
            Should -Invoke Invoke-MgGraphRequest -Times 0
            Should -Invoke Disconnect-MgGraph -Times 1
        }

        It 'disconnects owned authentication even when collection fails unexpectedly' {
            Mock Invoke-MgGraphRequest { throw [System.InvalidOperationException]::new('transport bug') }
            { Invoke-XrayLiveScan -TenantId $script:TestTenantId -Plan (Get-EntraXrayPlan -SourceId organization) -Settings (New-XraySettings) } | Should -Throw '*transport bug*'
            Should -Invoke Disconnect-MgGraph -Times 1
        }

        It 'surfaces missing Graph dependencies and failed authentication explicitly' {
            Mock Import-Module { throw [System.IO.FileNotFoundException]::new('Missing Graph module') }
            { Invoke-XrayLiveScan -TenantId $script:TestTenantId -Plan (Get-EntraXrayPlan -SourceId organization) -Settings (New-XraySettings) } | Should -Throw '*Microsoft.Graph.Authentication*'
            Mock Import-Module {}
            Mock Connect-MgGraph { throw 'Authentication denied' }
            { Invoke-XrayLiveScan -TenantId $script:TestTenantId -Plan (Get-EntraXrayPlan -SourceId organization) -Settings (New-XraySettings) } | Should -Throw '*Authentication denied*'
            Should -Invoke Disconnect-MgGraph -Times 0
        }
    }
}
