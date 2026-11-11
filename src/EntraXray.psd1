@{
    RootModule = 'EntraXray.psm1'
    ModuleVersion = '1.0.0'
    GUID = '49e4c59b-4717-4e15-901b-997dc234927d'
    Author = 'EntraXray contributors'
    Description = 'Read-only, evidence-backed Microsoft Entra ID assessment and offline replay.'
    PowerShellVersion = '7.2'
    FunctionsToExport = @('Get-EntraXrayPlan', 'Get-EntraXrayCheck', 'Invoke-EntraXray')
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @()
    PrivateData = @{
        PSData = @{
            Tags = @('Entra', 'Assessment', 'ReadOnly', 'MicrosoftGraph')
        }
    }
}
