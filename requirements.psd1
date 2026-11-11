@{
    Runtime = @{
        'Microsoft.Graph.Authentication' = @{ MinimumVersion = '2.0.0'; LiveCollectionOnly = $true }
    }
    Test = @{
        Pester = @{ MinimumVersion = '5.7.1' }
    }
}
