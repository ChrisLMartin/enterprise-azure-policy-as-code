BeforeAll {
    . (Join-Path $PSScriptRoot '../../../Scripts/Helpers/Get-FilteredPolicyRoleDefinitionIds.ps1')

    $script:storageRole = '/providers/Microsoft.Authorization/roleDefinitions/17d1049b-9a84-46fb-8f53-869881c3d3ab'

    function New-PolicyDetails {
        # Untyped, so that $null is passed through rather than coerced to an empty string.
        param (
            $EffectParameterName = 'effect',
            $EffectValue = 'AuditIfNotExists'
        )
        @{
            effectParameterName = $EffectParameterName
            effectValue         = $EffectValue
        }
    }

    function Invoke-Filter {
        param (
            $PolicyDetails,
            [hashtable] $AssignmentParameters = @{},
            $OverridesList = @(),
            [switch] $DefinitionVersionPinned
        )
        Get-FilteredPolicyRoleDefinitionIds `
            -PolicyDetails $PolicyDetails `
            -AssignmentParameters $AssignmentParameters `
            -OverridesList $OverridesList `
            -UnfilteredRoleDefinitionIds @( $script:storageRole ) `
            -DefinitionVersionPinned:$DefinitionVersionPinned
    }
}

Describe 'Get-FilteredPolicyRoleDefinitionIds' {

    Context 'effect set by the assignment parameter' {

        It 'removes the roles for <Effect>' -ForEach @(
            @{ Effect = 'AuditIfNotExists' }
            @{ Effect = 'Audit' }
            @{ Effect = 'Disabled' }
            @{ Effect = 'auditifnotexists' }
        ) {
            $result = Invoke-Filter -PolicyDetails (New-PolicyDetails -EffectValue 'DeployIfNotExists') -AssignmentParameters @{ effect = $Effect }
            @($result).Count | Should -Be 0
        }

        It 'keeps the roles for <Effect>' -ForEach @(
            @{ Effect = 'DeployIfNotExists' }
            @{ Effect = 'Modify' }
            @{ Effect = "[parameters('somethingElse')]" }
        ) {
            $result = Invoke-Filter -PolicyDetails (New-PolicyDetails) -AssignmentParameters @{ effect = $Effect }
            $result | Should -Be @( $script:storageRole )
        }

        It 'matches the effect parameter name case-insensitively' {
            $parameters = [System.Collections.Hashtable]::new([System.StringComparer]::Ordinal)
            $parameters['Effect'] = 'AuditIfNotExists'
            $result = Invoke-Filter -PolicyDetails (New-PolicyDetails -EffectValue 'DeployIfNotExists') -AssignmentParameters $parameters
            @($result).Count | Should -Be 0
        }

        It 'uses the assignment parameter even when definitionVersion is pinned' {
            $result = Invoke-Filter -PolicyDetails (New-PolicyDetails -EffectValue 'DeployIfNotExists') -AssignmentParameters @{ effect = 'AuditIfNotExists' } -DefinitionVersionPinned
            @($result).Count | Should -Be 0
        }
    }

    Context 'effect set by an override' {

        It 'keeps the roles when an override raises the effect to DeployIfNotExists' {
            $overrides = @( @{ kind = 'policyEffect'; value = 'DeployIfNotExists' } )
            $result = Invoke-Filter -PolicyDetails (New-PolicyDetails) -AssignmentParameters @{ effect = 'AuditIfNotExists' } -OverridesList $overrides
            $result | Should -Be @( $script:storageRole )
        }

        It 'removes the roles when an override lowers the effect to Disabled' {
            $overrides = @( @{ kind = 'policyEffect'; value = 'Disabled' } )
            $result = Invoke-Filter -PolicyDetails (New-PolicyDetails) -AssignmentParameters @{ effect = 'DeployIfNotExists' } -OverridesList $overrides
            @($result).Count | Should -Be 0
        }
    }

    Context 'effect taken from the Policy definition' {

        It 'removes the roles when the parameter defaultValue is non-deploying' {
            $result = Invoke-Filter -PolicyDetails (New-PolicyDetails -EffectValue 'AuditIfNotExists')
            @($result).Count | Should -Be 0
        }

        It 'keeps the roles when the parameter defaultValue is deploying' {
            $result = Invoke-Filter -PolicyDetails (New-PolicyDetails -EffectValue 'DeployIfNotExists')
            $result | Should -Be @( $script:storageRole )
        }

        It 'keeps the roles when the effect has no default' {
            $result = Invoke-Filter -PolicyDetails (New-PolicyDetails -EffectValue $null)
            $result | Should -Be @( $script:storageRole )
        }

        It 'keeps the roles when the effect default is an empty string' {
            $result = Invoke-Filter -PolicyDetails (New-PolicyDetails -EffectValue '')
            $result | Should -Be @( $script:storageRole )
        }

        It 'removes the roles when the definition hard-codes a non-deploying effect' {
            $result = Invoke-Filter -PolicyDetails (New-PolicyDetails -EffectParameterName $null -EffectValue 'AuditIfNotExists')
            @($result).Count | Should -Be 0
        }

        It 'keeps the roles when definitionVersion is pinned, since the latest default may differ' {
            $result = Invoke-Filter -PolicyDetails (New-PolicyDetails -EffectValue 'AuditIfNotExists') -DefinitionVersionPinned
            $result | Should -Be @( $script:storageRole )
        }
    }
}
