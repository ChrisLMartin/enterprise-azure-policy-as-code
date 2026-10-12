BeforeAll {
    . (Join-Path $PSScriptRoot '../../../Scripts/Helpers/Get-FilteredPolicyRoleDefinitionIds.ps1')

    $script:storageRole = '/providers/Microsoft.Authorization/roleDefinitions/17d1049b-9a84-46fb-8f53-869881c3d3ab'

    function New-PolicyDetails {
        param (
            [string] $EffectParameterName = 'effect',
            [string] $EffectValue = 'AuditIfNotExists'
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

Describe 'Build-AssignmentDefinitionAtLeaf identity for a single Policy' {

    BeforeAll {
        foreach ($helper in @(
                'Confirm-ValidPolicyResourceName.ps1'
                'Get-DeepCloneAsOrderedHashtable.ps1'
                'Build-AssignmentParameterObject.ps1'
                'Confirm-ObjectValueEqualityDeep.ps1'
                'Build-AssignmentDefinitionAtLeaf.ps1'
            )) {
            . (Join-Path $PSScriptRoot "../../../Scripts/Helpers/$helper")
        }

        $script:policyId = '/providers/Microsoft.Authorization/policyDefinitions/softdel'

        function New-LeafDefinition {
            param (
                [hashtable] $Parameters = @{},
                $AdditionalRoleAssignments = $null
            )
            $definition = @{
                nodeName                = '/root/test'
                assignment              = @{ name = 'softdel-test'; displayName = 'Test'; description = '' }
                definitionEntryList     = @(
                    @{
                        policyDefinitionId = $script:policyId
                        isPolicySet        = $false
                        assignment         = @{ append = $false; name = ''; displayName = ''; description = '' }
                    }
                )
                scopeCollection         = @( @{ scope = '/providers/Microsoft.Management/managementGroups/test-mg' } )
                metadata                = @{}
                parameters              = $Parameters
                enforcementMode         = 'Default'
                managedIdentityLocation = 'australiaeast'
            }
            if ($AdditionalRoleAssignments) {
                $definition.additionalRoleAssignments = $AdditionalRoleAssignments
            }
            $definition
        }

        function Invoke-Leaf {
            param (
                [hashtable] $AssignmentDefinition,
                [bool] $Filter = $true
            )
            $combinedPolicyDetails = @{
                policies   = @{
                    $script:policyId = @{
                        name                = 'softdel'
                        effectParameterName = 'effect'
                        effectValue         = 'AuditIfNotExists'
                        parameters          = @{
                            effect = @{ isEffect = $true; defaultValue = 'AuditIfNotExists' }
                        }
                    }
                }
                policySets = @{}
            }
            $hasErrors, $assignmentsList = Build-AssignmentDefinitionAtLeaf `
                -PacEnvironment @{ pacOwnerId = 'test'; deployedBy = 'test'; filterRoleAssignmentsByEffect = $Filter } `
                -AssignmentDefinition $AssignmentDefinition `
                -CombinedPolicyDetails $combinedPolicyDetails `
                -PolicyRoleIds @{ $script:policyId = @( $script:storageRole ) } `
                -RoleDefinitions @{}
            $hasErrors | Should -BeFalse
            $assignmentsList[0]
        }
    }

    It 'does not create an identity when the effect parameter equals the non-deploying default' {
        $assignment = Invoke-Leaf -AssignmentDefinition (New-LeafDefinition -Parameters @{ effect = 'AuditIfNotExists' })
        $assignment.identityRequired | Should -BeFalse
        $assignment.identity.type | Should -Be 'None'
        $assignment.Contains('managedIdentityLocation') | Should -BeFalse
        $assignment.requiredRoleAssignments | Should -BeNullOrEmpty
    }

    It 'creates an identity and role assignment for DeployIfNotExists' {
        $assignment = Invoke-Leaf -AssignmentDefinition (New-LeafDefinition -Parameters @{ effect = 'DeployIfNotExists' })
        $assignment.identityRequired | Should -BeTrue
        $assignment.identity.type | Should -Be 'SystemAssigned'
        @($assignment.requiredRoleAssignments).Count | Should -Be 1
        $assignment.requiredRoleAssignments[0].roleDefinitionId | Should -Be $script:storageRole
    }

    It 'keeps the identity for additionalRoleAssignments when the Policy roles are filtered out' {
        $additional = @( @{ roleDefinitionId = '/providers/Microsoft.Authorization/roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7'; scope = '/subscriptions/00000000-0000-0000-0000-000000000000' } )
        $assignment = Invoke-Leaf -AssignmentDefinition (New-LeafDefinition -Parameters @{ effect = 'AuditIfNotExists' } -AdditionalRoleAssignments $additional)
        $assignment.identityRequired | Should -BeTrue
        @($assignment.requiredRoleAssignments).Count | Should -Be 1
        $assignment.requiredRoleAssignments[0].scope | Should -Be '/subscriptions/00000000-0000-0000-0000-000000000000'
    }

    It 'keeps the previous behaviour when filterRoleAssignmentsByEffect is false' {
        $assignment = Invoke-Leaf -AssignmentDefinition (New-LeafDefinition -Parameters @{ effect = 'AuditIfNotExists' }) -Filter $false
        $assignment.identityRequired | Should -BeTrue
        @($assignment.requiredRoleAssignments).Count | Should -Be 1
    }
}
