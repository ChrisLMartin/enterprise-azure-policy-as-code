BeforeAll {
    foreach ($helper in @(
            'Confirm-ValidPolicyResourceName.ps1'
            'Get-DeepCloneAsOrderedHashtable.ps1'
            'Build-AssignmentParameterObject.ps1'
            'Confirm-ObjectValueEqualityDeep.ps1'
            'Get-FilteredPolicyRoleDefinitionIds.ps1'
            'Get-FilteredPolicySetRoleDefinitionIds.ps1'
            'Build-AssignmentDefinitionAtLeaf.ps1'
        )) {
        . (Join-Path $PSScriptRoot "../../../Scripts/Helpers/$helper")
    }

    $script:storageRole = '/providers/Microsoft.Authorization/roleDefinitions/17d1049b-9a84-46fb-8f53-869881c3d3ab'
    $script:readerRole = '/providers/Microsoft.Authorization/roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7'
    $script:testPolicyId = '/providers/Microsoft.Authorization/policyDefinitions/softdel'
    $script:testPolicySetId = '/providers/Microsoft.Authorization/policySetDefinitions/softdel-set'
    $script:userAssignedIdentityId = '/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-identity/providers/Microsoft.ManagedIdentity/userAssignedIdentities/uami-policy'

    function New-LeafDefinition {
        param (
            [hashtable] $Parameters = @{},
            [switch] $PolicySet,
            $Overrides = $null,
            $AdditionalRoleAssignments = $null,
            $UserAssignedIdentity = $null
        )
        $definitionId = if ($PolicySet) { $script:testPolicySetId } else { $script:testPolicyId }
        $definition = @{
            nodeName                = '/root/test'
            assignment              = @{ name = 'softdel-test'; displayName = 'Test'; description = '' }
            definitionEntryList     = @(
                @{
                    policyDefinitionId = $definitionId
                    isPolicySet        = [bool] $PolicySet
                    assignment         = @{ append = $false; name = ''; displayName = ''; description = '' }
                }
            )
            scopeCollection         = @( @{ scope = '/providers/Microsoft.Management/managementGroups/test-mg' } )
            metadata                = @{}
            parameters              = $Parameters
            enforcementMode         = 'Default'
            managedIdentityLocation = 'australiaeast'
        }
        if ($Overrides) {
            $definition.overrides = $Overrides
        }
        if ($AdditionalRoleAssignments) {
            $definition.additionalRoleAssignments = $AdditionalRoleAssignments
        }
        if ($UserAssignedIdentity) {
            $definition.userAssignedIdentity = $UserAssignedIdentity
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
                $script:testPolicyId = @{
                    name                   = 'softdel'
                    effectParameterName    = 'effect'
                    effectValue            = 'AuditIfNotExists'
                    effectAllowedOverrides = @( 'AuditIfNotExists', 'DeployIfNotExists', 'Disabled' )
                    parameters             = @{
                        effect = @{ isEffect = $true; defaultValue = 'AuditIfNotExists' }
                    }
                }
            }
            policySets = @{
                # The Policy Set hard-codes its only member to AuditIfNotExists.
                $script:testPolicySetId = @{
                    name              = 'softdel-set'
                    parameters        = @{}
                    policyDefinitions = @(
                        @{
                            id                          = $script:testPolicyId
                            policyDefinitionReferenceId = 'softdelRef'
                            effectReason                = 'PolicySet Fixed'
                            effectValue                 = 'AuditIfNotExists'
                        }
                    )
                }
            }
        }
        $hasErrors, $assignmentsList = Build-AssignmentDefinitionAtLeaf `
            -PacEnvironment @{ pacOwnerId = 'test'; deployedBy = 'test'; filterRoleAssignmentsByEffect = $Filter } `
            -AssignmentDefinition $AssignmentDefinition `
            -CombinedPolicyDetails $combinedPolicyDetails `
            -PolicyRoleIds @{
                $script:testPolicyId    = @( $script:storageRole )
                $script:testPolicySetId = @( $script:storageRole )
            } `
            -RoleDefinitions @{}
        $hasErrors | Should -BeFalse
        $assignmentsList[0]
    }
}

Describe 'Build-AssignmentDefinitionAtLeaf roles for a single Policy' {

    It 'keeps the identity but grants no roles when the effect parameter equals the non-deploying default' {
        $assignment = Invoke-Leaf -AssignmentDefinition (New-LeafDefinition -Parameters @{ effect = 'AuditIfNotExists' })
        $assignment.identityRequired | Should -BeTrue
        $assignment.identity.type | Should -Be 'SystemAssigned'
        $assignment.managedIdentityLocation | Should -Be 'australiaeast'
        $assignment.requiredRoleAssignments | Should -BeNullOrEmpty
    }

    It 'grants the roles for DeployIfNotExists' {
        $assignment = Invoke-Leaf -AssignmentDefinition (New-LeafDefinition -Parameters @{ effect = 'DeployIfNotExists' })
        $assignment.identityRequired | Should -BeTrue
        $assignment.identity.type | Should -Be 'SystemAssigned'
        @($assignment.requiredRoleAssignments).Count | Should -Be 1
        $assignment.requiredRoleAssignments[0].roleDefinitionId | Should -Be $script:storageRole
    }

    It 'grants the roles when an override raises the effect to DeployIfNotExists' {
        $overrides = @( @{ kind = 'policyEffect'; value = 'DeployIfNotExists' } )
        $assignment = Invoke-Leaf -AssignmentDefinition (New-LeafDefinition -Parameters @{ effect = 'AuditIfNotExists' } -Overrides $overrides)
        @($assignment.requiredRoleAssignments).Count | Should -Be 1
        $assignment.requiredRoleAssignments[0].roleDefinitionId | Should -Be $script:storageRole
    }

    It 'grants only the additionalRoleAssignments when the Policy roles are filtered out' {
        $additional = @( @{ roleDefinitionId = $script:readerRole; scope = '/subscriptions/00000000-0000-0000-0000-000000000000' } )
        $assignment = Invoke-Leaf -AssignmentDefinition (New-LeafDefinition -Parameters @{ effect = 'AuditIfNotExists' } -AdditionalRoleAssignments $additional)
        $assignment.identityRequired | Should -BeTrue
        @($assignment.requiredRoleAssignments).Count | Should -Be 1
        $assignment.requiredRoleAssignments[0].roleDefinitionId | Should -Be $script:readerRole
    }

    It 'keeps a userAssignedIdentity when the Policy roles are filtered out' {
        $assignment = Invoke-Leaf -AssignmentDefinition (New-LeafDefinition -Parameters @{ effect = 'AuditIfNotExists' } -UserAssignedIdentity $script:userAssignedIdentityId)
        $assignment.identityRequired | Should -BeTrue
        $assignment.identity.type | Should -Be 'UserAssigned'
        $assignment.requiredRoleAssignments | Should -BeNullOrEmpty
    }

    It 'grants every role when filterRoleAssignmentsByEffect is false' {
        $assignment = Invoke-Leaf -AssignmentDefinition (New-LeafDefinition -Parameters @{ effect = 'AuditIfNotExists' }) -Filter $false
        $assignment.identityRequired | Should -BeTrue
        @($assignment.requiredRoleAssignments).Count | Should -Be 1
    }
}

Describe 'Build-AssignmentDefinitionAtLeaf roles for a Policy Set' {

    It 'keeps the identity but grants no roles when every member role is filtered out' {
        $assignment = Invoke-Leaf -AssignmentDefinition (New-LeafDefinition -PolicySet)
        $assignment.identityRequired | Should -BeTrue
        $assignment.identity.type | Should -Be 'SystemAssigned'
        $assignment.requiredRoleAssignments | Should -BeNullOrEmpty
    }

    It 'grants the roles when an override raises the member to DeployIfNotExists' {
        $overrides = @(
            @{
                kind      = 'policyEffect'
                value     = 'DeployIfNotExists'
                selectors = @( @{ kind = 'policyDefinitionReferenceId'; in = @( 'softdelRef' ) } )
            }
        )
        $assignment = Invoke-Leaf -AssignmentDefinition (New-LeafDefinition -PolicySet -Overrides $overrides)
        @($assignment.requiredRoleAssignments).Count | Should -Be 1
        $assignment.requiredRoleAssignments[0].roleDefinitionId | Should -Be $script:storageRole
    }

    It 'grants every member role when filterRoleAssignmentsByEffect is false' {
        $assignment = Invoke-Leaf -AssignmentDefinition (New-LeafDefinition -PolicySet) -Filter $false
        @($assignment.requiredRoleAssignments).Count | Should -Be 1
    }
}
