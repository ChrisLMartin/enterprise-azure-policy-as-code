BeforeAll {
    . (Join-Path $PSScriptRoot '../../../Scripts/Helpers/Build-AssignmentIdentityChanges.ps1')

    $script:scope = '/providers/Microsoft.Management/managementGroups/test-mg'
    $script:assignmentId = "$($script:scope)/providers/Microsoft.Authorization/policyAssignments/softdel-test"
    $script:principalId = '11111111-1111-1111-1111-111111111111'

    $script:existing = @{
        id       = $script:assignmentId
        location = 'australiaeast'
        identity = @{ type = 'SystemAssigned'; principalId = $script:principalId }
    }
    $script:deployedRoleAssignment = @{
        id               = "$($script:scope)/providers/Microsoft.Authorization/roleAssignments/22222222-2222-2222-2222-222222222222"
        scope            = $script:scope
        roleDefinitionId = '/providers/Microsoft.Authorization/roleDefinitions/17d1049b-9a84-46fb-8f53-869881c3d3ab'
        principalId      = $script:principalId
    }

    function New-Assignment {
        param (
            $RequiredRoleAssignments = @()
        )
        @{
            id                      = $script:assignmentId
            displayName             = 'Test'
            identity                = @{ type = 'SystemAssigned' }
            identityRequired        = $true
            managedIdentityLocation = 'australiaeast'
            requiredRoleAssignments = $RequiredRoleAssignments
        }
    }
}

Describe 'Build-AssignmentIdentityChanges when role filtering removes every role' {

    It 'removes the role assignment without replacing the assignment' {
        $result = Build-AssignmentIdentityChanges `
            -Existing $script:existing `
            -Assignment (New-Assignment) `
            -ReplacedAssignment $false `
            -DeployedRoleAssignmentsByPrincipalId @{ $script:principalId = @( $script:deployedRoleAssignment ) }

        $result.replaced | Should -BeFalse
        $result.requiresRoleChanges | Should -BeTrue
        $result.changedIdentityStrings | Should -Be @( 'removedRoleAssignments' )
        @($result.removed).Count | Should -Be 1
        $result.removed[0].id | Should -Be $script:deployedRoleAssignment.id
        @($result.added).Count | Should -Be 0
    }

    It 'reports no changes once the role assignment has been removed' {
        $result = Build-AssignmentIdentityChanges `
            -Existing $script:existing `
            -Assignment (New-Assignment) `
            -ReplacedAssignment $false `
            -DeployedRoleAssignmentsByPrincipalId @{}

        $result.replaced | Should -BeFalse
        $result.requiresRoleChanges | Should -BeFalse
        $result.changedIdentityStrings | Should -BeNullOrEmpty
    }
}
