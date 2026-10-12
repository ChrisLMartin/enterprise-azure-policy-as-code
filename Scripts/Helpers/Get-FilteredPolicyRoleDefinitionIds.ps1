function Get-FilteredPolicyRoleDefinitionIds {
    <#
    .SYNOPSIS
    Removes the roleDefinitionIds of a single Policy assignment when the assignment evaluates the
    Policy with a non-deploying effect.

    .DESCRIPTION
    A Policy which declares roleDefinitionIds is normally granted those roles whatever effect the
    assignment chooses. A DeployIfNotExists or Modify Policy is commonly assigned twice, once with
    its effect parameter set to AuditIfNotExists or Audit for reporting and once with the deploying
    effect, and the reporting assignment can never use the roles it is granted.

    The effective effect is resolved in the same order Azure applies it:
      1. a 'policyEffect' override on the assignment
      2. the effect parameter value in the assignment
      3. the effect parameter defaultValue, or the literal effect in the Policy definition

    Only a recognised non-deploying literal removes the roles. Anything else - a deploying effect,
    an unrecognised value or an effect which cannot be resolved - keeps every role.

    When the assignment pins definitionVersion and the effect comes from the definition itself
    (step 3), the latest definition may not match the deployed version, so the roles are kept.
    #>

    [CmdletBinding()]
    param (
        $PolicyDetails,
        [hashtable] $AssignmentParameters,
        $OverridesList,
        $UnfilteredRoleDefinitionIds,
        [switch] $DefinitionVersionPinned
    )

    $unfilteredRoleDefinitionIds = @($UnfilteredRoleDefinitionIds)
    if ($unfilteredRoleDefinitionIds.Count -eq 0 -or $null -eq $PolicyDetails) {
        return $unfilteredRoleDefinitionIds
    }

    # Keep in sync with Get-FilteredPolicySetRoleDefinitionIds. This must be a whitelist so that any
    # value EPAC does not recognise keeps its roles.
    $nonDeployingEffects = @(
        "AddToNetworkGroup",
        "Append",
        "Audit",
        "AuditIfNotExists",
        "Deny",
        "DenyAction",
        "Disabled",
        "Manual"
    )

    $effectiveEffect = $null
    $effectFromAssignment = $false

    foreach ($override in $OverridesList) {
        if ($override.kind -eq "policyEffect" -and $null -ne $override.value) {
            $effectiveEffect = $override.value
            $effectFromAssignment = $true
        }
    }

    $effectParameterName = $PolicyDetails.effectParameterName
    if (-not $effectFromAssignment -and $effectParameterName -and $null -ne $AssignmentParameters) {
        # Match case-insensitively, as Azure does; the hashtable may have been built case-sensitive.
        foreach ($parameterName in $AssignmentParameters.Keys) {
            if ($parameterName -eq $effectParameterName) {
                $effectiveEffect = $AssignmentParameters.$parameterName
                $effectFromAssignment = $true
                break
            }
        }
    }

    if (-not $effectFromAssignment) {
        if ($DefinitionVersionPinned) {
            return $unfilteredRoleDefinitionIds
        }
        $effectiveEffect = $PolicyDetails.effectValue
    }

    if ($effectiveEffect -is [string] -and $effectiveEffect -in $nonDeployingEffects) {
        return @()
    }
    return $unfilteredRoleDefinitionIds
}
