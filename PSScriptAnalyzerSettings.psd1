@{
    Severity     = @('Error', 'Warning')
    ExcludeRules = @(
        # Console output is the point: scripts are run interactively or by an RMM that captures host output.
        'PSAvoidUsingWriteHost',
        # Empty catch blocks are deliberate for optional data sources (a role that is not installed,
        # a licence tier that is not present). Each one is a best-effort read, never a write.
        'PSAvoidUsingEmptyCatchBlock',
        # Helper functions are internal to each standalone script and are not exported cmdlets.
        'PSUseShouldProcessForStateChangingFunctions',
        'PSUseSingularNouns',
        # Parameters are read through Get-InputValue / Read-Input fallbacks the analyzer cannot follow.
        'PSReviewUnusedParameter',
        'PSUseDeclaredVarsMoreThanAssignments'
    )
}
