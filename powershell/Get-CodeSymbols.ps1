# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable reference: source - line 43
# variable reference: null - line 44
# variable reference: tokens - line 44
# variable reference: null - line 45
# variable reference: parseErrors - line 45
# variable reference: parseErrors - line 46
# variable reference: source - line 46
# variable reference: tokens - line 46
# variable reference: tree - line 46
# variable reference: parseErrors - line 47
# variable reference: symbols - line 48
# variable reference: tree - line 48
# parameter: Node - line 49
# variable reference: Node - line 49
# variable reference: Node - line 50
# variable reference: Node - line 51
# variable reference: Node - line 52
# variable reference: true - line 53
# variable reference: kind - line 54
# variable reference: _ - line 55
# variable reference: name - line 55
# variable reference: _ - line 56
# variable reference: _ - line 57
# variable reference: kind - line 57
# variable reference: name - line 57
# variable reference: _ - line 58
# variable reference: _ - line 59
# variable reference: kind - line 59
# variable reference: name - line 59
# variable reference: _ - line 61
# variable reference: kind - line 61
# variable reference: name - line 61
# variable reference: symbols - line 64
# END CODE MAP
# Jason Stys: parse-only PowerShell AST symbol map; never executes source supplied on stdin.
<#
.SYNOPSIS
Return exact source-line definitions, parameters and variable-reference locations for code headers.
#>
[CmdletBinding()]
param()
$source = [Console]::In.ReadToEnd()
$tokens = $null
$parseErrors = $null
$tree = [System.Management.Automation.Language.Parser]::ParseInput($source, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -gt 0) { throw 'PowerShell parse errors' }
$symbols = @($tree.FindAll({
    param($Node)
    $Node -is [System.Management.Automation.Language.FunctionDefinitionAst] -or
    $Node -is [System.Management.Automation.Language.ParameterAst] -or
    $Node -is [System.Management.Automation.Language.VariableExpressionAst]
}, $true) | ForEach-Object {
    $kind = 'variable reference'
    $name = $_.VariablePath.UserPath
    if ($_ -is [System.Management.Automation.Language.FunctionDefinitionAst]) {
        $kind = 'definition'; $name = $_.Name
    } elseif ($_ -is [System.Management.Automation.Language.ParameterAst]) {
        $kind = 'parameter'; $name = $_.Name.VariablePath.UserPath
    }
    ,@($kind, $name, $_.Extent.StartLineNumber)
})
# Unary comma prevents pipeline flattening of symbol tuples.
ConvertTo-Json -InputObject $symbols -Depth 4 -Compress
