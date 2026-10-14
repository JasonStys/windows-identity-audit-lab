# BEGIN CODE MAP (generated; python scripts/code_map.py)
# parameter: AnalyzerPath - line 133
# parameter: Native - line 133
# variable reference: AnalyzerPath - line 133
# variable reference: Native - line 133
# variable reference: ErrorActionPreference - line 135
# variable reference: PSScriptRoot - line 136
# variable reference: checks - line 137
# definition: Assert-Condition - line 138
# parameter: Condition - line 147
# parameter: Label - line 147
# variable reference: Condition - line 147
# variable reference: Label - line 147
# variable reference: Condition - line 148
# variable reference: Label - line 148
# variable reference: script:checks - line 149
# variable reference: null - line 151
# variable reference: true - line 151
# variable reference: user - line 151
# variable reference: group - line 152
# variable reference: member - line 153
# variable reference: user - line 153
# variable reference: external - line 154
# variable reference: time - line 155
# variable reference: external - line 156
# variable reference: group - line 156
# variable reference: member - line 156
# variable reference: snapshot - line 156
# variable reference: time - line 156
# variable reference: user - line 156
# variable reference: snapshot - line 157
# variable reference: snapshot - line 158
# variable reference: admin - line 159
# variable reference: snapshot - line 159
# variable reference: admin - line 160
# variable reference: external - line 161
# variable reference: foreign - line 161
# variable reference: snapshot - line 161
# variable reference: foreign - line 162
# variable reference: json - line 163
# variable reference: snapshot - line 163
# variable reference: json - line 164
# variable reference: snapshot - line 165
# variable reference: snapshot - line 166
# variable reference: unknown - line 167
# variable reference: null - line 168
# variable reference: unknown - line 168
# variable reference: malformed - line 169
# variable reference: user - line 169
# variable reference: malformed - line 170
# variable reference: null - line 170
# variable reference: sourceCase - line 171
# variable reference: normalized - line 172
# variable reference: sourceCase - line 172
# variable reference: user - line 172
# variable reference: normalized - line 173
# variable reference: sourceCase - line 173
# variable reference: failed - line 175
# variable reference: time - line 175
# variable reference: failed - line 176
# variable reference: failed - line 177
# variable reference: group - line 178
# variable reference: partial - line 178
# variable reference: time - line 178
# variable reference: user - line 178
# variable reference: partial - line 179
# variable reference: partialGroup - line 179
# variable reference: partialGroup - line 180
# variable reference: false - line 181
# variable reference: invalid - line 181
# variable reference: invalid - line 182
# variable reference: true - line 182
# variable reference: invalid - line 183
# variable reference: null - line 184
# variable reference: false - line 187
# variable reference: missingSid - line 187
# variable reference: missingSid - line 188
# variable reference: true - line 188
# variable reference: missingSid - line 189
# variable reference: failedUser - line 190
# variable reference: time - line 190
# variable reference: failedUser - line 191
# variable reference: failedMember - line 192
# variable reference: group - line 192
# variable reference: time - line 192
# variable reference: failedMember - line 193
# variable reference: group - line 194
# variable reference: time - line 194
# variable reference: unknownMember - line 194
# variable reference: user - line 194
# variable reference: unknownMember - line 195
# variable reference: false - line 196
# variable reference: refused - line 196
# variable reference: PSScriptRoot - line 197
# variable reference: false - line 197
# variable reference: refused - line 197
# variable reference: true - line 197
# variable reference: refused - line 198
# variable reference: AnalyzerPath - line 200
# variable reference: AnalyzerPath - line 201
# variable reference: PSScriptRoot - line 202
# variable reference: diagnostics - line 202
# variable reference: diagnostics - line 203
# variable reference: diagnostics - line 204
# variable reference: Native - line 206
# variable reference: env:GITHUB_ACTIONS - line 207
# variable reference: env:RUNNER_OS - line 207
# variable reference: null - line 208
# variable reference: wellKnown - line 208
# variable reference: wellKnown - line 209
# variable reference: live - line 210
# variable reference: live - line 211
# variable reference: live - line 212
# variable reference: wellKnown - line 212
# variable reference: PSVersionTable - line 215
# variable reference: psVersion - line 215
# variable reference: AnalyzerPath - line 216
# variable reference: Native - line 216
# variable reference: checks - line 216
# variable reference: psVersion - line 216
# variable reference: true - line 216
# END CODE MAP
# Jason Stys: synthetic collector contracts plus optional disposable-runner native checks; no PC collection by default.
<#
.SYNOPSIS
Test normalization, failures, localized SID handling and Windows API agreement without exporting real identities.
.PARAMETER Native
Allow read-only collection on a disposable CI runner. Real records are consumed privately in memory.
.PARAMETER AnalyzerPath
Optional hash-verified PSScriptAnalyzer manifest to check all authored PowerShell.
#>
[CmdletBinding()]
param([switch]$Native, [string]$AnalyzerPath)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'IdentitySnapshot.psm1') -Force
$checks = 0
function Assert-Condition {
    <#
    .SYNOPSIS
    Fail a named synthetic/native assertion without printing principal data.
    .PARAMETER Condition
    Boolean test result.
    .PARAMETER Label
    Nonpersonal assertion label.
    #>
    param([bool]$Condition, [string]$Label)
    if (-not $Condition) { throw "Assertion failed: $Label" }
    $script:checks += 1
}
$user = [pscustomobject]@{ SID='S-1-5-21-100-200-300-1001'; PrincipalSource='Local'; Enabled=$true; PasswordRequired=$true; LastLogon=[datetime]'2026-10-01T00:00:00Z'; AccountExpires=$null; Name='DO_NOT_EXPORT'; Description='PRIVATE' }
$group = [pscustomobject]@{ SID='S-1-5-32-544'; PrincipalSource='Local'; Name='Administrateurs' }
$member = [pscustomobject]@{ SID=$user.SID; PrincipalSource='Local'; ObjectClass='User' }
$external = [pscustomobject]@{ SID='S-1-5-21-900-800-700-2001'; PrincipalSource='ActiveDirectory'; ObjectClass='Group' }
$time = [datetimeoffset]'2026-10-14T00:00:00Z'
$snapshot = Get-IdentitySnapshot -HostAlias 'LAB-WIN' -Captured $time -ReadUsers { $user } -ReadGroups { $group } -ReadMembers { $member; $member; $external }
Assert-Condition ($snapshot.users_complete -and $snapshot.groups_complete) 'successful components'
Assert-Condition ($snapshot.principals.Count -eq 3) 'deduplicated identity records'
$admin = @($snapshot.principals | Where-Object sid -EQ 'S-1-5-32-544')[0]
Assert-Condition ($admin.members.Count -eq 2 -and $admin.members_complete) 'deduplicated direct membership'
$foreign = @($snapshot.principals | Where-Object sid -EQ $external.SID)[0]
Assert-Condition (-not $foreign.members_complete -and $foreign.source -eq 'ad') 'external group remains unknown'
$json = $snapshot | ConvertTo-Json -Depth 8
Assert-Condition ($json -notmatch 'DO_NOT_EXPORT|PRIVATE|Administrateurs|Description') 'no names or descriptions'
Assert-Condition ($snapshot.host -eq 'LAB-WIN' -and $snapshot.schema -eq 1) 'explicit alias/schema'
Assert-Condition ($snapshot.captured -eq '2026-10-14T00:00:00.0000000+00:00') 'UTC fixed clock'
$unknown = ConvertTo-IdentityRecord -Item ([pscustomobject]@{SID='S-1-5-21-100-200-300-1002'}) -Kind user
Assert-Condition ($null -eq $unknown.enabled -and $null -eq $unknown.password_required -and $null -eq $unknown.last_logon -and $unknown.source -eq 'unknown') 'missing fields stay null'
$malformed = ConvertTo-IdentityRecord -Item ([pscustomobject]@{SID=$user.SID; Enabled='false'; PasswordRequired=1}) -Kind user
Assert-Condition ($null -eq $malformed.enabled -and $null -eq $malformed.password_required) 'no truthy coercion'
foreach ($sourceCase in @(@('AzureAD','entra'),@('MicrosoftEntra','entra'),@('MicrosoftAccount','microsoft'),@('future','unknown'))) {
    $normalized = ConvertTo-IdentityRecord -Item ([pscustomobject]@{SID=$user.SID;PrincipalSource=$sourceCase[0]}) -Kind user
    Assert-Condition ($normalized.source -eq $sourceCase[1]) 'provider source normalization'
}
$failed = Get-IdentitySnapshot -HostAlias 'LAB-WIN' -Captured $time -ReadUsers { throw 'SECRET' } -ReadGroups { throw 'SECRET' }
Assert-Condition (-not $failed.users_complete -and -not $failed.groups_complete -and $failed.principals.Count -eq 0) 'denied is not empty success'
Assert-Condition (($failed | ConvertTo-Json -Depth 8) -notmatch 'SECRET') 'no exception content'
$partial = Get-IdentitySnapshot -HostAlias 'LAB-WIN' -Captured $time -ReadUsers { $user } -ReadGroups { $group } -ReadMembers { throw 'SECRET' }
$partialGroup = @($partial.principals | Where-Object kind -EQ group)[0]
Assert-Condition (-not $partialGroup.members_complete -and $partialGroup.members.Count -eq 0) 'failed membership unknown'
$invalid = $false
try { ConvertTo-IdentityRecord -Item ([pscustomobject]@{SID='not-a-sid'}) -Kind user | Out-Null } catch { $invalid = $true }
Assert-Condition $invalid 'invalid SID rejected by native parser'
Assert-Condition ($null -eq (ConvertTo-UtcStamp -Value $null)) 'null date preserved'
Assert-Condition ((ConvertTo-UtcStamp -Value ([datetime]'2026-10-01T00:00:00Z')) -eq '2026-10-01T00:00:00.0000000Z') 'native UTC dates'

$missingSid = $false
try { ConvertTo-IdentityRecord -Item ([pscustomobject]@{Enabled=$true}) -Kind user | Out-Null } catch { $missingSid = $true }
Assert-Condition $missingSid 'missing SID rejected'
$failedUser = Get-IdentitySnapshot -HostAlias 'LAB-WIN' -Captured $time -ReadUsers { [pscustomobject]@{SID='invalid'} } -ReadGroups { }
Assert-Condition (-not $failedUser.users_complete -and $failedUser.groups_complete) 'normalization failure marks component incomplete'
$failedMember = Get-IdentitySnapshot -HostAlias 'LAB-WIN' -Captured $time -ReadUsers { } -ReadGroups { $group } -ReadMembers { [pscustomobject]@{SID='invalid'} }
Assert-Condition (-not $failedMember.principals[0].members_complete) 'invalid membership does not become complete'
$unknownMember = Get-IdentitySnapshot -HostAlias 'LAB-WIN' -Captured $time -ReadUsers { } -ReadGroups { $group } -ReadMembers { [pscustomobject]@{SID=$user.SID;ObjectClass='future'} }
Assert-Condition (@($unknownMember.principals | Where-Object kind -EQ unknown).Count -eq 1) 'unsupported member classification stays unknown'
$refused = $false
try { & (Join-Path $PSScriptRoot 'Collect-Identity.ps1') -Authorized:$false -HostAlias LAB-WIN -OutputPath 'UNUSED-PATH' | Out-Null } catch { $refused = $true }
Assert-Condition $refused 'wrapper refuses missing authorization before any collection'

if ($AnalyzerPath) {
    Import-Module $AnalyzerPath -Force
    $diagnostics = @(Invoke-ScriptAnalyzer -Path $PSScriptRoot -Recurse -Severity Error,Warning)
    if ($diagnostics.Count -ne 0) { $diagnostics | Format-Table RuleName,ScriptName,Line,Message; throw 'PowerShell static analysis failed' }
    Assert-Condition ($diagnostics.Count -eq 0) 'PSScriptAnalyzer zero errors/warnings'
}
if ($Native) {
    Assert-Condition ($env:GITHUB_ACTIONS -eq 'true' -and $env:RUNNER_OS -eq 'Windows') 'native checks confined to disposable GitHub runner'
    $wellKnown = [System.Security.Principal.SecurityIdentifier]::new([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null)
    Assert-Condition ($wellKnown.Value -eq 'S-1-5-32-544') 'native well-known SID agreement'
    $live = Get-IdentitySnapshot -HostAlias 'DISPOSABLE-RUNNER'
    Assert-Condition ($live.users_complete -and $live.groups_complete) 'native LocalAccounts enumeration completed'
    Assert-Condition (@($live.principals | Where-Object sid -EQ $wellKnown.Value).Count -eq 1) 'native localized-independent administrators identity'
    # Only aggregate assertions reach logs; no real SID/account snapshots or artifacts are written.
}
$psVersion = $PSVersionTable.PSVersion.ToString()
@{author='Jason Stys';checks=$checks;native=[bool]$Native;synthetic=$true;powershell=$psVersion;analyzer=if($AnalyzerPath){'1.25.0'}else{'not requested'}} | ConvertTo-Json -Compress
