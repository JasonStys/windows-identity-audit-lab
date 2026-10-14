# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: ConvertTo-UtcStamp - line 122
# parameter: Value - line 129
# variable reference: Value - line 129
# variable reference: Value - line 130
# variable reference: null - line 130
# variable reference: Value - line 131
# definition: Get-ObservedProperty - line 134
# parameter: Item - line 143
# parameter: Name - line 143
# variable reference: Item - line 143
# variable reference: Name - line 143
# variable reference: Item - line 144
# variable reference: Name - line 144
# variable reference: property - line 144
# variable reference: null - line 145
# variable reference: property - line 145
# variable reference: property - line 146
# definition: ConvertTo-IdentityRecord - line 149
# parameter: Item - line 158
# parameter: Kind - line 158
# variable reference: Item - line 158
# variable reference: Kind - line 158
# variable reference: Item - line 159
# variable reference: rawSid - line 159
# variable reference: null - line 160
# variable reference: rawSid - line 160
# variable reference: principalSid - line 161
# variable reference: rawSid - line 161
# variable reference: Item - line 162
# variable reference: rawSource - line 162
# variable reference: rawSource - line 163
# variable reference: source - line 163
# variable reference: record - line 171
# variable reference: principalSid - line 172
# variable reference: Kind - line 173
# variable reference: source - line 174
# variable reference: null - line 175
# variable reference: null - line 176
# variable reference: null - line 177
# variable reference: null - line 178
# variable reference: false - line 180
# variable reference: Kind - line 182
# variable reference: Item - line 184
# variable reference: enabled - line 184
# variable reference: Item - line 185
# variable reference: required - line 185
# variable reference: enabled - line 186
# variable reference: record - line 186
# variable reference: record - line 187
# variable reference: required - line 187
# variable reference: Item - line 188
# variable reference: record - line 188
# variable reference: Item - line 189
# variable reference: record - line 189
# variable reference: record - line 191
# definition: Get-IdentitySnapshot - line 194
# parameter: HostAlias - line 210
# variable reference: HostAlias - line 210
# parameter: Captured - line 211
# variable reference: Captured - line 211
# parameter: ReadUsers - line 212
# variable reference: ReadUsers - line 212
# parameter: ReadGroups - line 213
# variable reference: ReadGroups - line 213
# parameter: Group - line 214
# parameter: ReadMembers - line 214
# variable reference: Group - line 214
# variable reference: ReadMembers - line 214
# variable reference: records - line 216
# variable reference: true - line 217
# variable reference: usersComplete - line 217
# variable reference: groupsComplete - line 218
# variable reference: true - line 218
# variable reference: ReadUsers - line 220
# variable reference: user - line 220
# variable reference: record - line 221
# variable reference: user - line 221
# variable reference: record - line 222
# variable reference: records - line 222
# variable reference: false - line 226
# variable reference: usersComplete - line 226
# variable reference: ReadGroups - line 229
# variable reference: group - line 229
# variable reference: group - line 230
# variable reference: record - line 230
# variable reference: record - line 231
# variable reference: records - line 231
# variable reference: memberSids - line 233
# variable reference: ReadMembers - line 234
# variable reference: group - line 234
# variable reference: member - line 234
# variable reference: member - line 235
# variable reference: objectClass - line 235
# variable reference: kind - line 236
# variable reference: objectClass - line 236
# variable reference: child - line 237
# variable reference: kind - line 237
# variable reference: member - line 237
# variable reference: child - line 238
# variable reference: memberSids - line 238
# variable reference: child - line 240
# variable reference: records - line 240
# variable reference: memberSids - line 242
# variable reference: record - line 242
# variable reference: record - line 243
# variable reference: true - line 243
# variable reference: false - line 245
# variable reference: record - line 245
# variable reference: record - line 246
# variable reference: false - line 249
# variable reference: groupsComplete - line 249
# variable reference: HostAlias - line 252
# variable reference: Captured - line 253
# variable reference: usersComplete - line 254
# variable reference: groupsComplete - line 255
# variable reference: records - line 256
# END CODE MAP
# Jason Stys: authorized read-only LocalAccounts collector; SID-only output with explicit partial evidence.
Set-StrictMode -Version Latest

function ConvertTo-UtcStamp {
    <#
    .SYNOPSIS
    Convert optional native account dates to UTC; null stays unknown.
    .PARAMETER Value
    Native date or null. No inference of never-used or password state.
    #>
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return $null }
    return ([datetime]$Value).ToUniversalTime().ToString('o')
}

function Get-ObservedProperty {
    <#
    .SYNOPSIS
    Read a known property without inventing a value when an OS/provider omits it.
    .PARAMETER Item
    Native or synthetic principal.
    .PARAMETER Name
    Allowlisted caller-selected property name.
    #>
    param([Parameter(Mandatory)][object]$Item, [Parameter(Mandatory)][string]$Name)
    $property = $Item.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

function ConvertTo-IdentityRecord {
    <#
    .SYNOPSIS
    Normalize native/synthetic objects without names, descriptions, secrets or raw errors.
    .PARAMETER Item
    LocalAccounts principal with SID.
    .PARAMETER Kind
    user, group or unknown; external group expansion is deliberately not performed.
    #>
    param([Parameter(Mandatory)][object]$Item, [Parameter(Mandatory)][ValidateSet('user','group','unknown')][string]$Kind)
    $rawSid = Get-ObservedProperty -Item $Item -Name 'SID'
    if ($null -eq $rawSid) { throw 'Missing SID' }
    $principalSid = [System.Security.Principal.SecurityIdentifier]::new([string]$rawSid)
    $rawSource = [string](Get-ObservedProperty -Item $Item -Name 'PrincipalSource')
    $source = switch ($rawSource) {
        'Local' { 'local' }
        'ActiveDirectory' { 'ad' }
        'AzureAD' { 'entra' }
        'MicrosoftEntra' { 'entra' }
        'MicrosoftAccount' { 'microsoft' }
        default { 'unknown' }
    }
    $record = [ordered]@{
        sid = $principalSid.Value
        kind = $Kind
        source = $source
        enabled = $null
        password_required = $null
        last_logon = $null
        expires = $null
        members = @()
        members_complete = $false
    }
    if ($Kind -eq 'user') {
        # Only observed booleans become booleans. Missing/malformed fields remain null.
        $enabled = Get-ObservedProperty -Item $Item -Name 'Enabled'
        $required = Get-ObservedProperty -Item $Item -Name 'PasswordRequired'
        if ($enabled -is [bool]) { $record.enabled = $enabled }
        if ($required -is [bool]) { $record.password_required = $required }
        $record.last_logon = ConvertTo-UtcStamp -Value (Get-ObservedProperty -Item $Item -Name 'LastLogon')
        $record.expires = ConvertTo-UtcStamp -Value (Get-ObservedProperty -Item $Item -Name 'AccountExpires')
    }
    return [pscustomobject]$record
}

function Get-IdentitySnapshot {
    <#
    .SYNOPSIS
    Collect local user/group membership only, using injectable read hooks for deterministic tests.
    .PARAMETER HostAlias
    Nonpersonal alias supplied by the owner, not the computer's real name.
    .PARAMETER Captured
    UTC collection start; tests provide fixed times.
    .PARAMETER ReadUsers
    Authorized read hook; defaults to Get-LocalUser -ErrorAction Stop.
    .PARAMETER ReadGroups
    Authorized read hook; defaults to Get-LocalGroup -ErrorAction Stop.
    .PARAMETER ReadMembers
    Authorized read hook accepting a native group; no directory recursion or credentials.
    #>
    param(
        [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$')][string]$HostAlias,
        [datetimeoffset]$Captured = [datetimeoffset]::UtcNow,
        [scriptblock]$ReadUsers = { Get-LocalUser -ErrorAction Stop },
        [scriptblock]$ReadGroups = { Get-LocalGroup -ErrorAction Stop },
        [scriptblock]$ReadMembers = { param($Group) Get-LocalGroupMember -Group $Group -ErrorAction Stop }
    )
    $records = @{}
    $usersComplete = $true
    $groupsComplete = $true
    try {
        foreach ($user in @(& $ReadUsers)) {
            $record = ConvertTo-IdentityRecord -Item $user -Kind 'user'
            $records[$record.sid] = $record
        }
    } catch {
        # Permission/provider failures are unknown, not empty success; raw exception strings stay private.
        $usersComplete = $false
    }
    try {
        foreach ($group in @(& $ReadGroups)) {
            $record = ConvertTo-IdentityRecord -Item $group -Kind 'group'
            $records[$record.sid] = $record
            try {
                $memberSids = [System.Collections.Generic.HashSet[string]]::new()
                foreach ($member in @(& $ReadMembers $group)) {
                    $objectClass = [string](Get-ObservedProperty -Item $member -Name 'ObjectClass')
                    $kind = switch ($objectClass) { 'User' { 'user' } 'Group' { 'group' } default { 'unknown' } }
                    $child = ConvertTo-IdentityRecord -Item $member -Kind $kind
                    [void]$memberSids.Add($child.sid)
                    # Enumerated local records take precedence over sparse group-member objects.
                    if (-not $records.ContainsKey($child.sid)) { $records[$child.sid] = $child }
                }
                $record.members = @($memberSids | Sort-Object)
                $record.members_complete = $true
            } catch {
                $record.members_complete = $false
                $record.members = @()
            }
        }
    } catch { $groupsComplete = $false }
    return [ordered]@{
        schema = 1
        host = $HostAlias
        captured = $Captured.ToUniversalTime().ToString('o')
        users_complete = $usersComplete
        groups_complete = $groupsComplete
        principals = @($records.Values | Sort-Object -Property sid)
    }
}

Export-ModuleMember -Function ConvertTo-UtcStamp, Get-ObservedProperty, ConvertTo-IdentityRecord, Get-IdentitySnapshot
