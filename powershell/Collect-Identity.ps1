# BEGIN CODE MAP (generated; python scripts/code_map.py)
# parameter: Authorized - line 37
# variable reference: Authorized - line 37
# parameter: HostAlias - line 38
# variable reference: HostAlias - line 38
# parameter: OutputPath - line 39
# variable reference: OutputPath - line 39
# variable reference: ErrorActionPreference - line 42
# variable reference: Authorized - line 43
# variable reference: PSScriptRoot - line 47
# variable reference: HostAlias - line 48
# variable reference: snapshot - line 48
# variable reference: snapshot - line 49
# variable reference: text - line 49
# variable reference: OutputPath - line 51
# variable reference: stream - line 51
# variable reference: bytes - line 53
# variable reference: false - line 53
# variable reference: text - line 53
# variable reference: bytes - line 54
# variable reference: stream - line 54
# variable reference: stream - line 55
# END CODE MAP
# Jason Stys: explicit owner-authorized local snapshot to a fresh private file; never uploaded by this script.
<#
.SYNOPSIS
Read local account/group metadata without any account, policy or privilege changes.
.PARAMETER Authorized
Explicit confirmation that the system owner permits this read-only collection.
.PARAMETER HostAlias
Opaque host alias; do not use a person's name.
.PARAMETER OutputPath
New file inside an owner-protected directory; existing files are never overwritten.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][switch]$Authorized,
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$')][string]$HostAlias,
    [Parameter(Mandatory)][string]$OutputPath
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not $Authorized) { throw 'Owner authorization is required.' }
if (-not [Environment]::Is64BitProcess -or [Environment]::OSVersion.Platform -ne 'Win32NT') {
    throw '64-bit Windows PowerShell is required.'
}
Import-Module (Join-Path $PSScriptRoot 'IdentitySnapshot.psm1') -Force
$snapshot = Get-IdentitySnapshot -HostAlias $HostAlias
$text = $snapshot | ConvertTo-Json -Depth 8
# CreateNew provides race-safe no-overwrite; output directory ACLs must already be private.
$stream = [IO.File]::Open($OutputPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
try {
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($text)
    $stream.Write($bytes, 0, $bytes.Length)
} finally { $stream.Dispose() }
Write-Output 'Private snapshot saved. Review component completeness; do not publish real SIDs.'
