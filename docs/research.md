# Primary-source research notes

Author: Jason Stys. Reviewed 2026-10-14; these are design references, not a compliance assertion.

- [Microsoft SID components](https://learn.microsoft.com/en-us/windows/win32/secauthz/sid-components): revision, 48-bit authority and subauthorities. The lab intentionally accepts a canonical decimal subset; native .NET SID parsing supplies an independent Windows check.
- [Microsoft security identifiers](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers): stable built-in Administrators SID and broad well-known principals. SID matching avoids localization/renaming mistakes.
- [Get-LocalGroupMember](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.localaccounts/get-localgroupmember): native member objects, SID-based APIs, source limitations and 32-bit caveat. This collector does not expand directories; incomplete reads stay unknown.
- [SID attributes in access tokens](https://learn.microsoft.com/en-us/windows/win32/secauthz/sid-attributes-in-an-access-token): enabled and deny-only token semantics. This directly motivates naming results “membership exposure,” not “effective permissions.”
- [PSScriptAnalyzer overview](https://learn.microsoft.com/en-us/powershell/utility-modules/psscriptanalyzer/overview): native static checks complement Python tools.
- [Official PSScriptAnalyzer 1.25.0 release](https://github.com/PowerShell/PSScriptAnalyzer/releases/tag/1.25.0): package SHA256 14e634c828eb98efb9f40b2918ba90f139ed5eccdf663a2a747736d996995d60, verified before repo-local extraction.

Inference from these sources: membership snapshots alone cannot establish access or maliciousness. Scope, freshness, unresolved identities and approval provenance need explicit human interpretation. Inactivity/priority thresholds are configurable lab heuristics, not Microsoft-required policy.
