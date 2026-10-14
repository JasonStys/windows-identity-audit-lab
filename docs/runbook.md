# Operator runbook and troubleshooting

Author: Jason Stys.

1. Obtain system-owner permission and define local host/protected-SID scope. Run the synthetic example first.
2. Choose a nonpersonal host alias; prepare a private directory with approved Windows ACLs outside Git.
3. Use 64-bit Windows PowerShell 7.2+ with LocalAccounts available. Do not automatically elevate or alter execution policy when blocked.
4. Invoke Collect-Identity.ps1 with -Authorized, alias and a **new** output filename. It reads local metadata only.
5. Review users_complete, groups_complete and group members_complete. Denied/unsupported enumeration is unknown; do not approve absence.
6. Create an exact-host private policy. Approve leaf user SIDs individually, not whole nested groups; ticket exceptions with explicit expiry.
7. Run python -m identitylab.cli audit with explicit UTC --as-of and a fresh --output directory whose parent already exists.
8. Review unknowns first, then evidence paths and account context. Verify live facts with an approved administrator before any external change process.
9. Keep bundles private; verify manifest digests using an approved SHA256 utility. Recollect after approved changes; use diff on strictly increasing same-host snapshots.

Status 1 is expected for review findings, not a crash. Status 2 prints only failure class; inspect schema/clock privately. Existing output: choose a new directory, never delete evidence automatically. Unsupported source fields are unknown. Null LastLogon is not “never logged in.” Use service-use context when investigating inactivity.

Troubleshooting: LocalAccounts unavailable → verify 64-bit Windows and supported OS/module. Enumeration denied → consult the owner; do not bypass protections. Membership incomplete → Get-LocalGroupMember/provider failed or an external group was not expanded. Invalid JSON → check exact keys, types, SID subset, duplicates, limits, future times. Reference mismatch → use matching host policy and clock not earlier than collection.

Synthetic development: install hash-locked dev dependencies in a venv, run ruff/mypy/pytest, code-map/file-guide checks, evaluate and benchmark. PSScriptAnalyzer is downloaded into ignored .tools with a verified official hash; never installed globally by this project. Test-Identity.ps1 defaults to synthetic-only. Its -Native mode is restricted to Windows GitHub runners.

No daemon/service is installed. Rollback: stop using the tool; there are no account/settings changes to reverse. Preserve private evidence according to owner retention policy. Generated partial bundles from a write failure must be labeled incomplete, not used as successful evidence.
