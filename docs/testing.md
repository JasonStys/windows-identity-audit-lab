# Test strategy

Author: Jason Stys. Risk-first targets: false clean verdicts, localization/SID ambiguity, unbounded/cyclic evidence, approval scope, privacy leaks and unsafe output.

Python: exact synthetic scenario rule sets and completeness; strict schema/type/size/time/SID boundaries; Hypothesis SID and ordering properties; 1500-group iterative chain; cycle/diamond behavior; conservative diff; actual CLI/module execution; no-overwrite JSON/SQLite/HTML bundle; SQL-injection-looking data and escaped markup. Combined statement/branch coverage gate 95%, with missing lines reported.

PowerShell: default synthetic mocked read hooks, duplicate members, source normalization, rich local metadata precedence, null/malformed fields, localized names excluded, denied components and membership, invalid native SID, UTC date normalization. These are deterministic assertions, not Pester tests or a measured PowerShell coverage percentage.

Independent Windows job: .NET well-known SID agreement, authorized read-only LocalAccounts enumeration on a disposable runner, actual collector wrapper to ignored temporary JSON, strict Python contract validation without printing any account SIDs. PSScriptAnalyzer 1.25.0 checks all authored PS files at Error/Warning severity. No accounts/groups are created/changed/deleted.

Matrix: Ubuntu 24.04 Python 3.12/3.14, Windows Python 3.14, macOS Intel Python 3.14. CodeQL security-extended Python, full Python dependency audit, hash-verified Gitleaks and actionlint. PowerShell uses PSScriptAnalyzer, not CodeQL.

Limitations: no AD/Entra connector, access-token/ACL rights, event-log correlation, domain controller integration, credential auditing, adversarial OS or complete real-world security proof. Native CI cannot guarantee every Windows version/provider works. Assertions and coverage are reported separately. Benchmarks are descriptive, not hardware-dependent pass gates.
