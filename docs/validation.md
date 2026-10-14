# Validation evidence

Author: Jason Stys.

Accepted implementation: [d473eaa08375d4211f8977ffdbf1777579eb6067](https://github.com/JasonStys/windows-identity-audit-lab/commit/d473eaa08375d4211f8977ffdbf1777579eb6067).

[Validate 38622550659](https://github.com/JasonStys/windows-identity-audit-lab/actions/runs/38622550659) passed all six jobs. [CodeQL 38622550750](https://github.com/JasonStys/windows-identity-audit-lab/actions/runs/38622550750) passed its Python job. Actual immutable run/job IDs and conclusions are in [ci.json](reports/ci.json).

- 95 Python tests passed, no skips, on Ubuntu 24.04/Python 3.12 and 3.14, Windows/Python 3.14 and macOS Intel/Python 3.14.
- 100% combined statement/branch coverage for all five runtime modules: 345 statements, 134 branches, none missed, on all four matrix entries.
- [24 exact synthetic scenario oracles](reports/evaluation.json) passed, including cycles, partial/unknown sources, expired approvals and broad-principal exposure.
- [Native Windows job](https://github.com/JasonStys/windows-identity-audit-lab/actions/runs/38622550659/job/116053456194) passed 29 assertions: 24 synthetic, one PSScriptAnalyzer gate and four native checks. PowerShell 7.6.6 / analyzer 1.25.0; zero analyzer Error/Warning diagnostics. Actual wrapper-produced runner snapshot passed Python schema validation with no private fields logged. See [powershell.json](reports/powershell.json).
- Full locked Python dependency graph: no known vulnerabilities. Gitleaks: no leaks. actionlint: passed. CodeQL: zero open alerts at verification.
- Actual Linux/Python 3.14.8 [benchmark](reports/benchmark.json): 1000 members, 999 findings, 15 samples, median 4.531822 ms and Python-only peak 221928 bytes. Not a whole-system memory or native-collection measurement.

Local Windows/Python 3.14.6 also passed 95 tests with the same 100% runtime coverage. Synthetic-only PowerShell + analyzer passed 25 assertions. No local PC account snapshot was collected.

[Synthetic HTML report](reports/example.html) generated from the committed public sample was visually inspected in a loopback browser. Three expected findings, zero scripts/media/iframes, restrictive CSP and no-referrer metadata confirmed. The temporary server/tab were closed after inspection. Public reports contain only synthetic SID data or aggregate native assertions.

Correction history: [initial Validate 38622279121](https://github.com/JasonStys/windows-identity-audit-lab/actions/runs/38622279121) failed only the native job's Python handoff import: that job lacked PYTHONPATH. The PowerShell native collector/29 assertions had already passed. Added the job's explicit repo path; no audit behavior or test gate was weakened. Failed history is retained.

Earlier local setup corrections: official analyzer expands to 299357415 bytes, above the initial 64 MiB cap; after inspecting its compatibility-profile content and verifying the official digest, the extraction cap became a bounded 384 MiB. A diff fixture had assumed insertion order despite sorted validated records; it now selects records by kind. ASCII PowerShell map separators avoid BOM compatibility warnings without suppressing analyzer rules.

Documentation commit is intentionally separate from the immutable implementation above; pushing it reruns all seven gates. This avoids a self-referential “this file proves its own commit” claim. Check the latest [main Actions](https://github.com/JasonStys/windows-identity-audit-lab/actions) for final documentation-commit status.

Limits: Python coverage is not PowerShell coverage; native tests are one disposable runner, not every Windows provider. No AD/Entra access connector, security-event correlation, effective access/ACL/token evaluation, automatic remediation, credential scanning or compliance certification. Read [security](security.md) before using real evidence.
