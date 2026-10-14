# Windows Identity Audit Lab

Created by [Jason Stys](https://github.com/JasonStys) · [Professional contact](https://www.linkedin.com/in/jason-stys-31b30b351/).

A defensive, read-only Windows identity assurance lab: PowerShell collects local account/group metadata; typed Python reviews SID-based membership exposure; SQL and inert HTML preserve explainable evidence. It does **not** change accounts, prove effective access, scan remote systems, export credentials, or claim compliance certification.

## Features

- Language-independent SID matching for protected groups such as built-in Administrators.
- Bounded nested-membership paths, cycle detection and explicit unknowns for external/unresolved groups.
- Host-scoped explicit approvals and ticketed, expiring exceptions; broad-principal warnings cannot be suppressed by approval.
- Local enabled-account hygiene with null-preserving history; never equate unavailable last-logon with “never used.”
- Conservative snapshot drift: distinguish confirmed direct changes from newly/not-observed partial evidence.
- Private fresh JSON/HTML/SQLite bundles and SHA256 manifests, with no-overwrite behavior.
- Synthetic scenarios, adversarial/property tests, multi-OS Python CI, independent Windows SID/native collection checks and PowerShell static analysis.

## Try safely, without collecting your accounts

Python 3.12+; runtime has no external Python dependencies. PowerShell 7.2+ is needed only for tooling/native Windows collection. Use a 64-bit Windows process for LocalAccounts.

```powershell
New-Item -ItemType Directory -Force out
python -m identitylab.cli audit --snapshot examples/snapshot.json --policy examples/policy.json --as-of 2026-10-14T00:00:00Z --output out/example-01
```

The synthetic example deliberately returns **1** (three review findings), not a software failure. Open `out/example-01/review.html` locally. Exit 0 means complete with no findings in the configured scope; 1 means review findings/incomplete evidence; 2 means invalid inputs or operational failure.

For tests: `python -m pip install --require-hashes -r requirements-dev.lock`, then `python -m pytest --cov=identitylab`. On Windows, `pwsh -NoProfile -File powershell/Test-Identity.ps1` runs synthetic collector tests without native account enumeration.

## Authorized collection

Read the [privacy and threat model](docs/security.md) and [runbook](docs/runbook.md) first. Use an owner-protected directory outside Git; provide a nonpersonal host alias. SIDs remain sensitive. Do not upload real snapshots or generated bundles. The collector never uploads files and never contacts a directory service.

```powershell
./powershell/Collect-Identity.ps1 -Authorized -HostAlias WORKSTATION-01 -OutputPath 'C:\private-audit\snapshot-01.json'
```

Customize [examples/policy.json](examples/policy.json) **privately** for that exact host and explicit user SID approvals. Null/partial data requires review, not enforcement. External group membership requires separately authorized evidence from another source; this collector does not recurse into AD/Entra. JSON inputs are data, never executed.

## Documentation and validation

[Architecture](docs/architecture.md) · [contracts/rules](docs/contracts.md) · [security](docs/security.md) · [runbook](docs/runbook.md) · [tests](docs/testing.md) · [performance](docs/performance.md) · [coding conventions](docs/coding.md) · [research](docs/research.md) · [review/release checklist](docs/review.md) · [validation evidence](docs/validation.md).

Actions deliberately upload no artifacts, create no caches, and print only synthetic evidence or native assertion summaries. PowerShell coverage is described separately from Python coverage; CodeQL covers Python, not PowerShell.

Accepted implementation validation: **95 tests / 100% Python statement-and-branch coverage** on all four OS/Python entries, **24 exact scenario oracles**, **29 Windows native/synthetic/static assertions**, and all seven CI jobs passed. See the immutable [validation report](docs/validation.md) and latest [Actions](https://github.com/JasonStys/windows-identity-audit-lab/actions). Risk-based testing and privacy documentation shaped the implementation, especially unknown evidence and approval boundaries.

## Every tracked file

<!-- BEGIN FILE GUIDE -->

| File | Purpose |
| --- | --- |
| [.gitattributes](.gitattributes) | Consistent LF text checkouts across operating systems. |
| [.github/workflows/ci.yml](.github/workflows/ci.yml) | Jason Stys: cross-platform offline evidence, disposable Windows collector tests and zero artifact/cache uploads. |
| [.github/workflows/codeql.yml](.github/workflows/codeql.yml) | Jason Stys: security-extended Python analysis; explicitly disable trap/dependency caches and database uploads. |
| [.gitignore](.gitignore) | Exclude private identity snapshots, databases, outputs and tool caches. |
| [LICENSE](LICENSE) | MIT license for Jason Stys's authored code. |
| [README.md](README.md) | Windows Identity Audit Lab. |
| [docs/architecture.md](docs/architecture.md) | Architecture and ADR-001: local collection, offline review. |
| [docs/coding.md](docs/coding.md) | Coding and documentation conventions. |
| [docs/contracts.md](docs/contracts.md) | Contracts and rule semantics. |
| [docs/performance.md](docs/performance.md) | Performance and complexity. |
| [docs/reports/benchmark.json](docs/reports/benchmark.json) | Measured bounded graph audit latency and Python allocation peak. |
| [docs/reports/ci.json](docs/reports/ci.json) | Actual immutable accepted-source CI snapshot. |
| [docs/reports/evaluation.json](docs/reports/evaluation.json) | Measured fixed synthetic scenario outcomes. |
| [docs/reports/example.html](docs/reports/example.html) | Inert synthetic analyst report. |
| [docs/reports/powershell.json](docs/reports/powershell.json) | Actual synthetic and disposable-runner Windows validation. |
| [docs/research.md](docs/research.md) | Primary-source research notes. |
| [docs/review.md](docs/review.md) | Code review and release checklist. |
| [docs/runbook.md](docs/runbook.md) | Operator runbook and troubleshooting. |
| [docs/security.md](docs/security.md) | Privacy and threat model. |
| [docs/testing.md](docs/testing.md) | Test strategy. |
| [docs/validation.md](docs/validation.md) | Validation evidence. |
| [examples/policy.json](examples/policy.json) | Synthetic protected-group policy and explicitly scoped approval. |
| [examples/scenarios.py](examples/scenarios.py) | Jason Stys: deterministic SID-only synthetic scenario fixtures and independent expected rule sets. |
| [examples/snapshot.json](examples/snapshot.json) | Synthetic Windows identity evidence; no real host/account information. |
| [identitylab/\_\_init\_\_.py](identitylab/__init__.py) | Jason Stys: offline Windows identity evidence analysis; no credentials, network or enforcement. |
| [identitylab/audit.py](identitylab/audit.py) | Jason Stys: explainable bounded membership exposure and account hygiene, never Windows access authorization. |
| [identitylab/cli.py](identitylab/cli.py) | Jason Stys: offline audit/diff command line with content-free diagnostics and explicit reference time. |
| [identitylab/contracts.py](identitylab/contracts.py) | Jason Stys: strict bounded SID-centric snapshot and policy contracts, with explicit unknown evidence. |
| [identitylab/evidence.py](identitylab/evidence.py) | Jason Stys: fresh private review bundles, parameterized SQLite evidence and inert escaped HTML. |
| [powershell/Collect-Identity.ps1](powershell/Collect-Identity.ps1) | Jason Stys: explicit owner-authorized local snapshot to a fresh private file; never uploaded by this script. |
| [powershell/Get-CodeSymbols.ps1](powershell/Get-CodeSymbols.ps1) | Jason Stys: parse-only PowerShell AST symbol map; never executes source supplied on stdin. |
| [powershell/IdentitySnapshot.psm1](powershell/IdentitySnapshot.psm1) | Jason Stys: authorized read-only LocalAccounts collector; SID-only output with explicit partial evidence. |
| [powershell/Test-Identity.ps1](powershell/Test-Identity.ps1) | Jason Stys: synthetic collector contracts plus optional disposable-runner native checks; no PC collection by default. |
| [pyproject.toml](pyproject.toml) | Jason Stys: zero-dependency offline runtime, strict types and combined statement/branch coverage. |
| [requirements-dev.in](requirements-dev.in) | Jason Stys: hash-locked tests, properties, typing, formatting and independent dependency/security tooling. |
| [requirements-dev.lock](requirements-dev.lock) | Universal complete hash-locked test and security-tool graph. |
| [scripts/benchmark.py](scripts/benchmark.py) | Jason Stys: deterministic synthetic graph-audit benchmark; latency is diagnostic, never a flaky CI gate. |
| [scripts/code\_map.py](scripts/code_map.py) | Jason Stys: exact Python/PowerShell AST symbol maps and lexical SQL/workflow physical line indexes. |
| [scripts/evaluate.py](scripts/evaluate.py) | Jason Stys: independent exact synthetic scenario oracle evaluation; JSON results contain no real identities. |
| [scripts/file\_guide.py](scripts/file_guide.py) | Jason Stys: exact tracked-file README purpose inventory, unknown files fail rather than receive guesses. |
| [scripts/native\_contract.py](scripts/native_contract.py) | Jason Stys: consume ephemeral runner-only collector output; print schema assertions, never real SIDs or values. |
| [scripts/preview.py](scripts/preview.py) | Jason Stys: temporary loopback-only inert synthetic HTML preview, not a hosted identity service. |
| [scripts/pssa.py](scripts/pssa.py) | Jason Stys: download the official digest-pinned PSScriptAnalyzer package into repo-local ignored tooling. |
| [scripts/scanners.py](scripts/scanners.py) | Install only hash-pinned official Linux scanner binaries. Created by Jason Stys. |
| [scripts/validate\_repo.py](scripts/validate_repo.py) | Jason Stys: tracked-file privacy, offline-runtime imports and zero-artifact/cache workflow guards. |
| [sql/evidence.sql](sql/evidence.sql) | Jason Stys: bounded review metadata and SID findings, not credential material or personal names. |
| [tests/test\_audit.py](tests/test_audit.py) | Jason Stys: independent exact scenario oracles, graph safety, approval boundaries and conservative snapshot diffs. |
| [tests/test\_contracts.py](tests/test_contracts.py) | Jason Stys: adversarial schema/SID/time/JSON boundaries and property-based canonical identifier checks. |
| [tests/test\_evidence.py](tests/test_evidence.py) | Jason Stys: private no-overwrite bundles, SQL injection safety, escaped HTML and actual CLI round trips. |
| [tools.lock.json](tools.lock.json) | Official Linux scanner versions, URLs and SHA256 digests. |

<!-- END FILE GUIDE -->
