# Windows Identity Audit Lab

## Native offline desktop workflow

The Windows portable app now provides actual project input/parameter controls, analysis, literal findings search, exact export and durable SQLite history, using the existing engines. Prepared fictional scenarios are inside this same full application. No live collection/enforcement or background upload runs. See the [native workbench guide](docs/native-workbench.md) for launch, workflow meanings, privacy and validation limits. Created by Jason Stys. Local candidate packaging does not establish a release or installation.

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

## Review nested membership and expiring exceptions

```powershell
python -m identitylab.cli recertify --before private/before.json --after private/after.json --policy private/policy.json --as-of 2026-10-15T00:00:00Z --horizon-hours 24 --output out/recertification
```

This read-only worklist preserves the original current audit and direct-edge drift, then compares deterministic shortest protected-group SID paths. A different nested path is distinguished from a newly added or removed exposure. Partial/unresolved/cyclic membership yields **not observed, unverified**, never proof of revoked access. Source snapshots must be for the same host with strictly increasing collection time; JSON-semantic hashes bind the reviewed inputs.

Current user memberships enter an explicit owner recertification queue even when already approved; disabled membership remains latent exposure. Active exceptions, unapproved memberships and expired/expiring tickets are separate, with a bounded1–168hour lookahead. Unassigned ownership is visible. Approval cannot suppress the original broad-principal warning, incomplete evidence or account-hygiene findings. No approval is renewed and no account changed. Output contains sensitive SIDs and must remain private. The command returns1 for review work,2 for invalid/operational errors, and writes a new inert HTML/JSON bundle for inspection.

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

## Native profile storage correction

Version 1.1.1 rejects pre-existing linked/nonregular fixed profile and SQLite
sidecar entries before initialization can write through an alias. Ordinary
recovery files and existing profile schemas remain supported; no data is reset.
See the [confirmed fixture, recovery tests and scope](docs/reports/profile-admission-2026-11-11.md).
Earlier native releases and documentation retain their own dated evidence.

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
| [docs/handbook.md](docs/handbook.md) | Windows Identity Audit Lab handbook. |
| [docs/licenses/tcl-9.0.4.txt](docs/licenses/tcl-9.0.4.txt) | Actual Tcl9.0.4 runtime notice read from the verified bundled SDK zipfs. |
| [docs/licenses/tk-9.0.4.txt](docs/licenses/tk-9.0.4.txt) | Actual Tk9.0.4 runtime notice read from the verified bundled SDK zipfs. |
| [docs/native-workbench.md](docs/native-workbench.md) | Native offline workbench. |
| [docs/performance.md](docs/performance.md) | Performance and complexity. |
| [docs/reports/benchmark.json](docs/reports/benchmark.json) | Measured bounded graph audit latency and Python allocation peak. |
| [docs/reports/ci.json](docs/reports/ci.json) | Actual immutable accepted-source CI snapshot. |
| [docs/reports/documentation-refresh-2026-11-09.md](docs/reports/documentation-refresh-2026-11-09.md) | Documentation refresh — 2026-11-09. |
| [docs/reports/evaluation.json](docs/reports/evaluation.json) | Measured fixed synthetic scenario outcomes. |
| [docs/reports/example.html](docs/reports/example.html) | Inert synthetic analyst report. |
| [docs/reports/native-workbench-2026-11-10.md](docs/reports/native-workbench-2026-11-10.md) | Native Windows identity workbench validation. |
| [docs/reports/office-input-boundary-2026-11-10.md](docs/reports/office-input-boundary-2026-11-10.md) | Documentation input boundary review — 2026-11-10. |
| [docs/reports/portfolio-sync-2026-10-22.md](docs/reports/portfolio-sync-2026-10-22.md) | <!-- File: docs/reports/portfolio-sync-2026-10-22.md; Purpose: certificate-bundle security repair and evidence by Jason Stys. -->. |
| [docs/reports/powershell.json](docs/reports/powershell.json) | Actual synthetic and disposable-runner Windows validation. |
| [docs/reports/profile-admission-2026-11-11.md](docs/reports/profile-admission-2026-11-11.md) | Fixed profile entry admission — November 11, 2026. |
| [docs/reports/project-guide.docx](docs/reports/project-guide.docx) | Reviewed Word project guide with source revision and dated validation scope. |
| [docs/reports/publications.json](docs/reports/publications.json) | Exact reviewed Office file identities, immutable source baseline and workflow observations. |
| [docs/reports/recertification-2026-11-09.md](docs/reports/recertification-2026-11-09.md) | Nested membership recertification validation — November 9, 2026. |
| [docs/research.md](docs/research.md) | Primary-source research notes. |
| [docs/review.md](docs/review.md) | Code review and release checklist. |
| [docs/runbook.md](docs/runbook.md) | Operator runbook and troubleshooting. |
| [docs/security.md](docs/security.md) | Privacy and threat model. |
| [docs/testing.md](docs/testing.md) | Test strategy. |
| [docs/validation.md](docs/validation.md) | Validation evidence. |
| [examples/desktop/after.json](examples/desktop/after.json) | Fictional changed snapshot with nested and newly observed direct membership edges. |
| [examples/desktop/before.json](examples/desktop/before.json) | Fictional earlier closed snapshot with one protected direct membership. |
| [examples/desktop/partial.json](examples/desktop/partial.json) | Fictional explicitly incomplete group evidence; absence does not prove revocation. |
| [examples/desktop/policy.json](examples/desktop/policy.json) | Fictional protected-group/approval policy used by actual desktop and CLI engines. |
| [examples/policy.json](examples/policy.json) | Synthetic protected-group policy and explicitly scoped approval. |
| [examples/scenarios.py](examples/scenarios.py) | Jason Stys: deterministic SID-only synthetic scenario fixtures and independent expected rule sets. |
| [examples/snapshot.json](examples/snapshot.json) | Synthetic Windows identity evidence; no real host/account information. |
| [identitylab/\_\_init\_\_.py](identitylab/__init__.py) | Jason Stys: offline Windows identity evidence analysis; no credentials, network or enforcement. |
| [identitylab/audit.py](identitylab/audit.py) | Jason Stys: explainable bounded membership exposure and account hygiene, never Windows access authorization. |
| [identitylab/cli.py](identitylab/cli.py) | Jason Stys: offline audit/diff command line with content-free diagnostics and explicit reference time. |
| [identitylab/contracts.py](identitylab/contracts.py) | Jason Stys: strict bounded SID-centric snapshot and policy contracts, with explicit unknown evidence. |
| [identitylab/desktop.py](identitylab/desktop.py) | Native offline workbench: real project inputs, analysis, searchable evidence, history and export. Jason Stys. |
| [identitylab/desktop\_io.py](identitylab/desktop_io.py) | Bounded regular descriptor reads and strict finite JSON for owner-local desktop state. Jason Stys. |
| [identitylab/desktop\_project.py](identitylab/desktop_project.py) | Actual offline SID audit, direct drift and recertification controls; no account enumeration or enforcement. Jason Stys. |
| [identitylab/desktop\_state.py](identitylab/desktop_state.py) | Owner-local desktop profile, bounded durable bundles and non-overwriting export. Jason Stys. |
| [identitylab/evidence.py](identitylab/evidence.py) | Jason Stys: fresh private review bundles, parameterized SQLite evidence and inert escaped HTML. |
| [identitylab/recertify.py](identitylab/recertify.py) | Jason Stys: conservative nested protected-membership drift and exception recertification worklist. |
| [powershell/Collect-Identity.ps1](powershell/Collect-Identity.ps1) | Jason Stys: explicit owner-authorized local snapshot to a fresh private file; never uploaded by this script. |
| [powershell/Get-CodeSymbols.ps1](powershell/Get-CodeSymbols.ps1) | Jason Stys: parse-only PowerShell AST symbol map; never executes source supplied on stdin. |
| [powershell/IdentitySnapshot.psm1](powershell/IdentitySnapshot.psm1) | Jason Stys: authorized read-only LocalAccounts collector; SID-only output with explicit partial evidence. |
| [powershell/Test-Identity.ps1](powershell/Test-Identity.ps1) | Jason Stys: synthetic collector contracts plus optional disposable-runner native checks; no PC collection by default. |
| [pyproject.toml](pyproject.toml) | Jason Stys: zero-dependency offline runtime, strict types and combined statement/branch coverage. |
| [requirements-dev.in](requirements-dev.in) | Jason Stys: hash-locked tests, properties, typing, formatting and independent dependency/security tooling. |
| [requirements-dev.lock](requirements-dev.lock) | Universal complete hash-locked test and security-tool graph. |
| [requirements-native.lock](requirements-native.lock) | Exact hash-locked Windows portable build graph; no runtime downloads on user launch. |
| [scripts/benchmark.py](scripts/benchmark.py) | Jason Stys: deterministic synthetic graph-audit benchmark; latency is diagnostic, never a flaky CI gate. |
| [scripts/build\_native.py](scripts/build_native.py) | Build the complete real offline workbench as one Windows portable executable. Jason Stys. |
| [scripts/code\_map.py](scripts/code_map.py) | Jason Stys: exact Python/PowerShell AST symbol maps and lexical SQL/workflow physical line indexes. |
| [scripts/evaluate.py](scripts/evaluate.py) | Jason Stys: independent exact synthetic scenario oracle evaluation; JSON results contain no real identities. |
| [scripts/file\_guide.py](scripts/file_guide.py) | Jason Stys: exact tracked-file README purpose inventory, unknown files fail rather than receive guesses. |
| [scripts/native\_acceptance.py](scripts/native_acceptance.py) | Real frozen widget/core/history/export/unknown-state acceptance on explicit synthetic profiles. Jason Stys. |
| [scripts/native\_contract.py](scripts/native_contract.py) | Jason Stys: consume ephemeral runner-only collector output; print schema assertions, never real SIDs or values. |
| [scripts/native\_entry.py](scripts/native_entry.py) | Launch the actual bundled offline project workbench; no setup shell commands. Jason Stys. |
| [scripts/preview.py](scripts/preview.py) | Jason Stys: temporary loopback-only inert synthetic HTML preview, not a hosted identity service. |
| [scripts/pssa.py](scripts/pssa.py) | Jason Stys: download the official digest-pinned PSScriptAnalyzer package into repo-local ignored tooling. |
| [scripts/scanners.py](scripts/scanners.py) | Install only hash-pinned official Linux scanner binaries. Created by Jason Stys. |
| [scripts/test\_native\_app.py](scripts/test_native_app.py) | Run the real frozen workbench twice with an owned synthetic profile and exact bundle persistence. Jason Stys. |
| [scripts/validate\_repo.py](scripts/validate_repo.py) | Jason Stys: tracked-file privacy, offline-runtime imports and zero-artifact/cache workflow guards. |
| [sql/evidence.sql](sql/evidence.sql) | Jason Stys: bounded review metadata and SID findings, not credential material or personal names. |
| [tests/test\_audit.py](tests/test_audit.py) | Jason Stys: independent exact scenario oracles, graph safety, approval boundaries and conservative snapshot diffs. |
| [tests/test\_contracts.py](tests/test_contracts.py) | Jason Stys: adversarial schema/SID/time/JSON boundaries and property-based canonical identifier checks. |
| [tests/test\_desktop\_gui.py](tests/test_desktop_gui.py) | Presentation-adapter unit tests with real core/SQLite workers; real widgets are separately frozen-tested. Jason Stys. |
| [tests/test\_desktop\_project.py](tests/test_desktop_project.py) | Independent SID-path, incomplete-evidence and no-enforcement native-adapter oracles. Jason Stys. |
| [tests/test\_desktop\_state.py](tests/test_desktop_state.py) | Independent offline desktop ownership, byte-bound, SQLite and non-overwrite regressions. Jason Stys. |
| [tests/test\_evidence.py](tests/test_evidence.py) | Jason Stys: private no-overwrite bundles, SQL injection safety, escaped HTML and actual CLI round trips. |
| [tests/test\_profile\_admission.py](tests/test_profile_admission.py) | Actual pre-existing alias refusal and ordinary SQLite recovery continuity. Jason Stys. |
| [tests/test\_publication\_privacy.py](tests/test_publication_privacy.py) | Jason Stys: credentials in actual Word XML remain visible to repository privacy checks. |
| [tests/test\_reader\_races.py](tests/test_reader_races.py) | Actual opened-device and POSIX regular-to-FIFO replacement regressions for bounded readers. Jason Stys. |
| [tests/test\_recertify.py](tests/test_recertify.py) | Jason Stys: independent nested exposure, partial-evidence and expiry worklist oracles. |
| [tools.lock.json](tools.lock.json) | Official Linux scanner versions, URLs and SHA256 digests. |

<!-- END FILE GUIDE -->

## Documentation editions

Start with the [organized handbook](docs/handbook.md) for current usage, design, security and test guidance. Reviewed downloadable editions: [project-guide.docx](docs/reports/project-guide.docx).

[Publication identities and source scope](docs/reports/publications.json) · [Documentation validation record](docs/reports/documentation-refresh-2026-11-09.md). Historical results retain their own tested revision and date.
