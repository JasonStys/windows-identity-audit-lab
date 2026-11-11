# Native offline workbench

Created by Jason Stys · [Source and contact](https://github.com/JasonStys).

## Start and select your inputs

The Windows portable application bundles Python 3.14.10, Tcl/Tk 9.0.4, the graphical interface and the actual project engines. Launch the single EXE; no Python/Node setup, terminal command, account or baked password is needed. This is a portable application, not an NSIS installer, signed executable or cross-platform binary. Packaging and source checks do not establish an independent security certification.

Choose an operation in **Inputs and analysis**, browse authorized local files/folders, set the explicit UTC clock and relevant parameters, acknowledge permission, then **Run analysis**. Only fields relevant to that operation are shown. Prepared fictional scenarios fill these same ordinary controls; they do not run automatically or replace the application with a separate demo. Changing a field resets permission acknowledgement. Your own supported inputs and policies can replace the prepared paths.

## Review, filter, export and return

The **Findings and timeline** tab preserves the original project findings. Choose a view, search literal record values and select a row to read its full structured evidence. The table shows at most 5000 rows; exact full retained files remain exportable. A finding or unknown state is a successful analysis result requiring human review, not a clean/security approval. An invalid input is rejected without replacing the previous saved result.

Use **Export selected analysis bundle** to create a new destination containing the exact retained files. Existing destinations are not overwritten. **Saved analyses** reopens earlier immutable bundles; restart uses the same durable profile. Delete is explicit and confirms the exact selected manifest. No automatic eviction or forensic-erasure claim is made. Help, runtime license notices and **Exit application** remain available at the minimum 980×700 window size. Exit waits for the one owned worker and closes its SQLite connection; it does not kill other applications.

## Local data and limits

The default version-independent profile is under `%LOCALAPPDATA%/JasonStys/WindowsIdentityAuditLab`; the source CLI keeps its existing explicit output/path arguments. Profile markers refuse unknown nonempty or linked paths rather than resetting them. A process lock, SQLite foreign keys/FULL synchronization/integrity checks and verified original-byte manifests protect application consistency. They do not provide authentication against another process running as the same OS user, encryption, collector authenticity or protection from an administrator. Keep the whole profile private and back it up only after clean exit. Plaintext history and exports may contain supplied evidence.

Retention is bounded to 20 analyses and 128 MiB of payload, with up to 8 files / 64 MiB per analysis and 32 MiB per file. Oversized inputs, malformed JSON, special files and unsafe links are rejected. There is no HTTP listener, live collector, account change, network lookup, user command/plugin or background upload in this native workflow. Original command-line capabilities remain available separately.

## SID evidence and incomplete collection

Audit an authorized offline snapshot against the selected protected-group/approval policy and explicit UTC clock. Compare two snapshots for observed **direct** edges, or create a recertification queue for nested representative paths with a 1–168 hour horizon. The full original current findings stay available even when an owner queue is empty. A missing edge in incomplete collection is NOT_OBSERVED_UNVERIFIED, never proof of revocation; changed representative paths and newly observed principals stay distinct.

These findings concern supplied SID membership/collection evidence, not effective access, complete Windows authorization semantics or an actual account approval. The native GUI never launches PowerShell or a collector and never changes accounts, groups or policies. Existing PowerShell synthetic/disposable-runner contracts remain separately tested in their original lane; do not run collection against a real host without explicit authorization.

## Build and validation

Developers install `requirements-dev.lock` and `requirements-native.lock` with `--require-hashes`, then run `python scripts/build_native.py` and `python scripts/test_native_app.py` on Windows using Python 3.14.10. The builder checks runtime DLL identity, collects actual Python/Tcl/Tk and applicable dependency notices, and records source revision/resource hashes. The native consumer launches the actual frozen application twice with a fresh marked synthetic profile and a restricted environment; it drives the same widgets, worker, SQLite engine, core analyzers and exports, checks independent domain oracles and normal owned PID exit. Source-controller tests use inert presentation adapters and are distinct from this real-widget/frozen proof.

The original four OS/Python quality lanes, security gates and project-specific interoperability/collector contracts remain. The added Windows native lane audits its complete hash-locked build graph, builds and exercises the actual EXE. It uploads no package, test profile or Actions cache. Hosted jobs and a clean committed build must be reviewed before release; a local dirty candidate is not a published/installed product.
