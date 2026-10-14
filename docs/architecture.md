# Architecture and ADR-001: local collection, offline review

Status: accepted. Author: Jason Stys.

Requirements: SID-centric Windows identity auditing, explainable bounded graph review, private evidence, deterministic validation, no privileged remediation, no network enumeration.

PowerShell is appropriate for native LocalAccounts metadata and .NET SID/parser APIs. Python is appropriate for portable typed contract validation, deterministic graph analysis and report generation. SQLite records evidence through parameterized statements. HTML is an inert, portable analyst view, not a service.

Flow: authorized local collector → private version-1 JSON → strict snapshot/policy parsing → bounded graph/account evaluation → fresh JSON/HTML/SQLite bundle. Snapshot comparison uses direct group edges and both sides' completeness. It never tries to infer authorization from observed membership.

Alternative: remote AD/Entra agent with token/ACL evaluation. Rejected for this lab: broader authority, credentials, directory access and platform-specific access semantics are not needed to demonstrate local assurance. The extensible input contract can represent externally supplied, separately authorized evidence; no external groups are expanded here.

The collector preserves null metadata and component/group failures. No names/descriptions are exported; SID privacy remains the owner's responsibility. Read hooks exist for tests, not untrusted plugin execution. Only trusted application code can supply hooks.

Collection spans time: start timestamp is not an atomic OS snapshot. Concurrent account changes can make evidence inconsistent. No directory lookup, native token/access check, user-right assignment, ACL evaluation or security-event ingestion is implemented.

No dependency injection framework, persistent daemon, database server or browser frontend is necessary. Shallow folders keep the lab inspectable.
