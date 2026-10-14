# Code review and release checklist

Author: Jason Stys.

Review boundaries: account metadata never coerced to false on absence; external groups remain incomplete; approvals are exact-host/group/leaf scoped; cycle traversal is iterative; raw names/description/provider errors excluded; injected data parameterized/escaped; outputs never overwrite; runtime has no active network or enforcement imports.

Before publishing: inspect tracked files for private snapshots, credentials or outputs; validate exact README inventory and physical code maps; run style/types/unit/property/scenario/CLI checks; hash-verify native tooling; pass Windows synthetic/native checks and static analysis; audit dependency graph and workflow pins; review known limitations.

Release gate: both Validate and CodeQL must pass on final main. Preserve failed-run history if corrections occur. Public evidence identifies immutable accepted implementation and actual run/job IDs, with separate final documentation commit verification. Do not call local checks “GitHub Actions passed.”

Deployment scope: source portfolio and local tool, no hosted service, users or account enforcement. No migration, feature-flag rollout or privileged install. Rollback requires no host account changes; retain private evidence and stop tool use.

Storage: no artifact upload, setup caching, CodeQL trap/dependency caching or CodeQL database upload. Account billing details are never copied into public docs. Old runs/caches are not deleted without fresh permission.
