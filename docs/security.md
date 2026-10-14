# Privacy and threat model

Author: Jason Stys. Assets: account SIDs, group membership, approval policy, evidence integrity and local host security.

Trust boundaries: native provider to collector; untrusted JSON to strict parser; data to SQL/HTML; private output directory to operator. Uploaded/embedded instructions are never executed. The runtime imports no network or subprocess modules. No telemetry, credentials, directory scanning, account remediation, ads, popups or active HTML.

Mitigations: bounded reads/counts, exact keys/types, duplicate rejection, iterative graph algorithms, SID matching rather than localized names, explicit unknowns, input link rejection, fresh output directories/files, parameterized SQL, HTML escaping and restrictive CSP, pinned Actions/tools/dependencies, secrets scanning and separate static analyzers. SHA256 manifests detect changes only if the manifest is trusted; they are not signatures.

Privacy: collector omits names, descriptions, raw provider errors and passwords/hashes. SIDs still identify principals and reveal access relationships. Store all real inputs/policies/reports outside Git in an owner-protected directory. Ignore patterns are a backstop, not an authorization boundary. No filesystem permissions are changed by the collector.

Windows mode=0700 is not an ACL guarantee. The owner must set/review ACLs before collection. SQLite and JSON are not encrypted by this application; use OS full-disk encryption and approved protected storage. Same-user/admin malware, malicious parent-directory links, concurrent filesystem replacement and compromised OS/providers are outside these mitigations. This is not a hostile multiuser sandbox.

The collector is read-only but observations can be incomplete or inconsistent during concurrent account changes. A failed Get-LocalGroupMember leaves that group incomplete; it is not silently empty. Native errors are suppressed from exported data. No private account snapshots or policy approvals should enter public Actions logs. Native CI only prints aggregate assertions from disposable runners.

Do not execute untrusted PowerShell hooks, plugins or document macros. No permission bypass, automatic elevation, execution-policy weakening or automatic remediation is provided. Report vulnerabilities privately through the author's public contact; never attach live identity evidence to public issues.

Not a penetration-testing tool, certification/ATO assertion or substitute for approved administrative/security review.
