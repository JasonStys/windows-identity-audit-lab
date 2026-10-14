# Contracts and rule semantics

Author: Jason Stys. See examples for exact field names; missing and additional JSON fields are rejected.

Snapshot schema 1: opaque host alias, timezone-bearing captured timestamp, users_complete/groups_complete booleans, unique principal records. Each principal has canonical SID, kind (user/group/unknown), source (local/ad/entra/microsoft/unknown), nullable enabled/password_required/last_logon/expires, unique members and members_complete. Non-users cannot contain account metadata; only groups contain members. Future last-logon is invalid.

Limits: 4 MiB JSON read, 2000 principals, 10000 aggregate edges, 8 protected groups, 64-character host/ticket aliases, bounded positive policy thresholds. Decimal SID subset: revision 1, 48-bit authority, 1–15 uint32 subauthorities, no leading zeros, abbreviations, hex authority, names or case normalization. This is intentionally narrower than all representations accepted by native Windows APIs.

Policy: same host alias, nonempty unique protected SIDs, unique (group,principal) explicit approvals, unique scoped ticketed exceptions with expiry, stale_days 1–3650 and max_age_hours 1–8760. Approval for a nested group **does not approve its users**. Active means expiry strictly later than reference time. Duplicate keys, NaN/Infinity and unknown fields fail.

Rules: collection-incomplete, snapshot-stale, protected-group-missing, membership-unknown, membership-cycle, unresolved-principal, unapproved-membership, broad-membership, exception-expired, account-source-unknown, account-state-unknown, account-history-unknown, password-not-required, inactive-account, expired-enabled-account.

Broad principals: Everyone, Authenticated Users, built-in Users and Guests by well-known SID. Approval cannot suppress their warning. Unapproved disabled users are review priority because membership remains latent; enabled or unknown-state users are high review priority. These are configurable-scope review heuristics, not an exploit or compliance verdict.

Hygiene is limited to local users not known disabled. PasswordRequired=false does not prove a blank password. Null history is unknown, not never used. Inactivity threshold uses collection time, inclusive at threshold; account expiry is inclusive at collection time. An expired enabled account does not prove successful sign-in.

Complete=true means the configured protected graph and relevant local account fields were observed and fresh. It says nothing about access tokens, ACLs, MFA, password strength, directory hygiene, logon rights or whole-host security. Finding priorities are manual triage suggestions.

Diff confirms removal only if the after group exists, has complete member evidence and top-level groups_complete=true. Missing groups are not deletion proof. Addition needs complete before evidence; otherwise it is newly-observed. Strictly increasing same-host timestamps required. No identity attribute/lifecycle diff or transitive-access drift claim is made.
