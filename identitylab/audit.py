"""Jason Stys: explainable bounded membership exposure and account hygiene, never Windows access authorization."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: BROAD — line 102
# definition: Finding — line 106
# variable: rule — line 109
# variable: severity — line 110
# variable: subject — line 111
# variable: path — line 112
# variable: detail — line 113
# variable: action — line 114
# definition: Result — line 118
# variable: host — line 121
# variable: captured — line 122
# variable: as_of — line 123
# variable: complete — line 124
# variable: findings — line 125
# definition: to_dict — line 127
# parameter: self — line 127
# definition: reachable — line 137
# parameter: group — line 138
# parameter: records — line 138
# variable: paths — line 141
# variable: queue — line 142
# variable: complete — line 143
# variable: current — line 145
# variable: record — line 146
# variable: complete — line 148
# variable: complete — line 151
# variable: member — line 152
# definition: cyclic — line 159
# parameter: paths — line 159
# parameter: records — line 159
# variable: groups — line 161
# variable: key — line 161
# variable: degree — line 162
# variable: group — line 163
# variable: member — line 164
# variable: key — line 167
# variable: queue — line 167
# variable: visited — line 168
# variable: group — line 170
# variable: visited — line 171
# variable: member — line 172
# definition: audit — line 180
# parameter: as_of — line 180
# parameter: policy — line 180
# parameter: snapshot — line 180
# variable: item — line 188
# variable: records — line 188
# variable: findings — line 189
# variable: complete — line 190
# definition: add — line 192
# parameter: rule — line 193
# parameter: severity — line 194
# parameter: subject — line 195
# parameter: path — line 196
# parameter: detail — line 197
# parameter: action — line 198
# variable: complete — line 213
# variable: approvals — line 222
# variable: grant — line 223
# variable: group — line 235
# variable: root — line 236
# variable: complete — line 238
# variable: expanded — line 248
# variable: paths — line 248
# variable: complete — line 249
# variable: complete — line 251
# variable: member — line 269
# variable: path — line 269
# variable: record — line 272
# variable: severity — line 292
# variable: record — line 301
# variable: complete — line 303
# variable: complete — line 315
# variable: complete — line 334
# definition: compare — line 370
# parameter: after — line 370
# parameter: before — line 370
# variable: item — line 376
# variable: old — line 376
# variable: item — line 377
# variable: new — line 377
# variable: changes — line 378
# variable: group — line 379
# variable: left — line 380
# variable: right — line 381
# variable: former — line 382
# variable: latter — line 383
# variable: member — line 384
# variable: member — line 394
# END CODE MAP

from __future__ import annotations

from collections import deque
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta

from identitylab.contracts import Policy, Principal, Snapshot

BROAD = {"S-1-1-0", "S-1-5-11", "S-1-5-32-545", "S-1-5-32-546"}


@dataclass(frozen=True, order=True)
class Finding:
    """One deterministic review item with stable rule, SID subject, evidence path and human next step."""

    rule: str
    severity: str
    subject: str
    path: tuple[str, ...]
    detail: str
    action: str


@dataclass(frozen=True)
class Result:
    """Immutable review result; complete describes reviewed evidence, not compliance or effective privileges."""

    host: str
    captured: str
    as_of: str
    complete: bool
    findings: tuple[Finding, ...]

    def to_dict(self) -> dict[str, object]:
        """Return portable machine-readable review data with explicit attribution and interpretation."""
        return {
            "schema": 1,
            "author": "Jason Stys",
            "interpretation": "membership exposure, not effective access",
            **asdict(self),
        }


def reachable(
    group: str, records: dict[str, Principal]
) -> tuple[dict[str, tuple[str, ...]], bool]:
    """Breadth-first shortest SID paths; bounded cycles terminate, missing/incomplete groups mark unknown."""
    paths: dict[str, tuple[str, ...]] = {group: (group,)}
    queue = deque([group])
    complete = True
    while queue:
        current = queue.popleft()
        record = records.get(current)
        if record is None or record.kind == "unknown":
            complete = False
            continue
        if record.kind == "group":
            complete &= record.members_complete
            for member in sorted(record.members):
                if member not in paths:
                    paths[member] = (*paths[current], member)
                    queue.append(member)
    return paths, complete


def cyclic(paths: dict[str, tuple[str, ...]], records: dict[str, Principal]) -> bool:
    """Kahn's algorithm detects reachable group cycles without recursive stack overflow or false diamond cycles."""
    groups = {key for key in paths if key in records and records[key].kind == "group"}
    degree = dict.fromkeys(groups, 0)
    for group in groups:
        for member in records[group].members:
            if member in degree:
                degree[member] += 1
    queue = deque(key for key in degree if degree[key] == 0)
    visited = 0
    while queue:
        group = queue.popleft()
        visited += 1
        for member in records[group].members:
            if member in degree:
                degree[member] -= 1
                if degree[member] == 0:
                    queue.append(member)
    return visited != len(groups)


def audit(snapshot: Snapshot, policy: Policy, as_of: datetime) -> Result:
    """Evaluate explicit host/time policy; never infer clean state from denied/partial/stale collection."""
    if (
        snapshot.host != policy.host
        or as_of.tzinfo is None
        or snapshot.captured > as_of
    ):
        raise ValueError("host or reference clock mismatch")
    records = {item.sid: item for item in snapshot.principals}
    findings: set[Finding] = set()
    complete = snapshot.users_complete and snapshot.groups_complete

    def add(
        rule: str,
        severity: str,
        subject: str,
        path: tuple[str, ...],
        detail: str,
        action: str,
    ) -> None:
        """Deduplicate findings with stable content; messages contain no source paths or personal names."""
        findings.add(Finding(rule, severity, subject, path, detail, action))

    if not complete:
        add(
            "collection-incomplete",
            "review",
            snapshot.host,
            (),
            "Local user/group enumeration was incomplete.",
            "Repeat authorized read-only collection; do not assume absent accounts were removed.",
        )
    if as_of - snapshot.captured > timedelta(hours=policy.max_age_hours):
        complete = False
        add(
            "snapshot-stale",
            "review",
            snapshot.host,
            (),
            "Evidence exceeds the configured freshness limit.",
            "Collect fresh evidence before approval decisions.",
        )
    approvals = set(policy.approved)
    for grant in policy.exceptions:
        if grant.expires > as_of:
            approvals.add((grant.group, grant.principal))
        else:
            add(
                "exception-expired",
                "review",
                grant.principal,
                (grant.group, grant.principal),
                "Approval expired: " + grant.ticket,
                "Owner must renew or remove the exception through normal change control.",
            )
    for group in policy.protected:
        root = records.get(group)
        if root is None or root.kind != "group":
            complete = False
            add(
                "protected-group-missing",
                "review",
                group,
                (group,),
                "Protected group membership is not available.",
                "Verify SID scope and collector access.",
            )
            continue
        paths, expanded = reachable(group, records)
        complete &= expanded
        if cyclic(paths, records):
            complete = False
            add(
                "membership-cycle",
                "review",
                group,
                (group,),
                "Reachable group membership contains a cycle.",
                "Verify exported membership semantics and source integrity.",
            )
        if not expanded:
            add(
                "membership-unknown",
                "review",
                group,
                (group,),
                "Nested, unresolved or partial membership prevents a complete exposure assessment.",
                "Obtain separately authorized directory evidence; do not assume external groups are empty.",
            )
        for member, path in sorted(paths.items()):
            if member == group:
                continue
            record = records.get(member)
            if member in BROAD:
                add(
                    "broad-membership",
                    "high",
                    member,
                    path,
                    "Broad well-known principal is in a protected-group path.",
                    "Review intended scope; approval does not suppress this exposure warning.",
                )
            if record is None or record.kind == "unknown":
                add(
                    "unresolved-principal",
                    "review",
                    member,
                    path,
                    "SID exists in membership evidence but identity classification is unknown.",
                    "Resolve using an authorized source without inferring deletion or maliciousness.",
                )
            elif record.kind == "user" and (group, member) not in approvals:
                severity = "review" if record.enabled is False else "high"
                add(
                    "unapproved-membership",
                    severity,
                    member,
                    path,
                    "User SID has no current explicit approval in this protected group.",
                    "Ask the owner to review justification; disabled membership remains latent exposure.",
                )
    for record in snapshot.principals:
        if record.kind == "user" and record.source == "unknown":
            complete = False
            add(
                "account-source-unknown",
                "review",
                record.sid,
                (),
                "Account source was not classified; local hygiene cannot be inferred.",
                "Obtain supported source metadata before interpreting account coverage.",
            )
        if record.kind != "user" or record.source != "local" or record.enabled is False:
            continue
        if record.enabled is None:
            complete = False
            add(
                "account-state-unknown",
                "review",
                record.sid,
                (),
                "Enabled state was not observed.",
                "Obtain account state before interpreting hygiene.",
            )
        if record.password_required is False:
            add(
                "password-not-required",
                "high",
                record.sid,
                (),
                "Account metadata does not require a password; this does not prove a blank password.",
                "Review password requirement and managed-account context.",
            )
        if record.password_required is None or record.last_logon is None:
            complete = False
            add(
                "account-history-unknown",
                "review",
                record.sid,
                (),
                "Password requirement or last-logon evidence is unavailable.",
                "Null last-logon is not proof of never used; corroborate with authorized records.",
            )
        elif snapshot.captured - record.last_logon >= timedelta(days=policy.stale_days):
            add(
                "inactive-account",
                "medium",
                record.sid,
                (),
                "Observed last logon exceeds the configured inactivity threshold.",
                "Review service/noninteractive use before disabling anything.",
            )
        if record.expires is not None and record.expires <= snapshot.captured:
            add(
                "expired-enabled-account",
                "medium",
                record.sid,
                (),
                "Enabled metadata and elapsed account-expiration timestamp coexist.",
                "Check intended account lifecycle; this is not evidence that sign-in succeeded.",
            )
    return Result(
        snapshot.host,
        snapshot.captured.isoformat(),
        as_of.isoformat(),
        bool(complete),
        tuple(sorted(findings)),
    )


def compare(before: Snapshot, after: Snapshot) -> dict[str, object]:
    """Report observed direct-edge changes; removals confirmed only from complete after-group evidence."""
    if before.host != after.host or before.captured >= after.captured:
        raise ValueError(
            "comparison requires same host and strictly increasing collection time"
        )
    old = {item.sid: item for item in before.principals if item.kind == "group"}
    new = {item.sid: item for item in after.principals if item.kind == "group"}
    changes = []
    for group in sorted(set(old) | set(new)):
        left = old.get(group)
        right = new.get(group)
        former = set(left.members) if left else set()
        latter = set(right.members) if right else set()
        for member in sorted(latter - former):
            changes.append(
                {
                    "group": group,
                    "principal": member,
                    "change": "added"
                    if left and left.members_complete and before.groups_complete
                    else "newly-observed",
                }
            )
        for member in sorted(former - latter):
            changes.append(
                {
                    "group": group,
                    "principal": member,
                    "change": "removed"
                    if right and right.members_complete and after.groups_complete
                    else "not-observed",
                }
            )
    return {
        "author": "Jason Stys",
        "host": after.host,
        "before": before.captured.isoformat(),
        "after": after.captured.isoformat(),
        "changes": changes,
    }
