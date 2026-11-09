"""Jason Stys: conservative nested protected-membership drift and exception recertification worklist."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: recertify — line 63
# parameter: before — line 64
# parameter: after — line 65
# parameter: policy_path — line 66
# parameter: as_of — line 67
# parameter: horizon_hours — line 68
# variable: values — line 72
# variable: hashes — line 73
# variable: path — line 74
# variable: p — line 77
# variable: value — line 80
# variable: new — line 89
# variable: old — line 89
# variable: policy — line 90
# variable: direct — line 91
# variable: current — line 92
# variable: horizon — line 93
# variable: new_records — line 94
# variable: old_records — line 94
# variable: p — line 95
# variable: p — line 96
# variable: changes — line 98
# variable: queue — line 99
# variable: group — line 100
# variable: left — line 101
# variable: old_complete — line 101
# variable: new_complete — line 102
# variable: right — line 102
# variable: old_complete — line 103
# variable: new_complete — line 110
# variable: principal — line 117
# variable: a — line 118
# variable: b — line 118
# variable: state — line 119
# variable: record — line 143
# variable: grant — line 145
# variable: g — line 148
# variable: grant — line 170
# definition: publish — line 203
# parameter: output — line 203
# parameter: result — line 203
# variable: target — line 205
# variable: p — line 206
# variable: text — line 209
# variable: page — line 211
# END CODE MAP

from __future__ import annotations

import hashlib
import html
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from identitylab.audit import audit, compare, cyclic, reachable
from identitylab.contracts import integer, parse_policy, parse_snapshot, read_json


def recertify(
    before: Path,
    after: Path,
    policy_path: Path,
    as_of: datetime,
    horizon_hours: int = 24,
) -> dict[str, Any]:
    """Compare representative nested SID exposure paths; incomplete new evidence cannot prove revocation."""
    integer(horizon_hours, 1, 168)
    values = []
    hashes = []
    for path in (before, after, policy_path):
        if any(
            p.is_symlink() or p.is_junction()
            for p in (path.absolute(), *path.absolute().parents)
        ):
            raise ValueError("linked recertification input")
        value = read_json(path)
        values.append(value)
        hashes.append(
            hashlib.sha256(
                json.dumps(
                    value, sort_keys=True, separators=(",", ":"), allow_nan=False
                ).encode()
            ).hexdigest()
        )
    old, new = parse_snapshot(values[0]), parse_snapshot(values[1])
    policy = parse_policy(values[2])
    direct = compare(old, new)
    current = audit(new, policy, as_of)
    horizon = as_of + timedelta(hours=horizon_hours)
    old_records, new_records = (
        {p.sid: p for p in old.principals},
        {p.sid: p for p in new.principals},
    )
    changes = []
    queue = []
    for group in policy.protected:
        left, old_complete = reachable(group, old_records)
        right, new_complete = reachable(group, new_records)
        old_complete = bool(
            old.groups_complete
            and old_complete
            and old_records.get(group)
            and old_records[group].kind == "group"
            and not cyclic(left, old_records)
        )
        new_complete = bool(
            new.groups_complete
            and new_complete
            and new_records.get(group)
            and new_records[group].kind == "group"
            and not cyclic(right, new_records)
        )
        for principal in sorted((left.keys() | right.keys()) - {group}):
            a, b = left.get(principal), right.get(principal)
            state = (
                "PERSISTENT"
                if a == b
                else "REPRESENTATIVE_PATH_CHANGED"
                if a and b
                else "EXPOSURE_ADDED"
                if b and old_complete
                else "NEWLY_OBSERVED"
                if b
                else "EXPOSURE_REMOVED"
                if new_complete
                else "NOT_OBSERVED_UNVERIFIED"
            )
            changes.append(
                {
                    "group": group,
                    "principal": principal,
                    "state": state,
                    "before_path": a,
                    "after_path": b,
                    "before_membership_complete": old_complete,
                    "after_membership_complete": new_complete,
                }
            )
            record = new_records.get(principal)
            if b is not None and record is not None and record.kind == "user":
                grant = next(
                    (
                        g
                        for g in policy.exceptions
                        if (g.group, g.principal) == (group, principal)
                        and g.expires > as_of
                    ),
                    None,
                )
                queue.append(
                    {
                        "kind": "MEMBERSHIP_RECERTIFICATION",
                        "group": group,
                        "principal": principal,
                        "path": b,
                        "approval": "EXPLICIT_APPROVAL"
                        if (group, principal) in policy.approved
                        else "ACTIVE_EXCEPTION"
                        if grant
                        else "UNAPPROVED",
                        "enabled": record.enabled,
                        "owner": "UNASSIGNED owner review",
                        "reason": "Review continuing justification and the original current findings; approval does not suppress broad exposure or prove effective access.",
                    }
                )
    for grant in policy.exceptions:
        if grant.expires <= horizon:
            queue.append(
                {
                    "kind": "EXCEPTION_EXPIRED"
                    if grant.expires <= as_of
                    else "EXCEPTION_EXPIRING",
                    "group": grant.group,
                    "principal": grant.principal,
                    "ticket": grant.ticket,
                    "expires": grant.expires.isoformat(),
                    "owner": "UNASSIGNED owner review",
                    "reason": "Renew or remove only through authorized normal change control; no automatic extension is provided.",
                }
            )
    return {
        "schema": 1,
        "kind": "protected_membership_recertification",
        "author": "Jason Stys",
        "host": new.host,
        "as_of": as_of.isoformat(),
        "horizon_hours": horizon_hours,
        "normalized_input_sha256": dict(
            zip(("before", "after", "policy"), hashes, strict=True)
        ),
        "direct_changes": direct,
        "nested_paths": changes,
        "current_audit": current.to_dict(),
        "review_queue": queue,
        "scope": "Observed membership exposure only, not Windows effective access or revocation enforcement. One deterministic shortest representative path per SID is shown, not every possible path. Partial/unresolved/cyclic membership cannot prove removal. Input hashes bind normalized JSON semantics, not acquisition identity. SIDs and local review evidence remain private; no accounts or directory services are queried or changed.",
    }


def publish(result: dict[str, Any], output: Path) -> None:
    """Write a new owner-private JSON/escaped inert worklist without changing any identity or previous evidence."""
    target = output.absolute()
    if any(p.is_symlink() or p.is_junction() for p in (target, *target.parents)):
        raise ValueError("linked recertification output")
    target.mkdir(mode=0o700)
    text = json.dumps(result, sort_keys=True, indent=2)
    (target / "recertification.json").write_text(text + "\n", encoding="utf-8")
    page = (
        '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src \'none\'; base-uri \'none\'; form-action \'none\'"><title>Membership recertification — Jason Stys</title><main><h1>Protected membership recertification</h1><p>Created by Jason Stys. Private SID exposure evidence; no account enforcement or effective-access claim.</p><pre>'
        + html.escape(text)
        + "</pre></main></html>"
    )
    (target / "recertification.html").write_text(page, encoding="utf-8")
