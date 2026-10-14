"""Jason Stys: strict bounded SID-centric snapshot and policy contracts, with explicit unknown evidence."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: MAX_BYTES — line 113
# variable: MAX_PRINCIPALS — line 114
# variable: MAX_EDGES — line 115
# variable: SOURCES — line 116
# definition: Principal — line 120
# variable: sid — line 123
# variable: kind — line 124
# variable: source — line 125
# variable: enabled — line 126
# variable: password_required — line 127
# variable: last_logon — line 128
# variable: expires — line 129
# variable: members — line 130
# variable: members_complete — line 131
# definition: Snapshot — line 135
# variable: host — line 138
# variable: captured — line 139
# variable: users_complete — line 140
# variable: groups_complete — line 141
# variable: principals — line 142
# definition: ExceptionGrant — line 146
# variable: group — line 149
# variable: principal — line 150
# variable: ticket — line 151
# variable: expires — line 152
# definition: Policy — line 156
# variable: host — line 159
# variable: protected — line 160
# variable: approved — line 161
# variable: exceptions — line 162
# variable: stale_days — line 163
# variable: max_age_hours — line 164
# definition: sid — line 167
# parameter: value — line 167
# variable: part — line 173
# variable: parts — line 173
# variable: part — line 174
# definition: timestamp — line 179
# parameter: value — line 179
# variable: result — line 184
# definition: fields — line 195
# parameter: expected — line 195
# parameter: value — line 195
# definition: boolean — line 202
# parameter: nullable — line 202
# parameter: value — line 202
# definition: integer — line 211
# parameter: lower — line 211
# parameter: upper — line 211
# parameter: value — line 211
# definition: sequence — line 218
# parameter: limit — line 218
# parameter: value — line 218
# definition: alias — line 225
# parameter: value — line 225
# definition: parse_snapshot — line 234
# parameter: value — line 234
# variable: data — line 236
# variable: captured — line 249
# variable: principals — line 250
# variable: item — line 251
# variable: row — line 252
# variable: member — line 273
# variable: members — line 273
# variable: enabled — line 276
# variable: required — line 277
# variable: last — line 278
# variable: expires — line 279
# variable: complete — line 282
# variable: item — line 286
# variable: item — line 303
# variable: item — line 304
# parameter: item — line 312
# definition: parse_policy — line 316
# parameter: value — line 316
# variable: data — line 318
# variable: item — line 322
# variable: protected — line 322
# variable: approved — line 325
# variable: item — line 326
# variable: row — line 327
# variable: exceptions — line 329
# variable: item — line 330
# variable: row — line 331
# variable: item — line 340
# variable: pairs — line 340
# variable: _ — line 342
# variable: group — line 342
# definition: unique_pairs — line 355
# parameter: pairs — line 355
# variable: result — line 357
# variable: key — line 358
# variable: value — line 358
# definition: read_json — line 365
# parameter: path — line 365
# variable: stream — line 369
# variable: data — line 370
# definition: reject_constant — line 383
# parameter: value — line 383
# END CODE MAP

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

MAX_BYTES = 4 * 1024 * 1024
MAX_PRINCIPALS = 2000
MAX_EDGES = 10000
SOURCES = {"local", "ad", "entra", "microsoft", "unknown"}


@dataclass(frozen=True)
class Principal:
    """Immutable identity keyed by SID; null fields mean not observed, never false or never used."""

    sid: str
    kind: str
    source: str
    enabled: bool | None
    password_required: bool | None
    last_logon: datetime | None
    expires: datetime | None
    members: tuple[str, ...]
    members_complete: bool


@dataclass(frozen=True)
class Snapshot:
    """One host-alias snapshot with component completeness, fixed collection time and unique principals."""

    host: str
    captured: datetime
    users_complete: bool
    groups_complete: bool
    principals: tuple[Principal, ...]


@dataclass(frozen=True)
class ExceptionGrant:
    """Time-limited, ticketed approval for one SID in one protected group; not an inherited blanket approval."""

    group: str
    principal: str
    ticket: str
    expires: datetime


@dataclass(frozen=True)
class Policy:
    """Host-scoped protected groups, explicit leaf approvals and narrowly scoped expiring exceptions."""

    host: str
    protected: tuple[str, ...]
    approved: tuple[tuple[str, str], ...]
    exceptions: tuple[ExceptionGrant, ...]
    stale_days: int
    max_age_hours: int


def sid(value: object) -> str:
    """Validate canonical revision-1 decimal SID subset (48-bit authority, 1..15 uint32 subauthorities)."""
    if not isinstance(value, str) or not re.fullmatch(
        r"S-1-(?:0|[1-9][0-9]*)(?:-(?:0|[1-9][0-9]*)){1,15}", value
    ):
        raise ValueError("invalid canonical SID")
    parts = [int(part) for part in value.split("-")[2:]]
    if parts[0] >= 2**48 or any(part >= 2**32 for part in parts[1:]):
        raise ValueError("SID component out of range")
    return value


def timestamp(value: object) -> datetime:
    """Accept timezone-bearing ISO-8601 strings and normalize UTC; reject naive or non-finite times."""
    if not isinstance(value, str) or len(value) > 40:
        raise ValueError("timestamp must be a bounded string")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("invalid timestamp") from error
    if result.tzinfo is None:
        raise ValueError("timezone required")
    try:
        return result.astimezone(UTC)
    except OverflowError as error:
        raise ValueError("UTC timestamp out of range") from error


def fields(value: object, expected: set[str]) -> dict[str, Any]:
    """Reject missing/extra keys rather than silently ignore configuration typos or hidden credential fields."""
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError("incorrect object fields")
    return value


def boolean(value: object, nullable: bool = False) -> bool | None:
    """Require JSON booleans (not truthy strings/integers); permit null only for explicitly unknown fields."""
    if value is None and nullable:
        return None
    if type(value) is not bool:
        raise ValueError("boolean required")
    return value


def integer(value: object, lower: int, upper: int) -> int:
    """Bound positive policy thresholds while rejecting bool-as-int ambiguity."""
    if type(value) is not int or not lower <= value <= upper:
        raise ValueError("integer out of range")
    return value


def sequence(value: object, limit: int) -> list[Any]:
    """Require arrays with explicit item caps, not arbitrary iterable input."""
    if not isinstance(value, list) or len(value) > limit:
        raise ValueError("bounded array required")
    return value


def alias(value: object) -> str:
    """Accept opaque nonpersonal host/ticket aliases only; no free-text names, paths or markup."""
    if not isinstance(value, str) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", value
    ):
        raise ValueError("invalid alias")
    return value


def parse_snapshot(value: object) -> Snapshot:
    """Validate a complete snapshot envelope; absent member SID records remain explicitly unresolved."""
    data = fields(
        value,
        {
            "schema",
            "host",
            "captured",
            "users_complete",
            "groups_complete",
            "principals",
        },
    )
    if type(data["schema"]) is not int or data["schema"] != 1:
        raise ValueError("unsupported schema")
    captured = timestamp(data["captured"])
    principals = []
    for item in sequence(data["principals"], MAX_PRINCIPALS):
        row = fields(
            item,
            {
                "sid",
                "kind",
                "source",
                "enabled",
                "password_required",
                "last_logon",
                "expires",
                "members",
                "members_complete",
            },
        )
        if (
            not isinstance(row["kind"], str)
            or not isinstance(row["source"], str)
            or row["kind"] not in {"user", "group", "unknown"}
            or row["source"] not in SOURCES
        ):
            raise ValueError("invalid identity classification")
        members = tuple(sid(member) for member in sequence(row["members"], MAX_EDGES))
        if len(set(members)) != len(members):
            raise ValueError("duplicate membership")
        enabled = boolean(row["enabled"], True)
        required = boolean(row["password_required"], True)
        last = None if row["last_logon"] is None else timestamp(row["last_logon"])
        expires = None if row["expires"] is None else timestamp(row["expires"])
        if last is not None and last > captured:
            raise ValueError("last logon after collection")
        complete = boolean(row["members_complete"])
        if row["kind"] != "group" and (members or complete):
            raise ValueError("non-group cannot contain membership evidence")
        if row["kind"] != "user" and any(
            item is not None for item in (enabled, required, last, expires)
        ):
            raise ValueError("non-user cannot contain account evidence")
        principals.append(
            Principal(
                sid(row["sid"]),
                row["kind"],
                row["source"],
                enabled,
                required,
                last,
                expires,
                members,
                bool(complete),
            )
        )
    if (
        len({item.sid for item in principals}) != len(principals)
        or sum(len(item.members) for item in principals) > MAX_EDGES
    ):
        raise ValueError("duplicate identity or edge cap exceeded")
    return Snapshot(
        alias(data["host"]),
        captured,
        bool(boolean(data["users_complete"])),
        bool(boolean(data["groups_complete"])),
        tuple(sorted(principals, key=lambda item: item.sid)),
    )


def parse_policy(value: object) -> Policy:
    """Validate SID approvals, duplicate-free exceptions and protected-group scope without implicit defaults."""
    data = fields(
        value,
        {"host", "protected", "approved", "exceptions", "stale_days", "max_age_hours"},
    )
    protected = tuple(sid(item) for item in sequence(data["protected"], 8))
    if not protected or len(set(protected)) != len(protected):
        raise ValueError("protected groups must be nonempty and unique")
    approved = []
    for item in sequence(data["approved"], MAX_PRINCIPALS):
        row = fields(item, {"group", "principal"})
        approved.append((sid(row["group"]), sid(row["principal"])))
    exceptions = []
    for item in sequence(data["exceptions"], MAX_PRINCIPALS):
        row = fields(item, {"group", "principal", "ticket", "expires"})
        exceptions.append(
            ExceptionGrant(
                sid(row["group"]),
                sid(row["principal"]),
                alias(row["ticket"]),
                timestamp(row["expires"]),
            )
        )
    pairs = approved + [(item.group, item.principal) for item in exceptions]
    if len(set(pairs)) != len(pairs) or any(
        group not in protected for group, _ in pairs
    ):
        raise ValueError("duplicate or out-of-scope approval")
    return Policy(
        alias(data["host"]),
        tuple(sorted(protected)),
        tuple(sorted(approved)),
        tuple(exceptions),
        integer(data["stale_days"], 1, 3650),
        integer(data["max_age_hours"], 1, 8760),
    )


def unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Reject duplicate JSON keys before contract validation; never accept last-key-wins policy overrides."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def read_json(path: Path) -> object:
    """Read bounded regular nonsymlink UTF-8 JSON only; error messages omit input paths/content."""
    if path.is_symlink() or path.is_junction() or not path.is_file():
        raise ValueError("regular input file required")
    with path.open("rb") as stream:
        data = stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError("input size cap exceeded")
    try:
        return json.loads(
            data.decode("utf-8-sig"),
            object_pairs_hook=unique_pairs,
            parse_constant=reject_constant,
        )
    except (UnicodeError, RecursionError, json.JSONDecodeError) as error:
        raise ValueError("invalid bounded JSON") from error


def reject_constant(value: str) -> None:
    """Reject nonstandard NaN/Infinity tokens even in fields that would later be rejected."""
    raise ValueError("nonstandard JSON constant")
