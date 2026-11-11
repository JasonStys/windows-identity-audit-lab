"""Jason Stys: strict bounded SID-centric snapshot and policy contracts, with explicit unknown evidence."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: MAX_BYTES — line 116
# variable: MAX_PRINCIPALS — line 117
# variable: MAX_EDGES — line 118
# variable: SOURCES — line 119
# definition: Principal — line 123
# variable: sid — line 126
# variable: kind — line 127
# variable: source — line 128
# variable: enabled — line 129
# variable: password_required — line 130
# variable: last_logon — line 131
# variable: expires — line 132
# variable: members — line 133
# variable: members_complete — line 134
# definition: Snapshot — line 138
# variable: host — line 141
# variable: captured — line 142
# variable: users_complete — line 143
# variable: groups_complete — line 144
# variable: principals — line 145
# definition: ExceptionGrant — line 149
# variable: group — line 152
# variable: principal — line 153
# variable: ticket — line 154
# variable: expires — line 155
# definition: Policy — line 159
# variable: host — line 162
# variable: protected — line 163
# variable: approved — line 164
# variable: exceptions — line 165
# variable: stale_days — line 166
# variable: max_age_hours — line 167
# definition: sid — line 170
# parameter: value — line 170
# variable: part — line 176
# variable: parts — line 176
# variable: part — line 177
# definition: timestamp — line 182
# parameter: value — line 182
# variable: result — line 187
# definition: fields — line 198
# parameter: expected — line 198
# parameter: value — line 198
# definition: boolean — line 205
# parameter: nullable — line 205
# parameter: value — line 205
# definition: integer — line 214
# parameter: lower — line 214
# parameter: upper — line 214
# parameter: value — line 214
# definition: sequence — line 221
# parameter: limit — line 221
# parameter: value — line 221
# definition: alias — line 228
# parameter: value — line 228
# definition: parse_snapshot — line 237
# parameter: value — line 237
# variable: data — line 239
# variable: captured — line 252
# variable: principals — line 253
# variable: item — line 254
# variable: row — line 255
# variable: member — line 276
# variable: members — line 276
# variable: enabled — line 279
# variable: required — line 280
# variable: last — line 281
# variable: expires — line 282
# variable: complete — line 285
# variable: item — line 289
# variable: item — line 306
# variable: item — line 307
# parameter: item — line 315
# definition: parse_policy — line 319
# parameter: value — line 319
# variable: data — line 321
# variable: item — line 325
# variable: protected — line 325
# variable: approved — line 328
# variable: item — line 329
# variable: row — line 330
# variable: exceptions — line 332
# variable: item — line 333
# variable: row — line 334
# variable: item — line 343
# variable: pairs — line 343
# variable: _ — line 345
# variable: group — line 345
# definition: unique_pairs — line 358
# parameter: pairs — line 358
# variable: result — line 360
# variable: key — line 361
# variable: value — line 361
# definition: read_json — line 368
# parameter: path — line 368
# variable: descriptor — line 372
# variable: stream — line 379
# variable: data — line 382
# definition: reject_constant — line 395
# parameter: value — line 395
# END CODE MAP

from __future__ import annotations

import json
import os
import re
import stat
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
    descriptor = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_BINARY", 0),
    )
    with os.fdopen(descriptor, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("regular opened input required")
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
