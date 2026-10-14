"""Jason Stys: deterministic SID-only synthetic scenario fixtures and independent expected rule sets."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: ADMIN — line 57
# variable: USER — line 58
# variable: OTHER — line 59
# variable: NESTED — line 60
# variable: AS_OF — line 61
# definition: account — line 64
# parameter: key — line 64
# definition: group — line 79
# parameter: key — line 79
# parameter: members — line 79
# definition: baseline — line 94
# variable: snapshot — line 96
# variable: policy — line 104
# definition: scenarios — line 115
# variable: result — line 117
# variable: name — line 118
# variable: policy — line 144
# variable: snapshot — line 144
# variable: admin — line 145
# variable: user — line 145
# variable: rules — line 146
# variable: complete — line 147
# variable: rules — line 150
# variable: rules — line 155
# variable: rules — line 160
# variable: complete — line 161
# variable: rules — line 164
# variable: rules — line 167
# variable: rules — line 172
# variable: complete — line 173
# variable: rules — line 176
# variable: complete — line 177
# variable: rules — line 180
# variable: complete — line 181
# variable: rules — line 184
# variable: complete — line 185
# variable: nested — line 194
# variable: rules — line 198
# variable: complete — line 199
# variable: rules — line 203
# variable: rules — line 206
# variable: complete — line 207
# variable: rules — line 224
# variable: broad — line 226
# variable: rules — line 230
# variable: rules — line 233
# variable: complete — line 234
# variable: rules — line 241
# variable: complete — line 242
# END CODE MAP

from copy import deepcopy
from typing import Any

ADMIN = "S-1-5-32-544"
USER = "S-1-5-21-100-200-300-1001"
OTHER = "S-1-5-21-100-200-300-1002"
NESTED = "S-1-5-21-900-800-700-2001"
AS_OF = "2026-10-14T00:00:00Z"


def account(key: str = USER) -> dict[str, Any]:
    """Make explicitly synthetic observed account evidence, not any current PC/user identity."""
    return dict(
        sid=key,
        kind="user",
        source="local",
        enabled=True,
        password_required=True,
        last_logon="2026-10-01T00:00:00Z",
        expires=None,
        members=[],
        members_complete=False,
    )


def group(key: str = ADMIN, members: list[str] | None = None) -> dict[str, Any]:
    """Make complete synthetic group evidence with configurable direct edges."""
    return dict(
        sid=key,
        kind="group",
        source="local",
        enabled=None,
        password_required=None,
        last_logon=None,
        expires=None,
        members=members if members is not None else [USER],
        members_complete=True,
    )


def baseline() -> tuple[dict[str, Any], dict[str, Any]]:
    """Return fresh copies of a complete approved one-account synthetic host and scoped policy."""
    snapshot = dict(
        schema=1,
        host="LAB-WIN",
        captured=AS_OF,
        users_complete=True,
        groups_complete=True,
        principals=[group(), account()],
    )
    policy = dict(
        host="LAB-WIN",
        protected=[ADMIN],
        approved=[dict(group=ADMIN, principal=USER)],
        exceptions=[],
        stale_days=90,
        max_age_hours=24,
    )
    return snapshot, policy


def scenarios() -> list[tuple[str, dict[str, Any], dict[str, Any], set[str], bool]]:
    """Build fixed expected outcomes independently of analyzer output; exact rules and completeness are asserted."""
    result = []
    for name in (
        "approved",
        "unapproved",
        "disabled-latent",
        "password-optional",
        "last-logon-null",
        "stale-account",
        "expired-account",
        "partial-users",
        "partial-groups",
        "partial-members",
        "missing-group",
        "unresolved-member",
        "external-group",
        "nested-approved",
        "nested-unapproved",
        "cycle",
        "diamond",
        "active-exception",
        "expired-exception",
        "broad-approved",
        "unknown-enabled",
        "unknown-password",
        "nonlocal-hygiene",
        "unknown-source",
    ):
        snapshot, policy = deepcopy(baseline())
        admin, user = snapshot["principals"]
        rules: set[str] = set()
        complete = True
        if name in {"unapproved", "disabled-latent"}:
            policy["approved"] = []
            rules = {"unapproved-membership"}
            if name == "disabled-latent":
                user["enabled"] = False
        elif name == "password-optional":
            user["password_required"] = False
            rules = {"password-not-required"}
        elif name in {"last-logon-null", "unknown-password"}:
            user["last_logon" if name == "last-logon-null" else "password_required"] = (
                None
            )
            rules = {"account-history-unknown"}
            complete = False
        elif name == "stale-account":
            user["last_logon"] = "2025-10-01T00:00:00Z"
            rules = {"inactive-account"}
        elif name == "expired-account":
            user["expires"] = AS_OF
            rules = {"expired-enabled-account"}
        elif name in {"partial-users", "partial-groups"}:
            snapshot[
                "users_complete" if name == "partial-users" else "groups_complete"
            ] = False
            rules = {"collection-incomplete"}
            complete = False
        elif name == "partial-members":
            admin["members_complete"] = False
            rules = {"membership-unknown"}
            complete = False
        elif name == "missing-group":
            snapshot["principals"] = [user]
            rules = {"protected-group-missing"}
            complete = False
        elif name == "unresolved-member":
            admin["members"].append(OTHER)
            rules = {"membership-unknown", "unresolved-principal"}
            complete = False
        elif name in {
            "external-group",
            "nested-approved",
            "nested-unapproved",
            "cycle",
            "diamond",
        }:
            admin["members"] = [NESTED]
            nested = group(NESTED)
            snapshot["principals"].append(nested)
            if name == "external-group":
                nested.update(source="ad", members=[], members_complete=False)
                rules = {"membership-unknown"}
                complete = False
            elif name == "nested-unapproved":
                nested["members"] = [OTHER]
                snapshot["principals"].append(account(OTHER))
                rules = {"unapproved-membership"}
            elif name == "cycle":
                nested["members"].append(ADMIN)
                rules = {"membership-cycle"}
                complete = False
            elif name == "diamond":
                admin["members"].append(OTHER)
                snapshot["principals"].append(group(OTHER))
        elif name in {"active-exception", "expired-exception"}:
            policy["approved"] = []
            policy["exceptions"] = [
                dict(
                    group=ADMIN,
                    principal=USER,
                    ticket="CHG-1042",
                    expires="2026-10-15T00:00:00Z"
                    if name == "active-exception"
                    else AS_OF,
                )
            ]
            if name == "expired-exception":
                rules = {"exception-expired", "unapproved-membership"}
        elif name == "broad-approved":
            broad = "S-1-5-32-545"
            admin["members"].append(broad)
            snapshot["principals"].append(group(broad, []))
            policy["approved"].append(dict(group=ADMIN, principal=broad))
            rules = {"broad-membership"}
        elif name == "unknown-enabled":
            user["enabled"] = None
            rules = {"account-state-unknown"}
            complete = False
        elif name == "nonlocal-hygiene":
            user.update(
                source="ad", password_required=None, last_logon=None, enabled=None
            )
        elif name == "unknown-source":
            user["source"] = "unknown"
            rules = {"account-source-unknown"}
            complete = False
        result.append((name, snapshot, policy, rules, complete))
    return result
