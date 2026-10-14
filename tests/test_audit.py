"""Jason Stys: independent exact scenario oracles, graph safety, approval boundaries and conservative snapshot diffs."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: row — line 97
# definition: test_scenarios — line 99
# parameter: complete — line 100
# parameter: name — line 100
# parameter: policy — line 100
# parameter: rules — line 100
# parameter: snapshot — line 100
# variable: result — line 103
# variable: item — line 104
# definition: test_clock_host_and_freshness — line 109
# variable: policy — line 111
# variable: snapshot — line 111
# variable: config — line 112
# variable: model — line 112
# variable: bad_clock — line 113
# variable: item — line 123
# definition: test_wrong_root_kind_and_unresolved — line 129
# variable: policy — line 131
# variable: snapshot — line 131
# variable: result — line 135
# variable: item — line 136
# variable: policy — line 137
# variable: snapshot — line 137
# variable: unknown — line 139
# variable: result — line 142
# variable: item — line 143
# definition: test_disabled_hygiene_and_path — line 149
# variable: row — line 151
# variable: policy — line 152
# variable: snapshot — line 152
# variable: result — line 156
# variable: row — line 159
# variable: result — line 160
# definition: test_input_order_invariant — line 165
# parameter: order — line 165
# variable: policy — line 167
# variable: snapshot — line 167
# parameter: item — line 170
# variable: model — line 171
# variable: result — line 172
# variable: complete — line 173
# variable: item — line 173
# variable: paths — line 173
# definition: test_deep_chain_no_recursion — line 177
# variable: policy — line 179
# variable: snapshot — line 179
# variable: i — line 180
# variable: keys — line 180
# variable: index — line 184
# variable: key — line 184
# variable: result — line 186
# definition: test_diff_status_and_scope — line 190
# variable: _ — line 192
# variable: left — line 192
# variable: _ — line 193
# variable: right — line 193
# variable: after — line 196
# variable: before — line 196
# variable: row — line 197
# variable: row — line 203
# variable: removed — line 208
# variable: item — line 210
# variable: empty — line 213
# variable: item — line 215
# variable: invalid — line 221
# definition: test_shared_child_group_is_not_cycle — line 226
# variable: policy — line 228
# variable: snapshot — line 228
# variable: shared — line 230
# END CODE MAP

from dataclasses import replace

import pytest
from hypothesis import given
from hypothesis import strategies as st

from examples.scenarios import (
    ADMIN,
    AS_OF,
    NESTED,
    OTHER,
    USER,
    baseline,
    group,
    scenarios,
)
from identitylab.audit import audit, compare, reachable
from identitylab.contracts import parse_policy, parse_snapshot, timestamp


@pytest.mark.parametrize(
    "name,snapshot,policy,rules,complete",
    scenarios(),
    ids=[row[0] for row in scenarios()],
)
def test_scenarios(
    name: str, snapshot: object, policy: object, rules: set[str], complete: bool
) -> None:
    """Require exact expected findings and epistemic completeness for each synthetic business case."""
    result = audit(parse_snapshot(snapshot), parse_policy(policy), timestamp(AS_OF))
    assert {item.rule for item in result.findings} == rules, name
    assert result.complete == complete, name
    assert result.to_dict()["author"] == "Jason Stys"


def test_clock_host_and_freshness() -> None:
    """Future collection, naive clocks and mismatched hosts fail; stale snapshots explicitly need review."""
    snapshot, policy = baseline()
    model, config = parse_snapshot(snapshot), parse_policy(policy)
    for bad_clock in (
        timestamp("2026-10-13T00:00:00Z"),
        timestamp(AS_OF).replace(tzinfo=None),
    ):
        with pytest.raises(ValueError):
            audit(model, config, bad_clock)
    with pytest.raises(ValueError):
        audit(model, replace(config, host="OTHER"), timestamp(AS_OF))
    assert {
        item.rule
        for item in audit(model, config, timestamp("2026-10-15T00:00:01Z")).findings
    } == {"snapshot-stale"}
    assert not audit(model, config, timestamp("2026-10-15T00:00:01Z")).complete
    assert audit(model, config, timestamp("2026-10-15T00:00:00Z")).complete


def test_wrong_root_kind_and_unresolved() -> None:
    """Protected SID must be a group, and explicitly unknown records remain unresolved."""
    snapshot, policy = baseline()
    snapshot["principals"] = [snapshot["principals"][1]]
    policy["protected"] = [USER]
    policy["approved"] = []
    result = audit(parse_snapshot(snapshot), parse_policy(policy), timestamp(AS_OF))
    assert {item.rule for item in result.findings} == {"protected-group-missing"}
    snapshot, policy = baseline()
    snapshot["principals"][0]["members"].append(OTHER)
    unknown = group(OTHER, [])
    unknown.update(kind="unknown", members_complete=False)
    snapshot["principals"].append(unknown)
    result = audit(parse_snapshot(snapshot), parse_policy(policy), timestamp(AS_OF))
    assert {item.rule for item in result.findings} == {
        "unresolved-principal",
        "membership-unknown",
    }


def test_disabled_hygiene_and_path() -> None:
    """Disabled accounts retain latent membership but do not emit enabled-account hygiene findings."""
    row = next(row for row in scenarios() if row[0] == "disabled-latent")
    snapshot, policy = row[1], row[2]
    snapshot["principals"][1].update(
        password_required=False, last_logon=None, expires=AS_OF
    )
    result = audit(parse_snapshot(snapshot), parse_policy(policy), timestamp(AS_OF))
    assert len(result.findings) == 1
    assert result.findings[0].severity == "review"
    row = next(row for row in scenarios() if row[0] == "nested-unapproved")
    result = audit(parse_snapshot(row[1]), parse_policy(row[2]), timestamp(AS_OF))
    assert result.findings[0].path == (ADMIN, NESTED, OTHER)


@given(st.permutations([ADMIN, NESTED, USER]))
def test_input_order_invariant(order: list[str]) -> None:
    """Equivalent reordered evidence has identical audit output; deterministic shortest paths survive diamonds."""
    snapshot, policy = baseline()
    snapshot["principals"].append(group(NESTED))
    snapshot["principals"][0]["members"].append(NESTED)
    snapshot["principals"].sort(key=lambda item: order.index(item["sid"]))
    model = parse_snapshot(snapshot)
    result = audit(model, parse_policy(policy), timestamp(AS_OF))
    paths, complete = reachable(ADMIN, {item.sid: item for item in model.principals})
    assert result.complete and complete and paths[USER] == (ADMIN, USER)


def test_deep_chain_no_recursion() -> None:
    """A 1500-group chain cannot exhaust Python recursion; path evidence stays bounded by input caps."""
    snapshot, policy = baseline()
    keys = [f"S-1-5-21-10-20-30-{i}" for i in range(1500)]
    snapshot["principals"][0]["members"] = [keys[0]]
    snapshot["principals"].extend(
        group(key, [keys[index + 1]] if index + 1 < len(keys) else [USER])
        for index, key in enumerate(keys)
    )
    result = audit(parse_snapshot(snapshot), parse_policy(policy), timestamp(AS_OF))
    assert result.complete and not result.findings


def test_diff_status_and_scope() -> None:
    """Direct changes distinguish confirmed removal/addition from partial not-observed/newly-observed evidence."""
    left, _ = baseline()
    right, _ = baseline()
    right["captured"] = "2026-10-14T01:00:00Z"
    right["principals"][0]["members"] = [OTHER]
    before, after = parse_snapshot(left), parse_snapshot(right)
    assert {row["change"] for row in compare(before, after)["changes"]} == {
        "added",
        "removed",
    }
    assert {
        row["change"]
        for row in compare(
            replace(before, groups_complete=False),
            replace(after, groups_complete=False),
        )["changes"]
    } == {"newly-observed", "not-observed"}
    removed = replace(
        after,
        principals=tuple(item for item in after.principals if item.kind != "group"),
    )
    assert compare(before, removed)["changes"][0]["change"] == "not-observed"
    empty = replace(
        before,
        principals=tuple(item for item in before.principals if item.kind != "group"),
    )
    assert compare(empty, after)["changes"][0]["change"] == "newly-observed"
    assert (
        compare(before, replace(after, principals=before.principals))["changes"] == []
    )
    for invalid in (before, replace(after, host="OTHER")):
        with pytest.raises(ValueError):
            compare(before, invalid)


def test_shared_child_group_is_not_cycle() -> None:
    """A diamond with two incoming group edges exercises indegree tracking without falsely flagging a cycle."""
    snapshot, policy = baseline()
    snapshot["principals"][0]["members"] = [NESTED, OTHER]
    shared = "S-1-5-21-10-20-30-5000"
    snapshot["principals"].extend(
        [group(NESTED, [shared]), group(OTHER, [shared]), group(shared, [USER])]
    )
    assert audit(
        parse_snapshot(snapshot), parse_policy(policy), timestamp(AS_OF)
    ).complete
