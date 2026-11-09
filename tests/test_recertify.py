"""Jason Stys: independent nested exposure, partial-evidence and expiry worklist oracles."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: fixture — line 79
# parameter: tmp_path — line 79
# variable: old — line 81
# variable: policy — line 81
# variable: new — line 82
# variable: a — line 84
# variable: b — line 84
# variable: p — line 84
# variable: data — line 89
# variable: f — line 89
# definition: write — line 94
# parameter: data — line 94
# parameter: path — line 94
# definition: test_path_change_added_and_removed_are_conservative — line 99
# parameter: tmp_path — line 99
# variable: a — line 101
# variable: b — line 101
# variable: new — line 101
# variable: old — line 101
# variable: p — line 101
# variable: policy — line 101
# variable: before — line 105
# variable: result — line 106
# variable: by_sid — line 107
# variable: r — line 107
# variable: r — line 112
# variable: r — line 114
# definition: test_partial_old_and_unknown_after_are_not_proof — line 136
# parameter: tmp_path — line 136
# variable: _ — line 138
# variable: a — line 138
# variable: b — line 138
# variable: new — line 138
# variable: old — line 138
# variable: p — line 138
# variable: result — line 151
# variable: r — line 153
# variable: r — line 158
# definition: test_exception_boundary_queue_and_original_findings — line 162
# parameter: tmp_path — line 162
# variable: _ — line 164
# variable: a — line 164
# variable: b — line 164
# variable: new — line 164
# variable: p — line 164
# variable: policy — line 164
# variable: result — line 175
# variable: expired — line 178
# variable: r — line 184
# definition: test_cli_bounds_scope_and_safe_outputs — line 189
# parameter: tmp_path — line 189
# variable: _ — line 191
# variable: a — line 191
# variable: b — line 191
# variable: new — line 191
# variable: p — line 191
# variable: out — line 192
# variable: args — line 193
# variable: before — line 207
# variable: hours — line 209
# variable: result — line 216
# END CODE MAP

import copy
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from examples.scenarios import ADMIN, NESTED, OTHER, USER, account, baseline, group
from identitylab.cli import main
from identitylab.contracts import timestamp
from identitylab.recertify import publish, recertify


def fixture(tmp_path):
    """Two strictly chronological synthetic snapshots; no PC identity enumeration."""
    old, policy = baseline()
    new = copy.deepcopy(old)
    new["captured"] = "2026-10-15T00:00:00Z"
    a, b, p = (
        tmp_path / "before.json",
        tmp_path / "after.json",
        tmp_path / "policy.json",
    )
    for f, data in ((a, old), (b, new), (p, policy)):
        f.write_text(json.dumps(data))
    return a, b, p, old, new, policy


def write(path, data):
    """Write local fictional JSON test inputs only."""
    path.write_text(json.dumps(data))


def test_path_change_added_and_removed_are_conservative(tmp_path: Path):
    """One changed representative path does not hide the same principal; complete evidence can confirm observed exposure changes."""
    a, b, p, old, new, policy = fixture(tmp_path)
    new["principals"][0]["members"] = [NESTED, OTHER]
    new["principals"] += [group(NESTED, [USER]), account(OTHER)]
    write(b, new)
    before = a.read_bytes(), b.read_bytes(), p.read_bytes()
    result = recertify(a, b, p, timestamp(new["captured"]))
    by_sid = {r["principal"]: r for r in result["nested_paths"]}
    assert by_sid[USER]["state"] == "REPRESENTATIVE_PATH_CHANGED" and by_sid[USER][
        "after_path"
    ] == (ADMIN, NESTED, USER)
    assert by_sid[OTHER]["state"] == "EXPOSURE_ADDED"
    assert {r["principal"] for r in result["review_queue"]} == {USER, OTHER}
    assert (
        next(r for r in result["review_queue"] if r["principal"] == OTHER)["approval"]
        == "UNAPPROVED"
    )
    assert before == (
        a.read_bytes(),
        b.read_bytes(),
        p.read_bytes(),
    ) and result == recertify(a, b, p, timestamp(new["captured"]))
    new["principals"][0]["members"] = []
    write(b, new)
    assert (
        recertify(a, b, p, timestamp(new["captured"]))["nested_paths"][0]["state"]
        == "EXPOSURE_REMOVED"
    )
    new["principals"][0]["members_complete"] = False
    write(b, new)
    assert (
        recertify(a, b, p, timestamp(new["captured"]))["nested_paths"][0]["state"]
        == "NOT_OBSERVED_UNVERIFIED"
    )


def test_partial_old_and_unknown_after_are_not_proof(tmp_path: Path):
    """Incomplete baseline makes additions newly observed; unresolved/cyclic new membership never proves absent access."""
    a, b, p, old, new, _ = fixture(tmp_path)
    old["groups_complete"] = False
    old["principals"][0]["members"] = []
    write(a, old)
    assert (
        recertify(a, b, p, timestamp(new["captured"]))["nested_paths"][0]["state"]
        == "NEWLY_OBSERVED"
    )
    old["principals"][0]["members"] = [USER]
    write(a, old)
    new["principals"][0]["members"] = [NESTED]
    new["principals"].append(group(NESTED, [NESTED]))
    write(b, new)
    result = recertify(a, b, p, timestamp(new["captured"]))
    assert (
        next(r for r in result["nested_paths"] if r["principal"] == USER)["state"]
        == "NOT_OBSERVED_UNVERIFIED"
    )
    assert not result["current_audit"]["complete"]
    assert any(
        r["rule"] == "membership-cycle" for r in result["current_audit"]["findings"]
    )


def test_exception_boundary_queue_and_original_findings(tmp_path: Path):
    """Expiring/exactly expired exceptions stay visible and never autoextend approval."""
    a, b, p, _, new, policy = fixture(tmp_path)
    policy["approved"] = []
    policy["exceptions"] = [
        {
            "group": ADMIN,
            "principal": USER,
            "ticket": "review-42",
            "expires": "2026-10-16T00:00:00Z",
        }
    ]
    write(p, policy)
    result = recertify(a, b, p, timestamp(new["captured"]), 24)
    assert result["review_queue"][0]["approval"] == "ACTIVE_EXCEPTION"
    assert result["review_queue"][1]["kind"] == "EXCEPTION_EXPIRING"
    expired = recertify(a, b, p, timestamp("2026-10-16T00:00:00Z"))
    assert (
        expired["review_queue"][0]["approval"] == "UNAPPROVED"
        and expired["review_queue"][1]["kind"] == "EXCEPTION_EXPIRED"
    )
    assert any(
        r["rule"] == "exception-expired" for r in expired["current_audit"]["findings"]
    )
    assert len(recertify(a, b, p, timestamp(new["captured"]), 1)["review_queue"]) == 1


def test_cli_bounds_scope_and_safe_outputs(tmp_path: Path):
    """Real command returns review status1, preserves previous evidence and rejects invalid scope/horizon/links."""
    a, b, p, _, new, _ = fixture(tmp_path)
    out = tmp_path / "review"
    args = [
        "recertify",
        "--before",
        str(a),
        "--after",
        str(b),
        "--policy",
        str(p),
        "--as-of",
        new["captured"],
        "--output",
        str(out),
    ]
    assert main(args) == 1
    before = (out / "recertification.json").read_bytes()
    assert main(args) == 2 and (out / "recertification.json").read_bytes() == before
    for hours in (0, True, 169):
        with pytest.raises(ValueError):
            recertify(a, b, p, timestamp(new["captured"]), hours)
    with pytest.raises(ValueError):
        recertify(b, a, p, timestamp(new["captured"]))
    with patch.object(Path, "is_symlink", return_value=True), pytest.raises(ValueError):
        recertify(a, b, p, timestamp(new["captured"]))
    result = json.loads(before)
    result["scope"] = "<script>private</script>"
    publish(result, tmp_path / "escaped")
    assert "&lt;script&gt;" in (tmp_path / "escaped/recertification.html").read_text(
        encoding="utf-8"
    )
    with (
        patch.object(Path, "is_junction", return_value=True),
        pytest.raises(ValueError),
    ):
        publish(result, tmp_path / "linked")
