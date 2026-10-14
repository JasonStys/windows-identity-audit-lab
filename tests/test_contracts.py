"""Jason Stys: adversarial schema/SID/time/JSON boundaries and property-based canonical identifier checks."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: test_bad_sid — line 83
# parameter: value — line 83
# definition: test_sid_property — line 93
# parameter: authority — line 93
# parameter: parts — line 93
# variable: part — line 95
# variable: value — line 95
# definition: test_bad_time — line 102
# parameter: value — line 102
# definition: test_time_normalized — line 108
# definition: test_bad_bool — line 114
# parameter: value — line 114
# definition: test_bad_threshold — line 122
# parameter: value — line 122
# definition: test_bad_alias — line 129
# parameter: value — line 129
# definition: test_bad_envelopes — line 135
# variable: policy — line 137
# variable: snapshot — line 137
# variable: bad — line 138
# definition: test_bad_accounts — line 168
# parameter: field — line 168
# parameter: value — line 168
# variable: _ — line 170
# variable: snapshot — line 170
# definition: test_bad_group_and_duplicates — line 176
# parameter: monkeypatch — line 176
# variable: _ — line 178
# variable: snapshot — line 178
# variable: _ — line 182
# variable: snapshot — line 182
# variable: _ — line 186
# variable: snapshot — line 186
# definition: test_bad_approvals — line 192
# variable: _ — line 194
# variable: policy — line 194
# variable: protected — line 195
# definition: test_bad_json — line 224
# parameter: data — line 224
# parameter: tmp_path — line 224
# variable: path — line 226
# definition: test_json_files — line 232
# parameter: monkeypatch — line 232
# parameter: tmp_path — line 232
# variable: path — line 234
# parameter: self — line 242
# definition: test_examples — line 247
# variable: snapshot — line 249
# variable: policy — line 250
# END CODE MAP

import json
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from examples.scenarios import ADMIN, AS_OF, USER, baseline
from identitylab import contracts as c


@pytest.mark.parametrize(
    "value",
    [
        None,
        1,
        "",
        "s-1-5-32-544",
        "S-2-5-32-544",
        "S-1-05-32-544",
        "S-1-5-032-544",
        "S-1-5",
        "S-1-281474976710656-1",
        "S-1-5-4294967296",
        "S-1-5--1",
        "S-1-5-1\n",
        "S-1-5" + "-1" * 16,
    ],
)
def test_bad_sid(value: object) -> None:
    """Reject noncanonical forms and numeric/structure overflows."""
    with pytest.raises(ValueError):
        c.sid(value)


@given(
    st.integers(min_value=0, max_value=2**48 - 1),
    st.lists(st.integers(min_value=0, max_value=2**32 - 1), min_size=1, max_size=15),
)
def test_sid_property(authority: int, parts: list[int]) -> None:
    """Every identifier generated within the documented decimal subset survives exactly, without name lookup."""
    value = "S-1-" + str(authority) + "".join("-" + str(part) for part in parts)
    assert c.sid(value) == value


@pytest.mark.parametrize(
    "value", [None, 1, "bad", "2026-10-14", "x" * 41, "0001-01-01T00:00:00+01:00"]
)
def test_bad_time(value: object) -> None:
    """Require valid bounded timezone-bearing dates."""
    with pytest.raises(ValueError):
        c.timestamp(value)


def test_time_normalized() -> None:
    """Equivalent UTC offsets produce the same instant."""
    assert c.timestamp("2026-10-14T01:00:00+01:00") == c.timestamp(AS_OF)


@pytest.mark.parametrize("value", [0, 1, "true", [], {}, None])
def test_bad_bool(value: object) -> None:
    """No integer/string truthiness is accepted."""
    with pytest.raises(ValueError):
        c.boolean(value)
    assert c.boolean(None, True) is None


@pytest.mark.parametrize("value", [True, 0, 3651, 1.5, "90"])
def test_bad_threshold(value: object) -> None:
    """Configuration threshold bounds and integer types are strict."""
    with pytest.raises(ValueError):
        c.integer(value, 1, 3650)


@pytest.mark.parametrize("value", ["", "../host", "<script>", "a" * 65, None, 7])
def test_bad_alias(value: object) -> None:
    """Opaque labels cannot become paths, markup or unbounded strings."""
    with pytest.raises(ValueError):
        c.alias(value)


def test_bad_envelopes() -> None:
    """Missing/extra keys, unsupported versions and principal limits fail before audit."""
    snapshot, policy = baseline()
    for bad in (
        [],
        {},
        {**snapshot, "secret": "do-not-export"},
        {**snapshot, "schema": True},
        {**snapshot, "schema": 2},
        {**snapshot, "principals": {}},
    ):
        with pytest.raises(ValueError):
            c.parse_snapshot(bad)
    with pytest.raises(ValueError):
        c.sequence([0] * (c.MAX_PRINCIPALS + 1), c.MAX_PRINCIPALS)
    with pytest.raises(ValueError):
        c.parse_policy({**policy, "stale_days": 0})


@pytest.mark.parametrize(
    "field,value",
    [
        ("kind", "machine"),
        ("kind", []),
        ("source", "arbitrary"),
        ("source", {}),
        ("members", [USER, USER]),
        ("members", [USER]),
        ("members_complete", True),
        ("last_logon", "2026-10-15T00:00:00Z"),
        ("enabled", 1),
    ],
)
def test_bad_accounts(field: str, value: object) -> None:
    """User records cannot smuggle membership, future history or unsupported classifications."""
    snapshot, _ = baseline()
    snapshot["principals"][1][field] = value
    with pytest.raises(ValueError):
        c.parse_snapshot(snapshot)


def test_bad_group_and_duplicates(monkeypatch: pytest.MonkeyPatch) -> None:
    """Group account fields, duplicate SIDs and aggregate edge overflows are rejected."""
    snapshot, _ = baseline()
    snapshot["principals"][0]["enabled"] = True
    with pytest.raises(ValueError):
        c.parse_snapshot(snapshot)
    snapshot, _ = baseline()
    snapshot["principals"].append(snapshot["principals"][1])
    with pytest.raises(ValueError):
        c.parse_snapshot(snapshot)
    snapshot, _ = baseline()
    monkeypatch.setattr(c, "MAX_EDGES", 0)
    with pytest.raises(ValueError):
        c.parse_snapshot(snapshot)


def test_bad_approvals() -> None:
    """Nonempty protected scope, uniqueness and exception ticket/time fields are enforced."""
    _, policy = baseline()
    for protected in ([], [ADMIN, ADMIN]):
        with pytest.raises(ValueError):
            c.parse_policy({**policy, "protected": protected})
    with pytest.raises(ValueError):
        c.parse_policy({**policy, "approved": policy["approved"] * 2})
    with pytest.raises(ValueError):
        c.parse_policy(
            {**policy, "approved": [{"group": "S-1-5-32-545", "principal": USER}]}
        )
    with pytest.raises(ValueError):
        c.parse_policy(
            {
                **policy,
                "exceptions": [
                    {
                        "group": ADMIN,
                        "principal": USER,
                        "ticket": "CHG-1",
                        "expires": AS_OF,
                    }
                ],
            }
        )


@pytest.mark.parametrize(
    "data",
    [b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}', b"{oops", b"\xff", b"[" * 2000],
)
def test_bad_json(tmp_path: Path, data: bytes) -> None:
    """Duplicate keys, nonstandard numbers, malformed encoding and nesting bombs fail closed."""
    path = tmp_path / "input.json"
    path.write_bytes(data)
    with pytest.raises(ValueError):
        c.read_json(path)


def test_json_files(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Bound reads independently of stat, reject nonfiles/links, and accept UTF-8 BOM from Windows."""
    path = tmp_path / "input.json"
    path.write_bytes(b'\xef\xbb\xbf{"ok":true}')
    assert c.read_json(path) == {"ok": True}
    with pytest.raises(ValueError):
        c.read_json(tmp_path)
    monkeypatch.setattr(c, "MAX_BYTES", 2)
    with pytest.raises(ValueError):
        c.read_json(path)
    monkeypatch.setattr(Path, "is_symlink", lambda self: True)
    with pytest.raises(ValueError):
        c.read_json(path)


def test_examples() -> None:
    """Committed public samples conform to contracts and are explicitly synthetic aliases."""
    snapshot = c.parse_snapshot(c.read_json(Path("examples/snapshot.json")))
    policy = c.parse_policy(c.read_json(Path("examples/policy.json")))
    assert snapshot.host == policy.host == "LAB-WIN"
    assert json.dumps(c.unique_pairs([("a", 1)])) == '{"a": 1}'
