"""Jason Stys: private no-overwrite bundles, SQL injection safety, escaped HTML and actual CLI round trips."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: test_bundle — line 73
# parameter: tmp_path — line 73
# variable: policy — line 75
# variable: snapshot — line 75
# variable: result — line 76
# variable: injection — line 77
# variable: result — line 85
# variable: output — line 86
# variable: hashes — line 87
# variable: digest — line 89
# variable: name — line 89
# variable: connection — line 91
# definition: test_link_output — line 102
# parameter: monkeypatch — line 102
# parameter: tmp_path — line 102
# variable: policy — line 104
# variable: snapshot — line 104
# variable: result — line 105
# parameter: self — line 106
# definition: test_cli — line 111
# parameter: capsys — line 111
# parameter: tmp_path — line 111
# variable: policy — line 113
# variable: snapshot — line 113
# variable: config — line 114
# variable: source — line 114
# variable: args — line 117
# variable: after — line 135
# definition: test_module_entry — line 145
# parameter: tmp_path — line 145
# variable: error — line 162
# definition: test_all_public_render_states — line 168
# variable: _ — line 170
# variable: policy — line 170
# variable: snapshot — line 170
# variable: result — line 171
# variable: page — line 172
# definition: test_sql_operational_failure — line 179
# parameter: capsys — line 180
# parameter: monkeypatch — line 180
# parameter: tmp_path — line 180
# variable: policy — line 183
# variable: snapshot — line 183
# variable: config — line 184
# variable: source — line 184
# definition: denied — line 188
# parameter: args — line 188
# parameter: kwargs — line 188
# END CODE MAP

import hashlib
import json
import runpy
import sqlite3
import sys
from contextlib import closing
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import pytest

from examples.scenarios import AS_OF, baseline, scenarios
from identitylab.audit import Finding, audit
from identitylab.cli import main
from identitylab.contracts import parse_policy, parse_snapshot, timestamp
from identitylab.evidence import render, write_bundle
from scripts.evaluate import evaluate


def test_bundle(tmp_path: Path) -> None:
    """Persist all report fields, verify each actual SHA256, refuse overwrite and keep SQLite values as data."""
    snapshot, policy = baseline()
    result = audit(parse_snapshot(snapshot), parse_policy(policy), timestamp(AS_OF))
    injection = Finding(
        "manual-review",
        "review",
        "'; DROP TABLE review;--",
        (),
        '<script>alert("x")</script>',
        "human review",
    )
    result = replace(result, findings=(injection,), complete=False)
    output = tmp_path / "review"
    hashes = write_bundle(result, output, Path("sql/evidence.sql"))
    assert hashes == json.loads((output / "manifest.json").read_text())
    for name, digest in hashes.items():
        assert hashlib.sha256((output / name).read_bytes()).hexdigest() == digest
    with closing(sqlite3.connect(output / "evidence.sqlite")) as connection:
        assert connection.execute("SELECT COUNT(*) FROM review").fetchone() == (1,)
        assert connection.execute("SELECT subject FROM finding").fetchone() == (
            injection.subject,
        )
    assert "<script>" not in (output / "review.html").read_text()
    assert "&lt;script&gt;" in render(result)
    with pytest.raises(FileExistsError):
        write_bundle(result, output, Path("sql/evidence.sql"))


def test_link_output(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Output symlink protection is exercised without requiring OS symlink privileges."""
    snapshot, policy = baseline()
    result = audit(parse_snapshot(snapshot), parse_policy(policy), timestamp(AS_OF))
    monkeypatch.setattr(Path, "is_symlink", lambda self: True)
    with pytest.raises(ValueError):
        write_bundle(result, tmp_path / "review", Path("sql/evidence.sql"))


def test_cli(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Actual audit/diff entry paths return stable status and never print raw input paths/content on failure."""
    snapshot, policy = baseline()
    source, config = tmp_path / "snapshot.json", tmp_path / "policy.json"
    source.write_text(json.dumps(snapshot))
    config.write_text(json.dumps(policy))
    args = [
        "audit",
        "--snapshot",
        str(source),
        "--policy",
        str(config),
        "--as-of",
        AS_OF,
        "--output",
        str(tmp_path / "complete"),
    ]
    assert main(args) == 0
    assert main(args) == 2
    assert str(tmp_path) not in capsys.readouterr().err
    policy["approved"] = []
    config.write_text(json.dumps(policy))
    args[-1] = str(tmp_path / "needs-review")
    assert main(args) == 1
    after = tmp_path / "after.json"
    snapshot["captured"] = "2026-10-14T01:00:00Z"
    after.write_text(json.dumps(snapshot))
    assert main(["diff", "--before", str(source), "--after", str(after)]) == 0
    assert '"changes": []' in capsys.readouterr().out
    source.write_bytes(b"\xff")
    args[-1] = str(tmp_path / "bad")
    assert main(args) == 2


def test_module_entry(tmp_path: Path) -> None:
    """Execute the public python -m entry point, not a mocked launcher."""
    with patch.dict(sys.modules):
        sys.modules.pop("identitylab.cli", None)
        with (
            patch.object(
                sys,
                "argv",
                [
                    "identitylab.cli",
                    "diff",
                    "--before",
                    str(tmp_path),
                    "--after",
                    str(tmp_path),
                ],
            ),
            pytest.raises(SystemExit) as error,
        ):
            runpy.run_module("identitylab.cli", run_name="__main__")
    assert error.value.code == 2


def test_all_public_render_states() -> None:
    """Render actual clean and finding states and confirm no active/remote-content elements."""
    for _, snapshot, policy, _, _ in scenarios():
        result = audit(parse_snapshot(snapshot), parse_policy(policy), timestamp(AS_OF))
        page = render(result)
        assert "Jason Stys" in page
        assert "<script" not in page and "<img" not in page and "<iframe" not in page
        assert "default-src 'none'" in page and "form-action 'none'" in page
    assert evaluate()["scenarios"] == 24


def test_sql_operational_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Database failures become content-free status 2, never a false successful bundle."""
    snapshot, policy = baseline()
    source, config = tmp_path / "snapshot.json", tmp_path / "policy.json"
    source.write_text(json.dumps(snapshot))
    config.write_text(json.dumps(policy))

    def denied(*args: object, **kwargs: object) -> None:
        """Simulate an OS database error without leaking its deliberately sensitive message."""
        raise sqlite3.OperationalError("PRIVATE-DATABASE-PATH")

    monkeypatch.setattr(sqlite3, "connect", denied)
    assert (
        main(
            [
                "audit",
                "--snapshot",
                str(source),
                "--policy",
                str(config),
                "--as-of",
                AS_OF,
                "--output",
                str(tmp_path / "failed"),
            ]
        )
        == 2
    )
    assert "PRIVATE-DATABASE-PATH" not in capsys.readouterr().err
