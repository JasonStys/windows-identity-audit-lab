"""Independent SID-path, incomplete-evidence and no-enforcement native-adapter oracles. Jason Stys."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: USER — line 89
# variable: OTHER — line 90
# variable: ADMIN — line 91
# variable: NESTED — line 92
# definition: state — line 96
# parameter: tmp_path — line 96
# variable: workspace — line 98
# definition: run — line 105
# parameter: changes — line 105
# parameter: index — line 105
# parameter: state — line 105
# parameter: tmp_path — line 105
# variable: parameters — line 107
# variable: stage — line 108
# variable: files — line 110
# variable: kind — line 110
# variable: summary — line 110
# variable: identity — line 111
# definition: test_supplied_real_audit_retains_findings_and_review_is_not_a_crash — line 116
# parameter: state — line 117
# parameter: tmp_path — line 117
# variable: files — line 120
# variable: summary — line 120
# variable: report — line 121
# definition: test_user_selected_external_policy_changes_actual_exposure_without_rewriting_input — line 134
# parameter: state — line 135
# parameter: tmp_path — line 135
# variable: snapshot — line 138
# variable: policy — line 139
# variable: original — line 140
# variable: raw — line 142
# variable: _ — line 145
# variable: files — line 145
# variable: report — line 146
# variable: row — line 148
# definition: test_nested_changed_path_and_new_principal_retain_original_current_findings — line 152
# parameter: state — line 153
# parameter: tmp_path — line 153
# variable: _ — line 156
# variable: files — line 156
# variable: report — line 157
# variable: paths — line 158
# variable: row — line 158
# variable: row — line 162
# variable: row — line 164
# definition: test_partial_membership_never_proves_revocation_or_complete_clean_audit — line 174
# parameter: state — line 175
# parameter: tmp_path — line 175
# variable: files — line 178
# variable: summary — line 178
# variable: report — line 179
# variable: row — line 180
# variable: user — line 180
# definition: test_direct_diff_and_literal_table_cells_are_not_an_effective_access_decision — line 188
# parameter: state — line 189
# parameter: tmp_path — line 189
# variable: files — line 192
# variable: summary — line 192
# variable: result — line 193
# variable: row — line 195
# definition: test_mistaken_configuration_does_not_replace_prior_bundle — line 216
# parameter: change — line 216
# parameter: state — line 216
# parameter: tmp_path — line 216
# variable: _ — line 218
# variable: files — line 218
# definition: test_wrong_host_and_reversed_chronology_fail_without_mutating_imports — line 224
# parameter: state — line 225
# parameter: tmp_path — line 225
# variable: before — line 228
# variable: old — line 229
# variable: changed — line 230
# variable: target — line 232
# definition: test_unknown_prepared_name_and_inert_metadata_markup — line 246
# variable: files — line 250
# END CODE MAP

import json
from pathlib import Path

import pytest

from identitylab import desktop_project as project
from identitylab.desktop_io import Rejected, json_value
from identitylab.desktop_state import Workspace

USER = "S-1-5-21-100-200-300-1001"
OTHER = "S-1-5-21-100-200-300-1002"
ADMIN = "S-1-5-32-544"
NESTED = "S-1-5-21-900-800-700-2001"


@pytest.fixture
def state(tmp_path):
    """Use only a fresh owned synthetic profile, outside the installation fixture root."""
    workspace = Workspace(
        tmp_path / "profile", project.PRODUCT, project.ROOT, synthetic=True
    )
    yield workspace
    workspace.close()


def run(state, tmp_path, index, **changes):
    """Call actual typed engines and atomic real SQLite retention; no analysis or result is mocked."""
    parameters = {**project.scenario(project.SCENARIOS[index]), **changes}
    stage = tmp_path / ("stage-" + str(len(state.history())))
    stage.mkdir(exist_ok=True)
    kind, summary, files = project.analyze(state, parameters, stage)
    identity = state.save(kind, summary, parameters, files)
    assert state.files(identity) == files
    return files, summary


def test_supplied_real_audit_retains_findings_and_review_is_not_a_crash(
    state, tmp_path
):
    """The published synthetic snapshot has exactly three original review findings, despite complete collection."""
    files, summary = run(state, tmp_path, 0)
    report = json_value(files["review.json"])
    assert report["complete"] is True and len(report["findings"]) == 3
    assert "3 review findings" in summary and "no account changes" in summary
    assert set(files) == {
        "review.json",
        "review.html",
        "manifest.json",
        "evidence.sqlite",
    }
    assert len(project.views(files)["Original identity findings"]) == 3
    assert "effective access" in report["interpretation"]


def test_user_selected_external_policy_changes_actual_exposure_without_rewriting_input(
    state, tmp_path
):
    """Removing the supplied approval creates an actual additional exposure; no path is restricted to packaged examples."""
    snapshot = tmp_path / "authorized-snapshot.json"
    policy = tmp_path / "authorized-policy.json"
    original = (project.ROOT / "examples/snapshot.json").read_bytes()
    snapshot.write_bytes(original)
    raw = json.loads((project.ROOT / "examples/policy.json").read_text())
    raw["approved"] = []
    policy.write_text(json.dumps(raw), encoding="utf-8")
    files, _ = run(state, tmp_path, 0, snapshot=str(snapshot), policy=str(policy))
    report = json_value(files["review.json"])
    assert len(report["findings"]) == 4
    assert any(row["subject"] == USER for row in report["findings"])
    assert snapshot.read_bytes() == original and json.loads(policy.read_text()) == raw


def test_nested_changed_path_and_new_principal_retain_original_current_findings(
    state, tmp_path
):
    """The same USER takes a different representative path; OTHER is a separately added exposure, not a renamed user."""
    files, _ = run(state, tmp_path, 1)
    report = json_value(files["recertification.json"])
    paths = {row["principal"]: row for row in report["nested_paths"]}
    assert paths[USER]["state"] == "REPRESENTATIVE_PATH_CHANGED"
    assert paths[USER]["after_path"] == [ADMIN, NESTED, USER]
    assert paths[OTHER]["state"] == "EXPOSURE_ADDED"
    assert {row["principal"] for row in report["review_queue"]} == {USER, OTHER}
    assert all(
        row["owner"] == "UNASSIGNED owner review" for row in report["review_queue"]
    )
    assert report["current_audit"]["complete"] is True
    assert len(report["current_audit"]["findings"]) == 1
    assert (
        project.views(files)["Original current findings"]
        == report["current_audit"]["findings"]
    )


def test_partial_membership_never_proves_revocation_or_complete_clean_audit(
    state, tmp_path
):
    """An absent edge in explicitly incomplete group evidence stays unverified, even with no current owner queue row."""
    files, summary = run(state, tmp_path, 2)
    report = json_value(files["recertification.json"])
    user = next(row for row in report["nested_paths"] if row["principal"] == USER)
    assert user["state"] == "NOT_OBSERVED_UNVERIFIED"
    assert report["current_audit"]["complete"] is False
    assert len(report["current_audit"]["findings"]) == 2
    assert "INCOMPLETE evidence — review required" in summary
    assert next(iter(project.views(files))) == "Original current findings"


def test_direct_diff_and_literal_table_cells_are_not_an_effective_access_decision(
    state, tmp_path
):
    """Actual supplied edges change in four places; rendered identifiers are only a preview of complete records."""
    files, summary = run(state, tmp_path, 3)
    result = json_value(files["result.json"])
    assert len(result["changes"]) == 4 and "not effective access" in summary
    assert {row["change"] for row in result["changes"]} == {
        "added",
        "removed",
        "newly-observed",
    }
    assert len(project.views(files)["Observed direct changes"]) == 4
    assert len(project.cells(result["changes"][0])) == 4


@pytest.mark.parametrize(
    "change",
    [
        {"horizon": "0"},
        {"horizon": "169"},
        {"horizon": "1.5"},
        {"horizon": "１２"},
        {"as_of": "not-a-time"},
        {"before": ""},
        {"mode": "collect accounts"},
    ],
)
def test_mistaken_configuration_does_not_replace_prior_bundle(state, tmp_path, change):
    """Wrong clocks/paths/horizons and invented collection commands cannot become a normal saved report."""
    files, _ = run(state, tmp_path, 0)
    with pytest.raises((ValueError, OSError)):
        run(state, tmp_path, 1, **change)
    assert len(state.history()) == 1 and state.files(1) == files


def test_wrong_host_and_reversed_chronology_fail_without_mutating_imports(
    state, tmp_path
):
    """Host and collection-time boundaries are original engine invariants; the GUI cannot silently coerce them."""
    before = Path(project.scenario(project.SCENARIOS[1])["before"])
    old = before.read_bytes()
    changed = json.loads(old)
    changed["host"] = "another-fictional-host"
    target = tmp_path / "different.json"
    target.write_text(json.dumps(changed), encoding="utf-8")
    with pytest.raises(ValueError):
        run(state, tmp_path, 1, before=str(target))
    with pytest.raises(ValueError):
        run(
            state,
            tmp_path,
            1,
            before=project.scenario(project.SCENARIOS[1])["snapshot"],
        )
    assert before.read_bytes() == old and state.history() == []


def test_unknown_prepared_name_and_inert_metadata_markup():
    """Prepared cases are closed data choices; markup remains literal text rather than scripts or external media."""
    with pytest.raises(Rejected):
        project.scenario("scan this PC")
    files = project.text_bundle(
        {"changes": [], "host": "<script>bad()</script>"}, "<img src=x>"
    )
    assert b"&lt;script&gt;" in files["result.html"]
    assert b"<script>" not in files["result.html"]
