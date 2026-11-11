"""Actual offline SID audit, direct drift and recertification controls; no account enumeration or enforcement. Jason Stys."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: ROOT — line 71
# variable: PRODUCT — line 72
# variable: PROFILE — line 72
# variable: TITLE — line 73
# variable: VERSION — line 73
# variable: COLUMNS — line 74
# variable: RESOURCES — line 75
# variable: name — line 77
# variable: MODES — line 86
# variable: REVIEW_MODE — line 91
# variable: CHOICES — line 92
# variable: FIELDS — line 93
# variable: ACTIVE_FIELDS — line 100
# variable: SCENARIOS — line 105
# variable: HELP — line 111
# definition: scenario — line 114
# parameter: name — line 114
# variable: values — line 118
# definition: text_bundle — line 143
# parameter: title — line 143
# parameter: value — line 143
# variable: raw — line 145
# variable: page — line 146
# definition: analyze — line 158
# parameter: parameters — line 159
# parameter: stage — line 159
# parameter: state — line 159
# variable: mode — line 162
# variable: result — line 163
# variable: result — line 165
# variable: horizon — line 178
# variable: result — line 186
# variable: output — line 193
# variable: files — line 195
# variable: p — line 195
# variable: assessed — line 208
# variable: output — line 213
# variable: p — line 224
# definition: views — line 228
# parameter: files — line 228
# variable: result — line 231
# variable: key — line 235
# variable: value — line 235
# variable: result — line 239
# variable: choices — line 240
# variable: key — line 248
# variable: value — line 248
# variable: result — line 265
# variable: key — line 269
# variable: value — line 269
# definition: cells — line 274
# parameter: row — line 274
# END CODE MAP

from __future__ import annotations

import html
import sys
from pathlib import Path
from typing import Any, cast

from .audit import audit, compare
from .contracts import parse_policy, parse_snapshot, read_json, timestamp
from .desktop_io import Rejected, canonical, json_value, read_bytes
from .desktop_state import Workspace
from .evidence import write_bundle
from .recertify import publish, recertify

ROOT = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parents[1]))
PRODUCT, PROFILE = "windows-identity-audit-lab", "WindowsIdentityAuditLab"
TITLE, VERSION = "Windows Identity Audit Workbench", "1.1.0"
COLUMNS = ("SID / group", "Rule / work item", "Evidence / owner", "State / priority")
RESOURCES = tuple(
    "examples/desktop/" + name + ".json"
    for name in ("before", "after", "partial", "policy")
) + (
    "examples/snapshot.json",
    "examples/policy.json",
    "sql/evidence.sql",
    "notices.txt",
    "app.ico",
    "python314.dll",
)
MODES = (
    "Audit authorized snapshot",
    "Compare direct membership evidence",
    "Build recertification work queue",
)
REVIEW_MODE = None
CHOICES: dict[str, tuple[str, ...]] = {}
FIELDS = (
    ("snapshot", "Current authorized snapshot JSON", "file"),
    ("before", "Earlier snapshot JSON for the same host", "file"),
    ("policy", "Private host-scoped SID policy JSON", "file"),
    ("as_of", "Explicit assessment time (UTC, e.g. 2026-10-15T00:00:00Z)", "text"),
    ("horizon", "Exception lookahead hours (1–168)", "text"),
)
ACTIVE_FIELDS = {
    MODES[0]: ("snapshot", "policy", "as_of"),
    MODES[1]: ("before", "snapshot"),
    MODES[2]: ("before", "snapshot", "policy", "as_of", "horizon"),
}
SCENARIOS = (
    "Fictional supplied identity snapshot",
    "Fictional changed nested membership",
    "Fictional partial evidence is not revocation",
    "Fictional direct membership changes",
)
HELP = "Select authorized offline JSON snapshots and a host-scoped policy. No PowerShell, account enumeration, remote directory, password collection, group edits or enforcement is available from this GUI. Assessment uses the explicit UTC clock; missing/partial/stale/null evidence remains review or unknown. SID exposure is not effective access. Recertification keeps original findings, distinguishes changed representative paths and never renews an exception. A review outcome is valid evidence, not an application crash. Prepared fictional scenarios populate these same controls. History and exports are plaintext OS-owner evidence; keep real SIDs private."


def scenario(name: str) -> dict[str, str]:
    """Populate ordinary project controls with public synthetic files; do not run analysis or inspect this PC."""
    if name not in SCENARIOS:
        raise Rejected("unknown prepared scenario")
    values = {
        "mode": MODES[0],
        "snapshot": str(ROOT / "examples/snapshot.json"),
        "before": str(ROOT / "examples/desktop/before.json"),
        "policy": str(ROOT / "examples/policy.json"),
        "as_of": "2026-10-14T00:00:00Z",
        "horizon": "24",
    }
    if name != SCENARIOS[0]:
        values.update(
            mode=MODES[1] if name == SCENARIOS[3] else MODES[2],
            snapshot=str(
                ROOT
                / (
                    "examples/desktop/partial.json"
                    if name == SCENARIOS[2]
                    else "examples/desktop/after.json"
                )
            ),
            policy=str(ROOT / "examples/desktop/policy.json"),
            as_of="2026-10-15T00:00:00Z",
        )
    return values


def text_bundle(value: dict[str, Any], title: str) -> dict[str, bytes]:
    """Retain exact metadata as finite JSON and escaped network-inert HTML; no executable input or external media."""
    raw = canonical(value)
    page = (
        '<!doctype html><html lang="en"><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src &#39;none&#39;; base-uri &#39;none&#39;; form-action &#39;none&#39;"><title>'
        + html.escape(title)
        + "</title><main><h1>"
        + html.escape(title)
        + "</h1><p>Jason Stys. Offline SID exposure review; no effective-access or enforcement claim.</p><pre>"
        + html.escape(raw.decode())
        + "</pre></main></html>"
    )
    return {"result.json": raw, "result.html": page.encode()}


def analyze(
    state: Workspace, parameters: dict[str, str], stage: Path
) -> tuple[str, str, dict[str, bytes]]:
    """Invoke original typed engines with explicit files/time; retain a review result without converting it to PASS."""
    mode = parameters["mode"]
    result: dict[str, Any]
    if mode == MODES[1]:
        result = cast(
            dict[str, Any],
            compare(
                parse_snapshot(read_json(Path(parameters["before"]))),
                parse_snapshot(read_json(Path(parameters["snapshot"]))),
            ),
        )
        return (
            mode,
            f"{len(result['changes'])} observed direct changes; not effective access",
            text_bundle(result, "Observed direct membership changes"),
        )
    if mode == MODES[2]:
        horizon = parameters["horizon"].strip()
        if (
            not horizon.isascii()
            or not horizon.isdecimal()
            or len(horizon) > 3
            or not 1 <= int(horizon) <= 168
        ):
            raise Rejected("lookahead must be a base-ten integer from 1 to 168 hours")
        result = recertify(
            Path(parameters["before"]),
            Path(parameters["snapshot"]),
            Path(parameters["policy"]),
            timestamp(parameters["as_of"]),
            int(horizon),
        )
        output = stage / "recertification"
        publish(result, output)
        files = {p.name: read_bytes(p, 32 * 1024 * 1024) for p in output.iterdir()}
        return (
            mode,
            f"{len(result['nested_paths'])} nested membership observations; {len(result['review_queue'])} owner review items; "
            + (
                "evidence complete"
                if result["current_audit"]["complete"]
                else "INCOMPLETE evidence — review required"
            ),
            files,
        )
    if mode != MODES[0]:
        raise Rejected("unsupported offline native operation")
    assessed = audit(
        parse_snapshot(read_json(Path(parameters["snapshot"]))),
        parse_policy(read_json(Path(parameters["policy"]))),
        timestamp(parameters["as_of"]),
    )
    output = stage / "assessment"
    write_bundle(assessed, output, ROOT / "sql/evidence.sql")
    return (
        mode,
        f"{len(assessed.findings)} review findings; "
        + (
            "evidence complete"
            if assessed.complete
            else "INCOMPLETE evidence — review required"
        )
        + "; no account changes",
        {p.name: read_bytes(p, 32 * 1024 * 1024) for p in output.iterdir()},
    )


def views(files: dict[str, bytes]) -> dict[str, list[dict[str, Any]]]:
    """Expose original findings, partial-evidence caveats and owner queues without inventing or suppressing SID facts."""
    if "review.json" in files:
        result = json_value(files["review.json"])
        return {
            "Original identity findings": result["findings"],
            "Scope and completeness": [
                {key: value for key, value in result.items() if key != "findings"}
            ],
        }
    if "recertification.json" in files:
        result = json_value(files["recertification.json"])
        choices = {
            "Owner recertification queue": result["review_queue"],
            "Representative nested paths": result["nested_paths"],
            "Original current findings": result["current_audit"]["findings"],
            "Observed direct changes": result["direct_changes"]["changes"],
            "Scope and input bindings": [
                {
                    key: value
                    for key, value in result.items()
                    if key
                    not in {
                        "review_queue",
                        "nested_paths",
                        "current_audit",
                        "direct_changes",
                    }
                }
            ],
        }
        if not result["current_audit"]["complete"]:
            return {
                "Original current findings": choices.pop("Original current findings"),
                **choices,
            }
        return choices
    result = json_value(files["result.json"])
    return {
        "Observed direct changes": result["changes"],
        "Exact reviewed scope": [
            {key: value for key, value in result.items() if key != "changes"}
        ],
    }


def cells(row: dict[str, Any]) -> tuple[str, str, str, str]:
    """Render bounded identifiers; the complete selected row remains available as literal text."""
    return (
        str(row.get("subject", row.get("principal", row.get("host", "scope")))),
        str(row.get("rule", row.get("kind", row.get("group", "scope")))),
        str(
            row.get(
                "detail", row.get("reason", row.get("owner", "inspect exact record"))
            )
        ),
        str(
            row.get(
                "severity",
                row.get(
                    "state", row.get("change", row.get("approval", "review evidence"))
                ),
            )
        ),
    )
