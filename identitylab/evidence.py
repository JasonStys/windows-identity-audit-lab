"""Jason Stys: fresh private review bundles, parameterized SQLite evidence and inert escaped HTML."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: render — line 30
# parameter: result — line 30
# variable: rows — line 32
# variable: item — line 34
# variable: state — line 36
# definition: write_bundle — line 54
# parameter: output — line 54
# parameter: result — line 54
# parameter: schema — line 54
# variable: connection — line 64
# variable: item — line 82
# variable: hashes — line 85
# variable: name — line 87
# END CODE MAP

from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import closing
from html import escape
from pathlib import Path

from identitylab.audit import Result


def render(result: Result) -> str:
    """Render escaped SID findings with no scripts, remote media, tracking or form submissions."""
    rows = "".join(
        f"<tr><td>{escape(item.rule)}</td><td>{escape(item.severity)}</td><td>{escape(item.subject)}</td><td>{escape(' → '.join(item.path))}</td><td>{escape(item.detail)}</td><td>{escape(item.action)}</td></tr>"
        for item in result.findings
    )
    state = (
        "Complete for configured scope"
        if result.complete
        else "Incomplete — human review required"
    )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<meta name="referrer" content="no-referrer"><title>Windows identity review · Jason Stys</title>
<style>body{{font:16px system-ui;background:#101b2a;color:#edf4ff;margin:2rem auto;padding:0 1rem;max-width:1100px}}header{{border-bottom:3px solid #64dbc4}}a{{color:#64dbc4}}section{{overflow:auto}}table{{border-collapse:collapse;width:100%;font-size:.9rem}}th,td{{padding:.75rem;border-bottom:1px solid #446;text-align:left;vertical-align:top}}h1{{font-size:2rem}}.state{{color:#ffcf80}}</style></head>
<body><header><p>READ-ONLY ASSURANCE / WINDOWS IDENTITY</p><h1>Membership exposure review</h1><p>Created by <a href="https://github.com/JasonStys" rel="noreferrer">Jason Stys</a> · <a href="https://www.linkedin.com/in/jason-stys-31b30b351/" rel="noreferrer">Contact</a></p></header>
<p>Host alias: {escape(result.host)} · captured: {escape(result.captured)}</p><p class="state">{state}</p>
<p>Membership paths are not effective access decisions. UAC, deny-only tokens, ACLs, logon rights and directory evidence require separate review.</p>
<section aria-label="Identity findings"><table><caption>{len(result.findings)} review findings</caption><thead><tr><th>Rule</th><th>Priority</th><th>Subject</th><th>SID path</th><th>Evidence</th><th>Next step</th></tr></thead><tbody>{rows}</tbody></table></section>
<footer><p>Help: review unknowns first, confirm scope with the system owner, and use normal change control. Keep real reports private; no changes are made by this tool.</p></footer></body></html>
"""


def write_bundle(result: Result, output: Path, schema: Path) -> dict[str, str]:
    """Create a new no-overwrite directory; hashes detect accidental modification, not hostile replacement."""
    if output.is_symlink() or output.is_junction():
        raise ValueError("output link forbidden")
    # mkdir(exist_ok=False) protects existing evidence. ACLs remain the owner's responsibility on Windows.
    output.mkdir(mode=0o700, parents=False)
    (output / "review.json").write_text(
        json.dumps(result.to_dict(), indent=2) + "\n", encoding="utf-8"
    )
    (output / "review.html").write_text(render(result), encoding="utf-8")
    with closing(sqlite3.connect(output / "evidence.sqlite")) as connection:
        connection.executescript(schema.read_text(encoding="utf-8"))
        with connection:
            connection.execute(
                "INSERT INTO review VALUES (?, ?, ?, ?)",
                (result.host, result.captured, result.as_of, int(result.complete)),
            )
            connection.executemany(
                "INSERT INTO finding VALUES (?, ?, ?, ?, ?, ?)",
                [
                    (
                        item.rule,
                        item.severity,
                        item.subject,
                        json.dumps(item.path),
                        item.detail,
                        item.action,
                    )
                    for item in result.findings
                ],
            )
    hashes = {
        name: hashlib.sha256((output / name).read_bytes()).hexdigest()
        for name in ("review.json", "review.html", "evidence.sqlite")
    }
    (output / "manifest.json").write_text(
        json.dumps(hashes, indent=2) + "\n", encoding="utf-8"
    )
    return hashes
