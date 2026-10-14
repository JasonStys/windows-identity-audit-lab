"""Jason Stys: exact Python/PowerShell AST symbol maps and lexical SQL/workflow physical line indexes."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: ROOT — line 57
# definition: mapped — line 60
# parameter: source — line 60
# parameter: suffix — line 60
# variable: prefix — line 62
# variable: begin — line 63
# variable: end — line 63
# variable: source — line 64
# variable: lines — line 70
# variable: records — line 71
# variable: insertion — line 72
# variable: tree — line 74
# variable: insertion — line 77
# variable: node — line 78
# variable: raw — line 90
# variable: kind — line 99
# variable: name — line 99
# variable: number — line 99
# variable: insertion — line 103
# variable: line — line 104
# variable: number — line 104
# variable: name — line 107
# variable: name — line 109
# variable: name — line 111
# variable: item — line 113
# variable: name — line 115
# variable: name — line 119
# variable: name — line 121
# variable: count — line 123
# variable: separator — line 124
# variable: header — line 125
# variable: kind — line 129
# variable: name — line 129
# variable: number — line 129
# parameter: item — line 130
# definition: main — line 139
# variable: parser — line 141
# variable: args — line 143
# variable: paths — line 144
# variable: stale — line 155
# variable: path — line 156
# variable: source — line 157
# variable: expected — line 158
# END CODE MAP

from __future__ import annotations

import argparse
import ast
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def mapped(source: str, suffix: str) -> str:
    """Insert physical line maps without executing source; SQL/YAML indexes are lexical, Python is AST-based."""
    prefix = "--" if suffix == ".sql" else "#"
    begin, end = prefix + " BEGIN CODE MAP", prefix + " END CODE MAP"
    source = re.sub(
        r"^" + re.escape(begin) + r"[^\n]*\n.*?^" + re.escape(end) + r"\n",
        "",
        source,
        flags=re.M | re.S,
    )
    lines = source.splitlines(keepends=True)
    records: set[tuple[str, str, int]] = set()
    insertion = 1 if source.startswith("#!") else 0
    if suffix == ".py":
        tree = ast.parse(source)
        if not ast.get_docstring(tree):
            raise ValueError("missing file purpose header")
        insertion = tree.body[0].end_lineno or 0
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                if not ast.get_docstring(node):
                    raise ValueError("missing function/class description: " + node.name)
                records.add(("definition", node.name, node.lineno))
            elif isinstance(node, ast.arg):
                records.add(("parameter", node.arg, node.lineno))
            elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                records.add(("variable", node.id, node.lineno))
            elif isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Store):
                records.add(("attribute", node.attr, node.lineno))
    elif suffix in {".ps1", ".psm1"}:
        raw = subprocess.check_output(
            [
                "pwsh",
                "-NoProfile",
                "-File",
                str(ROOT / "powershell/Get-CodeSymbols.ps1"),
            ],
            input=source.encode("utf-8"),
        )
        for kind, name, number in json.loads(raw):
            records.add((kind, name, number))
    else:
        while insertion < len(lines) and lines[insertion].startswith(prefix):
            insertion += 1
        for number, line in enumerate(lines, 1):
            if line.lstrip().startswith(prefix):
                continue
            for name in re.findall(r"^([a-z_][a-z0-9_]*)\(\)\s*\{", line):
                records.add(("shell function", name, number))
            for name in re.findall(r"\b([a-z_][a-z0-9_]*)=", line):
                records.add(("shell variable", name, number))
            for name in re.findall(r"\bfor\s+(\w+)\s+in|\bread\s+-r\s+(\w+)", line):
                records.add(
                    ("shell loop/input", next(item for item in name if item), number)
                )
            for name in re.findall(
                r"CREATE (?:TABLE|TRIGGER|INDEX) (?:IF NOT EXISTS )?(\w+)", line
            ):
                records.add(("SQL object", name, number))
            for name in re.findall(r"\b(\w+) (?:INTEGER|TEXT|BLOB)\b", line):
                records.add(("column", name, number))
            for name in re.findall(r"^\s*(?:- )?([\w-]+):", line):
                records.add(("parameter", name, number))
    count = len(records) + 2
    separator = " - line " if suffix in {".ps1", ".psm1"} else " — line "
    header = [
        begin + " (generated; python scripts/code_map.py)",
        *[
            f"{prefix} {kind}: {name}{separator}{number + count if number > insertion else number}"
            for kind, name, number in sorted(
                records, key=lambda item: (item[2], item[0], item[1])
            )
        ],
        end,
    ]
    lines.insert(insertion, "\n".join(header) + "\n")
    return "".join(lines)


def main() -> int:
    """Generate or check every authored Python, SQL and workflow header; drift or missing descriptions fail CI."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    paths = [
        *(ROOT / "identitylab").glob("*.py"),
        *(ROOT / "scripts").glob("*.py"),
        *(ROOT / "tests").glob("*.py"),
        *(ROOT / "examples").glob("*.py"),
        *(ROOT / "scripts").glob("*.sh"),
        *(ROOT / "sql").glob("*.sql"),
        *(ROOT / ".github/workflows").glob("*.yml"),
        *(ROOT / "powershell").glob("*.ps1"),
        *(ROOT / "powershell").glob("*.psm1"),
    ]
    stale = []
    for path in paths:
        source = path.read_text(encoding="utf-8")
        expected = mapped(source, path.suffix)
        if source != expected:
            stale.append(str(path.relative_to(ROOT)))
            if not args.check:
                path.write_text(expected, encoding="utf-8", newline="\n")
    print("Code maps current" if not stale else "Code maps: " + ", ".join(stale))
    return int(args.check and bool(stale))


if __name__ == "__main__":
    raise SystemExit(main())
