"""Jason Stys: exact tracked-file README purpose inventory, unknown files fail rather than receive guesses."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: ROOT — line 35
# variable: BEGIN — line 36
# variable: END — line 36
# variable: SPECIAL — line 37
# definition: purpose — line 62
# parameter: name — line 62
# variable: text — line 66
# variable: lines — line 71
# variable: index — line 72
# variable: line — line 72
# variable: description — line 74
# variable: continuation — line 76
# variable: description — line 82
# definition: main — line 87
# variable: parser — line 89
# variable: args — line 91
# variable: names — line 92
# variable: rows — line 100
# variable: name — line 101
# variable: label — line 102
# variable: path — line 104
# variable: original — line 105
# variable: end — line 106
# variable: start — line 106
# variable: expected — line 107
# END CODE MAP

import argparse
import ast
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BEGIN, END = "<!-- BEGIN FILE GUIDE -->", "<!-- END FILE GUIDE -->"
SPECIAL = {
    "requirements-native.lock": "Exact hash-locked Windows portable build graph; no runtime downloads on user launch.",
    "docs/licenses/tcl-9.0.4.txt": "Actual Tcl9.0.4 runtime notice read from the verified bundled SDK zipfs.",
    "docs/licenses/tk-9.0.4.txt": "Actual Tk9.0.4 runtime notice read from the verified bundled SDK zipfs.",
    "examples/desktop/before.json": "Fictional earlier closed snapshot with one protected direct membership.",
    "examples/desktop/after.json": "Fictional changed snapshot with nested and newly observed direct membership edges.",
    "examples/desktop/partial.json": "Fictional explicitly incomplete group evidence; absence does not prove revocation.",
    "examples/desktop/policy.json": "Fictional protected-group/approval policy used by actual desktop and CLI engines.",
    "docs/reports/project-guide.docx": "Reviewed Word project guide with source revision and dated validation scope.",
    "docs/reports/publications.json": "Exact reviewed Office file identities, immutable source baseline and workflow observations.",
    ".gitignore": "Exclude private identity snapshots, databases, outputs and tool caches.",
    ".gitattributes": "Consistent LF text checkouts across operating systems.",
    "LICENSE": "MIT license for Jason Stys's authored code.",
    "requirements-dev.lock": "Universal complete hash-locked test and security-tool graph.",
    "tools.lock.json": "Official Linux scanner versions, URLs and SHA256 digests.",
    "examples/policy.json": "Synthetic protected-group policy and explicitly scoped approval.",
    "examples/snapshot.json": "Synthetic Windows identity evidence; no real host/account information.",
    "docs/reports/ci.json": "Actual immutable accepted-source CI snapshot.",
    "docs/reports/evaluation.json": "Measured fixed synthetic scenario outcomes.",
    "docs/reports/powershell.json": "Actual synthetic and disposable-runner Windows validation.",
    "docs/reports/example.html": "Inert synthetic analyst report.",
    "docs/reports/benchmark.json": "Measured bounded graph audit latency and Python allocation peak.",
}


def purpose(name: str) -> str:
    """Read the authored module/header/title purpose or explicit noncommentable-file description."""
    if name in SPECIAL:
        return SPECIAL[name]
    text = (ROOT / name).read_text(encoding="utf-8")
    if name.endswith(".py"):
        return (ast.get_docstring(ast.parse(text)) or "").splitlines()[0]
    if name.endswith(".md"):
        return text.splitlines()[0].lstrip("# ") + "."
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if "Jason Stys:" in line:
            description = line.lstrip("#!/- ")
            if name.endswith((".cpp", ".hpp", ".rs")):
                for continuation in lines[index + 1 :]:
                    if (
                        not continuation.startswith("//")
                        or "BEGIN CODE MAP" in continuation
                    ):
                        break
                    description += " " + continuation.lstrip("/! ")
            return description
    raise ValueError("Tracked-file purpose missing: " + name)


def main() -> None:
    """Generate/check an exact full tracked-file table after staging only reviewed nonprivate files."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    names = (
        subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT)
        .decode()
        .rstrip("\0")
        .split("\0")
    )
    if names == [""]:
        raise ValueError("Stage reviewed files first")
    rows = ["| File | Purpose |", "| --- | --- |"]
    for name in sorted(names):
        label = name.replace("_", "\\_")
        rows.append(f"| [{label}]({name}) | {purpose(name).replace('|', '/')} |")
    path = ROOT / "README.md"
    original = path.read_text(encoding="utf-8")
    start, end = original.index(BEGIN) + len(BEGIN), original.index(END)
    expected = original[:start] + "\n\n" + "\n".join(rows) + "\n\n" + original[end:]
    if args.check and expected != original:
        raise ValueError("README file guide stale")
    if not args.check:
        path.write_text(expected, encoding="utf-8", newline="\n")
    print(f"README complete inventory: {len(names)}")


if __name__ == "__main__":
    main()
