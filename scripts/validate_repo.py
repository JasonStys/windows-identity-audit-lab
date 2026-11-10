"""Jason Stys: tracked-file privacy, offline-runtime imports and zero-artifact/cache workflow guards."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: ROOT — line 34
# definition: publication_text — line 37
# parameter: path — line 37
# variable: archive — line 39
# variable: entries — line 40
# variable: item — line 43
# variable: item — line 49
# variable: item — line 55
# definition: main — line 60
# variable: names — line 62
# variable: name — line 68
# variable: part — line 71
# variable: path — line 78
# variable: text — line 81
# variable: imports — line 94
# variable: node — line 95
# variable: alias — line 97
# variable: path — line 113
# variable: text — line 114
# variable: action — line 121
# variable: codeql — line 124
# variable: flag — line 125
# END CODE MAP

import ast
import json
import re
import subprocess
from pathlib import Path
from zipfile import ZipFile

ROOT = Path(__file__).resolve().parents[1]


def publication_text(path: Path) -> str:
    """Read bounded non-macro Word XML for the existing secret scan; reject malformed packages."""
    with ZipFile(path) as archive:
        entries = archive.infolist()
        if (
            len(entries) > 512
            or sum(item.file_size for item in entries) > 16 * 1024 * 1024
            or "word/document.xml" not in archive.namelist()
            or any(
                item.flag_bits & 1
                or "vbaproject" in item.filename.lower()
                or "/embeddings/" in item.filename.lower()
                for item in entries
            )
        ):
            raise ValueError("Invalid or oversized Word documentation package")
        return "\n".join(
            archive.read(item).decode("utf-8")
            for item in entries
            if item.filename.endswith((".xml", ".rels"))
        )


def main() -> None:
    """Inspect reviewed source only; imported offline runtime must not gain active network/process capabilities."""
    names = (
        subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT)
        .decode()
        .rstrip("\0")
        .split("\0")
    )
    for name in names:
        if any(
            part in {"out", ".venv", ".tools", "__pycache__"}
            for part in name.split("/")
        ) or name.lower().endswith(
            (".pcap", ".pcapng", ".sqlite", ".db", ".key", ".pem", ".env")
        ):
            raise ValueError(
                "private capture/database/credential or generated file is tracked"
            )
        path = ROOT / name
        if path.is_symlink() or path.is_junction():
            raise ValueError("tracked links are forbidden")
        text = (
            publication_text(path)
            if name == "docs/reports/project-guide.docx"
            else path.read_text(encoding="utf-8")
        )
        if re.search(
            r"(?:ghp_|github_pat_|sk-proj-)[A-Za-z0-9_]{12,}|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
            text,
        ):
            raise ValueError("possible credential in tracked source")
        if name.endswith(".json"):
            json.loads(text)
        if name.startswith("identitylab/") and name.endswith(".py"):
            imports = []
            for node in ast.walk(ast.parse(text)):
                if isinstance(node, ast.Import):
                    imports.extend(alias.name.split(".")[0] for alias in node.names)
                elif isinstance(node, ast.ImportFrom):
                    imports.append((node.module or "").split(".")[0])
            if set(imports) & {
                "socket",
                "subprocess",
                "urllib",
                "http",
                "requests",
                "ftplib",
                "telnetlib",
                "paramiko",
            }:
                raise ValueError(
                    "passive offline runtime cannot import active network/process modules"
                )
    for path in (ROOT / ".github/workflows").glob("*.yml"):
        text = path.read_text(encoding="utf-8")
        if (
            "upload-artifact@" in text
            or "actions/cache@" in text
            or re.search(r"^\s+cache:", text, re.M)
        ):
            raise ValueError("Actions artifact/cache use is disabled")
        for action in re.findall(r"uses:\s*([^\s#]+)", text):
            if not re.fullmatch(r"[\w./-]+@[0-9a-f]{40}", action):
                raise ValueError("remote action must be pinned to a reviewed commit")
    codeql = (ROOT / ".github/workflows/codeql.yml").read_text(encoding="utf-8")
    for flag in ("trap-caching", "dependency-caching", "upload-database"):
        if flag + ": false" not in codeql:
            raise ValueError("CodeQL cache/database opt-out missing")
    print(
        f"Privacy, passive import and workflow storage guards passed: {len(names)} tracked files"
    )


if __name__ == "__main__":
    main()
