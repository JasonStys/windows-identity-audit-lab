"""Jason Stys: download the official digest-pinned PSScriptAnalyzer package into repo-local ignored tooling."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: URL — line 21
# variable: SHA256 — line 22
# definition: main — line 25
# variable: response — line 27
# variable: package — line 28
# variable: destination — line 31
# variable: archive — line 33
# variable: item — line 34
# variable: item — line 36
# variable: path — line 37
# END CODE MAP

import hashlib
import io
import zipfile
from pathlib import Path
from urllib.request import urlopen

URL = "https://github.com/PowerShell/PSScriptAnalyzer/releases/download/1.25.0/PSScriptAnalyzer.1.25.0.nupkg"
SHA256 = "14e634c828eb98efb9f40b2918ba90f139ed5eccdf663a2a747736d996995d60"


def main() -> None:
    """Verify before extraction; reject links/absolute/traversal names and bound expanded package bytes."""
    with urlopen(URL, timeout=60) as response:
        package = response.read(32 * 1024 * 1024 + 1)
    if len(package) > 32 * 1024 * 1024 or hashlib.sha256(package).hexdigest() != SHA256:
        raise ValueError("official PowerShell analyzer checksum mismatch")
    destination = Path(".tools/pssa-1.25.0").resolve()
    destination.mkdir(parents=True, exist_ok=False)
    with zipfile.ZipFile(io.BytesIO(package)) as archive:
        if sum(item.file_size for item in archive.infolist()) > 384 * 1024 * 1024:
            raise ValueError("analyzer expansion cap exceeded")
        for item in archive.infolist():
            path = (destination / item.filename).resolve()
            if (
                not path.is_relative_to(destination)
                or (item.external_attr >> 16) & 0o170000 == 0o120000
            ):
                raise ValueError("unsafe analyzer member")
        archive.extractall(destination)
    print("Official PSScriptAnalyzer 1.25.0 checksum verified; repo-local tools only.")


if __name__ == "__main__":
    main()
