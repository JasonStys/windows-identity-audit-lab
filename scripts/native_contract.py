"""Jason Stys: consume ephemeral runner-only collector output; print schema assertions, never real SIDs or values."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: main — line 15
# variable: snapshot — line 22
# variable: item — line 27
# END CODE MAP

import json
import os
from pathlib import Path

from identitylab.contracts import parse_snapshot, read_json


def main() -> None:
    """Validate the actual wrapper-produced native JSON on Windows CI, kept solely in ignored temporary tooling."""
    if (
        os.environ.get("GITHUB_ACTIONS") != "true"
        or os.environ.get("RUNNER_OS") != "Windows"
    ):
        raise ValueError("native snapshot validation is CI-only")
    snapshot = parse_snapshot(read_json(Path(".tools/native-snapshot.json")))
    assert snapshot.host == "DISPOSABLE-RUNNER"
    assert snapshot.users_complete and snapshot.groups_complete
    assert any(
        item.sid == "S-1-5-32-544" and item.kind == "group"
        for item in snapshot.principals
    )
    print(
        json.dumps(
            dict(
                author="Jason Stys",
                native_schema_valid=True,
                private_fields_logged=False,
            )
        )
    )


if __name__ == "__main__":
    main()
