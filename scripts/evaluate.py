"""Jason Stys: independent exact synthetic scenario oracle evaluation; JSON results contain no real identities."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: evaluate — line 28
# variable: outcomes — line 30
# variable: complete — line 31
# variable: expected — line 31
# variable: name — line 31
# variable: policy — line 31
# variable: snapshot — line 31
# variable: actual — line 32
# variable: item — line 37
# definition: main — line 45
# variable: parser — line 49
# variable: args — line 51
# variable: result — line 52
# variable: text — line 53
# variable: stream — line 55
# END CODE MAP

import json
from pathlib import Path

from examples.scenarios import scenarios
from identitylab.audit import audit
from identitylab.contracts import parse_policy, parse_snapshot, timestamp


def evaluate() -> dict[str, object]:
    """Require every scenario's exact rule set and completeness, not merely at least one expected alert."""
    outcomes = []
    for name, snapshot, policy, expected, complete in scenarios():
        actual = audit(
            parse_snapshot(snapshot),
            parse_policy(policy),
            timestamp(snapshot["captured"]),
        )
        assert {item.rule for item in actual.findings} == expected, name
        assert actual.complete == complete, name
        outcomes.append(
            dict(name=name, rules=sorted(expected), complete=complete, passed=True)
        )
    return dict(author="Jason Stys", scenarios=len(outcomes), outcomes=outcomes)


def main() -> None:
    """Print synthetic oracle evidence; an optional explicit path records locally generated report JSON."""
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = evaluate()
    text = json.dumps(result, indent=2) + "\n"
    if args.output:
        with args.output.open("x", encoding="utf-8") as stream:
            stream.write(text)
    print(text)


if __name__ == "__main__":
    main()
