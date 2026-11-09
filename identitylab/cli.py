"""Jason Stys: offline audit/diff command line with content-free diagnostics and explicit reference time."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: main — line 29
# parameter: argv — line 29
# variable: parser — line 31
# variable: commands — line 34
# variable: review — line 35
# variable: diff — line 40
# variable: recertification — line 43
# variable: args — line 50
# variable: recertified — line 53
# variable: result — line 85
# END CODE MAP

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path

from identitylab.audit import audit, compare
from identitylab.contracts import parse_policy, parse_snapshot, read_json, timestamp
from identitylab.evidence import write_bundle
from identitylab.recertify import publish, recertify


def main(argv: list[str] | None = None) -> int:
    """Audit or compare explicit files; status 0=complete/no findings, 1=review, 2=invalid/operational failure."""
    parser = argparse.ArgumentParser(
        description="Windows identity review by Jason Stys; no account changes."
    )
    commands = parser.add_subparsers(dest="command", required=True)
    review = commands.add_parser("audit")
    review.add_argument("--snapshot", type=Path, required=True)
    review.add_argument("--policy", type=Path, required=True)
    review.add_argument("--as-of", required=True)
    review.add_argument("--output", type=Path, required=True)
    diff = commands.add_parser("diff")
    diff.add_argument("--before", type=Path, required=True)
    diff.add_argument("--after", type=Path, required=True)
    recertification = commands.add_parser("recertify")
    recertification.add_argument("--before", type=Path, required=True)
    recertification.add_argument("--after", type=Path, required=True)
    recertification.add_argument("--policy", type=Path, required=True)
    recertification.add_argument("--as-of", required=True)
    recertification.add_argument("--horizon-hours", type=int, default=24)
    recertification.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "recertify":
            recertified = recertify(
                args.before,
                args.after,
                args.policy,
                timestamp(args.as_of),
                args.horizon_hours,
            )
            publish(recertified, args.output)
            print(
                json.dumps(
                    {
                        "nested_memberships": len(recertified["nested_paths"]),
                        "review_items": len(recertified["review_queue"]),
                        "complete": recertified["current_audit"]["complete"],
                    }
                )
            )
            return int(
                bool(recertified["review_queue"])
                or not recertified["current_audit"]["complete"]
            )
        if args.command == "diff":
            print(
                json.dumps(
                    compare(
                        parse_snapshot(read_json(args.before)),
                        parse_snapshot(read_json(args.after)),
                    ),
                    indent=2,
                )
            )
            return 0
        result = audit(
            parse_snapshot(read_json(args.snapshot)),
            parse_policy(read_json(args.policy)),
            timestamp(args.as_of),
        )
        write_bundle(
            result,
            args.output,
            Path(__file__).resolve().parents[1] / "sql/evidence.sql",
        )
        print(
            json.dumps(
                {
                    "author": "Jason Stys",
                    "complete": result.complete,
                    "findings": len(result.findings),
                }
            )
        )
        return int(bool(result.findings) or not result.complete)
    except (ValueError, OSError, TypeError, OverflowError, sqlite3.Error) as error:
        print(
            "Review failed safely: "
            + type(error).__name__
            + "; inspect input contracts and private output permissions.",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
