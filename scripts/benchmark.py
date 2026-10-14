"""Jason Stys: deterministic synthetic graph-audit benchmark; latency is diagnostic, never a flaky CI gate."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: main — line 31
# variable: policy — line 33
# variable: snapshot — line 33
# variable: index — line 34
# variable: users — line 34
# variable: user — line 36
# variable: clock — line 37
# variable: model — line 37
# variable: rules — line 37
# variable: samples — line 43
# variable: _ — line 44
# variable: start — line 45
# variable: result — line 46
# variable: _ — line 50
# variable: peak — line 50
# END CODE MAP

import json
import platform
import statistics
import time
import tracemalloc

from examples.scenarios import AS_OF, account, baseline
from identitylab.audit import audit
from identitylab.contracts import parse_policy, parse_snapshot, timestamp


def main() -> None:
    """Measure 1000 direct members with 15 warmed samples and Python-only allocation peak; excludes native collection."""
    snapshot, policy = baseline()
    users = [account(f"S-1-5-21-100-200-300-{1000 + index}") for index in range(1000)]
    snapshot["principals"] = [snapshot["principals"][0], *users]
    snapshot["principals"][0]["members"] = [user["sid"] for user in users]
    model, rules, clock = (
        parse_snapshot(snapshot),
        parse_policy(policy),
        timestamp(AS_OF),
    )
    audit(model, rules, clock)
    samples = []
    for _ in range(15):
        start = time.perf_counter_ns()
        result = audit(model, rules, clock)
        samples.append((time.perf_counter_ns() - start) / 1e6)
    tracemalloc.start()
    audit(model, rules, clock)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert len(result.findings) == 999
    print(
        json.dumps(
            dict(
                author="Jason Stys",
                python=platform.python_version(),
                system=platform.system(),
                members=1000,
                findings=999,
                samples=15,
                median_ms=statistics.median(samples),
                min_ms=min(samples),
                max_ms=max(samples),
                python_peak_bytes=peak,
            ),
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
