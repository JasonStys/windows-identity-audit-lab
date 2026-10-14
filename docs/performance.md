# Performance and complexity

Author: Jason Stys.

For each of at most 8 protected roots, BFS visits reachable vertices/edges once, sorting each member list for stable shortest evidence paths. Cycle detection uses iterative Kahn traversal. This is not a claim of constant memory or exact Windows access evaluation.

Cost: O(V + E + Σ d log d + total emitted path lengths) per root plus sorting findings; storing explicit path tuples costs O(total path lengths), worst-case quadratic for a deep chain. Inputs are capped at 2000 principals/10000 edges and tests include a 1500-group chain. Large reports must be kept private. Collector cost includes one local membership query per observed group; provider latency is not benchmarked.

Benchmark: 1000 synthetic direct members, 999 unapproved findings, 15 warmed audit-only samples, median/min/max wall-clock milliseconds and tracemalloc Python-only peak bytes. Excludes native collection, parsing, filesystem writes and resident OS memory. No flaky performance threshold. [Accepted Linux/Python 3.14.8 result](reports/benchmark.json): median 4.531822 ms, Python-only peak 221928 bytes; hardware/environment variability prevents universal speed claims.
