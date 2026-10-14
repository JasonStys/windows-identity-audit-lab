# Coding and documentation conventions

Author: Jason Stys.

Task-appropriate languages: PowerShell for native Windows observation and parse-only AST inspection, Python for portable typed offline analysis/tests/tooling, SQL for structured evidence, HTML/CSS for inert review. Additional languages would add no useful boundary here.

Self-documenting names, immutable typed evidence records, explicit nulls/completeness, narrow pure audit functions, bounded inputs and visible trust-boundary comments. Functions/classes have purpose docstrings or PowerShell comment-based help. Do not infer behavior from keywords, localized group labels or exceptions.

Every authored Python/PowerShell/SQL/workflow source has a purpose header and CI-checked physical line map. Python maps use AST definitions/parameters/stored names and attributes. PowerShell maps use Microsoft's parse-only AST, including definitions, parameters and all variable-reference line locations (automatic variables included). SQL/YAML maps are lexical indexes, not semantic validation. Large maps are generated; never manually maintain line numbers.

Generate after formatting: python scripts/code_map.py. Check with --check. Stage only reviewed public files; python scripts/file_guide.py makes the README's exact tracked-file purpose table. Unknown file purposes fail, rather than invent summaries.

Hash-locked development graph, reviewed commit-pinned Actions, no credentials in source, no artifact/cache persistence. Ruff checks style/imports, mypy checks runtime types, pytest/hypothesis check semantics. Limits/counterexamples are documented rather than hidden.
