"""Dump the raw conversion output for a hand-picked set of Sigma rule fragments.

Run with `poetry run python dev/show_queries.py`. Used during development to
calibrate test expectations and inspect the real LogsQL the backend emits.
"""

from textwrap import indent

from sigma.collection import SigmaCollection

from sigma.backends.victorialogs import VictoriaLogsBackend

CASES: list[tuple[str, str]] = [
    (
        "simple_eq",
        """
title: T
status: test
logsource: { category: test }
detection:
    sel:
        fieldA: valueA
    condition: sel
""",
    ),
    (
        "and_two_fields",
        """
title: T
status: test
logsource: { category: test }
detection:
    sel:
        fieldA: valueA
        fieldB: valueB
    condition: sel
""",
    ),
    (
        "or_via_in_list",
        """
title: T
status: test
logsource: { category: test }
detection:
    sel:
        fieldA:
            - v1
            - v2
            - v3
    condition: sel
""",
    ),
    (
        "contains",
        """
title: T
status: test
logsource: { category: test }
detection:
    sel:
        fieldA|contains: needle
    condition: sel
""",
    ),
    (
        "startswith",
        """
title: T
status: test
logsource: { category: test }
detection:
    sel:
        fieldA|startswith: prefix
    condition: sel
""",
    ),
    (
        "endswith",
        """
title: T
status: test
logsource: { category: test }
detection:
    sel:
        fieldA|endswith: .exe
    condition: sel
""",
    ),
    (
        "regex",
        """
title: T
status: test
logsource: { category: test }
detection:
    sel:
        fieldA|re: foo.*bar
    condition: sel
""",
    ),
    (
        "cidr",
        """
title: T
status: test
logsource: { category: test }
detection:
    sel:
        src_ip|cidr: 192.168.0.0/16
    condition: sel
""",
    ),
    (
        "compare_gte",
        """
title: T
status: test
logsource: { category: test }
detection:
    sel:
        bytes|gte: 1024
    condition: sel
""",
    ),
    (
        "exists_true",
        """
title: T
status: test
logsource: { category: test }
detection:
    sel:
        fieldA|exists: true
    condition: sel
""",
    ),
    (
        "exists_false",
        """
title: T
status: test
logsource: { category: test }
detection:
    sel:
        fieldA|exists: false
    condition: sel
""",
    ),
    (
        "fieldref",
        """
title: T
status: test
logsource: { category: test }
detection:
    sel:
        fieldA|fieldref: fieldB
    condition: sel
""",
    ),
    (
        "unbound_keyword",
        """
title: T
status: test
logsource: { category: test }
detection:
    keywords:
        - badword
    condition: keywords
""",
    ),
    (
        "negation",
        """
title: T
status: test
logsource: { category: test }
detection:
    sel:
        fieldA: bad
    condition: not sel
""",
    ),
    (
        "case_sensitive",
        """
title: T
status: test
logsource: { category: test }
detection:
    sel:
        fieldA|cased: ExactCase
    condition: sel
""",
    ),
    (
        "wildcard_in_value",
        """
title: T
status: test
logsource: { category: test }
detection:
    sel:
        fieldA: foo*bar
    condition: sel
""",
    ),
    (
        "event_count_correlation",
        """
title: parent
name: parent_rule
status: test
logsource: { category: test }
detection:
    sel:
        fieldA: x
    condition: sel
---
title: corr
status: test
correlation:
    type: event_count
    rules: parent_rule
    group-by: fieldB
    timespan: 5m
    condition:
        gte: 10
""",
    ),
    (
        "value_count_correlation",
        """
title: parent
name: parent_rule
status: test
logsource: { category: test }
detection:
    sel:
        fieldA: x
    condition: sel
---
title: corr
status: test
correlation:
    type: value_count
    rules: parent_rule
    group-by: fieldB
    timespan: 5m
    condition:
        gte: 3
        field: fieldC
""",
    ),
]


def main() -> None:
    backend = VictoriaLogsBackend()
    for name, yaml in CASES:
        try:
            queries = backend.convert(SigmaCollection.from_yaml(yaml))
        except Exception as exc:
            print(f"## {name}")
            print(f"  EXCEPTION: {type(exc).__name__}: {exc}")
            print()
            continue
        print(f"## {name}")
        for q in queries:
            print(indent(q, "  "))
        print()


if __name__ == "__main__":
    main()
