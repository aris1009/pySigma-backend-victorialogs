# Architecture

Onboarding doc for contributors. Pairs with `docs/mapping.md` (the
*what*) — this is the *how*.

## At a glance

The backend is a single `TextQueryBackend` subclass:
`sigma.backends.victorialogs.VictoriaLogsBackend`. It is **attribute-
driven** — most of the work is configuring the parent's class attributes
to emit the right templates. Only three behaviours need real Python
overrides:

1. `convert_value_str` — fix the LogsQL `:="..."` escape semantics.
2. `convert_condition_field_eq_val_cidr` — dispatch IPv4/IPv6 networks
   to the right `*_range(...)` function.
3. `convert_condition_field_eq_val_str` — route `field: "*"` to the
   *exists* expression instead of the empty-prefix startswith path.

Everything else — boolean precedence, IN-lists, regex flag prefixes,
correlation pipelines, operator templates — is declared via class
attributes the parent class already understands.

## Why we override `convert_value_str`

LogsQL's quoted-string layer (the value side of `field:="..."`) has very
strict escape rules: `\\` and `\"` are the only valid backslash
sequences. Anything else — `\*`, `\?`, `\x`, … — is rejected with HTTP
400 *compound token cannot start with `\"`*.

The default `TextQueryBackend.convert_value_str` escapes every character
in `wildcard_multi + wildcard_single + add_escaped`. With our settings
that includes `*` and `?`, which is fine when those characters are
*wildcard* SpecialChars in the SigmaString — they get rendered first and
the escape is harmless — but **wrong** when they are *literal* `*` / `?`
characters left over from a Sigma escape (`\*` / `\?` in source). The
backend would then prepend `\` to a literal `*` and emit `\*`, which VL
rejects.

The override:

- If the SigmaString contains any wildcard SpecialChars, fall back to
  the parent — those values route to `wildcard_match_expression` (regex)
  anyway, and the parent's regex-side handling is correct.
- Otherwise, render with `wildcard_multi=None` and
  `wildcard_single=None`, escaping only `\` and `"`. Literal `*` / `?`
  survive verbatim.

Confirmed against live VL on 2026-04-28; pinned by
`tests/test_backend_victorialogs.py::test_literal_star_question_pass_through`.

## Why we override `convert_condition_field_eq_val_cidr`

The base hook uses a single `cidr_expression` template. That's fine for
IPv4 (`ipv4_range("...")`) but wrong for IPv6: a rule with
`|cidr: ::1/128` would emit `ipv4_range("::1/128")` and VL would reject
it as an invalid IPv4 CIDR.

The override inspects `cond.value.network` (an
`ipaddress.IPv4Network` or `IPv6Network`) and picks
`cidr_expression_ipv6` for the v6 case. Both templates are declared as
class attributes so the dispatch is the only Python in the path; the
template itself is unchanged from the attribute-driven style.

Pinned by `tests/test_backend_victorialogs.py::test_ipv6_cidr_routes_to_ipv6_range`.

## Why we override `convert_condition_field_eq_val_str`

Sigma allows `field: "*"` to mean "field has any value" (i.e. exists).
The default routing for this string-with-just-a-wildcard takes the
startswith path with an empty prefix and emits `field:=""*` — which
LogsQL parses as the AND of `field:=""` (empty-string equality) and a
top-level `*` (everything), so the rule degenerates into matching every
log line.

The override detects the bare-wildcard case (single SpecialChar, no
literal text) and routes it to `field_exists_expression` (`field:*`)
instead. Pinned by
`tests/test_backend_victorialogs.py::test_value_star_routes_to_exists`.

## The `dev/wrap.py` helper

Live-VL validation needs to embed the converted query into a wrapper
that adds time and tenant constraints (e.g. `_time:5m AND ({query})`).
A naive string concatenation breaks when the query already contains a
top-level pipe (`| stats ...`) — the wrap parens would land in the wrong
place.

`sigma._dev.wrap.wrap_query` does a *quote-aware* split on the first
top-level `|`: it tracks `"..."` and backtick contexts so pipes inside a
quoted regex (e.g. `field:~"a|b"`) do not count. The split happens at
parser depth 0, mirroring how LogsQL itself parses the pipeline.

The helper is shared by `tests/test_corpus_live.py` and
`dev/validate_queries.py` so the wrap logic has exactly one
implementation.

## TextQueryBackend hooks we use

| Hook                                              | What it does in our backend                                    |
|---------------------------------------------------|----------------------------------------------------------------|
| `eq_token`, `str_quote`, `escape_char`            | The `:=`, `"..."`, `\` of base equality.                       |
| `field_quote_pattern_negation = True`             | Bare-when-safe field naming (only quote irregular names).      |
| `startswith_expression`, `endswith_expression`    | Native prefix vs regex-suffix.                                 |
| `re_expression`, `re_escape`                      | Regex template; only `"` is regex-escaped (LogsQL handles `\*`). |
| `cidr_expression`, `cidr_expression_ipv6`         | Two CIDR templates; the override picks one.                    |
| `field_in_list_expression`, `or_in_operator`      | Native `in("a","b")` syntax.                                   |
| `correlation_methods`, `*_aggregation_expression` | The `_time:Xm <search> \| stats ... \| filter ...` shape.       |
| `compare_operators`, `compare_op_expression`      | `field:>=N` form for `gte`/`lte`/`gt`/`lt`.                    |
| `field_null_expression`, `field_exists_expression` | `field:""` and `field:*`.                                     |

Every other class attribute is a knob you can find in
`sigma.conversion.base.TextQueryBackend` — the source there is the
authoritative menu of what is configurable.

## Test layers

- `tests/test_backend_victorialogs.py` — exact-output unit tests, one
  per behaviour. Fast (no I/O).
- `tests/test_escape_fuzz.py` — Hypothesis-based fuzz over input shapes
  that historically broke escaping.
- `tests/test_corpus.py` — converts every public SigmaHQ rule and
  asserts a minimum success rate. No network.
- `tests/test_corpus_live.py` — converts every rule **and** sends each
  query to a live VictoriaLogs instance, asserting HTTP 200. Requires
  `SIGMA_CORPUS_PATH` and `VICTORIALOGS_URL`.
- `tests/test_live_victorialogs.py` — a curated set of hand-picked
  queries (~27 cases) that double as a smoke test against any live VL.

The unit suite must stay fast (`make test-fast` target). The full suite
(`make test`) enforces the 95% coverage gate.

## Windows EventLog end-to-end harness

`make test` does not exercise the `victorialogs_windows_eventlog()` pipeline
against real Windows event data. The pipeline maps Sigma fields onto
`winlog.*` paths under an assumption about ingestion shape (Winlogbeat /
Vector ECS layout); if that assumption is wrong, every Windows rule
silently emits a zero-hit query in production. Unit tests cannot catch
that — only ingest-then-query can.

The e2e harness lives at `e2e/` and `tests/e2e/`:

- `e2e/docker-compose.yml` — VictoriaLogs + Vector, networked. The whole
  stack is reproducible-anywhere; no homelab dependency.
- `e2e/datasets.yml` — manifest of [OTRF
  Security-Datasets](https://github.com/OTRF/Security-Datasets) JSON
  dumps, each pinned by URL + sha256.
- `e2e/vector.toml` — file source → VRL transform that remaps mordor
  top-level fields (`Channel`, `EventID`, `TargetImage`, …) into
  `winlog.{channel, event_id, event_data.*}` so the pipeline's queries
  actually find the events. The Python mirror in
  `tests/test_vector_remap_spec.py` documents the contract.
- `e2e/expectations.yml` — list of `(rule_path, dataset_path, kind,
  min_hits)` triples. `kind: positive` asserts hits ≥ min_hits;
  `kind: negative` asserts hits == 0.
- `tests/e2e/test_windows_eventlog_e2e.py` — gated behind
  `pytest -m e2e`; iterates the expectations and runs each one
  end-to-end against the live stack.

Local run:

```bash
git clone --depth=1 https://github.com/SigmaHQ/sigma /tmp/sigma-rules
make e2e-fetch     # one-time per manifest change; cached afterwards
make e2e           # bring stack up, run harness, tear stack down
```

CI: `.github/workflows/e2e.yml` runs nightly at 03:00 UTC and on manual
dispatch. Datasets are cached in `actions/cache` keyed on the manifest
hash so the heavy fetch only runs on a manifest bump. A nightly failure
opens (or comments on) a rolling tracking issue labelled
`e2e-nightly`.
