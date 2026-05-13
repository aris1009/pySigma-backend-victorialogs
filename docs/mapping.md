# Sigma → LogsQL mapping

This document is the canonical reference for what LogsQL the backend emits
for each Sigma feature, and **why**. Every non-trivial decision below was
calibrated against a live VictoriaLogs instance and is pinned by the unit
tests in `tests/test_backend_victorialogs.py` plus the live-corpus
assertion in `tests/test_corpus_live.py`.

> When this document and the backend source code disagree, the source code
> is correct — please open an issue, or a PR that updates this doc.

---

## 1. Quick reference table

| Sigma feature                     | LogsQL output                                                                |
|-----------------------------------|------------------------------------------------------------------------------|
| `field: value`                    | `field:="value"`                                                             |
| `field\|contains: x`              | `field:~"x"` (regex)                                                         |
| `field\|startswith: x`            | `field:="x"*` (native prefix)                                                |
| `field\|endswith: x`              | `field:~"x$"` (regex with `$` anchor)                                        |
| `field\|re: pattern`              | `field:~"pattern"`                                                           |
| `field\|re\|i: pattern`           | `field:~"(?i)pattern"`                                                       |
| `field\|cidr: 10.0.0.0/8`         | `field:ipv4_range("10.0.0.0/8")`                                             |
| `field\|cidr: ::1/128`            | `field:ipv6_range("::1/128")`                                                |
| `field\|gte: 1024`                | `field:>=1024` (also `lt`, `lte`, `gt`)                                      |
| `field\|fieldref: other`          | `field:eq_field(other)`                                                      |
| `field\|exists: true`             | `field:*`                                                                    |
| `field\|exists: false`            | `NOT field:*`                                                                |
| `field: null`                     | `field:""`                                                                   |
| `field: "*"` (any value)          | `field:*` (routes to exists, **not** `field:=""*`)                           |
| field IN [a, b]                   | `field:in("a", "b")`                                                         |
| keywords: bare strings            | `"badword"`                                                                  |
| keywords: regex variant           | `_msg:~"pattern"`                                                            |
| event_count correlation           | `_time:{ts} <search> \| stats by (g) count() as event_count \| filter event_count:>=N` |
| value_count correlation           | `_time:{ts} <search> \| stats by (g) count_uniq(f) as value_count \| filter value_count:>=N` |
| temporal / temporal_ordered       | **Unsupported** — see [limitations](limitations.md)                          |

---

## 2. Boolean structure

LogsQL accepts `AND` / `OR` / `NOT` keywords as well as implicit space-AND.
The backend always emits the explicit keywords for readability.

- **Precedence:** `NOT` > `AND` > `OR`. Matches both Sigma's documented
  precedence and LogsQL's parser.
- **Grouping:** `(expr)`. Plain parentheses, no `OR`-prefix or other
  decoration.

## 3. Field name handling

LogsQL field names accept three quote styles (`"`, `'`, backtick) but plain
identifiers can be left bare. The backend quotes only when required:

- Bare names matching `^[A-Za-z_][A-Za-z0-9_.]*$` are emitted unquoted.
- Anything else gets wrapped in `"..."` with `\` and `"` backslash-escaped.

> **Important:** whitespace inside a double-quoted field name does NOT need
> escaping — adding a backslash before whitespace is rejected by the parser
> in some contexts and unnecessary in all of them. The backend deliberately
> does not include whitespace in the field-escape pattern.

## 4. Equality and value escaping

The base equality template is `{field}:={value}` (the `:=` operator is
case-sensitive). Values are quoted with `"..."` and escaped according to
LogsQL's quoted-string rules.

**Critical escape semantics** (confirmed against live VL on 2026-04-28):
inside `:="..."` the *only* valid backslash escapes are `\\` and `\"`.
Unknown sequences such as `\*`, `\?`, or `\anything-else` cause HTTP 400
with `compound token cannot start with "\\""`.

That constrains the backend in two ways:

1. **`convert_value_str` override**: when the SigmaString carries no
   wildcard SpecialChars, plain literal `*` / `?` characters survive
   verbatim — we do *not* prefix them with `\`. Only `\` and `"` are
   escaped.
2. **Wildcard-bearing values never reach the `:=` template.** They route
   through `wildcard_match_expression` (regex), which uses the `:~"..."`
   regex form whose escape rules are different (regex layer, not string
   layer — `\*` etc. are valid there).

Case-sensitivity is the LogsQL default; the backend's
`case_sensitive_match_expression` is intentionally identical to the plain
match expression.

## 5. String-shape operators

LogsQL has fast forms for prefix and a native phrase filter; everything
else routes to regex.

- **`startswith`** → `field:="value"*`. Native, fast.
- **`contains`** → `field:~"value"`. Phase-0 calibration showed that the
  native phrase form (`field:"value"`) does *word-aware* unanchored
  matching, which silently changes semantics for substrings inside larger
  tokens. We pay the regex cost for correctness.
- **`endswith`** → `field:~"value$"`. Suffix wildcards in `:="..."` did
  not parse during Phase-0 probes, so this also goes through regex with
  an explicit `$` anchor.

The `_allow_special: False` flags on these three templates ensure pySigma
routes any value containing additional special characters (e.g.
`*foo*bar`) to the generic `wildcard_match_expression` — pre-quoted,
regex-compiled — rather than the native fast forms.

## 6. Regex

Template: `{field}:~"{regex}"`. Inside the regex string only the literal
double quote needs to be escaped (`\"`); LogsQL's regex layer handles `\*`
and friends correctly. The backend's `re_escape` is therefore a single
character (`"`).

Flag prefixes are emitted at the start of the pattern:

- `i` → `(?i)`
- `m` → `(?m)`
- `s` → `(?s)`

## 7. CIDR

The default `TextQueryBackend` hook `convert_condition_field_eq_val_cidr`
is hard-coded to a single template. That is wrong for IPv6: a rule with
`|cidr: ::1/128` would emit `ipv4_range("::1/128")` and VL would reject
it.

The backend overrides the hook to dispatch on `cidr.network`'s family:

- `ipaddress.IPv4Network` → `field:ipv4_range("CIDR")`
- `ipaddress.IPv6Network` → `field:ipv6_range("CIDR")`

If `cond.value` is somehow not a `SigmaCIDRExpression` (this should never
happen if the rule parsed cleanly), the override raises `SigmaTypeError`
so the failure is visible to a Sigma toolchain rather than masquerading as
a generic Python `TypeError`.

## 8. Numeric comparison

Template: `{field}:{operator}{value}` with operators `<`, `<=`, `>`, `>=`.
No quoting on numeric literals.

## 9. Field-equals-field (`fieldref`)

Template: `{field1}:eq_field({field2})`. LogsQL takes a *single* argument
in `eq_field` (the *other* field name); the colon-prefixed left side is
the field being compared. Both sides go through the field
quote/escape rules.

## 10. Null / exists

- `field: null` → `field:""` (empty-string equality matches the
  null-equivalent in LogsQL).
- `field|exists: true` → `field:*` (any value present).
- `field|exists: false` → `NOT field:*`.
- **Special case:** Sigma `field: "*"` (intended to mean "any value")
  routes to the *exists* expression — `field:*` — not to the default
  startswith-with-empty-prefix path that would emit `field:=""*`. LogsQL
  parses `field:=""*` as the AND of an empty-string equality and a
  top-level wildcard, which matches everything; that would silently
  change rule semantics.

## 11. IN-list

Template: `{field}:in("a", "b", "c")`. pySigma recognises homogeneous OR
groups over the same field and emits the native form via
`convert_or_as_in: True`. AND-in is intentionally disabled — there is no
native LogsQL form, so pySigma expands AND groups into explicit
conjunctions.

`in_expressions_allow_wildcards` is False: if any list element contains a
wildcard, pySigma falls back to the OR-expanded form so each value can
route through its own wildcard/regex template.

## 12. Unbound (keyword) values

A keyword-only Sigma rule (no field) emits the bare value, scoped against
LogsQL's full-text-message field `_msg` only when it is a regex:

- String keyword → `"badword"` (the value is already quoted by
  `convert_value_str`).
- Numeric keyword → `1234` (no quoting).
- Regex keyword → `_msg:~"pattern"`.

## 13. Correlations

Only `event_count` and `value_count` are implemented (Loki-envelope
parity). Both use the LogsQL stats-pipe pattern:

```text
_time:{timespan} {search} | stats by ({groupby}) {agg} | filter {field}:{op}{count}
```

Notable details:

- **Timespan prefix.** `_time:{timespan}` is prepended so a 5-minute
  `event_count` rule actually evaluates over a 5-minute window, not the
  entire retention range. The timespan unit mapping is the identity:
  `s/m/h/d` map straight through.
- **Filter syntax.** LogsQL's `| filter` clause uses *field-filter*
  syntax (`filter cnt:>N`) — **not** SQL-style `filter cnt > N`. This was
  a Phase-0 surprise; the corresponding test
  (`test_event_count_correlation`) pins it.
- **`temporal` / `temporal_ordered`** are not registered in
  `correlation_methods`, so pySigma raises `NotImplementedError` for any
  rule that requires multi-event window joining. See
  [limitations](limitations.md).

## 14. vmalert output format

The `vmalert` output format wraps every converted query in a
[vmalert](https://docs.victoriametrics.com/victorialogs/vmalert/) rule
group YAML deployable straight to a vmalert pointing at VictoriaLogs.

```bash
sigma convert -t victorialogs -f vmalert path/to/rule.yml > rules.yaml
```

Group scaffolding is fixed:

```yaml
groups:
  - name: Sigma rules
    type: vlogs        # routes expressions to VL's stats_query API
    interval: 5m
    rules: [...]
```

Rule-level mapping:

| Sigma          | vmalert                                  |
|----------------|------------------------------------------|
| `title`        | `alert` (sanitised: `[^A-Za-z0-9_]+→_`)  |
| `id`           | `labels.sigma_id`                        |
| `level`        | `labels.severity` (`level.name.lower()`) |
| `description`  | `annotations.description`                |
| `title`        | `annotations.summary`                    |
| `author`       | `annotations.author`                     |
| `tags`         | `annotations.tags` (comma-joined)        |
| `references`   | `annotations.references` (newline-joined)|

**Stats-pipe wrapping.** vmalert's `vlogs` rule type evaluates
expressions through `/select/logsql/stats_query{,_range}`, which only
returns metric series — so the LogsQL must contain a `stats` pipe.
Plain selectors are wrapped as
`<query> | stats count() as matches | filter matches:>0`. Queries that
already contain `| stats ` (correlation rules) pass through unwrapped.

The expression itself is intentionally time-agnostic: vmalert
auto-prepends `_time:<group_interval>` when the expression doesn't
supply its own. Don't add `_time:` in the backend or you'll double up.

**Required vmalert version.** `type: vlogs` requires vmalert
≥ v1.93 (mid-2024). Verify against the
[VictoriaMetrics changelog](https://docs.victoriametrics.com/victoriametrics/changelog/)
when pinning.

## 15. Operational ceilings

- **`-search.maxQueryLen`** defaults to 16 KiB. Seven SigmaHQ rules emit
  queries above that ceiling (bulk IOC and emoji blocklists, up to
  ~277 KB worst case). The live-corpus test allowlists exactly that set;
  any *new* over-ceiling failure is treated as a regression. Operators who
  need to deploy these rules can raise the flag at VL startup
  (`-search.maxQueryLen=524288` covers everything currently in SigmaHQ).
- **No native single-character wildcard.** LogsQL has no `?`-equivalent
  for matching exactly one character. The backend keeps `wildcard_single`
  declared so pySigma routes `?`-bearing values through the regex
  template; setting it to `None` would make pySigma refuse the rule.
