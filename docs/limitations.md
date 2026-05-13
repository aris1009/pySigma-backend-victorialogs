# Limitations

What this backend cannot do, and what to do about it. Every entry below is
deliberate — most are LogsQL parser realities rather than backend gaps —
and most have a workaround.

## Temporal correlations are not supported

Sigma's `temporal` and `temporal_ordered` correlation types describe a
*window join* across multiple distinct rules: e.g. "rule A fires within
5 minutes of rule B, on the same host". LogsQL has no native primitive
for this — it is a single-stream stats engine, not a join engine.

The backend deliberately does not register `temporal` /
`temporal_ordered` in `correlation_methods`. As a result, pySigma raises
`NotImplementedError` when it tries to convert such a rule.

**Workaround:** none in-process. Implementing this correctly requires a
two-stage pipeline (issue separate searches, correlate results in the
calling layer), which is out of scope for a query-shape backend. The unit
test `test_temporal_correlation_not_supported` pins the
`NotImplementedError` so the limitation is documented in the test suite.

## `-search.maxQueryLen` ceiling

VictoriaLogs caps the maximum query string length at the value of the
`-search.maxQueryLen` startup flag, which **defaults to 16384 bytes**.
Seven SigmaHQ rules currently emit queries that exceed this default —
bulk IOC blocklists (driver-load hash lists; ~277 KB worst case) and
emoji-glyph alternations (~22–30 KB):

- `windows/driver_load/driver_load_win_vuln_drivers.yml` (~277 KB)
- `windows/driver_load/driver_load_win_mal_drivers.yml` (~50 KB)
- `windows/process_creation/proc_creation_win_susp_emoji_usage_in_cli_{1..4}.yml` (~22–30 KB each)
- `windows/image_load/image_load_side_load_from_non_system_location.yml` (~18 KB)

**Workaround:** raise the flag at VL startup if you need to deploy any of
these rules. 512 KB covers everything currently in SigmaHQ:

```bash
victoria-logs -search.maxQueryLen=524288 ...
```

The live-corpus test (`tests/test_corpus_live.py`) allowlists exactly the
seven rules above. Any *new* over-ceiling failure is treated as a
regression and surfaces in CI.

## No native single-character wildcard

Sigma uses `?` to match a single character (e.g. `cmd?.exe` matching
`cmd1.exe` and `cmda.exe`). LogsQL has no equivalent — its only wildcard
is `*` (multi-character).

**Workaround:** the backend routes any value containing `?` through the
regex template (`field:~"..."`) where `?` becomes `.`. This is automatic;
no rule changes are needed. The behaviour is pinned by the test
`test_wildcard_single_routes_to_regex`. Performance is the standard
regex-vs-native trade-off — fine for low-cardinality fields, slower than
native equality on hot hashes.

## Case-sensitivity is the default

LogsQL is case-sensitive by default, and Sigma rules are written assuming
case-sensitive matching. The `eq_token` is `:=` (case-sensitive
equality); there is no case-insensitive override at the equality layer.

**Workaround:** Sigma's `|i` modifier on regex (`field|re|i: pattern`) is
honored — the backend emits `(?i)` as a regex flag prefix. For
case-insensitive equality, switch the rule to use the regex form, or
preprocess the field through a pipeline that lowercases values at ingest.

## YAML safe_load assumption

The backend reads Sigma YAML through pySigma, which uses `yaml.safe_load`
under the hood. We rely on this for the threat model in `SECURITY.md`:
hostile YAML rules cannot execute arbitrary Python objects. If you embed
this backend in a system that bypasses pySigma's loader and feeds raw
constructs directly, you are responsible for sanitising them.

## Field names with non-ASCII characters

The backend quotes any field name that does not match
`^[A-Za-z_][A-Za-z0-9_.]*$`. Inside a double-quoted name, `"` and `\` are
backslash-escaped; everything else (including whitespace, unicode, and
punctuation other than backtick) survives verbatim. This is consistent
with LogsQL's parser as of `victoriametrics/victoria-logs:v1.50.0` on
2026-04-28.

If you discover a field-name shape that the backend mis-quotes, please
file a bug with the rule YAML and the parser error from VL.

## What works for VictoriaLogs may differ from VictoriaMetrics

LogsQL is the query language for **VictoriaLogs only**. VictoriaMetrics
(the metrics product) speaks MetricsQL, which is incompatible. This
backend will not produce queries that run against a VictoriaMetrics
instance.
