# Security Policy

## Reporting a vulnerability

Please report suspected vulnerabilities **privately** by emailing
**aris@ariscodes.com** with the subject line
`[security] pysigma-backend-victorialogs: <short summary>`.

Do **not** open a public GitHub issue for security reports. Once a fix is
ready I will coordinate disclosure with you, publish a patched release,
and credit you in the changelog (unless you ask not to be).

I aim to acknowledge reports within 72 hours.

## Supported versions

Until the project reaches v1.0, only the latest minor release on PyPI
receives security fixes. After v1.0 the policy will be revisited.

## Threat model

This is a **query-shape backend**: it consumes Sigma rule YAML and emits
LogsQL strings. It does not execute queries, hold credentials, or
mediate network access. The threat surface is correspondingly narrow.

### LogsQL injection via values

A Sigma rule can place arbitrary characters inside string values. The
backend escapes `\` and `"` inside `:="..."` quoted values
(`convert_value_str`) and routes any wildcard-bearing or special-char
value through `wildcard_match_expression` (regex), where the LogsQL
regex layer handles its own escapes.

**What we test for**

- `tests/test_escape_fuzz.py` — Hypothesis-driven fuzz over arbitrary
  Unicode strings. Every conversion result must round-trip through the
  live VL parser without HTTP 400.
- `tests/test_corpus_live.py` — every rule in the public SigmaHQ corpus
  is converted and submitted to live VL; any new HTTP 400 fails the
  build.

### LogsQL injection via field names

Field names take a separate code path
(`field_quote_pattern_negation = True`): bare for plain identifiers,
double-quoted with `\`/`"` escaping otherwise. A dedicated field-name
fuzz strategy is a planned hardening item; pinned irregular-name
fixtures cover the current surface.

**What we test for**

- `tests/test_backend_victorialogs.py` — explicit cases for irregular
  field names (whitespace, dots, dashes, quotes).

### ReDoS via `|re:`

Sigma allows arbitrary regex via `|re:`. LogsQL is built on Go's
`regexp` package, which uses **RE2** — linear-time matching, no
catastrophic backtracking. RE2 explicitly forbids backreferences and
unbounded repetition that classical regex engines support, so a
malicious pattern from a Sigma rule cannot trigger super-linear matching
on the VL side.

**What we test for**

- `tests/test_redos_re2.py` — pinned regression against live VL. Sends
  a PCRE-pathological pattern (`(a+)+b`) and asserts a sub-second
  response, then sends a backreference pattern (`(.+)\1`) and asserts
  HTTP 400. If a future VL release silently swaps regex engines, both
  fingerprints break and the build fails.

### YAML deserialization

The backend reads Sigma YAML through `pysigma`, which uses
`yaml.safe_load`. Hostile rule YAML cannot construct arbitrary Python
objects. Callers that bypass `pysigma`'s loader and feed raw YAML
constructs directly take on this risk themselves.

### SSRF via `VICTORIALOGS_URL`

The library code itself does not make HTTP calls. Test scripts
(`dev/validate_queries.py`, `tests/test_corpus_live.py`,
`tests/test_live_victorialogs.py`) read the `VICTORIALOGS_URL`
environment variable and POST queries to it. There is **no default**;
the URL must be set explicitly in the environment.

If you embed those scripts (or their wrapping logic) into automation
that accepts user-controlled URLs, treat that integration as
SSRF-sensitive — pin the URL to a known-internal host or apply the
appropriate deny-list.

### Dependency supply chain

- `pyproject.toml` constrains direct dependencies to upper-bounded
  semver ranges.
- Dependabot watches both `pip` and `github-actions` ecosystems on a
  weekly schedule, with grouped minor/patch PRs
  (`.github/dependabot.yml`).
- `pip-audit` and CodeQL run as scheduled CI workflows. CI builds ship
  with `permissions: {}` at the workflow root and explicit per-job grants.
- Releases are cut by `release-please` and published via PyPI's OIDC
  Trusted Publisher flow — there are no long-lived API tokens stored in
  the repository.
