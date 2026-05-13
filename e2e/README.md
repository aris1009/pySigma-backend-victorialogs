# e2e harness

Two end-to-end harnesses live in this directory:

1. **Windows EventLog correctness** — `tests/e2e/test_windows_eventlog_e2e.py`.
   Pulls real attack telemetry from
   [OTRF Security-Datasets][otrf], runs it through Vector to remap into
   the Winlogbeat / Vector ECS layout, and asserts that converted Sigma
   rules find the expected events. Driven by `make e2e`.
2. **vmalert end-to-end** — `tests/e2e/test_vmalert_e2e.py`. Runs vmalert
   against VL with a rule group built from `sigma convert -t victorialogs
   -f vmalert`, ingests synthetic events, and asserts the alert fires
   (or — for the negative case — does not). Driven by `make vmalert`.

[otrf]: https://github.com/OTRF/Security-Datasets

The compose stack at `e2e/docker-compose.yml` backs three profiles:

| Profile | Command | Services | Used by |
| --- | --- | --- | --- |
| (default) | `make live-up` | victorialogs | parse-only dev loop |
| `e2e` | `make e2e-up` | victorialogs + vector | Windows EventLog harness |
| `vmalert` | `make vmalert-up` | victorialogs + vmalert | vmalert harness |

## Datasets manifest (`datasets.yml`)

Every dataset the harness consumes is declared in `e2e/datasets.yml` and
materialised by `make e2e-fetch` (which delegates to
`dev/fetch_datasets.py`). The fetcher pins each entry by sha256 and fails
closed on any mismatch.

Two source kinds are supported:

### `source: otrf | evtx-samples` — pinned-URL download

```yaml
- name: otrf_cmd_sharpview_pcre_net
  source: otrf
  url: https://raw.githubusercontent.com/OTRF/Security-Datasets/<commit>/.../cmd_sharpview_pcre_net.zip
  sha256: 314b1d08...
  archive: zip
  target: otrf/cmd_sharpview_pcre_net.json
  description: |
    SharpView discovery tool execution. ...
```

The fetcher downloads, sha256-verifies, and extracts the named JSON
member into `e2e/datasets/<target>`. The download is cached under
`e2e/.cache/` so re-runs are no-ops on a verified target.

### `source: synthetic` — deterministic generator output

```yaml
- name: synth_caddy_seed_smoke
  source: synthetic
  generator: caddy
  seed: 42
  count: 200
  sha256: 3f7c9ba0...
  target: synth/caddy_seed_smoke.ndjson
  description: |
    200-event Caddy v2 access-log smoke dataset. ...
```

The fetcher invokes `dev.synth.GENERATORS[<generator>](<seed>, <count>)`,
serialises the events as NDJSON, sha256-verifies the output bytes against
the manifest, and writes them to `e2e/datasets/<target>`. No network.

## Synthetic generator framework (`dev/synth/`)

Why synthetic? OTRF gives us authentic Windows attack telemetry, but the
four non-Windows pipelines (Caddy, journald, podman, Suricata) cannot
ship real homelab logs (privacy — see `CONTRIBUTING.md` Gate A). Public
fixtures exist for some sources but not in shapes that satisfy our
expectations contract end-to-end.

### Determinism

A given `(generator, seed, count)` triple yields **byte-identical**
NDJSON on every machine and every supported Python version:

* All randomness flows through one `random.Random(seed)` per run.
* Event `_time` stamps derive from a fixed baseline (2026-01-01T00:00:00Z)
  + per-event offset, never the wall clock.
* JSON serialisation is `sort_keys=True`, no ASCII escaping, fixed
  separators, `\n` line terminator, UTF-8 encoding.

The fetcher's sha256 verification covers the full output bytes, so any
non-determinism (including a generator change) trips the gate on the
next CI run. Re-pin via `make e2e-fetch-pin`.

### Privacy by construction

Every identifying value (IP, hostname, domain, username, container name,
container image, user-agent string) emitted by any generator originates
in `dev/synth/_vocab.py` — the trust-root vocabulary module — and only
there. The leak guarantee is "review the vocab module once, trust the
generator math" rather than scanning generator output on every PR.

The current vocab is RFC-clean:

* RFC 5737 IPv4 documentation (`192.0.2.0/24`, `198.51.100.0/24`,
  `203.0.113.0/24`).
* RFC 1918 IPv4 private (`10/8`, `172.16/12`, `192.168/16`) — only when
  a rule explicitly wants the "internal network" shape.
* RFC 3849 IPv6 documentation (`2001:db8::/32`).
* RFC 2606 reserved TLDs and domains (`.example`, `.test`, `.invalid`,
  `example.com|net|org`).
* The cryptography "alphabet alice" username pool — universally
  understood as fictional.

Two enforcement mechanisms keep the trust model honest:

* `.github/CODEOWNERS` requires owner review for any change under
  `dev/synth/` — including the vocab module itself.
* `tests/test_synth_determinism.py` asserts each generator with
  `seed=42` produces byte-identical output across two consecutive runs.
  Any nondeterminism implies an unpinned source of values (a generator
  reading env vars, the wall clock, files outside `dev/synth/`, or a
  third-party faker), which would defeat vocab-only review.

### Adding a generator

1. Drop `dev/synth/<name>.py` exposing `def generate(seed: int, count:
   int) -> Iterator[dict[str, Any]]` (see `caddy.py` for the canonical
   shape).
2. Register it in `dev/synth/__init__.py`'s `GENERATORS` mapping.
3. Add tests under `tests/test_synth.py` that assert count and the
   field shape that the matching `victorialogs_<name>` pipeline maps
   onto. Determinism is auto-asserted by `tests/test_synth_determinism.py`
   for every generator registered in `GENERATORS`.
4. Add at least one synthetic dataset entry to `e2e/datasets.yml` and
   run `make e2e-fetch-pin` to write back the sha256.

### CLI

```bash
python -m dev.synth caddy --seed=42 --count=1000 --out=./caddy.ndjson
```

Used standalone for ad-hoc data generation. The fetcher invokes the
same code path internally for `source: synthetic` entries.

## Running the harnesses

### Windows EventLog correctness

```bash
git clone --depth=1 https://github.com/SigmaHQ/sigma /tmp/sigma-rules
export SIGMA_CORPUS_PATH=/tmp/sigma-rules
make e2e-fetch    # idempotent; cached under e2e/.cache/
make e2e          # one-shot: e2e-up + e2e-test + e2e-down
```

CI: nightly (03:00 UTC on `main`) via `.github/workflows/e2e.yml`.

### vmalert

```bash
make vmalert      # one-shot: vmalert-up + vmalert-test + vmalert-down
```

The harness writes its rule-group YAML to `e2e/vmalert-rules/sigma.yaml`
on the host (mounted into the vmalert container at `/rules`). The file
is `.gitignore`d.
