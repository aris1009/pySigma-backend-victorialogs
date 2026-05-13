# Contributing

Thanks for your interest! This backend is small and the bar to land a PR
is low — we ask for green tests, a clean lint, and a Conventional Commit
title.

## Dev setup

```bash
git clone https://github.com/aris1009/pySigma-backend-victorialogs
cd pySigma-backend-victorialogs
poetry install

# Optional: install pre-commit hooks
poetry run pre-commit install
```

You will need Python 3.10 or newer.

## Branch model

- `main` is always green and is the only long-lived branch.
- Feature/fix work happens on a topic branch off `main`. Open a PR back
  to `main` when ready.
- Releases are cut automatically by [release-please][rp]; do not tag or
  push releases by hand.

[rp]: https://github.com/googleapis/release-please

## The dev loop

```bash
make test-fast       # unit + fuzz, ~2 seconds
make lint            # ruff check + ruff format --check + mypy strict
make audit           # radon cc, vulture, interrogate
make test            # full suite + 95% coverage gate
```

Bring up a local VictoriaLogs via the bundled compose file and run the
live tests against it. No homelab or external VL needed:

```bash
make live-up         # docker compose: VL only, blocks until /health=OK
make live            # curated live-VL smoke tests (defaults to localhost:9428)
make live-down       # tear down

# For the full SigmaHQ corpus, clone it once and point at it:
export SIGMA_CORPUS_PATH=/path/to/sigma
make corpus          # corpus conversion only
make corpus-live     # full corpus, every query asserted HTTP 200
```

`make live` and `make corpus-live` default `VICTORIALOGS_URL` to
`http://localhost:9428` (the compose VL). Override the env var only if
you need to run the suite against a different instance.

### End-to-end harness — fast lane vs nightly

The e2e suite is split between two CI workflows:

```bash
make e2e-fetch       # materialise / sha256-verify all datasets
make live-up         # VL only (no Vector, no vmalert)
make e2e-test-synth  # caddy / journald / podman / suricata only — <60s
make live-down

# Or the full thing (requires Vector + OTRF + vmalert):
make e2e             # one-shot up + every harness + down
```

`e2e-fast.yml` runs the synthetic subset on every PR. `e2e-nightly.yml`
runs the full set (Windows EventLog via OTRF + Vector + vmalert) once
a day at 03:00 UTC. A regression that breaks ingest now surfaces at PR
time rather than overnight.

## Conventional Commits — required

PR titles **must** follow [Conventional Commits][cc]:

```
<type>(<scope>): <short summary>
```

`release-please` uses the type to derive the next semver bump (`fix:` →
patch, `feat:` → minor, `feat!:` or a `BREAKING CHANGE:` footer →
major). A non-conforming title means the release notes will be wrong.

Allowed types in this repo:

- `feat` — user-visible new behaviour (bumps minor)
- `fix` — bug fix (bumps patch)
- `docs` — documentation only
- `test` — tests only
- `refactor` — internal change, no behaviour delta
- `chore` — repo plumbing, dependencies, CI
- `build` — build system or packaging

Common scopes: `backend`, `pipeline`, `repo`, `community`, `dev`,
`docs`, `test`, `corpus`.

[cc]: https://www.conventionalcommits.org/

## PR checklist

Before requesting review:

- [ ] PR title follows Conventional Commits (see above).
- [ ] `make lint && make test-fast` is green locally.
- [ ] If LogsQL output changed: `docs/mapping.md` updated.
- [ ] If a new public-facing edge case was found: a unit test pins it.
- [ ] No homelab IPs, internal hostnames, or personal artefacts
      introduced (the public tree is scrubbed — see Gate A).

## What kind of changes are welcome?

- **Bug fixes for LogsQL emission.** Open a bug from the issue
  template; include the rule YAML, expected LogsQL, and actual LogsQL.
- **New Sigma feature support.** Open a feature request from the issue
  template; describe the target LogsQL shape and rationale.
- **Pipelines.** Field-mapping pipelines for specific log sources
  (Windows Event Log, sysmon, journald, etc.) live under
  `sigma/pipelines/victorialogs/`. New pipelines are very welcome.
- **Tests and docs.** Always.

## What is out of scope?

- Anything that would break Sigma compatibility (i.e. require Sigma rule
  changes specific to this backend) — file an upstream pySigma issue
  instead.
- `temporal` / `temporal_ordered` correlations. LogsQL has no native
  multi-event window join. See [docs/limitations.md](docs/limitations.md).

## Bumping the pinned container images

CI and the e2e stack pin every container image by **tag and sha256
digest** for reproducibility and supply-chain hygiene. A floating tag
would let an upstream rebuild flip the suite red without any code
change here.

Pinned images:

- `victoriametrics/victoria-logs` — referenced in
  `.github/workflows/test.yml` (CI corpus-live job),
  `e2e/docker-compose.yml`, `docs/getting_started.md`, `README.md`,
  and `docs/limitations.md`.
- `timberio/vector` — referenced in `e2e/docker-compose.yml`.
- `victoriametrics/vmalert` — referenced in `e2e/docker-compose.yml`
  (vmalert profile, used by `make vmalert`).

To bump either image:

```bash
# 1. Pull the new tag and read the index digest.
docker pull <repo>:<tag>
docker inspect --format '{{index .RepoDigests 0}}' <repo>:<tag>
# → docker.io/<repo>@sha256:<digest>

# 2. Replace the old tag@sha256:... reference in all listed files.
#    grep -rn '<repo>:' .

# 3. Commit (Conventional Commits):
#    chore(deps): bump <repo> to <new-tag>

# 4. Open a PR. CI must be green on the new pinned digest before merge.
```

Automation (dependabot / renovate for digest bumps) is in scope for a
follow-up; manual bumps are the rule today.

## Code of Conduct

This project adopts the [Contributor Covenant 2.1](CODE_OF_CONDUCT.md).
By participating you agree to abide by its terms.
