# Getting Started

This guide walks a first-time user through installing the backend,
converting a Sigma rule to LogsQL, and running it against a local
VictoriaLogs instance.

It assumes you have:

- A working Python 3.10+ installation.
- Docker (for the throwaway VictoriaLogs container in step 2).
- One or more [Sigma rules](https://github.com/SigmaHQ/sigma) you want to
  convert.

## 1. Install the backend

The recommended path is via `sigma-cli`'s plugin system, which handles the
backend dependency for you:

```bash
pip install sigma-cli
sigma plugin install victorialogs
```

If you prefer to install the package directly (e.g. for use as a Python
library):

```bash
pip install pysigma-backend-victorialogs
```

Verify the install:

```bash
sigma list backends | grep victorialogs
```

You should see `victorialogs` listed alongside any other backends.

## 2. Spin up a local VictoriaLogs

A throwaway single-node container is enough to test queries end to end:

```bash
docker run --rm -d --name vl \
  -p 9428:9428 \
  victoriametrics/victoria-logs:v1.50.0@sha256:ae9bea8d8a3b0fc47c7f0058bcca410e79c84b4a0acd12d4dac71b9302526590
```

Verify it is up:

```bash
curl -s http://localhost:9428/health   # → "OK"
```

For larger SigmaHQ rules (bulk IOC blocklists, emoji alternations) you
will need to raise the maximum query length:

```bash
docker run --rm -d --name vl \
  -p 9428:9428 \
  victoriametrics/victoria-logs:v1.50.0@sha256:ae9bea8d8a3b0fc47c7f0058bcca410e79c84b4a0acd12d4dac71b9302526590 \
  -search.maxQueryLen=524288
```

See [limitations](limitations.md#-searchmaxquerylen-ceiling) for the
seven rules that need this.

## 3. Send a test log line

Push a single JSON log line into VictoriaLogs so we have something to
match against:

```bash
curl -X POST http://localhost:9428/insert/jsonline \
  -H 'Content-Type: application/stream+json' \
  -d '{"_msg":"sshd login failure","host":"web-01","user":"admin"}'
```

## 4. Convert a Sigma rule

Grab the SigmaHQ rule corpus:

```bash
git clone --depth=1 https://github.com/SigmaHQ/sigma /tmp/sigma-rules
```

Pick a rule and convert it:

```bash
sigma convert -t victorialogs \
  /tmp/sigma-rules/rules/linux/auth/lnx_auth_susp_su_logins.yml
```

You will get a LogsQL query string back, e.g.:

```text
type:="syslog" AND program:="sudo" AND _msg:~"FAILED su"
```

## 5. Run the query

Either paste the query into the VictoriaLogs UI at
<http://localhost:9428/select/vmui>, or run it from the command line:

```bash
curl -G http://localhost:9428/select/logsql/query \
  --data-urlencode 'query=_msg:~"sshd"'
```

That's the full happy path: a Sigma rule → LogsQL → query results.

## Next steps

- [Mapping reference](mapping.md) — what every Sigma feature compiles to.
- [Limitations](limitations.md) — temporal correlations,
  `-search.maxQueryLen` ceiling, single-char wildcards.
- [Architecture](architecture.md) — how the backend works, for
  contributors.
