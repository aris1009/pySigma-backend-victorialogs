.PHONY: install test test-fast cov lint format check audit live live-up live-down corpus corpus-live cli-itest all clean e2e e2e-up e2e-down e2e-test e2e-test-synth e2e-fetch e2e-fetch-pin vmalert vmalert-up vmalert-down vmalert-test

# Reproducible-anywhere VL stack. The same compose file backs the
# parse-only dev loop (`make live-up` -> VL only), the full Windows e2e
# harness (`make e2e-up` -> VL + Vector, gated behind the "e2e" profile),
# and the vmalert e2e harness (`make vmalert-up` -> VL + vmalert, gated
# behind the "vmalert" profile).
E2E_COMPOSE         := docker compose -f e2e/docker-compose.yml
E2E_COMPOSE_FULL    := docker compose -f e2e/docker-compose.yml --profile e2e
E2E_COMPOSE_VMALERT := docker compose -f e2e/docker-compose.yml --profile vmalert
E2E_VL_URL          := http://localhost:9428
VMALERT_URL         := http://localhost:8880

install:
	poetry install

# Default unit + fuzz suite — fast, no network or corpus.
test-fast:
	poetry run pytest tests/test_backend_victorialogs.py tests/test_backend_grafana_alerting.py tests/test_escape_fuzz.py

# Unit + fuzz + corpus + (if env set) live VL. Enforces the 95% coverage gate.
test:
	poetry run pytest tests/ --cov-fail-under=95

# Coverage report on stdout. Same gate as `make test`.
cov:
	poetry run pytest tests/ --cov-report=term-missing --cov-fail-under=95

lint:
	poetry run ruff check sigma tests dev
	poetry run ruff format --check sigma tests dev
	poetry run mypy

format:
	poetry run ruff check --fix sigma tests dev
	poetry run ruff format sigma tests dev

# Pre-commit-grade local verification: lint + fast tests.
check: lint test-fast

# Code-health audit gate: cyclomatic complexity, dead code, docstring coverage.
# Tighten thresholds here as the codebase matures.
audit:
	poetry run ruff check --select C90 sigma
	poetry run vulture sigma --min-confidence 80

# Run the corpus integration test (requires SigmaHQ rules cloned locally).
corpus:
	@test -n "$$SIGMA_CORPUS_PATH" || (echo "set SIGMA_CORPUS_PATH=/path/to/sigma" && exit 2)
	poetry run pytest tests/test_corpus.py -s

# Run the corpus + live VL integration test — every emitted query is sent to
# the configured VL instance and asserted to parse. Defaults to the local
# compose VL at http://localhost:9428; run `make live-up` first.
corpus-live:
	@test -n "$$SIGMA_CORPUS_PATH" || (echo "set SIGMA_CORPUS_PATH=/path/to/sigma" && exit 2)
	@if [ -z "$$VICTORIALOGS_URL" ]; then \
		echo "VICTORIALOGS_URL unset — defaulting to $(E2E_VL_URL). Run 'make live-up' first if not already running."; \
	fi
	VICTORIALOGS_URL=$${VICTORIALOGS_URL:-$(E2E_VL_URL)} poetry run pytest tests/test_corpus_live.py -v -s

# Bring up VL only (no Vector, no datasets). Parse-only dev loop entrypoint.
live-up:
	$(E2E_COMPOSE) up -d victorialogs
	@echo "Waiting for VictoriaLogs at $(E2E_VL_URL)/health ..."
	@for i in $$(seq 1 60); do \
		if curl -sf $(E2E_VL_URL)/health >/dev/null 2>&1; then \
			echo "VictoriaLogs is healthy."; \
			exit 0; \
		fi; \
		sleep 1; \
	done; \
	echo "VictoriaLogs did not become healthy within 60s." >&2; \
	$(E2E_COMPOSE) logs victorialogs >&2; \
	exit 1

# Tear down the parse-only stack (and any e2e services on the same compose).
live-down:
	$(E2E_COMPOSE_FULL) down -v

# Run the live-VictoriaLogs integration tests (read-only). Defaults to the
# local compose VL at http://localhost:9428; run `make live-up` first.
live:
	@if [ -z "$$VICTORIALOGS_URL" ]; then \
		echo "VICTORIALOGS_URL unset — defaulting to $(E2E_VL_URL). Run 'make live-up' first if not already running."; \
	fi
	VICTORIALOGS_URL=$${VICTORIALOGS_URL:-$(E2E_VL_URL)} poetry run pytest tests/test_live_victorialogs.py tests/test_redos_re2.py -v

# End-to-end packaging round-trip via the sigma CLI in a throwaway venv.
# Catches packaging regressions (missing files in the wheel, broken
# entry-point declarations) the Python suite cannot see.
cli-itest:
	bash tests/test_sigma_cli_integration.sh

# Everything CI would run.
all: lint test

clean:
	rm -rf .pytest_cache .ruff_cache .mypy_cache .coverage cov.xml
	find . -type d -name __pycache__ -prune -exec rm -rf {} +

# ----- E2E harness -----

# Materialise every dataset in e2e/datasets.yml under e2e/datasets/. Cached
# on disk in e2e/.cache/; CI keys actions/cache on hash(e2e/datasets.yml).
e2e-fetch:
	poetry run python dev/fetch_datasets.py

# Maintenance: compute and write back sha256 for any new manifest entries
# that were committed without a sha. Commit the result.
e2e-fetch-pin:
	poetry run python dev/fetch_datasets.py --pin


# Bring the VL+Vector stack up, then block until VL /health returns OK.
e2e-up:
	$(E2E_COMPOSE_FULL) up -d
	@echo "Waiting for VictoriaLogs at $(E2E_VL_URL)/health ..."
	@for i in $$(seq 1 60); do \
		if curl -sf $(E2E_VL_URL)/health >/dev/null 2>&1; then \
			echo "VictoriaLogs is healthy."; \
			exit 0; \
		fi; \
		sleep 1; \
	done; \
	echo "VictoriaLogs did not become healthy within 60s." >&2; \
	$(E2E_COMPOSE_FULL) logs victorialogs >&2; \
	exit 1

# Tear down and remove the data volume so each run is from a clean slate.
e2e-down:
	$(E2E_COMPOSE_FULL) down -v

# Run the e2e pytest suite against the running stack.
e2e-test:
	VL_E2E_URL=$(E2E_VL_URL) poetry run pytest tests/e2e -m e2e -v

# Synthetic-only e2e subset for the per-PR fast lane.
# Skips the Windows EventLog harness (needs Vector + OTRF dataset) and
# the vmalert harness — both run nightly. Target wall-time: <60s after
# venv + dataset cache warm-up.
e2e-test-synth:
	VL_E2E_URL=$(E2E_VL_URL) poetry run pytest \
	    tests/e2e/test_caddy_e2e.py \
	    tests/e2e/test_journald_e2e.py \
	    tests/e2e/test_podman_e2e.py \
	    tests/e2e/test_suricata_e2e.py \
	    -m e2e -v

# Full one-shot cycle for CI: up -> test -> down (down runs even on failure).
e2e: e2e-up
	@$(MAKE) e2e-test; rc=$$?; $(MAKE) e2e-down; exit $$rc

# ----- vmalert e2e harness -----

# Bring up VL + vmalert. Synthetic data is POSTed directly to VL by the
# test (Vector is not started — synthetic shape is already pipeline-target).
vmalert-up:
	$(E2E_COMPOSE_VMALERT) up -d
	@echo "Waiting for VictoriaLogs at $(E2E_VL_URL)/health ..."
	@for i in $$(seq 1 60); do \
		if curl -sf $(E2E_VL_URL)/health >/dev/null 2>&1; then \
			echo "VictoriaLogs is healthy."; \
			break; \
		fi; \
		sleep 1; \
	done
	@echo "Waiting for vmalert at $(VMALERT_URL)/health ..."
	@for i in $$(seq 1 60); do \
		if curl -sf $(VMALERT_URL)/health >/dev/null 2>&1; then \
			echo "vmalert is healthy."; \
			exit 0; \
		fi; \
		sleep 1; \
	done; \
	echo "vmalert did not become healthy within 60s." >&2; \
	$(E2E_COMPOSE_VMALERT) logs vmalert >&2; \
	exit 1

vmalert-down:
	$(E2E_COMPOSE_VMALERT) down -v

vmalert-test:
	VL_E2E_URL=$(E2E_VL_URL) VMALERT_URL=$(VMALERT_URL) \
		poetry run pytest tests/e2e/test_vmalert_e2e.py -m vmalert -v

vmalert: vmalert-up
	@$(MAKE) vmalert-test; rc=$$?; $(MAKE) vmalert-down; exit $$rc
