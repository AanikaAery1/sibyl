PGBIN ?= /opt/homebrew/opt/postgresql@17/bin
PGDATA ?= $(HOME)/.local/share/sibyl/pg17
PGPORT ?= 5433
export UV_SYSTEM_CERTS = 1
export SIBYL_PG_ADMIN_DSN ?= postgresql://postgres@localhost:$(PGPORT)/postgres

# Two ways to run Sibyl (D55, docs/setup/SETUP.md):
#   make demo         console only, demo data and a scripted scenario (Node only, no Docker)
#   make demo-stack   the full stack in Docker, seeded with the simulator's demo world
#   make up           the REAL deployment for your agents (no simulator), first-run bootstrap
REAL := bash deploy/compose/real.sh
DEMO_COMPOSE := docker compose -f deploy/compose/docker-compose.yml --env-file deploy/compose/.env --profile sim
# make key NAME=my-agent [KIND=sdk|gateway] [AGENT=slug] [DAYS=90]
KIND ?= sdk

.PHONY: help sync db-up db-down lint type test contracts check ci worktree \
	demo demo-dev demo-stack demo-stack-down up down logs status key password ca

help:
	@sed -n '6,10p' Makefile | sed 's/^# \{0,1\}//'
	@echo "  make status | logs | down [PURGE=1] | key NAME=.. | password | ca   (real deployment)"
	@echo "  make sync | db-up | check | ci                                      (development)"

# --- demo ---------------------------------------------------------------------------------------
demo:
	bash ops/demo/console.sh

demo-dev:
	bash ops/demo/console.sh --dev

demo-stack:
	bash ops/demo/up.sh
	$(DEMO_COMPOSE) run --rm --no-deps -T api python -m sibyl_control.cli seed --sim-host sim

demo-stack-down:
	bash ops/demo/down.sh

# --- real deployment ----------------------------------------------------------------------------
up:
	$(REAL) up

down:
	$(REAL) down $(if $(PURGE),--purge)

logs:
	$(REAL) logs

status:
	$(REAL) status

key:
	$(REAL) key --name "$(NAME)" --kind "$(KIND)" $(if $(AGENT),--agent "$(AGENT)") $(if $(DAYS),--days "$(DAYS)")

password:
	@$(REAL) password

ca:
	$(REAL) ca

# --- development --------------------------------------------------------------------------------
sync:
	uv sync --all-packages

db-up:
	@test -d $(PGDATA) || $(PGBIN)/initdb -D $(PGDATA) -U postgres --auth=trust -E UTF8 --locale=C
	@$(PGBIN)/pg_ctl -D $(PGDATA) status >/dev/null 2>&1 || $(PGBIN)/pg_ctl -D $(PGDATA) -o "-p $(PGPORT) -k /tmp" -l $(PGDATA)/../pg17.log start

db-down:
	$(PGBIN)/pg_ctl -D $(PGDATA) stop

lint:
	uv run ruff check .
	uv run ruff format --check .

type:
	uv run mypy packages/sibyl-schemas/src packages/sibyl-sdk/src services/control/src services/gateway/src sibyl-sim/src

contracts:
	uv run lint-imports

test:
	uv run pytest -q

check: lint contracts test

ci:
	bash ci/run.sh

worktree:
	bash ci/worktree.sh $(LANE) $(SLOT)
