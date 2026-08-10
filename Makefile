# DEEP-TRACE — common development commands
#
# Usage:
#   make help          — show this help
#   make install       — install dependencies
#   make test          — run the test suite
#   make lint          — run ruff + black (if installed)
#   make verify        — exercise every engine without needing the DB
#   make compose-up    — bring up the full stack
#   make compose-down  — tear it down
#   make logs          — tail the API logs
#   make db-shell      — open a psql shell in the dev DB
#   make clean         — remove build artifacts

SHELL := pwsh
PYTHON ?= python
PIP ?= pip
DOCKER_COMPOSE ?= docker compose

.DEFAULT_GOAL := help

.PHONY: help
help:
	@echo "DEEP-TRACE — available targets:"
	@echo "  install       Install Python dependencies"
	@echo "  test          Run pytest"
	@echo "  unit          Run unit tests only"
	@echo "  integration   Run integration tests only"
	@echo "  lint          Run ruff check + black --check"
	@echo "  format        Auto-format with black + ruff --fix"
	@echo "  verify        Self-test every engine (no DB needed)"
	@echo "  compose-up    Start Postgres + API via docker compose"
	@echo "  compose-down  Stop the stack"
	@echo "  compose-build Rebuild the API image"
	@echo "  logs          Tail the API container logs"
	@echo "  db-shell      Open a psql shell in the dev DB"
	@echo "  clean         Remove __pycache__, .pyc, .pytest_cache"

.PHONY: install
install:
	$(PIP) install -r requirements.txt
	$(PIP) install aiosqlite httpx pytest pytest-asyncio ruff black

.PHONY: test
test:
	$(PYTHON) -m pytest tests/ -v

.PHONY: unit
unit:
	$(PYTHON) -m pytest tests/unit/ -v

.PHONY: integration
integration:
	$(PYTHON) -m pytest tests/integration/ -v

.PHONY: lint
lint:
	ruff check app tests
	black --check app tests

.PHONY: format
format:
	ruff check --fix app tests
	black app tests

.PHONY: verify
verify:
	$(PYTHON) scripts/verify_installation.py

.PHONY: compose-up
compose-up:
	$(DOCKER_COMPOSE) up -d --build
	@echo "Waiting for API to become healthy…"
	$(DOCKER_COMPOSE) ps
	@echo ""
	@echo "API:    http://localhost:8000"
	@echo "Docs:   http://localhost:8000/docs"

.PHONY: compose-down
compose-down:
	$(DOCKER_COMPOSE) down

.PHONY: compose-build
compose-build:
	$(DOCKER_COMPOSE) build api

.PHONY: logs
logs:
	$(DOCKER_COMPOSE) logs -f api

.PHONY: db-shell
db-shell:
	$(DOCKER_COMPOSE) exec db psql -U postgres -d deeptrace

.PHONY: clean
clean:
	Get-ChildItem -Path . -Recurse -Directory -Filter __pycache__ -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force
	Get-ChildItem -Path . -Recurse -Filter .pytest_cache -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force
	Get-ChildItem -Path . -Recurse -Filter .ruff_cache -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force
	Get-ChildItem -Path . -Recurse -Filter .mypy_cache -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force
	Get-ChildItem -Path . -Recurse -Filter *.pyc -ErrorAction SilentlyContinue | Remove-Item -Force
	@echo "Cleaned."
