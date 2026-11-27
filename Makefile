.DEFAULT_GOAL := help
.DELETE_ON_ERROR:

SHELL := /usr/bin/env bash
UV ?= uv
PYTEST_ARGS ?=

.PHONY: help install install-all doctor test test-integration coverage \
        lint format type check docs docs-serve build clean

help: ## Show available make targets
	@awk 'BEGIN {FS = ":.*## "; printf "Usage:\n  make <target>\n"} /^##@/ { printf "\n%s\n", substr($$0, 5) } /^[a-zA-Z0-9_-]+:.*## / { printf "  %-18s %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

##@ Setup

install: ## Install runtime and development dependencies
	$(UV) sync

install-all: ## Install all optional extras and dependency groups
	$(UV) sync --all-extras --all-groups

doctor: ## Verify environment, tools, dependencies, and auth status
	@$(UV) --version
	@$(UV) run --no-sync python -c '\
import importlib, importlib.metadata as im, sys; \
pkgs = {(d.metadata["Name"] or "").lower().replace("_", "-"): d.version for d in im.distributions()}; \
fmt = lambda names: ", ".join(p + " " + pkgs.get(p, "not installed") for p in names); \
print("Python    " + sys.version.split()[0] + " (" + sys.executable + ")"); \
print("pwned     " + pkgs.get("pwned", "not installed")); \
print("Core      " + fmt(("click", "httpx", "pydantic", "pydantic-settings"))); \
print("Extras    " + fmt(("pykeepass", "keyring", "cryptography", "zxcvbn"))); \
print("Dev/Docs  " + fmt(("pytest", "ruff", "mypy", "mkdocs-material"))); \
print("API key   " + (importlib.import_module("pwned.config").get_api_key_source() if "pwned" in pkgs else "unavailable (run make install)"))'

##@ Testing

test: ## Run unit tests (excludes live integration tests)
	$(UV) run pytest $(PYTEST_ARGS)

test-integration: ## Run live HIBP API integration tests
	$(UV) run pytest -m integration tests/integration $(PYTEST_ARGS)

coverage: ## Run unit tests with branch coverage report
	$(UV) run pytest --cov=pwned --cov-branch --cov-report=term-missing $(PYTEST_ARGS)

##@ Quality

lint: ## Check code style and formatting with ruff
	$(UV) run ruff check src tests
	$(UV) run ruff format --check src tests

format: ## Auto-fix lint issues and format code with ruff
	$(UV) run ruff check --fix src tests
	$(UV) run ruff format src tests

type: ## Run mypy strict type checking
	$(UV) run mypy

check: lint type test ## Run lint, type checking, and unit tests (CI-safe)

##@ Docs & Packaging

docs: ## Build MkDocs Material site with strict validation
	$(UV) run --group docs mkdocs build --strict

docs-serve: ## Serve MkDocs Material site locally with live reload
	$(UV) run --group docs mkdocs serve

build: ## Build sdist and wheel distributions
	$(UV) build

clean: ## Remove build, test, docs, and cache artifacts
	rm -rf dist build site htmlcov .coverage .pytest_cache .mypy_cache .ruff_cache src/*.egg-info
