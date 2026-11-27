.PHONY: install doctor test test-integration coverage lint format type check docs docs-serve

install:
	uv sync

doctor:
	uv run python -c "import sys; from importlib.metadata import version; print(f'Python {sys.version.split()[0]}'); print('\n'.join(f'{p} {version(p)}' for p in ('click', 'httpx', 'pydantic', 'pydantic-settings')))"

test:
	uv run pytest

test-integration:
	uv run pytest -m integration tests/integration

coverage:
	uv run pytest --cov=pwned --cov-report=term-missing

lint:
	uv run ruff check src tests
	uv run ruff format --check src tests

format:
	uv run ruff check --fix src tests
	uv run ruff format src tests

type:
	uv run mypy

check: lint type test

docs:
	uv run --group docs mkdocs build --strict

docs-serve:
	uv run --group docs mkdocs serve
