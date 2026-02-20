.PHONY: install doctor test test-unit test-integration lint format type check

install:
	uv sync --all-extras

doctor:
	uv run python --version
	uv run python -c "from importlib.metadata import version; print(f'click {version(\"click\")}')"
	uv run python -c "from importlib.metadata import version; print(f'httpx {version(\"httpx\")}')"
	uv run python -c "from importlib.metadata import version; print(f'pydantic {version(\"pydantic\")}')"
	uv run python -c "from importlib.metadata import version; print(f'pydantic-settings {version(\"pydantic-settings\")}')"

test:
	uv run pytest

test-unit:
	uv run pytest tests/unit

test-integration:
	uv run pytest -m integration -o "addopts=" tests/integration

lint:
	uv run ruff check src tests
	uv run ruff format --check src tests

format:
	uv run ruff check --fix src tests
	uv run ruff format src tests

type:
	uv run mypy

check: format lint type test
