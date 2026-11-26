# Contributing

Contributions are welcome! Whether it's a bug fix, documentation improvement, or new feature, please follow the workflow below.

## Setup

Requires Python 3.12+ and [uv](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/domfahey/pwned.git
cd pwned
make install
make doctor
```

## Development Workflow

```bash
make check            # Run ruff lint/format check, mypy strict, and unit tests
make format           # Auto-fix lint issues and format code
make coverage         # Run unit tests with coverage report
make test-integration # Run live HIBP integration tests (requires network)
```

## Conventions

- **Formatting & linting:** Ruff (`E, F, I, N, UP, B, SIM, S`), 100-char line length.
- **Types:** `mypy --strict` must pass across both `src/` and `tests/`.
- **Models:** Pydantic v2 models use PascalCase aliases matching HIBP API JSON fields.
- **Tests:** Add unit tests (using `pytest-httpx` and `click.testing.CliRunner`) for any behavioral change. Do not rely on local `.env` files or live network calls in unit tests.
- **Commits:** Use [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `docs:`, `chore:`, etc.).

## Opening a Pull Request

1. Create a feature branch from `main`.
2. Make sure `make check` passes cleanly.
3. Open a pull request describing what changed and why.
