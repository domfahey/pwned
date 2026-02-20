# CLAUDE.md

## Commands

```bash
make install          # Set up venv and install deps
make doctor           # Verify environment and dependencies
make test             # Run all tests
make test-unit        # Run unit tests only
make test-integration # Run integration tests (hits live API)
make lint             # Check code with ruff
make format           # Auto-fix lint issues and format
make type             # Run mypy strict type checking
make check            # Run format + lint + type + test (all-in-one)
```

## Dependencies

Uses **uv** for package management (not pip/poetry).

## Architecture

```
src/pwned/
├── cli.py          # Click commands and output formatting
├── client.py       # HIBP API client (haveibeenpwned.com/api/v3)
├── passwords.py    # Pwned Passwords client (api.pwnedpasswords.com) — separate API, no auth
├── config.py       # pydantic-settings configuration with HIBP_ env prefix
└── models.py       # Pydantic models for API responses
```

Two separate HTTP clients: `HIBPClient` (main API, auth required for most endpoints) and
`PwnedPasswordsClient` (password range API, no auth, uses k-anonymity).

## Code Conventions

- Pydantic models use **PascalCase aliases** matching the HIBP API JSON fields (e.g., `Field(alias="PwnCount")`).
  Serialization uses `by_alias=True` to preserve API field names.
- `src/` layout — imports are `from pwned.xxx import ...` (not `from src.pwned`).
- Strict mypy (`mypy --strict`). Ruff rules: E, F, I, N, UP, B, SIM, S. Line length 100.

## Testing

- Unit tests use **pytest-httpx** for HTTP mocking and **click.testing.CliRunner** for CLI tests.
- Integration tests are marked `@pytest.mark.integration` and excluded by default.
  Run with `make test-integration`. They use the HIBP test API key (`00000000000000000000000000000000`)
  and test accounts on `hibp-integration-tests.com`.

## Configuration

Settings are loaded via pydantic-settings with env prefix `HIBP_`:
- `HIBP_API_KEY` — required for authenticated endpoints
- `HIBP_USER_AGENT` — custom User-Agent (default: `pwned-cli`)
- `.env` file is auto-loaded (copy `.env.sample` to `.env`)
