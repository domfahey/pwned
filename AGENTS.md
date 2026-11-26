# AGENTS.md

## Commands

```bash
make install          # Set up venv and install deps
make doctor           # Verify environment and dependencies
make test             # Run unit tests (integration excluded by default)
make test-integration # Run integration tests (hits live API)
make coverage         # Run unit tests with coverage report
make lint             # Check code with ruff
make format           # Auto-fix lint issues and format
make type             # Run mypy strict type checking
make check            # Run lint + type + test (non-mutating, CI-safe)
```

## Dependencies

Uses **uv** for package management (not pip/poetry).
All commands run through `uv run` (e.g., `uv run pytest`, `uv run mypy`). Python >=3.12 required.

## CLI Entrypoint

`pwned = "pwned.cli:cli"` — run with `uv run pwned` after install.

## Architecture

```
src/pwned/
├── __init__.py         # Public library API exports
├── _parsers.py         # Zero-dependency stdlib parsers (MD4, range response, HTML stripper, input lines)
├── async_client.py     # Async HIBP API client (`AsyncHIBPClient`)
├── audit.py            # Password manager vault auditing & reused password detection
├── baseline.py         # Exposure baseline snapshotting and diffing
├── batch.py            # Batch account/password checks with RPM rate limiting and stats
├── cache.py            # File-based TTL response caching for public endpoints
├── cli.py              # Click command groups and global option parser
├── cli_commands.py     # Additional commands (`auth`, `search`, `account-range`, `domain-verify`, `audit`, `cache`, `completion`)
├── cli_helpers.py      # CLI output rendering, error handling, and API key validation
├── client.py           # Sync HIBP API client (`HIBPClient`)
├── config.py           # pydantic-settings configuration with XDG fallback and OS Keychain backend
├── filtering.py        # Breach filtering and sorting helpers
├── formatting.py       # Output formatters (`text`, `json`, `jsonl`, `csv`, `table`, `sarif`)
├── models.py           # Pydantic v2 models for API responses
├── offline.py          # Offline sorted hash file lookups (`OfflinePasswordsClient`)
├── passwords.py        # Sync & async Pwned Passwords clients (`PwnedPasswordsClient`, `AsyncPwnedPasswordsClient`)
├── py.typed            # PEP 561 type marker
└── validators.py       # Framework password validation helpers (Pydantic / FastAPI / Django)
```

Client families and features:
- HTTP client families: `HIBPClient` / `AsyncHIBPClient` (main API, auth required for most endpoints) and `PwnedPasswordsClient` / `AsyncPwnedPasswordsClient` (password range API, no auth, uses k-anonymity).
- Offline client: `OfflinePasswordsClient` for local `O(log N)` binary search over official HIBP password hash dumps.
- Optional extras: `keepass` (`pykeepass`), `keyring` (`keyring`), `crypto` (`cryptography` for Bitwarden encrypted JSON), and `all`.

## Code Conventions

- Pydantic models use **PascalCase aliases** matching the HIBP API JSON fields (e.g., `Field(alias="PwnCount")`).
  Serialization uses `by_alias=True` to preserve API field names.
- `src/` layout — imports are `from pwned.xxx import ...` (not `from src.pwned`).
- Strict mypy (`mypy --strict`). Ruff rules: E, F, I, N, UP, B, SIM, S. Line length 100.
- Tests allow `assert` (`S101`), hardcoded passwords (`S106`), and insecure hash (`S324`) via ruff per-file-ignores.

## Testing

- Unit tests use **pytest-httpx** for HTTP mocking and **click.testing.CliRunner** for CLI tests.
- Test layout: `tests/unit/` and `tests/integration/`, shared fixtures in `tests/conftest.py`.
- Integration tests are marked `@pytest.mark.integration` and excluded by default.
  Run with `make test-integration`. They use the HIBP test API key (`00000000000000000000000000000000`)
  and test accounts on `hibp-integration-tests.com`.

## Configuration

Settings are loaded via pydantic-settings with env prefix `HIBP_` and XDG fallback (`~/.config/pwned/.env`) plus OS Keychain backend support:
- `HIBP_API_KEY` — required for authenticated endpoints
- `HIBP_USER_AGENT` — custom User-Agent (default: `pwned-cli`)
- Precedence: `--api-key` > `HIBP_API_KEY` > CWD `.env` > `~/.config/pwned/.env` > OS Keychain (`keyring`)
