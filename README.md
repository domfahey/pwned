# pwned

[![CI](https://github.com/domfahey/pwned/actions/workflows/ci.yml/badge.svg)](https://github.com/domfahey/pwned/actions/workflows/ci.yml)
[![CodeQL](https://github.com/domfahey/pwned/actions/workflows/codeql.yml/badge.svg)](https://github.com/domfahey/pwned/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/domfahey/pwned/badge)](https://scorecard.dev/viewer/?uri=github.com/domfahey/pwned)
[![Release](https://img.shields.io/github/v/release/domfahey/pwned)](https://github.com/domfahey/pwned/releases)
[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

A command-line tool and typed Python client for the [Have I Been Pwned](https://haveibeenpwned.com/) API v3.

Check email addresses against data breaches, search for compromised passwords, query stealer logs, audit password vaults, and more — all from the terminal or Python.

## Installation

Requires Python 3.12+ and [uv](https://docs.astral.sh/uv/).

### Zero-install with `uvx`
Run without installing:
```bash
uvx --from git+https://github.com/domfahey/pwned.git pwned password
```

### Global tool installation
```bash
uv tool install git+https://github.com/domfahey/pwned.git
```

With optional KeePass vault auditing support:
```bash
uv tool install "pwned[keepass] @ git+https://github.com/domfahey/pwned.git"
```

### Development setup
```bash
git clone https://github.com/domfahey/pwned.git && cd pwned
make install
```

When running from a local clone, prefix commands with `uv run pwned ...`. Examples below assume `pwned` is on your `PATH`.

## Configuration

Some commands require an [HIBP API key](https://haveibeenpwned.com/API/Key). Manage stored credentials with `pwned auth`:

- `pwned auth set` — Interactively prompt for and store your API key in `~/.config/pwned/.env` (with secure `0600` file permissions).
- `pwned auth show` — Display masked API key status and config file path.
- `pwned auth clear` — Remove the stored API key.

### API Key Precedence
Configuration is resolved in the following order (highest precedence first):
1. `--api-key` CLI flag
2. `HIBP_API_KEY` environment variable
3. Current working directory `.env` file
4. User XDG config file (`~/.config/pwned/.env`)

## CLI Usage (by HIBP Plan Tier)

### Free / No API key
- `password` — Check password exposure (supports `--stdin`, `--file`, `--ntlm`, `--pad`, `--threshold`, `--fail-if-pwned`)
- `audit` — Audit local password manager exports (Bitwarden JSON/CSV, generic CSV, KeePass via `--source keepass`)
- `breach` — Get details for a specific breach
- `breaches` — List all known breaches (supports `--domain`, `--spam-list`, `--no-spam-list`)
- `latest-breach` — Get the most recently added breach
- `dataclasses` — List tracked data classes (supports `--descriptions`)
- `cache clear` — Clear local response cache
- `auth set|show|clear` — Manage stored API key credentials

### Core / Pro / High RPM
- `account` — Check email or username breaches (supports `--file`, `--stdin`, `--rpm`, `--fail-if-pwned`, `--no-truncate`, `--domain`, `--no-include-unverified`)
- `search` — Composite search for breaches, pastes, and stealer logs (`--include-stealer-logs`)
- `pastes` — Get pastes for an email address
- `subscription` — View HIBP subscription status and rate limits
- `domain` — Get breached email addresses for a domain
- `subscribed-domains` — List subscribed domains

### Pro / High RPM
- `account-range <email>` — Query breach status via 6-character SHA-1 email prefix (*k*-anonymity)

### Pro
- `stealer email|website|domain` — Query stealer log records by email address, website domain, or email domain
- `domain-verify dns-token|dns-check|email` — Manage domain ownership verification via DNS TXT records or email aliases

### Global Options

| Flag | Description |
|---|---|
| `--api-key TEXT` | HIBP API key override |
| `--user-agent TEXT` | Custom User-Agent string override (default `pwned-cli`) |
| `--format TEXT` | Output format: `text`, `json`, `jsonl`, `csv`, or `table` |
| `--json` | Shorthand for `--format json` |
| `--cache / --no-cache` | Cache public endpoint responses locally |
| `--version` | Show CLI version and exit |

Global flags can appear before or after subcommands:
```bash
pwned --json --cache breach Adobe
pwned breach Adobe --format table
```

## Python Library Usage

`pwned` provides both synchronous and asynchronous typed clients (`py.typed` / PEP 561 compliant).

### Synchronous Clients
```python
from pwned import HIBPClient, PwnedPasswordsClient, ResponseCache

# Password checks with k-anonymity
with PwnedPasswordsClient(cache=ResponseCache()) as pw:
    is_compromised = pw.is_pwned("hunter2", threshold=1)
    suffix_map = pw.get_password_range("5BAA6")

# HIBP API requests
with HIBPClient(api_key="your_api_key", user_agent="my-app") as client:
    breaches = client.get_account_breaches("user@example.com", truncate=False)
    search_res = client.search_account("user@example.com", include_stealer_logs=True)
```

### Asynchronous Clients (`asyncio` / `httpx.AsyncClient`)
```python
import asyncio
from pwned import AsyncHIBPClient, AsyncPwnedPasswordsClient

async def main():
    async with AsyncPwnedPasswordsClient() as pw:
        count = await pw.check_password("hunter2", pad=True)

    async with AsyncHIBPClient(api_key="your_api_key") as client:
        sub = await client.get_subscription_status()
        print(sub)

asyncio.run(main())
```

## Official HIBP MCP Server

If you want to query Have I Been Pwned directly from an MCP-capable AI client, HIBP also provides an official remote [Model Context Protocol (MCP) server](https://haveibeenpwned.com/mcp):

- **Endpoint & docs:** `https://haveibeenpwned.com/mcp`
- **Public tools (no auth):** breach metadata, latest breach, data classes, and Pwned Passwords (*k*-anonymity range lookup)
- **Authenticated tools (HIBP subscription required):** account breaches, pastes, verified domain lookups/management, and stealer logs (via OAuth with `hibp.mcp` scope or an `hibp-api-key` header)

Example HTTP MCP client configuration:

```json
{
  "HIBP": {
    "type": "http",
    "url": "https://haveibeenpwned.com/mcp",
    "headers": {
      "hibp-api-key": "YOUR_HIBP_API_KEY"
    }
  }
}
```

> **Note:** For checking passwords, prefer the local CLI (`pwned password` or `pwned password --stdin`) so the plaintext password is hashed locally and never enters an AI chat prompt.

## Development

```bash
make install          # Set up venv and install deps
make test             # Run unit tests (default; integration excluded)
make test-integration # Run integration tests (hits live API)
make coverage         # Run unit tests with coverage report
make lint             # Check code style
make format           # Auto-fix lint/formatting
make type             # Run mypy strict type checking
make doctor           # Verify environment and dependencies
make check            # Run lint + type + test (non-mutating, CI-safe)
```

### Project structure

```
src/pwned/
├── __init__.py         # Public library API exports
├── async_client.py     # Async HIBP API client (httpx.AsyncClient)
├── audit.py            # Password manager vault auditing logic
├── batch.py            # Batch processing & rate limiting for accounts/passwords
├── cache.py            # SQLite response caching for public endpoints
├── cli.py              # Click command groups and global option parser
├── cli_commands.py     # Additional command modules (auth, search, audit, cache, etc.)
├── cli_helpers.py      # CLI error handling, output rendering, and validation helpers
├── client.py           # Sync HIBP API client (haveibeenpwned.com)
├── config.py           # pydantic-settings configuration & XDG credential storage
├── formatting.py       # Output formatters (text, json, jsonl, csv, table)
├── models.py           # Pydantic v2 models for API responses
├── passwords.py        # Sync & async Pwned Passwords client (api.pwnedpasswords.com)
└── py.typed            # PEP 561 type marker

tests/
├── unit/               # Fast tests with mocked HTTP
└── integration/        # Live API tests using HIBP test accounts
```

### Running integration tests

Integration tests use the [HIBP test API key](https://haveibeenpwned.com/API/v3#TestAccounts) (`00000000000000000000000000000000`) and test accounts on `hibp-integration-tests.com`. They hit the live API and require network access.

```bash
make test-integration
```

## See Also

Direct Have I Been Pwned CLIs in other ecosystems:

- [`wKovacs64/pwned`](https://github.com/wKovacs64/pwned) — Node.js/TypeScript
- [`brycx/checkpwn`](https://github.com/brycx/checkpwn) — Rust

## License

MIT
