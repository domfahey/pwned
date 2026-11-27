# pwned

[![CI](https://github.com/domfahey/pwned/actions/workflows/ci.yml/badge.svg)](https://github.com/domfahey/pwned/actions/workflows/ci.yml)
[![Docs](https://github.com/domfahey/pwned/actions/workflows/docs.yml/badge.svg)](https://domfahey.github.io/pwned/)
[![CodeQL](https://github.com/domfahey/pwned/actions/workflows/codeql.yml/badge.svg)](https://github.com/domfahey/pwned/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/domfahey/pwned/badge)](https://scorecard.dev/viewer/?uri=github.com/domfahey/pwned)
[![Release](https://img.shields.io/github/v/release/domfahey/pwned)](https://github.com/domfahey/pwned/releases)
[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

A command-line tool and typed Python client for the [Have I Been Pwned](https://haveibeenpwned.com/) API v3.

Check email addresses against data breaches, search for compromised passwords, query stealer logs, audit password vaults, perform offline hash checks, and more — all from the terminal or Python.

## Documentation

Read the hosted documentation at **[domfahey.github.io/pwned](https://domfahey.github.io/pwned/)** or browse [`docs/`](docs/README.md):

- [CLI Reference](docs/cli-reference.md) — Commands, aliases, flags, output formats, and exit codes
- [HIBP API v3 Coverage](docs/hibp-api-coverage.md) — Complete 21 / 21 endpoint, model, and protocol parity matrix
- [Python Library Guide](docs/python-api.md) — Sync/async clients, caching, batching, and framework validators
- [Vault & Active Directory Auditing](docs/vault-auditing.md) — 16 vault/browser/`pwdump`/`pass`/`gopass` formats, Argon2id, reuse & strength scoring
- [Monitoring, Webhooks & CI/CD](docs/monitoring-and-ci.md) — `pwned.toml`, baselines, Slack/Discord webhooks, SARIF/Markdown/HTML, GitHub Action, and Docker
- [Offline Lookups & Local MCP Server](docs/offline-and-mcp.md) — Resumable dump downloads and zero-dependency `pwned mcp` server

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

With optional extras (KeePass vault support, OS Keychain credential storage, Bitwarden encrypted JSON / Argon2id decryption, or optional `zxcvbn` password strength boost):
```bash
uv tool install "pwned[all] @ git+https://github.com/domfahey/pwned.git"
```
Available optional extras:
- `keepass` (`pykeepass`)
- `keyring` (`keyring` for OS Keychain storage)
- `crypto` (`cryptography>=44.0` for Bitwarden PBKDF2 & Argon2id encrypted JSON)
- `strength` (`zxcvbn` optional password strength boost)
- `all` (installs all optional dependencies)

### Development setup
```bash
git clone https://github.com/domfahey/pwned.git && cd pwned
make install
```

When running from a local clone, prefix commands with `uv run pwned ...`. Examples below assume `pwned` is on your `PATH`.

## Configuration

Some commands require an [HIBP API key](https://haveibeenpwned.com/API/Key). Manage stored credentials with `pwned auth`:

- `pwned auth set` — Interactively prompt for and store your API key in `~/.config/pwned/.env` (with secure `0600` file permissions) or OS Keychain via `--backend keyring`.
- `pwned auth show` — Display masked API key status, storage backend, and configuration path.
- `pwned auth clear` — Remove the stored API key from file or keychain storage.

### API Key Precedence
Configuration is resolved in the following order (highest precedence first):
1. `--api-key` CLI flag
2. `HIBP_API_KEY` environment variable
3. Current working directory `.env` file
4. User XDG config file (`~/.config/pwned/.env`)
5. OS Keychain backend (`keyring`)

## CLI Usage (by HIBP Plan Tier)

`pwned` implements **100% of the official HIBP API v3 specification (21 / 21 endpoints)** across sync/async clients and the CLI. See [docs/hibp-api-coverage.md](docs/hibp-api-coverage.md) for the complete endpoint, parameter, model, and protocol parity matrix.

### Free / No API key
- `password` — Check password exposure (supports `--stdin`, `--file`, `--hashed`, `--offline-db`, `--concurrency`, `--stats`, `--ntlm`, `--pad`, `--threshold`, `--cache`, `--fail-if-pwned`)
- `audit` — Audit local password manager, browser, or Active Directory exports (Bitwarden JSON/Encrypted-JSON/CSV, 1Password CSV/1PUX, LastPass CSV, Dashlane CSV, Proton Pass CSV, Chrome/Firefox/Apple CSV, generic CSV, KeePass `.kdbx`, Active Directory `pwdump`/`secretsdump`, Unix `pass`/`gopass`, `--check-reuse`, `--check-strength`, `--cache`, `--notify-webhook`, `--concurrency`, `--offline-db`, `--fail-if-pwned`)
- `offline download <output>` — Built-in resumable offline Pwned Passwords dump downloader (supports `--ntlm`, `--concurrency`, `--resume`, `--etag-cache`)
- `mcp` — Local privacy-first stdio Model Context Protocol server (`--offline-db`, `--ntlm`, `--cache`)
- `breach` — Get details for a specific breach
- `breaches` — List all known breaches (supports `--domain`, `--spam-list`, `--no-spam-list`, `--no-include-unverified`, `--since`, `--data-class`, `--verified-only`, `--exclude-retired`, `--sort pwn-count|date|name`)
- `latest-breach` — Get the most recently added breach
- `dataclasses` — List tracked data classes (supports `--descriptions`)
- `cache clear` — Clear local response cache
- `auth set|show|clear` — Manage stored API key credentials (`--backend file|keyring`)
- `completion` — Generate shell tab-completion scripts (`completion bash|zsh|fish`)

### Core / Pro / High RPM
- `account` — Check email or username breaches (supports `--file`, `--stdin`, `--rpm`, `--fail-if-pwned`, `--no-truncate`, `--domain`, `--no-include-unverified`, `--baseline`, `--save-baseline`, `--notify-webhook`, `--webhook-format`, `--stats`)
- `search` — Composite search for breaches, pastes, and stealer logs (`--include-stealer-logs`, `--baseline`, `--save-baseline`, `--notify-webhook`, `--webhook-format`)
- `pastes` — Get pastes for an email address
- `subscription` — View HIBP subscription status and rate limits
- `domain` — Get breached email addresses for a domain (supports `--baseline`, `--save-baseline`, `--notify-webhook`, `--webhook-format`, `--fail-if-pwned`)
- `domain-report <domain>` — Comprehensive domain exposure risk summary cross-referencing breach counts, stealer logs, and data classes (`--include-stealer-logs`, `--notify-webhook`, `--webhook-format`, `--fail-if-pwned`)
- `monitor` — Declarative TOML exposure monitoring (`--config pwned.toml`, `--save-baselines`, `--notify-webhook`, `--webhook-format`, `--fail-if-pwned`)
- `subscribed-domains` / `subscribed-domains list` — List subscribed domains

### Pro / High RPM
- `account-range <email>` — Query breach status via 6-character SHA-1 email prefix (*k*-anonymity)

### Pro
- `stealer email|website|domain` — Query stealer log records by email address, website domain, or email domain
- `domain-verify dns-token|dns-check|meta-tag|meta-check|email` — Manage domain ownership verification via DNS TXT records, HTML meta tags, or email aliases
- `subscribed-domains remove <domain>` — Remove a subscribed domain from your account

### Short Command Aliases
For convenience, ergonomic short aliases are available:
- `pw` (`password`)
- `ba` (`account`)
- `bar` (`account-range`)
- `pa` (`pastes`)
- `bd` (`domain`)
- `sd` (`subscribed-domains`)
- `lb` (`latest-breach`)
- `dc` (`dataclasses`)

### Global Options

| Flag | Description |
|---|---|
| `--api-key TEXT` | HIBP API key override |
| `--user-agent TEXT` | Custom User-Agent string override (default `pwned-cli`) |
| `--format TEXT` | Output format: `text`, `json`, `jsonl`, `csv`, `table`, `sarif`, `markdown`, or `html` |
| `--json` | Shorthand for `--format json` |
| `--cache / --no-cache` | Cache public endpoint and range responses locally |
| `--version` | Show CLI version and exit |

Global flags can appear before or after subcommands:
```bash
pwned --json --cache breach Adobe
pwned breach Adobe --format html > report.html
```

## Declarative Monitoring (`pwned.toml`)

Automate continuous exposure checks across accounts and domains using a declarative TOML configuration file:

```toml
[monitor]
baseline_dir = ".pwned-baselines"
cache = true
format = "markdown"
fail_if_pwned = true

[notify]
webhook_url = "${PWNED_WEBHOOK_URL}"
format = "auto"

[[accounts]]
email = "security@example.com"
include_stealer_logs = true
include_unverified = false

[[domains]]
domain = "example.com"
include_stealer_logs = true
```

Run monitoring with:
```bash
pwned monitor --config pwned.toml --save-baselines
```

## Container Usage

For air-gapped environments, CI pipelines, or non-Python systems, run `pwned` via Docker or Podman:

```bash
docker run --rm ghcr.io/domfahey/pwned password --stdin < passwords.txt
docker run --rm -v $(pwd):/data ghcr.io/domfahey/pwned audit --source bitwarden-json /data/vault.json --format markdown
```

## Python Library Usage

`pwned` provides both synchronous and asynchronous typed clients (`py.typed` / PEP 561 compliant).

### Synchronous Clients
```python
from pwned import HIBPClient, PwnedPasswordsClient, ResponseCache

# Password checks with k-anonymity
with PwnedPasswordsClient() as pw:
    is_compromised = pw.is_pwned("hunter2", threshold=1)
    suffix_map = pw.get_password_range("5BAA6")

# HIBP API requests (with optional public-endpoint & range caching)
with HIBPClient(api_key="your_api_key", user_agent="my-app", cache=ResponseCache()) as client:
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

### Offline Password DB Lookups
For high-scale or air-gapped password auditing against official Pwned Passwords SHA-1/NTLM hash dumps:
```python
from pathlib import Path
from pwned import OfflinePasswordsClient

with OfflinePasswordsClient(Path("/path/to/pwned-passwords-sha1.txt")) as offline:
    count = offline.check_password("hunter2")
    print(f"Compromised {count} times")
```

### Framework Password Validators (Pydantic / FastAPI / Django)
```python
from typing import Annotated
from pydantic import AfterValidator, BaseModel
from pwned import make_password_validator

SafePassword = Annotated[str, AfterValidator(make_password_validator(threshold=1))]

class SignupForm(BaseModel):
    username: str
    password: SafePassword
```

## CI/CD Integrations & Pre-commit

### GitHub Action
Use the official composite GitHub Action to audit repositories or credential exports in CI:
```yaml
steps:
  - uses: actions/checkout@v4
  - uses: domfahey/pwned@main
    with:
      args: audit --source bitwarden-json --fail-if-pwned vault.json
      api-key: ${{ secrets.HIBP_API_KEY }}
```

### Pre-commit Hook
Add `pwned` to your `.pre-commit-config.yaml`:
```yaml
repos:
  - repo: https://github.com/domfahey/pwned
    rev: v0.4.1
    hooks:
      - id: pwned-audit
```

## Model Context Protocol (MCP) Servers

`pwned` supports both HIBP's official remote MCP server and a local privacy-first stdio MCP server for AI clients:

### 1. HIBP Official Remote MCP Server
To query Have I Been Pwned directly via AI chat clients:
- **Endpoint & docs:** `https://haveibeenpwned.com/mcp`
- **Public tools (no auth):** breach metadata, latest breach, data classes, and Pwned Passwords range lookup
- **Authenticated tools (subscription required):** account breaches, pastes, verified domain management, and stealer logs

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

### 2. Local Privacy-First Stdio MCP Server (`pwned mcp`)
For offline or local workflows where plaintext passwords or internal vaults must never cross an AI chat prompt, `pwned` includes a built-in, zero-dependency local stdio Model Context Protocol server (`check_password_hash`, `audit_vault`, `diff_baseline`, `lookup_breach`, `check_account_range`):

```json
{
  "mcpServers": {
    "pwned-local": {
      "command": "pwned",
      "args": ["mcp", "--offline-db", "/path/to/pwned-passwords-sha1.txt"]
    }
  }
}
```

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
├── _parsers.py         # Zero-dependency stdlib parsers (MD4, range response, HTML stripper, input lines)
├── async_client.py     # Async HIBP API client (httpx.AsyncClient)
├── audit.py            # Password manager vault auditing & reused password detection
├── baseline.py         # Exposure baseline snapshotting and diffing
├── batch.py            # Batch processing & rate limiting for accounts/passwords
├── cache.py            # File-based TTL response caching for public endpoints & ranges
├── cli.py              # Click command groups and global option parser
├── cli_commands.py     # Additional command modules (auth, search, audit, cache, completion, etc.)
├── cli_helpers.py      # CLI error handling, output rendering, and validation helpers
├── client.py           # Sync HIBP API client (haveibeenpwned.com)
├── config.py           # pydantic-settings configuration & XDG / keyring credential storage
├── filtering.py        # Breach filtering and sorting helpers
├── formatting.py       # Output formatters (text, json, jsonl, csv, table, sarif, markdown, html)
├── mcp_server.py       # Local privacy-first stdio Model Context Protocol server
├── models.py           # Pydantic v2 models for API responses
├── monitor.py          # Declarative TOML exposure monitoring engine
├── notify.py           # Webhook notification client (Slack, Discord, generic JSON)
├── offline.py          # Offline sorted hash file lookups (OfflinePasswordsClient)
├── offline_download.py # Resumable official Pwned Passwords dump downloader
├── passwords.py        # Sync & async Pwned Passwords client (api.pwnedpasswords.com)
├── py.typed            # PEP 561 type marker
├── reporting.py        # Domain exposure risk summary reporting
├── strength.py         # Password strength heuristics & zxcvbn integration
└── validators.py       # Framework password validation helpers

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

Code is licensed under the [MIT License](LICENSE).

Breach and paste data returned by the Have I Been Pwned API is sourced from [Have I Been Pwned](https://haveibeenpwned.com/) and licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Applications displaying HIBP breach or paste data must clearly attribute Have I Been Pwned with a link to `https://haveibeenpwned.com/`.
