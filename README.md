# pwned

[![CI](https://github.com/domfahey/pwned/actions/workflows/ci.yml/badge.svg)](https://github.com/domfahey/pwned/actions/workflows/ci.yml)
[![Docs](https://github.com/domfahey/pwned/actions/workflows/docs.yml/badge.svg)](https://domfahey.github.io/pwned/)
[![CodeQL](https://github.com/domfahey/pwned/actions/workflows/codeql.yml/badge.svg)](https://github.com/domfahey/pwned/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/domfahey/pwned/badge)](https://scorecard.dev/viewer/?uri=github.com/domfahey/pwned)
[![Release](https://img.shields.io/github/v/release/domfahey/pwned)](https://github.com/domfahey/pwned/releases)
[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

An unofficial command-line tool and typed Python SDK for querying [Troy Hunt](https://www.troyhunt.com)'s [Have I Been Pwned](https://haveibeenpwned.com/) service (API v3) — with offline password auditing, declarative breach monitoring, and a local stdio MCP server.

- **100% HIBP API v3 parity** — all 21 / 21 endpoints across sync/async clients and the CLI ([coverage matrix](docs/hibp-api-coverage.md)).
- **Privacy-first password checks** — *k*-anonymity (SHA-1 & NTLM, 5-char prefix only, padded by default) or air-gapped `O(1)` per-prefix range directories and `O(log N)` offline hash dumps; plaintext passwords never leave your machine.
- **16 vault & Active Directory audit sources** — Bitwarden (JSON, PBKDF2/Argon2id encrypted JSON, CSV), 1Password (CSV, 1PUX), LastPass, Dashlane, Proton Pass, Chrome/Edge, Firefox, Apple Passwords, generic CSV, KeePass `.kdbx`, AD `pwdump`/`secretsdump`, and live Unix `pass`/`gopass`.
- **CI/CD & reporting ready** — `text`, `json`, `jsonl`, `csv`, `table`, `sarif`, `markdown`, and standalone `html` outputs, declarative `pwned.toml` monitoring, baseline diffing, Slack/Discord/generic webhooks, GitHub Action, and multi-arch container images.

## Quickstart

Try a public breach lookup without installing anything (free, no API key or secrets required):

```bash
uvx --from git+https://github.com/domfahey/pwned.git@v0.5.0 pwned breach Adobe
```

Common workflows once installed from a pinned or verified release:

```bash
# Check a password privately (hidden prompt, k-anonymity + padding on by default)
pwned password

# Audit a password manager export locally for breaches, reuse, and weak passwords
pwned audit vault.json --source bitwarden-json --check-reuse --check-strength

# Check an account for breaches, pastes, and stealer logs (requires HIBP API key)
pwned auth set
pwned search user@example.com --include-stealer-logs --format table

# Generate a standalone HTML domain exposure risk report
pwned domain-report example.com --cache --format html > report.html
```

## Documentation

Read the hosted docs at **[domfahey.github.io/pwned](https://domfahey.github.io/pwned/)** or browse [`docs/`](docs/README.md):

| Guide | Topics |
|---|---|
| [CLI Reference](docs/cli-reference.md) | Commands, short aliases, global flags, output formats, credential precedence, exit codes |
| [HIBP API v3 Coverage](docs/hibp-api-coverage.md) | 21 / 21 endpoint parity matrix, response models, rate limiting, error handling, test accounts |
| [Python Library Guide](docs/python-api.md) | Sync/async clients, caching, retry jitter, batching, Pydantic/FastAPI/Django validators |
| [Vault & Active Directory Auditing](docs/vault-auditing.md) | 16 vault/browser/`pwdump`/`pass`/`gopass` sources, Argon2id, reuse & strength scoring |
| [Monitoring, Webhooks & CI/CD](docs/monitoring-and-ci.md) | `pwned.toml`, baselines, webhooks, SARIF/Markdown/HTML, GitHub Action, pre-commit, Docker |
| [Offline Lookups & Local MCP Server](docs/offline-and-mcp.md) | Resumable offline dump downloads, `OfflinePasswordsClient`, and `pwned mcp` |
| [Roadmap](docs/roadmap.md) | Completed milestones and planned `v0.6.0` improvements |

## Installation

Requires Python 3.12+ and [uv](https://docs.astral.sh/uv/) (or Docker/Podman for container usage).

### Global CLI (`uv tool`)

```bash
uv tool install git+https://github.com/domfahey/pwned.git@v0.5.0

# With all optional extras (KeePass, OS Keychain, Bitwarden encryption, zxcvbn)
uv tool install "pwned[all] @ git+https://github.com/domfahey/pwned.git@v0.5.0"
```

For sensitive password or vault audits, prefer a pinned release tag, verified [GitHub Release](https://github.com/domfahey/pwned/releases) wheel (`SHA256SUMS.txt` + `gh attestation verify`), or audited local clone (`uv sync --frozen`).

Optional extras: `keepass` (`pykeepass`), `keyring` (OS Keychain), `crypto` (`cryptography>=44.0` for Bitwarden PBKDF2 & Argon2id encrypted JSON), `strength` (`zxcvbn`), or `all`.

### Python Library Dependency

```bash
uv add "pwned @ git+https://github.com/domfahey/pwned.git"
```

### Container Image (`ghcr.io/domfahey/pwned`)

Multi-arch (`linux/amd64`, `linux/arm64`) non-root (`65532:65532`) images with SLSA provenance attestations:

```bash
# Attach stdin (-i) when piping passwords
docker run --rm -i ghcr.io/domfahey/pwned password --stdin < passwords.txt

# Mount local vault exports read-only (:ro)
docker run --rm -v "$(pwd):/data:ro" ghcr.io/domfahey/pwned \
  audit /data/vault.json --source bitwarden-json --check-reuse --format markdown
```

### Local Development

```bash
git clone https://github.com/domfahey/pwned.git && cd pwned
make install
```

When running from a local clone, prefix commands with `uv run pwned ...`.

## Configuration

Authenticated endpoints require an [HIBP API key](https://haveibeenpwned.com/API/Key). Manage credentials securely via `pwned auth`:

```bash
pwned auth set                      # Store in OS Keychain if pwned[keyring] is installed, else ~/.config/pwned/.env (0600)
pwned auth set --backend file       # Force file storage (~/.config/pwned/.env, mode 0600)
pwned auth set --backend keyring    # Force OS Keychain storage (requires pwned[keyring])
pwned auth show                     # Show masked key status and active source
pwned auth clear                    # Remove stored key from OS Keychain and/or config file
```

API key precedence (highest first): `--api-key` CLI flag > `HIBP_API_KEY` env var > CWD `.env` (see [.env.example](.env.example)) > `~/.config/pwned/.env` > OS Keychain.

## CLI Overview

Commands are grouped by HIBP subscription tier. Protected commands (`Core` and above) require an [HIBP API key](https://haveibeenpwned.com/API/Key) configured via `pwned auth set` (see [CLI Reference](docs/cli-reference.md) for all flags and examples).

| Plan Tier | Commands |
|---|---|
| **Free / No API key** | `password` (`pw`), `password-range` (`pr`), `audit`, `offline download`, `mcp`, `breach`, `breaches`, `latest-breach` (`lb`), `dataclasses` (`dc`), `cache clear`, `auth set\|show\|clear`, `doctor`, `completion` |
| **Core / Pro / High RPM** | `account` (`ba`), `search`, `pastes` (`pa`), `subscription`, `domain` (`bd`), `domain-report`, `monitor`, `subscribed-domains` (`sd`) |
| **Pro / High RPM** | `account-range` (`bar`) |
| **Pro** | `stealer email\|website\|domain`, `domain-verify dns-token\|dns-check\|meta-tag\|meta-check\|email`, `subscribed-domains remove` |

### Global Options

Global flags are accepted before or after subcommands (`pwned --json --cache breach Adobe` or `pwned breach Adobe --format html > report.html`):

| Flag | Description |
|---|---|
| `--api-key TEXT` | HIBP API key override |
| `--user-agent TEXT` | Custom `User-Agent` header override (default `pwned-cli`) |
| `--format TEXT` | Output format: `text`, `json`, `jsonl`, `csv`, `table`, `sarif`, `markdown`, `html` |
| `--json` | Shorthand for `--format json` |
| `--markdown` | Shorthand for `--format markdown` |
| `--outfile PATH` | Write formatted UTF-8 output atomically to a file |
| `--force` | Overwrite an existing `--outfile` |
| `--cache / --no-cache` | Cache public endpoints and password range lookups locally |
| `--version` | Show CLI version and exit |

## Python Library Usage

`pwned` ships PEP 561 type annotations (`py.typed`) with sync, async, offline, and framework validator APIs. See [Python Library Guide](docs/python-api.md) for full details.

### Sync & Offline Clients

```python
from pathlib import Path
from pwned import HIBPClient, OfflinePasswordsClient, PwnedPasswordsClient, ResponseCache

with PwnedPasswordsClient() as pw:
    print(pw.is_pwned("hunter2", threshold=1))

with HIBPClient(api_key="your_api_key", user_agent="my-app", cache=ResponseCache()) as client:
    breaches = client.get_account_breaches("user@example.com", truncate=False)
    print(f"Found {len(breaches)} breaches")

with OfflinePasswordsClient(Path("/path/to/pwned-passwords-sha1.txt")) as offline:
    print(offline.check_password("hunter2"))
```

### Async Clients

```python
import asyncio
from pwned import AsyncHIBPClient, AsyncPwnedPasswordsClient

async def main() -> None:
    async with AsyncPwnedPasswordsClient() as pw:
        print(await pw.check_password("hunter2", pad=True))
    async with AsyncHIBPClient(api_key="your_api_key") as client:
        print(await client.get_subscription_status())

asyncio.run(main())
```

### Pydantic / FastAPI Password Validator

```python
from typing import Annotated
from pydantic import AfterValidator, BaseModel
from pwned import make_password_validator

SafePassword = Annotated[str, AfterValidator(make_password_validator(threshold=1))]

class SignupForm(BaseModel):
    username: str
    password: SafePassword
```

## Monitoring, CI/CD & GitHub Action

### Declarative Monitoring (`pwned.toml`)

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

[[domains]]
domain = "example.com"
include_stealer_logs = true
```

```bash
export HIBP_API_KEY="your_api_key"
export PWNED_WEBHOOK_URL="https://hooks.slack.com/services/..."  # required when [notify] is set
pwned monitor --config pwned.toml --save-baselines
```

### GitHub Action

Run scheduled exposure monitoring or local vault/hash audits in GitHub Actions with `domfahey/pwned@v0.5.0`:

```yaml
steps:
  - uses: actions/checkout@v4
  - uses: domfahey/pwned@v0.5.0
    env:
      PWNED_WEBHOOK_URL: ${{ secrets.PWNED_WEBHOOK_URL }}
    with:
      args: monitor --config pwned.toml --save-baselines --fail-if-pwned
      api-key: ${{ secrets.HIBP_API_KEY }}
```

Commands like `password` and `audit` use the free *k*-anonymity API and do not require `api-key`. Exit codes mirror the official HIBP CLI (`0` clean/success, `8` exposure found with `--fail-if-pwned`, `2`–`7`/`9`/`130` usage, auth, plan, rate-limit, network, file/store, missing-resource, or cancellation codes — see [CLI Reference](docs/cli-reference.md#exit-codes)).

| Input | Required | Default | Description |
|---|---|---|---|
| `args` | Yes | — | CLI arguments passed to `pwned` |
| `api-key` | No | `""` | HIBP API key (injected via `HIBP_API_KEY` env var) |
| `version` | No | Action ref (`main` fallback) | Git ref, tag, or branch of `domfahey/pwned` to execute |
| `output-file` | No | `""` | Optional file path to redirect stdout (e.g. `pwned.sarif`) |
| `python-version` | No | `"3.12"` | Python version set up via `astral-sh/setup-uv` |

### Pre-commit Hook

Add `pwned-audit` to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/domfahey/pwned
    rev: v0.5.0
    hooks:
      - id: pwned-audit
```

`pwned-audit` defaults to `stages: [manual]` so vault files are audited on demand:

```bash
pre-commit run pwned-audit --hook-stage manual --files vault.json
```

## Model Context Protocol (MCP)

`pwned` complements HIBP's [official remote MCP server](https://haveibeenpwned.com/Docs/MCP) (`https://haveibeenpwned.com/mcp`) with a built-in, zero-dependency **local stdio MCP server** (`pwned mcp`) for workflows where plaintext passwords or internal vaults must never leave your machine (`check_password_hash`, `audit_vault`, `diff_baseline`, `lookup_breach`, `check_account_range`):

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

See [Offline Lookups & Local MCP Server](docs/offline-and-mcp.md) for both local stdio and HIBP remote HTTP MCP configurations.

## Development

Run `make` (or `make help`) to list all targets:

```bash
make install          # Install runtime and development dependencies
make install-all      # Install all optional extras and dependency groups
make doctor           # Verify uv, Python, deps, extras, and API key source
make test             # Run unit tests (integration excluded by default)
make test-integration # Run live HIBP API integration tests (uses HIBP test key)
make coverage         # Run unit tests with branch coverage report
make lint             # Check code style and formatting with ruff
make format           # Auto-fix lint issues and format code with ruff
make type             # Run mypy strict type checking
make check            # Run lint + type + test (CI-safe)
make docs             # Build MkDocs Material site with --strict
make docs-serve       # Serve docs locally with live reload
make build            # Build sdist and wheel distributions
make clean            # Remove build, test, docs, and cache artifacts
```

<details>
<summary>Project structure</summary>

```text
src/pwned/
├── __init__.py         # Public library API exports
├── _parsers.py         # Zero-dependency stdlib parsers (MD4, range, HTML, pwdump, input lines)
├── async_client.py     # Async HIBP API client (httpx.AsyncClient)
├── audit.py            # Vault, browser, AD pwdump, and pass/gopass auditing
├── baseline.py         # Exposure baseline snapshotting and diffing
├── batch.py            # Sync & async batching with RPM pacing and stats
├── cache.py            # File-based XDG TTL response caching
├── cli.py              # Click command groups and global option parser
├── cli_commands.py     # Additional CLI commands (auth, search, audit, offline, monitor, mcp, ...)
├── cli_helpers.py      # CLI output rendering, error handling, and validation helpers
├── client.py           # Sync HIBP API client (haveibeenpwned.com)
├── config.py           # pydantic-settings config with XDG fallback and OS Keychain
├── filtering.py        # Breach filtering and sorting helpers
├── formatting.py       # Output formatters (text, json, jsonl, csv, table, sarif, markdown, html)
├── mcp_server.py       # Local privacy-first stdio MCP server
├── models.py           # Pydantic v2 response models
├── monitor.py          # Declarative TOML monitoring engine
├── notify.py           # HTTPS webhook notifications (Slack, Discord, generic JSON)
├── offline.py          # Offline sorted hash file lookups (OfflinePasswordsClient)
├── offline_download.py # Resumable official Pwned Passwords dump downloader
├── passwords.py        # Sync & async Pwned Passwords clients (k-anonymity)
├── py.typed            # PEP 561 type marker
├── reporting.py        # Domain exposure risk summary reporting
├── strength.py         # Password strength heuristics & optional zxcvbn integration
└── validators.py       # Framework password validators (Pydantic / FastAPI / Django)

tests/
├── unit/               # Fast unit tests with mocked HTTP (100% branch coverage)
└── integration/        # Live API tests against hibp-integration-tests.com test accounts
```

</details>

## Contributing & Security

- [Changelog](CHANGELOG.md) — Release history
- [Contributing Guide](.github/CONTRIBUTING.md) — Development workflow and PR checklist
- [Security Policy](.github/SECURITY.md) — Vulnerability reporting and security design
- [Code of Conduct](.github/CODE_OF_CONDUCT.md) — Community standards

### See Also

Other Have I Been Pwned CLIs:

- [`HaveIBeenPwned.Cli`](https://haveibeenpwned.com/cli) — .NET (official HIBP CLI)
- [`wKovacs64/pwned`](https://github.com/wKovacs64/pwned) — Node.js/TypeScript
- [`brycx/checkpwn`](https://github.com/brycx/checkpwn) — Rust

## License

Code is licensed under the [MIT License](LICENSE).

Breach and paste data returned by the Have I Been Pwned API is sourced from [Have I Been Pwned](https://haveibeenpwned.com/) and licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Applications displaying HIBP breach or paste data must clearly attribute Have I Been Pwned with a link to `https://haveibeenpwned.com/`.
