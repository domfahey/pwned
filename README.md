# pwned

[![CI](https://github.com/domfahey/pwned/actions/workflows/ci.yml/badge.svg)](https://github.com/domfahey/pwned/actions/workflows/ci.yml)
[![CodeQL](https://github.com/domfahey/pwned/actions/workflows/codeql.yml/badge.svg)](https://github.com/domfahey/pwned/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/domfahey/pwned/badge)](https://scorecard.dev/viewer/?uri=github.com/domfahey/pwned)
[![Release](https://img.shields.io/github/v/release/domfahey/pwned)](https://github.com/domfahey/pwned/releases)
[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

A command-line tool and typed Python client for the [Have I Been Pwned](https://haveibeenpwned.com/) API v3.

Check email addresses against data breaches, search for compromised passwords, query stealer logs, and more — all from the terminal or Python.

## Installation

Requires Python 3.12+ and [uv](https://docs.astral.sh/uv/).

```bash
# Install globally as a CLI tool
uv tool install git+https://github.com/domfahey/pwned.git
```

Or install from a local clone for development:

```bash
git clone https://github.com/domfahey/pwned.git && cd pwned
make install
```

When running from a local clone, prefix commands with `uv run pwned ...` (or activate `.venv/bin/activate`). Examples below assume `pwned` is on your `PATH`.

## Configuration

Some commands require an [HIBP API key](https://haveibeenpwned.com/API/Key). Provide it via:

1. **Environment variable** — `export HIBP_API_KEY=your_key`
2. **`.env` file** — copy `.env.sample` to `.env` and fill in your key
3. **CLI flag** — `pwned --api-key your_key <command>`

```bash
cp .env.sample .env
# Edit .env with your API key
```

## Usage

### Password check (no API key needed)

```bash
# Interactive prompt (hidden input, safest)
pwned password

# Read from stdin (useful in scripts)
echo "hunter2" | pwned password --stdin

# Pass as argument (visible in process table)
pwned password "hunter2"

# Use NTLM hash mode
pwned password "hunter2" --ntlm

# Request padded responses (prevents fingerprinting by response size)
pwned password "hunter2" --pad

# Output as JSON
pwned --json password "hunter2"
```

### Breach lookups (no API key needed)

```bash
# Get details for a specific breach
pwned breach Adobe

# List all known breaches
pwned breaches

# Filter breaches by domain
pwned breaches --domain adobe.com

# Only spam list breaches (or exclude them with --no-spam-list)
pwned breaches --spam-list
pwned breaches --no-spam-list

# Get the most recently added breach
pwned latest-breach

# List all data classes tracked by HIBP
pwned dataclasses
```

### Account search (API key required)

```bash
# Check an email against all breaches
pwned account user@example.com

# Full breach details (not truncated)
pwned account user@example.com --no-truncate

# Exclude unverified breaches
pwned account user@example.com --no-include-unverified

# Filter by breach domain
pwned account user@example.com --domain adobe.com
```

### Domain search (API key required)

```bash
# Get all breached emails for a domain
pwned domain example.com

# List your subscribed domains
pwned subscribed-domains
```

### Pastes (API key required)

```bash
pwned pastes user@example.com
```

### Stealer logs (API key required)

```bash
# Domains where an email appeared in stealer logs
pwned stealer email user@example.com

# Emails found in stealer logs for a website
pwned stealer website netflix.com

# Email aliases found for a domain
pwned stealer domain example.com
```

### Subscription status (API key required)

```bash
pwned subscription
```

### Global options

| Flag | Description |
|---|---|
| `--api-key TEXT` | HIBP API key (overrides `HIBP_API_KEY` / `.env`) |
| `--user-agent TEXT` | Custom User-Agent string (overrides `HIBP_USER_AGENT` / `.env`, default `pwned-cli`) |
| `--json` | Output raw JSON instead of formatted text |
| `--version` | Show CLI version and exit |

Global flags can appear before or after the subcommand:

```bash
pwned --json breach Adobe
pwned breach Adobe --json
```

## Python Library Usage

`pwned` also exports a typed Python client (`py.typed` / PEP 561 compliant):

```python
from pwned import HIBPClient, PwnedPasswordsClient

with PwnedPasswordsClient() as pw:
    count = pw.check_password("hunter2", pad=True)

with HIBPClient(api_key="your_api_key", user_agent="my-app") as client:
    breaches = client.get_account_breaches("user@example.com", truncate=False)
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
├── cli.py          # Click commands and output formatting
├── client.py       # HIBP API client (haveibeenpwned.com)
├── passwords.py    # Pwned Passwords client (api.pwnedpasswords.com)
├── config.py       # pydantic-settings configuration and .env loading
└── models.py       # Pydantic models for API responses

tests/
├── unit/           # Fast tests with mocked HTTP
└── integration/    # Live API tests using HIBP test accounts
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
