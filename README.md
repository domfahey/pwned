# pwned

A command-line tool for the [Have I Been Pwned](https://haveibeenpwned.com/) API v3.

Check email addresses against data breaches, search for compromised passwords, query stealer logs, and more — all from the terminal.

## Installation

Requires Python 3.12+ and [uv](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/domfahey/pwned.git && cd pwned
make install
```

Run commands via `uv run pwned ...` (or activate `.venv/bin/activate`, or install globally with `uv tool install .`). Examples below assume `pwned` is on your `PATH`.

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

## License

MIT
