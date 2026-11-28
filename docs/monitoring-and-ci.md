# Monitoring, Webhooks & CI/CD

`pwned` supports continuous exposure monitoring through baseline diffing, declarative TOML configuration, HTTPS webhook alerting, CI-native report formats (`sarif`, `markdown`, `html`), a reusable GitHub Action, a pre-commit hook, and multi-architecture container images.

## Declarative Monitoring (`pwned.toml`)

Define watched accounts, verified domains, baseline storage, output format, and webhook delivery in a version-controlled `pwned.toml`:

```toml
[monitor]
baseline_dir = ".pwned-baselines"
cache = true
smart_precheck = true
format = "markdown"
fail_if_pwned = true
rpm = 10

[notify]
webhook_url = "${PWNED_WEBHOOK_URL}"
format = "auto"

[[accounts]]
email = "security@example.com"
include_stealer_logs = true
include_unverified = false
exclude_retired = true

[[accounts]]
email = "ops@example.com"
since = "2025-01-01"
data_class = "Passwords"
verified_only = true

[[domains]]
domain = "example.com"
include_stealer_logs = true
```

Run monitoring:
```bash
export HIBP_API_KEY="..."
export PWNED_WEBHOOK_URL="https://hooks.slack.com/services/..."
pwned monitor --config pwned.toml --save-baselines
```

Key behaviors:
- **Secret-safe TOML:** `${ENV_VAR}` placeholders in `notify.webhook_url` are expanded from environment variables at runtime so secrets never enter git.
- **Safe baseline filenames:** Per-target snapshots inside `baseline_dir` use deterministic SHA-256 filenames (`account_<hash16>.json`, `domain_<hash16>.json`) to prevent path traversal.
- **Read-before-save diffing:** When `--save-baselines` is passed, existing baselines are read first to compute `new_exposures` before updating the stored snapshot.
- **Smart `latestBreach` pre-check:** Enable `smart_precheck = true` in `[monitor]` (or pass `--smart-precheck`) with `baseline_dir` configured to poll unauthenticated `GET /latestBreach` first and skip `GET /breachedDomain/{domain}` queries for already-baselined domains when no new breach has been published (stealer log checks and newly added domains still run).
- **Zero alert fatigue:** Webhooks fire **only** when `new_exposures > 0`.

## Ad-Hoc Baseline Diffing

`account`, `domain`, and `search` also support standalone baseline files:

```bash
# First run: save snapshot
pwned domain example.com --save-baseline domain-baseline.json

# Subsequent cron/CI runs: alert and exit 8 only on newly discovered exposures
pwned domain example.com \
  --baseline domain-baseline.json \
  --save-baseline domain-baseline.json \
  --notify-webhook "$PWNED_WEBHOOK_URL" \
  --fail-if-pwned
```

## Webhook Notifications (`--notify-webhook`)

Supported on `account`, `domain`, `domain-report`, `search`, `audit`, and `monitor`:

- **Formats (`--webhook-format`):**
  - `auto` *(default)*: detects `hooks.slack.com` / `hooks.gov.slack.com` (Slack Block Kit), `discord.com/api/webhooks/...` (Discord rich embed), and falls back to structured JSON (`generic`).
  - Explicit overrides: `slack`, `discord`, `generic`.
- **Security:** Enforces `https://` URLs by default (non-HTTPS URLs fail fast with exit code `2`), caps alert summaries safely for Slack/Discord message limits, and never includes API keys or plaintext passwords.

## Reporting Formats (`--format`)

| Format | Best For |
|---|---|
| `markdown` | GitHub Actions `$GITHUB_STEP_SUMMARY`, pull request comments, security tickets (includes CC BY 4.0 HIBP attribution footer on breach, paste, domain, audit, and monitor reports) |
| `html` | Standalone zero-dependency HTML5 compliance reports (responsive light/dark CSS, strict `html.escape()` XSS defense, CC BY 4.0 attribution) |
| `sarif` | GitHub Code Scanning / Security tab (`HIBP001`–`HIBP004`, SARIF 2.1.0) |
| `json` / `jsonl` | Downstream automation, SIEM ingestion, `jq` pipelines |
| `csv` / `table` | Spreadsheets and interactive terminal inspection |

Example writing directly to a GitHub Actions job summary:
```bash
pwned domain-report example.com --cache --format markdown >> "$GITHUB_STEP_SUMMARY"
```

## GitHub Action (`action.yml`)

```yaml
name: Scheduled Exposure Monitor
on:
  schedule:
    - cron: "0 8 * * 1"

jobs:
  monitor:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: domfahey/pwned@v0.5.0
        with:
          args: monitor --config pwned.toml --save-baselines --fail-if-pwned
          api-key: ${{ secrets.HIBP_API_KEY }}
```

## Pre-commit Hook (`.pre-commit-hooks.yaml`)

```yaml
repos:
  - repo: https://github.com/domfahey/pwned
    rev: v0.5.0
    hooks:
      - id: pwned-audit
```

## Multi-Arch Container Image (`ghcr.io/domfahey/pwned`)

Published for `linux/amd64` and `linux/arm64` on every release tag with SLSA build provenance attestations, running as non-root (`65532:65532`):

```bash
# Password check over stdin
printf 'hunter2\n' | docker run --rm -i ghcr.io/domfahey/pwned:0.5.0 password --stdin

# Mount a local vault or monitor config read-only
docker run --rm -v "$(pwd):/data:ro" \
  ghcr.io/domfahey/pwned:0.5.0 audit /data/vault.json --source bitwarden-json --check-reuse --format markdown
```
