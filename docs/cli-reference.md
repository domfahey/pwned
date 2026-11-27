# CLI Reference

`pwned` exposes all 21 official HIBP API v3 endpoints plus local auditing, offline dumps, declarative monitoring, and a local stdio MCP server.

## Global Options

Global options are accepted **before or after** any subcommand:

| Flag | Default | Description |
|---|---|---|
| `--api-key TEXT` | `None` | HIBP API key override (prefer `HIBP_API_KEY`, `.env`, or keyring over CLI flags to avoid process-table exposure) |
| `--user-agent TEXT` | `pwned-cli` | Custom `User-Agent` header (`HIBP_USER_AGENT`) |
| `--format CHOICE` | `text` | Output format: `text`, `json`, `jsonl`, `csv`, `table`, `sarif`, `markdown`, `html` |
| `--json` | `False` | Shorthand for `--format json` (cannot be combined with another `--format`) |
| `--cache / --no-cache` | `False` | Cache public endpoints (`/breaches`, `/dataclasses*`) and `/range/{prefix}` lookups locally |
| `--version` | — | Show CLI version and exit |

## Credential Precedence

API keys are resolved in order (highest priority first):

1. `--api-key` CLI option
2. `HIBP_API_KEY` environment variable
3. Current working directory `.env`
4. XDG config file (`~/.config/pwned/.env`, written with `0600` POSIX permissions via `pwned auth set`)
5. OS Keychain (`pwned auth set --backend keyring`, requires `pwned[keyring]`)

## Short Command Aliases

| Alias | Command |
|---|---|
| `pw` | `password` |
| `ba` | `account` |
| `bar` | `account-range` |
| `pa` | `pastes` |
| `bd` | `domain` |
| `sd` | `subscribed-domains` |
| `lb` | `latest-breach` |
| `dc` | `dataclasses` |

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | Success (or clean result when `--fail-if-pwned` is set) |
| `1` | Exposure detected with `--fail-if-pwned`, resource not found (`404`), authentication/API error, or runtime error |
| `2` | Invalid CLI usage, conflicting flags, invalid hash format, or invalid webhook URL |

---

## Commands by Plan Tier

### Free / No API Key Required

#### `pwned password [PASSWORD]` (`pw`)
Check one or more passwords or pre-computed hashes against Pwned Passwords (*k*-anonymity or local dump). Prompts interactively with hidden input if no argument, `--stdin`, or `--file` is supplied.

| Option | Default | Description |
|---|---|---|
| `--stdin` | `False` | Read single or multi-line passwords/hashes from stdin |
| `--file FILE` | `None` | Batch-check passwords/hashes (one per line) from file |
| `--ntlm` | `False` | Use NTLM hash (`?mode=ntlm`) instead of SHA-1 |
| `--pad` | `False` | Send `Add-Padding: true` header for traffic-analysis resistance |
| `--hashed` | `False` | Treat input(s) as pre-computed 40-char SHA-1 or 32-char NTLM hashes |
| `--offline-db FILE` | `None` | Query a local sorted HIBP dump file instead of the network API |
| `--concurrency INT` | `10` | Max concurrent requests in online batch mode |
| `--stats` | `False` | Print batch summary stats (`checked / pwned / clean / errors / elapsed`) to stderr |
| `--threshold INT` | `1` | Minimum breach count to treat as pwned |
| `--fail-if-pwned` | `False` | Exit `1` if count meets threshold |

#### `pwned audit [PATH]`
Audit a password-manager export, browser CSV, Active Directory `pwdump` file, or local `pass`/`gopass` store. See [Vault & Active Directory Auditing](vault-auditing.md).

#### `pwned offline download OUTPUT`
Download and build a sorted offline Pwned Passwords hash dump (`00000`–`FFFFF`). See [Offline Lookups & Local MCP Server](offline-and-mcp.md).

#### `pwned mcp`
Start the local zero-dependency stdio MCP server (`--offline-db`, `--ntlm`, global `--cache`). See [Offline Lookups & Local MCP Server](offline-and-mcp.md).

#### `pwned breach NAME`
Fetch full metadata for a single breach by its stable `Name` (e.g., `pwned breach Adobe`).

#### `pwned breaches`
List breaches in the HIBP catalog.

| Option | Description |
|---|---|
| `--domain TEXT` | Filter server-side by primary domain |
| `--spam-list / --no-spam-list` | Filter server-side to only spam lists or exclude them |
| `--no-include-unverified` | Exclude unverified breaches server-side (`?includeUnverified=false`) |
| `--since YYYY-MM-DD` | Client-side filter: breaches on or after date |
| `--data-class TEXT` | Client-side case-insensitive substring filter on `DataClasses` |
| `--verified-only` | Client-side filter: only verified breaches |
| `--exclude-retired` | Client-side filter: exclude retired breaches |
| `--sort [pwn-count\|date\|name]` | Sort breaches descending by count/date or ascending by name |

#### `pwned latest-breach` (`lb`)
Fetch the most recently added breach (`GET /latestBreach`).

#### `pwned dataclasses` (`dc`)
List all tracked data classes (`--descriptions` queries `GET /dataClasses/descriptions`).

#### `pwned auth set|show|clear`
- `pwned auth set [API_KEY] [--backend file|keyring]` — Store API key (prompts securely if omitted).
- `pwned auth show` — Show masked key, active source (`cli`, `env`, `dotenv`, `xdg`, `keyring`, `none`), config path, and keyring availability.
- `pwned auth clear [--backend file|keyring]` — Remove stored API key.

#### `pwned cache clear`
Remove all cached JSON files from the XDG cache directory (`~/.cache/pwned`).

#### `pwned completion [bash|zsh|fish]`
Print shell tab-completion script for eval/sourcing.

---

### Core / Pro / High RPM (API Key Required)

#### `pwned account [ACCOUNT]` (`ba`)
Check breaches for an email/username or batch via `--file`/`--stdin`.

| Option | Description |
|---|---|
| `--no-truncate` | Return full breach models instead of names only (single mode) |
| `--domain TEXT` | Filter server-side by breach domain |
| `--no-include-unverified` | Exclude unverified breaches server-side |
| `--since`, `--data-class`, `--verified-only`, `--exclude-retired`, `--sort` | Client-side breach filtering/sorting (single mode) |
| `--file FILE` / `--stdin` | Batch mode (one account per line; comments `#` and blank lines ignored) |
| `--rpm INT` | Requests-per-minute pacing override (auto-detects from `/subscription/status` when omitted) |
| `--baseline FILE` / `--save-baseline FILE` | Diff against or save JSON baseline snapshot |
| `--stats` | Print batch statistics to stderr |
| `--notify-webhook URL` / `--webhook-format [auto\|slack\|discord\|generic]` | Send HTTPS webhook alert on exposures |
| `--fail-if-pwned` | Exit `1` if exposed |

#### `pwned search ACCOUNT`
Composite lookup across breaches, pastes, and optionally stealer logs (`--include-stealer-logs`, `--no-truncate`, `--domain`, `--no-include-unverified`, `--baseline`, `--save-baseline`, `--notify-webhook`, `--webhook-format`, `--fail-if-pwned`).

#### `pwned pastes EMAIL` (`pa`)
List pastes containing an email address.

#### `pwned domain DOMAIN` (`bd`)
List breached aliases for a verified domain (`--baseline`, `--save-baseline`, `--notify-webhook`, `--webhook-format`, `--fail-if-pwned`).

#### `pwned domain-report DOMAIN`
Cross-reference a verified domain's breached aliases (and optional `--include-stealer-logs`) with breach catalog metadata to summarize top breaches, recency, and counts by compromised `DataClasses`. Supports `--cache`, `--notify-webhook`, `--webhook-format`, `--fail-if-pwned`, and all `--format` options (`markdown`, `html`, `json`, `table`, etc.).

#### `pwned monitor`
Run declarative TOML monitoring across accounts and domains (`--config pwned.toml`, `--save-baselines`, `--notify-webhook`, `--webhook-format`, `--fail-if-pwned`). See [Monitoring, Webhooks & CI/CD](monitoring-and-ci.md).

#### `pwned subscribed-domains [list]` (`sd`)
List all verified domains associated with your API key (`pwned subscribed-domains` and `pwned subscribed-domains list` are equivalent).

#### `pwned subscription`
Display subscription tier, expiry, RPM limit, domain limits, and feature flags.

---

### Pro / High RPM

#### `pwned account-range EMAIL` (`bar`)
Query email breaches via 6-character SHA-1 *k*-anonymity prefix without transmitting the plaintext email (`--fail-if-pwned`).

---

### Pro Tier

#### `pwned stealer email|website|domain TARGET`
- `pwned stealer email <email>` — Website domains captured in stealer logs for an email address.
- `pwned stealer website <domain>` — Email addresses captured against a verified website domain.
- `pwned stealer domain <domain>` — Breached email aliases and website domains for a verified email domain.

#### `pwned domain-verify <subcommand>`
- `dns-token <domain>` — Generate DNS TXT verification token.
- `dns-check <domain>` — Verify published DNS TXT record.
- `meta-tag <domain>` — Generate HTML `<meta>` verification tag.
- `meta-check <domain>` — Verify published `<meta>` tag on HTTPS home page.
- `email <domain> <admin|hostmaster|info|security|webmaster>` — Send approval verification email.

#### `pwned subscribed-domains remove DOMAIN` (`sd remove DOMAIN`)
Remove a verified domain from your account (`DELETE /subscribedDomains/{domain}`).
