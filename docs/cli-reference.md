# CLI Reference

`pwned` exposes all 21 official HIBP API v3 endpoints plus local auditing, offline dumps, declarative monitoring, and a local stdio MCP server.

## Global Options

Global options are accepted **before or after** any subcommand:

| Flag | Default | Description |
|---|---|---|
| `--api-key TEXT` | `None` | HIBP API key override (prefer `HIBP_API_KEY`, `.env`, or keyring over CLI flags to avoid process-table exposure) |
| `--user-agent TEXT` | `pwned-cli` | Custom `User-Agent` header (`HIBP_USER_AGENT`) |
| `--format CHOICE` | `text` | Output format: `text`, `json`, `jsonl`, `csv`, `table`, `sarif`, `markdown`, `html` |
| `--json` | `False` | Shorthand for `--format json` (cannot be combined with `--markdown` or another `--format`) |
| `--markdown` | `False` | Shorthand for `--format markdown` (cannot be combined with `--json` or another `--format`) |
| `--outfile PATH` | `None` | Write formatted UTF-8 output atomically to a file in an existing directory (`auth` commands always write to stdout) |
| `--force` | `False` | Overwrite an existing `--outfile` (or ignore saved ETags and force a full rebuild on `offline download`) |
| `--cache / --no-cache` | `False` | Cache public endpoints (`/breaches`, `/dataclasses*`) and `/range/{prefix}` lookups locally |
| `--version` | — | Show CLI version and exit |

Interactive prompts (`password`, `auth set`, encrypted `audit` vaults) write to `stderr` so piped `--json`/`--format` `stdout` stays clean.

## Credential Precedence

API keys are resolved in order (highest priority first):

1. `--api-key` CLI option
2. `HIBP_API_KEY` environment variable
3. Current working directory `.env`
4. XDG config file (`~/.config/pwned/.env`, written with `0600` POSIX permissions via `pwned auth set --backend file` or as the `--backend auto` fallback when OS Keychain is unavailable)
5. OS Keychain (preferred by `pwned auth set --backend auto` when `pwned[keyring]` is installed — saving to keyring automatically clears any stale `~/.config/pwned/.env` key; also selectable via `--backend keyring`)

## Short Command Aliases

| Alias | Command |
|---|---|
| `pw` | `password` |
| `pr` | `password-range` |
| `ba` | `account` |
| `bar` | `account-range` |
| `pa` | `pastes` |
| `bd` | `domain` |
| `sd` | `subscribed-domains` |
| `lb` | `latest-breach` |
| `dc` | `dataclasses` |

## Exit Codes

Exit codes mirror the official [Have I Been Pwned CLI (`hibp`)](https://haveibeenpwned.com/cli):

| Code | Constant | Meaning |
|---|---|---|
| `0` | `ExitCode.OK` | Success, including clean (no-match) results on `account`, `domain`, `pastes`, `stealer`, `search`, `account-range`, `password`, `password-range`, `audit`, `domain-report`, and `monitor` |
| `1` | `ExitCode.ERROR` | Unexpected failure (e.g., API response schema mismatch) |
| `2` | `ExitCode.INVALID_USAGE` | Invalid CLI usage/arguments, conflicting flags, invalid hash or webhook URL, or rejected API request (`HTTP 400`) |
| `3` | `ExitCode.AUTH_ERROR` | Missing or rejected API key (`HTTP 401`) |
| `4` | `ExitCode.FORBIDDEN` | Permission or subscription restriction (`HTTP 403`) |
| `5` | `ExitCode.RATE_LIMITED` | Rate limit exhausted after retries (`HTTP 429`) |
| `6` | `ExitCode.NETWORK_ERROR` | Network, timeout, webhook delivery, or upstream service failure (`HTTP 5xx`) |
| `7` | `ExitCode.FILE_OR_STORE_ERROR` | Local file, baseline, vault, monitor config, or credential-store failure |
| `8` | `ExitCode.FINDINGS` | Exposures detected with `--fail-if-pwned` / `--fail-if-found` |
| `9` | `ExitCode.NOT_FOUND` | Resource missing (e.g., unknown `breach` name) or domain verification unsuccessful (`HTTP 404`) |
| `130` | `ExitCode.CANCELLED` | Cancelled by user (`Ctrl+C` / prompt abort) |

---

## Commands by Plan Tier

### Free / No API Key Required

#### `pwned password [PASSWORD]` (`pw`)
Check one or more passwords or pre-computed hashes against Pwned Passwords (*k*-anonymity or local dump). Prompts interactively with hidden input if no argument, `--stdin`, or `--file` is supplied.

| Option | Default | Description |
|---|---|---|
| `--stdin` | `False` | Read single or multi-line passwords/hashes from stdin |
| `--file FILE` | `None` | Batch-check passwords/hashes (one per line) from file, preserving blank lines and exact 1-based line numbers |
| `--mode [sha1\|ntlm]` | `sha1` | Hash algorithm mode: `sha1` or `ntlm` |
| `-n`, `--ntlm` | `False` | Use NTLM hash (`?mode=ntlm`) instead of SHA-1 (overrides `--mode`) |
| `--pad / --no-pad` | `True` | Send `Add-Padding: true` header for traffic-analysis resistance (`--no-pad` to disable) |
| `--hashed` | `False` | Treat input(s) as pre-computed 40-char SHA-1 or 32-char NTLM hashes |
| `--offline-db PATH` | `None` | Query a local sorted HIBP dump file or per-prefix range directory (`00000.txt`–`FFFFF.txt`) instead of the network API |
| `--concurrency`, `--parallelism`, `-p INT` | `10` | Max concurrent requests in online batch mode |
| `--stats` | `False` | Print batch summary stats (`checked / pwned / clean / errors / elapsed`) to stderr |
| `--threshold INT` | `1` | Minimum breach count to treat as pwned |
| `--fail-if-pwned` / `--fail-if-found` | `False` | Exit `8` if count meets threshold |

#### `pwned password-range PREFIX` (`pr`)
Query the raw Pwned Passwords *k*-anonymity range for a 5-character hexadecimal hash prefix (`00000`–`FFFFF`) and return the suffix-to-count map (zero-count padding entries stripped). Supports global `--cache`.

| Option | Default | Description |
|---|---|---|
| `--mode [sha1\|ntlm]` | `sha1` | Hash algorithm mode: `sha1` or `ntlm` |
| `-n`, `--ntlm` | `False` | Query NTLM hash range (`?mode=ntlm`) instead of SHA-1 (overrides `--mode`) |
| `--pad / --no-pad` | `True` | Send `Add-Padding: true` header for traffic-analysis resistance (`--no-pad` to disable) |
| `--fail-if-pwned` / `--fail-if-found` | `False` | Exit `8` if the returned range is non-empty |
| `--cache / --no-cache` | `False` | Global option: cache `/range/{prefix}` responses locally |

#### `pwned audit [PATH]`
Audit a password-manager export, browser CSV, Active Directory `pwdump` file, or local `pass`/`gopass` store. Supports `--mode [sha1|ntlm]`, `-n`/`--ntlm`, `--concurrency`/`--parallelism`/`-p`, and `--offline-db` (accepting either a single sorted dump file or a per-prefix range directory `00000.txt`–`FFFFF.txt`). See [Vault & Active Directory Auditing](vault-auditing.md).

#### `pwned offline download OUTPUT`
Download an offline Pwned Passwords corpus (`00000`–`FFFFF`) as a per-prefix range directory (`00000.txt`–`FFFFF.txt`, default) or a single merged sorted dump (`--single` / `-s`). See [Offline Lookups & Local MCP Server](offline-and-mcp.md).

#### `pwned mcp`
Start the local zero-dependency stdio MCP server (`--offline-db` accepting either a single sorted dump file or a per-prefix range directory `00000.txt`–`FFFFF.txt`, `--ntlm`, global `--cache`). See [Offline Lookups & Local MCP Server](offline-and-mcp.md).

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
- `pwned auth set [API_KEY] [--stdin] [--backend auto|file|keyring]` — Store API key (reads from standard input with `--stdin`, or prompts securely on `stderr` if omitted; default `auto` prefers OS keyring when `pwned[keyring]` is installed and falls back to `~/.config/pwned/.env` with `0600` permissions). Saving to the OS keyring automatically removes any stale `HIBP_API_KEY` entry in `~/.config/pwned/.env` so it cannot shadow the keychain.
- `pwned auth show` — Show masked key, active source (`cli`, `env`, `dotenv`, `xdg`, `keyring`, `none`), config path, and keyring availability.
- `pwned auth clear [--backend auto|file|keyring]` — Remove stored API key (default `auto` clears both OS keyring when available and config file; exits `7` if keyring cleanup fails).

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
| `--no-truncate` / `--full` | Return full breach models instead of names only (single mode) |
| `--domain TEXT` | Filter server-side by breach domain |
| `--no-include-unverified` | Exclude unverified breaches server-side |
| `--since`, `--data-class`, `--verified-only`, `--exclude-retired`, `--sort` | Client-side breach filtering/sorting (single mode) |
| `--file FILE` / `--stdin` | Batch mode (one account per line; comments `#` and blank lines ignored) |
| `--rpm INT` | Requests-per-minute pacing override (auto-detects from `/subscription/status` when omitted) |
| `--baseline FILE` / `--save-baseline FILE` | Diff against or save JSON baseline snapshot |
| `--stats` | Print batch statistics to stderr |
| `--notify-webhook URL` / `--webhook-format [auto\|slack\|discord\|generic]` | Send HTTPS webhook alert on exposures |
| `--fail-if-pwned` / `--fail-if-found` | Exit `8` if exposed |

#### `pwned search ACCOUNT`
Composite lookup across breaches, pastes, and optionally stealer logs (`--include-stealer-logs`, `--no-truncate` / `--full`, `--domain`, `--no-include-unverified`, `--baseline`, `--save-baseline`, `--notify-webhook`, `--webhook-format`, `--fail-if-pwned` / `--fail-if-found`).

#### `pwned pastes EMAIL` (`pa`)
List pastes containing an email address (`--fail-if-pwned` / `--fail-if-found` exits `8` if found).

#### `pwned domain DOMAIN` (`bd`)
List breached aliases for a verified domain (`--baseline`, `--save-baseline`, `--notify-webhook`, `--webhook-format`, `--fail-if-pwned` / `--fail-if-found`).

#### `pwned domain-report DOMAIN`
Cross-reference a verified domain's breached aliases (and optional `--include-stealer-logs`) with breach catalog metadata to summarize top breaches, recency, and counts by compromised `DataClasses`. Supports `--cache`, `--notify-webhook`, `--webhook-format`, `--fail-if-pwned` / `--fail-if-found`, and all `--format` options (`markdown`, `html`, `json`, `table`, etc.).

#### `pwned monitor`
Run declarative TOML monitoring across accounts and domains (`--config pwned.toml`, `--save-baselines`, `--notify-webhook`, `--webhook-format`, `--fail-if-pwned` / `--fail-if-found`). See [Monitoring, Webhooks & CI/CD](monitoring-and-ci.md).

#### `pwned subscribed-domains [list]` (`sd`)
List all verified domains associated with your API key (`pwned subscribed-domains` and `pwned subscribed-domains list` are equivalent).

#### `pwned subscription`
Display subscription tier, expiry, RPM limit, domain limits, and feature flags.

---

### Pro / High RPM

#### `pwned account-range TARGET` (`bar`)
Query email breaches via HIBP's 6-character SHA-1 *k*-anonymity prefix API (`--fail-if-pwned` / `--fail-if-found` exits `8` if breaches are found). `TARGET` accepts either:

- **Email address** (e.g., `user@example.com`) — hashed locally with SHA-1 so only the 6-character prefix is transmitted and matching breaches for that exact email are returned.
- **Raw 6-character SHA-1 hex prefix** (e.g., `21BD12`) — queries the prefix directly and returns all matching SHA-1 suffixes and their breach names.

---

### Pro Tier

#### `pwned stealer email|website|domain TARGET`
- `pwned stealer email <email>` — Website domains captured in stealer logs for an email address (`--fail-if-pwned` / `--fail-if-found` exits `8` if found).
- `pwned stealer website <domain>` — Email addresses captured against a verified website domain (`--fail-if-pwned` / `--fail-if-found` exits `8` if found).
- `pwned stealer domain <domain>` — Breached email aliases and website domains for a verified email domain (`--fail-if-pwned` / `--fail-if-found` exits `8` if found).

#### `pwned domain-verify <subcommand>`
- `dns-token <domain>` — Generate DNS TXT verification token.
- `dns-check <domain>` — Verify published DNS TXT record.
- `meta-tag <domain>` — Generate HTML `<meta>` verification tag.
- `meta-check <domain>` — Verify published `<meta>` tag on HTTPS home page.
- `email <domain> <admin|hostmaster|info|security|webmaster>` — Send approval verification email.

#### `pwned subscribed-domains remove DOMAIN` (`sd remove DOMAIN`)
Remove a verified domain from your account (`DELETE /subscribedDomains/{domain}`).
