# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.6.0] - 2026-11-28

### Added
- Release assets now include a CycloneDX SBOM (`pwned-<version>.cdx.json`) and the Sigstore-signed build provenance bundle (`pwned-<version>.sigstore.json`), verifiable with `gh attestation verify <file> --bundle pwned-<version>.sigstore.json --repo domfahey/pwned`.
- Added extended Active Directory `pwdump` credential hygiene checks (`--check-ad-hygiene`, `--exclude-machines`, `ADHygieneFinding`, `EMPTY_LM_HASH`, `EMPTY_NTLM_HASH`, `parse_pwdump_records()`) to detect empty NTLM hashes (`31D6CFE0D16AE931B73C59D7E0C089C0`), present legacy LM hashes, and username-as-password matches (including case variants, `$` computer names, and UPN local-parts), plus `$` machine-account filtering across CLI, Python API, and local MCP `audit_vault`.
- Added custom organizational banned wordlist screening (`--custom-wordlist <file>`, `load_custom_wordlist()`, `WordlistFinding`) supporting `exact` and `case_insensitive` matches on plaintext vaults plus `exact` and `case_variant` (`lower`/`upper`/`capitalize`/`title`) matches on pre-hashed NTLM/SHA-1 dumps without exposing secrets, along with Markdown/HTML report sections, webhook exposure triggers, `--fail-if-pwned` exit code `8` support, and SARIF rules `HIBP005` (`ADCredentialHygiene`) and `HIBP006` (`BannedWordlistPassword`).
- Added live cloud vault CLI connectors (`--source bitwarden-cli` via `bw`/`rbw` and `--source 1password-cli` via `op`, `parse_bitwarden_cli()`, `parse_1password_cli()`) to audit unlocked Bitwarden and 1Password vaults directly in memory without writing plaintext exports across CLI, Python API, and local MCP `audit_vault`.
- Added vault breach and stealer-log correlation (`pwned audit --check-breaches`, `--include-stealer-logs`, `BreachCorrelationFinding`, `extract_domain()`) supporting zero-API-key site-domain catalog matching (`GET /breaches` with `--cache`), authenticated email breach lookups, Pro-tier stealer-log correlation, Markdown/HTML tables, SARIF rule `HIBP007` (`VaultBreachCorrelation`), `--fail-if-pwned` exit code `8` support, and local MCP `audit_vault` (`check_breaches`).
- Added a self-hosted HIBP-compatible *k*-anonymity HTTP server and caching proxy (`pwned serve`, `PwnedRangeServer`, `create_range_server()`, `ServerHealth`, `ServerMetrics`) serving `GET /range/<5-hex>` (with `?mode=sha1|ntlm` and `Add-Padding: true`), `GET /healthz`, and Prometheus `GET /metrics` backed by `--offline-db` or an upstream `--cache` proxy.
- Added SQLite exposure history and remediation tracking (`pwned monitor --db`, `db` in `pwned.toml`, `pwned domain-report --history-db`, `ExposureHistoryStore`, `ExposureRecord`, `HistoryTrendSummary`, `HistorySyncResult`) to persist first-seen, last-seen, and resolved timestamps across monitoring runs without falsely resolving errored or smart-precheck-skipped targets and surface remediation trends in Markdown, HTML, and JSON reports.
- Added compact offline hash indexes (`pwned offline compact` for ~50% smaller `PWNB` fixed-width binary files with an `O(1)` 1,048,576-prefix jump table and exact counts, plus `pwned offline build-bloom` for sub-1 GB mmap-able `PWNL` Bloom filters with zero false negatives; `build_compact_index()`, `build_bloom_filter()`, `CompactIndexReader`, `BloomFilterReader`, `CompactIndexStats`, `BloomIndexStats`, `OfflinePasswordsClient.format`), with transparent auto-detection across `password`, `audit`, `mcp`, `doctor`, and (for compact `PWNB` indexes) `serve`.
- Added expanded alert destinations: Microsoft Teams Adaptive Cards v1.4 (`--webhook-format teams` / auto-detected for `.webhook.office.com`, `.logic.azure.com`, and `.api.powerplatform.com` workflows URLs), PagerDuty Events API v2 (`--webhook-format pagerduty` / auto-detected for `events.pagerduty.com` & `events.eu.pagerduty.com`, `pagerduty_routing_key`, `pagerduty_severity`, `--pagerduty-routing-key` / `PAGERDUTY_ROUTING_KEY`), SMTP email (`[notify.email]`, `EmailNotifyConfig`, `send_email_notification()`), and GitHub Issue auto-creation/commenting (`[notify.github_issue]`, `GitHubIssueNotifyConfig`, `send_github_issue_notification()`, `MonitorReport.notifications_sent`).

## [0.5.0] - 2026-11-27

### Added
- Exported `ExitCode` (`IntEnum` mirroring official HIBP CLI codes `0`–`9` and `130`) and `BadRequestError` (HTTP `400` subclass of `HIBPError`) from `pwned`.
- Added `--fail-if-pwned` (exit `8`) to `pwned pastes` and `pwned stealer email|website|domain` for consistent CI scripting across all search commands.
- Added `pwned password-range <5-hex>` (alias `pr`) for raw Pwned Passwords *k*-anonymity range lookups and raw 6-character SHA-1 hex prefix support on `pwned account-range`.
- Added global `--outfile <path>` and `--force` options for atomic UTF-8 file output from data commands.
- Added global `--markdown` shorthand (for `--format markdown`), `--mode sha1|ntlm` and `-n` aliases (for `--ntlm`, including `pwned mcp`), and `--parallelism` / `-p` aliases (for `--concurrency`).
- Added non-interactive `pwned auth set --stdin` to read `HIBP_API_KEY` from standard input.
- Added `--full` alias (for `--no-truncate` on `account`/`search`) and `--fail-if-found` alias (for `--fail-if-pwned`).
- Added per-prefix offline dump directory mode (`00000.txt`–`FFFFF.txt` + `.pwned-index.json` hash-mode & ETag index with periodic checkpointing and atomic per-prefix writes) to `download_offline_db(..., directory=True)` and `pwned offline download` (`--single`/`-s` for merged sorted files, `--max-retries` with unlimited retries when omitted or `0` to disable, `--overwrite` / `-o`, `--force-refresh` ETag rebuild, `ranges_per_second` and `directory` fields in `DownloadStats`, and stderr TTY progress reporting), plus `O(1)` directory lookups with hash-mode validation in `OfflinePasswordsClient` and `--offline-db` across `password`, `audit`, and `mcp`.
- Added `pwned doctor` CLI subcommand and `run_doctor()` / `DoctorReport` / `DoctorCheck` Python API to verify HIBP API connectivity, subscription tier/RPM, active credential source, OS Keychain availability, local cache size, and optional `--offline-db` integrity (with `--no-network`, `--mode`, and `-n`/`--ntlm`).
- Added smart `GET /latestBreach` pre-check (`smart_precheck = true` in `pwned.toml` or `pwned monitor --smart-precheck`, plus `domains_skipped` on `MonitorReport`) to skip redundant `GET /breachedDomain/{domain}` queries when no new breach has been added since the last baseline snapshot.
- Added a compact CC BY 4.0 Have I Been Pwned attribution footer to `--format markdown` breach, paste, domain, vault audit, and monitor reports (matching `README.md` and `--format html`).
- Added `skip_empty: bool = True` parameter to `parse_input_lines()` and `load_input_file()`.

### Changed
- Mirrored official Have I Been Pwned CLI (`hibp`) exit codes: `0` success/clean search, `1` unexpected/schema failure, `2` invalid usage or HTTP `400` (`BadRequestError`), `3` missing/rejected API key (`401`), `4` permission/plan restriction (`403`), `5` rate limit exhausted (`429`), `6` network/timeout/upstream failure (`5xx`), `7` file/config/vault/credential-store failure, `8` findings with `--fail-if-pwned` (previously `1`), `9` missing resource or failed domain verification (`404`), and `130` cancelled (`Ctrl+C`/prompt abort).
- Enabled response padding (`Add-Padding: true`) by default on `pwned password`, `pwned audit` (`--pad/--no-pad`), and `PwnedPasswordsClient` / `AsyncPwnedPasswordsClient` (`pad: bool = True`).
- Routed all interactive CLI prompts (`password`, `auth set`, `audit` KeePass/Bitwarden) to `stderr` (`err=True`) so piped `--json`/`--format` stdout stays clean.
- Changed `pwned auth set` and `pwned auth clear` `--backend` default from `file` to `auto` (prefers OS Keychain when `pwned[keyring]` is installed and usable, falling back to `0600` `~/.config/pwned/.env`); saving to OS keyring now cleans up any stale `~/.config/pwned/.env` key, and `pwned auth clear` reports keyring errors with exit code `7`.
- Changed `pwned offline download` CLI default to per-prefix directory mode (`00000.txt`–`FFFFF.txt` + `.pwned-index.json`) for direct interoperability with official `hibp password download` (use `--single`/`-s` for a merged sorted file), backed by a bounded async worker pool for flat memory usage across 1,048,576 prefixes.
- Changed `pwned password --file` and multi-line `--stdin` to skip blank lines without hashing `""` while preserving exact 1-based line numbers (`skip_empty=False` in `load_input_file`/`parse_input_lines`).
- Changed no-match (`404`) search responses on `account`, `domain`, `pastes`, and `stealer` to exit `0` with clean status text (or empty `[]` / `{}` in JSON), reserving non-zero exits for `--fail-if-pwned`, unknown catalog breaches (`breach`), failed domain verification, and errors.
- Switched `README.md` zero-install `uvx` Quickstart to a pinned, zero-secret public lookup (`@v0.5.0 pwned breach Adobe`) and pinned `uv tool install` examples.

### Fixed
- Re-raised `BrokenPipeError` in `handle_errors` for clean Unix piping.

## [0.4.1] - 2026-11-26

### Added
- Comprehensive documentation guides in `docs/` (`cli-reference.md`, `hibp-api-coverage.md`, `python-api.md`, `vault-auditing.md`, `monitoring-and-ci.md`, `offline-and-mcp.md`, `roadmap.md`).
- Hosted MkDocs Material documentation site deployed to GitHub Pages (`mkdocs.yml`, `.github/workflows/docs.yml`) with `make docs` / `make docs-serve` targets.
- GitHub Marketplace `branding` (`shield` / `blue`) in `action.yml` and self-documenting `Makefile` targets (`help`, `install-all`, `build`, `clean`, enhanced `doctor`).

### Changed
- Organized repository root layout: moved community health files (`SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`) into `.github/`, moved `todos.md` to `docs/roadmap.md`, moved Homebrew formula template to `packaging/homebrew/pwned.rb`, and renamed `.env.sample` to `.env.example`.
- Defaulted `action.yml` `version` input to `github.action_ref` (falling back to `main`) so pinned workflow tags execute the matching `pwned` version.

### Fixed
- Configured `Settings` with `extra="ignore"` so unrelated keys in local `.env` files do not cause validation failures.
- Switched container release workflow from deprecated `qemu-user-static` to `qemu-user-binfmt` for Ubuntu 26.04 runners and added `workflow_dispatch` support.
- Removed `.clusterfuzzlite` from `.dockerignore` so ClusterFuzzLite PR fuzzing builds cleanly.
- Updated historical `CHANGELOG.md` link for `packaging/homebrew/pwned.rb`.

## [0.4.0] - 2026-11-26

### Added
- **Full HIBP API v3 Parity**:
  - `DELETE /subscribedDomains/{domain}` via `HIBPClient.remove_subscribed_domain()`, `AsyncHIBPClient.remove_subscribed_domain()`, and `pwned subscribed-domains remove <domain>` (retaining backwards-compatible `pwned subscribed-domains` / `pwned sd` listing alongside `subscribed-domains list`).
  - `includeUnverified=false` server-side filtering on `GET /breaches` via `get_breaches(include_unverified=False)` and `pwned breaches --no-include-unverified`.
  - Live integration test coverage for `breaches --no-include-unverified`, `opt-out-breach`, and `paste-sensitive-breach` test accounts, plus CC BY 4.0 HIBP data attribution in `README.md`.
- **Enterprise & Active Directory Auditing**:
  - `pwdump` / `secretsdump` / `NTDS` hash dump auditing (`pwned audit --source pwdump`) parsing NTLM hashes with `--check-reuse` support.
  - Built-in resumable Pwned Passwords dump downloader (`pwned offline download <output>`) supporting `--ntlm`, `--concurrency`, `--resume`, and ETag caching.
  - Bitwarden Argon2id encrypted JSON support (`kdfType=1`) using `cryptography>=44.0`.
- **Vault & Password Hygiene**:
  - Expanded password manager and browser support: LastPass CSV, Dashlane CSV, Proton Pass CSV, and live Unix `pass` / `gopass` store auditing.
  - Combined strength and risk scoring (`--check-strength`) utilizing zero-dependency heuristics or optional `zxcvbn` (`strength` extra).
  - Opt-in `--cache` support for Pwned Passwords range prefix queries (`/range/{prefix}`).
- **Monitoring, Reporting & Alerting**:
  - Markdown (`--format markdown`) and standalone HTML (`--format html`) report generation.
  - Declarative TOML exposure monitoring engine (`pwned monitor --config pwned.toml`).
  - Webhook notifications (`--notify-webhook <url>`, `--webhook-format auto|slack|discord|generic`) on newly discovered exposures.
  - Domain exposure risk summary (`pwned domain-report <domain>`).
- **Ecosystem & Distribution**:
  - Built-in zero-dependency local privacy-first stdio Model Context Protocol server (`pwned mcp`).
  - Async account batch checks (`async_batch_check_accounts`) with jittered 429 backoff (`retry_jitter`).
  - Multi-architecture container images published to GitHub Container Registry (`ghcr.io/domfahey/pwned`).

### Fixed
- Parsed JSON-string and `text/plain` HIBP error bodies (while still ignoring HTML/binary error pages) and surfaced endpoint-specific `401` and `404` details (such as `verifyMetaTag` diagnostics) in `UnauthorizedError`, `NotFoundError`, and CLI error output.

## [0.3.0] - 2026-11-26

### Added
- **Password Pre-Hashed Lookups & Offline Hash Files**:
  - Support pre-hashed 40-char SHA-1 or 32-char NTLM hashes via `--hashed` in `pwned password` and `check_hash()` across sync/async Pwned Passwords clients.
  - `OfflinePasswordsClient` for fast `O(log N)` binary search over official local Pwned Passwords SHA-1/NTLM text dumps (`--offline-db <path>`).
- **Expanded Vault & Browser Audit Formats**:
  - Vault and browser export auditing supporting 10 source formats: Bitwarden JSON, Bitwarden Encrypted JSON (`cryptography` extra), Bitwarden CSV, 1Password CSV, 1Password 1PUX, Chrome/Edge CSV, Firefox CSV, Apple Passwords CSV, generic CSV, and KeePass `.kdbx` (`pykeepass` extra).
  - Reused-password detection during vault audits (`--check-reuse`).
- **Async Concurrency & Performance**:
  - Bounded async concurrency (`--concurrency`) for vault audits and batch password checks.
- **Breach Filtering, Sorting & Monitoring**:
  - Client-side filtering and sorting for breaches and account checks (`--since YYYY-MM-DD`, `--data-class`, `--verified-only`, `--exclude-retired`, `--sort pwn-count|date|name`).
  - Exposure baseline snapshotting and diffing (`--baseline`, `--save-baseline`) for cron/CI monitoring.
- **SARIF & Batch Summary Stats**:
  - GitHub Code Scanning-compatible SARIF output (`--format sarif`).
  - Batch summary execution statistics on stderr (`--stats`).
- **Domain Verification & Shell Completions**:
  - HTML meta-tag domain ownership verification (`domain-verify meta-tag|meta-check`).
  - Shell tab-completion script generation (`completion bash|zsh|fish`).
- **OS Keychain & Short Aliases**:
  - Optional OS Keychain credential backend via `pwned auth set|clear --backend keyring` (`keyring` extra) with source reporting in `pwned auth show`.
  - Ergonomic short command aliases (`pw`, `ba`, `bar`, `pa`, `bd`, `sd`, `lb`, `dc`).
- **Framework Validators & CI Integration**:
  - Password validator factories and helpers for Pydantic, FastAPI, and Django (`pwned.validators`).
  - Reusable GitHub Action (`action.yml`) and pre-commit hook configuration (`.pre-commit-hooks.yaml`).
- **Expanded Integration Test Suite**:
  - Live API integration tests covering async clients, data class descriptions, password range/hash lookups, SARIF output, and `--fail-if-pwned`.

### Fixed
- Handled CPython `HTMLParser` `AssertionError` on malformed SGML marked sections in `strip_html` (discovered by ClusterFuzzLite).
- Wired automatic subscription RPM detection, TTY stderr progress, duplicate password line-index preservation, `--no-truncate` batch rejection, `NO_COLOR`/TTY status styling, and missing-home resilience in `auth show`.
- Fixed [packaging/homebrew/pwned.rb](packaging/homebrew/pwned.rb) Ruby syntax/URL and extracted standalone `_parsers.py` so ClusterFuzzLite builds without native Rust compilation.

## [0.2.0] - 2026-11-26

### Added
- **Async HIBP & Pwned Passwords Clients**: `AsyncHIBPClient` and `AsyncPwnedPasswordsClient` built on `httpx.AsyncClient` for async applications.
- **New HIBP API Endpoints & Features**:
  - Data class descriptions (`dataclasses --descriptions` / `client.get_data_class_descriptions()`).
  - k-Anonymity email breach check (`account-range <email>`).
  - Domain verification management (`domain-verify dns-token|dns-check|email`).
  - Composite search command (`search <account>` querying breaches, pastes, and stealer logs).
- **Batch Operations & Scripting Controls**:
  - Batch account and password audits via `--file` or multi-line `--stdin` with RPM rate limiting (`--rpm`).
  - Scripting exit codes and thresholds (`--fail-if-pwned`, `--threshold N`, `PwnedPasswordsClient.is_pwned()`).
- **Flexible Output Formats & Local Caching**:
  - Structured output formats (`--format text|json|jsonl|csv|table`).
  - File-based XDG TTL response caching for public endpoints (`--cache` / `--no-cache`, `pwned cache clear`).
- **Vault Auditing**:
  - Password manager export auditing (`pwned audit --source bitwarden-json|bitwarden-csv|csv|keepass`).
- **Global Configuration & XDG Credential Management**:
  - XDG config fallback (`~/.config/pwned/.env`) and `pwned auth set|show|clear` command with secure `0600` permissions.
- **Zero-Install & Packaging Improvements**:
  - `uvx` zero-install guidance and optional KeePass extras (`pwned[keepass]`).

## [0.1.1] - 2026-11-26

### Added
- Official HIBP MCP server reference, Python library usage snippet, badges, and See Also section in `README.md`
- PEP 561 `py.typed` marker and full package metadata (including Python 3.14 classifier and `sdist` exclusions) in `pyproject.toml`
- Open-source community files (`SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, issue forms, PR template)
- Automated release workflow (`.github/workflows/release.yml`) with wheel/sdist uploads and SLSA build provenance attestations
- Grouped Dependabot configuration for `uv` and `github-actions`

### Changed
- Hardened CI with SHA-pinned actions (`persist-credentials: false`), Python 3.12–3.14 + Linux/macOS/Windows matrix, and 95% coverage floor
- Upgraded runtime and development dependencies (`pydantic` 2.14.4, `pydantic-settings` 2.16.3, `click` 8.5.1, `pytest` 9.2.0, `mypy` 2.4.1, `ruff` 0.17.6)

## [0.1.0] - 2026-11-26

### Added
- CLI (`pwned`) and typed Python client (`HIBPClient`, `PwnedPasswordsClient`) for Have I Been Pwned API v3 and Pwned Passwords k-anonymity API
- Support for breaches, latest breach, data classes, account breaches, domain search, subscribed domains, pastes, stealer logs, subscription status, and password checks (SHA-1, NTLM via pure-Python MD4, `--pad`, `--stdin`, interactive prompt)
- Global CLI flags (`--api-key`, `--user-agent`, `--json`, `--version`) accepted before or after subcommands, with `pydantic-settings` env/`.env` configuration
- Structured error hierarchy (`HIBPError`, `NotFoundError`, `UnauthorizedError`, `ForbiddenError`, `RateLimitError`) and automatic 429 retry with capped `Retry-After`
- Strict `mypy`, `ruff` (including Bandit `S` rules), GitHub Actions CI, and unit + integration test suites

[Unreleased]: https://github.com/domfahey/pwned/compare/v0.6.0...HEAD
[0.6.0]: https://github.com/domfahey/pwned/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/domfahey/pwned/compare/v0.4.1...v0.5.0
[0.4.1]: https://github.com/domfahey/pwned/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/domfahey/pwned/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/domfahey/pwned/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/domfahey/pwned/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/domfahey/pwned/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/domfahey/pwned/releases/tag/v0.1.0
