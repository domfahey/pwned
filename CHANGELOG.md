# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.1] - 2026-11-26

### Added
- Comprehensive documentation guides in `docs/` (`cli-reference.md`, `hibp-api-coverage.md`, `python-api.md`, `vault-auditing.md`, `monitoring-and-ci.md`, `offline-and-mcp.md`, `roadmap.md`).
- Hosted MkDocs Material documentation site deployed to GitHub Pages (`mkdocs.yml`, `.github/workflows/docs.yml`) with `make docs` / `make docs-serve` targets.

### Changed
- Organized repository root layout: moved community health files (`SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`) into `.github/`, moved `todos.md` to `docs/roadmap.md`, moved Homebrew formula template to `packaging/homebrew/pwned.rb`, and renamed `.env.sample` to `.env.example`.

### Fixed
- Configured `Settings` with `extra="ignore"` so unrelated keys in local `.env` files do not cause validation failures.
- Switched container release workflow from deprecated `qemu-user-static` to `qemu-user-binfmt` for Ubuntu 26.04 runners and added `workflow_dispatch` support.
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

[Unreleased]: https://github.com/domfahey/pwned/compare/v0.4.1...HEAD
[0.4.1]: https://github.com/domfahey/pwned/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/domfahey/pwned/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/domfahey/pwned/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/domfahey/pwned/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/domfahey/pwned/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/domfahey/pwned/releases/tag/v0.1.0
