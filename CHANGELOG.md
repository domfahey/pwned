# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
  - SQLite response caching for public endpoints (`--cache`).
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

[Unreleased]: https://github.com/domfahey/pwned/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/domfahey/pwned/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/domfahey/pwned/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/domfahey/pwned/releases/tag/v0.1.0
