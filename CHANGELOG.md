# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Official HIBP MCP server reference and See Also section in `README.md`
- PEP 561 `py.typed` marker and package metadata in `pyproject.toml`
- Open-source community files (`SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, issue/PR templates, Dependabot config)
- Python 3.12 and 3.13 CI matrix with `uv build` verification

## [0.1.0] - 2026-11-26

### Added
- CLI (`pwned`) and typed Python client (`HIBPClient`, `PwnedPasswordsClient`) for Have I Been Pwned API v3 and Pwned Passwords k-anonymity API
- Support for breaches, latest breach, data classes, account breaches, domain search, subscribed domains, pastes, stealer logs, subscription status, and password checks (SHA-1, NTLM via pure-Python MD4, `--pad`, `--stdin`, interactive prompt)
- Global CLI flags (`--api-key`, `--user-agent`, `--json`, `--version`) accepted before or after subcommands, with `pydantic-settings` env/`.env` configuration
- Structured error hierarchy (`HIBPError`, `NotFoundError`, `UnauthorizedError`, `ForbiddenError`, `RateLimitError`) and automatic 429 retry with capped `Retry-After`
- Strict `mypy`, `ruff` (including Bandit `S` rules), GitHub Actions CI, and unit + integration test suites

[Unreleased]: https://github.com/domfahey/pwned/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/domfahey/pwned/releases/tag/v0.1.0
