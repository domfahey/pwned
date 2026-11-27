# `pwned` Documentation

Complete user and developer documentation for `pwned` — the command-line interface, typed Python SDK, offline password auditor, declarative breach monitor, and local privacy-first MCP server for [Have I Been Pwned](https://haveibeenpwned.com/).

## Guides

| Guide | What It Covers |
|---|---|
| [CLI Reference](cli-reference.md) | All commands, subcommands, short aliases, global options, output formats (`text`, `json`, `jsonl`, `csv`, `table`, `sarif`, `markdown`, `html`), credential precedence, and exit codes |
| [HIBP API v3 Coverage](hibp-api-coverage.md) | Full 21 / 21 HIBP API v3 endpoint matrix, response model field parity, headers, rate limiting, error parsing, and test accounts |
| [Python Library Guide](python-api.md) | Sync & async HIBP and Pwned Passwords clients, caching, retry jitter, batching, framework validators (Pydantic/FastAPI/Django), reporting, webhooks, and exception handling |
| [Vault & Active Directory Auditing](vault-auditing.md) | Auditing 16 password manager, browser, Active Directory `pwdump`/`secretsdump`, and Unix `pass`/`gopass` sources locally with `--check-reuse` and `--check-strength` |
| [Monitoring, Webhooks & CI/CD](monitoring-and-ci.md) | Declarative `pwned.toml` monitoring, baseline diffing, Slack/Discord/generic webhooks, SARIF/Markdown/HTML reports, GitHub Action, pre-commit hook, and Docker images |
| [Offline Lookups & Local MCP Server](offline-and-mcp.md) | Resumable Pwned Passwords dump downloads, `O(log N)` air-gapped binary search, and local privacy-first stdio MCP server (`pwned mcp`) vs. HIBP's remote MCP server |

## Project References

- [README](../README.md) — Quickstart, installation, and feature overview
- [Roadmap](roadmap.md) — Completed milestones and backlog
- [CHANGELOG](../CHANGELOG.md) — Release history
- [Security Policy](../.github/SECURITY.md) — Vulnerability reporting and security design
- [Contributing](../.github/CONTRIBUTING.md) — Local development setup and testing workflow
- [Code of Conduct](../.github/CODE_OF_CONDUCT.md) — Community standards
