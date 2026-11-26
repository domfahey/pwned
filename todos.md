# Roadmap & TODOs

Planned and completed improvements for `pwned`, prioritized from peer HIBP CLI/SDK research (`wKovacs64/pwned`, `wKovacs64/hibp`, `brycx/checkpwn`, `philnash/pwned`, `wneessen/go-hibp`).

## Completed (v0.2.0)

### HIBP API v3 Endpoints
- [x] **Data class descriptions (`dataclasses --descriptions`)** — free endpoint returning data class names with descriptions (`GET /dataclasses/descriptions`).
- [x] **k-Anonymity email breach lookup (`account-range`)** — query email breaches via 6-character SHA-1 email prefix without transmitting the full email (`Pro` / `High RPM`).
- [x] **Domain verification workflow (`domain-verify dns-token|dns-check|email`)** — support `Pro` plan DNS TXT token generation, DNS TXT verification, and approval email requests directly from the CLI.
- [x] **Composite `search <account>` command** — query breaches and pastes (and optionally stealer logs) for an account in a single invocation.
- [x] **Raw password range lookup (`PwnedPasswordsClient.get_password_range(prefix)`)** — expose raw `dict[str, int]` suffix map for library callers doing batch or cached checks.

### CLI UX, Output Formats & Global Configuration
- [x] **Global XDG config fallback (`~/.config/pwned/.env`)** — load user-level config when no local `.env` is present so global installs (`uv tool install`) work from any directory.
- [x] **`pwned auth set|show|clear` command** — interactive setup to store/check/clear API key in `~/.config/pwned/.env` with `0600` permissions on POSIX.
- [x] **Scripting exit codes & thresholds (`--fail-if-pwned`, `--threshold N`)** — clean, predictable exit codes for CI checks, pre-commit hooks, and monitoring scripts.
- [x] **`PwnedPasswordsClient.is_pwned(password, *, threshold=1) -> bool`** — ergonomic boolean helper for application signup validators.
- [x] **Batch account & password checks (`--file` / multi-line `--stdin`)** — audit a list of emails or passwords in one run with automatic subscription RPM pacing (`--rpm` override) and TTY progress output on stderr.
- [x] **Additional output formats (`--format text|json|jsonl|csv|table`)** — structured exports for domain/org audits and cleaner terminal tables (respecting `NO_COLOR` and non-TTY pipes).

### Async, Caching & Vault Auditing
- [x] **`AsyncHIBPClient` & `AsyncPwnedPasswordsClient`** — built on `httpx.AsyncClient` for FastAPI, Starlette, and `asyncio` apps.
- [x] **Expose `RateLimitError.retry_after: int | None`** — attach server `Retry-After` seconds to `RateLimitError` and support configurable `max_retries` (including `0`) and `timeout`.
- [x] **Custom `httpx.Client` / proxy injection** — allow passing an existing `httpx.Client` / `httpx.AsyncClient` or `proxy` config for connection pooling, corporate proxies, and testing.
- [x] **Password-manager export auditing (`pwned audit`)** — locally check Bitwarden JSON/CSV, generic CSV, or KeePass `.kdbx` exports via k-anonymity without sending plaintext passwords over the network.
- [x] **Local cache option for public endpoints (`--cache`, `pwned cache clear`)** — optional file-based XDG TTL cache for `/breaches`, `/dataclasses`, and `/dataclasses/descriptions`.

### Docs, Security & Distribution
- [x] **Document `uvx` zero-install usage** in `README.md` (`uvx --from git+https://github.com/domfahey/pwned.git pwned password`).
- [x] **Group CLI commands by HIBP plan tier** in `README.md` (Free / Core / Pro / High RPM).
- [x] **Dismiss false-positive CodeQL alerts** in GitHub Security tab (SHA-1 required by Pwned Passwords *k*-anonymity + test URL substring assertions).
- [x] **Homebrew formula template (`Formula/pwned.rb`)** — valid template pointing to the GitHub Release tarball for publishing via a `homebrew-tap` repo.
- [x] **ClusterFuzzLite fuzzing (`.github/workflows/cifuzz.yml`)** — Atheris fuzz target covering `_md4`, `_parse_range_response`, `strip_html`, and `parse_input_lines`.

## Completed (v0.3.0 — Ready on `main`, Pending Release Tag)

- [x] **Update `CHANGELOG.md` and architecture doc trees** — rolled post-`v0.2.0` fixes (`ea44a3c`, `c835bec`) and `_parsers.py` doc updates into `0.3.0` on `main`.
- [x] **Integration tests for `v0.2.0` features** — expand `tests/integration/` to cover `AsyncHIBPClient`, `AsyncPwnedPasswordsClient`, `dataclasses --descriptions`, `get_password_range`, `is_pwned`, and `check_hash`.

### Password & Vault Auditing
- [x] **Pre-hashed password lookups (`--hashed` / `check_hash()`)** — accept 40-char SHA-1 or 32-char NTLM hashes directly on `pwned password` and in `PwnedPasswordsClient` / `AsyncPwnedPasswordsClient` (for AD NTLM dumps and pre-hashed lists).
- [x] **Async concurrent password batch & vault auditing** — run `batch_check_passwords` and `audit_entries` concurrently via `AsyncPwnedPasswordsClient` with bounded concurrency (`--concurrency`) for ~10x faster vault audits.
- [x] **Reused-password detection (`pwned audit --check-reuse`)** — report entries sharing duplicate passwords locally during vault audits.
- [x] **Additional password manager & browser export formats** — add zero-dep parsers for 1Password CSV/1PUX, Chrome/Edge CSV, Firefox CSV, and Apple Passwords CSV, plus optional Bitwarden encrypted JSON decryption (`cryptography` extra).

### CLI UX & Library Ergonomics
- [x] **Optional OS Keychain backend (`keyring`)** — optional extra (`pwned[keyring]`) for storing API keys in macOS Keychain / Windows Credential Manager / SecretService via `pwned auth`.
- [x] **Client-side breach filtering & sorting (`breaches` / `account`)** — add `--since YYYY-MM-DD`, `--data-class`, `--verified-only`, `--exclude-retired`, and `--sort pwn-count|date`.
- [x] **Batch summary stats (`--stats`)** — optional stderr summary (`checked / pwned / clean / errors / elapsed`) for batch runs.
- [x] **Shell completions (`pwned completion bash|zsh|fish`)** — expose Click's built-in tab-completion scripts cleanly in CLI and docs.
- [x] **Optional short command aliases** — ergonomic shortcuts inspired by `wKovacs64/pwned` (`pw`, `ba`, `bar`, `pa`, `bd`, `sd`, `lb`, `dc`).
- [x] **Framework password-validator recipes/helpers** — thin validators/docs for Pydantic (`AfterValidator`), FastAPI, and Django built on `is_pwned()` / `AsyncPwnedPasswordsClient.is_pwned()`.

## Completed (v0.4.0 — Offline Lookups, Monitoring & CI Integrations)

- [x] **Offline sorted hash file lookup (`--offline-db <path>` / `OfflinePasswordsClient`)** — `O(log N)` binary search via `seek`/`mmap` (stdlib only) over official `PwnedPasswordsDownloader` SHA-1/NTLM dumps for air-gapped and high-scale checks.
- [x] **Baseline diffing (`--baseline` / `--save-baseline`)** — snapshot known breaches/pastes/stealer logs to JSON and report/exit non-zero only on newly discovered exposures for cron/CI monitoring.
- [x] **SARIF output format (`--format sarif`)** — emit GitHub Code Scanning-compatible SARIF from `account`, `domain`, and `audit`.
- [x] **Reusable GitHub Action / `pre-commit` hook** — composite `action.yml` for scheduled domain/account breach monitoring in CI.
- [x] **Meta-tag domain verification (`domain-verify meta-tag|meta-check`)** — verify and support HIBP HTML `<meta>` tag verification endpoints alongside DNS TXT and email verification.

## Backlog / External

- [ ] **PyPI publishing (optional)** — pick a non-colliding distribution name (since `pwned` is already taken on PyPI) while keeping the `pwned` CLI entrypoint, and configure OIDC Trusted Publishing in `.github/workflows/release.yml`.
- [ ] **OpenSSF Best Practices badge** — manual web registration on `bestpractices.dev`.
