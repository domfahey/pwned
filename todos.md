# Roadmap & TODOs

Planned improvements for `pwned`, prioritized from peer HIBP CLI/SDK research (`wKovacs64/pwned`, `wKovacs64/hibp`, `brycx/checkpwn`, `philnash/pwned`, `wneessen/go-hibp`).

## v0.2.0 — API Parity, Global Config & Async Clients

### New HIBP API v3 Endpoints
- [x] **Data class descriptions (`dataclasses --descriptions`)** — free endpoint returning data class names with descriptions (`GET /dataclasses/descriptions`).
- [x] **k-Anonymity email breach lookup (`account-range`)** — query email breaches via 6-character SHA-1 email prefix without transmitting the full email (`Pro` / `High RPM`).
- [x] **Domain verification workflow (`domain verify ...`)** — support `Pro` plan DNS TXT token generation, DNS TXT verification, and approval email requests directly from the CLI.
- [x] **Composite `search <account>` command** — query breaches and pastes (and optionally stealer logs) for an account in a single invocation.
- [x] **Raw password range lookup (`PwnedPasswordsClient.get_password_range(prefix)`)** — expose raw `dict[str, int]` suffix map for library callers doing batch or cached checks.

### CLI UX & Global Configuration
- [x] **Global XDG config fallback (`~/.config/pwned/.env`)** — load user-level config when no local `.env` is present so global installs (`uv tool install`) work from any directory.
- [x] **`pwned auth` / `config` command** — interactive setup to store/check/clear API key (file with `0600` permissions, or optional OS Keychain via `keyring`).
- [x] **Scripting exit codes & thresholds (`--fail-if-pwned`, `--threshold N`)** — clean, predictable exit codes for CI checks, pre-commit hooks, and monitoring scripts.
- [x] **`PwnedPasswordsClient.is_pwned(password, *, threshold=1) -> bool`** — ergonomic boolean helper for application signup validators.

### Async & Library Ergonomics (Zero New Runtime Dependencies)
- [x] **`AsyncHIBPClient` & `AsyncPwnedPasswordsClient`** — built on `httpx.AsyncClient` for FastAPI, Starlette, and `asyncio` apps.
- [x] **Expose `RateLimitError.retry_after: int | None`** — attach server `Retry-After` seconds to `RateLimitError` and support configurable `max_retries` (including `0`) and `timeout`.
- [x] **Custom `httpx.Client` / proxy injection** — allow passing an existing `httpx.Client` / `httpx.AsyncClient` or `proxy` config for connection pooling, corporate proxies, and testing.

## v0.3.0 — Bulk Operations & Output Formats

- [x] **Batch account & password checks (`--file` / multi-line `--stdin`)** — audit a list of emails or passwords in one run with automatic RPM-aware rate limiting and progress output.
- [x] **Additional output formats (`--format text|json|jsonl|csv|table`)** — structured exports for domain/org audits and cleaner terminal tables (respecting `NO_COLOR` and non-TTY pipes).

## Docs, Security & Distribution

- [x] **Document `uvx` zero-install usage** in `README.md` (`uvx --from git+https://github.com/domfahey/pwned.git pwned password`).
- [x] **Group CLI commands by HIBP plan tier** in `README.md` (Free / Core / Pro / High RPM).
- [x] **Dismiss false-positive CodeQL alerts** in GitHub Security tab (SHA-1 required by Pwned Passwords *k*-anonymity + test URL substring assertions).
- [ ] **PyPI publishing (optional)** — skipped for now; pick a non-colliding distribution name (since `pwned` is already taken on PyPI) while keeping the `pwned` CLI entrypoint, and configure OIDC Trusted Publishing in `.github/workflows/release.yml`.
- [x] **Homebrew formula template (`Formula/pwned.rb`)** — template added for publishing via a `homebrew-tap` repo.

## Backlog / Stretch Ideas

- [x] **Password-manager export auditing (`pwned audit`)** — locally check Bitwarden JSON/CSV or KeePass `.kdbx` exports via k-anonymity without sending plaintext passwords over the network.
- [x] **Local cache option for public endpoints** — optional short TTL cache for `/breaches`, `/dataclasses`, and `/dataclasses/descriptions` to speed up repeated lookups.
- [x] **ClusterFuzzLite fuzzing (`.github/workflows/cifuzz.yml`)** — Atheris fuzz target covering `_md4`, `_parse_range_response`, `strip_html`, and `parse_input_lines`.
- [ ] **OpenSSF Best Practices badge** — manual web registration on `bestpractices.dev`.
