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
- [x] **Homebrew formula template (`packaging/homebrew/pwned.rb`)** — valid template pointing to the GitHub Release tarball for publishing via a `homebrew-tap` repo.
- [x] **ClusterFuzzLite fuzzing (`.github/workflows/cifuzz.yml`)** — Atheris fuzz target covering `_md4`, `_parse_range_response`, `strip_html`, and `parse_input_lines`.

## Completed (v0.3.0)

- [x] **Update `CHANGELOG.md` and architecture doc trees** — rolled post-`v0.2.0` fixes (`ea44a3c`, `c835bec`) and `_parsers.py` doc updates into `v0.3.0`.
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

## Completed (v0.3.0 — Offline Lookups, Monitoring & CI Integrations)

- [x] **Offline sorted hash file lookup (`--offline-db <path>` / `OfflinePasswordsClient`)** — `O(log N)` binary search via `seek`/`mmap` (stdlib only) over official `PwnedPasswordsDownloader` SHA-1/NTLM dumps for air-gapped and high-scale checks.
- [x] **Baseline diffing (`--baseline` / `--save-baseline`)** — snapshot known breaches/pastes/stealer logs to JSON and report/exit non-zero only on newly discovered exposures for cron/CI monitoring.
- [x] **SARIF output format (`--format sarif`)** — emit GitHub Code Scanning-compatible SARIF from `account`, `domain`, and `audit`.
- [x] **Reusable GitHub Action / `pre-commit` hook** — composite `action.yml` for scheduled domain/account breach monitoring in CI.
- [x] **Meta-tag domain verification (`domain-verify meta-tag|meta-check`)** — verify and support HIBP HTML `<meta>` tag verification endpoints alongside DNS TXT and email verification.

## Completed (v0.4.0)

### Full HIBP API v3 Parity
- [x] **Remove subscribed domain (`DELETE /subscribedDomains/{domain}`)** — `HIBPClient.remove_subscribed_domain()`, `AsyncHIBPClient.remove_subscribed_domain()`, and `pwned subscribed-domains remove <domain>` (retaining backwards-compatible `pwned subscribed-domains` / `pwned sd` listing alongside `subscribed-domains list`).
- [x] **Exclude unverified breaches on `GET /breaches`** — `include_unverified=False` (`?includeUnverified=false`) in sync/async clients and `pwned breaches --no-include-unverified`.
- [x] **Spec-compliant error body parsing (`401`, `404`, JSON strings, `text/plain`)** — parse JSON objects, JSON strings, and `text/plain` bodies while ignoring HTML/binary error pages, surfacing `verifyMetaTag` 404 and API-key 401 diagnostics.
- [x] **Complete HIBP test-account integration coverage & CC BY 4.0 attribution** — cover all 16 documented `hibp-integration-tests.com` aliases and document HIBP CC BY 4.0 data attribution in `README.md`.

### Enterprise & Active Directory Credential Auditing
- [x] **`ntds` / `secretsdump` / `pwdump` hash-dump auditing (`pwned audit --source pwdump`)** — parse `domain\user:RID:LM:NT:::` dumps directly, check NTLM hashes via async k-anonymity (`?mode=ntlm`) or `--offline-db`, and detect shared NTLM hashes across domain accounts (`--check-reuse`) without plaintext passwords.
- [x] **Built-in resumable offline dump downloader (`pwned offline download <output>`)** — async resumable downloader (`00000`–`FFFFF`, `--ntlm`, `--concurrency`, `--resume`, ETag support) using `httpx` so `OfflinePasswordsClient` workflows work end-to-end in pure Python.
- [x] **Bitwarden Argon2id encrypted JSON (`kdfType == 1`)** — support modern Argon2id Bitwarden encrypted exports using `cryptography`'s native `Argon2id` with zero new dependencies.

### Vault & Password Hygiene Expansion
- [x] **Additional password managers (`pass`, `gopass`, LastPass, Dashlane, Proton Pass)** — zero-dep CSV/JSON parsers for LastPass, Dashlane, and Proton Pass, plus optional live Unix `pass` / `gopass` store auditing without writing plaintext exports to disk.
- [x] **Combined breach + reuse + weakness scoring (`pwned audit --check-strength`)** — flag short/low-entropy passwords alongside breached and reused entries (zero-dep heuristics or optional `zxcvbn` extra) with an overall vault risk summary.
- [x] **Opt-in `--cache` for `/range/{prefix}` lookups** — extend `ResponseCache` to optionally cache Pwned Passwords range responses (matching Cloudflare CDN caching) to speed up repeated local vault audits and batch runs.

### Continuous Monitoring, Reporting & Alerting
- [x] **Markdown & standalone HTML reports (`--format markdown` / `--format html`)** — pipe Markdown directly into PR comments or GitHub Actions `$GITHUB_STEP_SUMMARY`, or generate a zero-dep single-file HTML report for compliance/security reviews.
- [x] **Declarative monitoring config (`pwned monitor --config pwned.toml`)** — parse a repo-checked `pwned.toml` (via stdlib `tomllib`) defining watched accounts/domains, filters, baseline paths, and output formats in one file instead of long cron/CI command lines.
- [x] **Webhook notifications on new exposures (`--notify-webhook <url>`)** — pair with `--baseline` / `--save-baseline` to send Slack, Discord, or generic JSON webhooks via `httpx` only when newly discovered breaches, pastes, or stealer logs appear.
- [x] **Domain exposure risk summary (`pwned domain-report <domain>`)** — cross-reference a verified domain's breached aliases (and optional stealer logs) with cached breach metadata to summarize top breaches, recency, and counts by compromised `DataClasses`.

### Ecosystem & Distribution
- [x] **Local stdio MCP server (`pwned mcp`, built-in zero-dependency)** — local-only privacy tools complementing HIBP's remote MCP server for workflows that shouldn't cross a chat prompt: local k-anonymity/offline password checks, local vault auditing, and baseline diffing.
- [x] **Container image (`ghcr.io/domfahey/pwned`)** — publish a minimal distroless/alpine image via `release.yml` for air-gapped, Kubernetes CronJob, and non-Python CI environments.
- [x] **Async account batching (`async_batch_check_accounts`) + retry jitter** — mirror `async_batch_check_passwords` for async applications, with jittered 429 backoff.

## Completed (v0.4.1)

- [x] **Hosted MkDocs Material docs site (`domfahey.github.io/pwned`)** — comprehensive `docs/` guides deployed via SHA-pinned GitHub Pages workflow (`.github/workflows/docs.yml`) with locked `docs` dependency group.
- [x] **Repository & developer workflow polish** — organized `.github/` community health files, `packaging/homebrew/pwned.rb`, `.env.example`, self-documenting `Makefile` + enhanced `make doctor`, `Settings` `extra="ignore"` fix, and `action.yml` GitHub Marketplace branding + ref pinning.

## Completed (v0.5.0)

- [x] **Mirrored HIBP CLI semantic exit codes (`0`–`9`, `130`)** — align exit codes with official `HaveIBeenPwned.Cli` (`ExitCode` `IntEnum`, `BadRequestError`, `FileOrStoreError`, exit `8` on `--fail-if-pwned`, `3` auth, `4` forbidden, `5` rate limit, `6` network/5xx, `7` file/store, `9` missing resource/verification failure, `130` cancelled).
- [x] **Enable `--pad` by default on `pwned password`** — send `Add-Padding: true` by default (`--pad/--no-pad`, matching `pwned audit` and `pwned mcp`) so interactive password checks hide response lengths out of the box.
- [x] **Auto-prefer OS keyring on `pwned auth set|clear`** — default `--backend auto` stores credentials in the OS Keychain when `pwned[keyring]` is installed and usable (falling back to `0600` `~/.config/pwned/.env`), and clears both backends by default.
- [x] **Clean exit-0 on no-match search results (`account`, `domain`, `pastes`, `stealer`)** — treat HIBP HTTP `404` on search commands as clean exit `0` (`[]`/`{}` in JSON, green `Clean (...)` in text), matching `password`, `search`, `account-range`, and official `hibp`.
- [x] **CLI password range lookup (`pwned password-range <5-hex>`)** — expose `get_password_range()` on the CLI (`--ntlm`, padding stripped) alongside `pwned password`.
- [x] **Raw 6-char SHA-1 prefix support on `account-range`** — allow passing a pre-hashed 6-char hex prefix directly to `pwned account-range` (matching `hibp account range <prefix>`).
- [x] **Non-interactive `pwned auth set --stdin`** — read `HIBP_API_KEY` from standard input for scripted setup without exposing secrets in shell history or `ps` output.
- [x] **Global `--outfile <path>` (+ `--force`) and CLI shorthands** — write formatted UTF-8 output directly to disk from any data command with safe overwrite protection, plus global `--markdown`, `--mode sha1|ntlm`, `-n`, and `--parallelism`/`-p`.
- [x] **Per-prefix offline dump directory interop (`00000.txt`–`FFFFF.txt`)** — directory-per-prefix downloads with compact `.pwned-index.json` hash-mode & ETag checkpoints (`--force-refresh` / `--overwrite`), atomic shard writes, and `O(1)` directory lookups in `OfflinePasswordsClient` for direct interoperability with official `HaveIBeenPwned.Cli` (`hibp password download`).
- [x] **End-user `pwned doctor` CLI subcommand** — verify HIBP API connectivity, subscription tier/RPM, active credential source, keyring availability, cache size, and offline DB integrity directly from installed `pwned` binaries.
- [x] **Smart `latestBreach` pre-check in `pwned monitor`** — poll unauthenticated `GET /latestBreach` (Cloudflare-cached) first and skip `GET /breachedDomain/{domain}` queries when no new breach has been added since each domain's last baseline snapshot.
- [x] **CC BY 4.0 attribution footer in Markdown reports** — append a compact HIBP attribution footer to `--format markdown` breach, paste, domain, audit, and monitor reports (matching `README.md` and `--format html`).

## Planned (v0.6.0)

Prioritized from cross-ecosystem research (official `HaveIBeenPwned.Cli` / `haveibeenpwned.com/cli`, `DSInternals`, `easybill/easypwned`, `ScottHelme/when-pwned-passwords-bloom`, `alexbrazier/pwned-bloom`, `HaveIBeenPwned/PwnedPasswordsCloudflareWorker`, `Keyguard`, `1Password`/`Bitwarden` CLIs, `brycx/checkpwn`, and `wneessen/go-hibp`).

### Active Directory & Enterprise Credential Hygiene
- [ ] **Extended AD `pwdump` quality checks** — detect empty NTLM hashes (`31D6CFE0D16AE931B73C59D7E0C089C0`), present legacy LM hashes, username-as-password matches (local MD4 of `SamAccountName` and case variants), and add `--exclude-machines` filtering for `$` computer accounts.
- [ ] **Custom organizational wordlist support (`--custom-wordlist <file>`)** — check passwords and NTLM dumps against company-specific banned dictionaries (brand names, seasonal patterns, default onboarding passwords) alongside HIBP.

### Watchtower-Style Vault Auditing & Live CLI Connectors
- [ ] **Live cloud vault CLI connectors (`--source bitwarden-cli` / `1password-cli`)** — audit unlocked `bw` / `rbw` and `op` vaults directly in memory without writing plaintext exports to disk (mirroring existing `pass` / `gopass` support).
- [ ] **Vault breach & stealer-log correlation (`pwned audit --check-breaches`)** — cross-reference vault entry emails and login domains against HIBP breaches and stealer logs to flag accounts on compromised sites even when the password itself has not yet appeared in Pwned Passwords.

### Offline Scale & Self-Hosted Infrastructure
- [ ] **Self-hosted k-anonymity HTTP server / caching proxy (`pwned serve`)** — expose a drop-in `/range/{prefix}` endpoint, `/healthz`, and optional Prometheus `/metrics` backed by `--offline-db` or an upstream TTL cache for air-gapped services and high-QPS auth backends.
- [ ] **Compact offline hash indexes (`pwned offline build-bloom` / `compact`)** — build sub-1 GB mmap-able Bloom filters for RAM-resident checks in containers/CI runners, plus a fixed-width binary prefix-indexed format (~50% smaller than ASCII dumps with `O(1)` prefix jump).

### Continuous Monitoring, History & Alerting
- [ ] **SQLite exposure history & remediation tracking (`monitor --db`)** — persist first-seen and resolved exposure timestamps in a stdlib `sqlite3` store to track breach trends and rotated credentials across runs, feeding trend summaries into `domain-report`, `--format markdown`, and `--format html`.
- [ ] **Expanded alert destinations** — add Microsoft Teams (Adaptive Cards), PagerDuty (Events API v2), SMTP email, and GitHub Issue auto-creation/commenting for CI monitoring pipelines.

## Backlog / External

- [ ] **PyPI publishing (optional)** — pick a non-colliding distribution name (since `pwned` is already taken on PyPI) while keeping the `pwned` CLI entrypoint, and configure OIDC Trusted Publishing in `.github/workflows/release.yml`.
- [ ] **Homebrew tap (`domfahey/homebrew-tap`)** — publish `packaging/homebrew/pwned.rb` and automate formula URL/SHA256 updates on release tags.
- [ ] **GitHub Marketplace Action listing** — check **Publish this Action to the GitHub Marketplace** on the `v0.5.0` release UI after accepting the GitHub Marketplace Developer Agreement.
- [ ] **OpenSSF Best Practices badge** — manual web registration on `bestpractices.dev`.
