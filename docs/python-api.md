# Python Library Guide

`pwned` ships a strictly typed (PEP 561 `py.typed`) synchronous and asynchronous Python API built on `httpx` and Pydantic v2. All public types and helpers are re-exported from the top-level `pwned` package.

## Synchronous HIBP Client (`HIBPClient`)

```python
from pwned import HIBPClient, NotFoundError, ResponseCache

with HIBPClient(
    api_key="your-32-char-api-key",
    user_agent="my-security-tool",
    cache=ResponseCache(ttl_seconds=3600),
    max_retries=3,
    retry_jitter=0.25,
    timeout=10.0,
) as client:
    # Public catalog (cached when ResponseCache is supplied)
    verified_breaches = client.get_breaches(include_unverified=False)
    latest = client.get_latest_breach()
    descriptions = client.get_data_class_descriptions()

    # Account & domain queries
    try:
        breaches = client.get_account_breaches("user@example.com", truncate=False)
    except NotFoundError:
        breaches = []

    # Composite search (breaches + pastes + optional stealer logs)
    summary = client.search_account("user@example.com", include_stealer_logs=True)

    # k-Anonymity account check (Pro / High RPM)
    site_names = client.check_account_range("user@example.com")

    # Domain verification & management (Pro)
    token = client.generate_dns_token("example.com")
    client.verify_dns_token("example.com")
    client.remove_subscribed_domain("old.example.com")
```

## Asynchronous HIBP Client (`AsyncHIBPClient`)

```python
import asyncio
from pwned import AsyncHIBPClient, async_batch_check_accounts

async def main() -> None:
    async with AsyncHIBPClient(
        api_key="your-32-char-api-key",
        user_agent="my-async-app",
        retry_jitter=0.25,
    ) as client:
        sub = await client.get_subscription_status()
        print(f"{sub.subscription_name}: {sub.rpm} RPM")

        results = await async_batch_check_accounts(
            ["alice@example.com", "bob@example.com"],
            client,
            auto_rpm=True,
        )
        for item in results:
            print(item.account, item.status, item.breaches)

asyncio.run(main())
```

## Pwned Passwords Clients (Sync, Async & Offline)

```python
import asyncio
from pathlib import Path
from pwned import (
    AsyncPwnedPasswordsClient,
    OfflinePasswordsClient,
    PwnedPasswordsClient,
    ResponseCache,
)

# Sync online with default response padding (Add-Padding: true) and optional range caching
with PwnedPasswordsClient(cache=ResponseCache()) as pw:
    count = pw.check_password("hunter2")
    compromised = pw.is_pwned("hunter2", threshold=10)
    ntlm_count = pw.check_hash("31D6CFE0D16AE931B73C59D7E0C089C0", ntlm=True)
    suffix_map = pw.get_password_range("5BAA6")

# Async online
async def check_async() -> int:
    async with AsyncPwnedPasswordsClient(cache=ResponseCache()) as pw:
        return await pw.check_password("hunter2")

asyncio.run(check_async())

# Air-gapped lookup over a text dump, range directory, compact index (PWNB), or Bloom filter (PWNL)
with OfflinePasswordsClient(Path("/data/pwned-passwords-sha1.txt")) as offline:
    count = offline.check_password("hunter2")

# Build and query compact binary indexes (PWNB) and mmap-able Bloom filters (PWNL)
from pwned import (
    BloomFilterReader,
    CompactIndexReader,
    build_bloom_filter,
    build_compact_index,
)

build_compact_index(Path("/data/pwned-sha1"), Path("/data/pwned-sha1.pwnb"), overwrite=True)
build_bloom_filter(
    Path("/data/pwned-sha1.pwnb"),
    Path("/data/pwned-sha1.bloom"),
    false_positive_rate=0.01,
    overwrite=True,
)
with CompactIndexReader(Path("/data/pwned-sha1.pwnb")) as compact:
    exact_count = compact.lookup_hash("5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8")
    bucket = compact.get_range("5BAA6")

with BloomFilterReader(Path("/data/pwned-sha1.bloom")) as bloom:
    maybe_present = bloom.might_contain_hash("5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8")

# Self-hosted /range/{prefix} HTTP server (offline DB or upstream caching proxy)
from pwned import PwnedRangeServer, create_range_server

with PwnedRangeServer(offline_db=Path("/data/pwned-sha1.pwnb"), host="127.0.0.1", port=8080) as srv:
    srv.serve_forever()
# Or: create_range_server(port=8080, cache=ResponseCache())
```

## Vault Auditing, Live CLI Connectors & Breach Correlation

```python
from pwned import (
    HIBPClient,
    PwnedPasswordsClient,
    ResponseCache,
    audit_entries,
    parse_1password_cli,
    parse_bitwarden_cli,
)

# Read unlocked cloud vaults directly in memory (no plaintext export files)
bw_entries = parse_bitwarden_cli()
op_entries = parse_1password_cli("Work")

with (
    PwnedPasswordsClient(cache=ResponseCache()) as pw_client,
    HIBPClient(api_key="your-key", cache=ResponseCache()) as hibp_client,
):
    summary = audit_entries(
        op_entries,
        pw_client,
        check_reuse=True,
        check_breaches=True,
        hibp_client=hibp_client,
    )
    print(summary.compromised_entries, summary.breach_correlated_entries)
```

## Framework Password Validators (Pydantic / FastAPI / Django)

```python
from typing import Annotated
from pydantic import AfterValidator, BaseModel
from pwned import (
    async_validate_password_not_pwned,
    make_password_validator,
    validate_password_not_pwned,
)

# Pydantic v2 / FastAPI request model
SafePassword = Annotated[str, AfterValidator(make_password_validator(threshold=1, pad=True))]

class SignupRequest(BaseModel):
    email: str
    password: SafePassword

# Direct sync or async validation (raises ValueError if breached)
validate_password_not_pwned("my-candidate-password", threshold=1)
# await async_validate_password_not_pwned("my-candidate-password", threshold=1)
```

For Django forms or `AUTH_PASSWORD_VALIDATORS`, wrap `validate_password_not_pwned(password)` and re-raise `ValueError` as `django.core.exceptions.ValidationError`. See [Have I Been Pwned's NIST SP 800-63B guidance](https://haveibeenpwned.com/NIST) for compromised-password screening compliance details.

## Reporting, Notifications, Monitoring & Formatting

```python
from pathlib import Path
from pwned import (
    EmailNotifyConfig,
    ExposureHistoryStore,
    GitHubIssueNotifyConfig,
    HIBPClient,
    ResponseCache,
    format_output,
    generate_domain_report,
    load_monitor_config,
    run_monitor,
    send_email_notification,
    send_github_issue_notification,
    send_webhook_notification,
)

with HIBPClient(api_key="your-key", cache=ResponseCache()) as client:
    # Domain risk summary
    report = generate_domain_report(client, "example.com", include_stealer_logs=True)
    markdown = format_output(report, fmt="markdown")
    html = format_output(report, fmt="html")

    # Send webhooks only if exposures exist (auto-detects Slack, Discord, Teams, PagerDuty, generic)
    send_webhook_notification(
        "https://hooks.slack.com/services/...",
        report,
        fmt="auto",
        title="Domain Exposure Report",
    )
    send_webhook_notification(
        "https://org.webhook.office.com/webhookb2/...",
        report,
        fmt="teams",
        title="Domain Exposure Report",
    )
    send_webhook_notification(
        "https://events.pagerduty.com/v2/enqueue",
        report,
        fmt="pagerduty",
        routing_key="your-pd-routing-key",
        severity="error",
        title="Domain Exposure Report",
    )

    # Send SMTP email alert or open/comment on a GitHub Issue
    email_cfg = EmailNotifyConfig(
        host="smtp.example.com",
        port=587,
        from_addr="alerts@example.com",
        to_addrs=["soc@example.com"],
        username="alerts-bot",
        password="smtp-password",
    )
    send_email_notification(email_cfg, report, title="Domain Exposure Report")

    gh_cfg = GitHubIssueNotifyConfig(
        repo="org/security-alerts",
        token="ghp_...",
        labels=["security", "pwned"],
        dedup_title=True,
    )
    issue = send_github_issue_notification(gh_cfg, report, title="Domain Exposure Report")

    # Declarative TOML monitor with SQLite exposure history tracking
    cfg = load_monitor_config(Path("pwned.toml"))
    mon_report = run_monitor(
        cfg,
        client,
        save_baselines=True,
        db_path_override=Path("history.sqlite3"),
    )

# Inspect persisted SQLite exposure trends directly
with ExposureHistoryStore(Path("history.sqlite3")) as store:
    trend = store.get_trend_summary(target_type="domain", target="example.com")
    print(trend.active_exposures, trend.remediation_rate)
```

## Custom `httpx` Client & Proxy Injection

All HTTP clients (`HIBPClient`, `AsyncHIBPClient`, `PwnedPasswordsClient`, `AsyncPwnedPasswordsClient`) and `download_offline_db` / `send_webhook_notification` / `send_github_issue_notification` accept `proxy="http://..."` or an externally managed `client=` (`httpx.Client` / `httpx.AsyncClient`) for connection pooling, custom TLS roots, corporate proxies, and deterministic testing. Externally injected clients are never closed by `pwned`.

## Exception Hierarchy

| Exception | Cause |
|---|---|
| `HIBPError` | Base exception for all HTTP, network, and webhook failures |
| `BadRequestError` | HTTP `400` (rejected request, invalid domain/parameter, or already-verified domain) |
| `UnauthorizedError` | HTTP `401` (missing, malformed, or invalid `hibp-api-key`) |
| `ForbiddenError` | HTTP `403` (missing `User-Agent`, unverified domain, or plan tier restriction) |
| `NotFoundError` | HTTP `404` (no results found, or endpoint-specific detail such as `verifyMetaTag`) |
| `RateLimitError` | HTTP `429` exhausted after `max_retries`; exposes `.retry_after: int \| None` |
