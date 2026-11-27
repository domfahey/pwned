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

# Sync online with optional range caching and response padding
with PwnedPasswordsClient(cache=ResponseCache()) as pw:
    count = pw.check_password("hunter2", pad=True)
    compromised = pw.is_pwned("hunter2", threshold=10, pad=True)
    ntlm_count = pw.check_hash("31D6CFE0D16AE931B73C59D7E0C089C0", ntlm=True)
    suffix_map = pw.get_password_range("5BAA6")

# Async online
async def check_async() -> int:
    async with AsyncPwnedPasswordsClient(cache=ResponseCache()) as pw:
        return await pw.check_password("hunter2", pad=True)

asyncio.run(check_async())

# Air-gapped O(log N) binary search over a local sorted hash dump
with OfflinePasswordsClient(Path("/data/pwned-passwords-sha1.txt")) as offline:
    count = offline.check_password("hunter2")
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

## Reporting, Webhooks, Monitoring & Formatting

```python
from pathlib import Path
from pwned import (
    HIBPClient,
    ResponseCache,
    format_output,
    generate_domain_report,
    load_monitor_config,
    run_monitor,
    send_webhook_notification,
)

with HIBPClient(api_key="your-key", cache=ResponseCache()) as client:
    # Domain risk summary
    report = generate_domain_report(client, "example.com", include_stealer_logs=True)
    markdown = format_output(report, fmt="markdown")
    html = format_output(report, fmt="html")

    # Send webhook only if exposures exist
    send_webhook_notification(
        "https://hooks.slack.com/services/...",
        report,
        fmt="auto",
        title="Domain Exposure Report",
    )

    # Declarative TOML monitor
    cfg = load_monitor_config(Path("pwned.toml"))
    mon_report = run_monitor(cfg, client, save_baselines=True)
```

## Custom `httpx` Client & Proxy Injection

All HTTP clients (`HIBPClient`, `AsyncHIBPClient`, `PwnedPasswordsClient`, `AsyncPwnedPasswordsClient`) and `download_offline_db` / `send_webhook_notification` accept `proxy="http://..."` or an externally managed `client=` (`httpx.Client` / `httpx.AsyncClient`) for connection pooling, custom TLS roots, corporate proxies, and deterministic testing. Externally injected clients are never closed by `pwned`.

## Exception Hierarchy

| Exception | Cause |
|---|---|
| `HIBPError` | Base exception for all HTTP, network, and webhook failures |
| `BadRequestError` | HTTP `400` (rejected request, invalid domain/parameter, or already-verified domain) |
| `UnauthorizedError` | HTTP `401` (missing, malformed, or invalid `hibp-api-key`) |
| `ForbiddenError` | HTTP `403` (missing `User-Agent`, unverified domain, or plan tier restriction) |
| `NotFoundError` | HTTP `404` (no results found, or endpoint-specific detail such as `verifyMetaTag`) |
| `RateLimitError` | HTTP `429` exhausted after `max_retries`; exposes `.retry_after: int \| None` |
