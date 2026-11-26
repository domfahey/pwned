from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable, Sequence
from pathlib import Path
from typing import Literal

from pydantic import Field

from pwned._parsers import parse_input_lines as parse_input_lines
from pwned.async_client import AsyncHIBPClient
from pwned.client import HIBPClient, HIBPError, NotFoundError
from pwned.models import Breach, NonNegativeInt, PasswordChecker, _HIBPBase
from pwned.passwords import AsyncPwnedPasswordsClient


class AccountBatchItem(_HIBPBase):
    """Result record for a single account in a batch breach check."""

    account: str
    breaches: list[str] = Field(default_factory=list)
    status: Literal["pwned", "clean", "error"]
    error: str | None = None


class PasswordBatchItem(_HIBPBase):
    """Result record for a single password index in a batch check."""

    index: NonNegativeInt
    pwn_count: NonNegativeInt = 0
    status: Literal["pwned", "clean", "error"]
    error: str | None = None


class BatchStats(_HIBPBase):
    """Aggregate summary statistics for a batch check run."""

    checked: NonNegativeInt
    pwned: NonNegativeInt
    clean: NonNegativeInt
    errors: NonNegativeInt
    elapsed_seconds: float = Field(ge=0.0)


def compute_batch_stats(
    items: Sequence[AccountBatchItem | PasswordBatchItem],
    *,
    elapsed_seconds: float = 0.0,
) -> BatchStats:
    """Compute aggregate pwned, clean, and error counts for a batch run."""
    if elapsed_seconds < 0.0:
        raise ValueError("elapsed_seconds must be non-negative")
    pwned = 0
    clean = 0
    errors = 0
    for item in items:
        if item.status == "pwned":
            pwned += 1
        elif item.status == "clean":
            clean += 1
        else:
            errors += 1
    return BatchStats(
        checked=len(items),
        pwned=pwned,
        clean=clean,
        errors=errors,
        elapsed_seconds=elapsed_seconds,
    )


def format_batch_stats(stats: BatchStats) -> str:
    """Format batch statistics as a concise single-line summary."""
    return (
        f"Checked {stats.checked}: {stats.pwned} pwned, {stats.clean} clean, "
        f"{stats.errors} error(s) in {stats.elapsed_seconds:.2f}s"
    )


def load_input_file(
    path: Path,
    *,
    strip: bool = True,
    ignore_comments: bool = True,
    deduplicate: bool = True,
) -> list[str]:
    """Load and parse a UTF-8 newline-delimited input file."""
    with path.open("r", encoding="utf-8") as handle:
        return parse_input_lines(
            handle,
            strip=strip,
            ignore_comments=ignore_comments,
            deduplicate=deduplicate,
        )


def _account_item(account: str, breaches: Sequence[Breach]) -> AccountBatchItem:
    names = [b.name for b in breaches]
    return AccountBatchItem(
        account=account,
        breaches=names,
        status="pwned" if names else "clean",
    )


def _check_single_account(
    account: str,
    client: HIBPClient,
    *,
    domain: str | None,
    include_unverified: bool,
) -> AccountBatchItem:
    try:
        breaches = client.get_account_breaches(
            account,
            truncate=True,
            domain=domain,
            include_unverified=include_unverified,
        )
    except NotFoundError:
        return AccountBatchItem(account=account, breaches=[], status="clean")
    except HIBPError as exc:
        return AccountBatchItem(account=account, breaches=[], status="error", error=str(exc))
    return _account_item(account, breaches)


def _resolve_rpm(
    client: HIBPClient,
    rpm: int | None,
    *,
    auto_rpm: bool,
    total: int,
) -> int | None:
    if rpm is not None:
        if rpm <= 0:
            raise ValueError("rpm must be greater than 0")
        return rpm
    if not auto_rpm or total <= 1:
        return None
    try:
        detected = client.get_subscription_status().rpm
    except HIBPError:
        return None
    return detected if detected > 0 else None


def batch_check_accounts(
    accounts: Sequence[str],
    client: HIBPClient,
    *,
    rpm: int | None = None,
    auto_rpm: bool = False,
    domain: str | None = None,
    include_unverified: bool = True,
    sleep: Callable[[float], None] = time.sleep,
    on_progress: Callable[[int, int, AccountBatchItem], None] | None = None,
) -> list[AccountBatchItem]:
    """Check a sequence of accounts for breaches with optional RPM pacing."""
    total = len(accounts)
    effective_rpm = _resolve_rpm(client, rpm, auto_rpm=auto_rpm, total=total)
    delay = 60.0 / effective_rpm if effective_rpm is not None else 0.0
    results: list[AccountBatchItem] = []
    for idx, account in enumerate(accounts, start=1):
        if idx > 1 and delay > 0.0:
            sleep(delay)
        item = _check_single_account(
            account,
            client,
            domain=domain,
            include_unverified=include_unverified,
        )
        results.append(item)
        if on_progress is not None:
            on_progress(idx, total, item)
    return results


async def _async_check_single_account(
    account: str,
    client: AsyncHIBPClient,
    *,
    domain: str | None,
    include_unverified: bool,
) -> AccountBatchItem:
    try:
        breaches = await client.get_account_breaches(
            account,
            truncate=True,
            domain=domain,
            include_unverified=include_unverified,
        )
    except NotFoundError:
        return AccountBatchItem(account=account, breaches=[], status="clean")
    except HIBPError as exc:
        return AccountBatchItem(account=account, breaches=[], status="error", error=str(exc))
    return _account_item(account, breaches)


async def _async_resolve_rpm(
    client: AsyncHIBPClient,
    rpm: int | None,
    *,
    auto_rpm: bool,
    total: int,
) -> int | None:
    if rpm is not None:
        if rpm <= 0:
            raise ValueError("rpm must be greater than 0")
        return rpm
    if not auto_rpm or total <= 1:
        return None
    try:
        detected = (await client.get_subscription_status()).rpm
    except HIBPError:
        return None
    return detected if detected > 0 else None


async def async_batch_check_accounts(
    accounts: Sequence[str],
    client: AsyncHIBPClient,
    *,
    rpm: int | None = None,
    auto_rpm: bool = False,
    domain: str | None = None,
    include_unverified: bool = True,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    on_progress: Callable[[int, int, AccountBatchItem], None] | None = None,
) -> list[AccountBatchItem]:
    """Check a sequence of accounts asynchronously with optional RPM pacing."""
    total = len(accounts)
    effective_rpm = await _async_resolve_rpm(client, rpm, auto_rpm=auto_rpm, total=total)
    delay = 60.0 / effective_rpm if effective_rpm is not None else 0.0
    results: list[AccountBatchItem] = []
    for idx, account in enumerate(accounts, start=1):
        if idx > 1 and delay > 0.0:
            await sleep(delay)
        item = await _async_check_single_account(
            account,
            client,
            domain=domain,
            include_unverified=include_unverified,
        )
        results.append(item)
        if on_progress is not None:
            on_progress(idx, total, item)
    return results


def _password_item(index: int, count: int, threshold: int) -> PasswordBatchItem:
    return PasswordBatchItem(
        index=index,
        pwn_count=count,
        status="pwned" if count >= threshold else "clean",
    )


def batch_check_passwords(
    passwords: Sequence[str],
    client: PasswordChecker,
    *,
    threshold: int = 1,
    ntlm: bool = False,
    pad: bool = True,
    hashed: bool = False,
    on_progress: Callable[[int, int, PasswordBatchItem], None] | None = None,
) -> list[PasswordBatchItem]:
    """Check a sequence of passwords or hashes without storing inputs in results."""
    if threshold < 1:
        raise ValueError("threshold must be at least 1")

    cache: dict[str, int] = {}
    results: list[PasswordBatchItem] = []
    total = len(passwords)
    for idx, password in enumerate(passwords, start=1):
        if password in cache:
            item = _password_item(idx, cache[password], threshold)
        else:
            try:
                if hashed:
                    count = client.check_hash(password, ntlm=ntlm, pad=pad)
                else:
                    count = client.check_password(password, ntlm=ntlm, pad=pad)
            except (HIBPError, ValueError) as exc:
                item = PasswordBatchItem(
                    index=idx,
                    pwn_count=0,
                    status="error",
                    error=str(exc),
                )
            else:
                cache[password] = count
                item = _password_item(idx, count, threshold)
        results.append(item)
        if on_progress is not None:
            on_progress(idx, total, item)
    return results


async def async_batch_check_passwords(
    passwords: Sequence[str],
    client: AsyncPwnedPasswordsClient,
    *,
    threshold: int = 1,
    ntlm: bool = False,
    pad: bool = True,
    hashed: bool = False,
    concurrency: int = 10,
    on_progress: Callable[[int, int, PasswordBatchItem], None] | None = None,
) -> list[PasswordBatchItem]:
    """Check passwords or hashes concurrently while preserving input index order."""
    if threshold < 1:
        raise ValueError("threshold must be at least 1")
    if concurrency < 1:
        raise ValueError("concurrency must be at least 1")
    if not passwords:
        return []

    semaphore = asyncio.Semaphore(concurrency)
    unique_inputs = list(dict.fromkeys(passwords))

    async def _lookup_one(value: str) -> tuple[str, int | None, str | None]:
        async with semaphore:
            try:
                if hashed:
                    count = await client.check_hash(value, ntlm=ntlm, pad=pad)
                else:
                    count = await client.check_password(value, ntlm=ntlm, pad=pad)
            except (HIBPError, ValueError) as exc:
                return value, None, str(exc)
            return value, count, None

    outcomes = await asyncio.gather(*(_lookup_one(value) for value in unique_inputs))
    resolved = {value: (count, error) for value, count, error in outcomes}

    results: list[PasswordBatchItem] = []
    total = len(passwords)
    for idx, password in enumerate(passwords, start=1):
        count, error = resolved[password]
        if count is None:
            item = PasswordBatchItem(
                index=idx,
                pwn_count=0,
                status="error",
                error=error,
            )
        else:
            item = _password_item(idx, count, threshold)
        results.append(item)
        if on_progress is not None:
            on_progress(idx, total, item)
    return results
