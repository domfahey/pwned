from __future__ import annotations

import time
from collections.abc import Callable, Iterable, Sequence
from pathlib import Path
from typing import Literal

from pydantic import Field

from pwned.client import HIBPClient, HIBPError, NotFoundError
from pwned.models import NonNegativeInt, _HIBPBase
from pwned.passwords import PwnedPasswordsClient


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


def parse_input_lines(
    lines: Iterable[str],
    *,
    strip: bool = True,
    ignore_comments: bool = True,
) -> list[str]:
    """Normalize, filter, and deduplicate input lines while preserving order."""
    seen: set[str] = set()
    result: list[str] = []
    for raw in lines:
        value = raw.rstrip("\r\n")
        if strip:
            value = value.strip()
        if not value:
            continue
        if ignore_comments and value.lstrip().startswith("#"):
            continue
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result


def load_input_file(
    path: Path,
    *,
    strip: bool = True,
    ignore_comments: bool = True,
) -> list[str]:
    """Load and parse a UTF-8 newline-delimited input file."""
    with path.open("r", encoding="utf-8") as handle:
        return parse_input_lines(handle, strip=strip, ignore_comments=ignore_comments)


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
    names = [b.name for b in breaches]
    return AccountBatchItem(
        account=account,
        breaches=names,
        status="pwned" if names else "clean",
    )


def batch_check_accounts(
    accounts: Sequence[str],
    client: HIBPClient,
    *,
    rpm: int | None = None,
    domain: str | None = None,
    include_unverified: bool = True,
    sleep: Callable[[float], None] = time.sleep,
    on_progress: Callable[[int, int, AccountBatchItem], None] | None = None,
) -> list[AccountBatchItem]:
    """Check a sequence of accounts for breaches with optional RPM pacing."""
    if rpm is not None and rpm <= 0:
        raise ValueError("rpm must be greater than 0")

    delay = 60.0 / rpm if rpm is not None else 0.0
    results: list[AccountBatchItem] = []
    total = len(accounts)
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


def _password_item(index: int, count: int, threshold: int) -> PasswordBatchItem:
    return PasswordBatchItem(
        index=index,
        pwn_count=count,
        status="pwned" if count >= threshold else "clean",
    )


def batch_check_passwords(
    passwords: Sequence[str],
    client: PwnedPasswordsClient,
    *,
    threshold: int = 1,
    ntlm: bool = False,
    pad: bool = True,
    on_progress: Callable[[int, int, PasswordBatchItem], None] | None = None,
) -> list[PasswordBatchItem]:
    """Check a sequence of passwords without storing plaintext passwords in results."""
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
                count = client.check_password(password, ntlm=ntlm, pad=pad)
            except HIBPError as exc:
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
