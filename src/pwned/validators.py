from __future__ import annotations

from collections.abc import Callable

from pwned.client import HIBPError
from pwned.config import DEFAULT_USER_AGENT
from pwned.models import PasswordChecker
from pwned.passwords import AsyncPwnedPasswordsClient, PwnedPasswordsClient


def _validate_threshold(threshold: int) -> None:
    if threshold < 1:
        raise ValueError("threshold must be at least 1")


def _check_breach_count(password: str, count: int, threshold: int) -> str:
    if count >= threshold:
        raise ValueError(f"Password has appeared {count:,} times in data breaches.")
    return password


def validate_password_not_pwned(
    password: str,
    *,
    threshold: int = 1,
    ntlm: bool = False,
    pad: bool = True,
    fail_open: bool = False,
    client: PasswordChecker | None = None,
    user_agent: str = DEFAULT_USER_AGENT,
) -> str:
    """Validate that a password has appeared fewer than `threshold` times in HIBP breaches."""
    _validate_threshold(threshold)
    try:
        if client is not None:
            count = client.check_password(password, ntlm=ntlm, pad=pad)
        else:
            with PwnedPasswordsClient(user_agent=user_agent) as owned_client:
                count = owned_client.check_password(password, ntlm=ntlm, pad=pad)
    except HIBPError:
        if fail_open:
            return password
        raise
    return _check_breach_count(password, count, threshold)


async def async_validate_password_not_pwned(
    password: str,
    *,
    threshold: int = 1,
    ntlm: bool = False,
    pad: bool = True,
    fail_open: bool = False,
    client: AsyncPwnedPasswordsClient | None = None,
    user_agent: str = DEFAULT_USER_AGENT,
) -> str:
    """Asynchronously validate that a password has appeared fewer than `threshold` times."""
    _validate_threshold(threshold)
    try:
        if client is not None:
            count = await client.check_password(password, ntlm=ntlm, pad=pad)
        else:
            async with AsyncPwnedPasswordsClient(user_agent=user_agent) as owned_client:
                count = await owned_client.check_password(password, ntlm=ntlm, pad=pad)
    except HIBPError:
        if fail_open:
            return password
        raise
    return _check_breach_count(password, count, threshold)


def make_password_validator(
    *,
    threshold: int = 1,
    ntlm: bool = False,
    pad: bool = True,
    fail_open: bool = False,
    client: PasswordChecker | None = None,
    user_agent: str = DEFAULT_USER_AGENT,
) -> Callable[[str], str]:
    """Return a single-argument password validator callable for frameworks like Pydantic."""
    _validate_threshold(threshold)

    def _validator(password: str) -> str:
        return validate_password_not_pwned(
            password,
            threshold=threshold,
            ntlm=ntlm,
            pad=pad,
            fail_open=fail_open,
            client=client,
            user_agent=user_agent,
        )

    return _validator
