from __future__ import annotations

import hashlib

import httpx

from pwned._parsers import _md4 as _md4
from pwned._parsers import _parse_range_response as _parse_range_response
from pwned.cache import ResponseCache
from pwned.client import REQUEST_TIMEOUT, HIBPError
from pwned.config import DEFAULT_USER_AGENT

BASE_URL = "https://api.pwnedpasswords.com"
_HEX_CHARS = frozenset("0123456789ABCDEF")


def _hash_password(password: str, *, ntlm: bool) -> str:
    """Return the uppercase SHA-1 or NTLM hex digest for a password."""
    if ntlm:
        return _ntlm_hash(password)
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()  # noqa: S324


def _validate_prefix(prefix: str) -> str:
    """Normalize and validate a 5-character hexadecimal hash prefix."""
    normalized = prefix.strip().upper()
    if len(normalized) != 5 or any(ch not in _HEX_CHARS for ch in normalized):
        raise ValueError("Hash prefix must be exactly 5 hexadecimal characters")
    return normalized


def _validate_full_hash(hash_hex: str, *, ntlm: bool) -> str:
    """Normalize and validate a full SHA-1 (40-char) or NTLM (32-char) hex digest."""
    normalized = hash_hex.strip().upper()
    expected_len = 32 if ntlm else 40
    if len(normalized) != expected_len or any(ch not in _HEX_CHARS for ch in normalized):
        kind = "NTLM" if ntlm else "SHA-1"
        raise ValueError(f"{kind} hash must be exactly {expected_len} hexadecimal characters")
    return normalized


def _validate_threshold(threshold: int) -> None:
    if threshold < 1:
        raise ValueError("threshold must be at least 1")


def _build_range_request_args(*, ntlm: bool, pad: bool) -> tuple[dict[str, str], dict[str, str]]:
    headers: dict[str, str] = {}
    if pad:
        headers["Add-Padding"] = "true"
    params: dict[str, str] = {}
    if ntlm:
        params["mode"] = "ntlm"
    return headers, params


def _range_cache_key(normalized_prefix: str, *, ntlm: bool) -> str:
    mode = "ntlm" if ntlm else "sha1"
    return f"pwnedpasswords:/range/{normalized_prefix}?mode={mode}"


class PwnedPasswordsClient:
    """Synchronous client for the HIBP Pwned Passwords k-anonymity range API."""

    def __init__(
        self,
        user_agent: str = DEFAULT_USER_AGENT,
        *,
        timeout: float = REQUEST_TIMEOUT,
        proxy: str | None = None,
        client: httpx.Client | None = None,
        cache: ResponseCache | None = None,
    ) -> None:
        self._cache = cache
        self._owns_client = client is None
        if client is not None:
            self._client = client
        else:
            self._client = httpx.Client(
                base_url=BASE_URL,
                headers={"User-Agent": user_agent},
                timeout=timeout,
                proxy=proxy,
            )

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> PwnedPasswordsClient:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def get_password_range(
        self,
        prefix: str,
        *,
        ntlm: bool = False,
        pad: bool = False,
    ) -> dict[str, int]:
        """Fetch all compromised hash suffixes and counts matching a 5-char hex prefix."""
        normalized_prefix = _validate_prefix(prefix)
        cache_key = _range_cache_key(normalized_prefix, ntlm=ntlm)
        if self._cache is not None:
            cached = self._cache.get(cache_key)
            if cached is not None:
                return _parse_range_response(cached.decode("utf-8"))
        headers, params = _build_range_request_args(ntlm=ntlm, pad=pad)
        try:
            resp = self._client.get(
                f"/range/{normalized_prefix}",
                headers=headers,
                params=params,
            )
            resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise HIBPError(f"HTTP {exc.response.status_code}") from exc
        except httpx.RequestError as exc:
            raise HIBPError(f"Request failed: {exc}") from exc
        if self._cache is not None:
            self._cache.set(cache_key, resp.content)
        return _parse_range_response(resp.text)

    def check_hash(
        self,
        hash_hex: str,
        *,
        ntlm: bool = False,
        pad: bool = False,
    ) -> int:
        """Return the breach prevalence count for a pre-hashed SHA-1 or NTLM hex digest."""
        normalized = _validate_full_hash(hash_hex, ntlm=ntlm)
        counts = self.get_password_range(normalized[:5], ntlm=ntlm, pad=pad)
        return counts.get(normalized[5:], 0)

    def is_hash_pwned(
        self,
        hash_hex: str,
        *,
        threshold: int = 1,
        ntlm: bool = False,
        pad: bool = False,
    ) -> bool:
        """Return True if a pre-hashed digest appears at least `threshold` times in breaches."""
        _validate_threshold(threshold)
        return self.check_hash(hash_hex, ntlm=ntlm, pad=pad) >= threshold

    def check_password(
        self,
        password: str,
        *,
        ntlm: bool = False,
        pad: bool = False,
    ) -> int:
        """Return the breach prevalence count for a password (0 if not found)."""
        return self.check_hash(_hash_password(password, ntlm=ntlm), ntlm=ntlm, pad=pad)

    def is_pwned(
        self,
        password: str,
        *,
        threshold: int = 1,
        ntlm: bool = False,
        pad: bool = False,
    ) -> bool:
        """Return True if password appears at least `threshold` times in breaches."""
        _validate_threshold(threshold)
        return self.check_password(password, ntlm=ntlm, pad=pad) >= threshold


class AsyncPwnedPasswordsClient:
    """Asynchronous client for the HIBP Pwned Passwords k-anonymity range API."""

    def __init__(
        self,
        user_agent: str = DEFAULT_USER_AGENT,
        *,
        timeout: float = REQUEST_TIMEOUT,
        proxy: str | None = None,
        client: httpx.AsyncClient | None = None,
        cache: ResponseCache | None = None,
    ) -> None:
        self._cache = cache
        self._owns_client = client is None
        if client is not None:
            self._client = client
        else:
            self._client = httpx.AsyncClient(
                base_url=BASE_URL,
                headers={"User-Agent": user_agent},
                timeout=timeout,
                proxy=proxy,
            )

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def __aenter__(self) -> AsyncPwnedPasswordsClient:
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.aclose()

    async def get_password_range(
        self,
        prefix: str,
        *,
        ntlm: bool = False,
        pad: bool = False,
    ) -> dict[str, int]:
        """Fetch all compromised hash suffixes and counts matching a 5-char hex prefix."""
        normalized_prefix = _validate_prefix(prefix)
        cache_key = _range_cache_key(normalized_prefix, ntlm=ntlm)
        if self._cache is not None:
            cached = self._cache.get(cache_key)
            if cached is not None:
                return _parse_range_response(cached.decode("utf-8"))
        headers, params = _build_range_request_args(ntlm=ntlm, pad=pad)
        try:
            resp = await self._client.get(
                f"/range/{normalized_prefix}",
                headers=headers,
                params=params,
            )
            resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise HIBPError(f"HTTP {exc.response.status_code}") from exc
        except httpx.RequestError as exc:
            raise HIBPError(f"Request failed: {exc}") from exc
        if self._cache is not None:
            self._cache.set(cache_key, resp.content)
        return _parse_range_response(resp.text)

    async def check_hash(
        self,
        hash_hex: str,
        *,
        ntlm: bool = False,
        pad: bool = False,
    ) -> int:
        """Return the breach prevalence count for a pre-hashed SHA-1 or NTLM hex digest."""
        normalized = _validate_full_hash(hash_hex, ntlm=ntlm)
        counts = await self.get_password_range(normalized[:5], ntlm=ntlm, pad=pad)
        return counts.get(normalized[5:], 0)

    async def is_hash_pwned(
        self,
        hash_hex: str,
        *,
        threshold: int = 1,
        ntlm: bool = False,
        pad: bool = False,
    ) -> bool:
        """Return True if a pre-hashed digest appears at least `threshold` times in breaches."""
        _validate_threshold(threshold)
        return await self.check_hash(hash_hex, ntlm=ntlm, pad=pad) >= threshold

    async def check_password(
        self,
        password: str,
        *,
        ntlm: bool = False,
        pad: bool = False,
    ) -> int:
        """Return the breach prevalence count for a password (0 if not found)."""
        return await self.check_hash(_hash_password(password, ntlm=ntlm), ntlm=ntlm, pad=pad)

    async def is_pwned(
        self,
        password: str,
        *,
        threshold: int = 1,
        ntlm: bool = False,
        pad: bool = False,
    ) -> bool:
        """Return True if password appears at least `threshold` times in breaches."""
        _validate_threshold(threshold)
        return await self.check_password(password, ntlm=ntlm, pad=pad) >= threshold


def _ntlm_hash(password: str) -> str:
    return _md4(password.encode("utf-16-le")).upper()
