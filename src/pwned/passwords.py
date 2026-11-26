from __future__ import annotations

import hashlib
import struct

import httpx

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


def _parse_range_response(text: str) -> dict[str, int]:
    """Parse an HIBP range API body into uppercase suffix -> positive count."""
    results: dict[str, int] = {}
    for line in text.splitlines():
        parts = line.strip().split(":")
        if len(parts) != 2:
            continue
        suffix = parts[0].strip().upper()
        if not suffix:
            continue
        try:
            count = int(parts[1])
        except ValueError:
            continue
        # Padded responses include fake entries with count=0; only report genuine matches.
        if count > 0:
            results[suffix] = count
    return results


class PwnedPasswordsClient:
    """Synchronous client for the HIBP Pwned Passwords k-anonymity range API."""

    def __init__(
        self,
        user_agent: str = DEFAULT_USER_AGENT,
        *,
        timeout: float = REQUEST_TIMEOUT,
        proxy: str | None = None,
        client: httpx.Client | None = None,
    ) -> None:
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
        return _parse_range_response(resp.text)

    def check_password(
        self,
        password: str,
        *,
        ntlm: bool = False,
        pad: bool = False,
    ) -> int:
        """Return the breach prevalence count for a password (0 if not found)."""
        hash_value = _hash_password(password, ntlm=ntlm)
        counts = self.get_password_range(hash_value[:5], ntlm=ntlm, pad=pad)
        return counts.get(hash_value[5:], 0)

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
    ) -> None:
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
        return _parse_range_response(resp.text)

    async def check_password(
        self,
        password: str,
        *,
        ntlm: bool = False,
        pad: bool = False,
    ) -> int:
        """Return the breach prevalence count for a password (0 if not found)."""
        hash_value = _hash_password(password, ntlm=ntlm)
        counts = await self.get_password_range(hash_value[:5], ntlm=ntlm, pad=pad)
        return counts.get(hash_value[5:], 0)

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


def _md4(data: bytes) -> str:
    """Pure-Python MD4 (RFC 1320) used for NTLM hashing.

    A custom implementation is required because Python's hashlib does not
    guarantee MD4 availability -- OpenSSL 3.0+ disables legacy algorithms
    by default, making hashlib.new("md4") fail on many systems. Performance
    is not a concern since only a single short password is hashed per call.
    """

    def _f(x: int, y: int, z: int) -> int:
        return (x & y) | ((~x & 0xFFFFFFFF) & z)

    def _g(x: int, y: int, z: int) -> int:
        return (x & y) | (x & z) | (y & z)

    def _h(x: int, y: int, z: int) -> int:
        return x ^ y ^ z

    def _left_rotate(n: int, b: int) -> int:
        return ((n << b) | (n >> (32 - b))) & 0xFFFFFFFF

    msg = bytearray(data)
    orig_len = len(msg) * 8
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += struct.pack("<Q", orig_len)

    a0 = 0x67452301
    b0 = 0xEFCDAB89
    c0 = 0x98BADCFE
    d0 = 0x10325476

    for i in range(0, len(msg), 64):
        x = list(struct.unpack("<16I", msg[i : i + 64]))
        a, b, c, d = a0, b0, c0, d0

        for k in [0, 4, 8, 12]:
            a = _left_rotate((a + _f(b, c, d) + x[k]) & 0xFFFFFFFF, 3)
            d = _left_rotate((d + _f(a, b, c) + x[k + 1]) & 0xFFFFFFFF, 7)
            c = _left_rotate((c + _f(d, a, b) + x[k + 2]) & 0xFFFFFFFF, 11)
            b = _left_rotate((b + _f(c, d, a) + x[k + 3]) & 0xFFFFFFFF, 19)

        for k in [0, 1, 2, 3]:
            a = _left_rotate((a + _g(b, c, d) + x[k] + 0x5A827999) & 0xFFFFFFFF, 3)
            d = _left_rotate((d + _g(a, b, c) + x[k + 4] + 0x5A827999) & 0xFFFFFFFF, 5)
            c = _left_rotate((c + _g(d, a, b) + x[k + 8] + 0x5A827999) & 0xFFFFFFFF, 9)
            b = _left_rotate((b + _g(c, d, a) + x[k + 12] + 0x5A827999) & 0xFFFFFFFF, 13)

        for k in [0, 2, 1, 3]:
            a = _left_rotate((a + _h(b, c, d) + x[k] + 0x6ED9EBA1) & 0xFFFFFFFF, 3)
            d = _left_rotate((d + _h(a, b, c) + x[k + 8] + 0x6ED9EBA1) & 0xFFFFFFFF, 9)
            c = _left_rotate((c + _h(d, a, b) + x[k + 4] + 0x6ED9EBA1) & 0xFFFFFFFF, 11)
            b = _left_rotate((b + _h(c, d, a) + x[k + 12] + 0x6ED9EBA1) & 0xFFFFFFFF, 15)

        a0 = (a0 + a) & 0xFFFFFFFF
        b0 = (b0 + b) & 0xFFFFFFFF
        c0 = (c0 + c) & 0xFFFFFFFF
        d0 = (d0 + d) & 0xFFFFFFFF

    return struct.pack("<4I", a0, b0, c0, d0).hex()
