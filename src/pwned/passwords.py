from __future__ import annotations

import hashlib
import struct

import httpx

from pwned.client import HIBPError

BASE_URL = "https://api.pwnedpasswords.com"
REQUEST_TIMEOUT = 10.0


class PwnedPasswordsClient:
    def __init__(self, user_agent: str = "pwned-cli") -> None:
        self._client = httpx.Client(
            base_url=BASE_URL,
            headers={"User-Agent": user_agent},
            timeout=REQUEST_TIMEOUT,
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> PwnedPasswordsClient:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def check_password(
        self,
        password: str,
        *,
        ntlm: bool = False,
        pad: bool = False,
    ) -> int:
        if ntlm:
            hash_value = _ntlm_hash(password)
        else:
            hash_value = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()  # noqa: S324

        prefix = hash_value[:5]
        suffix = hash_value[5:]

        headers: dict[str, str] = {}
        if pad:
            headers["Add-Padding"] = "true"

        params: dict[str, str] = {}
        if ntlm:
            params["mode"] = "ntlm"

        resp = self._client.get(f"/range/{prefix}", headers=headers, params=params)
        try:
            resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise HIBPError(f"HTTP {resp.status_code}") from exc

        for line in resp.text.splitlines():
            parts = line.strip().split(":")
            if len(parts) == 2 and parts[0].upper() == suffix:
                count = int(parts[1])
                # Padded responses include fake entries with count=0; only report genuine matches.
                if count > 0:
                    return count
        return 0


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
