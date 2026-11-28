from __future__ import annotations

import html
import re
import struct
from collections.abc import Iterable
from html.parser import HTMLParser

_TAG_RE = re.compile(r"<[^>]*>")


class _HTMLStripper(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._parts: list[str] = []

    def handle_data(self, data: str) -> None:
        self._parts.append(data)

    def get_text(self) -> str:
        return "".join(self._parts)


def strip_html(text: str) -> str:
    """Strip HTML tags and decode character references."""
    stripper = _HTMLStripper()
    try:
        stripper.feed(text)
        stripper.close()
    except AssertionError:
        return html.unescape(_TAG_RE.sub("", text))
    return stripper.get_text()


def parse_input_lines(
    lines: Iterable[str],
    *,
    strip: bool = True,
    ignore_comments: bool = True,
    deduplicate: bool = True,
    skip_empty: bool = True,
) -> list[str]:
    """Normalize, filter, and optionally deduplicate input lines while preserving order."""
    seen: set[str] = set()
    result: list[str] = []
    for raw in lines:
        value = raw.rstrip("\r\n")
        if strip:
            value = value.strip()
        if skip_empty and not value:
            continue
        if ignore_comments and value.lstrip().startswith("#"):
            continue
        if deduplicate:
            if value in seen:
                continue
            seen.add(value)
        result.append(value)
    return result


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


EMPTY_LM_HASH = "AAD3B435B51404EEAAD3B435B51404EE"
EMPTY_NTLM_HASH = "31D6CFE0D16AE931B73C59D7E0C089C0"
_HEX_CHARS = frozenset("0123456789abcdefABCDEF")


def _is_hex32(value: str) -> bool:
    return len(value) == 32 and all(c in _HEX_CHARS for c in value)


def parse_pwdump_records(lines: Iterable[str]) -> list[tuple[str, str, str, str]]:
    """Parse impacket secretsdump / pwdump lines into (domain, user, lm_upper, nt_upper) tuples.

    If the LM field is missing or not a 32-character hex digest (e.g. placeholder text),
    the returned LM field is an empty string.
    """
    results: list[tuple[str, str, str, str]] = []
    for raw in lines:
        line = raw.rstrip("\r\n")
        if not line:
            continue
        stripped = line.lstrip()
        if stripped.startswith("#") or stripped.startswith("[*]"):
            continue
        parts = line.split(":")
        if len(parts) < 4:
            continue
        account = parts[0].strip()
        rid = parts[1].strip()
        lm = parts[2].strip()
        nt = parts[3].strip()

        if not account or not rid.isdigit():
            continue
        if not _is_hex32(nt):
            continue

        if "\\" in account:
            if account.startswith("\\"):
                continue
            domain, _, username = account.partition("\\")
        else:
            domain, username = "", account

        domain = domain.strip()
        username = username.strip()
        if not username:
            continue

        lm_upper = lm.upper() if _is_hex32(lm) else ""
        results.append((domain, username, lm_upper, nt.upper()))
    return results


def parse_pwdump_lines(lines: Iterable[str]) -> list[tuple[str, str, str]]:
    """Parse impacket secretsdump / pwdump lines into (domain, username, nt_hash_upper) tuples."""
    return [(domain, username, nt) for domain, username, _lm, nt in parse_pwdump_records(lines)]
