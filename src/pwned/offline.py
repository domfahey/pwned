from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import BinaryIO

from pwned._parsers import _md4

_HEX_CHARS = frozenset("0123456789ABCDEF")
_SHA1_HEX_LEN = 40
_NTLM_HEX_LEN = 32
_BACKWARD_CHUNK_SIZE = 256


def _hash_password(password: str, *, ntlm: bool) -> str:
    """Return the uppercase SHA-1 or NTLM hex digest for a password."""
    if ntlm:
        return _md4(password.encode("utf-16-le")).upper()
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()  # noqa: S324


def _validate_hash(hash_hex: str, *, ntlm: bool) -> str:
    """Normalize and validate a full SHA-1 (40-char) or NTLM (32-char) hex digest."""
    expected_len = _NTLM_HEX_LEN if ntlm else _SHA1_HEX_LEN
    normalized = hash_hex.strip().upper()
    if len(normalized) != expected_len or any(ch not in _HEX_CHARS for ch in normalized):
        kind = "NTLM" if ntlm else "SHA-1"
        raise ValueError(f"{kind} hash must be exactly {expected_len} hexadecimal characters")
    return normalized


def _validate_threshold(threshold: int) -> None:
    if threshold < 1:
        raise ValueError("threshold must be at least 1")


def _parse_count(raw_count: bytes) -> int:
    try:
        count = int(raw_count)
    except ValueError:
        return 0
    return count if count > 0 else 0


class OfflinePasswordsClient:
    """Zero-dependency O(log N) binary-search client for HIBP password dump files."""

    def __init__(self, path: str | os.PathLike[str], *, ntlm: bool = False) -> None:
        self._path = Path(path)
        self._ntlm = ntlm
        self._file: BinaryIO = self._path.open("rb")

    @property
    def path(self) -> Path:
        """Path to the opened HIBP password dump file."""
        return self._path

    @property
    def ntlm(self) -> bool:
        """Whether this client expects an NTLM dump instead of SHA-1."""
        return self._ntlm

    def close(self) -> None:
        """Close the underlying dump file handle."""
        self._file.close()

    def __enter__(self) -> OfflinePasswordsClient:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def _resolve_ntlm(self, ntlm: bool | None) -> bool:
        if ntlm is not None and ntlm != self._ntlm:
            expected = "NTLM" if self._ntlm else "SHA-1"
            raise ValueError(
                f"Client is configured for {expected} mode (ntlm={self._ntlm}); got ntlm={ntlm}"
            )
        return self._ntlm

    def _find_line_start(self, pos: int) -> int:
        while pos > 0:
            start = max(0, pos - _BACKWARD_CHUNK_SIZE)
            self._file.seek(start)
            chunk = self._file.read(pos - start)
            newline_idx = chunk.rfind(b"\n")
            if newline_idx != -1:
                return start + newline_idx + 1
            pos = start
        return 0

    def _lookup_hash(self, normalized_hash: str) -> int:
        target = normalized_hash.encode("ascii")
        file_size = os.fstat(self._file.fileno()).st_size
        low = 0
        high = file_size

        while low < high:
            mid = (low + high) // 2
            line_start = self._find_line_start(mid)
            self._file.seek(line_start)
            raw_line = self._file.readline()
            line_end = self._file.tell()

            entry_hash, sep, raw_count = raw_line.rstrip(b"\r\n").partition(b":")
            if not sep:
                return 0

            normalized_entry = entry_hash.strip().upper()
            if normalized_entry == target:
                return _parse_count(raw_count)
            if normalized_entry < target:
                low = line_end
            else:
                high = line_start

        return 0

    def check_password(
        self,
        password: str,
        *,
        ntlm: bool | None = None,
        pad: bool = False,
    ) -> int:
        """Return the breach prevalence count for a password (0 if not found)."""
        _ = pad
        use_ntlm = self._resolve_ntlm(ntlm)
        digest = _hash_password(password, ntlm=use_ntlm)
        return self._lookup_hash(digest)

    def check_hash(
        self,
        hash_hex: str,
        *,
        ntlm: bool | None = None,
        pad: bool = False,
    ) -> int:
        """Return the breach prevalence count for a precomputed hash (0 if not found)."""
        _ = pad
        use_ntlm = self._resolve_ntlm(ntlm)
        normalized = _validate_hash(hash_hex, ntlm=use_ntlm)
        return self._lookup_hash(normalized)

    def is_pwned(
        self,
        password: str,
        *,
        threshold: int = 1,
        ntlm: bool | None = None,
        pad: bool = False,
    ) -> bool:
        """Return True if password appears at least `threshold` times in the dump."""
        _validate_threshold(threshold)
        return self.check_password(password, ntlm=ntlm, pad=pad) >= threshold

    def is_hash_pwned(
        self,
        hash_hex: str,
        *,
        threshold: int = 1,
        ntlm: bool | None = None,
        pad: bool = False,
    ) -> bool:
        """Return True if hash appears at least `threshold` times in the dump."""
        _validate_threshold(threshold)
        return self.check_hash(hash_hex, ntlm=ntlm, pad=pad) >= threshold
