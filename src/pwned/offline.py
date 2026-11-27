from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path
from typing import BinaryIO

from pwned._parsers import _md4, _parse_range_response

_HEX_CHARS = frozenset("0123456789ABCDEF")
_SHA1_HEX_LEN = 40
_NTLM_HEX_LEN = 32
_BACKWARD_CHUNK_SIZE = 256
_INDEX_FILENAME = ".pwned-index.json"
_INDEX_SNIFF_BYTES = 256
_INDEX_HEAD_MODE_RE = re.compile(r'^\{\s*"mode"\s*:\s*"(sha1|ntlm)"\s*[,}]')
_INDEX_TAIL_MODE_RE = re.compile(r',\s*"mode"\s*:\s*"(sha1|ntlm)"\s*\}\s*$')


def _read_directory_mode(directory: Path) -> str | None:
    """Read optional hash mode metadata ('sha1' or 'ntlm') in O(1) bounded bytes."""
    index_path = directory / _INDEX_FILENAME
    if not index_path.is_file():
        return None
    try:
        with index_path.open("rb") as handle:
            head_bytes = handle.read(_INDEX_SNIFF_BYTES)
            head = head_bytes.decode("utf-8", errors="ignore").lstrip()
            if not head.startswith("{"):
                return None
            head_match = _INDEX_HEAD_MODE_RE.match(head)
            if head_match is not None:
                return head_match.group(1)
            size = os.fstat(handle.fileno()).st_size
            if size > len(head_bytes):
                handle.seek(size - _INDEX_SNIFF_BYTES)
                tail = handle.read(_INDEX_SNIFF_BYTES).decode("utf-8", errors="ignore")
            else:
                tail = head
    except OSError:
        return None
    tail_match = _INDEX_TAIL_MODE_RE.search(tail)
    return tail_match.group(1) if tail_match is not None else None


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


def _find_line_start(file_handle: BinaryIO, pos: int) -> int:
    while pos > 0:
        start = max(0, pos - _BACKWARD_CHUNK_SIZE)
        file_handle.seek(start)
        chunk = file_handle.read(pos - start)
        newline_idx = chunk.rfind(b"\n")
        if newline_idx != -1:
            return start + newline_idx + 1
        pos = start
    return 0


class OfflinePasswordsClient:
    """Zero-dependency offline client for HIBP password dumps.

    Supports both:
    - Single sorted dump files (``HASH:COUNT`` lines) using ``O(log N)`` binary search.
    - Per-prefix directories of range files (``00000.txt``..``FFFFF.txt`` containing
      ``SUFFIX:COUNT`` lines) using ``O(1)`` direct prefix lookup.
    """

    def __init__(self, path: str | os.PathLike[str], *, ntlm: bool = False) -> None:
        self._path = Path(path)
        self._ntlm = ntlm
        self._file: BinaryIO | None
        if self._path.is_dir():
            index_mode = _read_directory_mode(self._path)
            expected_mode = "ntlm" if ntlm else "sha1"
            if index_mode is not None and index_mode != expected_mode:
                raise ValueError(
                    f"Offline directory {self._path} contains {index_mode.upper()} hashes, "
                    f"but client was opened in {expected_mode.upper()} mode"
                )
            self._is_dir = True
            self._file = None
        else:
            self._is_dir = False
            self._file = self._path.open("rb")

    @property
    def path(self) -> Path:
        """Path to the opened HIBP password dump file or range directory."""
        return self._path

    @property
    def ntlm(self) -> bool:
        """Whether this client expects an NTLM dump instead of SHA-1."""
        return self._ntlm

    @property
    def is_directory(self) -> bool:
        """Whether this client reads from a per-prefix directory of range files."""
        return self._is_dir

    def close(self) -> None:
        """Close the underlying dump file handle if open."""
        if self._file is not None:
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

    def _lookup_hash(self, normalized_hash: str) -> int:
        if self._file is None:
            prefix_file = self._path / f"{normalized_hash[:5]}.txt"
            if not prefix_file.is_file():
                return 0
            return _parse_range_response(prefix_file.read_text(encoding="utf-8")).get(
                normalized_hash[5:],
                0,
            )

        file_handle = self._file
        target = normalized_hash.encode("ascii")
        file_size = os.fstat(file_handle.fileno()).st_size
        low = 0
        high = file_size

        while low < high:
            mid = (low + high) // 2
            line_start = _find_line_start(file_handle, mid)
            file_handle.seek(line_start)
            raw_line = file_handle.readline()
            line_end = file_handle.tell()

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
        pad: bool = True,
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
        pad: bool = True,
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
        pad: bool = True,
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
        pad: bool = True,
    ) -> bool:
        """Return True if hash appears at least `threshold` times in the dump."""
        _validate_threshold(threshold)
        return self.check_hash(hash_hex, ntlm=ntlm, pad=pad) >= threshold
