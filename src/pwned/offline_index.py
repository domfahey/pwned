from __future__ import annotations

import contextlib
import itertools
import math
import mmap
import os
import re
import struct
import tempfile
import time
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import BinaryIO, Literal

from pwned.models import NonNegativeInt, _HIBPBase

OfflineFormat = Literal["directory", "compact", "bloom", "text"]

COMPACT_MAGIC = b"PWNB"
COMPACT_VERSION = 1
BLOOM_MAGIC = b"PWNL"
BLOOM_VERSION = 1
PREFIX_COUNT = 1_048_576  # 0x100000

_COMPACT_HEADER_STRUCT = struct.Struct("<4sBBHQ")
_BLOOM_HEADER_STRUCT = struct.Struct("<4sBBHQQQ")
_JUMP_TABLE_STRUCT = struct.Struct(f"<{PREFIX_COUNT + 1}Q")
_JUMP_PAIR_STRUCT = struct.Struct("<QQ")
_COUNT_STRUCT = struct.Struct("<I")

_JUMP_TABLE_OFFSET = _COMPACT_HEADER_STRUCT.size  # 16
_JUMP_TABLE_BYTES = (PREFIX_COUNT + 1) * 8  # 8,388,616
_COMPACT_RECORDS_OFFSET = _JUMP_TABLE_OFFSET + _JUMP_TABLE_BYTES  # 8,388,632

_SHA1_DIGEST_LEN = 20
_NTLM_DIGEST_LEN = 16
_SHA1_HEX_LEN = 40
_NTLM_HEX_LEN = 32
_SHA1_SUFFIX_LEN = 35
_NTLM_SUFFIX_LEN = 27
_SHA1_RECORD_SIZE = _SHA1_DIGEST_LEN + _COUNT_STRUCT.size  # 24
_NTLM_RECORD_SIZE = _NTLM_DIGEST_LEN + _COUNT_STRUCT.size  # 20
_MAX_UINT32 = 0xFFFFFFFF

_HEX_CHARS = frozenset("0123456789ABCDEF")
_PREFIX_FILE_RE = re.compile(r"^[0-9A-Fa-f]{5}\.txt$")
_INDEX_FILENAME = ".pwned-index.json"
_INDEX_SNIFF_BYTES = 256
_INDEX_HEAD_MODE_RE = re.compile(r'^\{\s*"mode"\s*:\s*"(sha1|ntlm)"\s*[,}]')
_INDEX_TAIL_MODE_RE = re.compile(r',\s*"mode"\s*:\s*"(sha1|ntlm)"\s*\}\s*$')


class CompactIndexStats(_HIBPBase):
    """Summary statistics returned by :func:`build_compact_index`."""

    output_path: str
    ntlm: bool
    record_count: NonNegativeInt
    bytes_written: NonNegativeInt
    elapsed_seconds: float


class BloomIndexStats(_HIBPBase):
    """Summary statistics returned by :func:`build_bloom_filter`."""

    output_path: str
    ntlm: bool
    item_count: NonNegativeInt
    bit_count: NonNegativeInt
    num_hashes: int
    false_positive_rate: float
    bytes_written: NonNegativeInt
    elapsed_seconds: float


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


def detect_offline_format(path: Path) -> OfflineFormat:
    """Detect whether ``path`` is a range directory, compact binary index, Bloom filter, or text."""
    if path.is_dir():
        return "directory"
    with path.open("rb") as handle:
        magic = handle.read(4)
    if magic == COMPACT_MAGIC:
        return "compact"
    if magic == BLOOM_MAGIC:
        return "bloom"
    return "text"


def _parse_compact_header(raw: bytes, file_size: int) -> tuple[bool, int]:
    if len(raw) < _COMPACT_HEADER_STRUCT.size:
        raise ValueError("Truncated compact index header")
    magic, version, mode, _reserved, record_count = _COMPACT_HEADER_STRUCT.unpack_from(raw, 0)
    if magic != COMPACT_MAGIC:
        raise ValueError("Invalid compact index magic bytes")
    if version != COMPACT_VERSION:
        raise ValueError(f"Unsupported compact index version: {version}")
    if mode not in (0, 1):
        raise ValueError(f"Unsupported compact index mode: {mode}")
    ntlm = mode == 1
    record_size = _NTLM_RECORD_SIZE if ntlm else _SHA1_RECORD_SIZE
    expected_size = _COMPACT_RECORDS_OFFSET + record_count * record_size
    if file_size != expected_size:
        raise ValueError(
            f"Corrupt compact index file size: expected {expected_size} bytes, got {file_size}"
        )
    return ntlm, record_count


def _parse_bloom_header(raw: bytes, file_size: int) -> tuple[bool, int, int, int]:
    if len(raw) < _BLOOM_HEADER_STRUCT.size:
        raise ValueError("Truncated Bloom filter header")
    (
        magic,
        version,
        mode,
        num_hashes,
        bit_count,
        item_count,
        _reserved,
    ) = _BLOOM_HEADER_STRUCT.unpack_from(raw, 0)
    if magic != BLOOM_MAGIC:
        raise ValueError("Invalid Bloom filter magic bytes")
    if version != BLOOM_VERSION:
        raise ValueError(f"Unsupported Bloom filter version: {version}")
    if mode not in (0, 1):
        raise ValueError(f"Unsupported Bloom filter mode: {mode}")
    if num_hashes < 1:
        raise ValueError(f"Invalid Bloom filter hash count: {num_hashes}")
    if bit_count < 8 or bit_count % 8 != 0:
        raise ValueError(f"Invalid Bloom filter bit count: {bit_count}")
    expected_size = _BLOOM_HEADER_STRUCT.size + bit_count // 8
    if file_size != expected_size:
        raise ValueError(
            f"Corrupt Bloom filter file size: expected {expected_size} bytes, got {file_size}"
        )
    return mode == 1, item_count, bit_count, num_hashes


def read_binary_index_header(
    path: Path,
) -> tuple[Literal["compact", "bloom"], bool, dict[str, int]]:
    """Validate and decode metadata from a compact binary index or Bloom filter header."""
    with path.open("rb") as handle:
        file_size = os.fstat(handle.fileno()).st_size
        raw = handle.read(_BLOOM_HEADER_STRUCT.size)
    magic = raw[:4]
    if magic == COMPACT_MAGIC:
        ntlm, record_count = _parse_compact_header(raw, file_size)
        return "compact", ntlm, {"record_count": record_count}
    if magic == BLOOM_MAGIC:
        ntlm, item_count, bit_count, num_hashes = _parse_bloom_header(raw, file_size)
        return (
            "bloom",
            ntlm,
            {
                "item_count": item_count,
                "bit_count": bit_count,
                "num_hashes": num_hashes,
            },
        )
    raise ValueError(f"Unrecognized binary index header in {path}")


def _check_reader_mode(
    file_ntlm: bool,
    requested_ntlm: bool | None,
    *,
    kind: str,
    path: Path,
) -> None:
    if requested_ntlm is not None and requested_ntlm != file_ntlm:
        actual = "NTLM" if file_ntlm else "SHA1"
        requested = "NTLM" if requested_ntlm else "SHA1"
        raise ValueError(
            f"{kind} {path} contains {actual} hashes, but {requested} mode was requested"
        )


def _parse_hex_digest(hex_str: str, expected_hex_len: int) -> bytes:
    if len(hex_str) != expected_hex_len:
        raise ValueError(f"Expected {expected_hex_len}-character hex hash, got {len(hex_str)}")
    try:
        digest = bytes.fromhex(hex_str)
    except ValueError as exc:
        raise ValueError("Invalid hexadecimal hash") from exc
    if len(digest) != expected_hex_len // 2:
        raise ValueError("Invalid hexadecimal hash")
    return digest


@contextlib.contextmanager
def _atomic_open_binary(target: Path) -> Iterator[BinaryIO]:
    """Open a sibling temp file for binary writes and atomically replace ``target`` on success."""
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        dir=target.parent,
        prefix=f".{target.name}.",
        suffix=".tmp",
    )
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            yield handle
            handle.flush()
        os.replace(tmp_path, target)
    except BaseException:
        with contextlib.suppress(OSError):
            tmp_path.unlink(missing_ok=True)
        raise


def _list_prefix_files(directory: Path) -> list[tuple[int, Path]]:
    files: list[tuple[int, Path]] = []
    for entry in directory.iterdir():
        if entry.is_file() and _PREFIX_FILE_RE.fullmatch(entry.name):
            files.append((int(entry.stem, 16), entry))
    files.sort(key=lambda item: item[0])
    return files


def _resolve_directory_ntlm(
    directory: Path,
    prefix_files: list[tuple[int, Path]],
    *,
    ntlm: bool | None,
) -> bool:
    index_mode = _read_directory_mode(directory)
    if ntlm is not None:
        if index_mode is not None and (index_mode == "ntlm") != ntlm:
            requested = "NTLM" if ntlm else "SHA1"
            raise ValueError(
                f"Offline directory {directory} contains {index_mode.upper()} hashes, "
                f"but {requested} mode was requested"
            )
        return ntlm
    if index_mode is not None:
        return index_mode == "ntlm"
    for _prefix_int, prefix_file in prefix_files:
        with prefix_file.open("r", encoding="utf-8") as handle:
            for raw_line in handle:
                line = raw_line.strip()
                if not line:
                    continue
                raw_suffix, sep, _raw_count = line.partition(":")
                if not sep:
                    raise ValueError(f"Malformed range line in {prefix_file}")
                suffix_len = len(raw_suffix.strip())
                if suffix_len == _NTLM_SUFFIX_LEN:
                    return True
                if suffix_len == _SHA1_SUFFIX_LEN:
                    return False
                raise ValueError(f"Unexpected hash suffix length {suffix_len} in {prefix_file}")
    return False


def _resolve_text_ntlm(source: Path, *, ntlm: bool | None) -> bool:
    if ntlm is not None:
        return ntlm
    with source.open("r", encoding="utf-8") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line:
                continue
            raw_hash, sep, _raw_count = line.partition(":")
            if not sep:
                raise ValueError(f"Malformed dump line in {source}")
            hash_len = len(raw_hash.strip())
            if hash_len == _NTLM_HEX_LEN:
                return True
            if hash_len == _SHA1_HEX_LEN:
                return False
            raise ValueError(f"Unexpected hash length {hash_len} in {source}")
    return False


def _iter_directory_records(
    prefix_files: list[tuple[int, Path]],
    *,
    ntlm: bool,
) -> Iterator[tuple[bytes, int]]:
    expected_hex_len = _NTLM_HEX_LEN if ntlm else _SHA1_HEX_LEN
    for _prefix_int, prefix_file in prefix_files:
        prefix_hex = prefix_file.stem.upper()
        bucket: dict[bytes, int] = {}
        with prefix_file.open("r", encoding="utf-8") as handle:
            for raw_line in handle:
                line = raw_line.strip()
                if not line:
                    continue
                raw_suffix, sep, raw_count = line.partition(":")
                if not sep:
                    raise ValueError(f"Malformed range line in {prefix_file}")
                try:
                    count = int(raw_count.strip())
                except ValueError as exc:
                    raise ValueError(f"Invalid breach count in {prefix_file}") from exc
                digest = _parse_hex_digest(f"{prefix_hex}{raw_suffix.strip()}", expected_hex_len)
                if count <= 0:
                    continue
                bucket[digest] = count
        yield from sorted(bucket.items())


def _iter_text_records(
    source: Path,
    *,
    ntlm: bool,
    require_sorted: bool,
) -> Iterator[tuple[bytes, int]]:
    expected_hex_len = _NTLM_HEX_LEN if ntlm else _SHA1_HEX_LEN
    prev_digest: bytes | None = None
    with source.open("r", encoding="utf-8") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line:
                continue
            raw_hash, sep, raw_count = line.partition(":")
            if not sep:
                raise ValueError(f"Malformed dump line in {source}")
            try:
                count = int(raw_count.strip())
            except ValueError as exc:
                raise ValueError(f"Invalid breach count in {source}") from exc
            digest = _parse_hex_digest(raw_hash.strip(), expected_hex_len)
            if count <= 0:
                continue
            if require_sorted:
                if prev_digest is not None and digest <= prev_digest:
                    raise ValueError("Source dump file is not sorted in ascending hash order.")
                prev_digest = digest
            yield digest, count


def build_compact_index(
    source: Path,
    output: Path,
    *,
    ntlm: bool | None = None,
    overwrite: bool = False,
) -> CompactIndexStats:
    """Compile a per-prefix directory or sorted text dump into a compact binary index."""
    if not source.exists():
        raise FileNotFoundError(f"Source offline dump not found: {source}")
    if output.is_dir():
        raise IsADirectoryError(f"Output path is a directory: {output}")
    if output.exists() and not overwrite:
        raise FileExistsError(
            f"Output file already exists: {output} (use overwrite=True to replace)"
        )

    source_fmt = detect_offline_format(source)
    if source_fmt in ("compact", "bloom"):
        raise ValueError(
            f"Source for compact index must be a text dump or range directory, "
            f"got {source_fmt} file: {source}"
        )

    started = time.monotonic()
    if source_fmt == "directory":
        prefix_files = _list_prefix_files(source)
        resolved_ntlm = _resolve_directory_ntlm(source, prefix_files, ntlm=ntlm)
        records = _iter_directory_records(prefix_files, ntlm=resolved_ntlm)
    else:
        resolved_ntlm = _resolve_text_ntlm(source, ntlm=ntlm)
        records = _iter_text_records(source, ntlm=resolved_ntlm, require_sorted=True)

    record_size = _NTLM_RECORD_SIZE if resolved_ntlm else _SHA1_RECORD_SIZE
    pack_count = _COUNT_STRUCT.pack
    prefix_counts = [0] * PREFIX_COUNT
    record_count = 0

    with _atomic_open_binary(output) as handle:
        handle.write(bytes(_COMPACT_RECORDS_OFFSET))
        for digest, count in records:
            prefix_int = (digest[0] << 12) | (digest[1] << 4) | (digest[2] >> 4)
            prefix_counts[prefix_int] += 1
            clamped = min(count, _MAX_UINT32)
            handle.write(digest + pack_count(clamped))
            record_count += 1
        handle.seek(0)
        mode_byte = 1 if resolved_ntlm else 0
        handle.write(
            _COMPACT_HEADER_STRUCT.pack(
                COMPACT_MAGIC,
                COMPACT_VERSION,
                mode_byte,
                0,
                record_count,
            )
        )
        handle.write(_JUMP_TABLE_STRUCT.pack(*itertools.accumulate(prefix_counts, initial=0)))

    bytes_written = _COMPACT_RECORDS_OFFSET + record_count * record_size
    return CompactIndexStats(
        output_path=str(output),
        ntlm=resolved_ntlm,
        record_count=record_count,
        bytes_written=bytes_written,
        elapsed_seconds=max(0.0, time.monotonic() - started),
    )


class CompactIndexReader:
    """Memory-mapped reader for compact fixed-width prefix-indexed binary dumps."""

    def __init__(self, path: str | os.PathLike[str], *, ntlm: bool | None = None) -> None:
        self._path = Path(path)
        handle = self._path.open("rb")
        try:
            file_size = os.fstat(handle.fileno()).st_size
            header = handle.read(_COMPACT_HEADER_STRUCT.size)
            file_ntlm, record_count = _parse_compact_header(header, file_size)
            _check_reader_mode(file_ntlm, ntlm, kind="Compact index", path=self._path)
            mm = mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ)
        except BaseException:
            handle.close()
            raise
        self._file = handle
        self._mm = mm
        self._ntlm = file_ntlm
        self._record_count = record_count
        self._digest_len = _NTLM_DIGEST_LEN if file_ntlm else _SHA1_DIGEST_LEN
        self._hex_len = _NTLM_HEX_LEN if file_ntlm else _SHA1_HEX_LEN
        self._record_size = _NTLM_RECORD_SIZE if file_ntlm else _SHA1_RECORD_SIZE

    @property
    def path(self) -> Path:
        """Path to the opened compact binary index file."""
        return self._path

    @property
    def ntlm(self) -> bool:
        """Whether this compact index stores NTLM hashes instead of SHA-1."""
        return self._ntlm

    @property
    def record_count(self) -> int:
        """Total number of hash records in the compact index."""
        return self._record_count

    def close(self) -> None:
        """Close the memory map before closing the underlying file handle."""
        self._mm.close()
        self._file.close()

    def __enter__(self) -> CompactIndexReader:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def _iter_digests(self) -> Iterator[bytes]:
        record_size = self._record_size
        digest_len = self._digest_len
        mm = self._mm
        for idx in range(self._record_count):
            pos = _COMPACT_RECORDS_OFFSET + idx * record_size
            yield mm[pos : pos + digest_len]

    def lookup_hash(self, normalized_hash: str) -> int:
        """Return the breach prevalence count for a full SHA-1 or NTLM hex hash (0 if absent)."""
        normalized = normalized_hash.strip().upper()
        target = _parse_hex_digest(normalized, self._hex_len)
        prefix_int = int(normalized[:5], 16)
        lo, hi = _JUMP_PAIR_STRUCT.unpack_from(self._mm, _JUMP_TABLE_OFFSET + prefix_int * 8)

        record_size = self._record_size
        digest_len = self._digest_len
        mm = self._mm
        while lo < hi:
            mid = (lo + hi) // 2
            pos = _COMPACT_RECORDS_OFFSET + mid * record_size
            entry_digest = mm[pos : pos + digest_len]
            if entry_digest == target:
                return int(_COUNT_STRUCT.unpack_from(mm, pos + digest_len)[0])
            if entry_digest < target:
                lo = mid + 1
            else:
                hi = mid
        return 0

    def get_range(self, normalized_prefix: str) -> dict[str, int]:
        """Return uppercase hash suffixes -> positive breach counts for a 5-char hex prefix."""
        prefix = normalized_prefix.strip().upper()
        if len(prefix) != 5 or any(ch not in _HEX_CHARS for ch in prefix):
            raise ValueError("Hash prefix must be exactly 5 hexadecimal characters")
        prefix_int = int(prefix, 16)
        lo, hi = _JUMP_PAIR_STRUCT.unpack_from(self._mm, _JUMP_TABLE_OFFSET + prefix_int * 8)

        result: dict[str, int] = {}
        record_size = self._record_size
        digest_len = self._digest_len
        mm = self._mm
        for idx in range(lo, hi):
            pos = _COMPACT_RECORDS_OFFSET + idx * record_size
            full_hex = mm[pos : pos + digest_len].hex().upper()
            count = int(_COUNT_STRUCT.unpack_from(mm, pos + digest_len)[0])
            result[full_hex[5:]] = count
        return result


def _bloom_positions(digest_bytes: bytes, *, bit_count: int, num_hashes: int) -> Iterator[int]:
    h1 = int.from_bytes(digest_bytes[:8], "little")
    h2 = int.from_bytes(digest_bytes[8:16], "little") | 1
    for i in range(num_hashes):
        yield (h1 + i * h2) % bit_count


def _compute_bloom_params(expected_items: int, false_positive_rate: float) -> tuple[int, int]:
    if not (0.0 < false_positive_rate < 1.0):
        raise ValueError("false_positive_rate must be strictly between 0 and 1")
    if expected_items < 0:
        raise ValueError("expected_items must be non-negative")
    effective_n = max(1, expected_items)
    raw_bits = math.ceil(-(effective_n * math.log(false_positive_rate)) / (math.log(2.0) ** 2))
    bit_count = ((max(64, raw_bits) + 7) // 8) * 8
    num_hashes = max(1, min(32, round((bit_count / effective_n) * math.log(2.0))))
    return bit_count, num_hashes


def _set_bloom_bits(
    bits: bytearray,
    digests: Iterable[bytes],
    *,
    bit_count: int,
    num_hashes: int,
) -> int:
    item_count = 0
    for digest in digests:
        for pos in _bloom_positions(digest, bit_count=bit_count, num_hashes=num_hashes):
            bits[pos >> 3] |= 1 << (pos & 7)
        item_count += 1
    return item_count


def build_bloom_filter(
    source: Path,
    output: Path,
    *,
    ntlm: bool | None = None,
    false_positive_rate: float = 0.01,
    expected_items: int | None = None,
    overwrite: bool = False,
) -> BloomIndexStats:
    """Build an mmap-able Bloom filter from a compact index, range directory, or text dump."""
    if not (0.0 < false_positive_rate < 1.0):
        raise ValueError("false_positive_rate must be strictly between 0 and 1")
    if expected_items is not None and expected_items < 1:
        raise ValueError("expected_items must be at least 1")
    if not source.exists():
        raise FileNotFoundError(f"Source offline dump not found: {source}")
    if output.is_dir():
        raise IsADirectoryError(f"Output path is a directory: {output}")
    if output.exists() and not overwrite:
        raise FileExistsError(
            f"Output file already exists: {output} (use overwrite=True to replace)"
        )

    source_fmt = detect_offline_format(source)
    if source_fmt == "bloom":
        raise ValueError(f"Source for Bloom filter cannot be an existing Bloom filter: {source}")

    started = time.monotonic()
    if source_fmt == "compact":
        with CompactIndexReader(source, ntlm=ntlm) as reader:
            resolved_ntlm = reader.ntlm
            target_items = expected_items if expected_items is not None else reader.record_count
            bit_count, num_hashes = _compute_bloom_params(target_items, false_positive_rate)
            bits = bytearray(bit_count // 8)
            item_count = _set_bloom_bits(
                bits,
                reader._iter_digests(),
                bit_count=bit_count,
                num_hashes=num_hashes,
            )
    elif source_fmt == "directory":
        prefix_files = _list_prefix_files(source)
        resolved_ntlm = _resolve_directory_ntlm(source, prefix_files, ntlm=ntlm)
        target_items = (
            expected_items
            if expected_items is not None
            else sum(1 for _ in _iter_directory_records(prefix_files, ntlm=resolved_ntlm))
        )
        bit_count, num_hashes = _compute_bloom_params(target_items, false_positive_rate)
        bits = bytearray(bit_count // 8)
        item_count = _set_bloom_bits(
            bits,
            (
                digest
                for digest, _count in _iter_directory_records(prefix_files, ntlm=resolved_ntlm)
            ),
            bit_count=bit_count,
            num_hashes=num_hashes,
        )
    else:
        resolved_ntlm = _resolve_text_ntlm(source, ntlm=ntlm)
        target_items = (
            expected_items
            if expected_items is not None
            else sum(
                1 for _ in _iter_text_records(source, ntlm=resolved_ntlm, require_sorted=False)
            )
        )
        bit_count, num_hashes = _compute_bloom_params(target_items, false_positive_rate)
        bits = bytearray(bit_count // 8)
        item_count = _set_bloom_bits(
            bits,
            (
                digest
                for digest, _count in _iter_text_records(
                    source, ntlm=resolved_ntlm, require_sorted=False
                )
            ),
            bit_count=bit_count,
            num_hashes=num_hashes,
        )

    header = _BLOOM_HEADER_STRUCT.pack(
        BLOOM_MAGIC,
        BLOOM_VERSION,
        1 if resolved_ntlm else 0,
        num_hashes,
        bit_count,
        item_count,
        0,
    )
    with _atomic_open_binary(output) as handle:
        handle.write(header)
        handle.write(bits)

    bytes_written = _BLOOM_HEADER_STRUCT.size + len(bits)
    return BloomIndexStats(
        output_path=str(output),
        ntlm=resolved_ntlm,
        item_count=item_count,
        bit_count=bit_count,
        num_hashes=num_hashes,
        false_positive_rate=false_positive_rate,
        bytes_written=bytes_written,
        elapsed_seconds=max(0.0, time.monotonic() - started),
    )


class BloomFilterReader:
    """Memory-mapped reader for probabilistic HIBP Bloom filters."""

    def __init__(self, path: str | os.PathLike[str], *, ntlm: bool | None = None) -> None:
        self._path = Path(path)
        handle = self._path.open("rb")
        try:
            file_size = os.fstat(handle.fileno()).st_size
            header = handle.read(_BLOOM_HEADER_STRUCT.size)
            file_ntlm, item_count, bit_count, num_hashes = _parse_bloom_header(header, file_size)
            _check_reader_mode(file_ntlm, ntlm, kind="Bloom filter", path=self._path)
            mm = mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ)
        except BaseException:
            handle.close()
            raise
        self._file = handle
        self._mm = mm
        self._ntlm = file_ntlm
        self._item_count = item_count
        self._bit_count = bit_count
        self._num_hashes = num_hashes
        self._hex_len = _NTLM_HEX_LEN if file_ntlm else _SHA1_HEX_LEN

    @property
    def path(self) -> Path:
        """Path to the opened Bloom filter file."""
        return self._path

    @property
    def ntlm(self) -> bool:
        """Whether this Bloom filter stores NTLM hashes instead of SHA-1."""
        return self._ntlm

    @property
    def item_count(self) -> int:
        """Number of hash items recorded in the Bloom filter header."""
        return self._item_count

    @property
    def bit_count(self) -> int:
        """Total number of bits in the Bloom filter bitset."""
        return self._bit_count

    @property
    def num_hashes(self) -> int:
        """Number of hash probes per lookup (``k``)."""
        return self._num_hashes

    def close(self) -> None:
        """Close the memory map before closing the underlying file handle."""
        self._mm.close()
        self._file.close()

    def __enter__(self) -> BloomFilterReader:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def might_contain_hash(self, normalized_hash: str) -> bool:
        """Return True if all Bloom bit positions are set (False guarantees absence)."""
        normalized = normalized_hash.strip().upper()
        digest = _parse_hex_digest(normalized, self._hex_len)
        mm = self._mm
        header_size = _BLOOM_HEADER_STRUCT.size
        for pos in _bloom_positions(digest, bit_count=self._bit_count, num_hashes=self._num_hashes):
            if not (mm[header_size + (pos >> 3)] & (1 << (pos & 7))):
                return False
        return True

    def lookup_hash(self, normalized_hash: str) -> int:
        """Return 1 if the hash might be present in the filter, or 0 if definitely absent."""
        return 1 if self.might_contain_hash(normalized_hash) else 0
