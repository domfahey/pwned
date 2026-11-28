from __future__ import annotations

import json
import math
import struct
from pathlib import Path
from typing import Any

import pytest

from pwned.models import _HIBPBase
from pwned.offline_index import (
    BLOOM_MAGIC,
    COMPACT_MAGIC,
    PREFIX_COUNT,
    BloomFilterReader,
    BloomIndexStats,
    CompactIndexReader,
    CompactIndexStats,
    _bloom_positions,
    _compute_bloom_params,
    _read_directory_mode,
    build_bloom_filter,
    build_compact_index,
    detect_offline_format,
    read_binary_index_header,
)
from pwned.passwords import _hash_password


def _sha1(password: str) -> str:
    return _hash_password(password, ntlm=False)


def _ntlm(password: str) -> str:
    return _hash_password(password, ntlm=True)


def _write_text_dump(
    path: Path,
    entries: list[tuple[str, int]],
    *,
    sort: bool = True,
    newline: str = "\n",
    extra_lines: list[str] | None = None,
) -> Path:
    items = sorted(entries, key=lambda item: item[0].upper()) if sort else list(entries)
    lines = [f"{digest}:{count}" for digest, count in items]
    if extra_lines:
        lines.extend(extra_lines)
    body = newline.join(lines) + (newline if lines else "")
    path.write_text(body, encoding="utf-8")
    return path


def _write_range_dir(
    directory: Path,
    entries: list[tuple[str, int]],
    *,
    sort_buckets: bool = True,
    index_mode: str | None = None,
) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    grouped: dict[str, list[tuple[str, int]]] = {}
    for digest, count in entries:
        upper = digest.upper()
        grouped.setdefault(upper[:5], []).append((upper[5:], count))
    for prefix, items in grouped.items():
        if sort_buckets:
            items.sort(key=lambda item: item[0])
        body = "\n".join(f"{suffix}:{count}" for suffix, count in items) + "\n"
        (directory / f"{prefix}.txt").write_text(body, encoding="utf-8")
    if index_mode is not None:
        (directory / ".pwned-index.json").write_text(
            json.dumps({"mode": index_mode, "etags": {}}, separators=(",", ":")),
            encoding="utf-8",
        )
    return directory


class TestConstantsAndModels:
    def test_constants_and_stats_models(self) -> None:
        assert COMPACT_MAGIC == b"PWNB"
        assert BLOOM_MAGIC == b"PWNL"
        assert PREFIX_COUNT == 1_048_576

        compact_stats = CompactIndexStats(
            output_path="/tmp/out.pwned-bin",  # noqa: S108
            ntlm=False,
            record_count=10,
            bytes_written=16 + (PREFIX_COUNT + 1) * 8 + 240,
            elapsed_seconds=0.25,
        )
        assert isinstance(compact_stats, _HIBPBase)
        assert compact_stats.record_count == 10

        bloom_stats = BloomIndexStats(
            output_path="/tmp/out.pwned-bloom",  # noqa: S108
            ntlm=True,
            item_count=10,
            bit_count=128,
            num_hashes=7,
            false_positive_rate=0.01,
            bytes_written=48,
            elapsed_seconds=0.1,
        )
        assert isinstance(bloom_stats, _HIBPBase)
        assert bloom_stats.bit_count == 128


class TestDirectoryModeHelper:
    def test_read_directory_mode_variants(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        missing_dir = tmp_path / "no_index"
        missing_dir.mkdir()
        assert _read_directory_mode(missing_dir) is None

        head_dir = tmp_path / "head"
        head_dir.mkdir()
        (head_dir / ".pwned-index.json").write_text('{"mode":"sha1","etags":{}}', encoding="utf-8")
        assert _read_directory_mode(head_dir) == "sha1"

        small_tail_dir = tmp_path / "small_tail"
        small_tail_dir.mkdir()
        (small_tail_dir / ".pwned-index.json").write_text(
            '{"etags":{},"mode":"ntlm"}', encoding="utf-8"
        )
        assert _read_directory_mode(small_tail_dir) == "ntlm"

        big_etags = {f"{i:05X}": f'"etag-{i}"' for i in range(400)}
        large_tail_dir = tmp_path / "large_tail"
        large_tail_dir.mkdir()
        (large_tail_dir / ".pwned-index.json").write_text(
            json.dumps({"etags": big_etags, "mode": "ntlm"}, sort_keys=True, indent=2),
            encoding="utf-8",
        )
        assert _read_directory_mode(large_tail_dir) == "ntlm"

        non_obj_dir = tmp_path / "non_obj"
        non_obj_dir.mkdir()
        (non_obj_dir / ".pwned-index.json").write_text('["list"]', encoding="utf-8")
        assert _read_directory_mode(non_obj_dir) is None

        no_mode_dir = tmp_path / "no_mode"
        no_mode_dir.mkdir()
        (no_mode_dir / ".pwned-index.json").write_text('{"etags":{}}', encoding="utf-8")
        assert _read_directory_mode(no_mode_dir) is None

        unreadable_dir = tmp_path / "unreadable"
        unreadable_dir.mkdir()
        index_path = unreadable_dir / ".pwned-index.json"
        index_path.write_text('{"mode":"sha1"}', encoding="utf-8")
        real_open = Path.open

        def flaky_open(self: Path, *args: Any, **kwargs: Any) -> Any:
            if self == index_path:
                raise OSError("denied")
            return real_open(self, *args, **kwargs)

        monkeypatch.setattr(Path, "open", flaky_open)
        assert _read_directory_mode(unreadable_dir) is None


class TestFormatDetectionAndHeaders:
    def test_detect_offline_format_all_types(self, tmp_path: Path) -> None:
        dump_dir = _write_range_dir(tmp_path / "dir", [(_sha1("password"), 5)])
        text_dump = _write_text_dump(tmp_path / "dump.txt", [(_sha1("password"), 5)])
        empty_file = tmp_path / "empty.txt"
        empty_file.write_bytes(b"")
        short_file = tmp_path / "short.txt"
        short_file.write_bytes(b"PW")
        compact_path = tmp_path / "index.pwned-bin"
        bloom_path = tmp_path / "index.pwned-bloom"

        build_compact_index(text_dump, compact_path)
        build_bloom_filter(compact_path, bloom_path)

        assert detect_offline_format(dump_dir) == "directory"
        assert detect_offline_format(text_dump) == "text"
        assert detect_offline_format(empty_file) == "text"
        assert detect_offline_format(short_file) == "text"
        assert detect_offline_format(compact_path) == "compact"
        assert detect_offline_format(bloom_path) == "bloom"

        with pytest.raises(FileNotFoundError):
            detect_offline_format(tmp_path / "missing.bin")

    def test_read_binary_index_header_valid(self, tmp_path: Path) -> None:
        sha1_txt = _write_text_dump(
            tmp_path / "sha1.txt", [(_sha1("alpha"), 3), (_sha1("beta"), 9)]
        )
        ntlm_txt = _write_text_dump(tmp_path / "ntlm.txt", [(_ntlm("alpha"), 4)])

        compact_sha1 = tmp_path / "sha1.pwned-bin"
        compact_ntlm = tmp_path / "ntlm.pwned-bin"
        bloom_sha1 = tmp_path / "sha1.pwned-bloom"
        bloom_ntlm = tmp_path / "ntlm.pwned-bloom"

        build_compact_index(sha1_txt, compact_sha1)
        build_compact_index(ntlm_txt, compact_ntlm)
        b_sha1_stats = build_bloom_filter(compact_sha1, bloom_sha1)
        b_ntlm_stats = build_bloom_filter(compact_ntlm, bloom_ntlm)

        assert read_binary_index_header(compact_sha1) == ("compact", False, {"record_count": 2})
        assert read_binary_index_header(compact_ntlm) == ("compact", True, {"record_count": 1})
        assert read_binary_index_header(bloom_sha1) == (
            "bloom",
            False,
            {
                "item_count": 2,
                "bit_count": b_sha1_stats.bit_count,
                "num_hashes": b_sha1_stats.num_hashes,
            },
        )
        assert read_binary_index_header(bloom_ntlm) == (
            "bloom",
            True,
            {
                "item_count": 1,
                "bit_count": b_ntlm_stats.bit_count,
                "num_hashes": b_ntlm_stats.num_hashes,
            },
        )

    @pytest.mark.parametrize(
        "payload",
        [
            b"",
            b"NOPE1234567890123456",
            COMPACT_MAGIC + b"\x01\x00",  # truncated compact header
            struct.pack("<4sBBHQ", COMPACT_MAGIC, 2, 0, 0, 0),  # bad version
            struct.pack("<4sBBHQ", COMPACT_MAGIC, 1, 2, 0, 0),  # bad mode
            struct.pack("<4sBBHQ", COMPACT_MAGIC, 1, 0, 0, 0) + b"\x00" * 16,  # bad size
            BLOOM_MAGIC + b"\x01\x00\x01\x00",  # truncated bloom header
            struct.pack("<4sBBHQQQ", BLOOM_MAGIC, 2, 0, 7, 64, 1, 0) + b"\x00" * 8,  # bad version
            struct.pack("<4sBBHQQQ", BLOOM_MAGIC, 1, 5, 7, 64, 1, 0) + b"\x00" * 8,  # bad mode
            struct.pack("<4sBBHQQQ", BLOOM_MAGIC, 1, 0, 0, 64, 1, 0) + b"\x00" * 8,  # num_hashes=0
            struct.pack("<4sBBHQQQ", BLOOM_MAGIC, 1, 0, 7, 0, 1, 0),  # bit_count=0
            struct.pack("<4sBBHQQQ", BLOOM_MAGIC, 1, 0, 7, 12, 1, 0) + b"\x00",  # bit_count%8!=0
            struct.pack("<4sBBHQQQ", BLOOM_MAGIC, 1, 0, 7, 64, 1, 0) + b"\x00" * 4,  # bad size
        ],
    )
    def test_read_binary_index_header_corrupt_raises(self, tmp_path: Path, payload: bytes) -> None:
        bad = tmp_path / "corrupt.bin"
        bad.write_bytes(payload)
        with pytest.raises(ValueError):
            read_binary_index_header(bad)


class TestCompactIndex:
    def test_build_and_read_sha1_from_text_file(self, tmp_path: Path) -> None:
        h_pw = _sha1("password")
        prefix = h_pw[:5]
        h_low = f"{prefix}{'0' * 35}"
        h_high = f"{prefix}{'F' * 35}"
        h_min = "0" * 40
        h_max = "F" * 40
        h_clamped = _sha1("very-common-password")
        h_zero = _sha1("zero-count-padded")
        h_neg = _sha1("negative-count")

        entries = [
            (h_min, 1),
            (h_low, 11),
            (h_pw, 3_861_493),
            (h_high, 99),
            (h_clamped, 5_000_000_000),
            (h_zero, 0),
            (h_neg, -4),
            (h_max, 7),
        ]
        # Write with CRLF and blank lines interleaved
        sorted_entries = sorted(entries, key=lambda item: item[0])
        raw_lines = ["", *[f"{d}:{c}" for d, c in sorted_entries], "   ", ""]
        dump = tmp_path / "sha1.txt"
        dump.write_text("\r\n".join(raw_lines), encoding="utf-8")

        out = tmp_path / "nested" / "sha1.pwned-bin"
        stats = build_compact_index(dump, out)

        expected_records = 6  # zero & negative ignored
        assert stats.output_path == str(out)
        assert stats.ntlm is False
        assert stats.record_count == expected_records
        assert stats.bytes_written == 16 + (PREFIX_COUNT + 1) * 8 + expected_records * 24
        assert stats.elapsed_seconds >= 0.0
        assert out.stat().st_size == stats.bytes_written

        with CompactIndexReader(str(out)) as reader:
            assert reader.path == out
            assert reader.ntlm is False
            assert reader.record_count == expected_records

            assert reader.lookup_hash(h_min) == 1
            assert reader.lookup_hash(h_low) == 11
            assert reader.lookup_hash(h_pw) == 3_861_493
            assert reader.lookup_hash(f"  {h_pw.lower()}  ") == 3_861_493
            assert reader.lookup_hash(h_high) == 99
            assert reader.lookup_hash(h_clamped) == 0xFFFFFFFF
            assert reader.lookup_hash(h_max) == 7

            # Ignored zero/negative entries and misses
            assert reader.lookup_hash(h_zero) == 0
            assert reader.lookup_hash(h_neg) == 0
            assert reader.lookup_hash(f"{prefix}{'1' * 35}") == 0
            assert reader.lookup_hash(f"{prefix}{'E' * 35}") == 0
            assert reader.lookup_hash("12345" + "A" * 35) == 0

            # get_range on populated and empty prefixes
            prefix_range = reader.get_range(prefix.lower())
            assert prefix_range == {
                h_low[5:]: 11,
                h_pw[5:]: 3_861_493,
                h_high[5:]: 99,
            }
            assert reader.get_range("00000") == {"0" * 35: 1}
            assert reader.get_range("FFFFF") == {"F" * 35: 7}
            assert reader.get_range("12345") == {}

            with pytest.raises(ValueError, match="5 hexadecimal"):
                reader.get_range("1234")
            with pytest.raises(ValueError, match="5 hexadecimal"):
                reader.get_range("ZZZZZ")
            with pytest.raises(ValueError):
                reader.lookup_hash("0" * 32)  # wrong length for SHA-1
            with pytest.raises(ValueError):
                reader.lookup_hash("G" * 40)  # non-hex
            with pytest.raises(ValueError, match="Invalid hexadecimal"):
                reader.lookup_hash("00" * 9 + "  " + "00" * 10)  # embedded spaces

        # Idempotent close and post-close error
        reader.close()
        with pytest.raises(ValueError):
            reader.lookup_hash(h_pw)
        with pytest.raises(ValueError):
            reader.get_range(prefix)

    def test_build_and_read_ntlm_from_text_file(self, tmp_path: Path) -> None:
        h1 = _ntlm("Password123!")
        h2 = _ntlm("winter2026")
        dump = _write_text_dump(tmp_path / "ntlm.txt", [(h1, 250), (h2, 13)])

        out_auto = tmp_path / "ntlm_auto.pwned-bin"
        stats_auto = build_compact_index(dump, out_auto)
        assert stats_auto.ntlm is True
        assert stats_auto.record_count == 2
        assert stats_auto.bytes_written == 16 + (PREFIX_COUNT + 1) * 8 + 2 * 20

        out_explicit = tmp_path / "ntlm_explicit.pwned-bin"
        stats_explicit = build_compact_index(dump, out_explicit, ntlm=True)
        assert stats_explicit.ntlm is True
        assert stats_explicit.record_count == 2

        with CompactIndexReader(out_auto, ntlm=True) as reader:
            assert reader.ntlm is True
            assert reader.lookup_hash(h1) == 250
            assert reader.lookup_hash(h2.lower()) == 13
            assert reader.lookup_hash(_ntlm("absent")) == 0
            assert reader.get_range(h1[:5]) == {h1[5:]: 250}

    def test_build_from_directory_sha1_and_ntlm(self, tmp_path: Path) -> None:
        # Unsorted entries inside same prefix file + extra non-prefix file + subdir + padded 0
        h1 = _sha1("password")
        prefix = h1[:5]
        h_a = f"{prefix}{'A' * 35}"
        h_b = f"{prefix}{'2' * 35}"
        h_zero = f"{prefix}{'3' * 35}"

        sha1_dir = tmp_path / "sha1_dir"
        sha1_dir.mkdir()
        (sha1_dir / f"{prefix}.txt").write_text(
            f"\n{h_a[5:]}:10\n{h_zero[5:]}:0\n{h_b[5:]}:20\n{h_a[5:]}:15\n",
            encoding="utf-8",
        )
        (sha1_dir / "notes.txt").write_text("ignored\n", encoding="utf-8")
        (sha1_dir / "00000.txt").mkdir()  # subdirectory with prefix-like name -> ignored

        out_sha1 = tmp_path / "from_dir_sha1.pwned-bin"
        stats_sha1 = build_compact_index(sha1_dir, out_sha1)
        assert stats_sha1.ntlm is False
        assert stats_sha1.record_count == 2
        with CompactIndexReader(out_sha1) as reader:
            assert reader.lookup_hash(h_b) == 20
            assert reader.lookup_hash(h_a) == 15
            assert reader.lookup_hash(h_zero) == 0

        # NTLM directory without .pwned-index.json (auto-sniff 27-char suffix after blank line)
        ntlm_h = _ntlm("ntlm-dir-secret")
        ntlm_dir = tmp_path / "ntlm_dir_no_meta"
        ntlm_dir.mkdir()
        (ntlm_dir / f"{ntlm_h[:5]}.txt").write_text(f"\n  \n{ntlm_h[5:]}:88\n", encoding="utf-8")
        out_ntlm = tmp_path / "from_dir_ntlm.pwned-bin"
        stats_ntlm = build_compact_index(ntlm_dir, out_ntlm)
        assert stats_ntlm.ntlm is True
        assert stats_ntlm.record_count == 1
        with CompactIndexReader(out_ntlm, ntlm=True) as reader:
            assert reader.lookup_hash(ntlm_h) == 88

        # NTLM directory WITH .pwned-index.json (auto-detect via metadata + explicit match)
        ntlm_meta_dir = _write_range_dir(
            tmp_path / "ntlm_dir_meta", [(ntlm_h, 44)], index_mode="ntlm"
        )
        out_meta = tmp_path / "from_dir_meta.pwned-bin"
        assert build_compact_index(ntlm_meta_dir, out_meta).ntlm is True
        assert build_compact_index(ntlm_meta_dir, out_meta, ntlm=True, overwrite=True).ntlm is True

    def test_build_from_empty_sources(self, tmp_path: Path) -> None:
        empty_txt = tmp_path / "empty.txt"
        empty_txt.write_text("\n  \n", encoding="utf-8")
        out_txt = tmp_path / "empty_txt.pwned-bin"
        stats_txt = build_compact_index(empty_txt, out_txt)
        assert stats_txt.ntlm is False
        assert stats_txt.record_count == 0
        with CompactIndexReader(out_txt) as reader:
            assert reader.record_count == 0
            assert reader.lookup_hash(_sha1("password")) == 0
            assert reader.get_range("5BAA6") == {}

        empty_dir = tmp_path / "empty_dir"
        empty_dir.mkdir()
        (empty_dir / "00000.txt").write_text("\n", encoding="utf-8")
        out_dir = tmp_path / "empty_dir.pwned-bin"
        stats_dir = build_compact_index(empty_dir, out_dir)
        assert stats_dir.ntlm is False
        assert stats_dir.record_count == 0

    def test_large_multi_prefix_dataset(self, tmp_path: Path) -> None:
        # 200 hashes including a bucket with 15 entries sharing prefix "5BAA6"
        entries = [(_sha1(f"pw-{i:04d}"), i + 1) for i in range(185)]
        for j in range(15):
            entries.append((f"5BAA6{j:035X}", 1000 + j))
        dump = _write_text_dump(tmp_path / "many.txt", entries)
        out = tmp_path / "many.pwned-bin"

        stats = build_compact_index(dump, out)
        assert stats.record_count == 200

        with CompactIndexReader(out) as reader:
            for digest, count in entries:
                assert reader.lookup_hash(digest) == count
            assert reader.lookup_hash(_sha1("not-present")) == 0
            assert len(reader.get_range("5BAA6")) == 15

    def test_overwrite_and_error_handling(self, tmp_path: Path) -> None:
        dump = _write_text_dump(tmp_path / "sha1.txt", [(_sha1("one"), 1)])
        out = tmp_path / "out.pwned-bin"
        build_compact_index(dump, out)

        with pytest.raises(FileExistsError, match="overwrite=True"):
            build_compact_index(dump, out)

        dump2 = _write_text_dump(tmp_path / "sha1_v2.txt", [(_sha1("one"), 1), (_sha1("two"), 2)])
        stats2 = build_compact_index(dump2, out, overwrite=True)
        assert stats2.record_count == 2

        with pytest.raises(FileNotFoundError):
            build_compact_index(tmp_path / "missing.txt", tmp_path / "x.pwned-bin")

        out_dir = tmp_path / "existing_dir"
        out_dir.mkdir()
        with pytest.raises(IsADirectoryError):
            build_compact_index(dump, out_dir, overwrite=True)

        # Reject binary sources for build_compact_index
        with pytest.raises(ValueError, match="compact"):
            build_compact_index(out, tmp_path / "from_compact.pwned-bin")

        bloom_path = tmp_path / "filter.pwned-bloom"
        build_bloom_filter(out, bloom_path)
        with pytest.raises(ValueError, match="bloom"):
            build_compact_index(bloom_path, tmp_path / "from_bloom.pwned-bin")

    def test_unsorted_duplicate_and_malformed_sources_cleanup_temp(self, tmp_path: Path) -> None:
        out_dir = tmp_path / "outputs"
        out_dir.mkdir()

        # Unsorted text file
        unsorted = _write_text_dump(
            tmp_path / "unsorted.txt", [("B" * 40, 1), ("A" * 40, 2)], sort=False
        )
        with pytest.raises(ValueError, match="not sorted in ascending hash order"):
            build_compact_index(unsorted, out_dir / "unsorted.pwned-bin")
        assert list(out_dir.iterdir()) == []

        # Duplicate hash in text file
        dup = _write_text_dump(tmp_path / "dup.txt", [("A" * 40, 1), ("A" * 40, 2)], sort=False)
        with pytest.raises(ValueError, match="not sorted in ascending hash order"):
            build_compact_index(dup, out_dir / "dup.pwned-bin")
        assert list(out_dir.iterdir()) == []

        # Missing colon in text file (both auto-detect and explicit ntlm)
        no_colon = tmp_path / "no_colon.txt"
        no_colon.write_text("A" * 40 + "\n", encoding="utf-8")
        with pytest.raises(ValueError, match="Malformed"):
            build_compact_index(no_colon, out_dir / "x1.pwned-bin")
        with pytest.raises(ValueError, match="Malformed"):
            build_compact_index(no_colon, out_dir / "x2.pwned-bin", ntlm=False)

        # Unexpected hash length in text file when sniffing
        bad_len = tmp_path / "bad_len.txt"
        bad_len.write_text("ABCDEF:5\n", encoding="utf-8")
        with pytest.raises(ValueError, match="Unexpected hash length"):
            build_compact_index(bad_len, out_dir / "x3.pwned-bin")

        # Non-int count in text file
        bad_count = tmp_path / "bad_count.txt"
        bad_count.write_text(f"{'A' * 40}:notanint\n", encoding="utf-8")
        with pytest.raises(ValueError, match="Invalid breach count"):
            build_compact_index(bad_count, out_dir / "x4.pwned-bin")

        # Explicit ntlm mismatch on text file
        ntlm_txt = _write_text_dump(tmp_path / "ntlm_only.txt", [(_ntlm("pw"), 3)])
        with pytest.raises(ValueError, match="Expected 40-character"):
            build_compact_index(ntlm_txt, out_dir / "x5.pwned-bin", ntlm=False)

        # Directory metadata conflict
        dir_sha1 = _write_range_dir(tmp_path / "dir_sha1", [(_sha1("pw"), 1)], index_mode="sha1")
        with pytest.raises(ValueError, match="SHA1 hashes.*NTLM mode"):
            build_compact_index(dir_sha1, out_dir / "x6.pwned-bin", ntlm=True)

        # Directory sniffing errors (missing colon, bad suffix length)
        dir_nocolon = tmp_path / "dir_nocolon"
        dir_nocolon.mkdir()
        (dir_nocolon / "00000.txt").write_text("BADLINE\n", encoding="utf-8")
        with pytest.raises(ValueError, match="Malformed"):
            build_compact_index(dir_nocolon, out_dir / "x7.pwned-bin")
        with pytest.raises(ValueError, match="Malformed"):
            build_compact_index(dir_nocolon, out_dir / "x8.pwned-bin", ntlm=False)

        dir_badlen = tmp_path / "dir_badlen"
        dir_badlen.mkdir()
        (dir_badlen / "00000.txt").write_text("ABC:5\n", encoding="utf-8")
        with pytest.raises(ValueError, match="Unexpected hash suffix length"):
            build_compact_index(dir_badlen, out_dir / "x9.pwned-bin")

        dir_badcount = tmp_path / "dir_badcount"
        dir_badcount.mkdir()
        (dir_badcount / "00000.txt").write_text(f"{'A' * 35}:oops\n", encoding="utf-8")
        with pytest.raises(ValueError, match="Invalid breach count"):
            build_compact_index(dir_badcount, out_dir / "x10.pwned-bin")

        # Explicit ntlm mismatch on directory without metadata
        dir_ntlm_nometa = _write_range_dir(tmp_path / "dir_ntlm_nometa", [(_ntlm("pw"), 2)])
        with pytest.raises(ValueError, match="Expected 40-character"):
            build_compact_index(dir_ntlm_nometa, out_dir / "x11.pwned-bin", ntlm=False)

        assert list(out_dir.iterdir()) == []

    def test_compact_reader_validation_errors(self, tmp_path: Path) -> None:
        text_dump = _write_text_dump(tmp_path / "plain.txt", [(_sha1("pw"), 1)])
        with pytest.raises(ValueError, match="Invalid compact index magic"):
            CompactIndexReader(text_dump)

        compact_sha1 = tmp_path / "sha1.pwned-bin"
        build_compact_index(text_dump, compact_sha1)
        with pytest.raises(ValueError, match="SHA1 hashes.*NTLM mode"):
            CompactIndexReader(compact_sha1, ntlm=True)

        ntlm_dump = _write_text_dump(tmp_path / "ntlm.txt", [(_ntlm("pw"), 1)])
        compact_ntlm = tmp_path / "ntlm.pwned-bin"
        build_compact_index(ntlm_dump, compact_ntlm)
        with pytest.raises(ValueError, match="NTLM hashes.*SHA1 mode"):
            CompactIndexReader(compact_ntlm, ntlm=False)


class TestBloomFilter:
    def test_compute_bloom_params_and_positions(self) -> None:
        bits_empty, hashes_empty = _compute_bloom_params(0, 0.01)
        assert bits_empty == 64
        assert hashes_empty == 32

        bits_1k, hashes_1k = _compute_bloom_params(1000, 0.01)
        assert bits_1k % 8 == 0
        assert bits_1k >= 9584
        assert hashes_1k == 7

        bits_high_fpr, hashes_high_fpr = _compute_bloom_params(1000, 0.99)
        assert bits_high_fpr % 8 == 0
        assert hashes_high_fpr == 1

        digest = bytes.fromhex(_sha1("password"))
        positions = list(_bloom_positions(digest, bit_count=bits_1k, num_hashes=hashes_1k))
        assert len(positions) == hashes_1k
        assert all(0 <= p < bits_1k for p in positions)

        for bad_fpr in (0.0, -0.5, 1.0, 1.5, math.nan, math.inf):
            with pytest.raises(ValueError, match="false_positive_rate"):
                _compute_bloom_params(100, bad_fpr)

        with pytest.raises(ValueError, match="expected_items"):
            _compute_bloom_params(-1, 0.01)

    def test_build_bloom_from_compact_directory_and_text_sha1(self, tmp_path: Path) -> None:
        inserted = [_sha1(f"breached-{i}") for i in range(400)]
        entries = [(h, i + 1) for i, h in enumerate(inserted)]

        text_dump = _write_text_dump(tmp_path / "sha1.txt", entries)
        range_dir = _write_range_dir(tmp_path / "sha1_dir", entries, index_mode="sha1")
        compact_path = tmp_path / "sha1.pwned-bin"
        build_compact_index(text_dump, compact_path)

        out_compact = tmp_path / "from_compact.pwned-bloom"
        out_dir = tmp_path / "from_dir.pwned-bloom"
        out_text = tmp_path / "from_text.pwned-bloom"
        out_hint = tmp_path / "from_text_hint.pwned-bloom"

        s_compact = build_bloom_filter(compact_path, out_compact, false_positive_rate=0.01)
        s_dir = build_bloom_filter(range_dir, out_dir, false_positive_rate=0.01)
        s_text = build_bloom_filter(text_dump, out_text, false_positive_rate=0.01)
        s_hint = build_bloom_filter(
            text_dump, out_hint, false_positive_rate=0.01, expected_items=800
        )

        # Identical inputs -> identical bit arrays across all 3 source types
        assert out_compact.read_bytes() == out_dir.read_bytes() == out_text.read_bytes()
        assert s_compact.item_count == 400
        assert s_compact.ntlm is False
        assert s_compact.bytes_written == 32 + s_compact.bit_count // 8
        assert s_compact.elapsed_seconds >= 0.0
        assert s_dir.item_count == 400
        assert s_text.item_count == 400
        assert s_hint.item_count == 400
        assert s_hint.bit_count > s_text.bit_count

        unseen = [_sha1(f"unseen-{i}") for i in range(2000)]
        with BloomFilterReader(str(out_compact)) as reader:
            assert reader.path == out_compact
            assert reader.ntlm is False
            assert reader.item_count == 400
            assert reader.bit_count == s_compact.bit_count
            assert reader.num_hashes == s_compact.num_hashes

            # Zero false negatives
            for h in inserted:
                assert reader.might_contain_hash(h) is True
                assert reader.lookup_hash(h) == 1
            assert reader.might_contain_hash(f"  {inserted[0].lower()}  ") is True

            # Empirical false-positive rate stays bounded near 1% (allow generous 4% cap)
            false_positives = sum(1 for h in unseen if reader.might_contain_hash(h))
            assert false_positives < 80
            # Verify definite negative returns 0 via lookup_hash
            absent_hash = next(h for h in unseen if not reader.might_contain_hash(h))
            assert reader.lookup_hash(absent_hash) == 0

            with pytest.raises(ValueError):
                reader.might_contain_hash("0" * 32)
            with pytest.raises(ValueError):
                reader.might_contain_hash("Z" * 40)

        reader.close()
        with pytest.raises(ValueError):
            reader.might_contain_hash(inserted[0])

    def test_build_bloom_ntlm_and_unsorted_text_and_empty_sources(self, tmp_path: Path) -> None:
        # Unsorted NTLM text file with blank & zero-count lines
        h1 = _ntlm("Alpha1!")
        h2 = _ntlm("Beta2!")
        unsorted_ntlm = _write_text_dump(
            tmp_path / "unsorted_ntlm.txt",
            [(h2, 10), (h1, 5), (_ntlm("ignored"), 0)],
            sort=False,
        )
        out_ntlm = tmp_path / "ntlm.pwned-bloom"
        stats = build_bloom_filter(unsorted_ntlm, out_ntlm, false_positive_rate=0.001)
        assert stats.ntlm is True
        assert stats.item_count == 2

        with BloomFilterReader(out_ntlm, ntlm=True) as reader:
            assert reader.ntlm is True
            assert reader.lookup_hash(h1) == 1
            assert reader.lookup_hash(h2.lower()) == 1

        # From compact NTLM with explicit expected_items
        compact_ntlm = tmp_path / "ntlm.pwned-bin"
        sorted_ntlm = _write_text_dump(tmp_path / "sorted_ntlm.txt", [(h1, 5), (h2, 10)])
        build_compact_index(sorted_ntlm, compact_ntlm)
        out_ntlm_hint = tmp_path / "ntlm_hint.pwned-bloom"
        stats_hint = build_bloom_filter(compact_ntlm, out_ntlm_hint, expected_items=50, ntlm=True)
        assert stats_hint.ntlm is True
        assert stats_hint.item_count == 2

        # From directory with explicit expected_items
        dir_ntlm = _write_range_dir(tmp_path / "dir_ntlm", [(h1, 5), (h2, 10)], index_mode="ntlm")
        out_dir_hint = tmp_path / "dir_ntlm_hint.pwned-bloom"
        stats_dir_hint = build_bloom_filter(dir_ntlm, out_dir_hint, expected_items=50)
        assert stats_dir_hint.ntlm is True
        assert stats_dir_hint.item_count == 2

        # Empty text file -> 0 items, valid 40-byte bloom filter
        empty_txt = tmp_path / "empty.txt"
        empty_txt.write_text("", encoding="utf-8")
        empty_bloom = tmp_path / "empty.pwned-bloom"
        empty_stats = build_bloom_filter(empty_txt, empty_bloom)
        assert empty_stats.item_count == 0
        assert empty_stats.bit_count == 64
        assert empty_stats.bytes_written == 40
        with BloomFilterReader(empty_bloom) as reader:
            assert reader.item_count == 0
            assert reader.might_contain_hash(_sha1("password")) is False
            assert reader.lookup_hash(_sha1("password")) == 0

    def test_build_bloom_validation_overwrite_and_reader_errors(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        dump = _write_text_dump(tmp_path / "sha1.txt", [(_sha1("pw"), 1)])
        out = tmp_path / "out.pwned-bloom"
        build_bloom_filter(dump, out)

        with pytest.raises(FileExistsError, match="overwrite=True"):
            build_bloom_filter(dump, out)
        assert build_bloom_filter(dump, out, overwrite=True).item_count == 1

        with pytest.raises(FileNotFoundError):
            build_bloom_filter(tmp_path / "missing.txt", tmp_path / "x.pwned-bloom")

        out_dir = tmp_path / "dir_target"
        out_dir.mkdir()
        with pytest.raises(IsADirectoryError):
            build_bloom_filter(dump, out_dir, overwrite=True)

        with pytest.raises(ValueError, match="false_positive_rate"):
            build_bloom_filter(dump, tmp_path / "b1.pwned-bloom", false_positive_rate=0.0)
        with pytest.raises(ValueError, match="expected_items"):
            build_bloom_filter(dump, tmp_path / "b2.pwned-bloom", expected_items=0)
        with pytest.raises(ValueError, match="Bloom filter"):
            build_bloom_filter(out, tmp_path / "b3.pwned-bloom")

        # Reader errors
        with pytest.raises(ValueError, match="Invalid Bloom filter magic"):
            BloomFilterReader(dump)
        with pytest.raises(ValueError, match="SHA1 hashes.*NTLM mode"):
            BloomFilterReader(out, ntlm=True)

        # Atomic temp cleanup if os.replace fails
        clean_dir = tmp_path / "clean"
        clean_dir.mkdir()

        def boom_replace(src: Any, dst: Any) -> None:
            raise OSError("disk full")

        monkeypatch.setattr("pwned.offline_index.os.replace", boom_replace)
        with pytest.raises(OSError, match="disk full"):
            build_bloom_filter(dump, clean_dir / "fail.pwned-bloom")
        assert list(clean_dir.iterdir()) == []
