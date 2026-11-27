from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from pwned._parsers import _md4
from pwned.models import PasswordChecker
from pwned.offline import OfflinePasswordsClient


def _sha1_hex(password: str) -> str:
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()


def _ntlm_hex(password: str) -> str:
    return _md4(password.encode("utf-16-le")).upper()


def _write_dump(
    path: Path,
    entries: list[tuple[str, int]],
    *,
    newline: str = "\n",
    trailing_newline: bool = True,
) -> Path:
    sorted_entries = sorted(entries, key=lambda item: item[0])
    body = newline.join(f"{digest}:{count}" for digest, count in sorted_entries)
    if trailing_newline and body:
        body += newline
    path.write_bytes(body.encode("ascii"))
    return path


def _write_range_dir(
    directory: Path,
    entries: list[tuple[str, int]],
    *,
    newline: str = "\n",
) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    grouped: dict[str, list[tuple[str, int]]] = {}
    for digest, count in entries:
        prefix = digest[:5].upper()
        suffix = digest[5:].upper()
        grouped.setdefault(prefix, []).append((suffix, count))
    for prefix, items in grouped.items():
        items.sort(key=lambda item: item[0])
        body = newline.join(f"{suffix}:{count}" for suffix, count in items) + newline
        (directory / f"{prefix}.txt").write_text(body, encoding="utf-8")
    return directory


class TestLifecycleAndErrors:
    def test_context_manager_and_close(self, tmp_path: Path) -> None:
        h = _sha1_hex("password")
        dump = _write_dump(tmp_path / "sha1.txt", [(h, 42)])

        with OfflinePasswordsClient(dump) as client:
            assert client.ntlm is False
            assert client.is_directory is False
            assert client.path == dump
            assert client.check_password("password") == 42

        with pytest.raises(ValueError):
            client.check_password("password")

    def test_explicit_close_and_str_path(self, tmp_path: Path) -> None:
        h = _sha1_hex("secret")
        dump = _write_dump(tmp_path / "sha1.txt", [(h, 7)])

        client = OfflinePasswordsClient(str(dump))
        assert client.is_directory is False
        assert client.check_hash(h) == 7
        client.close()
        client.close()  # idempotent

        with pytest.raises(ValueError):
            client.check_hash(h)

    def test_missing_file_raises_file_not_found(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            OfflinePasswordsClient(tmp_path / "missing.txt")


class TestDirectoryMode:
    def test_context_manager_and_close_on_directory(self, tmp_path: Path) -> None:
        h = _sha1_hex("password")
        dump_dir = _write_range_dir(tmp_path / "ranges", [(h, 42)])

        with OfflinePasswordsClient(dump_dir) as client:
            assert client.is_directory is True
            assert client.ntlm is False
            assert client.path == dump_dir
            assert client.check_password("password") == 42

        client_str = OfflinePasswordsClient(str(dump_dir))
        assert client_str.is_directory is True
        assert client_str.check_hash(h) == 42
        client_str.close()
        client_str.close()  # idempotent no-op

    def test_sha1_directory_lookups(self, tmp_path: Path) -> None:
        pw_hit = "password"
        pw_miss_same_prefix = "miss-same-prefix"
        pw_miss_other_prefix = "correct-horse-battery-staple"
        h_hit = _sha1_hex(pw_hit)
        h_same_prefix_miss = f"{h_hit[:5]}{'0' * 35}"
        if h_same_prefix_miss == h_hit:
            h_same_prefix_miss = f"{h_hit[:5]}{'1' * 35}"
        h_other_prefix_miss = _sha1_hex(pw_miss_other_prefix)

        dump_dir = _write_range_dir(
            tmp_path / "sha1_dir",
            [
                (h_hit, 3861493),
                (f"{h_hit[:5]}{'F' * 35}", 12),
                (_sha1_hex("second-hit"), 77),
            ],
            newline="\r\n",
        )

        with OfflinePasswordsClient(dump_dir) as client:
            checker: PasswordChecker = client
            assert client.is_directory is True
            assert checker.check_password(pw_hit) == 3861493
            assert checker.check_hash(h_hit) == 3861493
            assert client.check_password("second-hit") == 77
            assert client.check_password(pw_miss_same_prefix) == 0
            assert client.check_password(pw_miss_other_prefix) == 0
            assert client.check_hash(h_hit.lower()) == 3861493
            assert client.check_hash(f"  {h_hit.lower()}  ") == 3861493
            assert client.check_hash(h_same_prefix_miss) == 0
            assert client.check_hash(h_other_prefix_miss) == 0

            assert client.is_pwned(pw_hit) is True
            assert client.is_pwned(pw_hit, threshold=3861493) is True
            assert client.is_pwned(pw_hit, threshold=3861494) is False
            assert client.is_pwned(pw_miss_other_prefix) is False

            assert client.is_hash_pwned(h_hit) is True
            assert client.is_hash_pwned(h_hit, threshold=3861493) is True
            assert client.is_hash_pwned(h_hit, threshold=3861494) is False
            assert client.is_hash_pwned(h_same_prefix_miss) is False
            assert client.is_hash_pwned(h_other_prefix_miss) is False

            with pytest.raises(ValueError, match="ntlm"):
                client.check_password(pw_hit, ntlm=True)

    def test_ntlm_directory_lookups(self, tmp_path: Path) -> None:
        pw_hit = "Password123!"
        pw_miss = "not-in-ntlm-dir"
        h_hit = _ntlm_hex(pw_hit)
        h_same_prefix_miss = f"{h_hit[:5]}{'A' * 27}"
        if h_same_prefix_miss == h_hit:
            h_same_prefix_miss = f"{h_hit[:5]}{'B' * 27}"
        h_miss = _ntlm_hex(pw_miss)

        dump_dir = _write_range_dir(
            tmp_path / "ntlm_dir",
            [
                (h_hit, 150),
                (_ntlm_hex("other-ntlm"), 9),
            ],
        )

        with OfflinePasswordsClient(dump_dir, ntlm=True) as client:
            assert client.is_directory is True
            assert client.ntlm is True
            assert client.check_password(pw_hit) == 150
            assert client.check_password("other-ntlm") == 9
            assert client.check_password(pw_miss) == 0
            assert client.check_hash(h_hit.lower()) == 150
            assert client.check_hash(h_same_prefix_miss) == 0
            assert client.check_hash(h_miss) == 0

            assert client.is_pwned(pw_hit) is True
            assert client.is_pwned(pw_hit, threshold=150) is True
            assert client.is_pwned(pw_hit, threshold=151) is False
            assert client.is_pwned(pw_miss) is False

            assert client.is_hash_pwned(h_hit) is True
            assert client.is_hash_pwned(h_hit, threshold=150) is True
            assert client.is_hash_pwned(h_hit, threshold=151) is False
            assert client.is_hash_pwned(h_same_prefix_miss) is False
            assert client.is_hash_pwned(h_miss) is False

            with pytest.raises(ValueError, match="ntlm"):
                client.check_password(pw_hit, ntlm=False)

    def test_empty_directory_and_missing_prefix_file_returns_zero(self, tmp_path: Path) -> None:
        empty_dir = tmp_path / "empty_ranges"
        empty_dir.mkdir()

        with OfflinePasswordsClient(empty_dir) as client:
            assert client.is_directory is True
            assert client.check_password("password") == 0
            assert client.check_hash(_sha1_hex("password")) == 0
            assert client.is_pwned("password") is False
            assert client.is_hash_pwned(_sha1_hex("password")) is False

    def test_prefix_path_that_is_subdirectory_returns_zero(self, tmp_path: Path) -> None:
        h = _sha1_hex("password")
        dump_dir = tmp_path / "subdir_prefix"
        (dump_dir / f"{h[:5]}.txt").mkdir(parents=True)

        with OfflinePasswordsClient(dump_dir) as client:
            assert client.check_hash(h) == 0

    def test_padded_zero_count_entries_ignored(self, tmp_path: Path) -> None:
        h_padded = _sha1_hex("padded-only")
        h_real = f"{h_padded[:5]}{'B' * 35}"
        dump_dir = _write_range_dir(
            tmp_path / "padded_dir",
            [
                (h_padded, 0),
                (h_real, 5),
            ],
        )

        with OfflinePasswordsClient(dump_dir) as client:
            assert client.check_password("padded-only") == 0
            assert client.check_hash(h_padded) == 0
            assert client.is_pwned("padded-only") is False
            assert client.is_hash_pwned(h_padded) is False
            assert client.check_hash(h_real) == 5

    def test_case_insensitive_suffixes_and_malformed_lines(self, tmp_path: Path) -> None:
        h = _sha1_hex("mixed-case-entry")
        dump_dir = tmp_path / "mixed_case_dir"
        dump_dir.mkdir()
        prefix_file = dump_dir / f"{h[:5]}.txt"
        prefix_file.write_text(
            f"not-a-valid-line\n:12\n{h[5:].lower()}:99\n{'A' * 35}:notanint\n",
            encoding="utf-8",
        )

        with OfflinePasswordsClient(dump_dir) as client:
            assert client.check_password("mixed-case-entry") == 99
            assert client.check_hash(h) == 99
            assert client.check_hash(f"{h[:5]}{'A' * 35}") == 0

    def test_directory_mode_mismatch_raises_value_error(self, tmp_path: Path) -> None:
        sha1_dir = _write_range_dir(tmp_path / "sha1_indexed", [(_sha1_hex("password"), 10)])
        (sha1_dir / ".pwned-index.json").write_text('{"mode":"sha1","etags":{}}', encoding="utf-8")
        with OfflinePasswordsClient(sha1_dir, ntlm=False) as client:
            assert client.check_password("password") == 10
        with pytest.raises(ValueError, match="SHA1 hashes.*NTLM mode"):
            OfflinePasswordsClient(sha1_dir, ntlm=True)

        ntlm_dir = _write_range_dir(tmp_path / "ntlm_indexed", [(_ntlm_hex("password"), 20)])
        (ntlm_dir / ".pwned-index.json").write_text('{"mode":"ntlm","etags":{}}', encoding="utf-8")
        with OfflinePasswordsClient(ntlm_dir, ntlm=True) as client:
            assert client.check_password("password") == 20
        with pytest.raises(ValueError, match="NTLM hashes.*SHA1 mode"):
            OfflinePasswordsClient(ntlm_dir, ntlm=False)

    def test_directory_mode_check_reads_bounded_bytes_for_large_index(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Large index (> 8 KiB) with "mode" at the head (compact format).
        head_dir = _write_range_dir(tmp_path / "large_head", [(_ntlm_hex("password"), 7)])
        big_etags = {f"{i:05X}": f'"etag-{i}"' for i in range(400)}
        head_index = head_dir / ".pwned-index.json"
        head_index.write_text(
            json.dumps({"mode": "ntlm", "etags": big_etags}, separators=(",", ":")),
            encoding="utf-8",
        )
        assert head_index.stat().st_size > 4096

        # Large index (> 8 KiB) with "mode" at the tail (sort_keys=True format).
        tail_dir = _write_range_dir(tmp_path / "large_tail", [(_ntlm_hex("password"), 7)])
        tail_index = tail_dir / ".pwned-index.json"
        tail_index.write_text(
            json.dumps({"etags": big_etags, "mode": "ntlm"}, sort_keys=True, indent=2),
            encoding="utf-8",
        )
        assert tail_index.stat().st_size > 4096

        # Small index with "mode" at the tail (fits within single sniff read).
        small_tail_dir = _write_range_dir(tmp_path / "small_tail", [(_ntlm_hex("password"), 7)])
        (small_tail_dir / ".pwned-index.json").write_text(
            '{"etags": {}, "mode": "ntlm"}',
            encoding="utf-8",
        )

        # Ensure Path.read_text is never used on the large index files.
        real_read_text = Path.read_text

        def forbid_index_read_text(self: Path, *args: object, **kwargs: object) -> str:
            if self.name == ".pwned-index.json":
                raise AssertionError("full index read_text should never be called")
            return real_read_text(self, *args, **kwargs)  # type: ignore[arg-type]

        monkeypatch.setattr(Path, "read_text", forbid_index_read_text)

        for d in (head_dir, tail_dir, small_tail_dir):
            with OfflinePasswordsClient(d, ntlm=True) as client:
                assert client.check_password("password") == 7
            with pytest.raises(ValueError, match="NTLM hashes.*SHA1 mode"):
                OfflinePasswordsClient(d, ntlm=False)

    @pytest.mark.parametrize(
        "index_content",
        [
            '{"00000": "etag"}',
            '{"mode": "md5", "etags": {}}',
            '["not", "a", "dict"]',
            "{not valid json",
        ],
    )
    def test_directory_ignores_legacy_or_invalid_index_metadata(
        self, tmp_path: Path, index_content: str
    ) -> None:
        dump_dir = _write_range_dir(tmp_path / "legacy_dir", [(_sha1_hex("password"), 5)])
        (dump_dir / ".pwned-index.json").write_text(index_content, encoding="utf-8")
        with OfflinePasswordsClient(dump_dir) as client:
            assert client.check_password("password") == 5

    def test_directory_ignores_unreadable_index_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        dump_dir = _write_range_dir(tmp_path / "unreadable_dir", [(_sha1_hex("password"), 5)])
        index_path = dump_dir / ".pwned-index.json"
        index_path.write_text('{"mode": "ntlm"}', encoding="utf-8")
        real_open = Path.open

        def flaky_open(self: Path, *args: Any, **kwargs: Any) -> Any:
            if self == index_path:
                raise OSError("permission denied")
            return real_open(self, *args, **kwargs)

        monkeypatch.setattr(Path, "open", flaky_open)
        with OfflinePasswordsClient(dump_dir) as client:
            assert client.check_password("password") == 5


class TestEmptyAndSingleLineFiles:
    def test_empty_file_returns_zero(self, tmp_path: Path) -> None:
        dump = tmp_path / "empty.txt"
        dump.write_bytes(b"")

        with OfflinePasswordsClient(dump) as client:
            assert client.check_password("password") == 0
            assert client.check_hash(_sha1_hex("password")) == 0
            assert client.is_pwned("password") is False
            assert client.is_hash_pwned(_sha1_hex("password")) is False

    def test_single_line_hit_and_misses(self, tmp_path: Path) -> None:
        mid_hash = "5" * 40
        dump = _write_dump(tmp_path / "single.txt", [(mid_hash, 123)], trailing_newline=False)

        with OfflinePasswordsClient(dump) as client:
            assert client.check_hash(mid_hash) == 123
            assert client.check_hash("4" * 40) == 0
            assert client.check_hash("6" * 40) == 0


class TestBoundaryAndLineEndings:
    @pytest.mark.parametrize(
        ("newline", "trailing_newline"),
        [
            ("\n", True),
            ("\n", False),
            ("\r\n", True),
            ("\r\n", False),
        ],
    )
    def test_hits_and_misses_across_line_endings(
        self,
        tmp_path: Path,
        newline: str,
        trailing_newline: bool,
    ) -> None:
        entries = [
            ("1" * 40, 10),
            ("3" * 40, 200),
            ("5" * 40, 3000),
            ("7" * 40, 40000),
            ("9" * 40, 5),
        ]
        dump = _write_dump(
            tmp_path / "bounds.txt",
            entries,
            newline=newline,
            trailing_newline=trailing_newline,
        )

        with OfflinePasswordsClient(dump) as client:
            # First, middle, last line hits
            assert client.check_hash("1" * 40) == 10
            assert client.check_hash("5" * 40) == 3000
            assert client.check_hash("9" * 40) == 5
            # Remaining hits
            assert client.check_hash("3" * 40) == 200
            assert client.check_hash("7" * 40) == 40000
            # Miss before first, misses between lines, miss after last
            assert client.check_hash("0" * 40) == 0
            assert client.check_hash("2" * 40) == 0
            assert client.check_hash("4" * 40) == 0
            assert client.check_hash("6" * 40) == 0
            assert client.check_hash("8" * 40) == 0
            assert client.check_hash("A" * 40) == 0


class TestSha1Mode:
    def test_sha1_methods(self, tmp_path: Path) -> None:
        pw_hit = "password"
        pw_miss = "correct-horse-battery-staple"
        h_hit = _sha1_hex(pw_hit)
        h_miss = _sha1_hex(pw_miss)
        dump = _write_dump(
            tmp_path / "sha1.txt",
            [
                ("0" * 40, 1),
                (h_hit, 3861493),
                ("F" * 40, 99),
            ],
        )

        with OfflinePasswordsClient(dump) as client:
            assert client.check_password(pw_hit) == 3861493
            assert client.check_password(pw_miss) == 0
            assert client.check_hash(h_hit.lower()) == 3861493
            assert client.check_hash(f"  {h_hit.lower()}  ") == 3861493
            assert client.check_hash(h_miss) == 0

            assert client.is_pwned(pw_hit) is True
            assert client.is_pwned(pw_hit, threshold=3861493) is True
            assert client.is_pwned(pw_hit, threshold=3861494) is False
            assert client.is_pwned(pw_miss) is False

            assert client.is_hash_pwned(h_hit) is True
            assert client.is_hash_pwned(h_hit, threshold=3861493) is True
            assert client.is_hash_pwned(h_hit, threshold=3861494) is False
            assert client.is_hash_pwned(h_miss) is False


class TestNtlmMode:
    def test_ntlm_methods(self, tmp_path: Path) -> None:
        pw_hit = "Password123!"
        pw_miss = "not-in-ntlm-dump"
        h_hit = _ntlm_hex(pw_hit)
        h_miss = _ntlm_hex(pw_miss)
        dump = _write_dump(
            tmp_path / "ntlm.txt",
            [
                ("0" * 32, 2),
                (h_hit, 150),
                ("F" * 32, 8),
            ],
        )

        with OfflinePasswordsClient(dump, ntlm=True) as client:
            assert client.ntlm is True
            assert client.check_password(pw_hit) == 150
            assert client.check_password(pw_miss) == 0
            assert client.check_hash(h_hit.lower()) == 150
            assert client.check_hash(h_miss) == 0

            assert client.is_pwned(pw_hit) is True
            assert client.is_pwned(pw_hit, threshold=150) is True
            assert client.is_pwned(pw_hit, threshold=151) is False
            assert client.is_pwned(pw_miss) is False

            assert client.is_hash_pwned(h_hit) is True
            assert client.is_hash_pwned(h_hit, threshold=150) is True
            assert client.is_hash_pwned(h_hit, threshold=151) is False
            assert client.is_hash_pwned(h_miss) is False


class TestProtocolAndKwargsCompatibility:
    def test_sha1_ntlm_kwarg_and_protocol(self, tmp_path: Path) -> None:
        h = _sha1_hex("alpha")
        dump = _write_dump(tmp_path / "sha1.txt", [(h, 12)])

        with OfflinePasswordsClient(dump, ntlm=False) as client:
            checker: PasswordChecker = client
            assert checker.check_password("alpha") == 12
            assert checker.check_hash(h) == 12
            assert client.check_password("alpha", ntlm=None, pad=True) == 12
            assert client.check_password("alpha", ntlm=False, pad=True) == 12
            assert client.check_hash(h, ntlm=False, pad=True) == 12
            assert client.is_pwned("alpha", ntlm=False, pad=True) is True
            assert client.is_hash_pwned(h, ntlm=False, pad=True) is True

            with pytest.raises(ValueError, match="ntlm"):
                client.check_password("alpha", ntlm=True)
            with pytest.raises(ValueError, match="ntlm"):
                client.check_hash(h, ntlm=True)
            with pytest.raises(ValueError, match="ntlm"):
                client.is_pwned("alpha", ntlm=True)
            with pytest.raises(ValueError, match="ntlm"):
                client.is_hash_pwned(h, ntlm=True)

    def test_ntlm_kwarg_and_protocol(self, tmp_path: Path) -> None:
        h = _ntlm_hex("alpha")
        dump = _write_dump(tmp_path / "ntlm.txt", [(h, 19)])

        with OfflinePasswordsClient(dump, ntlm=True) as client:
            checker: PasswordChecker = client
            assert checker.check_password("alpha") == 19
            assert checker.check_hash(h) == 19
            assert client.check_password("alpha", ntlm=None, pad=True) == 19
            assert client.check_password("alpha", ntlm=True, pad=True) == 19
            assert client.check_hash(h, ntlm=True, pad=True) == 19
            assert client.is_pwned("alpha", ntlm=True, pad=True) is True
            assert client.is_hash_pwned(h, ntlm=True, pad=True) is True

            with pytest.raises(ValueError, match="ntlm"):
                client.check_password("alpha", ntlm=False)
            with pytest.raises(ValueError, match="ntlm"):
                client.check_hash(h, ntlm=False)
            with pytest.raises(ValueError, match="ntlm"):
                client.is_pwned("alpha", ntlm=False)
            with pytest.raises(ValueError, match="ntlm"):
                client.is_hash_pwned(h, ntlm=False)


class TestValidation:
    @pytest.mark.parametrize(
        "bad_hash",
        [
            "",
            "ABC",
            "0" * 32,  # NTLM length passed to SHA-1 client
            "0" * 39,
            "0" * 41,
            "G" * 40,
            ("0" * 39) + "!",
        ],
    )
    def test_invalid_sha1_hash_raises(self, tmp_path: Path, bad_hash: str) -> None:
        dump = _write_dump(tmp_path / "sha1.txt", [("0" * 40, 1)])
        with OfflinePasswordsClient(dump) as client:
            with pytest.raises(ValueError):
                client.check_hash(bad_hash)
            with pytest.raises(ValueError):
                client.is_hash_pwned(bad_hash)

    @pytest.mark.parametrize(
        "bad_hash",
        [
            "",
            "0" * 31,
            "0" * 33,
            "0" * 40,  # SHA-1 length passed to NTLM client
            "Z" * 32,
        ],
    )
    def test_invalid_ntlm_hash_raises(self, tmp_path: Path, bad_hash: str) -> None:
        dump = _write_dump(tmp_path / "ntlm.txt", [("0" * 32, 1)])
        with OfflinePasswordsClient(dump, ntlm=True) as client:
            with pytest.raises(ValueError):
                client.check_hash(bad_hash)
            with pytest.raises(ValueError):
                client.is_hash_pwned(bad_hash)

    @pytest.mark.parametrize("bad_threshold", [0, -1, -100])
    def test_invalid_threshold_raises(self, tmp_path: Path, bad_threshold: int) -> None:
        h = "0" * 40
        dump = _write_dump(tmp_path / "sha1.txt", [(h, 1)])
        with OfflinePasswordsClient(dump) as client:
            with pytest.raises(ValueError, match="threshold"):
                client.is_pwned("anything", threshold=bad_threshold)
            with pytest.raises(ValueError, match="threshold"):
                client.is_hash_pwned(h, threshold=bad_threshold)


class TestMalformedLines:
    def test_missing_colon_returns_zero(self, tmp_path: Path) -> None:
        h = "A" * 40
        dump = tmp_path / "malformed.txt"
        dump.write_bytes(f"{h}\n".encode("ascii"))

        with OfflinePasswordsClient(dump) as client:
            assert client.check_hash(h) == 0

    def test_non_int_count_returns_zero(self, tmp_path: Path) -> None:
        h = "B" * 40
        dump = tmp_path / "malformed.txt"
        dump.write_bytes(f"{h}:notanumber\n".encode("ascii"))

        with OfflinePasswordsClient(dump) as client:
            assert client.check_hash(h) == 0

    @pytest.mark.parametrize("count_str", ["0", "-1", "-999"])
    def test_non_positive_count_returns_zero(self, tmp_path: Path, count_str: str) -> None:
        h = "C" * 40
        dump = tmp_path / "malformed.txt"
        dump.write_bytes(f"{h}:{count_str}\n".encode("ascii"))

        with OfflinePasswordsClient(dump) as client:
            assert client.check_hash(h) == 0

    def test_long_malformed_line_exceeding_chunk_size(self, tmp_path: Path) -> None:
        h = "D" * 40
        dump = tmp_path / "long.txt"
        dump.write_bytes((f"{h}:" + ("x" * 600) + "\n").encode("ascii"))

        with OfflinePasswordsClient(dump) as client:
            assert client.check_hash(h) == 0


class TestLargeSortedFixture:
    def test_500_sorted_sha1_entries(self, tmp_path: Path) -> None:
        entries = [(_sha1_hex(f"pw-{i:04d}"), (i + 1) * (10 ** (i % 6))) for i in range(500)]
        dump = _write_dump(tmp_path / "large_sha1.txt", entries, newline="\r\n")

        with OfflinePasswordsClient(dump) as client:
            for digest, expected in entries:
                assert client.check_hash(digest) == expected
            for i in range(0, 500, 25):
                assert client.check_password(f"pw-{i:04d}") == (i + 1) * (10 ** (i % 6))
            assert client.check_hash("0" * 40) == 0
            assert client.check_hash("F" * 40) == 0
            assert client.check_password("pw-not-present") == 0

    def test_500_sorted_ntlm_entries(self, tmp_path: Path) -> None:
        entries = [(_ntlm_hex(f"ntlm-{i:04d}"), i + 1) for i in range(500)]
        dump = _write_dump(tmp_path / "large_ntlm.txt", entries, newline="\n")

        with OfflinePasswordsClient(dump, ntlm=True) as client:
            for digest, expected in entries:
                assert client.check_hash(digest) == expected
            for i in range(0, 500, 50):
                assert client.check_password(f"ntlm-{i:04d}") == i + 1
            assert client.check_hash("0" * 32) == 0
            assert client.check_hash("F" * 32) == 0
