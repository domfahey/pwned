from __future__ import annotations

import hashlib
from pathlib import Path

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


class TestLifecycleAndErrors:
    def test_context_manager_and_close(self, tmp_path: Path) -> None:
        h = _sha1_hex("password")
        dump = _write_dump(tmp_path / "sha1.txt", [(h, 42)])

        with OfflinePasswordsClient(dump) as client:
            assert client.ntlm is False
            assert client.path == dump
            assert client.check_password("password") == 42

        with pytest.raises(ValueError):
            client.check_password("password")

    def test_explicit_close_and_str_path(self, tmp_path: Path) -> None:
        h = _sha1_hex("secret")
        dump = _write_dump(tmp_path / "sha1.txt", [(h, 7)])

        client = OfflinePasswordsClient(str(dump))
        assert client.check_hash(h) == 7
        client.close()
        client.close()  # idempotent

        with pytest.raises(ValueError):
            client.check_hash(h)

    def test_missing_file_raises_file_not_found(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            OfflinePasswordsClient(tmp_path / "missing.txt")

    def test_directory_path_raises_os_error(self, tmp_path: Path) -> None:
        with pytest.raises(IsADirectoryError):
            OfflinePasswordsClient(tmp_path)


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
