from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
from pytest_httpx import HTTPXMock

from pwned._parsers import _md4
from pwned.client import HIBPClient, HIBPError, UnauthorizedError
from pwned.doctor import DoctorCheck, DoctorReport, run_doctor
from pwned.models import Breach, Subscription
from pwned.offline_index import build_bloom_filter, build_compact_index
from pwned.passwords import BASE_URL as PASSWORDS_BASE
from pwned.passwords import PwnedPasswordsClient

API_BASE = "https://haveibeenpwned.com/api/v3"


def _sha1_hex(pw: str) -> str:
    return hashlib.sha1(pw.encode("utf-8")).hexdigest().upper()


def _ntlm_hex(pw: str) -> str:
    return _md4(pw.encode("utf-16-le")).upper()


class TestDoctorModels:
    def test_models_frozen_and_defaults(self, tmp_path: Path) -> None:
        check = DoctorCheck(name="credentials", status="ok", detail="Configured via env")
        assert check.status == "ok"
        report = DoctorReport(
            version="0.4.1",
            python_version="3.12.0",
            api_key_source="env",
            api_key_masked="abcd...1234",
            keyring_available=True,
            cache_dir=str(tmp_path / "cache"),
            cache_entries=0,
            cache_bytes=0,
            checks=[check],
        )
        assert report.healthy is True
        assert report.subscription_name is None
        assert report.offline_db_path is None

        compact_report = report.model_copy(update={"offline_db_kind": "compact"})
        bloom_report = report.model_copy(update={"offline_db_kind": "bloom"})
        assert compact_report.offline_db_kind == "compact"
        assert bloom_report.offline_db_kind == "bloom"


class TestRunDoctor:
    def test_healthy_full_online_check_with_cache_and_keyring(
        self,
        tmp_path: Path,
        httpx_mock: HTTPXMock,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        cache_dir = tmp_path / "cache"
        cache_dir.mkdir()
        (cache_dir / "a.json").write_text('{"x": 1}', encoding="utf-8")
        (cache_dir / "b.json").write_text('{"y": 22}', encoding="utf-8")
        (cache_dir / "subdir.json").mkdir()  # ignored non-file

        monkeypatch.setattr("pwned.doctor.keyring_available", lambda: True)
        httpx_mock.add_response(
            url=f"{PASSWORDS_BASE}/range/5BAA6",
            text="1E4C9B93F3F0682250B6CF8331B7EE68FD8:12345\r\n",
        )
        httpx_mock.add_response(
            url=f"{API_BASE}/latestbreach",
            json={"Name": "LatestBreach"},
        )
        httpx_mock.add_response(
            url=f"{API_BASE}/subscription/status",
            json={
                "SubscriptionName": "Pwned 2",
                "Description": "Desc",
                "SubscribedUntil": "2027-01-01T00:00:00Z",
                "Rpm": 50,
                "DomainSearchMaxBreachedAccounts": 100,
                "IncludesStealerLogs": True,
            },
        )

        report = run_doctor(
            api_key="0123456789abcdef0123456789abcdef",
            api_key_source="env",
            cache_dir=cache_dir,
        )

        assert report.healthy is True
        assert report.api_key_source == "env"
        assert report.api_key_masked == "0123...cdef"
        assert report.keyring_available is True
        assert report.cache_entries == 2
        assert report.cache_bytes == len('{"x": 1}') + len('{"y": 22}')
        assert report.subscription_name == "Pwned 2"
        assert report.subscription_rpm == 50

        by_name = {c.name: c for c in report.checks}
        assert by_name["credentials"].status == "ok"
        assert by_name["keyring"].status == "ok"
        assert by_name["cache"].status == "ok"
        assert by_name["pwned_passwords_api"].status == "ok"
        assert by_name["hibp_api"].status == "ok"
        assert "LatestBreach" in by_name["hibp_api"].detail
        assert by_name["subscription"].status == "ok"
        assert "50 RPM" in by_name["subscription"].detail

    def test_no_api_key_and_no_network_and_missing_cache(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr("pwned.doctor.keyring_available", lambda: False)
        monkeypatch.setattr("pwned.doctor.get_api_key_source", lambda api_key=None: "none")
        report = run_doctor(
            api_key=None,
            cache_dir=tmp_path / "missing_cache",
            check_network=False,
        )
        assert report.healthy is True
        assert report.api_key_source == "none"
        assert report.api_key_masked == "(not set)"
        assert report.keyring_available is False
        assert report.cache_entries == 0
        assert report.cache_bytes == 0

        by_name = {c.name: c for c in report.checks}
        assert by_name["credentials"].status == "warn"
        assert by_name["keyring"].status == "warn"
        assert by_name["cache"].status == "ok"
        assert by_name["network"].status == "skipped"

    def test_network_checks_without_api_key_skips_subscription_and_reports_errors(
        self, tmp_path: Path
    ) -> None:
        hibp = MagicMock(spec=HIBPClient)
        hibp.get_latest_breach.side_effect = HIBPError("HTTP 503")
        pw = MagicMock(spec=PwnedPasswordsClient)
        pw.get_password_range.side_effect = HIBPError("Connection refused")

        report = run_doctor(
            api_key=None,
            api_key_source="none",
            cache_dir=tmp_path / "cache",
            hibp_client=hibp,
            passwords_client=pw,
        )
        assert report.healthy is False
        by_name = {c.name: c for c in report.checks}
        assert by_name["pwned_passwords_api"].status == "error"
        assert "Connection refused" in by_name["pwned_passwords_api"].detail
        assert by_name["hibp_api"].status == "error"
        assert by_name["subscription"].status == "skipped"

        # Rejected API key -> subscription check errors
        hibp2 = MagicMock(spec=HIBPClient)
        hibp2.get_latest_breach.return_value = Breach(Name="Adobe")
        hibp2.get_subscription_status.side_effect = UnauthorizedError("Access denied")
        pw2 = MagicMock(spec=PwnedPasswordsClient)
        pw2.get_password_range.return_value = {"AAA": 1}

        report2 = run_doctor(
            api_key="badkey1234567890",
            api_key_source="cli",
            cache_dir=tmp_path / "cache",
            hibp_client=hibp2,
            passwords_client=pw2,
        )
        assert report2.healthy is False
        by_name2 = {c.name: c for c in report2.checks}
        assert by_name2["subscription"].status == "error"
        assert "Access denied" in by_name2["subscription"].detail

        # Healthy injected subscription path
        hibp3 = MagicMock(spec=HIBPClient)
        hibp3.get_latest_breach.return_value = Breach(Name="Adobe")
        hibp3.get_subscription_status.return_value = Subscription.model_validate(
            {
                "SubscriptionName": "Pwned 1",
                "Description": "Desc",
                "SubscribedUntil": "2027-01-01T00:00:00Z",
                "Rpm": 10,
                "DomainSearchMaxBreachedAccounts": 0,
                "IncludesStealerLogs": False,
            }
        )
        report3 = run_doctor(
            api_key="validkey1234567890",
            api_key_source="keyring",
            cache_dir=tmp_path / "cache",
            hibp_client=hibp3,
            passwords_client=pw2,
        )
        assert report3.healthy is True
        assert report3.subscription_name == "Pwned 1"
        assert report3.subscription_rpm == 10

    def test_offline_db_directory_checks(self, tmp_path: Path) -> None:
        # Missing path -> error
        missing = run_doctor(
            offline_db=tmp_path / "nope",
            cache_dir=tmp_path / "cache",
            check_network=False,
        )
        assert missing.healthy is False
        assert missing.checks[-2].name == "offline_db"
        assert missing.checks[-2].status == "error"

        # Empty directory -> warn
        empty_dir = tmp_path / "empty_dir"
        empty_dir.mkdir()
        (empty_dir / "notes.txt").write_text("not a prefix", encoding="utf-8")
        res_empty = run_doctor(
            offline_db=empty_dir,
            cache_dir=tmp_path / "cache",
            check_network=False,
        )
        assert res_empty.healthy is True
        assert res_empty.offline_db_kind == "directory"
        assert res_empty.offline_db_entries == 0
        by_name_empty = {c.name: c for c in res_empty.checks}
        assert by_name_empty["offline_db"].status == "warn"

        # Valid indexed NTLM directory (auto-detected mode)
        ntlm_dir = tmp_path / "ntlm_dir"
        ntlm_dir.mkdir()
        ntlm_hex = _ntlm_hex("password")
        (ntlm_dir / f"{ntlm_hex[:5]}.txt").write_text(f"{ntlm_hex[5:]}:10\r\n", encoding="utf-8")
        (ntlm_dir / ".pwned-index.json").write_text(
            json.dumps({"mode": "ntlm", "etags": {}}, separators=(",", ":")),
            encoding="utf-8",
        )
        res_auto = run_doctor(
            offline_db=ntlm_dir,
            cache_dir=tmp_path / "cache",
            check_network=False,
        )
        assert res_auto.healthy is True
        assert res_auto.offline_db_kind == "directory"
        assert res_auto.offline_db_mode == "ntlm"
        assert res_auto.offline_db_entries == 1
        assert {c.name: c for c in res_auto.checks}["offline_db"].status == "ok"

        # Explicit conflicting ntlm=False -> error
        res_mismatch = run_doctor(
            offline_db=ntlm_dir,
            ntlm=False,
            cache_dir=tmp_path / "cache",
            check_network=False,
        )
        assert res_mismatch.healthy is False
        assert {c.name: c for c in res_mismatch.checks}["offline_db"].status == "error"
        assert "NTLM hashes" in {c.name: c for c in res_mismatch.checks}["offline_db"].detail

    def test_offline_db_single_file_checks(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Valid multi-line sorted SHA-1 file
        sha1_file = tmp_path / "sha1.txt"
        sha1_file.write_text(
            f"{'0' * 40}:1\r\n{_sha1_hex('password')}:99\r\n{'F' * 40}:2\r\n",
            encoding="utf-8",
        )
        res_sha1 = run_doctor(
            offline_db=sha1_file,
            cache_dir=tmp_path / "cache",
            check_network=False,
        )
        assert res_sha1.healthy is True
        assert res_sha1.offline_db_kind == "file"
        assert res_sha1.offline_db_mode == "sha1"
        sha1_check = {c.name: c for c in res_sha1.checks}["offline_db"]
        assert sha1_check.status == "ok"
        assert "sampled records verified" in sha1_check.detail

        # Unsorted file -> error (must NOT report healthy!)
        unsorted_file = tmp_path / "unsorted.txt"
        unsorted_file.write_text(
            f"{'F' * 40}:1\r\n{'0' * 40}:2\r\n",
            encoding="utf-8",
        )
        res_unsorted = run_doctor(
            offline_db=unsorted_file,
            cache_dir=tmp_path / "cache",
            check_network=False,
        )
        assert res_unsorted.healthy is False
        unsorted_check = {c.name: c for c in res_unsorted.checks}["offline_db"]
        assert unsorted_check.status == "error"
        assert "not sorted" in unsorted_check.detail

        # Mixed SHA-1 + NTLM hash lengths -> error
        mixed_file = tmp_path / "mixed.txt"
        mixed_file.write_text(
            f"{'0' * 40}:1\r\n{'F' * 32}:2\r\n",
            encoding="utf-8",
        )
        res_mixed = run_doctor(
            offline_db=mixed_file,
            cache_dir=tmp_path / "cache",
            check_network=False,
        )
        assert res_mixed.healthy is False
        mixed_check = {c.name: c for c in res_mixed.checks}["offline_db"]
        assert mixed_check.status == "error"
        assert "Inconsistent hash lengths" in mixed_check.detail

        # Valid NTLM file + explicit mismatch
        ntlm_file = tmp_path / "ntlm.txt"
        ntlm_file.write_text(f"{_ntlm_hex('password')}:5\r\n", encoding="utf-8")
        res_ntlm = run_doctor(
            offline_db=ntlm_file,
            cache_dir=tmp_path / "cache",
            check_network=False,
        )
        assert res_ntlm.healthy is True
        assert res_ntlm.offline_db_mode == "ntlm"

        res_file_mismatch = run_doctor(
            offline_db=ntlm_file,
            ntlm=False,
            cache_dir=tmp_path / "cache",
            check_network=False,
        )
        assert res_file_mismatch.healthy is False
        assert {c.name: c for c in res_file_mismatch.checks}["offline_db"].status == "error"

        # Empty file -> warn
        empty_file = tmp_path / "empty.txt"
        empty_file.write_bytes(b"")
        res_empty = run_doctor(
            offline_db=empty_file,
            cache_dir=tmp_path / "cache",
            check_network=False,
        )
        assert res_empty.healthy is True
        assert {c.name: c for c in res_empty.checks}["offline_db"].status == "warn"

        # Malformed file -> error
        bad_file = tmp_path / "bad.txt"
        bad_file.write_text("not-a-valid-dump-line\n", encoding="utf-8")
        res_bad = run_doctor(
            offline_db=bad_file,
            cache_dir=tmp_path / "cache",
            check_network=False,
        )
        assert res_bad.healthy is False
        assert {c.name: c for c in res_bad.checks}["offline_db"].status == "error"

        # Unreadable file -> OSError caught as error check
        real_open = Path.open

        def fail_open(self: Path, *args: Any, **kwargs: Any) -> Any:
            if self == sha1_file:
                raise OSError("permission denied")
            return real_open(self, *args, **kwargs)

        monkeypatch.setattr(Path, "open", fail_open)
        res_oserr = run_doctor(
            offline_db=sha1_file,
            cache_dir=tmp_path / "cache",
            check_network=False,
        )
        assert res_oserr.healthy is False
        assert "permission denied" in {c.name: c for c in res_oserr.checks}["offline_db"].detail

    def test_offline_db_compact_index_checks(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sha1_src = tmp_path / "sha1_src.txt"
        sha1_lines = sorted(
            [
                f"{_sha1_hex('password')}:99\n",
                f"{_sha1_hex('hunter2')}:5\n",
            ]
        )
        sha1_src.write_text("".join(sha1_lines), encoding="utf-8")
        compact_sha1 = tmp_path / "sha1.pwnb"
        build_compact_index(sha1_src, compact_sha1)

        # Auto-detected SHA-1 compact index
        res_sha1 = run_doctor(
            offline_db=compact_sha1,
            cache_dir=tmp_path / "cache",
            check_network=False,
        )
        assert res_sha1.healthy is True
        assert res_sha1.offline_db_kind == "compact"
        assert res_sha1.offline_db_mode == "sha1"
        assert res_sha1.offline_db_entries == 2
        sha1_check = {c.name: c for c in res_sha1.checks}["offline_db"]
        assert sha1_check.status == "ok"
        assert "Compact binary index" in sha1_check.detail
        assert "SHA1" in sha1_check.detail
        assert "2 records" in sha1_check.detail

        # Explicit matching ntlm=False
        res_sha1_explicit = run_doctor(
            offline_db=compact_sha1,
            ntlm=False,
            cache_dir=tmp_path / "cache",
            check_network=False,
        )
        assert res_sha1_explicit.healthy is True
        assert res_sha1_explicit.offline_db_mode == "sha1"

        # Explicit conflicting ntlm=True -> error
        res_mismatch = run_doctor(
            offline_db=compact_sha1,
            ntlm=True,
            cache_dir=tmp_path / "cache",
            check_network=False,
        )
        assert res_mismatch.healthy is False
        assert res_mismatch.offline_db_kind == "compact"
        assert res_mismatch.offline_db_mode is None
        mismatch_check = {c.name: c for c in res_mismatch.checks}["offline_db"]
        assert mismatch_check.status == "error"
        assert "SHA1 hashes" in mismatch_check.detail

        # Valid NTLM compact index (auto-detected)
        ntlm_src = tmp_path / "ntlm_src.txt"
        ntlm_src.write_text(f"{_ntlm_hex('password')}:12\n", encoding="utf-8")
        compact_ntlm = tmp_path / "ntlm.pwnb"
        build_compact_index(ntlm_src, compact_ntlm, ntlm=True)

        res_ntlm = run_doctor(
            offline_db=compact_ntlm,
            cache_dir=tmp_path / "cache",
            check_network=False,
        )
        assert res_ntlm.healthy is True
        assert res_ntlm.offline_db_kind == "compact"
        assert res_ntlm.offline_db_mode == "ntlm"
        assert res_ntlm.offline_db_entries == 1
        ntlm_check = {c.name: c for c in res_ntlm.checks}["offline_db"]
        assert ntlm_check.status == "ok"
        assert "NTLM" in ntlm_check.detail
        assert "1 records" in ntlm_check.detail

        # Corrupt compact index (valid magic, truncated header) -> error
        corrupt_compact = tmp_path / "corrupt.pwnb"
        corrupt_compact.write_bytes(b"PWNB\x01\x00")
        res_corrupt = run_doctor(
            offline_db=corrupt_compact,
            cache_dir=tmp_path / "cache",
            check_network=False,
        )
        assert res_corrupt.healthy is False
        assert res_corrupt.offline_db_kind == "compact"
        corrupt_check = {c.name: c for c in res_corrupt.checks}["offline_db"]
        assert corrupt_check.status == "error"
        assert "Truncated compact index header" in corrupt_check.detail

        # OSError when opening compact reader -> error
        def fail_compact_reader(*args: Any, **kwargs: Any) -> Any:
            raise OSError("mmap compact failed")

        monkeypatch.setattr("pwned.doctor.CompactIndexReader", fail_compact_reader)
        res_oserr = run_doctor(
            offline_db=compact_sha1,
            cache_dir=tmp_path / "cache",
            check_network=False,
        )
        assert res_oserr.healthy is False
        assert res_oserr.offline_db_kind == "compact"
        assert "mmap compact failed" in {c.name: c for c in res_oserr.checks}["offline_db"].detail

    def test_offline_db_bloom_filter_checks(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sha1_src = tmp_path / "sha1_src.txt"
        sha1_src.write_text(
            f"{_sha1_hex('password')}:99\n{_sha1_hex('letmein')}:3\n",
            encoding="utf-8",
        )
        bloom_sha1 = tmp_path / "sha1.pwnl"
        sha1_stats = build_bloom_filter(sha1_src, bloom_sha1, false_positive_rate=0.01)

        # Auto-detected SHA-1 Bloom filter
        res_sha1 = run_doctor(
            offline_db=bloom_sha1,
            cache_dir=tmp_path / "cache",
            check_network=False,
        )
        assert res_sha1.healthy is True
        assert res_sha1.offline_db_kind == "bloom"
        assert res_sha1.offline_db_mode == "sha1"
        assert res_sha1.offline_db_entries == sha1_stats.item_count
        sha1_check = {c.name: c for c in res_sha1.checks}["offline_db"]
        assert sha1_check.status == "ok"
        assert "Bloom filter" in sha1_check.detail
        assert "SHA1" in sha1_check.detail
        assert f"{sha1_stats.item_count} items" in sha1_check.detail
        assert f"{sha1_stats.bit_count} bits" in sha1_check.detail
        assert f"k={sha1_stats.num_hashes}" in sha1_check.detail

        # Explicit conflicting ntlm=True -> error
        res_mismatch = run_doctor(
            offline_db=bloom_sha1,
            ntlm=True,
            cache_dir=tmp_path / "cache",
            check_network=False,
        )
        assert res_mismatch.healthy is False
        assert res_mismatch.offline_db_kind == "bloom"
        assert res_mismatch.offline_db_mode is None
        assert {c.name: c for c in res_mismatch.checks}["offline_db"].status == "error"

        # Valid NTLM Bloom filter (auto-detected)
        ntlm_src = tmp_path / "ntlm_src.txt"
        ntlm_src.write_text(f"{_ntlm_hex('password')}:7\n", encoding="utf-8")
        bloom_ntlm = tmp_path / "ntlm.pwnl"
        ntlm_stats = build_bloom_filter(ntlm_src, bloom_ntlm, ntlm=True)

        res_ntlm = run_doctor(
            offline_db=bloom_ntlm,
            cache_dir=tmp_path / "cache",
            check_network=False,
        )
        assert res_ntlm.healthy is True
        assert res_ntlm.offline_db_kind == "bloom"
        assert res_ntlm.offline_db_mode == "ntlm"
        assert res_ntlm.offline_db_entries == ntlm_stats.item_count
        assert "NTLM" in {c.name: c for c in res_ntlm.checks}["offline_db"].detail

        # Corrupt Bloom filter (valid magic, truncated header) -> error
        corrupt_bloom = tmp_path / "corrupt.pwnl"
        corrupt_bloom.write_bytes(b"PWNL\x01\x00")
        res_corrupt = run_doctor(
            offline_db=corrupt_bloom,
            cache_dir=tmp_path / "cache",
            check_network=False,
        )
        assert res_corrupt.healthy is False
        assert res_corrupt.offline_db_kind == "bloom"
        corrupt_check = {c.name: c for c in res_corrupt.checks}["offline_db"]
        assert corrupt_check.status == "error"
        assert "Truncated Bloom filter header" in corrupt_check.detail

        # OSError when opening Bloom reader -> error
        def fail_bloom_reader(*args: Any, **kwargs: Any) -> Any:
            raise OSError("mmap bloom failed")

        monkeypatch.setattr("pwned.doctor.BloomFilterReader", fail_bloom_reader)
        res_oserr = run_doctor(
            offline_db=bloom_sha1,
            cache_dir=tmp_path / "cache",
            check_network=False,
        )
        assert res_oserr.healthy is False
        assert res_oserr.offline_db_kind == "bloom"
        assert "mmap bloom failed" in {c.name: c for c in res_oserr.checks}["offline_db"].detail
