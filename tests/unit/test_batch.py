from __future__ import annotations

import asyncio
import hashlib
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, call

import pytest
from pydantic import ValidationError
from pytest_httpx import HTTPXMock

from pwned._parsers import _md4
from pwned.async_client import AsyncHIBPClient
from pwned.batch import (
    AccountBatchItem,
    BatchStats,
    PasswordBatchItem,
    async_batch_check_accounts,
    async_batch_check_passwords,
    batch_check_accounts,
    batch_check_passwords,
    compute_batch_stats,
    format_batch_stats,
    load_input_file,
    parse_input_lines,
)
from pwned.client import HIBPError, NotFoundError, RateLimitError
from pwned.models import Breach, Subscription
from pwned.offline import OfflinePasswordsClient
from pwned.passwords import AsyncPwnedPasswordsClient


class TestParseInputLines:
    def test_strips_skips_comments_blanks_and_deduplicates(self) -> None:
        lines = (
            line
            for line in [
                "  alice@example.com \r\n",
                "",
                "   \n",
                "# header comment\n",
                "   # indented comment\r\n",
                "bob@example.com\n",
                "alice@example.com\r\n",
                "carol@example.com",
            ]
        )

        result = parse_input_lines(lines)

        assert result == [
            "alice@example.com",
            "bob@example.com",
            "carol@example.com",
        ]

    def test_preserves_spaces_and_hash_when_password_mode(self) -> None:
        lines = [
            "  leading and trailing  \r\n",
            "#starts-with-hash\n",
            "\r\n",
            "\n",
            "",
            "  leading and trailing  \n",
            "plain\n",
        ]

        result = parse_input_lines(lines, strip=False, ignore_comments=False)

        assert result == [
            "  leading and trailing  ",
            "#starts-with-hash",
            "plain",
        ]

    def test_strip_false_with_ignore_comments_true(self) -> None:
        lines = [
            "# comment\n",
            "  # indented comment\n",
            "  keep spaces  \n",
        ]

        result = parse_input_lines(lines, strip=False, ignore_comments=True)

        assert result == ["  keep spaces  "]

    def test_empty_input(self) -> None:
        assert parse_input_lines([]) == []

    def test_deduplicate_false_preserves_duplicates(self) -> None:
        lines = ["pw1\n", "pw2\n", "pw1\n"]
        result = parse_input_lines(lines, strip=False, ignore_comments=False, deduplicate=False)
        assert result == ["pw1", "pw2", "pw1"]

    def test_skip_empty_false_preserves_blank_lines(self) -> None:
        lines = ["pw1\n", "\n", "  \n", "pw2\r\n"]
        result = parse_input_lines(
            lines,
            strip=False,
            ignore_comments=False,
            deduplicate=False,
            skip_empty=False,
        )
        assert result == ["pw1", "", "  ", "pw2"]

    def test_empty_input_with_skip_empty_false(self) -> None:
        assert parse_input_lines([], skip_empty=False) == []


class TestLoadInputFile:
    def test_loads_utf8_file_default_options(self, tmp_path: Path) -> None:
        path = tmp_path / "accounts.txt"
        path.write_text(
            "# accounts\r\n\r\n  alice@example.com  \r\nbob@example.com\nalice@example.com\n",
            encoding="utf-8",
        )

        assert load_input_file(path) == ["alice@example.com", "bob@example.com"]

    def test_loads_utf8_file_password_options(self, tmp_path: Path) -> None:
        path = tmp_path / "passwords.txt"
        path.write_text(
            "#hashpass\r\n pass with spaces \n\n#hashpass\n",
            encoding="utf-8",
        )

        assert load_input_file(path, strip=False, ignore_comments=False) == [
            "#hashpass",
            " pass with spaces ",
        ]

    def test_missing_file_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            load_input_file(tmp_path / "missing.txt")

    def test_loads_file_without_deduplicating(self, tmp_path: Path) -> None:
        path = tmp_path / "dups.txt"
        path.write_text("pw1\npw2\npw1\n", encoding="utf-8")

        assert load_input_file(path, strip=False, ignore_comments=False, deduplicate=False) == [
            "pw1",
            "pw2",
            "pw1",
        ]

    def test_loads_file_preserving_blank_lines_when_skip_empty_false(self, tmp_path: Path) -> None:
        path = tmp_path / "blanks.txt"
        path.write_bytes(b"pw1\n\n  \npw2\r\n")

        assert load_input_file(
            path,
            strip=False,
            ignore_comments=False,
            deduplicate=False,
            skip_empty=False,
        ) == ["pw1", "", "  ", "pw2"]

    def test_skip_empty_false_preserves_line_indices_in_batch_passwords(
        self, tmp_path: Path, httpx_mock: HTTPXMock
    ) -> None:
        h_pw1 = hashlib.sha1(b"pw1").hexdigest().upper()
        h_empty = hashlib.sha1(b"").hexdigest().upper()
        h_pw2 = hashlib.sha1(b"pw2").hexdigest().upper()

        plain_path = tmp_path / "plain_blanks.txt"
        plain_path.write_text("pw1\n\npw2\n", encoding="utf-8")
        plain_lines = load_input_file(
            plain_path,
            strip=False,
            ignore_comments=False,
            deduplicate=False,
            skip_empty=False,
        )
        assert plain_lines == ["pw1", "", "pw2"]

        hash_path = tmp_path / "hash_blanks.txt"
        hash_path.write_text(f"{h_pw1}\n\n{h_pw2}\n", encoding="utf-8")
        hash_lines = load_input_file(
            hash_path,
            strip=False,
            ignore_comments=False,
            deduplicate=False,
            skip_empty=False,
        )
        assert hash_lines == [h_pw1, "", h_pw2]

        entries = sorted([(h_pw1, 10), (h_empty, 3)], key=lambda item: item[0])
        dump = tmp_path / "sha1_dump.txt"
        dump.write_text(
            "\n".join(f"{digest}:{count}" for digest, count in entries) + "\n",
            encoding="utf-8",
        )
        with OfflinePasswordsClient(dump) as offline_client:
            sync_plain = batch_check_passwords(plain_lines, offline_client)
            sync_hashed = batch_check_passwords(hash_lines, offline_client, hashed=True)

        assert sync_plain == [
            PasswordBatchItem(index=1, pwn_count=10, status="pwned"),
            PasswordBatchItem(index=2, pwn_count=3, status="pwned"),
            PasswordBatchItem(index=3, pwn_count=0, status="clean"),
        ]
        assert sync_hashed == [
            PasswordBatchItem(index=1, pwn_count=10, status="pwned"),
            PasswordBatchItem(
                index=2,
                pwn_count=0,
                status="error",
                error="SHA-1 hash must be exactly 40 hexadecimal characters",
            ),
            PasswordBatchItem(index=3, pwn_count=0, status="clean"),
        ]

        httpx_mock.add_response(
            url=f"https://api.pwnedpasswords.com/range/{h_pw1[:5]}",
            text=f"{h_pw1[5:]}:10\r\n",
            is_reusable=True,
        )
        httpx_mock.add_response(
            url=f"https://api.pwnedpasswords.com/range/{h_empty[:5]}",
            text=f"{h_empty[5:]}:3\r\n",
        )
        httpx_mock.add_response(
            url=f"https://api.pwnedpasswords.com/range/{h_pw2[:5]}",
            text="00000000000000000000000000000000000:1\r\n",
            is_reusable=True,
        )

        async def _run_async() -> tuple[list[PasswordBatchItem], list[PasswordBatchItem]]:
            async with AsyncPwnedPasswordsClient(user_agent="test") as async_client:
                async_plain = await async_batch_check_passwords(
                    plain_lines, async_client, pad=False
                )
                async_hashed = await async_batch_check_passwords(
                    hash_lines, async_client, hashed=True, pad=False
                )
                return async_plain, async_hashed

        async_plain, async_hashed = asyncio.run(_run_async())

        assert async_plain == sync_plain
        assert async_hashed == sync_hashed


class TestBatchModels:
    def test_account_batch_item_defaults_and_frozen(self) -> None:
        item = AccountBatchItem(account="alice@example.com", status="clean")
        assert item.breaches == []
        assert item.error is None
        with pytest.raises(ValidationError):
            item.status = "pwned"

    def test_password_batch_item_defaults_and_no_plaintext_field(self) -> None:
        item = PasswordBatchItem(index=1, status="clean")
        assert item.pwn_count == 0
        assert item.error is None
        assert "password" not in PasswordBatchItem.model_fields
        with pytest.raises(ValidationError):
            PasswordBatchItem(index=-1, status="clean")


class TestBatchCheckAccounts:
    @pytest.mark.parametrize("bad_rpm", [0, -1, -60])
    def test_invalid_rpm_raises_value_error(self, bad_rpm: int) -> None:
        client = MagicMock()
        with pytest.raises(ValueError, match="rpm"):
            batch_check_accounts(["a@example.com"], client, rpm=bad_rpm)
        client.get_account_breaches.assert_not_called()

    def test_empty_accounts_returns_empty_without_sleeping(self) -> None:
        client = MagicMock()
        sleep = MagicMock()
        progress = MagicMock()

        results = batch_check_accounts([], client, rpm=60, sleep=sleep, on_progress=progress)

        assert results == []
        client.get_account_breaches.assert_not_called()
        sleep.assert_not_called()
        progress.assert_not_called()

    def test_mixed_outcomes_and_continues_after_error(self) -> None:
        client = MagicMock()
        client.get_account_breaches.side_effect = [
            [Breach(Name="Adobe"), Breach(Name="LinkedIn")],
            NotFoundError("Not found"),
            RateLimitError("Rate limit exceeded after retries"),
            [],
        ]
        progress_calls: list[tuple[int, int, AccountBatchItem]] = []

        results = batch_check_accounts(
            [
                "pwned@example.com",
                "clean@example.com",
                "err@example.com",
                "empty@example.com",
            ],
            client,
            domain="adobe.com",
            include_unverified=False,
            on_progress=lambda idx, total, item: progress_calls.append((idx, total, item)),
        )

        assert results == [
            AccountBatchItem(
                account="pwned@example.com",
                breaches=["Adobe", "LinkedIn"],
                status="pwned",
            ),
            AccountBatchItem(account="clean@example.com", breaches=[], status="clean"),
            AccountBatchItem(
                account="err@example.com",
                breaches=[],
                status="error",
                error="Rate limit exceeded after retries",
            ),
            AccountBatchItem(account="empty@example.com", breaches=[], status="clean"),
        ]
        assert progress_calls == [
            (1, 4, results[0]),
            (2, 4, results[1]),
            (3, 4, results[2]),
            (4, 4, results[3]),
        ]
        assert client.get_account_breaches.call_args_list == [
            call("pwned@example.com", truncate=True, domain="adobe.com", include_unverified=False),
            call("clean@example.com", truncate=True, domain="adobe.com", include_unverified=False),
            call("err@example.com", truncate=True, domain="adobe.com", include_unverified=False),
            call("empty@example.com", truncate=True, domain="adobe.com", include_unverified=False),
        ]

    def test_rpm_sleeps_only_between_requests(self) -> None:
        client = MagicMock()
        client.get_account_breaches.side_effect = NotFoundError("Not found")
        events: list[str] = []

        def fake_check(account: str, **kwargs: object) -> list[Breach]:
            events.append(f"req:{account}")
            return []

        client.get_account_breaches.side_effect = fake_check
        sleep = MagicMock(side_effect=lambda secs: events.append(f"sleep:{secs}"))

        batch_check_accounts(
            ["a@example.com", "b@example.com", "c@example.com"],
            client,
            rpm=30,
            sleep=sleep,
        )

        assert events == [
            "req:a@example.com",
            "sleep:2.0",
            "req:b@example.com",
            "sleep:2.0",
            "req:c@example.com",
        ]

    def test_single_account_with_rpm_does_not_sleep(self) -> None:
        client = MagicMock()
        client.get_account_breaches.return_value = []
        sleep = MagicMock()

        batch_check_accounts(["only@example.com"], client, rpm=60, sleep=sleep)

        sleep.assert_not_called()

    def test_rpm_none_does_not_sleep(self) -> None:
        client = MagicMock()
        client.get_account_breaches.return_value = []
        sleep = MagicMock()

        batch_check_accounts(["a@example.com", "b@example.com"], client, rpm=None, sleep=sleep)

        sleep.assert_not_called()
        client.get_subscription_status.assert_not_called()

    def test_auto_rpm_queries_subscription_when_rpm_omitted(self) -> None:
        client = MagicMock()
        client.get_subscription_status.return_value = Subscription.model_validate(
            {
                "SubscriptionName": "Pwned 1",
                "Description": "Desc",
                "SubscribedUntil": "2027-01-01T00:00:00Z",
                "Rpm": 120,
                "DomainSearchMaxBreachedAccounts": 0,
                "IncludesStealerLogs": False,
            }
        )
        client.get_account_breaches.return_value = []
        sleep = MagicMock()

        batch_check_accounts(
            ["a@example.com", "b@example.com"],
            client,
            auto_rpm=True,
            sleep=sleep,
        )

        client.get_subscription_status.assert_called_once()
        sleep.assert_called_once_with(0.5)

    def test_auto_rpm_skips_subscription_for_single_account(self) -> None:
        client = MagicMock()
        client.get_account_breaches.return_value = []
        sleep = MagicMock()

        batch_check_accounts(["only@example.com"], client, auto_rpm=True, sleep=sleep)

        client.get_subscription_status.assert_not_called()
        sleep.assert_not_called()

    def test_auto_rpm_falls_back_on_hibp_error(self) -> None:
        client = MagicMock()
        client.get_subscription_status.side_effect = HIBPError("HTTP 500")
        client.get_account_breaches.return_value = []
        sleep = MagicMock()

        results = batch_check_accounts(
            ["a@example.com", "b@example.com"],
            client,
            auto_rpm=True,
            sleep=sleep,
        )

        assert len(results) == 2
        sleep.assert_not_called()

    def test_auto_rpm_ignores_non_positive_subscription_rpm(self) -> None:
        client = MagicMock()
        client.get_subscription_status.return_value = Subscription.model_validate(
            {
                "SubscriptionName": "Custom",
                "Description": "Desc",
                "SubscribedUntil": "2027-01-01T00:00:00Z",
                "Rpm": 0,
                "DomainSearchMaxBreachedAccounts": 0,
                "IncludesStealerLogs": False,
            }
        )
        client.get_account_breaches.return_value = []
        sleep = MagicMock()

        batch_check_accounts(
            ["a@example.com", "b@example.com"],
            client,
            auto_rpm=True,
            sleep=sleep,
        )

        sleep.assert_not_called()


class TestBatchCheckPasswords:
    @pytest.mark.parametrize("bad_threshold", [0, -1])
    def test_invalid_threshold_raises_value_error(self, bad_threshold: int) -> None:
        client = MagicMock()
        with pytest.raises(ValueError, match="threshold"):
            batch_check_passwords(["secret"], client, threshold=bad_threshold)
        client.check_password.assert_not_called()

    def test_empty_passwords_returns_empty(self) -> None:
        client = MagicMock()
        progress = MagicMock()

        results = batch_check_passwords([], client, on_progress=progress)

        assert results == []
        client.check_password.assert_not_called()
        progress.assert_not_called()

    def test_threshold_dedup_errors_and_never_stores_plaintext(self) -> None:
        client = MagicMock()
        client.check_password.side_effect = [
            100,
            4,
            0,
            HIBPError("HTTP 503"),
        ]
        progress_calls: list[tuple[int, int, PasswordBatchItem]] = []
        passwords = [
            "SuperSecretPwned",
            "BelowThresholdPw",
            "CleanPassword",
            "SuperSecretPwned",  # duplicate: should use cache, not call client again
            "ErrorPassword",
        ]

        results = batch_check_passwords(
            passwords,
            client,
            threshold=5,
            ntlm=True,
            pad=False,
            on_progress=lambda idx, total, item: progress_calls.append((idx, total, item)),
        )

        assert results == [
            PasswordBatchItem(index=1, pwn_count=100, status="pwned"),
            PasswordBatchItem(index=2, pwn_count=4, status="clean"),
            PasswordBatchItem(index=3, pwn_count=0, status="clean"),
            PasswordBatchItem(index=4, pwn_count=100, status="pwned"),
            PasswordBatchItem(index=5, pwn_count=0, status="error", error="HTTP 503"),
        ]
        assert client.check_password.call_args_list == [
            call("SuperSecretPwned", ntlm=True, pad=False),
            call("BelowThresholdPw", ntlm=True, pad=False),
            call("CleanPassword", ntlm=True, pad=False),
            call("ErrorPassword", ntlm=True, pad=False),
        ]
        assert progress_calls == [(i + 1, 5, item) for i, item in enumerate(results)]
        serialized = "".join(item.model_dump_json() for item in results)
        for pw in passwords:
            assert pw not in serialized

    def test_defaults_and_no_progress_callback(self) -> None:
        client = MagicMock()
        client.check_password.return_value = 1

        results = batch_check_passwords(["hunter2"], client)

        assert results == [PasswordBatchItem(index=1, pwn_count=1, status="pwned")]
        client.check_password.assert_called_once_with("hunter2", ntlm=False, pad=True)

    def test_hashed_mode_calls_check_hash_and_catches_errors(self) -> None:
        h1 = hashlib.sha1(b"pwned").hexdigest().upper()
        h2 = hashlib.sha1(b"clean").hexdigest().upper()
        bad_hash = "NOT_A_VALID_HASH"
        client = MagicMock()
        client.check_hash.side_effect = [
            12,
            0,
            ValueError("SHA-1 hash must be exactly 40 hexadecimal characters"),
            HIBPError("HTTP 502"),
        ]
        h3 = hashlib.sha1(b"err").hexdigest().upper()

        results = batch_check_passwords(
            [h1, h2, h1, bad_hash, h3],
            client,
            threshold=5,
            ntlm=False,
            pad=False,
            hashed=True,
        )

        assert results == [
            PasswordBatchItem(index=1, pwn_count=12, status="pwned"),
            PasswordBatchItem(index=2, pwn_count=0, status="clean"),
            PasswordBatchItem(index=3, pwn_count=12, status="pwned"),
            PasswordBatchItem(
                index=4,
                pwn_count=0,
                status="error",
                error="SHA-1 hash must be exactly 40 hexadecimal characters",
            ),
            PasswordBatchItem(index=5, pwn_count=0, status="error", error="HTTP 502"),
        ]
        assert client.check_hash.call_args_list == [
            call(h1, ntlm=False, pad=False),
            call(h2, ntlm=False, pad=False),
            call(bad_hash, ntlm=False, pad=False),
            call(h3, ntlm=False, pad=False),
        ]
        client.check_password.assert_not_called()

    def test_plaintext_mode_catches_value_error_without_aborting(self) -> None:
        client = MagicMock()
        client.check_password.side_effect = [
            ValueError("Client mode mismatch"),
            9,
        ]

        results = batch_check_passwords(["first", "second"], client)

        assert results == [
            PasswordBatchItem(index=1, pwn_count=0, status="error", error="Client mode mismatch"),
            PasswordBatchItem(index=2, pwn_count=9, status="pwned"),
        ]

    def test_with_real_offline_client_sha1_plaintext_and_hashed(self, tmp_path: Path) -> None:
        h_pwned = hashlib.sha1(b"letmein").hexdigest().upper()
        h_below = hashlib.sha1(b"rarepass").hexdigest().upper()
        entries = sorted([(h_pwned, 25), (h_below, 2)], key=lambda item: item[0])
        dump = tmp_path / "sha1_dump.txt"
        dump.write_text(
            "\n".join(f"{digest}:{count}" for digest, count in entries) + "\n",
            encoding="utf-8",
        )

        with OfflinePasswordsClient(dump) as client:
            plain_results = batch_check_passwords(
                ["letmein", "rarepass", "notfound", "letmein"],
                client,
                threshold=5,
            )
            hash_results = batch_check_passwords(
                [h_pwned, "INVALID", h_below],
                client,
                threshold=5,
                hashed=True,
            )

        assert plain_results == [
            PasswordBatchItem(index=1, pwn_count=25, status="pwned"),
            PasswordBatchItem(index=2, pwn_count=2, status="clean"),
            PasswordBatchItem(index=3, pwn_count=0, status="clean"),
            PasswordBatchItem(index=4, pwn_count=25, status="pwned"),
        ]
        assert hash_results[0] == PasswordBatchItem(index=1, pwn_count=25, status="pwned")
        assert hash_results[1].index == 2
        assert hash_results[1].status == "error"
        assert hash_results[1].error is not None
        assert hash_results[2] == PasswordBatchItem(index=3, pwn_count=2, status="clean")

    def test_with_real_offline_client_ntlm(self, tmp_path: Path) -> None:
        ntlm_hash = _md4("hunter2".encode("utf-16-le")).upper()
        dump = tmp_path / "ntlm_dump.txt"
        dump.write_text(f"{ntlm_hash}:15\n", encoding="utf-8")

        with OfflinePasswordsClient(dump, ntlm=True) as client:
            results = batch_check_passwords(["hunter2", "cleanpw"], client, ntlm=True)
            hash_results = batch_check_passwords([ntlm_hash], client, ntlm=True, hashed=True)
            mismatch_results = batch_check_passwords(["hunter2"], client, ntlm=False)

        assert results == [
            PasswordBatchItem(index=1, pwn_count=15, status="pwned"),
            PasswordBatchItem(index=2, pwn_count=0, status="clean"),
        ]
        assert hash_results == [PasswordBatchItem(index=1, pwn_count=15, status="pwned")]
        assert mismatch_results[0].status == "error"
        assert mismatch_results[0].error is not None


class TestBatchStats:
    def test_valid_and_frozen(self) -> None:
        stats = BatchStats(checked=5, pwned=2, clean=2, errors=1, elapsed_seconds=1.23)
        assert stats.checked == 5
        assert stats.pwned == 2
        assert stats.clean == 2
        assert stats.errors == 1
        assert stats.elapsed_seconds == 1.23
        with pytest.raises(ValidationError):
            stats.checked = 10

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"checked": -1, "pwned": 0, "clean": 0, "errors": 0, "elapsed_seconds": 0.0},
            {"checked": 0, "pwned": -1, "clean": 0, "errors": 0, "elapsed_seconds": 0.0},
            {"checked": 0, "pwned": 0, "clean": -1, "errors": 0, "elapsed_seconds": 0.0},
            {"checked": 0, "pwned": 0, "clean": 0, "errors": -1, "elapsed_seconds": 0.0},
            {"checked": 0, "pwned": 0, "clean": 0, "errors": 0, "elapsed_seconds": -0.1},
        ],
    )
    def test_rejects_negative_values(self, kwargs: dict[str, int | float]) -> None:
        with pytest.raises(ValidationError):
            BatchStats.model_validate(kwargs)


class TestComputeAndFormatBatchStats:
    def test_compute_empty(self) -> None:
        stats = compute_batch_stats([])
        assert stats == BatchStats(checked=0, pwned=0, clean=0, errors=0, elapsed_seconds=0.0)

    def test_compute_account_items(self) -> None:
        items = [
            AccountBatchItem(account="a@example.com", breaches=["Adobe"], status="pwned"),
            AccountBatchItem(account="b@example.com", status="clean"),
            AccountBatchItem(account="c@example.com", status="error", error="timeout"),
            AccountBatchItem(account="d@example.com", breaches=["LinkedIn"], status="pwned"),
            AccountBatchItem(account="e@example.com", status="clean"),
        ]
        stats = compute_batch_stats(items, elapsed_seconds=1.234)
        assert stats == BatchStats(
            checked=5,
            pwned=2,
            clean=2,
            errors=1,
            elapsed_seconds=1.234,
        )

    def test_compute_password_items(self) -> None:
        items = [
            PasswordBatchItem(index=1, pwn_count=10, status="pwned"),
            PasswordBatchItem(index=2, pwn_count=0, status="clean"),
            PasswordBatchItem(index=3, pwn_count=0, status="error", error="HTTP 500"),
        ]
        stats = compute_batch_stats(items, elapsed_seconds=0.5)
        assert stats == BatchStats(checked=3, pwned=1, clean=1, errors=1, elapsed_seconds=0.5)

    def test_compute_negative_elapsed_raises(self) -> None:
        with pytest.raises(ValueError, match="elapsed_seconds"):
            compute_batch_stats([], elapsed_seconds=-0.01)

    def test_format_batch_stats(self) -> None:
        stats = BatchStats(checked=5, pwned=2, clean=2, errors=1, elapsed_seconds=1.234)
        assert format_batch_stats(stats) == "Checked 5: 2 pwned, 2 clean, 1 error(s) in 1.23s"

    def test_format_batch_stats_zeros(self) -> None:
        stats = BatchStats(checked=0, pwned=0, clean=0, errors=0, elapsed_seconds=0.0)
        assert format_batch_stats(stats) == "Checked 0: 0 pwned, 0 clean, 0 error(s) in 0.00s"


class TestAsyncBatchCheckPasswords:
    @pytest.mark.parametrize("bad_threshold", [0, -1])
    def test_invalid_threshold_raises(self, bad_threshold: int) -> None:
        client = MagicMock()
        client.check_password = AsyncMock()

        async def _run() -> None:
            with pytest.raises(ValueError, match="threshold"):
                await async_batch_check_passwords(["secret"], client, threshold=bad_threshold)

        asyncio.run(_run())
        client.check_password.assert_not_called()

    @pytest.mark.parametrize("bad_concurrency", [0, -2])
    def test_invalid_concurrency_raises(self, bad_concurrency: int) -> None:
        client = MagicMock()
        client.check_password = AsyncMock()

        async def _run() -> None:
            with pytest.raises(ValueError, match="concurrency"):
                await async_batch_check_passwords(["secret"], client, concurrency=bad_concurrency)

        asyncio.run(_run())
        client.check_password.assert_not_called()

    def test_empty_passwords_returns_empty(self) -> None:
        client = MagicMock()
        client.check_password = AsyncMock()
        progress = MagicMock()

        results = asyncio.run(async_batch_check_passwords([], client, on_progress=progress))

        assert results == []
        client.check_password.assert_not_called()
        progress.assert_not_called()

    def test_dedup_order_errors_progress_and_no_plaintext(self) -> None:
        counts: dict[str, int | Exception] = {
            "SuperSecretPwned": 100,
            "BelowThresholdPw": 4,
            "CleanPassword": 0,
            "ErrorPassword": HIBPError("HTTP 503"),
        }

        async def fake_check_password(
            password: str,
            *,
            ntlm: bool = False,
            pad: bool = True,
        ) -> int:
            _ = (ntlm, pad)
            val = counts[password]
            if isinstance(val, Exception):
                raise val
            return val

        client = MagicMock()
        client.check_password = AsyncMock(side_effect=fake_check_password)
        progress_calls: list[tuple[int, int, PasswordBatchItem]] = []
        passwords = [
            "SuperSecretPwned",
            "BelowThresholdPw",
            "CleanPassword",
            "SuperSecretPwned",
            "ErrorPassword",
            "ErrorPassword",
        ]

        results = asyncio.run(
            async_batch_check_passwords(
                passwords,
                client,
                threshold=5,
                ntlm=True,
                pad=False,
                concurrency=2,
                on_progress=lambda idx, total, item: progress_calls.append((idx, total, item)),
            )
        )

        assert results == [
            PasswordBatchItem(index=1, pwn_count=100, status="pwned"),
            PasswordBatchItem(index=2, pwn_count=4, status="clean"),
            PasswordBatchItem(index=3, pwn_count=0, status="clean"),
            PasswordBatchItem(index=4, pwn_count=100, status="pwned"),
            PasswordBatchItem(index=5, pwn_count=0, status="error", error="HTTP 503"),
            PasswordBatchItem(index=6, pwn_count=0, status="error", error="HTTP 503"),
        ]
        assert client.check_password.call_count == 4
        assert client.check_password.call_args_list == [
            call("SuperSecretPwned", ntlm=True, pad=False),
            call("BelowThresholdPw", ntlm=True, pad=False),
            call("CleanPassword", ntlm=True, pad=False),
            call("ErrorPassword", ntlm=True, pad=False),
        ]
        assert progress_calls == [(i + 1, 6, item) for i, item in enumerate(results)]
        serialized = "".join(item.model_dump_json() for item in results)
        for pw in passwords:
            assert pw not in serialized

    def test_hashed_mode_and_value_error_capture(self) -> None:
        h1 = hashlib.sha1(b"pwned").hexdigest().upper()
        h2 = hashlib.sha1(b"clean").hexdigest().upper()
        bad_hash = "BAD"

        async def fake_check_hash(
            hash_hex: str,
            *,
            ntlm: bool = False,
            pad: bool = True,
        ) -> int:
            _ = (ntlm, pad)
            if hash_hex == bad_hash:
                raise ValueError("Invalid hash")
            return 50 if hash_hex == h1 else 0

        client = MagicMock()
        client.check_hash = AsyncMock(side_effect=fake_check_hash)
        client.check_password = AsyncMock()

        results = asyncio.run(
            async_batch_check_passwords(
                [h1, bad_hash, h2, h1],
                client,
                hashed=True,
                ntlm=False,
                pad=True,
            )
        )

        assert results == [
            PasswordBatchItem(index=1, pwn_count=50, status="pwned"),
            PasswordBatchItem(index=2, pwn_count=0, status="error", error="Invalid hash"),
            PasswordBatchItem(index=3, pwn_count=0, status="clean"),
            PasswordBatchItem(index=4, pwn_count=50, status="pwned"),
        ]
        assert client.check_hash.call_count == 3
        client.check_password.assert_not_called()
        serialized = "".join(item.model_dump_json() for item in results)
        for item_val in [h1, h2, bad_hash]:
            assert item_val not in serialized

    def test_bounded_concurrency_and_out_of_order_completion_preserves_order(self) -> None:
        active = 0
        max_active = 0
        delays = {"pw1": 0.04, "pw2": 0.01, "pw3": 0.03, "pw4": 0.005, "pw5": 0.02}

        async def fake_check_password(
            password: str,
            *,
            ntlm: bool = False,
            pad: bool = True,
        ) -> int:
            nonlocal active, max_active
            _ = (ntlm, pad)
            active += 1
            max_active = max(max_active, active)
            try:
                await asyncio.sleep(delays[password])
                return int(password[-1])
            finally:
                active -= 1

        client = MagicMock()
        client.check_password = AsyncMock(side_effect=fake_check_password)
        progress_indices: list[int] = []

        results = asyncio.run(
            async_batch_check_passwords(
                ["pw1", "pw2", "pw3", "pw4", "pw5", "pw1"],
                client,
                concurrency=2,
                threshold=3,
                on_progress=lambda idx, total, item: progress_indices.append(idx),
            )
        )

        assert max_active == 2
        assert [r.index for r in results] == [1, 2, 3, 4, 5, 6]
        assert [r.pwn_count for r in results] == [1, 2, 3, 4, 5, 1]
        assert [r.status for r in results] == [
            "clean",
            "clean",
            "pwned",
            "pwned",
            "pwned",
            "clean",
        ]
        assert progress_indices == [1, 2, 3, 4, 5, 6]

    def test_with_real_async_client_and_httpx_mock(self, httpx_mock: HTTPXMock) -> None:
        h_pwned = hashlib.sha1(b"password").hexdigest().upper()
        h_clean = hashlib.sha1(b"unique-clean-pw-123").hexdigest().upper()

        httpx_mock.add_response(
            url=f"https://api.pwnedpasswords.com/range/{h_pwned[:5]}",
            text=f"{h_pwned[5:]}:999\r\n",
        )
        httpx_mock.add_response(
            url=f"https://api.pwnedpasswords.com/range/{h_clean[:5]}",
            text="00000000000000000000000000000000000:1\r\n",
        )

        async def _run() -> list[PasswordBatchItem]:
            async with AsyncPwnedPasswordsClient(user_agent="test") as client:
                return await async_batch_check_passwords(
                    ["password", "unique-clean-pw-123", "password"],
                    client,
                    pad=False,
                )

        results = asyncio.run(_run())

        assert results == [
            PasswordBatchItem(index=1, pwn_count=999, status="pwned"),
            PasswordBatchItem(index=2, pwn_count=0, status="clean"),
            PasswordBatchItem(index=3, pwn_count=999, status="pwned"),
        ]


class TestAsyncBatchCheckAccounts:
    @pytest.mark.parametrize("bad_rpm", [0, -1, -60])
    def test_invalid_rpm_raises_value_error(self, bad_rpm: int) -> None:
        client = MagicMock()
        client.get_account_breaches = AsyncMock()

        async def _run() -> None:
            with pytest.raises(ValueError, match="rpm"):
                await async_batch_check_accounts(["a@example.com"], client, rpm=bad_rpm)

        asyncio.run(_run())
        client.get_account_breaches.assert_not_called()

    def test_empty_accounts_returns_empty_without_sleeping(self) -> None:
        client = MagicMock()
        client.get_account_breaches = AsyncMock()
        sleep = AsyncMock()
        progress = MagicMock()

        results = asyncio.run(
            async_batch_check_accounts([], client, rpm=60, sleep=sleep, on_progress=progress)
        )

        assert results == []
        client.get_account_breaches.assert_not_called()
        sleep.assert_not_awaited()
        progress.assert_not_called()

    def test_mixed_outcomes_and_continues_after_error(self) -> None:
        client = MagicMock()
        client.get_account_breaches = AsyncMock(
            side_effect=[
                [Breach(Name="Adobe"), Breach(Name="LinkedIn")],
                NotFoundError("Not found"),
                RateLimitError("Rate limit exceeded after retries"),
                [],
            ]
        )
        progress_calls: list[tuple[int, int, AccountBatchItem]] = []

        results = asyncio.run(
            async_batch_check_accounts(
                [
                    "pwned@example.com",
                    "clean@example.com",
                    "err@example.com",
                    "empty@example.com",
                ],
                client,
                domain="adobe.com",
                include_unverified=False,
                on_progress=lambda idx, total, item: progress_calls.append((idx, total, item)),
            )
        )

        assert results == [
            AccountBatchItem(
                account="pwned@example.com",
                breaches=["Adobe", "LinkedIn"],
                status="pwned",
            ),
            AccountBatchItem(account="clean@example.com", breaches=[], status="clean"),
            AccountBatchItem(
                account="err@example.com",
                breaches=[],
                status="error",
                error="Rate limit exceeded after retries",
            ),
            AccountBatchItem(account="empty@example.com", breaches=[], status="clean"),
        ]
        assert progress_calls == [
            (1, 4, results[0]),
            (2, 4, results[1]),
            (3, 4, results[2]),
            (4, 4, results[3]),
        ]
        assert client.get_account_breaches.call_args_list == [
            call("pwned@example.com", truncate=True, domain="adobe.com", include_unverified=False),
            call("clean@example.com", truncate=True, domain="adobe.com", include_unverified=False),
            call("err@example.com", truncate=True, domain="adobe.com", include_unverified=False),
            call("empty@example.com", truncate=True, domain="adobe.com", include_unverified=False),
        ]

    def test_rpm_sleeps_only_between_requests(self) -> None:
        client = MagicMock()
        events: list[str] = []

        async def fake_check(account: str, **kwargs: object) -> list[Breach]:
            _ = kwargs
            events.append(f"req:{account}")
            return []

        async def fake_sleep(secs: float) -> None:
            events.append(f"sleep:{secs}")

        client.get_account_breaches = AsyncMock(side_effect=fake_check)

        asyncio.run(
            async_batch_check_accounts(
                ["a@example.com", "b@example.com", "c@example.com"],
                client,
                rpm=30,
                sleep=fake_sleep,
            )
        )

        assert events == [
            "req:a@example.com",
            "sleep:2.0",
            "req:b@example.com",
            "sleep:2.0",
            "req:c@example.com",
        ]

    def test_single_account_with_rpm_does_not_sleep(self) -> None:
        client = MagicMock()
        client.get_account_breaches = AsyncMock(return_value=[])
        sleep = AsyncMock()

        asyncio.run(async_batch_check_accounts(["only@example.com"], client, rpm=60, sleep=sleep))

        sleep.assert_not_awaited()

    def test_rpm_none_does_not_sleep(self) -> None:
        client = MagicMock()
        client.get_account_breaches = AsyncMock(return_value=[])
        client.get_subscription_status = AsyncMock()
        sleep = AsyncMock()

        asyncio.run(
            async_batch_check_accounts(
                ["a@example.com", "b@example.com"], client, rpm=None, sleep=sleep
            )
        )

        sleep.assert_not_awaited()
        client.get_subscription_status.assert_not_awaited()

    def test_auto_rpm_queries_subscription_when_rpm_omitted(self) -> None:
        client = MagicMock()
        client.get_subscription_status = AsyncMock(
            return_value=Subscription.model_validate(
                {
                    "SubscriptionName": "Pwned 1",
                    "Description": "Desc",
                    "SubscribedUntil": "2027-01-01T00:00:00Z",
                    "Rpm": 120,
                    "DomainSearchMaxBreachedAccounts": 0,
                    "IncludesStealerLogs": False,
                }
            )
        )
        client.get_account_breaches = AsyncMock(return_value=[])
        sleep = AsyncMock()

        asyncio.run(
            async_batch_check_accounts(
                ["a@example.com", "b@example.com"],
                client,
                auto_rpm=True,
                sleep=sleep,
            )
        )

        client.get_subscription_status.assert_awaited_once()
        sleep.assert_awaited_once_with(0.5)

    def test_auto_rpm_skips_subscription_for_single_account(self) -> None:
        client = MagicMock()
        client.get_account_breaches = AsyncMock(return_value=[])
        client.get_subscription_status = AsyncMock()
        sleep = AsyncMock()

        asyncio.run(
            async_batch_check_accounts(["only@example.com"], client, auto_rpm=True, sleep=sleep)
        )

        client.get_subscription_status.assert_not_awaited()
        sleep.assert_not_awaited()

    def test_auto_rpm_falls_back_on_hibp_error(self) -> None:
        client = MagicMock()
        client.get_subscription_status = AsyncMock(side_effect=HIBPError("HTTP 500"))
        client.get_account_breaches = AsyncMock(return_value=[])
        sleep = AsyncMock()

        results = asyncio.run(
            async_batch_check_accounts(
                ["a@example.com", "b@example.com"],
                client,
                auto_rpm=True,
                sleep=sleep,
            )
        )

        assert len(results) == 2
        sleep.assert_not_awaited()

    def test_auto_rpm_ignores_non_positive_subscription_rpm(self) -> None:
        client = MagicMock()
        client.get_subscription_status = AsyncMock(
            return_value=Subscription.model_validate(
                {
                    "SubscriptionName": "Custom",
                    "Description": "Desc",
                    "SubscribedUntil": "2027-01-01T00:00:00Z",
                    "Rpm": 0,
                    "DomainSearchMaxBreachedAccounts": 0,
                    "IncludesStealerLogs": False,
                }
            )
        )
        client.get_account_breaches = AsyncMock(return_value=[])
        sleep = AsyncMock()

        asyncio.run(
            async_batch_check_accounts(
                ["a@example.com", "b@example.com"],
                client,
                auto_rpm=True,
                sleep=sleep,
            )
        )

        sleep.assert_not_awaited()

    def test_with_real_async_hibp_client_and_httpx_mock(self, httpx_mock: HTTPXMock) -> None:
        base = "https://haveibeenpwned.com/api/v3"
        httpx_mock.add_response(
            url=f"{base}/breachedaccount/pwned%40example.com",
            json=[{"Name": "Adobe"}],
        )
        httpx_mock.add_response(
            url=f"{base}/breachedaccount/clean%40example.com",
            status_code=404,
        )
        sleep = AsyncMock()

        async def _run() -> list[AccountBatchItem]:
            async with AsyncHIBPClient(api_key="testkey", user_agent="test") as client:
                return await async_batch_check_accounts(
                    ["pwned@example.com", "clean@example.com"],
                    client,
                    rpm=60,
                    sleep=sleep,
                )

        results = asyncio.run(_run())

        assert results == [
            AccountBatchItem(account="pwned@example.com", breaches=["Adobe"], status="pwned"),
            AccountBatchItem(account="clean@example.com", breaches=[], status="clean"),
        ]
        sleep.assert_awaited_once_with(1.0)
