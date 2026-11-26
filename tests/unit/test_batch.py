from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, call

import pytest
from pydantic import ValidationError

from pwned.batch import (
    AccountBatchItem,
    PasswordBatchItem,
    batch_check_accounts,
    batch_check_passwords,
    load_input_file,
    parse_input_lines,
)
from pwned.client import HIBPError, NotFoundError, RateLimitError
from pwned.models import Breach, Subscription


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
