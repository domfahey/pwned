"""End-to-end tests exercising CLI commands against the live HIBP API.

Uses the test API key and test accounts documented at
https://haveibeenpwned.com/API/v3#TestAccounts

Note: The test API key only supports breachedaccount lookups on the
hibp-integration-tests.com domain. The stealer logs, pastes, domain search,
and subscription API endpoints require a real key and are not directly
exercised here (though some tests verify breachedaccount lookups for accounts
associated with stealer logs or subscription-free breaches).
"""

from __future__ import annotations

import json
import os
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from pwned.cli import cli

TEST_KEY = "00000000000000000000000000000000"
DOMAIN = "hibp-integration-tests.com"

pytestmark = pytest.mark.integration


def _run(*args: str) -> tuple[int, str]:
    """Invoke CLI and return (exit_code, output).

    Overrides HIBP env vars so only explicit --api-key is used
    and a consistent User-Agent is set.
    """
    runner = CliRunner()
    env_override = {"HIBP_API_KEY": "", "HIBP_USER_AGENT": "pwned-e2e-test"}
    with patch.dict(os.environ, env_override):
        result = runner.invoke(cli, list(args))
    return result.exit_code, result.output


def _run_ok(*args: str) -> str:
    """Invoke CLI, assert success, return output."""
    code, out = _run(*args)
    assert code == 0, f"exit {code}:\n{out}"
    return out


def _run_json(*args: str) -> object:
    """Invoke CLI with --json, assert success, return parsed JSON."""
    out = _run_ok("--json", *args)
    return json.loads(out)


def _run_fail(*args: str) -> str:
    """Invoke CLI, assert non-zero exit, return output."""
    code, out = _run(*args)
    assert code != 0, f"Expected failure but got exit 0:\n{out}"
    return out


# ── Public endpoints (no auth) ───────────────────────────────────────


class TestBreachCommand:
    def test_breach_by_name(self) -> None:
        out = _run_ok("breach", "Adobe")
        assert "Adobe" in out
        assert "adobe.com" in out

    def test_breach_json(self) -> None:
        data = _run_json("breach", "Adobe")
        assert isinstance(data, dict)
        assert data["Name"] == "Adobe"
        assert data["Domain"] == "adobe.com"
        assert isinstance(data["DataClasses"], list)

    def test_breach_not_found(self) -> None:
        out = _run_fail("breach", "ZzzNonExistentBreach999")
        assert "Not found" in out

    def test_breach_sarif(self) -> None:
        out = _run_ok("--format", "sarif", "breach", "Adobe")
        doc = json.loads(out)
        assert doc["version"] == "2.1.0"
        assert len(doc["runs"]) == 1
        assert len(doc["runs"][0]["results"]) >= 1


class TestBreachesCommand:
    def test_list_all(self) -> None:
        out = _run_ok("breaches")
        assert "Adobe" in out

    def test_list_json(self) -> None:
        data = _run_json("breaches")
        assert isinstance(data, list)
        assert len(data) > 100
        names = {b["Name"] for b in data}
        assert "Adobe" in names

    def test_filter_by_domain(self) -> None:
        data = _run_json("breaches", "--domain", "adobe.com")
        assert isinstance(data, list)
        assert all(b["Domain"] == "adobe.com" for b in data)

    def test_spam_list_filter(self) -> None:
        data = _run_json("breaches", "--spam-list")
        assert isinstance(data, list)
        assert all(b["IsSpamList"] is True for b in data)

    def test_exclude_unverified_filter(self) -> None:
        data = _run_json("breaches", "--no-include-unverified")
        assert isinstance(data, list)
        assert len(data) > 0
        assert all(b["IsVerified"] is True for b in data)


class TestLatestBreachCommand:
    def test_latest(self) -> None:
        out = _run_ok("latest-breach")
        assert "Name:" in out

    def test_latest_json(self) -> None:
        data = _run_json("latest-breach")
        assert isinstance(data, dict)
        assert "Name" in data
        assert "AddedDate" in data


class TestDataclassesCommand:
    def test_list(self) -> None:
        out = _run_ok("dataclasses")
        assert "Email addresses" in out
        assert "Passwords" in out

    def test_json(self) -> None:
        data = _run_json("dataclasses")
        assert isinstance(data, list)
        assert "Email addresses" in data
        assert "Passwords" in data

    def test_descriptions_text(self) -> None:
        out = _run_ok("dataclasses", "--descriptions")
        assert "Email addresses" in out
        assert "description:" in out

    def test_descriptions_json(self) -> None:
        data = _run_json("dataclasses", "--descriptions")
        assert isinstance(data, list)
        assert len(data) > 0
        assert all(
            isinstance(item, dict) and "name" in item and "description" in item for item in data
        )
        assert any(item["name"] == "Email addresses" and item["description"] for item in data)

    def test_table_format(self) -> None:
        out = _run_ok("--format", "table", "dataclasses")
        assert "Value" in out
        assert "---" in out
        assert "Email addresses" in out

    def test_csv_format(self) -> None:
        out = _run_ok("--format", "csv", "dataclasses")
        lines = out.splitlines()
        assert lines[0] == "value"
        assert "Email addresses" in lines


# ── Account breaches (test API key) ──────────────────────────────────


class TestAccountCommand:
    def test_account_exists_truncated(self) -> None:
        out = _run_ok("--api-key", TEST_KEY, "account", f"account-exists@{DOMAIN}")
        assert "Name:" in out

    def test_account_exists_json_truncated(self) -> None:
        data = _run_json("--api-key", TEST_KEY, "account", f"account-exists@{DOMAIN}")
        assert isinstance(data, list)
        assert len(data) >= 1
        assert "Name" in data[0]

    def test_account_exists_full(self) -> None:
        data = _run_json(
            "--api-key", TEST_KEY, "account", f"account-exists@{DOMAIN}", "--no-truncate"
        )
        assert isinstance(data, list)
        breach = data[0]
        assert "Name" in breach
        assert "Domain" in breach
        assert "DataClasses" in breach

    def test_multiple_breaches(self) -> None:
        data = _run_json("--api-key", TEST_KEY, "account", f"multiple-breaches@{DOMAIN}")
        assert isinstance(data, list)
        assert len(data) >= 3

    def test_spam_list_only(self) -> None:
        data = _run_json(
            "--api-key", TEST_KEY, "account", f"spam-list-only@{DOMAIN}", "--no-truncate"
        )
        assert isinstance(data, list)
        assert len(data) == 1
        assert data[0]["IsSpamList"] is True

    def test_spam_list_and_others(self) -> None:
        data = _run_json("--api-key", TEST_KEY, "account", f"spam-list-and-others@{DOMAIN}")
        assert isinstance(data, list)
        assert len(data) > 1

    def test_unverified_breach_included_by_default(self) -> None:
        data = _run_json("--api-key", TEST_KEY, "account", f"unverified-breach@{DOMAIN}")
        assert isinstance(data, list)
        assert len(data) >= 1

    def test_unverified_breach_excluded(self) -> None:
        out = _run_fail(
            "--api-key",
            TEST_KEY,
            "account",
            f"unverified-breach@{DOMAIN}",
            "--no-include-unverified",
        )
        assert "Not found" in out

    def test_opt_out_not_found(self) -> None:
        out = _run_fail("--api-key", TEST_KEY, "account", f"opt-out@{DOMAIN}")
        assert "Not found" in out

    def test_opt_out_breach_not_found(self) -> None:
        out = _run_fail("--api-key", TEST_KEY, "account", f"opt-out-breach@{DOMAIN}")
        assert "Not found" in out

    def test_paste_sensitive_breach_not_found(self) -> None:
        out = _run_fail("--api-key", TEST_KEY, "account", f"paste-sensitive-breach@{DOMAIN}")
        assert "Not found" in out

    def test_permanent_opt_out_not_found(self) -> None:
        out = _run_fail("--api-key", TEST_KEY, "account", f"permanent-opt-out@{DOMAIN}")
        assert "Not found" in out

    def test_sensitive_breach_hidden(self) -> None:
        """Sensitive-only breach returns 404 via the public API."""
        out = _run_fail("--api-key", TEST_KEY, "account", f"sensitive-breach@{DOMAIN}")
        assert "Not found" in out

    def test_sensitive_and_other_breaches(self) -> None:
        """Returns non-sensitive breaches; sensitive ones are hidden."""
        data = _run_json("--api-key", TEST_KEY, "account", f"sensitive-and-other-breaches@{DOMAIN}")
        assert isinstance(data, list)
        assert len(data) >= 2

    def test_not_active_breach_returns_nothing(self) -> None:
        out = _run_fail("--api-key", TEST_KEY, "account", f"not-active-breach@{DOMAIN}")
        assert "Not found" in out

    def test_not_active_and_active_breach(self) -> None:
        data = _run_json("--api-key", TEST_KEY, "account", f"not-active-and-active-breach@{DOMAIN}")
        assert isinstance(data, list)
        assert len(data) == 1
        assert data[0]["Name"] == "Adobe"

    def test_subscription_free_breach_not_visible_with_test_key(self) -> None:
        """Subscription-free breach is not returned with the test API key."""
        out = _run_fail("--api-key", TEST_KEY, "account", f"subscription-free-breach@{DOMAIN}")
        assert "Not found" in out

    def test_subscription_free_and_other_breaches(self) -> None:
        """Only the non-subscription-free breaches are returned with test key."""
        data = _run_json(
            "--api-key",
            TEST_KEY,
            "account",
            f"subscription-free-and-other-breaches@{DOMAIN}",
        )
        assert isinstance(data, list)
        assert len(data) >= 2

    def test_stealer_log_account(self) -> None:
        data = _run_json("--api-key", TEST_KEY, "account", f"stealer-log@{DOMAIN}")
        assert isinstance(data, list)
        assert len(data) >= 1

    def test_api_key_after_subcommand(self) -> None:
        """Global --api-key works when placed after the subcommand name."""
        data = _run_json("account", f"account-exists@{DOMAIN}", "--api-key", TEST_KEY)
        assert isinstance(data, list)
        assert len(data) >= 1

    def test_json_flag_after_subcommand(self) -> None:
        """Global --json works when placed after the subcommand name."""
        code, out = _run("--api-key", TEST_KEY, "account", f"account-exists@{DOMAIN}", "--json")
        assert code == 0
        data = json.loads(out)
        assert isinstance(data, list)

    def test_account_sarif(self) -> None:
        out = _run_ok(
            "--format",
            "sarif",
            "--api-key",
            TEST_KEY,
            "account",
            f"account-exists@{DOMAIN}",
        )
        doc = json.loads(out)
        assert doc["version"] == "2.1.0"
        assert len(doc["runs"]) == 1
        assert len(doc["runs"][0]["results"]) >= 1

    def test_account_fail_if_pwned_exits_one(self) -> None:
        code, out = _run(
            "--api-key",
            TEST_KEY,
            "account",
            f"account-exists@{DOMAIN}",
            "--fail-if-pwned",
        )
        assert code == 1
        assert "Name:" in out

    def test_account_fail_if_pwned_clean_exits_zero(self) -> None:
        code, out = _run(
            "--api-key",
            TEST_KEY,
            "account",
            f"opt-out@{DOMAIN}",
            "--fail-if-pwned",
        )
        assert code == 0
        assert "Clean" in out


# ── Password command (free, no auth) ─────────────────────────────────


class TestPasswordCommand:
    def test_known_pwned(self) -> None:
        out = _run_ok("password", "password")
        assert "found" in out.lower()
        assert "times" in out.lower()

    def test_known_pwned_json(self) -> None:
        data = _run_json("password", "password")
        assert isinstance(data, dict)
        assert "password" not in data
        assert data["count"] > 0

    def test_strong_password_not_found(self) -> None:
        out = _run_ok("password", "xK9#mL2$vQ7@nR4!pW8&jF5*hT3^bY6")
        assert "not found" in out.lower()

    def test_ntlm_mode(self) -> None:
        data = _run_json("password", "password", "--ntlm")
        assert isinstance(data, dict)
        assert data["count"] > 0

    def test_padding(self) -> None:
        data = _run_json("password", "password", "--pad")
        assert isinstance(data, dict)
        assert data["count"] > 0

    def test_ntlm_with_padding(self) -> None:
        data = _run_json("password", "password", "--ntlm", "--pad")
        assert isinstance(data, dict)
        assert data["count"] > 0

    @pytest.mark.parametrize("pw", ["123456", "qwerty", "letmein"])
    def test_common_passwords(self, pw: str) -> None:
        """Spot-check several known-pwned passwords."""
        data = _run_json("password", pw)
        assert isinstance(data, dict)
        assert data["count"] > 0, f"Expected {pw!r} to be pwned"

    def test_strong_password_json(self) -> None:
        data = _run_json("password", "xK9#mL2$vQ7@nR4!pW8&jF5*hT3^bY6")
        assert isinstance(data, dict)
        assert data["count"] == 0

    def test_fail_if_pwned_exits_one(self) -> None:
        code, out = _run("password", "password", "--fail-if-pwned")
        assert code == 1
        assert "found" in out.lower()

    def test_fail_if_pwned_strong_exits_zero(self) -> None:
        code, out = _run("password", "xK9#mL2$vQ7@nR4!pW8&jF5*hT3^bY6", "--fail-if-pwned")
        assert code == 0
        assert "not found" in out.lower()


# ── Error handling ───────────────────────────────────────────────────


class TestErrorHandling:
    def test_no_api_key_for_account(self) -> None:
        """Account lookup without any API key fails with auth error."""
        out = _run_fail("account", f"account-exists@{DOMAIN}")
        assert "API key" in out or "Unauthorized" in out
