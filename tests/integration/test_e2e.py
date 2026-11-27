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

import hashlib
import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from pwned._parsers import _md4
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


def _run_exit(expected_code: int, *args: str) -> str:
    """Invoke CLI, assert expected exit code, return output."""
    code, out = _run(*args)
    assert code == expected_code, f"Expected exit {expected_code} but got {code}:\n{out}"
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
        out = _run_exit(9, "breach", "ZzzNonExistentBreach999")
        assert "Not found" in out

    def test_breach_sarif(self) -> None:
        out = _run_ok("--format", "sarif", "breach", "Adobe")
        doc = json.loads(out)
        assert doc["version"] == "2.1.0"
        assert len(doc["runs"]) == 1
        assert len(doc["runs"][0]["results"]) >= 1

    def test_outfile_and_force(self, tmp_path: Path) -> None:
        out_file = tmp_path / "adobe.json"
        runner = CliRunner()
        env_override = {"HIBP_API_KEY": "", "HIBP_USER_AGENT": "pwned-e2e-test"}
        with patch.dict(os.environ, env_override):
            first = runner.invoke(
                cli,
                ["--json", "--outfile", str(out_file), "breach", "Adobe"],
            )
            assert first.exit_code == 0, first.output
            assert first.stdout == ""
            assert json.loads(out_file.read_text(encoding="utf-8"))["Name"] == "Adobe"

            second = runner.invoke(
                cli,
                ["--json", "--outfile", str(out_file), "breach", "Adobe"],
            )
            assert second.exit_code == 7, second.output

            third = runner.invoke(
                cli,
                ["--json", "--outfile", str(out_file), "--force", "breach", "Adobe"],
            )
            assert third.exit_code == 0, third.output
            assert third.stdout == ""
            assert json.loads(out_file.read_text(encoding="utf-8"))["Name"] == "Adobe"


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

    def test_client_side_filter_and_sort(self) -> None:
        data = _run_json(
            "breaches",
            "--since",
            "2020-01-01",
            "--verified-only",
            "--exclude-retired",
            "--sort",
            "pwn-count",
        )
        assert isinstance(data, list)
        assert len(data) > 0
        assert all(b["BreachDate"] >= "2020-01-01" for b in data)
        assert all(b["IsVerified"] is True for b in data)
        assert all(b["IsRetired"] is False for b in data)
        counts = [b["PwnCount"] for b in data]
        assert counts == sorted(counts, reverse=True)


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

    def test_dataclasses_with_cache(self, tmp_path: Path) -> None:
        with patch.dict(os.environ, {"XDG_CACHE_HOME": str(tmp_path)}):
            first = _run_json("--cache", "dataclasses")
            cache_files = list((tmp_path / "pwned").glob("*.json"))
            assert len(cache_files) >= 1
            mtime_before = cache_files[0].stat().st_mtime_ns
            second = _run_json("--cache", "dataclasses")
            assert cache_files[0].stat().st_mtime_ns == mtime_before
        assert first == second


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

    def test_account_domain_filter(self) -> None:
        data = _run_json(
            "--api-key",
            TEST_KEY,
            "account",
            f"multiple-breaches@{DOMAIN}",
            "--domain",
            "adobe.com",
        )
        assert data == [{"Name": "Adobe"}]

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
        out = _run_ok(
            "--api-key",
            TEST_KEY,
            "account",
            f"unverified-breach@{DOMAIN}",
            "--no-include-unverified",
        )
        assert "Clean" in out

    def test_opt_out_not_found(self) -> None:
        out = _run_ok("--api-key", TEST_KEY, "account", f"opt-out@{DOMAIN}")
        assert "Clean" in out
        assert _run_json("--api-key", TEST_KEY, "account", f"opt-out@{DOMAIN}") == []

    def test_opt_out_breach_not_found(self) -> None:
        out = _run_ok("--api-key", TEST_KEY, "account", f"opt-out-breach@{DOMAIN}")
        assert "Clean" in out

    def test_paste_sensitive_breach_not_found(self) -> None:
        out = _run_ok("--api-key", TEST_KEY, "account", f"paste-sensitive-breach@{DOMAIN}")
        assert "Clean" in out

    def test_permanent_opt_out_not_found(self) -> None:
        out = _run_ok("--api-key", TEST_KEY, "account", f"permanent-opt-out@{DOMAIN}")
        assert "Clean" in out

    def test_sensitive_breach_hidden(self) -> None:
        """Sensitive-only breach returns 404 via the public API -> clean exit 0."""
        out = _run_ok("--api-key", TEST_KEY, "account", f"sensitive-breach@{DOMAIN}")
        assert "Clean" in out

    def test_sensitive_and_other_breaches(self) -> None:
        """Returns non-sensitive breaches; sensitive ones are hidden."""
        data = _run_json("--api-key", TEST_KEY, "account", f"sensitive-and-other-breaches@{DOMAIN}")
        assert isinstance(data, list)
        assert len(data) >= 2

    def test_not_active_breach_returns_nothing(self) -> None:
        out = _run_ok("--api-key", TEST_KEY, "account", f"not-active-breach@{DOMAIN}")
        assert "Clean" in out

    def test_not_active_and_active_breach(self) -> None:
        data = _run_json("--api-key", TEST_KEY, "account", f"not-active-and-active-breach@{DOMAIN}")
        assert isinstance(data, list)
        assert len(data) == 1
        assert data[0]["Name"] == "Adobe"

    def test_subscription_free_breach_not_visible_with_test_key(self) -> None:
        """Subscription-free breach is not returned with the test API key -> clean exit 0."""
        out = _run_ok("--api-key", TEST_KEY, "account", f"subscription-free-breach@{DOMAIN}")
        assert "Clean" in out

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

    def test_account_fail_if_pwned_exits_eight(self) -> None:
        code, out = _run(
            "--api-key",
            TEST_KEY,
            "account",
            f"account-exists@{DOMAIN}",
            "--fail-if-pwned",
        )
        assert code == 8
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

    def test_account_full_and_fail_if_found_aliases(self) -> None:
        code, out = _run(
            "--json",
            "--api-key",
            TEST_KEY,
            "account",
            f"account-exists@{DOMAIN}",
            "--full",
            "--fail-if-found",
        )
        assert code == 8, out
        data = json.loads(out)
        assert isinstance(data, list)
        assert len(data) >= 1
        assert "Domain" in data[0]
        assert "DataClasses" in data[0]

    def test_account_markdown_and_html(self) -> None:
        md = _run_ok(
            "--format",
            "markdown",
            "--api-key",
            TEST_KEY,
            "account",
            f"account-exists@{DOMAIN}",
        )
        assert "|" in md
        assert "Adobe" in md

        html = _run_ok(
            "--format",
            "html",
            "--api-key",
            TEST_KEY,
            "account",
            f"account-exists@{DOMAIN}",
        )
        assert "<!DOCTYPE html>" in html
        assert "Have I Been Pwned" in html

    def test_account_baseline_save_and_diff(self, tmp_path: Path) -> None:
        baseline = tmp_path / "baseline.json"
        _run_ok(
            "--api-key",
            TEST_KEY,
            "account",
            f"account-exists@{DOMAIN}",
            "--save-baseline",
            str(baseline),
        )
        assert baseline.exists()

        code, out = _run(
            "--json",
            "--api-key",
            TEST_KEY,
            "account",
            f"account-exists@{DOMAIN}",
            "--baseline",
            str(baseline),
            "--fail-if-pwned",
        )
        assert code == 0
        assert json.loads(out) == []


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

    def test_no_padding(self) -> None:
        data = _run_json("password", "password", "--no-pad")
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

    def test_fail_if_pwned_exits_eight(self) -> None:
        code, out = _run("password", "password", "--fail-if-pwned")
        assert code == 8
        assert "found" in out.lower()

    def test_fail_if_pwned_strong_exits_zero(self) -> None:
        code, out = _run("password", "xK9#mL2$vQ7@nR4!pW8&jF5*hT3^bY6", "--fail-if-pwned")
        assert code == 0
        assert "not found" in out.lower()

    def test_hashed_sha1_and_ntlm(self) -> None:
        sha1_hex = hashlib.sha1(b"password").hexdigest().upper()
        ntlm_hex = _md4("password".encode("utf-16-le")).upper()
        sha1_data = _run_json("password", sha1_hex, "--hashed")
        ntlm_data = _run_json("password", ntlm_hex, "--hashed", "--ntlm")
        assert isinstance(sha1_data, dict) and sha1_data["count"] > 0
        assert isinstance(ntlm_data, dict) and ntlm_data["count"] > 0

    def test_file_batch_with_stats(self, tmp_path: Path) -> None:
        pw_file = tmp_path / "passwords.txt"
        pw_file.write_text("password\nxK9#mL2$vQ7@nR4!pW8&jF5*hT3^bY6\n", encoding="utf-8")
        runner = CliRunner()
        env_override = {"HIBP_API_KEY": "", "HIBP_USER_AGENT": "pwned-e2e-test"}
        with patch.dict(os.environ, env_override):
            result = runner.invoke(cli, ["--json", "password", "--file", str(pw_file), "--stats"])
        assert result.exit_code == 0, result.output
        data = json.loads(result.stdout)
        assert isinstance(data, list)
        assert len(data) == 2
        assert data[0]["pwn_count"] > 0
        assert data[0]["status"] == "pwned"
        assert data[1]["pwn_count"] == 0
        assert data[1]["status"] == "clean"
        assert "pwned" in result.stderr.lower()

    def test_range_cache(self, tmp_path: Path) -> None:
        with patch.dict(os.environ, {"XDG_CACHE_HOME": str(tmp_path)}):
            first = _run_json("--cache", "password", "password")
            cache_files = list((tmp_path / "pwned").glob("*.json"))
            assert len(cache_files) >= 1
            mtime_before = cache_files[0].stat().st_mtime_ns
            second = _run_json("--cache", "password", "password")
            assert cache_files[0].stat().st_mtime_ns == mtime_before
        assert isinstance(first, dict) and first["count"] > 0
        assert first == second


class TestPasswordRangeCommand:
    def test_password_range_sha1_and_alias(self) -> None:
        hex_upper = frozenset("0123456789ABCDEF")
        pw_suffix = "1E4C9B93F3F0682250B6CF8331B7EE68FD8"
        for cmd in ("password-range", "pr"):
            data = _run_json(cmd, "5BAA6")
            assert isinstance(data, dict)
            assert len(data) > 0
            assert all(
                isinstance(k, str)
                and len(k) == 35
                and set(k) <= hex_upper
                and isinstance(v, int)
                and not isinstance(v, bool)
                and v > 0
                for k, v in data.items()
            )
            assert pw_suffix in data
            assert data[pw_suffix] > 0

    def test_password_range_ntlm_and_fail_if_found(self) -> None:
        code, out = _run("--json", "password-range", "8846F", "--ntlm", "--fail-if-found")
        assert code == 8, out
        data = json.loads(out)
        assert isinstance(data, dict)
        assert len(data) > 0

    def test_password_range_invalid_prefix_exits_two(self) -> None:
        _run_exit(2, "password-range", "ZZZZZ")


# ── Audit & MCP commands (free, no auth) ─────────────────────────────


class TestAuditCommand:
    def test_audit_csv_reuse_and_strength(self, tmp_path: Path) -> None:
        vault = tmp_path / "vault.csv"
        vault.write_text(
            "name,username,password,url\n"
            "SiteA,alice@example.com,password,https://a.example\n"
            "SiteB,bob@example.com,password,https://b.example\n"
            "SiteC,carol@example.com,xK9#mL2$vQ7@nR4!pW8&jF5*hT3^bY6,https://c.example\n",
            encoding="utf-8",
        )
        code, out = _run(
            "--json",
            "audit",
            str(vault),
            "--source",
            "csv",
            "--check-reuse",
            "--check-strength",
            "--fail-if-pwned",
        )
        assert code == 8
        data = json.loads(out)
        assert data["total_entries"] == 3
        assert data["compromised_entries"] == 2
        assert len(data["reused_groups"]) == 1
        assert data["reused_groups"][0]["count"] == 2
        assert data["weak_entries"] >= 2
        assert data["risk_score"] is not None

    def test_audit_pwdump_ntlm(self, tmp_path: Path) -> None:
        ntlm_pw = _md4("password".encode("utf-16-le")).lower()
        empty_lm = "aad3b435b51404eeaad3b435b51404ee"
        dump = tmp_path / "ntds.pwdump"
        dump.write_text(
            f"CORP\\alice:1001:{empty_lm}:{ntlm_pw}:::\nCORP\\bob:1002:{empty_lm}:{ntlm_pw}:::\n",
            encoding="utf-8",
        )
        code, out = _run(
            "--json",
            "audit",
            str(dump),
            "--source",
            "pwdump",
            "--check-reuse",
            "--fail-if-pwned",
        )
        assert code == 8
        data = json.loads(out)
        assert data["total_entries"] == 2
        assert data["compromised_entries"] == 2
        assert len(data["reused_groups"]) == 1


class TestMcpCommand:
    def test_mcp_live_stdio_roundtrip(self) -> None:
        sha1_hex = hashlib.sha1(b"password").hexdigest().upper()
        requests = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "lookup_breach", "arguments": {"name": "Adobe"}},
            },
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "check_password_hash", "arguments": {"hash_hex": sha1_hex}},
            },
        ]
        stdin_payload = "\n".join(json.dumps(req) for req in requests) + "\n"
        runner = CliRunner()
        env_override = {"HIBP_API_KEY": "", "HIBP_USER_AGENT": "pwned-e2e-test"}
        with patch.dict(os.environ, env_override):
            result = runner.invoke(cli, ["mcp"], input=stdin_payload)
        assert result.exit_code == 0, result.output
        responses = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
        assert len(responses) == 3
        assert responses[0]["id"] == 1
        assert responses[0]["result"]["protocolVersion"] == "2024-11-05"

        breach_resp = responses[1]["result"]
        assert breach_resp.get("isError") is not True
        breach_payload = json.loads(breach_resp["content"][0]["text"])
        assert breach_payload["Name"] == "Adobe"

        pw_resp = responses[2]["result"]
        assert pw_resp.get("isError") is not True
        pw_payload = json.loads(pw_resp["content"][0]["text"])
        assert pw_payload["pwned"] is True
        assert pw_payload["count"] > 0


# ── Error handling ───────────────────────────────────────────────────


class TestErrorHandling:
    def test_no_api_key_for_account(self) -> None:
        """Account lookup without any API key fails with auth error (exit 3)."""
        out = _run_exit(3, "account", f"account-exists@{DOMAIN}")
        assert "API key" in out or "Unauthorized" in out

    def test_malformed_api_key_diagnostic(self) -> None:
        out = _run_exit(3, "--api-key", "not-a-valid-key", "account", f"account-exists@{DOMAIN}")
        assert "improperly formed" in out

    def test_invalid_hex_api_key_diagnostic(self) -> None:
        out = _run_exit(
            3,
            "--api-key",
            "11111111111111111111111111111111",
            "account",
            "test@example.com",
        )
        assert "invalid" in out.lower()
