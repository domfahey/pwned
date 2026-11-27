from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from pathlib import Path

import click
import httpx
import pytest
from click.testing import CliRunner
from pytest_httpx import HTTPXMock

import pwned
from pwned.batch import AccountBatchItem, batch_check_accounts
from pwned.cli import cli, handle_errors
from pwned.client import HIBPClient
from pwned.passwords import _ntlm_hash

BASE = "https://haveibeenpwned.com/api/v3"
TEST_KEY = "00000000000000000000000000000000"


def _sha1_parts(password: str) -> tuple[str, str]:
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    return digest[:5], digest[5:]


class TestBreachCommands:
    def test_breach(self, httpx_mock: HTTPXMock, cli_runner: CliRunner) -> None:
        httpx_mock.add_response(
            url=f"{BASE}/breach/Adobe",
            json={"Name": "Adobe", "Title": "Adobe", "Domain": "adobe.com"},
        )
        result = cli_runner.invoke(cli, ["breach", "Adobe"])
        assert result.exit_code == 0
        assert "Adobe" in result.output

    def test_breach_json(self, httpx_mock: HTTPXMock, cli_runner: CliRunner) -> None:
        httpx_mock.add_response(
            url=f"{BASE}/breach/Adobe",
            json={"Name": "Adobe", "Title": "Adobe"},
        )
        result = cli_runner.invoke(cli, ["--json", "breach", "Adobe"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["Name"] == "Adobe"

    def test_breach_strips_html_in_text_output(
        self, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        httpx_mock.add_response(
            url=f"{BASE}/breach/Adobe",
            json={
                "Name": "Adobe",
                "Description": '<em>Encrypted</em> &amp; <a href="https://x.test">details</a>.',
            },
        )
        result = cli_runner.invoke(cli, ["breach", "Adobe"])
        assert result.exit_code == 0
        assert "Encrypted & details." in result.output
        assert "<em>" not in result.output
        assert "<a " not in result.output

    def test_breach_tag_only_description_in_text_output(
        self, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        httpx_mock.add_response(
            url=f"{BASE}/breach/Adobe",
            json={"Name": "Adobe", "Description": "<br/>"},
        )
        result = cli_runner.invoke(cli, ["breach", "Adobe"])
        assert result.exit_code == 0
        assert "  Description: \n" in result.output

    def test_breach_preserves_html_in_json_output(
        self, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        raw_html = "<em>Encrypted</em> &amp; details."
        httpx_mock.add_response(
            url=f"{BASE}/breach/Adobe",
            json={"Name": "Adobe", "Description": raw_html},
        )
        result = cli_runner.invoke(cli, ["--json", "breach", "Adobe"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["Description"] == raw_html

    def test_breaches(self, httpx_mock: HTTPXMock, cli_runner: CliRunner) -> None:
        httpx_mock.add_response(
            url=f"{BASE}/breaches",
            json=[{"Name": "Adobe"}, {"Name": "Gawker"}],
        )
        result = cli_runner.invoke(cli, ["breaches"])
        assert result.exit_code == 0
        assert result.output == "  Name: Adobe\n\n  Name: Gawker\n"

    def test_breaches_empty_text_output(self, httpx_mock: HTTPXMock, cli_runner: CliRunner) -> None:
        httpx_mock.add_response(url=f"{BASE}/breaches", json=[])
        result = cli_runner.invoke(cli, ["breaches"])
        assert result.exit_code == 0
        assert result.output == "No results found.\n"

    def test_breaches_empty_json_output(self, httpx_mock: HTTPXMock, cli_runner: CliRunner) -> None:
        httpx_mock.add_response(url=f"{BASE}/breaches", json=[])
        result = cli_runner.invoke(cli, ["--json", "breaches"])
        assert result.exit_code == 0
        assert json.loads(result.output) == []

    def test_breaches_filters(self, httpx_mock: HTTPXMock, cli_runner: CliRunner) -> None:
        httpx_mock.add_response(json=[{"Name": "Adobe"}])
        result = cli_runner.invoke(cli, ["breaches", "--domain", "adobe.com", "--no-spam-list"])
        assert result.exit_code == 0
        request = httpx_mock.get_request()
        assert request is not None
        assert "domain=adobe.com" in str(request.url)
        assert "isSpamList=false" in str(request.url)

    def test_breaches_spam_list_only(self, httpx_mock: HTTPXMock, cli_runner: CliRunner) -> None:
        httpx_mock.add_response(json=[])
        result = cli_runner.invoke(cli, ["breaches", "--spam-list"])
        assert result.exit_code == 0
        request = httpx_mock.get_request()
        assert request is not None
        assert "isSpamList=true" in str(request.url)

    def test_breaches_no_include_unverified(
        self, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        httpx_mock.add_response(json=[{"Name": "Adobe"}])
        result = cli_runner.invoke(cli, ["breaches", "--no-include-unverified"])
        assert result.exit_code == 0
        assert "Adobe" in result.output
        request = httpx_mock.get_request()
        assert request is not None
        assert "includeUnverified=false" in str(request.url)

    def test_latest_breach(self, httpx_mock: HTTPXMock, cli_runner: CliRunner) -> None:
        httpx_mock.add_response(
            url=f"{BASE}/latestbreach",
            json={"Name": "Latest", "Title": "Latest Breach"},
        )
        result = cli_runner.invoke(cli, ["latest-breach"])
        assert result.exit_code == 0
        assert "Latest" in result.output

    def test_dataclasses(self, httpx_mock: HTTPXMock, cli_runner: CliRunner) -> None:
        httpx_mock.add_response(
            url=f"{BASE}/dataclasses",
            json=["Email addresses", "Passwords"],
        )
        result = cli_runner.invoke(cli, ["dataclasses"])
        assert result.exit_code == 0
        assert "Email addresses" in result.output


class TestAccountCommands:
    def test_account(self, httpx_mock: HTTPXMock, cli_runner: CliRunner) -> None:
        httpx_mock.add_response(json=[{"Name": "Adobe"}])
        result = cli_runner.invoke(
            cli,
            ["--api-key", TEST_KEY, "account", "test@example.com"],
        )
        assert result.exit_code == 0
        assert "Adobe" in result.output

    def test_account_options(self, httpx_mock: HTTPXMock, cli_runner: CliRunner) -> None:
        httpx_mock.add_response(json=[{"Name": "Adobe", "Domain": "adobe.com"}])
        result = cli_runner.invoke(
            cli,
            [
                "--api-key",
                TEST_KEY,
                "account",
                "test@example.com",
                "--no-truncate",
                "--domain",
                "adobe.com",
                "--no-include-unverified",
            ],
        )
        assert result.exit_code == 0
        request = httpx_mock.get_request()
        assert request is not None
        url = str(request.url)
        assert "truncateResponse=false" in url
        assert "domain=adobe.com" in url
        assert "includeUnverified=false" in url

    def test_account_not_found(self, httpx_mock: HTTPXMock, cli_runner: CliRunner) -> None:
        httpx_mock.add_response(status_code=404)
        result = cli_runner.invoke(
            cli,
            ["--api-key", TEST_KEY, "account", "nobody@example.com"],
        )
        assert result.exit_code == 0
        assert "Clean (not found in any breaches)." in result.output

    def test_account_not_found_json(self, httpx_mock: HTTPXMock, cli_runner: CliRunner) -> None:
        httpx_mock.add_response(status_code=404)
        result = cli_runner.invoke(
            cli,
            ["--api-key", TEST_KEY, "--json", "account", "nobody@example.com"],
        )
        assert result.exit_code == 0
        assert json.loads(result.output) == []

    def test_pastes_and_stealer_404_return_clean_exit_zero(
        self, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        httpx_mock.add_response(url=f"{BASE}/pasteaccount/clean%40example.com", status_code=404)
        res_pastes = cli_runner.invoke(cli, ["--api-key", TEST_KEY, "pastes", "clean@example.com"])
        assert res_pastes.exit_code == 0
        assert "Clean (not found in any pastes)." in res_pastes.output

        httpx_mock.add_response(url=f"{BASE}/pasteaccount/clean%40example.com", status_code=404)
        res_pastes_json = cli_runner.invoke(
            cli, ["--api-key", TEST_KEY, "--json", "pastes", "clean@example.com"]
        )
        assert res_pastes_json.exit_code == 0
        assert json.loads(res_pastes_json.output) == []

        httpx_mock.add_response(
            url=f"{BASE}/stealerlogsbyemail/clean%40example.com", status_code=404
        )
        res_se = cli_runner.invoke(
            cli, ["--api-key", TEST_KEY, "stealer", "email", "clean@example.com"]
        )
        assert res_se.exit_code == 0
        assert "Clean (no stealer log records found)." in res_se.output

        httpx_mock.add_response(url=f"{BASE}/stealerlogsbywebsitedomain/clean.com", status_code=404)
        res_sw = cli_runner.invoke(
            cli, ["--api-key", TEST_KEY, "--json", "stealer", "website", "clean.com"]
        )
        assert res_sw.exit_code == 0
        assert json.loads(res_sw.output) == []

        httpx_mock.add_response(url=f"{BASE}/stealerlogsbyemaildomain/clean.com", status_code=404)
        res_sd = cli_runner.invoke(
            cli, ["--api-key", TEST_KEY, "--json", "stealer", "domain", "clean.com"]
        )
        assert res_sd.exit_code == 0
        assert json.loads(res_sd.output) == {}

    def test_account_unauthorized(self, httpx_mock: HTTPXMock, cli_runner: CliRunner) -> None:
        httpx_mock.add_response(status_code=401)
        result = cli_runner.invoke(
            cli,
            ["--api-key", "badkey00000000000000000000000000", "account", "test@example.com"],
        )
        assert result.exit_code == 3
        assert "API key" in result.output

    @pytest.mark.parametrize(
        "argv",
        [
            ["account", "test@example.com"],
            ["domain", "example.com"],
            ["subscribed-domains"],
            ["subscribed-domains", "list"],
            ["subscribed-domains", "remove", "example.com"],
            ["pastes", "test@example.com"],
            ["stealer", "email", "t@e.com"],
            ["stealer", "website", "netflix.com"],
            ["stealer", "domain", "example.com"],
            ["subscription"],
        ],
    )
    def test_authenticated_commands_fail_fast_without_api_key(
        self, cli_runner: CliRunner, argv: list[str]
    ) -> None:
        """Missing API key fails locally without making any HTTP request."""
        result = cli_runner.invoke(cli, argv)
        assert result.exit_code == 3
        assert "API key" in result.output


class TestDomainCommands:
    def test_domain(self, httpx_mock: HTTPXMock, cli_runner: CliRunner) -> None:
        httpx_mock.add_response(json={"alias1": ["Adobe"]})
        result = cli_runner.invoke(
            cli,
            ["--api-key", TEST_KEY, "domain", "example.com"],
        )
        assert result.exit_code == 0
        assert "alias1" in result.output

    def test_domain_empty_dict_text_output(
        self, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        httpx_mock.add_response(json={})
        result = cli_runner.invoke(
            cli,
            ["--api-key", TEST_KEY, "domain", "example.com"],
        )
        assert result.exit_code == 0
        assert result.output == "No results found.\n"

    def test_domain_joins_multiple_breaches_and_empty_list(
        self, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        httpx_mock.add_response(json={"a": ["Adobe", "LinkedIn"], "b": []})
        result = cli_runner.invoke(cli, ["--api-key", TEST_KEY, "domain", "example.com"])
        assert result.exit_code == 0
        assert "  a: Adobe, LinkedIn\n" in result.output
        assert "  b: \n" in result.output

    def test_subscribed_domains(self, httpx_mock: HTTPXMock, cli_runner: CliRunner) -> None:
        httpx_mock.add_response(
            json=[{"DomainName": "example.com", "PwnCount": 100}],
        )
        result = cli_runner.invoke(
            cli,
            ["--api-key", TEST_KEY, "subscribed-domains"],
        )
        assert result.exit_code == 0
        assert "example.com" in result.output

    def test_subscribed_domains_list_subcommand(
        self, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        httpx_mock.add_response(
            url=f"{BASE}/subscribeddomains",
            json=[{"DomainName": "example.com", "PwnCount": 100}],
        )
        result = cli_runner.invoke(
            cli,
            ["--api-key", TEST_KEY, "subscribed-domains", "list"],
        )
        assert result.exit_code == 0
        assert "example.com" in result.output

    def test_subscribed_domains_remove_and_alias(
        self, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        httpx_mock.add_response(
            method="DELETE",
            url=f"{BASE}/subscribeddomains/example.com",
            status_code=200,
        )
        result = cli_runner.invoke(
            cli,
            ["--api-key", TEST_KEY, "--json", "subscribed-domains", "remove", "example.com"],
        )
        assert result.exit_code == 0
        assert json.loads(result.output) == {"domain": "example.com", "removed": True}

        httpx_mock.add_response(
            method="DELETE",
            url=f"{BASE}/subscribeddomains/other.com",
            status_code=200,
        )
        alias_result = cli_runner.invoke(
            cli,
            ["sd", "remove", "other.com", "--api-key", TEST_KEY],
        )
        assert alias_result.exit_code == 0
        assert "other.com" in alias_result.output
        assert "True" in alias_result.output


class TestPastesCommand:
    def test_pastes(self, httpx_mock: HTTPXMock, cli_runner: CliRunner) -> None:
        httpx_mock.add_response(
            json=[{"Source": "Pastebin", "Id": "abc", "EmailCount": 10}],
        )
        result = cli_runner.invoke(
            cli,
            ["--api-key", TEST_KEY, "pastes", "test@example.com"],
        )
        assert result.exit_code == 0
        assert "Pastebin" in result.output

    def test_pastes_fail_if_pwned(self, httpx_mock: HTTPXMock, cli_runner: CliRunner) -> None:
        httpx_mock.add_response(
            json=[{"Source": "Pastebin", "Id": "abc", "EmailCount": 10}],
        )
        res_found = cli_runner.invoke(
            cli,
            ["--api-key", TEST_KEY, "pastes", "test@example.com", "--fail-if-pwned"],
        )
        assert res_found.exit_code == 8
        assert "Pastebin" in res_found.output

        httpx_mock.add_response(status_code=404)
        res_clean = cli_runner.invoke(
            cli,
            ["--api-key", TEST_KEY, "pastes", "clean@example.com", "--fail-if-pwned"],
        )
        assert res_clean.exit_code == 0
        assert "Clean (not found in any pastes)." in res_clean.output


class TestStealerCommands:
    def test_stealer_email(self, httpx_mock: HTTPXMock, cli_runner: CliRunner) -> None:
        httpx_mock.add_response(json=["netflix.com"])
        result = cli_runner.invoke(
            cli,
            ["--api-key", TEST_KEY, "stealer", "email", "t@e.com"],
        )
        assert result.exit_code == 0
        assert "netflix.com" in result.output

    def test_stealer_website(self, httpx_mock: HTTPXMock, cli_runner: CliRunner) -> None:
        httpx_mock.add_response(json=["test@example.com"])
        result = cli_runner.invoke(
            cli,
            ["--api-key", TEST_KEY, "stealer", "website", "netflix.com"],
        )
        assert result.exit_code == 0
        assert "test@example.com" in result.output

    def test_stealer_domain(self, httpx_mock: HTTPXMock, cli_runner: CliRunner) -> None:
        httpx_mock.add_response(json={"andy": ["netflix.com"]})
        result = cli_runner.invoke(
            cli,
            [
                "--api-key",
                TEST_KEY,
                "stealer",
                "domain",
                "example.com",
            ],
        )
        assert result.exit_code == 0
        assert "andy" in result.output

    def test_stealer_fail_if_pwned_found_and_clean(
        self, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        httpx_mock.add_response(json=["netflix.com"])
        res_email = cli_runner.invoke(
            cli, ["--api-key", TEST_KEY, "stealer", "email", "t@e.com", "--fail-if-pwned"]
        )
        assert res_email.exit_code == 8
        assert "netflix.com" in res_email.output

        httpx_mock.add_response(status_code=404)
        res_email_clean = cli_runner.invoke(
            cli, ["--api-key", TEST_KEY, "stealer", "email", "clean@e.com", "--fail-if-pwned"]
        )
        assert res_email_clean.exit_code == 0

        httpx_mock.add_response(json=["test@example.com"])
        res_web = cli_runner.invoke(
            cli, ["--api-key", TEST_KEY, "stealer", "website", "netflix.com", "--fail-if-pwned"]
        )
        assert res_web.exit_code == 8
        assert "test@example.com" in res_web.output

        httpx_mock.add_response(status_code=404)
        res_web_clean = cli_runner.invoke(
            cli, ["--api-key", TEST_KEY, "stealer", "website", "clean.com", "--fail-if-pwned"]
        )
        assert res_web_clean.exit_code == 0

        httpx_mock.add_response(json={"andy": ["netflix.com"]})
        res_dom = cli_runner.invoke(
            cli, ["--api-key", TEST_KEY, "stealer", "domain", "example.com", "--fail-if-pwned"]
        )
        assert res_dom.exit_code == 8
        assert "andy" in res_dom.output

        httpx_mock.add_response(status_code=404)
        res_dom_clean = cli_runner.invoke(
            cli, ["--api-key", TEST_KEY, "stealer", "domain", "clean.com", "--fail-if-pwned"]
        )
        assert res_dom_clean.exit_code == 0

    def test_stealer_group_without_subcommand_shows_help(self, cli_runner: CliRunner) -> None:
        result = cli_runner.invoke(cli, ["stealer"])
        assert "email" in result.output
        assert "website" in result.output
        assert "domain" in result.output


class TestPasswordCommand:
    def test_password_found(self, httpx_mock: HTTPXMock, cli_runner: CliRunner) -> None:
        prefix, suffix = _sha1_parts("password")
        httpx_mock.add_response(
            url=f"https://api.pwnedpasswords.com/range/{prefix}",
            text=f"{suffix}:3861493\n",
        )
        result = cli_runner.invoke(cli, ["password", "password"])
        assert result.exit_code == 0
        assert "3,861,493" in result.output

    def test_password_not_found(self, httpx_mock: HTTPXMock, cli_runner: CliRunner) -> None:
        prefix, _ = _sha1_parts("supersecurepassword123!@#$%")
        httpx_mock.add_response(
            url=f"https://api.pwnedpasswords.com/range/{prefix}",
            text="0018A45C4D1DEF81644B54AB7F969B88D65:1\n",
        )
        result = cli_runner.invoke(cli, ["password", "supersecurepassword123!@#$%"])
        assert result.exit_code == 0
        assert "not found" in result.output

    def test_password_json(self, httpx_mock: HTTPXMock, cli_runner: CliRunner) -> None:
        prefix, suffix = _sha1_parts("password")
        httpx_mock.add_response(
            url=f"https://api.pwnedpasswords.com/range/{prefix}",
            text=f"{suffix}:100\n",
        )
        result = cli_runner.invoke(cli, ["--json", "password", "password"])
        assert result.exit_code == 0
        assert result.output == '{\n  "count": 100\n}\n'
        data = json.loads(result.output)
        assert data["count"] == 100
        assert "password" not in data

    def test_password_from_stdin(self, httpx_mock: HTTPXMock, cli_runner: CliRunner) -> None:
        prefix, suffix = _sha1_parts("password")
        httpx_mock.add_response(
            url=f"https://api.pwnedpasswords.com/range/{prefix}",
            text=f"{suffix}:500\n",
        )
        result = cli_runner.invoke(cli, ["password", "--stdin"], input="password\n")
        assert result.exit_code == 0
        assert "500" in result.output

    def test_password_from_stdin_crlf(self, httpx_mock: HTTPXMock, cli_runner: CliRunner) -> None:
        prefix, suffix = _sha1_parts("password")
        httpx_mock.add_response(
            url=f"https://api.pwnedpasswords.com/range/{prefix}",
            text=f"{suffix}:500\n",
        )
        result = cli_runner.invoke(cli, ["password", "--stdin"], input="password\r\n")
        assert result.exit_code == 0
        assert "500" in result.output

    def test_password_rejects_both_arg_and_stdin(self, cli_runner: CliRunner) -> None:
        result = cli_runner.invoke(cli, ["password", "secret", "--stdin"], input="other\n")
        assert result.exit_code == 2
        assert "Cannot specify both" in result.output

    @pytest.mark.parametrize("stdin_data", ["", "\n", "\r", "\r\n"])
    def test_password_from_stdin_empty_errors(self, cli_runner: CliRunner, stdin_data: str) -> None:
        result = cli_runner.invoke(cli, ["password", "--stdin"], input=stdin_data)
        assert result.exit_code == 2
        assert "No password provided on stdin" in result.output

    def test_password_from_stdin_without_trailing_newline(
        self, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        prefix, suffix = _sha1_parts("password")
        httpx_mock.add_response(
            url=f"https://api.pwnedpasswords.com/range/{prefix}",
            text=f"{suffix}:50\n",
        )
        result = cli_runner.invoke(cli, ["password", "--stdin"], input="password")
        assert result.exit_code == 0
        assert "50" in result.output

    def test_password_ntlm_and_pad_flags(
        self, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        digest = _ntlm_hash("password")
        httpx_mock.add_response(
            url=httpx.URL(
                f"https://api.pwnedpasswords.com/range/{digest[:5]}",
                params={"mode": "ntlm"},
            ),
            text=f"{digest[5:]}:42\n",
        )
        result = cli_runner.invoke(cli, ["password", "--ntlm", "--pad", "password"])
        assert result.exit_code == 0
        assert "42" in result.output
        request = httpx_mock.get_request()
        assert request is not None
        assert request.headers["add-padding"] == "true"

    def test_password_pads_by_default_and_respects_no_pad(
        self, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        prefix, suffix = _sha1_parts("password")
        httpx_mock.add_response(
            url=f"https://api.pwnedpasswords.com/range/{prefix}",
            text=f"{suffix}:7\n",
        )
        res_default = cli_runner.invoke(cli, ["password", "password"])
        assert res_default.exit_code == 0
        req_default = httpx_mock.get_requests()[-1]
        assert req_default.headers["add-padding"] == "true"

        httpx_mock.add_response(
            url=f"https://api.pwnedpasswords.com/range/{prefix}",
            text=f"{suffix}:7\n",
        )
        res_no_pad = cli_runner.invoke(cli, ["password", "--no-pad", "password"])
        assert res_no_pad.exit_code == 0
        req_no_pad = httpx_mock.get_requests()[-1]
        assert "add-padding" not in req_no_pad.headers

    def test_password_json_not_found(self, httpx_mock: HTTPXMock, cli_runner: CliRunner) -> None:
        prefix, _ = _sha1_parts("unique-pw")
        httpx_mock.add_response(
            url=f"https://api.pwnedpasswords.com/range/{prefix}",
            text="",
        )
        result = cli_runner.invoke(cli, ["--json", "password", "unique-pw"])
        assert result.exit_code == 0
        assert json.loads(result.output) == {"count": 0}

    def test_password_http_error_through_cli(
        self, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        prefix, _ = _sha1_parts("password")
        httpx_mock.add_response(
            url=f"https://api.pwnedpasswords.com/range/{prefix}",
            status_code=500,
        )
        result = cli_runner.invoke(cli, ["password", "password"])
        assert result.exit_code == 6
        assert "Error: HTTP 500" in result.output

    def test_password_interactive_prompt(
        self, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        prefix, suffix = _sha1_parts("password")
        httpx_mock.add_response(
            url=f"https://api.pwnedpasswords.com/range/{prefix}",
            text=f"{suffix}:999\n",
        )
        result = cli_runner.invoke(cli, ["--json", "password"], input="password\n")
        assert result.exit_code == 0
        assert "Password:" in result.stderr
        assert json.loads(result.stdout) == {"count": 999}


class TestSubscriptionCommand:
    def test_subscription(self, httpx_mock: HTTPXMock, cli_runner: CliRunner) -> None:
        httpx_mock.add_response(
            json={
                "SubscriptionName": "Pwned 1",
                "Description": "test",
                "SubscribedUntil": "2025-12-31T23:59:59Z",
                "Rpm": 10,
                "DomainSearchMaxBreachedAccounts": 25,
                "IncludesStealerLogs": False,
            },
        )
        result = cli_runner.invoke(
            cli,
            ["--api-key", TEST_KEY, "subscription"],
        )
        assert result.exit_code == 0
        assert "Pwned 1" in result.output


class TestErrorHandling:
    def test_rate_limit_error_through_cli(
        self, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        for _ in range(4):
            httpx_mock.add_response(
                url=f"{BASE}/breaches",
                status_code=429,
                headers={"retry-after": "0"},
            )
        result = cli_runner.invoke(cli, ["breaches"])
        assert result.exit_code == 5
        assert "Error:" in result.output

    def test_network_error_handled_gracefully(
        self, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        httpx_mock.add_exception(httpx.ConnectError("dns failure"), url=f"{BASE}/breaches")
        result = cli_runner.invoke(cli, ["breaches"])
        assert result.exit_code == 6
        assert "Error: Request failed:" in result.output

    def test_forbidden_error_with_detail_through_cli(
        self, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        httpx_mock.add_response(
            url=f"{BASE}/breacheddomain/unverified.com",
            status_code=403,
            json={"statusCode": 403, "message": "Domain not verified."},
        )
        result = cli_runner.invoke(cli, ["--api-key", TEST_KEY, "domain", "unverified.com"])
        assert result.exit_code == 4
        assert "Error: Domain not verified." in result.output

    def test_not_found_and_unauthorized_details_through_cli(
        self, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        detail = "The expected verification meta tag was not found in the home page head."
        httpx_mock.add_response(
            method="POST",
            url=f"{BASE}/domainVerification/verifyMetaTag",
            status_code=404,
            json={"message": detail},
        )
        res_404 = cli_runner.invoke(
            cli, ["--api-key", TEST_KEY, "domain-verify", "meta-check", "example.com"]
        )
        assert res_404.exit_code == 9
        assert res_404.output.strip() == f"Not found: {detail}"

        httpx_mock.add_response(
            url=f"{BASE}/breaches",
            status_code=401,
            text="Access denied due to improperly formed hibp-api-key.",
            headers={"content-type": "text/plain"},
        )
        res_401 = cli_runner.invoke(cli, ["breaches"])
        assert res_401.exit_code == 3
        assert (
            res_401.output.strip() == "Error: Access denied due to improperly formed hibp-api-key."
        )

    def test_bad_request_exits_2(self, httpx_mock: HTTPXMock, cli_runner: CliRunner) -> None:
        httpx_mock.add_response(
            url=f"{BASE}/breaches",
            status_code=400,
            json={"message": "Invalid domain parameter."},
        )
        result = cli_runner.invoke(cli, ["breaches"])
        assert result.exit_code == 2
        assert "Error: HTTP 400: Invalid domain parameter." in result.output

    def test_os_error_exits_7(self, cli_runner: CliRunner, monkeypatch: pytest.MonkeyPatch) -> None:
        def _raise_os(*args: object, **kwargs: object) -> None:
            raise OSError("disk full")

        monkeypatch.setattr("pwned.cli.HIBPClient.get_breaches", _raise_os)
        result = cli_runner.invoke(cli, ["breaches"])
        assert result.exit_code == 7
        assert "Error: disk full" in result.output

    def test_keyboard_interrupt_and_abort_exit_130(
        self, cli_runner: CliRunner, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def _raise_interrupt(*args: object, **kwargs: object) -> None:
            raise KeyboardInterrupt

        monkeypatch.setattr("pwned.cli.HIBPClient.get_breaches", _raise_interrupt)
        res_sigint = cli_runner.invoke(cli, ["breaches"])
        assert res_sigint.exit_code == 130
        assert "Cancelled." in res_sigint.output

        res_abort = cli_runner.invoke(cli, ["password"], input="")
        assert res_abort.exit_code == 130
        assert "Cancelled." in res_abort.output

    def test_validation_error_handled_gracefully(
        self, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        httpx_mock.add_response(
            url=f"{BASE}/breaches",
            json=[{"NotAValidField": "missing Name"}],
        )
        result = cli_runner.invoke(cli, ["breaches"])
        assert result.exit_code == 1
        assert "expected schema" in result.output


class TestGlobalOptionGroup:
    def test_api_key_after_subcommand(self, httpx_mock: HTTPXMock, cli_runner: CliRunner) -> None:
        httpx_mock.add_response(json=[{"Name": "Adobe"}])
        result = cli_runner.invoke(
            cli,
            ["account", "test@example.com", "--api-key", TEST_KEY],
        )
        assert result.exit_code == 0
        assert "Adobe" in result.output

    def test_equals_syntax_after_subcommand(
        self, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        httpx_mock.add_response(json=[{"Name": "Adobe"}])
        result = cli_runner.invoke(
            cli,
            ["account", "test@example.com", f"--api-key={TEST_KEY}", "--user-agent=custom-ua"],
        )
        assert result.exit_code == 0
        request = httpx_mock.get_request()
        assert request is not None
        assert request.headers["hibp-api-key"] == TEST_KEY
        assert request.headers["user-agent"] == "custom-ua"

    def test_missing_option_value_returns_usage_error(self, cli_runner: CliRunner) -> None:
        for argv in [["--api-key"], ["breach", "Adobe", "--api-key"], ["breach", "--user-agent"]]:
            result = cli_runner.invoke(cli, argv)
            assert result.exit_code == 2
            assert "requires an argument" in result.output

    def test_end_of_options_separator_preserved(
        self, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        prefix, suffix = _sha1_parts("--json")
        httpx_mock.add_response(
            url=f"https://api.pwnedpasswords.com/range/{prefix}",
            text=f"{suffix}:7\n",
        )
        result = cli_runner.invoke(cli, ["password", "--", "--json"])
        assert result.exit_code == 0
        assert "found 7 times" in result.output

    def test_user_agent_space_separated_and_empty_equals_key(
        self, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        httpx_mock.add_response(url=f"{BASE}/breaches", json=[])
        result = cli_runner.invoke(cli, ["breaches", "--user-agent", "my-agent", "--"])
        assert result.exit_code == 0
        request = httpx_mock.get_request()
        assert request is not None
        assert request.headers["user-agent"] == "my-agent"

        res_empty = cli_runner.invoke(cli, ["subscription", "--api-key="])
        assert res_empty.exit_code == 3
        assert "API key" in res_empty.output

    def test_json_flag_after_subcommand(self, httpx_mock: HTTPXMock, cli_runner: CliRunner) -> None:
        httpx_mock.add_response(
            url=f"{BASE}/breach/Adobe",
            json={"Name": "Adobe", "Title": "Adobe"},
        )
        result = cli_runner.invoke(cli, ["breach", "Adobe", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["Name"] == "Adobe"

    def test_version_flag(self, cli_runner: CliRunner) -> None:
        result = cli_runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert f"pwned, version {pwned.__version__}" in result.output

    def test_missing_subcommand_shows_usage(self, cli_runner: CliRunner) -> None:
        result = cli_runner.invoke(cli, [])
        assert "Usage:" in result.output or "Commands:" in result.output

    def test_options_do_not_duplicate_envvar_handling(self) -> None:
        opts = {p.name: p for p in cli.params}
        assert opts["api_key"].envvar is None
        assert opts["user_agent"].envvar is None

    def test_empty_env_var_overrides_dotenv_via_cli(
        self,
        cli_runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        (tmp_path / ".env").write_text("HIBP_API_KEY=dotenvsecret\n", encoding="utf-8")
        monkeypatch.setenv("HIBP_API_KEY", "")
        result = cli_runner.invoke(cli, ["subscription"])
        assert result.exit_code == 3
        assert "API key" in result.output


class TestPackageExports:
    def test_public_api_exported(self) -> None:
        assert isinstance(pwned.__version__, str)
        assert pwned.__version__
        for name in pwned.__all__:
            assert hasattr(pwned, name), f"Missing export {name}"

    def test_handle_errors_importable_from_cli(self) -> None:
        assert callable(handle_errors)

    def test_exit_code_enum_values(self) -> None:
        assert int(pwned.ExitCode.OK) == 0
        assert int(pwned.ExitCode.ERROR) == 1
        assert int(pwned.ExitCode.INVALID_USAGE) == 2
        assert int(pwned.ExitCode.AUTH_ERROR) == 3
        assert int(pwned.ExitCode.FORBIDDEN) == 4
        assert int(pwned.ExitCode.RATE_LIMITED) == 5
        assert int(pwned.ExitCode.NETWORK_ERROR) == 6
        assert int(pwned.ExitCode.FILE_OR_STORE_ERROR) == 7
        assert int(pwned.ExitCode.FINDINGS) == 8
        assert int(pwned.ExitCode.NOT_FOUND) == 9
        assert int(pwned.ExitCode.CANCELLED) == 130


class TestGlobalFormatAndCacheOptions:
    @pytest.mark.parametrize("fmt", ["text", "json", "jsonl", "csv", "table"])
    def test_format_option_all_formats(
        self, httpx_mock: HTTPXMock, cli_runner: CliRunner, fmt: str
    ) -> None:
        httpx_mock.add_response(
            url=f"{BASE}/breaches",
            json=[{"Name": "Adobe", "Domain": "adobe.com"}],
        )
        result = cli_runner.invoke(cli, ["--format", fmt, "breaches"])
        assert result.exit_code == 0
        assert "Adobe" in result.output

    def test_format_after_subcommand_space_and_equals(
        self, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        httpx_mock.add_response(url=f"{BASE}/breaches", json=[{"Name": "Adobe"}])
        res1 = cli_runner.invoke(cli, ["breaches", "--format", "json"])
        assert res1.exit_code == 0
        assert json.loads(res1.output) == [{"Name": "Adobe"}]

        httpx_mock.add_response(url=f"{BASE}/breaches", json=[{"Name": "Adobe"}])
        res2 = cli_runner.invoke(cli, ["breaches", "--format=csv"])
        assert res2.exit_code == 0
        assert "Name\nAdobe" in res2.output

    def test_json_and_format_json_compatible(
        self, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        httpx_mock.add_response(url=f"{BASE}/breaches", json=[{"Name": "Adobe"}])
        result = cli_runner.invoke(cli, ["--json", "--format", "json", "breaches"])
        assert result.exit_code == 0
        assert json.loads(result.output) == [{"Name": "Adobe"}]

    def test_json_and_non_json_format_rejected(self, cli_runner: CliRunner) -> None:
        result = cli_runner.invoke(cli, ["--json", "--format", "csv", "breaches"])
        assert result.exit_code == 2
        assert "Cannot combine --json with a non-json --format." in result.output

    def test_cache_and_no_cache_breaches(
        self,
        httpx_mock: HTTPXMock,
        cli_runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
        httpx_mock.add_response(url=f"{BASE}/breaches", json=[{"Name": "Adobe"}])

        first = cli_runner.invoke(cli, ["breaches", "--cache"])
        assert first.exit_code == 0
        assert "Adobe" in first.output
        assert len(httpx_mock.get_requests()) == 1

        second = cli_runner.invoke(cli, ["--cache", "breaches"])
        assert second.exit_code == 0
        assert "Adobe" in second.output
        assert len(httpx_mock.get_requests()) == 1

        httpx_mock.add_response(url=f"{BASE}/breaches", json=[{"Name": "Fresh"}])
        third = cli_runner.invoke(cli, ["breaches", "--no-cache"])
        assert third.exit_code == 0
        assert "Fresh" in third.output
        assert len(httpx_mock.get_requests()) == 2


class TestDataclassesDescriptions:
    def test_dataclasses_descriptions(self, httpx_mock: HTTPXMock, cli_runner: CliRunner) -> None:
        httpx_mock.add_response(
            url=f"{BASE}/dataclasses/descriptions",
            json=[{"name": "Email addresses", "description": "User email"}],
        )
        result = cli_runner.invoke(cli, ["dataclasses", "--descriptions"])
        assert result.exit_code == 0
        assert "Email addresses" in result.output
        assert "User email" in result.output

    def test_dataclasses_descriptions_json_and_cache(
        self,
        httpx_mock: HTTPXMock,
        cli_runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
        httpx_mock.add_response(
            url=f"{BASE}/dataclasses/descriptions",
            json=[{"name": "Passwords", "description": "Account passwords"}],
        )
        res1 = cli_runner.invoke(
            cli, ["--cache", "--format", "json", "dataclasses", "--descriptions"]
        )
        assert res1.exit_code == 0
        assert json.loads(res1.output) == [
            {"name": "Passwords", "description": "Account passwords"}
        ]
        res2 = cli_runner.invoke(cli, ["dataclasses", "--descriptions", "--cache"])
        assert res2.exit_code == 0
        assert "Passwords" in res2.output
        assert len(httpx_mock.get_requests()) == 1


class TestAccountExtended:
    def test_account_requires_exactly_one_input_source(
        self, cli_runner: CliRunner, tmp_path: Path
    ) -> None:
        f = tmp_path / "accounts.txt"
        f.write_text("a@example.com\n", encoding="utf-8")

        res_none = cli_runner.invoke(cli, ["--api-key", TEST_KEY, "account"])
        assert res_none.exit_code == 2

        res_arg_file = cli_runner.invoke(
            cli, ["--api-key", TEST_KEY, "account", "a@example.com", "--file", str(f)]
        )
        assert res_arg_file.exit_code == 2

        res_arg_stdin = cli_runner.invoke(
            cli, ["--api-key", TEST_KEY, "account", "a@example.com", "--stdin"], input="b@e.com\n"
        )
        assert res_arg_stdin.exit_code == 2

        res_file_stdin = cli_runner.invoke(
            cli, ["--api-key", TEST_KEY, "account", "--file", str(f), "--stdin"], input="b@e.com\n"
        )
        assert res_file_stdin.exit_code == 2

    def test_account_single_fail_if_pwned_when_pwned(
        self, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        httpx_mock.add_response(json=[{"Name": "Adobe"}])
        result = cli_runner.invoke(
            cli, ["--api-key", TEST_KEY, "account", "test@example.com", "--fail-if-pwned"]
        )
        assert result.exit_code == 8
        assert "Adobe" in result.output

    def test_account_single_fail_if_pwned_when_clean_text(
        self, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        httpx_mock.add_response(status_code=404)
        result = cli_runner.invoke(
            cli, ["--api-key", TEST_KEY, "account", "clean@example.com", "--fail-if-pwned"]
        )
        assert result.exit_code == 0
        assert "Clean (not found in any breaches)." in result.output

    def test_account_single_fail_if_pwned_when_clean_json(
        self, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        httpx_mock.add_response(status_code=404)
        result = cli_runner.invoke(
            cli,
            ["--api-key", TEST_KEY, "--json", "account", "clean@example.com", "--fail-if-pwned"],
        )
        assert result.exit_code == 0
        assert json.loads(result.output) == []

    def test_account_single_fail_if_pwned_empty_list(
        self, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        httpx_mock.add_response(json=[])
        result = cli_runner.invoke(
            cli, ["--api-key", TEST_KEY, "account", "clean@example.com", "--fail-if-pwned"]
        )
        assert result.exit_code == 0
        assert "No results found." in result.output

    def test_account_batch_file(
        self,
        httpx_mock: HTTPXMock,
        cli_runner: CliRunner,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        accounts_file = tmp_path / "accounts.txt"
        accounts_file.write_text(
            "# comment\n\n pwned@example.com \nclean@example.com\n",
            encoding="utf-8",
        )
        httpx_mock.add_response(
            url=httpx.URL(
                f"{BASE}/breachedaccount/pwned%40example.com",
                params={"domain": "adobe.com", "includeUnverified": "false"},
            ),
            json=[{"Name": "Adobe"}],
        )
        httpx_mock.add_response(
            url=httpx.URL(
                f"{BASE}/breachedaccount/clean%40example.com",
                params={"domain": "adobe.com", "includeUnverified": "false"},
            ),
            status_code=404,
        )
        sleeps: list[float] = []

        def spy_batch_check(
            accounts: list[str],
            client: HIBPClient,
            *,
            rpm: int | None = None,
            auto_rpm: bool = False,
            domain: str | None = None,
            include_unverified: bool = True,
            on_progress: Callable[[int, int, AccountBatchItem], None] | None = None,
        ) -> list[AccountBatchItem]:
            return batch_check_accounts(
                accounts,
                client,
                rpm=rpm,
                auto_rpm=auto_rpm,
                domain=domain,
                include_unverified=include_unverified,
                sleep=sleeps.append,
                on_progress=on_progress,
            )

        monkeypatch.setattr("pwned.cli.batch_check_accounts", spy_batch_check)

        result = cli_runner.invoke(
            cli,
            [
                "--api-key",
                TEST_KEY,
                "--format",
                "json",
                "account",
                "--file",
                str(accounts_file),
                "--domain",
                "adobe.com",
                "--no-include-unverified",
                "--rpm",
                "120",
            ],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data == [
            {"account": "pwned@example.com", "breaches": ["Adobe"], "status": "pwned"},
            {"account": "clean@example.com", "breaches": [], "status": "clean"},
        ]
        assert sleeps == [0.5]

    def test_account_batch_file_empty_errors(self, cli_runner: CliRunner, tmp_path: Path) -> None:
        empty_file = tmp_path / "empty.txt"
        empty_file.write_text("# comment only\n\n", encoding="utf-8")
        result = cli_runner.invoke(
            cli, ["--api-key", TEST_KEY, "account", "--file", str(empty_file)]
        )
        assert result.exit_code == 2
        assert "No accounts provided." in result.output

    def test_account_batch_stdin_and_fail_if_pwned(
        self, httpx_mock: HTTPXMock, cli_runner: CliRunner, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("pwned.batch.time.sleep", lambda _: None)
        httpx_mock.add_response(
            url=f"{BASE}/subscription/status",
            json={
                "SubscriptionName": "Pwned 1",
                "Description": "Desc",
                "SubscribedUntil": "2027-01-01T00:00:00Z",
                "Rpm": 120,
                "DomainSearchMaxBreachedAccounts": 0,
                "IncludesStealerLogs": False,
            },
        )
        httpx_mock.add_response(
            url=f"{BASE}/breachedaccount/a%40example.com",
            json=[{"Name": "Adobe"}],
        )
        httpx_mock.add_response(
            url=f"{BASE}/breachedaccount/b%40example.com",
            status_code=404,
        )
        res_pwned = cli_runner.invoke(
            cli,
            ["--api-key", TEST_KEY, "account", "--stdin", "--fail-if-pwned"],
            input="a@example.com\nb@example.com\n",
        )
        assert res_pwned.exit_code == 8
        assert "a@example.com" in res_pwned.output

        httpx_mock.add_response(
            url=f"{BASE}/breachedaccount/b%40example.com",
            status_code=404,
        )
        res_clean = cli_runner.invoke(
            cli,
            ["--api-key", TEST_KEY, "account", "--stdin", "--fail-if-pwned"],
            input="b@example.com\n",
        )
        assert res_clean.exit_code == 0

    def test_account_batch_rejects_no_truncate(self, cli_runner: CliRunner, tmp_path: Path) -> None:
        accounts_file = tmp_path / "accounts.txt"
        accounts_file.write_text("a@example.com\n", encoding="utf-8")
        result = cli_runner.invoke(
            cli,
            ["--api-key", TEST_KEY, "account", "--file", str(accounts_file), "--no-truncate"],
        )
        assert result.exit_code == 2
        assert "Cannot combine --no-truncate" in result.output

    def test_account_batch_tty_progress_emits_to_stderr(
        self, httpx_mock: HTTPXMock, cli_runner: CliRunner, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("pwned.batch.time.sleep", lambda _: None)
        monkeypatch.setattr("pwned.cli._is_stderr_tty", lambda: True)
        httpx_mock.add_response(
            url=f"{BASE}/subscription/status",
            status_code=500,
        )
        httpx_mock.add_response(
            url=f"{BASE}/breachedaccount/a%40example.com",
            json=[{"Name": "Adobe"}],
        )
        httpx_mock.add_response(
            url=f"{BASE}/breachedaccount/b%40example.com",
            status_code=404,
        )
        result = cli_runner.invoke(
            cli,
            ["--api-key", TEST_KEY, "account", "--stdin"],
            input="a@example.com\nb@example.com\n",
        )
        assert result.exit_code == 0
        assert "[1/2]" in result.output
        assert "[2/2]" in result.output

    def test_account_batch_stdin_empty_errors(self, cli_runner: CliRunner) -> None:
        result = cli_runner.invoke(
            cli, ["--api-key", TEST_KEY, "account", "--stdin"], input="\n# comment\n"
        )
        assert result.exit_code == 2
        assert "No accounts provided." in result.output


class TestPasswordExtended:
    def test_password_rejects_conflicting_file_options(
        self, cli_runner: CliRunner, tmp_path: Path
    ) -> None:
        pw_file = tmp_path / "pw.txt"
        pw_file.write_text("password\n", encoding="utf-8")

        res_arg_file = cli_runner.invoke(cli, ["password", "secret", "--file", str(pw_file)])
        assert res_arg_file.exit_code == 2

        res_stdin_file = cli_runner.invoke(
            cli, ["password", "--stdin", "--file", str(pw_file)], input="secret\n"
        )
        assert res_stdin_file.exit_code == 2

    @pytest.mark.parametrize("fmt", ["jsonl", "csv", "table"])
    def test_password_single_other_formats(
        self, httpx_mock: HTTPXMock, cli_runner: CliRunner, fmt: str
    ) -> None:
        prefix, suffix = _sha1_parts("password")
        httpx_mock.add_response(
            url=f"https://api.pwnedpasswords.com/range/{prefix}",
            text=f"{suffix}:123\n",
        )
        result = cli_runner.invoke(cli, ["--format", fmt, "password", "password"])
        assert result.exit_code == 0
        assert "123" in result.output

    def test_password_single_threshold_and_fail_if_pwned(
        self, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        prefix, suffix = _sha1_parts("password")
        httpx_mock.add_response(
            url=f"https://api.pwnedpasswords.com/range/{prefix}",
            text=f"{suffix}:5\n",
        )
        res_below = cli_runner.invoke(
            cli, ["password", "password", "--threshold", "10", "--fail-if-pwned"]
        )
        assert res_below.exit_code == 0
        assert "5" in res_below.output

        httpx_mock.add_response(
            url=f"https://api.pwnedpasswords.com/range/{prefix}",
            text=f"{suffix}:10\n",
        )
        res_meet = cli_runner.invoke(
            cli, ["password", "password", "--threshold", "10", "--fail-if-pwned"]
        )
        assert res_meet.exit_code == 8
        assert "10" in res_meet.output

    def test_password_stdin_multiline_batch_mode(
        self, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        p1_prefix, p1_suffix = _sha1_parts("pw1")
        p2_prefix, _ = _sha1_parts("pw2")
        httpx_mock.add_response(
            url=f"https://api.pwnedpasswords.com/range/{p1_prefix}",
            text=f"{p1_suffix}:15\n",
        )
        httpx_mock.add_response(
            url=f"https://api.pwnedpasswords.com/range/{p2_prefix}",
            text="",
        )
        result = cli_runner.invoke(
            cli,
            ["--format", "json", "password", "--stdin", "--threshold", "10", "--fail-if-pwned"],
            input="pw1\npw2\n",
        )
        assert result.exit_code == 8
        data = json.loads(result.output)
        assert data == [
            {"index": 1, "pwn_count": 15, "status": "pwned"},
            {"index": 2, "pwn_count": 0, "status": "clean"},
        ]
        assert "pw1" not in result.output
        assert "pw2" not in result.output

        httpx_mock.add_response(
            url=f"https://api.pwnedpasswords.com/range/{p1_prefix}",
            text=f"{p1_suffix}:15\n",
        )
        httpx_mock.add_response(
            url=f"https://api.pwnedpasswords.com/range/{p2_prefix}",
            text="",
        )
        res_ok = cli_runner.invoke(
            cli,
            ["--format", "json", "password", "--stdin"],
            input="pw1\npw2\n",
        )
        assert res_ok.exit_code == 0
        assert json.loads(res_ok.output) == [
            {"index": 1, "pwn_count": 15, "status": "pwned"},
            {"index": 2, "pwn_count": 0, "status": "clean"},
        ]

    def test_password_file_batch_mode_and_empty_error(
        self, httpx_mock: HTTPXMock, cli_runner: CliRunner, tmp_path: Path
    ) -> None:
        empty_file = tmp_path / "empty.txt"
        empty_file.write_text("\n\n", encoding="utf-8")
        res_empty = cli_runner.invoke(cli, ["password", "--file", str(empty_file)])
        assert res_empty.exit_code == 2
        assert "No passwords provided." in res_empty.output

        pw_file = tmp_path / "passwords.txt"
        pw_file.write_text("#notacomment\n alpha \n", encoding="utf-8")
        p1_prefix, p1_suffix = _sha1_parts("#notacomment")
        p2_prefix, _ = _sha1_parts(" alpha ")
        httpx_mock.add_response(
            url=f"https://api.pwnedpasswords.com/range/{p1_prefix}",
            text=f"{p1_suffix}:2\n",
        )
        httpx_mock.add_response(
            url=f"https://api.pwnedpasswords.com/range/{p2_prefix}",
            text="",
        )
        res_ok = cli_runner.invoke(
            cli,
            [
                "--format",
                "json",
                "password",
                "--file",
                str(pw_file),
                "--threshold",
                "5",
                "--fail-if-pwned",
            ],
        )
        assert res_ok.exit_code == 0
        assert json.loads(res_ok.output) == [
            {"index": 1, "pwn_count": 2, "status": "clean"},
            {"index": 2, "pwn_count": 0, "status": "clean"},
        ]

    def test_password_file_preserves_duplicate_indices_and_caches(
        self, httpx_mock: HTTPXMock, cli_runner: CliRunner, tmp_path: Path
    ) -> None:
        pw_file = tmp_path / "dups.txt"
        pw_file.write_text("dup\nunique\ndup\n", encoding="utf-8")
        p1_prefix, p1_suffix = _sha1_parts("dup")
        p2_prefix, _ = _sha1_parts("unique")
        httpx_mock.add_response(
            url=f"https://api.pwnedpasswords.com/range/{p1_prefix}",
            text=f"{p1_suffix}:7\n",
        )
        httpx_mock.add_response(
            url=f"https://api.pwnedpasswords.com/range/{p2_prefix}",
            text="",
        )
        result = cli_runner.invoke(
            cli,
            ["--format", "json", "password", "--file", str(pw_file)],
        )
        assert result.exit_code == 0
        assert json.loads(result.output) == [
            {"index": 1, "pwn_count": 7, "status": "pwned"},
            {"index": 2, "pwn_count": 0, "status": "clean"},
            {"index": 3, "pwn_count": 7, "status": "pwned"},
        ]
        assert len(httpx_mock.get_requests()) == 2

    def test_password_stdin_duplicate_lines_enter_batch_mode(
        self, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        p1_prefix, p1_suffix = _sha1_parts("dup")
        httpx_mock.add_response(
            url=f"https://api.pwnedpasswords.com/range/{p1_prefix}",
            text=f"{p1_suffix}:3\n",
        )
        result = cli_runner.invoke(
            cli,
            ["--format", "json", "password", "--stdin"],
            input="dup\ndup\n",
        )
        assert result.exit_code == 0
        assert json.loads(result.output) == [
            {"index": 1, "pwn_count": 3, "status": "pwned"},
            {"index": 2, "pwn_count": 3, "status": "pwned"},
        ]
        assert len(httpx_mock.get_requests()) == 1

    def test_password_batch_tty_progress_omits_plaintext(
        self, httpx_mock: HTTPXMock, cli_runner: CliRunner, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("pwned.cli._is_stderr_tty", lambda: True)
        p1_prefix, p1_suffix = _sha1_parts("secretA")
        p2_prefix, _ = _sha1_parts("secretB")
        httpx_mock.add_response(
            url=f"https://api.pwnedpasswords.com/range/{p1_prefix}",
            text=f"{p1_suffix}:9\n",
        )
        httpx_mock.add_response(
            url=f"https://api.pwnedpasswords.com/range/{p2_prefix}",
            text="",
        )
        result = cli_runner.invoke(
            cli,
            ["password", "--stdin"],
            input="secretA\nsecretB\n",
        )
        assert result.exit_code == 0
        assert "[1/2]" in result.output
        assert "[2/2]" in result.output
        assert "secretA" not in result.output
        assert "secretB" not in result.output

    def test_password_single_tty_color_and_no_color(
        self, httpx_mock: HTTPXMock, cli_runner: CliRunner, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("pwned.cli._is_stdout_tty", lambda: True)
        p1_prefix, p1_suffix = _sha1_parts("password")
        httpx_mock.add_response(
            url=f"https://api.pwnedpasswords.com/range/{p1_prefix}",
            text=f"{p1_suffix}:42\n",
        )
        res_color = cli_runner.invoke(cli, ["password", "password"], color=True)
        assert res_color.exit_code == 0
        assert "\x1b[" in res_color.output

        httpx_mock.add_response(
            url=f"https://api.pwnedpasswords.com/range/{p1_prefix}",
            text="",
        )
        res_clean_color = cli_runner.invoke(cli, ["password", "password"], color=True)
        assert res_clean_color.exit_code == 0
        assert "\x1b[" in res_clean_color.output

        monkeypatch.setenv("NO_COLOR", "1")
        httpx_mock.add_response(
            url=f"https://api.pwnedpasswords.com/range/{p1_prefix}",
            text=f"{p1_suffix}:42\n",
        )
        res_no_color = cli_runner.invoke(cli, ["password", "password"], color=True)
        assert res_no_color.exit_code == 0
        assert "\x1b[" not in res_no_color.output

    def test_extra_commands_registered_on_cli(self) -> None:
        for cmd in ("auth", "search", "account-range", "domain-verify", "audit", "cache"):
            assert cmd in cli.commands

    def test_empty_csv_and_jsonl_emit_no_output(
        self, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        for fmt in ("csv", "jsonl"):
            httpx_mock.add_response(url=f"{BASE}/breaches", json=[])
            res = cli_runner.invoke(cli, ["--format", fmt, "breaches"])
            assert res.exit_code == 0
            assert res.output == ""


class TestCommandAliasesAndContext:
    @pytest.mark.parametrize(
        ("alias", "url", "payload"),
        [
            ("lb", f"{BASE}/latestbreach", {"Name": "Latest"}),
            ("dc", f"{BASE}/dataclasses", ["Passwords"]),
        ],
    )
    def test_public_command_aliases(
        self,
        httpx_mock: HTTPXMock,
        cli_runner: CliRunner,
        alias: str,
        url: str,
        payload: object,
    ) -> None:
        httpx_mock.add_response(url=url, json=payload)
        result = cli_runner.invoke(cli, [alias])
        assert result.exit_code == 0

    @pytest.mark.parametrize(
        ("alias", "args", "url", "payload"),
        [
            (
                "ba",
                ["test@example.com"],
                f"{BASE}/breachedaccount/test%40example.com",
                [{"Name": "A"}],
            ),
            (
                "bar",
                ["test@example.com"],
                f"{BASE}/breachedaccount/range/{hashlib.sha1(b'test@example.com').hexdigest().upper()[:6]}",
                [{"hashSuffix": "0" * 34, "websites": ["adobe.com"]}],
            ),
            (
                "pa",
                ["test@example.com"],
                f"{BASE}/pasteaccount/test%40example.com",
                [{"Source": "P", "Id": "1"}],
            ),
            ("bd", ["example.com"], f"{BASE}/breacheddomain/example.com", {"a": ["Adobe"]}),
            ("sd", [], f"{BASE}/subscribeddomains", [{"DomainName": "example.com"}]),
        ],
    )
    def test_authenticated_command_aliases(
        self,
        httpx_mock: HTTPXMock,
        cli_runner: CliRunner,
        alias: str,
        args: list[str],
        url: str,
        payload: object,
    ) -> None:
        httpx_mock.add_response(url=url, json=payload)
        result = cli_runner.invoke(cli, ["--api-key", TEST_KEY, alias, *args])
        assert result.exit_code == 0

    def test_password_alias(self, httpx_mock: HTTPXMock, cli_runner: CliRunner) -> None:
        prefix, suffix = _sha1_parts("password")
        httpx_mock.add_response(
            url=f"https://api.pwnedpasswords.com/range/{prefix}",
            text=f"{suffix}:12\n",
        )
        result = cli_runner.invoke(cli, ["pw", "password"])
        assert result.exit_code == 0
        assert "12" in result.output

    def test_unknown_command_fails(self, cli_runner: CliRunner) -> None:
        result = cli_runner.invoke(cli, ["nonexistent"])
        assert result.exit_code == 2
        assert "No such command" in result.output

    def test_cli_stores_cli_api_key_in_ctx_obj(self, cli_runner: CliRunner) -> None:
        seen: list[str | None] = []

        @click.command("_probe-key")
        @click.pass_context
        def _probe(ctx: click.Context) -> None:
            seen.append(ctx.obj["cli_api_key"])

        cli.add_command(_probe)
        try:
            res_with = cli_runner.invoke(cli, ["--api-key", TEST_KEY, "_probe-key"])
            res_without = cli_runner.invoke(cli, ["_probe-key"])
            assert res_with.exit_code == 0
            assert res_without.exit_code == 0
            assert seen == [TEST_KEY, None]
        finally:
            cli.commands.pop("_probe-key", None)


class TestBreachFilteringAndSorting:
    _SAMPLE_BREACHES = [
        {
            "Name": "OldUnverified",
            "BreachDate": "2015-01-01",
            "PwnCount": 500,
            "DataClasses": ["Email addresses"],
            "IsVerified": False,
            "IsRetired": False,
        },
        {
            "Name": "BetaRetired",
            "BreachDate": "2022-06-01",
            "PwnCount": 2000,
            "DataClasses": ["Email addresses", "Passwords"],
            "IsVerified": True,
            "IsRetired": True,
        },
        {
            "Name": "AlphaNew",
            "BreachDate": "2023-03-15",
            "PwnCount": 1000,
            "DataClasses": ["Passwords", "Usernames"],
            "IsVerified": True,
            "IsRetired": False,
        },
    ]

    def test_breaches_filtering_and_sorting(
        self, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        httpx_mock.add_response(url=f"{BASE}/breaches", json=self._SAMPLE_BREACHES)
        result = cli_runner.invoke(
            cli,
            [
                "--json",
                "breaches",
                "--since",
                "2020-01-01",
                "--data-class",
                "password",
                "--verified-only",
                "--exclude-retired",
                "--sort",
                "name",
            ],
        )
        assert result.exit_code == 0
        names = [item["Name"] for item in json.loads(result.output)]
        assert names == ["AlphaNew"]

    def test_breaches_sort_pwn_count(self, httpx_mock: HTTPXMock, cli_runner: CliRunner) -> None:
        httpx_mock.add_response(url=f"{BASE}/breaches", json=self._SAMPLE_BREACHES)
        result = cli_runner.invoke(cli, ["--json", "breaches", "--sort", "pwn-count"])
        assert result.exit_code == 0
        names = [item["Name"] for item in json.loads(result.output)]
        assert names == ["BetaRetired", "AlphaNew", "OldUnverified"]

    def test_breaches_invalid_since_returns_usage_error(
        self, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        httpx_mock.add_response(url=f"{BASE}/breaches", json=self._SAMPLE_BREACHES)
        result = cli_runner.invoke(cli, ["breaches", "--since", "not-a-date"])
        assert result.exit_code == 2

    def test_account_single_filtering_and_sorting(
        self, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        httpx_mock.add_response(
            url=f"{BASE}/breachedaccount/test%40example.com?truncateResponse=false",
            json=self._SAMPLE_BREACHES,
        )
        result = cli_runner.invoke(
            cli,
            [
                "--api-key",
                TEST_KEY,
                "--json",
                "account",
                "test@example.com",
                "--no-truncate",
                "--since",
                "2020-01-01",
                "--data-class",
                "passwords",
                "--verified-only",
                "--exclude-retired",
                "--sort",
                "date",
            ],
        )
        assert result.exit_code == 0
        names = [item["Name"] for item in json.loads(result.output)]
        assert names == ["AlphaNew"]

    def test_account_single_invalid_since_returns_usage_error(
        self, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        httpx_mock.add_response(
            url=f"{BASE}/breachedaccount/test%40example.com",
            json=[{"Name": "Adobe"}],
        )
        result = cli_runner.invoke(
            cli,
            ["--api-key", TEST_KEY, "account", "test@example.com", "--since", "bad-date"],
        )
        assert result.exit_code == 2

    @pytest.mark.parametrize(
        "flag_args",
        [
            ["--since", "2020-01-01"],
            ["--data-class", "Passwords"],
            ["--verified-only"],
            ["--exclude-retired"],
            ["--sort", "name"],
        ],
    )
    def test_account_batch_rejects_filter_and_sort_flags(
        self, cli_runner: CliRunner, tmp_path: Path, flag_args: list[str]
    ) -> None:
        accounts_file = tmp_path / "accounts.txt"
        accounts_file.write_text("a@example.com\n", encoding="utf-8")
        res = cli_runner.invoke(
            cli,
            ["--api-key", TEST_KEY, "account", "--file", str(accounts_file), *flag_args],
        )
        assert res.exit_code == 2


class TestBaselineAndStats:
    def test_account_single_save_and_diff_baseline(
        self, httpx_mock: HTTPXMock, cli_runner: CliRunner, tmp_path: Path
    ) -> None:
        baseline_file = tmp_path / "baseline.json"
        next_baseline = tmp_path / "next_baseline.json"

        httpx_mock.add_response(
            url=f"{BASE}/breachedaccount/test%40example.com",
            json=[{"Name": "Adobe"}],
        )
        res1 = cli_runner.invoke(
            cli,
            [
                "--api-key",
                TEST_KEY,
                "--json",
                "account",
                "test@example.com",
                "--save-baseline",
                str(baseline_file),
            ],
        )
        assert res1.exit_code == 0
        assert json.loads(baseline_file.read_text(encoding="utf-8")) == [{"Name": "Adobe"}]

        httpx_mock.add_response(
            url=f"{BASE}/breachedaccount/test%40example.com",
            json=[{"Name": "Adobe"}, {"Name": "LinkedIn"}],
        )
        res2 = cli_runner.invoke(
            cli,
            [
                "--api-key",
                TEST_KEY,
                "--json",
                "account",
                "test@example.com",
                "--baseline",
                str(baseline_file),
                "--save-baseline",
                str(next_baseline),
                "--fail-if-pwned",
            ],
        )
        assert res2.exit_code == 8
        assert json.loads(res2.output) == [{"Name": "LinkedIn"}]
        assert json.loads(next_baseline.read_text(encoding="utf-8")) == [
            {"Name": "Adobe"},
            {"Name": "LinkedIn"},
        ]

        httpx_mock.add_response(
            url=f"{BASE}/breachedaccount/test%40example.com",
            json=[{"Name": "Adobe"}, {"Name": "LinkedIn"}],
        )
        res3 = cli_runner.invoke(
            cli,
            [
                "--api-key",
                TEST_KEY,
                "--json",
                "account",
                "test@example.com",
                "--baseline",
                str(next_baseline),
                "--fail-if-pwned",
            ],
        )
        assert res3.exit_code == 0
        assert json.loads(res3.output) == []

    def test_account_single_404_with_baseline_options(
        self, httpx_mock: HTTPXMock, cli_runner: CliRunner, tmp_path: Path
    ) -> None:
        baseline_file = tmp_path / "baseline.json"
        baseline_file.write_text('[{"Name": "Adobe"}]', encoding="utf-8")
        out_baseline = tmp_path / "out.json"

        httpx_mock.add_response(status_code=404)
        res_save = cli_runner.invoke(
            cli,
            [
                "--api-key",
                TEST_KEY,
                "account",
                "clean@example.com",
                "--save-baseline",
                str(out_baseline),
            ],
        )
        assert res_save.exit_code == 0
        assert "Clean (not found in any breaches)." in res_save.output
        assert json.loads(out_baseline.read_text(encoding="utf-8")) == []

        httpx_mock.add_response(status_code=404)
        res_diff = cli_runner.invoke(
            cli,
            [
                "--api-key",
                TEST_KEY,
                "account",
                "clean@example.com",
                "--baseline",
                str(baseline_file),
                "--fail-if-pwned",
            ],
        )
        assert res_diff.exit_code == 0
        assert "No results found." in res_diff.output

    def test_account_single_invalid_baseline_errors(
        self, httpx_mock: HTTPXMock, cli_runner: CliRunner, tmp_path: Path
    ) -> None:
        bad_file = tmp_path / "bad.json"
        bad_file.write_text('{"not": "a list"}', encoding="utf-8")
        httpx_mock.add_response(json=[{"Name": "Adobe"}])
        res = cli_runner.invoke(
            cli,
            ["--api-key", TEST_KEY, "account", "test@example.com", "--baseline", str(bad_file)],
        )
        assert res.exit_code == 7
        assert "Error:" in res.output

    def test_account_batch_baseline_and_stats(
        self,
        httpx_mock: HTTPXMock,
        cli_runner: CliRunner,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr("pwned.batch.time.sleep", lambda _: None)
        accounts_file = tmp_path / "accounts.txt"
        accounts_file.write_text("a@example.com\nb@example.com\n", encoding="utf-8")
        baseline_file = tmp_path / "batch_baseline.json"
        baseline_file.write_text(
            json.dumps([{"account": "a@example.com", "breaches": ["Adobe"], "status": "pwned"}]),
            encoding="utf-8",
        )
        saved_file = tmp_path / "saved_batch.json"

        httpx_mock.add_response(url=f"{BASE}/subscription/status", status_code=500)
        httpx_mock.add_response(
            url=f"{BASE}/breachedaccount/a%40example.com",
            json=[{"Name": "Adobe"}],
        )
        httpx_mock.add_response(
            url=f"{BASE}/breachedaccount/b%40example.com",
            json=[{"Name": "LinkedIn"}],
        )
        res = cli_runner.invoke(
            cli,
            [
                "--api-key",
                TEST_KEY,
                "--json",
                "account",
                "--file",
                str(accounts_file),
                "--baseline",
                str(baseline_file),
                "--save-baseline",
                str(saved_file),
                "--stats",
                "--fail-if-pwned",
            ],
        )
        assert res.exit_code == 8
        assert "Checked 2: 1 pwned, 1 clean, 0 error(s)" in res.output
        saved = json.loads(saved_file.read_text(encoding="utf-8"))
        assert saved == [
            {"account": "a@example.com", "breaches": ["Adobe"], "status": "pwned"},
            {"account": "b@example.com", "breaches": ["LinkedIn"], "status": "pwned"},
        ]

    def test_account_batch_invalid_baseline_errors(
        self,
        httpx_mock: HTTPXMock,
        cli_runner: CliRunner,
        tmp_path: Path,
    ) -> None:
        accounts_file = tmp_path / "accounts.txt"
        accounts_file.write_text("a@example.com\n", encoding="utf-8")
        bad_file = tmp_path / "bad.json"
        bad_file.write_text("not json", encoding="utf-8")
        httpx_mock.add_response(
            url=f"{BASE}/breachedaccount/a%40example.com",
            json=[{"Name": "Adobe"}],
        )
        res = cli_runner.invoke(
            cli,
            [
                "--api-key",
                TEST_KEY,
                "account",
                "--file",
                str(accounts_file),
                "--baseline",
                str(bad_file),
            ],
        )
        assert res.exit_code == 7
        assert "Error:" in res.output

    def test_domain_baseline_save_diff_and_fail_if_pwned(
        self, httpx_mock: HTTPXMock, cli_runner: CliRunner, tmp_path: Path
    ) -> None:
        baseline_file = tmp_path / "domain_base.json"
        next_file = tmp_path / "domain_next.json"

        httpx_mock.add_response(
            url=f"{BASE}/breacheddomain/example.com",
            json={"alice": ["Adobe"]},
        )
        res1 = cli_runner.invoke(
            cli,
            [
                "--api-key",
                TEST_KEY,
                "--json",
                "domain",
                "example.com",
                "--save-baseline",
                str(baseline_file),
                "--fail-if-pwned",
            ],
        )
        assert res1.exit_code == 8
        assert json.loads(baseline_file.read_text(encoding="utf-8")) == {"alice": ["Adobe"]}

        httpx_mock.add_response(
            url=f"{BASE}/breacheddomain/example.com",
            json={"alice": ["Adobe", "LinkedIn"]},
        )
        res2 = cli_runner.invoke(
            cli,
            [
                "--api-key",
                TEST_KEY,
                "--json",
                "domain",
                "example.com",
                "--baseline",
                str(baseline_file),
                "--save-baseline",
                str(next_file),
                "--fail-if-pwned",
            ],
        )
        assert res2.exit_code == 8
        assert json.loads(res2.output) == {"alice": ["LinkedIn"]}
        assert json.loads(next_file.read_text(encoding="utf-8")) == {"alice": ["Adobe", "LinkedIn"]}

        httpx_mock.add_response(
            url=f"{BASE}/breacheddomain/example.com",
            json={"alice": ["Adobe", "LinkedIn"]},
        )
        res3 = cli_runner.invoke(
            cli,
            [
                "--api-key",
                TEST_KEY,
                "--json",
                "domain",
                "example.com",
                "--baseline",
                str(next_file),
                "--fail-if-pwned",
            ],
        )
        assert res3.exit_code == 0
        assert json.loads(res3.output) == {}

    def test_domain_404_and_invalid_baseline(
        self, httpx_mock: HTTPXMock, cli_runner: CliRunner, tmp_path: Path
    ) -> None:
        httpx_mock.add_response(url=f"{BASE}/breacheddomain/clean.com", status_code=404)
        res_plain_404 = cli_runner.invoke(cli, ["--api-key", TEST_KEY, "domain", "clean.com"])
        assert res_plain_404.exit_code == 0
        assert "Clean (no breached accounts found)." in res_plain_404.output

        out_base = tmp_path / "clean_domain.json"
        httpx_mock.add_response(url=f"{BASE}/breacheddomain/clean.com", status_code=404)
        res_404_flag = cli_runner.invoke(
            cli,
            [
                "--api-key",
                TEST_KEY,
                "--json",
                "domain",
                "clean.com",
                "--save-baseline",
                str(out_base),
                "--fail-if-pwned",
            ],
        )
        assert res_404_flag.exit_code == 0
        assert json.loads(res_404_flag.output) == {}
        assert json.loads(out_base.read_text(encoding="utf-8")) == {}

        bad_file = tmp_path / "bad_domain.json"
        bad_file.write_text("[]", encoding="utf-8")
        httpx_mock.add_response(url=f"{BASE}/breacheddomain/example.com", json={"a": ["Adobe"]})
        res_bad = cli_runner.invoke(
            cli,
            ["--api-key", TEST_KEY, "domain", "example.com", "--baseline", str(bad_file)],
        )
        assert res_bad.exit_code == 7
        assert "Error:" in res_bad.output


class TestPasswordHashedOfflineConcurrencyStats:
    def _write_dump(self, path: Path, entries: list[tuple[str, int]]) -> Path:
        lines = [f"{h}:{c}\n" for h, c in sorted(entries, key=lambda item: item[0])]
        path.write_text("".join(lines), encoding="utf-8")
        return path

    def test_password_hashed_single_sha1_and_ntlm(
        self, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        sha1_hex = hashlib.sha1(b"password").hexdigest().upper()
        httpx_mock.add_response(
            url=f"https://api.pwnedpasswords.com/range/{sha1_hex[:5]}",
            text=f"{sha1_hex[5:]}:1234\n",
        )
        res_sha1 = cli_runner.invoke(cli, ["--json", "password", "--hashed", sha1_hex])
        assert res_sha1.exit_code == 0
        assert json.loads(res_sha1.output) == {"count": 1234}

        ntlm_hex = _ntlm_hash("password")
        httpx_mock.add_response(
            url=httpx.URL(
                f"https://api.pwnedpasswords.com/range/{ntlm_hex[:5]}",
                params={"mode": "ntlm"},
            ),
            text=f"{ntlm_hex[5:]}:77\n",
        )
        res_ntlm = cli_runner.invoke(cli, ["--json", "password", "--hashed", "--ntlm", ntlm_hex])
        assert res_ntlm.exit_code == 0
        assert json.loads(res_ntlm.output) == {"count": 77}

    def test_password_hashed_interactive_prompt_and_invalid_hash(
        self, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        sha1_hex = hashlib.sha1(b"password").hexdigest().upper()
        httpx_mock.add_response(
            url=f"https://api.pwnedpasswords.com/range/{sha1_hex[:5]}",
            text=f"{sha1_hex[5:]}:9\n",
        )
        res_prompt = cli_runner.invoke(
            cli, ["--json", "password", "--hashed"], input=f"{sha1_hex}\n"
        )
        assert res_prompt.exit_code == 0
        assert "Hash:" in res_prompt.stderr
        assert json.loads(res_prompt.stdout) == {"count": 9}

        res_bad = cli_runner.invoke(cli, ["password", "--hashed", "not-a-hash"])
        assert res_bad.exit_code == 2
        assert "SHA-1 hash" in res_bad.output

    def test_password_offline_db_single_and_batch(
        self, cli_runner: CliRunner, tmp_path: Path
    ) -> None:
        sha1_pw = hashlib.sha1(b"password").hexdigest().upper()
        sha1_other = hashlib.sha1(b"hunter2").hexdigest().upper()
        dump_file = self._write_dump(
            tmp_path / "pwned-sha1.txt",
            [(sha1_pw, 42), (sha1_other, 5)],
        )

        res_single = cli_runner.invoke(
            cli, ["--json", "password", "--offline-db", str(dump_file), "password"]
        )
        assert res_single.exit_code == 0
        assert json.loads(res_single.output) == {"count": 42}

        res_hashed = cli_runner.invoke(
            cli, ["--json", "password", "--offline-db", str(dump_file), "--hashed", sha1_other]
        )
        assert res_hashed.exit_code == 0
        assert json.loads(res_hashed.output) == {"count": 5}

        hashes_file = tmp_path / "hashes.txt"
        hashes_file.write_text(f"{sha1_pw}\nbadhash\n", encoding="utf-8")
        res_batch = cli_runner.invoke(
            cli,
            [
                "--json",
                "password",
                "--offline-db",
                str(dump_file),
                "--hashed",
                "--file",
                str(hashes_file),
                "--stats",
                "--fail-if-pwned",
            ],
        )
        assert res_batch.exit_code == 8
        assert "Checked 2: 1 pwned, 0 clean, 1 error(s)" in res_batch.output

    def test_password_online_batch_concurrency_hashed_and_stats(
        self, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        h1 = hashlib.sha1(b"pw1").hexdigest().upper()
        h2 = hashlib.sha1(b"pw2").hexdigest().upper()
        httpx_mock.add_response(
            url=f"https://api.pwnedpasswords.com/range/{h1[:5]}",
            text=f"{h1[5:]}:11\n",
        )
        httpx_mock.add_response(
            url=f"https://api.pwnedpasswords.com/range/{h2[:5]}",
            text="",
        )
        res = cli_runner.invoke(
            cli,
            [
                "--json",
                "password",
                "--stdin",
                "--hashed",
                "--concurrency",
                "2",
                "--stats",
            ],
            input=f"{h1}\n{h2}\n",
        )
        assert res.exit_code == 0
        assert "Checked 2: 1 pwned, 1 clean, 0 error(s)" in res.output


class TestSarifFormatEndToEnd:
    def test_sarif_breaches_account_and_domain(
        self, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        httpx_mock.add_response(
            url=f"{BASE}/breaches",
            json=[{"Name": "Adobe", "Domain": "adobe.com"}],
        )
        res_breaches = cli_runner.invoke(cli, ["--format", "sarif", "breaches"])
        assert res_breaches.exit_code == 0
        doc_b = json.loads(res_breaches.output)
        assert doc_b["version"] == "2.1.0"
        assert doc_b["runs"][0]["results"][0]["ruleId"] == "HIBP004"

        httpx_mock.add_response(
            url=f"{BASE}/breachedaccount/test%40example.com",
            json=[{"Name": "Adobe"}],
        )
        res_acc = cli_runner.invoke(
            cli, ["--api-key", TEST_KEY, "--format", "sarif", "account", "test@example.com"]
        )
        assert res_acc.exit_code == 0
        doc_a = json.loads(res_acc.output)
        assert doc_a["runs"][0]["results"][0]["ruleId"] == "HIBP004"

        httpx_mock.add_response(
            url=f"{BASE}/breachedaccount/clean%40example.com",
            status_code=404,
        )
        res_acc_clean = cli_runner.invoke(
            cli,
            [
                "--api-key",
                TEST_KEY,
                "--format",
                "sarif",
                "account",
                "clean@example.com",
                "--fail-if-pwned",
            ],
        )
        assert res_acc_clean.exit_code == 0
        assert json.loads(res_acc_clean.output)["runs"][0]["results"] == []

        httpx_mock.add_response(
            url=f"{BASE}/breacheddomain/example.com",
            json={"alice": ["Adobe"]},
        )
        res_dom = cli_runner.invoke(
            cli, ["--api-key", TEST_KEY, "--format", "sarif", "domain", "example.com"]
        )
        assert res_dom.exit_code == 0
        doc_d = json.loads(res_dom.output)
        assert doc_d["runs"][0]["results"][0]["ruleId"] == "HIBP003"


class TestMarkdownHtmlAndHelp:
    def test_global_format_help_mentions_markdown_and_html(self, cli_runner: CliRunner) -> None:
        result = cli_runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        normalized = " ".join(result.output.split())
        expected = "Output format: text, json, jsonl, csv, table, sarif, markdown, or html."
        assert expected in normalized

    def test_format_markdown_and_html_breaches(
        self, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        httpx_mock.add_response(
            url=f"{BASE}/breaches",
            json=[{"Name": "Adobe", "Domain": "adobe.com"}],
        )
        res_md = cli_runner.invoke(cli, ["--format", "markdown", "breaches"])
        assert res_md.exit_code == 0
        assert "| Name |" in res_md.output
        assert "Adobe" in res_md.output

        httpx_mock.add_response(
            url=f"{BASE}/breaches",
            json=[{"Name": "Adobe", "Domain": "adobe.com"}],
        )
        res_html = cli_runner.invoke(cli, ["--format", "html", "breaches"])
        assert res_html.exit_code == 0
        assert "<!DOCTYPE html>" in res_html.output
        assert "<table>" in res_html.output
        assert "Adobe" in res_html.output


class TestPasswordCache:
    def test_password_single_cache_hit_and_no_cache(
        self,
        httpx_mock: HTTPXMock,
        cli_runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
        prefix, suffix = _sha1_parts("password")
        httpx_mock.add_response(
            url=f"https://api.pwnedpasswords.com/range/{prefix}",
            text=f"{suffix}:12345\n",
        )

        first = cli_runner.invoke(cli, ["password", "--cache", "password"])
        assert first.exit_code == 0
        assert "12,345" in first.output
        assert len(httpx_mock.get_requests()) == 1

        second = cli_runner.invoke(cli, ["--cache", "--json", "password", "password"])
        assert second.exit_code == 0
        assert json.loads(second.output) == {"count": 12345}
        assert len(httpx_mock.get_requests()) == 1

        httpx_mock.add_response(
            url=f"https://api.pwnedpasswords.com/range/{prefix}",
            text=f"{suffix}:99\n",
        )
        third = cli_runner.invoke(cli, ["password", "--no-cache", "password"])
        assert third.exit_code == 0
        assert "99" in third.output
        assert len(httpx_mock.get_requests()) == 2

    def test_password_batch_cache_hit_file_and_stdin(
        self,
        httpx_mock: HTTPXMock,
        cli_runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
        p1_prefix, p1_suffix = _sha1_parts("alpha")
        p2_prefix, _ = _sha1_parts("beta")
        httpx_mock.add_response(
            url=f"https://api.pwnedpasswords.com/range/{p1_prefix}",
            text=f"{p1_suffix}:42\n",
        )
        httpx_mock.add_response(
            url=f"https://api.pwnedpasswords.com/range/{p2_prefix}",
            text="",
        )
        pw_file = tmp_path / "passwords.txt"
        pw_file.write_text("alpha\nbeta\n", encoding="utf-8")

        first = cli_runner.invoke(cli, ["--cache", "--json", "password", "--file", str(pw_file)])
        assert first.exit_code == 0
        assert json.loads(first.output) == [
            {"index": 1, "pwn_count": 42, "status": "pwned"},
            {"index": 2, "pwn_count": 0, "status": "clean"},
        ]
        assert len(httpx_mock.get_requests()) == 2

        second = cli_runner.invoke(
            cli,
            ["--cache", "--json", "password", "--stdin"],
            input="alpha\nbeta\n",
        )
        assert second.exit_code == 0
        assert json.loads(second.output) == [
            {"index": 1, "pwn_count": 42, "status": "pwned"},
            {"index": 2, "pwn_count": 0, "status": "clean"},
        ]
        assert len(httpx_mock.get_requests()) == 2


class TestWebhookNotifications:
    def test_account_single_notify_webhook_pwned_and_fail_if_pwned(
        self, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        webhook_url = "https://hooks.example.com/account"
        httpx_mock.add_response(
            url=f"{BASE}/breachedaccount/test%40example.com",
            json=[{"Name": "Adobe"}],
        )
        httpx_mock.add_response(method="POST", url=webhook_url, status_code=200)

        res = cli_runner.invoke(
            cli,
            [
                "--api-key",
                TEST_KEY,
                "account",
                "test@example.com",
                "--notify-webhook",
                webhook_url,
                "--fail-if-pwned",
            ],
        )
        assert res.exit_code == 8
        assert "Adobe" in res.output
        requests = httpx_mock.get_requests()
        assert len(requests) == 2
        payload = json.loads(requests[1].content.decode("utf-8"))
        assert payload["source"] == "pwned"
        assert payload["title"] == "pwned Account Alert: test@example.com"

    def test_account_single_notify_webhook_clean_no_http(
        self, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        httpx_mock.add_response(
            url=f"{BASE}/breachedaccount/clean%40example.com",
            status_code=404,
        )
        res = cli_runner.invoke(
            cli,
            [
                "--api-key",
                TEST_KEY,
                "account",
                "clean@example.com",
                "--fail-if-pwned",
                "--notify-webhook",
                "https://hooks.example.com/account",
            ],
        )
        assert res.exit_code == 0
        assert "Clean" in res.output
        assert len(httpx_mock.get_requests()) == 1

    def test_account_single_notify_webhook_invalid_url_exits_2(
        self, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        httpx_mock.add_response(
            url=f"{BASE}/breachedaccount/test%40example.com",
            json=[{"Name": "Adobe"}],
        )
        res_pwned = cli_runner.invoke(
            cli,
            [
                "--api-key",
                TEST_KEY,
                "account",
                "test@example.com",
                "--notify-webhook",
                "http://insecure.example.com/hook",
            ],
        )
        assert res_pwned.exit_code == 2
        assert "https" in res_pwned.output
        assert len(httpx_mock.get_requests()) == 1

        httpx_mock.add_response(
            url=f"{BASE}/breachedaccount/clean%40example.com",
            status_code=404,
        )
        res_clean = cli_runner.invoke(
            cli,
            [
                "--api-key",
                TEST_KEY,
                "account",
                "clean@example.com",
                "--fail-if-pwned",
                "--notify-webhook",
                "http://insecure.example.com/hook",
            ],
        )
        assert res_clean.exit_code == 2
        assert "https" in res_clean.output
        assert len(httpx_mock.get_requests()) == 2

    def test_account_batch_notify_webhook_pwned_and_error(
        self, httpx_mock: HTTPXMock, cli_runner: CliRunner, tmp_path: Path
    ) -> None:
        accounts_file = tmp_path / "accounts.txt"
        accounts_file.write_text("pwned@example.com\nclean@example.com\n", encoding="utf-8")
        webhook_url = "https://hooks.example.com/batch"

        httpx_mock.add_response(
            url=f"{BASE}/breachedaccount/pwned%40example.com",
            json=[{"Name": "Adobe"}],
        )
        httpx_mock.add_response(
            url=f"{BASE}/breachedaccount/clean%40example.com",
            status_code=404,
        )
        httpx_mock.add_response(method="POST", url=webhook_url, status_code=200)

        res = cli_runner.invoke(
            cli,
            [
                "--api-key",
                TEST_KEY,
                "account",
                "--file",
                str(accounts_file),
                "--rpm",
                "1000",
                "--notify-webhook",
                webhook_url,
            ],
        )
        assert res.exit_code == 0
        requests = httpx_mock.get_requests()
        assert len(requests) == 3
        payload = json.loads(requests[2].content.decode("utf-8"))
        assert payload["title"] == "pwned Batch Account Alert"

        httpx_mock.add_response(
            url=f"{BASE}/breachedaccount/pwned%40example.com",
            json=[{"Name": "Adobe"}],
        )
        httpx_mock.add_response(
            url=f"{BASE}/breachedaccount/clean%40example.com",
            status_code=404,
        )
        httpx_mock.add_response(method="POST", url=webhook_url, status_code=500)
        res_err = cli_runner.invoke(
            cli,
            [
                "--api-key",
                TEST_KEY,
                "account",
                "--file",
                str(accounts_file),
                "--rpm",
                "1000",
                "--notify-webhook",
                webhook_url,
            ],
        )
        assert res_err.exit_code == 6
        assert "Webhook notification failed" in res_err.output

    def test_domain_notify_webhook_slack_and_clean_baseline_no_http(
        self, httpx_mock: HTTPXMock, cli_runner: CliRunner, tmp_path: Path
    ) -> None:
        webhook_url = "https://hooks.example.com/slack"
        httpx_mock.add_response(
            url=f"{BASE}/breacheddomain/example.com",
            json={"alice": ["Adobe"]},
        )
        httpx_mock.add_response(method="POST", url=webhook_url, status_code=200)

        res_slack = cli_runner.invoke(
            cli,
            [
                "--api-key",
                TEST_KEY,
                "domain",
                "example.com",
                "--notify-webhook",
                webhook_url,
                "--webhook-format",
                "slack",
            ],
        )
        assert res_slack.exit_code == 0
        requests = httpx_mock.get_requests()
        assert len(requests) == 2
        payload = json.loads(requests[1].content.decode("utf-8"))
        assert "blocks" in payload
        assert payload["blocks"][0]["text"]["text"] == "pwned Domain Alert: example.com"

        baseline_file = tmp_path / "domain_base.json"
        baseline_file.write_text('{"alice": ["Adobe"]}', encoding="utf-8")
        httpx_mock.add_response(
            url=f"{BASE}/breacheddomain/example.com",
            json={"alice": ["Adobe"]},
        )
        res_clean = cli_runner.invoke(
            cli,
            [
                "--api-key",
                TEST_KEY,
                "--json",
                "domain",
                "example.com",
                "--baseline",
                str(baseline_file),
                "--notify-webhook",
                webhook_url,
            ],
        )
        assert res_clean.exit_code == 0
        assert json.loads(res_clean.output) == {}
        assert len(httpx_mock.get_requests()) == 3
