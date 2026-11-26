from __future__ import annotations

import hashlib
import json
from pathlib import Path

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
        assert result.exit_code == 1
        assert "Not found" in result.output

    def test_account_unauthorized(self, httpx_mock: HTTPXMock, cli_runner: CliRunner) -> None:
        httpx_mock.add_response(status_code=401)
        result = cli_runner.invoke(
            cli,
            ["--api-key", "badkey00000000000000000000000000", "account", "test@example.com"],
        )
        assert result.exit_code == 1
        assert "API key" in result.output

    @pytest.mark.parametrize(
        "argv",
        [
            ["account", "test@example.com"],
            ["domain", "example.com"],
            ["subscribed-domains"],
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
        assert result.exit_code == 1
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
        assert result.exit_code == 1
        assert "Error: HTTP 500" in result.output

    def test_password_interactive_prompt(
        self, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        prefix, suffix = _sha1_parts("password")
        httpx_mock.add_response(
            url=f"https://api.pwnedpasswords.com/range/{prefix}",
            text=f"{suffix}:999\n",
        )
        result = cli_runner.invoke(cli, ["password"], input="password\n")
        assert result.exit_code == 0
        assert "999" in result.output


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
        assert result.exit_code == 1
        assert "Error:" in result.output

    def test_network_error_handled_gracefully(
        self, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        httpx_mock.add_exception(httpx.ConnectError("dns failure"), url=f"{BASE}/breaches")
        result = cli_runner.invoke(cli, ["breaches"])
        assert result.exit_code == 1
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
        assert result.exit_code == 1
        assert "Error: Domain not verified." in result.output

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
        assert res_empty.exit_code == 1
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
        assert result.exit_code == 1
        assert "API key" in result.output


class TestPackageExports:
    def test_public_api_exported(self) -> None:
        assert isinstance(pwned.__version__, str)
        assert pwned.__version__
        for name in pwned.__all__:
            assert hasattr(pwned, name), f"Missing export {name}"

    def test_handle_errors_importable_from_cli(self) -> None:
        assert callable(handle_errors)


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
        assert result.exit_code == 1
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
            domain: str | None = None,
            include_unverified: bool = True,
        ) -> list[AccountBatchItem]:
            return batch_check_accounts(
                accounts,
                client,
                rpm=rpm,
                domain=domain,
                include_unverified=include_unverified,
                sleep=sleeps.append,
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
        self, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
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
        assert res_pwned.exit_code == 1
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
        assert res_meet.exit_code == 1
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
        assert result.exit_code == 1
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
