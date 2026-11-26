from __future__ import annotations

import hashlib
import json
from pathlib import Path

import httpx
import pytest
from click.testing import CliRunner
from pytest_httpx import HTTPXMock

import pwned
from pwned.cli import cli
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
