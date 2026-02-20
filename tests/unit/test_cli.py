from __future__ import annotations

import json

from click.testing import CliRunner
from pytest_httpx import HTTPXMock

from pwned.cli import cli

BASE = "https://haveibeenpwned.com/api/v3"
TEST_KEY = "00000000000000000000000000000000"


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

    def test_breaches(self, httpx_mock: HTTPXMock, cli_runner: CliRunner) -> None:
        httpx_mock.add_response(
            url=f"{BASE}/breaches",
            json=[{"Name": "Adobe"}, {"Name": "Gawker"}],
        )
        result = cli_runner.invoke(cli, ["breaches"])
        assert result.exit_code == 0
        assert "Adobe" in result.output
        assert "Gawker" in result.output

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


class TestDomainCommands:
    def test_domain(self, httpx_mock: HTTPXMock, cli_runner: CliRunner) -> None:
        httpx_mock.add_response(json={"alias1": ["Adobe"]})
        result = cli_runner.invoke(
            cli,
            ["--api-key", TEST_KEY, "domain", "example.com"],
        )
        assert result.exit_code == 0
        assert "alias1" in result.output

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


class TestPasswordCommand:
    def test_password_found(self, httpx_mock: HTTPXMock, cli_runner: CliRunner) -> None:
        import hashlib

        sha1 = hashlib.sha1(b"password").hexdigest().upper()
        prefix = sha1[:5]
        suffix = sha1[5:]
        httpx_mock.add_response(
            url=f"https://api.pwnedpasswords.com/range/{prefix}",
            text=f"{suffix}:3861493\n",
        )
        result = cli_runner.invoke(cli, ["password", "password"])
        assert result.exit_code == 0
        assert "3,861,493" in result.output

    def test_password_not_found(self, httpx_mock: HTTPXMock, cli_runner: CliRunner) -> None:
        import hashlib

        sha1 = hashlib.sha1(b"supersecurepassword123!@#$%").hexdigest().upper()
        prefix = sha1[:5]
        httpx_mock.add_response(
            url=f"https://api.pwnedpasswords.com/range/{prefix}",
            text="0018A45C4D1DEF81644B54AB7F969B88D65:1\n",
        )
        result = cli_runner.invoke(cli, ["password", "supersecurepassword123!@#$%"])
        assert result.exit_code == 0
        assert "not found" in result.output

    def test_password_json(self, httpx_mock: HTTPXMock, cli_runner: CliRunner) -> None:
        import hashlib

        sha1 = hashlib.sha1(b"password").hexdigest().upper()
        prefix = sha1[:5]
        suffix = sha1[5:]
        httpx_mock.add_response(
            url=f"https://api.pwnedpasswords.com/range/{prefix}",
            text=f"{suffix}:100\n",
        )
        result = cli_runner.invoke(cli, ["--json", "password", "password"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["count"] == 100
        assert "password" not in data

    def test_password_from_stdin(self, httpx_mock: HTTPXMock, cli_runner: CliRunner) -> None:
        import hashlib

        sha1 = hashlib.sha1(b"password").hexdigest().upper()
        prefix = sha1[:5]
        suffix = sha1[5:]
        httpx_mock.add_response(
            url=f"https://api.pwnedpasswords.com/range/{prefix}",
            text=f"{suffix}:500\n",
        )
        result = cli_runner.invoke(cli, ["password", "--stdin"], input="password\n")
        assert result.exit_code == 0
        assert "500" in result.output

    def test_password_interactive_prompt(
        self, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        import hashlib

        sha1 = hashlib.sha1(b"password").hexdigest().upper()
        prefix = sha1[:5]
        suffix = sha1[5:]
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
                "SubscribedUntil": "2025-12-31",
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

    def test_json_flag_after_subcommand(self, httpx_mock: HTTPXMock, cli_runner: CliRunner) -> None:
        httpx_mock.add_response(
            url=f"{BASE}/breach/Adobe",
            json={"Name": "Adobe", "Title": "Adobe"},
        )
        result = cli_runner.invoke(cli, ["breach", "Adobe", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["Name"] == "Adobe"
