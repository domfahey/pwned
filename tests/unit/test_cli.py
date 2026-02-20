from __future__ import annotations

import json

from click.testing import CliRunner
from pytest_httpx import HTTPXMock

from pwned.cli import cli

BASE = "https://haveibeenpwned.com/api/v3"


def invoke(*args: str, httpx_mock: HTTPXMock | None = None) -> CliRunner:
    return CliRunner()


def run(*args: str) -> object:
    runner = CliRunner()
    return runner.invoke(cli, list(args), catch_exceptions=False)


class TestBreachCommands:
    def test_breach(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url=f"{BASE}/breach/Adobe",
            json={"Name": "Adobe", "Title": "Adobe", "Domain": "adobe.com"},
        )
        result = CliRunner().invoke(cli, ["breach", "Adobe"])
        assert result.exit_code == 0
        assert "Adobe" in result.output

    def test_breach_json(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url=f"{BASE}/breach/Adobe",
            json={"Name": "Adobe", "Title": "Adobe"},
        )
        result = CliRunner().invoke(cli, ["--json", "breach", "Adobe"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["Name"] == "Adobe"

    def test_breaches(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url=f"{BASE}/breaches",
            json=[{"Name": "Adobe"}, {"Name": "Gawker"}],
        )
        result = CliRunner().invoke(cli, ["breaches"])
        assert result.exit_code == 0
        assert "Adobe" in result.output
        assert "Gawker" in result.output

    def test_latest_breach(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url=f"{BASE}/latestbreach",
            json={"Name": "Latest", "Title": "Latest Breach"},
        )
        result = CliRunner().invoke(cli, ["latest-breach"])
        assert result.exit_code == 0
        assert "Latest" in result.output

    def test_dataclasses(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url=f"{BASE}/dataclasses",
            json=["Email addresses", "Passwords"],
        )
        result = CliRunner().invoke(cli, ["dataclasses"])
        assert result.exit_code == 0
        assert "Email addresses" in result.output


class TestAccountCommands:
    def test_account(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json=[{"Name": "Adobe"}])
        result = CliRunner().invoke(
            cli,
            ["--api-key", "00000000000000000000000000000000", "account", "test@example.com"],
        )
        assert result.exit_code == 0
        assert "Adobe" in result.output

    def test_account_not_found(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(status_code=404)
        result = CliRunner().invoke(
            cli,
            ["--api-key", "00000000000000000000000000000000", "account", "nobody@example.com"],
        )
        assert result.exit_code == 1
        assert "Not found" in result.output

    def test_account_unauthorized(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(status_code=401)
        result = CliRunner().invoke(
            cli,
            ["--api-key", "badkey00000000000000000000000000", "account", "test@example.com"],
        )
        assert result.exit_code == 1
        assert "API key" in result.output


class TestDomainCommands:
    def test_domain(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json={"alias1": ["Adobe"]})
        result = CliRunner().invoke(
            cli,
            ["--api-key", "00000000000000000000000000000000", "domain", "example.com"],
        )
        assert result.exit_code == 0
        assert "alias1" in result.output

    def test_subscribed_domains(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            json=[{"DomainName": "example.com", "PwnCount": 100}],
        )
        result = CliRunner().invoke(
            cli,
            ["--api-key", "00000000000000000000000000000000", "subscribed-domains"],
        )
        assert result.exit_code == 0
        assert "example.com" in result.output


class TestPastesCommand:
    def test_pastes(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            json=[{"Source": "Pastebin", "Id": "abc", "EmailCount": 10}],
        )
        result = CliRunner().invoke(
            cli,
            ["--api-key", "00000000000000000000000000000000", "pastes", "test@example.com"],
        )
        assert result.exit_code == 0
        assert "Pastebin" in result.output


class TestStealerCommands:
    def test_stealer_email(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json=["netflix.com"])
        result = CliRunner().invoke(
            cli,
            ["--api-key", "00000000000000000000000000000000", "stealer", "email", "t@e.com"],
        )
        assert result.exit_code == 0
        assert "netflix.com" in result.output

    def test_stealer_website(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json=["test@example.com"])
        result = CliRunner().invoke(
            cli,
            ["--api-key", "00000000000000000000000000000000", "stealer", "website", "netflix.com"],
        )
        assert result.exit_code == 0
        assert "test@example.com" in result.output

    def test_stealer_domain(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json={"andy": ["netflix.com"]})
        result = CliRunner().invoke(
            cli,
            [
                "--api-key",
                "00000000000000000000000000000000",
                "stealer",
                "domain",
                "example.com",
            ],
        )
        assert result.exit_code == 0
        assert "andy" in result.output


class TestPasswordCommand:
    def test_password_found(self, httpx_mock: HTTPXMock) -> None:
        import hashlib

        sha1 = hashlib.sha1(b"password").hexdigest().upper()  # noqa: S324
        prefix = sha1[:5]
        suffix = sha1[5:]
        httpx_mock.add_response(
            url=f"https://api.pwnedpasswords.com/range/{prefix}",
            text=f"{suffix}:3861493\n",
        )
        result = CliRunner().invoke(cli, ["password", "password"])
        assert result.exit_code == 0
        assert "3,861,493" in result.output

    def test_password_not_found(self, httpx_mock: HTTPXMock) -> None:
        import hashlib

        sha1 = hashlib.sha1(b"supersecurepassword123!@#$%").hexdigest().upper()  # noqa: S324
        prefix = sha1[:5]
        httpx_mock.add_response(
            url=f"https://api.pwnedpasswords.com/range/{prefix}",
            text="0018A45C4D1DEF81644B54AB7F969B88D65:1\n",
        )
        result = CliRunner().invoke(cli, ["password", "supersecurepassword123!@#$%"])
        assert result.exit_code == 0
        assert "not found" in result.output

    def test_password_json(self, httpx_mock: HTTPXMock) -> None:
        import hashlib

        sha1 = hashlib.sha1(b"password").hexdigest().upper()  # noqa: S324
        prefix = sha1[:5]
        suffix = sha1[5:]
        httpx_mock.add_response(
            url=f"https://api.pwnedpasswords.com/range/{prefix}",
            text=f"{suffix}:100\n",
        )
        result = CliRunner().invoke(cli, ["--json", "password", "password"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["count"] == 100


class TestSubscriptionCommand:
    def test_subscription(self, httpx_mock: HTTPXMock) -> None:
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
        result = CliRunner().invoke(
            cli,
            ["--api-key", "00000000000000000000000000000000", "subscription"],
        )
        assert result.exit_code == 0
        assert "Pwned 1" in result.output
