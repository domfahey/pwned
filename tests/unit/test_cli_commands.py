from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path

import click
import pytest
from click.testing import CliRunner
from pytest_httpx import HTTPXMock

from pwned.audit import AuditEntry
from pwned.cache import ResponseCache
from pwned.cli_commands import register_extra_commands
from pwned.config import get_config_file, load_settings, save_api_key
from pwned.passwords import _ntlm_hash

BASE = "https://haveibeenpwned.com/api/v3"
PASSWORDS_BASE = "https://api.pwnedpasswords.com"
TEST_KEY = "00000000000000000000000000000000"


def _make_cli() -> click.Group:
    @click.group()
    @click.option("--api-key", default=None)
    @click.option("--user-agent", default=None)
    @click.option("--format", "fmt", default="text")
    @click.option("--json", "use_json", is_flag=True)
    @click.option("--cache", "use_cache", is_flag=True)
    @click.pass_context
    def group(
        ctx: click.Context,
        api_key: str | None,
        user_agent: str | None,
        fmt: str,
        use_json: bool,
        use_cache: bool,
    ) -> None:
        resolved_fmt = "json" if use_json else fmt
        ctx.ensure_object(dict)
        ctx.obj["settings"] = load_settings(api_key=api_key, user_agent=user_agent)
        ctx.obj["cli_api_key"] = api_key
        ctx.obj["fmt"] = resolved_fmt
        ctx.obj["use_json"] = use_json
        ctx.obj["use_cache"] = use_cache

    register_extra_commands(group)
    return group


def _sha1_parts(value: str) -> tuple[str, str]:
    digest = hashlib.sha1(value.encode("utf-8")).hexdigest().upper()
    return digest[:5], digest[5:]


def _sha1_hex(value: str) -> str:
    return hashlib.sha1(value.encode("utf-8")).hexdigest().upper()


def _email_sha1_parts(email: str) -> tuple[str, str]:
    digest = hashlib.sha1(email.strip().lower().encode("utf-8")).hexdigest().upper()
    return digest[:6], digest[6:]


@pytest.fixture
def isolated_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    monkeypatch.delenv("HIBP_API_KEY", raising=False)
    monkeypatch.setattr("pwned.config.get_keyring_api_key", lambda: None)
    monkeypatch.chdir(tmp_path)
    return tmp_path


class TestAuthCommands:
    def test_auth_set_with_argument(self, isolated_env: Path, cli_runner: CliRunner) -> None:
        app = _make_cli()
        result = cli_runner.invoke(app, ["auth", "set", "my-secret-api-key"])
        assert result.exit_code == 0
        expected_path = get_config_file()
        assert f"Saved API key to {expected_path}" in result.output
        assert "HIBP_API_KEY=my-secret-api-key" in expected_path.read_text(encoding="utf-8")

    def test_auth_set_prompts_when_omitted(self, isolated_env: Path, cli_runner: CliRunner) -> None:
        app = _make_cli()
        result = cli_runner.invoke(app, ["auth", "set"], input="prompted-secret-key\n")
        assert result.exit_code == 0
        expected_path = get_config_file()
        assert "HIBP API key" in result.output
        assert f"Saved API key to {expected_path}" in result.output
        assert "HIBP_API_KEY=prompted-secret-key" in expected_path.read_text(encoding="utf-8")

    def test_auth_set_invalid_key_raises_usage_error(
        self, isolated_env: Path, cli_runner: CliRunner
    ) -> None:
        app = _make_cli()
        result = cli_runner.invoke(app, ["auth", "set", "   "])
        assert result.exit_code == 2
        assert "API key must not be empty" in result.output

    def test_auth_set_keyring_success(
        self, isolated_env: Path, monkeypatch: pytest.MonkeyPatch, cli_runner: CliRunner
    ) -> None:
        saved: list[str] = []
        monkeypatch.setattr("pwned.cli_commands.save_api_key_keyring", saved.append)
        app = _make_cli()
        result = cli_runner.invoke(app, ["auth", "set", "my-keyring-key", "--backend", "keyring"])
        assert result.exit_code == 0
        assert saved == ["my-keyring-key"]
        assert result.output.strip() == "Saved API key to OS keyring."

    def test_auth_set_keyring_prompts_when_omitted(
        self, isolated_env: Path, monkeypatch: pytest.MonkeyPatch, cli_runner: CliRunner
    ) -> None:
        saved: list[str] = []
        monkeypatch.setattr("pwned.cli_commands.save_api_key_keyring", saved.append)
        app = _make_cli()
        result = cli_runner.invoke(
            app, ["auth", "set", "--backend", "keyring"], input="prompted-kr-key\n"
        )
        assert result.exit_code == 0
        assert saved == ["prompted-kr-key"]
        assert "Saved API key to OS keyring." in result.output

    def test_auth_set_keyring_invalid_key_raises_usage_error(
        self, isolated_env: Path, monkeypatch: pytest.MonkeyPatch, cli_runner: CliRunner
    ) -> None:
        def _raise_val(key: str) -> None:
            raise ValueError("API key must not be empty.")

        monkeypatch.setattr("pwned.cli_commands.save_api_key_keyring", _raise_val)
        app = _make_cli()
        result = cli_runner.invoke(app, ["auth", "set", "  ", "--backend", "keyring"])
        assert result.exit_code == 2
        assert "API key must not be empty." in result.output

    def test_auth_set_keyring_missing_dependency_raises_click_exception(
        self, isolated_env: Path, monkeypatch: pytest.MonkeyPatch, cli_runner: CliRunner
    ) -> None:
        def _raise_rt(key: str) -> None:
            raise RuntimeError("keyring package is not installed.")

        monkeypatch.setattr("pwned.cli_commands.save_api_key_keyring", _raise_rt)
        app = _make_cli()
        result = cli_runner.invoke(app, ["auth", "set", "secret-key", "--backend", "keyring"])
        assert result.exit_code == 1
        assert "keyring package is not installed." in result.output

    def test_auth_show_configured_json(
        self, isolated_env: Path, monkeypatch: pytest.MonkeyPatch, cli_runner: CliRunner
    ) -> None:
        save_api_key("1234567890abcdef")
        monkeypatch.setattr("pwned.cli_commands.keyring_available", lambda: False)
        app = _make_cli()
        result = cli_runner.invoke(app, ["--json", "auth", "show"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data == {
            "api_key": "1234...cdef",
            "config_file": str(get_config_file()),
            "configured": True,
            "source": "xdg",
            "keyring_available": False,
        }

    def test_auth_show_cli_source_and_keyring_available(
        self, isolated_env: Path, monkeypatch: pytest.MonkeyPatch, cli_runner: CliRunner
    ) -> None:
        monkeypatch.setattr("pwned.cli_commands.keyring_available", lambda: True)
        app = _make_cli()
        result = cli_runner.invoke(app, ["--api-key", "1234567890abcdef", "--json", "auth", "show"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data == {
            "api_key": "1234...cdef",
            "config_file": str(get_config_file()),
            "configured": True,
            "source": "cli",
            "keyring_available": True,
        }

    def test_auth_show_unconfigured_text(
        self, isolated_env: Path, monkeypatch: pytest.MonkeyPatch, cli_runner: CliRunner
    ) -> None:
        monkeypatch.setattr("pwned.cli_commands.keyring_available", lambda: False)
        app = _make_cli()
        result = cli_runner.invoke(app, ["auth", "show"])
        assert result.exit_code == 0
        assert "(not set)" in result.output
        assert "configured: False" in result.output
        assert "source: none" in result.output
        assert "keyring_available: False" in result.output

    def test_auth_show_handles_missing_home_dir(
        self, isolated_env: Path, monkeypatch: pytest.MonkeyPatch, cli_runner: CliRunner
    ) -> None:
        def _raise_no_home() -> Path:
            raise RuntimeError("Could not determine home directory.")

        monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
        monkeypatch.setattr(Path, "home", _raise_no_home)
        monkeypatch.setattr("pwned.cli_commands.keyring_available", lambda: False)
        app = _make_cli()
        result = cli_runner.invoke(app, ["--json", "auth", "show"])
        assert result.exit_code == 0
        assert json.loads(result.output) == {
            "api_key": "(not set)",
            "config_file": None,
            "configured": False,
            "source": "none",
            "keyring_available": False,
        }

    def test_auth_clear_removes_existing_key(
        self, isolated_env: Path, cli_runner: CliRunner
    ) -> None:
        save_api_key("1234567890abcdef")
        app = _make_cli()
        result = cli_runner.invoke(app, ["auth", "clear"])
        assert result.exit_code == 0
        assert result.output.strip() == "API key removed."
        assert not get_config_file().exists()

    def test_auth_clear_when_not_stored(self, isolated_env: Path, cli_runner: CliRunner) -> None:
        app = _make_cli()
        result = cli_runner.invoke(app, ["auth", "clear"])
        assert result.exit_code == 0
        assert result.output.strip() == "No stored API key found."

    def test_auth_clear_keyring_removed(
        self, isolated_env: Path, monkeypatch: pytest.MonkeyPatch, cli_runner: CliRunner
    ) -> None:
        monkeypatch.setattr("pwned.cli_commands.clear_api_key_keyring", lambda: True)
        app = _make_cli()
        result = cli_runner.invoke(app, ["auth", "clear", "--backend", "keyring"])
        assert result.exit_code == 0
        assert result.output.strip() == "API key removed from OS keyring."

    def test_auth_clear_keyring_not_found(
        self, isolated_env: Path, monkeypatch: pytest.MonkeyPatch, cli_runner: CliRunner
    ) -> None:
        monkeypatch.setattr("pwned.cli_commands.clear_api_key_keyring", lambda: False)
        app = _make_cli()
        result = cli_runner.invoke(app, ["auth", "clear", "--backend", "keyring"])
        assert result.exit_code == 0
        assert result.output.strip() == "No stored API key found in OS keyring."

    def test_auth_clear_keyring_missing_dependency_raises_click_exception(
        self, isolated_env: Path, monkeypatch: pytest.MonkeyPatch, cli_runner: CliRunner
    ) -> None:
        def _raise_rt() -> bool:
            raise RuntimeError("keyring package is not installed.")

        monkeypatch.setattr("pwned.cli_commands.clear_api_key_keyring", _raise_rt)
        app = _make_cli()
        result = cli_runner.invoke(app, ["auth", "clear", "--backend", "keyring"])
        assert result.exit_code == 1
        assert "keyring package is not installed." in result.output


class TestSearchCommand:
    def test_search_account_defaults(
        self, isolated_env: Path, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        httpx_mock.add_response(
            url=f"{BASE}/breachedaccount/user%40example.com",
            json=[{"Name": "Adobe"}],
        )
        httpx_mock.add_response(
            url=f"{BASE}/pasteaccount/user%40example.com",
            json=[{"Source": "Pastebin", "Id": "abc123", "EmailCount": 42}],
        )
        app = _make_cli()
        result = cli_runner.invoke(
            app, ["--api-key", TEST_KEY, "--json", "search", "user@example.com"]
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["breaches"] == [{"Name": "Adobe"}]
        assert data["pastes"] == [{"Source": "Pastebin", "Id": "abc123", "EmailCount": 42}]
        assert data["stealer_logs"] is None

    def test_search_account_all_flags(
        self, isolated_env: Path, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        httpx_mock.add_response(
            url=(
                f"{BASE}/breachedaccount/user%40example.com"
                "?truncateResponse=false&domain=adobe.com&includeUnverified=false"
            ),
            json=[{"Name": "Adobe", "Title": "Adobe"}],
        )
        httpx_mock.add_response(
            url=f"{BASE}/pasteaccount/user%40example.com",
            status_code=404,
        )
        httpx_mock.add_response(
            url=f"{BASE}/stealerlogsbyemail/user%40example.com",
            json=["login.example.com"],
        )
        app = _make_cli()
        result = cli_runner.invoke(
            app,
            [
                "--api-key",
                TEST_KEY,
                "--json",
                "search",
                "user@example.com",
                "--no-truncate",
                "--domain",
                "adobe.com",
                "--no-include-unverified",
                "--include-stealer-logs",
            ],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["breaches"] == [{"Name": "Adobe", "Title": "Adobe"}]
        assert data["pastes"] == []
        assert data["stealer_logs"] == ["login.example.com"]

    def test_search_missing_api_key(self, isolated_env: Path, cli_runner: CliRunner) -> None:
        app = _make_cli()
        result = cli_runner.invoke(app, ["search", "user@example.com"])
        assert result.exit_code == 1
        assert "Invalid or missing API key" in result.output

    def test_search_fail_if_pwned_on_breaches(
        self, isolated_env: Path, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        httpx_mock.add_response(
            url=f"{BASE}/breachedaccount/user%40example.com",
            json=[{"Name": "Adobe"}],
        )
        httpx_mock.add_response(url=f"{BASE}/pasteaccount/user%40example.com", status_code=404)
        app = _make_cli()
        result = cli_runner.invoke(
            app, ["--api-key", TEST_KEY, "search", "user@example.com", "--fail-if-pwned"]
        )
        assert result.exit_code == 1
        assert "Adobe" in result.output

    def test_search_fail_if_pwned_on_pastes(
        self, isolated_env: Path, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        httpx_mock.add_response(url=f"{BASE}/breachedaccount/user%40example.com", status_code=404)
        httpx_mock.add_response(
            url=f"{BASE}/pasteaccount/user%40example.com",
            json=[{"Source": "Pastebin", "Id": "p1"}],
        )
        app = _make_cli()
        result = cli_runner.invoke(
            app, ["--api-key", TEST_KEY, "search", "user@example.com", "--fail-if-pwned"]
        )
        assert result.exit_code == 1
        assert "Pastebin" in result.output

    def test_search_fail_if_pwned_on_stealer_logs(
        self, isolated_env: Path, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        httpx_mock.add_response(url=f"{BASE}/breachedaccount/user%40example.com", status_code=404)
        httpx_mock.add_response(url=f"{BASE}/pasteaccount/user%40example.com", status_code=404)
        httpx_mock.add_response(
            url=f"{BASE}/stealerlogsbyemail/user%40example.com",
            json=["evil.example"],
        )
        app = _make_cli()
        result = cli_runner.invoke(
            app,
            [
                "--api-key",
                TEST_KEY,
                "search",
                "user@example.com",
                "--include-stealer-logs",
                "--fail-if-pwned",
            ],
        )
        assert result.exit_code == 1
        assert "evil.example" in result.output

    def test_search_fail_if_pwned_clean(
        self, isolated_env: Path, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        httpx_mock.add_response(url=f"{BASE}/breachedaccount/user%40example.com", status_code=404)
        httpx_mock.add_response(url=f"{BASE}/pasteaccount/user%40example.com", status_code=404)
        app = _make_cli()
        result = cli_runner.invoke(
            app, ["--api-key", TEST_KEY, "search", "user@example.com", "--fail-if-pwned"]
        )
        assert result.exit_code == 0

    def test_search_save_baseline_before_diffing(
        self, isolated_env: Path, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        prev_file = isolated_env / "prev.json"
        prev_file.write_text(
            json.dumps(
                {
                    "breaches": [{"Name": "Adobe"}],
                    "pastes": [{"Source": "Pastebin", "Id": "p1", "EmailCount": 1}],
                    "stealer_logs": ["old.example"],
                }
            ),
            encoding="utf-8",
        )
        new_file = isolated_env / "saved" / "next.json"

        httpx_mock.add_response(
            url=f"{BASE}/breachedaccount/user%40example.com",
            json=[{"Name": "Adobe"}, {"Name": "LinkedIn"}],
        )
        httpx_mock.add_response(
            url=f"{BASE}/pasteaccount/user%40example.com",
            json=[
                {"Source": "Pastebin", "Id": "p1", "EmailCount": 1},
                {"Source": "Pastebin", "Id": "p2", "EmailCount": 2},
            ],
        )
        httpx_mock.add_response(
            url=f"{BASE}/stealerlogsbyemail/user%40example.com",
            json=["old.example", "new.example"],
        )

        app = _make_cli()
        result = cli_runner.invoke(
            app,
            [
                "--api-key",
                TEST_KEY,
                "--json",
                "search",
                "user@example.com",
                "--include-stealer-logs",
                "--baseline",
                str(prev_file),
                "--save-baseline",
                str(new_file),
                "--fail-if-pwned",
            ],
        )
        assert result.exit_code == 1
        diff_data = json.loads(result.output)
        assert diff_data == {
            "breaches": [{"Name": "LinkedIn"}],
            "pastes": [{"Source": "Pastebin", "Id": "p2", "EmailCount": 2}],
            "stealer_logs": ["new.example"],
        }
        saved_data = json.loads(new_file.read_text(encoding="utf-8"))
        assert saved_data == {
            "breaches": [{"Name": "Adobe"}, {"Name": "LinkedIn"}],
            "pastes": [
                {"Source": "Pastebin", "Id": "p1", "EmailCount": 1},
                {"Source": "Pastebin", "Id": "p2", "EmailCount": 2},
            ],
            "stealer_logs": ["old.example", "new.example"],
        }

    def test_search_baseline_no_new_exposures_fail_if_pwned_exits_zero(
        self, isolated_env: Path, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        prev_file = isolated_env / "prev.json"
        prev_file.write_text(
            json.dumps({"breaches": [{"Name": "Adobe"}], "pastes": []}),
            encoding="utf-8",
        )
        httpx_mock.add_response(
            url=f"{BASE}/breachedaccount/user%40example.com",
            json=[{"Name": "Adobe"}],
        )
        httpx_mock.add_response(url=f"{BASE}/pasteaccount/user%40example.com", status_code=404)

        app = _make_cli()
        result = cli_runner.invoke(
            app,
            [
                "--api-key",
                TEST_KEY,
                "--json",
                "search",
                "user@example.com",
                "--baseline",
                str(prev_file),
                "--fail-if-pwned",
            ],
        )
        assert result.exit_code == 0
        assert json.loads(result.output) == {"breaches": [], "pastes": [], "stealer_logs": None}

    def test_search_baseline_invalid_raises_click_exception(
        self, isolated_env: Path, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        bad_file = isolated_env / "bad_baseline.json"
        bad_file.write_text("[]", encoding="utf-8")
        httpx_mock.add_response(url=f"{BASE}/breachedaccount/user%40example.com", status_code=404)
        httpx_mock.add_response(url=f"{BASE}/pasteaccount/user%40example.com", status_code=404)

        app = _make_cli()
        result = cli_runner.invoke(
            app,
            [
                "--api-key",
                TEST_KEY,
                "search",
                "user@example.com",
                "--baseline",
                str(bad_file),
            ],
        )
        assert result.exit_code == 1
        assert "Baseline search result must be a JSON object" in result.output


class TestAccountRangeCommand:
    def test_account_range_found(
        self, isolated_env: Path, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        prefix, suffix = _email_sha1_parts("user@example.com")
        httpx_mock.add_response(
            url=f"{BASE}/breachedaccount/range/{prefix}",
            json=[
                {"hashSuffix": suffix, "websites": ["Adobe", "LinkedIn"]},
                {"hashSuffix": "0" * 34, "websites": ["Other"]},
            ],
        )
        app = _make_cli()
        result = cli_runner.invoke(
            app, ["--api-key", TEST_KEY, "--json", "account-range", "user@example.com"]
        )
        assert result.exit_code == 0
        assert json.loads(result.output) == ["Adobe", "LinkedIn"]

    def test_account_range_clean_with_fail_if_pwned(
        self, isolated_env: Path, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        prefix, _ = _email_sha1_parts("clean@example.com")
        httpx_mock.add_response(
            url=f"{BASE}/breachedaccount/range/{prefix}",
            status_code=404,
        )
        app = _make_cli()
        result = cli_runner.invoke(
            app, ["--api-key", TEST_KEY, "account-range", "clean@example.com", "--fail-if-pwned"]
        )
        assert result.exit_code == 0
        assert "No results found." in result.output

    def test_account_range_fail_if_pwned_exits_one(
        self, isolated_env: Path, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        prefix, suffix = _email_sha1_parts("user@example.com")
        httpx_mock.add_response(
            url=f"{BASE}/breachedaccount/range/{prefix}",
            json=[{"hashSuffix": suffix, "websites": ["Adobe"]}],
        )
        app = _make_cli()
        result = cli_runner.invoke(
            app, ["--api-key", TEST_KEY, "account-range", "user@example.com", "--fail-if-pwned"]
        )
        assert result.exit_code == 1
        assert "Adobe" in result.output

    def test_account_range_missing_api_key(self, isolated_env: Path, cli_runner: CliRunner) -> None:
        app = _make_cli()
        result = cli_runner.invoke(app, ["account-range", "user@example.com"])
        assert result.exit_code == 1
        assert "Invalid or missing API key" in result.output


class TestDomainVerifyCommands:
    def test_dns_token(
        self, isolated_env: Path, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        httpx_mock.add_response(
            method="POST",
            url=f"{BASE}/domainVerification/generateDnsToken",
            json={"txtRecordValue": "have-i-been-pwned-verification=abc123"},
        )
        app = _make_cli()
        result = cli_runner.invoke(
            app, ["--api-key", TEST_KEY, "--json", "domain-verify", "dns-token", "example.com"]
        )
        assert result.exit_code == 0
        assert json.loads(result.output) == {
            "txtRecordValue": "have-i-been-pwned-verification=abc123"
        }

    def test_dns_check(
        self, isolated_env: Path, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        httpx_mock.add_response(
            method="POST",
            url=f"{BASE}/domainVerification/verifyDnsToken",
            status_code=204,
        )
        app = _make_cli()
        result = cli_runner.invoke(
            app, ["--api-key", TEST_KEY, "--json", "domain-verify", "dns-check", "example.com"]
        )
        assert result.exit_code == 0
        assert json.loads(result.output) == {"domain": "example.com", "verified": True}

    def test_dns_check_error(
        self, isolated_env: Path, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        httpx_mock.add_response(
            method="POST",
            url=f"{BASE}/domainVerification/verifyDnsToken",
            status_code=400,
            json={"message": "TXT record not found"},
        )
        app = _make_cli()
        result = cli_runner.invoke(
            app, ["--api-key", TEST_KEY, "domain-verify", "dns-check", "example.com"]
        )
        assert result.exit_code == 1
        assert "TXT record not found" in result.output

    def test_email_verification(
        self, isolated_env: Path, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        httpx_mock.add_response(
            method="POST",
            url=f"{BASE}/domainVerification/sendEmail",
            status_code=204,
        )
        app = _make_cli()
        result = cli_runner.invoke(
            app,
            ["--api-key", TEST_KEY, "--json", "domain-verify", "email", "example.com", "security"],
        )
        assert result.exit_code == 0
        assert json.loads(result.output) == {
            "domain": "example.com",
            "alias": "security",
            "sent": True,
        }
        req = httpx_mock.get_request()
        assert req is not None
        assert json.loads(req.content) == {"DomainName": "example.com", "EmailAlias": "security"}

    def test_email_verification_invalid_alias(
        self, isolated_env: Path, cli_runner: CliRunner
    ) -> None:
        app = _make_cli()
        result = cli_runner.invoke(
            app, ["--api-key", TEST_KEY, "domain-verify", "email", "example.com", "nobody"]
        )
        assert result.exit_code == 2

    def test_meta_tag(
        self, isolated_env: Path, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        httpx_mock.add_response(
            method="POST",
            url=f"{BASE}/domainVerification/generateMetaTag",
            json={"metaTag": '<meta name="hibp" content="abc123" />'},
        )
        app = _make_cli()
        result = cli_runner.invoke(
            app, ["--api-key", TEST_KEY, "--json", "domain-verify", "meta-tag", "example.com"]
        )
        assert result.exit_code == 0
        assert json.loads(result.output) == {"metaTag": '<meta name="hibp" content="abc123" />'}

    def test_meta_check(
        self, isolated_env: Path, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        httpx_mock.add_response(
            method="POST",
            url=f"{BASE}/domainVerification/verifyMetaTag",
            status_code=204,
        )
        app = _make_cli()
        result = cli_runner.invoke(
            app, ["--api-key", TEST_KEY, "--json", "domain-verify", "meta-check", "example.com"]
        )
        assert result.exit_code == 0
        assert json.loads(result.output) == {"domain": "example.com", "verified": True}

    def test_meta_check_error(
        self, isolated_env: Path, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        httpx_mock.add_response(
            method="POST",
            url=f"{BASE}/domainVerification/verifyMetaTag",
            status_code=400,
            json={"message": "Meta tag not found"},
        )
        app = _make_cli()
        result = cli_runner.invoke(
            app, ["--api-key", TEST_KEY, "domain-verify", "meta-check", "example.com"]
        )
        assert result.exit_code == 1
        assert "Meta tag not found" in result.output

    def test_domain_verify_requires_api_key(
        self, isolated_env: Path, cli_runner: CliRunner
    ) -> None:
        app = _make_cli()
        for subcmd in (
            ["domain-verify", "dns-token", "example.com"],
            ["domain-verify", "dns-check", "example.com"],
            ["domain-verify", "email", "example.com", "admin"],
            ["domain-verify", "meta-tag", "example.com"],
            ["domain-verify", "meta-check", "example.com"],
        ):
            result = cli_runner.invoke(app, subcmd)
            assert result.exit_code == 1
            assert "Invalid or missing API key" in result.output


class TestAuditCommand:
    def test_audit_bitwarden_json_default_padding(
        self, isolated_env: Path, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        export_file = isolated_env / "bw.json"
        export_file.write_text(
            json.dumps(
                {
                    "items": [
                        {"name": "SiteA", "login": {"username": "a@x.com", "password": "password"}},
                        {
                            "name": "SiteB",
                            "login": {"username": "b@x.com", "password": "safe!pw99"},
                        },
                    ]
                }
            ),
            encoding="utf-8",
        )
        p_bad, s_bad = _sha1_parts("password")
        p_ok, _ = _sha1_parts("safe!pw99")
        httpx_mock.add_response(
            url=f"{PASSWORDS_BASE}/range/{p_bad}",
            text=f"{s_bad}:12345\n",
        )
        httpx_mock.add_response(
            url=f"{PASSWORDS_BASE}/range/{p_ok}",
            text="0" * 35 + ":0\n",
        )

        app = _make_cli()
        result = cli_runner.invoke(app, ["--json", "audit", str(export_file)])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data == {
            "total_entries": 2,
            "unique_passwords": 2,
            "compromised_entries": 1,
            "findings": [{"name": "SiteA", "username": "a@x.com", "pwn_count": 12345}],
        }
        assert "safe!pw99" not in result.output
        for req in httpx_mock.get_requests():
            assert req.headers.get("add-padding") == "true"

    def test_audit_bitwarden_csv_ntlm_no_pad_threshold(
        self, isolated_env: Path, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        export_file = isolated_env / "bw.csv"
        export_file.write_text(
            "name,login_username,login_password\nLowCount,u1,pwlow\nHighCount,u2,pwhigh\n",
            encoding="utf-8",
        )
        h_low = _ntlm_hash("pwlow")
        h_high = _ntlm_hash("pwhigh")
        httpx_mock.add_response(
            url=f"{PASSWORDS_BASE}/range/{h_low[:5]}?mode=ntlm",
            text=f"{h_low[5:]}:5\n",
        )
        httpx_mock.add_response(
            url=f"{PASSWORDS_BASE}/range/{h_high[:5]}?mode=ntlm",
            text=f"{h_high[5:]}:50\n",
        )

        app = _make_cli()
        result = cli_runner.invoke(
            app,
            [
                "--json",
                "audit",
                str(export_file),
                "--source",
                "bitwarden-csv",
                "--ntlm",
                "--no-pad",
                "--threshold",
                "10",
                "--fail-if-pwned",
            ],
        )
        assert result.exit_code == 1
        data = json.loads(result.output)
        assert data["total_entries"] == 2
        assert data["compromised_entries"] == 1
        assert data["findings"] == [{"name": "HighCount", "username": "u2", "pwn_count": 50}]
        for req in httpx_mock.get_requests():
            assert "add-padding" not in req.headers

    def test_audit_generic_csv_clean_with_fail_if_pwned(
        self, isolated_env: Path, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        export_file = isolated_env / "generic.csv"
        export_file.write_text("title,email,password\nBank,a@b.com,goodpw\n", encoding="utf-8")
        p_ok, _ = _sha1_parts("goodpw")
        httpx_mock.add_response(url=f"{PASSWORDS_BASE}/range/{p_ok}", text="")

        app = _make_cli()
        result = cli_runner.invoke(
            app, ["audit", str(export_file), "--source", "csv", "--fail-if-pwned"]
        )
        assert result.exit_code == 0
        assert "total_entries: 1" in result.output

    def test_audit_keepass_prompts_and_handles_runtime_error(
        self, isolated_env: Path, monkeypatch: pytest.MonkeyPatch, cli_runner: CliRunner
    ) -> None:
        db_file = isolated_env / "vault.kdbx"
        db_file.write_bytes(b"placeholder")

        def fake_load_export(
            path: Path, *, source: str, master_password: str | None = None
        ) -> list[AuditEntry]:
            raise RuntimeError("KeePass support requires the optional 'keepass' dependency")

        monkeypatch.setattr("pwned.cli_commands.load_export", fake_load_export)
        app = _make_cli()
        result = cli_runner.invoke(
            app,
            ["audit", str(db_file), "--source", "keepass"],
            input="masterpw\n",
        )
        assert result.exit_code == 1
        assert "KeePass master password" in result.output
        assert "optional 'keepass' dependency" in result.output

    def test_audit_keepass_success(
        self,
        isolated_env: Path,
        monkeypatch: pytest.MonkeyPatch,
        httpx_mock: HTTPXMock,
        cli_runner: CliRunner,
    ) -> None:
        db_file = isolated_env / "vault.kdbx"
        db_file.write_bytes(b"placeholder")
        captured: dict[str, object] = {}

        def fake_load_export(
            path: Path, *, source: str, master_password: str | None = None
        ) -> list[AuditEntry]:
            captured["source"] = source
            captured["master_password"] = master_password
            return [AuditEntry(name="KPEntry", username="kpuser", password="leakedpw")]

        monkeypatch.setattr("pwned.cli_commands.load_export", fake_load_export)
        prefix, suffix = _sha1_parts("leakedpw")
        httpx_mock.add_response(url=f"{PASSWORDS_BASE}/range/{prefix}", text=f"{suffix}:9\n")

        app = _make_cli()
        result = cli_runner.invoke(
            app,
            ["--json", "audit", str(db_file), "--source", "keepass"],
            input="secret-master\n",
        )
        assert result.exit_code == 0
        assert captured == {"source": "keepass", "master_password": "secret-master"}
        assert "KeePass master password" in result.output
        data = json.loads(result.output[result.output.index("{") :])
        assert data["compromised_entries"] == 1

    def test_audit_invalid_export_raises_click_exception(
        self, isolated_env: Path, cli_runner: CliRunner
    ) -> None:
        bad_file = isolated_env / "bad.json"
        bad_file.write_text("{not valid json", encoding="utf-8")
        app = _make_cli()
        result = cli_runner.invoke(app, ["audit", str(bad_file)])
        assert result.exit_code == 1
        assert "Error:" in result.output

    def test_audit_bitwarden_encrypted_json_prompts_and_passes_password(
        self,
        isolated_env: Path,
        monkeypatch: pytest.MonkeyPatch,
        httpx_mock: HTTPXMock,
        cli_runner: CliRunner,
    ) -> None:
        enc_file = isolated_env / "bw_enc.json"
        enc_file.write_text("{}", encoding="utf-8")
        captured: dict[str, object] = {}

        def fake_load_export(
            path: Path, *, source: str, master_password: str | None = None
        ) -> list[AuditEntry]:
            captured["source"] = source
            captured["master_password"] = master_password
            return [AuditEntry(name="EncSite", username="enc@x.com", password="leakedpw")]

        monkeypatch.setattr("pwned.cli_commands.load_export", fake_load_export)
        prefix, suffix = _sha1_parts("leakedpw")
        httpx_mock.add_response(url=f"{PASSWORDS_BASE}/range/{prefix}", text=f"{suffix}:12\n")

        app = _make_cli()
        result = cli_runner.invoke(
            app,
            ["--json", "audit", str(enc_file), "--source", "bitwarden-encrypted-json"],
            input="export-pw\n",
        )
        assert result.exit_code == 0
        assert captured == {
            "source": "bitwarden-encrypted-json",
            "master_password": "export-pw",
        }
        assert "Bitwarden export password" in result.output
        data = json.loads(result.output[result.output.index("{") :])
        assert data["compromised_entries"] == 1

    @pytest.mark.parametrize(
        ("source", "filename", "content"),
        [
            (
                "1password-csv",
                "1p.csv",
                "Title,Url,Username,Password\nBank,https://bank.test,u1,pw1\n",
            ),
            (
                "chrome-csv",
                "chrome.csv",
                "name,url,username,password\nBank,https://bank.test,u1,pw1\n",
            ),
            (
                "firefox-csv",
                "firefox.csv",
                "url,username,password\nhttps://bank.test,u1,pw1\n",
            ),
            (
                "apple-csv",
                "apple.csv",
                "Title,URL,Username,Password\nBank,https://bank.test,u1,pw1\n",
            ),
        ],
    )
    def test_audit_expanded_csv_sources(
        self,
        isolated_env: Path,
        httpx_mock: HTTPXMock,
        cli_runner: CliRunner,
        source: str,
        filename: str,
        content: str,
    ) -> None:
        export_file = isolated_env / filename
        export_file.write_text(content, encoding="utf-8")
        prefix, suffix = _sha1_parts("pw1")
        httpx_mock.add_response(url=f"{PASSWORDS_BASE}/range/{prefix}", text=f"{suffix}:3\n")

        app = _make_cli()
        result = cli_runner.invoke(app, ["--json", "audit", str(export_file), "--source", source])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["total_entries"] == 1
        assert data["compromised_entries"] == 1

    def test_audit_1password_1pux_source(
        self, isolated_env: Path, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        pux_file = isolated_env / "vault.1pux"
        payload = {
            "accounts": [
                {
                    "vaults": [
                        {
                            "items": [
                                {
                                    "overview": {"title": "Mail"},
                                    "details": {
                                        "loginFields": [
                                            {"designation": "username", "value": "me@x.com"},
                                            {"designation": "password", "value": "pw1"},
                                        ]
                                    },
                                }
                            ]
                        }
                    ]
                }
            ]
        }
        with zipfile.ZipFile(pux_file, "w") as zf:
            zf.writestr("export.data", json.dumps(payload))

        prefix, suffix = _sha1_parts("pw1")
        httpx_mock.add_response(url=f"{PASSWORDS_BASE}/range/{prefix}", text=f"{suffix}:7\n")

        app = _make_cli()
        result = cli_runner.invoke(
            app, ["--json", "audit", str(pux_file), "--source", "1password-1pux"]
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["findings"] == [{"name": "Mail", "username": "me@x.com", "pwn_count": 7}]

    def test_audit_check_reuse_and_concurrency(
        self, isolated_env: Path, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        export_file = isolated_env / "reuse.csv"
        export_file.write_text(
            "name,username,password\nSite1,u1,sharedpw\nSite2,u2,sharedpw\nSite3,u3,uniquepw\n",
            encoding="utf-8",
        )
        p_shared, s_shared = _sha1_parts("sharedpw")
        p_unique, _ = _sha1_parts("uniquepw")
        httpx_mock.add_response(url=f"{PASSWORDS_BASE}/range/{p_shared}", text=f"{s_shared}:20\n")
        httpx_mock.add_response(url=f"{PASSWORDS_BASE}/range/{p_unique}", text="")

        app = _make_cli()
        result = cli_runner.invoke(
            app,
            [
                "--json",
                "audit",
                str(export_file),
                "--source",
                "csv",
                "--check-reuse",
                "--concurrency",
                "2",
            ],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["total_entries"] == 3
        assert data["unique_passwords"] == 2
        assert data["compromised_entries"] == 2
        assert data["reused_groups"] == [
            {
                "entries": ["Site1 (u1)", "Site2 (u2)"],
                "count": 2,
                "pwn_count": 20,
            }
        ]

    def test_audit_invalid_concurrency_raises_usage_error(
        self, isolated_env: Path, cli_runner: CliRunner
    ) -> None:
        export_file = isolated_env / "ok.csv"
        export_file.write_text("name,username,password\nS,u,pw\n", encoding="utf-8")
        app = _make_cli()
        result = cli_runner.invoke(
            app, ["audit", str(export_file), "--source", "csv", "--concurrency", "0"]
        )
        assert result.exit_code == 2

    def test_audit_offline_db_sha1_and_ntlm_with_reuse(
        self, isolated_env: Path, cli_runner: CliRunner
    ) -> None:
        export_file = isolated_env / "vault.csv"
        export_file.write_text(
            "name,username,password\n"
            "SiteA,a@x.com,password\n"
            "SiteB,b@x.com,password\n"
            "SiteC,c@x.com,safe!pw99\n",
            encoding="utf-8",
        )
        sha1_lines = sorted([f"{_sha1_hex('password')}:999\n", f"{_sha1_hex('other')}:1\n"])
        sha1_db = isolated_env / "sha1.txt"
        sha1_db.write_text("".join(sha1_lines), encoding="utf-8")

        app = _make_cli()
        res_sha1 = cli_runner.invoke(
            app,
            [
                "--json",
                "audit",
                str(export_file),
                "--source",
                "csv",
                "--offline-db",
                str(sha1_db),
                "--check-reuse",
                "--fail-if-pwned",
            ],
        )
        assert res_sha1.exit_code == 1
        data_sha1 = json.loads(res_sha1.output)
        assert data_sha1["compromised_entries"] == 2
        assert data_sha1["reused_groups"] == [
            {
                "entries": ["SiteA (a@x.com)", "SiteB (b@x.com)"],
                "count": 2,
                "pwn_count": 999,
            }
        ]

        ntlm_db = isolated_env / "ntlm.txt"
        ntlm_db.write_text(f"{_ntlm_hash('safe!pw99')}:42\n", encoding="utf-8")
        res_ntlm = cli_runner.invoke(
            app,
            [
                "--json",
                "audit",
                str(export_file),
                "--source",
                "csv",
                "--offline-db",
                str(ntlm_db),
                "--ntlm",
            ],
        )
        assert res_ntlm.exit_code == 0
        data_ntlm = json.loads(res_ntlm.output)
        assert data_ntlm["compromised_entries"] == 1
        assert data_ntlm["findings"] == [{"name": "SiteC", "username": "c@x.com", "pwn_count": 42}]


class TestCompletionCommand:
    @pytest.mark.parametrize("shell", ["bash", "zsh", "fish"])
    def test_completion_generates_script(self, cli_runner: CliRunner, shell: str) -> None:
        app = _make_cli()
        result = cli_runner.invoke(app, ["completion", shell])
        assert result.exit_code == 0
        assert "_PWNED_COMPLETE" in result.output
        assert "pwned" in result.output

    def test_completion_invalid_shell_rejected(self, cli_runner: CliRunner) -> None:
        app = _make_cli()
        result = cli_runner.invoke(app, ["completion", "powershell"])
        assert result.exit_code == 2
        assert "Invalid value for" in result.output


class TestCacheCommands:
    def test_cache_clear_text(self, isolated_env: Path, cli_runner: CliRunner) -> None:
        cache = ResponseCache()
        cache.set("/breaches", b"[]")
        cache.set("/dataclasses", b"[]")
        app = _make_cli()
        result = cli_runner.invoke(app, ["cache", "clear"])
        assert result.exit_code == 0
        assert result.output.strip() == "Cleared 2 cached entries."

    def test_cache_clear_json(self, isolated_env: Path, cli_runner: CliRunner) -> None:
        cache = ResponseCache()
        cache.set("/breaches", b"[]")
        app = _make_cli()
        result = cli_runner.invoke(app, ["--json", "cache", "clear"])
        assert result.exit_code == 0
        assert json.loads(result.output) == {"cleared": 1}
