from __future__ import annotations

import hashlib
import json
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
        ctx.obj["fmt"] = resolved_fmt
        ctx.obj["use_json"] = use_json
        ctx.obj["use_cache"] = use_cache

    register_extra_commands(group)
    return group


def _sha1_parts(value: str) -> tuple[str, str]:
    digest = hashlib.sha1(value.encode("utf-8")).hexdigest().upper()
    return digest[:5], digest[5:]


def _email_sha1_parts(email: str) -> tuple[str, str]:
    digest = hashlib.sha1(email.strip().lower().encode("utf-8")).hexdigest().upper()
    return digest[:6], digest[6:]


@pytest.fixture
def isolated_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    monkeypatch.delenv("HIBP_API_KEY", raising=False)
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

    def test_auth_show_configured_json(self, isolated_env: Path, cli_runner: CliRunner) -> None:
        save_api_key("1234567890abcdef")
        app = _make_cli()
        result = cli_runner.invoke(app, ["--json", "auth", "show"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data == {
            "api_key": "1234...cdef",
            "config_file": str(get_config_file()),
            "configured": True,
        }

    def test_auth_show_unconfigured_text(self, isolated_env: Path, cli_runner: CliRunner) -> None:
        app = _make_cli()
        result = cli_runner.invoke(app, ["auth", "show"])
        assert result.exit_code == 0
        assert "(not set)" in result.output
        assert "configured: False" in result.output

    def test_auth_show_handles_missing_home_dir(
        self, isolated_env: Path, monkeypatch: pytest.MonkeyPatch, cli_runner: CliRunner
    ) -> None:
        def _raise_no_home() -> Path:
            raise RuntimeError("Could not determine home directory.")

        monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
        monkeypatch.setattr(Path, "home", _raise_no_home)
        app = _make_cli()
        result = cli_runner.invoke(app, ["--json", "auth", "show"])
        assert result.exit_code == 0
        assert json.loads(result.output) == {
            "api_key": "(not set)",
            "config_file": None,
            "configured": False,
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

    def test_domain_verify_requires_api_key(
        self, isolated_env: Path, cli_runner: CliRunner
    ) -> None:
        app = _make_cli()
        for subcmd in (
            ["domain-verify", "dns-token", "example.com"],
            ["domain-verify", "dns-check", "example.com"],
            ["domain-verify", "email", "example.com", "admin"],
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
