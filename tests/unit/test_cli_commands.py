from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path
from typing import Any

import click
import pytest
from click.testing import CliRunner
from pytest_httpx import HTTPXMock

from pwned.audit import AuditEntry
from pwned.cache import ResponseCache
from pwned.cli_commands import register_extra_commands
from pwned.client import HIBPError
from pwned.config import get_config_file, load_settings, save_api_key
from pwned.offline_download import DownloadStats
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
    @click.option("--outfile", type=click.Path(dir_okay=False, path_type=Path), default=None)
    @click.option("--force", is_flag=True)
    @click.pass_context
    def group(
        ctx: click.Context,
        api_key: str | None,
        user_agent: str | None,
        fmt: str,
        use_json: bool,
        use_cache: bool,
        outfile: Path | None,
        force: bool,
    ) -> None:
        resolved_fmt = "json" if use_json else fmt
        ctx.ensure_object(dict)
        ctx.obj["settings"] = load_settings(api_key=api_key, user_agent=user_agent)
        ctx.obj["cli_api_key"] = api_key
        ctx.obj["fmt"] = resolved_fmt
        ctx.obj["use_json"] = use_json
        ctx.obj["use_cache"] = use_cache
        ctx.obj["outfile"] = outfile
        ctx.obj["force"] = force

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
        assert "HIBP API key" in result.stderr
        assert "HIBP API key" not in result.stdout
        assert f"Saved API key to {expected_path}" in result.stdout
        assert "HIBP_API_KEY=prompted-secret-key" in expected_path.read_text(encoding="utf-8")

    def test_auth_set_stdin_success(
        self, isolated_env: Path, monkeypatch: pytest.MonkeyPatch, cli_runner: CliRunner
    ) -> None:
        monkeypatch.setattr("pwned.cli_commands.keyring_available", lambda: False)
        app = _make_cli()
        result = cli_runner.invoke(app, ["auth", "set", "--stdin"], input="stdin-secret-key\n")
        assert result.exit_code == 0
        expected_path = get_config_file()
        assert f"Saved API key to {expected_path}" in result.output
        assert expected_path.read_text(encoding="utf-8") == "HIBP_API_KEY=stdin-secret-key\n"

    def test_auth_set_stdin_strips_crlf_and_reads_first_line(
        self, isolated_env: Path, monkeypatch: pytest.MonkeyPatch, cli_runner: CliRunner
    ) -> None:
        monkeypatch.setattr("pwned.cli_commands.keyring_available", lambda: False)
        app = _make_cli()
        result = cli_runner.invoke(
            app,
            ["auth", "set", "--stdin"],
            input="crlf-secret-key\r\nignored-second-line\n",
        )
        assert result.exit_code == 0
        assert get_config_file().read_text(encoding="utf-8") == "HIBP_API_KEY=crlf-secret-key\n"

    @pytest.mark.parametrize("raw_input", ["", "\n", "\r\n"])
    def test_auth_set_stdin_empty_raises_usage_error(
        self, isolated_env: Path, cli_runner: CliRunner, raw_input: str
    ) -> None:
        app = _make_cli()
        result = cli_runner.invoke(app, ["auth", "set", "--stdin"], input=raw_input)
        assert result.exit_code == 2
        assert "No API key provided on stdin." in result.output

    def test_auth_set_arg_and_stdin_conflict_raises_usage_error(
        self, isolated_env: Path, cli_runner: CliRunner
    ) -> None:
        app = _make_cli()
        result = cli_runner.invoke(
            app, ["auth", "set", "inline-key", "--stdin"], input="stdin-key\n"
        )
        assert result.exit_code == 2
        assert "Cannot specify both API_KEY and --stdin." in result.output

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
        assert result.exit_code == 7
        assert "keyring package is not installed." in result.output

    def test_auth_set_auto_prefers_keyring_when_available(
        self, isolated_env: Path, monkeypatch: pytest.MonkeyPatch, cli_runner: CliRunner
    ) -> None:
        saved: list[str] = []
        monkeypatch.setattr("pwned.cli_commands.keyring_available", lambda: True)
        monkeypatch.setattr("pwned.cli_commands.save_api_key_keyring", saved.append)
        app = _make_cli()
        result = cli_runner.invoke(app, ["auth", "set", "auto-kr-key"])
        assert result.exit_code == 0
        assert saved == ["auto-kr-key"]
        assert result.output.strip() == "Saved API key to OS keyring."
        assert not get_config_file().exists()

    def test_auth_set_auto_removes_stale_config_file_so_keyring_wins(
        self, isolated_env: Path, monkeypatch: pytest.MonkeyPatch, cli_runner: CliRunner
    ) -> None:
        save_api_key("old-file-key")
        stored: dict[str, str] = {}

        def _save_kr(key: str) -> None:
            stored["key"] = key

        monkeypatch.setattr("pwned.cli_commands.keyring_available", lambda: True)
        monkeypatch.setattr("pwned.cli_commands.save_api_key_keyring", _save_kr)
        monkeypatch.setattr("pwned.config.get_keyring_api_key", lambda: stored.get("key"))
        app = _make_cli()
        result = cli_runner.invoke(app, ["auth", "set", "new-keyring-key"])
        assert result.exit_code == 0
        assert (
            result.output.strip()
            == "Saved API key to OS keyring (removed previous key from config file)."
        )
        assert not get_config_file().exists()
        assert load_settings().get_api_key() == "new-keyring-key"

    def test_auth_set_keyring_removes_stale_config_file_so_keyring_wins(
        self, isolated_env: Path, monkeypatch: pytest.MonkeyPatch, cli_runner: CliRunner
    ) -> None:
        save_api_key("old-file-key")
        stored: dict[str, str] = {}

        def _save_kr(key: str) -> None:
            stored["key"] = key

        monkeypatch.setattr("pwned.cli_commands.save_api_key_keyring", _save_kr)
        monkeypatch.setattr("pwned.config.get_keyring_api_key", lambda: stored.get("key"))
        app = _make_cli()
        result = cli_runner.invoke(app, ["auth", "set", "new-keyring-key", "--backend", "keyring"])
        assert result.exit_code == 0
        assert (
            result.output.strip()
            == "Saved API key to OS keyring (removed previous key from config file)."
        )
        assert not get_config_file().exists()
        assert load_settings().get_api_key() == "new-keyring-key"

    def test_auth_set_auto_invalid_key_does_not_fallback(
        self, isolated_env: Path, monkeypatch: pytest.MonkeyPatch, cli_runner: CliRunner
    ) -> None:
        def _raise_val(key: str) -> None:
            raise ValueError("API key must not be empty.")

        monkeypatch.setattr("pwned.cli_commands.keyring_available", lambda: True)
        monkeypatch.setattr("pwned.cli_commands.save_api_key_keyring", _raise_val)
        app = _make_cli()
        result = cli_runner.invoke(app, ["auth", "set", "   "])
        assert result.exit_code == 2
        assert "API key must not be empty." in result.output

    def test_auth_set_auto_falls_back_to_file_when_keyring_fails(
        self, isolated_env: Path, monkeypatch: pytest.MonkeyPatch, cli_runner: CliRunner
    ) -> None:
        def _raise_err(key: str) -> None:
            raise RuntimeError("No unlocked keyring backend.")

        monkeypatch.setattr("pwned.cli_commands.keyring_available", lambda: True)
        monkeypatch.setattr("pwned.cli_commands.save_api_key_keyring", _raise_err)
        app = _make_cli()
        result = cli_runner.invoke(app, ["auth", "set", "fallback-key"])
        assert result.exit_code == 0
        assert "falling back to file storage" in result.stderr
        assert "HIBP_API_KEY=fallback-key" in get_config_file().read_text(encoding="utf-8")

    def test_auth_set_explicit_file_skips_keyring(
        self, isolated_env: Path, monkeypatch: pytest.MonkeyPatch, cli_runner: CliRunner
    ) -> None:
        monkeypatch.setattr("pwned.cli_commands.keyring_available", lambda: True)
        app = _make_cli()
        result = cli_runner.invoke(app, ["auth", "set", "file-only-key", "--backend", "file"])
        assert result.exit_code == 0
        assert "HIBP_API_KEY=file-only-key" in get_config_file().read_text(encoding="utf-8")

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

    def test_auth_show_writes_to_stdout_ignoring_outfile(
        self, isolated_env: Path, monkeypatch: pytest.MonkeyPatch, cli_runner: CliRunner
    ) -> None:
        save_api_key("1234567890abcdef")
        monkeypatch.setattr("pwned.cli_commands.keyring_available", lambda: False)

        def _fail_render(*args: Any, **kwargs: Any) -> None:
            raise AssertionError("auth show must write directly to stdout")

        monkeypatch.setattr("pwned.cli_commands.render_output", _fail_render)
        out_file = isolated_env / "out.json"
        app = _make_cli()
        result = cli_runner.invoke(app, ["--outfile", str(out_file), "--json", "auth", "show"])
        assert result.exit_code == 0
        assert not out_file.exists()
        data = json.loads(result.stdout)
        assert data["configured"] is True
        assert data["api_key"] == "1234...cdef"

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
        assert result.exit_code == 7
        assert "keyring package is not installed." in result.output

    def test_auth_clear_auto_removes_both_keyring_and_file(
        self, isolated_env: Path, monkeypatch: pytest.MonkeyPatch, cli_runner: CliRunner
    ) -> None:
        save_api_key("1234567890abcdef")
        monkeypatch.setattr("pwned.cli_commands.keyring_available", lambda: True)
        monkeypatch.setattr("pwned.cli_commands.clear_api_key_keyring", lambda: True)
        app = _make_cli()
        result = cli_runner.invoke(app, ["auth", "clear"])
        assert result.exit_code == 0
        assert result.output.strip() == "API key removed from OS keyring and config file."
        assert not get_config_file().exists()

    def test_auth_clear_auto_removes_keyring_only(
        self, isolated_env: Path, monkeypatch: pytest.MonkeyPatch, cli_runner: CliRunner
    ) -> None:
        monkeypatch.setattr("pwned.cli_commands.keyring_available", lambda: True)
        monkeypatch.setattr("pwned.cli_commands.clear_api_key_keyring", lambda: True)
        app = _make_cli()
        result = cli_runner.invoke(app, ["auth", "clear"])
        assert result.exit_code == 0
        assert result.output.strip() == "API key removed from OS keyring."

    def test_auth_clear_auto_clears_file_and_reports_keyring_error(
        self, isolated_env: Path, monkeypatch: pytest.MonkeyPatch, cli_runner: CliRunner
    ) -> None:
        def _raise_err() -> bool:
            raise RuntimeError("No unlocked keyring backend.")

        save_api_key("1234567890abcdef")
        monkeypatch.setattr("pwned.cli_commands.keyring_available", lambda: True)
        monkeypatch.setattr("pwned.cli_commands.clear_api_key_keyring", _raise_err)
        app = _make_cli()
        result = cli_runner.invoke(app, ["auth", "clear"])
        assert result.exit_code == 7
        assert "API key removed from config file." in result.stdout
        assert "Failed to clear OS keyring: No unlocked keyring backend." in result.stderr
        assert not get_config_file().exists()

    def test_auth_clear_auto_reports_keyring_error_without_file_key(
        self, isolated_env: Path, monkeypatch: pytest.MonkeyPatch, cli_runner: CliRunner
    ) -> None:
        def _raise_err() -> bool:
            raise RuntimeError("No unlocked keyring backend.")

        monkeypatch.setattr("pwned.cli_commands.keyring_available", lambda: True)
        monkeypatch.setattr("pwned.cli_commands.clear_api_key_keyring", _raise_err)
        app = _make_cli()
        result = cli_runner.invoke(app, ["auth", "clear"])
        assert result.exit_code == 7
        assert "API key removed from config file." not in result.output
        assert "Failed to clear OS keyring: No unlocked keyring backend." in result.stderr

    def test_auth_clear_explicit_file_backend(
        self, isolated_env: Path, cli_runner: CliRunner
    ) -> None:
        save_api_key("1234567890abcdef")
        app = _make_cli()
        res_removed = cli_runner.invoke(app, ["auth", "clear", "--backend", "file"])
        assert res_removed.exit_code == 0
        assert res_removed.output.strip() == "API key removed."

        res_missing = cli_runner.invoke(app, ["auth", "clear", "--backend", "file"])
        assert res_missing.exit_code == 0
        assert res_missing.output.strip() == "No stored API key found."


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
        assert result.exit_code == 3
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
        assert result.exit_code == 8
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
        assert result.exit_code == 8
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
        assert result.exit_code == 8
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

    def test_search_full_and_fail_if_found_aliases(
        self, isolated_env: Path, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        httpx_mock.add_response(
            url=f"{BASE}/breachedaccount/user%40example.com?truncateResponse=false",
            json=[{"Name": "Adobe", "Title": "Adobe"}],
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
                "--full",
                "--fail-if-found",
            ],
        )
        assert result.exit_code == 8
        data = json.loads(result.output)
        assert data["breaches"] == [{"Name": "Adobe", "Title": "Adobe"}]

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
        assert result.exit_code == 8
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
        assert result.exit_code == 7
        assert "Baseline search result must be a JSON object" in result.output

    def test_search_notify_webhook_posts_before_fail_if_pwned(
        self, isolated_env: Path, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        httpx_mock.add_response(
            url=f"{BASE}/breachedaccount/user%40example.com",
            json=[{"Name": "Adobe"}],
        )
        httpx_mock.add_response(url=f"{BASE}/pasteaccount/user%40example.com", status_code=404)
        httpx_mock.add_response(
            method="POST",
            url="https://hooks.slack.com/services/T00/B00/XXX",
            status_code=200,
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
                "--notify-webhook",
                "https://hooks.slack.com/services/T00/B00/XXX",
                "--webhook-format",
                "slack",
                "--fail-if-pwned",
            ],
        )
        assert result.exit_code == 8
        assert json.loads(result.output)["breaches"] == [{"Name": "Adobe"}]
        webhook_reqs = [r for r in httpx_mock.get_requests() if r.method == "POST"]
        assert len(webhook_reqs) == 1
        payload = json.loads(webhook_reqs[0].content)
        assert "pwned Search Alert: user@example.com" in payload["text"]
        assert "blocks" in payload

    def test_search_notify_webhook_clean_skips_post(
        self, isolated_env: Path, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        httpx_mock.add_response(url=f"{BASE}/breachedaccount/clean%40example.com", status_code=404)
        httpx_mock.add_response(url=f"{BASE}/pasteaccount/clean%40example.com", status_code=404)
        app = _make_cli()
        result = cli_runner.invoke(
            app,
            [
                "--api-key",
                TEST_KEY,
                "search",
                "clean@example.com",
                "--notify-webhook",
                "https://example.com/webhook",
            ],
        )
        assert result.exit_code == 0
        assert [r for r in httpx_mock.get_requests() if r.method == "POST"] == []

    def test_search_notify_webhook_invalid_url_raises_usage_error(
        self, isolated_env: Path, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
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
                "--notify-webhook",
                "http://insecure.example/hook",
            ],
        )
        assert result.exit_code == 2
        assert "https scheme" in result.output


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

    def test_account_range_fail_if_pwned_exits_eight(
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
        assert result.exit_code == 8
        assert "Adobe" in result.output

    def test_account_range_missing_api_key(self, isolated_env: Path, cli_runner: CliRunner) -> None:
        app = _make_cli()
        result = cli_runner.invoke(app, ["account-range", "user@example.com"])
        assert result.exit_code == 3
        assert "Invalid or missing API key" in result.output

    def test_account_range_email_fail_if_found_alias(
        self, isolated_env: Path, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        prefix, suffix = _email_sha1_parts("user@example.com")
        httpx_mock.add_response(
            url=f"{BASE}/breachedaccount/range/{prefix}",
            json=[{"hashSuffix": suffix, "websites": ["Adobe"]}],
        )
        app = _make_cli()
        result = cli_runner.invoke(
            app, ["--api-key", TEST_KEY, "account-range", "user@example.com", "--fail-if-found"]
        )
        assert result.exit_code == 8
        assert "Adobe" in result.output

    def test_account_range_raw_prefix_found_json_and_text(
        self, isolated_env: Path, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        suffix = "A" * 34
        httpx_mock.add_response(
            url=f"{BASE}/breachedaccount/range/21BD12",
            json=[{"hashSuffix": suffix, "websites": ["Adobe", "LinkedIn"]}],
        )
        httpx_mock.add_response(
            url=f"{BASE}/breachedaccount/range/21BD12",
            json=[{"hashSuffix": suffix, "websites": ["Adobe", "LinkedIn"]}],
        )
        app = _make_cli()
        res_json = cli_runner.invoke(
            app, ["--api-key", TEST_KEY, "--json", "account-range", "21bd12"]
        )
        assert res_json.exit_code == 0
        assert json.loads(res_json.output) == [
            {"hashSuffix": suffix, "websites": ["Adobe", "LinkedIn"]}
        ]

        res_text = cli_runner.invoke(app, ["--api-key", TEST_KEY, "account-range", "21BD12"])
        assert res_text.exit_code == 0
        assert suffix in res_text.output
        assert "Adobe, LinkedIn" in res_text.output

    def test_account_range_raw_prefix_fail_if_found_exits_eight(
        self, isolated_env: Path, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        httpx_mock.add_response(
            url=f"{BASE}/breachedaccount/range/21BD12",
            json=[{"hashSuffix": "B" * 34, "websites": ["Adobe"]}],
        )
        app = _make_cli()
        result = cli_runner.invoke(
            app, ["--api-key", TEST_KEY, "account-range", "21BD12", "--fail-if-found"]
        )
        assert result.exit_code == 8
        assert "Adobe" in result.output

    def test_account_range_raw_prefix_not_found_returns_empty(
        self, isolated_env: Path, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        httpx_mock.add_response(
            url=f"{BASE}/breachedaccount/range/ABCDEF",
            status_code=404,
        )
        app = _make_cli()
        result = cli_runner.invoke(
            app, ["--api-key", TEST_KEY, "--json", "account-range", "ABCDEF", "--fail-if-found"]
        )
        assert result.exit_code == 0
        assert json.loads(result.output) == []

    def test_account_range_invalid_target_raises_usage_error(
        self, isolated_env: Path, cli_runner: CliRunner
    ) -> None:
        app = _make_cli()
        result = cli_runner.invoke(app, ["--api-key", TEST_KEY, "account-range", "not-an-email"])
        assert result.exit_code == 2
        assert "6 hexadecimal characters" in result.output


class TestPasswordRangeCommand:
    def test_password_range_sha1_default_padding_json_and_text(
        self, isolated_env: Path, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        body = (
            "0018A45C4D1DEF81644B54AB7F969B88D65:1\n"
            "1E4C9B93F3F0682250B6CF8331B7EE68FD8:3861493\n"
            "00000000000000000000000000000000000:0\n"
        )
        httpx_mock.add_response(url=f"{PASSWORDS_BASE}/range/21BD1", text=body)
        httpx_mock.add_response(url=f"{PASSWORDS_BASE}/range/21BD1", text=body)
        app = _make_cli()

        res_json = cli_runner.invoke(app, ["--json", "password-range", "21bd1"])
        assert res_json.exit_code == 0
        assert json.loads(res_json.output) == {
            "0018A45C4D1DEF81644B54AB7F969B88D65": 1,
            "1E4C9B93F3F0682250B6CF8331B7EE68FD8": 3861493,
        }
        req = httpx_mock.get_requests()[0]
        assert req.headers.get("add-padding") == "true"
        assert "mode" not in req.url.params

        res_text = cli_runner.invoke(app, ["password-range", "21BD1"])
        assert res_text.exit_code == 0
        assert "1E4C9B93F3F0682250B6CF8331B7EE68FD8: 3861493" in res_text.output

    def test_password_range_ntlm_and_no_pad(
        self, isolated_env: Path, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        httpx_mock.add_response(
            url=f"{PASSWORDS_BASE}/range/8846F?mode=ntlm",
            text="7EAEE8FB117AD06BDD830B7586C:42\n",
        )
        app = _make_cli()
        result = cli_runner.invoke(app, ["--json", "password-range", "8846f", "--ntlm", "--no-pad"])
        assert result.exit_code == 0
        assert json.loads(result.output) == {"7EAEE8FB117AD06BDD830B7586C": 42}
        req = httpx_mock.get_request()
        assert req is not None
        assert "add-padding" not in req.headers
        assert req.url.params["mode"] == "ntlm"

    def test_password_range_with_cache(
        self, isolated_env: Path, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        httpx_mock.add_response(
            url=f"{PASSWORDS_BASE}/range/ABCDE",
            text="12345:7\n",
        )
        app = _make_cli()
        res1 = cli_runner.invoke(app, ["--cache", "--json", "password-range", "ABCDE"])
        res2 = cli_runner.invoke(app, ["--cache", "--json", "password-range", "ABCDE"])
        assert res1.exit_code == 0
        assert res2.exit_code == 0
        assert json.loads(res1.output) == {"12345": 7}
        assert json.loads(res2.output) == {"12345": 7}
        assert len(httpx_mock.get_requests()) == 1

    @pytest.mark.parametrize("flag", ["--fail-if-pwned", "--fail-if-found"])
    def test_password_range_fail_flags_non_empty_and_empty(
        self, isolated_env: Path, httpx_mock: HTTPXMock, cli_runner: CliRunner, flag: str
    ) -> None:
        httpx_mock.add_response(
            url=f"{PASSWORDS_BASE}/range/21BD1",
            text="1E4C9B93F3F0682250B6CF8331B7EE68FD8:3861493\n",
        )
        app = _make_cli()
        res_found = cli_runner.invoke(app, ["password-range", "21BD1", flag])
        assert res_found.exit_code == 8
        assert "1E4C9B93F3F0682250B6CF8331B7EE68FD8" in res_found.output

        httpx_mock.add_response(
            url=f"{PASSWORDS_BASE}/range/00000",
            text="00000000000000000000000000000000000:0\n",
        )
        res_empty = cli_runner.invoke(app, ["password-range", "00000", flag])
        assert res_empty.exit_code == 0
        assert "No results found." in res_empty.output

    @pytest.mark.parametrize("bad_prefix", ["XYZ", "GGGG1", "123456"])
    def test_password_range_invalid_prefix_raises_usage_error(
        self, isolated_env: Path, cli_runner: CliRunner, bad_prefix: str
    ) -> None:
        app = _make_cli()
        result = cli_runner.invoke(app, ["password-range", bad_prefix])
        assert result.exit_code == 2
        assert "5 hexadecimal characters" in result.output

    def test_password_range_mode_ntlm_and_short_flag(
        self, isolated_env: Path, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        httpx_mock.add_response(
            url=f"{PASSWORDS_BASE}/range/8846F?mode=ntlm",
            text="7EAEE8FB117AD06BDD830B7586C:42\n",
        )
        httpx_mock.add_response(
            url=f"{PASSWORDS_BASE}/range/8846F?mode=ntlm",
            text="7EAEE8FB117AD06BDD830B7586C:99\n",
        )
        app = _make_cli()

        res_mode = cli_runner.invoke(
            app, ["--json", "password-range", "8846f", "--mode", "ntlm", "--no-pad"]
        )
        assert res_mode.exit_code == 0
        assert json.loads(res_mode.output) == {"7EAEE8FB117AD06BDD830B7586C": 42}

        res_short = cli_runner.invoke(
            app, ["--json", "password-range", "8846f", "--mode", "sha1", "-n", "--no-pad"]
        )
        assert res_short.exit_code == 0
        assert json.loads(res_short.output) == {"7EAEE8FB117AD06BDD830B7586C": 99}

        reqs = httpx_mock.get_requests()
        assert len(reqs) == 2
        assert all(req.url.params["mode"] == "ntlm" for req in reqs)

        res_bad_mode = cli_runner.invoke(app, ["password-range", "8846f", "--mode", "md5"])
        assert res_bad_mode.exit_code == 2


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
            json={"message": "Domain has already been verified."},
        )
        app = _make_cli()
        result = cli_runner.invoke(
            app, ["--api-key", TEST_KEY, "domain-verify", "dns-check", "example.com"]
        )
        assert result.exit_code == 2
        assert "Domain has already been verified." in result.output

        httpx_mock.add_response(
            method="POST",
            url=f"{BASE}/domainVerification/verifyDnsToken",
            status_code=404,
            json={"message": "No hibp-verify TXT records were found on the domain."},
        )
        res_404 = cli_runner.invoke(
            app, ["--api-key", TEST_KEY, "domain-verify", "dns-check", "example.com"]
        )
        assert res_404.exit_code == 9
        assert "No hibp-verify TXT records were found on the domain." in res_404.output

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
            json={"message": "Domain has already been verified."},
        )
        app = _make_cli()
        result = cli_runner.invoke(
            app, ["--api-key", TEST_KEY, "domain-verify", "meta-check", "example.com"]
        )
        assert result.exit_code == 2
        assert "Domain has already been verified." in result.output

        httpx_mock.add_response(
            method="POST",
            url=f"{BASE}/domainVerification/verifyMetaTag",
            status_code=404,
            json={"message": "Meta tag not found"},
        )
        res_404 = cli_runner.invoke(
            app, ["--api-key", TEST_KEY, "domain-verify", "meta-check", "example.com"]
        )
        assert res_404.exit_code == 9
        assert "Meta tag not found" in res_404.output

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
            assert result.exit_code == 3
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
        assert result.exit_code == 8
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

    def test_audit_fail_if_found_alias(
        self, isolated_env: Path, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        export_file = isolated_env / "found.csv"
        export_file.write_text("title,email,password\nBank,a@b.com,password\n", encoding="utf-8")
        prefix, suffix = _sha1_parts("password")
        httpx_mock.add_response(url=f"{PASSWORDS_BASE}/range/{prefix}", text=f"{suffix}:10\n")

        app = _make_cli()
        result = cli_runner.invoke(
            app, ["audit", str(export_file), "--source", "csv", "--fail-if-found"]
        )
        assert result.exit_code == 8

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
        assert result.exit_code == 7
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
        assert "KeePass master password" in result.stderr
        data = json.loads(result.stdout)
        assert data["compromised_entries"] == 1

    def test_audit_invalid_export_raises_click_exception(
        self, isolated_env: Path, cli_runner: CliRunner
    ) -> None:
        bad_file = isolated_env / "bad.json"
        bad_file.write_text("{not valid json", encoding="utf-8")
        app = _make_cli()
        result = cli_runner.invoke(app, ["audit", str(bad_file)])
        assert result.exit_code == 7
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
        assert "Bitwarden export password" in result.stderr
        data = json.loads(result.stdout)
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
        assert res_sha1.exit_code == 8
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

    def test_audit_missing_path_for_file_source_raises_usage_error(
        self, isolated_env: Path, cli_runner: CliRunner
    ) -> None:
        app = _make_cli()
        result = cli_runner.invoke(app, ["audit", "--source", "csv"])
        assert result.exit_code == 2
        assert "PATH is required for --source csv." in result.output

    def test_audit_directory_path_for_file_source_raises_usage_error(
        self, isolated_env: Path, cli_runner: CliRunner
    ) -> None:
        subdir = isolated_env / "vault_dir"
        subdir.mkdir()
        app = _make_cli()
        result = cli_runner.invoke(app, ["audit", str(subdir), "--source", "bitwarden-json"])
        assert result.exit_code == 2
        assert "PATH must be a file for --source bitwarden-json." in result.output

    @pytest.mark.parametrize(
        ("source", "filename", "content"),
        [
            (
                "lastpass-csv",
                "lastpass.csv",
                "url,username,password,name\nhttps://bank.test,u1,pw1,Bank\n",
            ),
            (
                "dashlane-csv",
                "dashlane.csv",
                "username,title,password\nu1,Bank,pw1\n",
            ),
            (
                "protonpass-csv",
                "protonpass.csv",
                "name,url,username,password\nBank,https://bank.test,u1,pw1\n",
            ),
        ],
    )
    def test_audit_v04_csv_sources(
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
        httpx_mock.add_response(url=f"{PASSWORDS_BASE}/range/{prefix}", text=f"{suffix}:4\n")

        app = _make_cli()
        result = cli_runner.invoke(app, ["--json", "audit", str(export_file), "--source", source])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["total_entries"] == 1
        assert data["compromised_entries"] == 1

    def test_audit_pwdump_auto_enables_ntlm(
        self, isolated_env: Path, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        nt_hash = _ntlm_hash("summer2024")
        pwdump_file = isolated_env / "hashes.pwdump"
        pwdump_file.write_text(
            f"CORP\\alice:1001:aad3b435b51404eeaad3b435b51404ee:{nt_hash}:::\n",
            encoding="utf-8",
        )
        httpx_mock.add_response(
            url=f"{PASSWORDS_BASE}/range/{nt_hash[:5]}?mode=ntlm",
            text=f"{nt_hash[5:]}:77\n",
        )

        app = _make_cli()
        result = cli_runner.invoke(app, ["--json", "audit", str(pwdump_file), "--source", "pwdump"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["compromised_entries"] == 1
        assert data["findings"] == [{"name": "CORP", "username": "alice", "pwn_count": 77}]

    @pytest.mark.parametrize("source", ["pass", "gopass"])
    def test_audit_pass_and_gopass_optional_path_and_directory(
        self,
        isolated_env: Path,
        monkeypatch: pytest.MonkeyPatch,
        httpx_mock: HTTPXMock,
        cli_runner: CliRunner,
        source: str,
    ) -> None:
        calls: list[tuple[Path | None, str]] = []

        def fake_load_export(
            path: Path | None, *, source: str, master_password: str | None = None
        ) -> list[AuditEntry]:
            calls.append((path, source))
            return [AuditEntry(name="email", username="u1", password="pw1")]

        monkeypatch.setattr("pwned.cli_commands.load_export", fake_load_export)
        prefix, suffix = _sha1_parts("pw1")
        httpx_mock.add_response(url=f"{PASSWORDS_BASE}/range/{prefix}", text=f"{suffix}:2\n")
        httpx_mock.add_response(url=f"{PASSWORDS_BASE}/range/{prefix}", text=f"{suffix}:2\n")

        store_dir = isolated_env / f"{source}_store"
        store_dir.mkdir()
        app = _make_cli()

        res_no_path = cli_runner.invoke(app, ["--json", "audit", "--source", source])
        assert res_no_path.exit_code == 0
        assert json.loads(res_no_path.output)["compromised_entries"] == 1

        res_with_dir = cli_runner.invoke(
            app, ["--json", "audit", str(store_dir), "--source", source]
        )
        assert res_with_dir.exit_code == 0
        assert json.loads(res_with_dir.output)["compromised_entries"] == 1
        assert calls == [(None, source), (store_dir, source)]

    def test_audit_check_strength_online_and_offline(
        self, isolated_env: Path, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        export_file = isolated_env / "strength.csv"
        export_file.write_text(
            "name,username,password\nBank,alice,123456\n",
            encoding="utf-8",
        )
        prefix, suffix = _sha1_parts("123456")
        httpx_mock.add_response(url=f"{PASSWORDS_BASE}/range/{prefix}", text=f"{suffix}:100\n")

        app = _make_cli()
        res_online = cli_runner.invoke(
            app,
            ["--json", "audit", str(export_file), "--source", "csv", "--check-strength"],
        )
        assert res_online.exit_code == 0
        data_online = json.loads(res_online.output)
        assert data_online["weak_entries"] == 1
        assert data_online["risk_score"] is not None
        assert len(data_online["strength_findings"]) == 1

        sha1_db = isolated_env / "offline.txt"
        sha1_db.write_text(f"{_sha1_hex('123456')}:100\n", encoding="utf-8")
        res_offline = cli_runner.invoke(
            app,
            [
                "--json",
                "audit",
                str(export_file),
                "--source",
                "csv",
                "--offline-db",
                str(sha1_db),
                "--check-strength",
            ],
        )
        assert res_offline.exit_code == 0
        data_offline = json.loads(res_offline.output)
        assert data_offline["weak_entries"] == 1
        assert data_offline["risk_score"] == data_online["risk_score"]

    def test_audit_with_cache_and_notify_webhook(
        self, isolated_env: Path, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        export_file = isolated_env / "notify.csv"
        export_file.write_text("name,username,password\nSite,u1,password\n", encoding="utf-8")
        prefix, suffix = _sha1_parts("password")
        httpx_mock.add_response(url=f"{PASSWORDS_BASE}/range/{prefix}", text=f"{suffix}:55\n")
        httpx_mock.add_response(
            method="POST",
            url="https://example.com/audit-hook",
            status_code=200,
        )

        app = _make_cli()
        result = cli_runner.invoke(
            app,
            [
                "--cache",
                "--json",
                "audit",
                str(export_file),
                "--source",
                "csv",
                "--notify-webhook",
                "https://example.com/audit-hook",
                "--webhook-format",
                "generic",
                "--fail-if-pwned",
            ],
        )
        assert result.exit_code == 8
        webhook_reqs = [r for r in httpx_mock.get_requests() if r.method == "POST"]
        assert len(webhook_reqs) == 1
        payload = json.loads(webhook_reqs[0].content)
        assert payload["title"] == "pwned Vault Audit Alert"
        assert payload["data"]["compromised_entries"] == 1

        # Second run with --cache hits cached range response without another GET
        res_cached = cli_runner.invoke(
            app,
            ["--cache", "--json", "audit", str(export_file), "--source", "csv"],
        )
        assert res_cached.exit_code == 0
        assert json.loads(res_cached.output)["compromised_entries"] == 1
        get_reqs = [r for r in httpx_mock.get_requests() if r.method == "GET"]
        assert len(get_reqs) == 1

    def test_audit_notify_webhook_invalid_url_raises_usage_error(
        self, isolated_env: Path, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        export_file = isolated_env / "clean.csv"
        export_file.write_text("name,username,password\nSite,u1,safe!pw99\n", encoding="utf-8")
        prefix, _ = _sha1_parts("safe!pw99")
        httpx_mock.add_response(url=f"{PASSWORDS_BASE}/range/{prefix}", text="")

        app = _make_cli()
        result = cli_runner.invoke(
            app,
            [
                "audit",
                str(export_file),
                "--source",
                "csv",
                "--notify-webhook",
                "http://bad.example/hook",
            ],
        )
        assert result.exit_code == 2
        assert "https scheme" in result.output

    def test_audit_mode_ntlm_short_flag_and_parallelism_aliases(
        self,
        isolated_env: Path,
        httpx_mock: HTTPXMock,
        monkeypatch: pytest.MonkeyPatch,
        cli_runner: CliRunner,
    ) -> None:
        from pwned.audit import async_audit_entries as real_async_audit

        export_file = isolated_env / "mode.csv"
        export_file.write_text("name,username,password\nSite,u1,pwmode\n", encoding="utf-8")
        ntlm_hex = _ntlm_hash("pwmode")
        httpx_mock.add_response(
            url=f"{PASSWORDS_BASE}/range/{ntlm_hex[:5]}?mode=ntlm",
            text=f"{ntlm_hex[5:]}:11\n",
        )
        httpx_mock.add_response(
            url=f"{PASSWORDS_BASE}/range/{ntlm_hex[:5]}?mode=ntlm",
            text=f"{ntlm_hex[5:]}:22\n",
        )

        seen_concurrency: list[int] = []

        async def spy_async_audit(*args: Any, **kwargs: Any) -> Any:
            seen_concurrency.append(kwargs["concurrency"])
            return await real_async_audit(*args, **kwargs)

        monkeypatch.setattr("pwned.cli_commands.async_audit_entries", spy_async_audit)

        app = _make_cli()
        res_mode = cli_runner.invoke(
            app,
            [
                "--json",
                "audit",
                str(export_file),
                "--source",
                "csv",
                "--mode",
                "ntlm",
                "-p",
                "4",
            ],
        )
        assert res_mode.exit_code == 0
        assert json.loads(res_mode.output)["findings"] == [
            {"name": "Site", "username": "u1", "pwn_count": 11}
        ]

        res_short = cli_runner.invoke(
            app,
            [
                "--json",
                "audit",
                str(export_file),
                "--source",
                "csv",
                "--mode",
                "sha1",
                "-n",
                "--parallelism",
                "6",
            ],
        )
        assert res_short.exit_code == 0
        assert json.loads(res_short.output)["findings"] == [
            {"name": "Site", "username": "u1", "pwn_count": 22}
        ]
        assert seen_concurrency == [4, 6]

    def test_audit_offline_db_per_prefix_directory(
        self, isolated_env: Path, cli_runner: CliRunner
    ) -> None:
        export_file = isolated_env / "dir_vault.csv"
        export_file.write_text(
            "name,username,password\nSiteA,a@x.com,password\nSiteB,b@x.com,safe!pw99\n",
            encoding="utf-8",
        )

        sha1_dir = isolated_env / "sha1_ranges"
        sha1_dir.mkdir()
        sha1_prefix, sha1_suffix = _sha1_parts("password")
        (sha1_dir / f"{sha1_prefix}.txt").write_text(f"{sha1_suffix}:321\r\n", encoding="utf-8")

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
                str(sha1_dir),
                "--fail-if-pwned",
            ],
        )
        assert res_sha1.exit_code == 8
        data_sha1 = json.loads(res_sha1.output)
        assert data_sha1["compromised_entries"] == 1
        assert data_sha1["findings"] == [{"name": "SiteA", "username": "a@x.com", "pwn_count": 321}]

        ntlm_dir = isolated_env / "ntlm_ranges"
        ntlm_dir.mkdir()
        ntlm_hex = _ntlm_hash("safe!pw99")
        (ntlm_dir / f"{ntlm_hex[:5]}.txt").write_text(f"{ntlm_hex[5:]}:42\r\n", encoding="utf-8")

        res_ntlm = cli_runner.invoke(
            app,
            [
                "--json",
                "audit",
                str(export_file),
                "--source",
                "csv",
                "--offline-db",
                str(ntlm_dir),
                "--mode",
                "ntlm",
            ],
        )
        assert res_ntlm.exit_code == 0
        data_ntlm = json.loads(res_ntlm.output)
        assert data_ntlm["compromised_entries"] == 1
        assert data_ntlm["findings"] == [{"name": "SiteB", "username": "b@x.com", "pwn_count": 42}]


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


class TestOfflineCommand:
    def test_offline_download_defaults_and_options(
        self, isolated_env: Path, monkeypatch: pytest.MonkeyPatch, cli_runner: CliRunner
    ) -> None:
        captured: list[dict[str, Any]] = []

        async def fake_download(
            output_path: Path,
            *,
            ntlm: bool = False,
            directory: bool = False,
            concurrency: int = 32,
            resume: bool = True,
            force: bool = False,
            overwrite: bool = True,
            etag_cache_path: Path | None = None,
            user_agent: str = "pwned-cli",
            max_retries: int | None = None,
            on_progress: Any = None,
        ) -> DownloadStats:
            captured.append(
                {
                    "output_path": output_path,
                    "ntlm": ntlm,
                    "directory": directory,
                    "concurrency": concurrency,
                    "resume": resume,
                    "force": force,
                    "overwrite": overwrite,
                    "etag_cache_path": etag_cache_path,
                    "user_agent": user_agent,
                    "max_retries": max_retries,
                    "on_progress": on_progress,
                }
            )
            return DownloadStats(
                prefixes_total=16,
                prefixes_downloaded=10,
                prefixes_cached=6,
                hashes_written=100,
                elapsed_seconds=1.25,
                output_path=str(output_path),
                ntlm=ntlm,
                directory=directory,
            )

        monkeypatch.setattr("pwned.cli_commands.download_offline_db", fake_download)
        out_dir = isolated_env / "ranges"
        out_dir.mkdir()
        out_file = isolated_env / "hashes.txt"
        etag_file = isolated_env / "etags.json"
        app = _make_cli()

        res_default = cli_runner.invoke(app, ["--json", "offline", "download", str(out_dir)])
        assert res_default.exit_code == 0
        default_data = json.loads(res_default.output)
        assert default_data["prefixes_total"] == 16
        assert default_data["directory"] is True

        res_opts = cli_runner.invoke(
            app,
            [
                "--user-agent",
                "custom-ua",
                "--force",
                "--json",
                "offline",
                "download",
                str(out_file),
                "--single",
                "--mode",
                "ntlm",
                "--parallelism",
                "8",
                "--no-resume",
                "--etag-cache",
                str(etag_file),
                "--max-retries",
                "5",
                "--overwrite",
            ],
        )
        assert res_opts.exit_code == 0
        opts_data = json.loads(res_opts.output)
        assert opts_data["ntlm"] is True
        assert opts_data["directory"] is False

        res_short = cli_runner.invoke(
            app,
            [
                "--json",
                "offline",
                "download",
                str(out_file),
                "-s",
                "--mode",
                "sha1",
                "-n",
                "-p",
                "8",
                "--max-retries",
                "0",
                "-o",
            ],
        )
        assert res_short.exit_code == 0
        assert json.loads(res_short.output)["ntlm"] is True

        assert captured == [
            {
                "output_path": out_dir,
                "ntlm": False,
                "directory": True,
                "concurrency": 32,
                "resume": True,
                "force": False,
                "overwrite": False,
                "etag_cache_path": None,
                "user_agent": "pwned-cli",
                "max_retries": None,
                "on_progress": None,
            },
            {
                "output_path": out_file,
                "ntlm": True,
                "directory": False,
                "concurrency": 8,
                "resume": False,
                "force": True,
                "overwrite": True,
                "etag_cache_path": etag_file,
                "user_agent": "custom-ua",
                "max_retries": 5,
                "on_progress": None,
            },
            {
                "output_path": out_file,
                "ntlm": True,
                "directory": False,
                "concurrency": 8,
                "resume": True,
                "force": False,
                "overwrite": True,
                "etag_cache_path": None,
                "user_agent": "pwned-cli",
                "max_retries": 0,
                "on_progress": None,
            },
        ]

    def test_offline_download_invalid_max_retries(
        self, isolated_env: Path, cli_runner: CliRunner
    ) -> None:
        app = _make_cli()
        result = cli_runner.invoke(
            app,
            ["offline", "download", str(isolated_env / "hashes.txt"), "--max-retries", "-1"],
        )
        assert result.exit_code == 2
        assert "Invalid value for '--max-retries'" in result.output

    def test_offline_download_file_exists_error_handled(
        self, isolated_env: Path, monkeypatch: pytest.MonkeyPatch, cli_runner: CliRunner
    ) -> None:
        out_file = isolated_env / "hashes.txt"
        out_file.write_text("existing\n", encoding="utf-8")

        async def fake_download(
            output_path: Path,
            *,
            overwrite: bool = True,
            **kwargs: Any,
        ) -> DownloadStats:
            if not overwrite and output_path.exists():
                raise FileExistsError(
                    f"Output file already exists: {output_path} (use --overwrite to replace)"
                )
            return DownloadStats(
                prefixes_total=1,
                prefixes_downloaded=1,
                prefixes_cached=0,
                hashes_written=1,
                elapsed_seconds=0.1,
                output_path=str(output_path),
                ntlm=False,
            )

        monkeypatch.setattr("pwned.cli_commands.download_offline_db", fake_download)
        app = _make_cli()
        result = cli_runner.invoke(app, ["offline", "download", str(out_file)])
        assert result.exit_code == 7
        assert "Output file already exists" in result.stderr

    def test_offline_download_tty_progress_throttled(
        self, isolated_env: Path, monkeypatch: pytest.MonkeyPatch, cli_runner: CliRunner
    ) -> None:
        async def fake_download(
            output_path: Path,
            *,
            on_progress: Any = None,
            **kwargs: Any,
        ) -> DownloadStats:
            assert on_progress is not None
            on_progress(1, 1005)
            on_progress(10, 1005)
            on_progress(1004, 1005)
            on_progress(1005, 1005)
            return DownloadStats(
                prefixes_total=1005,
                prefixes_downloaded=1005,
                prefixes_cached=0,
                hashes_written=5000,
                elapsed_seconds=2.5,
                output_path=str(output_path),
                ntlm=False,
            )

        monkeypatch.setattr("pwned.cli_commands._is_stderr_tty", lambda: True)
        monkeypatch.setattr("pwned.cli_commands.download_offline_db", fake_download)
        out_file = isolated_env / "hashes.txt"
        app = _make_cli()

        result = cli_runner.invoke(app, ["--json", "offline", "download", str(out_file)])
        assert result.exit_code == 0
        assert json.loads(result.stdout)["prefixes_total"] == 1005
        assert result.stderr.splitlines() == [
            "[10/1,005] ranges downloaded",
            "[1,005/1,005] ranges downloaded",
        ]

    def test_offline_download_error_handled(
        self, isolated_env: Path, monkeypatch: pytest.MonkeyPatch, cli_runner: CliRunner
    ) -> None:
        async def fake_download(*args: Any, **kwargs: Any) -> DownloadStats:
            raise HIBPError("HTTP 503 for prefix 00000")

        monkeypatch.setattr("pwned.cli_commands.download_offline_db", fake_download)
        app = _make_cli()
        result = cli_runner.invoke(app, ["offline", "download", str(isolated_env / "hashes.txt")])
        assert result.exit_code == 6
        assert "HTTP 503 for prefix 00000" in result.output


class TestDomainReportCommand:
    def test_domain_report_basic_and_stealer_logs(
        self, isolated_env: Path, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        httpx_mock.add_response(
            url=f"{BASE}/breacheddomain/example.com",
            json={"alice": ["Adobe"], "bob": ["Adobe", "LinkedIn"]},
        )
        httpx_mock.add_response(
            url=f"{BASE}/breaches",
            json=[
                {
                    "Name": "Adobe",
                    "Title": "Adobe",
                    "BreachDate": "2013-10-04",
                    "DataClasses": ["Emails", "Passwords"],
                    "IsVerified": True,
                },
                {
                    "Name": "LinkedIn",
                    "Title": "LinkedIn",
                    "BreachDate": "2012-05-05",
                    "DataClasses": ["Emails"],
                    "IsVerified": True,
                },
            ],
        )
        httpx_mock.add_response(
            url=f"{BASE}/stealerlogsbyemaildomain/example.com",
            json={"alice": ["evil.test"]},
        )

        app = _make_cli()
        result = cli_runner.invoke(
            app,
            [
                "--api-key",
                TEST_KEY,
                "--cache",
                "--json",
                "domain-report",
                "example.com",
                "--include-stealer-logs",
                "--fail-if-pwned",
            ],
        )
        assert result.exit_code == 8
        data = json.loads(result.output)
        assert data["domain"] == "example.com"
        assert data["total_exposed_aliases"] == 2
        assert data["unique_breaches"] == 2
        assert data["stealer_log_aliases"] == 1

    def test_domain_report_fail_if_pwned_stealer_logs_only_and_clean(
        self, isolated_env: Path, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        httpx_mock.add_response(url=f"{BASE}/breacheddomain/stealer.example", status_code=404)
        httpx_mock.add_response(
            url=f"{BASE}/stealerlogsbyemaildomain/stealer.example",
            json={"alice": ["bad.site"]},
        )
        app = _make_cli()
        res_stealer = cli_runner.invoke(
            app,
            [
                "--api-key",
                TEST_KEY,
                "domain-report",
                "stealer.example",
                "--include-stealer-logs",
                "--fail-if-pwned",
            ],
        )
        assert res_stealer.exit_code == 8

        httpx_mock.add_response(url=f"{BASE}/breacheddomain/clean.example", status_code=404)
        res_clean = cli_runner.invoke(
            app,
            ["--api-key", TEST_KEY, "--json", "domain-report", "clean.example", "--fail-if-pwned"],
        )
        assert res_clean.exit_code == 0
        assert json.loads(res_clean.output)["total_exposed_aliases"] == 0

    def test_domain_report_fail_if_found_alias(
        self, isolated_env: Path, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        httpx_mock.add_response(
            url=f"{BASE}/breacheddomain/example.com",
            json={"alice": ["Adobe"]},
        )
        httpx_mock.add_response(url=f"{BASE}/breaches", json=[])
        app = _make_cli()
        result = cli_runner.invoke(
            app,
            ["--api-key", TEST_KEY, "domain-report", "example.com", "--fail-if-found"],
        )
        assert result.exit_code == 8

    def test_domain_report_notify_webhook_and_missing_api_key(
        self, isolated_env: Path, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        app = _make_cli()
        res_no_key = cli_runner.invoke(app, ["domain-report", "example.com"])
        assert res_no_key.exit_code == 3
        assert "Invalid or missing API key" in res_no_key.output

        httpx_mock.add_response(
            url=f"{BASE}/breacheddomain/example.com",
            json={"alice": ["Adobe"]},
        )
        httpx_mock.add_response(url=f"{BASE}/breaches", json=[])
        httpx_mock.add_response(
            method="POST",
            url="https://example.com/domain-hook",
            status_code=200,
        )
        res_hook = cli_runner.invoke(
            app,
            [
                "--api-key",
                TEST_KEY,
                "domain-report",
                "example.com",
                "--notify-webhook",
                "https://example.com/domain-hook",
                "--webhook-format",
                "generic",
            ],
        )
        assert res_hook.exit_code == 0
        webhook_reqs = [r for r in httpx_mock.get_requests() if r.method == "POST"]
        assert len(webhook_reqs) == 1
        assert (
            json.loads(webhook_reqs[0].content)["title"] == "pwned Domain Report Alert: example.com"
        )

        httpx_mock.add_response(url=f"{BASE}/breacheddomain/clean.com", status_code=404)
        res_bad_hook = cli_runner.invoke(
            app,
            [
                "--api-key",
                TEST_KEY,
                "domain-report",
                "clean.com",
                "--notify-webhook",
                "http://insecure.example/hook",
            ],
        )
        assert res_bad_hook.exit_code == 2


class TestMonitorCommand:
    def test_monitor_runs_config_and_renders_report(
        self, isolated_env: Path, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        cfg = isolated_env / "pwned.toml"
        cfg.write_text(
            '[monitor]\nformat = "json"\n[[accounts]]\nemail = "user@example.com"\n',
            encoding="utf-8",
        )
        httpx_mock.add_response(
            url=f"{BASE}/breachedaccount/user%40example.com",
            json=[{"Name": "Adobe"}],
        )
        httpx_mock.add_response(url=f"{BASE}/pasteaccount/user%40example.com", status_code=404)

        app = _make_cli()
        result = cli_runner.invoke(app, ["--api-key", TEST_KEY, "monitor"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["accounts_checked"] == 1
        assert data["new_exposures"] == 1

    def test_monitor_cli_format_overrides_config_format(
        self, isolated_env: Path, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        cfg = isolated_env / "custom.toml"
        cfg.write_text(
            '[monitor]\nformat = "json"\ncache = true\nfail_if_pwned = true\n'
            '[[accounts]]\nemail = "user@example.com"\n',
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
            ["--api-key", TEST_KEY, "--format", "table", "monitor", "--config", str(cfg)],
        )
        assert result.exit_code == 8
        assert "Field" in result.output
        assert "new_exposures" in result.output

    def test_monitor_invalid_config_and_missing_api_key(
        self, isolated_env: Path, cli_runner: CliRunner
    ) -> None:
        bad_cfg = isolated_env / "bad.toml"
        bad_cfg.write_text("[monitor]\n", encoding="utf-8")

        app = _make_cli()
        res_bad = cli_runner.invoke(app, ["monitor", "--config", str(bad_cfg)])
        assert res_bad.exit_code == 7
        assert "at least one account or domain target" in res_bad.output

        valid_cfg = isolated_env / "valid.toml"
        valid_cfg.write_text('[[accounts]]\nemail = "a@b.com"\n', encoding="utf-8")
        res_no_key = cli_runner.invoke(app, ["monitor", "--config", str(valid_cfg)])
        assert res_no_key.exit_code == 3
        assert "Invalid or missing API key" in res_no_key.output

    def test_monitor_save_baselines_webhook_override_and_invalid_webhook(
        self, isolated_env: Path, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        cfg = isolated_env / "pwned.toml"
        cfg.write_text(
            '[monitor]\nbaseline_dir = "baselines"\n[[accounts]]\nemail = "user@example.com"\n',
            encoding="utf-8",
        )
        httpx_mock.add_response(
            url=f"{BASE}/breachedaccount/user%40example.com",
            json=[{"Name": "Adobe"}],
        )
        httpx_mock.add_response(url=f"{BASE}/pasteaccount/user%40example.com", status_code=404)
        httpx_mock.add_response(
            method="POST",
            url="https://example.com/monitor-hook",
            status_code=200,
        )

        app = _make_cli()
        res_ok = cli_runner.invoke(
            app,
            [
                "--api-key",
                TEST_KEY,
                "--json",
                "monitor",
                "--save-baselines",
                "--notify-webhook",
                "https://example.com/monitor-hook",
                "--webhook-format",
                "generic",
                "--fail-if-pwned",
            ],
        )
        assert res_ok.exit_code == 8
        assert json.loads(res_ok.output)["webhook_sent"] is True
        assert (isolated_env / "baselines").is_dir()

        # Re-run with saved baseline -> 0 new exposures -> fail-if-pwned exits 0
        httpx_mock.add_response(
            url=f"{BASE}/breachedaccount/user%40example.com",
            json=[{"Name": "Adobe"}],
        )
        httpx_mock.add_response(url=f"{BASE}/pasteaccount/user%40example.com", status_code=404)
        res_clean = cli_runner.invoke(
            app,
            ["--api-key", TEST_KEY, "monitor", "--fail-if-pwned"],
        )
        assert res_clean.exit_code == 0

        # Invalid webhook URL -> UsageError (exit code 2)
        httpx_mock.add_response(
            url=f"{BASE}/breachedaccount/user%40example.com",
            json=[{"Name": "Adobe"}],
        )
        httpx_mock.add_response(url=f"{BASE}/pasteaccount/user%40example.com", status_code=404)
        res_bad_hook = cli_runner.invoke(
            app,
            [
                "--api-key",
                TEST_KEY,
                "monitor",
                "--notify-webhook",
                "http://bad.example/hook",
            ],
        )
        assert res_bad_hook.exit_code == 2
        assert "https scheme" in res_bad_hook.output

    def test_monitor_fail_if_found_alias(
        self, isolated_env: Path, httpx_mock: HTTPXMock, cli_runner: CliRunner
    ) -> None:
        cfg = isolated_env / "pwned.toml"
        cfg.write_text('[[accounts]]\nemail = "user@example.com"\n', encoding="utf-8")
        httpx_mock.add_response(
            url=f"{BASE}/breachedaccount/user%40example.com",
            json=[{"Name": "Adobe"}],
        )
        httpx_mock.add_response(url=f"{BASE}/pasteaccount/user%40example.com", status_code=404)
        app = _make_cli()
        result = cli_runner.invoke(app, ["--api-key", TEST_KEY, "monitor", "--fail-if-found"])
        assert result.exit_code == 8


class TestMcpCommand:
    def test_mcp_defaults_and_options(
        self, isolated_env: Path, monkeypatch: pytest.MonkeyPatch, cli_runner: CliRunner
    ) -> None:
        served: list[Any] = []
        monkeypatch.setattr("pwned.cli_commands.serve_stdio", served.append)

        db_file = isolated_env / "hashes.txt"
        db_file.write_text(f"{_sha1_hex('password')}:1\n", encoding="utf-8")

        app = _make_cli()
        res_default = cli_runner.invoke(app, ["mcp"])
        assert res_default.exit_code == 0
        assert len(served) == 1
        s1 = served[0]
        assert s1._api_key is None
        assert s1._offline_db is None
        assert s1._ntlm is False
        assert s1._cache is None

        res_opts = cli_runner.invoke(
            app,
            [
                "--api-key",
                TEST_KEY,
                "--user-agent",
                "mcp-ua",
                "--cache",
                "mcp",
                "--offline-db",
                str(db_file),
                "--ntlm",
            ],
        )
        assert res_opts.exit_code == 0
        assert len(served) == 2
        s2 = served[1]
        assert s2._api_key == TEST_KEY
        assert s2._user_agent == "mcp-ua"
        assert s2._offline_db == db_file
        assert s2._ntlm is True
        assert isinstance(s2._cache, ResponseCache)

    def test_mcp_offline_db_directory_and_short_ntlm(
        self, isolated_env: Path, monkeypatch: pytest.MonkeyPatch, cli_runner: CliRunner
    ) -> None:
        served: list[Any] = []
        monkeypatch.setattr("pwned.cli_commands.serve_stdio", served.append)

        db_dir = isolated_env / "ranges_dir"
        db_dir.mkdir()
        prefix, suffix = _sha1_parts("password")
        (db_dir / f"{prefix}.txt").write_text(f"{suffix}:1\n", encoding="utf-8")

        app = _make_cli()
        result = cli_runner.invoke(app, ["mcp", "--offline-db", str(db_dir), "-n"])
        assert result.exit_code == 0
        assert len(served) == 1
        assert served[0]._offline_db == db_dir
        assert served[0]._ntlm is True
