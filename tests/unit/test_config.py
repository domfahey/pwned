from __future__ import annotations

import os
import stat
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import get_args
from unittest.mock import patch

import pytest
from pydantic import SecretStr, ValidationError

from pwned.config import (
    DEFAULT_USER_AGENT,
    KEYRING_SERVICE,
    KEYRING_USERNAME,
    ConfigBackend,
    Settings,
    clear_api_key,
    clear_api_key_keyring,
    get_api_key_source,
    get_config_dir,
    get_config_file,
    get_keyring_api_key,
    keyring_available,
    load_settings,
    mask_api_key,
    save_api_key,
    save_api_key_keyring,
)


class TestSettings:
    def test_frozen(self) -> None:
        s = Settings(api_key=SecretStr("key"), user_agent="ua")
        assert s.get_api_key() == "key"
        assert s.user_agent == "ua"

    def test_api_key_masked_in_repr(self) -> None:
        s = Settings(api_key=SecretStr("secret123"), user_agent="ua")
        assert "secret123" not in repr(s)
        assert "secret123" not in str(s)

    def test_frozen_rejects_assignment(self) -> None:
        s = Settings(api_key=SecretStr("key"), user_agent="ua")
        with pytest.raises(ValidationError):
            s.api_key = SecretStr("other")


class TestLoadSettings:
    def test_defaults(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            s = Settings()
            assert s.api_key is None
            assert s.user_agent == DEFAULT_USER_AGENT

    def test_explicit_overrides_env(self) -> None:
        s = Settings(api_key=SecretStr("override"), user_agent="custom")
        assert s.get_api_key() == "override"
        assert s.user_agent == "custom"

    def test_env_vars(self) -> None:
        with patch.dict(
            os.environ, {"HIBP_API_KEY": "envkey", "HIBP_USER_AGENT": "envua"}, clear=True
        ):
            s = Settings()
            assert s.get_api_key() == "envkey"
            assert s.user_agent == "envua"

    def test_load_settings_filters_none(self) -> None:
        with patch.dict(os.environ, {"HIBP_API_KEY": "envkey"}, clear=True):
            s = load_settings(api_key=None)
            assert s.get_api_key() == "envkey"

    def test_load_settings_explicit_overrides(self) -> None:
        with patch.dict(os.environ, {"HIBP_API_KEY": "envkey"}, clear=True):
            s = load_settings(api_key="override", user_agent="custom-ua")
            assert s.get_api_key() == "override"
            assert s.user_agent == "custom-ua"

    def test_empty_api_key_becomes_none(self) -> None:
        s = Settings.model_validate({"api_key": ""})
        assert s.api_key is None

    def test_whitespace_api_key_preserved(self) -> None:
        s = Settings.model_validate({"api_key": " "})
        assert s.get_api_key() == " "

    def test_empty_user_agent_falls_back_to_default(self) -> None:
        with patch.dict(os.environ, {"HIBP_USER_AGENT": "   "}, clear=True):
            s = Settings()
            assert s.user_agent == DEFAULT_USER_AGENT

        s2 = load_settings(user_agent="")
        assert s2.user_agent == DEFAULT_USER_AGENT

    def test_dotenv_loaded_and_empty_override_clears_key(self, tmp_path: Path) -> None:
        (tmp_path / ".env").write_text(
            "HIBP_API_KEY=dotenvkey\nHIBP_USER_AGENT=dotenvua\n", encoding="utf-8"
        )
        s = load_settings()
        assert s.get_api_key() == "dotenvkey"
        assert s.user_agent == "dotenvua"

        cleared = load_settings(api_key="")
        assert cleared.api_key is None

    def test_dotenv_unknown_hibp_keys_ignored(self, tmp_path: Path) -> None:
        (tmp_path / ".env").write_text(
            "HIBP_API_KEY=dotenvkey\nHIBP_EXTRA=1\nOTHER=2\n", encoding="utf-8"
        )
        assert load_settings().get_api_key() == "dotenvkey"
        assert get_api_key_source() == "dotenv"

    def test_empty_env_var_overrides_dotenv(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        (tmp_path / ".env").write_text("HIBP_API_KEY=dotenvkey\n", encoding="utf-8")
        monkeypatch.setenv("HIBP_API_KEY", "")
        s = load_settings()
        assert s.api_key is None
        assert s.get_api_key() is None

    def test_get_api_key_returns_none_when_unset(self) -> None:
        s = Settings()
        assert s.get_api_key() is None

    @pytest.mark.parametrize("bad_ua", [None, 123])
    def test_non_string_user_agent_rejected(self, bad_ua: object) -> None:
        with pytest.raises(ValidationError):
            Settings.model_validate({"user_agent": bad_ua})

    def test_non_string_api_key_rejected(self) -> None:
        with pytest.raises(ValidationError):
            Settings.model_validate({"api_key": 123})

    def test_empty_user_agent_override_clears_env(self) -> None:
        with patch.dict(os.environ, {"HIBP_USER_AGENT": "envua"}, clear=True):
            s = load_settings(user_agent="")
            assert s.user_agent == DEFAULT_USER_AGENT

    def test_load_settings_reads_xdg_config_file(self) -> None:
        cfg = get_config_file()
        cfg.parent.mkdir(parents=True, exist_ok=True)
        cfg.write_text("HIBP_API_KEY=xdg-key\nHIBP_USER_AGENT=xdg-ua\n", encoding="utf-8")

        s = load_settings()
        assert s.get_api_key() == "xdg-key"
        assert s.user_agent == "xdg-ua"

    def test_load_settings_cwd_dotenv_overrides_xdg(self, tmp_path: Path) -> None:
        cfg = get_config_file()
        cfg.parent.mkdir(parents=True, exist_ok=True)
        cfg.write_text("HIBP_API_KEY=xdg-key\nHIBP_USER_AGENT=xdg-ua\n", encoding="utf-8")
        (tmp_path / ".env").write_text("HIBP_API_KEY=cwd-key\n", encoding="utf-8")

        s = load_settings()
        assert s.get_api_key() == "cwd-key"
        assert s.user_agent == "xdg-ua"

    def test_load_settings_env_overrides_cwd_and_xdg(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        cfg = get_config_file()
        cfg.parent.mkdir(parents=True, exist_ok=True)
        cfg.write_text("HIBP_API_KEY=xdg-key\n", encoding="utf-8")
        (tmp_path / ".env").write_text("HIBP_API_KEY=cwd-key\n", encoding="utf-8")
        monkeypatch.setenv("HIBP_API_KEY", "env-key")

        s = load_settings()
        assert s.get_api_key() == "env-key"

    def test_load_settings_explicit_overrides_all(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        cfg = get_config_file()
        cfg.parent.mkdir(parents=True, exist_ok=True)
        cfg.write_text("HIBP_API_KEY=xdg-key\nHIBP_USER_AGENT=xdg-ua\n", encoding="utf-8")
        (tmp_path / ".env").write_text(
            "HIBP_API_KEY=cwd-key\nHIBP_USER_AGENT=cwd-ua\n", encoding="utf-8"
        )
        monkeypatch.setenv("HIBP_API_KEY", "env-key")
        monkeypatch.setenv("HIBP_USER_AGENT", "env-ua")

        s = load_settings(api_key="cli-key", user_agent="cli-ua")
        assert s.get_api_key() == "cli-key"
        assert s.user_agent == "cli-ua"

    def test_load_settings_falls_back_when_home_unavailable(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        def _raise_no_home() -> Path:
            raise RuntimeError("Could not determine home directory.")

        monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
        monkeypatch.setattr(Path, "home", _raise_no_home)
        (tmp_path / ".env").write_text("HIBP_API_KEY=cwd-only\n", encoding="utf-8")

        s = load_settings()
        assert s.get_api_key() == "cwd-only"


class TestConfigPaths:
    def test_get_config_dir_uses_xdg_config_home(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        custom_xdg = tmp_path / "custom-xdg"
        monkeypatch.setenv("XDG_CONFIG_HOME", str(custom_xdg))
        assert get_config_dir() == custom_xdg / "pwned"

    def test_get_config_dir_falls_back_to_home_when_unset(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        assert get_config_dir() == tmp_path / ".config" / "pwned"

    def test_get_config_dir_falls_back_to_home_when_empty(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setenv("XDG_CONFIG_HOME", "")
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        assert get_config_dir() == tmp_path / ".config" / "pwned"

    def test_get_config_file(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        custom_xdg = tmp_path / "xdg"
        monkeypatch.setenv("XDG_CONFIG_HOME", str(custom_xdg))
        assert get_config_file() == custom_xdg / "pwned" / ".env"


class TestSaveApiKey:
    def test_save_api_key_creates_file_and_dirs_with_permissions(self) -> None:
        returned = save_api_key("my-secret-key")
        expected = get_config_file()
        assert returned == expected
        assert expected.read_text(encoding="utf-8") == "HIBP_API_KEY=my-secret-key\n"
        if os.name == "posix":
            assert stat.S_IMODE(expected.parent.stat().st_mode) == 0o700
            assert stat.S_IMODE(expected.stat().st_mode) == 0o600

    def test_save_api_key_explicit_path_preserves_other_lines(self, tmp_path: Path) -> None:
        custom = tmp_path / "nested" / ".env"
        custom.parent.mkdir(parents=True)
        custom.write_text(
            "# comment\nHIBP_USER_AGENT=custom-ua\nHIBP_API_KEY=old-key\nOTHER=1\n",
            encoding="utf-8",
        )

        returned = save_api_key("new-key", path=custom)
        assert returned == custom
        assert custom.read_text(encoding="utf-8") == (
            "# comment\nHIBP_USER_AGENT=custom-ua\nHIBP_API_KEY=new-key\nOTHER=1\n"
        )
        if os.name == "posix":
            assert stat.S_IMODE(custom.stat().st_mode) == 0o600

    def test_save_api_key_appends_when_key_not_present(self, tmp_path: Path) -> None:
        custom = tmp_path / ".env"
        custom.write_text("HIBP_USER_AGENT=custom-ua\n", encoding="utf-8")

        save_api_key("new-key", path=custom)
        assert custom.read_text(encoding="utf-8") == (
            "HIBP_USER_AGENT=custom-ua\nHIBP_API_KEY=new-key\n"
        )

    def test_save_api_key_deduplicates_existing_keys(self, tmp_path: Path) -> None:
        custom = tmp_path / ".env"
        custom.write_text(
            "HIBP_API_KEY=first\nHIBP_USER_AGENT=ua\nHIBP_API_KEY=second\n",
            encoding="utf-8",
        )

        save_api_key("final-key", path=custom)
        assert custom.read_text(encoding="utf-8") == (
            "HIBP_API_KEY=final-key\nHIBP_USER_AGENT=ua\n"
        )

    @pytest.mark.parametrize(
        "bad_key",
        ["", "   ", "\t", "abc\ndef", "abc\rdef", "abc\r\ndef"],
    )
    def test_save_api_key_rejects_invalid(self, bad_key: str, tmp_path: Path) -> None:
        custom = tmp_path / ".env"
        with pytest.raises(ValueError):
            save_api_key(bad_key, path=custom)
        assert not custom.exists()

    def test_save_api_key_atomic_cleanup_on_replace_error(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        custom = tmp_path / "cfg" / ".env"

        def fail_replace(src: str | os.PathLike[str], dst: str | os.PathLike[str]) -> None:
            raise OSError("replace failed")

        monkeypatch.setattr(os, "replace", fail_replace)
        with pytest.raises(OSError, match="replace failed"):
            save_api_key("valid-key", path=custom)

        assert not custom.exists()
        assert list(custom.parent.iterdir()) == []

    def test_save_api_key_non_posix_skips_chmod(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        custom = tmp_path / "win" / ".env"
        monkeypatch.setattr(os, "name", "nt")
        returned = save_api_key("win-key-1234", path=custom)
        assert returned == custom
        assert custom.read_text(encoding="utf-8") == "HIBP_API_KEY=win-key-1234\n"


class TestClearApiKey:
    def test_clear_api_key_missing_file_returns_false(self, tmp_path: Path) -> None:
        assert clear_api_key(path=tmp_path / "missing.env") is False

    def test_clear_api_key_missing_key_returns_false(self, tmp_path: Path) -> None:
        custom = tmp_path / ".env"
        custom.write_text("HIBP_USER_AGENT=ua\n", encoding="utf-8")
        assert clear_api_key(path=custom) is False
        assert custom.read_text(encoding="utf-8") == "HIBP_USER_AGENT=ua\n"

    def test_clear_api_key_removes_empty_file(self, tmp_path: Path) -> None:
        custom = tmp_path / ".env"
        custom.write_text("HIBP_API_KEY=secret\n", encoding="utf-8")
        assert clear_api_key(path=custom) is True
        assert not custom.exists()

    def test_clear_api_key_preserves_other_lines_and_permissions(self, tmp_path: Path) -> None:
        custom = tmp_path / ".env"
        custom.write_text("HIBP_USER_AGENT=ua\nHIBP_API_KEY=secret\n", encoding="utf-8")
        assert clear_api_key(path=custom) is True
        assert custom.read_text(encoding="utf-8") == "HIBP_USER_AGENT=ua\n"
        if os.name == "posix":
            assert stat.S_IMODE(custom.stat().st_mode) == 0o600

    def test_clear_api_key_uses_default_config_file(self) -> None:
        save_api_key("secret-key")
        cfg = get_config_file()
        assert cfg.exists()
        assert clear_api_key() is True
        assert not cfg.exists()


class TestMaskApiKey:
    @pytest.mark.parametrize(
        ("api_key", "expected"),
        [
            (None, "(not set)"),
            ("", "(not set)"),
            ("a", "****"),
            ("12345678", "****"),
            ("123456789", "1234...6789"),
            ("0123456789abcdef0123456789abcdef", "0123...cdef"),
        ],
    )
    def test_mask_api_key(self, api_key: str | None, expected: str) -> None:
        assert mask_api_key(api_key) == expected


def _make_fake_keyring(store: dict[tuple[str, str], str]) -> SimpleNamespace:
    class PasswordDeleteError(Exception):
        pass

    def get_password(service: str, username: str) -> str | None:
        return store.get((service, username))

    def set_password(service: str, username: str, password: str) -> None:
        store[(service, username)] = password

    def delete_password(service: str, username: str) -> None:
        if (service, username) not in store:
            raise PasswordDeleteError("Password not found")
        del store[(service, username)]

    return SimpleNamespace(
        get_password=get_password,
        set_password=set_password,
        delete_password=delete_password,
        errors=SimpleNamespace(PasswordDeleteError=PasswordDeleteError),
    )


class TestKeyringBackend:
    def test_constants_and_type_alias(self) -> None:
        assert KEYRING_SERVICE == "pwned"
        assert KEYRING_USERNAME == "hibp_api_key"
        assert get_args(ConfigBackend) == ("file", "keyring")

    def test_keyring_available_true_when_installed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setitem(sys.modules, "keyring", _make_fake_keyring({}))
        assert keyring_available() is True

    def test_keyring_available_false_when_missing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setitem(sys.modules, "keyring", None)
        assert keyring_available() is False

    def test_get_keyring_api_key_returns_stored_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = _make_fake_keyring({(KEYRING_SERVICE, KEYRING_USERNAME): "kr-secret"})
        monkeypatch.setitem(sys.modules, "keyring", fake)
        assert get_keyring_api_key() == "kr-secret"

    @pytest.mark.parametrize("stored", [None, ""])
    def test_get_keyring_api_key_returns_none_when_empty_or_none(
        self, monkeypatch: pytest.MonkeyPatch, stored: str | None
    ) -> None:
        fake = SimpleNamespace(get_password=lambda _s, _u: stored)
        monkeypatch.setitem(sys.modules, "keyring", fake)
        assert get_keyring_api_key() is None

    def test_get_keyring_api_key_returns_none_when_missing_module(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setitem(sys.modules, "keyring", None)
        assert get_keyring_api_key() is None

    def test_get_keyring_api_key_returns_none_on_backend_exception(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def fail_get(_service: str, _username: str) -> str | None:
            raise RuntimeError("NoKeyringError: no backend available")

        monkeypatch.setitem(sys.modules, "keyring", SimpleNamespace(get_password=fail_get))
        assert get_keyring_api_key() is None

    def test_save_api_key_keyring_stores_password(self, monkeypatch: pytest.MonkeyPatch) -> None:
        store: dict[tuple[str, str], str] = {}
        monkeypatch.setitem(sys.modules, "keyring", _make_fake_keyring(store))
        save_api_key_keyring("my-keyring-key")
        assert store[(KEYRING_SERVICE, KEYRING_USERNAME)] == "my-keyring-key"

    @pytest.mark.parametrize(
        "bad_key",
        ["", "   ", "\t", "abc\ndef", "abc\rdef", "abc\r\ndef"],
    )
    def test_save_api_key_keyring_rejects_invalid(
        self, monkeypatch: pytest.MonkeyPatch, bad_key: str
    ) -> None:
        store: dict[tuple[str, str], str] = {}
        monkeypatch.setitem(sys.modules, "keyring", _make_fake_keyring(store))
        with pytest.raises(ValueError):
            save_api_key_keyring(bad_key)
        assert store == {}

    def test_save_api_key_keyring_raises_when_missing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setitem(sys.modules, "keyring", None)
        with pytest.raises(RuntimeError, match=r"uv pip install 'pwned\[keyring\]'"):
            save_api_key_keyring("my-keyring-key")

    def test_clear_api_key_keyring_deletes_when_present(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        store = {(KEYRING_SERVICE, KEYRING_USERNAME): "kr-secret"}
        monkeypatch.setitem(sys.modules, "keyring", _make_fake_keyring(store))
        assert clear_api_key_keyring() is True
        assert store == {}

    def test_clear_api_key_keyring_returns_false_when_not_stored(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        delete_called = False

        def fail_if_called(_s: str, _u: str) -> None:
            nonlocal delete_called
            delete_called = True

        fake = SimpleNamespace(get_password=lambda _s, _u: None, delete_password=fail_if_called)
        monkeypatch.setitem(sys.modules, "keyring", fake)
        assert clear_api_key_keyring() is False
        assert delete_called is False

    def test_clear_api_key_keyring_handles_password_delete_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = _make_fake_keyring({})
        fake.get_password = lambda _s, _u: "stale-key"
        monkeypatch.setitem(sys.modules, "keyring", fake)
        assert clear_api_key_keyring() is False

    def test_clear_api_key_keyring_reraises_unexpected_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def boom(_s: str, _u: str) -> None:
            raise RuntimeError("locked keyring")

        fake = SimpleNamespace(get_password=lambda _s, _u: "kr-key", delete_password=boom)
        monkeypatch.setitem(sys.modules, "keyring", fake)
        with pytest.raises(RuntimeError, match="locked keyring"):
            clear_api_key_keyring()

    def test_clear_api_key_keyring_raises_when_missing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setitem(sys.modules, "keyring", None)
        with pytest.raises(RuntimeError, match=r"uv pip install 'pwned\[keyring\]'"):
            clear_api_key_keyring()


class TestKeyringPrecedenceAndSource:
    def test_load_settings_falls_back_to_keyring(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = _make_fake_keyring({(KEYRING_SERVICE, KEYRING_USERNAME): "kr-key"})
        monkeypatch.setitem(sys.modules, "keyring", fake)
        monkeypatch.setenv("HIBP_USER_AGENT", "custom-ua")

        s = load_settings()
        assert s.get_api_key() == "kr-key"
        assert s.user_agent == "custom-ua"

    def test_load_settings_xdg_overrides_keyring(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = _make_fake_keyring({(KEYRING_SERVICE, KEYRING_USERNAME): "kr-key"})
        monkeypatch.setitem(sys.modules, "keyring", fake)
        cfg = get_config_file()
        cfg.parent.mkdir(parents=True, exist_ok=True)
        cfg.write_text("HIBP_API_KEY=xdg-key\n", encoding="utf-8")

        assert load_settings().get_api_key() == "xdg-key"

    def test_load_settings_cwd_dotenv_overrides_keyring(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        fake = _make_fake_keyring({(KEYRING_SERVICE, KEYRING_USERNAME): "kr-key"})
        monkeypatch.setitem(sys.modules, "keyring", fake)
        (tmp_path / ".env").write_text("HIBP_API_KEY=cwd-key\n", encoding="utf-8")

        assert load_settings().get_api_key() == "cwd-key"

    def test_load_settings_env_overrides_keyring(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = _make_fake_keyring({(KEYRING_SERVICE, KEYRING_USERNAME): "kr-key"})
        monkeypatch.setitem(sys.modules, "keyring", fake)
        monkeypatch.setenv("HIBP_API_KEY", "env-key")

        assert load_settings().get_api_key() == "env-key"

    def test_load_settings_explicit_overrides_keyring(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = _make_fake_keyring({(KEYRING_SERVICE, KEYRING_USERNAME): "kr-key"})
        monkeypatch.setitem(sys.modules, "keyring", fake)

        assert load_settings(api_key="cli-key").get_api_key() == "cli-key"

    def test_load_settings_empty_explicit_does_not_fallback_to_keyring(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = _make_fake_keyring({(KEYRING_SERVICE, KEYRING_USERNAME): "kr-key"})
        monkeypatch.setitem(sys.modules, "keyring", fake)

        s = load_settings(api_key="")
        assert s.api_key is None
        assert s.get_api_key() is None

    def test_load_settings_empty_env_does_not_fallback_to_keyring(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = _make_fake_keyring({(KEYRING_SERVICE, KEYRING_USERNAME): "kr-key"})
        monkeypatch.setitem(sys.modules, "keyring", fake)
        monkeypatch.setenv("HIBP_API_KEY", "")

        s = load_settings()
        assert s.api_key is None
        assert s.get_api_key() is None

    def test_get_api_key_source_precedence(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        fake = _make_fake_keyring({(KEYRING_SERVICE, KEYRING_USERNAME): "kr-key"})
        monkeypatch.setitem(sys.modules, "keyring", fake)
        assert get_api_key_source() == "keyring"

        cfg = get_config_file()
        cfg.parent.mkdir(parents=True, exist_ok=True)
        cfg.write_text("HIBP_API_KEY=xdg-key\n", encoding="utf-8")
        assert get_api_key_source() == "xdg"

        (tmp_path / ".env").write_text("HIBP_API_KEY=cwd-key\n", encoding="utf-8")
        assert get_api_key_source() == "dotenv"

        monkeypatch.setenv("HIBP_API_KEY", "env-key")
        assert get_api_key_source() == "env"

        assert get_api_key_source(api_key="cli-key") == "cli"

    def test_get_api_key_source_empty_overrides_return_none(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        fake = _make_fake_keyring({(KEYRING_SERVICE, KEYRING_USERNAME): "kr-key"})
        monkeypatch.setitem(sys.modules, "keyring", fake)
        cfg = get_config_file()
        cfg.parent.mkdir(parents=True, exist_ok=True)
        cfg.write_text("HIBP_API_KEY=xdg-key\n", encoding="utf-8")
        (tmp_path / ".env").write_text("HIBP_API_KEY=cwd-key\n", encoding="utf-8")
        monkeypatch.setenv("HIBP_API_KEY", "env-key")

        assert get_api_key_source(api_key="") == "none"

        monkeypatch.setenv("HIBP_API_KEY", "")
        assert get_api_key_source() == "none"

    def test_get_api_key_source_empty_dotenv_shadows_xdg(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setitem(sys.modules, "keyring", None)
        cfg = get_config_file()
        cfg.parent.mkdir(parents=True, exist_ok=True)
        cfg.write_text("HIBP_API_KEY=xdg-key\n", encoding="utf-8")
        (tmp_path / ".env").write_text("HIBP_API_KEY=\n", encoding="utf-8")

        assert get_api_key_source() == "none"

        fake = _make_fake_keyring({(KEYRING_SERVICE, KEYRING_USERNAME): "kr-key"})
        monkeypatch.setitem(sys.modules, "keyring", fake)
        assert get_api_key_source() == "keyring"

    def test_get_api_key_source_handles_home_unavailable_and_none(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def _raise_no_home() -> Path:
            raise RuntimeError("Could not determine home directory.")

        monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
        monkeypatch.setattr(Path, "home", _raise_no_home)
        monkeypatch.setitem(sys.modules, "keyring", None)

        assert get_api_key_source() == "none"
