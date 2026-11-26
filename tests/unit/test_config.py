from __future__ import annotations

import os
import stat
from pathlib import Path
from unittest.mock import patch

import pytest
from pydantic import SecretStr, ValidationError

from pwned.config import (
    DEFAULT_USER_AGENT,
    Settings,
    clear_api_key,
    get_config_dir,
    get_config_file,
    load_settings,
    mask_api_key,
    save_api_key,
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
