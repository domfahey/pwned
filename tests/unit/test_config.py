from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

import pytest
from pydantic import SecretStr, ValidationError

from pwned.config import DEFAULT_USER_AGENT, Settings, load_settings


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
