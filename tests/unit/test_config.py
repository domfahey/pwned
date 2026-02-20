from __future__ import annotations

import os
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from pwned.config import Settings, load_settings


class TestSettings:
    def test_frozen(self) -> None:
        s = Settings(api_key="key", user_agent="ua")
        assert s.get_api_key() == "key"
        assert s.user_agent == "ua"

    def test_api_key_masked_in_repr(self) -> None:
        s = Settings(api_key="secret123", user_agent="ua")
        assert "secret123" not in repr(s)
        assert "secret123" not in str(s)

    def test_frozen_rejects_assignment(self) -> None:
        s = Settings(api_key="key", user_agent="ua")
        with pytest.raises(ValidationError):
            s.api_key = "other"  # type: ignore[misc]


class TestLoadSettings:
    def test_defaults(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            s = Settings(_env_file=None)  # type: ignore[call-arg]
            assert s.api_key is None
            assert s.user_agent == "pwned-cli"

    def test_explicit_overrides_env(self) -> None:
        s = Settings(api_key="override", user_agent="custom")
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
            s = load_settings(api_key="override")
            assert s.get_api_key() == "override"

    def test_empty_api_key_becomes_none(self) -> None:
        s = Settings(api_key="")
        assert s.api_key is None

    def test_whitespace_api_key_preserved(self) -> None:
        s = Settings(api_key=" ")
        assert s.get_api_key() == " "
