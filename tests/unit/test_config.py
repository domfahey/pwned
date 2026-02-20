from __future__ import annotations

import os
from unittest.mock import patch

from pwned.config import Settings, load_settings


class TestSettings:
    def test_frozen(self) -> None:
        s = Settings(api_key="key", user_agent="ua")
        assert s.api_key == "key"
        assert s.user_agent == "ua"


class TestLoadSettings:
    def test_defaults(self) -> None:
        with (
            patch("pwned.config.load_dotenv"),
            patch.dict(os.environ, {}, clear=True),
        ):
            s = load_settings()
            assert s.api_key is None
            assert s.user_agent == "pwned-cli"

    def test_explicit_overrides_env(self) -> None:
        with patch("pwned.config.load_dotenv"):
            s = load_settings(api_key="override", user_agent="custom")
            assert s.api_key == "override"
            assert s.user_agent == "custom"

    def test_env_vars(self) -> None:
        with (
            patch("pwned.config.load_dotenv"),
            patch.dict(
                os.environ, {"HIBP_API_KEY": "envkey", "HIBP_USER_AGENT": "envua"}, clear=True
            ),
        ):
            s = load_settings()
            assert s.api_key == "envkey"
            assert s.user_agent == "envua"
