from __future__ import annotations

from typing import Any

from pydantic import SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

DEFAULT_USER_AGENT = "pwned-cli"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="HIBP_",
        env_file=".env",
        env_file_encoding="utf-8",
        frozen=True,
    )

    api_key: SecretStr | None = None
    user_agent: str = DEFAULT_USER_AGENT

    @field_validator("api_key", mode="before")
    @classmethod
    def _empty_str_to_none(cls, v: object) -> object:
        if isinstance(v, str) and not v:
            return None
        return v

    @field_validator("user_agent", mode="before")
    @classmethod
    def _empty_user_agent_to_default(cls, v: object) -> object:
        if isinstance(v, str) and not v.strip():
            return DEFAULT_USER_AGENT
        return v

    def get_api_key(self) -> str | None:
        """Return the plaintext API key, or None."""
        return self.api_key.get_secret_value() if self.api_key else None


def load_settings(
    *,
    api_key: str | None = None,
    user_agent: str | None = None,
) -> Settings:
    kwargs: dict[str, Any] = {}
    if api_key is not None:
        kwargs["api_key"] = SecretStr(api_key) if api_key else None
    if user_agent is not None:
        kwargs["user_agent"] = user_agent
    return Settings(**kwargs)
