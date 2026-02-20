from __future__ import annotations

from pydantic import SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="HIBP_",
        env_file=".env",
        env_file_encoding="utf-8",
        frozen=True,
    )

    api_key: SecretStr | None = None
    user_agent: str = "pwned-cli"

    @field_validator("api_key", mode="before")
    @classmethod
    def _empty_str_to_none(cls, v: str | None) -> str | None:
        if isinstance(v, str) and not v:
            return None
        return v

    def get_api_key(self) -> str | None:
        """Return the plaintext API key, or None."""
        return self.api_key.get_secret_value() if self.api_key else None


def load_settings(
    *,
    api_key: str | None = None,
    user_agent: str | None = None,
) -> Settings:
    kwargs: dict[str, str] = {}
    if api_key is not None:
        kwargs["api_key"] = api_key
    if user_agent is not None:
        kwargs["user_agent"] = user_agent
    return Settings(**kwargs)  # type: ignore[arg-type]
