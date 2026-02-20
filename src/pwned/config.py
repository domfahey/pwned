from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="HIBP_",
        frozen=True,
    )

    api_key: str | None = None
    user_agent: str = "pwned-cli"


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
    return Settings(_env_file=".env", **kwargs)  # type: ignore[call-arg]
