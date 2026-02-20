from __future__ import annotations

import os
from dataclasses import dataclass

from dotenv import load_dotenv


@dataclass(frozen=True)
class Settings:
    api_key: str | None
    user_agent: str


def load_settings(
    *,
    api_key: str | None = None,
    user_agent: str | None = None,
) -> Settings:
    load_dotenv()
    return Settings(
        api_key=api_key or os.environ.get("HIBP_API_KEY"),
        user_agent=user_agent or os.environ.get("HIBP_USER_AGENT", "pwned-cli"),
    )
