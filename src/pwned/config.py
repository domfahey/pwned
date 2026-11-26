from __future__ import annotations

import os
import tempfile
from contextlib import suppress
from pathlib import Path
from typing import Any

from pydantic import SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

DEFAULT_USER_AGENT = "pwned-cli"
_API_KEY_ENV_VAR = "HIBP_API_KEY"
_MIN_MASKED_LENGTH = 9


def get_config_dir() -> Path:
    """Return the XDG config directory for pwned."""
    xdg_config_home = os.environ.get("XDG_CONFIG_HOME")
    if xdg_config_home:
        return Path(xdg_config_home) / "pwned"
    return Path.home() / ".config" / "pwned"


def get_config_file() -> Path:
    """Return the path to the persistent pwned .env config file."""
    return get_config_dir() / ".env"


def _write_env_file_atomic(target: Path, content: str) -> None:
    """Atomically write env file content with 0o600 permissions on POSIX."""
    fd, tmp_name = tempfile.mkstemp(
        dir=target.parent,
        prefix=f".{target.name}.",
        suffix=".tmp",
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as tmp_file:
            tmp_file.write(content)
        if os.name == "posix":
            os.chmod(tmp_name, 0o600)
        os.replace(tmp_name, target)
    except BaseException:
        with suppress(OSError):
            os.unlink(tmp_name)
        raise


def save_api_key(api_key: str, *, path: Path | None = None) -> Path:
    """Persist HIBP_API_KEY to the config .env file with restrictive permissions."""
    if not api_key or not api_key.strip():
        raise ValueError("API key must not be empty.")
    if "\n" in api_key or "\r" in api_key:
        raise ValueError("API key must not contain newline characters.")

    target = path or get_config_file()
    created_parent = not target.parent.exists()
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if created_parent and os.name == "posix":
        os.chmod(target.parent, 0o700)

    existing_lines = target.read_text(encoding="utf-8").splitlines() if target.exists() else []
    new_lines: list[str] = []
    replaced = False
    prefix = f"{_API_KEY_ENV_VAR}="
    for line in existing_lines:
        if line.lstrip().startswith(prefix):
            if not replaced:
                new_lines.append(f"{prefix}{api_key}")
                replaced = True
        else:
            new_lines.append(line)

    if not replaced:
        new_lines.append(f"{prefix}{api_key}")

    _write_env_file_atomic(target, "\n".join(new_lines) + "\n")
    return target


def clear_api_key(*, path: Path | None = None) -> bool:
    """Remove HIBP_API_KEY from the config .env file, deleting it if empty."""
    target = path or get_config_file()
    if not target.exists():
        return False

    lines = target.read_text(encoding="utf-8").splitlines()
    prefix = f"{_API_KEY_ENV_VAR}="
    remaining = [line for line in lines if not line.lstrip().startswith(prefix)]
    if len(remaining) == len(lines):
        return False

    if not any(line.strip() for line in remaining):
        target.unlink()
        return True

    _write_env_file_atomic(target, "\n".join(remaining) + "\n")
    return True


def mask_api_key(api_key: str | None) -> str:
    """Return a masked representation of an API key for display."""
    if not api_key:
        return "(not set)"
    if len(api_key) < _MIN_MASKED_LENGTH:
        return "****"
    return f"{api_key[:4]}...{api_key[-4:]}"


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
    env_files: Path | tuple[Path, Path]
    try:
        env_files = (get_config_file(), Path(".env"))
    except RuntimeError:
        env_files = Path(".env")
    kwargs: dict[str, Any] = {"_env_file": env_files}
    if api_key is not None:
        kwargs["api_key"] = SecretStr(api_key) if api_key else None
    if user_agent is not None:
        kwargs["user_agent"] = user_agent
    return Settings(**kwargs)
