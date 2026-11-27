from __future__ import annotations

import importlib
import os
import tempfile
from contextlib import suppress
from pathlib import Path
from typing import Any, Literal, Protocol, cast

from pydantic import SecretStr, field_validator
from pydantic_settings import BaseSettings, DotEnvSettingsSource, SettingsConfigDict

DEFAULT_USER_AGENT = "pwned-cli"
KEYRING_SERVICE = "pwned"
KEYRING_USERNAME = "hibp_api_key"
ConfigBackend = Literal["file", "keyring"]
_API_KEY_ENV_VAR = "HIBP_API_KEY"
_KEYRING_INSTALL_HINT = "uv pip install 'pwned[keyring]'"
_MIN_MASKED_LENGTH = 9


class _KeyringModule(Protocol):
    def get_password(self, service_name: str, username: str) -> str | None: ...
    def set_password(self, service_name: str, username: str, password: str) -> None: ...
    def delete_password(self, service_name: str, username: str) -> None: ...


def _validate_api_key(api_key: str) -> None:
    if not api_key or not api_key.strip():
        raise ValueError("API key must not be empty.")
    if "\n" in api_key or "\r" in api_key:
        raise ValueError("API key must not contain newline characters.")


def _import_keyring() -> _KeyringModule:
    return cast(_KeyringModule, importlib.import_module("keyring"))


def _require_keyring() -> _KeyringModule:
    try:
        return _import_keyring()
    except ImportError as exc:
        raise RuntimeError(
            f"keyring package is not installed. Install with: {_KEYRING_INSTALL_HINT}"
        ) from exc


def keyring_available() -> bool:
    """Return True if the optional keyring package can be imported."""
    try:
        _import_keyring()
    except ImportError:
        return False
    return True


def get_keyring_api_key() -> str | None:
    """Return the HIBP API key stored in the OS keyring, or None."""
    try:
        kr = _import_keyring()
    except ImportError:
        return None
    try:
        value = kr.get_password(KEYRING_SERVICE, KEYRING_USERNAME)
    except Exception:
        return None
    return value if value else None


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
    _validate_api_key(api_key)

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


def save_api_key_keyring(api_key: str) -> None:
    """Persist HIBP_API_KEY to the OS keyring."""
    _validate_api_key(api_key)
    kr = _require_keyring()
    kr.set_password(KEYRING_SERVICE, KEYRING_USERNAME, api_key)


def clear_api_key_keyring() -> bool:
    """Remove HIBP_API_KEY from the OS keyring, returning True if deleted."""
    kr = _require_keyring()
    if not kr.get_password(KEYRING_SERVICE, KEYRING_USERNAME):
        return False
    errors_mod = getattr(kr, "errors", None)
    delete_error = getattr(errors_mod, "PasswordDeleteError", None)
    try:
        kr.delete_password(KEYRING_SERVICE, KEYRING_USERNAME)
    except Exception as exc:
        if isinstance(delete_error, type) and isinstance(exc, delete_error):
            return False
        raise
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
        extra="ignore",
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


def _dotenv_has_api_key(path: Path) -> tuple[bool, bool]:
    """Return (is_defined, is_non_empty) for HIBP_API_KEY in a dotenv file."""
    values = DotEnvSettingsSource(Settings, env_file=path, env_file_encoding="utf-8")()
    if "api_key" not in values:
        return False, False
    return True, bool(values["api_key"])


def get_api_key_source(
    *,
    api_key: str | None = None,
) -> Literal["cli", "env", "dotenv", "xdg", "keyring", "none"]:
    """Return the active HIBP API key source according to precedence."""
    if api_key is not None:
        return "cli" if api_key else "none"
    if _API_KEY_ENV_VAR in os.environ:
        return "env" if os.environ[_API_KEY_ENV_VAR] else "none"

    cwd_defined, cwd_non_empty = _dotenv_has_api_key(Path(".env"))
    if cwd_defined:
        if cwd_non_empty:
            return "dotenv"
    else:
        try:
            xdg_file: Path | None = get_config_file()
        except RuntimeError:
            xdg_file = None
        if xdg_file is not None:
            _, xdg_non_empty = _dotenv_has_api_key(xdg_file)
            if xdg_non_empty:
                return "xdg"

    if get_keyring_api_key():
        return "keyring"
    return "none"


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
    settings = Settings(**kwargs)
    if api_key is None and _API_KEY_ENV_VAR not in os.environ and settings.api_key is None:
        keyring_key = get_keyring_api_key()
        if keyring_key:
            return settings.model_copy(update={"api_key": SecretStr(keyring_key)})
    return settings
