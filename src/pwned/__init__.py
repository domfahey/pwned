from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

from pwned.client import (
    ForbiddenError,
    HIBPClient,
    HIBPError,
    NotFoundError,
    RateLimitError,
    UnauthorizedError,
)
from pwned.config import DEFAULT_USER_AGENT, Settings, load_settings
from pwned.models import Breach, Paste, SubscribedDomain, Subscription
from pwned.passwords import PwnedPasswordsClient

try:
    __version__ = version("pwned")
except PackageNotFoundError:  # pragma: no cover
    __version__ = "0.0.0"

__all__ = [
    "DEFAULT_USER_AGENT",
    "Breach",
    "ForbiddenError",
    "HIBPClient",
    "HIBPError",
    "NotFoundError",
    "Paste",
    "PwnedPasswordsClient",
    "RateLimitError",
    "Settings",
    "SubscribedDomain",
    "Subscription",
    "UnauthorizedError",
    "__version__",
    "load_settings",
]
