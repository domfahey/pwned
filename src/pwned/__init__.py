from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

from pwned.async_client import AsyncHIBPClient
from pwned.audit import (
    AuditEntry,
    AuditFinding,
    AuditSummary,
    ExportSource,
    audit_entries,
    load_export,
)
from pwned.batch import (
    AccountBatchItem,
    PasswordBatchItem,
    batch_check_accounts,
    batch_check_passwords,
)
from pwned.cache import ResponseCache
from pwned.client import (
    ForbiddenError,
    HIBPClient,
    HIBPError,
    NotFoundError,
    RateLimitError,
    UnauthorizedError,
)
from pwned.config import DEFAULT_USER_AGENT, Settings, clear_api_key, load_settings, save_api_key
from pwned.formatting import OutputFormat, format_output
from pwned.models import (
    Breach,
    BreachedAccountRangeResult,
    DataClassDescription,
    DnsToken,
    EmailAlias,
    Paste,
    SearchResult,
    SubscribedDomain,
    Subscription,
)
from pwned.passwords import AsyncPwnedPasswordsClient, PwnedPasswordsClient

try:
    __version__ = version("pwned")
except PackageNotFoundError:  # pragma: no cover
    __version__ = "0.0.0"

__all__ = [
    "AccountBatchItem",
    "AsyncHIBPClient",
    "AsyncPwnedPasswordsClient",
    "AuditEntry",
    "AuditFinding",
    "AuditSummary",
    "Breach",
    "BreachedAccountRangeResult",
    "DataClassDescription",
    "DnsToken",
    "EmailAlias",
    "ExportSource",
    "ForbiddenError",
    "HIBPClient",
    "HIBPError",
    "NotFoundError",
    "OutputFormat",
    "Paste",
    "PasswordBatchItem",
    "PwnedPasswordsClient",
    "RateLimitError",
    "ResponseCache",
    "SearchResult",
    "Settings",
    "SubscribedDomain",
    "Subscription",
    "UnauthorizedError",
    "DEFAULT_USER_AGENT",
    "__version__",
    "audit_entries",
    "batch_check_accounts",
    "batch_check_passwords",
    "clear_api_key",
    "format_output",
    "load_export",
    "load_settings",
    "save_api_key",
]
