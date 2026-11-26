from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

from pwned.async_client import AsyncHIBPClient
from pwned.audit import (
    AuditEntry,
    AuditFinding,
    AuditSummary,
    ExportSource,
    ReuseGroup,
    async_audit_entries,
    audit_entries,
    load_export,
)
from pwned.baseline import (
    diff_account_batch,
    diff_breaches,
    diff_domain_breaches,
    diff_search_result,
    load_baseline,
    save_baseline,
)
from pwned.batch import (
    AccountBatchItem,
    BatchStats,
    PasswordBatchItem,
    async_batch_check_passwords,
    batch_check_accounts,
    batch_check_passwords,
    compute_batch_stats,
    format_batch_stats,
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
from pwned.config import (
    DEFAULT_USER_AGENT,
    ConfigBackend,
    Settings,
    clear_api_key,
    clear_api_key_keyring,
    get_api_key_source,
    keyring_available,
    load_settings,
    save_api_key,
    save_api_key_keyring,
)
from pwned.filtering import BREACH_SORT_KEYS, BreachSortKey, filter_breaches
from pwned.formatting import OutputFormat, format_output
from pwned.models import (
    Breach,
    BreachedAccountRangeResult,
    DataClassDescription,
    DnsToken,
    EmailAlias,
    MetaTag,
    PasswordChecker,
    Paste,
    SearchResult,
    SubscribedDomain,
    Subscription,
)
from pwned.offline import OfflinePasswordsClient
from pwned.passwords import AsyncPwnedPasswordsClient, PwnedPasswordsClient
from pwned.validators import (
    async_validate_password_not_pwned,
    make_password_validator,
    validate_password_not_pwned,
)

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
    "BREACH_SORT_KEYS",
    "BatchStats",
    "Breach",
    "BreachSortKey",
    "BreachedAccountRangeResult",
    "ConfigBackend",
    "DataClassDescription",
    "DnsToken",
    "EmailAlias",
    "ExportSource",
    "ForbiddenError",
    "HIBPClient",
    "HIBPError",
    "MetaTag",
    "NotFoundError",
    "OfflinePasswordsClient",
    "OutputFormat",
    "PasswordBatchItem",
    "PasswordChecker",
    "Paste",
    "PwnedPasswordsClient",
    "RateLimitError",
    "ResponseCache",
    "ReuseGroup",
    "SearchResult",
    "Settings",
    "SubscribedDomain",
    "Subscription",
    "UnauthorizedError",
    "DEFAULT_USER_AGENT",
    "__version__",
    "async_audit_entries",
    "async_batch_check_passwords",
    "async_validate_password_not_pwned",
    "audit_entries",
    "batch_check_accounts",
    "batch_check_passwords",
    "clear_api_key",
    "clear_api_key_keyring",
    "compute_batch_stats",
    "diff_account_batch",
    "diff_breaches",
    "diff_domain_breaches",
    "diff_search_result",
    "filter_breaches",
    "format_batch_stats",
    "format_output",
    "get_api_key_source",
    "keyring_available",
    "load_baseline",
    "load_export",
    "load_settings",
    "make_password_validator",
    "save_api_key",
    "save_api_key_keyring",
    "save_baseline",
    "validate_password_not_pwned",
]
