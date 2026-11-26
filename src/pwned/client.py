from __future__ import annotations

import hashlib
import re
import time
from typing import Any
from urllib.parse import quote

import httpx
from pydantic import TypeAdapter

from pwned.cache import ResponseCache
from pwned.config import DEFAULT_USER_AGENT
from pwned.models import (
    Breach,
    BreachedAccountRangeResult,
    DataClassDescription,
    DnsToken,
    EmailAlias,
    MetaTag,
    Paste,
    SearchResult,
    SubscribedDomain,
    Subscription,
)

BASE_URL = "https://haveibeenpwned.com/api/v3"
MAX_RETRIES = 3
MAX_RETRY_AFTER = 30
REQUEST_TIMEOUT = 10.0
MAX_ERROR_MESSAGE_LEN = 200
_EMAIL_RE = re.compile(r"^.+@.+$")
_RANGE_PREFIX_RE = re.compile(r"[0-9A-Fa-f]{6}")

# Module-level adapters avoid rebuilding the validator schema on every API call.
_breaches_adapter = TypeAdapter(list[Breach])
_pastes_adapter = TypeAdapter(list[Paste])
_subscribed_domains_adapter = TypeAdapter(list[SubscribedDomain])
_data_class_descriptions_adapter = TypeAdapter(list[DataClassDescription])
_account_range_adapter = TypeAdapter(list[BreachedAccountRangeResult])
_str_list_adapter = TypeAdapter(list[str])
_str_list_dict_adapter = TypeAdapter(dict[str, list[str]])


class HIBPError(Exception):
    pass


class NotFoundError(HIBPError):
    pass


class UnauthorizedError(HIBPError):
    pass


class ForbiddenError(HIBPError):
    pass


class RateLimitError(HIBPError):
    def __init__(self, message: str, *, retry_after: int | None = None) -> None:
        super().__init__(message)
        self.retry_after = retry_after


_NON_TEXT_ERROR_MEDIA_TYPES = frozenset(
    {"text/html", "application/xhtml+xml", "application/xml", "text/xml"}
)


def _sanitize_error_text(raw: str) -> str | None:
    printable = "".join(ch for ch in raw if ch.isprintable() or ch.isspace())
    cleaned = " ".join(printable.split())
    if not cleaned:
        return None
    if len(cleaned) > MAX_ERROR_MESSAGE_LEN:
        return f"{cleaned[: MAX_ERROR_MESSAGE_LEN - 1]}…"
    return cleaned


def _extract_error_message(resp: httpx.Response) -> str | None:
    """Extract a sanitized error message from an HIBP JSON or plain-text error body."""
    content_type = resp.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type in _NON_TEXT_ERROR_MEDIA_TYPES:
        return None
    try:
        body = resp.json()
    except ValueError:
        if content_type not in ("", "text/plain"):
            return None
        text = resp.text.strip()
        if not text or text.startswith("<"):
            return None
        return _sanitize_error_text(text)
    if isinstance(body, str):
        return _sanitize_error_text(body)
    if isinstance(body, dict):
        message = body.get("message")
        if isinstance(message, str):
            return _sanitize_error_text(message)
    return None


def _parse_retry_after(resp: httpx.Response) -> int:
    """Parse and clamp Retry-After seconds to 0..MAX_RETRY_AFTER, defaulting to 2."""
    try:
        return max(0, min(int(resp.headers.get("retry-after", "2")), MAX_RETRY_AFTER))
    except ValueError:
        return 2


def _parse_raw_retry_after(resp: httpx.Response) -> int | None:
    """Return parsed non-negative Retry-After seconds if present and valid, else None."""
    raw = resp.headers.get("retry-after")
    if raw is None:
        return None
    try:
        value = int(raw)
    except ValueError:
        return None
    return value if value >= 0 else None


def _build_headers(api_key: str | None, user_agent: str) -> dict[str, str]:
    headers: dict[str, str] = {"User-Agent": user_agent}
    if api_key:
        headers["hibp-api-key"] = api_key
    return headers


def _raise_for_error_response(resp: httpx.Response) -> None:
    """Raise the appropriate HIBPError subclass for an HTTP error response."""
    if resp.status_code == 401:
        detail = _extract_error_message(resp)
        raise UnauthorizedError(detail or "Invalid or missing API key")
    if resp.status_code == 403:
        detail = _extract_error_message(resp)
        raise ForbiddenError(detail or "Forbidden")
    if resp.status_code == 404:
        detail = _extract_error_message(resp)
        raise NotFoundError(detail or "Not found")
    try:
        resp.raise_for_status()
    except httpx.HTTPStatusError as exc:
        detail = _extract_error_message(resp)
        msg = f"HTTP {resp.status_code}: {detail}" if detail else f"HTTP {resp.status_code}"
        raise HIBPError(msg) from exc


def _validate_range_prefix(prefix: str) -> str:
    if not _RANGE_PREFIX_RE.fullmatch(prefix):
        raise ValueError("prefix must be exactly 6 hexadecimal characters")
    return prefix.upper()


def _hash_email(email: str) -> tuple[str, str]:
    digest = hashlib.sha1(email.strip().lower().encode("utf-8")).hexdigest().upper()  # noqa: S324
    return digest[:6], digest[6:]


def _match_range_suffix(results: list[BreachedAccountRangeResult], suffix: str) -> list[str]:
    for entry in results:
        if entry.hash_suffix.upper() == suffix:
            return list(entry.websites)
    return []


def _is_email(account: str) -> bool:
    return bool(_EMAIL_RE.match(account.strip()))


def _build_breaches_params(
    domain: str | None,
    is_spam_list: bool | None,
    include_unverified: bool = True,
) -> dict[str, str]:
    params: dict[str, str] = {}
    if domain:
        params["domain"] = domain
    if is_spam_list is not None:
        params["isSpamList"] = str(is_spam_list).lower()
    if not include_unverified:
        params["includeUnverified"] = "false"
    return params


def _build_account_breaches_params(
    truncate: bool, domain: str | None, include_unverified: bool
) -> dict[str, str]:
    params: dict[str, str] = {}
    if not truncate:
        params["truncateResponse"] = "false"
    if domain:
        params["domain"] = domain
    if not include_unverified:
        params["includeUnverified"] = "false"
    return params


def _cache_key(path: str, params: dict[str, str] | None = None) -> str:
    if not params:
        return path
    query = "&".join(f"{k}={v}" for k, v in sorted(params.items()))
    return f"{path}?{query}"


class HIBPClient:
    def __init__(
        self,
        api_key: str | None = None,
        user_agent: str = DEFAULT_USER_AGENT,
        *,
        base_url: str = BASE_URL,
        timeout: float = REQUEST_TIMEOUT,
        max_retries: int = MAX_RETRIES,
        proxy: str | None = None,
        client: httpx.Client | None = None,
        cache: ResponseCache | None = None,
    ) -> None:
        if max_retries < 0:
            raise ValueError("max_retries must be non-negative")
        self._max_retries = max_retries
        self._cache = cache
        if client is not None:
            self._client = client
            self._owns_client = False
        else:
            self._client = httpx.Client(
                base_url=base_url,
                headers=_build_headers(api_key, user_agent),
                timeout=timeout,
                proxy=proxy,
            )
            self._owns_client = True

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> HIBPClient:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def _request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        for attempt in range(self._max_retries + 1):
            try:
                resp = self._client.request(method, path, **kwargs)
            except httpx.RequestError as exc:
                raise HIBPError(f"Request failed: {exc}") from exc
            if resp.status_code == 429:
                if attempt == self._max_retries:
                    raise RateLimitError(
                        "Rate limit exceeded after retries",
                        retry_after=_parse_raw_retry_after(resp),
                    )
                time.sleep(_parse_retry_after(resp))
                continue
            _raise_for_error_response(resp)
            return resp
        # Unreachable: 429 on final attempt raises, all other status codes return or raise.
        raise RateLimitError("Rate limit exceeded after retries")  # pragma: no cover

    def _get_cached_or_fetch(self, path: str, params: dict[str, str] | None = None) -> bytes:
        key = _cache_key(path, params)
        if self._cache is not None:
            cached = self._cache.get(key)
            if cached is not None:
                return cached
        resp = self._request("GET", path, params=params or {})
        if self._cache is not None:
            self._cache.set(key, resp.content)
        return resp.content

    def get_breaches(
        self,
        *,
        domain: str | None = None,
        is_spam_list: bool | None = None,
        include_unverified: bool = True,
    ) -> list[Breach]:
        params = _build_breaches_params(domain, is_spam_list, include_unverified)
        content = self._get_cached_or_fetch("/breaches", params=params)
        return _breaches_adapter.validate_json(content)

    def get_breach(self, name: str) -> Breach:
        resp = self._request("GET", f"/breach/{quote(name, safe='')}")
        return Breach.model_validate_json(resp.content)

    def get_latest_breach(self) -> Breach:
        resp = self._request("GET", "/latestbreach")
        return Breach.model_validate_json(resp.content)

    def get_data_classes(self) -> list[str]:
        content = self._get_cached_or_fetch("/dataclasses")
        return _str_list_adapter.validate_json(content)

    def get_data_class_descriptions(self) -> list[DataClassDescription]:
        content = self._get_cached_or_fetch("/dataclasses/descriptions")
        return _data_class_descriptions_adapter.validate_json(content)

    def get_account_breaches(
        self,
        account: str,
        *,
        truncate: bool = True,
        domain: str | None = None,
        include_unverified: bool = True,
    ) -> list[Breach]:
        resp = self._request(
            "GET",
            f"/breachedaccount/{quote(account, safe='')}",
            params=_build_account_breaches_params(truncate, domain, include_unverified),
        )
        return _breaches_adapter.validate_json(resp.content)

    def get_account_range(self, prefix: str) -> list[BreachedAccountRangeResult]:
        validated_prefix = _validate_range_prefix(prefix)
        resp = self._request("GET", f"/breachedaccount/range/{validated_prefix}")
        return _account_range_adapter.validate_json(resp.content)

    def check_account_range(self, email: str) -> list[str]:
        prefix, suffix = _hash_email(email)
        try:
            results = self.get_account_range(prefix)
        except NotFoundError:
            return []
        return _match_range_suffix(results, suffix)

    def get_domain_breaches(self, domain: str) -> dict[str, list[str]]:
        resp = self._request("GET", f"/breacheddomain/{quote(domain, safe='')}")
        return _str_list_dict_adapter.validate_json(resp.content)

    def get_subscribed_domains(self) -> list[SubscribedDomain]:
        resp = self._request("GET", "/subscribeddomains")
        return _subscribed_domains_adapter.validate_json(resp.content)

    def remove_subscribed_domain(self, domain: str) -> None:
        self._request("DELETE", f"/subscribeddomains/{quote(domain, safe='')}")

    def generate_dns_token(self, domain: str) -> DnsToken:
        resp = self._request(
            "POST",
            "/domainVerification/generateDnsToken",
            json={"DomainName": domain},
        )
        return DnsToken.model_validate_json(resp.content)

    def verify_dns_token(self, domain: str) -> None:
        self._request(
            "POST",
            "/domainVerification/verifyDnsToken",
            json={"DomainName": domain},
        )

    def send_verification_email(self, domain: str, email_alias: EmailAlias) -> None:
        self._request(
            "POST",
            "/domainVerification/sendEmail",
            json={"DomainName": domain, "EmailAlias": email_alias},
        )

    def generate_meta_tag(self, domain: str) -> MetaTag:
        resp = self._request(
            "POST",
            "/domainVerification/generateMetaTag",
            json={"DomainName": domain},
        )
        return MetaTag.model_validate_json(resp.content)

    def verify_meta_tag(self, domain: str) -> None:
        self._request(
            "POST",
            "/domainVerification/verifyMetaTag",
            json={"DomainName": domain},
        )

    def get_pastes(self, email: str) -> list[Paste]:
        resp = self._request("GET", f"/pasteaccount/{quote(email, safe='')}")
        return _pastes_adapter.validate_json(resp.content)

    def get_stealer_logs_by_email(self, email: str) -> list[str]:
        resp = self._request("GET", f"/stealerlogsbyemail/{quote(email, safe='')}")
        return _str_list_adapter.validate_json(resp.content)

    def get_stealer_logs_by_website_domain(self, domain: str) -> list[str]:
        resp = self._request("GET", f"/stealerlogsbywebsitedomain/{quote(domain, safe='')}")
        return _str_list_adapter.validate_json(resp.content)

    def get_stealer_logs_by_email_domain(self, domain: str) -> dict[str, list[str]]:
        resp = self._request("GET", f"/stealerlogsbyemaildomain/{quote(domain, safe='')}")
        return _str_list_dict_adapter.validate_json(resp.content)

    def get_subscription_status(self) -> Subscription:
        resp = self._request("GET", "/subscription/status")
        return Subscription.model_validate_json(resp.content)

    def search_account(
        self,
        account: str,
        *,
        truncate: bool = True,
        domain: str | None = None,
        include_unverified: bool = True,
        include_stealer_logs: bool = False,
    ) -> SearchResult:
        try:
            breaches = self.get_account_breaches(
                account,
                truncate=truncate,
                domain=domain,
                include_unverified=include_unverified,
            )
        except NotFoundError:
            breaches = []

        is_email = _is_email(account)
        pastes: list[Paste] = []
        if is_email:
            try:
                pastes = self.get_pastes(account)
            except NotFoundError:
                pastes = []

        stealer_logs: list[str] | None = None
        if include_stealer_logs and is_email:
            try:
                stealer_logs = self.get_stealer_logs_by_email(account)
            except NotFoundError:
                stealer_logs = []

        return SearchResult(breaches=breaches, pastes=pastes, stealer_logs=stealer_logs)
