from __future__ import annotations

import time
from typing import Any
from urllib.parse import quote

import httpx
from pydantic import TypeAdapter

from pwned.config import DEFAULT_USER_AGENT
from pwned.models import Breach, Paste, SubscribedDomain, Subscription

BASE_URL = "https://haveibeenpwned.com/api/v3"
MAX_RETRIES = 3
MAX_RETRY_AFTER = 30
REQUEST_TIMEOUT = 10.0
MAX_ERROR_MESSAGE_LEN = 200

# Module-level adapters avoid rebuilding the validator schema on every API call.
_breaches_adapter = TypeAdapter(list[Breach])
_pastes_adapter = TypeAdapter(list[Paste])
_subscribed_domains_adapter = TypeAdapter(list[SubscribedDomain])
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
    pass


def _extract_error_message(resp: httpx.Response) -> str | None:
    """Extract a sanitized error message from an HIBP JSON error body, if present."""
    try:
        body = resp.json()
    except ValueError:
        return None
    if not isinstance(body, dict):
        return None
    message = body.get("message")
    if not isinstance(message, str):
        return None
    printable = "".join(ch for ch in message if ch.isprintable() or ch.isspace())
    cleaned = " ".join(printable.split())
    if not cleaned:
        return None
    if len(cleaned) > MAX_ERROR_MESSAGE_LEN:
        return f"{cleaned[: MAX_ERROR_MESSAGE_LEN - 1]}…"
    return cleaned


class HIBPClient:
    def __init__(self, api_key: str | None = None, user_agent: str = DEFAULT_USER_AGENT) -> None:
        headers: dict[str, str] = {"User-Agent": user_agent}
        if api_key:
            headers["hibp-api-key"] = api_key
        self._client = httpx.Client(base_url=BASE_URL, headers=headers, timeout=REQUEST_TIMEOUT)

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> HIBPClient:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def _request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        for attempt in range(MAX_RETRIES + 1):
            try:
                resp = self._client.request(method, path, **kwargs)
            except httpx.RequestError as exc:
                raise HIBPError(f"Request failed: {exc}") from exc
            if resp.status_code == 429:
                if attempt == MAX_RETRIES:
                    raise RateLimitError("Rate limit exceeded after retries")
                try:
                    retry_after = max(
                        0, min(int(resp.headers.get("retry-after", "2")), MAX_RETRY_AFTER)
                    )
                except ValueError:
                    retry_after = 2
                time.sleep(retry_after)
                continue
            if resp.status_code == 401:
                raise UnauthorizedError("Invalid or missing API key")
            if resp.status_code == 403:
                detail = _extract_error_message(resp)
                raise ForbiddenError(detail or "Forbidden")
            if resp.status_code == 404:
                raise NotFoundError("Not found")
            try:
                resp.raise_for_status()
            except httpx.HTTPStatusError as exc:
                detail = _extract_error_message(resp)
                msg = f"HTTP {resp.status_code}: {detail}" if detail else f"HTTP {resp.status_code}"
                raise HIBPError(msg) from exc
            return resp
        # Unreachable: 429 on final attempt raises, all other status codes return or raise.
        raise RateLimitError("Rate limit exceeded after retries")  # pragma: no cover

    def get_breaches(
        self,
        *,
        domain: str | None = None,
        is_spam_list: bool | None = None,
    ) -> list[Breach]:
        params: dict[str, str] = {}
        if domain:
            params["domain"] = domain
        if is_spam_list is not None:
            params["isSpamList"] = str(is_spam_list).lower()
        resp = self._request("GET", "/breaches", params=params)
        return _breaches_adapter.validate_json(resp.content)

    def get_breach(self, name: str) -> Breach:
        resp = self._request("GET", f"/breach/{quote(name, safe='')}")
        return Breach.model_validate_json(resp.content)

    def get_latest_breach(self) -> Breach:
        resp = self._request("GET", "/latestbreach")
        return Breach.model_validate_json(resp.content)

    def get_data_classes(self) -> list[str]:
        resp = self._request("GET", "/dataclasses")
        return _str_list_adapter.validate_json(resp.content)

    def get_account_breaches(
        self,
        account: str,
        *,
        truncate: bool = True,
        domain: str | None = None,
        include_unverified: bool = True,
    ) -> list[Breach]:
        params: dict[str, str] = {}
        if not truncate:
            params["truncateResponse"] = "false"
        if domain:
            params["domain"] = domain
        if not include_unverified:
            params["includeUnverified"] = "false"
        resp = self._request("GET", f"/breachedaccount/{quote(account, safe='')}", params=params)
        return _breaches_adapter.validate_json(resp.content)

    def get_domain_breaches(self, domain: str) -> dict[str, list[str]]:
        resp = self._request("GET", f"/breacheddomain/{quote(domain, safe='')}")
        return _str_list_dict_adapter.validate_json(resp.content)

    def get_subscribed_domains(self) -> list[SubscribedDomain]:
        resp = self._request("GET", "/subscribeddomains")
        return _subscribed_domains_adapter.validate_json(resp.content)

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
