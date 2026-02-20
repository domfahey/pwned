from __future__ import annotations

import time
from typing import Any

import httpx

from pwned.models import Breach, Paste, SubscribedDomain, Subscription

BASE_URL = "https://haveibeenpwned.com/api/v3"
MAX_RETRIES = 3


class HIBPError(Exception):
    pass


class NotFoundError(HIBPError):
    pass


class UnauthorizedError(HIBPError):
    pass


class RateLimitError(HIBPError):
    pass


class HIBPClient:
    def __init__(self, api_key: str | None = None, user_agent: str = "pwned-cli") -> None:
        headers: dict[str, str] = {"User-Agent": user_agent}
        if api_key:
            headers["hibp-api-key"] = api_key
        self._client = httpx.Client(base_url=BASE_URL, headers=headers)

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> HIBPClient:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def _request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        for attempt in range(MAX_RETRIES + 1):
            resp = self._client.request(method, path, **kwargs)
            if resp.status_code == 429:
                if attempt == MAX_RETRIES:
                    raise RateLimitError("Rate limit exceeded after retries")
                retry_after = int(resp.headers.get("retry-after", "2"))
                time.sleep(retry_after)
                continue
            if resp.status_code == 401:
                raise UnauthorizedError("Invalid or missing API key")
            if resp.status_code == 404:
                raise NotFoundError("Not found")
            resp.raise_for_status()
            return resp
        raise RateLimitError("Rate limit exceeded after retries")  # pragma: no cover

    # --- Breaches (no auth for public endpoints) ---

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
        return resp.json()  # type: ignore[no-any-return]

    def get_breach(self, name: str) -> Breach:
        resp = self._request("GET", f"/breach/{name}")
        return resp.json()  # type: ignore[no-any-return]

    def get_latest_breach(self) -> Breach:
        resp = self._request("GET", "/latestbreach")
        return resp.json()  # type: ignore[no-any-return]

    def get_data_classes(self) -> list[str]:
        resp = self._request("GET", "/dataclasses")
        return resp.json()  # type: ignore[no-any-return]

    # --- Account breaches (auth required) ---

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
        resp = self._request("GET", f"/breachedaccount/{account}", params=params)
        return resp.json()  # type: ignore[no-any-return]

    # --- Domain search (auth required) ---

    def get_domain_breaches(self, domain: str) -> dict[str, list[str]]:
        resp = self._request("GET", f"/breacheddomain/{domain}")
        return resp.json()  # type: ignore[no-any-return]

    def get_subscribed_domains(self) -> list[SubscribedDomain]:
        resp = self._request("GET", "/subscribeddomains")
        return resp.json()  # type: ignore[no-any-return]

    # --- Pastes (auth required) ---

    def get_pastes(self, email: str) -> list[Paste]:
        resp = self._request("GET", f"/pasteaccount/{email}")
        return resp.json()  # type: ignore[no-any-return]

    # --- Stealer logs (auth required) ---

    def get_stealer_logs_by_email(self, email: str) -> list[str]:
        resp = self._request("GET", f"/stealerlogsbyemail/{email}")
        return resp.json()  # type: ignore[no-any-return]

    def get_stealer_logs_by_website_domain(self, domain: str) -> list[str]:
        resp = self._request("GET", f"/stealerlogsbywebsitedomain/{domain}")
        return resp.json()  # type: ignore[no-any-return]

    def get_stealer_logs_by_email_domain(self, domain: str) -> dict[str, list[str]]:
        resp = self._request("GET", f"/stealerlogsbyemaildomain/{domain}")
        return resp.json()  # type: ignore[no-any-return]

    # --- Subscription (auth required) ---

    def get_subscription_status(self) -> Subscription:
        resp = self._request("GET", "/subscription/status")
        return resp.json()  # type: ignore[no-any-return]
