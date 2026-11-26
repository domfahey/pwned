from __future__ import annotations

import asyncio
from collections.abc import Awaitable
from typing import Any
from urllib.parse import quote

import httpx

from pwned.cache import ResponseCache
from pwned.client import (
    BASE_URL,
    MAX_RETRIES,
    REQUEST_TIMEOUT,
    HIBPError,
    NotFoundError,
    RateLimitError,
    _account_range_adapter,
    _breaches_adapter,
    _build_account_breaches_params,
    _build_breaches_params,
    _build_headers,
    _cache_key,
    _data_class_descriptions_adapter,
    _hash_email,
    _is_email,
    _match_range_suffix,
    _parse_raw_retry_after,
    _parse_retry_after,
    _pastes_adapter,
    _raise_for_error_response,
    _str_list_adapter,
    _str_list_dict_adapter,
    _subscribed_domains_adapter,
    _validate_range_prefix,
)
from pwned.config import DEFAULT_USER_AGENT
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


async def _empty_if_not_found[T](coro: Awaitable[list[T]]) -> list[T]:
    """Await a list-returning request, converting 404 NotFoundError to an empty list."""
    try:
        return await coro
    except NotFoundError:
        return []


class AsyncHIBPClient:
    """Asynchronous client for the Have I Been Pwned v3 API."""

    def __init__(
        self,
        api_key: str | None = None,
        user_agent: str = DEFAULT_USER_AGENT,
        *,
        base_url: str = BASE_URL,
        timeout: float = REQUEST_TIMEOUT,
        max_retries: int = MAX_RETRIES,
        proxy: str | None = None,
        client: httpx.AsyncClient | None = None,
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
            self._client = httpx.AsyncClient(
                base_url=base_url,
                headers=_build_headers(api_key, user_agent),
                timeout=timeout,
                proxy=proxy,
            )
            self._owns_client = True

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def __aenter__(self) -> AsyncHIBPClient:
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.aclose()

    async def _request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        for attempt in range(self._max_retries + 1):
            try:
                resp = await self._client.request(method, path, **kwargs)
            except httpx.RequestError as exc:
                raise HIBPError(f"Request failed: {exc}") from exc
            if resp.status_code == 429:
                if attempt == self._max_retries:
                    raise RateLimitError(
                        "Rate limit exceeded after retries",
                        retry_after=_parse_raw_retry_after(resp),
                    )
                await asyncio.sleep(_parse_retry_after(resp))
                continue
            _raise_for_error_response(resp)
            return resp
        # Unreachable: 429 on final attempt raises, all other status codes return or raise.
        raise RateLimitError("Rate limit exceeded after retries")  # pragma: no cover

    async def _get_cached_or_fetch(self, path: str, params: dict[str, str] | None = None) -> bytes:
        key = _cache_key(path, params)
        if self._cache is not None:
            cached = self._cache.get(key)
            if cached is not None:
                return cached
        resp = await self._request("GET", path, params=params or {})
        if self._cache is not None:
            self._cache.set(key, resp.content)
        return resp.content

    async def get_breaches(
        self,
        *,
        domain: str | None = None,
        is_spam_list: bool | None = None,
    ) -> list[Breach]:
        params = _build_breaches_params(domain, is_spam_list)
        content = await self._get_cached_or_fetch("/breaches", params=params)
        return _breaches_adapter.validate_json(content)

    async def get_breach(self, name: str) -> Breach:
        resp = await self._request("GET", f"/breach/{quote(name, safe='')}")
        return Breach.model_validate_json(resp.content)

    async def get_latest_breach(self) -> Breach:
        resp = await self._request("GET", "/latestbreach")
        return Breach.model_validate_json(resp.content)

    async def get_data_classes(self) -> list[str]:
        content = await self._get_cached_or_fetch("/dataclasses")
        return _str_list_adapter.validate_json(content)

    async def get_data_class_descriptions(self) -> list[DataClassDescription]:
        content = await self._get_cached_or_fetch("/dataclasses/descriptions")
        return _data_class_descriptions_adapter.validate_json(content)

    async def get_account_breaches(
        self,
        account: str,
        *,
        truncate: bool = True,
        domain: str | None = None,
        include_unverified: bool = True,
    ) -> list[Breach]:
        resp = await self._request(
            "GET",
            f"/breachedaccount/{quote(account, safe='')}",
            params=_build_account_breaches_params(truncate, domain, include_unverified),
        )
        return _breaches_adapter.validate_json(resp.content)

    async def get_account_range(self, prefix: str) -> list[BreachedAccountRangeResult]:
        validated_prefix = _validate_range_prefix(prefix)
        resp = await self._request("GET", f"/breachedaccount/range/{validated_prefix}")
        return _account_range_adapter.validate_json(resp.content)

    async def check_account_range(self, email: str) -> list[str]:
        prefix, suffix = _hash_email(email)
        try:
            results = await self.get_account_range(prefix)
        except NotFoundError:
            return []
        return _match_range_suffix(results, suffix)

    async def get_domain_breaches(self, domain: str) -> dict[str, list[str]]:
        resp = await self._request("GET", f"/breacheddomain/{quote(domain, safe='')}")
        return _str_list_dict_adapter.validate_json(resp.content)

    async def get_subscribed_domains(self) -> list[SubscribedDomain]:
        resp = await self._request("GET", "/subscribeddomains")
        return _subscribed_domains_adapter.validate_json(resp.content)

    async def generate_dns_token(self, domain: str) -> DnsToken:
        resp = await self._request(
            "POST",
            "/domainVerification/generateDnsToken",
            json={"DomainName": domain},
        )
        return DnsToken.model_validate_json(resp.content)

    async def verify_dns_token(self, domain: str) -> None:
        await self._request(
            "POST",
            "/domainVerification/verifyDnsToken",
            json={"DomainName": domain},
        )

    async def send_verification_email(self, domain: str, email_alias: EmailAlias) -> None:
        await self._request(
            "POST",
            "/domainVerification/sendEmail",
            json={"DomainName": domain, "EmailAlias": email_alias},
        )

    async def get_pastes(self, email: str) -> list[Paste]:
        resp = await self._request("GET", f"/pasteaccount/{quote(email, safe='')}")
        return _pastes_adapter.validate_json(resp.content)

    async def get_stealer_logs_by_email(self, email: str) -> list[str]:
        resp = await self._request("GET", f"/stealerlogsbyemail/{quote(email, safe='')}")
        return _str_list_adapter.validate_json(resp.content)

    async def get_stealer_logs_by_website_domain(self, domain: str) -> list[str]:
        resp = await self._request("GET", f"/stealerlogsbywebsitedomain/{quote(domain, safe='')}")
        return _str_list_adapter.validate_json(resp.content)

    async def get_stealer_logs_by_email_domain(self, domain: str) -> dict[str, list[str]]:
        resp = await self._request("GET", f"/stealerlogsbyemaildomain/{quote(domain, safe='')}")
        return _str_list_dict_adapter.validate_json(resp.content)

    async def get_subscription_status(self) -> Subscription:
        resp = await self._request("GET", "/subscription/status")
        return Subscription.model_validate_json(resp.content)

    async def search_account(
        self,
        account: str,
        *,
        truncate: bool = True,
        domain: str | None = None,
        include_unverified: bool = True,
        include_stealer_logs: bool = False,
    ) -> SearchResult:
        breaches_coro = _empty_if_not_found(
            self.get_account_breaches(
                account,
                truncate=truncate,
                domain=domain,
                include_unverified=include_unverified,
            )
        )
        if not _is_email(account):
            breaches = await breaches_coro
            return SearchResult(breaches=breaches, pastes=[], stealer_logs=None)

        pastes_coro = _empty_if_not_found(self.get_pastes(account))
        if include_stealer_logs:
            breaches, pastes, stealer_logs = await asyncio.gather(
                breaches_coro,
                pastes_coro,
                _empty_if_not_found(self.get_stealer_logs_by_email(account)),
            )
            return SearchResult(breaches=breaches, pastes=pastes, stealer_logs=stealer_logs)

        breaches, pastes = await asyncio.gather(breaches_coro, pastes_coro)
        return SearchResult(breaches=breaches, pastes=pastes, stealer_logs=None)
