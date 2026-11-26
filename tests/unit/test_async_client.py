from __future__ import annotations

import asyncio
import hashlib
from pathlib import Path
from unittest.mock import AsyncMock, call, patch

import httpx
import pytest
from pydantic import ValidationError
from pytest_httpx import HTTPXMock

from pwned.async_client import AsyncHIBPClient
from pwned.cache import ResponseCache
from pwned.client import (
    MAX_RETRY_AFTER,
    ForbiddenError,
    HIBPError,
    NotFoundError,
    RateLimitError,
    UnauthorizedError,
)
from pwned.config import DEFAULT_USER_AGENT
from pwned.models import DataClassDescription, MetaTag, SearchResult

BASE = "https://haveibeenpwned.com/api/v3"
TEST_KEY = "testkey123456789012345678901234"


class TestAsyncRequestErrors:
    def test_401_raises_unauthorized(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url=f"{BASE}/breaches", status_code=401)

        async def _run() -> None:
            async with AsyncHIBPClient(api_key=TEST_KEY, user_agent="test") as client:
                with pytest.raises(UnauthorizedError):
                    await client.get_breaches()

        asyncio.run(_run())

    def test_404_raises_not_found(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url=f"{BASE}/breachedaccount/nobody%40example.com",
            status_code=404,
        )

        async def _run() -> None:
            async with AsyncHIBPClient(api_key=TEST_KEY, user_agent="test") as client:
                with pytest.raises(NotFoundError):
                    await client.get_account_breaches("nobody@example.com")

        asyncio.run(_run())

    def test_403_raises_forbidden_with_json_message(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url=f"{BASE}/breacheddomain/unverified.com",
            status_code=403,
            json={"statusCode": 403, "message": "Domain not verified."},
        )

        async def _run() -> None:
            async with AsyncHIBPClient(api_key=TEST_KEY, user_agent="test") as client:
                with pytest.raises(ForbiddenError, match="Domain not verified."):
                    await client.get_domain_breaches("unverified.com")

        asyncio.run(_run())

    def test_403_without_json_uses_generic_message(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url=f"{BASE}/breacheddomain/unverified.com",
            status_code=403,
            text="<html>Forbidden</html>",
        )

        async def _run() -> None:
            async with AsyncHIBPClient(api_key=TEST_KEY, user_agent="test") as client:
                with pytest.raises(ForbiddenError, match="^Forbidden$"):
                    await client.get_domain_breaches("unverified.com")

        asyncio.run(_run())

    def test_500_raises_hibp_error(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url=f"{BASE}/breaches", status_code=500)

        async def _run() -> None:
            async with AsyncHIBPClient(api_key=TEST_KEY, user_agent="test") as client:
                with pytest.raises(HIBPError, match="HTTP 500"):
                    await client.get_breaches()

        asyncio.run(_run())

    def test_network_error_raises_hibp_error(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_exception(
            httpx.ConnectError("connection failed"),
            url=f"{BASE}/breaches",
        )

        async def _run() -> None:
            async with AsyncHIBPClient(api_key=TEST_KEY, user_agent="test") as client:
                with pytest.raises(HIBPError, match="Request failed"):
                    await client.get_breaches()

        asyncio.run(_run())

    def test_429_missing_retry_after_defaults_to_two(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url=f"{BASE}/breaches", status_code=429)
        httpx_mock.add_response(url=f"{BASE}/breaches", json=[])

        async def _run() -> None:
            with patch("pwned.async_client.asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
                async with AsyncHIBPClient(api_key=TEST_KEY, user_agent="test") as client:
                    assert await client.get_breaches() == []
            mock_sleep.assert_awaited_once_with(2)

        asyncio.run(_run())

    def test_429_succeeds_on_final_retry_attempt(self, httpx_mock: HTTPXMock) -> None:
        for _ in range(3):
            httpx_mock.add_response(
                url=f"{BASE}/breaches",
                status_code=429,
                headers={"retry-after": "1"},
            )
        httpx_mock.add_response(url=f"{BASE}/breaches", json=[])

        async def _run() -> None:
            with patch("pwned.async_client.asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
                async with AsyncHIBPClient(api_key=TEST_KEY, user_agent="test") as client:
                    assert await client.get_breaches() == []
            assert mock_sleep.await_args_list == [call(1), call(1), call(1)]

        asyncio.run(_run())

    def test_429_retry_after_capped(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url=f"{BASE}/breaches",
            status_code=429,
            headers={"retry-after": "99999"},
        )
        httpx_mock.add_response(url=f"{BASE}/breaches", json=[])

        async def _run() -> None:
            with patch("pwned.async_client.asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
                async with AsyncHIBPClient(api_key=TEST_KEY, user_agent="test") as client:
                    assert await client.get_breaches() == []
            mock_sleep.assert_awaited_once_with(MAX_RETRY_AFTER)

        asyncio.run(_run())

    def test_429_retries_then_raises_with_retry_after(self, httpx_mock: HTTPXMock) -> None:
        for _ in range(4):
            httpx_mock.add_response(
                url=f"{BASE}/breaches",
                status_code=429,
                headers={"retry-after": "5"},
            )

        async def _run() -> None:
            with (
                patch("pwned.async_client.asyncio.sleep", new_callable=AsyncMock) as mock_sleep,
                pytest.raises(RateLimitError) as exc_info,
            ):
                async with AsyncHIBPClient(api_key=TEST_KEY, user_agent="test") as client:
                    await client.get_breaches()
            assert mock_sleep.await_args_list == [call(5), call(5), call(5)]
            assert exc_info.value.retry_after == 5

        asyncio.run(_run())

    def test_max_retries_zero_raises_immediately_without_sleep(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url=f"{BASE}/breaches",
            status_code=429,
            headers={"retry-after": "45"},
        )

        async def _run() -> None:
            with (
                patch("pwned.async_client.asyncio.sleep", new_callable=AsyncMock) as mock_sleep,
                pytest.raises(RateLimitError) as exc_info,
            ):
                async with AsyncHIBPClient(max_retries=0) as client:
                    await client.get_breaches()
            mock_sleep.assert_not_awaited()
            assert exc_info.value.retry_after == 45

        asyncio.run(_run())

    def test_429_exhausted_sets_none_retry_after_when_header_missing(
        self, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(url=f"{BASE}/breaches", status_code=429)

        async def _run() -> None:
            with pytest.raises(RateLimitError) as exc_info:
                async with AsyncHIBPClient(max_retries=0) as client:
                    await client.get_breaches()
            assert exc_info.value.retry_after is None

        asyncio.run(_run())


class TestAsyncHeadersAndConfig:
    def test_negative_max_retries_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="max_retries"):
            AsyncHIBPClient(max_retries=-1)

    def test_auth_client_sends_api_key_and_user_agent(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url=f"{BASE}/breaches", json=[])

        async def _run() -> None:
            async with AsyncHIBPClient(api_key=TEST_KEY, user_agent="test") as client:
                await client.get_breaches()

        asyncio.run(_run())
        request = httpx_mock.get_request()
        assert request is not None
        assert request.headers["hibp-api-key"] == TEST_KEY
        assert request.headers["user-agent"] == "test"

    def test_noauth_and_empty_api_key_omit_api_key(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url=f"{BASE}/breaches", json=[])

        async def _run() -> None:
            async with AsyncHIBPClient(api_key="") as client:
                await client.get_breaches()

        asyncio.run(_run())
        request = httpx_mock.get_request()
        assert request is not None
        assert "hibp-api-key" not in request.headers
        assert request.headers["user-agent"] == DEFAULT_USER_AGENT

    def test_custom_base_url_and_timeout(self, httpx_mock: HTTPXMock) -> None:
        custom_base = "https://proxy.example.test/api/v3"
        httpx_mock.add_response(url=f"{custom_base}/breaches", json=[])

        async def _run() -> None:
            async with AsyncHIBPClient(base_url=custom_base, timeout=5.0) as client:
                assert await client.get_breaches() == []
                assert client._client.timeout.read == 5.0

        asyncio.run(_run())

    def test_proxy_passed_to_async_client(self) -> None:
        with patch("pwned.async_client.httpx.AsyncClient") as mock_http_client:
            AsyncHIBPClient(proxy="http://127.0.0.1:8080")
        assert mock_http_client.call_args.kwargs["proxy"] == "http://127.0.0.1:8080"

    def test_injected_client_is_used_and_not_closed(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url=f"{BASE}/breaches", json=[])

        async def _run() -> None:
            external = httpx.AsyncClient(base_url=BASE)
            async with AsyncHIBPClient(client=external) as hibp:
                assert await hibp.get_breaches() == []
            assert not external.is_closed
            await external.aclose()

        asyncio.run(_run())


class TestAsyncContextManager:
    def test_aclose_called_on_exit(self) -> None:
        async def _run() -> None:
            client = AsyncHIBPClient(user_agent="test")
            async with client:
                assert not client._client.is_closed
            assert client._client.is_closed

        asyncio.run(_run())

    def test_aclose_called_on_exception(self) -> None:
        async def _run() -> None:
            client = AsyncHIBPClient(user_agent="test")
            with pytest.raises(RuntimeError, match="boom"):
                async with client:
                    raise RuntimeError("boom")
            assert client._client.is_closed

        asyncio.run(_run())


class TestAsyncCache:
    def test_get_breaches_uses_cache_on_hit(self, httpx_mock: HTTPXMock, tmp_path: Path) -> None:
        httpx_mock.add_response(
            url=f"{BASE}/breaches",
            json=[{"Name": "Adobe", "Title": "Adobe"}],
        )
        cache = ResponseCache(tmp_path)

        async def _run() -> None:
            async with AsyncHIBPClient(user_agent="test", cache=cache) as client:
                first = await client.get_breaches()
                second = await client.get_breaches()
            assert [b.name for b in first] == ["Adobe"]
            assert [b.name for b in second] == ["Adobe"]

        asyncio.run(_run())
        assert len(httpx_mock.get_requests()) == 1

    def test_get_data_classes_and_descriptions_use_cache(
        self, httpx_mock: HTTPXMock, tmp_path: Path
    ) -> None:
        httpx_mock.add_response(
            url=f"{BASE}/dataclasses",
            json=["Email addresses", "Passwords"],
        )
        httpx_mock.add_response(
            url=f"{BASE}/dataclasses/descriptions",
            json=[{"name": "Email addresses", "description": "User email addresses."}],
        )
        cache = ResponseCache(tmp_path)

        async def _run() -> None:
            async with AsyncHIBPClient(user_agent="test", cache=cache) as client:
                assert await client.get_data_classes() == ["Email addresses", "Passwords"]
                assert await client.get_data_classes() == ["Email addresses", "Passwords"]
                expected = [
                    DataClassDescription(
                        name="Email addresses",
                        description="User email addresses.",
                    )
                ]
                assert await client.get_data_class_descriptions() == expected
                assert await client.get_data_class_descriptions() == expected

        asyncio.run(_run())
        assert len(httpx_mock.get_requests()) == 2

    def test_disabled_cache_fetches_every_time(self, httpx_mock: HTTPXMock, tmp_path: Path) -> None:
        httpx_mock.add_response(url=f"{BASE}/dataclasses", json=["Passwords"])
        httpx_mock.add_response(url=f"{BASE}/dataclasses", json=["Passwords"])
        cache = ResponseCache(tmp_path, enabled=False)

        async def _run() -> None:
            async with AsyncHIBPClient(user_agent="test", cache=cache) as client:
                assert await client.get_data_classes() == ["Passwords"]
                assert await client.get_data_classes() == ["Passwords"]

        asyncio.run(_run())
        assert len(httpx_mock.get_requests()) == 2


class TestAsyncEndpoints:
    def test_get_breaches_filters(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url=f"{BASE}/breaches?domain=adobe.com&isSpamList=false",
            json=[{"Name": "Adobe"}],
        )

        async def _run() -> None:
            async with AsyncHIBPClient(user_agent="test") as client:
                result = await client.get_breaches(domain="adobe.com", is_spam_list=False)
            assert [b.name for b in result] == ["Adobe"]

        asyncio.run(_run())

    def test_get_breach_and_latest_breach(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url=f"{BASE}/breach/Foo%2FBar", json={"Name": "Foo/Bar"})
        httpx_mock.add_response(url=f"{BASE}/latestbreach", json={"Name": "Latest"})

        async def _run() -> None:
            async with AsyncHIBPClient(user_agent="test") as client:
                assert (await client.get_breach("Foo/Bar")).name == "Foo/Bar"
                assert (await client.get_latest_breach()).name == "Latest"

        asyncio.run(_run())

    def test_get_account_breaches_options(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url=(
                f"{BASE}/breachedaccount/user%2Btag%40example.com"
                "?truncateResponse=false&domain=adobe.com&includeUnverified=false"
            ),
            json=[{"Name": "Adobe", "Title": "Adobe"}],
        )

        async def _run() -> None:
            async with AsyncHIBPClient(api_key=TEST_KEY, user_agent="test") as client:
                result = await client.get_account_breaches(
                    "user+tag@example.com",
                    truncate=False,
                    domain="adobe.com",
                    include_unverified=False,
                )
            assert result[0].name == "Adobe"

        asyncio.run(_run())

    def test_get_account_range_and_invalid_prefix(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url=f"{BASE}/breachedaccount/range/ABCDEF",
            json=[{"hashSuffix": "0" * 34, "websites": ["Adobe"]}],
        )

        async def _run() -> None:
            async with AsyncHIBPClient(api_key=TEST_KEY, user_agent="test") as client:
                result = await client.get_account_range("abcdef")
                assert result[0].websites == ["Adobe"]
                with pytest.raises(ValueError, match="6 hexadecimal"):
                    await client.get_account_range("bad")

        asyncio.run(_run())

    def test_check_account_range_match_no_match_and_404(self, httpx_mock: HTTPXMock) -> None:
        digest = hashlib.sha1(b"user@example.com").hexdigest().upper()
        prefix, suffix = digest[:6], digest[6:]
        clean_digest = hashlib.sha1(b"clean@example.com").hexdigest().upper()
        gone_digest = hashlib.sha1(b"gone@example.com").hexdigest().upper()

        httpx_mock.add_response(
            url=f"{BASE}/breachedaccount/range/{prefix}",
            json=[{"hashSuffix": suffix.lower(), "websites": ["Adobe", "LinkedIn"]}],
        )
        httpx_mock.add_response(
            url=f"{BASE}/breachedaccount/range/{clean_digest[:6]}",
            json=[{"hashSuffix": "0" * 34, "websites": ["Adobe"]}],
        )
        httpx_mock.add_response(
            url=f"{BASE}/breachedaccount/range/{gone_digest[:6]}",
            status_code=404,
        )

        async def _run() -> None:
            async with AsyncHIBPClient(api_key=TEST_KEY, user_agent="test") as client:
                assert await client.check_account_range("  User@Example.COM ") == [
                    "Adobe",
                    "LinkedIn",
                ]
                assert await client.check_account_range("clean@example.com") == []
                assert await client.check_account_range("gone@example.com") == []

        asyncio.run(_run())

    def test_domain_endpoints_and_verification(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url=f"{BASE}/breacheddomain/example.com",
            json={"alias1": ["Adobe"]},
        )
        httpx_mock.add_response(
            url=f"{BASE}/subscribeddomains",
            json=[{"DomainName": "example.com", "PwnCount": 100}],
        )
        httpx_mock.add_response(
            method="POST",
            url=f"{BASE}/domainVerification/generateDnsToken",
            json={"txtRecordValue": "hibp-verify=abc123"},
        )
        httpx_mock.add_response(
            method="POST",
            url=f"{BASE}/domainVerification/verifyDnsToken",
            status_code=204,
        )
        httpx_mock.add_response(
            method="POST",
            url=f"{BASE}/domainVerification/sendEmail",
            status_code=204,
        )

        async def _run() -> None:
            async with AsyncHIBPClient(api_key=TEST_KEY, user_agent="test") as client:
                assert await client.get_domain_breaches("example.com") == {"alias1": ["Adobe"]}
                domains = await client.get_subscribed_domains()
                assert domains[0].domain_name == "example.com"
                token = await client.generate_dns_token("example.com")
                assert token.txt_record_value == "hibp-verify=abc123"
                await client.verify_dns_token("example.com")
                await client.send_verification_email("example.com", "security")

        asyncio.run(_run())
        requests = httpx_mock.get_requests()
        assert requests[2].read() == b'{"DomainName":"example.com"}'
        assert requests[3].read() == b'{"DomainName":"example.com"}'
        assert requests[4].read() == b'{"DomainName":"example.com","EmailAlias":"security"}'

    def test_generate_and_verify_meta_tag(self, httpx_mock: HTTPXMock) -> None:
        tag_html = '<meta name="hibp-verify" content="xyz789" />'
        httpx_mock.add_response(
            method="POST",
            url=f"{BASE}/domainVerification/generateMetaTag",
            json={"metaTag": tag_html},
        )
        httpx_mock.add_response(
            method="POST",
            url=f"{BASE}/domainVerification/verifyMetaTag",
            status_code=204,
        )

        async def _run() -> None:
            async with AsyncHIBPClient(api_key=TEST_KEY, user_agent="test") as client:
                meta = await client.generate_meta_tag("example.com")
                assert isinstance(meta, MetaTag)
                assert meta.meta_tag == tag_html
                await client.verify_meta_tag("example.com")

        asyncio.run(_run())
        requests = httpx_mock.get_requests()
        assert requests[0].read() == b'{"DomainName":"example.com"}'
        assert requests[1].read() == b'{"DomainName":"example.com"}'

    def test_pastes_stealer_logs_and_subscription(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url=f"{BASE}/pasteaccount/user%40example.com",
            json=[{"Source": "Pastebin", "Id": "abc123", "EmailCount": 10}],
        )
        httpx_mock.add_response(
            url=f"{BASE}/stealerlogsbyemail/user%40example.com",
            json=["netflix.com"],
        )
        httpx_mock.add_response(
            url=f"{BASE}/stealerlogsbywebsitedomain/netflix.com",
            json=["user@example.com"],
        )
        httpx_mock.add_response(
            url=f"{BASE}/stealerlogsbyemaildomain/example.com",
            json={"user": ["netflix.com"]},
        )
        httpx_mock.add_response(
            url=f"{BASE}/subscription/status",
            json={
                "SubscriptionName": "Pwned 1",
                "Description": "test",
                "SubscribedUntil": "2025-12-31T23:59:59Z",
                "Rpm": 10,
                "IncludesStealerLogs": False,
            },
        )

        async def _run() -> None:
            async with AsyncHIBPClient(api_key=TEST_KEY, user_agent="test") as client:
                pastes = await client.get_pastes("user@example.com")
                assert pastes[0].id == "abc123"
                assert await client.get_stealer_logs_by_email("user@example.com") == ["netflix.com"]
                assert await client.get_stealer_logs_by_website_domain("netflix.com") == [
                    "user@example.com"
                ]
                assert await client.get_stealer_logs_by_email_domain("example.com") == {
                    "user": ["netflix.com"]
                }
                sub = await client.get_subscription_status()
                assert sub.subscription_name == "Pwned 1"

        asyncio.run(_run())

    def test_malformed_response_raises_validation_error(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url=f"{BASE}/breaches", json=[{"NotValid": True}])

        async def _run() -> None:
            async with AsyncHIBPClient(user_agent="test") as client:
                with pytest.raises(ValidationError):
                    await client.get_breaches()

        asyncio.run(_run())


class TestAsyncSearchAccount:
    def test_search_account_email_with_breaches_and_pastes(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url=f"{BASE}/breachedaccount/user%40example.com",
            json=[{"Name": "Adobe"}],
        )
        httpx_mock.add_response(
            url=f"{BASE}/pasteaccount/user%40example.com",
            json=[{"Source": "Pastebin", "Id": "p1", "EmailCount": 5}],
        )

        async def _run() -> None:
            async with AsyncHIBPClient(api_key=TEST_KEY, user_agent="test") as client:
                result = await client.search_account("user@example.com")
            assert isinstance(result, SearchResult)
            assert [b.name for b in result.breaches] == ["Adobe"]
            assert [p.id for p in result.pastes] == ["p1"]
            assert result.stealer_logs is None

        asyncio.run(_run())

    def test_search_account_with_stealer_logs_and_options(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url=(
                f"{BASE}/breachedaccount/user%40example.com"
                "?truncateResponse=false&domain=adobe.com&includeUnverified=false"
            ),
            json=[{"Name": "Adobe"}],
        )
        httpx_mock.add_response(
            url=f"{BASE}/pasteaccount/user%40example.com",
            status_code=404,
        )
        httpx_mock.add_response(
            url=f"{BASE}/stealerlogsbyemail/user%40example.com",
            json=["netflix.com"],
        )

        async def _run() -> None:
            async with AsyncHIBPClient(api_key=TEST_KEY, user_agent="test") as client:
                result = await client.search_account(
                    "user@example.com",
                    truncate=False,
                    domain="adobe.com",
                    include_unverified=False,
                    include_stealer_logs=True,
                )
            assert [b.name for b in result.breaches] == ["Adobe"]
            assert result.pastes == []
            assert result.stealer_logs == ["netflix.com"]

        asyncio.run(_run())

    def test_search_account_all_404_returns_empty_lists(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url=f"{BASE}/breachedaccount/user%40example.com",
            status_code=404,
        )
        httpx_mock.add_response(
            url=f"{BASE}/pasteaccount/user%40example.com",
            status_code=404,
        )
        httpx_mock.add_response(
            url=f"{BASE}/stealerlogsbyemail/user%40example.com",
            status_code=404,
        )

        async def _run() -> None:
            async with AsyncHIBPClient(api_key=TEST_KEY, user_agent="test") as client:
                result = await client.search_account("user@example.com", include_stealer_logs=True)
            assert result == SearchResult(breaches=[], pastes=[], stealer_logs=[])

        asyncio.run(_run())

    def test_search_account_username_skips_pastes_and_stealer_logs(
        self, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(
            url=f"{BASE}/breachedaccount/someuser",
            json=[{"Name": "Adobe"}],
        )

        async def _run() -> None:
            async with AsyncHIBPClient(api_key=TEST_KEY, user_agent="test") as client:
                result = await client.search_account("someuser", include_stealer_logs=True)
            assert [b.name for b in result.breaches] == ["Adobe"]
            assert result.pastes == []
            assert result.stealer_logs is None

        asyncio.run(_run())
        assert len(httpx_mock.get_requests()) == 1

    def test_search_account_propagates_non_404_errors(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url=f"{BASE}/breachedaccount/user%40example.com",
            status_code=401,
        )
        httpx_mock.add_response(
            url=f"{BASE}/pasteaccount/user%40example.com",
            status_code=404,
        )

        async def _run() -> None:
            async with AsyncHIBPClient(api_key=TEST_KEY, user_agent="test") as client:
                with pytest.raises(UnauthorizedError):
                    await client.search_account("user@example.com")

        asyncio.run(_run())

    def test_search_account_runs_subqueries_concurrently(self) -> None:
        async def _run() -> None:
            in_flight = 0
            max_in_flight = 0
            all_started = asyncio.Event()

            async def _handler(request: httpx.Request) -> httpx.Response:
                nonlocal in_flight, max_in_flight
                in_flight += 1
                max_in_flight = max(max_in_flight, in_flight)
                if in_flight == 3:
                    all_started.set()
                await asyncio.wait_for(all_started.wait(), timeout=1.0)
                in_flight -= 1
                path = request.url.path
                if "/breachedaccount/" in path:
                    return httpx.Response(200, json=[{"Name": "Adobe"}])
                if "/pasteaccount/" in path:
                    return httpx.Response(
                        200,
                        json=[{"Source": "Pastebin", "Id": "p1", "EmailCount": 1}],
                    )
                if "/stealerlogsbyemail/" in path:
                    return httpx.Response(200, json=["netflix.com"])
                raise AssertionError(f"Unexpected path: {path}")

            transport = httpx.MockTransport(_handler)
            async with (
                httpx.AsyncClient(base_url=BASE, transport=transport) as raw_client,
                AsyncHIBPClient(client=raw_client) as client,
            ):
                result = await client.search_account("user@example.com", include_stealer_logs=True)

            assert max_in_flight == 3
            assert [b.name for b in result.breaches] == ["Adobe"]
            assert [p.id for p in result.pastes] == ["p1"]
            assert result.stealer_logs == ["netflix.com"]

        asyncio.run(_run())
