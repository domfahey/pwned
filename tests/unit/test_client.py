from __future__ import annotations

import hashlib
from collections.abc import Iterator
from datetime import date, datetime
from unittest.mock import call, patch

import httpx
import pytest
from pydantic import ValidationError
from pytest_httpx import HTTPXMock

from pwned.cache import ResponseCache
from pwned.client import (
    MAX_ERROR_MESSAGE_LEN,
    MAX_RETRY_AFTER,
    ForbiddenError,
    HIBPClient,
    HIBPError,
    NotFoundError,
    RateLimitError,
    UnauthorizedError,
    _compute_retry_delay,
    _parse_raw_retry_after,
    _parse_retry_after,
)
from pwned.config import DEFAULT_USER_AGENT
from pwned.models import (
    Breach,
    DataClassDescription,
    MetaTag,
    Paste,
    SearchResult,
    SubscribedDomain,
    Subscription,
)

BASE = "https://haveibeenpwned.com/api/v3"


@pytest.fixture
def client() -> Iterator[HIBPClient]:
    with HIBPClient(api_key="testkey123456789012345678901234", user_agent="test") as c:
        yield c


@pytest.fixture
def noauth_client() -> Iterator[HIBPClient]:
    with HIBPClient(user_agent="test") as c:
        yield c


class TestRequestErrors:
    def test_401_raises_unauthorized(self, client: HIBPClient, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url=f"{BASE}/breaches", status_code=401)
        with pytest.raises(UnauthorizedError, match="^Invalid or missing API key$"):
            client.get_breaches()

    def test_401_preserves_plain_text_and_json_string_detail(
        self, client: HIBPClient, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(
            url=f"{BASE}/breaches",
            status_code=401,
            text="Access denied due to missing hibp-api-key.",
            headers={"content-type": "text/plain; charset=utf-8"},
        )
        with pytest.raises(
            UnauthorizedError, match="^Access denied due to missing hibp-api-key\\.$"
        ):
            client.get_breaches()

        httpx_mock.add_response(
            url=f"{BASE}/breaches",
            status_code=401,
            json="Access denied due to improperly formed hibp-api-key.",
        )
        with pytest.raises(
            UnauthorizedError,
            match="^Access denied due to improperly formed hibp-api-key\\.$",
        ):
            client.get_breaches()

    def test_404_raises_not_found(self, client: HIBPClient, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url=f"{BASE}/breachedaccount/nobody%40example.com",
            status_code=404,
        )
        with pytest.raises(NotFoundError, match="^Not found$"):
            client.get_account_breaches("nobody@example.com")

    def test_404_preserves_json_detail_on_verify_meta_tag(
        self, client: HIBPClient, httpx_mock: HTTPXMock
    ) -> None:
        detail = "The expected verification meta tag was not found in the home page head."
        httpx_mock.add_response(
            method="POST",
            url=f"{BASE}/domainVerification/verifyMetaTag",
            status_code=404,
            json={"message": detail},
        )
        with pytest.raises(NotFoundError, match=f"^{detail}$"):
            client.verify_meta_tag("example.com")

    def test_error_ignores_html_and_binary_content_types(
        self, client: HIBPClient, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(
            url=f"{BASE}/breaches",
            status_code=503,
            text="Cloudflare outage",
            headers={"content-type": "text/html; charset=utf-8"},
        )
        with pytest.raises(HIBPError, match="^HTTP 503$"):
            client.get_breaches()

        httpx_mock.add_response(
            url=f"{BASE}/breaches",
            status_code=500,
            content=b"raw binary error",
            headers={"content-type": "application/octet-stream"},
        )
        with pytest.raises(HIBPError, match="^HTTP 500$"):
            client.get_breaches()

    def test_error_handles_plain_text_and_blank_text_bodies(
        self, client: HIBPClient, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(
            url=f"{BASE}/breaches",
            status_code=400,
            text="Invalid query parameter.",
            headers={"content-type": "text/plain"},
        )
        with pytest.raises(HIBPError, match="^HTTP 400: Invalid query parameter\\.$"):
            client.get_breaches()

        httpx_mock.add_response(
            url=f"{BASE}/breaches",
            status_code=400,
            text="   ",
            headers={"content-type": "text/plain"},
        )
        with pytest.raises(HIBPError, match="^HTTP 400$"):
            client.get_breaches()

    def test_403_raises_forbidden_with_json_message(
        self, client: HIBPClient, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(
            url=f"{BASE}/breacheddomain/unverified.com",
            status_code=403,
            json={"statusCode": 403, "message": "Domain not verified."},
        )
        with pytest.raises(ForbiddenError, match="Domain not verified."):
            client.get_domain_breaches("unverified.com")

    def test_403_without_json_uses_generic_message(
        self, client: HIBPClient, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(
            url=f"{BASE}/breacheddomain/unverified.com",
            status_code=403,
            text="<html><body>Forbidden</body></html>",
        )
        with pytest.raises(ForbiddenError, match="^Forbidden$"):
            client.get_domain_breaches("unverified.com")

    @pytest.mark.parametrize(
        "body",
        [[], None, {"error": "no message"}, {"message": 123}, {"message": ""}, {"message": "   "}],
    )
    def test_error_ignores_non_string_or_blank_json_message(
        self, client: HIBPClient, httpx_mock: HTTPXMock, body: object
    ) -> None:
        httpx_mock.add_response(url=f"{BASE}/breaches", status_code=400, json=body)
        with pytest.raises(HIBPError, match="^HTTP 400$"):
            client.get_breaches()

    def test_error_strips_non_printable_control_chars(
        self, client: HIBPClient, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(
            url=f"{BASE}/breaches",
            status_code=400,
            json={"message": "Bad\x00\x1b[31m request\x07"},
        )
        with pytest.raises(HIBPError, match=r"^HTTP 400: Bad\[31m request$"):
            client.get_breaches()

    def test_error_control_chars_only_treated_as_empty(
        self, client: HIBPClient, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(
            url=f"{BASE}/breaches",
            status_code=400,
            json={"message": "\x00\x07\x1b"},
        )
        with pytest.raises(HIBPError, match="^HTTP 400$"):
            client.get_breaches()

    def test_error_message_truncation_boundary(
        self, client: HIBPClient, httpx_mock: HTTPXMock
    ) -> None:
        exact = "a" * MAX_ERROR_MESSAGE_LEN
        httpx_mock.add_response(url=f"{BASE}/breaches", status_code=400, json={"message": exact})
        with pytest.raises(HIBPError) as exc_exact:
            client.get_breaches()
        assert str(exc_exact.value) == f"HTTP 400: {exact}"

        over = "a" * (MAX_ERROR_MESSAGE_LEN + 1)
        httpx_mock.add_response(url=f"{BASE}/breaches", status_code=400, json={"message": over})
        with pytest.raises(HIBPError) as exc_over:
            client.get_breaches()
        detail = str(exc_over.value).removeprefix("HTTP 400: ")
        assert len(detail) == MAX_ERROR_MESSAGE_LEN
        assert detail.endswith("…")

    def test_429_missing_retry_after_defaults_to_two(
        self, client: HIBPClient, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(url=f"{BASE}/breaches", status_code=429)
        httpx_mock.add_response(url=f"{BASE}/breaches", json=[])
        with patch("pwned.client.time.sleep") as mock_sleep:
            assert client.get_breaches() == []
        mock_sleep.assert_called_once_with(2)

    def test_429_succeeds_on_final_retry_attempt(
        self, client: HIBPClient, httpx_mock: HTTPXMock
    ) -> None:
        for _ in range(3):
            httpx_mock.add_response(
                url=f"{BASE}/breaches",
                status_code=429,
                headers={"retry-after": "1"},
            )
        httpx_mock.add_response(url=f"{BASE}/breaches", json=[])
        with patch("pwned.client.time.sleep") as mock_sleep:
            assert client.get_breaches() == []
        assert mock_sleep.call_args_list == [call(1), call(1), call(1)]

    def test_400_includes_sanitized_json_message(
        self, client: HIBPClient, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(
            url=f"{BASE}/breaches",
            status_code=400,
            json={"statusCode": 400, "message": "Bad\n\trequest  " + ("x" * 300)},
        )
        with pytest.raises(HIBPError) as exc_info:
            client.get_breaches()
        msg = str(exc_info.value)
        assert msg.startswith("HTTP 400: Bad request ")
        assert "\n" not in msg
        assert "\t" not in msg
        assert len(msg) <= 220

    def test_503_html_body_not_leaked(self, client: HIBPClient, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url=f"{BASE}/breaches",
            status_code=503,
            text="<html>Cloudflare error</html>",
        )
        with pytest.raises(HIBPError, match="^HTTP 503$"):
            client.get_breaches()

    def test_429_retries_then_raises(self, client: HIBPClient, httpx_mock: HTTPXMock) -> None:
        for _ in range(4):
            httpx_mock.add_response(
                url=f"{BASE}/breaches",
                status_code=429,
                headers={"retry-after": "1"},
            )
        with (
            patch("pwned.client.time.sleep") as mock_sleep,
            pytest.raises(RateLimitError),
        ):
            client.get_breaches()
        assert mock_sleep.call_args_list == [call(1), call(1), call(1)]

    def test_429_retries_then_succeeds(self, client: HIBPClient, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url=f"{BASE}/breaches",
            status_code=429,
            headers={"retry-after": "3"},
        )
        httpx_mock.add_response(url=f"{BASE}/breaches", json=[])
        with patch("pwned.client.time.sleep") as mock_sleep:
            result = client.get_breaches()
        assert result == []
        mock_sleep.assert_called_once_with(3)

    def test_429_retry_after_capped(self, client: HIBPClient, httpx_mock: HTTPXMock) -> None:
        """A huge retry-after value is capped to MAX_RETRY_AFTER."""
        httpx_mock.add_response(
            url=f"{BASE}/breaches",
            status_code=429,
            headers={"retry-after": "99999"},
        )
        httpx_mock.add_response(url=f"{BASE}/breaches", json=[])
        with patch("pwned.client.time.sleep") as mock_sleep:
            result = client.get_breaches()
        assert result == []
        mock_sleep.assert_called_once_with(MAX_RETRY_AFTER)

    def test_429_retry_after_negative_clamped_to_zero(
        self, client: HIBPClient, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(
            url=f"{BASE}/breaches",
            status_code=429,
            headers={"retry-after": "-5"},
        )
        httpx_mock.add_response(url=f"{BASE}/breaches", json=[])
        with patch("pwned.client.time.sleep") as mock_sleep:
            result = client.get_breaches()
        assert result == []
        mock_sleep.assert_called_once_with(0)

    def test_429_retry_after_non_integer(self, client: HIBPClient, httpx_mock: HTTPXMock) -> None:
        """Non-integer retry-after defaults to 2 seconds."""
        httpx_mock.add_response(
            url=f"{BASE}/breaches",
            status_code=429,
            headers={"retry-after": "not-a-number"},
        )
        for _ in range(3):
            httpx_mock.add_response(
                url=f"{BASE}/breaches",
                status_code=429,
                headers={"retry-after": "0"},
            )
        with (
            patch("pwned.client.time.sleep") as mock_sleep,
            pytest.raises(RateLimitError),
        ):
            client.get_breaches()
        assert mock_sleep.call_args_list == [call(2), call(0), call(0)]

    def test_500_raises_hibp_error(self, client: HIBPClient, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url=f"{BASE}/breaches", status_code=500)
        with pytest.raises(HIBPError, match="HTTP 500"):
            client.get_breaches()

    def test_network_error_raises_hibp_error(
        self, client: HIBPClient, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_exception(httpx.ConnectError("connection failed"), url=f"{BASE}/breaches")
        with pytest.raises(HIBPError, match="Request failed"):
            client.get_breaches()


class TestHeaders:
    def test_auth_client_sends_api_key_and_user_agent(
        self, client: HIBPClient, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(url=f"{BASE}/breaches", json=[])
        client.get_breaches()
        request = httpx_mock.get_request()
        assert request is not None
        assert request.headers["hibp-api-key"] == "testkey123456789012345678901234"
        assert request.headers["user-agent"] == "test"

    def test_noauth_client_omits_api_key(
        self, noauth_client: HIBPClient, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(url=f"{BASE}/breaches", json=[])
        noauth_client.get_breaches()
        request = httpx_mock.get_request()
        assert request is not None
        assert "hibp-api-key" not in request.headers
        assert request.headers["user-agent"] == "test"

    def test_default_user_agent_and_empty_api_key(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url=f"{BASE}/breaches", json=[])
        with HIBPClient(api_key="") as c:
            c.get_breaches()
        request = httpx_mock.get_request()
        assert request is not None
        assert "hibp-api-key" not in request.headers
        assert request.headers["user-agent"] == DEFAULT_USER_AGENT


class TestBreaches:
    def test_get_breaches(self, noauth_client: HIBPClient, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url=f"{BASE}/breaches",
            json=[{"Name": "Adobe", "Title": "Adobe"}],
        )
        result = noauth_client.get_breaches()
        assert len(result) == 1
        assert result[0].name == "Adobe"

    def test_get_breaches_with_domain(
        self, noauth_client: HIBPClient, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(json=[{"Name": "Adobe"}])
        noauth_client.get_breaches(domain="adobe.com")
        request = httpx_mock.get_request()
        assert request is not None
        assert "domain=adobe.com" in str(request.url)

    def test_get_breaches_with_spam_list(
        self, noauth_client: HIBPClient, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(json=[])
        noauth_client.get_breaches(is_spam_list=True)
        request = httpx_mock.get_request()
        assert request is not None
        assert "isSpamList=true" in str(request.url)

    def test_get_breaches_exclude_spam_list(
        self, noauth_client: HIBPClient, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(json=[])
        noauth_client.get_breaches(is_spam_list=False)
        request = httpx_mock.get_request()
        assert request is not None
        assert "isSpamList=false" in str(request.url)

    def test_get_breaches_exclude_unverified(
        self, noauth_client: HIBPClient, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(json=[{"Name": "Adobe"}])
        result = noauth_client.get_breaches(include_unverified=False)
        assert [b.name for b in result] == ["Adobe"]
        request = httpx_mock.get_request()
        assert request is not None
        assert "includeUnverified=false" in str(request.url)

    def test_get_breach(self, noauth_client: HIBPClient, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url=f"{BASE}/breach/Adobe",
            json={"Name": "Adobe", "Title": "Adobe", "Domain": "adobe.com"},
        )
        result = noauth_client.get_breach("Adobe")
        assert result.name == "Adobe"

    def test_get_latest_breach(self, noauth_client: HIBPClient, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url=f"{BASE}/latestbreach",
            json={"Name": "Latest", "Title": "Latest Breach"},
        )
        result = noauth_client.get_latest_breach()
        assert result.name == "Latest"

    def test_get_data_classes(self, noauth_client: HIBPClient, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url=f"{BASE}/dataclasses",
            json=["Email addresses", "Passwords"],
        )
        result = noauth_client.get_data_classes()
        assert "Email addresses" in result


class TestAccountBreaches:
    def test_get_account_breaches_truncated(
        self, client: HIBPClient, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(json=[{"Name": "Adobe"}])
        result = client.get_account_breaches("test@example.com")
        assert len(result) == 1
        assert result[0].name == "Adobe"

    def test_get_account_breaches_full(self, client: HIBPClient, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json=[{"Name": "Adobe", "Title": "Adobe", "Domain": "adobe.com"}])
        client.get_account_breaches("test@example.com", truncate=False)
        request = httpx_mock.get_request()
        assert request is not None
        assert "truncateResponse=false" in str(request.url)

    def test_get_account_breaches_with_domain(
        self, client: HIBPClient, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(json=[{"Name": "Adobe"}])
        client.get_account_breaches("test@example.com", domain="adobe.com")
        request = httpx_mock.get_request()
        assert request is not None
        assert "domain=adobe.com" in str(request.url)

    def test_get_account_breaches_no_unverified(
        self, client: HIBPClient, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(json=[])
        client.get_account_breaches("test@example.com", include_unverified=False)
        request = httpx_mock.get_request()
        assert request is not None
        assert "includeUnverified=false" in str(request.url)


class TestDomainSearch:
    def test_get_domain_breaches(self, client: HIBPClient, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url=f"{BASE}/breacheddomain/example.com",
            json={"alias1": ["Adobe"], "alias2": ["Adobe", "Gawker"]},
        )
        result = client.get_domain_breaches("example.com")
        assert "alias1" in result

    def test_get_subscribed_domains(self, client: HIBPClient, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url=f"{BASE}/subscribeddomains",
            json=[{"DomainName": "example.com", "PwnCount": 100}],
        )
        result = client.get_subscribed_domains()
        assert result[0].domain_name == "example.com"

    def test_remove_subscribed_domain(self, client: HIBPClient, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            method="DELETE",
            url=f"{BASE}/subscribeddomains/sub.example.com",
            status_code=200,
        )
        client.remove_subscribed_domain("sub.example.com")
        request = httpx_mock.get_request()
        assert request is not None
        assert request.method == "DELETE"

    def test_remove_subscribed_domain_percent_encoded_and_errors(
        self, client: HIBPClient, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(
            method="DELETE",
            url=f"{BASE}/subscribeddomains/bad%2Fdomain",
            status_code=400,
            json={"message": "Invalid domain."},
        )
        with pytest.raises(HIBPError, match="HTTP 400: Invalid domain\\."):
            client.remove_subscribed_domain("bad/domain")

        httpx_mock.add_response(
            method="DELETE",
            url=f"{BASE}/subscribeddomains/example.com",
            status_code=403,
            json={"message": "Pro subscription required."},
        )
        with pytest.raises(ForbiddenError, match="Pro subscription required\\."):
            client.remove_subscribed_domain("example.com")


class TestPastes:
    def test_get_pastes(self, client: HIBPClient, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            json=[{"Source": "Pastebin", "Id": "abc123", "EmailCount": 10}],
        )
        result = client.get_pastes("test@example.com")
        assert result[0].source == "Pastebin"


class TestStealerLogs:
    def test_by_email(self, client: HIBPClient, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json=["netflix.com", "spotify.com"])
        result = client.get_stealer_logs_by_email("test@example.com")
        assert "netflix.com" in result

    def test_by_website_domain(self, client: HIBPClient, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json=["test@example.com"])
        result = client.get_stealer_logs_by_website_domain("netflix.com")
        assert "test@example.com" in result

    def test_by_email_domain(self, client: HIBPClient, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json={"andy": ["netflix.com"]})
        result = client.get_stealer_logs_by_email_domain("example.com")
        assert "andy" in result


class TestContextManager:
    def test_close_called_on_exit(self) -> None:
        client = HIBPClient(user_agent="test")
        with client:
            pass
        assert client._client.is_closed

    def test_close_called_on_exception(self) -> None:
        client = HIBPClient(user_agent="test")
        with pytest.raises(RuntimeError, match="boom"), client:
            raise RuntimeError("boom")
        assert client._client.is_closed


class TestSubscription:
    def test_get_subscription_status(self, client: HIBPClient, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url=f"{BASE}/subscription/status",
            json={
                "SubscriptionName": "Pwned 1",
                "Description": "test",
                "SubscribedUntil": "2025-12-31T23:59:59Z",
                "Rpm": 10,
                "DomainSearchMaxBreachedAccounts": 25,
                "IncludesStealerLogs": False,
            },
        )
        result = client.get_subscription_status()
        assert result.subscription_name == "Pwned 1"
        assert isinstance(result.subscribed_until, datetime)

    def test_get_subscription_status_unlimited_domain_search(
        self, client: HIBPClient, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(
            url=f"{BASE}/subscription/status",
            json={
                "SubscriptionName": "Pwned 4",
                "Description": "unlimited",
                "SubscribedUntil": "2026-12-31T00:00:00Z",
                "Rpm": 100,
                "DomainSearchMaxBreachedAccounts": None,
                "IncludesStealerLogs": False,
            },
        )
        result = client.get_subscription_status()
        assert result.domain_search_max_breached_accounts is None


class TestValidation:
    def test_breach_date_parsed(self, noauth_client: HIBPClient, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url=f"{BASE}/breaches",
            json=[{"Name": "Adobe", "BreachDate": "2013-10-04"}],
        )
        result = noauth_client.get_breaches()
        assert result[0].breach_date == date(2013, 10, 4)

    def test_breach_defaults_when_fields_absent(
        self, noauth_client: HIBPClient, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(url=f"{BASE}/breaches", json=[{"Name": "Adobe"}])
        result = noauth_client.get_breaches()
        assert result[0].pwn_count == 0
        assert result[0].is_verified is False
        assert result[0].data_classes == []
        assert result[0].breach_date is None

    def test_malformed_response_raises_validation_error(
        self, noauth_client: HIBPClient, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(
            url=f"{BASE}/breaches",
            json=[{"NotAValidField": "missing Name"}],
        )
        with pytest.raises(ValidationError):
            noauth_client.get_breaches()

    def test_negative_pwn_count_raises_validation_error(
        self, noauth_client: HIBPClient, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(
            url=f"{BASE}/breaches",
            json=[{"Name": "Bad", "PwnCount": -1}],
        )
        with pytest.raises(ValidationError):
            noauth_client.get_breaches()

    def test_negative_subscribed_domain_pwn_count_raises_validation_error(
        self, client: HIBPClient, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(
            url=f"{BASE}/subscribeddomains",
            json=[{"DomainName": "example.com", "PwnCount": -1}],
        )
        with pytest.raises(ValidationError):
            client.get_subscribed_domains()

    def test_negative_domain_search_max_raises_validation_error(
        self, client: HIBPClient, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(
            url=f"{BASE}/subscription/status",
            json={
                "SubscriptionName": "Pwned 1",
                "Description": "test",
                "SubscribedUntil": "2025-12-31T23:59:59Z",
                "Rpm": 10,
                "DomainSearchMaxBreachedAccounts": -1,
                "IncludesStealerLogs": False,
            },
        )
        with pytest.raises(ValidationError):
            client.get_subscription_status()

    def test_account_email_percent_encoded_in_url(
        self, client: HIBPClient, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(
            url=f"{BASE}/breachedaccount/user%2Btag%40example.com",
            json=[{"Name": "Adobe"}],
        )
        result = client.get_account_breaches("user+tag@example.com")
        assert result[0].name == "Adobe"

    def test_paste_and_stealer_email_percent_encoded(
        self, client: HIBPClient, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(
            url=f"{BASE}/pasteaccount/user%40example.com",
            json=[{"Source": "Pastebin", "Id": "1", "EmailCount": 1}],
        )
        httpx_mock.add_response(
            url=f"{BASE}/stealerlogsbyemail/user%40example.com",
            json=["netflix.com"],
        )
        assert client.get_pastes("user@example.com")[0].id == "1"
        assert client.get_stealer_logs_by_email("user@example.com") == ["netflix.com"]

    def test_breach_name_percent_encoded(
        self, noauth_client: HIBPClient, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(url=f"{BASE}/breach/Foo%2FBar", json={"Name": "Foo/Bar"})
        assert noauth_client.get_breach("Foo/Bar").name == "Foo/Bar"

    def test_models_frozen_populate_by_name_and_constraints(self) -> None:
        b = Breach.model_validate({"name": "Adobe"})
        assert b.model_dump(by_alias=True, exclude_unset=True) == {"Name": "Adobe"}
        with pytest.raises(ValidationError):
            b.name = "Other"

        p = Paste.model_validate({"Source": "Pastebin", "Id": "p1"})
        assert p.title is None
        assert p.date is None
        assert p.email_count == 0
        with pytest.raises(ValidationError):
            Paste.model_validate({"Source": "Pastebin", "Id": "p1", "EmailCount": -1})

        sub = Subscription.model_validate(
            {
                "SubscriptionName": "Pwned 5",
                "Description": "Full",
                "SubscribedUntil": "2026-12-31T00:00:00Z",
                "Rpm": 0,
                "IncludesStealerLogs": True,
            }
        )
        assert sub.domain_search_max_breached_accounts is None
        assert sub.includes_stealer_logs is True
        with pytest.raises(ValidationError):
            Subscription.model_validate(
                {
                    "SubscriptionName": "Bad",
                    "Description": "Bad",
                    "SubscribedUntil": "2026-12-31T00:00:00Z",
                    "Rpm": -1,
                    "IncludesStealerLogs": False,
                }
            )

        sd = SubscribedDomain.model_validate({"DomainName": "example.com"})
        assert sd.pwn_count is None
        assert sd.pwn_count_excluding_spam_lists is None
        assert sd.pwn_count_excluding_spam_lists_at_last_subscription_renewal is None
        assert sd.next_subscription_renewal is None
        with pytest.raises(ValidationError):
            SubscribedDomain.model_validate(
                {"DomainName": "example.com", "PwnCountExcludingSpamLists": -1}
            )


class TestRetryAfterHelpers:
    def test_parse_retry_after_valid_clamped_and_invalid(self) -> None:
        assert _parse_retry_after(httpx.Response(429, headers={"retry-after": "5"})) == 5
        assert _parse_retry_after(httpx.Response(429, headers={"retry-after": "0"})) == 0
        assert (
            _parse_retry_after(httpx.Response(429, headers={"retry-after": "999"}))
            == MAX_RETRY_AFTER
        )
        assert _parse_retry_after(httpx.Response(429, headers={"retry-after": "-3"})) == 0
        assert _parse_retry_after(httpx.Response(429, headers={"retry-after": "abc"})) == 2
        assert _parse_retry_after(httpx.Response(429)) == 2

    def test_parse_raw_retry_after(self) -> None:
        assert _parse_raw_retry_after(httpx.Response(429, headers={"retry-after": "120"})) == 120
        assert _parse_raw_retry_after(httpx.Response(429, headers={"retry-after": "0"})) == 0
        assert _parse_raw_retry_after(httpx.Response(429, headers={"retry-after": "-1"})) is None
        assert _parse_raw_retry_after(httpx.Response(429, headers={"retry-after": "bad"})) is None
        assert _parse_raw_retry_after(httpx.Response(429)) is None


class TestClientConfig:
    def test_negative_max_retries_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="max_retries"):
            HIBPClient(max_retries=-1)

    def test_max_retries_zero_raises_immediately_with_retry_after(
        self, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(
            url=f"{BASE}/breaches",
            status_code=429,
            headers={"retry-after": "45"},
        )
        with (
            patch("pwned.client.time.sleep") as mock_sleep,
            HIBPClient(max_retries=0) as client,
            pytest.raises(RateLimitError) as exc_info,
        ):
            client.get_breaches()
        mock_sleep.assert_not_called()
        assert exc_info.value.retry_after == 45

    def test_429_exhausted_sets_none_retry_after_when_header_missing(
        self, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(url=f"{BASE}/breaches", status_code=429)
        with (
            HIBPClient(max_retries=0) as client,
            pytest.raises(RateLimitError) as exc_info,
        ):
            client.get_breaches()
        assert exc_info.value.retry_after is None

    def test_custom_base_url_and_timeout(self, httpx_mock: HTTPXMock) -> None:
        custom_base = "https://proxy.example.test/api/v3"
        httpx_mock.add_response(url=f"{custom_base}/breaches", json=[])
        with HIBPClient(base_url=custom_base, timeout=5.0) as client:
            assert client.get_breaches() == []
            assert client._client.timeout.read == 5.0

    def test_proxy_passed_to_httpx_client(self) -> None:
        with patch("pwned.client.httpx.Client") as mock_http_client:
            HIBPClient(proxy="http://127.0.0.1:8080")
        assert mock_http_client.call_args.kwargs["proxy"] == "http://127.0.0.1:8080"

    def test_injected_client_is_used_and_not_closed(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url=f"{BASE}/breaches", json=[])
        external = httpx.Client(base_url=BASE)
        with HIBPClient(client=external) as hibp:
            assert hibp.get_breaches() == []
        assert not external.is_closed
        external.close()


class TestDataClassDescriptions:
    def test_get_data_class_descriptions(
        self, noauth_client: HIBPClient, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(
            url=f"{BASE}/dataclasses/descriptions",
            json=[
                {"name": "Email addresses", "description": "User email addresses."},
                {"name": "Passwords", "description": "Account passwords."},
            ],
        )
        result = noauth_client.get_data_class_descriptions()
        assert result == [
            DataClassDescription(name="Email addresses", description="User email addresses."),
            DataClassDescription(name="Passwords", description="Account passwords."),
        ]


class TestAccountRange:
    def test_get_account_range_uppercases_prefix(
        self, client: HIBPClient, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(
            url=f"{BASE}/breachedaccount/range/ABCDEF",
            json=[{"hashSuffix": "0" * 34, "websites": ["Adobe", "Dropbox"]}],
        )
        result = client.get_account_range("abcdef")
        assert len(result) == 1
        assert result[0].hash_suffix == "0" * 34
        assert result[0].websites == ["Adobe", "Dropbox"]

    @pytest.mark.parametrize("bad_prefix", ["", "abc", "abcdef0", "ghijkl", "12345\n", "12 345"])
    def test_get_account_range_invalid_prefix_raises(
        self, client: HIBPClient, bad_prefix: str
    ) -> None:
        with pytest.raises(ValueError, match="6 hexadecimal"):
            client.get_account_range(bad_prefix)

    def test_check_account_range_match_normalizes_email(
        self, client: HIBPClient, httpx_mock: HTTPXMock
    ) -> None:
        digest = hashlib.sha1(b"user@example.com").hexdigest().upper()
        prefix, suffix = digest[:6], digest[6:]
        httpx_mock.add_response(
            url=f"{BASE}/breachedaccount/range/{prefix}",
            json=[
                {"hashSuffix": "F" * 34, "websites": ["Unrelated"]},
                {"hashSuffix": suffix.lower(), "websites": ["Adobe", "LinkedIn"]},
            ],
        )
        result = client.check_account_range("  User@Example.COM ")
        assert result == ["Adobe", "LinkedIn"]

    def test_check_account_range_no_match_returns_empty(
        self, client: HIBPClient, httpx_mock: HTTPXMock
    ) -> None:
        digest = hashlib.sha1(b"clean@example.com").hexdigest().upper()
        httpx_mock.add_response(
            url=f"{BASE}/breachedaccount/range/{digest[:6]}",
            json=[{"hashSuffix": "0" * 34, "websites": ["Adobe"]}],
        )
        assert client.check_account_range("clean@example.com") == []

    def test_check_account_range_404_returns_empty(
        self, client: HIBPClient, httpx_mock: HTTPXMock
    ) -> None:
        digest = hashlib.sha1(b"clean@example.com").hexdigest().upper()
        httpx_mock.add_response(
            url=f"{BASE}/breachedaccount/range/{digest[:6]}",
            status_code=404,
        )
        assert client.check_account_range("clean@example.com") == []


class TestDomainVerification:
    def test_generate_dns_token(self, client: HIBPClient, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            method="POST",
            url=f"{BASE}/domainVerification/generateDnsToken",
            json={"txtRecordValue": "hibp-verify=abc123"},
        )
        result = client.generate_dns_token("example.com")
        assert result.txt_record_value == "hibp-verify=abc123"
        req = httpx_mock.get_request()
        assert req is not None
        assert req.read() == b'{"DomainName":"example.com"}'

    def test_verify_dns_token(self, client: HIBPClient, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            method="POST",
            url=f"{BASE}/domainVerification/verifyDnsToken",
            status_code=204,
        )
        client.verify_dns_token("example.com")
        req = httpx_mock.get_request()
        assert req is not None
        assert req.read() == b'{"DomainName":"example.com"}'

    def test_send_verification_email(self, client: HIBPClient, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            method="POST",
            url=f"{BASE}/domainVerification/sendEmail",
            status_code=204,
        )
        client.send_verification_email("example.com", "security")
        req = httpx_mock.get_request()
        assert req is not None
        assert req.read() == b'{"DomainName":"example.com","EmailAlias":"security"}'

    def test_generate_meta_tag(self, client: HIBPClient, httpx_mock: HTTPXMock) -> None:
        tag_html = '<meta name="hibp-verify" content="abc123" />'
        httpx_mock.add_response(
            method="POST",
            url=f"{BASE}/domainVerification/generateMetaTag",
            json={"metaTag": tag_html},
        )
        result = client.generate_meta_tag("example.com")
        assert isinstance(result, MetaTag)
        assert result.meta_tag == tag_html
        req = httpx_mock.get_request()
        assert req is not None
        assert req.read() == b'{"DomainName":"example.com"}'

    def test_verify_meta_tag(self, client: HIBPClient, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            method="POST",
            url=f"{BASE}/domainVerification/verifyMetaTag",
            status_code=204,
        )
        client.verify_meta_tag("example.com")
        req = httpx_mock.get_request()
        assert req is not None
        assert req.read() == b'{"DomainName":"example.com"}'


class TestSearchAccount:
    def test_search_account_email_with_breaches_and_pastes(
        self, client: HIBPClient, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(
            url=f"{BASE}/breachedaccount/user%40example.com",
            json=[{"Name": "Adobe"}],
        )
        httpx_mock.add_response(
            url=f"{BASE}/pasteaccount/user%40example.com",
            json=[{"Source": "Pastebin", "Id": "p1", "EmailCount": 5}],
        )
        result = client.search_account("user@example.com")
        assert isinstance(result, SearchResult)
        assert [b.name for b in result.breaches] == ["Adobe"]
        assert [p.id for p in result.pastes] == ["p1"]
        assert result.stealer_logs is None

    def test_search_account_with_stealer_logs_and_options(
        self, client: HIBPClient, httpx_mock: HTTPXMock
    ) -> None:
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
        result = client.search_account(
            "user@example.com",
            truncate=False,
            domain="adobe.com",
            include_unverified=False,
            include_stealer_logs=True,
        )
        assert [b.name for b in result.breaches] == ["Adobe"]
        assert result.pastes == []
        assert result.stealer_logs == ["netflix.com"]

    def test_search_account_all_404_returns_empty_lists(
        self, client: HIBPClient, httpx_mock: HTTPXMock
    ) -> None:
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
        result = client.search_account("user@example.com", include_stealer_logs=True)
        assert result == SearchResult(breaches=[], pastes=[], stealer_logs=[])

    def test_search_account_username_skips_pastes_and_stealer_logs(
        self, client: HIBPClient, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(
            url=f"{BASE}/breachedaccount/someuser",
            json=[{"Name": "Adobe"}],
        )
        result = client.search_account("someuser", include_stealer_logs=True)
        assert [b.name for b in result.breaches] == ["Adobe"]
        assert result.pastes == []
        assert result.stealer_logs is None
        assert len(httpx_mock.get_requests()) == 1


class TestPublicResponseCache:
    def test_public_endpoints_use_response_cache(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url=f"{BASE}/breaches?domain=adobe.com",
            json=[{"Name": "Adobe"}],
        )
        httpx_mock.add_response(
            url=f"{BASE}/dataclasses",
            json=["Passwords"],
        )
        httpx_mock.add_response(
            url=f"{BASE}/dataclasses/descriptions",
            json=[{"name": "Passwords", "description": "Compromised passwords."}],
        )
        cache = ResponseCache()
        with HIBPClient(user_agent="test", cache=cache) as c:
            assert c.get_breaches(domain="adobe.com") == c.get_breaches(domain="adobe.com")
            assert c.get_data_classes() == c.get_data_classes()
            assert c.get_data_class_descriptions() == c.get_data_class_descriptions()
        assert len(httpx_mock.get_requests()) == 3

    def test_breaches_cache_differentiates_include_unverified(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url=f"{BASE}/breaches", json=[{"Name": "All"}])
        httpx_mock.add_response(
            url=f"{BASE}/breaches?includeUnverified=false",
            json=[{"Name": "VerifiedOnly"}],
        )
        cache = ResponseCache()
        with HIBPClient(user_agent="test", cache=cache) as c:
            assert [b.name for b in c.get_breaches()] == ["All"]
            assert [b.name for b in c.get_breaches(include_unverified=False)] == ["VerifiedOnly"]
            assert [b.name for b in c.get_breaches(include_unverified=False)] == ["VerifiedOnly"]
        assert len(httpx_mock.get_requests()) == 2


class TestRetryJitter:
    @pytest.mark.parametrize("bad_jitter", [-0.1, -1.0, 1.01, 2.0, float("nan"), float("inf")])
    def test_invalid_retry_jitter_raises_value_error(self, bad_jitter: float) -> None:
        with pytest.raises(ValueError, match="retry_jitter must be between 0.0 and 1.0"):
            HIBPClient(retry_jitter=bad_jitter)

    @pytest.mark.parametrize("valid_jitter", [0.0, 0.25, 1.0])
    def test_valid_retry_jitter_accepted(self, valid_jitter: float) -> None:
        with HIBPClient(retry_jitter=valid_jitter) as c:
            assert c._retry_jitter == valid_jitter

    def test_compute_retry_delay_without_jitter_preserves_int_base(self) -> None:
        delay = _compute_retry_delay(httpx.Response(429, headers={"retry-after": "4"}), jitter=0.0)
        assert delay == 4
        assert isinstance(delay, int)

    def test_compute_retry_delay_with_positive_base_and_jitter(self) -> None:
        resp = httpx.Response(429, headers={"retry-after": "10"})
        with patch("pwned.client.secrets.randbelow", return_value=500) as mock_rand:
            delay = _compute_retry_delay(resp, jitter=0.5)
        mock_rand.assert_called_once_with(1000)
        assert delay == pytest.approx(12.5)

    def test_compute_retry_delay_with_zero_base_and_jitter(self) -> None:
        resp = httpx.Response(429, headers={"retry-after": "0"})
        with patch("pwned.client.secrets.randbelow", return_value=250) as mock_rand:
            delay = _compute_retry_delay(resp, jitter=0.8)
        mock_rand.assert_called_once_with(1000)
        assert delay == pytest.approx(0.2)

    def test_429_uses_configured_retry_jitter(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url=f"{BASE}/breaches",
            status_code=429,
            headers={"retry-after": "4"},
        )
        httpx_mock.add_response(url=f"{BASE}/breaches", json=[])
        with (
            patch("pwned.client.secrets.randbelow", return_value=500),
            patch("pwned.client.time.sleep") as mock_sleep,
            HIBPClient(user_agent="test", retry_jitter=0.5) as c,
        ):
            assert c.get_breaches() == []
        mock_sleep.assert_called_once_with(5.0)
