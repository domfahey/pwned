from __future__ import annotations

from collections.abc import Iterator
from datetime import date, datetime
from unittest.mock import call, patch

import httpx
import pytest
from pydantic import ValidationError
from pytest_httpx import HTTPXMock

from pwned.client import (
    MAX_ERROR_MESSAGE_LEN,
    MAX_RETRY_AFTER,
    ForbiddenError,
    HIBPClient,
    HIBPError,
    NotFoundError,
    RateLimitError,
    UnauthorizedError,
)
from pwned.config import DEFAULT_USER_AGENT
from pwned.models import Breach, Paste, SubscribedDomain, Subscription

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
        with pytest.raises(UnauthorizedError):
            client.get_breaches()

    def test_404_raises_not_found(self, client: HIBPClient, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url=f"{BASE}/breachedaccount/nobody%40example.com",
            status_code=404,
        )
        with pytest.raises(NotFoundError):
            client.get_account_breaches("nobody@example.com")

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
        b = Breach(name="Adobe")
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
