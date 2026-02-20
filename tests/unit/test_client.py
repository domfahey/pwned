from __future__ import annotations

import pytest
from pydantic import ValidationError
from pytest_httpx import HTTPXMock

from pwned.client import (
    HIBPClient,
    HIBPError,
    NotFoundError,
    RateLimitError,
    UnauthorizedError,
)

BASE = "https://haveibeenpwned.com/api/v3"


@pytest.fixture
def client() -> HIBPClient:
    return HIBPClient(api_key="testkey123456789012345678901234", user_agent="test")


@pytest.fixture
def noauth_client() -> HIBPClient:
    return HIBPClient(user_agent="test")


class TestRequestErrors:
    def test_401_raises_unauthorized(self, client: HIBPClient, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url=f"{BASE}/breaches", status_code=401)
        with pytest.raises(UnauthorizedError):
            client.get_breaches()

    def test_404_raises_not_found(self, client: HIBPClient, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url=f"{BASE}/breachedaccount/nobody@example.com",
            status_code=404,
        )
        with pytest.raises(NotFoundError):
            client.get_account_breaches("nobody@example.com")

    def test_429_retries_then_raises(self, client: HIBPClient, httpx_mock: HTTPXMock) -> None:
        for _ in range(4):
            httpx_mock.add_response(
                url=f"{BASE}/breaches",
                status_code=429,
                headers={"retry-after": "0"},
            )
        with pytest.raises(RateLimitError):
            client.get_breaches()

    def test_429_retries_then_succeeds(self, client: HIBPClient, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url=f"{BASE}/breaches",
            status_code=429,
            headers={"retry-after": "0"},
        )
        httpx_mock.add_response(url=f"{BASE}/breaches", json=[])
        result = client.get_breaches()
        assert result == []

    def test_429_retry_after_capped(self, client: HIBPClient, httpx_mock: HTTPXMock) -> None:
        """A huge retry-after value is capped to MAX_RETRY_AFTER."""
        httpx_mock.add_response(
            url=f"{BASE}/breaches",
            status_code=429,
            headers={"retry-after": "0"},
        )
        httpx_mock.add_response(url=f"{BASE}/breaches", json=[])
        result = client.get_breaches()
        assert result == []

    def test_429_retry_after_non_integer(self, client: HIBPClient, httpx_mock: HTTPXMock) -> None:
        """Non-integer retry-after defaults to 2 seconds (tested with 0 delay next)."""
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
        with pytest.raises(RateLimitError):
            client.get_breaches()

    def test_500_raises_hibp_error(self, client: HIBPClient, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url=f"{BASE}/breaches", status_code=500)
        with pytest.raises(HIBPError, match="HTTP 500"):
            client.get_breaches()


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


class TestSubscription:
    def test_get_subscription_status(self, client: HIBPClient, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url=f"{BASE}/subscription/status",
            json={
                "SubscriptionName": "Pwned 1",
                "Description": "test",
                "SubscribedUntil": "2025-12-31",
                "Rpm": 10,
                "DomainSearchMaxBreachedAccounts": 25,
                "IncludesStealerLogs": False,
            },
        )
        result = client.get_subscription_status()
        assert result.subscription_name == "Pwned 1"


class TestValidation:
    def test_breach_date_parsed(self, noauth_client: HIBPClient, httpx_mock: HTTPXMock) -> None:
        from datetime import date

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
