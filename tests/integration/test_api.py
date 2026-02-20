from __future__ import annotations

import pytest

from pwned.client import HIBPClient, NotFoundError
from pwned.passwords import PwnedPasswordsClient

TEST_API_KEY = "00000000000000000000000000000000"
TEST_DOMAIN = "hibp-integration-tests.com"


pytestmark = pytest.mark.integration


class TestPublicEndpoints:
    def test_get_breaches(self) -> None:
        with HIBPClient(user_agent="pwned-integration-test") as client:
            breaches = client.get_breaches()
            assert len(breaches) > 0
            assert breaches[0].name

    def test_get_breach_adobe(self) -> None:
        with HIBPClient(user_agent="pwned-integration-test") as client:
            breach = client.get_breach("Adobe")
            assert breach.name == "Adobe"
            assert breach.domain == "adobe.com"

    def test_get_latest_breach(self) -> None:
        with HIBPClient(user_agent="pwned-integration-test") as client:
            breach = client.get_latest_breach()
            assert breach.name

    def test_get_data_classes(self) -> None:
        with HIBPClient(user_agent="pwned-integration-test") as client:
            classes = client.get_data_classes()
            assert "Email addresses" in classes


class TestAuthenticatedEndpoints:
    def test_account_exists(self) -> None:
        with HIBPClient(api_key=TEST_API_KEY, user_agent="pwned-integration-test") as client:
            breaches = client.get_account_breaches(f"account-exists@{TEST_DOMAIN}")
            assert len(breaches) >= 1

    def test_account_not_found(self) -> None:
        with (
            HIBPClient(api_key=TEST_API_KEY, user_agent="pwned-integration-test") as client,
            pytest.raises(NotFoundError),
        ):
            client.get_account_breaches(f"opt-out@{TEST_DOMAIN}")

    def test_multiple_breaches(self) -> None:
        with HIBPClient(api_key=TEST_API_KEY, user_agent="pwned-integration-test") as client:
            breaches = client.get_account_breaches(f"multiple-breaches@{TEST_DOMAIN}")
            assert len(breaches) >= 3


class TestPwnedPasswords:
    def test_known_pwned_password(self) -> None:
        with PwnedPasswordsClient(user_agent="pwned-integration-test") as client:
            count = client.check_password("password")
            assert count > 0

    def test_unlikely_password(self) -> None:
        with PwnedPasswordsClient(user_agent="pwned-integration-test") as client:
            count = client.check_password("xK9#mL2$vQ7@nR4!pW8&jF5*hT3^bY6")
            assert count == 0
