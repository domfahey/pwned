from __future__ import annotations

import asyncio
import hashlib

import pytest

from pwned.async_client import AsyncHIBPClient
from pwned.client import HIBPClient, NotFoundError
from pwned.models import Breach, DataClassDescription
from pwned.passwords import AsyncPwnedPasswordsClient, PwnedPasswordsClient

TEST_API_KEY = "00000000000000000000000000000000"
TEST_DOMAIN = "hibp-integration-tests.com"
_UNLIKELY_VALUE = "xK9#mL2$vQ7@nR4!pW8&jF5*hT3^bY6"
_PASSWORD_SHA1 = hashlib.sha1(b"password").hexdigest().upper()
_PASSWORD_PREFIX = _PASSWORD_SHA1[:5]
_PASSWORD_SUFFIX = _PASSWORD_SHA1[5:]


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

    def test_get_data_class_descriptions(self) -> None:
        with HIBPClient(user_agent="pwned-integration-test") as client:
            descriptions = client.get_data_class_descriptions()
            assert len(descriptions) > 0
            assert all(isinstance(item, DataClassDescription) for item in descriptions)
            assert any(item.name == "Email addresses" and item.description for item in descriptions)


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
            count = client.check_password(_UNLIKELY_VALUE)
            assert count == 0

    def test_get_password_range(self) -> None:
        with PwnedPasswordsClient(user_agent="pwned-integration-test") as client:
            counts = client.get_password_range(_PASSWORD_PREFIX)
            assert len(counts) > 0
            assert counts.get(_PASSWORD_SUFFIX, 0) > 0

    def test_is_pwned(self) -> None:
        with PwnedPasswordsClient(user_agent="pwned-integration-test") as client:
            assert client.is_pwned("password") is True
            assert client.is_pwned(_UNLIKELY_VALUE) is False

    def test_check_hash_and_is_hash_pwned(self) -> None:
        with PwnedPasswordsClient(user_agent="pwned-integration-test") as client:
            assert client.check_hash(_PASSWORD_SHA1) > 0
            assert client.is_hash_pwned(_PASSWORD_SHA1) is True


class TestAsyncEndpoints:
    def test_get_data_class_descriptions(self) -> None:
        async def _run() -> list[DataClassDescription]:
            async with AsyncHIBPClient(user_agent="pwned-integration-test") as client:
                return await client.get_data_class_descriptions()

        descriptions = asyncio.run(_run())
        assert len(descriptions) > 0
        assert all(isinstance(item, DataClassDescription) for item in descriptions)
        assert any(item.name == "Email addresses" and item.description for item in descriptions)

    def test_get_breach_adobe(self) -> None:
        async def _run() -> Breach:
            async with AsyncHIBPClient(user_agent="pwned-integration-test") as client:
                return await client.get_breach("Adobe")

        breach = asyncio.run(_run())
        assert breach.name == "Adobe"
        assert breach.domain == "adobe.com"

    def test_get_account_breaches(self) -> None:
        async def _run() -> list[Breach]:
            async with AsyncHIBPClient(
                api_key=TEST_API_KEY, user_agent="pwned-integration-test"
            ) as client:
                return await client.get_account_breaches(f"account-exists@{TEST_DOMAIN}")

        breaches = asyncio.run(_run())
        assert len(breaches) >= 1


class TestAsyncPwnedPasswords:
    def test_check_password_and_is_pwned(self) -> None:
        async def _run() -> tuple[int, bool]:
            async with AsyncPwnedPasswordsClient(user_agent="pwned-integration-test") as client:
                count = await client.check_password("password")
                pwned = await client.is_pwned("password")
                return count, pwned

        count, pwned = asyncio.run(_run())
        assert count > 0
        assert pwned is True

    def test_check_hash_and_range(self) -> None:
        async def _run() -> tuple[int, dict[str, int]]:
            async with AsyncPwnedPasswordsClient(user_agent="pwned-integration-test") as client:
                count = await client.check_hash(_PASSWORD_SHA1)
                counts = await client.get_password_range(_PASSWORD_PREFIX)
                return count, counts

        count, counts = asyncio.run(_run())
        assert count > 0
        assert len(counts) > 0
        assert counts.get(_PASSWORD_SUFFIX, 0) > 0
