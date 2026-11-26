from __future__ import annotations

import asyncio
import hashlib
from typing import Annotated
from unittest.mock import patch

import httpx
import pytest
from pydantic import AfterValidator, BaseModel, ValidationError
from pytest_httpx import HTTPXMock

from pwned.client import HIBPError
from pwned.passwords import AsyncPwnedPasswordsClient, PwnedPasswordsClient
from pwned.validators import (
    async_validate_password_not_pwned,
    make_password_validator,
    validate_password_not_pwned,
)

PWNED_PW_BASE = "https://api.pwnedpasswords.com"


class _FakeChecker:
    def __init__(self, count: int = 0, error: Exception | None = None) -> None:
        self.count = count
        self.error = error
        self.calls: list[tuple[str, bool, bool]] = []
        self.closed = False

    def check_password(
        self,
        password: str,
        *,
        ntlm: bool = False,
        pad: bool = False,
    ) -> int:
        self.calls.append((password, ntlm, pad))
        if self.error is not None:
            raise self.error
        return self.count

    def check_hash(
        self,
        hash_hex: str,
        *,
        ntlm: bool = False,
        pad: bool = False,
    ) -> int:
        return self.count

    def close(self) -> None:
        self.closed = True


def _sha1_parts(password: str) -> tuple[str, str]:
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    return digest[:5], digest[5:]


class TestValidatePasswordNotPwned:
    @pytest.mark.parametrize("bad_threshold", [0, -1, -10])
    def test_invalid_threshold_raises(self, bad_threshold: int) -> None:
        checker = _FakeChecker(count=0)
        with pytest.raises(ValueError, match="threshold"):
            validate_password_not_pwned("secret", threshold=bad_threshold, client=checker)
        assert checker.calls == []

    def test_clean_password_returns_password_and_forwards_flags(self) -> None:
        checker = _FakeChecker(count=0)
        result = validate_password_not_pwned(
            "correct-horse-battery",
            ntlm=True,
            pad=False,
            client=checker,
        )
        assert result == "correct-horse-battery"
        assert checker.calls == [("correct-horse-battery", True, False)]
        assert checker.closed is False

    def test_pwned_password_raises_value_error_with_formatted_count(self) -> None:
        checker = _FakeChecker(count=12345)
        with pytest.raises(
            ValueError,
            match=r"^Password has appeared 12,345 times in data breaches\.$",
        ):
            validate_password_not_pwned("password", client=checker)
        assert checker.calls == [("password", False, True)]

    def test_threshold_boundary(self) -> None:
        below = _FakeChecker(count=4)
        assert validate_password_not_pwned("pw", threshold=5, client=below) == "pw"

        at_limit = _FakeChecker(count=5)
        with pytest.raises(
            ValueError,
            match=r"^Password has appeared 5 times in data breaches\.$",
        ):
            validate_password_not_pwned("pw", threshold=5, client=at_limit)

    def test_hibp_error_fail_closed_reraises(self) -> None:
        checker = _FakeChecker(error=HIBPError("HTTP 503"))
        with pytest.raises(HIBPError, match="HTTP 503"):
            validate_password_not_pwned("pw", client=checker)

    def test_hibp_error_fail_open_returns_password(self) -> None:
        checker = _FakeChecker(error=HIBPError("timeout"))
        assert validate_password_not_pwned("pw", fail_open=True, client=checker) == "pw"

    def test_creates_and_closes_client_when_none_provided(self, httpx_mock: HTTPXMock) -> None:
        prefix, suffix = _sha1_parts("hunter2")
        httpx_mock.add_response(
            url=f"{PWNED_PW_BASE}/range/{prefix}",
            text=f"{suffix}:42\r\n",
        )
        close_calls = 0
        original_close = PwnedPasswordsClient.close

        def spy_close(self: PwnedPasswordsClient) -> None:
            nonlocal close_calls
            close_calls += 1
            original_close(self)

        with (
            patch.object(PwnedPasswordsClient, "close", spy_close),
            pytest.raises(
                ValueError,
                match=r"^Password has appeared 42 times in data breaches\.$",
            ),
        ):
            validate_password_not_pwned("hunter2", user_agent="my-app/1.0")

        assert close_calls == 1
        req = httpx_mock.get_request()
        assert req is not None
        assert req.headers["user-agent"] == "my-app/1.0"
        assert req.headers["add-padding"] == "true"

    def test_closes_owned_client_when_hibp_error_raised(self, httpx_mock: HTTPXMock) -> None:
        prefix, _ = _sha1_parts("hunter2")
        httpx_mock.add_response(
            url=f"{PWNED_PW_BASE}/range/{prefix}",
            status_code=500,
        )
        close_calls = 0
        original_close = PwnedPasswordsClient.close

        def spy_close(self: PwnedPasswordsClient) -> None:
            nonlocal close_calls
            close_calls += 1
            original_close(self)

        with (
            patch.object(PwnedPasswordsClient, "close", spy_close),
            pytest.raises(HIBPError, match="HTTP 500"),
        ):
            validate_password_not_pwned("hunter2")

        assert close_calls == 1


class TestAsyncValidatePasswordNotPwned:
    @pytest.mark.parametrize("bad_threshold", [0, -3])
    def test_invalid_threshold_raises(self, bad_threshold: int) -> None:
        async def _run() -> None:
            with pytest.raises(ValueError, match="threshold"):
                await async_validate_password_not_pwned("secret", threshold=bad_threshold)

        asyncio.run(_run())

    def test_clean_and_pwned_with_injected_client(self, httpx_mock: HTTPXMock) -> None:
        prefix, suffix = _sha1_parts("password123")
        httpx_mock.add_response(
            url=f"{PWNED_PW_BASE}/range/{prefix}",
            text=f"{suffix}:3\r\n",
        )
        httpx_mock.add_response(
            url=f"{PWNED_PW_BASE}/range/{prefix}",
            text=f"{suffix}:3\r\n",
        )

        async def _run() -> None:
            async with AsyncPwnedPasswordsClient(user_agent="injected") as client:
                assert (
                    await async_validate_password_not_pwned(
                        "password123",
                        threshold=4,
                        pad=False,
                        client=client,
                    )
                    == "password123"
                )
                with pytest.raises(
                    ValueError,
                    match=r"^Password has appeared 3 times in data breaches\.$",
                ):
                    await async_validate_password_not_pwned(
                        "password123",
                        threshold=3,
                        client=client,
                    )

        asyncio.run(_run())
        reqs = httpx_mock.get_requests()
        assert "add-padding" not in reqs[0].headers
        assert reqs[1].headers["add-padding"] == "true"

    def test_hibp_error_fail_open_and_fail_closed(self, httpx_mock: HTTPXMock) -> None:
        prefix, _ = _sha1_parts("pw")
        httpx_mock.add_response(url=f"{PWNED_PW_BASE}/range/{prefix}", status_code=503)
        httpx_mock.add_exception(httpx.ConnectError("offline"))

        async def _run() -> None:
            async with AsyncPwnedPasswordsClient(user_agent="test") as client:
                with pytest.raises(HIBPError, match="HTTP 503"):
                    await async_validate_password_not_pwned("pw", client=client)
                assert (
                    await async_validate_password_not_pwned(
                        "pw",
                        fail_open=True,
                        client=client,
                    )
                    == "pw"
                )

        asyncio.run(_run())

    def test_creates_and_closes_async_client_when_none_provided(
        self, httpx_mock: HTTPXMock
    ) -> None:
        prefix, _ = _sha1_parts("clean-pw")
        httpx_mock.add_response(url=f"{PWNED_PW_BASE}/range/{prefix}", text="")
        aclose_calls = 0
        original_aclose = AsyncPwnedPasswordsClient.aclose

        async def spy_aclose(self: AsyncPwnedPasswordsClient) -> None:
            nonlocal aclose_calls
            aclose_calls += 1
            await original_aclose(self)

        async def _run() -> None:
            with patch.object(AsyncPwnedPasswordsClient, "aclose", spy_aclose):
                result = await async_validate_password_not_pwned(
                    "clean-pw",
                    user_agent="async-app/2.0",
                )
                assert result == "clean-pw"

        asyncio.run(_run())
        assert aclose_calls == 1
        req = httpx_mock.get_request()
        assert req is not None
        assert req.headers["user-agent"] == "async-app/2.0"
        assert req.headers["add-padding"] == "true"


class TestMakePasswordValidator:
    @pytest.mark.parametrize("bad_threshold", [0, -1])
    def test_validates_threshold_eagerly(self, bad_threshold: int) -> None:
        with pytest.raises(ValueError, match="threshold"):
            make_password_validator(threshold=bad_threshold)

    def test_pydantic_after_validator_integration(self) -> None:
        clean_checker = _FakeChecker(count=1)
        pwned_checker = _FakeChecker(count=1500)
        error_checker = _FakeChecker(error=HIBPError("network down"))

        class CleanModel(BaseModel):
            password: Annotated[
                str,
                AfterValidator(make_password_validator(threshold=2, client=clean_checker)),
            ]

        class PwnedModel(BaseModel):
            password: Annotated[
                str,
                AfterValidator(
                    make_password_validator(
                        threshold=2,
                        ntlm=True,
                        pad=False,
                        client=pwned_checker,
                    )
                ),
            ]

        class FailOpenModel(BaseModel):
            password: Annotated[
                str,
                AfterValidator(make_password_validator(fail_open=True, client=error_checker)),
            ]

        class FailClosedModel(BaseModel):
            password: Annotated[
                str,
                AfterValidator(make_password_validator(fail_open=False, client=error_checker)),
            ]

        acceptable = "acceptable-pw"
        model = CleanModel(password=acceptable)
        assert model.password == acceptable
        assert clean_checker.calls == [(acceptable, False, True)]

        with pytest.raises(ValidationError) as exc_info:
            PwnedModel(password="bad-pw")
        assert "Password has appeared 1,500 times in data breaches." in str(exc_info.value)
        assert pwned_checker.calls == [("bad-pw", True, False)]

        offline_ok = "offline-ok"
        open_model = FailOpenModel(password=offline_ok)
        assert open_model.password == offline_ok

        with pytest.raises(HIBPError, match="network down"):
            FailClosedModel(password="offline-fail")
