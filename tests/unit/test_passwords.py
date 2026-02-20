from __future__ import annotations

import hashlib

import httpx
import pytest
from pytest_httpx import HTTPXMock

from pwned.passwords import PwnedPasswordsClient, _ntlm_hash

SHA1_PASSWORD = hashlib.sha1(b"password").hexdigest().upper()  # noqa: S324
PREFIX = SHA1_PASSWORD[:5]
SUFFIX = SHA1_PASSWORD[5:]

RANGE_RESPONSE = f"""{SUFFIX}:3861493
0018A45C4D1DEF81644B54AB7F969B88D65:1
00D4F6E8FA6EECAD2A3AA415EEC418D38EC:2
"""


@pytest.fixture
def client() -> PwnedPasswordsClient:
    return PwnedPasswordsClient(user_agent="test-agent")


class TestCheckPassword:
    def test_found(self, client: PwnedPasswordsClient, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url=f"https://api.pwnedpasswords.com/range/{PREFIX}",
            text=RANGE_RESPONSE,
        )
        count = client.check_password("password")
        assert count == 3861493

    def test_not_found(self, client: PwnedPasswordsClient, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url=f"https://api.pwnedpasswords.com/range/{PREFIX}",
            text="0018A45C4D1DEF81644B54AB7F969B88D65:1\n00D4F6E8FA6EECAD2A3AA415EEC418D38EC:2\n",
        )
        count = client.check_password("password")
        assert count == 0

    def test_ntlm_mode(self, client: PwnedPasswordsClient, httpx_mock: HTTPXMock) -> None:
        ntlm = _ntlm_hash("password")
        prefix = ntlm[:5]
        suffix = ntlm[5:]
        httpx_mock.add_response(
            url=httpx.URL(
                f"https://api.pwnedpasswords.com/range/{prefix}",
                params={"mode": "ntlm"},
            ),
            text=f"{suffix}:999\n",
        )
        count = client.check_password("password", ntlm=True)
        assert count == 999

    def test_padding_header(self, client: PwnedPasswordsClient, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url=f"https://api.pwnedpasswords.com/range/{PREFIX}",
            text=f"{SUFFIX}:42\nABCDE00000000000000000000000000000F:0\n",
        )
        count = client.check_password("password", pad=True)
        assert count == 42

        request = httpx_mock.get_request()
        assert request is not None
        assert request.headers["Add-Padding"] == "true"

    def test_padded_zero_count_ignored(
        self, client: PwnedPasswordsClient, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(
            url=f"https://api.pwnedpasswords.com/range/{PREFIX}",
            text=f"{SUFFIX}:0\n",
        )
        count = client.check_password("password", pad=True)
        assert count == 0


class TestNtlmHash:
    def test_known_value(self) -> None:
        result = _ntlm_hash("password")
        assert result == "8846F7EAEE8FB117AD06BDD830B7586C"
