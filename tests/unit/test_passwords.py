from __future__ import annotations

import hashlib

import httpx
import pytest
from pytest_httpx import HTTPXMock

from pwned.passwords import PwnedPasswordsClient, _md4, _ntlm_hash

SHA1_PASSWORD = hashlib.sha1(b"password").hexdigest().upper()
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


class TestMd4Rfc1320:
    """RFC 1320 Appendix A.5 test vectors."""

    def test_empty_string(self) -> None:
        assert _md4(b"") == "31d6cfe0d16ae931b73c59d7e0c089c0"

    def test_a(self) -> None:
        assert _md4(b"a") == "bde52cb31de33e46245e05fbdbd6fb24"

    def test_abc(self) -> None:
        assert _md4(b"abc") == "a448017aaf21d8525fc10ae87aa6729d"

    def test_message_digest(self) -> None:
        assert _md4(b"message digest") == "d9130a8164549fe818874806e1c7014b"

    def test_alphabet(self) -> None:
        assert _md4(b"abcdefghijklmnopqrstuvwxyz") == "d79e1c308aa5bbcdeea8ed63df412da9"

    def test_alphanumeric(self) -> None:
        assert (
            _md4(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
            == "043f8582f241db351ce627e153e7f0e4"
        )

    def test_numeric_sequence(self) -> None:
        assert (
            _md4(
                b"12345678901234567890123456789012345678901234567890123456789012345678901234567890"
            )
            == "e33b4ddc9c38f2199c3e7b164fcc0536"
        )
