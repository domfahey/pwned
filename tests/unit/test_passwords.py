from __future__ import annotations

import hashlib
from collections.abc import Iterator

import httpx
import pytest
from pytest_httpx import HTTPXMock

from pwned.client import HIBPError
from pwned.config import DEFAULT_USER_AGENT
from pwned.passwords import PwnedPasswordsClient, _md4, _ntlm_hash

SHA1_PASSWORD = hashlib.sha1(b"password").hexdigest().upper()
PREFIX = SHA1_PASSWORD[:5]
SUFFIX = SHA1_PASSWORD[5:]

RANGE_RESPONSE = f"""{SUFFIX}:3861493
0018A45C4D1DEF81644B54AB7F969B88D65:1
00D4F6E8FA6EECAD2A3AA415EEC418D38EC:2
"""


@pytest.fixture
def client() -> Iterator[PwnedPasswordsClient]:
    with PwnedPasswordsClient(user_agent="test-agent") as c:
        yield c


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

    def test_http_error_wrapped(self, client: PwnedPasswordsClient, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url=f"https://api.pwnedpasswords.com/range/{PREFIX}",
            status_code=500,
        )
        with pytest.raises(HIBPError, match="HTTP 500"):
            client.check_password("password")

    def test_network_error_wrapped(
        self, client: PwnedPasswordsClient, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_exception(
            httpx.ReadTimeout("timed out"),
            url=f"https://api.pwnedpasswords.com/range/{PREFIX}",
        )
        with pytest.raises(HIBPError, match="Request failed"):
            client.check_password("password")

    @pytest.mark.parametrize(
        ("body", "expected"),
        [
            ("", 0),
            (f"\n   \nNO_COLON_LINE\n{SUFFIX}:5\n", 5),
            (f"{SUFFIX}:5:extra\n", 0),
            (f"{SUFFIX.lower()}:123\n", 123),
            (f"  {SUFFIX}:7  \r\n", 7),
            (f"{SUFFIX}:0\n{SUFFIX}:15\n", 15),
        ],
    )
    def test_response_parsing_edge_cases(
        self,
        client: PwnedPasswordsClient,
        httpx_mock: HTTPXMock,
        body: str,
        expected: int,
    ) -> None:
        httpx_mock.add_response(
            url=f"https://api.pwnedpasswords.com/range/{PREFIX}",
            text=body,
        )
        assert client.check_password("password") == expected

    def test_ntlm_and_pad_combined_and_default_omits_both(
        self, client: PwnedPasswordsClient, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(text="")
        client.check_password("password")
        req1 = httpx_mock.get_request()
        assert req1 is not None
        assert "Add-Padding" not in req1.headers
        assert "mode" not in req1.url.params

        httpx_mock.add_response(text="")
        client.check_password("password", ntlm=True, pad=True)
        req2 = httpx_mock.get_requests()[-1]
        assert req2.headers["Add-Padding"] == "true"
        assert req2.url.params["mode"] == "ntlm"

    def test_default_user_agent_and_explicit_close(self, httpx_mock: HTTPXMock) -> None:
        c = PwnedPasswordsClient()
        httpx_mock.add_response(text="")
        c.check_password("password")
        req = httpx_mock.get_request()
        assert req is not None
        assert req.headers["User-Agent"] == DEFAULT_USER_AGENT
        c.close()
        assert c._client.is_closed


class TestContextManager:
    def test_close_called_on_exit(self) -> None:
        client = PwnedPasswordsClient(user_agent="test-agent")
        with client:
            pass
        assert client._client.is_closed


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

    def test_padding_block_boundaries(self) -> None:
        # 55 bytes -> 56 bytes after 0x80 (0 padding zero bytes); 56 bytes wraps to 2nd block.
        d55 = _md4(b"a" * 55)
        d56 = _md4(b"a" * 56)
        assert len(d55) == 32
        assert len(d56) == 32
        assert d55 != d56

    def test_ntlm_unicode_password(self) -> None:
        assert _ntlm_hash("päss") == _md4("päss".encode("utf-16-le")).upper()
